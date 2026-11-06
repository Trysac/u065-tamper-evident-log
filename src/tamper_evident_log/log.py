"""Hash-chained append-only audit log."""

from __future__ import annotations

import hmac
import logging
from collections.abc import Callable, Iterator, Mapping
from datetime import datetime, timezone
from typing import Any

from .canonical import validate_data, validate_text
from .errors import AuditLogError, CorruptLogError
from .model import (
    FORMAT_VERSION,
    GENESIS_HASH,
    Checkpoint,
    Entry,
    VerificationReason,
    VerificationReport,
    compute_hash,
)
from .store import LogStore, MemoryStore

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

MIN_KEY_BYTES = 32
MAX_KEY_BYTES = 4096

EventHook = Callable[[Mapping[str, str | int | bool]], None]


def _check_key(key: object) -> bytes | None:
    if key is None:
        return None
    if not isinstance(key, (bytes, bytearray)) or not MIN_KEY_BYTES <= len(key) <= MAX_KEY_BYTES:
        raise AuditLogError("invalid_key", f"key must be {MIN_KEY_BYTES}-{MAX_KEY_BYTES} bytes")
    return bytes(key)


def _fail(reason: VerificationReason, seq: int, checked: int) -> VerificationReport:
    return VerificationReport(ok=False, checked=checked, first_bad_seq=seq, reason=reason)


class AuditLog:
    """Append-only audit log chained by SHA-256, or HMAC-SHA256 when a key is given.

    One writer per log: there is no locking. Every method that accepts untrusted input
    enforces the limits documented in ``docs/FORMAT.md`` and raises :class:`AuditLogError`.
    """

    def __init__(
        self,
        store: LogStore | None = None,
        *,
        clock: Callable[[], datetime],
        key: bytes | None = None,
        max_memory_entries: int = 100_000,
        on_event: EventHook | None = None,
    ) -> None:
        if not callable(clock):
            raise AuditLogError("invalid_clock", "clock must be a callable returning a datetime")
        self._key = _check_key(key)
        if type(max_memory_entries) is not int or max_memory_entries < 1:
            raise AuditLogError("invalid_data", "max_memory_entries must be a positive integer")
        self._store: LogStore = store if store is not None else MemoryStore(max_memory_entries)
        self._clock = clock
        self._alg = "sha256" if self._key is None else "hmac-sha256"
        self._on_event = on_event

    def _emit(self, payload: Mapping[str, str | int | bool]) -> None:
        if self._on_event is None:
            return
        try:
            self._on_event(payload)
        except Exception:
            logger.warning("on_event hook failed; the failure was ignored")

    def _timestamp(self) -> str:
        try:
            now = self._clock()
        except Exception as exc:
            raise AuditLogError("invalid_clock", "clock raised an error") from exc
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise AuditLogError("invalid_clock", "clock must return a timezone-aware datetime")
        try:
            utc = now.astimezone(timezone.utc)
        except (OverflowError, ValueError) as exc:
            raise AuditLogError("invalid_clock", "clock value is out of range") from exc
        return (
            f"{utc.year:04d}-{utc.month:02d}-{utc.day:02d}T"
            f"{utc.hour:02d}:{utc.minute:02d}:{utc.second:02d}.{utc.microsecond:06d}Z"
        )

    def _build(self, actor: str, action: str, data: Mapping[str, Any]) -> Entry:
        actor = validate_text("actor", actor)
        action = validate_text("action", action)
        clean = validate_data(data)
        stamp = self._timestamp()
        last = self._store.last()
        seq = 0 if last is None else last.seq + 1
        prev = GENESIS_HASH if last is None else last.hash
        fields: dict[str, Any] = {
            "v": FORMAT_VERSION,
            "alg": self._alg,
            "seq": seq,
            "ts": stamp,
            "actor": actor,
            "action": action,
            "data": clean,
            "prev": prev,
        }
        digest = compute_hash(fields, self._key)
        return Entry(
            v=FORMAT_VERSION,
            alg=self._alg,
            seq=seq,
            ts=stamp,
            actor=actor,
            action=action,
            data=clean,
            prev=prev,
            hash=digest,
        )

    def append(self, actor: str, action: str, data: Mapping[str, Any]) -> Entry:
        """Validate and append one entry and return it.

        Raises:
            AuditLogError: ``invalid_data``, ``invalid_clock``, ``store_full`` or (as
                :class:`CorruptLogError`) ``corrupt_log``. Nothing is appended on error.
        """
        try:
            entry = self._build(actor, action, data)
            self._store.append(entry)
        except AuditLogError as exc:
            self._emit({"event": "append_rejected", "code": exc.code})
            raise
        logger.debug("appended entry %d", entry.seq)
        self._emit({"event": "append", "seq": entry.seq, "alg": entry.alg})
        return entry

    def entries(self, start: int = 0) -> Iterator[Entry]:
        """Iterate entries from position ``start``.

        Raises:
            AuditLogError: ``invalid_data`` for a negative or non-integer ``start``.
            CorruptLogError: while iterating, when a stored record is corrupt.
        """
        if type(start) is not int or start < 0:
            raise AuditLogError("invalid_data", "start must be a non-negative integer")
        return self._iter_entries(start)

    def _iter_entries(self, start: int) -> Iterator[Entry]:
        for record in self._store.iter_records(start):
            if not isinstance(record, Entry):
                raise CorruptLogError("the log contains a corrupt record")
            yield record

    def head(self) -> Checkpoint | None:
        """Return a checkpoint of the last entry, or ``None`` for an empty log."""
        last = self._store.last()
        return None if last is None else Checkpoint(seq=last.seq, hash=last.hash)

    def _hash_ok(self, entry: Entry) -> bool:
        if entry.alg != self._alg or entry.v != FORMAT_VERSION or not isinstance(entry.hash, str):
            return False
        try:
            expected = compute_hash(entry.unsigned_fields(), self._key)
        except AuditLogError:
            return False
        return hmac.compare_digest(expected.encode("utf-8"), entry.hash.encode("utf-8"))

    def _walk(self, expected_head: Checkpoint | None) -> VerificationReport:
        position = 0
        prev = GENESIS_HASH
        anchor: str | None = None
        for record in self._store.iter_records(0):
            if not isinstance(record, Entry):
                return _fail("corrupt_line", position, position)
            if record.seq != position:
                return _fail("seq_gap", position, position)
            if record.prev != prev:
                return _fail("broken_link", position, position)
            if not self._hash_ok(record):
                return _fail("hash_mismatch", position, position)
            if expected_head is not None and record.seq == expected_head.seq:
                anchor = record.hash
            prev = record.hash
            position += 1
        if expected_head is not None and anchor != expected_head.hash:
            return _fail("head_mismatch", expected_head.seq, position)
        return VerificationReport(ok=True, checked=position, first_bad_seq=None, reason=None)

    def verify(self, expected_head: Checkpoint | None = None) -> VerificationReport:
        """Walk the log and report the first integrity problem.

        Per entry the checks run in this order: ``corrupt_line``, ``seq_gap``,
        ``broken_link``, ``hash_mismatch`` (which includes a different algorithm than the
        verifier's mode). Afterwards ``head_mismatch`` is reported when ``expected_head``
        is absent from the log or has a different hash; growth past it is fine.
        """
        report = self._walk(expected_head)
        payload: dict[str, str | int | bool] = {
            "event": "verify",
            "ok": report.ok,
            "checked": report.checked,
        }
        if report.first_bad_seq is not None and report.reason is not None:
            payload["first_bad_seq"] = report.first_bad_seq
            payload["reason"] = report.reason
        self._emit(payload)
        return report
