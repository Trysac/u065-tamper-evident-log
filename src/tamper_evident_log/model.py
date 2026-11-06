"""Immutable data model of the audit log."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from .canonical import canonical_bytes, validate_data, validate_text
from .errors import AuditLogError

FORMAT_VERSION = 1
GENESIS_HASH = "0" * 64
ALGORITHMS = ("sha256", "hmac-sha256")
MAX_CHECKPOINT_CHARS = 1024

VerificationReason = Literal[
    "corrupt_line", "seq_gap", "broken_link", "hash_mismatch", "head_mismatch"
]

_HEX64 = re.compile(r"[0-9a-f]{64}")
_TS = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z")
_ENTRY_KEYS = frozenset({"v", "alg", "seq", "ts", "actor", "action", "data", "prev", "hash"})


@dataclass(frozen=True)
class Entry:
    """One log record. ``hash`` covers every other field, including ``v`` and ``alg``."""

    v: int
    alg: str
    seq: int
    ts: str
    actor: str
    action: str
    data: dict[str, Any]
    prev: str
    hash: str

    def unsigned_fields(self) -> dict[str, Any]:
        """Return the fields that are hashed (everything except ``hash``)."""
        return {
            "v": self.v,
            "alg": self.alg,
            "seq": self.seq,
            "ts": self.ts,
            "actor": self.actor,
            "action": self.action,
            "data": self.data,
            "prev": self.prev,
        }

    def to_dict(self) -> dict[str, Any]:
        """Return every field, including ``hash``."""
        fields = self.unsigned_fields()
        fields["hash"] = self.hash
        return fields


@dataclass(frozen=True)
class CorruptLine:
    """A stored record that could not be parsed into an :class:`Entry`."""

    line: int
    reason: str


@dataclass(frozen=True)
class VerificationReport:
    """Result of :meth:`AuditLog.verify`."""

    ok: bool
    checked: int
    first_bad_seq: int | None
    reason: VerificationReason | None


@dataclass(frozen=True)
class Checkpoint:
    """Commitment to the log prefix ending at ``seq`` with hash ``hash``."""

    seq: int
    hash: str

    def to_json(self) -> str:
        """Serialize the checkpoint to a compact JSON string."""
        return json.dumps(
            {"seq": self.seq, "hash": self.hash}, sort_keys=True, separators=(",", ":")
        )

    @classmethod
    def from_json(cls, text: str) -> Checkpoint:
        """Parse a checkpoint produced by :meth:`to_json`.

        Raises:
            AuditLogError: with code ``invalid_data`` for malformed or oversized input.
        """
        if not isinstance(text, str) or len(text) > MAX_CHECKPOINT_CHARS:
            raise AuditLogError("invalid_data", "checkpoint text is invalid or too long")
        try:
            obj = json.loads(text)
        except (ValueError, RecursionError) as exc:
            raise AuditLogError("invalid_data", "checkpoint is not valid JSON") from exc
        if not isinstance(obj, dict) or set(obj) != {"seq", "hash"}:
            raise AuditLogError("invalid_data", "checkpoint must have exactly seq and hash")
        seq = obj["seq"]
        digest = obj["hash"]
        if (
            type(seq) is not int
            or seq < 0
            or not isinstance(digest, str)
            or not _HEX64.fullmatch(digest)
        ):
            raise AuditLogError("invalid_data", "checkpoint fields are invalid")
        return cls(seq=seq, hash=digest)


def compute_hash(fields: Mapping[str, Any], key: bytes | None) -> str:
    """Return the lowercase hex digest of the canonical bytes of ``fields``.

    Uses SHA-256, or HMAC-SHA256 when ``key`` is given.
    """
    try:
        payload = canonical_bytes(fields)
    except (TypeError, ValueError, RecursionError) as exc:
        raise AuditLogError("invalid_data", "entry cannot be canonicalized") from exc
    if key is None:
        return hashlib.sha256(payload).hexdigest()
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def entry_from_obj(obj: object) -> Entry:
    """Build an :class:`Entry` from parsed JSON, raising ``ValueError`` when malformed."""
    if not isinstance(obj, dict) or set(obj) != _ENTRY_KEYS:
        raise ValueError("malformed entry")
    version = obj["v"]
    alg = obj["alg"]
    seq = obj["seq"]
    stamp = obj["ts"]
    prev = obj["prev"]
    digest = obj["hash"]
    if type(version) is not int or version != FORMAT_VERSION:
        raise ValueError("unsupported version")
    if not isinstance(alg, str) or alg not in ALGORITHMS:
        raise ValueError("unknown algorithm")
    if type(seq) is not int or seq < 0:
        raise ValueError("invalid seq")
    if not isinstance(stamp, str) or not _TS.fullmatch(stamp):
        raise ValueError("invalid timestamp")
    if not isinstance(prev, str) or not _HEX64.fullmatch(prev):
        raise ValueError("invalid prev")
    if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
        raise ValueError("invalid hash")
    try:
        actor = validate_text("actor", obj["actor"])
        action = validate_text("action", obj["action"])
        data = validate_data(obj["data"])
    except AuditLogError as exc:
        raise ValueError(exc.message) from exc
    return Entry(
        v=version,
        alg=alg,
        seq=seq,
        ts=stamp,
        actor=actor,
        action=action,
        data=data,
        prev=prev,
        hash=digest,
    )
