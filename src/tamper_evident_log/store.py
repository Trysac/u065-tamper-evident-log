"""Storage backends for the audit log."""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Iterator
from pathlib import Path
from typing import IO, Any, Protocol

from .canonical import canonical_bytes
from .errors import AuditLogError, CorruptLogError
from .model import CorruptLine, Entry, entry_from_obj

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

DEFAULT_MAX_LINE_BYTES = 1_048_576
_TAIL_CHUNK = 4096
_DRAIN_CHUNK = 65_536


class LogStore(Protocol):
    """Persistence contract of :class:`AuditLog`. A store holds one log with a single writer."""

    def append(self, entry: Entry) -> None:
        """Persist ``entry`` after the current last entry."""

    def last(self) -> Entry | None:
        """Return the last entry, or ``None`` when the store is empty."""

    def iter_records(self, start: int = 0) -> Iterator[Entry | CorruptLine]:
        """Yield records from position ``start``; unparseable ones as :class:`CorruptLine`."""


class MemoryStore:
    """Bounded in-memory store. It never evicts: eviction would break the chain."""

    def __init__(self, max_entries: int) -> None:
        self._max_entries = max_entries
        self._items: list[Entry] = []

    def append(self, entry: Entry) -> None:
        """Append ``entry`` or raise ``store_full`` when the cap is reached."""
        if len(self._items) >= self._max_entries:
            raise AuditLogError(
                "store_full", f"memory store is limited to {self._max_entries} entries"
            )
        self._items.append(entry)

    def last(self) -> Entry | None:
        """Return the last entry or ``None``."""
        return self._items[-1] if self._items else None

    def iter_records(self, start: int = 0) -> Iterator[Entry | CorruptLine]:
        """Yield entries from ``start``."""
        index = max(start, 0)
        while index < len(self._items):
            yield self._items[index]
            index += 1


def _reject_constant(name: str) -> Any:
    raise ValueError("non-finite number")


def _reject_float(text: str) -> Any:
    raise ValueError("floats are not allowed")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("duplicate key")
    return result


def _parse_line(raw: bytes, index: int) -> Entry | CorruptLine:
    try:
        obj = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_pairs,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
        return entry_from_obj(obj)
    except (ValueError, RecursionError):
        return CorruptLine(index, "malformed entry")


class JsonlFileStore:
    """JSON Lines file store: one canonical entry per line, single writer, no locking.

    Each append opens the file with ``O_APPEND``, writes the whole line and calls
    ``os.fsync`` before returning. Lines longer than ``max_line_bytes`` and a trailing
    line without newline (torn write) are reported as :class:`CorruptLine`.
    """

    def __init__(self, path: Path, *, max_line_bytes: int = DEFAULT_MAX_LINE_BYTES) -> None:
        if type(max_line_bytes) is not int or max_line_bytes < 1:
            raise AuditLogError("invalid_data", "max_line_bytes must be a positive integer")
        self._path = Path(path)
        self._max_line_bytes = max_line_bytes

    def _tail_line(self) -> bytes | None:
        if not self._path.exists():
            return None
        limit = self._max_line_bytes
        with self._path.open("rb") as handle:
            size = handle.seek(0, os.SEEK_END)
            if size == 0:
                return None
            handle.seek(size - 1)
            if handle.read(1) != b"\n":
                logger.warning("log tail is incomplete")
                raise CorruptLogError("the last log line is incomplete")
            buffer = b""
            position = size - 1
            while True:
                start = max(0, position - _TAIL_CHUNK)
                handle.seek(start)
                chunk = handle.read(position - start)
                newline = chunk.rfind(b"\n")
                if newline != -1:
                    buffer = chunk[newline + 1 :] + buffer
                    break
                buffer = chunk + buffer
                position = start
                if position == 0 or len(buffer) > limit:
                    break
        if len(buffer) > limit:
            raise CorruptLogError("the last log line exceeds the line limit")
        return buffer

    def last(self) -> Entry | None:
        """Return the last entry.

        Raises:
            CorruptLogError: when the tail of the file is incomplete, oversized or malformed.
        """
        raw = self._tail_line()
        if raw is None:
            return None
        record = _parse_line(raw, 0)
        if isinstance(record, CorruptLine):
            raise CorruptLogError("the last log line is malformed")
        return record

    def append(self, entry: Entry) -> None:
        """Append one line durably.

        Raises:
            CorruptLogError: when the current tail is corrupt.
            AuditLogError: with code ``invalid_data`` when the entry exceeds the line limit.
        """
        line = canonical_bytes(entry.to_dict()) + b"\n"
        if len(line) - 1 > self._max_line_bytes:
            raise AuditLogError("invalid_data", "entry exceeds the store line limit")
        self.last()
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0)
        descriptor = os.open(self._path, flags, 0o600)
        try:
            view = memoryview(line)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        logger.debug("appended a line of %d bytes", len(line))

    def _scan(self, handle: IO[bytes]) -> Iterator[bytes | None]:
        limit = self._max_line_bytes
        while True:
            raw = handle.readline(limit + 2)
            if not raw:
                return
            if raw.endswith(b"\n"):
                body = raw[:-1]
                yield body if len(body) <= limit else None
            elif len(raw) < limit + 2:
                yield None
                return
            else:
                yield None
                self._drain(handle)

    @staticmethod
    def _drain(handle: IO[bytes]) -> None:
        while True:
            chunk = handle.readline(_DRAIN_CHUNK)
            if not chunk or chunk.endswith(b"\n"):
                return

    def iter_records(self, start: int = 0) -> Iterator[Entry | CorruptLine]:
        """Yield records from line ``start``; bad lines become :class:`CorruptLine`."""
        if not self._path.exists():
            return
        with self._path.open("rb") as handle:
            for index, raw in enumerate(self._scan(handle)):
                if index < start:
                    continue
                if raw is None:
                    yield CorruptLine(index, "partial or oversized line")
                else:
                    yield _parse_line(raw, index)
