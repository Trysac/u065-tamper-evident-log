"""Typed errors for the tamper-evident log."""

from __future__ import annotations

from typing import Literal

ErrorCode = Literal["invalid_data", "invalid_key", "invalid_clock", "store_full", "corrupt_log"]

MAX_MESSAGE_CHARS = 200


class AuditLogError(Exception):
    """Base class of every error raised by this library.

    Attributes:
        code: stable machine-readable error code.
        message: human-readable text, at most 200 characters, never containing log data.
    """

    def __init__(self, code: ErrorCode, message: str) -> None:
        text = message[:MAX_MESSAGE_CHARS]
        super().__init__(text)
        self.code: ErrorCode = code
        self.message: str = text


class CorruptLogError(AuditLogError):
    """Raised when stored log data is corrupt and the operation cannot continue."""

    def __init__(self, message: str) -> None:
        super().__init__("corrupt_log", message)
