"""Append-only audit log chained by SHA-256 or HMAC-SHA256 over a restricted canonical JSON.

Threat model (see ``docs/SECURITY.md`` and ``docs/FORMAT.md``).

Defended: in-place edits, deletion, reordering, forgery without the key (keyed mode),
algorithm downgrade, truncation when an external :class:`Checkpoint` is verified, and torn
writes (reported as ``corrupt_line``; appending to a corrupt tail is refused).

Not defended: an attacker who holds the key; truncation or a full rewrite without an
external checkpoint; rollback of the log and the checkpoint together; confidentiality (data
is stored in clear text); concurrent writers (one writer per log, no locking).
"""

from __future__ import annotations

from .errors import AuditLogError, CorruptLogError
from .log import AuditLog
from .model import Checkpoint, CorruptLine, Entry, VerificationReport
from .store import JsonlFileStore, LogStore

__all__ = [
    "AuditLog",
    "AuditLogError",
    "Checkpoint",
    "CorruptLine",
    "CorruptLogError",
    "Entry",
    "JsonlFileStore",
    "LogStore",
    "VerificationReport",
    "__version__",
]

__version__ = "0.1.0"
