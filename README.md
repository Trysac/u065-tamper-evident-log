# tamper-evident-log

[![PyPI version](https://img.shields.io/pypi/v/trysac-tamper-evident-log)](https://pypi.org/project/trysac-tamper-evident-log/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-tamper-evident-log)](LICENSE)
[![CI](https://github.com/Trysac/u065-tamper-evident-log/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u065-tamper-evident-log/actions/workflows/ci.yml)

Append-only audit log chained by SHA-256 or HMAC-SHA256 over a restricted canonical JSON, with ordered integrity checks and checkpoint anchoring.

## Problem

Audit trails stored as plain rows or log lines can be edited or truncated without anyone noticing, which defeats their purpose in compliance reviews. A hash chain over canonical entries makes in-place edits, deletions and reordering detectable. A keyed HMAC makes forging entries detectable without the key, and an external checkpoint makes truncation detectable.

## Install

```sh
pip install trysac-tamper-evident-log
# or
uv add trysac-tamper-evident-log
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
import os
from datetime import datetime, timezone
from tamper_evident_log import AuditLog

log = AuditLog(clock=lambda: datetime.now(timezone.utc), key=os.urandom(32))
log.append("alice", "login", {"ok": True})
log.append("alice", "export", {"rows": 12})
checkpoint = log.head()  # keep this outside the log
print(log.verify(checkpoint))
```

## API summary

- `AuditLog(store=None, *, clock, key=None, max_memory_entries=100_000, on_event=None)`: `key` must be 32 to 4,096 bytes (`invalid_key` otherwise); `clock` must return a timezone-aware datetime (`invalid_clock` otherwise).
- `append(actor, action, data) -> Entry`: `actor` and `action` are 1 to 256 characters. `data` is a mapping of str keys, lists, strings, booleans, None and integers within plus or minus 2**53 - 1; floats are rejected. Depth is limited to 32 and the canonical encoding to 65,536 bytes (`invalid_data`). Nothing is appended on error.
- `entries(start=0) -> Iterator[Entry]`: raises `CorruptLogError` while iterating when a stored record is corrupt.
- `head() -> Checkpoint | None`: checkpoint of the last entry, or `None` for an empty log.
- `verify(expected_head=None) -> VerificationReport(ok, checked, first_bad_seq, reason)`: reasons are `corrupt_line`, `seq_gap`, `broken_link`, `hash_mismatch`, `head_mismatch`. It stops at the first problem.
- `Checkpoint(seq, hash)` with `to_json()` and `from_json()`; input is limited to 1,024 characters.
- `JsonlFileStore(path, *, max_line_bytes=1_048_576)`: one canonical entry per line, appended with `O_APPEND` and `fsync`. A torn or oversized tail is reported as corrupt; appending to a corrupt tail raises `CorruptLogError`.
- `MemoryStore` is used when `store` is None; it raises `store_full` beyond `max_memory_entries` and never evicts.
- Errors: `AuditLogError` with `code` in `invalid_data`, `invalid_key`, `invalid_clock`, `store_full`, `corrupt_log`; `CorruptLogError` is a subclass. Messages are at most 200 characters and never contain log data.
- `on_event` receives only event names, sequence numbers, counts, algorithm names and error codes.

The log has one writer; there is no locking.

## Threat model

Defended: in-place edits, deletion, reordering, keyed forgery, algorithm downgrade, truncation given an external checkpoint, and torn writes. Not defended: an attacker holding the key, truncation or full rewrite without an external checkpoint, rollback of log and checkpoint together, confidentiality, and concurrent writers. See [security](docs/SECURITY.md).

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
