# Architecture

## Purpose

`trysac-tamper-evident-log` is a small, dependency-free Python library (import name `tamper_evident_log`) that implements an append-only audit log. Each entry is chained to the previous one by a SHA-256 or HMAC-SHA256 digest over a restricted canonical JSON form.

## Shape

```text
caller code --> tamper_evident_log (public API in __init__.py)
                    |
                    +-- log.py      AuditLog: append, entries, head, verify
                    +-- model.py    Entry, Checkpoint, VerificationReport, compute_hash
                    +-- canonical.py restricted canonical JSON and data validation
                    +-- store.py    LogStore protocol, MemoryStore, JsonlFileStore
                    +-- errors.py   AuditLogError and CorruptLogError
```

- **Public API**: the names listed in `__all__` of `src/tamper_evident_log/__init__.py`. Anything else is internal.
- **Errors**: invalid input raises `AuditLogError` with a stable `code`; corrupt stored data raises `CorruptLogError`.
- **Logging**: a module logger with a `NullHandler`; the library never configures logging.
- **Side effects**: only the store backends perform I/O. `JsonlFileStore` is the only backend that touches the file system.

## Quality contract

`scripts/check.py` is the single definition of the gates; `fabrica.json` tells the factory and CI how to run it. See [TESTING.md](TESTING.md).

## Decisions

Architecture decisions are recorded in [decisions/](decisions/) as numbered ADRs.
