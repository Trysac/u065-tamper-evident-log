# Hash chain over restricted canonical JSON with checkpoint anchoring

Status: accepted (generated, pending human review)

## Context

Audit trails kept as plain rows or log lines can be edited, reordered or truncated unnoticed. Existing tamper-evident logs such as immudb and Trillian are servers; a small embeddable library is needed. Full RFC 8785 canonicalization is complex, and float formatting differs between languages.

## Decision

Each entry commits to the previous entry through SHA-256, or HMAC-SHA256 when a key is supplied, over a restricted canonical JSON (sorted keys, compact separators, UTF-8, no floats, integers within +/- 2**53-1, depth 32, 65,536 bytes) that includes the format version and the algorithm. Verification checks each entry in a fixed order and stops at the first problem; an external checkpoint detects truncation. The in-memory store is capped and raises store_full instead of evicting. The JSONL store appends with O_APPEND and fsync and treats partial or oversized lines as corrupt. There is a single writer and no locking.

## Consequences

Edits, deletions, reordering, forgery without the key, algorithm downgrade and torn writes are detected, and truncation is detected with a checkpoint. Floats must be encoded by callers as strings or integers. The format is not interoperable with RFC 8785 tooling. An attacker with the key, or one who rewrites the log and the checkpoint together, is not stopped. Concurrent writers are unsupported. Key rotation and Merkle proofs are left out of scope.
