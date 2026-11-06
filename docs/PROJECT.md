# Project record

## Objective

Provide a small Python library that makes modification, deletion, reordering, forgery and truncation of an audit trail detectable, using a hash chain over canonical entries, an optional HMAC key and external checkpoints.

## Scope

- In scope: append-only logging with SHA-256 or HMAC-SHA256 chaining; restricted canonical JSON for data; ordered verification with stable reason codes; checkpoint commitment and verification; an in-memory store with a hard cap and a JSONL file store with fsync and torn-write detection; typed errors with stable codes.
- Out of scope: Merkle proofs, key rotation, confidentiality (entries are stored in clear text), locking for concurrent writers, and any runtime dependency or I/O beyond the stores without an accepted ADR. Servers such as immudb and Trillian are not part of this library.

## Timeline

| Date | Event |
|---|---|
| 2026 | Repository created from the factory utility template. |

## Effort metrics

Measured values only; a value that has not been measured stays "pending measurement".

| Metric | Value |
|---|---|
| Tokens (input / output) | 465659 / 80296 |
| Hours (human) | pending measurement |
| Cost (USD) | 0.7227 |

## Factory run u065 (measured from API usage)

| Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|
| generation | claude-sonnet-5-5 | yes | 2590 | 65200 | 0 | 4246 | 0.3290 |
| fix-1 | claude-sonnet-5-5 | no | 8 | 1180 | 7334 | 55533 | 0.0357 |
| fix-2 | claude-sonnet-5-5 | no | 6 | 519 | 6356 | 40253 | 0.0251 |
| fix-3 | claude-sonnet-5-5 | no | 8 | 853 | 7076 | 56137 | 0.0318 |
| audit | claude-sonnet-5-5 | no | 12 | 6282 | 46637 | 150621 | 0.1945 |
| fix-4 | claude-sonnet-5-5 | no | 6 | 1322 | 7629 | 40714 | 0.0364 |
| docs | claude-haiku-5-5 | no | 115525 | 4940 | 0 | 0 | 0.0701 |

Total: $0.7227. Prices: Anthropic list prices.
