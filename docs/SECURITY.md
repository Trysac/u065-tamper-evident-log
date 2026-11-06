# Security

## Threat model

`tamper-evident-log` makes modification of an audit trail **detectable**. It does not prevent modification and it is not a server.

### Defended

| Attack | Detection |
|---|---|
| In-place edit of an entry | `hash_mismatch`, or `broken_link` at the next entry when the hash is recomputed |
| Deletion of an entry | `seq_gap` |
| Reordering of entries | `seq_gap` |
| Forgery without the key (keyed mode) | `hash_mismatch`, because the HMAC cannot be recomputed |
| Algorithm downgrade (rewriting `alg` as `sha256`) | `hash_mismatch`, because the verifier's mode must match `alg` |
| Truncation, given an external checkpoint | `head_mismatch` |
| Torn writes | `corrupt_line`; appending to a corrupt tail raises `CorruptLogError` |

Digests are compared with `hmac.compare_digest`.

### Not defended

- An attacker who holds the key can forge a valid chain.
- Truncation or a full rewrite without an external checkpoint verifies as ok.
- Rollback of the log and the checkpoint together verifies as ok.
- Confidentiality: entries are stored in clear text; the hash only provides integrity.
- Concurrent writers: the library has no locking. Use one writer per log; racing writers can fork the chain, which verification reports as `seq_gap`.

Key rotation and Merkle proofs are out of scope.

## Operational guidance

- Store checkpoints (`Checkpoint.to_json()`) outside the log's trust domain and verify against them regularly.
- Keep the HMAC key in a secret manager, not in the repository or the log directory.
- `on_event` payloads contain only event names, sequence numbers, counts, algorithm names and error codes, never entry data. The library never configures logging and never logs data.

## Resource limits

| Input | Limit |
|---|---|
| `data` canonical bytes | 65,536 |
| `data` depth | 32 |
| `actor`, `action` | 1-256 characters |
| JSONL line | 1,048,576 bytes by default |
| Checkpoint text | 1,024 characters |
| Key | 32 to 4,096 bytes |
| In-memory store | `max_memory_entries` (default 100,000); `store_full` beyond it, never evicts |

Error messages never exceed 200 characters and never contain entry data.

## Reporting a vulnerability

See the repository's `SECURITY.md` for the disclosure process.
