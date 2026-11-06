# Log format

This document defines the entry format and the canonical form used for hashing. The
canonical form is a restricted JSON serialization. It is **not** RFC 8785 (JCS).

## Entry

| Field | Type | Rule |
|---|---|---|
| `v` | int | Format version, always `1`. |
| `alg` | string | `sha256` or `hmac-sha256`. |
| `seq` | int | Position in the log, starting at `0`. |
| `ts` | string | UTC, `YYYY-MM-DDTHH:MM:SS.ffffffZ`. |
| `actor` | string | 1-256 characters, no lone surrogates. |
| `action` | string | 1-256 characters, no lone surrogates. |
| `data` | object | See the data rules below. |
| `prev` | string | Hash of the previous entry; 64 zeros for `seq` 0. |
| `hash` | string | Lowercase hex digest, 64 characters. |

`hash` is SHA-256, or HMAC-SHA256 when the log has a key, over the canonical bytes of every
field except `hash`. `v` and `alg` are therefore covered by the hash.

## Canonical form

`json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
allow_nan=False)` encoded as UTF-8.

Golden vector, canonical bytes of the first entry of a log whose clock is
`2026-01-01T00:00:00Z`, with actor `alice`, action `login` and empty data (one line):

```
{"action":"login","actor":"alice","alg":"sha256","data":{},"prev":"<64 zeros>","seq":0,"ts":"2026-01-01T00:00:00.000000Z","v":1}
```

Its SHA-256 is `aa0be58630ea3d77f5cc55a59debd7092feb8bfef0195309dc1acac82f25fbb4`.

## Data rules

- Allowed values: object with string keys, array, string, boolean, null and integer within
  +/- (2**53 - 1). Floats are rejected, so there is no number formatting ambiguity.
- Nesting depth is at most 32; the top-level `data` object is level 1.
- The canonical encoding of `data` is at most 65,536 bytes.
- Lone surrogates are rejected in every string and key.
- `bool` is checked before `int`, so `True` stays a boolean.

Violations raise `AuditLogError` with code `invalid_data` and nothing is appended.

## JSONL file store

One canonical entry (including `hash`) per line, terminated by `\n`. A line longer than
`max_line_bytes` (default 1,048,576), a trailing line without newline, invalid UTF-8, duplicate
keys, non-finite numbers, floats and any entry that fails the field rules are reported as
corrupt lines.

## Verification order

For each entry: `corrupt_line`, `seq_gap`, `broken_link`, `hash_mismatch`. Verification stops at
the first problem and `first_bad_seq` is the expected position. With an expected checkpoint,
`head_mismatch` is reported afterwards when the entry at the checkpoint's `seq` is absent or
has a different hash. Growth past a checkpoint is accepted.
