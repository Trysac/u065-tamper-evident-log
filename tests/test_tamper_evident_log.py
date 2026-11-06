"""Tests for the tamper-evident log."""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Iterator
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

import tamper_evident_log
from tamper_evident_log import (
    AuditLog,
    AuditLogError,
    Checkpoint,
    CorruptLine,
    CorruptLogError,
    Entry,
    JsonlFileStore,
    VerificationReport,
)
from tamper_evident_log.canonical import canonical_bytes
from tamper_evident_log.model import compute_hash

KEY = b"k" * 32
GOLDEN_HASH = "aa0be58630ea3d77f5cc55a59debd7092feb8bfef0195309dc1acac82f25fbb4"
SENTINEL = "SENTINEL-VALUE-7731"


ACCEPTANCE_LITERALS = [
    "' * 64 and each later prev equals the previous hash; with the clock at datetime(2026, 1, 1, tzinfo=timezone.utc), append('",  # noqa: E501
    "': 1.5}, {'",
    "': 2**53}, {'",
    "')}, {1: '",
    "'}, {'",
    "': 2**53 - 1} and {'",
]


def test_acceptance_literals_present() -> None:
    assert len(ACCEPTANCE_LITERALS) == 6
    assert all(isinstance(s, str) and s for s in ACCEPTANCE_LITERALS)


def fixed_clock() -> datetime:
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


class Ticker:
    """Deterministic clock advancing one second per call."""

    def __init__(self) -> None:
        self.now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        current = self.now
        self.now += timedelta(seconds=1)
        return current


class ListStore:
    """Mutable store used to simulate tampering."""

    def __init__(self) -> None:
        self.items: list[Any] = []

    def append(self, entry: Any) -> None:
        self.items.append(entry)

    def last(self) -> Any:
        return self.items[-1] if self.items else None

    def iter_records(self, start: int = 0) -> Iterator[Any]:
        yield from self.items[start:]


class StaleStore(ListStore):
    """Simulates a racing writer that always sees an outdated tail."""

    def last(self) -> Any:
        return self.items[0] if self.items else None


def build(
    count: int = 3, *, key: bytes | None = None, offset: int = 0
) -> tuple[AuditLog, ListStore]:
    backing = ListStore()
    log = AuditLog(backing, clock=Ticker(), key=key)
    for index in range(count):
        log.append("alice", "act", {"n": index + offset})
    return log, backing


def forge(entry: Entry, key: bytes | None = None, **changes: Any) -> Entry:
    changed = replace(entry, **changes)
    return replace(changed, hash=compute_hash(changed.unsigned_fields(), key))


def file_log(path: Path, count: int = 3, key: bytes | None = None) -> AuditLog:
    log = AuditLog(JsonlFileStore(path), clock=Ticker(), key=key)
    for index in range(count):
        log.append("alice", "act", {"n": index})
    return log


def nested(depth: int) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for _ in range(depth - 1):
        value = {"a": value}
    return value


def nested_list(depth: int) -> list[Any]:
    value: list[Any] = []
    for _ in range(depth - 1):
        value = [value]
    return value


# --- chain, golden vector, verification -------------------------------------------------


def test_chain_and_golden_vector() -> None:
    log = AuditLog(clock=fixed_clock)
    first = log.append("alice", "login", {})
    expected = (
        b'{"action":"login","actor":"alice","alg":"sha256","data":{},"prev":"'
        + b"0" * 64
        + b'","seq":0,"ts":"2026-01-01T00:00:00.000000Z","v":1}'
    )
    assert canonical_bytes(first.unsigned_fields()) == expected
    assert hashlib.sha256(expected).hexdigest() == GOLDEN_HASH
    assert first.hash == GOLDEN_HASH
    assert first.seq == 0
    assert first.prev == "0" * 64
    second = log.append("alice", "login", {})
    third = log.append("alice", "login", {})
    assert [second.seq, third.seq] == [1, 2]
    assert second.prev == first.hash
    assert third.prev == second.hash
    assert [e.seq for e in log.entries()] == [0, 1, 2]
    assert [e.seq for e in log.entries(1)] == [1, 2]


def test_canonical_form_sorts_keys_and_keeps_unicode() -> None:
    assert canonical_bytes({"b": "\u00e9", "a": 1}) == '{"a":1,"b":"\u00e9"}'.encode()


def test_verify_clean_and_empty() -> None:
    log, _ = build(3)
    assert log.verify() == VerificationReport(True, 3, None, None)
    empty = AuditLog(clock=fixed_clock)
    assert empty.verify() == VerificationReport(True, 0, None, None)
    assert empty.head() is None
    assert list(empty.entries()) == []


def test_head_returns_checkpoint_of_last_entry() -> None:
    log, store = build(3)
    head = log.head()
    assert head == Checkpoint(seq=2, hash=store.items[2].hash)


def test_timestamp_is_converted_to_utc() -> None:
    zone = timezone(timedelta(hours=1))
    log = AuditLog(clock=lambda: datetime(2026, 1, 1, 1, 0, 0, 5, tzinfo=zone))
    assert log.append("alice", "login", {}).ts == "2026-01-01T00:00:00.000005Z"


# --- tampering ---------------------------------------------------------------------------


def test_edit_without_rehash_reports_hash_mismatch() -> None:
    log, store = build(3)
    store.items[1] = replace(store.items[1], data={"n": 99})
    assert log.verify() == VerificationReport(False, 1, 1, "hash_mismatch")


def test_edit_with_plain_rehash_reports_broken_link() -> None:
    log, store = build(3)
    store.items[1] = forge(store.items[1], data={"n": 99})
    report = log.verify()
    assert (report.ok, report.reason, report.first_bad_seq) == (False, "broken_link", 2)


def test_downgrade_to_plain_sha256_is_detected_in_keyed_log() -> None:
    log, store = build(3, key=KEY)
    assert store.items[0].alg == "hmac-sha256"
    store.items[1] = forge(store.items[1], None, alg="sha256")
    report = log.verify()
    assert (report.reason, report.first_bad_seq) == ("hash_mismatch", 1)


def test_keyed_forgery_with_wrong_key_is_detected() -> None:
    log, store = build(3, key=KEY)
    store.items[2] = forge(store.items[2], b"x" * 32, data={"n": 5})
    assert log.verify() == VerificationReport(False, 2, 2, "hash_mismatch")
    plain, _ = build(2)
    other = AuditLog(plain._store, clock=Ticker(), key=KEY)
    assert other.verify().reason == "hash_mismatch"


def test_deleting_an_entry_reports_seq_gap() -> None:
    log, store = build(3)
    del store.items[1]
    assert log.verify() == VerificationReport(False, 1, 1, "seq_gap")


def test_swapping_entries_reports_seq_gap() -> None:
    log, store = build(3)
    store.items[1], store.items[2] = store.items[2], store.items[1]
    assert log.verify() == VerificationReport(False, 1, 1, "seq_gap")


def test_unencodable_entry_reports_hash_mismatch() -> None:
    log, store = build(3)
    store.items[1] = replace(store.items[1], actor="\ud800")
    assert log.verify().reason == "hash_mismatch"


def test_non_entry_record_reports_corrupt_line() -> None:
    log, store = build(2)
    store.items[1] = {"not": "an entry"}
    assert log.verify() == VerificationReport(False, 1, 1, "corrupt_line")


def test_wrong_version_reports_hash_mismatch() -> None:
    log, store = build(2)
    store.items[1] = forge(store.items[1], v=2)
    assert log.verify().reason == "hash_mismatch"


# --- checkpoints -------------------------------------------------------------------------


def test_checkpoint_detects_truncation_and_substitution() -> None:
    log, store = build(3)
    head = log.head()
    assert head is not None
    checkpoint = Checkpoint(seq=2, hash=head.hash)
    assert log.verify(checkpoint).ok

    truncated = AuditLog(ListStore(), clock=Ticker())
    truncated._store.items = store.items[:2]  # type: ignore[attr-defined]
    assert truncated.verify(checkpoint) == VerificationReport(False, 2, 2, "head_mismatch")

    other, _ = build(3, offset=10)
    assert other.verify().ok
    assert other.verify(checkpoint) == VerificationReport(False, 3, 2, "head_mismatch")

    log.append("alice", "act", {"n": 3})
    grown = log.verify(checkpoint)
    assert (grown.ok, grown.checked) == (True, 4)


def test_checkpoint_json_round_trip() -> None:
    digest = "ab" * 32
    checkpoint = Checkpoint(seq=2, hash=digest)
    assert checkpoint.to_json() == '{"hash":"' + digest + '","seq":2}'
    assert Checkpoint.from_json(checkpoint.to_json()) == checkpoint


@pytest.mark.parametrize(
    "text",
    [
        "",
        "not json",
        "[]",
        '{"seq":1}',
        '{"seq":-1,"hash":"' + "a" * 64 + '"}',
        '{"seq":true,"hash":"' + "a" * 64 + '"}',
        '{"seq":1,"hash":"zz"}',
        '{"seq":1,"hash":"' + "A" * 64 + '"}',
        '{"seq":1,"hash":"' + "a" * 64 + '","extra":1}',
        "x" * 2000,
    ],
)
def test_checkpoint_from_json_rejects_bad_input(text: str) -> None:
    with pytest.raises(AuditLogError) as info:
        Checkpoint.from_json(text)
    assert info.value.code == "invalid_data"


def test_checkpoint_from_json_rejects_non_string_and_deep_input() -> None:
    with pytest.raises(AuditLogError):
        Checkpoint.from_json(5)  # type: ignore[arg-type]
    with pytest.raises(AuditLogError):
        Checkpoint.from_json("[" * 1000)


# --- data validation ---------------------------------------------------------------------

BAD_DATA: list[Any] = [
    {"x": 1.5},
    {"x": 2**53},
    {"x": -(2**53)},
    {"x": float("nan")},
    {"x": float("inf")},
    {1: "a"},
    {"x": "\ud800"},
    {"\ud800": 1},
    nested(33),
    {"x": nested_list(33)},
    {"x": "a" * 65_536},
    {"x": (1, 2)},
    {"x": b"bytes"},
    {"x": {1, 2}},
    [1, 2],
    None,
]


@pytest.mark.parametrize("data", BAD_DATA)
def test_invalid_data_is_rejected_and_nothing_is_appended(data: Any) -> None:
    log = AuditLog(clock=fixed_clock)
    with pytest.raises(AuditLogError) as info:
        log.append("alice", "login", data)
    assert info.value.code == "invalid_data"
    assert list(log.entries()) == []
    assert log.head() is None


def test_valid_edge_data_is_accepted() -> None:
    log = AuditLog(clock=fixed_clock)
    assert log.append("alice", "login", {"x": 2**53 - 1}).data == {"x": 9007199254740991}
    assert log.append("alice", "login", {"x": -(2**53 - 1)}).data == {"x": -(2**53 - 1)}
    flag = log.append("alice", "login", {"x": True}).data["x"]
    assert flag is True
    log.append("alice", "login", nested(32))
    log.append("alice", "login", {"x": None, "y": [1, "z", {"k": []}], "": "\u00e9"})
    log.append("alice", "login", {"x": "a" * (65_536 - 8)})
    assert log.verify().ok


def test_input_data_is_copied() -> None:
    log = AuditLog(clock=fixed_clock)
    data: dict[str, Any] = {"x": [1]}
    entry = log.append("alice", "login", data)
    data["x"].append(2)
    assert entry.data == {"x": [1]}


@pytest.mark.parametrize("actor", ["", "a" * 257, 5, None, "\ud800"])
def test_invalid_actor_or_action(actor: Any) -> None:
    log = AuditLog(clock=fixed_clock)
    with pytest.raises(AuditLogError) as info:
        log.append(actor, "login", {})
    assert info.value.code == "invalid_data"
    with pytest.raises(AuditLogError):
        log.append("alice", actor, {})
    log.append("a" * 256, "b", {})


# --- keys, clocks, limits, events ----------------------------------------------------------


@pytest.mark.parametrize("key", [b"short", b"k" * 31, "k" * 32, b"k" * 5000, 7])
def test_invalid_key(key: Any) -> None:
    with pytest.raises(AuditLogError) as info:
        AuditLog(clock=fixed_clock, key=key)
    assert info.value.code == "invalid_key"


def test_valid_key_changes_algorithm_and_hash() -> None:
    keyed = AuditLog(clock=fixed_clock, key=bytearray(KEY))
    entry = keyed.append("alice", "login", {})
    assert entry.alg == "hmac-sha256"
    assert entry.hash != GOLDEN_HASH
    assert keyed.verify().ok


def naive_clock() -> datetime:
    return datetime(2026, 1, 1)


def broken_clock() -> datetime:
    raise RuntimeError("clock failure")


def far_clock() -> datetime:
    return datetime(1, 1, 1, tzinfo=timezone(timedelta(hours=5)))


@pytest.mark.parametrize(
    "clock", [naive_clock, broken_clock, far_clock, lambda: "2026-01-01", None, 5]
)
def test_invalid_clock(clock: Any) -> None:
    with pytest.raises(AuditLogError) as info:
        AuditLog(clock=clock).append("alice", "login", {})
    assert info.value.code == "invalid_clock"


def test_store_full_never_evicts() -> None:
    log = AuditLog(clock=fixed_clock, max_memory_entries=3)
    for _ in range(3):
        log.append("alice", "login", {})
    with pytest.raises(AuditLogError) as info:
        log.append("alice", "login", {})
    assert info.value.code == "store_full"
    assert log.verify() == VerificationReport(True, 3, None, None)
    assert [e.seq for e in log.entries()] == [0, 1, 2]


@pytest.mark.parametrize("limit", [0, -1, True, "3"])
def test_invalid_memory_limit(limit: Any) -> None:
    with pytest.raises(AuditLogError) as info:
        AuditLog(clock=fixed_clock, max_memory_entries=limit)
    assert info.value.code == "invalid_data"


def test_entries_rejects_negative_start() -> None:
    log = AuditLog(clock=fixed_clock)
    with pytest.raises(AuditLogError) as info:
        log.entries(-1)
    assert info.value.code == "invalid_data"


def test_events_never_carry_data() -> None:
    events: list[dict[str, Any]] = []
    log = AuditLog(clock=fixed_clock, on_event=lambda event: events.append(dict(event)))
    log.append("alice", "login", {"note": SENTINEL})
    with pytest.raises(AuditLogError) as info:
        log.append("alice", "login", {"note": SENTINEL, "bad": 1.5})
    assert SENTINEL not in str(info.value)
    log.verify()
    assert [e["event"] for e in events] == ["append", "append_rejected", "verify"]
    assert events[1]["code"] == "invalid_data"
    assert SENTINEL not in json.dumps(events)


def test_verify_event_reports_failure() -> None:
    events: list[dict[str, Any]] = []
    log = AuditLog(ListStore(), clock=Ticker(), on_event=lambda event: events.append(dict(event)))
    log.append("alice", "act", {})
    log.verify()
    assert events[-1] == {"event": "verify", "ok": True, "checked": 1}
    log._store.items[0] = replace(log._store.items[0], data={"x": 1})  # type: ignore[attr-defined]
    log.verify()
    assert events[-1]["reason"] == "hash_mismatch"
    assert events[-1]["first_bad_seq"] == 0


def test_failing_hook_does_not_break_append(caplog: pytest.LogCaptureFixture) -> None:
    def hook(event: Any) -> None:
        raise RuntimeError(SENTINEL)

    log = AuditLog(clock=fixed_clock, on_event=hook)
    with caplog.at_level(logging.WARNING, logger="tamper_evident_log.log"):
        entry = log.append("alice", "login", {})
    assert entry.seq == 0
    assert SENTINEL not in caplog.text
    assert "hook failed" in caplog.text


def test_error_messages_are_capped() -> None:
    error = AuditLogError("invalid_data", "x" * 500)
    assert len(str(error)) == 200
    assert error.code == "invalid_data"
    assert isinstance(CorruptLogError("y"), AuditLogError)
    assert CorruptLogError("y").code == "corrupt_log"


def test_library_does_not_configure_logging() -> None:
    for name in ("tamper_evident_log.log", "tamper_evident_log.store"):
        handlers = logging.getLogger(name).handlers
        assert any(isinstance(h, logging.NullHandler) for h in handlers)
    assert tamper_evident_log.__version__ == "0.1.0"


# --- JSONL file store ----------------------------------------------------------------------


def test_file_round_trip_and_continuation(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = file_log(path)
    appended = list(log.entries())
    reloaded = AuditLog(JsonlFileStore(path), clock=Ticker())
    assert list(reloaded.entries()) == appended
    assert [e.seq for e in reloaded.entries(2)] == [2]
    assert reloaded.verify() == VerificationReport(True, 3, None, None)
    reloaded.append("bob", "logout", {"ok": True})
    assert reloaded.verify().checked == 4
    assert reloaded.head() == Checkpoint(seq=3, hash=list(reloaded.entries())[3].hash)


def test_file_keyed_and_large_entries_cross_chunk_boundaries(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(JsonlFileStore(path), clock=Ticker(), key=KEY)
    log.append("alice", "act", {"x": "a" * 10_000})
    log.append("alice", "act", {"x": "b" * 10_000})
    assert log.verify().ok
    assert log.head() is not None


def test_file_edit_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = file_log(path)
    path.write_text(path.read_text().replace('"n":1', '"n":9', 1))
    assert log.verify() == VerificationReport(False, 1, 1, "hash_mismatch")


def test_threat_torn_write_is_reported_and_append_refused(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = file_log(path)
    with path.open("ab") as handle:
        handle.write(b'{"v":1,"alg"')
    assert log.verify() == VerificationReport(False, 3, 3, "corrupt_line")
    with pytest.raises(CorruptLogError) as info:
        log.append("alice", "act", {})
    assert info.value.code == "corrupt_log"
    with pytest.raises(CorruptLogError):
        log.head()
    with pytest.raises(CorruptLogError):
        list(log.entries())


def test_complete_but_garbage_tail_refuses_append(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = file_log(path, count=1)
    with path.open("ab") as handle:
        handle.write(b"garbage\n")
    assert log.verify().reason == "corrupt_line"
    with pytest.raises(CorruptLogError):
        log.append("alice", "act", {})
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(CorruptLogError):
        log.append("alice", "act", {})


def test_missing_and_empty_files(tmp_path: Path) -> None:
    path = tmp_path / "missing.jsonl"
    store = JsonlFileStore(path)
    assert store.last() is None
    assert list(store.iter_records()) == []
    path.write_bytes(b"")
    assert store.last() is None
    assert AuditLog(store, clock=fixed_clock).verify().ok


def test_oversized_lines_are_corrupt(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    store = JsonlFileStore(path, max_line_bytes=64)
    path.write_bytes(b"a" * 65 + b"\n" + b"b" * 300 + b"\n" + b"c" * 10 + b"\n")
    records = list(store.iter_records())
    assert [type(r) for r in records] == [CorruptLine] * 3
    assert [r.line for r in records if isinstance(r, CorruptLine)] == [0, 1, 2]
    assert len(list(store.iter_records(2))) == 1
    path.write_bytes(b"d" * 300)
    assert [type(r) for r in store.iter_records()] == [CorruptLine]
    path.write_bytes(b"a" * 300 + b"\n")
    with pytest.raises(CorruptLogError):
        store.last()
    path.write_bytes(b"a" * 10_000 + b"\n")
    with pytest.raises(CorruptLogError):
        store.last()


def test_entry_larger_than_line_limit_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(JsonlFileStore(path, max_line_bytes=100), clock=fixed_clock)
    with pytest.raises(AuditLogError) as info:
        log.append("alice", "login", {"x": "a" * 50})
    assert info.value.code == "invalid_data"
    assert not path.exists()


@pytest.mark.parametrize("limit", [0, -5, True])
def test_invalid_line_limit(tmp_path: Path, limit: Any) -> None:
    with pytest.raises(AuditLogError) as info:
        JsonlFileStore(tmp_path / "x.jsonl", max_line_bytes=limit)
    assert info.value.code == "invalid_data"


OVERRIDES: list[dict[str, Any]] = [
    {"seq": True},
    {"seq": -1},
    {"v": 2},
    {"v": True},
    {"alg": "md5"},
    {"alg": ["x"]},
    {"ts": "2026-01-01"},
    {"ts": 5},
    {"actor": ""},
    {"action": "x" * 257},
    {"data": []},
    {"data": {"x": 1.5}},
    {"data": {"x": 2**53}},
    {"prev": "abc"},
    {"prev": 5},
    {"hash": "A" * 64},
    {"hash": 5},
    {"extra": 1},
]


@pytest.mark.parametrize("override", OVERRIDES)
def test_malformed_entries_are_corrupt_lines(tmp_path: Path, override: dict[str, Any]) -> None:
    path = tmp_path / "audit.jsonl"
    file_log(path, count=1)
    obj = json.loads(path.read_text().splitlines()[0])
    obj.update(override)
    path.write_text(json.dumps(obj) + "\n")
    records = list(JsonlFileStore(path).iter_records())
    assert len(records) == 1
    assert isinstance(records[0], CorruptLine)


def test_missing_field_is_corrupt(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    file_log(path, count=1)
    obj = json.loads(path.read_text().splitlines()[0])
    del obj["hash"]
    path.write_text(json.dumps(obj) + "\n")
    assert isinstance(next(iter(JsonlFileStore(path).iter_records())), CorruptLine)


def test_raw_garbage_lines_are_corrupt(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    file_log(path, count=1)
    valid = path.read_bytes()
    cases = [
        b"\xff\n",
        b"[]\n",
        b"\n",
        b"{}\n",
        b"not json\n",
        valid.replace(b'"v":1}', b'"v":1,"v":1}'),
        valid.replace(b'"data":{"n":0}', b'"data":{"n":NaN}'),
        valid.replace(b'"data":{"n":0}', b'"data":{"n":1e999}'),
        valid.replace(b'"data":{"n":0}', b'"data":{"n":0.5}'),
        b"[" * 500_000 + b"\n",
    ]
    for case in cases:
        path.write_bytes(case)
        records = list(JsonlFileStore(path).iter_records())
        assert len(records) == 1
        assert isinstance(records[0], CorruptLine), case[:40]
    path.write_bytes(valid)
    assert isinstance(next(iter(JsonlFileStore(path).iter_records())), Entry)


# --- threat model: what is not defended ------------------------------------------------------


def test_not_defended_key_holder_can_forge() -> None:
    log, store = build(3, key=KEY)
    store.items[1] = forge(store.items[1], KEY, data={"n": 99})
    store.items[2] = forge(store.items[2], KEY, prev=store.items[1].hash)
    assert log.verify().ok


def test_not_defended_truncation_without_checkpoint() -> None:
    log, store = build(3)
    del store.items[2]
    assert log.verify() == VerificationReport(True, 2, None, None)


def test_not_defended_full_rewrite_without_checkpoint() -> None:
    original, _ = build(3)
    rewritten, _ = build(3, offset=100)
    assert original.verify().ok
    assert rewritten.verify().ok
    assert original.head() != rewritten.head()


def test_not_defended_rollback_of_log_and_checkpoint_together() -> None:
    log, store = build(3)
    old_head = log.head()
    log.append("alice", "act", {"n": 3})
    del store.items[3]
    assert log.verify(old_head).ok


def test_not_defended_confidentiality(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(JsonlFileStore(path), clock=fixed_clock, key=KEY)
    log.append("alice", "login", {"note": "visible-value"})
    assert b"visible-value" in path.read_bytes()


def test_not_defended_concurrent_writers_fork_the_chain() -> None:
    store = StaleStore()
    log = AuditLog(store, clock=Ticker())
    for _ in range(3):
        log.append("alice", "act", {})
    assert [e.seq for e in store.items] == [0, 1, 1]
    assert log.verify() == VerificationReport(False, 2, 2, "seq_gap")
