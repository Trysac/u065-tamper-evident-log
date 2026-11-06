"""Behavior tests for the public API of tamper_evident_log."""

from __future__ import annotations

import pytest

import tamper_evident_log


def test_normalize_trims_and_lowercases() -> None:
    assert tamper_evident_log.normalize("  Hello World ") == "hello world"


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_normalize_rejects_blank_input(value: str) -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        tamper_evident_log.normalize(value)


def test_version_is_semver() -> None:
    parts = tamper_evident_log.__version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)
