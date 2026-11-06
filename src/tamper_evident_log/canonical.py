"""Restricted canonical JSON used as the hash input (not RFC 8785)."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from .errors import AuditLogError

MAX_DEPTH = 32
MAX_DATA_BYTES = 65_536
MAX_SAFE_INT = 2**53 - 1
MAX_TEXT_CHARS = 256


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    """Serialize ``value`` to its canonical UTF-8 bytes.

    Keys are sorted, separators are ``,`` and ``:``, non-ASCII text is kept as is and
    NaN or infinity are rejected by the encoder.
    """
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _bad(message: str) -> AuditLogError:
    return AuditLogError("invalid_data", message)


def _encodable(value: str) -> bool:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def validate_text(label: str, value: object) -> str:
    """Return ``value`` if it is a 1-256 character string without lone surrogates."""
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_TEXT_CHARS or not _encodable(value):
        raise _bad(f"{label} must be a string of 1-{MAX_TEXT_CHARS} characters")
    return value


def _check_str(value: str) -> None:
    if len(value) > MAX_DATA_BYTES or not _encodable(value):
        raise _bad("data strings must be valid Unicode within the size limit")


def _clean_mapping(value: Mapping[Any, Any], depth: int) -> dict[str, Any]:
    if depth > MAX_DEPTH:
        raise _bad(f"data nesting exceeds {MAX_DEPTH} levels")
    out: dict[str, Any] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise _bad("data keys must be strings")
        _check_str(key)
        out[key] = _clean(item, depth + 1)
    return out


def _clean(value: object, depth: int) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INT:
            raise _bad("integers must be within +/- (2**53 - 1)")
        return int(value)
    if isinstance(value, str):
        _check_str(value)
        return value
    if isinstance(value, Mapping):
        return _clean_mapping(value, depth)
    if isinstance(value, list):
        if depth > MAX_DEPTH:
            raise _bad(f"data nesting exceeds {MAX_DEPTH} levels")
        return [_clean(item, depth + 1) for item in value]
    raise _bad(f"unsupported data type {type(value).__name__}")


def validate_data(data: object) -> dict[str, Any]:
    """Validate ``data`` and return a deep, plain copy.

    Allowed values: dict with str keys, list, str, bool, None and int within
    +/- (2**53 - 1). Floats are rejected. Depth is limited to 32 (the top-level
    mapping is level 1) and the canonical encoding to 65,536 bytes.

    Raises:
        AuditLogError: with code ``invalid_data`` when a rule is violated.
    """
    if not isinstance(data, Mapping):
        raise _bad("data must be a mapping")
    clean = _clean_mapping(data, 1)
    if len(canonical_bytes(clean)) > MAX_DATA_BYTES:
        raise _bad(f"data exceeds {MAX_DATA_BYTES} canonical bytes")
    return clean
