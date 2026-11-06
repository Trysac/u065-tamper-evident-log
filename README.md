# tamper-evident-log

[![PyPI version](https://img.shields.io/pypi/v/trysac-tamper-evident-log)](https://pypi.org/project/trysac-tamper-evident-log/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-tamper-evident-log)](LICENSE)
[![CI](https://github.com/Trysac/u065-tamper-evident-log/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u065-tamper-evident-log/actions/workflows/ci.yml)

Append-only audit log chained by SHA-256 or HMAC-SHA256 over a restricted canonical JSON, with ordered integrity checks and checkpoint anchoring

## Problem

Describe in two or three sentences the concrete problem this utility solves, who hits it, and what
they do today without it. Replace this paragraph when the first real feature lands.

## Install

```sh
pip install trysac-tamper-evident-log
# or
uv add trysac-tamper-evident-log
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
import tamper_evident_log

# normalize() trims surrounding whitespace and lower-cases the text.
print(tamper_evident_log.normalize("  Hello World "))  # -> "hello world"

# Blank input is rejected explicitly instead of returning an empty string.
try:
    tamper_evident_log.normalize("   ")
except ValueError as exc:
    print(f"rejected: {exc}")
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
