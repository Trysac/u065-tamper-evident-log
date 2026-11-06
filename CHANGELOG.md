# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add `AuditLog`, an append-only audit log chained by SHA-256 or HMAC-SHA256 over a restricted canonical JSON, with an in-memory store, a JSONL file store, ordered verification and checkpoint anchoring.
- Initial project structure from the factory utility template.
