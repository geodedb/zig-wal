# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Core WAL library: append, iterate, compact, recover
- AES-256-GCM per-record encryption with AAD binding
- Atomic file writes (temp+fsync+rename)
- Unit and integration test suites
- Performance benchmarks
- CI/CD pipeline with multi-optimization-level testing
- Documentation and examples

[Unreleased]: https://gitlab.com/devnw/zig/wal/-/commits/main

## [0.1.15] - 2026-09-15

### Changed

- Converge grpc_zig v0.1.10 (GAP-0838 diamond sync).

## [0.1.14] - 2026-09-12

### Changed

- Converge thread_pool v0.2.7, fips v0.1.1, protobuf v0.1.5, config v0.1.13 (GAP-0838 diamond sync).

## [0.1.13] - 2026-09-12

### Changed

- Converge thread_pool v0.2.7, fips v0.1.1, protobuf v0.1.5 (GAP-0838 diamond sync).
