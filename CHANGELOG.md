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

## [0.1.26] - 2026-11-16

### Changed

- otel v0.1.28 -> v0.1.29, whose slog, json, config and yaml pins now carry
  thread-pool v0.2.11, so wal and its consumers resolve a single thread-pool
  (SONNY-6630).

## [0.1.25] - 2026-11-15

### Fixed

- `truncateAfter` no longer cuts away records it is asked to keep
  (SONNY-6628). It truncated wherever its validated scan stopped, so a
  damaged record before the last record with LSN <= `after_lsn` made it
  silently drop the valid records after the damage. Damage anywhere mid-log
  also turned a no-op request into a cut. It now cuts only at a proven
  boundary and otherwise fails closed, leaving the file and the WAL's state
  untouched, with the same errors as `init` and `compact`:
  `error.WalEncryptionMismatch`, `error.WalAuthFailed` or
  `error.WalCorrupted`. Damage lying entirely past the cut point, and a torn
  tail, are still removed.

### Changed

- `truncateAfter` can now return the three `wal.RecoveryError` errors.

## [0.1.24] - 2026-11-15

### Fixed

- Recovery no longer destroys data it cannot read (SONNY-6620).
  `WriteAheadLog.init` used to truncate the file at the end of the last
  record it could decode, so a key-mode mismatch or a wrong key wiped the
  whole WAL and a corrupt record mid-log silently dropped every valid record
  after it. `init` now classifies the stop point read-only and fails closed,
  leaving the file untouched, with `error.WalEncryptionMismatch`,
  `error.WalAuthFailed` or `error.WalCorrupted`. Only a genuine torn tail,
  with no valid record after the first bad one, is still truncated. The
  search for valid records past a bad one also finds records after
  caller-assigned LSN jumps.
- Compaction no longer destroys records it cannot read (SONNY-6620). Its scan
  stopped at the first undecodable record and, when no record above the
  watermark had been seen yet, rewrote the WAL as empty, dropping every valid
  record after the bad one. The plaintext scan also skipped CRCs (SEC-0027),
  carrying corrupt records into the new log. `compact` now validates every
  record with the recovery scan and, if any byte is not part of a valid
  record, fails closed with the same errors as `init` and leaves the file
  untouched.
- `init`, compaction's file reopen and `truncateAfter` ignored the result of
  the seek that positions the write cursor, and libc `lseek` cannot address
  a Windows handle. They now seek through `std.Io`; `init` returns the
  error, the other two poison the WAL.

### Added

- `Options.salvage_corrupt_records` (default `false`): opt-in point-in-time
  recovery that opens a `WalCorrupted` WAL up to the last valid record
  before the corrupt one. It needs a valid prefix and never applies to a
  key-mode mismatch or a wrong key.
- `wal.RecoveryError`, the error set above.

### Changed

- `init` and `compact` fail on inputs they used to accept by truncating or
  dropping them. `compact` also refuses a log with a torn tail; reopening the
  WAL truncates the tail. Callers that opened a plaintext WAL with a key
  to start an empty encrypted WAL now get `error.WalEncryptionMismatch`;
  move or delete the old file first.
- `init` tightens file permissions (SEC-0021) only after recovery accepts
  the file, so a refused open changes nothing on disk.
- thread-pool v0.2.11, aligning with geode.

## [0.1.19] - 2026-10-11

### Changed

- fips v0.1.3, otel v0.1.25 and thread-pool v0.2.8, so every package
  appears at one version in the graph.
- CI: create GitLab Releases with the job token. The gitleaks exception for
  the public OpenSSL signing-key fingerprints is scoped to the vendored
  installer (SONNY-4789), which turns security-gitleaks on main green again.

## [0.1.14] - 2026-09-12

### Changed

- Converge thread_pool v0.2.7, fips v0.1.1, protobuf v0.1.5, config v0.1.13 (GAP-0838 diamond sync).

## [0.1.13] - 2026-09-12

### Changed

- Converge thread_pool v0.2.7, fips v0.1.1, protobuf v0.1.5 (GAP-0838 diamond sync).
