# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test

```bash
zig build                # Build library
zig build test           # Unit tests (116 pass + 1 skip across 11 modules)
zig build test-integration  # Integration + scenario tests (39 tests)
zig build check          # Fast syntax check (no codegen, good for IDE)

make dev                 # Quick iteration: fmt + check + unit tests
make ci                  # Full CI: clean + build + all tests
make test-all-optimizations  # Unit tests at all optimization levels
```

Run tests at a specific optimization level:

```bash
zig build test -Doptimize=ReleaseSafe --summary all
```

## Architecture

**Single-file WAL with LSN-based ordering.** The WAL appends framed records to one file. No segment rotation — compaction rewrites the file atomically.

Data flow: `caller payload → record.serialize (frame+CRC) → [optional encryption.encrypt] → file write`

### Module dependency graph

```text
root.zig (public API re-exports)
  └── wal.zig (WriteAheadLog struct — orchestrator)
        ├── record.zig (serialize/deserialize, CRC32, verifyCrc, file I/O)
        ├── iterator.zig (forward Iterator over WAL records)
        ├── recovery.zig (forward scan, CRC validation, truncation, incremental recovery)
        ├── compaction.zig (bulk-copy above LSN watermark, zero-copy on Linux)
        ├── encryption.zig (AES-256-GCM per-record encrypt/decrypt, readEncryptedBlob)
        ├── checkpoint.zig (recovery checkpoint sidecar for O(1) startup)
        ├── atomic.zig (temp+fsync+rename file writes)
        ├── observability.zig (OpenTelemetry seam — comptime no-op when disabled)
        └── observability_init.zig (OTel bootstrap helper — compiled only with -Dwith_otel=true)
```

`wal.zig` is the only module that imports all others. Lower modules are independent of each other.

### API shape

`WriteAheadLog.init(allocator, dir, filename, options)` — takes a `std.fs.Dir` handle and filename string (not a path string). This is a common mistake in examples.

### Record format (plaintext)

```text
[lsn: u64 LE][payload_len: u32 LE][payload: N bytes][crc32: u32 LE]
```

Header: 12 bytes. CRC covers header+payload bytes. Minimum record: 16 bytes.

### Encrypted record format

```text
[blob_len: u32 LE]["ZIGWALE\0" magic][nonce: 12][tag: 16][ciphertext]
```

Overhead: 40 bytes. Detection: peek 12 bytes, check for magic at offset 4.

## Key Conventions

- `// SPDX-License-Identifier: Apache-2.0` + `// Copyright (c) 2024-2026 CodePros` on all source files
- Zig 0.16.0+ — uses unmanaged container APIs (allocator passed to every method) and the `std.Io` interfaces (`std.Io.File`, `std.Io.Dir`, `std.Io.RwLock`)
- CRC variant: `std.hash.crc.Crc32IsoHdlc`
- Crypto: `std.crypto.aead.aes_gcm.Aes256Gcm`
- Thread-safe: internal `std.Io.RwLock` (exclusive for writes, shared for reads)
- Optional `thread-pool` for parallel batch serialization (PAR-0002)
- No global/singleton state — everything is instance-based
- Unit tests colocated in source files; integration/scenario tests in `tests/`
- Temp files use `{filename}.tmp` pattern (not hardcoded names)

## Source Implementations

Unified from two production WALs:

- **Geode**: `~/src/gl/devnw/codepros/geode/geode/src/wal.zig`
- **Raft**: `~/src/gl/devnw/zig/raft/src/file_storage.zig`

See `docs/DESIGN.md` for detailed analysis of both sources and full specification.
