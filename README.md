# wal

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Zig](https://img.shields.io/badge/Zig-0.16.0+-orange.svg)](https://ziglang.org/)

A generic, payload-agnostic Write-Ahead Log (WAL) engine for Zig. Provides
crash-safe, CRC-verified, optionally-encrypted append-only record storage with
compaction support.

Extracted from the shared mechanics of two production WAL implementations:

- [Geode](https://gitlab.com/devnw/codepros/geode) — graph database delta persistence
- [Raft](https://gitlab.com/devnw/zig/raft) — consensus log entry persistence

## Features

- **Payload-agnostic** — stores opaque byte payloads; callers serialize their own domain types
- **CRC32 integrity** — every record is checksummed on write and verified on read
- **Crash recovery** — linear scan with torn write detection and automatic truncation
- **Atomic compaction** — rewrite-based compaction via temp file + fsync + rename
- **Optional AES-256-GCM encryption** — per-record encryption with random nonces
- **LSN ordering** — monotonically increasing log sequence numbers for watermark-based compaction
- **No required runtime dependencies** — core engine is pure Zig standard library; the thread-pool integration (parallel batch serialization) and OpenTelemetry observability are optional add-ons
- **Single-file simplicity** — no segment rotation; one file per WAL instance

## Installation

### Using Zig Package Manager

Add to your `build.zig.zon`:

```zig
.dependencies = .{
    .wal = .{
        .url = "https://gitlab.com/devnw/zig/wal/-/archive/v0.1.0/wal-v0.1.0.tar.gz",
        // Replace with actual hash — run: zig fetch <url>
        .hash = "1220...",
    },
},
```

Then in your `build.zig`:

```zig
const wal_dep = b.dependency("wal", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("wal", wal_dep.module("wal"));
```

## Quick Start

```zig
const std = @import("std");
const wal = @import("wal");

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // init takes a std.Io.Dir handle + filename (not a path string).
    const dir = std.Io.Dir.cwd();

    var log = try wal.WriteAheadLog.init(allocator, dir, "my-app.wal", .{});
    defer log.deinit();

    // Append records (payload is opaque bytes — serialize your own types)
    const lsn1 = try log.append("hello world");
    _ = try log.append("second entry");

    // Iterate records
    var iter = try log.iterator(0);
    defer iter.deinit();
    while (true) {
        var entry = try iter.next() orelse break;
        defer entry.deinit();
        std.debug.print("LSN={d} payload={s}\n", .{ entry.lsn, entry.payload });
    }

    // Compact (remove records with LSN <= lsn1)
    try log.compact(lsn1);
}
```

A complete, compile-checked version of this program lives in
[`examples/basic.zig`](examples/basic.zig) (built in CI via `zig build example`).

### With Encryption

```zig
var log = try wal.WriteAheadLog.init(allocator, dir, "secure.wal", .{
    .encryption_key = my_256_bit_key,
});
```

## Durability Configuration

By default every `append()` call syncs to disk immediately (`fdatasync`). This
is the safest option but limits throughput to one fsync per record.

```zig
// Sync every 100 appends (trade durability window for throughput)
var log = try wal.WriteAheadLog.init(allocator, dir, "my.wal", .{
    .sync_every_n = 100,
});

// Full manual control — caller decides when to sync
var log2 = try wal.WriteAheadLog.init(allocator, dir, "my.wal", .{
    .manual_sync = true,
});
// ... append many records ...
try log2.sync(); // explicit sync
```

`appendBatch()` respects `sync_every_n` and `manual_sync` the same way `append()` does — it accumulates the batch count and syncs only when the threshold is reached (SEC-0028).

## Crash Recovery

Recovery runs **automatically** during `init()` — no user action is needed.

- The WAL file is scanned forward from byte 0, validating each record's CRC
  (plaintext) or AES-GCM authentication tag (encrypted).
- LSN monotonicity is verified — a record with a non-increasing LSN is
  treated as corrupt.
- Encrypted and plaintext records are detected transparently via magic-byte
  probing.
- A torn tail — a bad record with no valid record after it — is truncated.
- Anything else fails closed and leaves the file untouched (SONNY-6620):

  | Error | Cause |
  |-------|-------|
  | `error.WalEncryptionMismatch` | Plaintext WAL opened with a key, encrypted WAL opened without one, or plaintext records inside an encrypted WAL |
  | `error.WalAuthFailed` | No record authenticates under the configured key (wrong key) |
  | `error.WalCorrupted` | A corrupt record has valid records after it |

  `Options.salvage_corrupt_records = true` opts into point-in-time recovery
  for `WalCorrupted`: the WAL opens up to the last valid record before the
  corrupt one and the rest is truncated. It needs at least one valid record
  before the corrupt one and never applies to the other two errors. The set
  is exported as `wal.RecoveryError`.

After `init()` returns, the WAL is guaranteed to contain only fully-written,
integrity-verified records.

### Recovery Checkpoint (PERF-0013)

Enable `Options.checkpoint = true` for O(1) startup on clean shutdown:

```zig
var wal = try WriteAheadLog.init(allocator, dir, "my.wal", .{
    .checkpoint = true,
});
```

On clean `deinit()`, a 28-byte `.ckpt` sidecar file is written atomically.
On the next `init()`:

- If the checkpoint matches the file size exactly: **O(1) skip** (no scan).
- If the file grew (records appended after checkpoint): **incremental scan** from the checkpoint position.
- If the checkpoint is missing, corrupt, or stale: **full scan** fallback.

The checkpoint is deleted automatically after compaction.

### Zero-Copy Compaction (PERF-0014)

Enable `Options.zero_copy_compaction = true` for kernel-level data transfer during compaction on Linux:

```zig
var wal = try WriteAheadLog.init(allocator, dir, "my.wal", .{
    .zero_copy_compaction = true,
});
```

Uses `copy_file_range(2)` to transfer data entirely in kernel space, avoiding
user-space buffer copies. Falls back automatically to the standard 256 KiB
buffer loop on non-Linux platforms or unsupported filesystem combinations.

## Key Management

All records are encrypted with the single key provided at `init()` time.
There is no built-in multi-key support.

**Key rotation procedure:**

1. Compact the WAL with the current key (rewrites all retained records).
2. Close the WAL (`deinit()`).
3. Re-open with the new key.

The encryption key is zeroized in memory on `deinit()`. Callers should also
zeroize their own copy of the key after passing it to `init()` (see
`encryption.secureZero`).

AES-256-GCM's security degrades after ~2^32 encryptions under the same key.
Rotate keys before reaching this limit in high-throughput systems.

## Design

See [docs/DESIGN.md](docs/DESIGN.md) for the full architecture, record format
specification, crash safety model, and implementation plan.

## Requirements

- Zig 0.16.0 or later

## Building

```bash
# Build the library
make build

# Run unit tests
make test

# Run integration tests
make test-integration

# Full CI pipeline
make ci
```

## Observability

wal ships an opt-in OpenTelemetry seam. Build with `-Dwith_otel=true`
to compile in instrumentation; the default (`-Dwith_otel=false`) leaves
every span site as a comptime no-op so the optimizer eliminates the
entry/exit calls and the `otel` dependency is never fetched.

Each public WAL operation emits exactly one span per call, named
`wal.{operation}` with the OpenTelemetry `db.*` semantic-convention
attributes:

- `db.system = "wal"`
- `db.operation = <method>` (e.g. `append`, `commit`, `replay`,
  `checkpoint`, `truncate`)
- `wal.bytes_written` (when applicable, e.g. on `append` / `append_batch`)
- `wal.replay.start_lsn` / `wal.replay.end_lsn` (on the outer `replay`
  scan only — individual record reads are not spanned)

The instrumented entry points are `append` / `appendWithLsn`,
`appendBatch` / `appendBatchWithLsns`, `sync` (the durable-write
boundary, mapped to `wal.commit`), `compact` (`wal.checkpoint`),
`truncateAfter` (`wal.truncate`), and the recovery scan inside `init`
(`wal.replay`).

```bash
zig build test                  # default: -Dwith_otel=false (no-op)
zig build test -Dwith_otel=true # otel compiled in, spans emitted
```

When enabled, the consumer's process bootstrap calls
`wal.observability_init.Otel.init(allocator, "service-name")` and
parks the returned value at a stable address (a `var` in `main` or a
heap allocation), then calls `installGlobals(&that_value)` so the
seam can publish its tracer pointer. Span emission is non-fatal:
every emit is `catch {}`-discarded so a failed exporter cannot
propagate into WAL operations.

For the full integration recipe and template files, see
`otel/docs/integration/RECIPE.md` in the otel repo.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

See [SECURITY.md](SECURITY.md) for security policy and vulnerability reporting.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
