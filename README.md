# wal

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Zig](https://img.shields.io/badge/Zig-0.15.1+-orange.svg)](https://ziglang.org/)

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
- **Zero dependencies** — pure Zig standard library only
- **Single-file simplicity** — no segment rotation; one file per WAL instance

## Installation

### Using Zig Package Manager

Add to your `build.zig.zon`:

```zig
.dependencies = .{
    .wal = .{
        .url = "https://gitlab.com/devnw/zig/wal/-/archive/v0.1.0/wal-v0.1.0.tar.gz",
        .hash = "...",
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
    const allocator = std.heap.page_allocator;

    // Open or create a WAL (takes a directory handle + filename)
    var dir = try std.fs.cwd().openDir("/tmp", .{});
    defer dir.close();

    var log = try wal.WriteAheadLog.init(allocator, dir, "my-app.wal", .{});
    defer log.deinit();

    // Append records (payload is opaque bytes — serialize your own types)
    const lsn1 = try log.append("hello world");
    _ = try log.append("second entry");

    // Iterate records
    var iter = try log.iterator(0);
    defer iter.deinit();
    while (try iter.next()) |*entry| {
        defer entry.deinit();
        std.debug.print("LSN={d} payload={s}\n", .{ entry.lsn, entry.payload });
    }

    // Compact (remove records with LSN <= lsn1)
    try log.compact(lsn1);
}
```

### With Encryption

```zig
var log = try wal.WriteAheadLog.init(allocator, dir, "secure.wal", .{
    .encryption_key = my_256_bit_key,
});
```

## Design

See [docs/DESIGN.md](docs/DESIGN.md) for the full architecture, record format
specification, crash safety model, and implementation plan.

## Requirements

- Zig 0.15.1 or later

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

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

See [SECURITY.md](SECURITY.md) for security policy and vulnerability reporting.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
