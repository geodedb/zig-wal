// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # wal
//!
//! A generic, payload-agnostic Write-Ahead Log engine for Zig.
//!
//! Provides durable, crash-safe, append-only storage for opaque byte payloads.
//! Each record is assigned a monotonically increasing LSN (Log Sequence Number).
//! Supports optional AES-256-GCM per-record encryption and atomic compaction.
//!
//! ## Quick Start
//!
//! ```zig
//! const wal = @import("wal");
//!
//! var log = try wal.WriteAheadLog.init(allocator, dir, "my.wal", .{});
//! defer log.deinit();
//!
//! const lsn = try log.append("hello, WAL!");
//! ```
//!
//! ## License
//!
//! Apache-2.0

pub const WriteAheadLog = @import("wal.zig").WriteAheadLog;
pub const Options = @import("wal.zig").Options;

/// Atomically write data to a file using temp+fsync+rename.
pub const atomicWriteFile = @import("atomic.zig").atomicWriteFile;

/// **Internal/unstable** — record serialization utilities.
///
/// These are implementation details exposed for benchmarks, fuzz tests, and
/// advanced tooling. They are NOT part of the stable public API and may change
/// without notice between versions. Downstream consumers should only depend
/// on `WriteAheadLog`, `Options`, and `atomicWriteFile` (QA-0053).
pub const record = @import("record.zig");

/// **Internal/unstable** — encryption utilities.
///
/// See `record` above — same stability caveat applies.
pub const encryption = @import("encryption.zig");

// Convenience re-exports of commonly needed format constants (QA-0053).
pub const RECORD_HEADER_SIZE = record.HEADER_SIZE;
pub const RECORD_CRC_SIZE = record.CRC_SIZE;
pub const ENCRYPTION_OVERHEAD = encryption.ENCRYPTION_OVERHEAD;

test {
    // Pull in all module tests
    _ = @import("record.zig");
    _ = @import("wal.zig");
    _ = @import("iterator.zig");
    _ = @import("recovery.zig");
    _ = @import("compaction.zig");
    _ = @import("encryption.zig");
    _ = @import("atomic.zig");
    _ = @import("checkpoint.zig");
}
