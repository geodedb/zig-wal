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
pub const record = @import("record.zig");
pub const encryption = @import("encryption.zig");

/// Atomically write data to a file using temp+fsync+rename.
pub const atomicWriteFile = @import("atomic.zig").atomicWriteFile;

test {
    // Pull in all module tests
    _ = @import("record.zig");
    _ = @import("wal.zig");
    _ = @import("recovery.zig");
    _ = @import("compaction.zig");
    _ = @import("encryption.zig");
    _ = @import("atomic.zig");
}
