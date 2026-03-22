// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Recovery checkpoint sidecar for O(1) WAL startup (PERF-0013).
//!
//! On clean shutdown the WAL writes a small `.ckpt` file recording the
//! recovery state (last LSN, valid end position, record count). On the
//! next `init()` the checkpoint is read and — if consistent with the WAL
//! file — used to skip the full O(N) recovery scan.
//!
//! ## On-disk format (28 bytes, little-endian)
//!
//! ```
//! [last_lsn: u64 LE][valid_end: u64 LE][record_count: u64 LE][crc32: u32 LE]
//! ```
//!
//! The CRC-32 (ISO-HDLC) covers the first 24 bytes. If the CRC does not
//! match, the checkpoint is treated as corrupt and the full scan runs.
//!
//! ## Safety invariants
//!
//! - The checkpoint is only written during clean `deinit()` — never mid-flight.
//! - On `init()`, three cases are handled:
//!   1. **Exact match** (`file_size == ckpt.valid_end`): clean shutdown, use
//!      checkpoint directly — O(1).
//!   2. **File grew** (`file_size > ckpt.valid_end`): records appended after
//!      the last checkpoint (or crash after writes). Incremental scan from
//!      `ckpt.valid_end` — O(delta).
//!   3. **File shrank or mismatch**: checkpoint is stale/corrupt — full scan.
//! - After compaction the checkpoint is deleted (file layout changed).

const std = @import("std");
const Crc32IsoHdlc = std.hash.crc.Crc32IsoHdlc;
const atomic = @import("atomic.zig");
const recovery_mod = @import("recovery.zig");

// ============================================================================
// Constants
// ============================================================================

/// Fixed size of the checkpoint file in bytes.
pub const CHECKPOINT_SIZE: usize = 28;

/// Suffix appended to the WAL filename to derive the checkpoint filename.
pub const CHECKPOINT_SUFFIX = ".ckpt";

// ============================================================================
// Types
// ============================================================================

/// Checkpoint data read from or written to the sidecar file.
pub const Checkpoint = struct {
    last_lsn: u64,
    valid_end: u64,
    record_count: u64,
};

// ============================================================================
// Public API
// ============================================================================

/// Write a checkpoint sidecar for `wal_filename` into `dir`.
///
/// The write is atomic (temp+fsync+rename via `atomicWriteFile`) so a crash
/// during the write will leave either the old checkpoint or no checkpoint —
/// never a partial one.
pub fn writeCheckpoint(
    dir: std.fs.Dir,
    wal_filename: []const u8,
    info: recovery_mod.RecoveryInfo,
) !void {
    var ckpt_name_buf: [atomic.TMP_NAME_BUF_SIZE]u8 = undefined;
    const ckpt_name = std.fmt.bufPrint(&ckpt_name_buf, "{s}" ++ CHECKPOINT_SUFFIX, .{wal_filename}) catch return error.FilenameTooLong;

    var buf: [CHECKPOINT_SIZE]u8 = undefined;
    std.mem.writeInt(u64, buf[0..8], info.last_lsn, .little);
    std.mem.writeInt(u64, buf[8..16], info.valid_end, .little);
    std.mem.writeInt(u64, buf[16..24], info.record_count, .little);
    const crc = Crc32IsoHdlc.hash(buf[0..24]);
    std.mem.writeInt(u32, buf[24..28], crc, .little);

    try atomic.atomicWriteFile(dir, ckpt_name, &buf);
}

/// Read and validate a checkpoint sidecar for `wal_filename` from `dir`.
///
/// Returns `null` if the file does not exist or is corrupt (wrong size, bad CRC).
pub fn readCheckpoint(dir: std.fs.Dir, wal_filename: []const u8) ?Checkpoint {
    var ckpt_name_buf: [atomic.TMP_NAME_BUF_SIZE]u8 = undefined;
    const ckpt_name = std.fmt.bufPrint(&ckpt_name_buf, "{s}" ++ CHECKPOINT_SUFFIX, .{wal_filename}) catch return null;

    const file = dir.openFile(ckpt_name, .{}) catch return null;
    defer file.close();

    var buf: [CHECKPOINT_SIZE]u8 = undefined;
    const n = file.readAll(&buf) catch return null;
    if (n < CHECKPOINT_SIZE) return null;

    // Validate CRC.
    const stored_crc = std.mem.readInt(u32, buf[24..28], .little);
    const computed_crc = Crc32IsoHdlc.hash(buf[0..24]);
    if (stored_crc != computed_crc) return null;

    return Checkpoint{
        .last_lsn = std.mem.readInt(u64, buf[0..8], .little),
        .valid_end = std.mem.readInt(u64, buf[8..16], .little),
        .record_count = std.mem.readInt(u64, buf[16..24], .little),
    };
}

/// Delete the checkpoint sidecar for `wal_filename` from `dir`.
///
/// Silently ignores errors (file not found, permissions, etc.).
pub fn deleteCheckpoint(dir: std.fs.Dir, wal_filename: []const u8) void {
    var ckpt_name_buf: [atomic.TMP_NAME_BUF_SIZE]u8 = undefined;
    const ckpt_name = std.fmt.bufPrint(&ckpt_name_buf, "{s}" ++ CHECKPOINT_SUFFIX, .{wal_filename}) catch return;
    dir.deleteFile(ckpt_name) catch {};
}

// ============================================================================
// Tests
// ============================================================================

test "writeCheckpoint + readCheckpoint round-trip" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const info = recovery_mod.RecoveryInfo{
        .last_lsn = 42,
        .valid_end = 1024,
        .record_count = 10,
    };

    try writeCheckpoint(tmp.dir, "wal.log", info);

    const ckpt = readCheckpoint(tmp.dir, "wal.log") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 42), ckpt.last_lsn);
    try std.testing.expectEqual(@as(u64, 1024), ckpt.valid_end);
    try std.testing.expectEqual(@as(u64, 10), ckpt.record_count);
}

test "readCheckpoint: missing file returns null" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const result = readCheckpoint(tmp.dir, "nonexistent.wal");
    try std.testing.expect(result == null);
}

test "readCheckpoint: corrupt CRC returns null" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Write a valid checkpoint, then corrupt a byte.
    const info = recovery_mod.RecoveryInfo{
        .last_lsn = 1,
        .valid_end = 100,
        .record_count = 5,
    };
    try writeCheckpoint(tmp.dir, "wal.log", info);

    // Corrupt the file.
    const file = try tmp.dir.openFile("wal.log.ckpt", .{ .mode = .read_write });
    defer file.close();
    try file.seekTo(0);
    try file.writeAll(&[_]u8{0xFF}); // corrupt first byte

    const result = readCheckpoint(tmp.dir, "wal.log");
    try std.testing.expect(result == null);
}

test "readCheckpoint: truncated file returns null" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Write only 10 bytes — less than CHECKPOINT_SIZE.
    const file = try tmp.dir.createFile("wal.log.ckpt", .{});
    defer file.close();
    try file.writeAll(&[_]u8{0} ** 10);

    const result = readCheckpoint(tmp.dir, "wal.log");
    try std.testing.expect(result == null);
}

test "deleteCheckpoint: removes file" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const info = recovery_mod.RecoveryInfo{
        .last_lsn = 1,
        .valid_end = 100,
        .record_count = 1,
    };
    try writeCheckpoint(tmp.dir, "wal.log", info);

    // Verify it exists.
    try std.testing.expect(readCheckpoint(tmp.dir, "wal.log") != null);

    deleteCheckpoint(tmp.dir, "wal.log");

    // Now it should be gone.
    try std.testing.expect(readCheckpoint(tmp.dir, "wal.log") == null);
}

test "deleteCheckpoint: missing file is a no-op" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Should not error.
    deleteCheckpoint(tmp.dir, "nonexistent.wal");
}
