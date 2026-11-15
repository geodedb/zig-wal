// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! `truncateAfter` must not drop records it is asked to keep (SONNY-6628).
//!
//! It scanned for the last record with LSN <= `after_lsn` and truncated where
//! the scan stopped. A damaged record before that point stopped the scan
//! early, so every valid record after it that should have been kept was
//! silently truncated away. These scenarios damage the file while the WAL is
//! open and require `truncateAfter` to fail closed, file untouched, whenever
//! the records it keeps cannot all be read.

const std = @import("std");
const wal = @import("wal");

const record = wal.record;
const encryption = wal.encryption;

const NAME = "wal";
const KEY: [32]u8 = [_]u8{0x7D} ** 32;
const PAYLOADS = [_][]const u8{ "rec-1", "rec-2", "rec-3", "rec-4", "rec-5", "rec-6" };

fn io() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

fn readAll(dir: std.Io.Dir) ![]u8 {
    return dir.readFileAlloc(io(), NAME, std.testing.allocator, .unlimited);
}

/// Size of one record holding a 5-byte payload ("rec-N").
fn recSize(key: ?[32]u8) u64 {
    const plain = record.MIN_RECORD_SIZE + "rec-1".len;
    return if (key != null) encryption.ENCRYPTION_OVERHEAD + plain else plain;
}

fn openWithRecords(dir: std.Io.Dir, key: ?[32]u8) !wal.WriteAheadLog {
    var log = try wal.WriteAheadLog.init(std.testing.allocator, dir, NAME, .{ .encryption_key = key });
    errdefer log.deinit();
    for (PAYLOADS) |p| _ = try log.append(p);
    return log;
}

/// Damage the on-disk bytes behind the open WAL's back.
fn xorAt(dir: std.Io.Dir, offset: u64, mask: u8) !void {
    const f = try dir.openFile(io(), NAME, .{ .mode = .read_write });
    defer f.close(io());
    var b: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try f.readPositionalAll(io(), &b, offset));
    b[0] ^= mask;
    try f.writePositionalAll(io(), &b, offset);
}

fn writeAt(dir: std.Io.Dir, offset: u64, bytes: []const u8) !void {
    const f = try dir.openFile(io(), NAME, .{ .mode = .read_write });
    defer f.close(io());
    try f.writePositionalAll(io(), bytes, offset);
}

/// `truncateAfter` must fail with `expected`, leave the file byte-for-byte as
/// it was, and leave the WAL's position and usability unchanged.
fn expectTruncateFailsIntact(log: *wal.WriteAheadLog, dir: std.Io.Dir, after: u64, expected: anyerror) !void {
    const before = try readAll(dir);
    defer std.testing.allocator.free(before);

    try std.testing.expectError(expected, log.truncateAfter(after));

    const after_bytes = try readAll(dir);
    defer std.testing.allocator.free(after_bytes);
    try std.testing.expectEqualSlices(u8, before, after_bytes);
    try std.testing.expectEqual(@as(u64, PAYLOADS.len), log.currentLsn());
}

/// Truncation succeeded: the file holds exactly records 1..`keep`, reopens to
/// them, and the WAL appends `keep + 1` next.
fn expectKept(log: *wal.WriteAheadLog, dir: std.Io.Dir, key: ?[32]u8, keep: u64) !void {
    try std.testing.expectEqual(keep, log.currentLsn());
    const bytes = try readAll(dir);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqual(keep * recSize(key), bytes.len);
    try std.testing.expectEqual(keep + 1, try log.append("next"));
}

// ============================================================================
// Damage inside the kept range: refuse
// ============================================================================

test "truncateAfter safety: plaintext damage before the cut fails closed (SONNY-6628)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var log = try openWithRecords(tmp.dir, null);
    defer log.deinit();
    // CRC damage in record 2; records 3 and 4 must be kept.
    try xorAt(tmp.dir, recSize(null) + record.HEADER_SIZE, 0xFF);

    try expectTruncateFailsIntact(&log, tmp.dir, 4, error.WalCorrupted);
}

test "truncateAfter safety: encrypted damage before the cut fails closed (SONNY-6628)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var log = try openWithRecords(tmp.dir, KEY);
    defer log.deinit();
    try xorAt(tmp.dir, recSize(KEY) + encryption.ENCRYPTION_OVERHEAD, 0xFF);

    try expectTruncateFailsIntact(&log, tmp.dir, 4, error.WalCorrupted);
}

test "truncateAfter safety: damage with a cut above every record fails closed (SONNY-6628)" {
    // A no-op truncation request must not turn mid-log damage into a cut.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var log = try openWithRecords(tmp.dir, null);
    defer log.deinit();
    try xorAt(tmp.dir, recSize(null) + 11, 0xFF);

    try expectTruncateFailsIntact(&log, tmp.dir, 100, error.WalCorrupted);
}

test "truncateAfter safety: damaged first record fails closed (SONNY-6628)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var log = try openWithRecords(tmp.dir, KEY);
    defer log.deinit();
    try xorAt(tmp.dir, encryption.ENCRYPTION_OVERHEAD, 0xFF);

    try expectTruncateFailsIntact(&log, tmp.dir, 3, error.WalCorrupted);
}

test "truncateAfter safety: non-monotonic LSN before the cut fails closed (SONNY-6628)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var log = try openWithRecords(tmp.dir, null);
    defer log.deinit();
    var stale: [record.MIN_RECORD_SIZE + 5]u8 = undefined;
    record.serializeInto(&stale, 1, "rec-3");
    try writeAt(tmp.dir, 2 * recSize(null), &stale);

    try expectTruncateFailsIntact(&log, tmp.dir, 5, error.WalCorrupted);
}

test "truncateAfter safety: plaintext record inside an encrypted WAL fails closed (SONNY-6628)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var log = try openWithRecords(tmp.dir, KEY);
    defer log.deinit();
    var plain: [record.MIN_RECORD_SIZE + 5]u8 = undefined;
    record.serializeInto(&plain, 2, "rec-2");
    try writeAt(tmp.dir, recSize(KEY), &plain);

    try expectTruncateFailsIntact(&log, tmp.dir, 4, error.WalEncryptionMismatch);
}

test "truncateAfter safety: refused truncation leaves the WAL appendable (SONNY-6628)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var log = try openWithRecords(tmp.dir, null);
    defer log.deinit();
    try xorAt(tmp.dir, recSize(null) + record.HEADER_SIZE, 0xFF);

    try std.testing.expectError(error.WalCorrupted, log.truncateAfter(4));
    try std.testing.expectEqual(@as(u64, 7), try log.append("rec-7"));
    const bytes = try readAll(tmp.dir);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqual(7 * recSize(null), bytes.len);
}

// ============================================================================
// Damage only in the removed range: allowed
// ============================================================================

test "truncateAfter safety: damage after the cut is removed with the tail (SONNY-6628)" {
    for ([_]?[32]u8{ null, KEY }) |key| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var log = try openWithRecords(tmp.dir, key);
        defer log.deinit();
        // Record 5 is damaged; record 4 is the first one above the cut.
        try xorAt(tmp.dir, 5 * recSize(key) - 1, 0xFF);

        try log.truncateAfter(3);
        try expectKept(&log, tmp.dir, key, 3);
    }
}

test "truncateAfter safety: damaged record right after the cut is removed (SONNY-6628)" {
    // Record 3 is the last kept one; record 4 follows it, so by LSN order its
    // LSN is above the cut even though it cannot be read.
    for ([_]?[32]u8{ null, KEY }) |key| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var log = try openWithRecords(tmp.dir, key);
        defer log.deinit();
        try xorAt(tmp.dir, 4 * recSize(key) - 1, 0xFF);

        try log.truncateAfter(3);
        try expectKept(&log, tmp.dir, key, 3);
    }
}

test "truncateAfter safety: torn tail is removed (SONNY-6628)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var log = try openWithRecords(tmp.dir, null);
    defer log.deinit();
    try writeAt(tmp.dir, 6 * recSize(null), &[_]u8{ 7, 0, 0, 0, 0 });

    try log.truncateAfter(100);
    try expectKept(&log, tmp.dir, null, 6);
}

test "truncateAfter safety: after_lsn 0 removes everything even if damaged (SONNY-6628)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var log = try openWithRecords(tmp.dir, KEY);
    defer log.deinit();
    try xorAt(tmp.dir, encryption.ENCRYPTION_OVERHEAD, 0xFF);

    try log.truncateAfter(0);
    try expectKept(&log, tmp.dir, KEY, 0);
}

test "truncateAfter safety: clean logs still truncate and reopen (SONNY-6628)" {
    for ([_]?[32]u8{ null, KEY }) |key| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        {
            var log = try openWithRecords(tmp.dir, key);
            defer log.deinit();
            try log.truncateAfter(4);
            try expectKept(&log, tmp.dir, key, 4);
        }
        var log = try wal.WriteAheadLog.init(std.testing.allocator, tmp.dir, NAME, .{ .encryption_key = key });
        defer log.deinit();
        try std.testing.expectEqual(@as(u64, 5), log.currentLsn());
    }
}
