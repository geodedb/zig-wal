// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! Compaction must not destroy records it cannot read (SONNY-6620).
//!
//! `compact` scanned the log for the first record above the watermark and
//! stopped at the first record it could not decode. When that happened before
//! any record above the watermark, it rewrote the WAL as empty, dropping every
//! valid record after the bad one. The plaintext scan also skipped CRCs, so it
//! carried corrupt records into the rewritten log. Recovery validates the log
//! only when it is opened; these scenarios damage it afterwards, while the WAL
//! is open, and require compaction to fail closed and leave the file intact.

const std = @import("std");
const wal = @import("wal");

const record = wal.record;
const encryption = wal.encryption;

const NAME = "wal";
const KEY: [32]u8 = [_]u8{0x6C} ** 32;
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

/// `compact` must fail with `expected` and leave the file byte-for-byte as it
/// was; the WAL must stay usable afterwards.
fn expectCompactFailsIntact(log: *wal.WriteAheadLog, dir: std.Io.Dir, up_to: u64, expected: anyerror) !void {
    const before = try readAll(dir);
    defer std.testing.allocator.free(before);

    try std.testing.expectError(expected, log.compact(up_to));

    const after = try readAll(dir);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
    try std.testing.expectEqual(@as(u64, PAYLOADS.len), log.currentLsn());
}

test "compaction safety: plaintext CRC damage above the watermark fails closed (SONNY-6620)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var log = try openWithRecords(tmp.dir, null);
    defer log.deinit();
    // Payload byte of record 3: header intact, CRC now wrong.
    try xorAt(tmp.dir, 2 * recSize(null) + record.HEADER_SIZE, 0xFF);

    try expectCompactFailsIntact(&log, tmp.dir, 2, error.WalCorrupted);
}

test "compaction safety: plaintext length damage above the watermark fails closed (SONNY-6620)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var log = try openWithRecords(tmp.dir, null);
    defer log.deinit();
    // High byte of record 3's payload_len: the scan cannot frame it.
    try xorAt(tmp.dir, 2 * recSize(null) + 11, 0xFF);

    try expectCompactFailsIntact(&log, tmp.dir, 2, error.WalCorrupted);
}

test "compaction safety: plaintext damage below the watermark fails closed (SONNY-6620)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var log = try openWithRecords(tmp.dir, null);
    defer log.deinit();
    try xorAt(tmp.dir, recSize(null) + 11, 0xFF);

    try expectCompactFailsIntact(&log, tmp.dir, 3, error.WalCorrupted);
}

test "compaction safety: encrypted damage above the watermark fails closed (SONNY-6620)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var log = try openWithRecords(tmp.dir, KEY);
    defer log.deinit();
    try xorAt(tmp.dir, 2 * recSize(KEY) + encryption.ENCRYPTION_OVERHEAD, 0xFF);

    try expectCompactFailsIntact(&log, tmp.dir, 2, error.WalCorrupted);
}

test "compaction safety: encrypted damage below the first kept record fails closed (SONNY-6620)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var log = try openWithRecords(tmp.dir, KEY);
    defer log.deinit();
    // Record 3 is below the watermark; records 5 and 6 are kept.
    try xorAt(tmp.dir, 2 * recSize(KEY) + encryption.ENCRYPTION_OVERHEAD, 0xFF);

    try expectCompactFailsIntact(&log, tmp.dir, 4, error.WalCorrupted);
}

test "compaction safety: damaged final record fails closed (SONNY-6620)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var log = try openWithRecords(tmp.dir, KEY);
    defer log.deinit();
    // The last record is above the watermark and must not be copied corrupt
    // or silently dropped.
    try xorAt(tmp.dir, 6 * recSize(KEY) - 1, 0xFF);

    try expectCompactFailsIntact(&log, tmp.dir, 2, error.WalCorrupted);
}

test "compaction safety: non-monotonic LSN mid-log fails closed (SONNY-6620)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var log = try openWithRecords(tmp.dir, null);
    defer log.deinit();
    // Rewrite record 4 as a CRC-valid record with LSN 2.
    {
        const f = try tmp.dir.openFile(io(), NAME, .{ .mode = .read_write });
        defer f.close(io());
        var stale: [record.MIN_RECORD_SIZE + 5]u8 = undefined;
        record.serializeInto(&stale, 2, "rec-4");
        try f.writePositionalAll(io(), &stale, 3 * recSize(null));
    }

    try expectCompactFailsIntact(&log, tmp.dir, 1, error.WalCorrupted);
}

test "compaction safety: plaintext record inside an encrypted WAL fails closed (SONNY-6620)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var log = try openWithRecords(tmp.dir, KEY);
    defer log.deinit();
    // Overwrite record 3 with a well-formed plaintext record of the same size
    // class; records 4..6 stay encrypted and valid.
    {
        const f = try tmp.dir.openFile(io(), NAME, .{ .mode = .read_write });
        defer f.close(io());
        var plain: [record.MIN_RECORD_SIZE + 5]u8 = undefined;
        record.serializeInto(&plain, 3, "rec-3");
        try f.writePositionalAll(io(), &plain, 2 * recSize(KEY));
    }

    try expectCompactFailsIntact(&log, tmp.dir, 2, error.WalEncryptionMismatch);
}

test "compaction safety: unreadable bytes after the last record fail closed (SONNY-6620)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var log = try openWithRecords(tmp.dir, null);
    defer log.deinit();
    {
        const f = try tmp.dir.openFile(io(), NAME, .{ .mode = .read_write });
        defer f.close(io());
        try f.writePositionalAll(io(), &[_]u8{0xEE} ** 9, 6 * recSize(null));
    }

    try expectCompactFailsIntact(&log, tmp.dir, 2, error.WalCorrupted);
}

test "compaction safety: refused compaction leaves the WAL appendable (SONNY-6620)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var log = try openWithRecords(tmp.dir, null);
    defer log.deinit();
    try xorAt(tmp.dir, 2 * recSize(null) + record.HEADER_SIZE, 0xFF);

    try std.testing.expectError(error.WalCorrupted, log.compact(2));
    try std.testing.expectEqual(@as(u64, 7), try log.append("rec-7"));
    const after = try readAll(tmp.dir);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqual(7 * recSize(null), after.len);
}

test "compaction safety: clean logs still compact, plaintext and encrypted (SONNY-6620)" {
    for ([_]?[32]u8{ null, KEY }) |key| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        {
            var log = try openWithRecords(tmp.dir, key);
            defer log.deinit();
            try log.compact(4);
            const after = try readAll(tmp.dir);
            defer std.testing.allocator.free(after);
            try std.testing.expectEqual(2 * recSize(key), after.len);
            try std.testing.expectEqual(@as(u64, 7), try log.append("rec-7"));
        }
        var log = try wal.WriteAheadLog.init(std.testing.allocator, tmp.dir, NAME, .{ .encryption_key = key });
        defer log.deinit();
        var it = try log.iterator(0);
        defer it.deinit();
        var lsn: u64 = 5;
        while (try it.next()) |*entry| : (lsn += 1) {
            var e = entry.*;
            defer e.deinit();
            try std.testing.expectEqual(lsn, e.lsn);
        }
        try std.testing.expectEqual(@as(u64, 8), lsn);
    }
}
