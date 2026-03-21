// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Compaction scenario tests: verify that repeated compact cycles, full
//! compaction, and the bytesSinceCompact counter all behave correctly.

const std = @import("std");
const wal = @import("wal");

// ============================================================================
// Compaction Tests
// ============================================================================

test "compaction: repeated compact cycles maintain correctness" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
    defer log.deinit();

    // Write records 1-10.
    var i: usize = 1;
    while (i <= 10) : (i += 1) {
        var buf: [8]u8 = undefined;
        const payload = try std.fmt.bufPrint(&buf, "rec-{}", .{i});
        _ = try log.append(payload);
    }

    // Compact at LSN 5 — removes records 1-5.
    try log.compact(5);
    try std.testing.expectEqual(@as(u64, 10), log.currentLsn());
    try std.testing.expectEqual(@as(u64, 0), log.bytesSinceCompact());

    // Write records 11-20.
    while (i <= 20) : (i += 1) {
        var buf: [8]u8 = undefined;
        const payload = try std.fmt.bufPrint(&buf, "rec-{}", .{i});
        _ = try log.append(payload);
    }

    // Compact at LSN 15 — removes records 6-15.
    try log.compact(15);
    try std.testing.expectEqual(@as(u64, 20), log.currentLsn());
    try std.testing.expectEqual(@as(u64, 0), log.bytesSinceCompact());

    // Iterate from 0 — should see only records 16-20.
    var iter = try log.iterator(0);
    defer iter.deinit();

    var expected_lsn: u64 = 16;
    while (try iter.next()) |entry| {
        var e = entry;
        defer e.deinit();
        try std.testing.expectEqual(expected_lsn, e.lsn);
        expected_lsn += 1;
    }
    try std.testing.expectEqual(@as(u64, 21), expected_lsn);
}

test "compaction: compact everything then append" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
    defer log.deinit();

    _ = try log.append("first");
    try std.testing.expectEqual(@as(u64, 1), log.currentLsn());

    // Compact the only record — file should be empty of records.
    try log.compact(1);
    try std.testing.expectEqual(@as(u64, 1), log.currentLsn());

    // Verify file is empty via iterator.
    {
        var iter = try log.iterator(0);
        defer iter.deinit();
        try std.testing.expect((try iter.next()) == null);
    }

    // Append a fresh record — should get LSN 2.
    const fresh_lsn = try log.append("second");
    try std.testing.expectEqual(@as(u64, 2), fresh_lsn);

    // Iterator should now return only the fresh record.
    var iter = try log.iterator(0);
    defer iter.deinit();

    var maybe_entry = try iter.next();
    try std.testing.expect(maybe_entry != null);
    defer maybe_entry.?.deinit();
    try std.testing.expectEqual(@as(u64, 2), maybe_entry.?.lsn);
    try std.testing.expectEqualSlices(u8, "second", maybe_entry.?.payload);

    try std.testing.expect((try iter.next()) == null);
}

test "compaction: bytesSinceCompact resets after compact" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
    defer log.deinit();

    // Initially zero.
    try std.testing.expectEqual(@as(u64, 0), log.bytesSinceCompact());

    _ = try log.append("hello");
    _ = try log.append("world");

    // Must be > 0 after writing.
    try std.testing.expect(log.bytesSinceCompact() > 0);

    // Compact keeping all records (compact at current LSN).
    try log.compact(log.currentLsn());

    // Must reset to 0.
    try std.testing.expectEqual(@as(u64, 0), log.bytesSinceCompact());
}
