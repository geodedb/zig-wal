// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Integration tests for the WAL library.
//!
//! These tests verify end-to-end functionality via the public API, exercising
//! the full stack from append through recovery and iteration.

const std = @import("std");
const wal = @import("wal");

// ============================================================================
// Lifecycle Tests
// ============================================================================

test "lifecycle: init, append 100 records, close, reopen, iterate, verify all" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Phase 1: write 100 records and close.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
        defer log.deinit();

        var i: usize = 1;
        while (i <= 100) : (i += 1) {
            var payload_buf: [16]u8 = undefined;
            const payload = try std.fmt.bufPrint(&payload_buf, "record-{}", .{i});
            const lsn = try log.append(payload);
            try std.testing.expectEqual(@as(u64, i), lsn);
        }

        try std.testing.expectEqual(@as(u64, 100), log.currentLsn());
    }

    // Phase 2: reopen, verify LSN, iterate and verify all 100 records.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
        defer log.deinit();

        try std.testing.expectEqual(@as(u64, 100), log.currentLsn());

        var iter = try log.iterator(0);
        defer iter.deinit();

        var expected_lsn: u64 = 1;
        while (try iter.next()) |entry| {
            var e = entry;
            defer e.deinit();

            try std.testing.expectEqual(expected_lsn, e.lsn);

            var payload_buf: [16]u8 = undefined;
            const expected_payload = try std.fmt.bufPrint(&payload_buf, "record-{}", .{expected_lsn});
            try std.testing.expectEqualSlices(u8, expected_payload, e.payload);

            expected_lsn += 1;
        }

        try std.testing.expectEqual(@as(u64, 101), expected_lsn);
    }
}

test "lifecycle: append, compact, append, verify ordering" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
    defer log.deinit();

    // Append a, b, c (LSNs 1, 2, 3).
    _ = try log.append("a");
    _ = try log.append("b");
    _ = try log.append("c");

    // Compact at LSN 2 — removes a and b.
    try log.compact(2);

    // Append d, e (LSNs 4, 5).
    _ = try log.append("d");
    _ = try log.append("e");

    // Iterate from beginning — expect LSN 3="c", 4="d", 5="e".
    var iter = try log.iterator(0);
    defer iter.deinit();

    const expected = [_]struct { lsn: u64, payload: []const u8 }{
        .{ .lsn = 3, .payload = "c" },
        .{ .lsn = 4, .payload = "d" },
        .{ .lsn = 5, .payload = "e" },
    };

    for (expected) |exp| {
        var maybe_entry = try iter.next();
        try std.testing.expect(maybe_entry != null);
        defer maybe_entry.?.deinit();
        try std.testing.expectEqual(exp.lsn, maybe_entry.?.lsn);
        try std.testing.expectEqualSlices(u8, exp.payload, maybe_entry.?.payload);
    }

    const eof = try iter.next();
    try std.testing.expect(eof == null);
}

test "lifecycle: multiple WAL instances in same process" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Create two independent WAL files in the same directory.
    var wal1 = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal1", .{});
    defer wal1.deinit();

    var wal2 = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal2", .{});
    defer wal2.deinit();

    // Append to wal1.
    const lsn1a = try wal1.append("wal1-record-1");
    const lsn1b = try wal1.append("wal1-record-2");

    // Append to wal2.
    const lsn2a = try wal2.append("wal2-record-1");
    const lsn2b = try wal2.append("wal2-record-2");
    const lsn2c = try wal2.append("wal2-record-3");

    // Verify independent LSN sequences.
    try std.testing.expectEqual(@as(u64, 1), lsn1a);
    try std.testing.expectEqual(@as(u64, 2), lsn1b);
    try std.testing.expectEqual(@as(u64, 2), wal1.currentLsn());

    try std.testing.expectEqual(@as(u64, 1), lsn2a);
    try std.testing.expectEqual(@as(u64, 2), lsn2b);
    try std.testing.expectEqual(@as(u64, 3), lsn2c);
    try std.testing.expectEqual(@as(u64, 3), wal2.currentLsn());

    // Verify wal1 contents.
    var iter1 = try wal1.iterator(0);
    defer iter1.deinit();

    var e1 = (try iter1.next()).?;
    defer e1.deinit();
    try std.testing.expectEqualSlices(u8, "wal1-record-1", e1.payload);

    var e2 = (try iter1.next()).?;
    defer e2.deinit();
    try std.testing.expectEqualSlices(u8, "wal1-record-2", e2.payload);

    try std.testing.expect((try iter1.next()) == null);

    // Verify wal2 has 3 records.
    var iter2 = try wal2.iterator(0);
    defer iter2.deinit();

    var count: usize = 0;
    while (try iter2.next()) |entry| {
        var e = entry;
        defer e.deinit();
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 3), count);
}

test "lifecycle: batch append" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
    defer log.deinit();

    const payloads = [_][]const u8{ "alpha", "beta", "gamma", "delta" };
    const last_lsn = try log.appendBatch(&payloads);

    try std.testing.expectEqual(@as(u64, 4), last_lsn);
    try std.testing.expectEqual(@as(u64, 4), log.currentLsn());
}

test "lifecycle: large payload (128KB)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const payload_size = 128 * 1024;
    const large_payload = try allocator.alloc(u8, payload_size);
    defer allocator.free(large_payload);
    @memset(large_payload, 0xBE);

    // Write and close.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
        defer log.deinit();
        _ = try log.append(large_payload);
    }

    // Reopen and verify.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
        defer log.deinit();

        var iter = try log.iterator(0);
        defer iter.deinit();

        var maybe_entry = try iter.next();
        try std.testing.expect(maybe_entry != null);
        defer maybe_entry.?.deinit();

        try std.testing.expectEqual(@as(u64, 1), maybe_entry.?.lsn);
        try std.testing.expectEqual(payload_size, maybe_entry.?.payload.len);

        for (maybe_entry.?.payload) |byte| {
            try std.testing.expectEqual(@as(u8, 0xBE), byte);
        }

        const eof = try iter.next();
        try std.testing.expect(eof == null);
    }
}

// ============================================================================
// Sync Tests (QA-0042)
// ============================================================================

test "lifecycle: manual_sync with explicit sync survives reopen" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Phase 1: write 3 records with manual_sync, call sync(), close.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{
            .manual_sync = true,
        });
        defer log.deinit();

        _ = try log.append("sync-record-1");
        _ = try log.append("sync-record-2");
        _ = try log.append("sync-record-3");

        try log.sync();
    }

    // Phase 2: reopen and verify all 3 records via iterator.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{
            .manual_sync = true,
        });
        defer log.deinit();

        try std.testing.expectEqual(@as(u64, 3), log.currentLsn());

        var iter = try log.iterator(0);
        defer iter.deinit();

        const expected_payloads = [_][]const u8{ "sync-record-1", "sync-record-2", "sync-record-3" };
        for (expected_payloads, 1..) |expected, lsn| {
            var maybe_entry = try iter.next();
            try std.testing.expect(maybe_entry != null);
            defer maybe_entry.?.deinit();
            try std.testing.expectEqual(@as(u64, lsn), maybe_entry.?.lsn);
            try std.testing.expectEqualSlices(u8, expected, maybe_entry.?.payload);
        }

        try std.testing.expect((try iter.next()) == null);
    }
}

// ============================================================================
// Batch Content Verification (QA-0043)
// ============================================================================

test "lifecycle: batch append verifies record contents" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
    defer log.deinit();

    const payloads = [_][]const u8{ "alpha", "beta", "gamma", "delta" };
    const last_lsn = try log.appendBatch(&payloads);

    try std.testing.expectEqual(@as(u64, 4), last_lsn);

    // Iterate and verify each payload matches in order.
    var iter = try log.iterator(0);
    defer iter.deinit();

    for (payloads, 1..) |expected, lsn| {
        var maybe_entry = try iter.next();
        try std.testing.expect(maybe_entry != null);
        defer maybe_entry.?.deinit();
        try std.testing.expectEqual(@as(u64, lsn), maybe_entry.?.lsn);
        try std.testing.expectEqualSlices(u8, expected, maybe_entry.?.payload);
    }

    try std.testing.expect((try iter.next()) == null);
}

// ============================================================================
// Iterator from_lsn Tests (QA-0047)
// ============================================================================

test "lifecycle: iterator from_lsn skips earlier records" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
    defer log.deinit();

    // Write 5 records with known payloads.
    _ = try log.append("first");
    _ = try log.append("second");
    _ = try log.append("third");
    _ = try log.append("fourth");
    _ = try log.append("fifth");

    try std.testing.expectEqual(@as(u64, 5), log.currentLsn());

    // Iterate from LSN 3 — should skip records 1, 2, 3 and return only 4, 5.
    var iter = try log.iterator(3);
    defer iter.deinit();

    var e1 = try iter.next();
    try std.testing.expect(e1 != null);
    defer e1.?.deinit();
    try std.testing.expectEqual(@as(u64, 4), e1.?.lsn);
    try std.testing.expectEqualSlices(u8, "fourth", e1.?.payload);

    var e2 = try iter.next();
    try std.testing.expect(e2 != null);
    defer e2.?.deinit();
    try std.testing.expectEqual(@as(u64, 5), e2.?.lsn);
    try std.testing.expectEqualSlices(u8, "fifth", e2.?.payload);

    // No more records.
    try std.testing.expect((try iter.next()) == null);
}
