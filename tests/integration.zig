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

// ============================================================================
// appendWithLsn / appendBatchWithLsns Tests
// ============================================================================

test "lifecycle: appendWithLsn 100 records with Raft-style indices, close, reopen, verify" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Phase 1: simulate a Raft node that had a snapshot at index 499,
    // so new entries start at 500. Write 100 records with LSNs 500-599.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
        defer log.deinit();

        var i: u64 = 500;
        while (i <= 599) : (i += 1) {
            var payload_buf: [32]u8 = undefined;
            const payload = try std.fmt.bufPrint(&payload_buf, "entry-{}", .{i});
            const lsn = try log.appendWithLsn(i, payload);
            try std.testing.expectEqual(i, lsn);
        }

        try std.testing.expectEqual(@as(u64, 599), log.currentLsn());
    }

    // Phase 2: reopen, verify LSN, iterate and verify all 100 records.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
        defer log.deinit();

        try std.testing.expectEqual(@as(u64, 599), log.currentLsn());

        var iter = try log.iterator(0);
        defer iter.deinit();

        var expected_lsn: u64 = 500;
        while (try iter.next()) |entry| {
            var e = entry;
            defer e.deinit();

            try std.testing.expectEqual(expected_lsn, e.lsn);

            var payload_buf: [32]u8 = undefined;
            const expected_payload = try std.fmt.bufPrint(&payload_buf, "entry-{}", .{expected_lsn});
            try std.testing.expectEqualSlices(u8, expected_payload, e.payload);

            expected_lsn += 1;
        }

        try std.testing.expectEqual(@as(u64, 600), expected_lsn);
    }
}

test "lifecycle: appendWithLsn, compact at LSN, append more, verify continuity" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Phase 1: write entries 100-109, compact at 104, write 110-114, verify.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
        defer log.deinit();

        // Write entries 100-109.
        var i: u64 = 100;
        while (i <= 109) : (i += 1) {
            var payload_buf: [16]u8 = undefined;
            const payload = try std.fmt.bufPrint(&payload_buf, "e{}", .{i});
            _ = try log.appendWithLsn(i, payload);
        }

        // Compact at LSN 104 — removes entries 100-104.
        try log.compact(104);

        // Write entries 110-114.
        i = 110;
        while (i <= 114) : (i += 1) {
            var payload_buf: [16]u8 = undefined;
            const payload = try std.fmt.bufPrint(&payload_buf, "e{}", .{i});
            _ = try log.appendWithLsn(i, payload);
        }

        // Verify only entries 105-114 remain.
        var iter = try log.iterator(0);
        defer iter.deinit();

        var expected_lsn: u64 = 105;
        while (try iter.next()) |entry| {
            var e = entry;
            defer e.deinit();

            try std.testing.expectEqual(expected_lsn, e.lsn);

            var payload_buf: [16]u8 = undefined;
            const expected_payload = try std.fmt.bufPrint(&payload_buf, "e{}", .{expected_lsn});
            try std.testing.expectEqualSlices(u8, expected_payload, e.payload);

            expected_lsn += 1;
        }

        try std.testing.expectEqual(@as(u64, 115), expected_lsn);
    }

    // Phase 2: reopen, verify same state persists.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
        defer log.deinit();

        try std.testing.expectEqual(@as(u64, 114), log.currentLsn());

        var iter = try log.iterator(0);
        defer iter.deinit();

        var expected_lsn: u64 = 105;
        while (try iter.next()) |entry| {
            var e = entry;
            defer e.deinit();

            try std.testing.expectEqual(expected_lsn, e.lsn);

            var payload_buf: [16]u8 = undefined;
            const expected_payload = try std.fmt.bufPrint(&payload_buf, "e{}", .{expected_lsn});
            try std.testing.expectEqualSlices(u8, expected_payload, e.payload);

            expected_lsn += 1;
        }

        try std.testing.expectEqual(@as(u64, 115), expected_lsn);
    }
}

test "lifecycle: appendBatchWithLsns, close, reopen, verify" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Phase 1: write 3 batches of 10 entries with LSN ranges
    // 1000-1009, 1010-1019, 1020-1029.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
        defer log.deinit();

        // Batch 1: LSNs 1000-1009.
        var lsns1: [10]u64 = undefined;
        var payloads1: [10][]const u8 = undefined;
        var bufs1: [10][32]u8 = undefined;
        for (0..10) |j| {
            lsns1[j] = 1000 + @as(u64, @intCast(j));
            const payload = std.fmt.bufPrint(&bufs1[j], "batch1-{}", .{j}) catch unreachable;
            payloads1[j] = payload;
        }
        const last1 = try log.appendBatchWithLsns(&lsns1, &payloads1);
        try std.testing.expectEqual(@as(u64, 1009), last1);

        // Batch 2: LSNs 1010-1019.
        var lsns2: [10]u64 = undefined;
        var payloads2: [10][]const u8 = undefined;
        var bufs2: [10][32]u8 = undefined;
        for (0..10) |j| {
            lsns2[j] = 1010 + @as(u64, @intCast(j));
            const payload = std.fmt.bufPrint(&bufs2[j], "batch2-{}", .{j}) catch unreachable;
            payloads2[j] = payload;
        }
        const last2 = try log.appendBatchWithLsns(&lsns2, &payloads2);
        try std.testing.expectEqual(@as(u64, 1019), last2);

        // Batch 3: LSNs 1020-1029.
        var lsns3: [10]u64 = undefined;
        var payloads3: [10][]const u8 = undefined;
        var bufs3: [10][32]u8 = undefined;
        for (0..10) |j| {
            lsns3[j] = 1020 + @as(u64, @intCast(j));
            const payload = std.fmt.bufPrint(&bufs3[j], "batch3-{}", .{j}) catch unreachable;
            payloads3[j] = payload;
        }
        const last3 = try log.appendBatchWithLsns(&lsns3, &payloads3);
        try std.testing.expectEqual(@as(u64, 1029), last3);

        try std.testing.expectEqual(@as(u64, 1029), log.currentLsn());
    }

    // Phase 2: reopen and verify all 30 records.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
        defer log.deinit();

        try std.testing.expectEqual(@as(u64, 1029), log.currentLsn());

        var iter = try log.iterator(0);
        defer iter.deinit();

        var count: usize = 0;
        var prev_lsn: u64 = 999;
        while (try iter.next()) |entry| {
            var e = entry;
            defer e.deinit();

            try std.testing.expect(e.lsn > prev_lsn);
            try std.testing.expectEqual(@as(u64, 1000 + count), e.lsn);
            prev_lsn = e.lsn;
            count += 1;
        }

        try std.testing.expectEqual(@as(usize, 30), count);
    }
}

test "lifecycle: appendWithLsn large payload (128KB) with non-sequential LSN" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const payload_size = 128 * 1024;
    const large_payload = try allocator.alloc(u8, payload_size);
    defer allocator.free(large_payload);
    @memset(large_payload, 0xAB);

    // Write a 128KB payload at LSN 999999 and close.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
        defer log.deinit();
        const lsn = try log.appendWithLsn(999999, large_payload);
        try std.testing.expectEqual(@as(u64, 999999), lsn);
    }

    // Reopen and verify payload survives recovery at correct LSN.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
        defer log.deinit();

        try std.testing.expectEqual(@as(u64, 999999), log.currentLsn());

        var iter = try log.iterator(0);
        defer iter.deinit();

        var maybe_entry = try iter.next();
        try std.testing.expect(maybe_entry != null);
        defer maybe_entry.?.deinit();

        try std.testing.expectEqual(@as(u64, 999999), maybe_entry.?.lsn);
        try std.testing.expectEqual(payload_size, maybe_entry.?.payload.len);

        for (maybe_entry.?.payload) |byte| {
            try std.testing.expectEqual(@as(u8, 0xAB), byte);
        }

        const eof = try iter.next();
        try std.testing.expect(eof == null);
    }
}

test "lifecycle: appendWithLsn with manual_sync" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Phase 1: write 5 entries with manual_sync using appendWithLsn, sync, close.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{
            .manual_sync = true,
        });
        defer log.deinit();

        var i: u64 = 50;
        while (i <= 54) : (i += 1) {
            var payload_buf: [16]u8 = undefined;
            const payload = try std.fmt.bufPrint(&payload_buf, "ms-{}", .{i});
            _ = try log.appendWithLsn(i, payload);
        }

        try log.sync();
    }

    // Phase 2: reopen and verify all 5 entries survive.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{
            .manual_sync = true,
        });
        defer log.deinit();

        try std.testing.expectEqual(@as(u64, 54), log.currentLsn());

        var iter = try log.iterator(0);
        defer iter.deinit();

        var expected_lsn: u64 = 50;
        while (try iter.next()) |entry| {
            var e = entry;
            defer e.deinit();

            try std.testing.expectEqual(expected_lsn, e.lsn);

            var payload_buf: [16]u8 = undefined;
            const expected_payload = try std.fmt.bufPrint(&payload_buf, "ms-{}", .{expected_lsn});
            try std.testing.expectEqualSlices(u8, expected_payload, e.payload);

            expected_lsn += 1;
        }

        try std.testing.expectEqual(@as(u64, 55), expected_lsn);
    }
}

test "lifecycle: mixed append and appendWithLsn interleaving" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Phase 1: interleave append, appendWithLsn, appendBatch, appendBatchWithLsns.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
        defer log.deinit();

        // appendWithLsn(100, "a")
        const lsn1 = try log.appendWithLsn(100, "a");
        try std.testing.expectEqual(@as(u64, 100), lsn1);

        // append("b") -> should get LSN 101
        const lsn2 = try log.append("b");
        try std.testing.expectEqual(@as(u64, 101), lsn2);

        // appendWithLsn(200, "c") -> gap to 200
        const lsn3 = try log.appendWithLsn(200, "c");
        try std.testing.expectEqual(@as(u64, 200), lsn3);

        // append("d") -> should get LSN 201
        const lsn4 = try log.append("d");
        try std.testing.expectEqual(@as(u64, 201), lsn4);

        // appendBatch(["e","f"]) -> should get LSNs 202, 203
        const payloads_ef = [_][]const u8{ "e", "f" };
        const lsn5 = try log.appendBatch(&payloads_ef);
        try std.testing.expectEqual(@as(u64, 203), lsn5);

        // appendBatchWithLsns([300,301], ["g","h"]) -> gap to 300
        const batch_lsns = [_]u64{ 300, 301 };
        const batch_payloads = [_][]const u8{ "g", "h" };
        const lsn6 = try log.appendBatchWithLsns(&batch_lsns, &batch_payloads);
        try std.testing.expectEqual(@as(u64, 301), lsn6);

        try std.testing.expectEqual(@as(u64, 301), log.currentLsn());
    }

    // Phase 2: reopen, verify all 8 records with correct LSNs and payloads.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
        defer log.deinit();

        try std.testing.expectEqual(@as(u64, 301), log.currentLsn());

        var iter = try log.iterator(0);
        defer iter.deinit();

        const expected = [_]struct { lsn: u64, payload: []const u8 }{
            .{ .lsn = 100, .payload = "a" },
            .{ .lsn = 101, .payload = "b" },
            .{ .lsn = 200, .payload = "c" },
            .{ .lsn = 201, .payload = "d" },
            .{ .lsn = 202, .payload = "e" },
            .{ .lsn = 203, .payload = "f" },
            .{ .lsn = 300, .payload = "g" },
            .{ .lsn = 301, .payload = "h" },
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
}

test "lifecycle: appendWithLsn with checkpoint acceleration" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Phase 1: write 50 records with LSNs 1000-1049 using appendWithLsn,
    // checkpoint enabled. Close writes checkpoint.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{
            .checkpoint = true,
        });
        defer log.deinit();

        var i: u64 = 1000;
        while (i <= 1049) : (i += 1) {
            var payload_buf: [32]u8 = undefined;
            const payload = try std.fmt.bufPrint(&payload_buf, "ckpt-{}", .{i});
            _ = try log.appendWithLsn(i, payload);
        }

        try std.testing.expectEqual(@as(u64, 1049), log.currentLsn());
    }

    // Phase 2: reopen with checkpoint, verify, write one more, close again.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{
            .checkpoint = true,
        });
        defer log.deinit();

        try std.testing.expectEqual(@as(u64, 1049), log.currentLsn());

        // Write one more at LSN 1050.
        const lsn = try log.appendWithLsn(1050, "ckpt-1050");
        try std.testing.expectEqual(@as(u64, 1050), lsn);
    }

    // Phase 3: reopen again, verify all 51 records.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{
            .checkpoint = true,
        });
        defer log.deinit();

        try std.testing.expectEqual(@as(u64, 1050), log.currentLsn());

        var iter = try log.iterator(0);
        defer iter.deinit();

        var count: usize = 0;
        var expected_lsn: u64 = 1000;
        while (try iter.next()) |entry| {
            var e = entry;
            defer e.deinit();

            try std.testing.expectEqual(expected_lsn, e.lsn);

            var payload_buf: [32]u8 = undefined;
            const expected_payload = try std.fmt.bufPrint(&payload_buf, "ckpt-{}", .{expected_lsn});
            try std.testing.expectEqualSlices(u8, expected_payload, e.payload);

            expected_lsn += 1;
            count += 1;
        }

        try std.testing.expectEqual(@as(usize, 51), count);
    }
}
