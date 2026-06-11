// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! Crash and chaos scenario tests for caller-provided LSN methods
//! (`appendWithLsn` and `appendBatchWithLsns`).

const std = @import("std");

fn scenario_io() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

const wal = @import("wal");

// Internal/unstable modules used for crash scenario construction (QA-0053).
const record = wal.record;

// ============================================================================
// Crash Recovery Tests
// ============================================================================

test "crash: torn write after appendWithLsn recovers previous records" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Write 3 records with caller-provided LSNs 500, 501, 502.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
        defer log.deinit();
        _ = try log.appendWithLsn(500, "rec-500");
        _ = try log.appendWithLsn(501, "rec-501");
        _ = try log.appendWithLsn(502, "rec-502");
    }

    // Append 6 garbage bytes directly — simulates a torn header write.
    {
        const f = try tmp.dir.openFile(scenario_io(), "wal", .{ .mode = .read_write });
        defer f.close(scenario_io());
        const _end_pos_f = try f.length(scenario_io());
        const garbage = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE };
        try f.writePositionalAll(scenario_io(), &garbage, _end_pos_f);
    }

    // Reopen — recovery should truncate the garbage and restore LSNs 500-502.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
        defer log.deinit();

        try std.testing.expectEqual(@as(u64, 502), log.currentLsn());

        var iter = try log.iterator(0);
        defer iter.deinit();

        const expected_lsns = [_]u64{ 500, 501, 502 };
        const expected_payloads = [_][]const u8{ "rec-500", "rec-501", "rec-502" };

        for (expected_lsns, expected_payloads) |expected_lsn, expected_payload| {
            var maybe_entry = try iter.next();
            try std.testing.expect(maybe_entry != null);
            defer maybe_entry.?.deinit();
            try std.testing.expectEqual(expected_lsn, maybe_entry.?.lsn);
            try std.testing.expectEqualSlices(u8, expected_payload, maybe_entry.?.payload);
        }

        try std.testing.expect((try iter.next()) == null);
    }
}

test "crash: torn write mid-batch appendBatchWithLsns recovers before batch" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Write LSNs 100, 101, 102 individually.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
        defer log.deinit();
        _ = try log.appendWithLsn(100, "rec-100");
        _ = try log.appendWithLsn(101, "rec-101");
        _ = try log.appendWithLsn(102, "rec-102");
    }

    // Append a partial valid record header (incomplete payload) to simulate
    // a torn batch write.
    {
        const f = try tmp.dir.openFile(scenario_io(), "wal", .{ .mode = .read_write });
        defer f.close(scenario_io());
        const _end_pos_f = try f.length(scenario_io());
        // Fake header: LSN=103, payload_len=1000
        var hdr: [record.HEADER_SIZE]u8 = undefined;
        std.mem.writeInt(u64, hdr[0..8], 103, .little);
        std.mem.writeInt(u32, hdr[8..12], 1000, .little);
        try f.writePositionalAll(scenario_io(), &hdr, _end_pos_f);

        // Only 10 bytes of payload (instead of 1000).
        const partial = [_]u8{0xFF} ** 10;
        try f.writePositionalAll(scenario_io(), &partial, _end_pos_f + hdr.len);
    }

    // Reopen — should recover only LSNs 100-102.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
        defer log.deinit();

        try std.testing.expectEqual(@as(u64, 102), log.currentLsn());

        var iter = try log.iterator(0);
        defer iter.deinit();

        const expected_lsns = [_]u64{ 100, 101, 102 };
        const expected_payloads = [_][]const u8{ "rec-100", "rec-101", "rec-102" };

        for (expected_lsns, expected_payloads) |expected_lsn, expected_payload| {
            var maybe_entry = try iter.next();
            try std.testing.expect(maybe_entry != null);
            defer maybe_entry.?.deinit();
            try std.testing.expectEqual(expected_lsn, maybe_entry.?.lsn);
            try std.testing.expectEqualSlices(u8, expected_payload, maybe_entry.?.payload);
        }

        try std.testing.expect((try iter.next()) == null);
    }
}

test "crash: recovery with non-sequential LSNs after compaction" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Write LSNs 1000-1009, compact at 1004, then close.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
        defer log.deinit();

        var lsn: u64 = 1000;
        while (lsn <= 1009) : (lsn += 1) {
            var buf: [16]u8 = undefined;
            const payload = try std.fmt.bufPrint(&buf, "rec-{}", .{lsn});
            _ = try log.appendWithLsn(lsn, payload);
        }

        // Compact at 1004 — removes records 1000-1004.
        try log.compact(1004);
    }

    // Append garbage to the WAL file to simulate crash.
    {
        const f = try tmp.dir.openFile(scenario_io(), "wal", .{ .mode = .read_write });
        defer f.close(scenario_io());
        const _end_pos_f = try f.length(scenario_io());
        const garbage = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE };
        try f.writePositionalAll(scenario_io(), &garbage, _end_pos_f);
    }

    // Reopen — should recover LSNs 1005-1009.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
        defer log.deinit();

        try std.testing.expectEqual(@as(u64, 1009), log.currentLsn());

        var iter = try log.iterator(0);
        defer iter.deinit();

        var expected_lsn: u64 = 1005;
        while (try iter.next()) |entry| {
            var e = entry;
            defer e.deinit();
            try std.testing.expectEqual(expected_lsn, e.lsn);
            expected_lsn += 1;
        }
        try std.testing.expectEqual(@as(u64, 1010), expected_lsn);

        // Continue appending at 1010.
        const new_lsn = try log.appendWithLsn(1010, "after-crash");
        try std.testing.expectEqual(@as(u64, 1010), new_lsn);
    }
}

// ============================================================================
// Chaos / Stress Tests
// ============================================================================

test "chaos: rapid append-compact cycles with caller LSNs" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
    defer log.deinit();

    var current_lsn: u64 = 0;

    // 50 iterations: each appends 10 records, then compacts all but the last 3.
    var cycle: usize = 0;
    while (cycle < 50) : (cycle += 1) {
        // Append 10 records.
        var j: usize = 0;
        while (j < 10) : (j += 1) {
            current_lsn += 1;
            var buf: [32]u8 = undefined;
            const payload = try std.fmt.bufPrint(&buf, "cycle-{}-rec-{}", .{ cycle, j });
            _ = try log.appendWithLsn(current_lsn, payload);
        }

        // Compact all but last 3 records.
        const compact_at = current_lsn - 3;
        try log.compact(compact_at);
    }

    // After all cycles, verify the last 3 records have correct LSNs.
    try std.testing.expectEqual(current_lsn, log.currentLsn());

    {
        var iter = try log.iterator(0);
        defer iter.deinit();

        var expected_lsn = current_lsn - 2;
        while (try iter.next()) |entry| {
            var e = entry;
            defer e.deinit();
            try std.testing.expectEqual(expected_lsn, e.lsn);
            expected_lsn += 1;
        }
        try std.testing.expectEqual(current_lsn + 1, expected_lsn);
    }

    // Close and reopen, verify same.
    log.deinit();
    log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});

    try std.testing.expectEqual(current_lsn, log.currentLsn());

    {
        var iter = try log.iterator(0);
        defer iter.deinit();

        var expected_lsn = current_lsn - 2;
        while (try iter.next()) |entry| {
            var e = entry;
            defer e.deinit();
            try std.testing.expectEqual(expected_lsn, e.lsn);
            expected_lsn += 1;
        }
        try std.testing.expectEqual(current_lsn + 1, expected_lsn);
    }
}

test "chaos: large LSN gaps simulate Raft snapshot restore" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Write first record, then compact it away (empty WAL).
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
        defer log.deinit();

        _ = try log.appendWithLsn(1, "first");
        try log.compact(1);

        // Simulate Raft snapshot restore: jump to LSN 1_000_000.
        _ = try log.appendWithLsn(1_000_000, "after-million-snapshot");
        _ = try log.appendWithLsn(1_000_001, "second");
    }

    // Close and reopen.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
        defer log.deinit();

        try std.testing.expectEqual(@as(u64, 1_000_001), log.currentLsn());

        var iter = try log.iterator(0);
        defer iter.deinit();

        var e1 = try iter.next();
        try std.testing.expect(e1 != null);
        defer e1.?.deinit();
        try std.testing.expectEqual(@as(u64, 1_000_000), e1.?.lsn);
        try std.testing.expectEqualSlices(u8, "after-million-snapshot", e1.?.payload);

        var e2 = try iter.next();
        try std.testing.expect(e2 != null);
        defer e2.?.deinit();
        try std.testing.expectEqual(@as(u64, 1_000_001), e2.?.lsn);
        try std.testing.expectEqualSlices(u8, "second", e2.?.payload);

        try std.testing.expect((try iter.next()) == null);
    }
}

test "chaos: interleaved appendWithLsn and appendBatchWithLsns under compaction" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
    defer log.deinit();

    // Write LSNs 1-5 individually.
    var lsn: u64 = 1;
    while (lsn <= 5) : (lsn += 1) {
        var buf: [16]u8 = undefined;
        const payload = try std.fmt.bufPrint(&buf, "rec-{}", .{lsn});
        _ = try log.appendWithLsn(lsn, payload);
    }

    // Compact at 3 — removes records 1-3.
    try log.compact(3);

    // Write batch LSNs 6-10.
    {
        const lsns = [_]u64{ 6, 7, 8, 9, 10 };
        const payloads = [_][]const u8{ "rec-6", "rec-7", "rec-8", "rec-9", "rec-10" };
        _ = try log.appendBatchWithLsns(&lsns, &payloads);
    }

    // Compact at 7 — removes records 4-7.
    try log.compact(7);

    // Write LSN 11 individually.
    _ = try log.appendWithLsn(11, "rec-11");

    // Close and reopen.
    log.deinit();
    log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});

    // Should have records 8, 9, 10, 11.
    try std.testing.expectEqual(@as(u64, 11), log.currentLsn());

    var iter = try log.iterator(0);
    defer iter.deinit();

    const expected_lsns = [_]u64{ 8, 9, 10, 11 };
    const expected_payloads = [_][]const u8{ "rec-8", "rec-9", "rec-10", "rec-11" };

    for (expected_lsns, expected_payloads) |expected_lsn, expected_payload| {
        var maybe_entry = try iter.next();
        try std.testing.expect(maybe_entry != null);
        defer maybe_entry.?.deinit();
        try std.testing.expectEqual(expected_lsn, maybe_entry.?.lsn);
        try std.testing.expectEqualSlices(u8, expected_payload, maybe_entry.?.payload);
    }

    try std.testing.expect((try iter.next()) == null);
}

test "chaos: deterministic stress — 1000 records with random gaps, periodic compaction" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
    defer log.deinit();

    // Deterministic PRNG with seed=42.
    var prng = std.Random.DefaultPrng.init(42);
    const random = prng.random();

    // Track all LSNs written and what's still in the WAL.
    var all_lsns: [1000]u64 = undefined;
    var current_lsn: u64 = 0;
    var last_compact_idx: usize = 0; // index into all_lsns of last compaction point

    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        // Increment LSN by 1-10 randomly.
        const gap = @as(u64, random.intRangeAtMost(u8, 1, 10));
        current_lsn += gap;
        all_lsns[i] = current_lsn;

        var buf: [32]u8 = undefined;
        const payload = try std.fmt.bufPrint(&buf, "s-{}", .{current_lsn});
        _ = try log.appendWithLsn(current_lsn, payload);

        // Every 100 records, compact at the LSN that was 50 entries back.
        if ((i + 1) % 100 == 0 and i >= 50) {
            const compact_idx = i - 50;
            try log.compact(all_lsns[compact_idx]);
            last_compact_idx = compact_idx + 1; // records after this index survive
        }
    }

    try std.testing.expectEqual(current_lsn, log.currentLsn());

    // Close and reopen.
    log.deinit();
    log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});

    try std.testing.expectEqual(current_lsn, log.currentLsn());

    // Iterate and verify monotonically increasing LSNs that match expected.
    {
        var iter = try log.iterator(0);
        defer iter.deinit();

        var prev_lsn: u64 = 0;
        var count: usize = 0;
        var expected_idx: usize = last_compact_idx;

        while (try iter.next()) |entry| {
            var e = entry;
            defer e.deinit();

            // Monotonically increasing.
            try std.testing.expect(e.lsn > prev_lsn);
            prev_lsn = e.lsn;

            // Must match expected LSN sequence.
            try std.testing.expectEqual(all_lsns[expected_idx], e.lsn);
            expected_idx += 1;
            count += 1;
        }

        // Should have exactly (1000 - last_compact_idx) records.
        try std.testing.expectEqual(1000 - last_compact_idx, count);
    }
}
