// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Crash scenario tests: simulate torn writes and on-disk corruption, then
//! verify that `WriteAheadLog.init` recovers cleanly.

const std = @import("std");
const wal = @import("wal");

// ============================================================================
// Crash Tests
// ============================================================================

test "crash: torn write mid-header recovers previous records" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Write one good record and close cleanly.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
        defer log.deinit();
        _ = try log.append("record-1");
    }

    // Append 6 garbage bytes directly — simulates a torn header write.
    {
        const f = try tmp.dir.openFile("wal", .{ .mode = .read_write });
        defer f.close();
        try f.seekFromEnd(0);
        const garbage = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE };
        try f.writeAll(&garbage);
    }

    // Reopen — recovery should truncate the garbage and restore LSN 1.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
        defer log.deinit();

        try std.testing.expectEqual(@as(u64, 1), log.currentLsn());

        // Iterator should return exactly one record.
        var iter = try log.iterator(0);
        defer iter.deinit();

        var maybe_entry = try iter.next();
        try std.testing.expect(maybe_entry != null);
        defer maybe_entry.?.deinit();
        try std.testing.expectEqual(@as(u64, 1), maybe_entry.?.lsn);
        try std.testing.expectEqualSlices(u8, "record-1", maybe_entry.?.payload);

        try std.testing.expect((try iter.next()) == null);

        // New appends must still work.
        const new_lsn = try log.append("after-crash");
        try std.testing.expectEqual(@as(u64, 2), new_lsn);
    }
}

test "crash: torn write mid-payload recovers previous records" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Write one good record and close.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
        defer log.deinit();
        _ = try log.append("record-1");
    }

    // Write a valid-looking header claiming a 1000-byte payload, but only
    // supply 10 bytes of data — simulates a crash mid-payload.
    {
        const f = try tmp.dir.openFile("wal", .{ .mode = .read_write });
        defer f.close();
        try f.seekFromEnd(0);

        // Fake header: LSN=2, payload_len=1000
        var hdr: [wal.record.HEADER_SIZE]u8 = undefined;
        std.mem.writeInt(u64, hdr[0..8], 2, .little);
        std.mem.writeInt(u32, hdr[8..12], 1000, .little);
        try f.writeAll(&hdr);

        // Only 10 bytes of payload (instead of 1000).
        const partial = [_]u8{0xFF} ** 10;
        try f.writeAll(&partial);
    }

    // Reopen — should recover only record 1.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
        defer log.deinit();

        try std.testing.expectEqual(@as(u64, 1), log.currentLsn());

        var iter = try log.iterator(0);
        defer iter.deinit();

        var maybe_entry = try iter.next();
        try std.testing.expect(maybe_entry != null);
        defer maybe_entry.?.deinit();
        try std.testing.expectEqual(@as(u64, 1), maybe_entry.?.lsn);

        try std.testing.expect((try iter.next()) == null);
    }
}

test "crash: completely empty file after creation" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
    defer log.deinit();

    try std.testing.expectEqual(@as(u64, 0), log.currentLsn());

    var iter = try log.iterator(0);
    defer iter.deinit();

    try std.testing.expect((try iter.next()) == null);
}

test "crash: corrupt CRC in middle of file, records after corruption lost" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Write 3 records.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
        defer log.deinit();
        _ = try log.append("alpha");
        _ = try log.append("beta");
        _ = try log.append("gamma");
    }

    // Corrupt a payload byte in record 2.
    // Record 1 layout: HEADER(12) + "alpha"(5) + CRC(4) = 21 bytes.
    // Record 2 starts at offset 21.  Payload starts at offset 21+12 = 33.
    // Flip the first payload byte of record 2.
    {
        const f = try tmp.dir.openFile("wal", .{ .mode = .read_write });
        defer f.close();

        const record2_payload_offset: u64 = (wal.record.HEADER_SIZE + "alpha".len + wal.record.CRC_SIZE) +
            wal.record.HEADER_SIZE;
        try f.seekTo(record2_payload_offset);
        var byte: [1]u8 = undefined;
        _ = try f.readAll(&byte);
        byte[0] ^= 0xFF;
        try f.seekTo(record2_payload_offset);
        try f.writeAll(&byte);
    }

    // Reopen — recovery stops at the corrupt record; only record 1 survives.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
        defer log.deinit();

        try std.testing.expectEqual(@as(u64, 1), log.currentLsn());

        var iter = try log.iterator(0);
        defer iter.deinit();

        var maybe_entry = try iter.next();
        try std.testing.expect(maybe_entry != null);
        defer maybe_entry.?.deinit();
        try std.testing.expectEqual(@as(u64, 1), maybe_entry.?.lsn);
        try std.testing.expectEqualSlices(u8, "alpha", maybe_entry.?.payload);

        try std.testing.expect((try iter.next()) == null);
    }
}
