// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! Crash scenario tests: simulate torn writes and on-disk corruption, then
//! verify that `WriteAheadLog.init` recovers cleanly.

const std = @import("std");

fn scenario_io() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

const wal = @import("wal");

// Internal/unstable modules used for crash scenario construction (QA-0053).
const record = wal.record;
const encryption = wal.encryption;

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
        const f = try tmp.dir.openFile(scenario_io(), "wal", .{ .mode = .read_write });
        defer f.close(scenario_io());
        const _end_pos_f = try f.length(scenario_io());
        const garbage = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE };
        try f.writePositionalAll(scenario_io(), &garbage, _end_pos_f);
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
        const f = try tmp.dir.openFile(scenario_io(), "wal", .{ .mode = .read_write });
        defer f.close(scenario_io());
        const _end_pos_f = try f.length(scenario_io());
        // Fake header: LSN=2, payload_len=1000
        var hdr: [record.HEADER_SIZE]u8 = undefined;
        std.mem.writeInt(u64, hdr[0..8], 2, .little);
        std.mem.writeInt(u32, hdr[8..12], 1000, .little);
        try f.writePositionalAll(scenario_io(), &hdr, _end_pos_f);

        // Only 10 bytes of payload (instead of 1000).
        const partial = [_]u8{0xFF} ** 10;
        try f.writePositionalAll(scenario_io(), &partial, _end_pos_f + hdr.len);
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
        const f = try tmp.dir.openFile(scenario_io(), "wal", .{ .mode = .read_write });
        defer f.close(scenario_io());

        const record2_payload_offset: u64 = (record.HEADER_SIZE + "alpha".len + record.CRC_SIZE) +
            record.HEADER_SIZE;
        var byte: [1]u8 = undefined;
        _ = try f.readPositionalAll(scenario_io(), &byte, record2_payload_offset);
        byte[0] ^= 0xFF;
        try f.writePositionalAll(scenario_io(), &byte, record2_payload_offset);
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

// ============================================================================
// Encrypted Crash Tests (QA-0039)
// ============================================================================

test "encrypted: torn write mid-header recovery" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var key: [32]u8 = undefined;
    std.Io.Threaded.global_single_threaded.io().random(&key);

    // Write 3 encrypted records and close.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{
            .encryption_key = key,
        });
        defer log.deinit();

        _ = try log.append("enc-record-1");
        _ = try log.append("enc-record-2");
        _ = try log.append("enc-record-3");
        try log.sync();
    }

    // Append 6 garbage bytes directly — simulates a torn header write of a 4th record.
    {
        const f = try tmp.dir.openFile(scenario_io(), "wal", .{ .mode = .read_write });
        defer f.close(scenario_io());
        const _end_pos_f = try f.length(scenario_io());
        const garbage = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE };
        try f.writePositionalAll(scenario_io(), &garbage, _end_pos_f);
    }

    // Reopen — recovery should truncate the garbage and restore LSN 3.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{
            .encryption_key = key,
        });
        defer log.deinit();

        try std.testing.expectEqual(@as(u64, 3), log.currentLsn());

        // Iterator should return exactly 3 records.
        var iter = try log.iterator(0);
        defer iter.deinit();

        const expected_payloads = [_][]const u8{ "enc-record-1", "enc-record-2", "enc-record-3" };
        for (expected_payloads, 1..) |expected, lsn| {
            var maybe_entry = try iter.next();
            try std.testing.expect(maybe_entry != null);
            defer maybe_entry.?.deinit();
            try std.testing.expectEqual(@as(u64, lsn), maybe_entry.?.lsn);
            try std.testing.expectEqualSlices(u8, expected, maybe_entry.?.payload);
        }

        try std.testing.expect((try iter.next()) == null);

        // New appends must still work.
        const new_lsn = try log.append("after-crash");
        try std.testing.expectEqual(@as(u64, 4), new_lsn);
    }
}

test "encrypted: corrupt ciphertext recovery" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var key: [32]u8 = undefined;
    std.Io.Threaded.global_single_threaded.io().random(&key);

    // Write 3 encrypted records and close.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{
            .encryption_key = key,
        });
        defer log.deinit();

        _ = try log.append("enc-alpha");
        _ = try log.append("enc-beta");
        _ = try log.append("enc-gamma");
        try log.sync();
    }

    // Corrupt the ciphertext of the last (3rd) encrypted record.
    // Each encrypted record wraps a plaintext record:
    //   plaintext_size = HEADER(12) + payload.len + CRC(4)
    //   encrypted_size = ENCRYPTION_OVERHEAD(40) + plaintext_size
    // Record sizes (payload lengths: 9, 8, 9):
    //   rec1 = 40 + (12 + 9 + 4)  = 65
    //   rec2 = 40 + (12 + 8 + 4)  = 64
    //   rec3 = 40 + (12 + 9 + 4)  = 65
    // rec3 starts at offset 65 + 64 = 129.
    // Ciphertext starts at offset 40 within the encrypted record.
    // So flip a byte at file offset 129 + 40 = 169 (inside rec3's ciphertext).
    {
        const f = try tmp.dir.openFile(scenario_io(), "wal", .{ .mode = .read_write });
        defer f.close(scenario_io());

        const rec1_size: u64 = encryption.ENCRYPTION_OVERHEAD + record.HEADER_SIZE + "enc-alpha".len + record.CRC_SIZE;
        const rec2_size: u64 = encryption.ENCRYPTION_OVERHEAD + record.HEADER_SIZE + "enc-beta".len + record.CRC_SIZE;
        const rec3_ciphertext_offset: u64 = rec1_size + rec2_size + encryption.ENCRYPTION_OVERHEAD;

        var byte: [1]u8 = undefined;
        _ = try f.readPositionalAll(scenario_io(), &byte, rec3_ciphertext_offset);
        byte[0] ^= 0xFF;
        try f.writePositionalAll(scenario_io(), &byte, rec3_ciphertext_offset);
    }

    // Reopen — recovery should detect the corrupt record and truncate it.
    // Only 2 records should survive.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{
            .encryption_key = key,
        });
        defer log.deinit();

        try std.testing.expectEqual(@as(u64, 2), log.currentLsn());

        var iter = try log.iterator(0);
        defer iter.deinit();

        var e1 = try iter.next();
        try std.testing.expect(e1 != null);
        defer e1.?.deinit();
        try std.testing.expectEqual(@as(u64, 1), e1.?.lsn);
        try std.testing.expectEqualSlices(u8, "enc-alpha", e1.?.payload);

        var e2 = try iter.next();
        try std.testing.expect(e2 != null);
        defer e2.?.deinit();
        try std.testing.expectEqual(@as(u64, 2), e2.?.lsn);
        try std.testing.expectEqualSlices(u8, "enc-beta", e2.?.payload);

        try std.testing.expect((try iter.next()) == null);
    }
}
