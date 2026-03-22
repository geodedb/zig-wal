// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Encryption scenario tests: verify AES-256-GCM lifecycle, ciphertext
//! opacity, and batch behaviour under encryption.

const std = @import("std");
const wal = @import("wal");

// ============================================================================
// Encryption Tests
// ============================================================================

test "encryption: full lifecycle with encryption" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    // Write 3 records with encryption and close.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{
            .encryption_key = key,
        });
        defer log.deinit();

        _ = try log.append("secret-1");
        _ = try log.append("secret-2");
        _ = try log.append("secret-3");

        try std.testing.expectEqual(@as(u64, 3), log.currentLsn());
    }

    // Reopen with the same key — LSN should be recovered.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{
            .encryption_key = key,
        });
        defer log.deinit();

        try std.testing.expectEqual(@as(u64, 3), log.currentLsn());

        var iter = try log.iterator(0);
        defer iter.deinit();

        const expected_payloads = [_][]const u8{ "secret-1", "secret-2", "secret-3" };
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

test "encryption: data not readable as plaintext" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    const secret = "my-super-secret-payload";

    // Write with encryption.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{
            .encryption_key = key,
        });
        defer log.deinit();
        _ = try log.append(secret);
    }

    // Read the raw file bytes and verify the secret string does NOT appear.
    const stat = try tmp.dir.statFile("wal");
    const raw = try allocator.alloc(u8, stat.size);
    defer allocator.free(raw);

    {
        const f = try tmp.dir.openFile("wal", .{});
        defer f.close();
        _ = try f.readAll(raw);
    }

    // The plaintext secret must not appear in the ciphertext.
    const found = std.mem.indexOf(u8, raw, secret);
    try std.testing.expect(found == null);
}

test "encryption: batch append with encryption" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{
        .encryption_key = key,
    });
    defer log.deinit();

    const payloads = [_][]const u8{ "enc-alpha", "enc-beta", "enc-gamma" };
    const last_lsn = try log.appendBatch(&payloads);

    try std.testing.expectEqual(@as(u64, 3), last_lsn);
    try std.testing.expectEqual(@as(u64, 3), log.currentLsn());

    // Verify all records are readable.
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

test "encryption: compaction of encrypted WAL preserves kept records" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    // Create an encrypted WAL and append 5 records.
    var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{
        .encryption_key = key,
    });
    defer log.deinit();

    _ = try log.append("enc-record-1");
    _ = try log.append("enc-record-2");
    _ = try log.append("enc-record-3");
    _ = try log.append("enc-record-4");
    _ = try log.append("enc-record-5");

    try std.testing.expectEqual(@as(u64, 5), log.currentLsn());

    // Compact at LSN 3 — records 1, 2, 3 should be removed; 4 and 5 kept.
    try log.compact(3);

    try std.testing.expectEqual(@as(u64, 5), log.currentLsn());
    try std.testing.expectEqual(@as(u64, 0), log.bytesSinceCompact());

    // Iterate from 0 — should see only records 4 and 5.
    var iter = try log.iterator(0);
    defer iter.deinit();

    var maybe_e4 = try iter.next();
    try std.testing.expect(maybe_e4 != null);
    defer maybe_e4.?.deinit();
    try std.testing.expectEqual(@as(u64, 4), maybe_e4.?.lsn);
    try std.testing.expectEqualSlices(u8, "enc-record-4", maybe_e4.?.payload);

    var maybe_e5 = try iter.next();
    try std.testing.expect(maybe_e5 != null);
    defer maybe_e5.?.deinit();
    try std.testing.expectEqual(@as(u64, 5), maybe_e5.?.lsn);
    try std.testing.expectEqualSlices(u8, "enc-record-5", maybe_e5.?.payload);

    try std.testing.expect((try iter.next()) == null);
}

test "encryption: mixed plaintext then encrypted WAL migration" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    // Phase 1: Write plaintext records (no encryption key).
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
        defer log.deinit();

        _ = try log.append("plain-1");
        _ = try log.append("plain-2");
        _ = try log.append("plain-3");

        try std.testing.expectEqual(@as(u64, 3), log.currentLsn());
    }

    // Phase 2: Reopen with encryption key and append encrypted records.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{
            .encryption_key = key,
        });
        defer log.deinit();

        // Recovery should have found the 3 plaintext records.
        try std.testing.expectEqual(@as(u64, 3), log.currentLsn());

        _ = try log.append("encrypted-4");
        _ = try log.append("encrypted-5");

        try std.testing.expectEqual(@as(u64, 5), log.currentLsn());
    }

    // Phase 3: Reopen with key and iterate all 5 records (3 plain + 2 encrypted).
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{
            .encryption_key = key,
        });
        defer log.deinit();

        try std.testing.expectEqual(@as(u64, 5), log.currentLsn());

        var iter = try log.iterator(0);
        defer iter.deinit();

        const expected = [_]struct { lsn: u64, payload: []const u8 }{
            .{ .lsn = 1, .payload = "plain-1" },
            .{ .lsn = 2, .payload = "plain-2" },
            .{ .lsn = 3, .payload = "plain-3" },
            .{ .lsn = 4, .payload = "encrypted-4" },
            .{ .lsn = 5, .payload = "encrypted-5" },
        };

        for (expected) |exp| {
            var maybe_entry = try iter.next();
            try std.testing.expect(maybe_entry != null);
            defer maybe_entry.?.deinit();
            try std.testing.expectEqual(exp.lsn, maybe_entry.?.lsn);
            try std.testing.expectEqualSlices(u8, exp.payload, maybe_entry.?.payload);
        }

        try std.testing.expect((try iter.next()) == null);
    }
}

test "encryption: compaction of mixed plaintext/encrypted WAL" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    // Write 2 plaintext records, close, then 2 encrypted records.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
        defer log.deinit();
        _ = try log.append("plain-1");
        _ = try log.append("plain-2");
    }
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{
            .encryption_key = key,
        });
        defer log.deinit();
        _ = try log.append("encrypted-3");
        _ = try log.append("encrypted-4");

        // Compact at LSN 2 — removes both plaintext records.
        try log.compact(2);

        try std.testing.expectEqual(@as(u64, 0), log.bytesSinceCompact());

        // Iterate — should see only encrypted records 3 and 4.
        var iter = try log.iterator(0);
        defer iter.deinit();

        var maybe_e3 = try iter.next();
        try std.testing.expect(maybe_e3 != null);
        defer maybe_e3.?.deinit();
        try std.testing.expectEqual(@as(u64, 3), maybe_e3.?.lsn);
        try std.testing.expectEqualSlices(u8, "encrypted-3", maybe_e3.?.payload);

        var maybe_e4 = try iter.next();
        try std.testing.expect(maybe_e4 != null);
        defer maybe_e4.?.deinit();
        try std.testing.expectEqual(@as(u64, 4), maybe_e4.?.lsn);
        try std.testing.expectEqualSlices(u8, "encrypted-4", maybe_e4.?.payload);

        try std.testing.expect((try iter.next()) == null);
    }
}
