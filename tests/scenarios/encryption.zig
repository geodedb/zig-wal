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
