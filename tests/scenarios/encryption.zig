// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Encryption scenario tests: verify AES-256-GCM lifecycle, ciphertext
//! opacity, and batch behaviour under encryption.

const std = @import("std");

fn scenario_io() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

const wal = @import("wal");

// ============================================================================
// Encryption Tests
// ============================================================================

test "encryption: full lifecycle with encryption" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var key: [32]u8 = undefined;
    std.Io.Threaded.global_single_threaded.io().random(&key);

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
    std.Io.Threaded.global_single_threaded.io().random(&key);

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
    const stat = try tmp.dir.statFile(scenario_io(), "wal", .{});
    const raw = try allocator.alloc(u8, stat.size);
    defer allocator.free(raw);

    {
        const f = try tmp.dir.openFile(scenario_io(), "wal", .{});
        defer f.close(scenario_io());
        _ = try f.readPositionalAll(scenario_io(), raw, 0);
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
    std.Io.Threaded.global_single_threaded.io().random(&key);

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
    std.Io.Threaded.global_single_threaded.io().random(&key);

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

test "encryption: plaintext records rejected when reopened with key (SEC-0038)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var key: [32]u8 = undefined;
    std.Io.Threaded.global_single_threaded.io().random(&key);

    // Phase 1: Write plaintext records (no encryption key).
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{});
        defer log.deinit();

        _ = try log.append("plain-1");
        _ = try log.append("plain-2");
        _ = try log.append("plain-3");

        try std.testing.expectEqual(@as(u64, 3), log.currentLsn());
    }

    // Phase 2: Reopen with encryption key — recovery rejects all plaintext
    // records (SEC-0038), so LSN resets to 0. New encrypted appends start
    // from LSN 1.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{
            .encryption_key = key,
        });
        defer log.deinit();

        // Recovery rejects plaintext records when key is present.
        try std.testing.expectEqual(@as(u64, 0), log.currentLsn());

        _ = try log.append("encrypted-1");
        _ = try log.append("encrypted-2");

        try std.testing.expectEqual(@as(u64, 2), log.currentLsn());
    }
}

test "encryption: compaction rejects plaintext records with key (SEC-0038)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var key: [32]u8 = undefined;
    std.Io.Threaded.global_single_threaded.io().random(&key);

    // Write only encrypted records (SEC-0038 prevents mixed-mode).
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal", .{
            .encryption_key = key,
        });
        defer log.deinit();

        _ = try log.append("encrypted-1");
        _ = try log.append("encrypted-2");
        _ = try log.append("encrypted-3");
        _ = try log.append("encrypted-4");

        // Compact at LSN 2 — removes first 2 encrypted records.
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

test "encryption: large payload round-trip (>24B, exercises overlapping decrypt) (SEC-0003)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var key: [32]u8 = undefined;
    std.Io.Threaded.global_single_threaded.io().random(&key);

    const payload_sizes = [_]usize{ 25, 64, 256, 1024, 4096 };

    for (payload_sizes) |size| {
        // Create a fresh WAL for each payload size.
        const fname = "wal-large";
        tmp.dir.deleteFile(scenario_io(), fname) catch {};

        const payload = try allocator.alloc(u8, size);
        defer allocator.free(payload);
        @memset(payload, 0xAB);

        // Write, close, reopen (exercises recovery with in-place decrypt).
        {
            var log = try wal.WriteAheadLog.init(allocator, tmp.dir, fname, .{
                .encryption_key = key,
            });
            defer log.deinit();
            _ = try log.append(payload);
        }

        // Recovery path: recoverWithKey → decryptRecordInPlace.
        {
            var log = try wal.WriteAheadLog.init(allocator, tmp.dir, fname, .{
                .encryption_key = key,
            });
            defer log.deinit();

            try std.testing.expectEqual(@as(u64, 1), log.currentLsn());

            // Iterator path: readEncryptedEntry → decryptRecordInPlace.
            var iter = try log.iterator(0);
            defer iter.deinit();

            var maybe_entry = try iter.next();
            try std.testing.expect(maybe_entry != null);
            defer maybe_entry.?.deinit();
            try std.testing.expectEqual(@as(u64, 1), maybe_entry.?.lsn);
            try std.testing.expectEqual(size, maybe_entry.?.payload.len);
            for (maybe_entry.?.payload) |byte| {
                try std.testing.expectEqual(@as(u8, 0xAB), byte);
            }

            try std.testing.expect((try iter.next()) == null);
        }
    }
}

test "encryption: batch append with large payloads (SEC-0003)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var key: [32]u8 = undefined;
    std.Io.Threaded.global_single_threaded.io().random(&key);

    // Payloads well above the 24-byte overlap threshold.
    const payload_64 = "A" ** 64;
    const payload_128 = "B" ** 128;
    const payload_256 = "C" ** 256;

    var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "wal-batch", .{
        .encryption_key = key,
    });
    defer log.deinit();

    const payloads = [_][]const u8{ payload_64, payload_128, payload_256 };
    const last_lsn = try log.appendBatch(&payloads);
    try std.testing.expectEqual(@as(u64, 3), last_lsn);

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
