// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! WAL performance benchmarks.
//!
//! Measures append throughput, recovery time, compaction time, and pure
//! encryption/decryption throughput across payload sizes and encryption modes.
//!
//! Run:  zig build bench
//!       make bench

const std = @import("std");
const wal = @import("wal");

// Internal/unstable modules used for benchmarking (QA-0053).
const record = wal.record;
const encryption = wal.encryption;

const WARM_UP = 50;

/// Benchmark configuration.
const Bench = struct {
    name: []const u8,
    payload_size: usize,
    record_count: usize,
    encryption_key: ?[32]u8,
};

const benchmarks = [_]Bench{
    .{ .name = "append_64B_plain", .payload_size = 64, .record_count = 10_000, .encryption_key = null },
    .{ .name = "append_1KB_plain", .payload_size = 1024, .record_count = 5_000, .encryption_key = null },
    .{ .name = "append_64KB_plain", .payload_size = 64 * 1024, .record_count = 500, .encryption_key = null },
    .{ .name = "append_64B_encrypted", .payload_size = 64, .record_count = 10_000, .encryption_key = makeKey() },
    .{ .name = "append_1KB_encrypted", .payload_size = 1024, .record_count = 5_000, .encryption_key = makeKey() },
    .{ .name = "recovery_10k_plain", .payload_size = 64, .record_count = 10_000, .encryption_key = null },
    .{ .name = "recovery_10k_encrypted", .payload_size = 64, .record_count = 10_000, .encryption_key = makeKey() },
    .{ .name = "compact_5k_plain", .payload_size = 64, .record_count = 5_000, .encryption_key = null },
    .{ .name = "compact_5k_encrypted", .payload_size = 64, .record_count = 5_000, .encryption_key = makeKey() },
    // Iteration benchmarks (PERF-0015)
    .{ .name = "iterate_10k_plain", .payload_size = 64, .record_count = 10_000, .encryption_key = null },
    .{ .name = "iterate_10k_encrypted", .payload_size = 64, .record_count = 10_000, .encryption_key = makeKey() },
    .{ .name = "iterate_lsn_5k_plain", .payload_size = 64, .record_count = 10_000, .encryption_key = null },
    .{ .name = "iterate_lsn_5k_enc", .payload_size = 64, .record_count = 10_000, .encryption_key = makeKey() },
    // Pure encryption throughput (no file I/O) — QA-0029
    .{ .name = "encrypt_64B", .payload_size = 64, .record_count = 50_000, .encryption_key = makeKey() },
    .{ .name = "encrypt_1KB", .payload_size = 1024, .record_count = 20_000, .encryption_key = makeKey() },
    .{ .name = "decrypt_64B", .payload_size = 64, .record_count = 50_000, .encryption_key = makeKey() },
    .{ .name = "decrypt_1KB", .payload_size = 1024, .record_count = 20_000, .encryption_key = makeKey() },
};

/// Deterministic key for reproducible benchmarks.
/// NOT FOR PRODUCTION USE — this key is publicly visible in source code (SEC-0012).
fn makeKey() [32]u8 {
    return .{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20 };
}

pub fn main() !void {
    // Use GeneralPurposeAllocator for realistic allocation overhead (QA-0012).
    // page_allocator calls mmap/munmap per alloc, masking true WAL throughput.
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var buf: [4096]u8 = undefined;
    var file_writer = std.fs.File.stdout().writer(&buf);
    const w = &file_writer.interface;

    try w.print("\n{s:<30} {s:>12} {s:>12} {s:>14}\n", .{
        "Benchmark", "Records", "Time (ms)", "Throughput",
    });
    try w.print("{s}\n", .{"-" ** 70});

    for (benchmarks) |bench| {
        if (std.mem.startsWith(u8, bench.name, "append_")) {
            try runAppendBench(allocator, w, bench);
        } else if (std.mem.startsWith(u8, bench.name, "recovery_")) {
            try runRecoveryBench(allocator, w, bench);
        } else if (std.mem.startsWith(u8, bench.name, "compact_")) {
            try runCompactBench(allocator, w, bench);
        } else if (std.mem.startsWith(u8, bench.name, "iterate_")) {
            try runIterateBench(allocator, w, bench);
        } else if (std.mem.startsWith(u8, bench.name, "encrypt_")) {
            try runEncryptBench(allocator, w, bench);
        } else if (std.mem.startsWith(u8, bench.name, "decrypt_")) {
            try runDecryptBench(allocator, w, bench);
        }
    }

    try w.print("\n", .{});
    try w.flush();
}

fn runAppendBench(allocator: std.mem.Allocator, w: *std.Io.Writer, bench: Bench) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const payload = try allocator.alloc(u8, bench.payload_size);
    defer allocator.free(payload);
    @memset(payload, 0xAB);

    const opts: wal.Options = .{
        .encryption_key = bench.encryption_key,
        .manual_sync = true, // benchmark raw append speed without fsync
    };

    // Warm up with a separate WAL so warmup records don't contaminate the
    // timed run (QA-0037).
    {
        var warmup_log = try wal.WriteAheadLog.init(allocator, tmp.dir, "warmup.wal", opts);
        defer warmup_log.deinit();
        for (0..WARM_UP) |_| {
            _ = try warmup_log.append(payload);
        }
    }
    tmp.dir.deleteFile("warmup.wal") catch {};

    var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "bench.wal", opts);
    defer log.deinit();

    var timer = try std.time.Timer.start();
    for (0..bench.record_count) |_| {
        _ = try log.append(payload);
    }
    const elapsed_ns = timer.read();
    const elapsed_ms = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000.0;
    const throughput = @as(f64, @floatFromInt(bench.record_count)) / (elapsed_ms / 1000.0);

    try w.print("{s:<30} {d:>12} {d:>12.2} {d:>11.0} r/s\n", .{
        bench.name, bench.record_count, elapsed_ms, throughput,
    });
}

fn runRecoveryBench(allocator: std.mem.Allocator, w: *std.Io.Writer, bench: Bench) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const payload = try allocator.alloc(u8, bench.payload_size);
    defer allocator.free(payload);
    @memset(payload, 0xAB);

    const opts: wal.Options = .{
        .encryption_key = bench.encryption_key,
        .manual_sync = true,
    };

    // Write records.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "bench.wal", opts);
        defer log.deinit();
        for (0..bench.record_count) |_| {
            _ = try log.append(payload);
        }
        try log.sync();
    }

    // Benchmark recovery (re-open).
    var timer = try std.time.Timer.start();
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "bench.wal", opts);
        defer log.deinit();
    }
    const elapsed_ns = timer.read();
    const elapsed_ms = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000.0;
    const throughput = @as(f64, @floatFromInt(bench.record_count)) / (elapsed_ms / 1000.0);

    try w.print("{s:<30} {d:>12} {d:>12.2} {d:>11.0} r/s\n", .{
        bench.name, bench.record_count, elapsed_ms, throughput,
    });
}

fn runCompactBench(allocator: std.mem.Allocator, w: *std.Io.Writer, bench: Bench) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const payload = try allocator.alloc(u8, bench.payload_size);
    defer allocator.free(payload);
    @memset(payload, 0xAB);

    const opts: wal.Options = .{
        .encryption_key = bench.encryption_key,
        .manual_sync = true,
    };

    var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "bench.wal", opts);
    defer log.deinit();

    for (0..bench.record_count) |_| {
        _ = try log.append(payload);
    }
    try log.sync();

    // Compact half the records (keep the upper half).
    const watermark = bench.record_count / 2;
    const records_kept = bench.record_count - watermark;

    var timer = try std.time.Timer.start();
    try log.compact(@intCast(watermark));
    const elapsed_ns = timer.read();
    const elapsed_ms = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000.0;
    // Report throughput as records_kept / time — the actual work done (QA-0037).
    const throughput = @as(f64, @floatFromInt(records_kept)) / (elapsed_ms / 1000.0);

    try w.print("{s:<30} {d:>12} {d:>12.2} {d:>11.0} r/s\n", .{
        bench.name, records_kept, elapsed_ms, throughput,
    });
}

/// Iteration throughput — measures full forward scan of WAL records (PERF-0015).
/// "iterate_lsn_*" variants use from_lsn = record_count / 2 to measure skip performance.
fn runIterateBench(allocator: std.mem.Allocator, w: *std.Io.Writer, bench: Bench) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const payload = try allocator.alloc(u8, bench.payload_size);
    defer allocator.free(payload);
    @memset(payload, 0xAB);

    const opts: wal.Options = .{
        .encryption_key = bench.encryption_key,
        .manual_sync = true,
    };

    // Write records.
    {
        var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "bench.wal", opts);
        defer log.deinit();
        for (0..bench.record_count) |_| {
            _ = try log.append(payload);
        }
        try log.sync();
    }

    // Determine from_lsn: "iterate_lsn_*" skip first half, others read all.
    const is_lsn_bench = std.mem.indexOf(u8, bench.name, "_lsn_") != null;
    const from_lsn: u64 = if (is_lsn_bench) @intCast(bench.record_count / 2) else 0;
    const records_returned = bench.record_count - from_lsn;

    // Re-open for iteration.
    var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "bench.wal", opts);
    defer log.deinit();

    var timer = try std.time.Timer.start();
    var iter = try log.iterator(from_lsn);
    defer iter.deinit();
    var count: usize = 0;
    while (try iter.next()) |*entry| {
        var e = entry.*;
        e.deinit();
        count += 1;
    }
    const elapsed_ns = timer.read();
    const elapsed_ms = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000.0;
    const throughput = @as(f64, @floatFromInt(count)) / (elapsed_ms / 1000.0);

    try w.print("{s:<30} {d:>12} {d:>12.2} {d:>11.0} r/s\n", .{
        bench.name, records_returned, elapsed_ms, throughput,
    });
}

/// Pure encryption throughput — no file I/O (QA-0029).
fn runEncryptBench(allocator: std.mem.Allocator, w: *std.Io.Writer, bench: Bench) !void {
    const enc = encryption;
    const key = &bench.encryption_key.?;

    // Build a serialized plaintext record to encrypt.
    const payload = try allocator.alloc(u8, bench.payload_size);
    defer allocator.free(payload);
    @memset(payload, 0xAB);

    const plaintext = try record.serialize(allocator, 1, payload);
    defer allocator.free(plaintext);

    // Pre-allocate a reusable buffer for in-place encryption (PERF-0017).
    const enc_len = enc.ENCRYPTION_OVERHEAD + plaintext.len;
    const reuse_buf = try allocator.alloc(u8, enc_len);
    defer allocator.free(reuse_buf);

    // Warm up
    for (0..WARM_UP) |_| {
        enc.encryptInto(reuse_buf, key, plaintext);
    }

    var timer = try std.time.Timer.start();
    for (0..bench.record_count) |_| {
        enc.encryptInto(reuse_buf, key, plaintext);
    }
    const elapsed_ns = timer.read();
    const elapsed_ms = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000.0;
    const throughput = @as(f64, @floatFromInt(bench.record_count)) / (elapsed_ms / 1000.0);

    try w.print("{s:<30} {d:>12} {d:>12.2} {d:>11.0} r/s\n", .{
        bench.name, bench.record_count, elapsed_ms, throughput,
    });
}

/// Pure decryption throughput — no file I/O (QA-0029).
/// Uses a pre-allocated reusable buffer instead of allocator.dupe per iteration
/// to avoid mixing GPA alloc/free overhead into the AES-GCM measurement (PERF-0015).
fn runDecryptBench(allocator: std.mem.Allocator, w: *std.Io.Writer, bench: Bench) !void {
    const enc = encryption;
    const key = &bench.encryption_key.?;

    // Build a serialized plaintext record, then encrypt it once as the template.
    const payload = try allocator.alloc(u8, bench.payload_size);
    defer allocator.free(payload);
    @memset(payload, 0xAB);

    const plaintext = try record.serialize(allocator, 1, payload);
    defer allocator.free(plaintext);

    const template = try enc.encryptRecord(allocator, key, plaintext);
    defer allocator.free(template);

    // Pre-allocate a reusable buffer for in-place decryption (PERF-0015).
    const reuse_buf = try allocator.alloc(u8, template.len);
    defer allocator.free(reuse_buf);

    // Warm up
    for (0..WARM_UP) |_| {
        @memcpy(reuse_buf, template);
        _ = try enc.decryptRecordInPlace(key, reuse_buf);
    }

    var timer = try std.time.Timer.start();
    for (0..bench.record_count) |_| {
        @memcpy(reuse_buf, template);
        _ = try enc.decryptRecordInPlace(key, reuse_buf);
    }
    const elapsed_ns = timer.read();
    const elapsed_ms = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000.0;
    const throughput = @as(f64, @floatFromInt(bench.record_count)) / (elapsed_ms / 1000.0);

    try w.print("{s:<30} {d:>12} {d:>12.2} {d:>11.0} r/s\n", .{
        bench.name, bench.record_count, elapsed_ms, throughput,
    });
}
