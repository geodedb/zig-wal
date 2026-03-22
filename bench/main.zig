// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! WAL performance benchmarks.
//!
//! Measures append throughput, recovery time, and compaction time across
//! payload sizes and encryption modes.
//!
//! Run:  zig build bench
//!       make bench

const std = @import("std");
const wal = @import("wal");

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
};

fn makeKey() [32]u8 {
    return .{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20 };
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;

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

    var log = try wal.WriteAheadLog.init(allocator, tmp.dir, "bench.wal", opts);
    defer log.deinit();

    // Warm up
    for (0..WARM_UP) |_| {
        _ = try log.append(payload);
    }

    var timer = try std.time.Timer.start();
    for (0..bench.record_count) |_| {
        _ = try log.append(payload);
    }
    const elapsed_ns = timer.read();
    const elapsed_ms = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000.0;
    const throughput = @as(f64, @floatFromInt(bench.record_count)) / (elapsed_ms / 1000.0);

    try w.print("{s:<30} {d:>12} {d:>12.2} {d:>11.0} r/s\n", .{
        bench.name,
        bench.record_count,
        elapsed_ms,
        throughput,
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
        bench.name,
        bench.record_count,
        elapsed_ms,
        throughput,
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

    // Compact half the records.
    const watermark = bench.record_count / 2;

    var timer = try std.time.Timer.start();
    try log.compact(@intCast(watermark));
    const elapsed_ns = timer.read();
    const elapsed_ms = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000.0;
    const throughput = @as(f64, @floatFromInt(bench.record_count)) / (elapsed_ms / 1000.0);

    try w.print("{s:<30} {d:>12} {d:>12.2} {d:>11.0} r/s\n", .{
        bench.name,
        bench.record_count,
        elapsed_ms,
        throughput,
    });
}
