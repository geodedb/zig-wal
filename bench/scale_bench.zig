// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Multi-tier WAL scale benchmarks with JSON output for baseline tracking.
//!
//! Runs WAL operations at increasing scale tiers (1K, 10K, 50K, 100K records)
//! and measures append throughput, batch throughput, recovery time, compaction,
//! iteration, and encryption overhead.
//!
//! JSON results go to stdout, human-readable summary to stderr.
//!
//! Usage:
//!   zig build scale-bench                    # Run all tiers
//!   zig build scale-bench -- 10K             # Run up to 10K tier
//!   zig build scale-bench -- 100K encrypted  # Include encryption tiers

const std = @import("std");
const wal_mod = @import("wal");
const tp = @import("thread_pool");

const WriteAheadLog = wal_mod.WriteAheadLog;
const Options = wal_mod.Options;
const record = wal_mod.record;
const encryption = wal_mod.encryption;

// Zig 0.16 compat: Timer was removed; use monotonic clock directly.
const Timer = struct {
    start_ns: i96,

    fn start() error{}!Timer {
        return .{ .start_ns = nanoTimestamp() };
    }

    fn read(self: *Timer) u64 {
        const diff = nanoTimestamp() - self.start_ns;
        return if (diff > 0) @intCast(diff) else 0;
    }

    fn nanoTimestamp() i96 {
        const io = std.Io.Threaded.global_single_threaded.io();
        return std.Io.Clock.Timestamp.now(io, .real).raw.nanoseconds;
    }
};

// Zig 0.16 compat: std.testing.tmpDir asserts builtin.is_test.
// Lightweight replacement for bench executables.
const BenchTmpDir = struct {
    dir: std.Io.Dir,
    parent: std.Io.Dir,
    sub_path: [12]u8,

    fn create() BenchTmpDir {
        const sio = std.Io.Threaded.global_single_threaded.io();
        const cwd = std.Io.Dir.cwd();
        var cache_dir = cwd.createDirPathOpen(sio, ".zig-cache/tmp", .{}) catch
            @panic("bench: cannot create .zig-cache/tmp");
        var sub: [12]u8 = undefined;
        var rng_bytes: [9]u8 = undefined;
        sio.random(&rng_bytes);
        _ = std.base64.url_safe.Encoder.encode(&sub, &rng_bytes);
        const dir = cache_dir.createDirPathOpen(sio, &sub, .{}) catch
            @panic("bench: cannot create tmp subdir");
        return .{ .dir = dir, .parent = cache_dir, .sub_path = sub };
    }

    fn cleanup(self: *BenchTmpDir) void {
        const sio = std.Io.Threaded.global_single_threaded.io();
        self.dir.close(sio);
        self.parent.deleteTree(sio, &self.sub_path) catch {};
        self.parent.close(sio);
    }
};

// ============================================================================
// Configuration
// ============================================================================

const WARM_UP = 50;

/// Per-tier timeout: 5 minutes.
const TIER_TIMEOUT_NS: u64 = 300 * std.time.ns_per_s;

const Tier = struct {
    name: []const u8,
    record_count: usize,
    payload_size: usize,
    batch_size: usize,
    /// Number of iterations for non-append benchmarks.
    iterations: usize,
};

const tiers = [_]Tier{
    .{ .name = "1K", .record_count = 1_000, .payload_size = 64, .batch_size = 100, .iterations = 500 },
    .{ .name = "10K", .record_count = 10_000, .payload_size = 64, .batch_size = 500, .iterations = 200 },
    .{ .name = "50K", .record_count = 50_000, .payload_size = 64, .batch_size = 1_000, .iterations = 100 },
    .{ .name = "100K", .record_count = 100_000, .payload_size = 64, .batch_size = 2_000, .iterations = 50 },
};

// ============================================================================
// Result types (mirrors JSON output schema)
// ============================================================================

const TierResult = struct {
    name: []const u8,
    record_count: u64,
    payload_size: u64,
    // Throughput metrics (higher is better)
    append_ops_sec: f64,
    batch_ops_sec: f64,
    batch_parallel_ops_sec: f64,
    iterate_ops_sec: f64,
    // Latency metrics (lower is better)
    recovery_ms: f64,
    compact_ms: f64,
    // Encrypted variants
    append_enc_ops_sec: f64,
    batch_enc_ops_sec: f64,
    iterate_enc_ops_sec: f64,
    recovery_enc_ms: f64,
    // Status
    skipped: bool = false,
    skip_reason: ?[]const u8 = null,
};

// ============================================================================
// Benchmark helpers
// ============================================================================

fn makeKey() [32]u8 {
    return .{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20 };
}

fn makePayload(allocator: std.mem.Allocator, size: usize) ![]u8 {
    const buf = try allocator.alloc(u8, size);
    @memset(buf, 0xAB);
    return buf;
}

fn opsPerSec(count: usize, elapsed_ns: u64) f64 {
    if (elapsed_ns == 0) return 0;
    return @as(f64, @floatFromInt(count)) / (@as(f64, @floatFromInt(elapsed_ns)) / 1_000_000_000.0);
}

fn nsToMs(ns: u64) f64 {
    return @as(f64, @floatFromInt(ns)) / 1_000_000.0;
}

// ============================================================================
// Individual benchmark runners
// ============================================================================

fn benchAppend(allocator: std.mem.Allocator, tier: Tier, opts: Options) !f64 {
    var tmp = BenchTmpDir.create();
    defer tmp.cleanup();

    const payload = try makePayload(allocator, tier.payload_size);
    defer allocator.free(payload);

    // Warm up
    {
        var log = try WriteAheadLog.init(allocator, tmp.dir, "warmup.wal", opts);
        defer log.deinit();
        for (0..WARM_UP) |_| _ = try log.append(payload);
    }
    tmp.dir.deleteFile(std.Io.Threaded.global_single_threaded.io(), "warmup.wal") catch {};

    var log = try WriteAheadLog.init(allocator, tmp.dir, "bench.wal", opts);
    defer log.deinit();

    var timer = try Timer.start();
    for (0..tier.record_count) |_| {
        _ = try log.append(payload);
    }
    return opsPerSec(tier.record_count, timer.read());
}

fn benchBatch(allocator: std.mem.Allocator, tier: Tier, opts: Options) !f64 {
    var tmp = BenchTmpDir.create();
    defer tmp.cleanup();

    const payload = try makePayload(allocator, tier.payload_size);
    defer allocator.free(payload);

    // Build batch payload array.
    const batch = try allocator.alloc([]const u8, tier.batch_size);
    defer allocator.free(batch);
    for (batch) |*p| p.* = payload;

    var log = try WriteAheadLog.init(allocator, tmp.dir, "bench.wal", opts);
    defer log.deinit();

    const num_batches = tier.record_count / tier.batch_size;
    var timer = try Timer.start();
    for (0..num_batches) |_| {
        _ = try log.appendBatch(batch);
    }
    return opsPerSec(num_batches * tier.batch_size, timer.read());
}

fn benchBatchParallel(allocator: std.mem.Allocator, tier: Tier, pool: *tp.ThreadPool) !f64 {
    var tmp = BenchTmpDir.create();
    defer tmp.cleanup();

    const payload = try makePayload(allocator, tier.payload_size);
    defer allocator.free(payload);

    const batch = try allocator.alloc([]const u8, tier.batch_size);
    defer allocator.free(batch);
    for (batch) |*p| p.* = payload;

    const opts = Options{
        .manual_sync = true,
        .thread_pool = pool,
    };

    var log = try WriteAheadLog.init(allocator, tmp.dir, "bench.wal", opts);
    defer log.deinit();

    const num_batches = tier.record_count / tier.batch_size;
    var timer = try Timer.start();
    for (0..num_batches) |_| {
        _ = try log.appendBatch(batch);
    }
    return opsPerSec(num_batches * tier.batch_size, timer.read());
}

fn benchRecovery(allocator: std.mem.Allocator, tier: Tier, opts: Options) !f64 {
    var tmp = BenchTmpDir.create();
    defer tmp.cleanup();

    const payload = try makePayload(allocator, tier.payload_size);
    defer allocator.free(payload);

    // Write records.
    {
        var log = try WriteAheadLog.init(allocator, tmp.dir, "bench.wal", opts);
        defer log.deinit();
        for (0..tier.record_count) |_| _ = try log.append(payload);
        try log.sync();
    }

    // Benchmark recovery (re-open).
    var timer = try Timer.start();
    {
        var log = try WriteAheadLog.init(allocator, tmp.dir, "bench.wal", opts);
        defer log.deinit();
    }
    return nsToMs(timer.read());
}

fn benchCompact(allocator: std.mem.Allocator, tier: Tier, opts: Options) !f64 {
    var tmp = BenchTmpDir.create();
    defer tmp.cleanup();

    const payload = try makePayload(allocator, tier.payload_size);
    defer allocator.free(payload);

    var log = try WriteAheadLog.init(allocator, tmp.dir, "bench.wal", opts);
    defer log.deinit();

    for (0..tier.record_count) |_| _ = try log.append(payload);
    try log.sync();

    // Compact half.
    const watermark = tier.record_count / 2;
    var timer = try Timer.start();
    try log.compact(@intCast(watermark));
    return nsToMs(timer.read());
}

fn benchIterate(allocator: std.mem.Allocator, tier: Tier, opts: Options) !f64 {
    var tmp = BenchTmpDir.create();
    defer tmp.cleanup();

    const payload = try makePayload(allocator, tier.payload_size);
    defer allocator.free(payload);

    // Write records.
    {
        var log = try WriteAheadLog.init(allocator, tmp.dir, "bench.wal", opts);
        defer log.deinit();
        for (0..tier.record_count) |_| _ = try log.append(payload);
        try log.sync();
    }

    var log = try WriteAheadLog.init(allocator, tmp.dir, "bench.wal", opts);
    defer log.deinit();

    var timer = try Timer.start();
    var iter = try log.iterator(0);
    defer iter.deinit();
    var count: usize = 0;
    while (true) {
        var entry = try iter.next() orelse break;
        entry.deinit();
        count += 1;
    }
    return opsPerSec(count, timer.read());
}

// ============================================================================
// Tier runner
// ============================================================================

fn runTier(allocator: std.mem.Allocator, tier: Tier, pool: *tp.ThreadPool) !TierResult {
    const plain_opts = Options{ .manual_sync = true };
    const enc_opts = Options{ .manual_sync = true, .encryption_key = makeKey() };

    return TierResult{
        .name = tier.name,
        .record_count = @intCast(tier.record_count),
        .payload_size = @intCast(tier.payload_size),
        .append_ops_sec = try benchAppend(allocator, tier, plain_opts),
        .batch_ops_sec = try benchBatch(allocator, tier, plain_opts),
        .batch_parallel_ops_sec = try benchBatchParallel(allocator, tier, pool),
        .iterate_ops_sec = try benchIterate(allocator, tier, plain_opts),
        .recovery_ms = try benchRecovery(allocator, tier, plain_opts),
        .compact_ms = try benchCompact(allocator, tier, plain_opts),
        .append_enc_ops_sec = try benchAppend(allocator, tier, enc_opts),
        .batch_enc_ops_sec = try benchBatch(allocator, tier, enc_opts),
        .iterate_enc_ops_sec = try benchIterate(allocator, tier, enc_opts),
        .recovery_enc_ms = try benchRecovery(allocator, tier, enc_opts),
    };
}

// ============================================================================
// JSON output (stdout)
// ============================================================================

fn writeJsonOutput(results: []const TierResult) !void {
    const sio = std.Io.Threaded.global_single_threaded.io();
    var buf: [8192]u8 = undefined;
    var w = std.Io.File.stdout().writer(sio, &buf);
    const out = &w.interface;

    // Timestamp
    const ts = @divTrunc(Timer.nanoTimestamp(), std.time.ns_per_s);
    const epoch = std.time.epoch.EpochSeconds{ .secs = @intCast(ts) };
    const day = epoch.getEpochDay();
    const yd = day.calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = epoch.getDaySeconds();

    try out.print("{{\n", .{});
    try out.print("  \"version\": 1,\n", .{});
    try out.print("  \"timestamp\": \"{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z\",\n", .{
        yd.year,              md.month.numeric(),      md.day_index + 1,
        ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    });
    try out.print("  \"git_commit\": \"unknown\",\n", .{});
    try out.print("  \"system\": {{ \"os\": \"{s}\", \"arch\": \"{s}\" }},\n", .{
        @tagName(@import("builtin").os.tag), @tagName(@import("builtin").cpu.arch),
    });
    try out.print("  \"tiers\": [\n", .{});

    for (results, 0..) |r, i| {
        try out.print("    {{\n", .{});
        try out.print("      \"name\": \"{s}\",\n", .{r.name});
        try out.print("      \"record_count\": {d},\n", .{r.record_count});
        try out.print("      \"payload_size\": {d},\n", .{r.payload_size});
        try out.print("      \"append_ops_sec\": {d:.0},\n", .{r.append_ops_sec});
        try out.print("      \"batch_ops_sec\": {d:.0},\n", .{r.batch_ops_sec});
        try out.print("      \"batch_parallel_ops_sec\": {d:.0},\n", .{r.batch_parallel_ops_sec});
        try out.print("      \"iterate_ops_sec\": {d:.0},\n", .{r.iterate_ops_sec});
        try out.print("      \"recovery_ms\": {d:.1},\n", .{r.recovery_ms});
        try out.print("      \"compact_ms\": {d:.1},\n", .{r.compact_ms});
        try out.print("      \"append_enc_ops_sec\": {d:.0},\n", .{r.append_enc_ops_sec});
        try out.print("      \"batch_enc_ops_sec\": {d:.0},\n", .{r.batch_enc_ops_sec});
        try out.print("      \"iterate_enc_ops_sec\": {d:.0},\n", .{r.iterate_enc_ops_sec});
        try out.print("      \"recovery_enc_ms\": {d:.1}", .{r.recovery_enc_ms});
        if (r.skipped) {
            try out.print(",\n      \"skipped\": true", .{});
            if (r.skip_reason) |reason| {
                try out.print(",\n      \"skip_reason\": \"{s}\"", .{reason});
            }
        }
        try out.print("\n    }}", .{});
        if (i < results.len - 1) try out.print(",", .{});
        try out.print("\n", .{});
    }

    try out.print("  ]\n", .{});
    try out.print("}}\n", .{});
    try out.flush();
}

// ============================================================================
// Human-readable summary (stderr)
// ============================================================================

fn writeSummary(results: []const TierResult) void {
    const print = std.debug.print;

    print("\n{s}\n", .{"=" ** 120});
    print("  WAL Scale Benchmark Suite\n", .{});
    print("{s}\n\n", .{"=" ** 120});

    print("  {s:<6} {s:>8} {s:>14} {s:>14} {s:>14} {s:>14} {s:>10} {s:>10}\n", .{
        "Tier", "Records", "Append r/s", "Batch r/s", "BatchPar r/s", "Iterate r/s", "Recov(ms)", "Compact(ms)",
    });
    print("  {s}\n", .{"-" ** 112});

    for (results) |r| {
        if (r.skipped) {
            print("  {s:<6} (skipped)\n", .{r.name});
            continue;
        }
        print("  {s:<6} {d:>8} {d:>14.0} {d:>14.0} {d:>14.0} {d:>14.0} {d:>10.1} {d:>10.1}\n", .{
            r.name,                   r.record_count,    r.append_ops_sec, r.batch_ops_sec,
            r.batch_parallel_ops_sec, r.iterate_ops_sec, r.recovery_ms,    r.compact_ms,
        });
    }

    print("\n  Encrypted:\n", .{});
    print("  {s:<6} {s:>14} {s:>14} {s:>14} {s:>10}\n", .{
        "Tier", "Append r/s", "Batch r/s", "Iterate r/s", "Recov(ms)",
    });
    print("  {s}\n", .{"-" ** 60});

    for (results) |r| {
        if (r.skipped) continue;
        print("  {s:<6} {d:>14.0} {d:>14.0} {d:>14.0} {d:>10.1}\n", .{
            r.name,                r.append_enc_ops_sec, r.batch_enc_ops_sec,
            r.iterate_enc_ops_sec, r.recovery_enc_ms,
        });
    }

    print("\n{s}\n\n", .{"=" ** 120});
}

// ============================================================================
// Main
// ============================================================================

pub fn main(init: std.process.Init.Minimal) !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse optional max-tier argument.
    var max_tier: []const u8 = "100K";
    const argv = try init.args.toSlice(allocator);
    if (argv.len > 1) {
        max_tier = argv[1];
    }

    // Start thread pool for parallel benchmarks.
    var pool = try tp.ThreadPool.init(allocator, .{});
    defer pool.deinit();

    var results: std.ArrayListUnmanaged(TierResult) = .empty;
    defer results.deinit(allocator);

    for (tiers) |tier| {
        std.debug.print("  Running tier {s}...\n", .{tier.name});
        const result = runTier(allocator, tier, &pool) catch |err| {
            try results.append(allocator, TierResult{
                .name = tier.name,
                .record_count = @intCast(tier.record_count),
                .payload_size = @intCast(tier.payload_size),
                .append_ops_sec = 0,
                .batch_ops_sec = 0,
                .batch_parallel_ops_sec = 0,
                .iterate_ops_sec = 0,
                .recovery_ms = 0,
                .compact_ms = 0,
                .append_enc_ops_sec = 0,
                .batch_enc_ops_sec = 0,
                .iterate_enc_ops_sec = 0,
                .recovery_enc_ms = 0,
                .skipped = true,
                .skip_reason = @errorName(err),
            });
            continue;
        };
        try results.append(allocator, result);

        if (std.mem.eql(u8, tier.name, max_tier)) break;
    }

    // Output JSON to stdout, summary to stderr.
    try writeJsonOutput(results.items);
    writeSummary(results.items);
}
