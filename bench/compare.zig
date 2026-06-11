// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! Benchmark comparison tool for the WAL library.
//!
//! Reads two JSON result files (baseline and current), compares each metric
//! at each tier, and prints a table showing delta% and pass/fail.
//!
//! Usage: zig build compare-bench -- baseline.json current.json
//! Optional: zig build compare-bench -- baseline.json current.json 25
//!           (last arg is the regression threshold percentage, default 20)
//!
//! Exit code 0 if all pass, 1 if any regression exceeds threshold.

const std = @import("std");

const print = std.debug.print;

// ---------------------------------------------------------------------------
// JSON parsing types
// ---------------------------------------------------------------------------

const TierData = struct {
    name: []const u8 = "",
    record_count: f64 = 0,
    payload_size: f64 = 0,
    append_ops_sec: f64 = 0,
    batch_ops_sec: f64 = 0,
    batch_parallel_ops_sec: f64 = 0,
    iterate_ops_sec: f64 = 0,
    recovery_ms: f64 = 0,
    compact_ms: f64 = 0,
    append_enc_ops_sec: f64 = 0,
    batch_enc_ops_sec: f64 = 0,
    iterate_enc_ops_sec: f64 = 0,
    recovery_enc_ms: f64 = 0,
    skipped: bool = false,
};

const BenchResult = struct {
    version: f64 = 0,
    tiers: []TierData = &[_]TierData{},
};

// ---------------------------------------------------------------------------
// Metric definitions
// ---------------------------------------------------------------------------

const MetricKind = enum {
    /// Higher is better (throughput metrics). A decrease is a regression.
    higher_is_better,
    /// Lower is better (latency metrics). An increase is a regression.
    lower_is_better,
};

const Metric = struct {
    name: []const u8,
    kind: MetricKind,
    get: *const fn (TierData) f64,
};

fn getAppendOps(t: TierData) f64 {
    return t.append_ops_sec;
}
fn getBatchOps(t: TierData) f64 {
    return t.batch_ops_sec;
}
fn getBatchParOps(t: TierData) f64 {
    return t.batch_parallel_ops_sec;
}
fn getIterateOps(t: TierData) f64 {
    return t.iterate_ops_sec;
}
fn getRecoveryMs(t: TierData) f64 {
    return t.recovery_ms;
}
fn getCompactMs(t: TierData) f64 {
    return t.compact_ms;
}
fn getAppendEncOps(t: TierData) f64 {
    return t.append_enc_ops_sec;
}
fn getBatchEncOps(t: TierData) f64 {
    return t.batch_enc_ops_sec;
}
fn getIterateEncOps(t: TierData) f64 {
    return t.iterate_enc_ops_sec;
}
fn getRecoveryEncMs(t: TierData) f64 {
    return t.recovery_enc_ms;
}

const metrics = [_]Metric{
    .{ .name = "append_ops_sec", .kind = .higher_is_better, .get = getAppendOps },
    .{ .name = "batch_ops_sec", .kind = .higher_is_better, .get = getBatchOps },
    .{ .name = "batch_par_ops_sec", .kind = .higher_is_better, .get = getBatchParOps },
    .{ .name = "iterate_ops_sec", .kind = .higher_is_better, .get = getIterateOps },
    .{ .name = "recovery_ms", .kind = .lower_is_better, .get = getRecoveryMs },
    .{ .name = "compact_ms", .kind = .lower_is_better, .get = getCompactMs },
    .{ .name = "append_enc_ops_sec", .kind = .higher_is_better, .get = getAppendEncOps },
    .{ .name = "batch_enc_ops_sec", .kind = .higher_is_better, .get = getBatchEncOps },
    .{ .name = "iterate_enc_ops_sec", .kind = .higher_is_better, .get = getIterateEncOps },
    .{ .name = "recovery_enc_ms", .kind = .lower_is_better, .get = getRecoveryEncMs },
};

// ---------------------------------------------------------------------------
// File reading and parsing
// ---------------------------------------------------------------------------

fn readJsonFile(allocator: std.mem.Allocator, path: []const u8) !BenchResult {
    const bench_io = std.Io.Threaded.global_single_threaded.io();
    const content = std.Io.Dir.cwd().readFileAlloc(bench_io, path, allocator, .limited(10 * 1024 * 1024)) catch |err| {
        print("Error: cannot open '{s}': {s}\n", .{ path, @errorName(err) });
        return err;
    };
    defer allocator.free(content);

    const parsed = std.json.parseFromSlice(BenchResult, allocator, content, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch |err| {
        print("Error: failed to parse '{s}': {s}\n", .{ path, @errorName(err) });
        return err;
    };
    // Intentionally leak parsed data — program exits shortly.
    _ = &parsed;

    return parsed.value;
}

// ---------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------

fn findTier(result: BenchResult, name: []const u8) ?TierData {
    for (result.tiers) |t| {
        if (std.mem.eql(u8, t.name, name)) return t;
    }
    return null;
}

fn computeDeltaPct(baseline_val: f64, current_val: f64) f64 {
    if (baseline_val == 0) return 0;
    return ((current_val - baseline_val) / baseline_val) * 100.0;
}

fn isRegression(delta_pct: f64, kind: MetricKind, threshold: f64) bool {
    return switch (kind) {
        .higher_is_better => delta_pct < -threshold,
        .lower_is_better => delta_pct > threshold,
    };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init.Minimal) !void {
    const allocator = std.heap.page_allocator;

    const argv = try init.args.toSlice(allocator);

    if (argv.len < 3) {
        print("Usage: compare-bench <baseline.json> <current.json> [threshold%]\n", .{});
        std.process.exit(2);
    }
    const baseline_path = argv[1];
    const current_path = argv[2];

    var threshold: f64 = 20.0;
    if (argv.len > 3) {
        threshold = std.fmt.parseFloat(f64, argv[3]) catch 20.0;
    }

    const baseline = readJsonFile(allocator, baseline_path) catch {
        std.process.exit(2);
    };
    const current = readJsonFile(allocator, current_path) catch {
        std.process.exit(2);
    };

    // Print header.
    print("\n{s}\n", .{"=" ** 100});
    print("  WAL Benchmark Comparison\n", .{});
    print("  Baseline: {s}\n", .{baseline_path});
    print("  Current:  {s}\n", .{current_path});
    print("  Threshold: {d:.0}%\n", .{threshold});
    print("{s}\n\n", .{"=" ** 100});

    print("  {s:<6} {s:<22} {s:>14} {s:>14} {s:>10} {s:>6}\n", .{
        "Tier", "Metric", "Baseline", "Current", "Delta%", "Status",
    });
    print("  {s:<6} {s:<22} {s:>14} {s:>14} {s:>10} {s:>6}\n", .{
        "-" ** 6, "-" ** 22, "-" ** 14, "-" ** 14, "-" ** 10, "-" ** 6,
    });

    var any_regression = false;

    for (baseline.tiers) |base_tier| {
        if (base_tier.skipped) continue;

        const cur_tier = findTier(current, base_tier.name) orelse continue;
        if (cur_tier.skipped) continue;

        for (metrics) |m| {
            const base_val = m.get(base_tier);
            const cur_val = m.get(cur_tier);
            const delta = computeDeltaPct(base_val, cur_val);
            const regressed = isRegression(delta, m.kind, threshold);

            if (regressed) any_regression = true;

            const status: []const u8 = if (regressed) "FAIL" else "PASS";
            const sign: []const u8 = if (delta >= 0) "+" else "";

            print("  {s:<6} {s:<22} {d:>14.1} {d:>14.1} {s}{d:>8.1}% {s:>6}\n", .{
                base_tier.name, m.name, base_val, cur_val,
                sign,           delta,  status,
            });
        }

        print("\n", .{});
    }

    print("{s}\n", .{"=" ** 100});

    if (any_regression) {
        print("  RESULT: FAIL -- regression(s) detected above threshold\n\n", .{});
        std.process.exit(1);
    } else {
        print("  RESULT: PASS -- all metrics within threshold\n\n", .{});
    }
}
