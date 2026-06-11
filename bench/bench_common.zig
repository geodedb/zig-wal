// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! Shared helpers for the WAL benchmark executables (QA-0080).
//!
//! `bench/main.zig` and `bench/scale_bench.zig` both need a monotonic timer and
//! a throwaway temp directory; this module is the single source of truth for
//! both so they cannot drift apart.

const std = @import("std");

/// Zig 0.16 compat: `std.time.Timer` was removed; use the monotonic clock.
pub const Timer = struct {
    start_ns: i96,

    pub fn start() error{}!Timer {
        return .{ .start_ns = nanoTimestamp() };
    }

    pub fn read(self: *Timer) u64 {
        const diff = nanoTimestamp() - self.start_ns;
        return if (diff > 0) @intCast(diff) else 0;
    }

    /// Raw monotonic nanosecond reading (also used directly by scale_bench for
    /// a wall-clock timestamp, so it is public).
    pub fn nanoTimestamp() i96 {
        const io = std.Io.Threaded.global_single_threaded.io();
        return std.Io.Clock.Timestamp.now(io, .real).raw.nanoseconds;
    }
};

/// Zig 0.16 compat: `std.testing.tmpDir` asserts `builtin.is_test`, so benchmark
/// executables (which are not test binaries) need their own throwaway dir.
pub const BenchTmpDir = struct {
    dir: std.Io.Dir,
    parent: std.Io.Dir,
    sub_path: [12]u8,

    pub fn create() BenchTmpDir {
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

    pub fn cleanup(self: *BenchTmpDir) void {
        const sio = std.Io.Threaded.global_single_threaded.io();
        self.dir.close(sio);
        self.parent.deleteTree(sio, &self.sub_path) catch {};
        self.parent.close(sio);
    }
};
