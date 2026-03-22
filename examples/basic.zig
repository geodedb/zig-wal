// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Basic usage example for the WAL library.
//!
//! Demonstrates append, iterate, close/reopen (crash recovery), and compaction.
//!
//! This example demonstrates WAL library usage. To compile, add the WAL
//! module to your own build.zig as shown in the README, then:
//!   @import("wal") to access the library.

const std = @import("std");
const wal = @import("wal");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Open (or create) a WAL in the current working directory.
    const cwd = std.fs.cwd();
    var log = try wal.WriteAheadLog.init(allocator, cwd, "demo.wal", .{});

    // Append some records.
    const lsn1 = try log.append("first record");
    const lsn2 = try log.append("second record");
    const lsn3 = try log.append("third record");

    std.debug.print("Appended 3 records (LSNs {d}, {d}, {d})\n", .{ lsn1, lsn2, lsn3 });

    // Iterate all records.
    {
        var iter = try log.iterator(0);
        defer iter.deinit();

        std.debug.print("\nAll records:\n", .{});
        while (true) {
            var entry = try iter.next() orelse break;
            defer entry.deinit();
            std.debug.print("  LSN {d}: {s}\n", .{ entry.lsn, entry.payload });
        }
    }

    // Close and reopen — recovery restores the LSN.
    log.deinit();
    log = try wal.WriteAheadLog.init(allocator, cwd, "demo.wal", .{});

    std.debug.print("\nAfter reopen: current LSN = {d}\n", .{log.currentLsn()});

    // Compact away records with LSN <= 2.
    try log.compact(2);
    std.debug.print("Compacted (kept LSN > 2)\n", .{});

    // Iterate after compaction — only LSN 3 remains.
    {
        var iter = try log.iterator(0);
        defer iter.deinit();

        std.debug.print("\nRecords after compaction:\n", .{});
        while (true) {
            var entry = try iter.next() orelse break;
            defer entry.deinit();
            std.debug.print("  LSN {d}: {s}\n", .{ entry.lsn, entry.payload });
        }
    }

    log.deinit();

    // Clean up the demo file.
    cwd.deleteFile("demo.wal") catch {};
    std.debug.print("\nDone.\n", .{});
}
