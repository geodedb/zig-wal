// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Atomic file write utility using the temp+fsync+rename pattern.
//!
//! This ensures that a file is either fully written or not written at all,
//! preventing partial writes from leaving the file in a corrupt state.

const std = @import("std");

/// The temporary filename used during atomic writes.
const tmp_filename = "wal.tmp";

/// Atomically writes `data` to `filename` within `dir`.
///
/// The write is performed by:
///   1. Creating (or truncating) a temporary file "wal.tmp" in `dir`
///   2. Writing all `data` to the temporary file
///   3. fsync-ing the temporary file to flush OS buffers to disk
///   4. Closing the temporary file
///   5. Renaming "wal.tmp" to `filename` (atomic on POSIX via renameat)
///
/// On any error the temporary file is closed and deleted before returning.
///
/// Note: This function is NOT thread-safe. Callers must synchronize concurrent
/// calls that target the same directory.
pub fn atomicWriteFile(dir: std.fs.Dir, filename: []const u8, data: []const u8) !void {
    var tmp_file = try dir.createFile(tmp_filename, .{ .truncate = true });
    errdefer {
        tmp_file.close();
        dir.deleteFile(tmp_filename) catch {};
    }

    try tmp_file.writeAll(data);
    try tmp_file.sync();
    tmp_file.close();

    try dir.rename(tmp_filename, filename);
}

// ============================================================================
// Unit Tests
// ============================================================================

test "atomicWriteFile: creates file with correct contents" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const content = "hello world";
    try atomicWriteFile(tmp_dir.dir, "test.dat", content);

    const read_back = try tmp_dir.dir.readFileAlloc(std.testing.allocator, "test.dat", 4096);
    defer std.testing.allocator.free(read_back);

    try std.testing.expectEqualStrings(content, read_back);
}

test "atomicWriteFile: overwrites existing file" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try atomicWriteFile(tmp_dir.dir, "test.dat", "version 1");
    try atomicWriteFile(tmp_dir.dir, "test.dat", "version 2");

    const read_back = try tmp_dir.dir.readFileAlloc(std.testing.allocator, "test.dat", 4096);
    defer std.testing.allocator.free(read_back);

    try std.testing.expectEqualStrings("version 2", read_back);
}

test "atomicWriteFile: empty data" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try atomicWriteFile(tmp_dir.dir, "empty.dat", "");

    const read_back = try tmp_dir.dir.readFileAlloc(std.testing.allocator, "empty.dat", 4096);
    defer std.testing.allocator.free(read_back);

    try std.testing.expectEqualStrings("", read_back);
}
