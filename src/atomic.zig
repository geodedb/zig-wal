// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Atomic file write utility using the temp+fsync+rename pattern.
//!
//! This ensures that a file is either fully written or not written at all,
//! preventing partial writes from leaving the file in a corrupt state.

const std = @import("std");

/// Atomically writes `data` to `filename` within `dir`.
///
/// The write is performed by:
///   1. Creating (or truncating) a temporary file "`filename`.tmp" in `dir`
///   2. Writing all `data` to the temporary file
///   3. fsync-ing the temporary file to flush OS buffers to disk
///   4. Closing the temporary file
///   5. Renaming "`filename`.tmp" to `filename` (atomic on POSIX via renameat)
///
/// The temp file is derived from `filename` by appending ".tmp", so two
/// concurrent `atomicWriteFile` calls for different filenames in the same
/// directory will not collide on the same temp file.
///
/// On any error the temporary file is closed and deleted before returning.
///
/// Note: This function is NOT thread-safe. Callers must synchronize concurrent
/// calls that target the same directory and same filename.
///
/// Returns `error.FilenameTooLong` if `filename` is too long to derive a
/// temp name from (limit: 251 bytes for the base name).
pub fn atomicWriteFile(dir: std.fs.Dir, filename: []const u8, data: []const u8) !void {
    var tmp_name_buf: [256]u8 = undefined;
    const tmp_name = std.fmt.bufPrint(&tmp_name_buf, "{s}.tmp", .{filename}) catch return error.FilenameTooLong;

    var tmp_file = try dir.createFile(tmp_name, .{ .truncate = true });
    errdefer {
        tmp_file.close();
        dir.deleteFile(tmp_name) catch {};
    }

    try tmp_file.writeAll(data);
    try tmp_file.sync();
    tmp_file.close();

    try dir.rename(tmp_name, filename);
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
