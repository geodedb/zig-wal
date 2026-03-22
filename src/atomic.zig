// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Atomic file write utility using the temp+fsync+rename pattern.
//!
//! This ensures that a file is either fully written or not written at all,
//! preventing partial writes from leaving the file in a corrupt state.

const std = @import("std");

/// Maximum buffer size for deriving temporary filenames ("{filename}.tmp").
/// Shared by atomic.zig and compaction.zig (QA-0056).
pub const TMP_NAME_BUF_SIZE = 256;

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
    var tmp_name_buf: [TMP_NAME_BUF_SIZE]u8 = undefined;
    const tmp_name = std.fmt.bufPrint(&tmp_name_buf, "{s}.tmp", .{filename}) catch return error.FilenameTooLong;

    // Remove any pre-existing temp file to prevent symlink attacks (SEC-0005).
    // Note: A narrow TOCTOU window exists between delete and create. A fully
    // race-free solution would require O_TMPFILE+linkat (Linux-specific),
    // which is not available in Zig's std.fs API (SEC-0011).
    dir.deleteFile(tmp_name) catch {};
    var tmp_file = try dir.createFile(tmp_name, .{ .truncate = true, .mode = 0o600 });
    errdefer {
        tmp_file.close();
        dir.deleteFile(tmp_name) catch {};
    }

    try tmp_file.writeAll(data);
    try tmp_file.sync();
    // Rename before close: if rename() fails the fd is still open and the
    // caller's errdefer can close it safely. Closing first would make the
    // errdefer double-close a stale fd → Zig's std.posix.close treats EBADF
    // as unreachable (UB in ReleaseFast/ReleaseSmall, panic otherwise).
    // SEC-0035.
    try dir.rename(tmp_name, filename);
    tmp_file.close();
    // Note: A directory fsync after rename would make the directory entry fully
    // durable on all filesystems. However, Zig's std.fs.Dir opens directories
    // with O_PATH, which does not support fsync. Opening a separate read-only
    // fd for the directory is not possible without knowing the directory's
    // absolute path (which the caller does not provide). On ext4 with the
    // default data=ordered mode, directory renames are journaled and durable
    // without an explicit fsync. On data=writeback or non-journaling
    // filesystems, a narrow durability gap exists (SEC-0020).
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
