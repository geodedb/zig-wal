// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

const std = @import("std");
const builtin = @import("builtin");

// POSIX mode bits and Windows file attributes are distinct APIs. On Windows,
// access control comes from the containing directory's inherited ACL.
pub const has_posix_permissions = @hasDecl(std.Io.File.Permissions, "fromMode");
pub const private_permissions: std.Io.File.Permissions = if (has_posix_permissions)
    .fromMode(0o600)
else
    .default_file;

/// Position the streaming write cursor at `offset`. Appends use streaming
/// writes, so a cursor left anywhere else would place the next record off the
/// record boundary (SONNY-6620). Portable: std's Io seek, not libc `lseek`,
/// which takes an fd and cannot address a Windows HANDLE.
pub fn seekTo(file: std.Io.File, offset: u64) std.Io.File.SeekError!void {
    const io = std.Io.Threaded.global_single_threaded.io();
    return io.vtable.fileSeekTo(io.userdata, file, offset);
}

/// Preserve the data-only POSIX flush; Windows uses FlushFileBuffers via Io.
pub fn syncData(file: std.Io.File) !void {
    if (builtin.os.tag == .windows) {
        try file.sync(std.Io.Threaded.global_single_threaded.io());
    } else {
        try std.posix.fdatasync(file.handle);
    }
}
