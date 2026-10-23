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

/// Preserve the data-only POSIX flush; Windows uses FlushFileBuffers via Io.
pub fn syncData(file: std.Io.File) !void {
    if (builtin.os.tag == .windows) {
        try file.sync(std.Io.Threaded.global_single_threaded.io());
    } else {
        try std.posix.fdatasync(file.handle);
    }
}
