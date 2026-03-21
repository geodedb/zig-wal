// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Basic usage example for wal

const std = @import("std");

// Note: When running from the examples directory, you would import like this:
// const lib = @import("wal");

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();

    try stdout.print("wal Example\n", .{});
    try stdout.print("========================\n\n", .{});

    // Example usage:
    // const config = lib.Config{
    //     .debug = true,
    // };
    // try lib.init(config);

    try stdout.print("Example completed successfully!\n", .{});
}
