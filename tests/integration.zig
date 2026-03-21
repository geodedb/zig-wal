// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Integration tests for wal
//!
//! These tests verify end-to-end functionality and cross-module interactions.

const std = @import("std");
const lib = @import("wal");

// ============================================================================
// Integration Tests
// ============================================================================

test "integration: library initializes successfully" {
    try lib.init(.{});
}

test "integration: custom configuration" {
    try lib.init(.{
        .debug = true,
        .max_retries = 5,
        .timeout_ms = 60_000,
    });
}

test "integration: version is defined" {
    try std.testing.expectEqualStrings("0.1.0", lib.version);
}

// ============================================================================
// Test Utilities
// ============================================================================

fn expectSuccess(result: anytype) !void {
    _ = result catch |err| {
        std.debug.print("Unexpected error: {}\n", .{err});
        return error.TestUnexpectedResult;
    };
}
