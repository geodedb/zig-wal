// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Fuzz tests for binary parsing entrypoints (SEC-0040).
//!
//! These tests exercise `record.deserialize`, `encryption.decryptRecord`,
//! `encryption.decryptRecordInPlace`, and `encryption.isEncrypted` with
//! arbitrary byte sequences to surface crashes, undefined behaviour, or
//! panics caused by malformed input.
//!
//! When run under `zig build test-fuzz` the fuzz engine generates random
//! inputs.  In regular `zig build test` mode the tests execute the seed
//! corpus deterministically and pass immediately.

const std = @import("std");
const wal = @import("wal");

// Internal/unstable modules used for fuzz testing (QA-0053).
const record = wal.record;
const encryption = wal.encryption;

/// Deterministic test key for decryption fuzz targets.
const fuzz_key: [32]u8 = .{
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
};

// ============================================================================
// Fuzz targets
// ============================================================================

test "fuzz: record.deserialize rejects arbitrary bytes without crashing" {
    try std.testing.fuzz(.{}, struct {
        fn testOne(_: @TypeOf(.{}), input: []const u8) !void {
            // Must not crash regardless of input — errors are expected and fine.
            _ = record.deserialize(input) catch return;
        }
    }.testOne, .{});
}

test "fuzz: encryption.decryptRecord rejects arbitrary bytes without crashing" {
    try std.testing.fuzz(.{}, struct {
        fn testOne(_: @TypeOf(.{}), input: []const u8) !void {
            const allocator = std.testing.allocator;
            const key = fuzz_key;
            const result = encryption.decryptRecord(allocator, &key, input) catch return;
            // If decryption somehow succeeded, free the result.
            allocator.free(result);
        }
    }.testOne, .{});
}

test "fuzz: encryption.decryptRecordInPlace rejects arbitrary bytes without crashing" {
    try std.testing.fuzz(.{}, struct {
        fn testOne(_: @TypeOf(.{}), input: []const u8) !void {
            const allocator = std.testing.allocator;
            const key = fuzz_key;
            // decryptRecordInPlace needs a mutable buffer — duplicate.
            if (input.len == 0) return;
            const buf = try allocator.dupe(u8, input);
            defer allocator.free(buf);
            _ = encryption.decryptRecordInPlace(&key, buf) catch return;
        }
    }.testOne, .{});
}

test "fuzz: encryption.isEncrypted handles arbitrary bytes without crashing" {
    try std.testing.fuzz(.{}, struct {
        fn testOne(_: @TypeOf(.{}), input: []const u8) !void {
            // Pure function, must never crash.
            _ = encryption.isEncrypted(input);
        }
    }.testOne, .{});
}
