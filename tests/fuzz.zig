// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! Fuzz tests for binary parsing entrypoints (SEC-0040).
//!
//! These tests exercise `record.deserialize`, `encryption.decryptRecord`,
//! `encryption.decryptRecordInPlace`, and `encryption.isEncrypted` with
//! arbitrary byte sequences to surface crashes, undefined behaviour, or
//! panics caused by malformed input.
//!
//! `zig build test-fuzz` runs deterministic seed cases; add `--fuzz` for
//! coverage-guided generation. Inputs are bounded to 64 KiB per invocation.

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
        fn testOne(_: @TypeOf(.{}), smith: *std.testing.Smith) !void {
            var storage: [64 * 1024]u8 = undefined;
            const input = storage[0..smith.slice(&storage)];
            // Must not crash regardless of input — errors are expected and fine.
            _ = record.deserialize(input) catch return;
        }
    }.testOne, .{});
}

test "fuzz: encryption.decryptRecord rejects arbitrary bytes without crashing" {
    try std.testing.fuzz(.{}, struct {
        fn testOne(_: @TypeOf(.{}), smith: *std.testing.Smith) !void {
            var storage: [64 * 1024]u8 = undefined;
            const input = storage[0..smith.slice(&storage)];
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
        fn testOne(_: @TypeOf(.{}), smith: *std.testing.Smith) !void {
            var storage: [64 * 1024]u8 = undefined;
            const input = storage[0..smith.slice(&storage)];
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
        fn testOne(_: @TypeOf(.{}), smith: *std.testing.Smith) !void {
            var storage: [64 * 1024]u8 = undefined;
            const input = storage[0..smith.slice(&storage)];
            // Pure function, must never crash.
            _ = encryption.isEncrypted(input);
        }
    }.testOne, .{});
}
