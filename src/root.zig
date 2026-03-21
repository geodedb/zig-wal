// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # wal
//!
//! A Zig library for wal
//!
//! ## Features
//!
//! - Feature 1
//! - Feature 2
//! - Feature 3
//!
//! ## Quick Start
//!
//! ```zig
//! const wal = @import("wal");
//!
//! pub fn main() !void {
//!     // Your code here
//! }
//! ```
//!
//! ## License
//!
//! Apache-2.0

const std = @import("std");

/// Library version
pub const version = "0.1.0";

// Re-export submodules here as the library grows:
pub const atomic = @import("atomic.zig");
pub const compaction = @import("compaction.zig");
pub const encryption = @import("encryption.zig");
pub const record = @import("record.zig");
pub const recovery = @import("recovery.zig");
pub const wal = @import("wal.zig");

// ============================================================================
// Public Types
// ============================================================================

/// Example configuration structure
pub const Config = struct {
    /// Enable debug output
    debug: bool = false,
    /// Maximum retry attempts
    max_retries: u32 = 3,
    /// Timeout in milliseconds
    timeout_ms: u64 = 30_000,
};

// ============================================================================
// Public Functions
// ============================================================================

/// Initialize the library with the given configuration.
///
/// Returns an error if the configuration is invalid.
pub fn init(config: Config) !void {
    _ = config;
    // Implementation here
}

// ============================================================================
// Unit Tests
// ============================================================================

test "Config default values" {
    const config = Config{};
    try std.testing.expectEqual(false, config.debug);
    try std.testing.expectEqual(@as(u32, 3), config.max_retries);
    try std.testing.expectEqual(@as(u64, 30_000), config.timeout_ms);
}

test "init with default config" {
    try init(.{});
}

test {
    // Ensure all declarations are referenced for test coverage
    std.testing.refAllDecls(@This());
}
