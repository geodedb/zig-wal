// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Optional AES-256-GCM per-record encryption layer.
//!
//! All functions are pure (no file I/O). Callers are responsible for key
//! management and for freeing allocator-owned slices returned by
//! `encryptRecord` and `decryptRecord`.
//!
//! Encrypted record format on disk:
//! ```
//! [blob_len: u32 LE][magic: "ZIGWALE\x00" (8)][nonce: (12)][tag: (16)][ciphertext]
//! ```
//! - `blob_len` is the byte count of everything AFTER the blob_len field
//!   (magic + nonce + tag + ciphertext).
//! - Total overhead per record: 4 + 8 + 12 + 16 = 40 bytes (plus ciphertext
//!   which is the same length as the plaintext).

const std = @import("std");
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;

// ============================================================================
// Constants
// ============================================================================

/// Magic bytes written at offset 4 of every encrypted record.
pub const MAGIC: [8]u8 = "ZIGWALE\x00".*;

/// Size of the magic field in bytes.
pub const MAGIC_SIZE: usize = 8;

/// Size of the AES-256-GCM nonce in bytes (96-bit random nonce).
pub const NONCE_SIZE: usize = Aes256Gcm.nonce_length; // 12

/// Size of the AES-256-GCM authentication tag in bytes.
pub const TAG_SIZE: usize = Aes256Gcm.tag_length; // 16

/// Size of the blob_len prefix field in bytes.
pub const BLOB_LEN_SIZE: usize = 4;

/// Total per-record overhead (blob_len + magic + nonce + tag).
/// The ciphertext is the same length as the plaintext, so total encrypted
/// record size = `ENCRYPTION_OVERHEAD + plaintext.len`.
pub const ENCRYPTION_OVERHEAD: usize = BLOB_LEN_SIZE + MAGIC_SIZE + NONCE_SIZE + TAG_SIZE; // 40

// Byte offsets within a serialised encrypted record.
const OFF_BLOB_LEN: usize = 0; // u32 LE at [0..4]
const OFF_MAGIC: usize = 4; // [4..12]
const OFF_NONCE: usize = 12; // [12..24]
const OFF_TAG: usize = 24; // [24..40]
const OFF_CIPHERTEXT: usize = 40; // [40..]

// ============================================================================
// Errors
// ============================================================================

pub const EncryptionError = error{
    /// The blob_len field, magic bytes, or overall buffer size is wrong.
    InvalidEncryptedRecord,
    /// AES-256-GCM authentication tag verification failed (wrong key or
    /// tampered data).
    DecryptionFailed,
    /// The environment variable value is not a valid 64-hex-digit key.
    InvalidKey,
};

// ============================================================================
// Core functions
// ============================================================================

/// Encrypt `plaintext` with AES-256-GCM using `key`.
///
/// Returns a newly allocated buffer containing the full encrypted record:
/// ```
/// [blob_len: u32 LE][magic (8)][nonce (12)][tag (16)][ciphertext]
/// ```
/// The caller owns the returned slice and must free it with `allocator.free`.
pub fn encryptRecord(
    allocator: std.mem.Allocator,
    key: *const [32]u8,
    plaintext: []const u8,
) ![]u8 {
    const total_len = ENCRYPTION_OVERHEAD + plaintext.len;
    const buf = try allocator.alloc(u8, total_len);
    errdefer allocator.free(buf);

    // blob_len = everything after the blob_len field itself.
    const blob_len: u32 = @intCast(MAGIC_SIZE + NONCE_SIZE + TAG_SIZE + plaintext.len);
    std.mem.writeInt(u32, buf[OFF_BLOB_LEN..][0..4], blob_len, .little);

    // Write magic.
    @memcpy(buf[OFF_MAGIC..][0..MAGIC_SIZE], &MAGIC);

    // Generate a random 96-bit nonce.
    var nonce: [NONCE_SIZE]u8 = undefined;
    std.crypto.random.bytes(&nonce);
    @memcpy(buf[OFF_NONCE..][0..NONCE_SIZE], &nonce);

    // Encrypt in-place into the ciphertext region; write tag at OFF_TAG.
    var tag: [TAG_SIZE]u8 = undefined;
    const ct = buf[OFF_CIPHERTEXT..][0..plaintext.len];
    Aes256Gcm.encrypt(ct, &tag, plaintext, &.{}, nonce, key.*);
    @memcpy(buf[OFF_TAG..][0..TAG_SIZE], &tag);

    return buf;
}

/// Decrypt an encrypted record previously produced by `encryptRecord`.
///
/// Returns a newly allocated buffer containing the plaintext.
/// The caller owns the returned slice and must free it with `allocator.free`.
///
/// Errors:
/// - `error.InvalidEncryptedRecord` — buffer too short, bad blob_len, or
///   magic mismatch.
/// - `error.DecryptionFailed` — AES-256-GCM authentication failed (wrong key
///   or tampered ciphertext / tag).
pub fn decryptRecord(
    allocator: std.mem.Allocator,
    key: *const [32]u8,
    blob: []const u8,
) ![]u8 {
    // Must be at least large enough to hold the fixed overhead with empty
    // ciphertext.
    if (blob.len < ENCRYPTION_OVERHEAD) return error.InvalidEncryptedRecord;

    // Verify blob_len field matches actual remaining bytes.
    const stored_blob_len = std.mem.readInt(u32, blob[OFF_BLOB_LEN..][0..4], .little);
    const expected_blob_len: u32 = @intCast(blob.len - BLOB_LEN_SIZE);
    if (stored_blob_len != expected_blob_len) return error.InvalidEncryptedRecord;

    // Verify magic.
    if (!std.mem.eql(u8, blob[OFF_MAGIC..][0..MAGIC_SIZE], &MAGIC)) {
        return error.InvalidEncryptedRecord;
    }

    // Extract nonce, tag, and ciphertext.
    const nonce: [NONCE_SIZE]u8 = blob[OFF_NONCE..][0..NONCE_SIZE].*;
    const tag: [TAG_SIZE]u8 = blob[OFF_TAG..][0..TAG_SIZE].*;
    const ciphertext = blob[OFF_CIPHERTEXT..];

    // Allocate plaintext buffer.
    const plaintext = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(plaintext);

    Aes256Gcm.decrypt(plaintext, ciphertext, tag, &.{}, nonce, key.*) catch {
        return error.DecryptionFailed;
    };

    return plaintext;
}

/// Return true if `buf` begins with the encrypted record magic bytes at
/// offset 4.  Does NOT validate blob_len or authenticate the record.
pub fn isEncrypted(buf: []const u8) bool {
    if (buf.len < OFF_MAGIC + MAGIC_SIZE) return false;
    return std.mem.eql(u8, buf[OFF_MAGIC..][0..MAGIC_SIZE], &MAGIC);
}

/// Read a 64-hex-character AES-256 key from environment variable `env_var`.
///
/// Returns:
/// - `null` if the environment variable is not set.
/// - `error.InvalidKey` if the value is present but not exactly 64 hex digits.
/// - A `[32]u8` key on success.
pub fn loadKeyFromEnv(env_var: []const u8) EncryptionError!?[32]u8 {
    const hex_str = std.posix.getenv(env_var) orelse return null;

    // A 256-bit key encoded as hex must be exactly 64 characters.
    if (hex_str.len != 64) return error.InvalidKey;

    var key: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&key, hex_str) catch return error.InvalidKey;
    return key;
}

// ============================================================================
// Tests
// ============================================================================

const record = @import("record.zig");

test "encrypt/decrypt: round-trip" {
    const allocator = std.testing.allocator;
    const plaintext = "hello, encrypted WAL!";

    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    const encrypted = try encryptRecord(allocator, &key, plaintext);
    defer allocator.free(encrypted);

    const decrypted = try decryptRecord(allocator, &key, encrypted);
    defer allocator.free(decrypted);

    try std.testing.expectEqualSlices(u8, plaintext, decrypted);
}

test "encrypt/decrypt: empty plaintext" {
    const allocator = std.testing.allocator;

    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    const encrypted = try encryptRecord(allocator, &key, &.{});
    defer allocator.free(encrypted);

    try std.testing.expectEqual(ENCRYPTION_OVERHEAD, encrypted.len);

    const decrypted = try decryptRecord(allocator, &key, encrypted);
    defer allocator.free(decrypted);

    try std.testing.expectEqual(@as(usize, 0), decrypted.len);
}

test "decryptRecord: wrong key returns DecryptionFailed" {
    const allocator = std.testing.allocator;
    const plaintext = "secret data";

    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    const encrypted = try encryptRecord(allocator, &key, plaintext);
    defer allocator.free(encrypted);

    var wrong_key: [32]u8 = undefined;
    std.crypto.random.bytes(&wrong_key);
    // Ensure keys are different (astronomically unlikely to collide, but be safe).
    wrong_key[0] ^= 0xFF;

    const result = decryptRecord(allocator, &wrong_key, encrypted);
    try std.testing.expectError(error.DecryptionFailed, result);
}

test "isEncrypted: detects encrypted blob" {
    const allocator = std.testing.allocator;

    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    const encrypted = try encryptRecord(allocator, &key, "test");
    defer allocator.free(encrypted);

    try std.testing.expect(isEncrypted(encrypted));
}

test "isEncrypted: plaintext record returns false" {
    const allocator = std.testing.allocator;

    const plain = try record.serialize(allocator, 1, "test payload");
    defer allocator.free(plain);

    try std.testing.expect(!isEncrypted(plain));
}

test "decryptRecord: truncated blob returns InvalidEncryptedRecord" {
    const allocator = std.testing.allocator;

    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    const encrypted = try encryptRecord(allocator, &key, "some data");
    defer allocator.free(encrypted);

    // A slice shorter than ENCRYPTION_OVERHEAD must be rejected.
    const truncated = encrypted[0 .. ENCRYPTION_OVERHEAD - 1];
    const result = decryptRecord(allocator, &key, truncated);
    try std.testing.expectError(error.InvalidEncryptedRecord, result);
}
