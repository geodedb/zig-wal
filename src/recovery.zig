// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Crash recovery for the WAL.
//!
//! Scans a WAL file forward from byte 0, validates each record's CRC, and
//! returns the position and LSN of the last valid record. The file is NOT
//! modified by this module; truncation is the caller's responsibility.
//!
//! ## Algorithm
//!
//! ```
//! seek to 0
//! loop:
//!   read header (12 bytes) → if short, break (EOF or torn header)
//!   read payload + CRC footer (payload_len + 4 bytes)
//!   if short read, break (torn write in payload/CRC)
//!   verify CRC over header bytes + payload bytes
//!   if CRC mismatch, break (on-disk corruption)
//!   update last_lsn, valid_end, record_count
//! return info
//! ```

const std = @import("std");
const Crc32IsoHdlc = std.hash.crc.Crc32IsoHdlc;
const record = @import("record.zig");
const encryption = @import("encryption.zig");

// ============================================================================
// Constants
// ============================================================================

/// Stack buffer threshold for recovery payload reads: payloads at or below
/// this size are read into a stack buffer to avoid heap allocation.
const STACK_READ_THRESHOLD: usize = 64 * 1024;

// ============================================================================
// Types
// ============================================================================

/// Summary of a WAL file scan produced by `recover`.
pub const RecoveryInfo = struct {
    /// Highest valid LSN found during the scan, or 0 if the file is empty
    /// or contains no valid records.
    last_lsn: u64,
    /// File offset immediately after the last valid record. This is the
    /// position at which the next append should write, and the position at
    /// which the file should be truncated to discard any trailing corruption.
    valid_end: u64,
    /// Number of valid records found during the scan.
    record_count: u64,
};

// ============================================================================
// Public API
// ============================================================================

/// Scan `file` from the beginning, validating each record's CRC.
///
/// Stops at the first incomplete read (torn write) or CRC mismatch and
/// returns information about the last fully-valid record boundary.
///
/// The file position is left at the end of the last valid record
/// (i.e., at `valid_end`). The file is NOT truncated or otherwise modified.
///
/// `allocator` is used only for payload reads that exceed `STACK_READ_THRESHOLD`
/// (64 KB). For typical small payloads no heap allocation occurs.
///
/// This function handles **plaintext records only**.  For WAL files that may
/// contain encrypted records, use `recoverWithKey`.
pub fn recover(allocator: std.mem.Allocator, file: std.fs.File) !RecoveryInfo {
    return recoverWithKey(allocator, file, null);
}

/// Scan `file` from the beginning, handling both plaintext and encrypted
/// records.
///
/// When `key` is non-null, any record that begins with the encryption magic
/// bytes is decrypted so that the inner LSN can be extracted.  If `key` is
/// null the function behaves identically to `recover` (plaintext-only).
///
/// All other semantics (stopping at the first invalid record, not modifying
/// the file, etc.) are the same as `recover`.
pub fn recoverWithKey(
    allocator: std.mem.Allocator,
    file: std.fs.File,
    key: ?*const [32]u8,
) !RecoveryInfo {
    // Seek to the beginning of the file before scanning.
    try file.seekTo(0);

    var info = RecoveryInfo{
        .last_lsn = 0,
        .valid_end = 0,
        .record_count = 0,
    };

    while (true) {
        // ── Peek: detect encrypted vs plaintext ──────────────────────────────
        // Read the first 12 bytes to decide which parsing path to take.
        // For encrypted records bytes [4..12] contain the MAGIC.
        // For plaintext records this is the standard header.
        var peek_buf: [12]u8 = undefined;
        const peek_n = try file.readAll(&peek_buf);
        if (peek_n < 12) {
            // EOF or torn write — stop scanning.
            break;
        }

        if (key != null and encryption.isEncrypted(&peek_buf)) {
            // ── Encrypted record path ───────────────────────────────────────
            // The first 4 bytes we just read are blob_len (u32 LE).
            const blob_len = std.mem.readInt(u32, peek_buf[0..4], .little);
            const total_on_disk = @as(u64, encryption.BLOB_LEN_SIZE) + @as(u64, blob_len);

            // We already consumed 12 bytes of the blob via peek; the remaining
            // bytes are (total_on_disk - 12).
            if (total_on_disk < 12) break; // corrupt blob_len
            const remaining = total_on_disk - 12;

            // Allocate a contiguous buffer for the full encrypted blob.
            const blob_buf = try allocator.alloc(u8, @intCast(total_on_disk));
            defer allocator.free(blob_buf);

            // Copy the 12 bytes we already read into the front.
            @memcpy(blob_buf[0..12], &peek_buf);

            // Read the rest from disk.
            if (remaining > 0) {
                const rest_n = try file.readAll(blob_buf[12..]);
                if (rest_n < @as(usize, @intCast(remaining))) break; // torn write
            }

            // Decrypt in-place to get the inner plaintext record bytes (PERF-0003).
            const plaintext = encryption.decryptRecordInPlace(key.?, blob_buf) catch {
                break; // decryption failure — treat as end-of-valid-log
            };

            // Deserialize the inner record to extract the LSN and verify CRC.
            const rec = record.deserialize(plaintext) catch {
                break; // inner record corrupt
            };

            // ── Valid encrypted record — update scan state ─────────────────
            info.last_lsn = rec.lsn;
            info.record_count += 1;
            info.valid_end += total_on_disk;
        } else {
            // ── Plaintext record path (unchanged logic) ─────────────────────
            // The 12 bytes we just read are the standard header.
            const header_buf: [record.HEADER_SIZE]u8 = peek_buf;

            const lsn = std.mem.readInt(u64, header_buf[0..8], .little);
            const payload_len = std.mem.readInt(u32, header_buf[8..12], .little);
            const tail_len = @as(usize, payload_len) + record.CRC_SIZE;

            if (tail_len <= STACK_READ_THRESHOLD + record.CRC_SIZE) {
                var stack_buf: [STACK_READ_THRESHOLD + record.CRC_SIZE]u8 = undefined;
                const tail = stack_buf[0..tail_len];

                const n = try file.readAll(tail);
                if (n < tail_len) break;

                if (!verifyCrc(header_buf, tail[0..payload_len], tail[payload_len..])) break;
            } else {
                const heap_buf = try allocator.alloc(u8, tail_len);
                defer allocator.free(heap_buf);

                const n = try file.readAll(heap_buf);
                if (n < tail_len) break;

                const payload_slice = heap_buf[0..payload_len];
                const crc_slice = heap_buf[payload_len..];
                if (!verifyCrc(header_buf, payload_slice, crc_slice)) break;
            }

            info.last_lsn = lsn;
            info.record_count += 1;
            info.valid_end += @as(u64, record.HEADER_SIZE) + @as(u64, payload_len) + @as(u64, record.CRC_SIZE);
        }
    }

    return info;
}

// ============================================================================
// Internal helpers
// ============================================================================

/// Verify the CRC32 of a record given its raw header bytes, payload bytes,
/// and the 4-byte stored CRC slice. Returns `true` if the CRC matches.
inline fn verifyCrc(
    header_buf: [record.HEADER_SIZE]u8,
    payload: []const u8,
    crc_bytes: []const u8,
) bool {
    std.debug.assert(crc_bytes.len >= record.CRC_SIZE);
    const stored_crc = std.mem.readInt(u32, crc_bytes[0..4], .little);
    var h = Crc32IsoHdlc.init();
    h.update(&header_buf);
    h.update(payload);
    const computed_crc = h.final();
    return stored_crc == computed_crc;
}

// ============================================================================
// Tests
// ============================================================================

test "recover: empty file returns zero state" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const file = try tmp.dir.createFile("wal.log", .{ .read = true });
    defer file.close();

    const info = try recover(allocator, file);

    try std.testing.expectEqual(@as(u64, 0), info.last_lsn);
    try std.testing.expectEqual(@as(u64, 0), info.valid_end);
    try std.testing.expectEqual(@as(u64, 0), info.record_count);
}

test "recover: single valid record" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const file = try tmp.dir.createFile("wal.log", .{ .read = true });
    defer file.close();

    const payload = "hello, WAL!";
    const bytes_written = try record.writeToFile(file, allocator, 1, payload);

    const info = try recover(allocator, file);

    try std.testing.expectEqual(@as(u64, 1), info.last_lsn);
    try std.testing.expectEqual(@as(u64, bytes_written), info.valid_end);
    try std.testing.expectEqual(@as(u64, 1), info.record_count);
}

test "recover: multiple records" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const file = try tmp.dir.createFile("wal.log", .{ .read = true });
    defer file.close();

    var total_bytes: u64 = 0;
    total_bytes += try record.writeToFile(file, allocator, 1, "alpha");
    total_bytes += try record.writeToFile(file, allocator, 2, "beta");
    total_bytes += try record.writeToFile(file, allocator, 3, "gamma");

    const info = try recover(allocator, file);

    try std.testing.expectEqual(@as(u64, 3), info.last_lsn);
    try std.testing.expectEqual(total_bytes, info.valid_end);
    try std.testing.expectEqual(@as(u64, 3), info.record_count);
}

test "recover: torn write — incomplete header" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const file = try tmp.dir.createFile("wal.log", .{ .read = true });
    defer file.close();

    // Write one valid record, then append only 6 bytes of what would be a
    // second header (incomplete — the header is 12 bytes).
    const bytes_written = try record.writeToFile(file, allocator, 1, "good");
    try file.writeAll(&[_]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x00 }); // partial header

    const info = try recover(allocator, file);

    // Only the first record is valid; the incomplete header is torn.
    try std.testing.expectEqual(@as(u64, 1), info.last_lsn);
    try std.testing.expectEqual(bytes_written, info.valid_end);
    try std.testing.expectEqual(@as(u64, 1), info.record_count);
}

test "recover: torn write — valid record then incomplete payload" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const file = try tmp.dir.createFile("wal.log", .{ .read = true });
    defer file.close();

    // Write one valid record.
    const bytes_written = try record.writeToFile(file, allocator, 1, "good");

    // Write a complete header for a second record (claiming 10 bytes of
    // payload), but provide only 4 bytes of that payload — torn write.
    var torn_header: [record.HEADER_SIZE]u8 = undefined;
    std.mem.writeInt(u64, torn_header[0..8], 2, .little);
    std.mem.writeInt(u32, torn_header[8..12], 10, .little);
    try file.writeAll(&torn_header);
    try file.writeAll(&[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF }); // only 4 of 10 payload bytes

    const info = try recover(allocator, file);

    // Only the first record is valid.
    try std.testing.expectEqual(@as(u64, 1), info.last_lsn);
    try std.testing.expectEqual(bytes_written, info.valid_end);
    try std.testing.expectEqual(@as(u64, 1), info.record_count);
}

test "recover: corrupt CRC stops scan" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const file = try tmp.dir.createFile("wal.log", .{ .read = true });
    defer file.close();

    // Write one valid record.
    const bytes_written = try record.writeToFile(file, allocator, 1, "good");

    // Serialize a second record, corrupt its CRC, then write it.
    const payload = "corrupt";
    const second_buf = try record.serialize(allocator, 2, payload);
    defer allocator.free(second_buf);

    // Flip a bit in the CRC footer (last 4 bytes).
    var corrupt_buf = try allocator.dupe(u8, second_buf);
    defer allocator.free(corrupt_buf);
    corrupt_buf[corrupt_buf.len - 1] ^= 0xFF;

    try file.writeAll(corrupt_buf);

    const info = try recover(allocator, file);

    // Only the first record is valid; the second has a bad CRC.
    try std.testing.expectEqual(@as(u64, 1), info.last_lsn);
    try std.testing.expectEqual(bytes_written, info.valid_end);
    try std.testing.expectEqual(@as(u64, 1), info.record_count);
}
