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
const record = @import("record.zig");
const encryption = @import("encryption.zig");

// Guard: plaintext path reinterprets peek buffer as header (QA-0035).
comptime {
    std.debug.assert(encryption.DETECT_PEEK_SIZE == record.HEADER_SIZE);
}

// ============================================================================
// Constants
// ============================================================================

/// Stack buffer threshold for recovery payload reads (QA-0022: unified with
/// record.STACK_WRITE_THRESHOLD — both are 64 KiB for consistent stack usage).
const STACK_READ_THRESHOLD: usize = record.STACK_WRITE_THRESHOLD;

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

/// Incremental recovery: scan `file` starting from a checkpoint position
/// rather than from byte 0 (PERF-0013).
///
/// The checkpoint provides the known-good state up to `start.valid_end`.
/// This function seeks to that position and continues the forward scan,
/// using `start.last_lsn` as the monotonicity baseline.
///
/// If the file is shorter than `start.valid_end`, returns `error.CheckpointStale`
/// so the caller can fall back to a full scan.
pub fn recoverFrom(
    allocator: std.mem.Allocator,
    file: std.fs.File,
    start: RecoveryInfo,
) !RecoveryInfo {
    return recoverFromWithKey(allocator, file, start, null);
}

/// Incremental recovery with encryption key support (PERF-0013).
///
/// Returns `error.CheckpointStale` if the file is shorter than
/// `start.valid_end`, indicating the checkpoint is no longer valid.
pub fn recoverFromWithKey(
    allocator: std.mem.Allocator,
    file: std.fs.File,
    start: RecoveryInfo,
    key: ?*const [32]u8,
) !RecoveryInfo {
    // Verify the file is at least as large as the checkpoint claims.
    const stat = try file.stat();
    if (stat.size < start.valid_end) return error.CheckpointStale;

    // Seek to the checkpoint position and scan forward.
    try file.seekTo(start.valid_end);

    // Seed the scan state from the checkpoint.
    // If the checkpoint has a non-zero last_lsn, ensure record_count > 0
    // so the monotonicity guard is active from the first incremental record.
    // Without this, a crafted record with LSN <= last_lsn appended after the
    // checkpoint would be accepted (SEC audit NEW-1).
    var info = start;
    if (info.last_lsn > 0 and info.record_count == 0) {
        info.record_count = 1;
    }

    // Reusable buffer for encrypted record reads (PERF-0016).
    var reuse_buf: ?[]u8 = null;
    defer if (reuse_buf) |buf| {
        encryption.secureZero(buf); // SEC-0029
        allocator.free(buf);
    };

    while (true) {
        var peek_buf: [encryption.DETECT_PEEK_SIZE]u8 = undefined;
        const peek_n = try file.readAll(&peek_buf);
        if (peek_n < encryption.DETECT_PEEK_SIZE) break;

        if (key != null and encryption.isEncrypted(&peek_buf)) {
            const blob_result = try encryption.readEncryptedBlobReuse(allocator, file, &peek_buf, &reuse_buf) orelse break;
            const plaintext = encryption.decryptRecordInPlace(key.?, blob_result.blob) catch break;
            const rec = record.deserialize(plaintext) catch break;

            if (info.record_count > 0 and rec.lsn <= info.last_lsn) break;
            info.last_lsn = rec.lsn;
            info.record_count += 1;
            info.valid_end += blob_result.total_on_disk;
        } else if (key != null) {
            break; // SEC-0038
        } else {
            const header_buf: [record.HEADER_SIZE]u8 = peek_buf;
            const lsn = std.mem.readInt(u64, header_buf[0..8], .little);
            const payload_len = std.mem.readInt(u32, header_buf[8..12], .little);
            const tail_len = @as(usize, payload_len) + record.CRC_SIZE;

            if (record.HEADER_SIZE + tail_len > record.MAX_RECORD_SIZE) break;

            if (tail_len <= STACK_READ_THRESHOLD + record.CRC_SIZE) {
                var stack_buf: [STACK_READ_THRESHOLD + record.CRC_SIZE]u8 = undefined;
                const tail = stack_buf[0..tail_len];
                const n = try file.readAll(tail);
                if (n < tail_len) break;
                if (!record.verifyCrc(header_buf, tail[0..payload_len], tail[payload_len..])) break;
            } else {
                const heap_buf = try allocator.alloc(u8, tail_len);
                defer allocator.free(heap_buf);
                const n = try file.readAll(heap_buf);
                if (n < tail_len) break;
                if (!record.verifyCrc(header_buf, heap_buf[0..payload_len], heap_buf[payload_len..])) break;
            }

            if (info.record_count > 0 and lsn <= info.last_lsn) break;
            info.last_lsn = lsn;
            info.record_count += 1;
            info.valid_end += @as(u64, record.HEADER_SIZE) + @as(u64, payload_len) + @as(u64, record.CRC_SIZE);
        }
    }

    try file.seekTo(info.valid_end);
    return info;
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

    // Reusable buffer for encrypted record reads — avoids per-record
    // allocation churn during scan (PERF-0016).
    var reuse_buf: ?[]u8 = null;
    defer if (reuse_buf) |buf| {
        encryption.secureZero(buf); // SEC-0029
        allocator.free(buf);
    };

    while (true) {
        // ── Peek: detect encrypted vs plaintext ──────────────────────────────
        // Read DETECT_PEEK_SIZE bytes (blob_len + magic) to decide which
        // parsing path to take (QA-0014).
        var peek_buf: [encryption.DETECT_PEEK_SIZE]u8 = undefined;
        const peek_n = try file.readAll(&peek_buf);
        if (peek_n < encryption.DETECT_PEEK_SIZE) {
            // EOF or torn write — stop scanning.
            break;
        }

        if (key != null and encryption.isEncrypted(&peek_buf)) {
            // ── Encrypted record path (QA-0002: shared reader, PERF-0016: reuse buffer) ──
            const blob_result = try encryption.readEncryptedBlobReuse(allocator, file, &peek_buf, &reuse_buf) orelse break;

            // Decrypt in-place to get the inner plaintext record bytes (PERF-0003).
            const plaintext = encryption.decryptRecordInPlace(key.?, blob_result.blob) catch {
                break; // decryption failure — treat as end-of-valid-log
            };

            // Deserialize the inner record to extract the LSN and verify CRC.
            const rec = record.deserialize(plaintext) catch {
                break; // inner record corrupt
            };

            // ── Valid encrypted record — update scan state ─────────────────
            // Reject non-monotonic LSNs as corruption (SEC-0022).
            if (info.record_count > 0 and rec.lsn <= info.last_lsn) break;
            info.last_lsn = rec.lsn;
            info.record_count += 1;
            info.valid_end += blob_result.total_on_disk;
        } else if (key != null) {
            // SEC-0038: encryption key is configured but record lacks magic
            // bytes — reject to prevent plaintext record injection into an
            // encrypted WAL. Stop scanning; treat as end-of-valid-log.
            break;
        } else {
            // ── Plaintext record path (no encryption key) ───────────────────
            // The 12 bytes we just read are the standard header.
            const header_buf: [record.HEADER_SIZE]u8 = peek_buf;

            const lsn = std.mem.readInt(u64, header_buf[0..8], .little);
            const payload_len = std.mem.readInt(u32, header_buf[8..12], .little);
            const tail_len = @as(usize, payload_len) + record.CRC_SIZE;

            // Reject unreasonably large records to prevent OOM (SEC-0004).
            if (record.HEADER_SIZE + tail_len > record.MAX_RECORD_SIZE) break;

            if (tail_len <= STACK_READ_THRESHOLD + record.CRC_SIZE) {
                var stack_buf: [STACK_READ_THRESHOLD + record.CRC_SIZE]u8 = undefined;
                const tail = stack_buf[0..tail_len];

                const n = try file.readAll(tail);
                if (n < tail_len) break;

                if (!record.verifyCrc(header_buf, tail[0..payload_len], tail[payload_len..])) break;
            } else {
                const heap_buf = try allocator.alloc(u8, tail_len);
                defer allocator.free(heap_buf);

                const n = try file.readAll(heap_buf);
                if (n < tail_len) break;

                const payload_slice = heap_buf[0..payload_len];
                const crc_slice = heap_buf[payload_len..];
                if (!record.verifyCrc(header_buf, payload_slice, crc_slice)) break;
            }

            // Reject non-monotonic LSNs as corruption (SEC-0022).
            if (info.record_count > 0 and lsn <= info.last_lsn) break;
            info.last_lsn = lsn;
            info.record_count += 1;
            info.valid_end += @as(u64, record.HEADER_SIZE) + @as(u64, payload_len) + @as(u64, record.CRC_SIZE);
        }
    }

    // Explicitly position file at valid_end so callers can rely on the
    // documented guarantee without depending on scan-loop internals (QA-0027).
    try file.seekTo(info.valid_end);

    return info;
}

// verifyCrc moved to record.zig (QA-0015) — use record.verifyCrc.

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
    const bytes_written = try record.writeToFile(allocator, file, 1, payload);

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
    total_bytes += try record.writeToFile(allocator, file, 1, "alpha");
    total_bytes += try record.writeToFile(allocator, file, 2, "beta");
    total_bytes += try record.writeToFile(allocator, file, 3, "gamma");

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
    const bytes_written = try record.writeToFile(allocator, file, 1, "good");
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
    const bytes_written = try record.writeToFile(allocator, file, 1, "good");

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
    const bytes_written = try record.writeToFile(allocator, file, 1, "good");

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

test "recover: non-monotonic LSN stops scan (SEC-0022)" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const file = try tmp.dir.createFile("wal.log", .{ .read = true });
    defer file.close();

    // Write 3 records with monotonic LSNs: 1, 2, 3.
    const first_size = try record.writeToFile(allocator, file, 1, "one");
    const second_size = try record.writeToFile(allocator, file, 2, "two");
    _ = second_size;
    _ = try record.writeToFile(allocator, file, 3, "three");

    // Overwrite the second record's LSN with 1 (non-monotonic: 1 <= 1).
    // Seek to the start of the second record and write LSN=1.
    try file.seekTo(first_size);
    var lsn_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &lsn_buf, 1, .little);
    try file.writeAll(&lsn_buf);

    // Now rewrite the CRC of the second record so it's valid for the modified LSN.
    // Read the full modified second record, recompute CRC, and write it back.
    try file.seekTo(first_size);
    const payload_str = "two";
    const rec_size = record.HEADER_SIZE + payload_str.len + record.CRC_SIZE;
    var rec_buf: [record.HEADER_SIZE + 3 + record.CRC_SIZE]u8 = undefined;
    const n = try file.readAll(rec_buf[0..rec_size]);
    if (n < rec_size) return error.Unexpected;

    // Recompute CRC over header + payload.
    const crc = std.hash.crc.Crc32IsoHdlc.hash(rec_buf[0 .. record.HEADER_SIZE + payload_str.len]);
    std.mem.writeInt(u32, rec_buf[record.HEADER_SIZE + payload_str.len ..][0..4], crc, .little);

    // Write the fixed record back.
    try file.seekTo(first_size);
    try file.writeAll(rec_buf[0..rec_size]);

    // Recovery should stop at the non-monotonic record (LSN 1 <= 1).
    const info = try recover(allocator, file);

    try std.testing.expectEqual(@as(u64, 1), info.last_lsn);
    try std.testing.expectEqual(@as(u64, first_size), info.valid_end);
    try std.testing.expectEqual(@as(u64, 1), info.record_count);
}

test "recover: oversized payload_len stops scan (SEC-0004/QA-0024)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const file = try tmp.dir.createFile("wal.log", .{ .read = true });
    defer file.close();

    // Write one valid record.
    const bytes_written = try record.writeToFile(allocator, file, 1, "good");

    // Write a crafted header claiming a payload larger than MAX_RECORD_SIZE.
    var bad_header: [record.HEADER_SIZE]u8 = undefined;
    std.mem.writeInt(u64, bad_header[0..8], 2, .little); // LSN 2
    // payload_len that makes total > MAX_RECORD_SIZE:
    // MAX_RECORD_SIZE = 16 * 1024 * 1024, minus HEADER_SIZE(12) minus CRC_SIZE(4) + 1
    const huge_len: u32 = @intCast(record.MAX_RECORD_SIZE - record.HEADER_SIZE - record.CRC_SIZE + 1);
    std.mem.writeInt(u32, bad_header[8..12], huge_len, .little);
    try file.writeAll(&bad_header);

    const info = try recover(allocator, file);

    // Only the first record is valid; the oversized one is rejected.
    try std.testing.expectEqual(@as(u64, 1), info.last_lsn);
    try std.testing.expectEqual(@as(u64, bytes_written), info.valid_end);
    try std.testing.expectEqual(@as(u64, 1), info.record_count);
}

// ============================================================================
// Encrypted recovery tests (QA-0018)
// ============================================================================

/// Deterministic test key for encrypted recovery tests.
const test_key = encryption.test_key;

test "recoverWithKey: empty file returns zero state (QA-0018)" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const file = try tmp.dir.createFile("wal.log", .{ .read = true });
    defer file.close();

    const key = test_key;
    const info = try recoverWithKey(allocator, file, &key);

    try std.testing.expectEqual(@as(u64, 0), info.last_lsn);
    try std.testing.expectEqual(@as(u64, 0), info.valid_end);
    try std.testing.expectEqual(@as(u64, 0), info.record_count);
}

test "recoverWithKey: single encrypted record (QA-0018)" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const file = try tmp.dir.createFile("wal.log", .{ .read = true });
    defer file.close();

    const key = test_key;
    const bytes_written = try encryption.encryptAndWriteToFile(allocator, file, &key, 1, "hello encrypted");

    const info = try recoverWithKey(allocator, file, &key);

    try std.testing.expectEqual(@as(u64, 1), info.last_lsn);
    try std.testing.expectEqual(@as(u64, bytes_written), info.valid_end);
    try std.testing.expectEqual(@as(u64, 1), info.record_count);
}

test "recoverWithKey: multiple encrypted records (QA-0018)" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const file = try tmp.dir.createFile("wal.log", .{ .read = true });
    defer file.close();

    const key = test_key;
    var total_bytes: u64 = 0;
    total_bytes += try encryption.encryptAndWriteToFile(allocator, file, &key, 1, "alpha");
    total_bytes += try encryption.encryptAndWriteToFile(allocator, file, &key, 2, "beta");
    total_bytes += try encryption.encryptAndWriteToFile(allocator, file, &key, 3, "gamma");

    const info = try recoverWithKey(allocator, file, &key);

    try std.testing.expectEqual(@as(u64, 3), info.last_lsn);
    try std.testing.expectEqual(total_bytes, info.valid_end);
    try std.testing.expectEqual(@as(u64, 3), info.record_count);
}

test "recoverWithKey: torn write — incomplete header (QA-0018)" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const file = try tmp.dir.createFile("wal.log", .{ .read = true });
    defer file.close();

    const key = test_key;
    // Write one valid encrypted record, then append only 6 bytes of what
    // would be a second record (incomplete — the peek/header is 12 bytes).
    const bytes_written = try encryption.encryptAndWriteToFile(allocator, file, &key, 1, "good");
    try file.writeAll(&[_]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x00 }); // partial header

    const info = try recoverWithKey(allocator, file, &key);

    // Only the first record is valid; the incomplete header is torn.
    try std.testing.expectEqual(@as(u64, 1), info.last_lsn);
    try std.testing.expectEqual(@as(u64, bytes_written), info.valid_end);
    try std.testing.expectEqual(@as(u64, 1), info.record_count);
}

test "recoverWithKey: torn write — valid record then incomplete payload (QA-0018)" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const file = try tmp.dir.createFile("wal.log", .{ .read = true });
    defer file.close();

    const key = test_key;
    // Write one valid encrypted record.
    const bytes_written = try encryption.encryptAndWriteToFile(allocator, file, &key, 1, "good");

    // Write a fake encrypted record header that claims a large blob_len but
    // only provide a few bytes of data — simulating a torn write mid-record.
    var torn_header: [encryption.DETECT_PEEK_SIZE]u8 = undefined;
    // blob_len = 100 (claiming 100 bytes of content after blob_len field)
    std.mem.writeInt(u32, torn_header[0..4], 100, .little);
    // Write the encryption magic so it's recognised as an encrypted record.
    @memcpy(torn_header[4..12], &encryption.MAGIC);
    try file.writeAll(&torn_header);
    // Only 4 bytes of the remaining 100 — torn write.
    try file.writeAll(&[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF });

    const info = try recoverWithKey(allocator, file, &key);

    // Only the first record is valid.
    try std.testing.expectEqual(@as(u64, 1), info.last_lsn);
    try std.testing.expectEqual(@as(u64, bytes_written), info.valid_end);
    try std.testing.expectEqual(@as(u64, 1), info.record_count);
}

test "recoverWithKey: decryption failure stops scan (QA-0018)" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const file = try tmp.dir.createFile("wal.log", .{ .read = true });
    defer file.close();

    const key = test_key;
    // Write one valid encrypted record.
    const bytes_written = try encryption.encryptAndWriteToFile(allocator, file, &key, 1, "good");

    // Write garbage bytes that look like an encrypted record (valid blob_len
    // and magic) but contain random ciphertext that will fail decryption.
    const garbage_payload_len = 20;
    const garbage_blob_len: u32 = @intCast(encryption.MAGIC_SIZE + encryption.NONCE_SIZE + encryption.TAG_SIZE + garbage_payload_len);
    var garbage: [encryption.BLOB_LEN_SIZE + encryption.MAGIC_SIZE + encryption.NONCE_SIZE + encryption.TAG_SIZE + garbage_payload_len]u8 = undefined;
    // Fill with deterministic garbage.
    for (&garbage, 0..) |*b, i| {
        b.* = @intCast(i % 256);
    }
    // Set valid blob_len and magic so isEncrypted returns true.
    std.mem.writeInt(u32, garbage[0..4], garbage_blob_len, .little);
    @memcpy(garbage[4..12], &encryption.MAGIC);
    try file.writeAll(&garbage);

    const info = try recoverWithKey(allocator, file, &key);

    // Only the first record is valid; the second fails decryption.
    try std.testing.expectEqual(@as(u64, 1), info.last_lsn);
    try std.testing.expectEqual(@as(u64, bytes_written), info.valid_end);
    try std.testing.expectEqual(@as(u64, 1), info.record_count);
}

test "recoverWithKey: non-monotonic LSN stops scan (SEC-0022, QA-0018)" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const file = try tmp.dir.createFile("wal.log", .{ .read = true });
    defer file.close();

    const key = test_key;
    // Write two encrypted records with monotonic LSNs: 1, 2.
    const first_size = try encryption.encryptAndWriteToFile(allocator, file, &key, 1, "one");
    const second_size = try encryption.encryptAndWriteToFile(allocator, file, &key, 2, "two");

    // Write a third encrypted record with LSN 1 (non-monotonic: 1 <= 2).
    // encryptAndWriteToFile embeds the LSN inside the encrypted payload,
    // so recovery will decrypt and find the regressed LSN.
    _ = try encryption.encryptAndWriteToFile(allocator, file, &key, 1, "regression");

    const info = try recoverWithKey(allocator, file, &key);

    // Recovery should accept records 1 and 2, then stop at the third
    // because LSN 1 <= 2.
    try std.testing.expectEqual(@as(u64, 2), info.last_lsn);
    try std.testing.expectEqual(@as(u64, first_size + second_size), info.valid_end);
    try std.testing.expectEqual(@as(u64, 2), info.record_count);
}

test "recoverWithKey: plaintext records rejected when key is present (SEC-0038)" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const file = try tmp.dir.createFile("wal.log", .{ .read = true });
    defer file.close();

    // Write plaintext records (no encryption).
    _ = try record.writeToFile(allocator, file, 1, "plain-1");
    _ = try record.writeToFile(allocator, file, 2, "plain-2");

    // Recover with an encryption key — should reject all plaintext records.
    const key = test_key;
    const info = try recoverWithKey(allocator, file, &key);

    try std.testing.expectEqual(@as(u64, 0), info.last_lsn);
    try std.testing.expectEqual(@as(u64, 0), info.valid_end);
    try std.testing.expectEqual(@as(u64, 0), info.record_count);
}

test "recoverWithKey: encrypted then plaintext stops at boundary (SEC-0038)" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const file = try tmp.dir.createFile("wal.log", .{ .read = true });
    defer file.close();

    const key = test_key;

    // Write 2 encrypted records, then 1 plaintext record.
    const enc1 = try encryption.encryptAndWriteToFile(allocator, file, &key, 1, "enc-1");
    const enc2 = try encryption.encryptAndWriteToFile(allocator, file, &key, 2, "enc-2");
    _ = try record.writeToFile(allocator, file, 3, "plain-3");

    // Recovery should accept the 2 encrypted records, then stop at the
    // plaintext record because the key is present.
    const info = try recoverWithKey(allocator, file, &key);

    try std.testing.expectEqual(@as(u64, 2), info.last_lsn);
    try std.testing.expectEqual(@as(u64, enc1 + enc2), info.valid_end);
    try std.testing.expectEqual(@as(u64, 2), info.record_count);
}

// ============================================================================
// Incremental recovery tests (PERF-0013)
// ============================================================================

test "recoverFrom: exact checkpoint — no additional records" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const file = try tmp.dir.createFile("wal.log", .{ .read = true });
    defer file.close();

    _ = try record.writeToFile(allocator, file, 1, "one");
    _ = try record.writeToFile(allocator, file, 2, "two");

    // Get the full recovery state.
    const full_info = try recover(allocator, file);

    // Incremental from the same state — should return unchanged.
    const inc_info = try recoverFrom(allocator, file, full_info);
    try std.testing.expectEqual(full_info.last_lsn, inc_info.last_lsn);
    try std.testing.expectEqual(full_info.valid_end, inc_info.valid_end);
    try std.testing.expectEqual(full_info.record_count, inc_info.record_count);
}

test "recoverFrom: picks up new records after checkpoint" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const file = try tmp.dir.createFile("wal.log", .{ .read = true });
    defer file.close();

    _ = try record.writeToFile(allocator, file, 1, "one");
    _ = try record.writeToFile(allocator, file, 2, "two");

    // Snapshot after 2 records.
    const ckpt = try recover(allocator, file);

    // Seek to end and write 2 more records.
    try file.seekTo(ckpt.valid_end);
    _ = try record.writeToFile(allocator, file, 3, "three");
    _ = try record.writeToFile(allocator, file, 4, "four");

    // Incremental recovery should find the 2 new records.
    const inc_info = try recoverFrom(allocator, file, ckpt);
    try std.testing.expectEqual(@as(u64, 4), inc_info.last_lsn);
    try std.testing.expectEqual(@as(u64, 4), inc_info.record_count);
}

test "recoverFrom: stale checkpoint returns error" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const file = try tmp.dir.createFile("wal.log", .{ .read = true });
    defer file.close();

    _ = try record.writeToFile(allocator, file, 1, "one");

    // Create a checkpoint claiming more data than the file has.
    const stale_ckpt = RecoveryInfo{
        .last_lsn = 100,
        .valid_end = 99999,
        .record_count = 50,
    };

    const result = recoverFrom(allocator, file, stale_ckpt);
    try std.testing.expectError(error.CheckpointStale, result);
}

test "recoverFromWithKey: incremental encrypted recovery (PERF-0013)" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const file = try tmp.dir.createFile("wal.log", .{ .read = true });
    defer file.close();

    const key = test_key;
    _ = try encryption.encryptAndWriteToFile(allocator, file, &key, 1, "enc-one");
    _ = try encryption.encryptAndWriteToFile(allocator, file, &key, 2, "enc-two");

    // Checkpoint after 2 encrypted records.
    const ckpt = try recoverWithKey(allocator, file, &key);

    // Write 1 more encrypted record.
    try file.seekTo(ckpt.valid_end);
    _ = try encryption.encryptAndWriteToFile(allocator, file, &key, 3, "enc-three");

    // Incremental recovery should find the new record.
    const inc_info = try recoverFromWithKey(allocator, file, ckpt, &key);
    try std.testing.expectEqual(@as(u64, 3), inc_info.last_lsn);
    try std.testing.expectEqual(@as(u64, 3), inc_info.record_count);
}

test "recoverFrom: rejects non-monotonic LSN at checkpoint boundary (SEC NEW-1)" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const file = try tmp.dir.createFile("wal.log", .{ .read = true });
    defer file.close();

    // Write 3 records: LSNs 1, 2, 3.
    _ = try record.writeToFile(allocator, file, 1, "one");
    _ = try record.writeToFile(allocator, file, 2, "two");
    _ = try record.writeToFile(allocator, file, 3, "three");

    // Create a checkpoint at LSN 3 with record_count=0 (simulating the
    // original bug where deinit always wrote record_count=0).
    const ckpt = RecoveryInfo{
        .last_lsn = 3,
        .valid_end = try file.getPos(),
        .record_count = 0,
    };

    // Append a crafted record with LSN=1 (non-monotonic: 1 <= 3).
    _ = try record.writeToFile(allocator, file, 1, "regression");

    // Incremental recovery must reject the non-monotonic record.
    // Before the fix, record_count=0 would bypass the monotonicity guard.
    const inc_info = try recoverFrom(allocator, file, ckpt);
    try std.testing.expectEqual(@as(u64, 3), inc_info.last_lsn);
    try std.testing.expectEqual(ckpt.valid_end, inc_info.valid_end);
}
