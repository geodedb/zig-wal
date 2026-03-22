// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! WAL compaction: rewrite the log keeping only records with LSN > watermark.
//!
//! Uses a bulk-copy optimisation: because LSNs are monotonically increasing,
//! once the first record that must be kept is located we can block-copy the
//! remainder of the file without parsing each record individually.
//!
//! ## Algorithm
//!
//! 1. Open the source file read-only.
//! 2. Scan forward reading only record headers (12 bytes each), seeking past
//!    payload + CRC without parsing them.
//! 3. Remember the file offset of the first record whose LSN > `up_to_lsn`.
//! 4. If no such record exists → write an empty temp file and rename it over
//!    the original (all records removed).
//! 5. If the first kept record is at offset 0 → all records are already kept;
//!    return immediately without touching the file.
//! 6. Otherwise → create "wal.tmp", seek the source to the first kept offset,
//!    block-copy the rest with a 64 KB buffer, fsync, close, rename.

const std = @import("std");
const record = @import("record.zig");
const encryption = @import("encryption.zig");

// ============================================================================
// Constants
// ============================================================================

/// Copy buffer size for the bulk transfer phase (256 KiB).
/// Increased from 64 KiB to reduce syscall count for large WALs (PERF-0008).
const COPY_BUF_SIZE: usize = 256 * 1024;

// ============================================================================
// Types
// ============================================================================

/// Summary returned by `compact`.
pub const CompactResult = struct {
    /// Number of records written to the compacted file.
    records_kept: u64,
    /// Size of the compacted file in bytes.
    new_size: u64,
};

// ============================================================================
// Public API
// ============================================================================

/// Compact the WAL file at `dir`/`filename`, discarding all records whose
/// LSN is ≤ `up_to_lsn`.
///
/// Pass a non-null `encryption_key` when the WAL was written with AES-256-GCM
/// encryption. The scan phase will correctly interpret the on-disk
/// `[blob_len: u32 LE][magic (8)][nonce (12)][tag (16)][ciphertext]` format
/// and extract each record's LSN via decryption. The bulk-copy phase is
/// format-agnostic and remains unchanged.
///
/// The rewrite is atomic: a temporary file named `filename ++ ".tmp"` is
/// written and fsync-ed before being renamed over the original. If all records
/// are already above the watermark the file is left untouched and a
/// `CompactResult` reflecting the current state is returned.
///
/// No CRC validation is performed during scanning — it is assumed that
/// `recovery.recover` has already validated every record on startup.
pub fn compact(
    allocator: std.mem.Allocator,
    dir: std.fs.Dir,
    filename: []const u8,
    up_to_lsn: u64,
    encryption_key: ?*const [32]u8,
) !CompactResult {
    // Derive the temporary filename from the target filename.
    var tmp_name_buf: [256]u8 = undefined;
    const tmp_name = std.fmt.bufPrint(&tmp_name_buf, "{s}.tmp", .{filename}) catch return error.FilenameTooLong;

    // Open source file for reading.
    const src = try dir.openFile(filename, .{ .mode = .read_only });
    defer src.close();

    // ---- Scan phase ---------------------------------------------------------
    // Walk every record, tracking the offset of the first kept record.
    // Peek at the first 12 bytes to distinguish encrypted from plaintext records.

    var first_kept_offset: ?u64 = null;
    var records_kept: u64 = 0;

    while (true) {
        const offset = try src.getPos();

        // Read 12 bytes to detect the record type.
        var peek_buf: [12]u8 = undefined;
        const peek_n = try src.readAll(&peek_buf);
        if (peek_n < 12) break; // EOF or torn header

        if (encryption_key != null and encryption.isEncrypted(&peek_buf)) {
            // ── Encrypted record path ────────────────────────────────────────
            // peek_buf[0..4] = blob_len (u32 LE).  Total on-disk size is
            // BLOB_LEN_SIZE(4) + blob_len bytes.
            const blob_len = std.mem.readInt(u32, peek_buf[0..4], .little);
            const total_on_disk: usize = encryption.BLOB_LEN_SIZE + @as(usize, blob_len);

            if (total_on_disk < 12) break; // corrupt blob_len

            // Read the remaining bytes of the encrypted blob.
            const remaining = total_on_disk - 12;
            const blob_buf = try allocator.alloc(u8, total_on_disk);
            defer allocator.free(blob_buf);
            @memcpy(blob_buf[0..12], &peek_buf);
            if (remaining > 0) {
                const n = try src.readAll(blob_buf[12..]);
                if (n < remaining) break; // torn write
            }

            // Decrypt in-place to extract LSN — avoids extra allocation (PERF-0003).
            const key = encryption_key.?;
            const plaintext = encryption.decryptRecordInPlace(key, blob_buf) catch break;

            if (plaintext.len < record.HEADER_SIZE) break; // corrupt inner record
            const lsn = std.mem.readInt(u64, plaintext[0..8], .little);

            if (lsn > up_to_lsn) {
                records_kept += 1;
                if (first_kept_offset == null) {
                    first_kept_offset = offset;
                }
            }
        } else {
            // ── Plaintext record path ────────────────────────────────────────
            // peek_buf contains the 12-byte header already consumed.
            const hdr = record.HeaderInfo{
                .lsn = std.mem.readInt(u64, peek_buf[0..8], .little),
                .payload_len = std.mem.readInt(u32, peek_buf[8..12], .little),
            };

            if (hdr.lsn > up_to_lsn) {
                records_kept += 1;
                if (first_kept_offset == null) {
                    first_kept_offset = offset;
                }
            }

            // Seek past payload + CRC without reading them.
            try src.seekBy(@as(i64, @intCast(@as(usize, hdr.payload_len) + record.CRC_SIZE)));
        }
    }

    // ---- Decision phase -----------------------------------------------------

    if (first_kept_offset == null) {
        // Every record is below (or at) the watermark → empty the file.
        const tmp = try dir.createFile(tmp_name, .{ .truncate = true });
        errdefer {
            tmp.close();
            dir.deleteFile(tmp_name) catch {};
        }
        try tmp.sync();
        tmp.close();
        try dir.rename(tmp_name, filename);

        return CompactResult{ .records_kept = 0, .new_size = 0 };
    }

    const kept_offset = first_kept_offset.?;

    if (kept_offset == 0) {
        // All records are above the watermark → nothing to do.
        const stat = try src.stat();
        return CompactResult{
            .records_kept = records_kept,
            .new_size = stat.size,
        };
    }

    // ---- Bulk-copy phase ----------------------------------------------------
    // Seek source back to the first kept record and stream-copy to temp file.
    // This phase is format-agnostic: we copy raw bytes regardless of whether
    // records are encrypted or plaintext.

    try src.seekTo(kept_offset);

    const tmp = try dir.createFile(tmp_name, .{ .truncate = true });
    errdefer {
        tmp.close();
        dir.deleteFile(tmp_name) catch {};
    }

    var copy_buf: [COPY_BUF_SIZE]u8 = undefined;
    var bytes_written: u64 = 0;

    while (true) {
        const n = try src.read(&copy_buf);
        if (n == 0) break;
        try tmp.writeAll(copy_buf[0..n]);
        bytes_written += n;
    }

    try tmp.sync();
    tmp.close();
    try dir.rename(tmp_name, filename);

    return CompactResult{
        .records_kept = records_kept,
        .new_size = bytes_written,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "compact: removes records below watermark" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    // Write 5 records with LSNs 1..5.
    const wf = try tmp_dir.dir.createFile("wal.log", .{ .truncate = true });
    for (1..6) |lsn| {
        _ = try record.writeToFile(wf, allocator, @intCast(lsn), "payload");
    }
    wf.close();

    // Compact: keep only records with LSN > 3.
    const result = try compact(allocator, tmp_dir.dir, "wal.log", 3, null);
    try std.testing.expectEqual(@as(u64, 2), result.records_kept);

    // Re-open and verify only LSNs 4 and 5 remain.
    const rf = try tmp_dir.dir.openFile("wal.log", .{ .mode = .read_only });
    defer rf.close();

    var expected_lsn: u64 = 4;
    while (true) {
        const hdr_result = try record.readHeaderRaw(rf) orelse break;
        const payload = try record.readPayloadAndVerify(rf, allocator, hdr_result.info, hdr_result.raw) orelse break;
        defer allocator.free(payload);

        try std.testing.expectEqual(expected_lsn, hdr_result.info.lsn);
        try std.testing.expectEqualStrings("payload", payload);
        expected_lsn += 1;
    }
    try std.testing.expectEqual(@as(u64, 6), expected_lsn); // saw LSNs 4 and 5
}

test "compact: all records removed" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    // Write 3 records.
    const wf = try tmp_dir.dir.createFile("wal.log", .{ .truncate = true });
    for (1..4) |lsn| {
        _ = try record.writeToFile(wf, allocator, @intCast(lsn), "data");
    }
    wf.close();

    // Compact above max LSN → all records removed.
    const result = try compact(allocator, tmp_dir.dir, "wal.log", 100, null);
    try std.testing.expectEqual(@as(u64, 0), result.records_kept);
    try std.testing.expectEqual(@as(u64, 0), result.new_size);

    // File should exist but be empty.
    const stat = try tmp_dir.dir.statFile("wal.log");
    try std.testing.expectEqual(@as(u64, 0), stat.size);
}

test "compact: no records removed" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    // Write 3 records with LSNs 1..3.
    const wf = try tmp_dir.dir.createFile("wal.log", .{ .truncate = true });
    for (1..4) |lsn| {
        _ = try record.writeToFile(wf, allocator, @intCast(lsn), "keep");
    }
    wf.close();

    // Record the original file size.
    const original_stat = try tmp_dir.dir.statFile("wal.log");

    // Compact at watermark 0 → all records have LSN > 0, so all kept.
    const result = try compact(allocator, tmp_dir.dir, "wal.log", 0, null);
    try std.testing.expectEqual(@as(u64, 3), result.records_kept);
    try std.testing.expectEqual(original_stat.size, result.new_size);

    // Verify file is unchanged.
    const new_stat = try tmp_dir.dir.statFile("wal.log");
    try std.testing.expectEqual(original_stat.size, new_stat.size);
}

test "compact: append after compact works" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    // Write records LSN 1..4.
    const wf = try tmp_dir.dir.createFile("wal.log", .{ .truncate = true });
    for (1..5) |lsn| {
        _ = try record.writeToFile(wf, allocator, @intCast(lsn), "before");
    }
    wf.close();

    // Compact: keep LSN > 2 (keeps LSNs 3 and 4).
    const result = try compact(allocator, tmp_dir.dir, "wal.log", 2, null);
    try std.testing.expectEqual(@as(u64, 2), result.records_kept);

    // Append two more records: LSN 5 and 6.
    const af = try tmp_dir.dir.openFile("wal.log", .{ .mode = .write_only });
    try af.seekFromEnd(0);
    _ = try record.writeToFile(af, allocator, 5, "after");
    _ = try record.writeToFile(af, allocator, 6, "after");
    af.close();

    // Read back all 4 records and verify.
    const rf = try tmp_dir.dir.openFile("wal.log", .{ .mode = .read_only });
    defer rf.close();

    const expected_lsns = [_]u64{ 3, 4, 5, 6 };
    const expected_payloads = [_][]const u8{ "before", "before", "after", "after" };
    var idx: usize = 0;

    while (true) {
        const hdr_result = try record.readHeaderRaw(rf) orelse break;
        const payload = try record.readPayloadAndVerify(rf, allocator, hdr_result.info, hdr_result.raw) orelse break;
        defer allocator.free(payload);

        try std.testing.expectEqual(expected_lsns[idx], hdr_result.info.lsn);
        try std.testing.expectEqualStrings(expected_payloads[idx], payload);
        idx += 1;
    }
    try std.testing.expectEqual(@as(usize, 4), idx);
}
