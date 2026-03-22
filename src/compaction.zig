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
const atomic = @import("atomic.zig");

// Guard: plaintext path reinterprets peek buffer as header (QA-0035).
comptime {
    std.debug.assert(encryption.DETECT_PEEK_SIZE == record.HEADER_SIZE);
}

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
// Temp file helpers (QA-0028: deduplicated from two call sites in compact)
// ============================================================================

/// Create a temporary file, removing any stale one first (SEC-0005).
/// The caller must set up an errdefer for close+delete on the returned handle.
fn createTempFile(dir: std.fs.Dir, tmp_name: []const u8) !std.fs.File {
    // Note: A narrow TOCTOU window exists between delete and create (SEC-0011).
    dir.deleteFile(tmp_name) catch {};
    return dir.createFile(tmp_name, .{ .truncate = true, .mode = 0o600 });
}

/// Sync, close, and atomically rename a temporary file over the target.
/// Close is deferred until after rename so that a rename failure does not
/// leave the fd closed — the caller's errdefer can still safely close it
/// (SEC-0035: avoids double-close → unreachable/UB on EBADF).
fn finalizeTempFile(dir: std.fs.Dir, tmp: std.fs.File, tmp_name: []const u8, filename: []const u8) !void {
    try tmp.sync();
    try dir.rename(tmp_name, filename);
    tmp.close();
    // Directory fsync omitted — see SEC-0020 comment in atomic.zig.
}

// ============================================================================
// Bulk copy helpers (PERF-0014)
// ============================================================================

/// Copy all remaining data from `src` (current position to EOF) into `dst`.
///
/// When `zero_copy` is true on Linux, uses `copy_file_range(2)` to transfer
/// data inside the kernel without user-space buffering. Falls back to the
/// user-space loop if the syscall is unavailable or on non-Linux platforms.
fn bulkCopy(src: std.fs.File, dst: std.fs.File, zero_copy: bool) !u64 {
    if (zero_copy) {
        return zeroCopyTransfer(src, dst) catch |err| switch (err) {
            // Unsupported or cross-filesystem — fall back.
            error.OperationNotSupported => return userSpaceCopy(src, dst),
            else => return err,
        };
    }
    return userSpaceCopy(src, dst);
}

/// User-space copy loop using a 256 KiB stack buffer (original PERF-0008 path).
fn userSpaceCopy(src: std.fs.File, dst: std.fs.File) !u64 {
    var copy_buf: [COPY_BUF_SIZE]u8 = undefined;
    var bytes_written: u64 = 0;
    while (true) {
        const n = try src.read(&copy_buf);
        if (n == 0) break;
        try dst.writeAll(copy_buf[0..n]);
        bytes_written += n;
    }
    return bytes_written;
}

/// Zero-copy transfer using Linux `copy_file_range(2)` (PERF-0014).
///
/// Copies data entirely in kernel space, avoiding user-space buffer copies.
/// The transfer is done in 256 KiB chunks to match the user-space buffer size.
///
/// Returns `error.OperationNotSupported` if the syscall is not available
/// (non-Linux, old kernel, or cross-filesystem with incompatible backing stores).
fn zeroCopyTransfer(src: std.fs.File, dst: std.fs.File) !u64 {
    const native_os = @import("builtin").os.tag;
    if (native_os != .linux) return error.OperationNotSupported;

    var bytes_written: u64 = 0;
    while (true) {
        const n = std.os.linux.copy_file_range(src.handle, null, dst.handle, null, COPY_BUF_SIZE, 0);
        switch (std.os.linux.E.init(n)) {
            .SUCCESS => {},
            .INTR => continue, // Interrupted by signal — retry (SEC NEW-6).
            .NOSYS, .XDEV, .INVAL => return error.OperationNotSupported,
            .BADF => return error.BadFileDescriptor,
            .IO => return error.InputOutput,
            .ISDIR => return error.IsDir,
            .NOMEM => return error.SystemResources,
            .NXIO => return error.Unseekable,
            .PERM => return error.AccessDenied,
            else => return error.Unexpected,
        }
        if (n == 0) break; // EOF
        bytes_written += n;
    }
    return bytes_written;
}

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
/// **CRC validation is intentionally skipped during scanning (SEC-0027).**
/// The recovery module (`recovery.recover` / `recoverWithKey`) validates
/// every record's CRC on WAL open and truncates the file at the first
/// invalid record. Compaction only runs after recovery, so all records
/// in the file are known-good. Re-validating CRCs here would double the
/// I/O cost without security benefit. Encrypted records still get
/// implicit integrity verification via the AES-GCM authentication tag
/// during decryption in the scan phase.
pub fn compact(
    allocator: std.mem.Allocator,
    dir: std.fs.Dir,
    filename: []const u8,
    up_to_lsn: u64,
    encryption_key: ?*const [32]u8,
    zero_copy: bool,
) !CompactResult {
    // Derive the temporary filename from the target filename.
    var tmp_name_buf: [atomic.TMP_NAME_BUF_SIZE]u8 = undefined;
    const tmp_name = std.fmt.bufPrint(&tmp_name_buf, "{s}.tmp", .{filename}) catch return error.FilenameTooLong;

    // Open source file for reading.
    const src = try dir.openFile(filename, .{ .mode = .read_only });
    defer src.close();

    // ---- Scan phase ---------------------------------------------------------
    // Walk every record, tracking the offset of the first kept record.
    // Peek at DETECT_PEEK_SIZE bytes to distinguish encrypted from plaintext records (QA-0014).

    var first_kept_offset: ?u64 = null;
    var records_kept: u64 = 0;
    // Track file offset manually instead of getPos() syscall per record (PERF-0018).
    var current_offset: u64 = 0;

    // Reusable buffer for encrypted record reads (PERF-0016).
    var reuse_buf: ?[]u8 = null;
    defer if (reuse_buf) |buf| {
        encryption.secureZero(buf); // SEC-0029
        allocator.free(buf);
    };

    while (true) {
        const offset = current_offset;

        // Read DETECT_PEEK_SIZE bytes to detect the record type.
        var peek_buf: [encryption.DETECT_PEEK_SIZE]u8 = undefined;
        const peek_n = try src.readAll(&peek_buf);
        if (peek_n < encryption.DETECT_PEEK_SIZE) break; // EOF or torn header

        if (encryption_key != null and encryption.isEncrypted(&peek_buf)) {
            // ── Encrypted record path (QA-0002: shared reader, PERF-0016: reuse buffer) ──
            const blob_result = try encryption.readEncryptedBlobReuse(allocator, src, &peek_buf, &reuse_buf) orelse break;
            // No per-record defer — reuse_buf freed once after the loop (PERF-0016).

            // Decrypt in-place to extract LSN — avoids extra allocation (PERF-0003).
            const key = encryption_key.?;
            const plaintext = encryption.decryptRecordInPlace(key, blob_result.blob) catch break;

            if (plaintext.len < record.HEADER_SIZE) break; // corrupt inner record
            const lsn = std.mem.readInt(u64, plaintext[0..8], .little);

            if (lsn > up_to_lsn) {
                records_kept += 1;
                if (first_kept_offset == null) {
                    first_kept_offset = offset;
                }
            }
            current_offset += blob_result.total_on_disk;
        } else if (encryption_key != null) {
            // SEC-0038: encryption key is configured but record lacks magic
            // bytes — reject to prevent plaintext record injection.
            break;
        } else {
            // ── Plaintext record path (no encryption key) ────────────────────
            // peek_buf contains the 12-byte header already consumed.
            const hdr = record.HeaderInfo{
                .lsn = std.mem.readInt(u64, peek_buf[0..8], .little),
                .payload_len = std.mem.readInt(u32, peek_buf[8..12], .little),
            };

            // Reject unreasonably large records (SEC-0004).
            if (@as(usize, hdr.payload_len) + record.HEADER_SIZE + record.CRC_SIZE > record.MAX_RECORD_SIZE) break;

            if (hdr.lsn > up_to_lsn) {
                records_kept += 1;
                if (first_kept_offset == null) {
                    first_kept_offset = offset;
                }
            }

            // Seek past payload + CRC without reading them.
            try src.seekBy(@as(i64, @intCast(@as(usize, hdr.payload_len) + record.CRC_SIZE)));
            current_offset += @as(u64, record.HEADER_SIZE) + @as(u64, hdr.payload_len) + @as(u64, record.CRC_SIZE);
        }
    }

    // ---- Decision phase -----------------------------------------------------

    if (first_kept_offset == null) {
        // Every record is below (or at) the watermark → empty the file.
        const tmp = try createTempFile(dir, tmp_name);
        errdefer {
            tmp.close();
            dir.deleteFile(tmp_name) catch {};
        }
        try finalizeTempFile(dir, tmp, tmp_name, filename);

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

    const tmp = try createTempFile(dir, tmp_name);
    errdefer {
        tmp.close();
        dir.deleteFile(tmp_name) catch {};
    }

    const bytes_written = try bulkCopy(src, tmp, zero_copy);

    try finalizeTempFile(dir, tmp, tmp_name, filename);

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
        _ = try record.writeToFile(allocator, wf, @intCast(lsn), "payload");
    }
    wf.close();

    // Compact: keep only records with LSN > 3.
    const result = try compact(allocator, tmp_dir.dir, "wal.log", 3, null, false);
    try std.testing.expectEqual(@as(u64, 2), result.records_kept);

    // Re-open and verify only LSNs 4 and 5 remain.
    const rf = try tmp_dir.dir.openFile("wal.log", .{ .mode = .read_only });
    defer rf.close();

    var expected_lsn: u64 = 4;
    while (true) {
        const hdr_result = try record.readHeaderRaw(rf) orelse break;
        const payload = try record.readPayloadAndVerify(allocator, rf, hdr_result.info, hdr_result.raw) orelse break;
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
        _ = try record.writeToFile(allocator, wf, @intCast(lsn), "data");
    }
    wf.close();

    // Compact above max LSN → all records removed.
    const result = try compact(allocator, tmp_dir.dir, "wal.log", 100, null, false);
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
        _ = try record.writeToFile(allocator, wf, @intCast(lsn), "keep");
    }
    wf.close();

    // Record the original file size.
    const original_stat = try tmp_dir.dir.statFile("wal.log");

    // Compact at watermark 0 → all records have LSN > 0, so all kept.
    const result = try compact(allocator, tmp_dir.dir, "wal.log", 0, null, false);
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
        _ = try record.writeToFile(allocator, wf, @intCast(lsn), "before");
    }
    wf.close();

    // Compact: keep LSN > 2 (keeps LSNs 3 and 4).
    const result = try compact(allocator, tmp_dir.dir, "wal.log", 2, null, false);
    try std.testing.expectEqual(@as(u64, 2), result.records_kept);

    // Append two more records: LSN 5 and 6.
    const af = try tmp_dir.dir.openFile("wal.log", .{ .mode = .write_only });
    try af.seekFromEnd(0);
    _ = try record.writeToFile(allocator, af, 5, "after");
    _ = try record.writeToFile(allocator, af, 6, "after");
    af.close();

    // Read back all 4 records and verify.
    const rf = try tmp_dir.dir.openFile("wal.log", .{ .mode = .read_only });
    defer rf.close();

    const expected_lsns = [_]u64{ 3, 4, 5, 6 };
    const expected_payloads = [_][]const u8{ "before", "before", "after", "after" };
    var idx: usize = 0;

    while (true) {
        const hdr_result = try record.readHeaderRaw(rf) orelse break;
        const payload = try record.readPayloadAndVerify(allocator, rf, hdr_result.info, hdr_result.raw) orelse break;
        defer allocator.free(payload);

        try std.testing.expectEqual(expected_lsns[idx], hdr_result.info.lsn);
        try std.testing.expectEqualStrings(expected_payloads[idx], payload);
        idx += 1;
    }
    try std.testing.expectEqual(@as(usize, 4), idx);
}

test "compact: filename too long returns error" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    // 253 chars + ".tmp" = 257 > 256-byte buffer in compact().
    const long_name = "a" ** 253;
    const result = compact(allocator, tmp_dir.dir, long_name, 0, null, false);
    try std.testing.expectError(error.FilenameTooLong, result);
}

// ============================================================================
// Encrypted compaction tests (QA-0025)
// ============================================================================

/// Deterministic test key used by all encrypted compaction tests.
const test_key = encryption.test_key;

test "compact: encrypted — removes records below watermark (QA-0025)" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const key = test_key;

    // Write 5 encrypted records with LSNs 1..5.
    const wf = try tmp_dir.dir.createFile("wal.log", .{ .truncate = true });
    for (1..6) |lsn| {
        _ = try encryption.encryptAndWriteToFile(allocator, wf, &key, @intCast(lsn), "payload");
    }
    wf.close();

    // Compact: keep only records with LSN > 3.
    const result = try compact(allocator, tmp_dir.dir, "wal.log", 3, &key, false);
    try std.testing.expectEqual(@as(u64, 2), result.records_kept);

    // Re-open and verify only LSNs 4 and 5 remain by reading encrypted records.
    const rf = try tmp_dir.dir.openFile("wal.log", .{ .mode = .read_only });
    defer rf.close();

    var expected_lsn: u64 = 4;
    while (true) {
        // Peek to detect record.
        var peek_buf: [encryption.DETECT_PEEK_SIZE]u8 = undefined;
        const peek_n = try rf.readAll(&peek_buf);
        if (peek_n < encryption.DETECT_PEEK_SIZE) break;

        const blob_result = try encryption.readEncryptedBlob(allocator, rf, &peek_buf) orelse break;
        defer {
            encryption.secureZero(blob_result.blob);
            allocator.free(blob_result.blob);
        }

        const plaintext = try encryption.decryptRecordInPlace(&key, blob_result.blob);
        const rec = try record.deserialize(plaintext);
        try std.testing.expectEqual(expected_lsn, rec.lsn);
        expected_lsn += 1;
    }
    try std.testing.expectEqual(@as(u64, 6), expected_lsn); // saw LSNs 4 and 5
}

test "compact: encrypted — all records removed (QA-0025)" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const key = test_key;

    // Write 3 encrypted records.
    const wf = try tmp_dir.dir.createFile("wal.log", .{ .truncate = true });
    for (1..4) |lsn| {
        _ = try encryption.encryptAndWriteToFile(allocator, wf, &key, @intCast(lsn), "data");
    }
    wf.close();

    // Compact above max LSN → all records removed.
    const result = try compact(allocator, tmp_dir.dir, "wal.log", 100, &key, false);
    try std.testing.expectEqual(@as(u64, 0), result.records_kept);
    try std.testing.expectEqual(@as(u64, 0), result.new_size);

    // File should exist but be empty.
    const stat = try tmp_dir.dir.statFile("wal.log");
    try std.testing.expectEqual(@as(u64, 0), stat.size);
}

test "compact: encrypted — no records removed (QA-0025)" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const key = test_key;

    // Write 3 encrypted records with LSNs 1..3.
    const wf = try tmp_dir.dir.createFile("wal.log", .{ .truncate = true });
    for (1..4) |lsn| {
        _ = try encryption.encryptAndWriteToFile(allocator, wf, &key, @intCast(lsn), "keep");
    }
    wf.close();

    // Record the original file size.
    const original_stat = try tmp_dir.dir.statFile("wal.log");

    // Compact at watermark 0 → all records have LSN > 0, so all kept.
    const result = try compact(allocator, tmp_dir.dir, "wal.log", 0, &key, false);
    try std.testing.expectEqual(@as(u64, 3), result.records_kept);
    try std.testing.expectEqual(original_stat.size, result.new_size);

    // Verify file is unchanged.
    const new_stat = try tmp_dir.dir.statFile("wal.log");
    try std.testing.expectEqual(original_stat.size, new_stat.size);
}

// ============================================================================
// Zero-copy compaction tests (PERF-0014)
// ============================================================================

test "compact: zero-copy removes records below watermark (PERF-0014)" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const wf = try tmp_dir.dir.createFile("wal.log", .{ .truncate = true });
    for (1..6) |lsn| {
        _ = try record.writeToFile(allocator, wf, @intCast(lsn), "payload");
    }
    wf.close();

    // Compact with zero_copy=true.
    const result = try compact(allocator, tmp_dir.dir, "wal.log", 3, null, true);
    try std.testing.expectEqual(@as(u64, 2), result.records_kept);

    // Verify only LSNs 4 and 5 remain.
    const rf = try tmp_dir.dir.openFile("wal.log", .{ .mode = .read_only });
    defer rf.close();

    var expected_lsn: u64 = 4;
    while (true) {
        const hdr_result = try record.readHeaderRaw(rf) orelse break;
        const payload = try record.readPayloadAndVerify(allocator, rf, hdr_result.info, hdr_result.raw) orelse break;
        defer allocator.free(payload);
        try std.testing.expectEqual(expected_lsn, hdr_result.info.lsn);
        expected_lsn += 1;
    }
    try std.testing.expectEqual(@as(u64, 6), expected_lsn);
}

test "compact: zero-copy all records removed (PERF-0014)" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const wf = try tmp_dir.dir.createFile("wal.log", .{ .truncate = true });
    for (1..4) |lsn| {
        _ = try record.writeToFile(allocator, wf, @intCast(lsn), "data");
    }
    wf.close();

    const result = try compact(allocator, tmp_dir.dir, "wal.log", 100, null, true);
    try std.testing.expectEqual(@as(u64, 0), result.records_kept);
    try std.testing.expectEqual(@as(u64, 0), result.new_size);
}

test "compact: zero-copy encrypted (PERF-0014)" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const key = test_key;

    const wf = try tmp_dir.dir.createFile("wal.log", .{ .truncate = true });
    for (1..6) |lsn| {
        _ = try encryption.encryptAndWriteToFile(allocator, wf, &key, @intCast(lsn), "payload");
    }
    wf.close();

    const result = try compact(allocator, tmp_dir.dir, "wal.log", 3, &key, true);
    try std.testing.expectEqual(@as(u64, 2), result.records_kept);

    // Verify records.
    const rf = try tmp_dir.dir.openFile("wal.log", .{ .mode = .read_only });
    defer rf.close();

    var expected_lsn: u64 = 4;
    while (true) {
        var peek_buf: [encryption.DETECT_PEEK_SIZE]u8 = undefined;
        const peek_n = try rf.readAll(&peek_buf);
        if (peek_n < encryption.DETECT_PEEK_SIZE) break;
        const blob_result = try encryption.readEncryptedBlob(allocator, rf, &peek_buf) orelse break;
        defer {
            encryption.secureZero(blob_result.blob);
            allocator.free(blob_result.blob);
        }
        const plaintext = try encryption.decryptRecordInPlace(&key, blob_result.blob);
        const rec = try record.deserialize(plaintext);
        try std.testing.expectEqual(expected_lsn, rec.lsn);
        expected_lsn += 1;
    }
    try std.testing.expectEqual(@as(u64, 6), expected_lsn);
}
