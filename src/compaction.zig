// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! WAL compaction: rewrite the log keeping only records with LSN > watermark.
//!
//! Uses a bulk-copy optimisation: because LSNs are monotonically increasing,
//! once the first record that must be kept is located we can block-copy the
//! remainder of the file without re-reading it record by record. The scan
//! itself validates every record first (SONNY-6620).
//!
//! ## Algorithm
//!
//! 1. Open the source file read-only.
//! 2. Scan forward validating every record exactly as recovery does (CRC,
//!    AES-GCM tag, LSN monotonicity). If any byte up to end of file is not
//!    part of a valid record, fail closed and leave the file untouched
//!    (SONNY-6620).
//! 3. Remember the file offset of the first record whose LSN > `up_to_lsn`.
//! 4. If no such record exists → write an empty temp file and rename it over
//!    the original (all records removed).
//! 5. If the first kept record is at offset 0 → all records are already kept;
//!    return immediately without touching the file.
//! 6. Otherwise → create "wal.tmp", seek the source to the first kept offset,
//!    block-copy the rest with a 64 KB buffer, fsync, close, rename.

const std = @import("std");
const file_ops = @import("file_ops.zig");
const record = @import("record.zig");
const encryption = @import("encryption.zig");
const atomic = @import("atomic.zig");
const recovery = @import("recovery.zig");
const recovery_classify = @import("recovery_classify.zig");

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
fn createTempFile(dir: std.Io.Dir, tmp_name: []const u8) !std.Io.File {
    const io = std.Io.Threaded.global_single_threaded.io();
    // Note: A narrow TOCTOU window exists between delete and create (SEC-0011).
    dir.deleteFile(io, tmp_name) catch {};
    return dir.createFile(io, tmp_name, .{ .truncate = true, .permissions = file_ops.private_permissions });
}

/// Sync, close, and atomically rename a temporary file over the target.
/// Close is deferred until after rename so that a rename failure does not
/// leave the fd closed — the caller's errdefer can still safely close it
/// (SEC-0035: avoids double-close → unreachable/UB on EBADF).
fn finalizeTempFile(dir: std.Io.Dir, tmp: std.Io.File, tmp_name: []const u8, filename: []const u8) !void {
    try tmp.sync(std.Io.Threaded.global_single_threaded.io());
    try dir.rename(tmp_name, dir, filename, std.Io.Threaded.global_single_threaded.io());
    tmp.close(std.Io.Threaded.global_single_threaded.io());
    // Directory fsync omitted here (SEC-0020). When compaction empties the
    // log, WriteAheadLog.compact rewrites the checkpoint sidecar through
    // atomic.atomicWriteFile, whose atomic.syncDir fsyncs this same directory.
}

// ============================================================================
// Bulk copy helpers (PERF-0014)
// ============================================================================

/// Copy all remaining data from `src` (current position to EOF) into `dst`.
///
/// When `zero_copy` is true on Linux, uses `copy_file_range(2)` to transfer
/// data inside the kernel without user-space buffering. Falls back to the
/// user-space loop if the syscall is unavailable or on non-Linux platforms.
fn bulkCopy(src: std.Io.File, dst: std.Io.File, zero_copy: bool, src_offset: u64) !u64 {
    if (zero_copy) {
        // Use if/else rather than exhaustive switch: on non-Linux targets the
        // inferred error set of `zeroCopyTransfer` is just `{OperationNotSupported}`
        // (the Linux-only branch is comptime-pruned), which would make an `else`
        // switch prong unreachable and fail to compile on Zig 0.16+.
        return zeroCopyTransfer(src, dst, src_offset) catch |err| {
            if (err == error.OperationNotSupported) return userSpaceCopy(src, dst, src_offset);
            return err;
        };
    }
    return userSpaceCopy(src, dst, src_offset);
}

/// User-space copy loop using a 256 KiB stack buffer (original PERF-0008 path).
fn userSpaceCopy(src: std.Io.File, dst: std.Io.File, src_offset: u64) !u64 {
    const io = std.Io.Threaded.global_single_threaded.io();
    var copy_buf: [COPY_BUF_SIZE]u8 = undefined;
    var read_off: u64 = src_offset;
    var write_off: u64 = 0;
    while (true) {
        const n = try src.readPositionalAll(io, &copy_buf, read_off);
        if (n == 0) break;
        try dst.writePositionalAll(io, copy_buf[0..n], write_off);
        read_off += n;
        write_off += n;
    }
    return write_off;
}

/// Zero-copy transfer using Linux `copy_file_range(2)` (PERF-0014).
///
/// Copies data entirely in kernel space, avoiding user-space buffer copies.
/// The transfer is done in 256 KiB chunks to match the user-space buffer size.
///
/// Returns `error.OperationNotSupported` if the syscall is not available
/// (non-Linux, old kernel, or cross-filesystem with incompatible backing stores).
fn zeroCopyTransfer(src: std.Io.File, dst: std.Io.File, src_offset: u64) !u64 {
    const native_os = @import("builtin").os.tag;
    if (native_os != .linux) return error.OperationNotSupported;

    var off_in: i64 = @intCast(src_offset);
    var bytes_written: u64 = 0;
    while (true) {
        const n = std.os.linux.copy_file_range(src.handle, @ptrCast(&off_in), dst.handle, null, COPY_BUF_SIZE, 0);
        switch (std.os.linux.errno(n)) {
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
/// Every record is validated before anything is written (SONNY-6620; this
/// replaces SEC-0027's header-only plaintext scan). Recovery validates the
/// log only when it is opened, and a partial scan used to rewrite the log as
/// empty or carry a bad record forward. Compaction fails closed, leaving the
/// file untouched, when any byte up to end of file is not part of a valid
/// record: `error.WalEncryptionMismatch` for a record of the other key mode,
/// otherwise `error.WalCorrupted` (or `error.WalAuthFailed` when no record
/// authenticates). A compaction therefore never keeps fewer valid records than
/// the log holds above the watermark.
pub fn compact(
    allocator: std.mem.Allocator,
    dir: std.Io.Dir,
    filename: []const u8,
    up_to_lsn: u64,
    encryption_key: ?*const [32]u8,
    zero_copy: bool,
) !CompactResult {
    // Derive the temporary filename from the target filename.
    var tmp_name_buf: [atomic.TMP_NAME_BUF_SIZE]u8 = undefined;
    const tmp_name = std.fmt.bufPrint(&tmp_name_buf, "{s}.tmp", .{filename}) catch return error.FilenameTooLong;

    // Open source file for reading.
    const src = try dir.openFile(std.Io.Threaded.global_single_threaded.io(), filename, .{ .mode = .read_only });
    defer src.close(std.Io.Threaded.global_single_threaded.io());

    // ---- Scan phase ---------------------------------------------------------
    // Validate every record with the recovery scan (CRC, AEAD, LSN
    // monotonicity, SEC-0038 mode check) and find where the valid records
    // cross the watermark. Recovery only validated the log when it was opened;
    // it can be damaged since. If any byte is not part of a valid record,
    // refuse: rewriting from a partial scan would drop the valid records after
    // the bad one, or carry the bad one into the new log (SONNY-6620).

    const file_len = try src.length(std.Io.Threaded.global_single_threaded.io());
    var split = recovery.Split{ .up_to_lsn = up_to_lsn };
    const info = try recovery.scanSplitWithKey(allocator, src, encryption_key, &split);
    if (info.valid_end != file_len) {
        // Prefer the specific diagnosis (e.g. a plaintext record inside an
        // encrypted WAL). Salvage is never applied here, and a torn tail is
        // still refused: only `init` may truncate.
        _ = try recovery_classify.classifyStop(allocator, src, file_len, encryption_key, info, false);
        return error.WalCorrupted;
    }
    const first_kept_offset = split.first_kept_offset;
    const records_kept = split.records_kept;

    // ---- Decision phase -----------------------------------------------------

    if (first_kept_offset == null) {
        // Every record is below (or at) the watermark → empty the file.
        const tmp = try createTempFile(dir, tmp_name);
        errdefer {
            tmp.close(std.Io.Threaded.global_single_threaded.io());
            dir.deleteFile(std.Io.Threaded.global_single_threaded.io(), tmp_name) catch {};
        }
        try finalizeTempFile(dir, tmp, tmp_name, filename);

        return CompactResult{ .records_kept = 0, .new_size = 0 };
    }

    const kept_offset = first_kept_offset.?;

    if (kept_offset == 0) {
        // All records are above the watermark → nothing to do.
        const stat = try src.stat(std.Io.Threaded.global_single_threaded.io());
        return CompactResult{
            .records_kept = records_kept,
            .new_size = stat.size,
        };
    }

    // ---- Bulk-copy phase ----------------------------------------------------
    // Stream-copy the first kept record onward to the temp file. This phase is
    // format-agnostic: we copy raw bytes regardless of whether records are
    // encrypted or plaintext. Both copy paths (userSpaceCopy, zeroCopyTransfer)
    // are fully positional — they read from `kept_offset` directly and never use
    // the file cursor — so no lseek is required here.

    const tmp = try createTempFile(dir, tmp_name);
    errdefer {
        tmp.close(std.Io.Threaded.global_single_threaded.io());
        dir.deleteFile(std.Io.Threaded.global_single_threaded.io(), tmp_name) catch {};
    }

    const bytes_written = try bulkCopy(src, tmp, zero_copy, kept_offset);

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
    const wf = try tmp_dir.dir.createFile(std.Io.Threaded.global_single_threaded.io(), "wal.log", .{ .truncate = true });
    for (1..6) |lsn| {
        _ = try record.writeToFile(allocator, wf, @intCast(lsn), "payload");
    }
    wf.close(std.Io.Threaded.global_single_threaded.io());

    // Compact: keep only records with LSN > 3.
    const result = try compact(allocator, tmp_dir.dir, "wal.log", 3, null, false);
    try std.testing.expectEqual(@as(u64, 2), result.records_kept);

    // Re-open and verify only LSNs 4 and 5 remain.
    const rf = try tmp_dir.dir.openFile(std.Io.Threaded.global_single_threaded.io(), "wal.log", .{ .mode = .read_only });
    defer rf.close(std.Io.Threaded.global_single_threaded.io());
    var rfs = record.FileSource.init(rf);

    var expected_lsn: u64 = 4;
    while (true) {
        const hdr_result = try record.readHeaderRaw(&rfs) orelse break;
        const payload = try record.readPayloadAndVerify(allocator, &rfs, hdr_result.info, hdr_result.raw) orelse break;
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
    const wf = try tmp_dir.dir.createFile(std.Io.Threaded.global_single_threaded.io(), "wal.log", .{ .truncate = true });
    for (1..4) |lsn| {
        _ = try record.writeToFile(allocator, wf, @intCast(lsn), "data");
    }
    wf.close(std.Io.Threaded.global_single_threaded.io());

    // Compact above max LSN → all records removed.
    const result = try compact(allocator, tmp_dir.dir, "wal.log", 100, null, false);
    try std.testing.expectEqual(@as(u64, 0), result.records_kept);
    try std.testing.expectEqual(@as(u64, 0), result.new_size);

    // File should exist but be empty.
    const stat = try tmp_dir.dir.statFile(std.Io.Threaded.global_single_threaded.io(), "wal.log", .{});
    try std.testing.expectEqual(@as(u64, 0), stat.size);
}

test "compact: no records removed" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    // Write 3 records with LSNs 1..3.
    const wf = try tmp_dir.dir.createFile(std.Io.Threaded.global_single_threaded.io(), "wal.log", .{ .truncate = true });
    for (1..4) |lsn| {
        _ = try record.writeToFile(allocator, wf, @intCast(lsn), "keep");
    }
    wf.close(std.Io.Threaded.global_single_threaded.io());

    // Record the original file size.
    const original_stat = try tmp_dir.dir.statFile(std.Io.Threaded.global_single_threaded.io(), "wal.log", .{});

    // Compact at watermark 0 → all records have LSN > 0, so all kept.
    const result = try compact(allocator, tmp_dir.dir, "wal.log", 0, null, false);
    try std.testing.expectEqual(@as(u64, 3), result.records_kept);
    try std.testing.expectEqual(original_stat.size, result.new_size);

    // Verify file is unchanged.
    const new_stat = try tmp_dir.dir.statFile(std.Io.Threaded.global_single_threaded.io(), "wal.log", .{});
    try std.testing.expectEqual(original_stat.size, new_stat.size);
}

test "compact: append after compact works" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    // Write records LSN 1..4.
    const wf = try tmp_dir.dir.createFile(std.Io.Threaded.global_single_threaded.io(), "wal.log", .{ .truncate = true });
    for (1..5) |lsn| {
        _ = try record.writeToFile(allocator, wf, @intCast(lsn), "before");
    }
    wf.close(std.Io.Threaded.global_single_threaded.io());

    // Compact: keep LSN > 2 (keeps LSNs 3 and 4).
    const result = try compact(allocator, tmp_dir.dir, "wal.log", 2, null, false);
    try std.testing.expectEqual(@as(u64, 2), result.records_kept);

    // Append two more records: LSN 5 and 6.
    // Use createFile with truncate=false to append via streaming write at end.
    const io = std.Io.Threaded.global_single_threaded.io();
    const af = try tmp_dir.dir.openFile(io, "wal.log", .{ .mode = .read_write });
    // Get current file size to position append correctly.
    const file_len = try af.length(io);
    // Serialize records into a buffer and write positionally at the end.
    const rec5_size = record.HEADER_SIZE + "after".len + record.CRC_SIZE;
    const rec6_size = record.HEADER_SIZE + "after".len + record.CRC_SIZE;
    var rec5_buf: [rec5_size]u8 = undefined;
    var rec6_buf: [rec6_size]u8 = undefined;
    record.serializeInto(&rec5_buf, 5, "after");
    record.serializeInto(&rec6_buf, 6, "after");
    try af.writePositionalAll(io, &rec5_buf, file_len);
    try af.writePositionalAll(io, &rec6_buf, file_len + rec5_size);
    af.close(io);

    // Read back all 4 records and verify.
    const rf = try tmp_dir.dir.openFile(std.Io.Threaded.global_single_threaded.io(), "wal.log", .{ .mode = .read_only });
    defer rf.close(std.Io.Threaded.global_single_threaded.io());
    var rfs = record.FileSource.init(rf);

    const expected_lsns = [_]u64{ 3, 4, 5, 6 };
    const expected_payloads = [_][]const u8{ "before", "before", "after", "after" };
    var idx: usize = 0;

    while (true) {
        const hdr_result = try record.readHeaderRaw(&rfs) orelse break;
        const payload = try record.readPayloadAndVerify(allocator, &rfs, hdr_result.info, hdr_result.raw) orelse break;
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
    const wf = try tmp_dir.dir.createFile(std.Io.Threaded.global_single_threaded.io(), "wal.log", .{ .truncate = true });
    for (1..6) |lsn| {
        _ = try encryption.encryptAndWriteToFile(allocator, wf, &key, @intCast(lsn), "payload");
    }
    wf.close(std.Io.Threaded.global_single_threaded.io());

    // Compact: keep only records with LSN > 3.
    const result = try compact(allocator, tmp_dir.dir, "wal.log", 3, &key, false);
    try std.testing.expectEqual(@as(u64, 2), result.records_kept);

    // Re-open and verify only LSNs 4 and 5 remain by reading encrypted records.
    const rf = try tmp_dir.dir.openFile(std.Io.Threaded.global_single_threaded.io(), "wal.log", .{ .mode = .read_only });
    defer rf.close(std.Io.Threaded.global_single_threaded.io());
    var rfs = record.FileSource.init(rf);

    var expected_lsn: u64 = 4;
    while (true) {
        // Peek to detect record.
        var peek_buf: [encryption.DETECT_PEEK_SIZE]u8 = undefined;
        const peek_n = try rfs.readPositionalAll(std.Io.Threaded.global_single_threaded.io(), &peek_buf, 0);
        if (peek_n < encryption.DETECT_PEEK_SIZE) break;

        const blob_result = try encryption.readEncryptedBlob(allocator, &rfs, &peek_buf) orelse break;
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
    const wf = try tmp_dir.dir.createFile(std.Io.Threaded.global_single_threaded.io(), "wal.log", .{ .truncate = true });
    for (1..4) |lsn| {
        _ = try encryption.encryptAndWriteToFile(allocator, wf, &key, @intCast(lsn), "data");
    }
    wf.close(std.Io.Threaded.global_single_threaded.io());

    // Compact above max LSN → all records removed.
    const result = try compact(allocator, tmp_dir.dir, "wal.log", 100, &key, false);
    try std.testing.expectEqual(@as(u64, 0), result.records_kept);
    try std.testing.expectEqual(@as(u64, 0), result.new_size);

    // File should exist but be empty.
    const stat = try tmp_dir.dir.statFile(std.Io.Threaded.global_single_threaded.io(), "wal.log", .{});
    try std.testing.expectEqual(@as(u64, 0), stat.size);
}

test "compact: encrypted — no records removed (QA-0025)" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const key = test_key;

    // Write 3 encrypted records with LSNs 1..3.
    const wf = try tmp_dir.dir.createFile(std.Io.Threaded.global_single_threaded.io(), "wal.log", .{ .truncate = true });
    for (1..4) |lsn| {
        _ = try encryption.encryptAndWriteToFile(allocator, wf, &key, @intCast(lsn), "keep");
    }
    wf.close(std.Io.Threaded.global_single_threaded.io());

    // Record the original file size.
    const original_stat = try tmp_dir.dir.statFile(std.Io.Threaded.global_single_threaded.io(), "wal.log", .{});

    // Compact at watermark 0 → all records have LSN > 0, so all kept.
    const result = try compact(allocator, tmp_dir.dir, "wal.log", 0, &key, false);
    try std.testing.expectEqual(@as(u64, 3), result.records_kept);
    try std.testing.expectEqual(original_stat.size, result.new_size);

    // Verify file is unchanged.
    const new_stat = try tmp_dir.dir.statFile(std.Io.Threaded.global_single_threaded.io(), "wal.log", .{});
    try std.testing.expectEqual(original_stat.size, new_stat.size);
}

// ============================================================================
// Zero-copy compaction tests (PERF-0014)
// ============================================================================

test "compact: zero-copy removes records below watermark (PERF-0014)" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const wf = try tmp_dir.dir.createFile(std.Io.Threaded.global_single_threaded.io(), "wal.log", .{ .truncate = true });
    for (1..6) |lsn| {
        _ = try record.writeToFile(allocator, wf, @intCast(lsn), "payload");
    }
    wf.close(std.Io.Threaded.global_single_threaded.io());

    // Compact with zero_copy=true.
    const result = try compact(allocator, tmp_dir.dir, "wal.log", 3, null, true);
    try std.testing.expectEqual(@as(u64, 2), result.records_kept);

    // Verify only LSNs 4 and 5 remain.
    const rf = try tmp_dir.dir.openFile(std.Io.Threaded.global_single_threaded.io(), "wal.log", .{ .mode = .read_only });
    defer rf.close(std.Io.Threaded.global_single_threaded.io());
    var rfs = record.FileSource.init(rf);

    var expected_lsn: u64 = 4;
    while (true) {
        const hdr_result = try record.readHeaderRaw(&rfs) orelse break;
        const payload = try record.readPayloadAndVerify(allocator, &rfs, hdr_result.info, hdr_result.raw) orelse break;
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

    const wf = try tmp_dir.dir.createFile(std.Io.Threaded.global_single_threaded.io(), "wal.log", .{ .truncate = true });
    for (1..4) |lsn| {
        _ = try record.writeToFile(allocator, wf, @intCast(lsn), "data");
    }
    wf.close(std.Io.Threaded.global_single_threaded.io());

    const result = try compact(allocator, tmp_dir.dir, "wal.log", 100, null, true);
    try std.testing.expectEqual(@as(u64, 0), result.records_kept);
    try std.testing.expectEqual(@as(u64, 0), result.new_size);
}

test "compact: zero-copy encrypted (PERF-0014)" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const key = test_key;

    const wf = try tmp_dir.dir.createFile(std.Io.Threaded.global_single_threaded.io(), "wal.log", .{ .truncate = true });
    for (1..6) |lsn| {
        _ = try encryption.encryptAndWriteToFile(allocator, wf, &key, @intCast(lsn), "payload");
    }
    wf.close(std.Io.Threaded.global_single_threaded.io());

    const result = try compact(allocator, tmp_dir.dir, "wal.log", 3, &key, true);
    try std.testing.expectEqual(@as(u64, 2), result.records_kept);

    // Verify records.
    const rf = try tmp_dir.dir.openFile(std.Io.Threaded.global_single_threaded.io(), "wal.log", .{ .mode = .read_only });
    defer rf.close(std.Io.Threaded.global_single_threaded.io());
    var rfs = record.FileSource.init(rf);

    var expected_lsn: u64 = 4;
    while (true) {
        var peek_buf: [encryption.DETECT_PEEK_SIZE]u8 = undefined;
        const peek_n = try rfs.readPositionalAll(std.Io.Threaded.global_single_threaded.io(), &peek_buf, 0);
        if (peek_n < encryption.DETECT_PEEK_SIZE) break;
        const blob_result = try encryption.readEncryptedBlob(allocator, &rfs, &peek_buf) orelse break;
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
