// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Core WAL engine: orchestrates record writing, reading, and crash recovery.
//!
//! The `WriteAheadLog` struct is the primary public interface. It is:
//! - Payload-agnostic: stores opaque `[]const u8` blobs.
//! - LSN-based: every record gets a monotonically increasing Log Sequence Number.
//! - Single-file: no segment rotation; compaction rewrites the file atomically.
//! - Not thread-safe: callers are responsible for external synchronisation.

const std = @import("std");
const record = @import("record.zig");
const recovery_mod = @import("recovery.zig");
const compaction = @import("compaction.zig");
const encryption = @import("encryption.zig");
const checkpoint_mod = @import("checkpoint.zig");

// ============================================================================
// Options
// ============================================================================

/// Configuration options for a `WriteAheadLog` instance.
///
/// **Key material note (SEC-0026):** `Options` is passed **by value** to
/// `WriteAheadLog.init`, which means the `encryption_key` field is copied
/// onto the stack at each call site. Zig does not guarantee that
/// intermediate stack copies are zeroized when they go out of scope.
/// Callers who need defense-in-depth against stack-residue attacks should
/// zeroize their own copy of the key after calling `init`:
///
/// ```zig
/// var opts = Options{ .encryption_key = my_key };
/// var wal = try WriteAheadLog.init(allocator, dir, "wal.log", opts);
/// encryption.secureZero(std.mem.asBytes(&opts.encryption_key.?));
/// ```
///
/// The `WriteAheadLog` struct zeroizes its internal copy in `deinit`.
pub const Options = struct {
    /// Optional AES-256-GCM encryption key.  `null` means plaintext mode.
    /// See the struct-level doc comment for key-material lifecycle notes.
    encryption_key: ?[32]u8 = null,

    /// When `true`, the caller is responsible for calling `sync()` explicitly.
    /// When `false` (the default), appends are synced automatically according
    /// to `sync_every_n`.
    manual_sync: bool = false,

    /// When `manual_sync` is `false`, sync after every N appends instead of
    /// every single append. Defaults to 1 (sync every append, the safest
    /// option). Values > 1 amortize fsync cost at the risk of losing up to
    /// N-1 records on crash.
    sync_every_n: u32 = 1,

    /// When `true`, `init()` attempts to use a checkpoint sidecar file
    /// (`{filename}.ckpt`) for O(1) recovery on clean shutdown (PERF-0013).
    /// Falls back to full scan if the checkpoint is missing, corrupt, or stale.
    /// The checkpoint is written atomically during `deinit()`.
    checkpoint: bool = false,

    /// When `true`, compaction uses `copy_file_range(2)` for zero-copy bulk
    /// transfer on Linux (PERF-0014). Falls back to the user-space copy loop
    /// on non-Linux platforms or if the syscall is unavailable at runtime.
    zero_copy_compaction: bool = false,
};

// ============================================================================
// WriteAheadLog
// ============================================================================

/// A Write-Ahead Log that appends framed, CRC-verified records to a single
/// file and recovers cleanly after a crash.
pub const WriteAheadLog = struct {
    allocator: std.mem.Allocator,
    dir: std.fs.Dir,
    /// Owned copy of the filename — freed in `deinit` (QA-0067).
    filename: []const u8,
    file: std.fs.File,
    current_lsn: u64,
    file_end: u64,
    bytes_since_compact: u64,
    options: Options,
    appends_since_sync: u32,
    /// When `true` the WAL file handle is invalid and all operations
    /// will return `error.WalPoisoned`. Set when the file handle cannot
    /// be reopened after compaction (SEC-0008).
    poisoned: bool = false,

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    /// Open (or create) the WAL file at `dir/filename`, recover state from any
    /// existing records, truncate any trailing corruption, and position the
    /// file cursor ready for the next append.
    ///
    /// The returned `WriteAheadLog` owns the open file handle; call `deinit`
    /// when done.
    pub fn init(
        allocator: std.mem.Allocator,
        dir: std.fs.Dir,
        filename: []const u8,
        options: Options,
    ) !WriteAheadLog {
        // Own the filename so the WAL is safe even if the caller's slice
        // is freed or goes out of scope (QA-0067).
        const owned_filename = try allocator.dupe(u8, filename);
        errdefer allocator.free(owned_filename);

        // Open existing file, or create a new one with read+write access.
        // New files get 0o600 permissions (owner-only) for defense-in-depth (SEC-0015).
        const file = dir.openFile(filename, .{ .mode = .read_write }) catch |err| switch (err) {
            error.FileNotFound => try dir.createFile(filename, .{ .read = true, .mode = 0o600 }),
            else => return err,
        };
        errdefer file.close();

        // Tighten permissions on existing files to owner-only (SEC-0021).
        // Files created before the SEC-0015 fix may have world-readable
        // permissions. This is best-effort — fails silently on non-POSIX
        // platforms or when the caller is not the file owner.
        std.posix.fchmod(file.handle, 0o600) catch {};

        // Recover WAL state: try checkpoint-accelerated path first if enabled,
        // then fall back to full scan (PERF-0013).
        const info = blk: {
            if (options.checkpoint) {
                if (checkpoint_mod.readCheckpoint(dir, filename)) |ckpt| {
                    const start = recovery_mod.RecoveryInfo{
                        .last_lsn = ckpt.last_lsn,
                        .valid_end = ckpt.valid_end,
                        .record_count = ckpt.record_count,
                    };
                    const inc = if (options.encryption_key) |*key|
                        recovery_mod.recoverFromWithKey(allocator, file, start, key)
                    else
                        recovery_mod.recoverFrom(allocator, file, start);
                    if (inc) |result| {
                        // Guard: if incremental recovery found zero new records
                        // but the file is larger than the checkpoint, the checkpoint
                        // may point mid-record (forged or corrupt). Fall back to
                        // full scan rather than trusting the checkpoint's valid_end,
                        // which would cause init() to truncate valid data (SEC NEW-3).
                        const stat = try file.stat();
                        if (result.valid_end == ckpt.valid_end and stat.size > ckpt.valid_end) {
                            break :blk if (options.encryption_key) |*key|
                                try recovery_mod.recoverWithKey(allocator, file, key)
                            else
                                try recovery_mod.recover(allocator, file);
                        }
                        break :blk result;
                    } else |_| {
                        // CheckpointStale or other error — fall through to full scan.
                        break :blk if (options.encryption_key) |*key|
                            try recovery_mod.recoverWithKey(allocator, file, key)
                        else
                            try recovery_mod.recover(allocator, file);
                    }
                }
            }
            // No checkpoint or checkpoint disabled — full scan.
            break :blk if (options.encryption_key) |*key|
                try recovery_mod.recoverWithKey(allocator, file, key)
            else
                try recovery_mod.recover(allocator, file);
        };

        // Truncate any bytes beyond the last valid record (torn writes, etc.).
        try file.setEndPos(info.valid_end);

        // Position cursor at the write tail.
        try file.seekTo(info.valid_end);

        return WriteAheadLog{
            .allocator = allocator,
            .dir = dir,
            .filename = owned_filename,
            .file = file,
            .current_lsn = info.last_lsn,
            .file_end = info.valid_end,
            .bytes_since_compact = info.valid_end,
            .options = options,
            .appends_since_sync = 0,
            .poisoned = false,
        };
    }

    /// Close the underlying file handle, free the owned filename, and
    /// zeroize any key material (SEC-0002).
    pub fn deinit(self: *WriteAheadLog) void {
        // Write checkpoint sidecar on clean shutdown (PERF-0013).
        // Best-effort — errors are silently ignored since we're tearing down.
        if (self.options.checkpoint and !self.poisoned) {
            checkpoint_mod.writeCheckpoint(self.dir, self.filename, .{
                .last_lsn = self.current_lsn,
                .valid_end = self.file_end,
                .record_count = 0, // record_count not tracked by WAL; checkpoint serves as position hint
            }) catch {};
        }
        if (self.options.encryption_key) |*key| {
            encryption.secureZero(key);
        }
        // Free the owned filename copy (QA-0067).
        self.allocator.free(self.filename);
        // Guard: if the WAL was poisoned because reopenOrPoison failed to
        // open a new fd, self.file still holds the stale (already-closed)
        // handle. Closing it again triggers EBADF → unreachable in
        // ReleaseFast/ReleaseSmall (UB). Skip the close when poisoned
        // (SEC-0037, CWE-675).
        if (!self.poisoned) {
            self.file.close();
        }
    }

    // -------------------------------------------------------------------------
    // Write path
    // -------------------------------------------------------------------------

    /// Append a single record to the WAL.
    ///
    /// Increments the LSN, serialises and writes the record, and — unless
    /// `options.manual_sync` is true — issues an `fsync`.
    ///
    /// Returns the LSN assigned to this record.
    pub fn append(self: *WriteAheadLog, payload: []const u8) !u64 {
        return self.appendWithLsn(self.current_lsn + 1, payload);
    }

    /// Append a single record with a caller-provided LSN.
    ///
    /// The provided LSN must be strictly greater than the current LSN
    /// (monotonicity invariant). Returns `error.InvalidLsn` if violated.
    ///
    /// This is useful for consumers that maintain their own sequence
    /// numbering (e.g., Raft log indices) and need the WAL LSN to match.
    pub fn appendWithLsn(self: *WriteAheadLog, lsn: u64, payload: []const u8) !u64 {
        if (self.poisoned) return error.WalPoisoned;
        if (lsn <= self.current_lsn) return error.InvalidLsn;

        // Record file position before write so we can truncate on error (SEC-0030).
        const pre_write_pos = self.file_end;

        if (self.options.encryption_key) |*key| {
            // Encrypt-then-write path: stack-buffer for small payloads (PERF-0001).
            const bytes_written = encryption.encryptAndWriteToFile(
                self.allocator,
                self.file,
                key,
                lsn,
                payload,
            ) catch |err| {
                // Truncate any partial write to prevent torn records (SEC-0030).
                self.file.seekTo(pre_write_pos) catch {};
                std.posix.ftruncate(self.file.handle, pre_write_pos) catch {};
                return err;
            };
            self.file_end += bytes_written;
            self.bytes_since_compact += bytes_written;
        } else {
            // Plaintext path.
            const bytes_written = record.writeToFile(self.allocator, self.file, lsn, payload) catch |err| {
                self.file.seekTo(pre_write_pos) catch {};
                std.posix.ftruncate(self.file.handle, pre_write_pos) catch {};
                return err;
            };
            self.file_end += bytes_written;
            self.bytes_since_compact += bytes_written;
        }

        // LSN only advances after successful write (SEC-0030).
        self.current_lsn = lsn;

        if (!self.options.manual_sync) {
            self.appends_since_sync +|= 1; // Saturating add (SEC-0031).
            if (self.appends_since_sync >= self.options.sync_every_n) {
                try std.posix.fdatasync(self.file.handle);
                self.appends_since_sync = 0;
            }
        }

        return lsn;
    }

    /// Append multiple records in a single batch with at most one `fdatasync`.
    ///
    /// All records are written before the sync decision is made.  If
    /// `options.manual_sync` is `false` (the default), a single `fsync` is
    /// issued after all records are written, amortising the sync cost across
    /// many appends.  If `options.manual_sync` is `true`, no automatic sync
    /// is issued and the caller is responsible for calling `sync()` explicitly.
    ///
    /// Returns the LSN assigned to the last record in the batch.
    /// Errors if `payloads` is empty (there is nothing to flush).
    pub fn appendBatch(self: *WriteAheadLog, payloads: []const []const u8) !u64 {
        if (self.poisoned) return error.WalPoisoned;
        if (payloads.len == 0) return error.EmptyBatch; // SEC-0023

        // Build auto-incrementing LSN array.
        const lsns = try self.allocator.alloc(u64, payloads.len);
        defer self.allocator.free(lsns);
        var next_lsn = self.current_lsn;
        for (lsns) |*l| {
            next_lsn += 1;
            l.* = next_lsn;
        }

        return self.appendBatchWithLsns(lsns, payloads);
    }

    /// Append multiple records with caller-provided LSNs in a single batch.
    ///
    /// Each LSN must be strictly greater than the previous one and greater
    /// than the current WAL LSN (monotonicity invariant). Returns
    /// `error.InvalidLsn` if violated.
    ///
    /// `lsns` and `payloads` must have the same length; returns
    /// `error.EmptyBatch` if both are empty.
    ///
    /// This is useful for consumers that maintain their own sequence
    /// numbering (e.g., Raft log indices) and need WAL LSNs to match.
    pub fn appendBatchWithLsns(self: *WriteAheadLog, lsns: []const u64, payloads: []const []const u8) !u64 {
        if (self.poisoned) return error.WalPoisoned;
        if (payloads.len == 0) return error.EmptyBatch; // SEC-0023
        if (lsns.len != payloads.len) return error.InvalidLsn;

        // Validate monotonicity of provided LSNs.
        var prev_lsn = self.current_lsn;
        for (lsns) |lsn| {
            if (lsn <= prev_lsn) return error.InvalidLsn;
            prev_lsn = lsn;
        }

        // Compute total buffer size needed for all records (PERF-0002).
        var total_size: usize = 0;
        for (payloads) |payload| {
            const rec_size = record.HEADER_SIZE + payload.len + record.CRC_SIZE;
            if (self.options.encryption_key != null) {
                total_size += encryption.ENCRYPTION_OVERHEAD + rec_size;
            } else {
                total_size += rec_size;
            }
        }

        const buf = try self.allocator.alloc(u8, total_size);
        defer {
            // Zeroize the buffer when encryption is active to prevent plaintext
            // residue in freed heap memory (SEC-0019). The scratch region at the
            // end of buf holds serialized plaintext records before encryption.
            if (self.options.encryption_key != null) {
                encryption.secureZero(buf);
            }
            self.allocator.free(buf);
        }

        var offset: usize = 0;
        var last_lsn: u64 = self.current_lsn;

        for (payloads, 0..) |payload, i| {
            last_lsn = lsns[i];

            const rec_size = record.HEADER_SIZE + payload.len + record.CRC_SIZE;

            if (self.options.encryption_key) |*key| {
                const enc_size = encryption.ENCRYPTION_OVERHEAD + rec_size;
                // Serialize plaintext record into a temp region, then encrypt.
                // Use the end of `buf` as scratch space for the plaintext.
                const pt_start = total_size - rec_size;
                record.serializeInto(buf[pt_start..][0..rec_size], last_lsn, payload);
                encryption.encryptInto(buf[offset..][0..enc_size], key, buf[pt_start..][0..rec_size]);
                offset += enc_size;
            } else {
                record.serializeInto(buf[offset..][0..rec_size], last_lsn, payload);
                offset += rec_size;
            }
        }

        // Record file position before write so we can truncate on error (SEC-0030).
        const pre_write_pos = self.file_end;

        self.file.writeAll(buf[0..offset]) catch |err| {
            // Truncate any partial write to prevent torn records (SEC-0030).
            self.file.seekTo(pre_write_pos) catch {};
            std.posix.ftruncate(self.file.handle, pre_write_pos) catch {};
            return err;
        };

        // LSN only advances after successful write (SEC-0030).
        self.current_lsn = last_lsn;
        self.file_end += offset;
        self.bytes_since_compact += offset;

        // Respect sync_every_n threshold, consistent with append() (SEC-0028).
        if (!self.options.manual_sync) {
            self.appends_since_sync +|= @intCast(payloads.len); // Saturating add (SEC-0031).
            if (self.appends_since_sync >= self.options.sync_every_n) {
                try std.posix.fdatasync(self.file.handle);
                self.appends_since_sync = 0;
            }
        }

        return last_lsn;
    }

    /// Explicitly flush all buffered writes to durable storage.
    ///
    /// Uses `fdatasync` (metadata-update not needed for appends).
    /// Use this when `options.manual_sync` is `true`.
    pub fn sync(self: *WriteAheadLog) !void {
        if (self.poisoned) return error.WalPoisoned;
        try std.posix.fdatasync(self.file.handle);
        self.appends_since_sync = 0;
    }

    /// Remove all records with LSN <= `up_to_lsn` by rewriting the WAL.
    ///
    /// The rewrite is atomic (temp file + fsync + rename).  After a successful
    /// compaction the write cursor is positioned at the new end of file and
    /// `bytes_since_compact` is reset to zero.
    ///
    /// If compaction fails the file handle is reopened so the WAL remains
    /// usable, and the original error is propagated.
    ///
    /// If the file handle cannot be reopened after either a failed or
    /// successful compaction, the WAL is marked poisoned and subsequent
    /// operations will return `error.WalPoisoned` (SEC-0008).
    pub fn compact(self: *WriteAheadLog, up_to_lsn: u64) !void {
        if (self.poisoned) return error.WalPoisoned;

        // Close the current file handle — compaction will rename a new file
        // over it and we must not hold a stale handle afterward.
        self.file.close();

        // Run the atomic rewrite.  On error, attempt to reopen the original
        // file so the WAL remains usable.
        const result = compaction.compact(
            self.allocator,
            self.dir,
            self.filename,
            up_to_lsn,
            if (self.options.encryption_key) |*key| key else null,
            self.options.zero_copy_compaction,
        ) catch |err| {
            self.reopenOrPoison();
            return err;
        };

        // Reopen the (now compacted) file for appending (QA-0010).
        self.reopenOrPoison();
        if (self.poisoned) return error.WalPoisoned;

        // Update bookkeeping.
        self.file_end = result.new_size;
        self.bytes_since_compact = 0;
        self.appends_since_sync = 0; // finalizeTempFile already fsynced (QA-0036)

        // Invalidate the checkpoint — the file layout changed (PERF-0013).
        if (self.options.checkpoint) {
            checkpoint_mod.deleteCheckpoint(self.dir, self.filename);
        }
    }

    /// Reopen the WAL file for appending and seek to end.  If either the
    /// open or seek fails the WAL is marked poisoned (SEC-0008, QA-0010).
    ///
    /// Invariant (SEC-0037): when this function sets `poisoned = true`,
    /// `self.file` is always already-closed (stale). This allows `deinit`
    /// to skip the close unconditionally when poisoned, preventing a
    /// double-close that would trigger EBADF → `unreachable` in
    /// ReleaseFast/ReleaseSmall builds (CWE-675).
    fn reopenOrPoison(self: *WriteAheadLog) void {
        self.file = self.dir.openFile(self.filename, .{ .mode = .read_write }) catch {
            // openFile failed — self.file still holds the stale (closed) fd.
            self.poisoned = true;
            return;
        };
        self.file.seekFromEnd(0) catch {
            // seekFromEnd failed — self.file holds a valid fd that we must
            // close now so the poisoned invariant (stale fd) holds.
            self.file.close();
            self.poisoned = true;
        };
    }

    // -------------------------------------------------------------------------
    // Getters
    // -------------------------------------------------------------------------

    /// Return the LSN of the most recently appended record (0 if empty).
    pub fn currentLsn(self: *const WriteAheadLog) u64 {
        return self.current_lsn;
    }

    /// Return the number of bytes written since the last compaction (or since
    /// the file was first opened, if it has never been compacted).
    pub fn bytesSinceCompact(self: *const WriteAheadLog) u64 {
        return self.bytes_since_compact;
    }

    // -------------------------------------------------------------------------
    // Iterator
    // -------------------------------------------------------------------------

    /// Open a read-only iterator over records starting after `from_lsn`.
    ///
    /// The iterator uses an independent file handle so it does not disturb the
    /// write position.  Call `Iterator.deinit` when done.
    pub fn iterator(self: *const WriteAheadLog, from_lsn: u64) !Iterator {
        const read_file = try self.dir.openFile(self.filename, .{ .mode = .read_only });
        return Iterator.init(
            self.allocator,
            read_file,
            from_lsn,
            if (self.options.encryption_key) |k| k else null,
        );
    }

    /// A forward iterator over WAL records (extracted to iterator.zig — QA-0001).
    pub const Iterator = @import("iterator.zig").Iterator;
};

// ============================================================================
// Tests
// ============================================================================

test "init: filename is owned copy, safe after caller frees original (QA-0067)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Allocate a filename on the heap, pass it to init, then free the original.
    // The WAL must continue to work because it owns a copy.
    const heap_name = try allocator.dupe(u8, "owned.wal");
    var wal = try WriteAheadLog.init(allocator, tmp.dir, heap_name, .{});
    defer wal.deinit();

    // Free the caller's original — WAL must still function.
    allocator.free(heap_name);

    // Append and iterate to prove the internal filename copy works.
    _ = try wal.append("data");
    var iter = try wal.iterator(0);
    defer iter.deinit();
    var entry = try iter.next();
    try std.testing.expect(entry != null);
    defer entry.?.deinit();
    try std.testing.expectEqualSlices(u8, "data", entry.?.payload);
}

test "init: creates WAL file, append returns LSN 1" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var wal = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{});
    defer wal.deinit();

    const lsn = try wal.append("hello");
    try std.testing.expectEqual(@as(u64, 1), lsn);
}

test "append: LSN increases monotonically" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var wal = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{});
    defer wal.deinit();

    const l1 = try wal.append("a");
    const l2 = try wal.append("b");
    const l3 = try wal.append("c");

    try std.testing.expectEqual(@as(u64, 1), l1);
    try std.testing.expectEqual(@as(u64, 2), l2);
    try std.testing.expectEqual(@as(u64, 3), l3);
    try std.testing.expectEqual(@as(u64, 3), wal.currentLsn());
}

test "appendBatch: single fsync for multiple records" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Use manual_sync so we can verify no automatic sync fires between records.
    var wal = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{ .manual_sync = true });
    defer wal.deinit();

    const payloads = [_][]const u8{ "alpha", "beta", "gamma" };
    const last_lsn = try wal.appendBatch(&payloads);

    try std.testing.expectEqual(@as(u64, 3), last_lsn);
    try std.testing.expectEqual(@as(u64, 3), wal.currentLsn());

    // Explicit sync — must not error.
    try wal.sync();
}

test "appendBatch: empty payloads returns EmptyBatch (SEC-0023)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var wal = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{});
    defer wal.deinit();

    const empty = [_][]const u8{};
    const result = wal.appendBatch(&empty);
    try std.testing.expectError(error.EmptyBatch, result);

    // LSN should not have changed.
    try std.testing.expectEqual(@as(u64, 0), wal.currentLsn());
}

test "init: recovers state after close and reopen" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var wal = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{});
        defer wal.deinit();
        _ = try wal.append("record-1");
        _ = try wal.append("record-2");
        _ = try wal.append("record-3");
        try std.testing.expectEqual(@as(u64, 3), wal.currentLsn());
    }

    // Re-open the same file — should recover LSN = 3.
    {
        var wal = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{});
        defer wal.deinit();
        try std.testing.expectEqual(@as(u64, 3), wal.currentLsn());

        // The next append should be LSN 4.
        const lsn = try wal.append("record-4");
        try std.testing.expectEqual(@as(u64, 4), lsn);
    }
}

test "bytesSinceCompact: tracks bytes written" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var wal = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{});
    defer wal.deinit();

    try std.testing.expectEqual(@as(u64, 0), wal.bytesSinceCompact());

    const payload = "hello";
    // Each record = HEADER_SIZE(12) + payload.len + CRC_SIZE(4)
    const expected_per_record: u64 = record.HEADER_SIZE + payload.len + record.CRC_SIZE;

    _ = try wal.append(payload);
    try std.testing.expectEqual(expected_per_record, wal.bytesSinceCompact());

    _ = try wal.append(payload);
    try std.testing.expectEqual(expected_per_record * 2, wal.bytesSinceCompact());
}

test "iterator: reads all records from beginning" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var wal = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{});
    defer wal.deinit();

    _ = try wal.append("first");
    _ = try wal.append("second");
    _ = try wal.append("third");

    var iter = try wal.iterator(0);
    defer iter.deinit();

    var maybe_e1 = try iter.next();
    try std.testing.expect(maybe_e1 != null);
    defer maybe_e1.?.deinit();
    try std.testing.expectEqual(@as(u64, 1), maybe_e1.?.lsn);
    try std.testing.expectEqualSlices(u8, "first", maybe_e1.?.payload);

    var maybe_e2 = try iter.next();
    try std.testing.expect(maybe_e2 != null);
    defer maybe_e2.?.deinit();
    try std.testing.expectEqual(@as(u64, 2), maybe_e2.?.lsn);
    try std.testing.expectEqualSlices(u8, "second", maybe_e2.?.payload);

    var maybe_e3 = try iter.next();
    try std.testing.expect(maybe_e3 != null);
    defer maybe_e3.?.deinit();
    try std.testing.expectEqual(@as(u64, 3), maybe_e3.?.lsn);
    try std.testing.expectEqualSlices(u8, "third", maybe_e3.?.payload);

    const maybe_e4 = try iter.next();
    try std.testing.expect(maybe_e4 == null);
}

test "iterator: from_lsn skips earlier records" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var wal = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{});
    defer wal.deinit();

    _ = try wal.append("one");
    _ = try wal.append("two");
    _ = try wal.append("three");
    _ = try wal.append("four");

    // Start iteration after LSN 2 — should see only LSN 3 and 4.
    var iter = try wal.iterator(2);
    defer iter.deinit();

    var maybe_e3 = try iter.next();
    try std.testing.expect(maybe_e3 != null);
    defer maybe_e3.?.deinit();
    try std.testing.expectEqual(@as(u64, 3), maybe_e3.?.lsn);
    try std.testing.expectEqualSlices(u8, "three", maybe_e3.?.payload);

    var maybe_e4 = try iter.next();
    try std.testing.expect(maybe_e4 != null);
    defer maybe_e4.?.deinit();
    try std.testing.expectEqual(@as(u64, 4), maybe_e4.?.lsn);

    const eof = try iter.next();
    try std.testing.expect(eof == null);
}

test "iterator: empty WAL returns null immediately" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var wal = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{});
    defer wal.deinit();

    var iter = try wal.iterator(0);
    defer iter.deinit();

    const entry = try iter.next();
    try std.testing.expect(entry == null);
}

test "compact: removes records and allows continued append" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var wal = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{});
    defer wal.deinit();

    // Append three records — LSNs 1, 2, 3.
    _ = try wal.append("one");
    _ = try wal.append("two");
    _ = try wal.append("three");

    // Compact at LSN 2: records with LSN <= 2 ("one", "two") are removed.
    try wal.compact(2);

    // bytes_since_compact resets to 0 after a successful compaction.
    try std.testing.expectEqual(@as(u64, 0), wal.bytesSinceCompact());

    // Append a fourth record — should receive LSN 4 (current_lsn is preserved).
    const lsn4 = try wal.append("four");
    try std.testing.expectEqual(@as(u64, 4), lsn4);

    // Iterate from 0: should see only LSN 3 ("three") and LSN 4 ("four").
    var iter = try wal.iterator(0);
    defer iter.deinit();

    var maybe_e3 = try iter.next();
    try std.testing.expect(maybe_e3 != null);
    defer maybe_e3.?.deinit();
    try std.testing.expectEqual(@as(u64, 3), maybe_e3.?.lsn);
    try std.testing.expectEqualSlices(u8, "three", maybe_e3.?.payload);

    var maybe_e4 = try iter.next();
    try std.testing.expect(maybe_e4 != null);
    defer maybe_e4.?.deinit();
    try std.testing.expectEqual(@as(u64, 4), maybe_e4.?.lsn);
    try std.testing.expectEqualSlices(u8, "four", maybe_e4.?.payload);

    const eof = try iter.next();
    try std.testing.expect(eof == null);
}

test "encrypted: append and iterate with encryption" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    var wal = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{
        .encryption_key = key,
    });
    defer wal.deinit();

    const lsn1 = try wal.append("encrypted-hello");
    const lsn2 = try wal.append("encrypted-world");

    try std.testing.expectEqual(@as(u64, 1), lsn1);
    try std.testing.expectEqual(@as(u64, 2), lsn2);

    // Iterate and verify payloads match.
    var iter = try wal.iterator(0);
    defer iter.deinit();

    var maybe_e1 = try iter.next();
    try std.testing.expect(maybe_e1 != null);
    defer maybe_e1.?.deinit();
    try std.testing.expectEqual(@as(u64, 1), maybe_e1.?.lsn);
    try std.testing.expectEqualSlices(u8, "encrypted-hello", maybe_e1.?.payload);

    var maybe_e2 = try iter.next();
    try std.testing.expect(maybe_e2 != null);
    defer maybe_e2.?.deinit();
    try std.testing.expectEqual(@as(u64, 2), maybe_e2.?.lsn);
    try std.testing.expectEqualSlices(u8, "encrypted-world", maybe_e2.?.payload);

    const eof_enc = try iter.next();
    try std.testing.expect(eof_enc == null);
}

test "encrypted: recovery after close and reopen" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    // Write records with encryption, then close.
    {
        var wal = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{
            .encryption_key = key,
        });
        defer wal.deinit();
        _ = try wal.append("record-1");
        _ = try wal.append("record-2");
        _ = try wal.append("record-3");
        try std.testing.expectEqual(@as(u64, 3), wal.currentLsn());
    }

    // Reopen with the same key — should recover LSN = 3.
    {
        var wal = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{
            .encryption_key = key,
        });
        defer wal.deinit();
        try std.testing.expectEqual(@as(u64, 3), wal.currentLsn());

        // The next append should be LSN 4.
        const lsn = try wal.append("record-4");
        try std.testing.expectEqual(@as(u64, 4), lsn);

        // Iterate all 4 records.
        var iter = try wal.iterator(0);
        defer iter.deinit();

        const expected = [_][]const u8{ "record-1", "record-2", "record-3", "record-4" };
        for (expected, 1..) |expected_payload, i| {
            var maybe_entry = try iter.next();
            try std.testing.expect(maybe_entry != null);
            defer maybe_entry.?.deinit();
            try std.testing.expectEqual(@as(u64, i), maybe_entry.?.lsn);
            try std.testing.expectEqualSlices(u8, expected_payload, maybe_entry.?.payload);
        }

        const eof_enc = try iter.next();
        try std.testing.expect(eof_enc == null);
    }
}

test "encrypted: appendBatch with encryption" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    var wal = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{
        .encryption_key = key,
    });
    defer wal.deinit();

    const payloads = [_][]const u8{ "alpha", "beta", "gamma" };
    const last_lsn = try wal.appendBatch(&payloads);

    try std.testing.expectEqual(@as(u64, 3), last_lsn);
    try std.testing.expectEqual(@as(u64, 3), wal.currentLsn());

    // Iterate and verify.
    var iter = try wal.iterator(0);
    defer iter.deinit();

    for (payloads, 1..) |expected_payload, i| {
        var maybe_entry = try iter.next();
        try std.testing.expect(maybe_entry != null);
        defer maybe_entry.?.deinit();
        try std.testing.expectEqual(@as(u64, i), maybe_entry.?.lsn);
        try std.testing.expectEqualSlices(u8, expected_payload, maybe_entry.?.payload);
    }

    const eof_enc = try iter.next();
    try std.testing.expect(eof_enc == null);
}

test "encrypted: iterator from_lsn skips earlier encrypted records" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    var wal = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{
        .encryption_key = key,
    });
    defer wal.deinit();

    _ = try wal.append("one");
    _ = try wal.append("two");
    _ = try wal.append("three");
    _ = try wal.append("four");

    // Start after LSN 2 — should see only 3 and 4.
    var iter = try wal.iterator(2);
    defer iter.deinit();

    var maybe_e3 = try iter.next();
    try std.testing.expect(maybe_e3 != null);
    defer maybe_e3.?.deinit();
    try std.testing.expectEqual(@as(u64, 3), maybe_e3.?.lsn);
    try std.testing.expectEqualSlices(u8, "three", maybe_e3.?.payload);

    var maybe_e4 = try iter.next();
    try std.testing.expect(maybe_e4 != null);
    defer maybe_e4.?.deinit();
    try std.testing.expectEqual(@as(u64, 4), maybe_e4.?.lsn);
    try std.testing.expectEqualSlices(u8, "four", maybe_e4.?.payload);

    const eof_enc = try iter.next();
    try std.testing.expect(eof_enc == null);
}

test "deinit: encryption key zeroized after close (SEC-0002)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    var wal_inst = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{
        .encryption_key = key,
    });
    _ = try wal_inst.append("data");

    // Verify key is present before deinit.
    try std.testing.expect(!std.mem.allEqual(u8, &wal_inst.options.encryption_key.?, 0));

    wal_inst.deinit();

    // After deinit, key must be zeroed.
    try std.testing.expect(std.mem.allEqual(u8, &wal_inst.options.encryption_key.?, 0));
}

test "iterator deinit: encryption key zeroized (SEC-0002)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    var wal_inst = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{
        .encryption_key = key,
    });
    defer wal_inst.deinit();
    _ = try wal_inst.append("data");

    var iter = try wal_inst.iterator(0);

    // Verify key is present before deinit.
    try std.testing.expect(!std.mem.allEqual(u8, &iter.encryption_key.?, 0));

    iter.deinit();

    // After deinit, key must be zeroed.
    try std.testing.expect(std.mem.allEqual(u8, &iter.encryption_key.?, 0));
}

test "init: tightens permissions on existing files to 0o600 (SEC-0021)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Create a file with world-readable permissions (simulating pre-SEC-0015 file).
    const f = try tmp.dir.createFile("wal.log", .{ .read = true, .mode = 0o644 });
    f.close();

    // Verify file is world-readable.
    const stat_before = try tmp.dir.statFile("wal.log");
    // Check group-read bit (0o040) — should be set for 0o644.
    try std.testing.expect(stat_before.mode & 0o040 != 0);

    // Open via WAL init — should tighten to 0o600.
    var wal = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{});
    defer wal.deinit();

    // Verify permissions were tightened.
    const stat_after = try tmp.dir.statFile("wal.log");
    // group-read and other-read bits should be cleared.
    try std.testing.expectEqual(@as(u32, 0), stat_after.mode & 0o077);
}

test "sync_every_n: counter increments and resets (QA-0021)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var log = try WriteAheadLog.init(allocator, tmp.dir, "test.wal", .{
        .sync_every_n = 3,
    });
    defer log.deinit();

    // After 1 append, counter should be 1
    _ = try log.append("one");
    try std.testing.expectEqual(@as(u32, 1), log.appends_since_sync);

    // After 2 appends, counter should be 2
    _ = try log.append("two");
    try std.testing.expectEqual(@as(u32, 2), log.appends_since_sync);

    // After 3 appends, counter should reset to 0 (sync fired)
    _ = try log.append("three");
    try std.testing.expectEqual(@as(u32, 0), log.appends_since_sync);

    // Counter starts again
    _ = try log.append("four");
    try std.testing.expectEqual(@as(u32, 1), log.appends_since_sync);
}

test "sync_every_n: manual_sync skips counter (QA-0021)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var log = try WriteAheadLog.init(allocator, tmp.dir, "test.wal", .{
        .manual_sync = true,
        .sync_every_n = 2,
    });
    defer log.deinit();

    _ = try log.append("one");
    try std.testing.expectEqual(@as(u32, 0), log.appends_since_sync);

    _ = try log.append("two");
    try std.testing.expectEqual(@as(u32, 0), log.appends_since_sync);
}

test "sync_every_n: appendBatch respects threshold (QA-0021)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var log = try WriteAheadLog.init(allocator, tmp.dir, "test.wal", .{
        .sync_every_n = 5,
    });
    defer log.deinit();

    // Batch of 3 — should set counter to 3
    const batch1 = [_][]const u8{ "a", "b", "c" };
    _ = try log.appendBatch(&batch1);
    try std.testing.expectEqual(@as(u32, 3), log.appends_since_sync);

    // Batch of 3 more — total 6 >= 5, should trigger sync and reset
    const batch2 = [_][]const u8{ "d", "e", "f" };
    _ = try log.appendBatch(&batch2);
    try std.testing.expectEqual(@as(u32, 0), log.appends_since_sync);
}

test "poisoned WAL rejects all operations (QA-0017)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var wal = try WriteAheadLog.init(allocator, tmp.dir, "test.wal", .{ .manual_sync = true });
    defer wal.deinit();

    // Verify normal operation works first.
    _ = try wal.append("before poison");

    // Poison the WAL.
    wal.poisoned = true;

    // All write operations should return WalPoisoned.
    try std.testing.expectError(error.WalPoisoned, wal.append("after poison"));

    const batch = [_][]const u8{ "a", "b" };
    try std.testing.expectError(error.WalPoisoned, wal.appendBatch(&batch));

    try std.testing.expectError(error.WalPoisoned, wal.sync());
}

test "checkpoint: O(1) recovery on clean reopen (PERF-0013)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Write records with checkpoint enabled, then close cleanly.
    {
        var wal = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{ .checkpoint = true });
        defer wal.deinit();
        _ = try wal.append("one");
        _ = try wal.append("two");
        _ = try wal.append("three");
    }

    // Verify the checkpoint file was created.
    const ckpt = checkpoint_mod.readCheckpoint(tmp.dir, "wal.log");
    try std.testing.expect(ckpt != null);
    try std.testing.expectEqual(@as(u64, 3), ckpt.?.last_lsn);

    // Reopen with checkpoint — should skip full scan.
    {
        var wal = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{ .checkpoint = true });
        defer wal.deinit();
        try std.testing.expectEqual(@as(u64, 3), wal.currentLsn());

        // Append more — LSN should continue from 3.
        const lsn = try wal.append("four");
        try std.testing.expectEqual(@as(u64, 4), lsn);
    }
}

test "checkpoint: incremental recovery after append without clean shutdown (PERF-0013)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Write 2 records and close cleanly — creates checkpoint at LSN 2.
    {
        var wal = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{ .checkpoint = true });
        defer wal.deinit();
        _ = try wal.append("one");
        _ = try wal.append("two");
    }

    // Reopen, write 2 more records, simulate a crash (no deinit → no checkpoint update).
    {
        var wal = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{ .checkpoint = true });
        _ = try wal.append("three");
        _ = try wal.append("four");
        // Skip deinit — simulate crash. Manually close the file to avoid leak.
        wal.file.close();
        allocator.free(wal.filename);
    }

    // Reopen with checkpoint — should do incremental recovery from checkpoint
    // position (LSN 2) and find the 2 new records.
    {
        var wal = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{ .checkpoint = true });
        defer wal.deinit();
        try std.testing.expectEqual(@as(u64, 4), wal.currentLsn());
    }
}

test "checkpoint: deleted after compaction (PERF-0013)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var wal = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{ .checkpoint = true });
        defer wal.deinit();
        _ = try wal.append("one");
        _ = try wal.append("two");
        _ = try wal.append("three");

        // Compact — should delete checkpoint.
        try wal.compact(2);

        // Checkpoint should be gone.
        try std.testing.expect(checkpoint_mod.readCheckpoint(tmp.dir, "wal.log") == null);
    }

    // After deinit, a fresh checkpoint should be written.
    try std.testing.expect(checkpoint_mod.readCheckpoint(tmp.dir, "wal.log") != null);
}

test "checkpoint: falls back to full scan when disabled" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Write with checkpoint enabled.
    {
        var wal = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{ .checkpoint = true });
        defer wal.deinit();
        _ = try wal.append("one");
        _ = try wal.append("two");
    }

    // Reopen with checkpoint disabled — should still work via full scan.
    {
        var wal = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{ .checkpoint = false });
        defer wal.deinit();
        try std.testing.expectEqual(@as(u64, 2), wal.currentLsn());
    }
}

test "zero_copy_compaction: compact uses kernel transfer (PERF-0014)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var wal = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{
        .zero_copy_compaction = true,
    });
    defer wal.deinit();

    _ = try wal.append("one");
    _ = try wal.append("two");
    _ = try wal.append("three");
    _ = try wal.append("four");

    // Compact with zero-copy enabled.
    try wal.compact(2);

    // Verify records 3 and 4 remain.
    var iter = try wal.iterator(0);
    defer iter.deinit();

    var e3 = try iter.next();
    try std.testing.expect(e3 != null);
    defer e3.?.deinit();
    try std.testing.expectEqual(@as(u64, 3), e3.?.lsn);

    var e4 = try iter.next();
    try std.testing.expect(e4 != null);
    defer e4.?.deinit();
    try std.testing.expectEqual(@as(u64, 4), e4.?.lsn);

    const eof = try iter.next();
    try std.testing.expect(eof == null);

    // New append should work.
    const lsn5 = try wal.append("five");
    try std.testing.expectEqual(@as(u64, 5), lsn5);
}

// =========================================================================
// Tests: appendWithLsn / appendBatchWithLsns (caller-provided LSNs)
// =========================================================================

test "appendWithLsn: basic append with caller-provided LSNs" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var wal = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{});
    defer wal.deinit();

    // Append with explicit LSNs (e.g., Raft log indices starting at 100).
    const lsn1 = try wal.appendWithLsn(100, "entry-100");
    try std.testing.expectEqual(@as(u64, 100), lsn1);
    try std.testing.expectEqual(@as(u64, 100), wal.currentLsn());

    const lsn2 = try wal.appendWithLsn(101, "entry-101");
    try std.testing.expectEqual(@as(u64, 101), lsn2);

    // Verify records are readable with correct LSNs.
    var iter = try wal.iterator(0);
    defer iter.deinit();

    var e1 = try iter.next();
    try std.testing.expect(e1 != null);
    defer e1.?.deinit();
    try std.testing.expectEqual(@as(u64, 100), e1.?.lsn);
    try std.testing.expectEqualStrings("entry-100", e1.?.payload);

    var e2 = try iter.next();
    try std.testing.expect(e2 != null);
    defer e2.?.deinit();
    try std.testing.expectEqual(@as(u64, 101), e2.?.lsn);
    try std.testing.expectEqualStrings("entry-101", e2.?.payload);

    const eof = try iter.next();
    try std.testing.expect(eof == null);
}

test "appendWithLsn: rejects non-monotonic LSN" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var wal = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{});
    defer wal.deinit();

    _ = try wal.appendWithLsn(10, "first");

    // Same LSN should fail.
    try std.testing.expectError(error.InvalidLsn, wal.appendWithLsn(10, "dup"));

    // Lower LSN should fail.
    try std.testing.expectError(error.InvalidLsn, wal.appendWithLsn(5, "lower"));

    // Zero LSN should fail.
    try std.testing.expectError(error.InvalidLsn, wal.appendWithLsn(0, "zero"));

    // Higher LSN should succeed (gaps are allowed).
    const lsn = try wal.appendWithLsn(1000, "jump");
    try std.testing.expectEqual(@as(u64, 1000), lsn);
}

test "appendWithLsn: survives crash recovery with non-sequential LSNs" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Write records with gaps in LSN sequence (simulating snapshot restore).
    {
        var wal = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{});
        defer wal.deinit();

        _ = try wal.appendWithLsn(500, "after-snapshot-a");
        _ = try wal.appendWithLsn(501, "after-snapshot-b");
        _ = try wal.appendWithLsn(502, "after-snapshot-c");
    }

    // Reopen — recovery should find all 3 records with correct LSNs.
    {
        var wal = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{});
        defer wal.deinit();

        try std.testing.expectEqual(@as(u64, 502), wal.currentLsn());

        // Continue appending after recovery.
        const lsn = try wal.appendWithLsn(503, "after-recovery");
        try std.testing.expectEqual(@as(u64, 503), lsn);

        // Verify all 4 records.
        var iter = try wal.iterator(0);
        defer iter.deinit();

        var count: u64 = 0;
        while (true) {
            var entry = try iter.next() orelse break;
            defer entry.deinit();
            count += 1;
        }
        try std.testing.expectEqual(@as(u64, 4), count);
    }
}

test "appendWithLsn: compact works with caller-provided LSNs" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var wal = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{});
    defer wal.deinit();

    _ = try wal.appendWithLsn(100, "a");
    _ = try wal.appendWithLsn(101, "b");
    _ = try wal.appendWithLsn(102, "c");
    _ = try wal.appendWithLsn(103, "d");

    // Compact up to LSN 101 — should remove records 100 and 101.
    try wal.compact(101);

    // Verify only LSN 102 and 103 remain.
    var iter = try wal.iterator(0);
    defer iter.deinit();

    var e1 = try iter.next();
    try std.testing.expect(e1 != null);
    defer e1.?.deinit();
    try std.testing.expectEqual(@as(u64, 102), e1.?.lsn);

    var e2 = try iter.next();
    try std.testing.expect(e2 != null);
    defer e2.?.deinit();
    try std.testing.expectEqual(@as(u64, 103), e2.?.lsn);

    const eof = try iter.next();
    try std.testing.expect(eof == null);

    // Continue appending after compact.
    const lsn = try wal.appendWithLsn(104, "e");
    try std.testing.expectEqual(@as(u64, 104), lsn);
}

test "appendBatchWithLsns: basic batch with caller-provided LSNs" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var wal = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{});
    defer wal.deinit();

    const lsns = [_]u64{ 50, 51, 52 };
    const payloads = [_][]const u8{ "alpha", "beta", "gamma" };
    const last = try wal.appendBatchWithLsns(&lsns, &payloads);
    try std.testing.expectEqual(@as(u64, 52), last);
    try std.testing.expectEqual(@as(u64, 52), wal.currentLsn());

    // Verify all records.
    var iter = try wal.iterator(0);
    defer iter.deinit();

    var e1 = try iter.next();
    try std.testing.expect(e1 != null);
    defer e1.?.deinit();
    try std.testing.expectEqual(@as(u64, 50), e1.?.lsn);
    try std.testing.expectEqualStrings("alpha", e1.?.payload);

    var e2 = try iter.next();
    try std.testing.expect(e2 != null);
    defer e2.?.deinit();
    try std.testing.expectEqual(@as(u64, 51), e2.?.lsn);

    var e3 = try iter.next();
    try std.testing.expect(e3 != null);
    defer e3.?.deinit();
    try std.testing.expectEqual(@as(u64, 52), e3.?.lsn);

    const eof = try iter.next();
    try std.testing.expect(eof == null);
}

test "appendBatchWithLsns: rejects non-monotonic LSNs" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var wal = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{});
    defer wal.deinit();

    // Non-monotonic within batch.
    const bad_lsns = [_]u64{ 10, 9, 11 };
    const payloads = [_][]const u8{ "a", "b", "c" };
    try std.testing.expectError(error.InvalidLsn, wal.appendBatchWithLsns(&bad_lsns, &payloads));

    // Duplicate within batch.
    const dup_lsns = [_]u64{ 10, 10, 11 };
    try std.testing.expectError(error.InvalidLsn, wal.appendBatchWithLsns(&dup_lsns, &payloads));

    // Length mismatch.
    const short_lsns = [_]u64{ 10, 11 };
    try std.testing.expectError(error.InvalidLsn, wal.appendBatchWithLsns(&short_lsns, &payloads));

    // Valid batch should still work after rejections.
    const good_lsns = [_]u64{ 10, 11, 12 };
    const last = try wal.appendBatchWithLsns(&good_lsns, &payloads);
    try std.testing.expectEqual(@as(u64, 12), last);
}

test "appendBatchWithLsns: rejects LSNs not greater than current" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var wal = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{});
    defer wal.deinit();

    _ = try wal.appendWithLsn(100, "existing");

    // Batch starting at or below current LSN should fail.
    const bad_lsns = [_]u64{ 100, 101, 102 };
    const payloads = [_][]const u8{ "a", "b", "c" };
    try std.testing.expectError(error.InvalidLsn, wal.appendBatchWithLsns(&bad_lsns, &payloads));

    // Batch starting above current LSN should succeed.
    const good_lsns = [_]u64{ 101, 102, 103 };
    const last = try wal.appendBatchWithLsns(&good_lsns, &payloads);
    try std.testing.expectEqual(@as(u64, 103), last);
}

test "appendWithLsn: mixed with auto-increment append" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var wal = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{});
    defer wal.deinit();

    // Start with caller-provided LSN.
    _ = try wal.appendWithLsn(42, "explicit");
    try std.testing.expectEqual(@as(u64, 42), wal.currentLsn());

    // Auto-increment continues from 42.
    const auto_lsn = try wal.append("auto");
    try std.testing.expectEqual(@as(u64, 43), auto_lsn);

    // Explicit LSN must be > 43.
    const explicit_lsn = try wal.appendWithLsn(100, "jump");
    try std.testing.expectEqual(@as(u64, 100), explicit_lsn);

    // Auto-increment continues from 100.
    const auto_lsn2 = try wal.append("auto2");
    try std.testing.expectEqual(@as(u64, 101), auto_lsn2);
}
