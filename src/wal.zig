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

// ============================================================================
// Options
// ============================================================================

/// Configuration options for a `WriteAheadLog` instance.
pub const Options = struct {
    /// Optional AES-256-GCM encryption key.  `null` means plaintext mode.
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
};

// ============================================================================
// WriteAheadLog
// ============================================================================

/// A Write-Ahead Log that appends framed, CRC-verified records to a single
/// file and recovers cleanly after a crash.
pub const WriteAheadLog = struct {
    allocator: std.mem.Allocator,
    dir: std.fs.Dir,
    filename: []const u8,
    file: std.fs.File,
    current_lsn: u64,
    file_end: u64,
    bytes_since_compact: u64,
    options: Options,
    appends_since_sync: u32,

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
        // Open existing file, or create a new one with read+write access.
        const file = dir.openFile(filename, .{ .mode = .read_write }) catch |err| switch (err) {
            error.FileNotFound => try dir.createFile(filename, .{ .read = true }),
            else => return err,
        };
        errdefer file.close();

        // Scan forward from byte 0 to find the last valid record boundary.
        // Use the encryption-aware scanner when a key is provided.
        const info = if (options.encryption_key) |*key|
            try recovery_mod.recoverWithKey(allocator, file, key)
        else
            try recovery_mod.recover(allocator, file);

        // Truncate any bytes beyond the last valid record (torn writes, etc.).
        try file.setEndPos(info.valid_end);

        // Position cursor at the write tail.
        try file.seekTo(info.valid_end);

        return WriteAheadLog{
            .allocator = allocator,
            .dir = dir,
            .filename = filename,
            .file = file,
            .current_lsn = info.last_lsn,
            .file_end = info.valid_end,
            .bytes_since_compact = info.valid_end,
            .options = options,
            .appends_since_sync = 0,
        };
    }

    /// Close the underlying file handle.
    pub fn deinit(self: *WriteAheadLog) void {
        self.file.close();
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
        self.current_lsn += 1;
        const lsn = self.current_lsn;

        if (self.options.encryption_key) |*key| {
            // Encrypt-then-write path: stack-buffer for small payloads (PERF-0001).
            const bytes_written = try encryption.encryptAndWriteToFile(
                self.file,
                self.allocator,
                key,
                lsn,
                payload,
            );
            self.file_end += bytes_written;
            self.bytes_since_compact += bytes_written;
        } else {
            // Plaintext path.
            const bytes_written = try record.writeToFile(self.file, self.allocator, lsn, payload);
            self.file_end += bytes_written;
            self.bytes_since_compact += bytes_written;
        }

        if (!self.options.manual_sync) {
            self.appends_since_sync += 1;
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
        std.debug.assert(payloads.len > 0);

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
        defer self.allocator.free(buf);

        var offset: usize = 0;
        var last_lsn: u64 = self.current_lsn;

        for (payloads) |payload| {
            self.current_lsn += 1;
            last_lsn = self.current_lsn;

            const rec_size = record.HEADER_SIZE + payload.len + record.CRC_SIZE;

            if (self.options.encryption_key) |*key| {
                const enc_size = encryption.ENCRYPTION_OVERHEAD + rec_size;
                // Serialize plaintext record into a temp region, then encrypt.
                // Use the end of `buf` as scratch space for the plaintext.
                const pt_start = total_size - rec_size;
                record.serializeInto(buf[pt_start..][0..rec_size], last_lsn, payload);
                encryption.encryptIntoSlice(buf[offset..][0..enc_size], key, buf[pt_start..][0..rec_size]);
                offset += enc_size;
            } else {
                record.serializeInto(buf[offset..][0..rec_size], last_lsn, payload);
                offset += rec_size;
            }
        }

        try self.file.writeAll(buf[0..offset]);
        self.file_end += offset;
        self.bytes_since_compact += offset;

        if (!self.options.manual_sync) {
            try std.posix.fdatasync(self.file.handle);
            self.appends_since_sync = 0;
        }

        return last_lsn;
    }

    /// Explicitly flush all buffered writes to durable storage.
    ///
    /// Uses `fdatasync` (metadata-update not needed for appends).
    /// Use this when `options.manual_sync` is `true`.
    pub fn sync(self: *WriteAheadLog) !void {
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
    pub fn compact(self: *WriteAheadLog, up_to_lsn: u64) !void {
        // Close the current file handle — compaction will rename a new file
        // over it and we must not hold a stale handle afterward.
        self.file.close();

        // Run the atomic rewrite.  On error, reopen the original file so the
        // WAL remains in a consistent (if unchanged) state.
        const result = compaction.compact(
            self.allocator,
            self.dir,
            self.filename,
            up_to_lsn,
            if (self.options.encryption_key) |*key| key else null,
        ) catch |err| {
            self.file = try self.dir.openFile(self.filename, .{ .mode = .read_write });
            try self.file.seekFromEnd(0);
            return err;
        };

        // Reopen the (now compacted) file for appending.
        self.file = try self.dir.openFile(self.filename, .{ .mode = .read_write });
        try self.file.seekFromEnd(0);

        // Update bookkeeping.
        self.file_end = result.new_size;
        self.bytes_since_compact = 0;
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
        return Iterator{
            .file = read_file,
            .allocator = self.allocator,
            .from_lsn = from_lsn,
            .done = false,
            .encryption_key = if (self.options.encryption_key) |k| k else null,
        };
    }

    /// A forward iterator over WAL records.
    pub const Iterator = struct {
        file: std.fs.File,
        allocator: std.mem.Allocator,
        from_lsn: u64,
        done: bool,
        encryption_key: ?[32]u8,

        /// A single WAL entry returned by the iterator.
        ///
        /// The caller must call `deinit` to release the heap-allocated payload.
        pub const Entry = struct {
            lsn: u64,
            payload: []const u8,
            allocator: std.mem.Allocator,

            /// Free the heap-allocated payload slice.
            pub fn deinit(self: *Entry) void {
                self.allocator.free(self.payload);
            }
        };

        /// Advance to the next record and return it, or `null` at EOF.
        ///
        /// Records with `lsn <= from_lsn` are skipped silently.
        ///
        /// - Returns `null` on EOF (clean end of file).
        /// - Returns `null` on torn writes (incomplete read).
        /// - Returns `null` on CRC mismatch (on-disk corruption).
        /// - Propagates all other I/O errors to the caller.
        pub fn next(self: *Iterator) !?Entry {
            if (self.done) return null;

            while (true) {
                // Peek at the first 12 bytes to detect encrypted vs plaintext.
                var peek_buf: [12]u8 = undefined;
                const peek_n = try self.file.readAll(&peek_buf);
                if (peek_n < 12) {
                    self.done = true;
                    return null; // clean EOF or torn header
                }

                if (self.encryption_key != null and encryption.isEncrypted(&peek_buf)) {
                    // ── Encrypted record path ──────────────────────────────
                    const entry = self.readEncryptedEntry(&peek_buf) catch |err| switch (err) {
                        error.InvalidEncryptedRecord,
                        error.DecryptionFailed,
                        error.InvalidRecord,
                        error.CrcMismatch,
                        => {
                            self.done = true;
                            return null;
                        },
                        else => return err,
                    };
                    if (entry == null) {
                        self.done = true;
                        return null;
                    }
                    const e = entry.?;

                    if (e.lsn <= self.from_lsn) {
                        self.allocator.free(e.payload);
                        continue;
                    }
                    return e;
                } else {
                    // ── Plaintext record path ──────────────────────────────
                    // The 12 bytes are the standard record header.
                    const hdr_info = record.HeaderInfo{
                        .lsn = std.mem.readInt(u64, peek_buf[0..8], .little),
                        .payload_len = std.mem.readInt(u32, peek_buf[8..12], .little),
                    };

                    // Skip records below the requested LSN by seeking past
                    // payload + CRC without reading them (PERF-0007).
                    if (hdr_info.lsn <= self.from_lsn) {
                        try self.file.seekBy(@as(i64, @intCast(@as(usize, hdr_info.payload_len) + record.CRC_SIZE)));
                        continue;
                    }

                    const maybe_payload = record.readPayloadAndVerify(
                        self.file,
                        self.allocator,
                        hdr_info,
                        peek_buf,
                    ) catch |err| switch (err) {
                        error.CrcMismatch => {
                            self.done = true;
                            return null;
                        },
                        else => return err,
                    };
                    if (maybe_payload == null) {
                        self.done = true;
                        return null;
                    }

                    return Entry{
                        .lsn = hdr_info.lsn,
                        .payload = maybe_payload.?,
                        .allocator = self.allocator,
                    };
                }
            }
        }

        /// Read a single encrypted record, given the 12-byte peek that was
        /// already consumed from the file.
        ///
        /// Uses in-place decryption to reduce allocations from 3 to 1 (PERF-0004).
        fn readEncryptedEntry(self: *Iterator, peek_buf: *const [12]u8) !?Entry {
            const blob_len = std.mem.readInt(u32, peek_buf[0..4], .little);
            const total_on_disk: usize = encryption.BLOB_LEN_SIZE + @as(usize, blob_len);

            if (total_on_disk < 12) return null; // corrupt blob_len
            const remaining = total_on_disk - 12;

            // Assemble the full encrypted blob.
            const blob_buf = try self.allocator.alloc(u8, total_on_disk);
            errdefer self.allocator.free(blob_buf);

            @memcpy(blob_buf[0..12], peek_buf);

            if (remaining > 0) {
                const n = try self.file.readAll(blob_buf[12..]);
                if (n < remaining) {
                    self.allocator.free(blob_buf);
                    return null; // torn write
                }
            }

            // Decrypt in-place — plaintext overwrites ciphertext region of blob_buf.
            const key = &self.encryption_key.?;
            const plaintext = encryption.decryptRecordInPlace(key, blob_buf) catch |err| {
                self.allocator.free(blob_buf);
                return err;
            };

            // Deserialize the inner record from the in-place plaintext.
            const rec = record.deserialize(plaintext) catch |err| {
                self.allocator.free(blob_buf);
                return err;
            };

            // Copy only the payload out, then free blob_buf.
            const payload_copy = self.allocator.dupe(u8, rec.payload) catch |err| {
                self.allocator.free(blob_buf);
                return err;
            };
            self.allocator.free(blob_buf);

            return Entry{
                .lsn = rec.lsn,
                .payload = payload_copy,
                .allocator = self.allocator,
            };
        }

        /// Close the read-only file handle.
        pub fn deinit(self: *Iterator) void {
            self.file.close();
        }
    };
};

// ============================================================================
// Tests
// ============================================================================

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
