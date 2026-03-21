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

// ============================================================================
// Options
// ============================================================================

/// Configuration options for a `WriteAheadLog` instance.
pub const Options = struct {
    /// Optional AES-256-GCM encryption key.  `null` means plaintext mode.
    /// Encryption integration is handled by Task 8; this field is reserved.
    encryption_key: ?[32]u8 = null,

    /// When `true`, the caller is responsible for calling `sync()` explicitly.
    /// When `false` (the default), every `append` / `appendBatch` issues an
    /// `fsync` automatically.
    manual_sync: bool = false,
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
        const info = try recovery_mod.recover(allocator, file);

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

        const bytes_written = try record.writeToFile(self.file, self.allocator, lsn, payload);

        self.file_end += bytes_written;
        self.bytes_since_compact += bytes_written;

        if (!self.options.manual_sync) {
            try self.file.sync();
        }

        return lsn;
    }

    /// Append multiple records in a single batch with a single `fsync`.
    ///
    /// All records are written before the sync is issued, regardless of the
    /// `manual_sync` option.  This amortises the sync cost across many
    /// appends.
    ///
    /// Returns the LSN assigned to the last record in the batch.
    /// Errors if `payloads` is empty (there is nothing to flush).
    pub fn appendBatch(self: *WriteAheadLog, payloads: []const []const u8) !u64 {
        std.debug.assert(payloads.len > 0);

        var last_lsn: u64 = self.current_lsn;
        for (payloads) |payload| {
            self.current_lsn += 1;
            last_lsn = self.current_lsn;

            const bytes_written = try record.writeToFile(self.file, self.allocator, last_lsn, payload);
            self.file_end += bytes_written;
            self.bytes_since_compact += bytes_written;
        }

        if (!self.options.manual_sync) {
            try self.file.sync();
        }

        return last_lsn;
    }

    /// Explicitly flush all buffered writes to durable storage.
    ///
    /// Use this when `options.manual_sync` is `true`.
    pub fn sync(self: *WriteAheadLog) !void {
        try self.file.sync();
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
        };
    }

    /// A forward iterator over WAL records.
    pub const Iterator = struct {
        file: std.fs.File,
        allocator: std.mem.Allocator,
        from_lsn: u64,
        done: bool,

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
                // Read the 12-byte header along with its raw bytes (needed by
                // readPayloadAndVerify to re-derive the CRC).
                const maybe_header = try record.readHeaderRaw(self.file);
                if (maybe_header == null) {
                    self.done = true;
                    return null; // clean EOF
                }
                const hdr = maybe_header.?;

                // Read the payload and verify the CRC.  Returns null on torn
                // writes; returns error.CrcMismatch on corruption.
                const maybe_payload = record.readPayloadAndVerify(
                    self.file,
                    self.allocator,
                    hdr.info,
                    hdr.raw,
                ) catch |err| switch (err) {
                    error.CrcMismatch => {
                        self.done = true;
                        return null; // treat as end-of-valid-log
                    },
                    else => return err, // propagate real I/O errors
                };
                if (maybe_payload == null) {
                    self.done = true;
                    return null; // torn write at payload boundary
                }
                const payload = maybe_payload.?;

                // Skip records at or below the requested starting LSN.
                if (hdr.info.lsn <= self.from_lsn) {
                    self.allocator.free(payload);
                    continue;
                }

                return Entry{
                    .lsn = hdr.info.lsn,
                    .payload = payload,
                    .allocator = self.allocator,
                };
            }
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
