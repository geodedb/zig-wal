// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Forward iterator over WAL records.
//!
//! Extracted from `wal.zig` to reduce file size (QA-0001).  The Iterator
//! opens an independent read-only file handle so it does not disturb the
//! write cursor.

const std = @import("std");
const record = @import("record.zig");
const encryption = @import("encryption.zig");

// The plaintext path reinterprets the DETECT_PEEK_SIZE-byte peek buffer as a
// record header. This only works because the two constants are numerically
// equal. Guard against silent breakage if either format changes (QA-0035).
comptime {
    std.debug.assert(encryption.DETECT_PEEK_SIZE == record.HEADER_SIZE);
}

/// Default I/O buffer size for the buffered reader (PERF-0021).
/// 64KB reduces syscalls from 2-3 per record to ~1 per ~5K records
/// for typical 64-byte payloads.
const IO_BUF_SIZE = 65536;

/// Wraps `std.fs.File.Reader` with a `readAll`-compatible interface so
/// `anytype` functions in `record.zig` and `encryption.zig` can accept
/// both `std.fs.File` (unbuffered) and this type (buffered) — PERF-0021.
const BufferedSource = struct {
    reader: *std.Io.Reader,

    pub fn readAll(self: BufferedSource, buf: []u8) !usize {
        return self.reader.readSliceShort(buf);
    }
};

/// A forward iterator over WAL records.
pub const Iterator = struct {
    /// Independent read-only file handle (does not share the write cursor).
    _file: std.fs.File,
    /// Allocator used for payload copies returned by `next`.
    allocator: std.mem.Allocator,
    /// Records with LSN <= this value are silently skipped.
    from_lsn: u64,
    /// Set to `true` when EOF or corruption is hit; all subsequent
    /// `next` calls return `null`.
    _done: bool,
    /// Copy of the encryption key, or `null` for plaintext WALs.
    encryption_key: ?[32]u8,
    /// Reusable buffer for encrypted blob reads — avoids per-record
    /// alloc/free in the encrypted iteration path (PERF-0020).
    _reuse_buf: ?[]u8 = null,
    /// Heap-allocated I/O buffer backing `_file_reader` (PERF-0021).
    _io_buf: []u8,
    /// Buffered reader over the file — coalesces small reads into
    /// large buffer-fill syscalls (PERF-0021).
    _file_reader: std.fs.File.Reader,

    /// Create an iterator with a heap-allocated I/O buffer for buffered reads.
    pub fn init(allocator: std.mem.Allocator, file: std.fs.File, from_lsn: u64, encryption_key: ?[32]u8) !Iterator {
        const io_buf = try allocator.alloc(u8, IO_BUF_SIZE);
        return .{
            ._file = file,
            .allocator = allocator,
            .from_lsn = from_lsn,
            ._done = false,
            .encryption_key = encryption_key,
            ._io_buf = io_buf,
            ._file_reader = file.reader(io_buf),
        };
    }

    /// A single WAL entry returned by the iterator.
    ///
    /// The caller must call `deinit` to release the heap-allocated payload.
    pub const Entry = struct {
        /// Log Sequence Number of this record.
        lsn: u64,
        /// Heap-allocated copy of the record payload. Caller must call
        /// `deinit` to free.
        payload: []const u8,
        /// Allocator used for the payload allocation (needed by `deinit`).
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
        if (self._done) return null;

        // All reads go through the buffered source (PERF-0021).
        const source = BufferedSource{ .reader = &self._file_reader.interface };

        while (true) {
            // Peek at DETECT_PEEK_SIZE bytes to detect encrypted vs plaintext (QA-0014).
            var peek_buf: [encryption.DETECT_PEEK_SIZE]u8 = undefined;
            const peek_n = try source.readAll(&peek_buf);
            if (peek_n < encryption.DETECT_PEEK_SIZE) {
                self._done = true;
                return null; // clean EOF or torn header
            }

            if (self.encryption_key != null and encryption.isEncrypted(&peek_buf)) {
                // ── Encrypted record path ──────────────────────────────
                const entry = self.readEncryptedEntry(source, &peek_buf) catch |err| switch (err) {
                    error.InvalidEncryptedRecord,
                    error.DecryptionFailed,
                    error.InvalidRecord,
                    error.CrcMismatch,
                    => {
                        self._done = true;
                        return null;
                    },
                    else => return err,
                };
                if (entry == null) {
                    self._done = true;
                    return null;
                }
                const e = entry.?;

                if (e.lsn <= self.from_lsn) {
                    // Skipped record — payload was not duped (PERF-0012),
                    // blob_buf already secureZero'd+freed inside readEncryptedEntry.
                    continue;
                }
                return e;
            } else if (self.encryption_key != null) {
                // SEC-0038: encryption key is configured but record lacks
                // magic bytes — reject to prevent plaintext record injection.
                self._done = true;
                return null;
            } else {
                // ── Plaintext record path (no encryption key) ─────────
                // The peek bytes are the standard record header.
                const hdr_info = record.HeaderInfo{
                    .lsn = std.mem.readInt(u64, peek_buf[0..8], .little),
                    .payload_len = std.mem.readInt(u32, peek_buf[8..12], .little),
                };

                // Reject unreasonably large records to prevent issues (SEC-0004).
                if (@as(usize, hdr_info.payload_len) + record.HEADER_SIZE + record.CRC_SIZE > record.MAX_RECORD_SIZE) {
                    self._done = true;
                    return null;
                }

                // Skip records below the requested LSN by discarding
                // payload + CRC through the buffer (PERF-0007/PERF-0021).
                if (hdr_info.lsn <= self.from_lsn) {
                    try self._file_reader.interface.discardAll(@as(usize, hdr_info.payload_len) + record.CRC_SIZE);
                    continue;
                }

                const maybe_payload = record.readPayloadAndVerify(
                    self.allocator,
                    source,
                    hdr_info,
                    peek_buf,
                ) catch |err| switch (err) {
                    error.CrcMismatch => {
                        self._done = true;
                        return null;
                    },
                    else => return err,
                };
                if (maybe_payload == null) {
                    self._done = true;
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

    /// Read a single encrypted record, given the DETECT_PEEK_SIZE-byte peek
    /// that was already consumed from the file.
    ///
    /// Uses shared readEncryptedBlob (QA-0002) + in-place decryption (PERF-0004).
    fn readEncryptedEntry(self: *Iterator, source: BufferedSource, peek_buf: *const [encryption.DETECT_PEEK_SIZE]u8) !?Entry {
        // Read full encrypted blob using the reusable-buffer reader (PERF-0020).
        // The buffer is grown only when a larger blob is encountered; it is
        // freed once in `deinit`, not per-record.
        const blob_result = try encryption.readEncryptedBlobReuse(self.allocator, source, peek_buf, &self._reuse_buf) orelse return null;
        const blob_buf = blob_result.blob;

        // Decrypt in-place — plaintext overwrites ciphertext region of blob_buf.
        const key = &self.encryption_key.?;
        const plaintext = try encryption.decryptRecordInPlace(key, blob_buf);

        // Deserialize the inner record from the in-place plaintext.
        const rec = try record.deserialize(plaintext);

        // Check LSN before duping payload to avoid unnecessary alloc+free
        // for records that will be skipped (PERF-0012).
        if (rec.lsn <= self.from_lsn) {
            return Entry{
                .lsn = rec.lsn,
                .payload = &.{}, // empty — caller must not use payload for skipped entries
                .allocator = self.allocator,
            };
        }

        // Copy only the payload out; reuse_buf stays alive for the next record.
        const payload_copy = try self.allocator.dupe(u8, rec.payload);

        return Entry{
            .lsn = rec.lsn,
            .payload = payload_copy,
            .allocator = self.allocator,
        };
    }

    /// Close the read-only file handle, free the reusable blob buffer and
    /// I/O buffer, and zeroize any key material (SEC-0002).
    pub fn deinit(self: *Iterator) void {
        // SecureZero + free the reusable encrypted-blob buffer (PERF-0020).
        if (self._reuse_buf) |buf| {
            encryption.secureZero(buf);
            self.allocator.free(buf);
            self._reuse_buf = null;
        }
        if (self.encryption_key) |*key| {
            encryption.secureZero(key);
        }
        self.allocator.free(self._io_buf); // PERF-0021
        self._file.close();
    }
};

// ============================================================================
// Tests (QA-0016)
// ============================================================================

test "iterator: EOF on empty file returns null" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Create an empty file.
    const wf = try tmp.dir.createFile("empty.wal", .{ .truncate = true });
    wf.close();

    // Open read-only for iteration.
    const rf = try tmp.dir.openFile("empty.wal", .{ .mode = .read_only });

    var iter = try Iterator.init(allocator, rf, 0, null);
    defer iter.deinit();

    // First call must return null (EOF).
    try std.testing.expect(try iter.next() == null);
    // done flag must be set.
    try std.testing.expect(iter._done);
    // Subsequent calls must also return null.
    try std.testing.expect(try iter.next() == null);
}

test "iterator: single plaintext record iteration" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Write one record.
    const wf = try tmp.dir.createFile("single.wal", .{ .truncate = true });
    _ = try record.writeToFile(allocator, wf, 1, "hello");
    wf.close();

    // Open read-only.
    const rf = try tmp.dir.openFile("single.wal", .{ .mode = .read_only });

    var iter = try Iterator.init(allocator, rf, 0, null);
    defer iter.deinit();

    // Read the single entry.
    var entry = (try iter.next()) orelse return error.Unexpected;
    defer entry.deinit();
    try std.testing.expectEqual(@as(u64, 1), entry.lsn);
    try std.testing.expectEqualSlices(u8, "hello", entry.payload);

    // Next call must be EOF.
    try std.testing.expect(try iter.next() == null);
    try std.testing.expect(iter._done);
}

test "iterator: multiple records iteration verifies all LSNs" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Write three records with distinct payloads.
    const wf = try tmp.dir.createFile("multi.wal", .{ .truncate = true });
    _ = try record.writeToFile(allocator, wf, 10, "alpha");
    _ = try record.writeToFile(allocator, wf, 20, "beta");
    _ = try record.writeToFile(allocator, wf, 30, "gamma");
    wf.close();

    // Open read-only.
    const rf = try tmp.dir.openFile("multi.wal", .{ .mode = .read_only });

    var iter = try Iterator.init(allocator, rf, 0, null);
    defer iter.deinit();

    const expected_lsns = [_]u64{ 10, 20, 30 };
    const expected_payloads = [_][]const u8{ "alpha", "beta", "gamma" };

    for (expected_lsns, expected_payloads) |expected_lsn, expected_payload| {
        var entry = (try iter.next()) orelse return error.Unexpected;
        defer entry.deinit();
        try std.testing.expectEqual(expected_lsn, entry.lsn);
        try std.testing.expectEqualSlices(u8, expected_payload, entry.payload);
    }

    // After the last record, must return null.
    try std.testing.expect(try iter.next() == null);
    try std.testing.expect(iter._done);
}

test "iterator: from_lsn filtering skips records at or below threshold" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Write five records with LSNs 1..5.
    const wf = try tmp.dir.createFile("filter.wal", .{ .truncate = true });
    _ = try record.writeToFile(allocator, wf, 1, "one");
    _ = try record.writeToFile(allocator, wf, 2, "two");
    _ = try record.writeToFile(allocator, wf, 3, "three");
    _ = try record.writeToFile(allocator, wf, 4, "four");
    _ = try record.writeToFile(allocator, wf, 5, "five");
    wf.close();

    // Open read-only with from_lsn = 3 (skip LSNs 1, 2, 3).
    const rf = try tmp.dir.openFile("filter.wal", .{ .mode = .read_only });

    var iter = try Iterator.init(allocator, rf, 3, null);
    defer iter.deinit();

    // First returned entry must be LSN 4.
    var e1 = (try iter.next()) orelse return error.Unexpected;
    defer e1.deinit();
    try std.testing.expectEqual(@as(u64, 4), e1.lsn);
    try std.testing.expectEqualSlices(u8, "four", e1.payload);

    // Second returned entry must be LSN 5.
    var e2 = (try iter.next()) orelse return error.Unexpected;
    defer e2.deinit();
    try std.testing.expectEqual(@as(u64, 5), e2.lsn);
    try std.testing.expectEqualSlices(u8, "five", e2.payload);

    // EOF.
    try std.testing.expect(try iter.next() == null);
    try std.testing.expect(iter._done);
}

test "iterator: corrupt CRC stops iteration" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Write a valid record first, then a corrupt record.
    const wf = try tmp.dir.createFile("corrupt.wal", .{ .truncate = true });

    // First record: valid.
    _ = try record.writeToFile(allocator, wf, 1, "good");

    // Second record: serialize manually and corrupt the CRC.
    const corrupt_buf = try record.serialize(allocator, 2, "bad");
    defer allocator.free(corrupt_buf);
    // Flip a byte in the CRC footer (last byte of the serialized record).
    corrupt_buf[corrupt_buf.len - 1] ^= 0xFF;
    try wf.writeAll(corrupt_buf);

    // Third record: valid (should never be reached).
    _ = try record.writeToFile(allocator, wf, 3, "unreachable");
    wf.close();

    // Open read-only.
    const rf = try tmp.dir.openFile("corrupt.wal", .{ .mode = .read_only });

    var iter = try Iterator.init(allocator, rf, 0, null);
    defer iter.deinit();

    // First entry should succeed.
    var entry = (try iter.next()) orelse return error.Unexpected;
    defer entry.deinit();
    try std.testing.expectEqual(@as(u64, 1), entry.lsn);
    try std.testing.expectEqualSlices(u8, "good", entry.payload);

    // Second entry hits the corrupt CRC — returns null.
    try std.testing.expect(try iter.next() == null);
    // done flag must be set.
    try std.testing.expect(iter._done);
    // All subsequent calls also return null.
    try std.testing.expect(try iter.next() == null);
}

test "iterator: oversized payload_len stops iteration (SEC-0004/QA-0024)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const wf = try tmp.dir.createFile("test.wal", .{ .truncate = true });
    _ = try record.writeToFile(allocator, wf, 1, "valid");

    // Craft oversized header
    var bad_header: [record.HEADER_SIZE]u8 = undefined;
    std.mem.writeInt(u64, bad_header[0..8], 2, .little);
    const huge_len: u32 = @intCast(record.MAX_RECORD_SIZE - record.HEADER_SIZE - record.CRC_SIZE + 1);
    std.mem.writeInt(u32, bad_header[8..12], huge_len, .little);
    try wf.writeAll(&bad_header);
    wf.close();

    const rf = try tmp.dir.openFile("test.wal", .{ .mode = .read_only });

    var iter = try Iterator.init(allocator, rf, 0, null);
    defer iter.deinit();

    // First record should be valid
    var entry = (try iter.next()) orelse return error.Unexpected;
    defer entry.deinit();
    try std.testing.expectEqual(@as(u64, 1), entry.lsn);

    // Second "record" with oversized payload should return null
    try std.testing.expect(try iter.next() == null);
    try std.testing.expect(iter._done);
}

test "iterator: plaintext record rejected when encryption key is set (SEC-0038)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Write plaintext records.
    const wf = try tmp.dir.createFile("test.wal", .{ .truncate = true });
    _ = try record.writeToFile(allocator, wf, 1, "plain-1");
    _ = try record.writeToFile(allocator, wf, 2, "plain-2");
    wf.close();

    // Open with an encryption key — iterator should reject plaintext records.
    const rf = try tmp.dir.openFile("test.wal", .{ .mode = .read_only });
    const key: [32]u8 = .{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    };

    var iter = try Iterator.init(allocator, rf, 0, key);
    defer iter.deinit();

    // First call returns null — plaintext rejected.
    try std.testing.expect(try iter.next() == null);
    try std.testing.expect(iter._done);
}
