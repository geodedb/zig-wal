// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! Classify the record at which a recovery scan stopped (SONNY-6620).
//!
//! The recovery scan stops at the first record it cannot accept. Truncating
//! there is right for a torn tail, but the scan cannot tell a torn tail from a
//! WAL it cannot read at all: a key-mode mismatch or a wrong key decodes zero
//! records, and a corrupt record mid-log hides every valid record after it.
//! `classifyStop` looks at the bad record and the bytes after it, read-only,
//! and decides which case applies:
//!
//! - the bad record is a well-formed record of the other key mode →
//!   `error.WalEncryptionMismatch`;
//! - valid records follow the bad one, so it is not a torn tail →
//!   `error.WalCorrupted`, or `.salvage` when salvage is enabled and a valid
//!   prefix exists;
//! - no record was readable, nothing valid follows, but a record of the
//!   other key mode does → `error.WalEncryptionMismatch`;
//! - no record was readable and the first one failed AEAD authentication →
//!   `error.WalAuthFailed`;
//! - otherwise → `.torn_tail`: the caller truncates at the bad record.
//!
//! The file is never written here.

const std = @import("std");
const record = @import("record.zig");
const encryption = @import("encryption.zig");
const RecoveryInfo = @import("recovery.zig").RecoveryInfo;

/// Errors `WriteAheadLog.init` returns instead of truncating data it cannot
/// read. The WAL file is left untouched on every one of them.
pub const RecoveryError = error{
    /// The WAL holds records of the other key mode: a plaintext WAL opened
    /// with an encryption key, an encrypted WAL opened without one, or a
    /// plaintext record inside an encrypted WAL.
    WalEncryptionMismatch,
    /// No record authenticates under the configured key (wrong key).
    WalAuthFailed,
    /// A record before the end of the WAL is corrupt and valid records follow
    /// it, so it is not a torn tail.
    WalCorrupted,
};

pub const Verdict = enum {
    /// Nothing valid follows the bad record; truncate from it onward.
    torn_tail,
    /// Valid records follow the bad record, and salvage was requested;
    /// truncate from it onward, dropping them.
    salvage,
};

const PEEK = encryption.DETECT_PEEK_SIZE;
const MIN_ENCRYPTED_RECORD = encryption.ENCRYPTION_OVERHEAD + record.MIN_RECORD_SIZE;
const SCAN_WINDOW: usize = 1024 * 1024;

comptime {
    std.debug.assert(PEEK == record.HEADER_SIZE);
}

const Frame = union(enum) {
    valid: u64,
    /// Extends past end of file.
    partial,
    /// Bad bounds, CRC, or inner record.
    bad,
    /// AES-GCM tag check failed.
    auth_failed,
    /// A well-formed record of the other key mode.
    foreign,
};

const Mode = enum { plaintext, encrypted };

const Scanner = struct {
    allocator: std.mem.Allocator,
    file: std.Io.File,
    file_len: u64,
    key: ?*const [32]u8,
    buf: std.ArrayList(u8) = .empty,

    fn deinit(self: *Scanner) void {
        encryption.secureZero(self.buf.allocatedSlice());
        self.buf.deinit(self.allocator);
    }

    fn io() std.Io {
        return std.Io.Threaded.global_single_threaded.io();
    }

    fn readExact(self: *Scanner, off: u64, len: usize) ![]u8 {
        try self.buf.resize(self.allocator, len);
        const n = try self.file.readPositionalAll(io(), self.buf.items, off);
        if (n != len) return error.UnexpectedEndOfFile;
        return self.buf.items;
    }

    /// Plaintext frame size from its header, or null if out of bounds.
    fn plaintextSize(self: *const Scanner, off: u64, header: *const [PEEK]u8) ?u64 {
        const payload_len = std.mem.readInt(u32, header[8..12], .little);
        const size = @as(u64, record.MIN_RECORD_SIZE) + payload_len;
        if (size > record.MAX_RECORD_SIZE) return null;
        if (size > self.file_len - off) return null;
        return size;
    }

    /// Encrypted frame size from its header, or null if out of bounds.
    fn encryptedSize(self: *const Scanner, off: u64, header: *const [PEEK]u8) ?u64 {
        const blob_len = std.mem.readInt(u32, header[0..4], .little);
        const size = @as(u64, encryption.BLOB_LEN_SIZE) + blob_len;
        if (size < MIN_ENCRYPTED_RECORD or size > record.MAX_RECORD_SIZE) return null;
        if (size > self.file_len - off) return null;
        return size;
    }

    fn plaintextLsn(self: *Scanner, off: u64, size: u64) !?u64 {
        const bytes = try self.readExact(off, @intCast(size));
        const rec = record.deserialize(bytes) catch return null;
        return rec.lsn;
    }

    const Decrypted = union(enum) { lsn: u64, auth_failed, bad };

    fn decryptAt(self: *Scanner, off: u64, size: u64) !Decrypted {
        const key = self.key.?;
        const bytes = try self.readExact(off, @intCast(size));
        defer encryption.secureZero(bytes);
        const plaintext = encryption.decryptRecordInPlace(key, bytes) catch |err| return switch (err) {
            error.DecryptionFailed => .auth_failed,
            else => .bad,
        };
        const rec = record.deserialize(plaintext) catch return .bad;
        return .{ .lsn = rec.lsn };
    }

    /// Decode the frame at `off` in the configured key mode.
    fn frameAt(self: *Scanner, off: u64) !Frame {
        if (self.file_len - off < PEEK) return .partial;
        var header: [PEEK]u8 = undefined;
        if (try self.file.readPositionalAll(io(), &header, off) != PEEK) return .partial;
        const has_magic = encryption.isEncrypted(&header);

        if (self.key == null) {
            if (has_magic) return if (self.encryptedSize(off, &header) != null) .foreign else .bad;
            const payload_len = std.mem.readInt(u32, header[8..12], .little);
            const claimed = @as(u64, record.MIN_RECORD_SIZE) + payload_len;
            if (claimed > record.MAX_RECORD_SIZE) return .bad;
            if (claimed > self.file_len - off) return .partial;
            const lsn = try self.plaintextLsn(off, claimed) orelse return .bad;
            return .{ .valid = lsn };
        }

        if (!has_magic) {
            // SEC-0038 rejects plaintext frames under a key. A CRC-valid one
            // means plaintext records were written into this WAL.
            const size = self.plaintextSize(off, &header) orelse return .bad;
            return if (try self.plaintextLsn(off, size) != null) .foreign else .bad;
        }
        const blob_len = std.mem.readInt(u32, header[0..4], .little);
        const claimed = @as(u64, encryption.BLOB_LEN_SIZE) + blob_len;
        if (claimed < MIN_ENCRYPTED_RECORD or claimed > record.MAX_RECORD_SIZE) return .bad;
        if (claimed > self.file_len - off) return .partial;
        return switch (try self.decryptAt(off, claimed)) {
            .lsn => |lsn| .{ .valid = lsn },
            .auth_failed => .auth_failed,
            .bad => .bad,
        };
    }

    /// Whether a plaintext record ending at `end` with LSN `lsn` is plausibly
    /// followed by the rest of a log: end of file, a torn header, or a header
    /// whose LSN lies in `(lsn, lsn + records that fit in the rest]`. Reads
    /// one header, so random bytes are rejected without hashing a payload.
    fn chainsAt(self: *Scanner, end: u64, lsn: u64) !bool {
        const rest = self.file_len - end;
        if (rest < PEEK) return true;
        var next: [PEEK]u8 = undefined;
        if (try self.file.readPositionalAll(io(), &next, end) != PEEK) return true;
        const next_lsn = std.mem.readInt(u64, next[0..8], .little);
        return next_lsn > lsn and next_lsn - lsn <= rest / record.MIN_RECORD_SIZE + 1;
    }

    /// Search `(from, file_len)` for a record that is valid in `mode`.
    /// Plaintext candidates must carry an LSN above `min_lsn`. One in
    /// `(min_lsn, dense_max]` is CRC-checked directly; one above `dense_max`
    /// (an LSN gap, or no prefix to anchor on) must first pass `chainsAt`,
    /// which keeps a scan over random bytes from hashing a payload at every
    /// offset whose header happens to fit.
    /// Encrypted candidates are authenticated when a key is configured, and
    /// accepted on magic plus an in-bounds length when it is not.
    fn validRecordAfter(self: *Scanner, from: u64, mode: Mode, min_lsn: u64, dense_max: u64) !bool {
        const window = try self.allocator.alloc(u8, SCAN_WINDOW);
        defer self.allocator.free(window);

        var win_start: u64 = from + 1;
        while (win_start + PEEK <= self.file_len) {
            const want: usize = @intCast(@min(@as(u64, SCAN_WINDOW), self.file_len - win_start));
            const got = try self.file.readPositionalAll(io(), window[0..want], win_start);
            if (got < PEEK) return false;
            var i: usize = 0;
            while (i + PEEK <= got) : (i += 1) {
                const p = win_start + i;
                const header: *const [PEEK]u8 = window[i..][0..PEEK];
                switch (mode) {
                    .encrypted => {
                        if (!encryption.isEncrypted(header)) continue;
                        const size = self.encryptedSize(p, header) orelse continue;
                        if (self.key == null) return true;
                        if (try self.decryptAt(p, size) == .lsn) return true;
                    },
                    .plaintext => {
                        const lsn = std.mem.readInt(u64, header[0..8], .little);
                        if (lsn <= min_lsn) continue;
                        const size = self.plaintextSize(p, header) orelse continue;
                        if (lsn > dense_max and !try self.chainsAt(p + size, lsn)) continue;
                        if (try self.plaintextLsn(p, size) != null) return true;
                    },
                }
            }
            // Overlap windows by PEEK-1 bytes so no header straddles a seam.
            win_start += got - (PEEK - 1);
        }
        return false;
    }
};

/// Classify the stop point of a recovery scan. `info` is the scan result and
/// `file_len` the file length; the caller only calls this when
/// `info.valid_end < file_len`. Returns how the caller may truncate, or a
/// `RecoveryError` when truncating would destroy readable data.
pub fn classifyStop(
    allocator: std.mem.Allocator,
    file: std.Io.File,
    file_len: u64,
    key: ?*const [32]u8,
    info: RecoveryInfo,
    salvage: bool,
) !Verdict {
    std.debug.assert(info.valid_end < file_len);

    var scanner = Scanner{
        .allocator = allocator,
        .file = file,
        .file_len = file_len,
        .key = key,
    };
    defer scanner.deinit();

    const bad_at = info.valid_end;
    const has_prefix = info.valid_end > 0;
    const frame = try scanner.frameAt(bad_at);
    switch (frame) {
        .foreign => return error.WalEncryptionMismatch,
        // The scan rejected a record this decoder accepts. Only a
        // non-monotonic LSN (SEC-0022) explains that; anything else means
        // the two disagree, so refuse to guess.
        .valid => |lsn| if (!(info.record_count > 0 and lsn <= info.last_lsn)) return error.WalCorrupted,
        .partial, .bad, .auth_failed => {},
    }

    const own: Mode = if (key != null) .encrypted else .plaintext;
    const other: Mode = if (key != null) .plaintext else .encrypted;

    // `append` numbers records densely, so a successor's LSN usually lies in
    // (last_lsn, last_lsn + records that fit in the rest]. Caller-assigned
    // LSNs may jump; `validRecordAfter` still finds such a successor through
    // its chain check. With no valid prefix there is no anchor for the window.
    const rest_records = (file_len - bad_at) / record.MIN_RECORD_SIZE + 1;
    const dense_max = if (has_prefix) info.last_lsn +| rest_records else info.last_lsn;

    if (try scanner.validRecordAfter(bad_at, own, info.last_lsn, dense_max)) {
        if (salvage and has_prefix) return .salvage;
        return error.WalCorrupted;
    }

    if (!has_prefix) {
        // The first record framed as encrypted but no record authenticates
        // under this key. A wrong key and a WAL whose only complete record is
        // damaged look the same; keep the file.
        if (frame == .auth_failed) return error.WalAuthFailed;
        if (try scanner.validRecordAfter(bad_at, other, 0, 0)) {
            return error.WalEncryptionMismatch;
        }
    }

    return .torn_tail;
}

// ============================================================================
// Tests. Scenario coverage through WriteAheadLog.init lives in
// tests/scenarios/recovery_safety.zig; these pin scanner branches.
// ============================================================================

const testing = std.testing;
const TEST_KEY: [32]u8 = [_]u8{0x3C} ** 32;

fn scanAndClassify(file: std.Io.File, key: ?*const [32]u8, salvage: bool) !Verdict {
    const info = try @import("recovery.zig").recoverWithKey(testing.allocator, file, key);
    const len = try file.length(std.Io.Threaded.global_single_threaded.io());
    return classifyStop(testing.allocator, file, len, key, info, salvage);
}

test "classifyStop: corrupt record found across a scan-window seam is mid-log" {
    // Record 2 is ~1 MiB, so record 3's header straddles the first scan
    // window's end. The window overlap must still find it.
    const tio = std.Io.Threaded.global_single_threaded.io();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try tmp.dir.createFile(tio, "w", .{ .read = true });
    defer file.close(tio);

    const big = try testing.allocator.alloc(u8, SCAN_WINDOW - 20);
    defer testing.allocator.free(big);
    @memset(big, 0x61);
    _ = try record.writeToFile(testing.allocator, file, 1, "first");
    _ = try record.writeToFile(testing.allocator, file, 2, big);
    _ = try record.writeToFile(testing.allocator, file, 3, "third");

    const rec2 = record.MIN_RECORD_SIZE + "first".len;
    var b: [1]u8 = undefined;
    _ = try file.readPositionalAll(tio, &b, rec2 + record.HEADER_SIZE + 10);
    b[0] ^= 0xFF;
    try file.writePositionalAll(tio, &b, rec2 + record.HEADER_SIZE + 10);

    const rec3 = rec2 + record.MIN_RECORD_SIZE + big.len;
    try testing.expect(rec3 < rec2 + 1 + SCAN_WINDOW);
    try testing.expect(rec3 + PEEK > rec2 + 1 + SCAN_WINDOW);

    try testing.expectError(error.WalCorrupted, scanAndClassify(file, null, false));
    try testing.expectEqual(Verdict.salvage, try scanAndClassify(file, null, true));
}

test "classifyStop: encrypted torn tail after valid records" {
    const tio = std.Io.Threaded.global_single_threaded.io();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try tmp.dir.createFile(tio, "w", .{ .read = true });
    defer file.close(tio);

    _ = try encryption.encryptAndWriteToFile(testing.allocator, file, &TEST_KEY, 1, "a");
    _ = try encryption.encryptAndWriteToFile(testing.allocator, file, &TEST_KEY, 2, "b");
    try file.writeStreamingAll(tio, &[_]u8{ 0x40, 0, 0, 0, 'Z', 'I', 'G' });

    try testing.expectEqual(Verdict.torn_tail, try scanAndClassify(file, &TEST_KEY, false));
}
