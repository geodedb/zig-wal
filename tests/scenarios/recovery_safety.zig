// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! Recovery must not destroy data it cannot read (SONNY-6620).
//!
//! `WriteAheadLog.init` used to truncate the file at the end of the last
//! record it could decode. A key-mode mismatch or a wrong key decoded zero
//! records and wiped the file; a corrupt record mid-log silently dropped every
//! valid record after it. These scenarios pin the fail-closed contract:
//! distinct errors, the file left byte-for-byte intact on a failed open, and
//! truncation only of a genuine torn tail.

const std = @import("std");
const builtin = @import("builtin");
const wal = @import("wal");

const record = wal.record;
const encryption = wal.encryption;

const NAME = "wal";
const KEY: [32]u8 = [_]u8{0x5A} ** 32;
const OTHER_KEY: [32]u8 = [_]u8{0xA5} ** 32;

fn io() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

fn writeWal(dir: std.Io.Dir, key: ?[32]u8, payloads: []const []const u8) !void {
    var log = try wal.WriteAheadLog.init(std.testing.allocator, dir, NAME, .{ .encryption_key = key });
    defer log.deinit();
    for (payloads) |p| _ = try log.append(p);
}

fn readAll(dir: std.Io.Dir) ![]u8 {
    return dir.readFileAlloc(io(), NAME, std.testing.allocator, .unlimited);
}

fn writeAll(dir: std.Io.Dir, bytes: []const u8) !void {
    try dir.writeFile(io(), .{ .sub_path = NAME, .data = bytes });
}

fn flipByte(dir: std.Io.Dir, offset: u64) !void {
    const f = try dir.openFile(io(), NAME, .{ .mode = .read_write });
    defer f.close(io());
    var b: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try f.readPositionalAll(io(), &b, offset));
    b[0] ^= 0xFF;
    try f.writePositionalAll(io(), &b, offset);
}

fn plainSize(payload: []const u8) u64 {
    return record.MIN_RECORD_SIZE + payload.len;
}

fn encSize(payload: []const u8) u64 {
    return encryption.ENCRYPTION_OVERHEAD + record.MIN_RECORD_SIZE + payload.len;
}

/// Open must fail with `expected` and leave the file exactly as it was.
fn expectOpenFailsIntact(dir: std.Io.Dir, opts: wal.Options, expected: anyerror) !void {
    const before = try readAll(dir);
    defer std.testing.allocator.free(before);

    try std.testing.expectError(expected, wal.WriteAheadLog.init(std.testing.allocator, dir, NAME, opts));

    const after = try readAll(dir);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
}

/// Open and return the payloads recovered, in order. Caller frees.
fn openAndCollect(dir: std.Io.Dir, opts: wal.Options) !std.ArrayList([]u8) {
    var log = try wal.WriteAheadLog.init(std.testing.allocator, dir, NAME, opts);
    defer log.deinit();
    var out: std.ArrayList([]u8) = .empty;
    errdefer freeCollected(&out);
    var it = try log.iterator(0);
    defer it.deinit();
    while (try it.next()) |*entry| {
        var e = entry.*;
        defer e.deinit();
        try out.append(std.testing.allocator, try std.testing.allocator.dupe(u8, e.payload));
    }
    return out;
}

fn freeCollected(list: *std.ArrayList([]u8)) void {
    for (list.items) |p| std.testing.allocator.free(p);
    list.deinit(std.testing.allocator);
}

fn expectPayloads(dir: std.Io.Dir, opts: wal.Options, want: []const []const u8) !void {
    var got = try openAndCollect(dir, opts);
    defer freeCollected(&got);
    try std.testing.expectEqual(want.len, got.items.len);
    for (want, got.items) |w, g| try std.testing.expectEqualSlices(u8, w, g);
}

// ============================================================================
// Key-mode mismatch and wrong key
// ============================================================================

test "recovery safety: plaintext WAL opened with a key fails closed (SONNY-6620)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeWal(tmp.dir, null, &.{ "p1", "p2", "p3" });

    try expectOpenFailsIntact(tmp.dir, .{ .encryption_key = KEY }, error.WalEncryptionMismatch);
    try expectPayloads(tmp.dir, .{}, &.{ "p1", "p2", "p3" });
}

test "recovery safety: encrypted WAL opened without a key fails closed (SONNY-6620)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeWal(tmp.dir, KEY, &.{ "e1", "e2", "e3" });

    try expectOpenFailsIntact(tmp.dir, .{}, error.WalEncryptionMismatch);
    try expectPayloads(tmp.dir, .{ .encryption_key = KEY }, &.{ "e1", "e2", "e3" });
}

test "recovery safety: encrypted WAL opened with the wrong key fails closed (SONNY-6620)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeWal(tmp.dir, KEY, &.{ "e1", "e2", "e3" });

    try expectOpenFailsIntact(tmp.dir, .{ .encryption_key = OTHER_KEY }, error.WalAuthFailed);
    try expectPayloads(tmp.dir, .{ .encryption_key = KEY }, &.{ "e1", "e2", "e3" });
}

test "recovery safety: wrong key on a single-record WAL fails closed (SONNY-6620)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeWal(tmp.dir, KEY, &.{"only"});

    try expectOpenFailsIntact(tmp.dir, .{ .encryption_key = OTHER_KEY }, error.WalAuthFailed);
    try expectPayloads(tmp.dir, .{ .encryption_key = KEY }, &.{"only"});
}

test "recovery safety: plaintext frame after encrypted records is a mismatch (SONNY-6620)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeWal(tmp.dir, KEY, &.{ "e1", "e2" });

    const good = try readAll(tmp.dir);
    defer std.testing.allocator.free(good);
    var injected: [record.MIN_RECORD_SIZE + 2]u8 = undefined;
    record.serializeInto(&injected, 3, "p3");
    const bytes = try std.mem.concat(std.testing.allocator, u8, &.{ good, &injected });
    defer std.testing.allocator.free(bytes);
    try writeAll(tmp.dir, bytes);

    try expectOpenFailsIntact(tmp.dir, .{ .encryption_key = KEY }, error.WalEncryptionMismatch);
}

test "recovery safety: salvage never applies to a mismatch or a wrong key (SONNY-6620)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeWal(tmp.dir, KEY, &.{ "e1", "e2" });

    try expectOpenFailsIntact(tmp.dir, .{ .salvage_corrupt_records = true }, error.WalEncryptionMismatch);
    try expectOpenFailsIntact(tmp.dir, .{ .encryption_key = OTHER_KEY, .salvage_corrupt_records = true }, error.WalAuthFailed);
}

test "recovery safety: failed open leaves file permissions alone (SONNY-6620)" {
    if (!@hasDecl(std.Io.File.Permissions, "fromMode")) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeWal(tmp.dir, null, &.{"p1"});

    const f = try tmp.dir.openFile(io(), NAME, .{ .mode = .read_write });
    try f.setPermissions(io(), .fromMode(0o640));
    f.close(io());

    try expectOpenFailsIntact(tmp.dir, .{ .encryption_key = KEY }, error.WalEncryptionMismatch);

    const st = try tmp.dir.statFile(io(), NAME, .{});
    try std.testing.expectEqual(@as(u32, 0o640), @as(u32, @intCast(st.permissions.toMode() & 0o777)));
}

// ============================================================================
// Mid-log corruption
// ============================================================================

test "recovery safety: plaintext mid-log corruption fails closed (SONNY-6620)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeWal(tmp.dir, null, &.{ "alpha", "beta", "gamma" });
    // Flip a payload byte of record 2.
    try flipByte(tmp.dir, plainSize("alpha") + record.HEADER_SIZE);

    try expectOpenFailsIntact(tmp.dir, .{}, error.WalCorrupted);
}

test "recovery safety: encrypted mid-log corruption fails closed (SONNY-6620)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeWal(tmp.dir, KEY, &.{ "alpha", "beta", "gamma" });
    // Flip a ciphertext byte of record 2.
    try flipByte(tmp.dir, encSize("alpha") + encryption.ENCRYPTION_OVERHEAD);

    try expectOpenFailsIntact(tmp.dir, .{ .encryption_key = KEY }, error.WalCorrupted);
}

test "recovery safety: encrypted mid-log header damage fails closed (SONNY-6620)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeWal(tmp.dir, KEY, &.{ "alpha", "beta", "gamma" });
    // Damage record 2's magic so it no longer frames as encrypted.
    try flipByte(tmp.dir, encSize("alpha") + encryption.BLOB_LEN_SIZE);

    try expectOpenFailsIntact(tmp.dir, .{ .encryption_key = KEY }, error.WalCorrupted);
}

test "recovery safety: plaintext corrupt first record followed by valid records fails closed (SONNY-6620)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeWal(tmp.dir, null, &.{ "alpha", "beta", "gamma" });
    try flipByte(tmp.dir, record.HEADER_SIZE);

    try expectOpenFailsIntact(tmp.dir, .{}, error.WalCorrupted);
    // Salvage needs a valid prefix; with none it still refuses.
    try expectOpenFailsIntact(tmp.dir, .{ .salvage_corrupt_records = true }, error.WalCorrupted);
}

test "recovery safety: encrypted corrupt first record followed by valid records fails closed (SONNY-6620)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeWal(tmp.dir, KEY, &.{ "alpha", "beta", "gamma" });
    try flipByte(tmp.dir, encryption.ENCRYPTION_OVERHEAD);

    try expectOpenFailsIntact(tmp.dir, .{ .encryption_key = KEY }, error.WalCorrupted);
    try expectOpenFailsIntact(tmp.dir, .{ .encryption_key = KEY, .salvage_corrupt_records = true }, error.WalCorrupted);
}

test "recovery safety: plaintext corrupt first-record length followed by valid records fails closed (SONNY-6620)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeWal(tmp.dir, null, &.{ "alpha", "beta", "gamma" });
    // Inflate payload_len past the end of file.
    try flipByte(tmp.dir, 11);

    try expectOpenFailsIntact(tmp.dir, .{}, error.WalCorrupted);
}

test "recovery safety: non-monotonic LSN mid-log fails closed (SONNY-6620)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeWal(tmp.dir, null, &.{ "a", "b" });

    const good = try readAll(tmp.dir);
    defer std.testing.allocator.free(good);
    var stale: [record.MIN_RECORD_SIZE + 1]u8 = undefined;
    record.serializeInto(&stale, 1, "x");
    var next: [record.MIN_RECORD_SIZE + 1]u8 = undefined;
    record.serializeInto(&next, 3, "c");
    const bytes = try std.mem.concat(std.testing.allocator, u8, &.{ good, &stale, &next });
    defer std.testing.allocator.free(bytes);
    try writeAll(tmp.dir, bytes);

    try expectOpenFailsIntact(tmp.dir, .{}, error.WalCorrupted);
}

test "recovery safety: corruption past a checkpoint boundary fails closed (SONNY-6620)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var log = try wal.WriteAheadLog.init(std.testing.allocator, tmp.dir, NAME, .{ .checkpoint = true });
        defer log.deinit();
        _ = try log.append("one");
        _ = try log.append("two");
    }
    // Append past the checkpoint without rewriting it.
    try writeWal(tmp.dir, null, &.{ "three", "four", "five" });
    try flipByte(tmp.dir, plainSize("one") + plainSize("two") + record.HEADER_SIZE);

    try expectOpenFailsIntact(tmp.dir, .{ .checkpoint = true }, error.WalCorrupted);
}

// ============================================================================
// Salvage (opt-in point-in-time recovery)
// ============================================================================

test "recovery safety: salvage keeps the valid prefix before mid-log corruption (SONNY-6620)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeWal(tmp.dir, null, &.{ "alpha", "beta", "gamma" });
    try flipByte(tmp.dir, plainSize("alpha") + record.HEADER_SIZE);

    {
        var log = try wal.WriteAheadLog.init(std.testing.allocator, tmp.dir, NAME, .{ .salvage_corrupt_records = true });
        defer log.deinit();
        try std.testing.expectEqual(@as(u64, 1), log.currentLsn());
        try std.testing.expectEqual(@as(u64, 2), try log.append("delta"));
    }
    try expectPayloads(tmp.dir, .{}, &.{ "alpha", "delta" });
}

test "recovery safety: encrypted salvage keeps the valid prefix (SONNY-6620)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeWal(tmp.dir, KEY, &.{ "alpha", "beta", "gamma" });
    try flipByte(tmp.dir, encSize("alpha") + encSize("beta") - 1);

    try expectOpenFailsIntact(tmp.dir, .{ .encryption_key = KEY }, error.WalCorrupted);
    try expectPayloads(tmp.dir, .{ .encryption_key = KEY, .salvage_corrupt_records = true }, &.{"alpha"});
}

// ============================================================================
// Torn tails are still truncated
// ============================================================================

test "recovery safety: plaintext torn header tail is truncated (SONNY-6620)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeWal(tmp.dir, null, &.{ "a", "b" });
    const good = try readAll(tmp.dir);
    defer std.testing.allocator.free(good);
    const bytes = try std.mem.concat(std.testing.allocator, u8, &.{ good, &[_]u8{ 3, 0, 0, 0, 0 } });
    defer std.testing.allocator.free(bytes);
    try writeAll(tmp.dir, bytes);

    {
        var log = try wal.WriteAheadLog.init(std.testing.allocator, tmp.dir, NAME, .{});
        defer log.deinit();
        try std.testing.expectEqual(@as(u64, 2), log.currentLsn());
        try std.testing.expectEqual(@as(u64, 3), try log.append("c"));
    }
    try expectPayloads(tmp.dir, .{}, &.{ "a", "b", "c" });
}

test "recovery safety: plaintext torn payload tail is truncated (SONNY-6620)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeWal(tmp.dir, null, &.{ "a", "b", "torn-record" });
    const full = try readAll(tmp.dir);
    defer std.testing.allocator.free(full);
    try writeAll(tmp.dir, full[0 .. full.len - 5]);

    try expectPayloads(tmp.dir, .{}, &.{ "a", "b" });
    const after = try readAll(tmp.dir);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqual(plainSize("a") + plainSize("b"), after.len);
}

test "recovery safety: encrypted torn tail is truncated (SONNY-6620)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeWal(tmp.dir, KEY, &.{ "a", "b", "torn-record" });
    const full = try readAll(tmp.dir);
    defer std.testing.allocator.free(full);
    try writeAll(tmp.dir, full[0 .. full.len - 7]);

    {
        var log = try wal.WriteAheadLog.init(std.testing.allocator, tmp.dir, NAME, .{ .encryption_key = KEY });
        defer log.deinit();
        try std.testing.expectEqual(@as(u64, 2), log.currentLsn());
        try std.testing.expectEqual(@as(u64, 3), try log.append("c"));
    }
    try expectPayloads(tmp.dir, .{ .encryption_key = KEY }, &.{ "a", "b", "c" });
}

test "recovery safety: torn sole record is truncated to empty (SONNY-6620)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeWal(tmp.dir, KEY, &.{"only"});
    const full = try readAll(tmp.dir);
    defer std.testing.allocator.free(full);
    try writeAll(tmp.dir, full[0 .. full.len - 3]);

    try expectPayloads(tmp.dir, .{ .encryption_key = KEY }, &.{});
}

test "recovery safety: zero-filled tail is truncated (SONNY-6620)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeWal(tmp.dir, null, &.{ "a", "b" });
    const good = try readAll(tmp.dir);
    defer std.testing.allocator.free(good);
    const zeros = [_]u8{0} ** 4096;
    const bytes = try std.mem.concat(std.testing.allocator, u8, &.{ good, &zeros });
    defer std.testing.allocator.free(bytes);
    try writeAll(tmp.dir, bytes);

    try expectPayloads(tmp.dir, .{}, &.{ "a", "b" });
}

test "recovery safety: corrupt final record with nothing after it is a torn tail (SONNY-6620)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeWal(tmp.dir, null, &.{ "alpha", "beta", "gamma" });
    try flipByte(tmp.dir, plainSize("alpha") + plainSize("beta") + record.HEADER_SIZE);

    try expectPayloads(tmp.dir, .{}, &.{ "alpha", "beta" });
}

test "recovery safety: non-monotonic LSN at the end is a torn tail (SONNY-6620)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeWal(tmp.dir, null, &.{ "a", "b" });
    const good = try readAll(tmp.dir);
    defer std.testing.allocator.free(good);
    var stale: [record.MIN_RECORD_SIZE + 1]u8 = undefined;
    record.serializeInto(&stale, 1, "x");
    const bytes = try std.mem.concat(std.testing.allocator, u8, &.{ good, &stale });
    defer std.testing.allocator.free(bytes);
    try writeAll(tmp.dir, bytes);

    try expectPayloads(tmp.dir, .{}, &.{ "a", "b" });
}

test "recovery safety: append after torn-tail truncation lands at the record boundary (SONNY-6620)" {
    // The streaming write cursor is positioned at valid_end after recovery.
    // If that seek were wrong the next record would land past a hole or
    // inside the old tail and the reopen below would not see it.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeWal(tmp.dir, null, &.{ "a", "b" });
    const good = try readAll(tmp.dir);
    defer std.testing.allocator.free(good);
    const bytes = try std.mem.concat(std.testing.allocator, u8, &.{ good, &[_]u8{0xEE} ** 9 });
    defer std.testing.allocator.free(bytes);
    try writeAll(tmp.dir, bytes);

    {
        var log = try wal.WriteAheadLog.init(std.testing.allocator, tmp.dir, NAME, .{});
        defer log.deinit();
        _ = try log.append("c");
    }
    const after = try readAll(tmp.dir);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqual(good.len + plainSize("c"), after.len);
    try std.testing.expectEqualSlices(u8, good, after[0..good.len]);
}
