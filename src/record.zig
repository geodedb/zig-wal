// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! WAL record framing: serialization, deserialization, and file I/O helpers.
//!
//! Each plaintext record on disk has the format:
//! ```
//! [lsn: u64 LE][payload_len: u32 LE][payload: N bytes][crc32: u32 LE]
//! ```
//! - Header: 12 bytes (LSN + payload_len)
//! - CRC: 4 bytes (CRC-32/ISO-HDLC over header+payload)
//! - Minimum record: 16 bytes (empty payload)
//!
//! The CRC is computed over all bytes from the start of the header through the
//! last byte of the payload. It does NOT cover the CRC field itself.

const std = @import("std");
const Crc32IsoHdlc = std.hash.crc.Crc32IsoHdlc;

// ============================================================================
// Constants
// ============================================================================

/// Size of the fixed record header in bytes: [lsn: u64][payload_len: u32]
pub const HEADER_SIZE: usize = 12;

/// Size of the CRC32 footer in bytes.
pub const CRC_SIZE: usize = 4;

/// Minimum record size (header + empty payload + CRC).
pub const MIN_RECORD_SIZE: usize = HEADER_SIZE + CRC_SIZE;

/// Maximum payload size (u32 max, ~4 GiB).
pub const MAX_PAYLOAD_SIZE: u64 = std.math.maxInt(u32);

/// Maximum on-disk record size accepted during recovery/iteration (16 MiB).
/// Records larger than this are treated as corrupt to prevent OOM from crafted
/// WAL files (SEC-0004). This is a defensive limit only; the write path does
/// not enforce it (callers control their own payload sizes).
pub const MAX_RECORD_SIZE: usize = 16 * 1024 * 1024;

// The WAL assumes usize is at least 64-bit so that u32 payload_len + constant
// header/CRC sizes cannot overflow in record-size guards (QA-0031).
comptime {
    std.debug.assert(@sizeOf(usize) >= 8);
}

/// Stack buffer threshold: payloads at or below this size use stack allocation
/// in writeToFile and encryptAndWriteToFile to avoid heap allocation on the
/// hot write path. Shared by record.zig and encryption.zig (QA-0006).
pub const STACK_WRITE_THRESHOLD: usize = 64 * 1024;

// ============================================================================
// Types
// ============================================================================

/// A deserialized WAL record. `payload` is a slice into the caller-provided
/// buffer or an allocator-owned allocation; ownership depends on how the
/// Record was obtained (see `deserialize` vs `readPayloadAndVerify`).
pub const Record = struct {
    /// Log Sequence Number assigned by the WAL engine.
    lsn: u64,
    /// Opaque caller payload. The WAL never interprets this data.
    payload: []const u8,
};

/// Parsed header fields returned by `readHeaderRaw`.
pub const HeaderInfo = struct {
    /// Log Sequence Number from the record header.
    lsn: u64,
    /// Number of payload bytes that follow the header on disk.
    payload_len: u32,
};

// ============================================================================
// Errors
// ============================================================================

pub const RecordError = error{
    /// Buffer is too small to contain a valid record.
    InvalidRecord,
    /// CRC32 in the record does not match the computed checksum.
    CrcMismatch,
};

// ============================================================================
// Core serialization / deserialization (pure, no I/O)
// ============================================================================

/// Serialize a WAL record into a newly allocated buffer.
///
/// The caller owns the returned slice and must free it with `allocator.free`.
///
/// Layout: `[lsn: u64 LE][payload_len: u32 LE][payload][crc32: u32 LE]`
pub fn serialize(
    allocator: std.mem.Allocator,
    lsn: u64,
    payload: []const u8,
) ![]u8 {
    const total_len = HEADER_SIZE + payload.len + CRC_SIZE;
    const buf = try allocator.alloc(u8, total_len);
    errdefer allocator.free(buf);

    serializeInto(buf, lsn, payload);

    return buf;
}

/// Serialize a WAL record into an existing buffer `buf`.
///
/// `buf` must be at least `HEADER_SIZE + payload.len + CRC_SIZE` bytes.
/// Panics unconditionally if `buf` is too small (SEC-0025: safe in all
/// build modes, including ReleaseFast/ReleaseSmall).
pub fn serializeInto(buf: []u8, lsn: u64, payload: []const u8) void {
    if (payload.len > MAX_PAYLOAD_SIZE) {
        @panic("serializeInto: payload exceeds u32 max (MAX_PAYLOAD_SIZE)");
    }
    if (buf.len < HEADER_SIZE + payload.len + CRC_SIZE) {
        @panic("serializeInto: buffer too small");
    }

    std.mem.writeInt(u64, buf[0..8], lsn, .little);
    std.mem.writeInt(u32, buf[8..12], @intCast(payload.len), .little);
    @memcpy(buf[HEADER_SIZE..][0..payload.len], payload);

    // CRC over header bytes + payload bytes (not the CRC field itself).
    const crc = Crc32IsoHdlc.hash(buf[0 .. HEADER_SIZE + payload.len]);
    std.mem.writeInt(u32, buf[HEADER_SIZE + payload.len ..][0..4], crc, .little);
}

/// Deserialize a WAL record from `buf`.
///
/// Returns a `Record` whose `payload` field is a sub-slice of `buf`.
/// The caller retains ownership of `buf`; no allocations are made.
///
/// Errors:
/// - `error.InvalidRecord` — buffer is too small to hold a valid record.
/// - `error.CrcMismatch` — integrity check failed (corruption or torn write).
pub fn deserialize(buf: []const u8) RecordError!Record {
    if (buf.len < MIN_RECORD_SIZE) return error.InvalidRecord;

    const lsn = std.mem.readInt(u64, buf[0..8], .little);
    const payload_len = std.mem.readInt(u32, buf[8..12], .little);

    const expected_len = HEADER_SIZE + payload_len + CRC_SIZE;
    if (buf.len < expected_len) return error.InvalidRecord;

    // Verify CRC over header + payload.
    const stored_crc = std.mem.readInt(u32, buf[HEADER_SIZE + payload_len ..][0..4], .little);
    const computed_crc = Crc32IsoHdlc.hash(buf[0 .. HEADER_SIZE + payload_len]);
    if (stored_crc != computed_crc) return error.CrcMismatch;

    return Record{
        .lsn = lsn,
        .payload = buf[HEADER_SIZE .. HEADER_SIZE + payload_len],
    };
}

// ============================================================================
// File I/O helpers
// ============================================================================

/// Write a WAL record to `file` at the current file position.
///
/// Uses a stack buffer for payloads ≤ 64 KB to avoid heap allocation on the
/// hot write path (Issue #559 pattern from Geode). Falls back to heap for
/// larger payloads. Issues a single `writeAll` call to minimize torn writes.
///
/// Returns the total number of bytes written.
pub fn writeToFile(
    allocator: std.mem.Allocator,
    file: std.fs.File,
    lsn: u64,
    payload: []const u8,
) !usize {
    const total_len = HEADER_SIZE + payload.len + CRC_SIZE;

    if (total_len <= STACK_WRITE_THRESHOLD + HEADER_SIZE + CRC_SIZE) {
        // Stack-allocate a buffer large enough for any payload ≤ 64 KB.
        var stack_buf: [HEADER_SIZE + STACK_WRITE_THRESHOLD + CRC_SIZE]u8 = undefined;
        const record_slice = stack_buf[0..total_len];
        serializeInto(record_slice, lsn, payload);
        try file.writeAll(record_slice);
    } else {
        // Heap allocation for payloads > 64 KB.
        const heap_buf = try allocator.alloc(u8, total_len);
        defer allocator.free(heap_buf);
        serializeInto(heap_buf, lsn, payload);
        try file.writeAll(heap_buf);
    }

    return total_len;
}

/// Read the payload and CRC footer following a previously-read header,
/// verify integrity, and return an allocator-owned copy of the payload.
///
/// The caller owns the returned slice and must free it with `allocator.free`.
///
/// Returns `null` if the read is incomplete (torn write at payload/CRC
/// boundary). Returns `error.CrcMismatch` if the record is fully present but
/// the CRC does not match (indicates on-disk corruption).
///
/// `header_buf` must contain the 12 raw header bytes that were already read
/// from disk (needed to recompute the CRC over header+payload).
pub fn readPayloadAndVerify(
    allocator: std.mem.Allocator,
    source: anytype,
    header_info: HeaderInfo,
    header_buf: [HEADER_SIZE]u8,
) !?[]u8 {
    const payload_len = header_info.payload_len;

    // Reject unreasonably large payloads to prevent OOM from crafted files (SEC-0004).
    if (@as(usize, payload_len) + HEADER_SIZE + CRC_SIZE > MAX_RECORD_SIZE) return null;

    // Allocate only the payload buffer — read CRC separately into a stack var.
    const payload = try allocator.alloc(u8, payload_len);
    errdefer allocator.free(payload);

    const pn = try source.readAll(payload);
    if (pn < payload_len) {
        allocator.free(payload);
        return null; // torn write
    }

    var crc_buf: [CRC_SIZE]u8 = undefined;
    const cn = try source.readAll(&crc_buf);
    if (cn < CRC_SIZE) {
        allocator.free(payload);
        return null; // torn write
    }

    const stored_crc = std.mem.readInt(u32, &crc_buf, .little);

    // Recompute CRC over the 12-byte header we already consumed + payload.
    var h = Crc32IsoHdlc.init();
    h.update(&header_buf);
    h.update(payload);
    const computed_crc = h.final();

    if (stored_crc != computed_crc) {
        // errdefer at line 224 handles the free on error return (QA-0008 / SEC-0032 pattern).
        return error.CrcMismatch;
    }

    return payload;
}

// ============================================================================
// readHeaderRaw — returns parsed header and raw bytes
// ============================================================================

/// Read a 12-byte record header from the current file position, returning both
/// the parsed `HeaderInfo` and the raw bytes (needed by `readPayloadAndVerify`).
///
/// Returns `null` on EOF or short read.
pub fn readHeaderRaw(source: anytype) !?struct { info: HeaderInfo, raw: [HEADER_SIZE]u8 } {
    var buf: [HEADER_SIZE]u8 = undefined;
    const n = try source.readAll(&buf);
    if (n < HEADER_SIZE) return null;

    return .{
        .info = HeaderInfo{
            .lsn = std.mem.readInt(u64, buf[0..8], .little),
            .payload_len = std.mem.readInt(u32, buf[8..12], .little),
        },
        .raw = buf,
    };
}

// ============================================================================
// CRC verification helper (moved from recovery.zig — QA-0015)
// ============================================================================

/// Verify the CRC32 of a record given its raw header bytes, payload bytes,
/// and the 4-byte stored CRC slice. Returns `true` if the CRC matches.
pub inline fn verifyCrc(
    header_buf: [HEADER_SIZE]u8,
    payload: []const u8,
    crc_bytes: []const u8,
) bool {
    if (crc_bytes.len < CRC_SIZE) @panic("verifyCrc: crc_bytes too short");
    const stored_crc = std.mem.readInt(u32, crc_bytes[0..4], .little);
    var h = Crc32IsoHdlc.init();
    h.update(&header_buf);
    h.update(payload);
    const computed_crc = h.final();
    return stored_crc == computed_crc;
}

// ============================================================================
// Tests
// ============================================================================

test "serialize: empty payload round-trips" {
    const allocator = std.testing.allocator;

    const buf = try serialize(allocator, 1, &.{});
    defer allocator.free(buf);

    const record = try deserialize(buf);
    try std.testing.expectEqual(@as(u64, 1), record.lsn);
    try std.testing.expectEqualSlices(u8, &.{}, record.payload);
}

test "serialize: non-empty payload round-trips" {
    const allocator = std.testing.allocator;
    const payload = "hello, WAL!";

    const buf = try serialize(allocator, 42, payload);
    defer allocator.free(buf);

    const record = try deserialize(buf);
    try std.testing.expectEqual(@as(u64, 42), record.lsn);
    try std.testing.expectEqualSlices(u8, payload, record.payload);
}

test "deserialize: buffer too small returns InvalidRecord" {
    // Buffer shorter than MIN_RECORD_SIZE
    const tiny: [4]u8 = .{ 0, 0, 0, 0 };
    const result = deserialize(&tiny);
    try std.testing.expectError(error.InvalidRecord, result);

    // Buffer exactly MIN_RECORD_SIZE - 1
    const short: [MIN_RECORD_SIZE - 1]u8 = [_]u8{0} ** (MIN_RECORD_SIZE - 1);
    const result2 = deserialize(&short);
    try std.testing.expectError(error.InvalidRecord, result2);
}

test "deserialize: corrupt CRC returns CrcMismatch" {
    const allocator = std.testing.allocator;

    const buf = try serialize(allocator, 7, "data");
    defer allocator.free(buf);

    // Flip a bit in the CRC footer (last 4 bytes).
    var corrupt = try allocator.dupe(u8, buf);
    defer allocator.free(corrupt);
    corrupt[corrupt.len - 1] ^= 0xFF;

    const result = deserialize(corrupt);
    try std.testing.expectError(error.CrcMismatch, result);
}

test "serialize: LSN and payload_len are little-endian" {
    const allocator = std.testing.allocator;
    const payload = "ab";

    const buf = try serialize(allocator, 0x0102030405060708, payload);
    defer allocator.free(buf);

    // LSN bytes 0..8 in little-endian order.
    try std.testing.expectEqual(@as(u8, 0x08), buf[0]);
    try std.testing.expectEqual(@as(u8, 0x07), buf[1]);
    try std.testing.expectEqual(@as(u8, 0x06), buf[2]);
    try std.testing.expectEqual(@as(u8, 0x05), buf[3]);
    try std.testing.expectEqual(@as(u8, 0x04), buf[4]);
    try std.testing.expectEqual(@as(u8, 0x03), buf[5]);
    try std.testing.expectEqual(@as(u8, 0x02), buf[6]);
    try std.testing.expectEqual(@as(u8, 0x01), buf[7]);

    // payload_len bytes 8..12 in little-endian order (value = 2).
    try std.testing.expectEqual(@as(u8, 0x02), buf[8]);
    try std.testing.expectEqual(@as(u8, 0x00), buf[9]);
    try std.testing.expectEqual(@as(u8, 0x00), buf[10]);
    try std.testing.expectEqual(@as(u8, 0x00), buf[11]);
}

test "serialize: large payload (1 MB)" {
    const allocator = std.testing.allocator;

    const large_payload = try allocator.alloc(u8, 1024 * 1024);
    defer allocator.free(large_payload);
    @memset(large_payload, 0xAB);

    const buf = try serialize(allocator, 100, large_payload);
    defer allocator.free(buf);

    const record = try deserialize(buf);
    try std.testing.expectEqual(@as(u64, 100), record.lsn);
    try std.testing.expectEqual(large_payload.len, record.payload.len);
    for (record.payload) |byte| {
        try std.testing.expectEqual(@as(u8, 0xAB), byte);
    }
}

test "writeToFile: heap fallback for payloads above STACK_WRITE_THRESHOLD" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Create a payload larger than STACK_WRITE_THRESHOLD (64 * 1024 = 65536).
    const payload_size = 100_000;
    const large_payload = try allocator.alloc(u8, payload_size);
    defer allocator.free(large_payload);
    // Fill with a recognisable pattern.
    for (large_payload, 0..) |*b, i| {
        b.* = @truncate(i);
    }

    const lsn: u64 = 99;

    // Write the record to a file.
    const wf = try tmp.dir.createFile("heap_fallback.wal", .{ .truncate = true });
    const bytes_written = try writeToFile(allocator, wf, lsn, large_payload);
    wf.close();

    // Verify reported size matches expected total.
    try std.testing.expectEqual(HEADER_SIZE + payload_size + CRC_SIZE, bytes_written);

    // Reopen read-only and read back via readHeaderRaw + readPayloadAndVerify.
    const rf = try tmp.dir.openFile("heap_fallback.wal", .{ .mode = .read_only });
    defer rf.close();

    const hdr = (try readHeaderRaw(rf)) orelse return error.Unexpected;
    try std.testing.expectEqual(lsn, hdr.info.lsn);
    try std.testing.expectEqual(@as(u32, payload_size), hdr.info.payload_len);

    const read_payload = (try readPayloadAndVerify(allocator, rf, hdr.info, hdr.raw)) orelse return error.Unexpected;
    defer allocator.free(read_payload);

    try std.testing.expectEqualSlices(u8, large_payload, read_payload);
}
