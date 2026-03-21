# WAL Library Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a generic, payload-agnostic Write-Ahead Log engine for Zig, extracted from Geode and Raft WAL implementations.

**Architecture:** Single-file WAL with LSN-based record ordering, CRC32 integrity, crash recovery via forward scan + truncation, atomic compaction via temp+fsync+rename, and optional AES-256-GCM per-record encryption. All state is instance-based (no singletons). Callers serialize their domain types into opaque `[]const u8` payloads before appending.

**Tech Stack:** Zig 0.15.1+ standard library only. `std.hash.crc.Crc32IsoHdlc` for CRC, `std.crypto.aead.aes_gcm.Aes256Gcm` for encryption, `std.fs` for file I/O.

---

## File Structure

```
src/
├── root.zig          # Public API re-exports (modify existing)
├── record.zig        # Record framing: serialize, deserialize, CRC (create)
├── wal.zig           # Core WAL engine: init, append, iterator (create)
├── recovery.zig      # Crash recovery: scan, validate, truncate (create)
├── compaction.zig    # Compaction: rewrite above watermark (create)
├── encryption.zig    # Optional AES-256-GCM encryption layer (create)
└── atomic.zig        # Atomic file operations: temp+fsync+rename (create)

tests/
├── integration.zig   # End-to-end WAL tests (modify existing)
└── scenarios/
    ├── crash.zig      # Torn write and corruption recovery tests (create)
    ├── compaction.zig # Compaction correctness tests (create)
    └── encryption.zig # Encryption round-trip tests (create)

build.zig              # Add scenario test steps (modify existing)
```

**Module dependency graph (compile-time `@import` only):**
```
root.zig ──> wal.zig ──> record.zig
                     ──> recovery.zig ──> record.zig
                     ──> compaction.zig ──> record.zig
                     ──>                   encryption.zig
                     ──> encryption.zig
                     ──> atomic.zig
```

**Responsibility boundaries:**
- `record.zig` — Pure functions. Serialize/deserialize record frames. CRC compute/verify. No file I/O.
- `recovery.zig` — Reads a file handle, scans records, reports last valid position. No file mutation.
- `compaction.zig` — Reads old file, writes new file, performs atomic swap. Stateless.
- `encryption.zig` — Pure functions. Encrypt/decrypt record blobs. Magic byte detection. No file I/O.
- `atomic.zig` — Pure utility. temp+fsync+rename pattern. No WAL knowledge.
- `wal.zig` — Orchestrates all of the above. Owns file handle, LSN counter, options.

---

## Task 1: Record Framing (`src/record.zig`)

**Files:**
- Create: `src/record.zig`

This is the foundation — pure functions for serializing/deserializing WAL records with CRC32 integrity.

**Record format (plaintext):**
```
[lsn: u64 LE][payload_len: u32 LE][payload: N bytes][crc32: u32 LE]
Header: 12 bytes | CRC: 4 bytes | Min record: 16 bytes
```

- [ ] **Step 1: Write failing test — serialize empty payload**

Create `src/record.zig` with the license header, imports, constants, and the first test:

```zig
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Record framing for the Write-Ahead Log.
//!
//! Each record is serialized as:
//! `[lsn: u64 LE][payload_len: u32 LE][payload][crc32: u32 LE]`
//!
//! CRC32 is computed over the header + payload bytes (not the CRC itself).

const std = @import("std");

/// Size of the record header: 8 (LSN) + 4 (payload_len) = 12 bytes.
pub const HEADER_SIZE: usize = 12;

/// Size of the CRC32 footer: 4 bytes.
pub const CRC_SIZE: usize = 4;

/// Minimum record size: header + CRC with zero-length payload.
pub const MIN_RECORD_SIZE: usize = HEADER_SIZE + CRC_SIZE;

/// Maximum payload size: ~4GB (u32 max).
pub const MAX_PAYLOAD_SIZE: usize = std.math.maxInt(u32);

/// A deserialized WAL record.
pub const Record = struct {
    lsn: u64,
    payload: []const u8,
};

test "serialize: empty payload round-trips" {
    const allocator = std.testing.allocator;
    const buf = try serialize(allocator, 1, "");
    defer allocator.free(buf);

    try std.testing.expectEqual(@as(usize, MIN_RECORD_SIZE), buf.len);

    const rec = try deserialize(buf);
    try std.testing.expectEqual(@as(u64, 1), rec.lsn);
    try std.testing.expectEqual(@as(usize, 0), rec.payload.len);
}
```

- [ ] **Step 2: Run test — verify it fails**

Run: `zig build test --summary all 2>&1 | head -20`
Expected: Compilation error — `serialize` and `deserialize` not defined.

- [ ] **Step 3: Implement `serialize`**

Add below the constants, above the tests:

```zig
/// Serialize a record into a caller-owned buffer.
/// Layout: [lsn: u64 LE][payload_len: u32 LE][payload][crc32: u32 LE]
/// CRC covers bytes [0..HEADER_SIZE + payload.len).
pub fn serialize(allocator: std.mem.Allocator, lsn: u64, payload: []const u8) ![]u8 {
    const total = HEADER_SIZE + payload.len + CRC_SIZE;
    const buf = try allocator.alloc(u8, total);
    errdefer allocator.free(buf);

    // Header
    @memcpy(buf[0..8], &std.mem.toBytes(std.mem.nativeToLittle(u64, lsn)));
    @memcpy(buf[8..12], &std.mem.toBytes(std.mem.nativeToLittle(u32, @intCast(payload.len))));

    // Payload
    if (payload.len > 0) {
        @memcpy(buf[HEADER_SIZE..][0..payload.len], payload);
    }

    // CRC over header + payload
    const crc = std.hash.crc.Crc32IsoHdlc.hash(buf[0 .. HEADER_SIZE + payload.len]);
    @memcpy(buf[HEADER_SIZE + payload.len ..][0..CRC_SIZE], &std.mem.toBytes(std.mem.nativeToLittle(u32, crc)));

    return buf;
}
```

- [ ] **Step 4: Implement `deserialize`**

```zig
/// Deserialize a record from a buffer. Returns a Record with a payload
/// slice pointing into `buf`. Does NOT take ownership of `buf`.
/// Returns `error.InvalidRecord` if the buffer is too small or CRC fails.
pub fn deserialize(buf: []const u8) !Record {
    if (buf.len < MIN_RECORD_SIZE) return error.InvalidRecord;

    const lsn = std.mem.littleToNative(u64, std.mem.bytesToValue(u64, buf[0..8]));
    const payload_len: usize = std.mem.littleToNative(u32, std.mem.bytesToValue(u32, buf[8..12]));

    const expected_len = HEADER_SIZE + payload_len + CRC_SIZE;
    if (buf.len < expected_len) return error.InvalidRecord;

    const payload = buf[HEADER_SIZE..][0..payload_len];

    // Verify CRC
    const stored_crc = std.mem.littleToNative(u32, std.mem.bytesToValue(u32, buf[HEADER_SIZE + payload_len ..][0..CRC_SIZE]));
    const computed_crc = std.hash.crc.Crc32IsoHdlc.hash(buf[0 .. HEADER_SIZE + payload_len]);
    if (stored_crc != computed_crc) return error.CrcMismatch;

    return .{ .lsn = lsn, .payload = payload };
}
```

- [ ] **Step 5: Run test — verify it passes**

Run: `zig build test --summary all`
Expected: PASS

- [ ] **Step 6: Write additional tests**

Add these tests to `src/record.zig`:

```zig
test "serialize: non-empty payload round-trips" {
    const allocator = std.testing.allocator;
    const payload = "hello, WAL!";
    const buf = try serialize(allocator, 42, payload);
    defer allocator.free(buf);

    try std.testing.expectEqual(@as(usize, HEADER_SIZE + payload.len + CRC_SIZE), buf.len);

    const rec = try deserialize(buf);
    try std.testing.expectEqual(@as(u64, 42), rec.lsn);
    try std.testing.expectEqualStrings(payload, rec.payload);
}

test "deserialize: buffer too small returns InvalidRecord" {
    const buf = [_]u8{0} ** (MIN_RECORD_SIZE - 1);
    try std.testing.expectError(error.InvalidRecord, deserialize(&buf));
}

test "deserialize: corrupt CRC returns CrcMismatch" {
    const allocator = std.testing.allocator;
    const buf = try serialize(allocator, 1, "data");
    defer allocator.free(buf);

    // Flip a bit in the CRC
    buf[buf.len - 1] ^= 0xFF;
    try std.testing.expectError(error.CrcMismatch, deserialize(buf));
}

test "serialize: LSN and payload_len are little-endian" {
    const allocator = std.testing.allocator;
    const buf = try serialize(allocator, 0x0102030405060708, "AB");
    defer allocator.free(buf);

    // LSN bytes (little-endian)
    try std.testing.expectEqual(@as(u8, 0x08), buf[0]);
    try std.testing.expectEqual(@as(u8, 0x07), buf[1]);
    try std.testing.expectEqual(@as(u8, 0x06), buf[2]);

    // payload_len = 2 (little-endian)
    try std.testing.expectEqual(@as(u8, 2), buf[8]);
    try std.testing.expectEqual(@as(u8, 0), buf[9]);
}

test "serialize: large payload (1MB)" {
    const allocator = std.testing.allocator;
    const payload = try allocator.alloc(u8, 1024 * 1024);
    defer allocator.free(payload);
    @memset(payload, 0xAB);

    const buf = try serialize(allocator, 999, payload);
    defer allocator.free(buf);

    const rec = try deserialize(buf);
    try std.testing.expectEqual(@as(u64, 999), rec.lsn);
    try std.testing.expectEqual(@as(usize, 1024 * 1024), rec.payload.len);
    try std.testing.expectEqual(@as(u8, 0xAB), rec.payload[0]);
    try std.testing.expectEqual(@as(u8, 0xAB), rec.payload[rec.payload.len - 1]);
}
```

- [ ] **Step 7: Run tests — verify all pass**

Run: `zig build test --summary all`
Expected: All pass

- [ ] **Step 8: Add `writeToFile` and `readHeaderFromFile` helpers**

These helpers write/read records to/from file handles without allocating. Used by `wal.zig` and `recovery.zig`.

```zig
/// Write a serialized record to a file. Uses stack buffer for payloads <= 64KB,
/// heap for larger. Returns the total bytes written.
pub fn writeToFile(file: std.fs.File, allocator: std.mem.Allocator, lsn: u64, payload: []const u8) !usize {
    const total = HEADER_SIZE + payload.len + CRC_SIZE;

    // Build header
    var header: [HEADER_SIZE]u8 = undefined;
    @memcpy(header[0..8], &std.mem.toBytes(std.mem.nativeToLittle(u64, lsn)));
    @memcpy(header[8..12], &std.mem.toBytes(std.mem.nativeToLittle(u32, @intCast(payload.len))));

    // CRC over header + payload
    var crc_hasher = std.hash.crc.Crc32IsoHdlc.init();
    crc_hasher.update(&header);
    crc_hasher.update(payload);
    const crc = crc_hasher.final();
    var crc_bytes: [CRC_SIZE]u8 = undefined;
    @memcpy(&crc_bytes, &std.mem.toBytes(std.mem.nativeToLittle(u32, crc)));

    // Stack-allocated fast path for small records (<=64KB payload)
    const stack_limit = 65536;
    if (payload.len <= stack_limit) {
        var buf: [HEADER_SIZE + stack_limit + CRC_SIZE]u8 = undefined;
        @memcpy(buf[0..HEADER_SIZE], &header);
        @memcpy(buf[HEADER_SIZE..][0..payload.len], payload);
        @memcpy(buf[HEADER_SIZE + payload.len ..][0..CRC_SIZE], &crc_bytes);
        try file.writeAll(buf[0..total]);
    } else {
        // Heap path for large payloads
        const buf = try allocator.alloc(u8, total);
        defer allocator.free(buf);
        @memcpy(buf[0..HEADER_SIZE], &header);
        @memcpy(buf[HEADER_SIZE..][0..payload.len], payload);
        @memcpy(buf[HEADER_SIZE + payload.len ..][0..CRC_SIZE], &crc_bytes);
        try file.writeAll(buf);
    }

    return total;
}

/// Information read from a record header (first 12 bytes).
pub const HeaderInfo = struct {
    lsn: u64,
    payload_len: u32,
};

/// Read and parse a record header from the current file position.
/// Returns null if fewer than HEADER_SIZE bytes are available (EOF/torn write).
pub fn readHeader(file: std.fs.File) !?HeaderInfo {
    var buf: [HEADER_SIZE]u8 = undefined;
    const n = try file.readAll(&buf);
    if (n < HEADER_SIZE) return null;

    return .{
        .lsn = std.mem.littleToNative(u64, std.mem.bytesToValue(u64, buf[0..8])),
        .payload_len = std.mem.littleToNative(u32, std.mem.bytesToValue(u32, buf[8..12])),
    };
}

/// Read a full record (payload + CRC) after the header has been read.
/// `header_info` comes from `readHeader`. Returns the payload if CRC matches,
/// null if the record is incomplete (torn write), or error.CrcMismatch.
/// Caller owns the returned payload slice.
pub fn readPayloadAndVerify(
    file: std.fs.File,
    allocator: std.mem.Allocator,
    header_info: HeaderInfo,
) !?[]u8 {
    const payload_len: usize = header_info.payload_len;
    const read_len = payload_len + CRC_SIZE;

    const buf = try allocator.alloc(u8, read_len);
    errdefer allocator.free(buf);

    const n = try file.readAll(buf);
    if (n < read_len) {
        allocator.free(buf);
        return null; // Torn write — incomplete record
    }

    // Rebuild header bytes for CRC computation
    var header_bytes: [HEADER_SIZE]u8 = undefined;
    @memcpy(header_bytes[0..8], &std.mem.toBytes(std.mem.nativeToLittle(u64, header_info.lsn)));
    @memcpy(header_bytes[8..12], &std.mem.toBytes(std.mem.nativeToLittle(u32, header_info.payload_len)));

    var crc_hasher = std.hash.crc.Crc32IsoHdlc.init();
    crc_hasher.update(&header_bytes);
    crc_hasher.update(buf[0..payload_len]);
    const computed_crc = crc_hasher.final();

    const stored_crc = std.mem.littleToNative(u32, std.mem.bytesToValue(u32, buf[payload_len..][0..CRC_SIZE]));
    if (computed_crc != stored_crc) {
        allocator.free(buf);
        return error.CrcMismatch;
    }

    // Shrink allocation to just the payload (drop CRC bytes)
    if (payload_len == 0) {
        allocator.free(buf);
        return try allocator.alloc(u8, 0);
    }
    if (allocator.resize(buf, payload_len)) {
        return buf[0..payload_len];
    }
    // resize not supported — copy
    const payload = try allocator.alloc(u8, payload_len);
    @memcpy(payload, buf[0..payload_len]);
    allocator.free(buf);
    return payload;
}
```

- [ ] **Step 9: Run all tests — verify pass**

Run: `zig build test --summary all`
Expected: All pass

- [ ] **Step 10: Commit**

```bash
git add src/record.zig
git commit -m "feat: add record framing module with serialize/deserialize and CRC32"
```

---

## Task 2: Atomic File Utility (`src/atomic.zig`)

**Files:**
- Create: `src/atomic.zig`

Simple utility: write data to a temp file, fsync, rename over target. Used by compaction and exposed publicly for callers (Raft hard_state, Geode checkpoint).

- [ ] **Step 1: Write failing test — atomic write creates file**

Create `src/atomic.zig`:

```zig
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Atomic file write utility.
//!
//! Writes data to a temporary file, fsyncs it, then renames it over the
//! target file. This ensures the target file is always either the old
//! version or the new version, never a partial write.

const std = @import("std");

test "atomicWriteFile: creates file with correct contents" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try atomicWriteFile(tmp_dir.dir, "test.dat", "hello world");

    const contents = try tmp_dir.dir.readFileAlloc(std.testing.allocator, "test.dat", 4096);
    defer std.testing.allocator.free(contents);
    try std.testing.expectEqualStrings("hello world", contents);
}
```

- [ ] **Step 2: Run test — verify it fails**

Run: `zig build test --summary all 2>&1 | head -20`
Expected: `atomicWriteFile` not defined.

- [ ] **Step 3: Implement `atomicWriteFile`**

```zig
/// Atomically write `data` to `filename` within `dir`.
///
/// Creates a temporary file, writes data, fsyncs, then renames over
/// the target. If power fails before rename completes, the old file
/// (or no file) remains.
pub fn atomicWriteFile(dir: std.fs.Dir, filename: []const u8, data: []const u8) !void {
    const tmp_filename = "wal.tmp";

    // Create temp file (truncate if leftover from a crash)
    var tmp = try dir.createFile(tmp_filename, .{ .truncate = true });
    errdefer {
        tmp.close();
        dir.deleteFile(tmp_filename) catch {};
    }

    try tmp.writeAll(data);
    try tmp.sync();
    tmp.close();

    try dir.rename(tmp_filename, filename);
}
```

- [ ] **Step 4: Run test — verify it passes**

Run: `zig build test --summary all`
Expected: PASS

- [ ] **Step 5: Write additional tests**

```zig
test "atomicWriteFile: overwrites existing file" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try atomicWriteFile(tmp_dir.dir, "test.dat", "version 1");
    try atomicWriteFile(tmp_dir.dir, "test.dat", "version 2");

    const contents = try tmp_dir.dir.readFileAlloc(std.testing.allocator, "test.dat", 4096);
    defer std.testing.allocator.free(contents);
    try std.testing.expectEqualStrings("version 2", contents);
}

test "atomicWriteFile: empty data" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try atomicWriteFile(tmp_dir.dir, "test.dat", "");

    const contents = try tmp_dir.dir.readFileAlloc(std.testing.allocator, "test.dat", 4096);
    defer std.testing.allocator.free(contents);
    try std.testing.expectEqual(@as(usize, 0), contents.len);
}
```

- [ ] **Step 6: Run tests — verify all pass**

Run: `zig build test --summary all`
Expected: All pass

- [ ] **Step 7: Commit**

```bash
git add src/atomic.zig
git commit -m "feat: add atomic file write utility (temp+fsync+rename)"
```

---

## Task 3: Recovery Module (`src/recovery.zig`)

**Files:**
- Create: `src/recovery.zig`

Scans a WAL file forward, validates each record's CRC, and returns the position of the last valid record. Used by `wal.zig` during init.

- [ ] **Step 1: Write failing test — recover empty file**

Create `src/recovery.zig`:

```zig
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Crash recovery for the Write-Ahead Log.
//!
//! Scans a WAL file forward from byte 0, validates each record's CRC,
//! and returns the position and LSN of the last valid record. Callers
//! use this to truncate any torn writes and resume appending.

const std = @import("std");
const record = @import("record.zig");

/// Result of a recovery scan.
pub const RecoveryInfo = struct {
    /// Highest valid LSN found, or 0 if no valid records.
    last_lsn: u64,
    /// File offset just past the last valid record. Truncate here.
    valid_end: u64,
    /// Number of valid records found.
    record_count: u64,
};

test "recover: empty file returns zero state" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    // Create an empty file
    var f = try tmp_dir.dir.createFile("wal", .{});
    f.close();

    var file = try tmp_dir.dir.openFile("wal", .{ .mode = .read_only });
    defer file.close();

    const info = try recover(std.testing.allocator, file);
    try std.testing.expectEqual(@as(u64, 0), info.last_lsn);
    try std.testing.expectEqual(@as(u64, 0), info.valid_end);
    try std.testing.expectEqual(@as(u64, 0), info.record_count);
}
```

- [ ] **Step 2: Run test — verify it fails**

Run: `zig build test --summary all 2>&1 | head -20`
Expected: `recover` not defined.

- [ ] **Step 3: Implement `recover`**

```zig
/// Scan the WAL file from the beginning and validate each record.
///
/// Returns the position and LSN of the last valid record. The file
/// should be truncated at `valid_end` to remove any torn writes.
///
/// This function does NOT modify the file.
pub fn recover(allocator: std.mem.Allocator, file: std.fs.File) !RecoveryInfo {
    try file.seekTo(0);

    var info = RecoveryInfo{
        .last_lsn = 0,
        .valid_end = 0,
        .record_count = 0,
    };

    while (true) {
        const offset = try file.getPos();

        // Try to read header
        const header_info = try record.readHeader(file) orelse break;

        // Read payload + CRC for validation
        const payload_len: usize = header_info.payload_len;
        const read_len = payload_len + record.CRC_SIZE;
        const payload_and_crc: u64 = @as(u64, payload_len) + record.CRC_SIZE;

        // Rebuild header bytes for CRC computation
        var header_bytes: [record.HEADER_SIZE]u8 = undefined;
        @memcpy(header_bytes[0..8], &std.mem.toBytes(std.mem.nativeToLittle(u64, header_info.lsn)));
        @memcpy(header_bytes[8..12], &std.mem.toBytes(std.mem.nativeToLittle(u32, header_info.payload_len)));

        // Use stack buffer for small records, heap for large
        const stack_limit = 65536 + record.CRC_SIZE;
        var stack_buf: [stack_limit]u8 = undefined;

        const data_buf: []u8 = if (read_len <= stack_limit)
            stack_buf[0..read_len]
        else
            allocator.alloc(u8, read_len) catch break;

        defer if (read_len > stack_limit) allocator.free(data_buf);

        const n = try file.readAll(data_buf);
        if (n < read_len) break; // Torn write

        // Verify CRC over header + payload
        var crc_hasher = std.hash.crc.Crc32IsoHdlc.init();
        crc_hasher.update(&header_bytes);
        crc_hasher.update(data_buf[0..payload_len]);
        const computed = crc_hasher.final();
        const stored = std.mem.littleToNative(u32, std.mem.bytesToValue(u32, data_buf[payload_len..][0..record.CRC_SIZE]));
        if (computed != stored) break; // Corrupt record

        info.last_lsn = header_info.lsn;
        info.valid_end = offset + record.HEADER_SIZE + payload_and_crc;
        info.record_count += 1;
    }

    return info;
}
```

- [ ] **Step 4: Run test — verify it passes**

Run: `zig build test --summary all`
Expected: PASS

- [ ] **Step 5: Write additional tests — valid records, torn writes, corrupt CRC**

```zig
test "recover: single valid record" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    // Write one record
    var f = try tmp_dir.dir.createFile("wal", .{});
    _ = try record.writeToFile(f, allocator, 1, "hello");
    f.close();

    var file = try tmp_dir.dir.openFile("wal", .{ .mode = .read_only });
    defer file.close();

    const info = try recover(std.testing.allocator, file);
    try std.testing.expectEqual(@as(u64, 1), info.last_lsn);
    try std.testing.expectEqual(@as(u64, record.HEADER_SIZE + 5 + record.CRC_SIZE), info.valid_end);
    try std.testing.expectEqual(@as(u64, 1), info.record_count);
}

test "recover: multiple records" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var f = try tmp_dir.dir.createFile("wal", .{});
    _ = try record.writeToFile(f, allocator, 1, "first");
    _ = try record.writeToFile(f, allocator, 2, "second");
    _ = try record.writeToFile(f, allocator, 3, "third");
    f.close();

    var file = try tmp_dir.dir.openFile("wal", .{ .mode = .read_only });
    defer file.close();

    const info = try recover(std.testing.allocator, file);
    try std.testing.expectEqual(@as(u64, 3), info.last_lsn);
    try std.testing.expectEqual(@as(u64, 3), info.record_count);
}

test "recover: torn write — incomplete header" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    // Write 6 bytes of garbage (less than HEADER_SIZE=12)
    var f = try tmp_dir.dir.createFile("wal", .{});
    try f.writeAll(&[_]u8{ 1, 2, 3, 4, 5, 6 });
    f.close();

    var file = try tmp_dir.dir.openFile("wal", .{ .mode = .read_only });
    defer file.close();

    const info = try recover(std.testing.allocator, file);
    try std.testing.expectEqual(@as(u64, 0), info.last_lsn);
    try std.testing.expectEqual(@as(u64, 0), info.valid_end);
}

test "recover: torn write — valid record then incomplete" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var f = try tmp_dir.dir.createFile("wal", .{});
    _ = try record.writeToFile(f, allocator, 1, "good");
    // Write partial second record (just header, no payload or CRC)
    var header: [record.HEADER_SIZE]u8 = undefined;
    @memcpy(header[0..8], &std.mem.toBytes(std.mem.nativeToLittle(u64, @as(u64, 2))));
    @memcpy(header[8..12], &std.mem.toBytes(std.mem.nativeToLittle(u32, @as(u32, 100))));
    try f.writeAll(&header);
    f.close();

    var file = try tmp_dir.dir.openFile("wal", .{ .mode = .read_only });
    defer file.close();

    const info = try recover(std.testing.allocator, file);
    try std.testing.expectEqual(@as(u64, 1), info.last_lsn);
    try std.testing.expectEqual(@as(u64, 1), info.record_count);
}

test "recover: corrupt CRC stops scan" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var f = try tmp_dir.dir.createFile("wal", .{ .mode = .read_write });
    _ = try record.writeToFile(f, allocator, 1, "good");
    const second_start = try f.getPos();
    _ = try record.writeToFile(f, allocator, 2, "bad");
    _ = try record.writeToFile(f, allocator, 3, "also good but unreachable");

    // Corrupt the CRC of record 2
    try f.seekTo(second_start + record.HEADER_SIZE + 3); // inside payload
    try f.writeAll(&[_]u8{0xFF}); // flip a payload byte → CRC mismatch
    f.close();

    var file = try tmp_dir.dir.openFile("wal", .{ .mode = .read_only });
    defer file.close();

    const info = try recover(std.testing.allocator, file);
    try std.testing.expectEqual(@as(u64, 1), info.last_lsn);
    try std.testing.expectEqual(@as(u64, 1), info.record_count);
}
```

- [ ] **Step 6: Run tests — verify all pass**

Run: `zig build test --summary all`
Expected: All pass

- [ ] **Step 7: Commit**

```bash
git add src/recovery.zig
git commit -m "feat: add crash recovery module with forward scan and CRC validation"
```

---

## Task 4: Core WAL Engine (`src/wal.zig`)

**Files:**
- Create: `src/wal.zig`

Orchestrates record, recovery, and file I/O into the main `WriteAheadLog` struct.

- [ ] **Step 1: Write failing test — init creates file, append returns LSN**

Create `src/wal.zig`:

```zig
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Core Write-Ahead Log engine.
//!
//! Provides append-only durable storage for opaque byte payloads.
//! Each record is assigned a monotonically increasing Log Sequence Number (LSN).
//! Supports crash recovery, compaction, and optional AES-256-GCM encryption.

const std = @import("std");
const record = @import("record.zig");
const recovery_mod = @import("recovery.zig");

pub const Options = struct {
    /// AES-256-GCM encryption key. If null, records are plaintext.
    encryption_key: ?[32]u8 = null,
    /// If true, do not fsync after each append. Caller manages durability.
    manual_sync: bool = false,
};

test "init: creates WAL file, append returns LSN 1" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var wal = try WriteAheadLog.init(std.testing.allocator, tmp_dir.dir, "wal", .{});
    defer wal.deinit();

    const lsn = try wal.append("hello");
    try std.testing.expectEqual(@as(u64, 1), lsn);
}
```

- [ ] **Step 2: Run test — verify it fails**

Run: `zig build test --summary all 2>&1 | head -20`
Expected: `WriteAheadLog` not defined.

- [ ] **Step 3: Implement WriteAheadLog struct — init, deinit, append**

```zig
pub const WriteAheadLog = struct {
    allocator: std.mem.Allocator,
    dir: std.fs.Dir,
    filename: []const u8,
    file: std.fs.File,
    current_lsn: u64,
    file_end: u64,
    bytes_since_compact: u64,
    options: Options,

    /// Open or create a WAL at the given path. Runs recovery on open.
    pub fn init(
        allocator: std.mem.Allocator,
        dir: std.fs.Dir,
        filename: []const u8,
        options: Options,
    ) !WriteAheadLog {
        // Open or create the file
        const file = dir.openFile(filename, .{ .mode = .read_write }) catch |err| blk: {
            if (err == error.FileNotFound) {
                break :blk try dir.createFile(filename, .{
                    .read = true,
                    .truncate = false,
                });
            }
            return err;
        };
        errdefer file.close();

        // Run recovery
        const info = try recovery_mod.recover(allocator, file);

        // Truncate at last valid record
        if (info.valid_end < try file.getEndPos()) {
            try file.setEndPos(info.valid_end);
        }

        // Seek to end for appending
        try file.seekTo(info.valid_end);

        return .{
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

    pub fn deinit(self: *WriteAheadLog) void {
        self.file.close();
        self.* = undefined;
    }

    /// Append an opaque payload. Returns the assigned LSN.
    pub fn append(self: *WriteAheadLog, payload: []const u8) !u64 {
        self.current_lsn += 1;
        const lsn = self.current_lsn;

        const bytes_written = try record.writeToFile(self.file, self.allocator, lsn, payload);

        if (!self.options.manual_sync) {
            try self.file.sync();
        }

        self.file_end += bytes_written;
        self.bytes_since_compact += bytes_written;

        return lsn;
    }

    /// Append multiple payloads with a single fsync.
    /// Returns the LSN of the last record written.
    pub fn appendBatch(self: *WriteAheadLog, payloads: []const []const u8) !u64 {
        var last_lsn: u64 = self.current_lsn;

        for (payloads) |payload| {
            self.current_lsn += 1;
            last_lsn = self.current_lsn;

            const bytes_written = try record.writeToFile(self.file, self.allocator, last_lsn, payload);
            self.file_end += bytes_written;
            self.bytes_since_compact += bytes_written;
        }

        if (!self.options.manual_sync and payloads.len > 0) {
            try self.file.sync();
        }

        return last_lsn;
    }

    /// Explicit fsync.
    pub fn sync(self: *WriteAheadLog) !void {
        try self.file.sync();
    }

    /// Return the highest assigned LSN, or 0 if no records.
    pub fn currentLsn(self: *const WriteAheadLog) u64 {
        return self.current_lsn;
    }

    /// Return bytes written since last compaction.
    pub fn bytesSinceCompact(self: *const WriteAheadLog) u64 {
        return self.bytes_since_compact;
    }
};
```

- [ ] **Step 4: Run test — verify it passes**

Run: `zig build test --summary all`
Expected: PASS

- [ ] **Step 5: Write additional tests — multi-append, batch, reopen recovery**

```zig
test "append: LSN increases monotonically" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var wal = try WriteAheadLog.init(std.testing.allocator, tmp_dir.dir, "wal", .{});
    defer wal.deinit();

    const lsn1 = try wal.append("first");
    const lsn2 = try wal.append("second");
    const lsn3 = try wal.append("third");

    try std.testing.expectEqual(@as(u64, 1), lsn1);
    try std.testing.expectEqual(@as(u64, 2), lsn2);
    try std.testing.expectEqual(@as(u64, 3), lsn3);
    try std.testing.expectEqual(@as(u64, 3), wal.currentLsn());
}

test "appendBatch: single fsync for multiple records" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var wal = try WriteAheadLog.init(std.testing.allocator, tmp_dir.dir, "wal", .{});
    defer wal.deinit();

    const payloads = [_][]const u8{ "one", "two", "three" };
    const last_lsn = try wal.appendBatch(&payloads);

    try std.testing.expectEqual(@as(u64, 3), last_lsn);
    try std.testing.expectEqual(@as(u64, 3), wal.currentLsn());
}

test "init: recovers state after close and reopen" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    // Write some records
    {
        var wal = try WriteAheadLog.init(std.testing.allocator, tmp_dir.dir, "wal", .{});
        _ = try wal.append("first");
        _ = try wal.append("second");
        _ = try wal.append("third");
        wal.deinit();
    }

    // Reopen — should recover LSN
    {
        var wal = try WriteAheadLog.init(std.testing.allocator, tmp_dir.dir, "wal", .{});
        defer wal.deinit();

        try std.testing.expectEqual(@as(u64, 3), wal.currentLsn());

        // Next append should get LSN 4
        const lsn = try wal.append("fourth");
        try std.testing.expectEqual(@as(u64, 4), lsn);
    }
}

test "bytesSinceCompact: tracks bytes written" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var wal = try WriteAheadLog.init(std.testing.allocator, tmp_dir.dir, "wal", .{});
    defer wal.deinit();

    try std.testing.expectEqual(@as(u64, 0), wal.bytesSinceCompact());

    _ = try wal.append("test");
    const expected = record.HEADER_SIZE + 4 + record.CRC_SIZE; // "test" = 4 bytes
    try std.testing.expectEqual(@as(u64, expected), wal.bytesSinceCompact());
}
```

- [ ] **Step 6: Run tests — verify all pass**

Run: `zig build test --summary all`
Expected: All pass

- [ ] **Step 7: Add Iterator to WriteAheadLog**

Add inside the `WriteAheadLog` struct:

```zig
    pub const Iterator = struct {
        file: std.fs.File,
        allocator: std.mem.Allocator,
        from_lsn: u64,
        done: bool,

        pub const Entry = struct {
            lsn: u64,
            payload: []const u8,
            allocator: std.mem.Allocator,

            pub fn deinit(self: *Entry) void {
                self.allocator.free(self.payload);
            }
        };

        /// Return the next valid record, or null at end-of-log.
        /// Returns error on I/O failure. Stops (returns null) at first
        /// CRC mismatch or incomplete record (torn write boundary).
        /// Caller must call `entry.deinit()` on each returned entry.
        pub fn next(self: *Iterator) !?Entry {
            if (self.done) return null;

            while (true) {
                const header_info = record.readHeader(self.file) catch |err| {
                    self.done = true;
                    return err; // Propagate I/O errors
                } orelse {
                    // EOF — no more records
                    self.done = true;
                    return null;
                };

                const payload = record.readPayloadAndVerify(
                    self.file,
                    self.allocator,
                    header_info,
                ) catch |err| {
                    self.done = true;
                    if (err == error.CrcMismatch) return null; // Corruption boundary
                    return err; // Propagate other errors (I/O, OOM)
                } orelse {
                    // Torn write — stop
                    self.done = true;
                    return null;
                };

                // Skip records below the requested LSN
                if (header_info.lsn <= self.from_lsn) {
                    self.allocator.free(payload);
                    continue;
                }

                return .{
                    .lsn = header_info.lsn,
                    .payload = payload,
                    .allocator = self.allocator,
                };
            }
        }
    };

    /// Iterate over records starting after `from_lsn`.
    /// Pass 0 to iterate from the beginning.
    /// Opens a separate read handle. Caller must call `iter.deinit()`.
    pub fn iterator(self: *WriteAheadLog, from_lsn: u64) !Iterator {
        const read_file = try self.dir.openFile(self.filename, .{ .mode = .read_only });
        return .{
            .file = read_file,
            .allocator = self.allocator,
            .from_lsn = from_lsn,
            .done = false,
        };
    }
```

**Note:** `Iterator.deinit()` must be included directly in the Iterator struct definition (not as a separate step). Add it right after the `next()` method inside the struct:

```zig
        pub fn deinit(self: *Iterator) void {
            self.file.close();
        }
```

- [ ] **Step 8: Write iterator tests**

```zig
test "iterator: reads all records from beginning" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var wal = try WriteAheadLog.init(std.testing.allocator, tmp_dir.dir, "wal", .{});
    defer wal.deinit();

    _ = try wal.append("first");
    _ = try wal.append("second");
    _ = try wal.append("third");

    var iter = try wal.iterator(0);
    defer iter.deinit();

    var entry1 = (try iter.next()).?;
    defer entry1.deinit();
    try std.testing.expectEqual(@as(u64, 1), entry1.lsn);
    try std.testing.expectEqualStrings("first", entry1.payload);

    var entry2 = (try iter.next()).?;
    defer entry2.deinit();
    try std.testing.expectEqual(@as(u64, 2), entry2.lsn);
    try std.testing.expectEqualStrings("second", entry2.payload);

    var entry3 = (try iter.next()).?;
    defer entry3.deinit();
    try std.testing.expectEqual(@as(u64, 3), entry3.lsn);
    try std.testing.expectEqualStrings("third", entry3.payload);

    try std.testing.expectEqual(@as(?Iterator.Entry, null), try iter.next());
}

test "iterator: from_lsn skips earlier records" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var wal = try WriteAheadLog.init(std.testing.allocator, tmp_dir.dir, "wal", .{});
    defer wal.deinit();

    _ = try wal.append("first");
    _ = try wal.append("second");
    _ = try wal.append("third");

    var iter = try wal.iterator(2); // Skip LSN 1 and 2
    defer iter.deinit();

    var entry = (try iter.next()).?;
    defer entry.deinit();
    try std.testing.expectEqual(@as(u64, 3), entry.lsn);
    try std.testing.expectEqualStrings("third", entry.payload);

    try std.testing.expectEqual(@as(?Iterator.Entry, null), try iter.next());
}

test "iterator: empty WAL returns null immediately" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var wal = try WriteAheadLog.init(std.testing.allocator, tmp_dir.dir, "wal", .{});
    defer wal.deinit();

    var iter = try wal.iterator(0);
    defer iter.deinit();

    try std.testing.expectEqual(@as(?Iterator.Entry, null), try iter.next());
}
```

- [ ] **Step 9: Run tests — verify all pass**

Run: `zig build test --summary all`
Expected: All pass

- [ ] **Step 10: Commit**

```bash
git add src/wal.zig
git commit -m "feat: add core WAL engine with init, append, batch, iterator, and recovery"
```

---

## Task 5: Compaction (`src/compaction.zig`)

**Files:**
- Create: `src/compaction.zig`

Rewrites the WAL keeping only records with LSN > watermark. Uses the bulk-copy optimization from Geode: since LSNs are monotonic, once we find the first kept record, everything after it is also kept.

- [ ] **Step 1: Write failing test — compact removes old records**

Create `src/compaction.zig`:

```zig
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! WAL compaction: rewrite file keeping records with LSN > watermark.
//!
//! Uses a bulk-copy optimization: since LSNs are monotonically increasing,
//! once the first kept record is found, all subsequent bytes can be copied
//! as a contiguous block without parsing individual records.

const std = @import("std");
const record = @import("record.zig");
const atomic = @import("atomic.zig");

test "compact: removes records below watermark" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    // Write 5 records
    var f = try tmp_dir.dir.createFile("wal", .{ .read = true });
    _ = try record.writeToFile(f, allocator, 1, "one");
    _ = try record.writeToFile(f, allocator, 2, "two");
    _ = try record.writeToFile(f, allocator, 3, "three");
    _ = try record.writeToFile(f, allocator, 4, "four");
    _ = try record.writeToFile(f, allocator, 5, "five");
    f.close();

    const result = try compact(tmp_dir.dir, "wal", 3);
    try std.testing.expectEqual(@as(u64, 2), result.records_kept);

    // Verify remaining records
    var rf = try tmp_dir.dir.openFile("wal", .{ .mode = .read_only });
    defer rf.close();

    const h1 = (try record.readHeader(rf)).?;
    try std.testing.expectEqual(@as(u64, 4), h1.lsn);
    const p1 = (try record.readPayloadAndVerify(rf, allocator, h1)).?;
    defer allocator.free(p1);
    try std.testing.expectEqualStrings("four", p1);

    const h2 = (try record.readHeader(rf)).?;
    try std.testing.expectEqual(@as(u64, 5), h2.lsn);
    const p2 = (try record.readPayloadAndVerify(rf, allocator, h2)).?;
    defer allocator.free(p2);
    try std.testing.expectEqualStrings("five", p2);
}
```

- [ ] **Step 2: Run test — verify it fails**

Run: `zig build test --summary all 2>&1 | head -20`

- [ ] **Step 3: Implement `compact`**

```zig
/// Result of a compaction operation.
pub const CompactResult = struct {
    /// Number of records kept after compaction.
    records_kept: u64,
    /// New file size in bytes.
    new_size: u64,
};

/// Rewrite the WAL file keeping only records with LSN > `up_to_lsn`.
///
/// Uses bulk-copy: scans to find the first kept record's file offset,
/// then copies everything from that offset forward to a temp file.
/// The swap is atomic (temp + fsync + rename).
///
/// Returns the number of records kept and the new file size.
pub fn compact(
    dir: std.fs.Dir,
    filename: []const u8,
    up_to_lsn: u64,
) !CompactResult {
    // Open source file for reading
    var src = try dir.openFile(filename, .{ .mode = .read_only });
    defer src.close();

    const file_size = try src.getEndPos();

    // Scan forward to find the first record with LSN > up_to_lsn
    var first_kept_offset: ?u64 = null;
    var skipped: u64 = 0;
    var total_records: u64 = 0;

    try src.seekTo(0);
    while (true) {
        const offset = try src.getPos();
        const header_info = try record.readHeader(src) orelse break;
        const payload_and_crc: usize = header_info.payload_len + record.CRC_SIZE;

        // Skip past payload + CRC
        const end_pos = try src.getEndPos();
        if (offset + record.HEADER_SIZE + payload_and_crc > end_pos) break;
        try src.seekTo(offset + record.HEADER_SIZE + payload_and_crc);

        total_records += 1;

        if (header_info.lsn > up_to_lsn and first_kept_offset == null) {
            first_kept_offset = offset;
        }
        if (header_info.lsn <= up_to_lsn) {
            skipped += 1;
        }
    }

    const kept = total_records - skipped;

    if (first_kept_offset) |offset| {
        if (offset == 0) {
            // All records kept — nothing to do
            return .{ .records_kept = kept, .new_size = file_size };
        }

        // Bulk-copy from first_kept_offset to end
        const remaining = file_size - offset;

        // Write to temp file using block copy
        const tmp_filename = "wal.tmp";
        var tmp = try dir.createFile(tmp_filename, .{ .truncate = true });
        errdefer {
            tmp.close();
            dir.deleteFile(tmp_filename) catch {};
        }

        try src.seekTo(offset);
        var buf: [65536]u8 = undefined;
        var copied: u64 = 0;
        while (copied < remaining) {
            const to_read: usize = @intCast(@min(buf.len, remaining - copied));
            const n = try src.readAll(buf[0..to_read]);
            if (n == 0) break;
            try tmp.writeAll(buf[0..n]);
            copied += n;
        }

        try tmp.sync();
        tmp.close();

        // Atomic swap
        try dir.rename(tmp_filename, filename);

        return .{ .records_kept = kept, .new_size = remaining };
    } else {
        // No records kept — truncate to empty
        const tmp_filename = "wal.tmp";
        var tmp = try dir.createFile(tmp_filename, .{ .truncate = true });
        try tmp.sync();
        tmp.close();
        try dir.rename(tmp_filename, filename);

        return .{ .records_kept = 0, .new_size = 0 };
    }
}
```

- [ ] **Step 4: Run test — verify it passes**

Run: `zig build test --summary all`
Expected: PASS

- [ ] **Step 5: Write additional tests**

```zig
test "compact: all records removed" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var f = try tmp_dir.dir.createFile("wal", .{ .read = true });
    _ = try record.writeToFile(f, allocator, 1, "one");
    _ = try record.writeToFile(f, allocator, 2, "two");
    f.close();

    const result = try compact(tmp_dir.dir, "wal", 5);
    try std.testing.expectEqual(@as(u64, 0), result.records_kept);
    try std.testing.expectEqual(@as(u64, 0), result.new_size);
}

test "compact: no records removed" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var f = try tmp_dir.dir.createFile("wal", .{ .read = true });
    _ = try record.writeToFile(f, allocator, 1, "one");
    _ = try record.writeToFile(f, allocator, 2, "two");
    const size = try f.getPos();
    f.close();

    const result = try compact(tmp_dir.dir, "wal", 0);
    try std.testing.expectEqual(@as(u64, 2), result.records_kept);
    try std.testing.expectEqual(size, result.new_size);
}

test "compact: append after compact works" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    // Write records, compact, then write more
    var f = try tmp_dir.dir.createFile("wal", .{ .read = true });
    _ = try record.writeToFile(f, allocator, 1, "old");
    _ = try record.writeToFile(f, allocator, 2, "keep");
    f.close();

    _ = try compact(tmp_dir.dir, "wal", 1);

    // Open for append
    var af = try tmp_dir.dir.openFile("wal", .{ .mode = .read_write });
    try af.seekFromEnd(0);
    _ = try record.writeToFile(af, allocator, 3, "new");
    af.close();

    // Verify all records readable
    var rf = try tmp_dir.dir.openFile("wal", .{ .mode = .read_only });
    defer rf.close();

    const h1 = (try record.readHeader(rf)).?;
    try std.testing.expectEqual(@as(u64, 2), h1.lsn);
    const p1 = (try record.readPayloadAndVerify(rf, allocator, h1)).?;
    defer allocator.free(p1);

    const h2 = (try record.readHeader(rf)).?;
    try std.testing.expectEqual(@as(u64, 3), h2.lsn);
    const p2 = (try record.readPayloadAndVerify(rf, allocator, h2)).?;
    defer allocator.free(p2);
    try std.testing.expectEqualStrings("new", p2);
}
```

- [ ] **Step 6: Run tests — verify all pass**

Run: `zig build test --summary all`
Expected: All pass

- [ ] **Step 7: Commit**

```bash
git add src/compaction.zig
git commit -m "feat: add compaction module with bulk-copy optimization"
```

---

## Task 6: Wire Compaction into WAL Engine

**Files:**
- Modify: `src/wal.zig`

- [ ] **Step 1: Write failing test — WAL.compact removes old records**

Add to `src/wal.zig`:

```zig
test "compact: removes records and allows continued append" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var wal = try WriteAheadLog.init(std.testing.allocator, tmp_dir.dir, "wal", .{});

    _ = try wal.append("one");
    _ = try wal.append("two");
    _ = try wal.append("three");

    try wal.compact(2); // Remove LSN 1 and 2

    // Append should still work
    const lsn = try wal.append("four");
    try std.testing.expectEqual(@as(u64, 4), lsn);

    // Iterator should only see LSN 3 and 4
    var iter = try wal.iterator(0);
    defer iter.deinit();

    var e1 = (try iter.next()).?;
    defer e1.deinit();
    try std.testing.expectEqual(@as(u64, 3), e1.lsn);

    var e2 = (try iter.next()).?;
    defer e2.deinit();
    try std.testing.expectEqual(@as(u64, 4), e2.lsn);

    try std.testing.expectEqual(@as(?Iterator.Entry, null), try iter.next());

    wal.deinit();
}
```

- [ ] **Step 2: Run test — verify it fails**

- [ ] **Step 3: Add `compact` method to WriteAheadLog**

Add import at top of `src/wal.zig`:
```zig
const compaction = @import("compaction.zig");
```

Add inside `WriteAheadLog` struct:
```zig
    /// Remove all records with LSN <= `up_to_lsn` by rewriting the WAL.
    /// The rewrite is atomic (temp file + fsync + rename).
    pub fn compact(self: *WriteAheadLog, up_to_lsn: u64) !void {
        // Close current file handle before compaction rewrites the file
        self.file.close();

        const result = compaction.compact(self.dir, self.filename, up_to_lsn) catch |err| {
            // Reopen file on error
            self.file = try self.dir.openFile(self.filename, .{ .mode = .read_write });
            try self.file.seekFromEnd(0);
            return err;
        };

        // Reopen the compacted file
        self.file = try self.dir.openFile(self.filename, .{ .mode = .read_write });
        try self.file.seekFromEnd(0);

        self.file_end = result.new_size;
        self.bytes_since_compact = 0;
    }
```

- [ ] **Step 4: Run tests — verify all pass**

Run: `zig build test --summary all`
Expected: All pass

- [ ] **Step 5: Commit**

```bash
git add src/wal.zig
git commit -m "feat: wire compaction into WAL engine"
```

---

## Task 7: Encryption Layer (`src/encryption.zig`)

**Files:**
- Create: `src/encryption.zig`

Optional AES-256-GCM per-record encryption. Pure functions, no file I/O.

**Encrypted record format:**
```
[blob_len: u32 LE][magic: "ZIGWALE\0" (8)][nonce: (12)][tag: (16)][ciphertext]
```

- [ ] **Step 1: Write failing test — encrypt/decrypt round-trip**

Create `src/encryption.zig`:

```zig
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Optional AES-256-GCM encryption layer for the WAL.
//!
//! Each record is independently encrypted with a fresh random nonce.
//! Encrypted records are framed with a length prefix and magic bytes
//! for detection, allowing mixed plaintext/encrypted WAL files.
//!
//! Format: [blob_len: u32 LE]["ZIGWALE\0"][nonce: 12][tag: 16][ciphertext]

const std = @import("std");
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;

/// Magic bytes identifying an encrypted record.
pub const MAGIC = "ZIGWALE\x00".*;
pub const MAGIC_SIZE: usize = 8;
pub const NONCE_SIZE: usize = Aes256Gcm.nonce_length; // 12
pub const TAG_SIZE: usize = Aes256Gcm.tag_length; // 16
pub const BLOB_LEN_SIZE: usize = 4;

/// Overhead added by encryption framing (before ciphertext):
/// 4 (blob_len) + 8 (magic) + 12 (nonce) + 16 (tag) = 40 bytes.
pub const ENCRYPTION_OVERHEAD: usize = BLOB_LEN_SIZE + MAGIC_SIZE + NONCE_SIZE + TAG_SIZE;

test "encrypt/decrypt: round-trip" {
    const allocator = std.testing.allocator;
    const key: [32]u8 = [_]u8{0x42} ** 32;
    const plaintext = "hello, encrypted WAL!";

    const blob = try encryptRecord(allocator, &key, plaintext);
    defer allocator.free(blob);

    const decrypted = try decryptRecord(allocator, &key, blob);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}
```

- [ ] **Step 2: Run test — verify it fails**

- [ ] **Step 3: Implement `encryptRecord`**

```zig
/// Encrypt a plaintext record. Returns the full encrypted blob
/// (blob_len + magic + nonce + tag + ciphertext). Caller owns the result.
pub fn encryptRecord(
    allocator: std.mem.Allocator,
    key: *const [32]u8,
    plaintext: []const u8,
) ![]u8 {
    const ciphertext_len = plaintext.len;
    const blob_content_len = MAGIC_SIZE + NONCE_SIZE + TAG_SIZE + ciphertext_len;
    const total_len = BLOB_LEN_SIZE + blob_content_len;

    const buf = try allocator.alloc(u8, total_len);
    errdefer allocator.free(buf);

    // blob_len (u32 LE) — size of everything after blob_len
    @memcpy(buf[0..4], &std.mem.toBytes(std.mem.nativeToLittle(u32, @intCast(blob_content_len))));

    // Magic
    @memcpy(buf[4..12], &MAGIC);

    // Random nonce
    var nonce: [NONCE_SIZE]u8 = undefined;
    std.crypto.random.bytes(&nonce);
    @memcpy(buf[12..24], &nonce);

    // Encrypt
    var tag: [TAG_SIZE]u8 = undefined;
    const ct_slice = buf[ENCRYPTION_OVERHEAD..][0..ciphertext_len];
    Aes256Gcm.encrypt(ct_slice, &tag, plaintext, &.{}, nonce, key.*);

    // Tag
    @memcpy(buf[24..40], &tag);

    return buf;
}
```

- [ ] **Step 4: Implement `decryptRecord`**

```zig
/// Decrypt an encrypted blob. Returns the plaintext. Caller owns the result.
/// Returns error if the blob is malformed, magic doesn't match, or
/// authentication fails (wrong key or tampered data).
pub fn decryptRecord(
    allocator: std.mem.Allocator,
    key: *const [32]u8,
    blob: []const u8,
) ![]u8 {
    if (blob.len < ENCRYPTION_OVERHEAD) return error.InvalidEncryptedRecord;

    // Verify blob_len
    const blob_content_len = std.mem.littleToNative(u32, std.mem.bytesToValue(u32, blob[0..4]));
    if (blob.len < BLOB_LEN_SIZE + blob_content_len) return error.InvalidEncryptedRecord;

    // Verify magic
    if (!std.mem.eql(u8, blob[4..12], &MAGIC)) return error.InvalidEncryptedRecord;

    // Extract nonce, tag, ciphertext
    const nonce: [NONCE_SIZE]u8 = blob[12..24].*;
    const tag: [TAG_SIZE]u8 = blob[24..40].*;
    const ciphertext = blob[ENCRYPTION_OVERHEAD..BLOB_LEN_SIZE + blob_content_len];

    const plaintext = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(plaintext);

    Aes256Gcm.decrypt(plaintext, ciphertext, tag, &.{}, nonce, key.*) catch {
        allocator.free(plaintext);
        return error.DecryptionFailed;
    };

    return plaintext;
}

/// Check if a buffer begins with an encrypted record marker.
/// Checks the magic bytes at offset 4.
pub fn isEncrypted(buf: []const u8) bool {
    if (buf.len < BLOB_LEN_SIZE + MAGIC_SIZE) return false;
    return std.mem.eql(u8, buf[4..12], &MAGIC);
}

/// Load a 256-bit key from a hex-encoded environment variable.
/// Returns null if the variable is not set.
/// Returns error.InvalidKey if the value is not exactly 64 hex characters.
/// NOTE: Spec says this takes an allocator param, but it's unnecessary —
/// all work is done on the stack. Spec should be updated to match.
pub fn loadKeyFromEnv(env_var: []const u8) !?[32]u8 {
    const value = std.posix.getenv(env_var) orelse return null;

    if (value.len != 64) return error.InvalidKey;

    var key: [32]u8 = undefined;
    for (0..32) |i| {
        key[i] = std.fmt.parseUnsigned(u8, value[i * 2 ..][0..2], 16) catch return error.InvalidKey;
    }
    return key;
}
```

- [ ] **Step 5: Run test — verify it passes**

Run: `zig build test --summary all`
Expected: PASS

- [ ] **Step 6: Write additional tests**

```zig
test "encrypt/decrypt: empty plaintext" {
    const allocator = std.testing.allocator;
    const key: [32]u8 = [_]u8{0x01} ** 32;

    const blob = try encryptRecord(allocator, &key, "");
    defer allocator.free(blob);

    const decrypted = try decryptRecord(allocator, &key, blob);
    defer allocator.free(decrypted);

    try std.testing.expectEqual(@as(usize, 0), decrypted.len);
}

test "decryptRecord: wrong key returns DecryptionFailed" {
    const allocator = std.testing.allocator;
    const key1: [32]u8 = [_]u8{0x01} ** 32;
    const key2: [32]u8 = [_]u8{0x02} ** 32;

    const blob = try encryptRecord(allocator, &key1, "secret");
    defer allocator.free(blob);

    try std.testing.expectError(error.DecryptionFailed, decryptRecord(allocator, &key2, blob));
}

test "isEncrypted: detects encrypted blob" {
    const allocator = std.testing.allocator;
    const key: [32]u8 = [_]u8{0x42} ** 32;

    const blob = try encryptRecord(allocator, &key, "data");
    defer allocator.free(blob);

    try std.testing.expect(isEncrypted(blob));
}

test "isEncrypted: plaintext record returns false" {
    const allocator = std.testing.allocator;
    const record_mod = @import("record.zig");

    const buf = try record_mod.serialize(allocator, 1, "data");
    defer allocator.free(buf);

    try std.testing.expect(!isEncrypted(buf));
}

test "decryptRecord: truncated blob returns InvalidEncryptedRecord" {
    try std.testing.expectError(
        error.InvalidEncryptedRecord,
        decryptRecord(std.testing.allocator, &([_]u8{0} ** 32), &[_]u8{ 1, 2, 3 }),
    );
}
```

- [ ] **Step 7: Run tests — verify all pass**

Run: `zig build test --summary all`
Expected: All pass

- [ ] **Step 8: Commit**

```bash
git add src/encryption.zig
git commit -m "feat: add AES-256-GCM encryption layer for WAL records"
```

---

## Task 8: Integrate Encryption into WAL Engine

**Files:**
- Modify: `src/wal.zig`
- Modify: `src/recovery.zig`

Wire encryption into the write path (encrypt before write), read path (decrypt after read), and recovery (detect encrypted records).

- [ ] **Step 1: Write failing test — encrypted WAL round-trip**

Add to `src/wal.zig`:

```zig
test "encrypted: append and iterate with encryption" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const key: [32]u8 = [_]u8{0xAB} ** 32;
    var wal = try WriteAheadLog.init(std.testing.allocator, tmp_dir.dir, "wal", .{
        .encryption_key = key,
    });
    defer wal.deinit();

    _ = try wal.append("secret one");
    _ = try wal.append("secret two");

    var iter = try wal.iterator(0);
    defer iter.deinit();

    var e1 = (try iter.next()).?;
    defer e1.deinit();
    try std.testing.expectEqual(@as(u64, 1), e1.lsn);
    try std.testing.expectEqualStrings("secret one", e1.payload);

    var e2 = (try iter.next()).?;
    defer e2.deinit();
    try std.testing.expectEqual(@as(u64, 2), e2.lsn);
    try std.testing.expectEqualStrings("secret two", e2.payload);

    try std.testing.expectEqual(@as(?Iterator.Entry, null), try iter.next());
}
```

- [ ] **Step 2: Run test — verify it fails**

- [ ] **Step 3: Modify `wal.zig` append to encrypt when key is set**

Add import:
```zig
const encryption = @import("encryption.zig");
```

Modify `append` method: if `options.encryption_key` is set, serialize the plaintext record to a buffer, encrypt it, and write the encrypted blob. Otherwise, use the existing plaintext path.

The approach:
1. Serialize plaintext record into buffer using `record.serialize`
2. Encrypt the buffer using `encryption.encryptRecord`
3. Write the encrypted blob to file

```zig
    pub fn append(self: *WriteAheadLog, payload: []const u8) !u64 {
        self.current_lsn += 1;
        const lsn = self.current_lsn;

        if (self.options.encryption_key) |key| {
            // Serialize plaintext record, then encrypt
            const plaintext = try record.serialize(self.allocator, lsn, payload);
            defer self.allocator.free(plaintext);

            const blob = try encryption.encryptRecord(self.allocator, &key, plaintext);
            defer self.allocator.free(blob);

            try self.file.writeAll(blob);
            self.file_end += blob.len;
            self.bytes_since_compact += blob.len;
        } else {
            const bytes_written = try record.writeToFile(self.file, self.allocator, lsn, payload);
            self.file_end += bytes_written;
            self.bytes_since_compact += bytes_written;
        }

        if (!self.options.manual_sync) {
            try self.file.sync();
        }

        return lsn;
    }
```

Similarly update `appendBatch`.

- [ ] **Step 4: Modify recovery to handle encrypted records**

Update `src/recovery.zig` — add import for `encryption` and modify `recover` to accept an optional key. When a key is provided, the scanner detects encrypted records by reading a peek buffer and checking magic bytes.

Add at top of `src/recovery.zig`:
```zig
const encryption = @import("encryption.zig");
```

Replace the `recover` function with two entry points:

```zig
/// Recover a plaintext WAL.
pub fn recover(allocator: std.mem.Allocator, file: std.fs.File) !RecoveryInfo {
    return recoverWithKey(allocator, file, null);
}

/// Recover a WAL that may contain encrypted records.
/// If `key` is provided, encrypted records are decrypted and validated.
/// If `key` is null, only plaintext records are expected.
pub fn recoverWithKey(allocator: std.mem.Allocator, file: std.fs.File, key: ?*const [32]u8) !RecoveryInfo {
    try file.seekTo(0);

    var info = RecoveryInfo{
        .last_lsn = 0,
        .valid_end = 0,
        .record_count = 0,
    };

    while (true) {
        const offset = try file.getPos();

        // Peek at first 12 bytes to detect record type
        var peek: [12]u8 = undefined;
        const peek_n = try file.readAll(&peek);
        if (peek_n < 4) break; // Not enough for any record

        // Seek back to record start
        try file.seekTo(offset);

        // Check if this is an encrypted record (magic at offset 4)
        if (key != null and peek_n >= 12 and std.mem.eql(u8, peek[4..12], &encryption.MAGIC)) {
            // Encrypted record: [blob_len: u32 LE][blob_content...]
            var len_buf: [4]u8 = undefined;
            const ln = try file.readAll(&len_buf);
            if (ln < 4) break;

            const blob_content_len: usize = std.mem.littleToNative(u32, std.mem.bytesToValue(u32, len_buf[0..4]));
            const total_blob_len = encryption.BLOB_LEN_SIZE + blob_content_len;

            // Read full encrypted blob
            const blob = allocator.alloc(u8, total_blob_len) catch break;
            defer allocator.free(blob);
            @memcpy(blob[0..4], &len_buf);

            const rest_n = try file.readAll(blob[4..]);
            if (rest_n < blob_content_len) break; // Torn write

            // Decrypt
            const plaintext = encryption.decryptRecord(allocator, key.?, blob) catch break;
            defer allocator.free(plaintext);

            // plaintext is a serialized record: [lsn][payload_len][payload][crc]
            // Verify CRC of inner record
            const inner_rec = record.deserialize(plaintext) catch break;

            info.last_lsn = inner_rec.lsn;
            info.valid_end = offset + total_blob_len;
            info.record_count += 1;
        } else {
            // Plaintext record — existing logic
            const header_info = try record.readHeader(file) orelse break;
            const payload_len: usize = header_info.payload_len;
            const read_len = payload_len + record.CRC_SIZE;
            const payload_and_crc: u64 = @as(u64, payload_len) + record.CRC_SIZE;

            var header_bytes: [record.HEADER_SIZE]u8 = undefined;
            @memcpy(header_bytes[0..8], &std.mem.toBytes(std.mem.nativeToLittle(u64, header_info.lsn)));
            @memcpy(header_bytes[8..12], &std.mem.toBytes(std.mem.nativeToLittle(u32, header_info.payload_len)));

            const stack_limit = 65536 + record.CRC_SIZE;
            var stack_buf: [stack_limit]u8 = undefined;
            const data_buf: []u8 = if (read_len <= stack_limit)
                stack_buf[0..read_len]
            else
                allocator.alloc(u8, read_len) catch break;
            defer if (read_len > stack_limit) allocator.free(data_buf);

            const n = try file.readAll(data_buf);
            if (n < read_len) break;

            var crc_hasher = std.hash.crc.Crc32IsoHdlc.init();
            crc_hasher.update(&header_bytes);
            crc_hasher.update(data_buf[0..payload_len]);
            const computed = crc_hasher.final();
            const stored = std.mem.littleToNative(u32, std.mem.bytesToValue(u32, data_buf[payload_len..][0..record.CRC_SIZE]));
            if (computed != stored) break;

            info.last_lsn = header_info.lsn;
            info.valid_end = offset + record.HEADER_SIZE + payload_and_crc;
            info.record_count += 1;
        }
    }

    return info;
}
```

Update `wal.zig` `init` to pass the encryption key to recovery:
```zig
const info = if (options.encryption_key) |key|
    try recovery_mod.recoverWithKey(allocator, file, &key)
else
    try recovery_mod.recover(allocator, file);
```

- [ ] **Step 5: Modify iterator to decrypt**

Add `encryption_key` field to the Iterator struct. Modify `WriteAheadLog.iterator()` to pass the key. Modify `Iterator.next()` to detect and decrypt encrypted records.

Add to Iterator struct:
```zig
        encryption_key: ?[32]u8,
```

Update `WriteAheadLog.iterator()`:
```zig
    pub fn iterator(self: *WriteAheadLog, from_lsn: u64) !Iterator {
        const read_file = try self.dir.openFile(self.filename, .{ .mode = .read_only });
        return .{
            .file = read_file,
            .allocator = self.allocator,
            .from_lsn = from_lsn,
            .done = false,
            .encryption_key = self.options.encryption_key,
        };
    }
```

Update `Iterator.next()` — before reading a plaintext header, peek to detect encrypted records:

```zig
        pub fn next(self: *Iterator) !?Entry {
            if (self.done) return null;

            while (true) {
                const offset = try self.file.getPos();

                // Peek to detect encrypted vs plaintext
                var peek: [12]u8 = undefined;
                const peek_n = self.file.readAll(&peek) catch |err| {
                    self.done = true;
                    return err;
                };
                if (peek_n < 4) { self.done = true; return null; }

                // Seek back
                try self.file.seekTo(offset);

                var lsn: u64 = undefined;
                var payload: []u8 = undefined;

                if (self.encryption_key != null and peek_n >= 12 and
                    std.mem.eql(u8, peek[4..12], &encryption.MAGIC))
                {
                    // Encrypted record
                    var len_buf: [4]u8 = undefined;
                    if ((try self.file.readAll(&len_buf)) < 4) {
                        self.done = true;
                        return null;
                    }
                    const blob_content_len: usize = std.mem.littleToNative(
                        u32, std.mem.bytesToValue(u32, len_buf[0..4]));
                    const total = encryption.BLOB_LEN_SIZE + blob_content_len;

                    const blob = self.allocator.alloc(u8, total) catch |err| {
                        self.done = true;
                        return err;
                    };
                    defer self.allocator.free(blob);
                    @memcpy(blob[0..4], &len_buf);
                    if ((try self.file.readAll(blob[4..])) < blob_content_len) {
                        self.done = true;
                        return null;
                    }

                    const plaintext = encryption.decryptRecord(
                        self.allocator, &self.encryption_key.?, blob,
                    ) catch {
                        self.done = true;
                        return null; // Decryption failure = corruption boundary
                    };
                    defer self.allocator.free(plaintext);

                    const inner = record.deserialize(plaintext) catch {
                        self.done = true;
                        return null;
                    };
                    lsn = inner.lsn;

                    // Copy payload out (plaintext will be freed)
                    payload = try self.allocator.alloc(u8, inner.payload.len);
                    @memcpy(payload, inner.payload);
                } else {
                    // Plaintext record — existing logic
                    const header_info = record.readHeader(self.file) catch |err| {
                        self.done = true;
                        return err;
                    } orelse {
                        self.done = true;
                        return null;
                    };

                    payload = record.readPayloadAndVerify(
                        self.file, self.allocator, header_info,
                    ) catch |err| {
                        self.done = true;
                        if (err == error.CrcMismatch) return null;
                        return err;
                    } orelse {
                        self.done = true;
                        return null;
                    };
                    lsn = header_info.lsn;
                }

                if (lsn <= self.from_lsn) {
                    self.allocator.free(payload);
                    continue;
                }

                return .{
                    .lsn = lsn,
                    .payload = payload,
                    .allocator = self.allocator,
                };
            }
        }
```

**Note on compaction + encryption:** The bulk-copy optimization still works for encrypted WALs because the scanner only needs to find the first kept record's *file offset*. Since LSNs are extracted during the scan (by decrypting), and everything after the first kept offset is a contiguous block of valid encrypted records, the block can be copied verbatim without re-encryption. Update `compaction.zig` to also accept an optional key for scanning, or pass through an opaque "record measurer" callback. The simplest approach: add a `compactEncrypted` variant that uses `recovery.recoverWithKey` logic for scanning, then bulk-copies from the first kept offset.

- [ ] **Step 6: Run tests — verify all pass**

Run: `zig build test --summary all`
Expected: All pass including the new encrypted test

- [ ] **Step 7: Write test — encrypted WAL survives close/reopen**

```zig
test "encrypted: recovery after close and reopen" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const key: [32]u8 = [_]u8{0xCD} ** 32;

    {
        var wal = try WriteAheadLog.init(std.testing.allocator, tmp_dir.dir, "wal", .{
            .encryption_key = key,
        });
        _ = try wal.append("persisted secret");
        wal.deinit();
    }

    {
        var wal = try WriteAheadLog.init(std.testing.allocator, tmp_dir.dir, "wal", .{
            .encryption_key = key,
        });
        defer wal.deinit();

        try std.testing.expectEqual(@as(u64, 1), wal.currentLsn());

        var iter = try wal.iterator(0);
        defer iter.deinit();

        var entry = (try iter.next()).?;
        defer entry.deinit();
        try std.testing.expectEqualStrings("persisted secret", entry.payload);
    }
}
```

- [ ] **Step 8: Run tests — verify all pass**

Run: `zig build test --summary all`
Expected: All pass

- [ ] **Step 9: Commit**

```bash
git add src/wal.zig src/recovery.zig
git commit -m "feat: integrate AES-256-GCM encryption into WAL engine"
```

---

## Task 9: Public API (`src/root.zig`)

**Files:**
- Modify: `src/root.zig`

Replace the skeleton template with re-exports of the real WAL types.

- [ ] **Step 1: Rewrite `src/root.zig`**

```zig
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # wal
//!
//! A generic, payload-agnostic Write-Ahead Log engine for Zig.
//!
//! Provides durable, crash-safe, append-only storage for opaque byte payloads.
//! Each record is assigned a monotonically increasing LSN (Log Sequence Number).
//! Supports optional AES-256-GCM per-record encryption and atomic compaction.
//!
//! ## Quick Start
//!
//! ```zig
//! const wal = @import("wal");
//!
//! var log = try wal.WriteAheadLog.init(allocator, dir, "my.wal", .{});
//! defer log.deinit();
//!
//! const lsn = try log.append("hello, WAL!");
//! ```
//!
//! ## License
//!
//! Apache-2.0

pub const WriteAheadLog = @import("wal.zig").WriteAheadLog;
pub const Options = @import("wal.zig").Options;
pub const record = @import("record.zig");
pub const encryption = @import("encryption.zig");

/// Atomically write data to a file using temp+fsync+rename.
pub const atomicWriteFile = @import("atomic.zig").atomicWriteFile;

test {
    // Pull in all module tests
    _ = @import("record.zig");
    _ = @import("wal.zig");
    _ = @import("recovery.zig");
    _ = @import("compaction.zig");
    _ = @import("encryption.zig");
    _ = @import("atomic.zig");
}
```

- [ ] **Step 2: Run unit tests**

Run: `zig build test --summary all`
Expected: All pass (tests from all modules pulled in via `root.zig`)

- [ ] **Step 3: Commit**

```bash
git add src/root.zig
git commit -m "feat: wire public API re-exports in root.zig"
```

---

## Task 10: Integration Tests

**Files:**
- Modify: `tests/integration.zig`
- Modify: `build.zig` (add scenario test steps)
- Create: `tests/scenarios/crash.zig`
- Create: `tests/scenarios/compaction.zig`
- Create: `tests/scenarios/encryption.zig`

- [ ] **Step 1: Rewrite `tests/integration.zig`**

Replace the skeleton with real end-to-end tests:

```zig
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Integration tests for the WAL library.
//!
//! These tests verify full WAL lifecycle: init, append, close, reopen,
//! iterate, compact, and verify.

const std = @import("std");
const wal = @import("wal");

test "lifecycle: init, append 100 records, close, reopen, iterate, verify all" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const count = 100;

    // Write phase
    {
        var log = try wal.WriteAheadLog.init(std.testing.allocator, tmp_dir.dir, "test.wal", .{});
        for (0..count) |i| {
            var buf: [64]u8 = undefined;
            const payload = std.fmt.bufPrint(&buf, "record-{d}", .{i + 1}) catch unreachable;
            _ = try log.append(payload);
        }
        try std.testing.expectEqual(@as(u64, count), log.currentLsn());
        log.deinit();
    }

    // Read phase
    {
        var log = try wal.WriteAheadLog.init(std.testing.allocator, tmp_dir.dir, "test.wal", .{});
        defer log.deinit();

        try std.testing.expectEqual(@as(u64, count), log.currentLsn());

        var iter = try log.iterator(0);
        defer iter.deinit();

        var seen: u64 = 0;
        while (try iter.next()) |*entry| {
            defer @constCast(entry).deinit();
            seen += 1;
            try std.testing.expectEqual(seen, entry.lsn);
        }
        try std.testing.expectEqual(@as(u64, count), seen);
    }
}

test "lifecycle: append, compact, append, verify ordering" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var log = try wal.WriteAheadLog.init(std.testing.allocator, tmp_dir.dir, "test.wal", .{});

    // First batch
    _ = try log.append("a");
    _ = try log.append("b");
    _ = try log.append("c");

    // Compact away first two
    try log.compact(2);

    // Second batch
    _ = try log.append("d");
    _ = try log.append("e");

    // Verify: should see c(3), d(4), e(5)
    var iter = try log.iterator(0);
    defer iter.deinit();

    var lsns: std.ArrayListUnmanaged(u64) = .empty;
    defer lsns.deinit(std.testing.allocator);

    while (try iter.next()) |*entry| {
        defer @constCast(entry).deinit();
        try lsns.append(std.testing.allocator, entry.lsn);
    }

    try std.testing.expectEqual(@as(usize, 3), lsns.items.len);
    try std.testing.expectEqual(@as(u64, 3), lsns.items[0]);
    try std.testing.expectEqual(@as(u64, 4), lsns.items[1]);
    try std.testing.expectEqual(@as(u64, 5), lsns.items[2]);

    log.deinit();
}

test "lifecycle: multiple WAL instances in same process" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var log1 = try wal.WriteAheadLog.init(std.testing.allocator, tmp_dir.dir, "wal1", .{});
    defer log1.deinit();

    var log2 = try wal.WriteAheadLog.init(std.testing.allocator, tmp_dir.dir, "wal2", .{});
    defer log2.deinit();

    _ = try log1.append("log1-record");
    _ = try log2.append("log2-record");

    try std.testing.expectEqual(@as(u64, 1), log1.currentLsn());
    try std.testing.expectEqual(@as(u64, 1), log2.currentLsn());
}

test "lifecycle: batch append" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var log = try wal.WriteAheadLog.init(std.testing.allocator, tmp_dir.dir, "test.wal", .{});
    defer log.deinit();

    const payloads = [_][]const u8{ "alpha", "beta", "gamma", "delta" };
    const last = try log.appendBatch(&payloads);
    try std.testing.expectEqual(@as(u64, 4), last);
}

test "lifecycle: large payload (128KB)" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var log = try wal.WriteAheadLog.init(std.testing.allocator, tmp_dir.dir, "test.wal", .{});

    const payload = try std.testing.allocator.alloc(u8, 128 * 1024);
    defer std.testing.allocator.free(payload);
    @memset(payload, 0xBE);

    _ = try log.append(payload);
    log.deinit();

    // Reopen and verify
    var log2 = try wal.WriteAheadLog.init(std.testing.allocator, tmp_dir.dir, "test.wal", .{});
    defer log2.deinit();

    var iter = try log2.iterator(0);
    defer iter.deinit();

    var entry = (try iter.next()).?;
    defer entry.deinit();
    try std.testing.expectEqual(@as(usize, 128 * 1024), entry.payload.len);
    try std.testing.expectEqual(@as(u8, 0xBE), entry.payload[0]);
}
```

- [ ] **Step 2: Run integration tests**

Run: `zig build test-integration --summary all`
Expected: All pass

- [ ] **Step 3: Create `tests/scenarios/crash.zig`**

```zig
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Crash recovery scenario tests.
//!
//! Simulates torn writes by truncating the WAL file at various positions
//! and verifying that recovery correctly identifies valid records.

const std = @import("std");
const wal = @import("wal");

test "crash: torn write mid-header recovers previous records" {
    // Test implementation: write N records, truncate mid-header of N+1,
    // reopen, verify N records survive.
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    {
        var log = try wal.WriteAheadLog.init(std.testing.allocator, tmp_dir.dir, "test.wal", .{});
        _ = try log.append("survived");
        log.deinit();
    }

    // Append garbage bytes (simulating torn next-record header)
    {
        var f = try tmp_dir.dir.openFile("test.wal", .{ .mode = .read_write });
        try f.seekFromEnd(0);
        try f.writeAll(&[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02 }); // 6 bytes < header
        f.close();
    }

    // Reopen — should recover the one good record
    {
        var log = try wal.WriteAheadLog.init(std.testing.allocator, tmp_dir.dir, "test.wal", .{});
        defer log.deinit();

        try std.testing.expectEqual(@as(u64, 1), log.currentLsn());

        // Verify we can still append
        const lsn = try log.append("after crash");
        try std.testing.expectEqual(@as(u64, 2), lsn);
    }
}

test "crash: torn write mid-payload recovers previous records" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    {
        var log = try wal.WriteAheadLog.init(std.testing.allocator, tmp_dir.dir, "test.wal", .{});
        _ = try log.append("good record");
        log.deinit();
    }

    // Write a valid header claiming 1000-byte payload, but only write 10 bytes
    {
        var f = try tmp_dir.dir.openFile("test.wal", .{ .mode = .read_write });
        try f.seekFromEnd(0);
        // Header: LSN=2, payload_len=1000
        var header: [wal.record.HEADER_SIZE]u8 = undefined;
        @memcpy(header[0..8], &std.mem.toBytes(std.mem.nativeToLittle(u64, @as(u64, 2))));
        @memcpy(header[8..12], &std.mem.toBytes(std.mem.nativeToLittle(u32, @as(u32, 1000))));
        try f.writeAll(&header);
        try f.writeAll(&[_]u8{0xAA} ** 10); // Only 10 of 1000 bytes
        f.close();
    }

    {
        var log = try wal.WriteAheadLog.init(std.testing.allocator, tmp_dir.dir, "test.wal", .{});
        defer log.deinit();

        try std.testing.expectEqual(@as(u64, 1), log.currentLsn());
    }
}

test "crash: completely empty file after creation" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var log = try wal.WriteAheadLog.init(std.testing.allocator, tmp_dir.dir, "test.wal", .{});
    defer log.deinit();

    try std.testing.expectEqual(@as(u64, 0), log.currentLsn());

    var iter = try log.iterator(0);
    defer iter.deinit();

    try std.testing.expectEqual(@as(?wal.WriteAheadLog.Iterator.Entry, null), try iter.next());
}

test "crash: corrupt CRC in middle of file, records after corruption lost" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    {
        var log = try wal.WriteAheadLog.init(std.testing.allocator, tmp_dir.dir, "test.wal", .{});
        _ = try log.append("record 1");
        _ = try log.append("record 2");
        _ = try log.append("record 3");
        log.deinit();
    }

    // Corrupt a byte in record 2's payload
    {
        var f = try tmp_dir.dir.openFile("test.wal", .{ .mode = .read_write });
        const rec1_size = wal.record.HEADER_SIZE + 8 + wal.record.CRC_SIZE; // "record 1"
        try f.seekTo(rec1_size + wal.record.HEADER_SIZE + 2); // mid-payload of record 2
        try f.writeAll(&[_]u8{0xFF});
        f.close();
    }

    {
        var log = try wal.WriteAheadLog.init(std.testing.allocator, tmp_dir.dir, "test.wal", .{});
        defer log.deinit();

        // Only record 1 should survive
        try std.testing.expectEqual(@as(u64, 1), log.currentLsn());
    }
}
```

- [ ] **Step 4: Create `tests/scenarios/compaction.zig`**

```zig
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Compaction scenario tests.

const std = @import("std");
const wal = @import("wal");

test "compaction: repeated compact cycles maintain correctness" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var log = try wal.WriteAheadLog.init(std.testing.allocator, tmp_dir.dir, "test.wal", .{});

    // Cycle 1: write 10, compact 5
    for (0..10) |_| _ = try log.append("cycle1");
    try log.compact(5);

    // Cycle 2: write 10 more, compact 15
    for (0..10) |_| _ = try log.append("cycle2");
    try log.compact(15);

    // Should have records 16-20
    var iter = try log.iterator(0);
    defer iter.deinit();

    var count: u64 = 0;
    while (try iter.next()) |*entry| {
        defer @constCast(entry).deinit();
        count += 1;
        try std.testing.expect(entry.lsn > 15);
    }
    try std.testing.expectEqual(@as(u64, 5), count);

    log.deinit();
}

test "compaction: compact everything then append" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var log = try wal.WriteAheadLog.init(std.testing.allocator, tmp_dir.dir, "test.wal", .{});

    _ = try log.append("will be removed");
    try log.compact(1);

    // File should be empty, but append should work
    const lsn = try log.append("fresh start");
    try std.testing.expectEqual(@as(u64, 2), lsn);

    var iter = try log.iterator(0);
    defer iter.deinit();

    var entry = (try iter.next()).?;
    defer entry.deinit();
    try std.testing.expectEqualStrings("fresh start", entry.payload);

    log.deinit();
}

test "compaction: bytesSinceCompact resets after compact" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var log = try wal.WriteAheadLog.init(std.testing.allocator, tmp_dir.dir, "test.wal", .{});
    defer log.deinit();

    _ = try log.append("data");
    try std.testing.expect(log.bytesSinceCompact() > 0);

    try log.compact(0); // Keep all
    try std.testing.expectEqual(@as(u64, 0), log.bytesSinceCompact());
}
```

- [ ] **Step 5: Create `tests/scenarios/encryption.zig`**

```zig
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Encryption scenario tests.

const std = @import("std");
const wal = @import("wal");

test "encryption: full lifecycle with encryption" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const key: [32]u8 = [_]u8{0x42} ** 32;

    {
        var log = try wal.WriteAheadLog.init(std.testing.allocator, tmp_dir.dir, "test.wal", .{
            .encryption_key = key,
        });
        _ = try log.append("secret 1");
        _ = try log.append("secret 2");
        _ = try log.append("secret 3");
        log.deinit();
    }

    {
        var log = try wal.WriteAheadLog.init(std.testing.allocator, tmp_dir.dir, "test.wal", .{
            .encryption_key = key,
        });
        defer log.deinit();

        try std.testing.expectEqual(@as(u64, 3), log.currentLsn());

        var iter = try log.iterator(0);
        defer iter.deinit();

        var count: u64 = 0;
        while (try iter.next()) |*entry| {
            defer @constCast(entry).deinit();
            count += 1;
        }
        try std.testing.expectEqual(@as(u64, 3), count);
    }
}

test "encryption: data not readable as plaintext" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const key: [32]u8 = [_]u8{0xAA} ** 32;
    const secret = "this should not appear in the file";

    {
        var log = try wal.WriteAheadLog.init(std.testing.allocator, tmp_dir.dir, "test.wal", .{
            .encryption_key = key,
        });
        _ = try log.append(secret);
        log.deinit();
    }

    // Read raw file and verify secret is NOT present as plaintext
    const raw = try tmp_dir.dir.readFileAlloc(std.testing.allocator, "test.wal", 1024 * 1024);
    defer std.testing.allocator.free(raw);

    // Search for the plaintext string in the raw bytes
    const found = std.mem.indexOf(u8, raw, secret);
    try std.testing.expectEqual(@as(?usize, null), found);
}

test "encryption: batch append with encryption" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const key: [32]u8 = [_]u8{0xBB} ** 32;
    var log = try wal.WriteAheadLog.init(std.testing.allocator, tmp_dir.dir, "test.wal", .{
        .encryption_key = key,
    });
    defer log.deinit();

    const payloads = [_][]const u8{ "enc-one", "enc-two", "enc-three" };
    const last = try log.appendBatch(&payloads);
    try std.testing.expectEqual(@as(u64, 3), last);
}
```

- [ ] **Step 6: Update `build.zig` to add scenario test steps**

Add scenario test files as dependencies of the `test-integration` step. Each scenario needs the `wal` module imported.

Add this code inside `build()`, after the existing `integration_step` block:

```zig
    // Scenario tests (depend on integration step)
    const scenario_files = [_][]const u8{
        "tests/scenarios/crash.zig",
        "tests/scenarios/compaction.zig",
        "tests/scenarios/encryption.zig",
    };
    for (scenario_files) |scenario_path| {
        const scenario_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path(scenario_path),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "wal", .module = module },
                },
            }),
        });
        const run_scenario = b.addRunArtifact(scenario_tests);
        integration_step.dependOn(&run_scenario.step);
    }
```

This ensures `zig build test-integration` runs all scenario tests alongside `tests/integration.zig`.

- [ ] **Step 7: Run all tests**

Run: `zig build test --summary all && zig build test-integration --summary all`
Expected: All pass

- [ ] **Step 8: Commit**

```bash
git add tests/ build.zig
git commit -m "feat: add integration and scenario tests (crash, compaction, encryption)"
```

---

## Task 11: Final Verification and Cleanup

**Files:**
- All source files for review

- [ ] **Step 1: Run full test suite**

Run: `make ci`
Expected: All pass

- [ ] **Step 2: Run `zig fmt`**

Run: `zig fmt src/ tests/ build.zig`
Expected: No changes (or apply formatting fixes)

- [ ] **Step 3: Verify all files have license headers**

Every `.zig` file must start with:
```zig
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros
```

- [ ] **Step 4: Run tests at all optimization levels**

Run: `make test-all-optimizations`
Expected: All pass

- [ ] **Step 5: Commit any final fixes**

```bash
git add -A
git commit -m "chore: final cleanup, formatting, and verification"
```

---

## API Summary

After all tasks, the public API will be:

```zig
const wal = @import("wal");

// Core types
wal.WriteAheadLog          // Main WAL struct
wal.WriteAheadLog.Iterator // Record iterator
wal.WriteAheadLog.Iterator.Entry // A single record (lsn + payload)
wal.Options                // Init options (encryption_key, manual_sync)

// Record framing (for advanced callers)
wal.record.HEADER_SIZE
wal.record.CRC_SIZE
wal.record.MIN_RECORD_SIZE
wal.record.serialize()
wal.record.deserialize()

// Encryption utilities
wal.encryption.encryptRecord()
wal.encryption.decryptRecord()
wal.encryption.isEncrypted()
wal.encryption.loadKeyFromEnv()

// Atomic file utility
wal.atomicWriteFile()
```
