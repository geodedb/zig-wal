# WAL Library Design Specification

> **Status:** Draft
> **Date:** 2026-03-21
> **Authors:** CodePros
> **License:** Apache-2.0

## 1. Motivation

Two CodePros projects independently implemented Write-Ahead Logs in Zig:

- **Geode** (`geode/src/wal.zig`, ~1000 lines) — a graph database WAL that
  records mutation deltas (CreateNode, SetProperty, etc.) with optional
  AES-256-GCM encryption and checkpoint-based compaction.
- **Raft** (`zig/raft/src/file_storage.zig`, ~650 lines) — a consensus library
  WAL that persists Raft log entries (index, term, kind, data) with in-memory
  index and snapshot-aware compaction.

Both share identical low-level mechanics:

| Mechanic | Geode | Raft |
|---|---|---|
| Record framing | 21-byte header + payload + 4-byte CRC32 | 21-byte header + payload + 4-byte CRC32 |
| Integrity | CRC32 (ISO HDLC variant) | CRC32 (std.hash.Crc32) |
| Crash recovery | Linear scan, CRC verify, stop at first error | Linear scan, CRC verify, truncate at first error |
| Durability | append + fsync | append + fsync |
| Atomic metadata | temp + fsync + rename | temp + fsync + rename |
| Compaction | Rewrite file keeping records above watermark | Rewrite file keeping entries above snapshot |
| Segmentation | None (single file) | None (single file) |

The domain-specific differences (header field semantics, replay targets, record
types) sit cleanly above a generic record-oriented WAL engine. Extracting that
engine eliminates ~300 lines of duplicated, bug-prone code from each project and
provides a single, well-tested, optionally-encrypted WAL for any Zig application.

## 2. Source Analysis

### 2.1 Geode WAL

**Location:** `geode/src/wal.zig`

**Record format (plaintext):**
```
[u64: LSN][u64: txn_id][u8: op_type][u32: payload_len][payload][u32: CRC32]
```

**Record format (encrypted):**
```
[u32: encrypted_blob_len][MAGIC "GEOTDEFL" (8)][nonce (12)][tag (16)][ciphertext]
```

**Key characteristics:**
- LSN-based ordering (monotonically increasing sequence numbers)
- 10 domain-specific operation types (CreateNode, CreateEdge, etc.)
- Tightly coupled to `GraphStore` for replay (calls `createNodeWithId`, etc.)
- TDE encryption via `storage/tde_file_encryption.zig` (AES-256-GCM)
- Checkpoint integration: `needsCheckpoint()` with byte + time thresholds
- Mutex-based thread safety
- Global singleton pattern with mutation callback hooks
- Plaintext compaction uses O(1)-memory bulk-copy optimization
- Encrypted compaction buffers kept records (capped at 4MB)

**Geode-specific concerns (NOT extracted):**
- `WalRecord` union type and serialization/deserialization
- `GraphStore` replay integration
- Mutation callback mechanism
- Global singleton + persistence loop hooks
- `SerializedProperty` type handling

### 2.2 Raft FileStorage WAL

**Location:** `zig/raft/src/file_storage.zig`

**Record format:**
```
[u32: data_len][u64: index][u64: term][u8: kind][data][u32: CRC32]
```

**Key characteristics:**
- Raft log index ordering (monotonically increasing)
- 3 entry kinds (noop, normal, config)
- In-memory `ArrayList(IndexEntry)` for O(1) term lookups by raft_index
- No encryption
- Snapshot-aware compaction: entries below snapshot_index removed
- Separate files for hard_state (16 bytes) and snapshot metadata
- Instance-based (multiple per process for multi-node testing)
- Atomic compaction via temp file + rename

**Raft-specific concerns (NOT extracted):**
- `rpc.Entry` structure (index, term, kind, data)
- `state.HardState` persistence
- `rpc.Snapshot` persistence
- `Storage` vtable interface
- In-memory index mapping raft_index → file_offset

### 2.3 Shared Core (EXTRACTED into this library)

The generic WAL engine handles:

1. **Record framing** — write `[header][payload][CRC32]` atomically
2. **CRC32 integrity** — compute over header+payload, verify on read
3. **Crash recovery** — scan forward, validate each record, truncate at corruption
4. **Compaction** — rewrite file keeping only records above a caller-specified watermark
5. **Durability** — fsync after writes
6. **Optional encryption** — AES-256-GCM per-record encryption (from Geode's TDE)

## 3. Architecture

### 3.1 Design Principles

1. **Payload-agnostic** — the WAL stores opaque byte payloads. Callers
   serialize their domain types (Raft entries, graph mutations) before
   appending. The WAL never interprets payload contents.

2. **Header-minimal** — each record has a small fixed header managed by the
   WAL: sequence number (LSN) and payload length. Domain-specific metadata
   (raft term, txn_id, op_type) is part of the payload.

3. **Zero-copy reads** — `readRecord` returns a view into an allocated buffer.
   Caller owns the allocation.

4. **No global state** — purely instance-based. Callers manage their own
   WAL instances. No singletons, no callbacks, no thread-local state.

5. **Optional encryption** — encryption is a composable layer, not baked into
   the core. Callers can provide an encryption key at init time; if absent,
   records are plaintext.

6. **Single-file simplicity** — no segment rotation. Compaction rewrites the
   file atomically. This matches both source implementations and is sufficient
   for the target workloads.

### 3.2 Record Format

#### Plaintext Record

```
Offset  Size  Field        Description
─────────────────────────────────────────────────────
0       8     lsn          Log Sequence Number (u64 LE, assigned by WAL)
8       4     payload_len  Length of payload in bytes (u32 LE)
12      N     payload      Opaque caller data (N = payload_len)
12+N    4     crc32        CRC32 of bytes [0..12+N) (u32 LE)
─────────────────────────────────────────────────────
Total: 16 + payload_len bytes per record
```

**Header size:** 12 bytes (8 LSN + 4 payload_len)
**CRC size:** 4 bytes
**Minimum record size:** 16 bytes (empty payload)

The LSN is assigned by the WAL, monotonically increasing from 1. Callers use
LSNs as watermarks for compaction, checkpointing, and replay-from.

> **Design note:** The Geode WAL uses a 21-byte header (LSN + txn_id + op_type
> + payload_len). The Raft WAL also uses 21 bytes (data_len + index + term +
> kind). By moving domain fields into the payload, we reduce the fixed header
> to 12 bytes while keeping the WAL generic. Callers prepend their own header
> inside the payload.

#### Encrypted Record

When encryption is enabled, each record is wrapped:

```
Offset  Size  Field            Description
─────────────────────────────────────────────────────
0       4     blob_len         Total encrypted blob size (u32 LE)
4       8     magic            "ZIGWALE\0" (encryption marker)
12      12    nonce            AES-256-GCM nonce (random per record)
24      16    tag              AES-256-GCM authentication tag
40      M     ciphertext       Encrypted plaintext record (M bytes)
─────────────────────────────────────────────────────
Total: 40 + M bytes (where M = 16 + payload_len)
```

The encrypted blob contains the full plaintext record (header + payload + CRC).
The CRC inside the ciphertext provides a second integrity check after
decryption, catching key mismatches that AES-GCM's tag might not surface
clearly in error messages.

### 3.3 Module Structure

```
src/
├── root.zig            # Public API re-exports
├── wal.zig             # Core WAL engine (WriteAheadLog struct)
├── record.zig          # Record framing: serialize, deserialize, CRC
├── recovery.zig        # Crash recovery: scan, validate, truncate
├── compaction.zig      # Compaction: rewrite file above watermark
├── encryption.zig      # Optional AES-256-GCM encryption layer
└── atomic.zig          # Atomic file operations (temp+fsync+rename)

tests/
├── integration.zig     # End-to-end WAL tests
└── scenarios/
    ├── crash.zig        # Torn write and corruption recovery tests
    ├── compaction.zig   # Compaction correctness tests
    └── encryption.zig   # Encryption round-trip and key handling tests
```

### 3.4 Public API

```zig
const wal = @import("wal");

// ── Types ──────────────────────────────────────────────────────────

pub const WriteAheadLog = struct {
    // ... internal state ...

    /// Open or create a WAL file at `dir`/`filename`, recover state from any
    /// existing records, truncate trailing corruption, and position for append.
    /// If `encryption_key` is provided, records are AES-256-GCM encrypted.
    pub fn init(
        allocator: std.mem.Allocator,
        dir: std.fs.Dir,
        filename: []const u8,
        options: Options,
    ) !WriteAheadLog;

    pub fn deinit(self: *WriteAheadLog) void;

    /// Append an opaque payload to the WAL. Returns the assigned LSN.
    /// The payload is framed with a header and CRC, then fsynced.
    pub fn append(self: *WriteAheadLog, payload: []const u8) !u64;

    /// Append multiple payloads atomically (single fsync).
    /// Returns the LSN of the last record written.
    pub fn appendBatch(self: *WriteAheadLog, payloads: []const []const u8) !u64;

    /// Fsync the WAL file to disk. Called automatically by append/appendBatch,
    /// but exposed for callers who want explicit control (e.g., batch writes
    /// followed by a single sync).
    pub fn sync(self: *WriteAheadLog) !void;

    /// Iterate over all valid records in the WAL, starting after `from_lsn`.
    /// Returns an iterator that yields Entry values. Caller must call
    /// `entry.deinit()` on each yielded entry to free its payload allocation.
    /// The iterator opens an independent read-only file handle.
    pub fn iterator(self: *const WriteAheadLog, from_lsn: u64) !Iterator;

    /// Remove all records with LSN <= `up_to_lsn` by rewriting the WAL file.
    /// The rewrite is atomic (temp file + fsync + rename).
    pub fn compact(self: *WriteAheadLog, up_to_lsn: u64) !void;

    /// Return the current (highest assigned) LSN, or 0 if no records exist.
    pub fn currentLsn(self: *const WriteAheadLog) u64;

    /// Return the number of bytes written since the last compaction.
    pub fn bytesSinceCompact(self: *const WriteAheadLog) u64;

    pub const Iterator = struct {
        // ... internal state ...

        pub const Entry = struct {
            lsn: u64,
            payload: []const u8,
            allocator: std.mem.Allocator,

            pub fn deinit(self: *Entry) void;
        };

        /// Return the next valid entry, or null at end-of-log.
        /// Returns error on I/O failure. Stops (returns null) at first
        /// CRC mismatch or incomplete record (torn write boundary).
        pub fn next(self: *Iterator) !?Entry;

        /// Close the read-only file handle.
        pub fn deinit(self: *Iterator) void;
    };
};

pub const Options = struct {
    /// AES-256-GCM encryption key. If null, records are plaintext.
    encryption_key: ?[32]u8 = null,
    /// If true, do not fsync after each append (caller manages durability).
    /// Useful for batch writes where a single sync at the end is sufficient.
    manual_sync: bool = false,
};

// ── Utilities ──────────────────────────────────────────────────────

/// Atomically write data to a file using temp+fsync+rename pattern.
/// Useful for callers persisting metadata alongside the WAL
/// (e.g., Raft hard_state, Geode checkpoint state).
pub fn atomicWriteFile(
    dir: std.fs.Dir,
    filename: []const u8,
    data: []const u8,
) !void;
```

### 3.5 How Consumers Use It

#### Raft (FileStorage)

```zig
const wal_lib = @import("wal");

const FileStorage = struct {
    wal: wal_lib.WriteAheadLog,
    index: std.ArrayList(IndexEntry),  // in-memory raft_index → LSN mapping
    // ...

    pub fn appendEntriesImpl(self: *FileStorage, entries: []const rpc.Entry) !void {
        for (entries) |entry| {
            // Serialize Raft entry into payload (caller's format)
            var buf: [4096]u8 = undefined;
            const payload = serializeEntry(entry, &buf);

            const lsn = try self.wal.append(payload);

            // Update in-memory index
            try self.index.append(self.allocator, .{
                .lsn = lsn,
                .raft_index = entry.index,
                .term = entry.term,
            });
        }
    }

    pub fn recoverEntries(self: *FileStorage) !void {
        var iter = self.wal.iterator(0);
        while (try iter.next()) |*record| {
            defer record.deinit();
            const entry = deserializeEntry(record.payload);
            try self.index.append(self.allocator, .{
                .lsn = record.lsn,
                .raft_index = entry.index,
                .term = entry.term,
            });
        }
    }
};
```

#### Geode (WriteAheadLog wrapper)

```zig
const wal_lib = @import("wal");

const GeodeWal = struct {
    wal: wal_lib.WriteAheadLog,
    checkpoint_lsn: u64,
    bytes_since_checkpoint: u64,
    // ...

    pub fn appendRecord(self: *GeodeWal, txn_id: u64, record: WalRecord) !u64 {
        // Serialize Geode record into payload (caller's format:
        // [txn_id][op_type][domain-specific fields])
        const payload = serializeWalRecord(self.allocator, txn_id, record);
        defer self.allocator.free(payload);

        const lsn = try self.wal.append(payload);
        self.bytes_since_checkpoint += payload.len + FRAMING_OVERHEAD;
        return lsn;
    }

    pub fn replay(self: *GeodeWal, store: *GraphStore) !u64 {
        var iter = self.wal.iterator(self.checkpoint_lsn);
        var last_lsn: u64 = self.checkpoint_lsn;
        while (try iter.next()) |*record| {
            defer record.deinit();
            if (record.lsn <= self.checkpoint_lsn) continue;
            applyToStore(store, record.payload);
            last_lsn = record.lsn;
        }
        return last_lsn;
    }
};
```

## 4. Crash Safety

### 4.1 Write Path

1. Serialize record: `[lsn][payload_len][payload][CRC32]`
2. If encrypted: encrypt the serialized record, prepend `[blob_len][magic][nonce][tag]`
3. Write entire record in a single `writeAll()` syscall (minimizes torn write window)
4. If `manual_sync` is false, call `file.sync()` (fsync)
5. Update `current_lsn` and `file_end` position

For payloads ≤ 64KB, the write buffer is stack-allocated (matching Geode's
optimization from Issue #559). Larger payloads use heap allocation.

### 4.2 Recovery Path

On `init()`:

1. Open WAL file (create if not exists, return early if empty)
2. Scan forward from byte 0:
   - Read header (12 bytes for plaintext, or 4-byte blob_len for encrypted)
   - Check completeness: `offset + record_size <= file_size`
   - Read full record
   - Verify CRC32 (after decryption if encrypted)
   - On success: record `current_lsn`, advance offset
   - On failure (incomplete, CRC mismatch): stop scan
3. Truncate file at last valid record boundary (`setEndPos`)
4. Set `file_end` to the truncation point for future appends

### 4.3 Compaction Path

1. Open WAL file for reading
2. Scan records, collecting those with LSN > `up_to_lsn`
3. Write kept records to temp file (`{filename}.tmp`)
4. Fsync temp file
5. Atomic rename `{filename}.tmp` → `{filename}`
6. Reopen for append
7. Update internal state (`file_end`, byte counters)

For plaintext mode, use Geode's bulk-copy optimization: once the first kept
record is found, all subsequent records are kept (LSNs are monotonic), so a
simple block-copy from that offset forward avoids buffering.

### 4.4 Atomic File Utility

The `atomicWriteFile` helper provides the temp+fsync+rename pattern for
metadata files. Both Raft (hard_state, snapshot.meta) and Geode (checkpoint
state) need this.

## 5. Encryption

### 5.1 Design

Encryption is optional and configured at init time via `Options.encryption_key`.
When enabled:

- Each record is independently encrypted with a fresh random nonce
- The plaintext record (header + payload + CRC) becomes the AES-256-GCM input
- The output is framed with a 4-byte length prefix and magic bytes for detection
- On read, the magic bytes determine whether to decrypt or treat as plaintext
- This allows mixed plaintext/encrypted WALs during migration

### 5.2 Key Management

The WAL library does NOT manage keys. It accepts a `[32]u8` key at init time.
Key loading from environment variables, key rotation, and key storage are the
caller's responsibility.

A convenience function is provided for the common pattern:

```zig
/// Load a 256-bit key from a hex-encoded environment variable.
/// Returns null if the variable is not set.
/// Returns error.InvalidKey if the value is not exactly 64 hex characters.
pub fn loadKeyFromEnv(env_var: []const u8) EncryptionError!?[32]u8;
```

### 5.3 CRC Variant

The library uses `std.hash.crc.Crc32IsoHdlc` (CRC-32/ISO-HDLC), matching
Geode's implementation. This is the most widely used CRC-32 variant (used by
Ethernet, gzip, PNG, etc.) and provides strong error detection for the record
sizes involved.

> **Migration note:** The Raft FileStorage currently uses `std.hash.Crc32`
> (which is the same algorithm in Zig's standard library — `Crc32` is an alias
> for `Crc32IsoHdlc`). No format change is needed.

## 6. Thread Safety

The WAL struct is NOT thread-safe by default. Callers that need concurrent
access must provide their own synchronization (mutex, per-thread instances,
etc.).

**Rationale:** Geode uses a mutex internally; Raft does not need one (single-
threaded per node). Forcing a mutex on all callers adds overhead for the common
single-threaded case. The caller knows their concurrency model better.

## 7. Implementation Plan

### Phase 1: Core Record Engine

**Files:** `src/record.zig`, `src/root.zig`

- Record serialization: `serialize(lsn, payload) -> []u8`
- Record deserialization: `deserialize(buf) -> Record`
- CRC32 computation and verification
- Constants: `HEADER_SIZE`, `CRC_SIZE`, `MIN_RECORD_SIZE`
- Unit tests: round-trip, CRC verification, malformed input

### Phase 2: WAL Writer + Reader

**Files:** `src/wal.zig`

- `WriteAheadLog.init()` — open/create file, recover state
- `WriteAheadLog.deinit()` — close file
- `WriteAheadLog.append()` — serialize + write + fsync
- `WriteAheadLog.appendBatch()` — multi-record + single fsync
- `WriteAheadLog.sync()` — explicit fsync
- `WriteAheadLog.currentLsn()` — return highest LSN
- Unit tests: append, read back, LSN monotonicity, empty WAL

### Phase 3: Recovery

**Files:** `src/recovery.zig`

- `recover(file) -> {last_lsn, file_end}` — scan + validate + truncate
- `Iterator` — yields records from file position
- Torn write handling: incomplete header, incomplete payload, bad CRC
- Unit tests: clean recovery, torn header, torn payload, corrupt CRC,
  empty file, single record, many records

### Phase 4: Compaction

**Files:** `src/compaction.zig`

- `compact(file, up_to_lsn)` — rewrite keeping LSN > watermark
- Bulk-copy optimization for plaintext (no buffering)
- Atomic rename for crash safety
- Unit tests: compact none, compact some, compact all, compact + append

### Phase 5: Atomic File Utility

**Files:** `src/atomic.zig`

- `atomicWriteFile(dir, filename, data)` — temp + fsync + rename
- Unit tests: write, overwrite, crash between write and rename

### Phase 6: Encryption Layer

**Files:** `src/encryption.zig`

- `encryptRecord(key, plaintext_record) -> encrypted_blob`
- `decryptRecord(key, blob) -> plaintext_record`
- `isEncrypted(blob) -> bool` — check magic bytes
- `loadKeyFromEnv(env_var) -> ?[32]u8`
- Integration with WAL writer/reader (transparent encrypt/decrypt)
- Unit tests: round-trip, wrong key detection, mixed mode,
  key loading from env

### Phase 7: Integration Tests

**Files:** `tests/integration.zig`, `tests/scenarios/*.zig`

- Full WAL lifecycle: init → append → close → reopen → iterate → verify
- Crash scenarios: torn writes at various positions
- Compaction under load: append + compact + verify
- Encryption end-to-end: encrypted WAL lifecycle
- Performance baseline: append throughput, recovery time

### Phase 8: Consumer Migration

After the library is complete and tested:

1. **Raft** — replace `file_storage.zig` WAL internals with `@import("wal")`,
   keeping the Raft-specific `FileStorage` wrapper, in-memory index, hard_state
   persistence, and `Storage` vtable.

2. **Geode** — replace `wal.zig` WAL internals with `@import("wal")`, keeping
   the Geode-specific `WalRecord` serialization, `GraphStore` replay, mutation
   callbacks, and global singleton.

## 8. Testing Strategy

### Unit Tests (per module)

| Module | Tests |
|---|---|
| `record.zig` | Serialize/deserialize round-trip, CRC verification, empty payload, max-size payload, malformed buffers |
| `wal.zig` | Append single/batch, LSN assignment, currentLsn, bytesSinceCompact, manual_sync mode |
| `recovery.zig` | Clean scan, torn header, torn payload, corrupt CRC, empty file, truncation correctness |
| `compaction.zig` | Compact none/some/all, bulk-copy correctness, atomic rename, append after compact |
| `encryption.zig` | Encrypt/decrypt round-trip, wrong key, magic detection, mixed mode, key loading |
| `atomic.zig` | Write/overwrite, directory handling |

### Integration Tests

| Scenario | Description |
|---|---|
| Full lifecycle | init → append 1000 records → close → reopen → iterate → verify all |
| Crash recovery | Write N records, truncate file at various points, recover, verify |
| Compaction cycle | Append → compact → append → compact → verify ordering |
| Encrypted lifecycle | Same as full lifecycle but with encryption key |
| Mixed encryption | Start plaintext, switch to encrypted, verify both readable |
| Concurrent instances | Multiple WAL instances in same process (different files) |
| Large payloads | Records with payloads > 64KB (heap allocation path) |

### Property-Based Invariants

Every test verifies:
1. **LSN monotonicity** — LSNs always increase
2. **CRC integrity** — every record passes CRC verification after write
3. **Recovery completeness** — all records written before last fsync are recoverable
4. **Compaction correctness** — no record with LSN > watermark is lost
5. **Encryption transparency** — encrypted WAL produces identical logical records as plaintext

## 9. Dependencies

- **Zero external dependencies** — pure Zig standard library
- AES-256-GCM via `std.crypto.aead.aes_gcm.Aes256Gcm`
- CRC32 via `std.hash.crc.Crc32IsoHdlc`
- File I/O via `std.fs`
- Requires Zig 0.15.1+

## 10. Non-Goals

These are explicitly out of scope for this library:

- **Segment rotation** — single-file WAL is sufficient for both consumers
- **Built-in thread safety** — callers manage their own concurrency
- **Domain-specific replay** — the WAL yields opaque payloads; callers interpret
- **Key management** — callers load/rotate/store encryption keys
- **Compression** — could be added later as a composable layer
- **Async I/O** — synchronous file I/O matches both consumers' models
- **WAL-level transactions** — no multi-record atomicity guarantees beyond
  single-record writes. Callers implement their own transaction semantics
  in the payload.
