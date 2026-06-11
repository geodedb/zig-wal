// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! Core WAL engine: orchestrates record writing, reading, and crash recovery.
//!
//! The `WriteAheadLog` struct is the primary public interface. It is:
//! - Payload-agnostic: stores opaque `[]const u8` blobs.
//! - LSN-based: every record gets a monotonically increasing Log Sequence Number.
//! - Single-file: no segment rotation; compaction rewrites the file atomically.
//! - Thread-safe: all public methods are protected by an internal mutex.

const std = @import("std");
const tp = @import("thread_pool");
const record = @import("record.zig");
const recovery_mod = @import("recovery.zig");
const compaction = @import("compaction.zig");
const encryption = @import("encryption.zig");
const checkpoint_mod = @import("checkpoint.zig");
const observability = @import("observability");

/// Scoped logger for the WAL engine. Used to surface startup data loss
/// (recovery truncation) that would otherwise be silent (QA-0079).
const wal_log = std.log.scoped(.wal);

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

    /// Optional thread pool for parallel batch serialization (PAR-0002).
    /// When non-null, `appendBatch` and `appendBatchWithLsns` parallelize
    /// record serialization (CRC32 + optional encryption) across available
    /// cores using flat-chunk submitBatch + WaitGroup.
    ///
    /// The thread pool is **not owned** by the WAL — the caller must manage
    /// its lifecycle (init/deinit). When `null` (the default), all
    /// serialization runs sequentially on the calling thread.
    ///
    /// For best throughput on long-running writer loops, wrap the loop in
    /// `registerWriterThread` / `releaseWriterThread` — this opts the
    /// writer thread into the pool's per-submitter fast path and bypasses
    /// global-freelist CAS on descriptor allocation. Note: the pool must
    /// be constructed with `max_submitter_queues >= 1` (the library's
    /// default of 0 disables registerSubmitter entirely).
    thread_pool: ?*tp.ThreadPool = null,
};

// ============================================================================
// Parallel batch serialization (PAR-0002)
// ============================================================================

/// Shared context for parallel batch serialization. Immutable after setup.
const ParallelSerializeCtx = struct {
    buf: [*]u8,
    offsets: [*]const usize,
    lsns: [*]const u64,
    payloads: [*]const [*]const u8,
    payload_lens: [*]const usize,
    encrypted: bool,
    enc_key: ?*const [32]u8,
    /// Per-record plaintext scratch buffer (encrypted mode only).
    pt_buf: ?[*]u8,
    pt_offsets: ?[*]const usize,
};

/// A range [start, end) of records to serialize, plus a pointer to shared ctx.
const SerializeRange = struct {
    ctx: *const ParallelSerializeCtx,
    start: u32,
    end: u32,
};

/// Serialize a single record at index `i` into the output buffer.
fn serializeOneRecord(ctx: *const ParallelSerializeCtx, i: usize) void {
    const payload_ptr = ctx.payloads[i];
    const payload_len = ctx.payload_lens[i];
    const payload = payload_ptr[0..payload_len];
    const lsn = ctx.lsns[i];
    const rec_size = record.HEADER_SIZE + payload_len + record.CRC_SIZE;
    const out_offset = ctx.offsets[i];

    if (ctx.encrypted) {
        const enc_size = encryption.ENCRYPTION_OVERHEAD + rec_size;
        const pt_offset = ctx.pt_offsets.?[i];
        const pt_region = ctx.pt_buf.?[pt_offset..][0..rec_size];
        record.serializeInto(pt_region, lsn, payload);
        encryption.encryptInto(ctx.buf[out_offset..][0..enc_size], ctx.enc_key.?, pt_region);
    } else {
        record.serializeInto(ctx.buf[out_offset..][0..rec_size], lsn, payload);
    }
}

/// Maximum number of chunks for parallel serialization (matches thread-pool worker bitmap width).
const MAX_SERIALIZE_CHUNKS = 64;

/// Chunk context for a parallel serialization task.
const SerializeChunk = struct {
    ctx: *const ParallelSerializeCtx,
    start: u32,
    end: u32,

    fn run(ctx_ptr: *anyopaque, _: *tp.TaskContext) void {
        const self: *SerializeChunk = @ptrCast(@alignCast(ctx_ptr));
        var i = self.start;
        while (i < self.end) : (i += 1) {
            serializeOneRecord(self.ctx, i);
        }
    }
};

// ============================================================================
// WriteAheadLog
// ============================================================================

/// A Write-Ahead Log that appends framed, CRC-verified records to a single
/// file and recovers cleanly after a crash.
///
/// Thread safety: all public methods that mutate WAL state acquire an
/// exclusive write lock.  Read-only getters (`currentLsn`,
/// `bytesSinceCompact`) and `iterator` acquire a shared read lock, so
/// multiple concurrent readers proceed without blocking each other
/// (PAR-0005).  The `iterator` method opens an independent file handle
/// and does not hold any lock during iteration.
pub const WriteAheadLog = struct {
    allocator: std.mem.Allocator,
    dir: std.Io.Dir,
    /// Owned copy of the filename — freed in `deinit` (QA-0067).
    filename: []const u8,
    file: std.Io.File,
    current_lsn: u64,
    file_end: u64,
    bytes_since_compact: u64,
    /// Byte offset at which the last record begins (so `[last_record_start,
    /// file_end)` is that record's on-disk bytes). Persisted in the checkpoint
    /// so the O(1) startup path can re-validate the boundary (SEC-0044/0046).
    /// 0 when the WAL is empty.
    last_record_start: u64,
    options: Options,
    appends_since_sync: u32,
    /// When `true` the WAL file handle is invalid and all operations
    /// will return `error.WalPoisoned`. Set when the file handle cannot
    /// be reopened after compaction (SEC-0008).
    poisoned: bool = false,
    /// Internal read-write lock protecting all mutable state (PAR-0005).
    /// Writers (append, appendBatch, sync, compact) acquire exclusive access.
    /// Readers (currentLsn, bytesSinceCompact, iterator) acquire shared access.
    mu: std.Io.RwLock = .init,

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
        dir: std.Io.Dir,
        filename: []const u8,
        options: Options,
    ) !WriteAheadLog {
        // Own the filename so the WAL is safe even if the caller's slice
        // is freed or goes out of scope (QA-0067).
        const owned_filename = try allocator.dupe(u8, filename);
        errdefer allocator.free(owned_filename);

        // Open existing file, or create a new one with read+write access.
        // New files get 0o600 permissions (owner-only) for defense-in-depth (SEC-0015).
        const io = std.Io.Threaded.global_single_threaded.io();
        const file = dir.openFile(io, filename, .{ .mode = .read_write }) catch |err| switch (err) {
            error.FileNotFound => try dir.createFile(io, filename, .{ .read = true, .permissions = std.Io.File.Permissions.fromMode(0o600) }),
            else => return err,
        };
        errdefer file.close(std.Io.Threaded.global_single_threaded.io());

        // Tighten permissions on existing files to owner-only (SEC-0021).
        // Files created before the SEC-0015 fix may have world-readable
        // permissions. This is best-effort — fails silently on non-POSIX
        // platforms or when the caller is not the file owner.
        file.setPermissions(io, std.Io.File.Permissions.fromMode(0o600)) catch {};

        // Recover WAL state: try checkpoint-accelerated path first if enabled,
        // then fall back to full scan (PERF-0013). The outer recovery scan is
        // mapped to the otel "wal.replay" span — we deliberately do NOT span
        // individual record reads inside the scan (too noisy).
        const replay_span = observability.startWalSpan("replay");
        var replay_ok = false;
        defer observability.endWalSpan(replay_span, replay_ok, 0);
        const info = blk: {
            if (options.checkpoint) {
                if (checkpoint_mod.readCheckpoint(dir, filename)) |ckpt| {
                    // Re-validate the checkpoint's boundary against the actual
                    // file before trusting the unscanned prefix. A stale,
                    // cross-WAL, or forged checkpoint whose valid_end does not
                    // land on a real intact record (matching last_lsn, CRC/AEAD)
                    // is rejected here, forcing a full scan rather than letting
                    // recovery start mid-prefix and truncate valid data
                    // (SEC-0044/SEC-0045/SEC-0046).
                    const boundary_ok = recovery_mod.validateCheckpointBoundary(
                        allocator,
                        file,
                        if (options.encryption_key) |*key| key else null,
                        ckpt.last_lsn,
                        ckpt.valid_end,
                        ckpt.last_record_start,
                    );
                    if (!boundary_ok) {
                        break :blk if (options.encryption_key) |*key|
                            try recovery_mod.recoverWithKey(allocator, file, key)
                        else
                            try recovery_mod.recover(allocator, file);
                    }
                    const start = recovery_mod.RecoveryInfo{
                        .last_lsn = ckpt.last_lsn,
                        .valid_end = ckpt.valid_end,
                        .record_count = ckpt.record_count,
                        .last_record_start = ckpt.last_record_start,
                    };
                    const inc = if (options.encryption_key) |*key|
                        recovery_mod.recoverFromWithKey(allocator, file, start, key)
                    else
                        recovery_mod.recoverFrom(allocator, file, start);
                    if (inc) |result| {
                        // The earlier validateCheckpointBoundary call already
                        // proved ckpt.valid_end lands on a real, intact record
                        // boundary in this file, so a forged/mid-record checkpoint
                        // never reaches here (it forces a full scan above). The
                        // old SEC-NEW-3 "zero new records but file grew → full
                        // scan" guard — and its second file.stat() — is therefore
                        // redundant and was removed (PERF-0025). Any bytes past
                        // result.valid_end are torn/corrupt and init() correctly
                        // truncates them. Covered by the "forged boundary is
                        // rejected" test.
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
        // Annotate the replay span with the LSN range covered by this
        // recovery scan and mark it successful. `setIntAttribute` is
        // best-effort — telemetry never propagates to the caller.
        if (observability.enabled) {
            replay_span.setIntAttribute("wal.replay.start_lsn", 0) catch {};
            replay_span.setIntAttribute("wal.replay.end_lsn", @intCast(info.last_lsn)) catch {};
        }
        replay_ok = true;

        // Surface startup data loss: if recovery stopped before the physical
        // end of file, trailing records were discarded (torn write, CRC/AEAD
        // failure, or non-monotonic LSN). Silent truncation makes this
        // undiagnosable, so log the byte delta at warn level (QA-0079).
        const recovery_io = std.Io.Threaded.global_single_threaded.io();
        if (file.stat(recovery_io)) |st| {
            if (st.size > info.valid_end) {
                wal_log.warn(
                    "recovery of '{s}' discarded {d} trailing byte(s) beyond the last valid record " ++
                        "(kept {d} record(s) up to LSN {d}; valid_end={d}, file size was {d}); " ++
                        "likely a torn write, CRC/AEAD failure, or non-monotonic LSN",
                    .{ filename, st.size - info.valid_end, info.record_count, info.last_lsn, info.valid_end, st.size },
                );
            }
        } else |_| {}

        // Truncate any bytes beyond the last valid record (torn writes, etc.).
        try file.setLength(recovery_io, info.valid_end);

        // Position cursor at the write tail for streaming writes.
        _ = std.c.lseek(file.handle, @intCast(info.valid_end), 0);

        return WriteAheadLog{
            .allocator = allocator,
            .dir = dir,
            .filename = owned_filename,
            .file = file,
            .current_lsn = info.last_lsn,
            .file_end = info.valid_end,
            .bytes_since_compact = info.valid_end,
            .last_record_start = info.last_record_start,
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
                // record_count is intentionally not tracked by the WAL and MUST
                // NOT be trusted for integrity (QA-0069). Checkpoint soundness is
                // established by re-validating the last-record boundary on load
                // (last_record_start + last_lsn + CRC/AEAD, SEC-0044/0046), and the
                // monotonicity baseline is seeded defensively in recoverFrom* when
                // record_count is 0 but last_lsn > 0 (SEC NEW-1). The field is kept
                // only for on-disk format stability.
                .record_count = 0,
                .last_record_start = self.last_record_start,
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
            self.file.close(std.Io.Threaded.global_single_threaded.io());
        }
    }

    // -------------------------------------------------------------------------
    // Thread-pool submitter registration
    // -------------------------------------------------------------------------

    /// Opt the calling thread into the thread-pool's per-submitter fast
    /// path. WAL's writer loop is a single long-lived submitter thread
    /// per instance; registering that thread lets `appendBatch`'s
    /// `submitBatch` bypass global-freelist CAS on descriptor allocation.
    ///
    /// Call ONCE on the thread that will drive `appendBatch` before
    /// entering the writer loop; pair with exactly one
    /// `releaseWriterThread` on the same thread before the loop exits.
    /// Each call claims a fresh slot, so do not call per-append — wrap
    /// the whole writer-loop lifetime.
    ///
    /// Returns `error.NoSubmitterSlots` if the pool's submitter bitmap is
    /// full OR if the pool was configured with `max_submitter_queues = 0`
    /// (the default — callers must set it explicitly in
    /// `tp.ThreadPool.init`'s `Config`). Returns `error.NoThreadPool`
    /// when no pool was wired at init.
    pub fn registerWriterThread(self: *WriteAheadLog) !usize {
        const pool = self.options.thread_pool orelse return error.NoThreadPool;
        return pool.registerSubmitter();
    }

    /// Release a slot previously acquired via `registerWriterThread`.
    /// Must be called on the same thread that registered the slot for
    /// the per-slot descriptor cache to drain correctly. Out-of-range
    /// `idx` is silently ignored. Safe to call when `options.thread_pool`
    /// is null (no-op).
    pub fn releaseWriterThread(self: *WriteAheadLog, idx: usize) void {
        const pool = self.options.thread_pool orelse return;
        pool.releaseSubmitter(idx);
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
    /// Thread-safe: acquires internal mutex.
    pub fn append(self: *WriteAheadLog, payload: []const u8) !u64 {
        const span = observability.startWalSpan("append");
        var ok = false;
        var bytes_written: u64 = 0;
        defer observability.endWalSpan(span, ok, bytes_written);
        self.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mu.unlock(std.Io.Threaded.global_single_threaded.io());
        const before = self.file_end;
        const lsn = try self.appendWithLsnLocked(self.current_lsn + 1, payload);
        bytes_written = self.file_end - before;
        ok = true;
        return lsn;
    }

    /// Append a single record with a caller-provided LSN.
    ///
    /// The provided LSN must be strictly greater than the current LSN
    /// (monotonicity invariant). Returns `error.InvalidLsn` if violated.
    ///
    /// This is useful for consumers that maintain their own sequence
    /// numbering (e.g., Raft log indices) and need the WAL LSN to match.
    /// Thread-safe: acquires internal mutex.
    pub fn appendWithLsn(self: *WriteAheadLog, lsn: u64, payload: []const u8) !u64 {
        const span = observability.startWalSpan("append");
        var ok = false;
        var bytes_written: u64 = 0;
        defer observability.endWalSpan(span, ok, bytes_written);
        self.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mu.unlock(std.Io.Threaded.global_single_threaded.io());
        const before = self.file_end;
        const result = try self.appendWithLsnLocked(lsn, payload);
        bytes_written = self.file_end - before;
        ok = true;
        return result;
    }

    /// Internal unlocked implementation of appendWithLsn.
    /// Caller must hold `self.mu`.
    /// Reject a payload whose on-disk record would exceed `MAX_RECORD_SIZE` —
    /// the same limit the recovery and iterator read paths enforce. Without this
    /// the write path is asymmetric with the read path: a caller could append a
    /// record that recovery silently rejects and truncates on the next open, and
    /// the batch allocator would size an unbounded contiguous buffer (PERF-0033).
    /// The bound accounts for AES-256-GCM framing overhead when encryption is on.
    fn checkWritable(self: *const WriteAheadLog, payload_len: usize) !void {
        const overhead = record.HEADER_SIZE + record.CRC_SIZE +
            (if (self.options.encryption_key != null) encryption.ENCRYPTION_OVERHEAD else 0);
        // Subtraction-form bound avoids any overflow in HEADER+payload+CRC(+40).
        if (payload_len > record.MAX_RECORD_SIZE - overhead) return error.RecordTooLarge;
    }

    fn appendWithLsnLocked(self: *WriteAheadLog, lsn: u64, payload: []const u8) !u64 {
        if (self.poisoned) return error.WalPoisoned;
        if (lsn <= self.current_lsn) return error.InvalidLsn;
        try self.checkWritable(payload.len);

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
                self.file.setLength(std.Io.Threaded.global_single_threaded.io(), pre_write_pos) catch {};
                return err;
            };
            self.file_end += bytes_written;
            self.bytes_since_compact += bytes_written;
        } else {
            // Plaintext path.
            const bytes_written = record.writeToFile(self.allocator, self.file, lsn, payload) catch |err| {
                self.file.setLength(std.Io.Threaded.global_single_threaded.io(), pre_write_pos) catch {};
                return err;
            };
            self.file_end += bytes_written;
            self.bytes_since_compact += bytes_written;
        }

        // LSN and last-record boundary only advance after a successful write
        // (SEC-0030). pre_write_pos is the start of the record just written.
        self.current_lsn = lsn;
        self.last_record_start = pre_write_pos;

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
    /// Thread-safe: acquires internal mutex.
    pub fn appendBatch(self: *WriteAheadLog, payloads: []const []const u8) !u64 {
        const span = observability.startWalSpan("append_batch");
        var ok = false;
        var bytes_written: u64 = 0;
        defer observability.endWalSpan(span, ok, bytes_written);
        self.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mu.unlock(std.Io.Threaded.global_single_threaded.io());
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

        const before = self.file_end;
        const result = try self.appendBatchWithLsnsLocked(lsns, payloads);
        bytes_written = self.file_end - before;
        ok = true;
        return result;
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
    /// Thread-safe: acquires internal mutex.
    pub fn appendBatchWithLsns(self: *WriteAheadLog, lsns: []const u64, payloads: []const []const u8) !u64 {
        const span = observability.startWalSpan("append_batch");
        var ok = false;
        var bytes_written: u64 = 0;
        defer observability.endWalSpan(span, ok, bytes_written);
        self.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mu.unlock(std.Io.Threaded.global_single_threaded.io());
        const before = self.file_end;
        const result = try self.appendBatchWithLsnsLocked(lsns, payloads);
        bytes_written = self.file_end - before;
        ok = true;
        return result;
    }

    /// Internal unlocked implementation of appendBatchWithLsns.
    /// Caller must hold `self.mu`.
    fn appendBatchWithLsnsLocked(self: *WriteAheadLog, lsns: []const u64, payloads: []const []const u8) !u64 {
        if (self.poisoned) return error.WalPoisoned;
        if (payloads.len == 0) return error.EmptyBatch; // SEC-0023
        if (lsns.len != payloads.len) return error.InvalidLsn;

        // Validate monotonicity of provided LSNs.
        var prev_lsn = self.current_lsn;
        for (lsns) |lsn| {
            if (lsn <= prev_lsn) return error.InvalidLsn;
            prev_lsn = lsn;
        }

        // Reject any oversize record before allocating the batch buffer, keeping
        // the write path symmetric with recovery and bounding the allocation
        // (PERF-0033). Validate all payloads up front so a bad record fails the
        // whole batch atomically rather than mid-serialization.
        for (payloads) |payload| try self.checkWritable(payload.len);

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

        // Serialize all records into the output buffer.
        // When a thread pool is available and the batch has enough
        // records, serialization runs in parallel (PAR-0002).
        const use_parallel = self.options.thread_pool != null and payloads.len > 1;

        if (use_parallel) {
            // Pre-compute per-record output offsets.
            const offsets = try self.allocator.alloc(usize, payloads.len);
            defer self.allocator.free(offsets);

            // Build parallel-friendly pointer/length arrays from the payload slices.
            const payload_ptrs = try self.allocator.alloc([*]const u8, payloads.len);
            defer self.allocator.free(payload_ptrs);
            const payload_lens = try self.allocator.alloc(usize, payloads.len);
            defer self.allocator.free(payload_lens);

            const is_encrypted = self.options.encryption_key != null;

            var off: usize = 0;
            for (payloads, 0..) |payload, i| {
                payload_ptrs[i] = payload.ptr;
                payload_lens[i] = payload.len;
                offsets[i] = off;
                const rec_size = record.HEADER_SIZE + payload.len + record.CRC_SIZE;
                if (is_encrypted) {
                    off += encryption.ENCRYPTION_OVERHEAD + rec_size;
                } else {
                    off += rec_size;
                }
            }

            // For encrypted mode, allocate a plaintext scratch buffer with
            // per-record regions so parallel workers don't share scratch space.
            var pt_buf: ?[]u8 = null;
            var pt_offsets_buf: ?[]usize = null;
            defer if (pt_buf) |b| {
                encryption.secureZero(b);
                self.allocator.free(b);
            };
            defer if (pt_offsets_buf) |o| self.allocator.free(o);

            if (is_encrypted) {
                var total_pt: usize = 0;
                pt_offsets_buf = try self.allocator.alloc(usize, payloads.len);
                for (payloads, 0..) |payload, i| {
                    pt_offsets_buf.?[i] = total_pt;
                    total_pt += record.HEADER_SIZE + payload.len + record.CRC_SIZE;
                }
                pt_buf = try self.allocator.alloc(u8, total_pt);
            }

            const ctx = ParallelSerializeCtx{
                .buf = buf.ptr,
                .offsets = offsets.ptr,
                .lsns = lsns.ptr,
                .payloads = payload_ptrs.ptr,
                .payload_lens = payload_lens.ptr,
                .encrypted = is_encrypted,
                .enc_key = if (self.options.encryption_key) |*key| key else null,
                .pt_buf = if (pt_buf) |b| b.ptr else null,
                .pt_offsets = if (pt_offsets_buf) |o| o.ptr else null,
            };

            const count: u32 = @intCast(payloads.len);
            const n_chunks = @min(count, MAX_SERIALIZE_CHUNKS);
            const chunk_size = (count + n_chunks - 1) / n_chunks;

            var chunks: [MAX_SERIALIZE_CHUNKS]SerializeChunk = undefined;
            var batch_tasks: [MAX_SERIALIZE_CHUNKS]tp.BatchTask = undefined;
            var n: u32 = 0;
            var start: u32 = 0;
            while (start < count) {
                const end = @min(start + chunk_size, count);
                chunks[n] = .{ .ctx = &ctx, .start = start, .end = end };
                batch_tasks[n] = .{ .task_fn = &SerializeChunk.run, .ctx = @ptrCast(&chunks[n]) };
                n += 1;
                start = end;
            }

            var wg = self.options.thread_pool.?.waitGroup();
            if (self.options.thread_pool.?.submitBatch(batch_tasks[0..n], .{ .wait_group = &wg })) |_| {
                wg.wait();
            } else |_| {
                // submitBatch failed (pool shutting down or queue full); fall back to sequential.
                var i: u32 = 0;
                while (i < count) : (i += 1) serializeOneRecord(&ctx, i);
            }
        } else {
            // Sequential serialization (original path).
            var offset: usize = 0;
            for (payloads, 0..) |payload, i| {
                const rec_size = record.HEADER_SIZE + payload.len + record.CRC_SIZE;

                if (self.options.encryption_key) |*key| {
                    const enc_size = encryption.ENCRYPTION_OVERHEAD + rec_size;
                    // Serialize the plaintext into a scratch region at the buffer
                    // tail, then encrypt it into its final position at `offset`.
                    // For the LAST record this scratch (buf[total_size-rec_size..])
                    // exactly aliases encryptInto's ciphertext output region. That
                    // is safe because AES-256-GCM is CTR mode (see encryption.zig
                    // encryptInto / decryptRecordInPlace, SEC-0003): the keystream
                    // XOR is applied low-to-high with dst == src, so each byte is
                    // consumed before it is overwritten. The per-record `+40`
                    // ENCRYPTION_OVERHEAD guarantees no NON-last record's ciphertext
                    // write ever reaches a not-yet-serialized record's scratch
                    // (proven across 200k batch shapes; see PERF-0027 / QA-0084).
                    // Do NOT reverse the copy direction or share scratch across
                    // records without re-checking this invariant.
                    const pt_start = total_size - rec_size;
                    record.serializeInto(buf[pt_start..][0..rec_size], lsns[i], payload);
                    encryption.encryptInto(buf[offset..][0..enc_size], key, buf[pt_start..][0..rec_size]);
                    offset += enc_size;
                } else {
                    record.serializeInto(buf[offset..][0..rec_size], lsns[i], payload);
                    offset += rec_size;
                }
            }
        }

        const last_lsn = lsns[lsns.len - 1];

        // Record file position before write so we can truncate on error (SEC-0030).
        const pre_write_pos = self.file_end;

        self.file.writeStreamingAll(std.Io.Threaded.global_single_threaded.io(), buf[0..total_size]) catch |err| {
            // Truncate any partial write to prevent torn records (SEC-0030).
            self.file.setLength(std.Io.Threaded.global_single_threaded.io(), pre_write_pos) catch {};
            return err;
        };

        // LSN only advances after successful write (SEC-0030).
        self.current_lsn = last_lsn;
        // Track where the LAST record of the batch begins (for the checkpoint
        // boundary anchor, SEC-0044/0046): its on-disk size subtracted from the
        // batch end.
        const last_payload_len = payloads[payloads.len - 1].len;
        const last_rec_size = record.HEADER_SIZE + last_payload_len + record.CRC_SIZE;
        const last_on_disk = if (self.options.encryption_key != null)
            encryption.ENCRYPTION_OVERHEAD + last_rec_size
        else
            last_rec_size;
        self.last_record_start = pre_write_pos + total_size - last_on_disk;
        self.file_end += total_size;
        self.bytes_since_compact += total_size;

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
    /// Thread-safe: acquires internal mutex.
    pub fn sync(self: *WriteAheadLog) !void {
        // Maps to the otel "wal.commit" span — the durable-write boundary.
        const span = observability.startWalSpan("commit");
        var ok = false;
        defer observability.endWalSpan(span, ok, 0);
        self.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mu.unlock(std.Io.Threaded.global_single_threaded.io());
        if (self.poisoned) return error.WalPoisoned;
        try std.posix.fdatasync(self.file.handle);
        self.appends_since_sync = 0;
        ok = true;
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
    /// Thread-safe: acquires internal mutex.
    pub fn compact(self: *WriteAheadLog, up_to_lsn: u64) !void {
        // Maps to the otel "wal.checkpoint" span — compaction is the
        // WAL's checkpoint primitive (rewrite above the watermark).
        const span = observability.startWalSpan("checkpoint");
        var ok = false;
        defer observability.endWalSpan(span, ok, 0);
        self.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mu.unlock(std.Io.Threaded.global_single_threaded.io());
        if (self.poisoned) return error.WalPoisoned;

        // Close the current file handle — compaction will rename a new file
        // over it and we must not hold a stale handle afterward.
        self.file.close(std.Io.Threaded.global_single_threaded.io());

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

        // Update bookkeeping before reopen so cursor is positioned correctly.
        // Compaction removes a prefix [0, first_kept_offset) and shifts every
        // kept record down by that amount, so the last record's start moves by
        // the same delta (old_file_end - new_size). When nothing is kept the WAL
        // is empty and there is no record anchor (SEC-0044/0046).
        const removed = self.file_end - result.new_size;
        if (result.records_kept == 0) {
            self.last_record_start = 0;
        } else {
            self.last_record_start -= removed;
        }
        self.file_end = result.new_size;

        // Reopen the (now compacted) file for appending (QA-0010).
        self.reopenOrPoison();
        if (self.poisoned) return error.WalPoisoned;
        self.bytes_since_compact = 0;
        self.appends_since_sync = 0; // finalizeTempFile already fsynced (QA-0036)

        // Invalidate the checkpoint — the file layout changed (PERF-0013).
        if (self.options.checkpoint) {
            checkpoint_mod.deleteCheckpoint(self.dir, self.filename);
        }
        ok = true;
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
        self.file = self.dir.openFile(std.Io.Threaded.global_single_threaded.io(), self.filename, .{ .mode = .read_write }) catch {
            // openFile failed — self.file still holds the stale (closed) fd.
            self.poisoned = true;
            return;
        };
        // Position cursor at write tail for streaming writes.
        _ = std.c.lseek(self.file.handle, @intCast(self.file_end), 0);
    }

    /// Remove all records with LSN > `after_lsn` by truncating the WAL tail.
    ///
    /// Scans from the file start to locate the byte position after the last
    /// record with LSN <= `after_lsn`, then truncates the file there.
    /// Updates `current_lsn` and `file_end` accordingly.
    ///
    /// This is the inverse of `compact`: compact removes the head (LSN <=),
    /// truncateAfter removes the tail (LSN >).
    ///
    /// If `after_lsn` is 0, truncates the entire file (all records removed).
    /// Thread-safe: acquires internal mutex.
    ///
    /// Cost: O(records up to `after_lsn`). Since SEC-0041 this scan is fully
    /// validated (one buffered read + CRC per plaintext record, or read +
    /// AES-GCM decrypt per encrypted record) rather than the old header-only
    /// pass, so it does ~2x the syscalls plus per-record CRC/AEAD work. That is
    /// the deliberate cost of integrity-checked, encryption-correct truncation;
    /// `truncateAfter` is a control-plane operation (e.g. Raft log-conflict
    /// truncation), not a per-append hot path, so the constant factor is
    /// acceptable.
    pub fn truncateAfter(self: *WriteAheadLog, after_lsn: u64) !void {
        const span = observability.startWalSpan("truncate");
        var ok = false;
        defer observability.endWalSpan(span, ok, 0);
        self.mu.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mu.unlock(std.Io.Threaded.global_single_threaded.io());
        if (self.poisoned) return error.WalPoisoned;

        const io = std.Io.Threaded.global_single_threaded.io();

        // Locate the truncation boundary with the same validated forward scan
        // used by recovery: CRC + AEAD + LSN monotonicity + encrypted/plaintext
        // detection (SEC-0041, SEC-0043). This replaces the old bespoke scan,
        // which skipped all integrity checks and — fatally — misread encrypted
        // records (parsing blob_len+magic as a plaintext LSN), truncating the
        // entire file on every call against an encrypted WAL. The scan is also
        // buffered through FileSource rather than one pread per 12-byte header
        // (PERF-0024).
        const info = try recovery_mod.recoverUpToWithKey(
            self.allocator,
            self.file,
            if (self.options.encryption_key) |*k| k else null,
            after_lsn,
        );
        const valid_end = info.valid_end;

        // Truncate the file and reposition the streaming-write cursor.
        try self.file.setLength(io, valid_end);
        // fdatasync (not full fsync): setLength's size change is data-reachability
        // metadata, which fdatasync flushes; this matches every other sync site
        // in the WAL (PERF-0024).
        try std.posix.fdatasync(self.file.handle);
        _ = std.c.lseek(self.file.handle, @intCast(valid_end), 0);

        self.file_end = valid_end;
        self.current_lsn = info.last_lsn;
        self.last_record_start = info.last_record_start;
        self.bytes_since_compact = valid_end;
        self.appends_since_sync = 0;

        // Invalidate checkpoint.
        if (self.options.checkpoint) {
            checkpoint_mod.deleteCheckpoint(self.dir, self.filename);
        }
        ok = true;
    }

    // -------------------------------------------------------------------------
    // Getters
    // -------------------------------------------------------------------------

    /// Return the LSN of the most recently appended record (0 if empty).
    /// Thread-safe: acquires shared lock (PAR-0005).
    pub fn currentLsn(self: *WriteAheadLog) u64 {
        self.mu.lockSharedUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mu.unlockShared(std.Io.Threaded.global_single_threaded.io());
        return self.current_lsn;
    }

    /// Return the number of bytes written since the last compaction (or since
    /// the file was first opened, if it has never been compacted).
    /// Thread-safe: acquires shared lock (PAR-0005).
    pub fn bytesSinceCompact(self: *WriteAheadLog) u64 {
        self.mu.lockSharedUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mu.unlockShared(std.Io.Threaded.global_single_threaded.io());
        return self.bytes_since_compact;
    }

    // -------------------------------------------------------------------------
    // Iterator
    // -------------------------------------------------------------------------

    /// Open a read-only iterator over records starting after `from_lsn`.
    ///
    /// The iterator uses an independent file handle so it does not disturb the
    /// write position.  Call `Iterator.deinit` when done.
    /// Thread-safe: acquires shared lock briefly to snapshot configuration (PAR-0005).
    ///
    /// **Consistency (SEC-0048):** the returned `Iterator` does NOT hold the
    /// WAL lock for its lifetime — it reads its own file handle positionally and
    /// only the brief snapshot above is locked. Concurrent `append` (extends the
    /// file) and `truncateAfter` (shrinks the live inode in place) are therefore
    /// NOT serialized against an in-flight iteration: a record visible on one
    /// `next()` may be gone on the next, and records appended after the iterator
    /// was created may or may not be observed. This is memory-safe — the kernel
    /// serializes `read` against `ftruncate`, and short/torn reads return a clean
    /// `null` stop — but it is not a point-in-time snapshot. A concurrent
    /// `compact` is unaffected: it swaps in a new inode via rename, so the
    /// iterator's open handle keeps reading the original (now-unlinked) file to
    /// completion. If you need read-during-mutate consistency, coordinate
    /// externally (e.g. drain iterators before truncating).
    pub fn iterator(self: *WriteAheadLog, from_lsn: u64) !Iterator {
        self.mu.lockSharedUncancelable(std.Io.Threaded.global_single_threaded.io());
        const enc_key = if (self.options.encryption_key) |k| k else null;
        self.mu.unlockShared(std.Io.Threaded.global_single_threaded.io());
        const read_file = try self.dir.openFile(std.Io.Threaded.global_single_threaded.io(), self.filename, .{ .mode = .read_only });
        return Iterator.init(
            self.allocator,
            read_file,
            from_lsn,
            enc_key,
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
    std.Io.Threaded.global_single_threaded.io().random(&key);

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
    std.Io.Threaded.global_single_threaded.io().random(&key);

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
    std.Io.Threaded.global_single_threaded.io().random(&key);

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
    std.Io.Threaded.global_single_threaded.io().random(&key);

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
    std.Io.Threaded.global_single_threaded.io().random(&key);

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
    std.Io.Threaded.global_single_threaded.io().random(&key);

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
    const f = try tmp.dir.createFile(std.Io.Threaded.global_single_threaded.io(), "wal.log", .{ .read = true, .permissions = std.Io.File.Permissions.fromMode(0o644) });
    f.close(std.Io.Threaded.global_single_threaded.io());

    // Verify file is world-readable.
    const stat_before = try tmp.dir.statFile(std.Io.Threaded.global_single_threaded.io(), "wal.log", .{});
    // Check group-read bit (0o040) — should be set for 0o644.
    try std.testing.expect(stat_before.permissions.toMode() & 0o040 != 0);

    // Open via WAL init — should tighten to 0o600.
    var wal = try WriteAheadLog.init(allocator, tmp.dir, "wal.log", .{});
    defer wal.deinit();

    // Verify permissions were tightened.
    const stat_after = try tmp.dir.statFile(std.Io.Threaded.global_single_threaded.io(), "wal.log", .{});
    // group-read and other-read bits should be cleared.
    try std.testing.expectEqual(@as(u32, 0), stat_after.permissions.toMode() & 0o077);
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
        wal.file.close(std.Io.Threaded.global_single_threaded.io());
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

test "appendBatch: parallel serialization with thread pool (PAR-0002)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var pool = try tp.ThreadPool.init(allocator, .{ .max_threads = 2 });
    defer pool.deinit();

    var wal = try WriteAheadLog.init(allocator, tmp.dir, "par.wal", .{
        .manual_sync = true,
        .thread_pool = &pool,
    });
    defer wal.deinit();

    const payloads = [_][]const u8{ "alpha", "beta", "gamma", "delta", "epsilon" };
    const last_lsn = try wal.appendBatch(&payloads);
    try std.testing.expectEqual(@as(u64, 5), last_lsn);
    try wal.sync();

    // Verify all records are readable and correct.
    var iter = try wal.iterator(0);
    defer iter.deinit();
    var count: usize = 0;
    while (true) {
        var entry = try iter.next() orelse break;
        defer entry.deinit();
        try std.testing.expectEqualSlices(u8, payloads[count], entry.payload);
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 5), count);
}

test "appendBatch: parallel serialization with encryption (PAR-0002)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var pool = try tp.ThreadPool.init(allocator, .{ .max_threads = 2 });
    defer pool.deinit();

    const key = [_]u8{0x42} ** 32;
    var wal = try WriteAheadLog.init(allocator, tmp.dir, "par_enc.wal", .{
        .manual_sync = true,
        .encryption_key = key,
        .thread_pool = &pool,
    });
    defer wal.deinit();

    const payloads = [_][]const u8{ "secret1", "secret2", "secret3", "secret4", "secret5" };
    const last_lsn = try wal.appendBatch(&payloads);
    try std.testing.expectEqual(@as(u64, 5), last_lsn);
    try wal.sync();

    // Verify all records decrypt and match.
    var iter = try wal.iterator(0);
    defer iter.deinit();
    var count: usize = 0;
    while (true) {
        var entry = try iter.next() orelse break;
        defer entry.deinit();
        try std.testing.expectEqualSlices(u8, payloads[count], entry.payload);
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 5), count);
}

test "appendBatch: encrypted batch with non-uniform payload sizes (PERF-0027)" {
    // Regression guard for the sequential encrypted-batch tail-scratch aliasing.
    // The serializer reuses the buffer tail as plaintext scratch; with payloads
    // of DIFFERENT sizes a buggy scratch layout could corrupt a record. No thread
    // pool, so this exercises the sequential path. A 200k-shape exhaustive proof
    // (PERF-0027) showed 0 cross-record overlaps; this pins one concrete mix.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const key = [_]u8{0x6B} ** 32;
    var wal = try WriteAheadLog.init(allocator, tmp.dir, "enc_nonuniform.wal", .{
        .manual_sync = true,
        .encryption_key = key,
    });
    defer wal.deinit();

    // Deliberately varied sizes incl. tiny, large, then tiny again (the "huge
    // middle / huge first" adversarial shapes).
    var big1: [4096]u8 = undefined;
    @memset(&big1, 0xA1);
    var big2: [3000]u8 = undefined;
    @memset(&big2, 0xB2);
    const payloads = [_][]const u8{ &big1, "x", &big2, "yz", "", &big1 };

    const last_lsn = try wal.appendBatch(&payloads);
    try std.testing.expectEqual(@as(u64, 6), last_lsn);
    try wal.sync();

    var iter = try wal.iterator(0);
    defer iter.deinit();
    var count: usize = 0;
    while (true) {
        var entry = try iter.next() orelse break;
        defer entry.deinit();
        try std.testing.expectEqualSlices(u8, payloads[count], entry.payload);
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 6), count);
}

test "appendBatchWithLsns: parallel serialization with caller LSNs (PAR-0002)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var pool = try tp.ThreadPool.init(allocator, .{ .max_threads = 2 });
    defer pool.deinit();

    var wal = try WriteAheadLog.init(allocator, tmp.dir, "par_lsn.wal", .{
        .manual_sync = true,
        .thread_pool = &pool,
    });
    defer wal.deinit();

    const lsns = [_]u64{ 10, 20, 30, 40, 50 };
    const payloads = [_][]const u8{ "a", "bb", "ccc", "dddd", "eeeee" };
    const last_lsn = try wal.appendBatchWithLsns(&lsns, &payloads);
    try std.testing.expectEqual(@as(u64, 50), last_lsn);
    try wal.sync();

    // Verify records with correct LSNs.
    var iter = try wal.iterator(0);
    defer iter.deinit();
    var count: usize = 0;
    while (true) {
        var entry = try iter.next() orelse break;
        defer entry.deinit();
        try std.testing.expectEqual(lsns[count], entry.lsn);
        try std.testing.expectEqualSlices(u8, payloads[count], entry.payload);
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 5), count);
}

test "registerWriterThread: returns a valid slot and releases cleanly" {
    const allocator = std.testing.allocator;

    var pool = try tp.ThreadPool.init(allocator, .{
        .max_threads = 2,
        .max_submitter_queues = 1, // required for registerSubmitter to return a slot
    });
    defer pool.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var wal = try WriteAheadLog.init(allocator, tmp.dir, "reg_writer.wal", .{
        .manual_sync = true,
        .thread_pool = &pool,
    });
    defer wal.deinit();

    const slot = try wal.registerWriterThread();
    try std.testing.expect(slot < 64);

    // With max_submitter_queues=1, a second register call exhausts the bitmap.
    try std.testing.expectError(error.NoSubmitterSlots, wal.registerWriterThread());

    wal.releaseWriterThread(slot);

    // After release, a fresh register must succeed again.
    const slot2 = try wal.registerWriterThread();
    defer wal.releaseWriterThread(slot2);
    try std.testing.expect(slot2 < 64);
}

test "registerWriterThread: appendBatch works from a registered submitter" {
    const allocator = std.testing.allocator;

    var pool = try tp.ThreadPool.init(allocator, .{
        .max_threads = 2,
        .max_submitter_queues = 1,
    });
    defer pool.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var wal = try WriteAheadLog.init(allocator, tmp.dir, "reg_append.wal", .{
        .manual_sync = true,
        .thread_pool = &pool,
    });
    defer wal.deinit();

    const slot = try wal.registerWriterThread();
    defer wal.releaseWriterThread(slot);

    const payloads = [_][]const u8{ "alpha", "beta", "gamma" };
    const last_lsn = try wal.appendBatch(&payloads);
    try std.testing.expectEqual(@as(u64, 3), last_lsn);
}

test "registerWriterThread: returns NoThreadPool when pool not wired" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var wal = try WriteAheadLog.init(allocator, tmp.dir, "no_pool.wal", .{});
    defer wal.deinit();

    try std.testing.expectError(error.NoThreadPool, wal.registerWriterThread());
    // releaseWriterThread should be a safe no-op when there's no pool.
    wal.releaseWriterThread(0);
}

// ---------------------------------------------------------------------------
// truncateAfter tests (SEC-0041 / SEC-0043 / PERF-0024)
//
// truncateAfter must route through the same validated scan as recovery:
// CRC-verified, AEAD-verified, LSN-monotonic, and encryption-aware. Before
// SEC-0041 it reimplemented a bespoke plaintext-only header scan that
// truncated the ENTIRE file on any encrypted WAL (it parsed blob_len+magic as
// a u64 LSN). These tests pin the correct behavior across both formats.
// ---------------------------------------------------------------------------

test "truncateAfter: plaintext keeps records with LSN <= after_lsn" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var wal = try WriteAheadLog.init(allocator, tmp.dir, "trunc_plain.wal", .{ .manual_sync = true });
    defer wal.deinit();

    for (1..6) |i| {
        var buf: [16]u8 = undefined;
        const p = try std.fmt.bufPrint(&buf, "rec-{d}", .{i});
        _ = try wal.append(p);
    }
    try wal.sync();
    try std.testing.expectEqual(@as(u64, 5), wal.currentLsn());

    try wal.truncateAfter(3);
    try std.testing.expectEqual(@as(u64, 3), wal.currentLsn());

    var iter = try wal.iterator(0);
    defer iter.deinit();
    var count: u64 = 0;
    while (try iter.next()) |*entry| {
        var e = entry.*;
        defer e.deinit();
        count += 1;
        try std.testing.expectEqual(count, e.lsn);
    }
    try std.testing.expectEqual(@as(u64, 3), count);
}

test "truncateAfter: plaintext round-trip survives reopen" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var wal = try WriteAheadLog.init(allocator, tmp.dir, "trunc_rt.wal", .{ .manual_sync = true });
        defer wal.deinit();
        for (1..6) |i| {
            var buf: [16]u8 = undefined;
            _ = try wal.append(try std.fmt.bufPrint(&buf, "rec-{d}", .{i}));
        }
        try wal.sync();
        try wal.truncateAfter(2);
    }

    // Reopen: recovery must see exactly the kept prefix.
    var wal = try WriteAheadLog.init(allocator, tmp.dir, "trunc_rt.wal", .{ .manual_sync = true });
    defer wal.deinit();
    try std.testing.expectEqual(@as(u64, 2), wal.currentLsn());

    var iter = try wal.iterator(0);
    defer iter.deinit();
    var count: u64 = 0;
    while (try iter.next()) |*entry| {
        var e = entry.*;
        defer e.deinit();
        count += 1;
    }
    try std.testing.expectEqual(@as(u64, 2), count);
}

test "truncateAfter: after_lsn=0 empties the file" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var wal = try WriteAheadLog.init(allocator, tmp.dir, "trunc_zero.wal", .{ .manual_sync = true });
    defer wal.deinit();
    _ = try wal.append("a");
    _ = try wal.append("b");
    try wal.sync();

    try wal.truncateAfter(0);
    try std.testing.expectEqual(@as(u64, 0), wal.currentLsn());

    var iter = try wal.iterator(0);
    defer iter.deinit();
    try std.testing.expect((try iter.next()) == null);
}

test "truncateAfter: after_lsn at or above max keeps everything" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var wal = try WriteAheadLog.init(allocator, tmp.dir, "trunc_max.wal", .{ .manual_sync = true });
    defer wal.deinit();
    for (1..4) |_| _ = try wal.append("x");
    try wal.sync();

    try wal.truncateAfter(1000);
    try std.testing.expectEqual(@as(u64, 3), wal.currentLsn());

    var iter = try wal.iterator(0);
    defer iter.deinit();
    var count: u64 = 0;
    while (try iter.next()) |*entry| {
        var e = entry.*;
        defer e.deinit();
        count += 1;
    }
    try std.testing.expectEqual(@as(u64, 3), count);
}

test "truncateAfter: encrypted WAL keeps records with LSN <= after_lsn (SEC-0041)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const key = [_]u8{0x37} ** 32;
    var wal = try WriteAheadLog.init(allocator, tmp.dir, "trunc_enc.wal", .{
        .manual_sync = true,
        .encryption_key = key,
    });
    defer wal.deinit();

    for (1..6) |i| {
        var buf: [16]u8 = undefined;
        _ = try wal.append(try std.fmt.bufPrint(&buf, "secret-{d}", .{i}));
    }
    try wal.sync();
    try std.testing.expectEqual(@as(u64, 5), wal.currentLsn());

    // Before SEC-0041 this truncated the entire file (blob_len+magic parsed as
    // a bogus huge LSN, so the loop broke on record 1 and setLength(0) ran).
    try wal.truncateAfter(3);
    try std.testing.expectEqual(@as(u64, 3), wal.currentLsn());

    var iter = try wal.iterator(0);
    defer iter.deinit();
    var count: u64 = 0;
    while (try iter.next()) |*entry| {
        var e = entry.*;
        defer e.deinit();
        count += 1;
        var buf: [16]u8 = undefined;
        const want = try std.fmt.bufPrint(&buf, "secret-{d}", .{count});
        try std.testing.expectEqualStrings(want, e.payload);
        try std.testing.expectEqual(count, e.lsn);
    }
    try std.testing.expectEqual(@as(u64, 3), count);
}

test "truncateAfter: encrypted round-trip survives reopen (SEC-0041)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const key = [_]u8{0x99} ** 32;
    {
        var wal = try WriteAheadLog.init(allocator, tmp.dir, "trunc_enc_rt.wal", .{
            .manual_sync = true,
            .encryption_key = key,
        });
        defer wal.deinit();
        for (1..6) |i| {
            var buf: [16]u8 = undefined;
            _ = try wal.append(try std.fmt.bufPrint(&buf, "secret-{d}", .{i}));
        }
        try wal.sync();
        try wal.truncateAfter(4);
    }

    var wal = try WriteAheadLog.init(allocator, tmp.dir, "trunc_enc_rt.wal", .{
        .manual_sync = true,
        .encryption_key = key,
    });
    defer wal.deinit();
    try std.testing.expectEqual(@as(u64, 4), wal.currentLsn());

    var iter = try wal.iterator(0);
    defer iter.deinit();
    var count: u64 = 0;
    while (try iter.next()) |*entry| {
        var e = entry.*;
        defer e.deinit();
        count += 1;
    }
    try std.testing.expectEqual(@as(u64, 4), count);
}

// ---------------------------------------------------------------------------
// Write-side record-size cap tests (PERF-0033)
//
// The write path must reject any payload whose on-disk record would exceed
// MAX_RECORD_SIZE — the exact limit the recovery/iterator read paths enforce.
// Without this, a caller could write a record that recovery later silently
// rejects and truncates (a write/read asymmetry and an unbounded-allocation
// hazard).
// ---------------------------------------------------------------------------

test "append: rejects payload exceeding MAX_RECORD_SIZE (PERF-0033)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var wal = try WriteAheadLog.init(allocator, tmp.dir, "toobig.wal", .{ .manual_sync = true });
    defer wal.deinit();

    // A payload whose record overflows the 16 MiB cap must be rejected up front.
    const big = try allocator.alloc(u8, record.MAX_RECORD_SIZE);
    defer allocator.free(big);
    @memset(big, 0xAB);
    try std.testing.expectError(error.RecordTooLarge, wal.append(big));
    try std.testing.expectError(error.RecordTooLarge, wal.appendWithLsn(1, big));
    try std.testing.expectEqual(@as(u64, 0), wal.currentLsn());

    // The exact plaintext maximum payload is accepted and survives recovery.
    const max_payload = record.MAX_RECORD_SIZE - record.HEADER_SIZE - record.CRC_SIZE;
    const ok_buf = try allocator.alloc(u8, max_payload);
    defer allocator.free(ok_buf);
    @memset(ok_buf, 0xCD);
    _ = try wal.append(ok_buf);
    try wal.sync();
    try std.testing.expectEqual(@as(u64, 1), wal.currentLsn());
}

test "appendBatch: rejects oversize payload before allocating (PERF-0033)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var wal = try WriteAheadLog.init(allocator, tmp.dir, "batchbig.wal", .{ .manual_sync = true });
    defer wal.deinit();

    const big = try allocator.alloc(u8, record.MAX_RECORD_SIZE);
    defer allocator.free(big);
    @memset(big, 0x11);
    const payloads = [_][]const u8{ "ok", big, "also-ok" };
    try std.testing.expectError(error.RecordTooLarge, wal.appendBatch(&payloads));
    // Nothing should have been written.
    try std.testing.expectEqual(@as(u64, 0), wal.currentLsn());
}

test "append: encrypted record-size limit accounts for AEAD overhead (PERF-0033)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const key = [_]u8{0x5A} ** 32;
    var wal = try WriteAheadLog.init(allocator, tmp.dir, "encbig.wal", .{
        .manual_sync = true,
        .encryption_key = key,
    });
    defer wal.deinit();

    // A payload that just fits the PLAINTEXT limit overflows the cap once the
    // 40-byte encryption overhead is added — must be rejected on an encrypted WAL.
    const plain_max = record.MAX_RECORD_SIZE - record.HEADER_SIZE - record.CRC_SIZE;
    const buf = try allocator.alloc(u8, plain_max);
    defer allocator.free(buf);
    @memset(buf, 0x22);
    try std.testing.expectError(error.RecordTooLarge, wal.append(buf));
}

// ---------------------------------------------------------------------------
// Checkpoint integrity tests (SEC-0044 / SEC-0045 / SEC-0046)
//
// The checkpoint's CRC-32 is not a MAC, so a stale, cross-WAL, or forged
// sidecar could otherwise point the O(1) recovery start at an arbitrary offset
// and cause init() to truncate valid data. init() now re-validates the
// boundary (recovery.validateCheckpointBoundary) before trusting the prefix.
// ---------------------------------------------------------------------------

fn forgeCheckpoint(
    dir: std.Io.Dir,
    name: []const u8,
    last_lsn: u64,
    valid_end: u64,
    record_count: u64,
    last_record_start: u64,
) !void {
    const io = std.Io.Threaded.global_single_threaded.io();
    var buf: [checkpoint_mod.CHECKPOINT_SIZE]u8 = undefined;
    std.mem.writeInt(u64, buf[0..8], last_lsn, .little);
    std.mem.writeInt(u64, buf[8..16], valid_end, .little);
    std.mem.writeInt(u64, buf[16..24], record_count, .little);
    std.mem.writeInt(u64, buf[24..32], last_record_start, .little);
    // A valid CRC — readCheckpoint accepts it; only the boundary check rejects it.
    const crc = std.hash.crc.Crc32IsoHdlc.hash(buf[0..32]);
    std.mem.writeInt(u32, buf[32..36], crc, .little);
    const f = try dir.createFile(io, name, .{ .truncate = true });
    defer f.close(io);
    try f.writeStreamingAll(io, &buf);
}

test "checkpoint: forged boundary is rejected; full scan recovers all (SEC-0044/SEC-0046)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var wal = try WriteAheadLog.init(allocator, tmp.dir, "ck.wal", .{ .checkpoint = true });
        defer wal.deinit();
        for (1..6) |i| {
            var b: [16]u8 = undefined;
            _ = try wal.append(try std.fmt.bufPrint(&b, "rec-{d}", .{i}));
        }
    }

    // Forge: claim valid_end=10 (mid first record) with a bogus high LSN but a
    // VALID CRC. If trusted, init() would truncate the file to 10 bytes.
    try forgeCheckpoint(tmp.dir, "ck.wal.ckpt", 99, 10, 1, 0);

    var wal = try WriteAheadLog.init(allocator, tmp.dir, "ck.wal", .{ .checkpoint = true });
    defer wal.deinit();
    // Boundary validation rejected the forgery → full scan recovered everything.
    try std.testing.expectEqual(@as(u64, 5), wal.currentLsn());

    var iter = try wal.iterator(0);
    defer iter.deinit();
    var count: u64 = 0;
    while (try iter.next()) |*entry| {
        var e = entry.*;
        defer e.deinit();
        count += 1;
    }
    try std.testing.expectEqual(@as(u64, 5), count);
}

test "checkpoint: tampered last_lsn is rejected; full scan recovers all (SEC-0045/SEC-0046)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var real_valid_end: u64 = 0;
    var real_last_start: u64 = 0;
    {
        var wal = try WriteAheadLog.init(allocator, tmp.dir, "ck2.wal", .{ .checkpoint = true });
        defer wal.deinit();
        for (1..4) |i| {
            var b: [16]u8 = undefined;
            _ = try wal.append(try std.fmt.bufPrint(&b, "rec-{d}", .{i}));
        }
        real_valid_end = wal.file_end;
        real_last_start = wal.last_record_start;
    }

    // Keep the REAL boundary offsets (so the record exists and ends at valid_end)
    // but tamper last_lsn. The record at last_record_start has LSN 3, not 999, so
    // boundary validation must reject the checkpoint.
    try forgeCheckpoint(tmp.dir, "ck2.wal.ckpt", 999, real_valid_end, 1, real_last_start);

    var wal = try WriteAheadLog.init(allocator, tmp.dir, "ck2.wal", .{ .checkpoint = true });
    defer wal.deinit();
    try std.testing.expectEqual(@as(u64, 3), wal.currentLsn());

    var iter = try wal.iterator(0);
    defer iter.deinit();
    var count: u64 = 0;
    while (try iter.next()) |*entry| {
        var e = entry.*;
        defer e.deinit();
        count += 1;
    }
    try std.testing.expectEqual(@as(u64, 3), count);
}

test "checkpoint: legitimate checkpoint round-trips with boundary anchor (SEC-0046)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var wal = try WriteAheadLog.init(allocator, tmp.dir, "ck3.wal", .{ .checkpoint = true });
        defer wal.deinit();
        for (1..4) |i| {
            var b: [16]u8 = undefined;
            _ = try wal.append(try std.fmt.bufPrint(&b, "rec-{d}", .{i}));
        }
    }

    // The written checkpoint's last_record_start must point at the real last
    // record so validateCheckpointBoundary accepts it (O(1) path stays usable).
    const ckpt = checkpoint_mod.readCheckpoint(tmp.dir, "ck3.wal") orelse return error.TestUnexpectedResult;
    try std.testing.expect(ckpt.last_record_start < ckpt.valid_end);

    const io = std.Io.Threaded.global_single_threaded.io();
    const wal_file = try tmp.dir.openFile(io, "ck3.wal", .{});
    defer wal_file.close(io);
    const ok = recovery_mod.validateCheckpointBoundary(
        allocator,
        wal_file,
        null,
        ckpt.last_lsn,
        ckpt.valid_end,
        ckpt.last_record_start,
    );
    try std.testing.expect(ok);
}
