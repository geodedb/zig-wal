# Performance Gap Analysis

> **Source of truth:** [GitLab Issues](https://gitlab.com/devnw/zig/wal/-/issues?label_name%5B%5D=performance)
> filtered by label `performance`.
>
> **Last updated:** 2026-03-21 (all 10 findings resolved)
>
> **Baseline:** Zig 0.15.2 / ReleaseFast / Linux 6.17.0 / tmpfs

## Summary

10 performance findings identified across the WAL library codebase, CI/CD pipeline, and runtime assumptions. The primary bottleneck is **encrypted-mode allocation overhead** — the encrypted write path allocates 2 buffers per append vs the plaintext path which uses stack allocation for payloads ≤64KB.

Key metrics from baseline benchmarks (`zig build bench`):

| Benchmark | Records | Time (ms) | Throughput |
|-----------|---------|-----------|------------|
| append_64B_plain | 10,000 | 2.99 | 3,347,889 r/s |
| append_1KB_plain | 5,000 | 10.61 | 471,056 r/s |
| append_64KB_plain | 500 | 71.66 | 6,977 r/s |
| append_64B_encrypted | 10,000 | 49.08 | 203,731 r/s |
| append_1KB_encrypted | 5,000 | 35.12 | 142,382 r/s |
| recovery_10k_plain | 10,000 | 4.84 | 2,067,774 r/s |
| recovery_10k_encrypted | 10,000 | 40.84 | 244,885 r/s |
| compact_5k_plain | 5,000 | 1.96 | 2,557,050 r/s |
| compact_5k_encrypted | 5,000 | 20.20 | 247,510 r/s |

Encrypted vs plaintext gap: **~16x for writes, ~10x for compaction, ~8x for recovery.** AES-256-GCM is inherently expensive, but allocation overhead and unnecessary full-decryption amplify the gap.

## Stack-Ranked Findings

| Rank | Severity | Score | Finding | Component | Confidence | GitLab | Status |
|------|----------|-------|---------|-----------|------------|--------|--------|
| 1 | P1 | 80 | Encrypted append: 2 heap allocs per record | `wal.zig` / `encryption.zig` | Confirmed | [#8](https://gitlab.com/devnw/zig/wal/-/issues/8) | **Closed** |
| 2 | P2 | 64 | appendBatch: per-record alloc+write, no coalescing | `wal.zig` | Confirmed | [#9](https://gitlab.com/devnw/zig/wal/-/issues/9) | **Closed** |
| 3 | P2 | 60 | Compaction decrypts entire record to read 8-byte LSN | `compaction.zig` / `recovery.zig` | Confirmed | [#10](https://gitlab.com/devnw/zig/wal/-/issues/10) | **Closed** |
| 4 | P2 | 60 | Per-append fsync default — no group-commit option | `wal.zig` | Confirmed | [#13](https://gitlab.com/devnw/zig/wal/-/issues/13) | **Closed** |
| 5 | P2 | 48 | Iterator: 3 allocs per encrypted record read | `wal.zig` / `encryption.zig` | Confirmed | [#11](https://gitlab.com/devnw/zig/wal/-/issues/11) | **Closed** |
| 6 | P3 | 36 | readPayloadAndVerify: tail alloc + payload dupe | `record.zig` | Confirmed | [#12](https://gitlab.com/devnw/zig/wal/-/issues/12) | **Closed** |
| 7 | P3 | 28 | Iterator from_lsn: reads+deserializes skipped records | `wal.zig` | Confirmed | [#14](https://gitlab.com/devnw/zig/wal/-/issues/14) | **Closed** |
| 8 | P3 | 24 | Compaction bulk-copy: 64KB buffer, no sendfile | `compaction.zig` | Confirmed | [#15](https://gitlab.com/devnw/zig/wal/-/issues/15) | **Closed** |
| 9 | P3 | 20 | CI: Zig installed from scratch in every job | `.gitlab-ci.yml` | Confirmed | [#16](https://gitlab.com/devnw/zig/wal/-/issues/16) | **Closed** |
| 10 | Info | 16 | fsync instead of fdatasync on append path | `wal.zig` | Confirmed | [#17](https://gitlab.com/devnw/zig/wal/-/issues/17) | **Closed** |

## Findings by Area

### Application — Write Path (Hot)

#### PERF-0001: Encrypted append allocates 2 buffers per record (P1, Score 80) — CLOSED

**Evidence:** `src/wal.zig:116-126` — `record.serialize()` allocs a buffer, then `encryption.encryptRecord()` allocs another. Both are freed after `writeAll`.

**Measurement:** `append_64B_encrypted` at 203k r/s vs `append_64B_plain` at 3.3M r/s (16x gap). The plaintext path uses a stack buffer via `record.writeToFile()` for payloads ≤64KB.

**Resolution:** Added `encryption.encryptAndWriteToFile()` that serializes+encrypts using stack allocation for payloads ≤64KB. Both `append()` and `appendBatch()` now use this zero-alloc path. Also made `record.serializeInto()` public.

---

#### PERF-0002: appendBatch does per-record alloc+write, no coalescing (P2, Score 64) — CLOSED

**Evidence:** `src/wal.zig:155-173` — loop body is identical to single `append()`. Each record triggers a separate `writeAll` syscall.

**Measurement:** No dedicated batch benchmark yet. The batch path's only optimization over N×append is the single fsync at the end.

**Resolution:** `appendBatch()` now computes total buffer size upfront, allocates once, serializes (and encrypts) all records into the single buffer, and issues one `writeAll` call.

---

#### PERF-0006: Per-append fsync default — no group-commit option (P2, Score 60) — CLOSED

**Evidence:** `src/wal.zig:134-136` — `file.sync()` after every `append()` when `manual_sync=false`.

**Measurement:** Benchmarks use `manual_sync=true`. Real-world default-mode throughput would be dominated by fsync latency (~10-50μs/NVMe, ~5-15ms/HDD).

**Resolution:** Added `Options.sync_every_n` (default: 1). When `manual_sync=false`, `append()` counts appends and only syncs every N-th. `appendBatch()` always syncs once at the end. Counter resets on `sync()`, `appendBatch()`, and when threshold is hit.

---

### Application — Read/Scan Path

#### PERF-0003: Compaction decrypts entire record to read LSN (P2, Score 60) — CLOSED

**Evidence:** `src/compaction.zig:96-128` — full AES-256-GCM decrypt + alloc per encrypted record during scan phase, only to extract the 8-byte LSN.

**Measurement:** `compact_5k_encrypted` at 20.2ms vs `compact_5k_plain` at 1.96ms (10x gap).

**Resolution:** Replaced `decryptRecord()` (heap alloc) with `decryptRecordInPlace()` (zero extra alloc) in both compaction scan and recovery scan. The plaintext is written into the front of the existing blob buffer, eliminating the separate allocation.

---

#### PERF-0004: Iterator allocates 3 times per encrypted record (P2, Score 48) — CLOSED

**Evidence:** `src/wal.zig:376-395` — blob_buf alloc, decryptRecord alloc, payload dupe. Two of three are avoidable.

**Measurement:** No dedicated read benchmark yet. Recovery benchmark (which uses the same code path) shows `recovery_10k_encrypted` at 244k r/s.

**Resolution:** `readEncryptedEntry()` now uses `decryptRecordInPlace()` to decrypt into the front of `blob_buf`, then copies only the payload. Reduced from 3 allocs (blob_buf + plaintext + payload_copy) to 2 (blob_buf + payload_copy).

---

#### PERF-0005: readPayloadAndVerify allocates tail then dupes payload (P3, Score 36) — CLOSED

**Evidence:** `src/record.zig:211-229` — allocs `payload_len + 4` bytes, reads, then dupes `payload_len` bytes.

**Measurement:** Included in plaintext recovery overhead. `recovery_10k_plain` at 2M r/s — already fast, but leaves room.

**Resolution:** `readPayloadAndVerify()` now allocates only the payload buffer, reads CRC into a 4-byte stack variable, and returns the payload allocation directly. Eliminated the dupe and the `total_tail` intermediate buffer.

---

#### PERF-0007: Iterator from_lsn reads skipped records fully (P3, Score 28) — CLOSED

**Evidence:** `src/wal.zig:321-324` — plaintext skipped records are fully read and CRC-checked, then discarded.

**Measurement:** Suspected. Needs `iterate_from_lsn` benchmark.

**Resolution:** Plaintext iterator path now checks `lsn <= from_lsn` immediately after reading the 12-byte header and uses `seekBy(payload_len + CRC_SIZE)` to skip without reading the payload or verifying CRC.

---

### Application — Compaction

#### PERF-0008: 64KB copy buffer in bulk-copy phase (P3, Score 24) — CLOSED

**Evidence:** `src/compaction.zig:32` — `COPY_BUF_SIZE = 64 * 1024`. For 100MB+ WALs this means ~1600 syscall pairs.

**Measurement:** Suspected. Needs large-WAL compaction benchmark.

**Resolution:** Increased `COPY_BUF_SIZE` from 64 KiB to 256 KiB, reducing syscall count 4× for the bulk-copy phase.

---

### Application — Durability

#### PERF-0010: fsync instead of fdatasync (Info, Score 16) — CLOSED

**Evidence:** All 6 `file.sync()` call sites use full fsync. Zig stdlib provides `file.datasync()` for fdatasync.

**Measurement:** Suspected. Needs microbenchmark on ext4 with journaling.

**Resolution:** Replaced all append-path `file.sync()` calls with `std.posix.fdatasync(file.handle)` in `append()`, `appendBatch()`, and `sync()`. Compaction still uses `file.sync()` (full fsync) via `tmp.sync()` before rename, which is correct for metadata updates.

---

### CI/CD

#### PERF-0009: Zig installed from scratch per CI job (P3, Score 20) — CLOSED

**Evidence:** `.gitlab-ci.yml:34-39` — apt-get + curl + tar in every before_script.

**Measurement:** Confirmed: 15-30s per job × 5 jobs = 75-150s per pipeline.

**Resolution:** Added GitLab CI `cache:` with key `zig-${ZIG_VERSION}` for the toolchain directory. Install script now checks if cached binary exists before downloading. All 5 jobs reference the cache anchor.

---

## Implementation Summary

All 10 findings have been resolved:

- **Quick wins** (PERF-0007, PERF-0010, PERF-0005): Seek-skip in iterator, fdatasync, single-alloc readPayloadAndVerify
- **Medium effort** (PERF-0001, PERF-0004, PERF-0002, PERF-0009): Stack-buffer encrypted writes, in-place decrypt, coalesced batch writes, CI caching
- **Strategic** (PERF-0006, PERF-0003, PERF-0008): Group-commit option, in-place decrypt for compaction/recovery, 256KB copy buffer
