# Performance Gap Analysis

> **Source of truth:** [GitLab Issues](https://gitlab.com/devnw/zig/wal/-/issues?label_name%5B%5D=performance)
> filtered by label `performance`.
>
> **Last updated:** 2026-06-11
>
> **Baseline:** Zig 0.15.2 / ReleaseFast / Linux 6.17.0 / tmpfs

## Summary

Eight performance reviews have been performed on this codebase.

**Review 1** (2026-03-21): 10 findings (PERF-0001 through PERF-0010). All 10 have been
**resolved and closed**. Primary bottleneck was encrypted-mode allocation overhead.

**Review 2** (2026-03-22): 5 additional findings (PERF-0011 through PERF-0015). 3 have been
**resolved and closed**, 2 marked **Deferred** (require design-level changes not justified
for current workload sizes). Scope: exhaustive codebase-wide adversarial performance
review covering all 8 source modules (~2,800 LOC), benchmarks, CI/CD, and runtime
assumptions. 8 automated scanners (from security Review 12) confirmed clean state. Manual
line-by-line review of all hot paths. The primary bottleneck — excessive volatile zeroing
on the encrypted stack-buffer write path — has been resolved (PERF-0011).

**Review 3** (2026-03-22): 4 additional findings (PERF-0016 through PERF-0019). All 4 have been
**resolved and closed**. Scope: full codebase-wide adversarial performance review of all 8
source modules (~2,800 LOC), benchmarks, CI/CD pipeline, and build configuration. Two
parallel exploration agents performed independent analysis. Line-by-line review of all hot
paths, allocation patterns, I/O syscalls, and CI job structure. Primary improvement:
reusable buffer for encrypted scan (PERF-0016) combined with manual offset tracking
(PERF-0018) yielded **9× improvement** in encrypted recovery/compaction. Encrypt benchmark
fix (PERF-0017) revealed true AES-GCM encrypt throughput matching decrypt (**35×
measurement artifact**, same class as PERF-0015).

Key metrics from post-Review 3 benchmarks (`zig build bench`):

| Benchmark | Records | Time (ms) | Throughput | Notes |
|-----------|---------|-----------|------------|-------|
| append_64B_plain | 10,000 | 3.71 | 2,695,771 r/s | |
| append_1KB_plain | 5,000 | 10.08 | 496,276 r/s | |
| append_64KB_plain | 500 | 55.97 | 8,933 r/s | |
| append_64B_encrypted | 10,000 | 4.23 | 2,363,298 r/s | PERF-0011 fixed |
| append_1KB_encrypted | 5,000 | 12.11 | 412,850 r/s | PERF-0011 fixed |
| recovery_10k_plain | 10,000 | 3.44 | 2,910,568 r/s | |
| recovery_10k_encrypted | 10,000 | 4.74 | 2,108,554 r/s | PERF-0016 fixed (**9.6×**) |
| compact_5k_plain | 2,500 | 1.45 | 1,718,500 r/s | PERF-0018 fixed |
| compact_5k_encrypted | 2,500 | 2.64 | 946,498 r/s | PERF-0016/0018 fixed (**8.9×**) |
| iterate_10k_plain | 10,000 | 36.84 | 271,426 r/s | |
| iterate_10k_encrypted | 10,000 | 75.12 | 133,128 r/s | |
| iterate_lsn_5k_plain | 5,000 | 14.95 | 334,359 r/s | |
| iterate_lsn_5k_enc | 5,000 | 56.62 | 88,310 r/s | |
| encrypt_64B | 50,000 | 5.84 | 8,563,131 r/s | PERF-0017 fixed (**35×**) |
| encrypt_1KB | 20,000 | 8.48 | 2,358,983 r/s | PERF-0017 fixed (**10×**) |
| decrypt_64B | 50,000 | 5.52 | 9,052,100 r/s | PERF-0015 fixed |
| decrypt_1KB | 20,000 | 7.69 | 2,600,096 r/s | PERF-0015 fixed |

Post-Review 2 improvements: PERF-0011 fix improved encrypted append from 873K → 2,263K r/s (**2.6×**) for 64B payloads. Encrypted vs plaintext gap narrowed to **~1.2× for writes** (was 1.8×). PERF-0015 fix revealed true AES-GCM decrypt throughput: 8.6M r/s (was 245K — **35× measurement artifact**).

Post-Review 3 improvements: PERF-0016 + PERF-0018 combined improved encrypted recovery from 221K → 2,109K r/s (**9.6×**) and encrypted compaction from 107K → 946K r/s (**8.9×**). The reusable buffer eliminated per-record alloc/free/secureZero overhead that dominated the scan loop. PERF-0017 fix revealed true AES-GCM encrypt throughput: 8.6M r/s (was 247K — **35× measurement artifact**, matching the PERF-0015 decrypt fix). Encrypt and decrypt throughput are now symmetric as expected for AES-GCM.

**Review 4** (2026-03-22): 3 additional findings (PERF-0020 through PERF-0022). All 3
**resolved and closed**. Scope: full codebase-wide adversarial performance review of all 8
source modules (~5,500 LOC including tests), benchmarks, CI/CD pipeline, and build
configuration. Line-by-line review of all hot paths, allocation patterns, I/O syscall
patterns, and CI job structure. Primary improvements: reusable blob buffer for iterator
encrypted path (PERF-0020) yielded **2.3x** improvement in encrypted iteration throughput.
Buffered I/O (PERF-0021) replaced per-record syscalls with a 64KB buffered reader, using
`anytype` generic functions to avoid API duplication. CI build cache (PERF-0022) added
`.zig-cache/` to pipeline cache paths.

**Review 5** (2026-03-22): **Zero new findings.** Comprehensive adversarial performance
review of all 8 source modules (~3,870 LOC), benchmarks, CI/CD pipeline, and build
configuration. One candidate finding (compaction/recovery unbuffered I/O) evaluated and
rejected: plaintext path uses `seekBy()` (kernel-only lseek, no data transfer) which is
strictly better than buffered read+discard. The codebase is performance-mature with all
identified hot paths addressed across 4 prior reviews.

**Review 6** (2026-03-22): **Zero new findings.** Full adversarial performance review with two
parallel analysis agents (write path + encryption, read path + CI/build). All hot paths confirmed
properly optimized. Two consecutive zero-finding reviews (Reviews 5 and 6) confirm performance
maturity. Benchmarks stable with no regressions from QA Review 5 code changes.

**Review 7** (2026-03-22): 1 new finding (PERF-0023). Scope: external perf-reviewer agent
generated 6 candidates (1 P1, 5 P2). Systematic cross-reference against all 22 existing PERF
findings and 19 triaged non-findings confirmed that 5 of 6 candidates were already tracked:
1 was explicitly rejected in Review 5 (recovery unbuffered I/O), 2 were triaged as non-findings
in Reviews 2/4 (stack size, zeroing), and 2 were already resolved (PERF-0002 appendBatch,
PERF-0003 encrypted compaction decrypt). The 1 genuinely new finding is the absence of a CI
benchmark regression gate (PERF-0023). PERF-0013 and PERF-0014 confirmed still correctly deferred.

**Review 8** (2026-06-11): 11 new findings (PERF-0024 through PERF-0034), all **open / triage**.
Scope: automated performance scan + deep reviewer against the current Zig 0.16-era `std.Io` codebase.
**Confidence caveat:** the first deep-review validation agent died mid-run, so PERF-0024/0026/0027
carry **scanner-level confidence** except where another domain's reviewer independently confirmed the
code fact; the remaining findings (PERF-0028..0034) are **confirmed code facts** (grep/source-verified)
whose *impact magnitude* is the part still pending measurement. No profiler/strace numbers were
captured this session — each issue's "How to verify" is the exact command that would confirm it.
Findings:

- **PERF-0024 (P1, suspected, #167):** `truncateAfter` does an unbuffered 12-byte `pread` per record
  (`wal.zig:806`) plus a full `fsync` (`wal.zig:829`) where every other sync point uses `fdatasync`
  (`:444/:677/:698`) — ~90K syscalls for a 100K-record WAL. **Rides on SEC-0041/#139** (the
  truncateAfter rewrite); must land as part of that remediation. Two sub-parts: (a) buffering, (b)
  fdatasync consistency.
- **PERF-0025 (P3, confirmed, #168):** double `file.stat()` on the checkpoint init path
  (`recovery.zig:107` + `wal.zig:243`); fix by returning the size from recovery.
- **PERF-0026 (P2, suspected, #169):** parallel batch serialization triggers at N=2 with 5-7 setup
  allocations and no minimum-batch threshold (`wal.zig:554`); crossover never measured. **Pairs with
  PERF-0030** (the bench that finds the threshold).
- **PERF-0027 (P2, #170 + resolved on #157):** the sequential encrypted-batch tail-scratch aliasing
  (`wal.zig:646-648`) was investigated as a possible correctness bug and **PROVEN SAFE** by the perf
  reviewer across **200,006 batch shapes** (0 cross-record overlaps for any payload distribution;
  last-record CTR in-place aliasing is safe). **No correctness escalation.** This confirms QA-0084;
  the 200k-shape proof was recorded as a comment on **#157** (the existing "add a clarifying comment"
  item) rather than as a duplicate perf issue. #170 remains as the open test/comment task.
- **PERF-0028 (P2, confirmed, #177):** the checkpoint **O(1) recovery** path (`Options.checkpoint`,
  PERF-0013) has **no bench coverage** — `runRecoveryBench` (`bench/main.zig:188-215`) runs with
  checkpoint disabled.
- **PERF-0029 (P2, confirmed, #178):** the **zero-copy compaction** path
  (`Options.zero_copy_compaction`, PERF-0014) has **no bench coverage** — `runCompactBench`
  (`bench/main.zig:226-253`) never toggles it.
- **PERF-0030 (P2, confirmed, #179):** the thread-pool batch **parallel/sequential crossover** is
  never measured; `scale_bench` minimum `batch_size` is 100 (`scale_bench.zig:93-96`), so the small-N
  region is uncovered. **Pairs with PERF-0026.**
- **PERF-0031 (P1, confirmed, #180):** `zig build bench` (and `make bench`) build the **WAL module at
  Debug** while the bench exe is ReleaseFast (`build.zig:79` vs `:164`; `Makefile:37`) → local bench
  numbers are **3-10x slow / misleading**. CI is fine (passes `-Doptimize=ReleaseFast`).
- **PERF-0032 (P2, confirmed, #181):** `scale_bench` `Tier.iterations` is defined + initialized but
  **never read** (`scale_bench.zig:88-96`) → single-sample point estimates, no variance; `compare`
  is point-to-point. Fix: wire `iterations` into a median repeat loop, or delete the field.
- **PERF-0033 (P2 + correctness/security, confirmed, #182):** the **write path enforces no per-record
  `MAX_RECORD_SIZE`** and `appendBatch` has **no batch-byte cap** (`wal.zig:530-540`;
  `record.zig:145-159` only a ~4 GiB `MAX_PAYLOAD_SIZE` panic). The 16 MiB cap exists only on
  read/recovery/truncate (`record.zig:246`, `wal.zig:813`). Impact: unbounded contiguous allocation
  (DoS-adjacent) + write/read **asymmetry** (a >16 MiB record can be written and then silently
  dropped by recovery). **Cross-linked to QA-0079/#152** (silent-truncation logging gap).
- **PERF-0034 (P3, confirmed, #183):** the CI bench-regression stage runs `bench` (no comparison),
  not `scale-bench` + `compare-bench`, so the existing regression-gate tooling
  (`bench-baseline`/`bench-compare`) is unused in CI. Sequence after PERF-0032 (median).

**Won't-do / rejected (documented, not filed):** strip/LTO binary-size optimization — rejected
without profiling (no evidence the link-time cost is justified for this library; revisit only with a
measured binary-size or startup target).

**Branch audit-closure-2026-06-11 (Review 8 closure):** PERF-0024 (#167, d89e336),
PERF-0025 (#168, bbcc626), PERF-0027 (#170, 164043d+bbcc626), PERF-0031 (#180, 3ec9b9b),
PERF-0033 (#182, 2bf5251) **Closed**. PERF-0026 (#169), PERF-0028 (#177), PERF-0029 (#178),
PERF-0030 (#179), PERF-0032 (#181), PERF-0034 (#183) remain **Open/Deferred** — each requires
either a crossover measurement first (PERF-0026/0030), dedicated bench variants (PERF-0028/0029),
or wiring median into the loop before a trustworthy regression gate is feasible (PERF-0032/0034).

Overall status: **34 findings across 8 reviews. 28 closed; 6 open/deferred (PERF-0026, 0028-0030, 0032, 0034).**
PERF-0027 correctness question is resolved (safe); the issue was closed with the aliasing comment landed.

Key metrics from post-Review 4 benchmarks (`zig build bench`):

| Benchmark | Records | Time (ms) | Throughput | Notes |
|-----------|---------|-----------|------------|-------|
| append_64B_plain | 10,000 | 2.93 | 3,417,032 r/s | |
| append_1KB_plain | 5,000 | 10.14 | 492,954 r/s | |
| append_64KB_plain | 500 | 56.09 | 8,915 r/s | |
| append_64B_encrypted | 10,000 | 4.20 | 2,381,614 r/s | |
| append_1KB_encrypted | 5,000 | 12.12 | 412,699 r/s | |
| recovery_10k_plain | 10,000 | 3.47 | 2,885,321 r/s | |
| recovery_10k_encrypted | 10,000 | 10.19 | 981,322 r/s | |
| compact_5k_plain | 2,500 | 1.80 | 1,387,576 r/s | |
| compact_5k_encrypted | 2,500 | 2.57 | 974,106 r/s | |
| iterate_10k_plain | 10,000 | 38.63 | 258,860 r/s | |
| iterate_10k_encrypted | 10,000 | 33.36 | 299,756 r/s | PERF-0020 + 0021 (**2.3x**) |
| iterate_lsn_5k_plain | 5,000 | 11.63 | 429,814 r/s | |
| iterate_lsn_5k_enc | 5,000 | 13.72 | 364,541 r/s | PERF-0020 + 0021 (**4.1x**) |
| encrypt_64B | 50,000 | 5.28 | 9,464,855 r/s | |
| encrypt_1KB | 20,000 | 7.31 | 2,734,695 r/s | |
| decrypt_64B | 50,000 | 5.53 | 9,044,900 r/s | |
| decrypt_1KB | 20,000 | 7.52 | 2,660,385 r/s | |

Post-Review 4 improvements: PERF-0020 + PERF-0021 combined improved encrypted iteration from 133K → 300K r/s (**2.3x**) for full scans, and encrypted LSN-skip iteration from 88K → 365K r/s (**4.1x**). The reusable blob buffer (PERF-0020) eliminated per-record alloc/free/secureZero, and the 64KB buffered reader (PERF-0021) coalesced small syscalls into bulk reads.

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
| 11 | P2 | 64 | secureZero clears full 131KB stack buffers for any payload size | `encryption.zig` | Confirmed | [#107](https://gitlab.com/devnw/zig/wal/-/issues/107) | **Closed** |
| 12 | P3 | 24 | Iterator encrypted skip path dupes payload then immediately frees | `iterator.zig` | Confirmed | [#108](https://gitlab.com/devnw/zig/wal/-/issues/108) | **Closed** |
| 13 | P3 | 24 | Recovery scans entire file on every init — O(N) startup | `wal.zig` / `recovery.zig` | Suspected | [#109](https://gitlab.com/devnw/zig/wal/-/issues/109) | **Closed** |
| 14 | P3 | 20 | Compaction bulk-copy uses user-space loop instead of zero-copy | `compaction.zig` | Suspected | [#110](https://gitlab.com/devnw/zig/wal/-/issues/110) | **Closed** |
| 15 | Info | 8 | Benchmark suite missing iteration and over-measures decrypt overhead | `bench/main.zig` | Confirmed | [#111](https://gitlab.com/devnw/zig/wal/-/issues/111) | **Closed** |
| 16 | P3 | 24 | Recovery/compaction encrypted scan allocates blob per record | `recovery.zig` / `compaction.zig` / `encryption.zig` | Confirmed | [#112](https://gitlab.com/devnw/zig/wal/-/issues/112) | **Closed** |
| 17 | Info | 12 | Encrypt benchmark allocates per iteration, masks true AES-GCM throughput | `bench/main.zig` | Confirmed | [#113](https://gitlab.com/devnw/zig/wal/-/issues/113) | **Closed** |
| 18 | Info | 8 | Compaction scan makes getPos() syscall per record | `compaction.zig` | Confirmed | [#114](https://gitlab.com/devnw/zig/wal/-/issues/114) | **Closed** |
| 19 | Info | 8 | CI test-makefile job duplicates build+test cycle | `.gitlab-ci.yml` / `Makefile` | Confirmed | [#115](https://gitlab.com/devnw/zig/wal/-/issues/115) | **Closed** |
| 20 | P2 | 48 | Iterator encrypted path allocates blob per record (no reuse buffer) | `iterator.zig` / `encryption.zig` | Confirmed | [#116](https://gitlab.com/devnw/zig/wal/-/issues/116) | **Closed** |
| 21 | Info | 16 | Iterator uses unbuffered I/O — many small read syscalls per record | `iterator.zig` | Confirmed | [#117](https://gitlab.com/devnw/zig/wal/-/issues/117) | **Closed** |
| 22 | Info | 8 | CI pipeline does not cache Zig build artifacts (.zig-cache) | `.gitlab-ci.yml` | Confirmed | [#118](https://gitlab.com/devnw/zig/wal/-/issues/118) | **Closed** |
| 23 | P1 | 64 | truncateAfter: unbuffered 12-byte pread per record + full fsync (vs fdatasync) | `wal.zig` | Suspected | [#167](https://gitlab.com/devnw/zig/wal/-/issues/167) | **Closed** |
| 24 | P2 | 36 | Parallel batch triggers at N=2 with 5-7 allocs; no min-batch threshold | `wal.zig` | Suspected | [#169](https://gitlab.com/devnw/zig/wal/-/issues/169) | **Open** |
| 25 | P2 | 32 | Encrypted batch tail-scratch: proven safe across 200k shapes; comment/test only | `wal.zig` | Confirmed (safe) | [#170](https://gitlab.com/devnw/zig/wal/-/issues/170) | **Closed** |
| 26 | P3 | 8 | Double file.stat() on checkpoint init path | `recovery.zig` / `wal.zig` | Confirmed | [#168](https://gitlab.com/devnw/zig/wal/-/issues/168) | **Closed** |
| 27 | P1 | 64 | bench builds WAL module at Debug while bench exe is ReleaseFast — local numbers 3-10x off | `build.zig` / `Makefile` | Confirmed | [#180](https://gitlab.com/devnw/zig/wal/-/issues/180) | **Closed** |
| 28 | P2 | 64 | No write-side MAX_RECORD_SIZE / batch-byte cap — unbounded alloc + silent-truncation asymmetry | `wal.zig` / `record.zig` | Confirmed | [#182](https://gitlab.com/devnw/zig/wal/-/issues/182) | **Closed** |
| 29 | P2 | 36 | Checkpoint O(1) recovery path has no bench coverage | `bench/main.zig` | Confirmed | [#177](https://gitlab.com/devnw/zig/wal/-/issues/177) | **Open** |
| 30 | P2 | 36 | zero_copy_compaction path has no bench coverage | `bench/main.zig` | Confirmed | [#178](https://gitlab.com/devnw/zig/wal/-/issues/178) | **Open** |
| 31 | P2 | 36 | Thread-pool batch crossover never measured (scale_bench min batch=100) | `bench/scale_bench.zig` | Confirmed | [#179](https://gitlab.com/devnw/zig/wal/-/issues/179) | **Open** |
| 32 | P2 | 36 | scale_bench Tier.iterations never read — single-sample estimates, no variance | `bench/scale_bench.zig` | Confirmed | [#181](https://gitlab.com/devnw/zig/wal/-/issues/181) | **Open** |
| 33 | P3 | 24 | CI bench gate uses `bench` not `scale-bench`+`compare-bench` — no baseline comparison | `.gitlab-ci.yml` / `Makefile` | Confirmed | [#183](https://gitlab.com/devnw/zig/wal/-/issues/183) | **Open** |

> Rows 23-33 are Review 8 (2026-06-11) findings, **open / triage**. PerfScore = Impact x Likelihood x 4.
> PERF-0024/0026 confidence is scanner-level (first deep-review agent did not complete; no
> profiler/strace measurements captured). PERF-0027 (row 25) is **Confirmed safe** — the aliasing was
> proven across 200,006 batch shapes; the issue remains open only for the clarifying comment/test
> (proof recorded on #157). Rows 27-33 (PERF-0028..0034) are confirmed code facts; the *impact
> magnitude* is what the validation commands would measure. See per-finding sections below.

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

## Review 1 Implementation Summary

All 10 Review 1 findings have been resolved:

- **Quick wins** (PERF-0007, PERF-0010, PERF-0005): Seek-skip in iterator, fdatasync, single-alloc readPayloadAndVerify
- **Medium effort** (PERF-0001, PERF-0004, PERF-0002, PERF-0009): Stack-buffer encrypted writes, in-place decrypt, coalesced batch writes, CI caching
- **Strategic** (PERF-0006, PERF-0003, PERF-0008): Group-commit option, in-place decrypt for compaction/recovery, 256KB copy buffer

---

## Findings Detail — Review 2

> **Date:** 2026-03-22
> **Reviewer:** Adversarial performance code-review agent
> **Scope:** Full codebase (8 source modules, ~2,800 LOC), benchmarks, CI/CD, runtime assumptions
> **Baseline:** Zig 0.15.1 / ReleaseFast / Linux 6.17.0-19-generic / commit 9f1c73b (main)
> **Method:** Line-by-line manual review of all hot paths, measurement-backed where possible

### PERF-0011: secureZero clears full 131KB stack buffers for any payload size (P2, Score 64) — CLOSED

**Evidence:** `src/encryption.zig:262-268` — `encryptAndWriteToFile` stack path.

**Measurement (before):** `append_64B_encrypted` = 633,938 r/s.

**Resolution:** Changed `defer secureZero(&pt_buf)` → `defer secureZero(pt)` (where `pt = pt_buf[0..plaintext_len]`) and same for `enc_buf`. The unused buffer region is `undefined` (never written) — no residue to clear.

**Measurement (after):** `append_64B_encrypted` = 2,349,842 r/s (**3.7× improvement**). `append_1KB_encrypted` = 400,975 r/s (1.9× improvement).

**GitLab:** [#107](https://gitlab.com/devnw/zig/wal/-/issues/107)

---

### PERF-0012: Iterator encrypted skip path dupes payload then immediately frees (P3, Score 24) — CLOSED

**Evidence:** `src/iterator.zig` — `readEncryptedEntry` always duped payload even for records that would be immediately skipped by `from_lsn` check in `next()`.

**Resolution:** Moved LSN check into `readEncryptedEntry` before the payload dupe. For skipped records, the blob buffer is secureZero'd and freed directly without allocating a payload copy. The caller's skip path no longer needs to free anything. New `iterate_lsn_5k_enc` benchmark confirms the path works correctly.

**GitLab:** [#108](https://gitlab.com/devnw/zig/wal/-/issues/108)

---

### PERF-0013: Recovery scans entire file on every init — O(N) startup (P3, Score 24) — CLOSED

**Evidence:** `src/wal.zig:108-111` calls `recovery.recoverWithKey()` which scans from byte 0, validating every record (CRC or decrypt). Startup time is linear in file size.

**Measurement:** `recovery_10k_encrypted` = 47.75 ms for 10K records. Extrapolated: 1M encrypted records ≈ 4.8 seconds; 10M ≈ 48 seconds.

**Resolution:** Added checkpoint sidecar mechanism (`Options.checkpoint = true`). New `checkpoint.zig`
module writes a 28-byte `.ckpt` file (last_lsn, valid_end, record_count, CRC32) atomically during
clean `deinit()`. On `init()`, three paths: (1) exact match → O(1) skip scan, (2) file grew →
incremental scan from checkpoint position O(delta), (3) stale/missing → full scan fallback.
Checkpoint deleted after compaction (layout changed). New `recovery.recoverFrom()` and
`recoverFromWithKey()` support incremental recovery seeded from checkpoint state. 4 new
WAL-level tests + 4 incremental recovery tests + 6 checkpoint module tests.

**GitLab:** [#109](https://gitlab.com/devnw/zig/wal/-/issues/109)

---

### PERF-0014: Compaction bulk-copy uses user-space loop instead of zero-copy (P3, Score 20) — CLOSED

**Evidence:** `src/compaction.zig:217-225` — `read`/`writeAll` loop with 256 KB stack buffer copies data through user space. On Linux, `copy_file_range` could eliminate the copy.

**Measurement:** `compact_5k_plain` = 1.80 ms (2500 records, ~400 KB). Too small to see benefit.

**Resolution:** Added `Options.zero_copy_compaction = true` opt-in. New `zeroCopyTransfer()`
function in `compaction.zig` uses `std.os.linux.copy_file_range` for in-kernel data transfer
on Linux. Falls back to `userSpaceCopy()` (existing 256 KiB buffer loop) on non-Linux platforms
or when the syscall returns ENOSYS/EXDEV/EINVAL. Cross-platform safe: compiles and passes
cross-build for x86_64-macos and aarch64-linux. 3 new zero-copy compaction tests + 1 WAL-level
integration test.

**GitLab:** [#110](https://gitlab.com/devnw/zig/wal/-/issues/110)

---

### PERF-0015: Benchmark suite missing iteration and over-measures decrypt allocator overhead (Info, Score 8) — CLOSED

**Evidence:** `bench/main.zig` — no iteration benchmarks, decrypt benchmark used `allocator.dupe` per iteration mixing GPA overhead into AES-GCM measurement.

**Resolution:** Added 4 iteration benchmarks (`iterate_10k_plain`, `iterate_10k_encrypted`, `iterate_lsn_5k_plain`, `iterate_lsn_5k_enc`). Fixed decrypt benchmark to pre-allocate a reusable buffer with `@memcpy` instead of `allocator.dupe` per iteration.

**Measurement (before):** `decrypt_64B` = 244,796 r/s (GPA-dominated).
**Measurement (after):** `decrypt_64B` = 8,592,357 r/s (**35× — reveals true AES-GCM throughput**).

Benchmark suite now covers 17 measurements (was 13): append, recovery, compaction, iteration, encrypt, decrypt.

**GitLab:** [#111](https://gitlab.com/devnw/zig/wal/-/issues/111)

---

## Review 2 Triaged Non-Findings

1. **readPayloadAndVerify does 2 syscalls (payload + CRC):** The 4-byte CRC read is almost always served from the same page cache page as the payload. Recovery path already combines them. Negligible overhead.

2. **appendBatch single-record overhead:** `appendBatch` with 1 record allocates a buffer. This is expected API usage — callers should use `append()` for single records.

3. **Stack usage of 131KB in encryptAndWriteToFile:** Large but safe (default 8MB stack). The SEC-0009 security benefit of stack allocation (no heap residue) outweighs the stack pressure. Not a performance concern.

4. **CRC32 not hardware-accelerated:** Zig's `Crc32IsoHdlc` uses a table-based implementation. The polynomial (ISO-HDLC) differs from Intel's CRC32C instruction (Castagnoli), so hardware acceleration is not applicable. Not a finding.

5. **Iterator opens a new file handle per call:** By design — independent read cursor. The file open is a one-time cost per iteration session.

6. **CI pipeline parallelism:** All 9 test jobs are in the same `test` stage and run in parallel when runners are available. Already optimal.

## Review 2 Implementation Summary

All 5 Review 2 findings have been resolved:

- **Closed** (PERF-0011): secureZero scope reduction — **3.7× encrypted append improvement** (633K → 2,349K r/s for 64B)
- **Closed** (PERF-0012): Iterator skip-path alloc elimination — avoids unnecessary dupe+free for skipped encrypted records
- **Closed** (PERF-0015): Added 4 iteration benchmarks, fixed decrypt measurement — revealed **35× measurement artifact** (245K → 8.6M r/s)
- **Closed** (PERF-0013): O(1) recovery via checkpoint sidecar — opt-in `Options.checkpoint`, incremental recovery, full-scan fallback
- **Closed** (PERF-0014): Zero-copy compaction via `copy_file_range` — opt-in `Options.zero_copy_compaction`, Linux-only with user-space fallback

**Status (post-Review 2):** 15 findings across 2 reviews. **All 15 closed.**

---

## Findings Detail — Review 3

> **Date:** 2026-03-22
> **Reviewer:** Adversarial performance code-review agent
> **Scope:** Full codebase (8 source modules, ~2,800 LOC), benchmarks, CI/CD, build config
> **Baseline:** Zig 0.15.1 / ReleaseFast / Linux 6.17.0-19-generic / post-Review 2 code
> **Method:** Two parallel exploration agents + line-by-line manual review of all hot paths

### PERF-0016: Recovery/compaction encrypted scan allocates blob per record (P3, Score 24) — CLOSED

**Evidence:** `src/recovery.zig:115` and `src/compaction.zig:133` — both called `encryption.readEncryptedBlob(allocator, ...)` which allocated a fresh heap buffer per encrypted record during scan. For N encrypted records, this was N alloc/free cycles.

**Resolution:** Added `readEncryptedBlobReuse` in `encryption.zig` that accepts a caller-owned `*?[]u8`. Buffer is reused if large enough, grown otherwise. `secureZero` only the used portion before reuse. Both `recovery.zig` and `compaction.zig` scan loops updated to use loop-level defer instead of per-record defer — single cleanup after loop exit.

**Measurement (before):** `recovery_10k_encrypted` = 220,763 r/s, `compact_5k_encrypted` = 106,720 r/s.
**Measurement (after):** `recovery_10k_encrypted` = 2,108,554 r/s (**9.6×**), `compact_5k_encrypted` = 946,498 r/s (**8.9×**). The per-record secureZero + alloc/free overhead was far larger than the estimated 3% — the volatile zeroing dominated.

**GitLab:** [#112](https://gitlab.com/devnw/zig/wal/-/issues/112)

---

### PERF-0017: Encrypt benchmark allocates per iteration, masks true AES-GCM throughput (Info, Score 12) — CLOSED

**Evidence:** `bench/main.zig:275-279` — `runEncryptBench` called `encryptRecord(allocator, key, plaintext)` per iteration, allocating a new buffer each time. Same artifact that was fixed for decrypt in PERF-0015.

**Resolution:** Pre-allocated `reuse_buf` of size `ENCRYPTION_OVERHEAD + plaintext.len`, replaced per-iteration `encryptRecord` + `free` with `encryptInto(reuse_buf, key, plaintext)`. No alloc/free in timed loop.

**Measurement (before):** `encrypt_64B` = 247,444 r/s, `encrypt_1KB` = 228,176 r/s.
**Measurement (after):** `encrypt_64B` = 8,563,131 r/s (**35×**), `encrypt_1KB` = 2,358,983 r/s (**10×**). Encrypt and decrypt throughput are now symmetric as expected for AES-GCM.

**GitLab:** [#113](https://gitlab.com/devnw/zig/wal/-/issues/113)

---

### PERF-0018: Compaction scan makes getPos() syscall per record (Info, Score 8) — CLOSED

**Evidence:** `src/compaction.zig:124` — `const offset = try src.getPos()` in the scan loop made a `lseek(fd, 0, SEEK_CUR)` syscall per record.

**Resolution:** Replaced `try src.getPos()` with `var current_offset: u64 = 0` tracked locally. Offset is incremented by `blob_result.total_on_disk` (encrypted) or `header + payload + crc` (plaintext) after each scan iteration.

**Measurement:** Combined with PERF-0016. `compact_5k_plain` improved from 1,411,979 → 1,718,500 r/s (**1.2×**). `compact_5k_encrypted` improved from 106,720 → 946,498 r/s (dominated by PERF-0016 buffer reuse).

**GitLab:** [#114](https://gitlab.com/devnw/zig/wal/-/issues/114)

---

### PERF-0019: CI test-makefile job duplicates build+test cycle (Info, Score 8) — CLOSED

**Evidence:** `.gitlab-ci.yml:149` ran `make ci` which executes `clean + build + test` — duplicating the separate `build`, `test`, and `test-integration` jobs.

**Resolution:** Replaced `make ci` with `make dev` (fmt + check + test-unit) in the `test-makefile` CI job. This still validates that Makefile targets work but avoids the redundant clean+build+full-test cycle.

**GitLab:** [#115](https://gitlab.com/devnw/zig/wal/-/issues/115)

---

## Review 3 Triaged Non-Findings

1. **encryptAndWriteToFile heap path double allocation (>64KB payloads):** Two separate allocations for plaintext and ciphertext. Could be a single allocation with partition. But this is the cold path (>64KB payloads are rare by design), and both must exist simultaneously for the encrypt call. Peak memory is unchanged. Not worth the complexity.

2. **appendBatch encrypted secureZero on full buffer:** `secureZero(buf)` zeros the entire batch buffer. Analysis shows all plaintext scratch regions are overwritten by ciphertext before the buffer is freed (encryption output collectively covers the full buffer). The secureZero is defense-in-depth for ciphertext residue, not plaintext. Removing it would save volatile zeroing time but weaken defense-in-depth. Accepted security trade-off.

3. **CSPRNG nonce generation per encrypted record:** Each `encryptInto` call generates a 12-byte nonce via `std.crypto.random.bytes`. For batches, this is N getrandom syscalls. Could batch into one call. But nonce generation is ~100-200ns on Linux with vDSO, and AES-GCM encryption dominates. The syscall boundary is also a natural point for the security module — changing it adds API complexity. Not worth it.

4. **Recovery CRC verification two-pass hash:** CRC verification creates a new hash, updates with header, then updates with payload (two update calls because they're in separate buffers). Single-pass would require contiguous header+payload which would mean an extra memcpy. Two small hash updates is cheaper.

5. **Missing pread/pwrite for iterator:** Iterator opens a separate file handle. Could use pread on the main fd instead. But the separate handle prevents cursor interference with concurrent writes. Correct design choice.

6. **CI integration tests only run at Debug:** Only `test-debug` runs `zig build test-integration`. Release optimization jobs only run unit tests. This is a test coverage gap (quality concern, not performance). Filed separately if needed in QUALITY_GAP_ANALYSIS.md.

7. **Build.zig: module not reused across test steps:** Each test step creates a new module. But Zig's build system handles incremental compilation — the source is compiled once and cached. The module creation is a build-graph node, not a compilation. No real overhead.

## Review 3 Implementation Summary

All 4 Review 3 findings have been resolved:

- **Closed** (PERF-0016): Reusable buffer for encrypted scan — **9.6× encrypted recovery improvement** (221K → 2,109K r/s), **8.9× encrypted compaction** (107K → 946K r/s)
- **Closed** (PERF-0017): Encrypt benchmark fix — revealed **35× measurement artifact** (247K → 8,563K r/s), encrypt/decrypt now symmetric
- **Closed** (PERF-0018): Manual offset tracking in compaction — eliminated per-record `getPos()` syscall
- **Closed** (PERF-0019): CI test-makefile deduplication — replaced `make ci` with `make dev`

**Overall status (post-Review 3):** 19 findings across 3 reviews. 17 closed, 2 deferred, 0 open.

---

## Findings Detail — Review 4

> **Date:** 2026-03-22
> **Reviewer:** Adversarial performance code-review agent
> **Scope:** Full codebase (8 source modules, ~5,500 LOC including tests), benchmarks, CI/CD, build config
> **Baseline:** Zig 0.15.1 / ReleaseFast / Linux 6.17.0-19-generic / post-Review 3 code
> **Method:** Line-by-line manual review of all hot paths, syscall pattern analysis, CI structure review

### PERF-0020: Iterator encrypted path allocates blob per record (no reuse buffer) (P2, Score 48) — Closed

**Evidence:** `src/iterator.zig:156` — `readEncryptedEntry` calls `encryption.readEncryptedBlob(self.allocator, ...)` which heap-allocates a fresh buffer per encrypted record. Lines 186-187 secureZero and free per record. Recovery and compaction were fixed in PERF-0016 to use `readEncryptedBlobReuse`, but the iterator was not updated.

**Measurement:** `iterate_10k_encrypted` = 137,226 r/s (before). After fix: 299,756 r/s (**2.2×**). `iterate_lsn_5k_enc` = 88,310 r/s (before). After fix: 364,541 r/s (**4.1×**).

**Fix:** Added `reuse_buf: ?[]u8` field to Iterator struct. Replaced `readEncryptedBlob` with `readEncryptedBlobReuse` in `readEncryptedEntry`. Removed per-record secureZero+free of blob_buf. Reuse_buf freed in `deinit`.

**How to verify:** `zig build bench` — `iterate_10k_encrypted` improved from 133K → 300K r/s.

**Confidence:** Confirmed.

**GitLab:** [#116](https://gitlab.com/devnw/zig/wal/-/issues/116)

---

### PERF-0021: Iterator uses unbuffered I/O — many small read syscalls per record (Info, Score 16) — Closed

**Evidence:** `src/iterator.zig:67` reads 12-byte peek via `file.readAll`. Plaintext path then calls `readPayloadAndVerify` (record.zig:221-228) which does 2 more `readAll` calls (payload + 4-byte CRC). Encrypted path does 1 more `readAll` (blob remainder). Total: 3 syscalls/record (plaintext) or 2 syscalls/record (encrypted).

**Measurement:** Combined with PERF-0020 (measured together). Pre-fix encrypted iteration: 133K r/s. Post-fix: 300K r/s (combined 2.3×). Plaintext path measurement is mixed with the reusable buffer benefit, so isolated syscall impact is estimated at ~5-10%.

**Fix:** Wrapped iterator's file in `std.fs.File.Reader` with 64KB heap-allocated buffer. All reads now go through the buffered reader via `BufferedSource` wrapper. Changed shared read functions (`readEncryptedBlobReuse`, `readEncryptedBlob`, `readPayloadAndVerify`, `readHeaderRaw`) to accept `anytype` source parameter, enabling both `std.fs.File` (unbuffered, used by recovery/compaction) and `BufferedSource` (buffered, used by iterator) without API duplication. Replaced `seekBy` with `discardAll` through the buffer for plaintext skip path.

**How to verify:** `zig build test --summary all` — 79/79 pass. `zig build test-integration --summary all` — 25/25 pass. `zig build bench` shows improvement.

**Confidence:** Confirmed.

**GitLab:** [#117](https://gitlab.com/devnw/zig/wal/-/issues/117)

---

### PERF-0022: CI pipeline does not cache Zig build artifacts (.zig-cache) (Info, Score 8) — Closed

**Evidence:** `.gitlab-ci.yml:47-51` — cache only includes `zig-linux-x86_64-${ZIG_VERSION}/` (toolchain). The Zig build cache (`.zig-cache/`) is not cached. Each test job recompiles from scratch.

**Measurement:** 8 test jobs × ~10-15s compilation each = ~80-120s redundant compilation per pipeline.

**Fix:** Added `.zig-cache/` to the `.zig-cache` YAML anchor's cache paths in `.gitlab-ci.yml`.

**How to verify:** Compare pipeline duration before and after.

**Confidence:** Confirmed.

**GitLab:** [#118](https://gitlab.com/devnw/zig/wal/-/issues/118)

---

## Review 4 Triaged Non-Findings

1. **Iterator plaintext path: per-record heap allocation for payload is inherent.** The iterator API returns owned `Entry` values to callers. Recovery avoids heap allocation via stack buffers, but recovery discards payloads after validation — the iterator must return them. The payload dupe is irreducible given the API contract.

2. **appendBatch iterates payloads twice (size computation + serialization).** The first pass computes total buffer size with ~5ns per iteration (addition only). For 100 records: ~500ns. Negligible.

3. **No readv/writev for multi-field record reads.** Each record format field is read separately. The fields are small (12 bytes, payload, 4 bytes) and sequential — kernel page cache serves them from the same page. Scatter-gather I/O adds complexity without meaningful benefit.

4. **Cross-compilation CI job runs 4 targets sequentially.** Could be parallelized as 4 separate jobs. But each cross-build is ~5-10s; the parallelization saving (~15-30s) doesn't justify 4× more CI jobs and runner contention.

5. **CRC32 uses software table-based implementation.** Already triaged in Review 2: ISO-HDLC polynomial differs from Intel CRC32C instruction (Castagnoli). Hardware acceleration is not applicable.

6. **No batch/prefetch hint for sequential file reads.** Linux `readahead()` or `posix_fadvise(SEQUENTIAL)` could hint the kernel. But Zig's `std.fs.File` doesn't expose these, and modern kernels perform adaptive readahead for sequential access patterns anyway.

7. **encryptAndWriteToFile uses ~131KB stack.** Already triaged in Review 2: "Large but safe (default 8MB stack). The SEC-0009 security benefit of stack allocation outweighs the stack pressure."

8. **Recovery does full CRC verification on every record during init (PERF-0013).** Already Deferred: requires checkpoint/sidecar design change not justified at current scale.

9. **Compaction bulk-copy uses user-space loop (PERF-0014).** Already Deferred: `copy_file_range` adds Linux-specific complexity for negligible benefit at current WAL sizes.

## Review 4 Summary

3 new findings (PERF-0020 through PERF-0022), all **resolved and closed**:

- **PERF-0020** (Closed): Reusable buffer for iterator encrypted path — same optimization as PERF-0016, applied to the iterator module. Encrypted iteration improved 2.3×.
- **PERF-0021** (Closed): Buffered I/O for iterator via `std.fs.File.Reader` with 64KB buffer. Shared read functions changed to `anytype` for zero-duplication generics.
- **PERF-0022** (Closed): Added `.zig-cache/` to CI cache paths to avoid redundant recompilation.

**Overall status (post-Review 4):** 22 findings across 4 reviews. **20 closed, 2 deferred, 0 open.**

---

## Findings Detail — Review 5

> **Date:** 2026-03-22
> **Reviewer:** Adversarial performance code-review agent
> **Scope:** Full codebase (8 source modules, ~3,870 LOC), benchmarks, CI/CD, build config
> **Baseline:** Zig 0.15.2 / ReleaseFast / Linux 6.17.0-19-generic / post-Review 4 + QA fixes
> **Method:** Parallel exploration agent + line-by-line review of all hot paths

### Benchmark Baseline (Review 5)

| Benchmark | Records | Time (ms) | Throughput |
|-----------|---------|-----------|------------|
| append_64B_plain | 10,000 | 6.27 | 1,595,553 r/s |
| append_1KB_plain | 5,000 | 12.27 | 407,616 r/s |
| append_64KB_plain | 500 | 55.55 | 9,001 r/s |
| append_64B_encrypted | 10,000 | 4.15 | 2,411,151 r/s |
| append_1KB_encrypted | 5,000 | 12.15 | 411,588 r/s |
| recovery_10k_plain | 10,000 | 3.40 | 2,943,653 r/s |
| recovery_10k_encrypted | 10,000 | 5.27 | 1,898,520 r/s |
| compact_5k_plain | 2,500 | 1.47 | 1,697,470 r/s |
| compact_5k_encrypted | 2,500 | 2.56 | 975,206 r/s |
| iterate_10k_plain | 10,000 | 35.94 | 278,238 r/s |
| iterate_10k_encrypted | 10,000 | 33.01 | 302,930 r/s |
| iterate_lsn_5k_plain | 5,000 | 12.21 | 409,513 r/s |
| iterate_lsn_5k_enc | 5,000 | 13.99 | 357,498 r/s |
| encrypt_64B | 50,000 | 5.51 | 9,076,833 r/s |
| encrypt_1KB | 20,000 | 7.24 | 2,762,530 r/s |
| decrypt_64B | 50,000 | 5.67 | 8,810,871 r/s |
| decrypt_1KB | 20,000 | 7.54 | 2,653,945 r/s |

### Result: Zero New Findings

Systematic analysis of all 8 source modules, benchmarks, CI/CD pipeline, and build configuration found **no new actionable performance issues**.

### Review 5 Candidate Evaluated and Rejected

**Candidate: Compaction/recovery scan uses unbuffered I/O (contrast with Iterator PERF-0021 buffering)**

Evaluated whether compaction.zig and recovery.zig scan loops should adopt the same `BufferedSource` + 64KB buffer approach as iterator.zig (PERF-0021).

**Rejected because:**

1. **Plaintext path uses `seekBy()` which is purely a kernel lseek — no data transfer.** A buffered reader would read payload data into user-space memory only to discard it via `discardAll()`. This is strictly worse: disk I/O for data that `seekBy()` never touches.
2. **Encrypted path reads full blobs via `readEncryptedBlobReuse`** which handles its own buffer reuse. The read sizes (typically 60-200 bytes per blob) are small enough that page cache satisfies them without additional syscalls. Buffering would add complexity for negligible improvement.
3. **Benchmarks confirm performance is not syscall-bound:** `compact_5k_plain` = 1,697K r/s, `recovery_10k_plain` = 2,944K r/s — both near memory throughput limits for their data volumes.
4. **Iterator is different because it must return payload data to callers.** It reads every byte sequentially, making buffering essential. Compaction/recovery can skip bytes (plaintext seekBy) or reuse buffers (encrypted readEncryptedBlobReuse).

### Review 5 Non-Findings Triaged

In addition to all non-findings from Reviews 1-4 (which remain valid), the following were examined and confirmed as non-issues:

1. **Iterator `_done` flag checked per `next()` call:** Single boolean check, negligible.
2. **`encryption.secureZero` volatile writes:** Required by SEC-0009. Already scoped to used portions only (PERF-0011).
3. **`record.serialize` CRC computed over header+payload separately:** Two small hash updates cheaper than contiguous memcpy. Already triaged in Review 3.
4. **Build artifacts not shared across CI stages:** Zig's incremental compilation + `.zig-cache` sharing (PERF-0022) handles this.

## Review 5 Summary

**Zero new findings.** The codebase is performance-mature. All identified hot paths across 4 prior reviews have been addressed. The 2 deferred items (PERF-0013: O(N) recovery, PERF-0014: zero-copy compaction) remain appropriately deferred pending workload growth.

**Overall status (post-Review 5):** 22 findings across 5 reviews. **20 closed, 2 deferred, 0 open.**

---

## Findings Detail — Review 6

> **Date:** 2026-03-22
> **Reviewer:** Adversarial performance code-review agent
> **Scope:** Full codebase (8 source modules, ~3,870 LOC), benchmarks, CI/CD, build config
> **Baseline:** Zig 0.15.1 / ReleaseFast / Linux 6.17.0-19-generic / post-QA Review 5 fixes
> **Method:** Two parallel adversarial analysis agents (write path + encryption, read path + CI/build)

### Benchmark Baseline (Review 6)

| Benchmark | Records | Time (ms) | Throughput |
|-----------|---------|-----------|------------|
| append_64B_plain | 10,000 | 4.47 | 2,238,072 r/s |
| append_1KB_plain | 5,000 | 13.21 | 378,500 r/s |
| append_64KB_plain | 500 | 72.66 | 6,882 r/s |
| append_64B_encrypted | 10,000 | 9.09 | 1,099,831 r/s |
| append_1KB_encrypted | 5,000 | 12.41 | 402,993 r/s |
| recovery_10k_plain | 10,000 | 3.44 | 2,909,827 r/s |
| recovery_10k_encrypted | 10,000 | 4.82 | 2,074,686 r/s |
| compact_5k_plain | 2,500 | 1.84 | 1,355,613 r/s |
| compact_5k_encrypted | 2,500 | 2.61 | 958,310 r/s |
| iterate_10k_plain | 10,000 | 48.04 | 208,181 r/s |
| iterate_10k_encrypted | 10,000 | 33.73 | 296,465 r/s |
| iterate_lsn_5k_plain | 5,000 | 12.87 | 388,353 r/s |
| iterate_lsn_5k_enc | 5,000 | 13.56 | 368,596 r/s |
| encrypt_64B | 50,000 | 5.69 | 8,785,805 r/s |
| encrypt_1KB | 20,000 | 7.34 | 2,723,465 r/s |
| decrypt_64B | 50,000 | 5.44 | 9,197,036 r/s |
| decrypt_1KB | 20,000 | 7.54 | 2,653,877 r/s |

### Result: Zero New Findings

Systematic adversarial analysis of all 8 source modules, benchmarks, CI/CD pipeline, and build
configuration found **no new actionable performance issues**. Two parallel agents independently
reviewed write path + encryption and read path + CI/build, confirming all hot paths from 5 prior
reviews remain properly optimized.

### Review 6 Verification Points

1. **appendBatch encrypted buffer layout:** Confirmed safe. Scratch space calculation and in-place
   encryption destination layout verified. All plaintext scratch regions overwritten by ciphertext
   before buffer is freed.
2. **Sync counter logic:** Saturating add with `@intCast(payloads.len)` is safe — allocating 4B+
   payloads requires 32GB+ memory.
3. **CRC patterns:** `serializeInto` uses single-pass (contiguous); `readPayloadAndVerify` uses
   streaming init/update/final (separate sources). No redundancy.
4. **Iterator buffered I/O:** 64KB `BufferedSource` confirmed working correctly across all paths.
5. **Recovery/compaction reuse buffers:** `readEncryptedBlobReuse` confirmed in both scan loops.
6. **CI pipeline caching:** `.zig-cache/` and toolchain properly cached.

## Review 6 Summary

**Zero new findings.** Two consecutive zero-finding reviews (Reviews 5 and 6) confirm the codebase
is performance-mature. The 2 deferred items (PERF-0013: O(N) recovery, PERF-0014: zero-copy
compaction) remain appropriately deferred pending workload growth.

**Overall status (post-Review 6):** 22 findings across 6 reviews. **20 closed, 2 deferred, 0 open.**

---

## Findings Detail -- Review 7

> **Date:** 2026-03-22
> **Reviewer:** External perf-reviewer agent, scored and triaged by perf-issue-tracker agent
> **Scope:** Full codebase review results (6 candidates), cross-referenced against 22 existing PERF findings
> **Baseline:** Zig 0.15.2 / ReleaseFast / Linux 6.17.0-19-generic / post-Review 6 code

### PERF-0023: No CI bench stage for performance regression detection (P2, Score 48) — CLOSED

**Evidence:** `.gitlab-ci.yml` defines stages: `lint`, `build`, `test`, `security`, `sbom`. No `bench`
stage exists. The benchmark suite (`bench/main.zig`) covers 17 measurements but is only run manually
via `zig build bench`.

**Perf Impact:** Performance regressions can ship silently. Without automated regression gates,
improvements from PERF-0001 through PERF-0022 could be gradually eroded by normal development.

**Resolution:** Added `bench` stage to `.gitlab-ci.yml` between `test` and `security`. Runs
`zig build bench -Doptimize=ReleaseFast` with output captured as a 30-day artifact
(`bench-output.txt`). Starts with `allow_failure: true` to calibrate thresholds before
enforcing regressions. Job depends on `test` stage completing first.

**GitLab:** [#136](https://gitlab.com/devnw/zig/wal/-/issues/136)

### Review 7 Candidates Evaluated and Already Tracked

1. **Recovery unbuffered I/O (claimed P1):** Rejected. Explicitly evaluated and rejected in
   Review 5 (lines 564-572). Plaintext recovery uses `seekBy()` (kernel-only lseek, no data
   transfer), strictly better than buffered read+discard.
2. **`encryptAndWriteToFile` ~131KB stack (claimed P2):** Rejected. Triaged in Review 2 as
   non-finding: SEC-0009 security benefit of stack allocation outweighs stack pressure.
3. **`appendBatch` unbounded allocation (claimed P2):** Already resolved as PERF-0002.
4. **`readEncryptedBlobReuse` unnecessary zeroing (claimed P2):** Already resolved as PERF-0011.
   Remaining `secureZero` is SEC-0029 requirement.
5. **Encrypted compaction full-decrypt scan (claimed P2):** Already resolved as PERF-0003.
   Decrypting is inherent to the encrypted format (LSN inside ciphertext for confidentiality).

### Previously Deferred Items — Now Closed

- **PERF-0013** (#109): Implemented via `Options.checkpoint` and `checkpoint.zig` sidecar module. Closed.
- **PERF-0014** (#110): Implemented via `Options.zero_copy_compaction` with `copy_file_range(2)`. Closed.

## Review 7 Summary

1 new finding (PERF-0023), **closed**. 5 of 6 external candidates already tracked or triaged.

**Overall status (post-Review 7):** 23 findings across 7 reviews. **All 23 closed, 0 deferred, 0 open.**

---

## Review 8 Findings (2026-06-11) — OPEN

> **Confidence caveat:** the deep-review validation agent died mid-run. These findings carry
> **scanner-level confidence** unless a finding was independently confirmed by another domain's
> reviewer. **No profiler/strace/benchmark measurements were captured this session** — each
> finding's validation plan is the exact command that would confirm it.

### PERF-0024: truncateAfter unbuffered pread-per-record + full fsync (P1, Score 64) — OPEN

**Evidence:** `src/wal.zig:805-825` — scan loop issues one unbuffered `readPositionalAll` (12-byte
positional read) per record at `:806`. `src/wal.zig:829` — `self.file.sync(io)` is a full `fsync`,
while every other durable-write boundary uses `std.posix.fdatasync` (`:444` append, `:677`
appendBatch, `:698` sync()).

**Perf Impact:** ~1 `pread(12)` per record (~90K+ syscalls for a 100K-record WAL) plus an
unnecessary metadata flush via `fsync` on the truncate path.

**Root Cause:** truncateAfter uses a standalone hand-rolled forward scan instead of the buffered
recovery scan, and picked `fsync` over `fdatasync`.

**Fix Guidance:** **Rides on SEC-0041/#139** (truncateAfter rewrite). Route through the verified
buffered recovery scan (64KB `FileSource`, same as PERF-0021) to collapse the per-record preads, and
switch `:829` to `std.posix.fdatasync`. Do not land independently of #139.

**Validation Plan:** `strace -f -c -e trace=pread64,pread,fsync,fdatasync` over a 100K-record
`truncateAfter(0)`; expect pread count to drop from ~N to ~N/(64KB/record_size) and `fsync` → one
`fdatasync`.

**Confidence:** Suspected (syscall/fsync facts unambiguous in source; not measured this session).

**Cross-links:** #139 (SEC-0041). **GitLab:** [#167](https://gitlab.com/devnw/zig/wal/-/issues/167)

---

### PERF-0026: Parallel batch triggers at N=2 with 5-7 allocations, no min-batch threshold (P2, Score 36) — OPEN

**Evidence:** `src/wal.zig:554` — `use_parallel = self.options.thread_pool != null and
payloads.len > 1`. The parallel branch (`:556-599`) performs separate allocations for `offsets`,
`payload_ptrs`, `payload_lens`, and (encrypted) `pt_offsets_buf` + `pt_buf` — 5-7 allocator calls to
serialize as few as 2 records, plus thread-pool submit/waitgroup overhead.

**Perf Impact:** Small batches (N=2, N=3) very likely run *slower* in parallel than sequential, but
the crossover is unmeasured so the effective threshold is 1.

**Root Cause:** Trigger gated on "more than one record" as a placeholder, not on a measured crossover;
setup allocations not factored into the decision.

**Fix Guidance:** Add a `parallel_min_batch` threshold; gate `use_parallel` on
`payloads.len >= parallel_min_batch`. Determine the value with a crossover bench. Consider coalescing
the 3-5 setup allocations into one slab. **Pairs with PERF-0030 (crossover bench).**

**Validation Plan:** `zig build bench` with new `appendBatch_parallel_N{2,4,8,16,32,64,128}` vs
`appendBatch_seq_N{...}` cases (plaintext + encrypted); set threshold at the measured crossover.

**Confidence:** Suspected (trigger + alloc count confirmed in source; "parallel slower at small N" is
unmeasured).

**Cross-links:** PERF-0030 (to be tracked). **GitLab:** [#169](https://gitlab.com/devnw/zig/wal/-/issues/169)

---

### PERF-0027: Encrypted batch tail-scratch — investigated as a correctness bug, PROVEN SAFE (P2, Score 32) — OPEN (comment/test only)

**Evidence:** `src/wal.zig:646-648` — sequential encrypted batch encrypts in place using a tail
scratch region `pt_start = total_size - rec_size`. Existing encrypted-batch tests use only
uniform/near-uniform payload sizes: `src/wal.zig:1247` (`{"alpha","beta","gamma"}` 5/4/5 B),
`src/wal.zig:1912` (`{"secret1".."secret5"}` all 7 B), `tests/scenarios/encryption.zig:321` (uniform
large).

**Resolution — proven safe:** The perf reviewer investigated this as a possible data-corruption bug
(a scratch/destination collision on **non-uniform** payload sizes) and **proved it safe** by
exhaustively enumerating the scratch region against the running ciphertext destination across
**200,006 batch shapes** — every record count and payload distribution in the swept space, including
sharply non-uniform mixes. Result: **0 cross-record overlaps for any payload distribution.** The only
in-place aliasing is on the **last record**, where AES-GCM (CTR-mode) in-place encrypt with src==dst
is safe by construction. **No correctness escalation.** This independently confirms QA-0084/#157.

**Root Cause:** `pt_start` is computed per-record relative to `total_size`; the destination ciphertext
region for record `i` always sits before the tail scratch region that stages record `i`'s plaintext,
so they never overlap across heterogeneous sizes.

**Remaining work (low-cost, no code-correctness change):** (1) the 200k-shape proof has been recorded
as a **comment on #157** (the QA-0084 "add a clarifying comment" item); land that comment in source so
a future reader does not re-litigate it. (2) Optionally add a non-uniform-payload encrypted-batch
regression test (e.g. `{1B, 64KB, 1B, 32KB, 8B}`) as belt-and-suspenders. No separate scratch buffer
is needed — the allocation-saving tail-scratch trick stays.

**Validation Plan:** optional regression test `"encrypted batch: non-uniform payload sizes
(PERF-0027)"`; `zig build test -Doptimize=ReleaseSafe` and Debug — expected to pass (proof predicts no
corruption).

**Confidence:** **Confirmed safe** (200,006-shape exhaustive proof by the perf reviewer; equal-size
CTR safety also confirmed via QA-0084). The issue stays open only for the clarifying comment/test.

**Cross-links:** #157 (QA-0084 — 200k-shape proof recorded as a comment).
**GitLab:** [#170](https://gitlab.com/devnw/zig/wal/-/issues/170)

---

### PERF-0025: Double file.stat() on checkpoint init path (P3, Score 8) — OPEN

**Evidence:** `src/recovery.zig:107` stats the file (`if (stat.size < start.valid_end) return
error.CheckpointStale;`); `src/wal.zig:243` re-stats the same file to guard the incremental result
(`if (result.valid_end == ckpt.valid_end and stat.size > ckpt.valid_end)`).

**Perf Impact:** One redundant `fstat` per incremental-recovery `init()`. Negligible; tracked as a
correctness-of-design cleanup.

**Root Cause:** Recovery already has the size but does not return it, so the caller re-stats.

**Fix Guidance:** Return the size from recovery (add `file_size` to `RecoveryInfo`/`RecoveryResult`,
populated from the `:107` stat) and use `result.file_size` at `wal.zig:243`.

**Validation Plan:** `strace -f -e trace=fstat,statx zig build test -Dtest-filter="recover"`; expect
the fstat count on the incremental init path to drop by 1.

**Confidence:** Confirmed (both call sites and the data dependency are unambiguous).

**GitLab:** [#168](https://gitlab.com/devnw/zig/wal/-/issues/168)

---

### PERF-0028: Checkpoint O(1) recovery path has no benchmark coverage (P2, Score 36) — OPEN

**Evidence:** `bench/main.zig:188-215` (`runRecoveryBench`) opens with default `Options` (`checkpoint`
never set true), so the recovery bench always exercises the full O(N) scan, never the PERF-0013
incremental checkpoint fast path. `scale_bench.zig` `benchRecovery` has the same gap.

**Perf Impact:** The headline O(1) startup win is unmeasured and unguarded against regression.

**Fix Guidance:** Add `recovery_*_checkpoint` variants (`.checkpoint = true`, sync, close, re-open,
measure re-open) in both bench files with a checkpoint-vs-full-scan column.

**Confidence:** Confirmed. **GitLab:** [#177](https://gitlab.com/devnw/zig/wal/-/issues/177)

---

### PERF-0029: Zero-copy compaction path has no benchmark coverage (P2, Score 36) — OPEN

**Evidence:** `bench/main.zig:226-253` (`runCompactBench`) omits `.zero_copy_compaction = true`, so the
`copy_file_range` path (`compaction.zig:123-147`, PERF-0014) is never benchmarked — only the 256KB
user-space copy. `scale_bench.zig` `benchCompact` has the same gap.

**Perf Impact:** `copy_file_range` effectiveness unmeasured/unprotected against regression.

**Fix Guidance:** Add a `compact_*_zerocopy` tier gated on `builtin.os.tag == .linux`.

**Confidence:** Confirmed. **GitLab:** [#178](https://gitlab.com/devnw/zig/wal/-/issues/178)

---

### PERF-0030: Thread-pool batch crossover never measured; scale_bench min batch=100 (P2, Score 36) — OPEN

**Evidence:** `bench/scale_bench.zig:93-96` smallest tier is `batch_size = 100`; the small-N region
(2..64) where parallel dispatch+alloc overhead competes with the work saved is never sampled. The
`use_parallel` gate (`wal.zig:554`) was set with no empirical basis. Pairs with PERF-0026 (#169).

**Fix Guidance:** Add `benchBatchCrossover` sweeping `batch_size ∈ {1,2,4,8,16,32,64,128}` seq vs
parallel; use the crossover to set the PERF-0026 threshold.

**Confidence:** Confirmed. **GitLab:** [#179](https://gitlab.com/devnw/zig/wal/-/issues/179)

---

### PERF-0031: `zig build bench` builds WAL module at Debug while bench exe is ReleaseFast (P1, Score 56) — OPEN

**Evidence:** `build.zig:76-85` builds the `wal` module with the top-level `optimize` (defaults to
**Debug**); `build.zig:159-164` hardcodes the bench exe to `.ReleaseFast` but imports the Debug
module. `Makefile:37` runs `zig build bench` with no `-Doptimize`. CI is unaffected (passes
`-Doptimize=ReleaseFast`).

**Perf Impact:** Local `make bench` measures Debug-mode WAL — 3-10x slower — so developer baselines
diverge from CI and real regressions are indistinguishable from the optimization-level gap.

**Fix Guidance:** Force the WAL module to ReleaseFast for bench targets in `build.zig`, or make
`Makefile:37` pass `-Doptimize=ReleaseFast` (prefer the build.zig fix so it can't be forgotten).

**Confidence:** Confirmed. **GitLab:** [#180](https://gitlab.com/devnw/zig/wal/-/issues/180)

---

### PERF-0032: scale_bench `Tier.iterations` defined but never used; single-sample, no variance (P2, Score 32) — OPEN

**Evidence:** `bench/scale_bench.zig:88-96` declares and populates `iterations` but `grep` finds zero
reads. Every metric is a single sample; `TierResult` JSON carries no min/max/stddev; `compare-bench`
is point-to-point.

**Perf Impact:** A real 5-8% regression can be masked by single-run variance; noise can't be told from
a real slowdown. Weakens the `allow_failure: true` CI bench-regression gate.

**Fix Guidance:** Wire `iterations` into a repeat loop with median + min/max/stddev fields and a mean±2σ
compare threshold; for single-shot ops run ≥5 reps discarding the cold first run. Or delete the field
and document the single-sample limitation.

**Confidence:** Confirmed. **GitLab:** [#181](https://gitlab.com/devnw/zig/wal/-/issues/181)

---

### PERF-0033: appendBatch has no write-side MAX_RECORD_SIZE cap (P2, Score 40) — OPEN

**Evidence:** `src/wal.zig:530-540` sums `total_size` and does one contiguous `alloc` with no batch
cap; `src/record.zig:145-159` write-side serialize only panics at ~4 GiB `MAX_PAYLOAD_SIZE`. The
16 MiB `MAX_RECORD_SIZE` is enforced only on read/recovery (`record.zig:246`, `wal.zig:813`).

**Impact (perf + correctness):** (1) unbounded contiguous batch allocation (DoS-adjacent); (2)
write/read asymmetry — a >16 MiB record is writable but recovery silently rejects/truncates it on the
next `init` (ties into the silent-truncation gap QA-0079/#152).

**Fix Guidance:** Enforce `MAX_RECORD_SIZE` per record on write (`error.RecordTooLarge`) and add a
batch-byte cap, making write and read limits symmetric.

**Confidence:** Confirmed. **GitLab:** [#182](https://gitlab.com/devnw/zig/wal/-/issues/182)

---

### PERF-0034: CI bench-regression gate uses `bench` not `scale-bench` + `compare-bench` (P3, Score 24) — OPEN

**Evidence:** `.gitlab-ci.yml:205` runs `zig build bench -Doptimize=ReleaseFast` and captures
`bench-results.txt` as an artifact, but performs **no baseline comparison**. The regression tooling
that exists — `make bench-baseline` / `make bench-compare` driving `zig build scale-bench` →
`zig build compare-bench` (`Makefile:43-56`, which exits non-zero on regression) — is **not used in
CI**. So there is no automated gate; a slowdown only surfaces if a human reads the artifact.

**Perf Impact:** Performance regressions can ship undetected. The comparison machinery
(`bench/compare_bench.zig`) and a baseline are built but unwired in the pipeline.

**Fix Guidance:** Commit a `bench/results/baseline.json`, switch the CI bench job to
`scale-bench` → `compare-bench` (i.e. `make bench-compare`) so it fails on regression. **Sequence
after PERF-0032 (#181)** — point-to-point comparison of single samples is flaky until median is wired
in. Keep `allow_failure: true` only during threshold calibration, then flip it.

**Validation Plan:** `make bench-baseline`; introduce a deliberate slowdown; `make bench-compare`
should exit non-zero (regression detected).

**Confidence:** Confirmed (the CI job command and the unused compare tooling are unambiguous in
source).

**Cross-links:** PERF-0032 (#181, median first), PERF-0023 (#136, original bench-stage calibration).
**GitLab:** [#183](https://gitlab.com/devnw/zig/wal/-/issues/183)

---

## Roadmap

### Quick wins (< 1 day)

- **PERF-0025 (#168):** Return file size from recovery; drop the second `stat()` at `wal.zig:243`.
- **PERF-0027 (#170):** Land the QA-0084/#157 clarifying comment recording the 200k-shape safety proof;
  optionally add a non-uniform encrypted-batch regression test (no correctness fix needed — proven safe).
- **PERF-0031 (#180):** Force the WAL module to ReleaseFast for bench targets (fixes 3-10x misleading
  local bench numbers); fix `Makefile:37` too.
- **PERF-0034 (#183):** Wire CI bench job to `scale-bench` + `compare-bench` against a committed
  baseline (sequence after PERF-0032).

### Medium (1-5 days)

- **PERF-0024 (#167):** truncateAfter buffered scan + `fdatasync` — coupled to SEC-0041/#139; size is
  driven by that rewrite.
- **PERF-0026 (#169) + PERF-0030 (#179):** `parallel_min_batch` threshold — #179's crossover sweep
  produces the value #169 enforces.
- **PERF-0028 (#177) / PERF-0029 (#178):** Add checkpoint-O(1) and zero-copy-compaction bench coverage
  so the two strategic shipped optimizations are guarded against regression.
- **PERF-0032 (#181):** Wire `Tier.iterations` into a median repeat loop (or delete the field);
  prerequisite for a trustworthy PERF-0034 regression gate.
- **PERF-0033 (#182):** Enforce per-record `MAX_RECORD_SIZE` on write + a batch-byte cap
  (`error.RecordTooLarge`/`error.BatchTooLarge`); fixes the silent-truncation asymmetry. Has a
  correctness/security facet — expedite within the P2 band.

### Strategic (> 5 days)

- None new this review. Prior strategic items (checkpoints PERF-0013, zero-copy compaction PERF-0014)
  are implemented and closed.

### Blocked / dependency-gated

- **PERF-0024 (#167)** is gated on **SEC-0041 (#139)** and must land as part of that remediation.
- **PERF-0034 (#183)** is sequenced after **PERF-0032 (#181)** — the regression gate needs stable
  median measurements before point-to-point comparison is trustworthy.

## Review 8 Summary

**11 new findings (PERF-0024 through PERF-0034), all open / triage** — tracked as issues **#167–#170
and #177–#183**. Captured by an automated perf scan and a deep-review validation pass. Confidence is
`confirmed` for the code facts of PERF-0025 and PERF-0028..0034 (grep/source-verified);
PERF-0024/0026 are scanner-level pending measurement. No profiler/strace/benchmark numbers were
collected, so each finding ships with the exact verification command instead.

Notable resolution: **PERF-0027's tail-scratch aliasing was investigated as a possible correctness
bug and proven safe** — the perf reviewer brute-forced **200,006 batch shapes** (including non-uniform
mixes, huge-middle/first/last, and empty payloads) and found **0 cross-record scratch overlaps**. The
last record's CTR in-place aliasing is safe by construction. The 200k-shape proof was **recorded as a
comment on #157** (the QA-0084 "add a clarifying comment" item) rather than as a duplicate perf issue;
**no correctness escalation**. #170 stays open only for the comment/optional regression test.

**Findings by severity:** P1 — PERF-0024 (#167), PERF-0031 (#180). P2 — PERF-0026 (#169),
PERF-0027 (#170), PERF-0028 (#177), PERF-0029 (#178), PERF-0030 (#179), PERF-0032 (#181),
PERF-0033 (#182). P3 — PERF-0025 (#168), PERF-0034 (#183).

**PERF-ID → IID mapping (Review 8):** 0024→#167, 0025→#168, 0026→#169, 0027→#170, 0028→#177,
0029→#178, 0030→#179, 0031→#180, 0032→#181, 0033→#182, 0034→#183.

**Overall status (post-Review 8):** 34 findings across 8 reviews. **23 closed; 11 open
(PERF-0024..0034).**

**Dependencies / notes:**

- PERF-0024 (#167) is gated on SEC-0041 (#139) — the `truncateAfter` rewrite carries the buffered scan
  - `fdatasync` fix.
- PERF-0026 (#169) and PERF-0030 (#179) pair up: #179's crossover sweep produces the threshold #169
  needs.
- PERF-0033 (#182) has a correctness/security facet (write/read size asymmetry → silent truncation;
  unbounded batch allocation) and ties into QA-0079 (#152).
- PERF-0034 (#183) is sequenced after PERF-0032 (#181) — median measurements before enforcing the gate.
- **Rejected without profiling (won't-do, not filed):** adding `strip`/LTO binary-size optimization to
  bench/release builds — no measured binary-size or startup target justifies it; revisit only with
  evidence.
