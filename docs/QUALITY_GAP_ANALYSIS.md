# Quality Gap Analysis

> **Source of truth:** [GitLab Issues](https://gitlab.com/devnw/zig/wal/-/issues?label_name%5B%5D=quality)
> filtered by label `quality`. This file mirrors findings status.
>
> **Last updated:** 2026-06-11 (Review 7 + Review 15 closure — branch audit-closure-2026-06-11: QA-0069–QA-0084 all Closed)

## Summary

**84 findings** across 10 categories from eight comprehensive code-quality, maintainability, and performance reviews.

| Metric | Count |
|--------|-------|
| Total findings | 84 |
| Critical severity | 0 |
| High severity | 13 |
| Medium severity | 39 |
| Low severity | 29 |
| Info severity | 3 |
| Confirmed | 83 |
| Suspected | 1 |
| Open | 0 |
| Closed | 84 |

All Review 7 findings (QA-0074–QA-0084) and Review 15 findings (QA-0069–QA-0073) were implemented,
tested, and closed on branch `audit-closure-2026-06-11` (129 unit + 1 skip / 39 integration tests
pass; appsec/quality/perf re-reviews clean). See per-row commit references below.

## Stack-Ranked Findings (Review 15 — Closed)

PriorityScore = Impact(1–5) × Likelihood(1–5) × 4. Max = 100.

| # | ID | Score | Severity | Category | Confidence | Title | File(s) | Issue | Status |
|---|-----|-------|----------|----------|------------|-------|---------|-------|--------|
| 1 | QA-0069 | 8 | Low | Correctness | Confirmed | deinit hardcodes record_count=0 in checkpoint — structurally incorrect for non-empty WAL | wal.zig:304, recovery.zig:120-122 | [#142](https://gitlab.com/devnw/zig/wal/-/issues/142) | Closed (5c2006a) |
| 2 | QA-0070 | 8 | Low | Documentation | Confirmed | loadKeyFromEnv uses std.c.getenv — thread-safety caveat missing from doc comment | encryption.zig:468-471,478 | [#143](https://gitlab.com/devnw/zig/wal/-/issues/143) | Closed (5c2006a) |
| 3 | QA-0071 | 4 | Info | Readability | Confirmed | Two misleading code comments: encryption overlap threshold and iterator blob_buf lifecycle | encryption.zig:444, iterator.zig:141 | [#144](https://gitlab.com/devnw/zig/wal/-/issues/144) | Closed (5c2006a) |
| 4 | QA-0072 | 4 | Info | Documentation | Confirmed | CLAUDE.md states wrong RwLock type (std.Thread.RwLock) and stale test count (110/117) | CLAUDE.md:72,9 | [#145](https://gitlab.com/devnw/zig/wal/-/issues/145) | Closed (164043d+1dfd246) |
| 5 | QA-0073 | 4 | Info | Documentation | Confirmed | GAP_ANALYSIS_RESOLVED.md GAP-0003 cites test names replaced by SEC-0038 hardening | docs/GAP_ANALYSIS_RESOLVED.md:36-39 | [#146](https://gitlab.com/devnw/zig/wal/-/issues/146) | Closed (0df088b) |

### Review 15 Findings by Category

- **Correctness (1):** QA-0069 (checkpoint record_count hidden coupling).
- **Documentation (2):** QA-0070 (thread-safety caveat), QA-0072 (CLAUDE.md RwLock type + stale count), QA-0073 (stale GAP-0003 test names).
- **Readability (1):** QA-0071 (two misleading comments).

### Review 15 Methodology

**Manual review (branch audit-closure-2026-06-11):** Adversarial appsec + quality reviewer re-audited
the Zig 0.16-era codebase post-SEC-0041 remediation. Focus: documentation accuracy, checkpoint metadata
correctness, comment accuracy, and stale audit trail references. All 5 findings cross-referenced against
existing issues (QA-0001–QA-0068, SEC series) to avoid duplicates.

**Note:** These 5 findings were originally catalogued in the security-review audit (GAP_ANALYSIS.md
Review 15, sec review) and tracked as GitLab issues #142–#146. All were implemented and closed on
branch `audit-closure-2026-06-11`.

---

## Stack-Ranked Findings (Review 7 — Closed)

PriorityScore = Impact(1–5) × Likelihood(1–5) × 4. Max = 100.

| # | ID | Score | Severity | Category | Confidence | Title | File(s) | Issue | Status |
|---|-----|-------|----------|----------|------------|-------|---------|-------|--------|
| 1 | QA-0074 | 60 | High | CI/CD | Confirmed | build.zig.zon minimum_zig_version="0.15.1" but code requires Zig 0.16 (std.Io.*) | build.zig.zon:5, README.md:4 | [#147](https://gitlab.com/devnw/zig/wal/-/issues/147) | Closed |
| 2 | QA-0075 | 48 | High | Maintainability | Confirmed | observability seam hardcodes enabled=false; -Dwith_otel=true fails its own test and the seam is dead | src/observability.zig:33, tests/observability_disabled_test.zig:25 | [#148](https://gitlab.com/devnw/zig/wal/-/issues/148) | Closed |
| 3 | QA-0076 | 36 | Medium | CI/CD | Confirmed | pre-commit run --all-files fails — unstaged auto-fixes, 6× MD040 bare fences, 13× MD029 numbering | CONTRIBUTING.md:48, .gitlab/issue_templates/Bug Report.md:44, docs/superpowers/plans/2026-03-21-wal-library.md:15,37,67,1533, docs/SECURITY_REVIEW_NOTES.md | [#149](https://gitlab.com/devnw/zig/wal/-/issues/149) | Closed |
| 4 | QA-0077 | 36 | Medium | CI/CD | Confirmed | examples/basic.zig does not compile; example absent from CI; README Quick Start uses 0.15 idioms | examples/basic.zig:70, Makefile, .gitlab-ci.yml, README.md | [#150](https://gitlab.com/devnw/zig/wal/-/issues/150) | Closed |
| 5 | QA-0078 | 36 | Medium | Documentation | Confirmed | README claims "Zero dependencies" but build.zig.zon declares thread_pool (required) + otel (lazy) | README.md:22, build.zig.zon | [#151](https://gitlab.com/devnw/zig/wal/-/issues/151) | Closed |
| 6 | QA-0079 | 36 | Medium | Maintainability | Confirmed | Silent recovery truncation — no std.log anywhere in src/; startup data loss undiagnosable | recovery.zig:160,166,227-234, wal.zig:276 | [#152](https://gitlab.com/devnw/zig/wal/-/issues/152) | Closed |
| 7 | QA-0080 | 8 | Low | Maintainability | Confirmed | Timer + BenchTmpDir duplicated verbatim across bench entry points | bench/main.zig:20-75, bench/scale_bench.zig:27-82 | [#153](https://gitlab.com/devnw/zig/wal/-/issues/153) | Closed |
| 8 | QA-0081 | 4 | Low | Documentation | Confirmed | Copyright headers say 2024-2025 in all 24 .zig files; current year is 2026 | All 24 .zig files | [#154](https://gitlab.com/devnw/zig/wal/-/issues/154) | Closed |
| 9 | QA-0082 | 8 | Low | Documentation | Confirmed | QA-0055 Won't-Fix rationale claims 3-4 levels nesting; actual is 5-6 | docs/QUALITY_GAP_ANALYSIS.md (Review 4), iterator.zig:105-195 | [#155](https://gitlab.com/devnw/zig/wal/-/issues/155) | Closed |
| 10 | QA-0083 | 8 | Low | Cleanup | Confirmed | Dead `_ = std.c.lseek(...)` at compaction.zig:294; both copy paths are positional | compaction.zig:294 | [#156](https://gitlab.com/devnw/zig/wal/-/issues/156) | Closed |
| 11 | QA-0084 | 4 | Low | Readability | Confirmed | Sequential encrypted batch tail-scratch aliasing is correct but uncommented | wal.zig:646-648 (cf. encryption.zig:444-446) | [#157](https://gitlab.com/devnw/zig/wal/-/issues/157) | Closed |

### Review 7 Findings by Category

- **CI/CD (3):** QA-0074 (min Zig version), QA-0076 (pre-commit failures), QA-0077 (uncompiled/broken example).
- **Maintainability (2):** QA-0075 (dead otel seam), QA-0079 (silent truncation, no logging).
- **Documentation (3):** QA-0078 (false "zero dependencies"), QA-0081 (stale copyright year), QA-0082 (incorrect QA-0055 Won't-Fix rationale).
- **Cleanup (1):** QA-0083 (dead lseek).
- **Readability (1):** QA-0084 (uncommented intentional aliasing).

### Review 7 Roadmap

- **Quick wins (< 1 day):** QA-0074 (bump min Zig version), QA-0078 (fix README dependency claim), QA-0081 (copyright year), QA-0082 (amend rationale), QA-0083 (delete dead lseek), QA-0084 (add aliasing comment), QA-0080 (extract bench_common.zig).
- **Medium (1–5 days):** QA-0075 (restore otel conditional + verify under -Dwith_otel; file geode dedup tracking note), QA-0076 (fix pre-commit: fences, MD029, ruff/cz auto-fixes), QA-0077 (repair example, wire `zig build example` into CI, fix README snippet), QA-0079 (add std.log.warn on truncation + test).
- **Strategic (> 5 days):** none — all Review 7 findings are bounded.

### Review 7 Methodology

**Manual review:** Phase 3 quality-reviewer agent re-audited build/CI configuration, documentation accuracy,
the observability seam, recovery diagnosability, and bench duplication, with empirical verification of the
otel build-flag behavior (restoring `enabled = build_options.with_otel` passes 115/117, 2 skip) and the
encrypted `truncateAfter` data-loss reproduction. All findings cross-referenced against existing issues
(QA-0001–QA-0073, SEC-0041–SEC-0043) to avoid duplicates.

**Numbering note:** This review's internal numbering originally collided with the gap-pipeline IDs
QA-0069–QA-0073 (GitLab #142–#146, created the same day for unrelated appsec/docs items). The quality
findings were therefore **renumbered to start at QA-0074** to preserve global ID uniqueness. The mapping
from internal numbers to final IDs is: QA-0069→QA-0074, QA-0073→QA-0075, QA-0074→QA-0076, QA-0078→QA-0077,
QA-0079→QA-0078, QA-0080→QA-0079, QA-0075→QA-0080, QA-0076→QA-0081, QA-0081→QA-0082, QA-0082→QA-0083,
QA-0083→QA-0084.

**Comment-only updates (no new issue — folded into existing tracking):**

- **CLAUDE.md/README documentation drift** → consolidated onto **#145 (QA-0072)** via a scope comment.
  Full scope: CLAUDE.md:9,10,32-41,69,72 (counts 129 unit (+1 skip) / 39 integration, 11 modules, `std.Io.RwLock`)
  plus README:4 (Zig badge) and README:189 (stale counts). The `build.zig.zon` `minimum_zig_version`
  companion is tracked separately as QA-0074 (#147).
- **truncateAfter encrypted data-loss** (internally QA-0077) → root cause already tracked as
  **SEC-0041 (#139)**. Added an empirical-reproduction comment (encrypted WAL LSNs 1,2,3 +
  `truncateAfter(2)` → entire file truncated to 0 bytes, no error) and a **severity-escalation
  rationale (High — silent data loss, reviewer-reproduced)** rather than opening a duplicate.

## Stack-Ranked Findings (Review 6 — Closed)

PriorityScore = Impact(1-5) x Likelihood(1-5) x 4. Max = 100.

| # | ID | Score | Severity | Category | Confidence | Title | File(s) | Issue | Status |
|---|-----|-------|----------|----------|------------|-------|---------|-------|--------|
| 1 | QA-0068 | 48 | Medium | Documentation | Confirmed | README incorrectly states appendBatch always syncs at end | README.md:113, wal.zig:280-287 | [#138](https://gitlab.com/devnw/zig/wal/-/issues/138) | Closed |
| 2 | QA-0067 | 24 | Medium | API Contract | Confirmed | WriteAheadLog.filename stores borrowed slice, not owned copy | wal.zig:64,122,326,353,390 | [#137](https://gitlab.com/devnw/zig/wal/-/issues/137) | Closed |

### Review 6 Resolution Summary

2 findings: both implemented and closed.

**Implemented:**

- **QA-0068**: Corrected README to state that `appendBatch()` respects `sync_every_n` and `manual_sync` (same as `append()`), not "always syncs at the end"
- **QA-0067**: `WriteAheadLog.filename` now stores an owned copy (`allocator.dupe`) freed in `deinit()`, with `errdefer` cleanup in `init()`. Added unit test proving safety after caller frees the original slice. 80/80 unit tests pass (was 79).

### Review 6 Methodology

**Manual review:** Phase 3 quality-reviewer agent performed readability, architecture,
documentation, and edge-case analysis across all 8 modules. Findings cross-referenced
against existing 66 issues (QA-0001-QA-0066) to avoid duplicates.

**Positive observations (10):** Security defense-in-depth (key zeroization, errdefer
discipline, poisoned-WAL pattern), comptime assertions for format constants, consistent
CRC variant usage, well-documented security rationales (SEC-0xxx comments), and clean
module independence.

**Triaged during this review:**

- **R-1 (duplicate encrypted-vs-plaintext dispatch)**: Duplicate of QA-0050 (Won't Fix).
  Same root cause, same files. Architectural decision stands: scan loops have fundamentally
  different semantics; extraction would violate module independence.
- **E-2 (stale file_end after failed compaction)**: False positive. Compaction is atomic
  via `finalizeTempFile` (temp+fsync+rename). All error paths before rename leave the
  original file untouched, so `file_end` correctly reflects the original size.
- **14 Low findings**: Noted but not tracked as issues (various doc gaps, stack sizes,
  edge cases already covered by existing patterns or architectural decisions).

## Stack-Ranked Findings (Review 5 — Closed)

PriorityScore = Impact(1–5) × Likelihood(1–5) × 4. Max = 100.

| # | ID | Score | Severity | Category | Confidence | Title | File(s) | Issue | Status |
|---|-----|-------|----------|----------|------------|-------|---------|-------|--------|
| 1 | QA-0060 | 60 | Medium | CI/CD | Confirmed | Makefile missing 4 CI-parity targets (test-fuzz, test-all-optimizations, security-scan, release) | Makefile | [#129](https://gitlab.com/devnw/zig/wal/-/issues/129) | Closed |
| 2 | QA-0061 | 48 | Medium | Documentation | Confirmed | README Quick Start uses page_allocator and /tmp open pattern | README.md:58-61 | [#130](https://gitlab.com/devnw/zig/wal/-/issues/130) | Closed |
| 3 | QA-0062 | 36 | Medium | Documentation | Confirmed | README missing durability configuration documentation (sync options) | README.md | [#131](https://gitlab.com/devnw/zig/wal/-/issues/131) | Closed |
| 4 | QA-0063 | 36 | Medium | Documentation | Confirmed | README missing crash recovery behavior documentation | README.md | [#132](https://gitlab.com/devnw/zig/wal/-/issues/132) | Closed |
| 5 | QA-0064 | 32 | Medium | Documentation | Confirmed | README missing encryption key rotation requirement documentation | README.md | [#133](https://gitlab.com/devnw/zig/wal/-/issues/133) | Closed |
| 6 | QA-0065 | 32 | Medium | CI/CD | Confirmed | Makefile test-all-optimizations omits Debug optimization level | Makefile:73-78 | [#134](https://gitlab.com/devnw/zig/wal/-/issues/134) | Closed |
| 7 | QA-0066 | 8 | Low | Readability | Confirmed | Encryption offset constants not derived from field sizes | encryption.zig:65-69 | [#135](https://gitlab.com/devnw/zig/wal/-/issues/135) | Closed |

### Review 5 Resolution Summary

7 findings: all 7 implemented and closed.

**Implemented:**

- **QA-0060**: Added 4 Makefile targets (`test-fuzz`, `test-debug`, `security-scan`, `release`) for CI parity
- **QA-0061**: Replaced `page_allocator` with `GeneralPurposeAllocator` and `/tmp` with `"data"` dir in README Quick Start
- **QA-0062**: Added "Durability Configuration" section to README documenting `sync_every_n` and `manual_sync`
- **QA-0063**: Added "Crash Recovery" section to README documenting automatic recovery on init, CRC validation, truncation, LSN monotonicity
- **QA-0064**: Added "Key Management" section to README documenting single-key constraint, rotation procedure, zeroization
- **QA-0065**: Added `test-debug` target as first step in `test-all-optimizations` (all 4 optimization levels)
- **QA-0066**: Replaced hardcoded `OFF_*` constants with expressions derived from field sizes + `comptime` assertion

### Review 5 Methodology

**Automated checks:** `zig build test` (79 pass), `zig build test-integration` (25 pass), `zig fmt --check` (clean), `zig build check` (clean).

**Manual review:** Four parallel analysis agents covering readability/naming, CI/CD/build, test quality/documentation, and performance/memory. All findings cross-referenced against existing 59 issues (QA-0001–QA-0059) to avoid duplicates.

**Triaged during this review:**

- appendBatch encrypted buffer overlap (performance agent): Same false positive as SEC Reviews 2, 7, 12, 13 — already in Triaged False Positives section
- Recovery/compaction unbuffered I/O (performance agent): Evaluated and rejected in PERF Review 5 — infrequent operations, not worth buffering complexity
- Entry.deinit() on skipped iterator records (test agent): Skipped entries never reach caller; freeing an empty slice is a no-op
- Poison state persistence across instances (test agent): Poisoned is per-instance by design; covered by QA-0017
- build.zig.zon missing paths (CI agent): Intentional — `.paths` controls package distribution, not local development

## Stack-Ranked Findings (Review 4 — Closed)

PriorityScore = Impact(1–5) × Likelihood(1–5) × 4. Max = 100.

| # | ID | Score | Severity | Category | Confidence | Title | File(s) | Issue | Status |
|---|-----|-------|----------|----------|------------|-------|---------|-------|--------|
| 1 | QA-0050 | 64 | High | Maintainability | Confirmed | Scan loop duplication across recovery, compaction, and iterator modules | recovery.zig:110-184, compaction.zig:132-185, iterator.zig:105-188 | [#119](https://gitlab.com/devnw/zig/wal/-/issues/119) | Won't Fix |
| 2 | QA-0051 | 48 | High | Readability | Confirmed | Four functions exceed 50-line guideline (up to 140 lines) | compaction.zig:101-240, recovery.zig:88-191, iterator.zig:99-189, wal.zig:216-289 | [#120](https://gitlab.com/devnw/zig/wal/-/issues/120) | Won't Fix |
| 3 | QA-0053 | 36 | Medium | Architecture | Confirmed | Over-exposure of internal modules (record, encryption) in public API | root.zig:29-30 | [#122](https://gitlab.com/devnw/zig/wal/-/issues/122) | Closed |
| 4 | QA-0058 | 36 | Medium | CI/CD | Confirmed | Fuzz tests exist but are not integrated into CI pipeline | build.zig:66-79, tests/fuzz.zig | [#127](https://gitlab.com/devnw/zig/wal/-/issues/127) | Closed |
| 5 | QA-0052 | 32 | Medium | Maintainability | Confirmed | Parameter ordering inconsistency — allocator not first | record.zig:170, record.zig:206, encryption.zig:311 | [#121](https://gitlab.com/devnw/zig/wal/-/issues/121) | Closed |
| 6 | QA-0054 | 24 | Medium | Maintainability | Confirmed | Repeated `test_key` constant in recovery.zig and compaction.zig | recovery.zig:417, compaction.zig:386 | [#123](https://gitlab.com/devnw/zig/wal/-/issues/123) | Closed |
| 7 | QA-0055 | 24 | Medium | Readability | Confirmed | Deep nesting (5+ levels) in `iterator.next()` and `recovery.recoverWithKey()` | iterator.zig:99-189, recovery.zig:88-191 | [#124](https://gitlab.com/devnw/zig/wal/-/issues/124) | Won't Fix |
| 8 | QA-0057 | 20 | Low | Documentation | Confirmed | CLAUDE.md reports stale unit test count (70 vs actual 79) | CLAUDE.md | [#126](https://gitlab.com/devnw/zig/wal/-/issues/126) | Closed |
| 9 | QA-0056 | 16 | Low | Maintainability | Confirmed | Magic number 256 for `tmp_name_buf` in compaction.zig and atomic.zig | compaction.zig:109, atomic.zig:32 | [#125](https://gitlab.com/devnw/zig/wal/-/issues/125) | Closed |
| 10 | QA-0059 | 16 | Low | Architecture | Confirmed | Iterator struct fields expose implementation details without privacy signal | iterator.zig:38-57 | [#128](https://gitlab.com/devnw/zig/wal/-/issues/128) | Closed |

### Review 4 Resolution Summary

10 findings: 7 implemented and closed, 3 closed as Won't Fix.

**Implemented:**

- **QA-0052**: Swapped 3 function signatures + ~48 call sites to allocator-first parameter ordering
- **QA-0053**: Documented internal/unstable API surface in root.zig with convenience re-exports
- **QA-0054**: Deduplicated test_key — defined in encryption.zig, imported elsewhere
- **QA-0056**: Extracted shared TMP_NAME_BUF_SIZE constant from atomic.zig
- **QA-0057**: Updated stale test counts in CLAUDE.md (79 unit, 25 integration)
- **QA-0058**: Added test-fuzz CI job in .gitlab-ci.yml
- **QA-0059**: Prefixed Iterator private fields with underscore (_file,_done, _reuse_buf, _io_buf, _file_reader)

**Won't Fix (with architectural justification):**

- **QA-0050**: Scan loops share structural similarity but have fundamentally different semantics (recovery validates CRC, compaction skips CRC, iterator uses BufferedSource). Extracting a shared abstraction would violate "lower modules are independent" architecture and add coupling.
- **QA-0051**: Long functions are orchestrator functions whose length comes from inherent algorithmic complexity. Internal helpers already extracted where sensible.
- **QA-0055**: Accepted on cost grounds, not on guideline conformance. Re-measured (QA-0082, #155) the actual nesting in `iterator.next()` and `recovery.recoverWithKey()` is **5-6 indent levels**, driven by the error-classification `catch`-`switch` inside the encrypted-record branch — it exceeds the max-4 style guideline. Refactoring (e.g. extracting the encrypted-record arm into a helper) would reach ≤4 but is deferred; the prior "3-4 levels, within guideline" note was an inaccurate measurement and is corrected here.

## Stack-Ranked Findings (Review 3 — Closed)

PriorityScore = Impact(1–5) × Likelihood(1–5) × 4. Max = 100.

| # | ID | Score | Severity | Category | Confidence | Title | File(s) | Issue | Status |
|---|-----|-------|----------|----------|------------|-------|---------|-------|--------|
| 1 | QA-0032 | 80 | High | CI/CD | Confirmed | `zig build check` broken — missing `link_libc = true` in check step | build.zig:83-91 | [#81](https://gitlab.com/devnw/zig/wal/-/issues/81) | Closed |
| 2 | QA-0033 | 48 | High | CI/CD | Confirmed | Example not compiled by build system; missing from `make fmt` and pre-commit | build.zig, Makefile:50, .pre-commit-config.yaml:70 | [#82](https://gitlab.com/devnw/zig/wal/-/issues/82) | Closed |
| 3 | QA-0034 | 36 | High | Maintainability | Confirmed | `build.zig.zon` paths missing `NOTICE` file (Apache 2.0 Section 4(d)) | build.zig.zon:7-13 | [#83](https://gitlab.com/devnw/zig/wal/-/issues/83) | Closed |
| 4 | QA-0035 | 32 | Medium | Maintainability | Confirmed | Missing comptime assertion `DETECT_PEEK_SIZE == HEADER_SIZE` across 3 modules | iterator.zig, recovery.zig, compaction.zig | [#84](https://gitlab.com/devnw/zig/wal/-/issues/84) | Closed |
| 5 | QA-0036 | 32 | Medium | Correctness | Confirmed | `appends_since_sync` not reset after successful compaction | wal.zig:334 | [#85](https://gitlab.com/devnw/zig/wal/-/issues/85) | Closed |
| 6 | QA-0037 | 32 | Medium | Performance | Confirmed | Benchmark methodology — misleading compaction throughput and warmup contamination | bench/main.zig | [#86](https://gitlab.com/devnw/zig/wal/-/issues/86) | Closed |
| 7 | QA-0038 | 24 | Medium | Correctness | Confirmed | `verifyCrc` uses `debug.assert` instead of unconditional check (SEC-0025 inconsistency) | record.zig:280 | [#87](https://gitlab.com/devnw/zig/wal/-/issues/87) | Closed |
| 8 | QA-0039 | 24 | Medium | Tests | Confirmed | Crash scenario tests don't cover encrypted WAL torn writes | tests/scenarios/crash.zig | [#88](https://gitlab.com/devnw/zig/wal/-/issues/88) | Closed |
| 9 | QA-0040 | 24 | Medium | Tests | Confirmed | No test for `writeToFile` heap fallback path (payloads >64 KB) | record.zig | [#89](https://gitlab.com/devnw/zig/wal/-/issues/89) | Closed |
| 10 | QA-0041 | 24 | Medium | Tests | Confirmed | No dedicated test for `decryptRecordInPlace` round-trip | encryption.zig | [#90](https://gitlab.com/devnw/zig/wal/-/issues/90) | Closed |
| 11 | QA-0042 | 24 | Medium | Tests | Confirmed | No integration test for `sync()`/`manual_sync`/`sync_every_n` options | tests/integration.zig | [#91](https://gitlab.com/devnw/zig/wal/-/issues/91) | Closed |
| 12 | QA-0043 | 24 | Medium | Tests | Confirmed | Batch append integration test doesn't verify record contents | tests/integration.zig | [#92](https://gitlab.com/devnw/zig/wal/-/issues/92) | Closed |
| 13 | QA-0044 | 24 | Medium | CI/CD | Confirmed | Pre-commit `zig-fmt` hook missing `bench/` and `examples/` directories | .pre-commit-config.yaml:70 | [#93](https://gitlab.com/devnw/zig/wal/-/issues/93) | Closed |
| 14 | QA-0045 | 16 | Medium | Correctness | Confirmed | `MAX_PAYLOAD_SIZE` defined but never enforced; `@intCast` UB risk in release | record.zig:115-117 | [#94](https://gitlab.com/devnw/zig/wal/-/issues/94) | Closed |
| 15 | QA-0046 | 16 | Medium | CI/CD | Confirmed | CI pipeline missing `ReleaseSmall` optimization test | .gitlab-ci.yml | [#95](https://gitlab.com/devnw/zig/wal/-/issues/95) | Closed |
| 16 | QA-0047 | 16 | Medium | Tests | Confirmed | No test for `iterator(from_lsn)` with non-zero value in integration tests | tests/integration.zig | [#96](https://gitlab.com/devnw/zig/wal/-/issues/96) | Closed |
| 17 | QA-0048 | 12 | Low | Maintainability | Confirmed | Hand-rolled `secureZero` vs `std.crypto.secureZero` | encryption.zig:91-96 | [#97](https://gitlab.com/devnw/zig/wal/-/issues/97) | Closed |
| 18 | QA-0049 | 12 | Low | Documentation | Confirmed | CHANGELOG.md has duplicate and contradictory version sections | CHANGELOG.md | [#98](https://gitlab.com/devnw/zig/wal/-/issues/98) | Closed |

## Stack-Ranked Findings (Review 2 — Closed)

PriorityScore = Impact(1–5) × Likelihood(1–5) × 4. Max = 100.

| # | ID | Score | Severity | Category | Confidence | Title | File(s) | Issue | Status |
|---|-----|-------|----------|----------|------------|-------|---------|-------|--------|
| 1 | QA-0016 | 48 | High | Tests | Confirmed | Iterator module has zero unit tests | iterator.zig | [#65](https://gitlab.com/devnw/zig/wal/-/issues/65) | Closed |
| 2 | QA-0017 | 48 | High | Tests | Confirmed | Poisoned WAL state has no test coverage | wal.zig | [#66](https://gitlab.com/devnw/zig/wal/-/issues/66) | Closed |
| 3 | QA-0018 | 36 | High | Tests | Confirmed | Recovery module tests only cover plaintext records | recovery.zig | [#67](https://gitlab.com/devnw/zig/wal/-/issues/67) | Closed |
| 4 | QA-0021 | 24 | Medium | Tests | Confirmed | No tests for sync_every_n threshold behavior | wal.zig | [#70](https://gitlab.com/devnw/zig/wal/-/issues/70) | Closed |
| 5 | QA-0024 | 24 | Medium | Tests | Confirmed | No test for MAX_RECORD_SIZE defense (SEC-0004) | iterator.zig, recovery.zig | [#73](https://gitlab.com/devnw/zig/wal/-/issues/73) | Closed |
| 6 | QA-0025 | 24 | Medium | Tests | Confirmed | Compaction unit tests missing encrypted WAL scenarios | compaction.zig | [#74](https://gitlab.com/devnw/zig/wal/-/issues/74) | Closed |
| 7 | QA-0019 | 20 | Medium | Documentation | Confirmed | docs/README.md references 5 non-existent documentation files | docs/README.md | [#68](https://gitlab.com/devnw/zig/wal/-/issues/68) | Closed |
| 8 | QA-0020 | 20 | Medium | Documentation | Confirmed | README.md contains placeholder hash in installation example | README.md | [#69](https://gitlab.com/devnw/zig/wal/-/issues/69) | Closed |
| 9 | QA-0023 | 20 | Medium | Documentation | Confirmed | Example build instructions use invalid Zig 0.15 CLI syntax | examples/basic.zig | [#72](https://gitlab.com/devnw/zig/wal/-/issues/72) | Closed |
| 10 | QA-0022 | 16 | Medium | Maintainability | Confirmed | STACK_READ_THRESHOLD defined locally in recovery.zig instead of shared | recovery.zig:34, record.zig:45 | [#71](https://gitlab.com/devnw/zig/wal/-/issues/71) | Closed |
| 11 | QA-0028 | 12 | Low | Maintainability | Confirmed | Compaction temp file create/sync/rename pattern duplicated | compaction.zig:152-206 | [#77](https://gitlab.com/devnw/zig/wal/-/issues/77) | Closed |
| 12 | QA-0027 | 12 | Low | Maintainability | Confirmed | Recovery file position guarantee is implicit, not explicit | recovery.zig:62-63,172 | [#76](https://gitlab.com/devnw/zig/wal/-/issues/76) | Closed |
| 13 | QA-0029 | 8 | Low | Performance | Confirmed | Benchmark lacks isolated encryption throughput measurement | bench/main.zig | [#78](https://gitlab.com/devnw/zig/wal/-/issues/78) | Closed |
| 14 | QA-0030 | 8 | Low | CI/CD | Confirmed | Makefile targets not exercised in CI pipeline | .gitlab-ci.yml, Makefile | [#79](https://gitlab.com/devnw/zig/wal/-/issues/79) | Closed |
| 15 | QA-0026 | 4 | Low | Documentation | Confirmed | CHANGELOG.md contains placeholder release date | CHANGELOG.md:18 | [#75](https://gitlab.com/devnw/zig/wal/-/issues/75) | Closed |
| 16 | QA-0031 | 4 | Low | Maintainability | Suspected | 32-bit usize overflow in record size guard | record.zig:44 | [#80](https://gitlab.com/devnw/zig/wal/-/issues/80) | Closed |

## Stack-Ranked Findings (Review 1 — Closed)

| # | ID | Score | Severity | Category | Confidence | Title | File(s) | Issue | Status |
|---|-----|-------|----------|----------|------------|-------|---------|-------|--------|
| 1 | QA-0002 | 48 | High | Maintainability | Confirmed | Duplicated encrypted record detection/parsing across 4 modules | wal.zig, recovery.zig, compaction.zig, encryption.zig | [#50](https://gitlab.com/devnw/zig/wal/-/issues/50) | Closed |
| 2 | QA-0008 | 48 | High | Correctness | Confirmed | Double-free in `readPayloadAndVerify` on CRC mismatch — `errdefer` + manual free | record.zig:247-249 | [#57](https://gitlab.com/devnw/zig/wal/-/issues/57) | Closed |
| 3 | QA-0011 | 36 | High | Testing/CI | Confirmed | CI pipeline only tests at ReleaseSafe; missing ReleaseFast and Debug | .gitlab-ci.yml:91-100 | [#51](https://gitlab.com/devnw/zig/wal/-/issues/51) | Closed |
| 4 | QA-0001 | 32 | Medium | Readability | Confirmed | `wal.zig` at 1039 lines — extract Iterator into own module | wal.zig | [#52](https://gitlab.com/devnw/zig/wal/-/issues/52) | Closed |
| 5 | QA-0006 | 24 | Medium | Maintainability | Confirmed | `STACK_WRITE_THRESHOLD` duplicated between `record.zig` and `encryption.zig` | record.zig:44, encryption.zig:226 | [#53](https://gitlab.com/devnw/zig/wal/-/issues/53) | Closed |
| 6 | QA-0010 | 24 | Medium | Maintainability | Confirmed | Duplicated file reopen logic in `compact()` error and success paths | wal.zig:322-342 | [#54](https://gitlab.com/devnw/zig/wal/-/issues/54) | Closed |
| 7 | QA-0009 | 24 | Medium | CI/CD | Confirmed | CI installs `curl`/`xz-utils` via `apt-get` on every uncached run | .gitlab-ci.yml:37-38 | [#55](https://gitlab.com/devnw/zig/wal/-/issues/55) | Closed |
| 8 | QA-0014 | 16 | Low | Maintainability | Confirmed | Magic number `12` repeated across encrypted record detection code | recovery.zig, compaction.zig, wal.zig | [#59](https://gitlab.com/devnw/zig/wal/-/issues/59) | Closed |
| 9 | QA-0004 | 12 | Low | Cleanup | Confirmed | Unused `readHeader` function in `record.zig` (dead code) | record.zig:189-198 | [#56](https://gitlab.com/devnw/zig/wal/-/issues/56) | Closed |
| 10 | QA-0012 | 12 | Low | Performance | Confirmed | Benchmark uses `std.heap.page_allocator` — masks true WAL throughput | bench/main.zig:44 | [#58](https://gitlab.com/devnw/zig/wal/-/issues/58) | Closed |
| 11 | QA-0003 | 8 | Low | Maintainability | Confirmed | `encryptIntoSlice` trivial one-line wrapper | encryption.zig:167-169 | [#60](https://gitlab.com/devnw/zig/wal/-/issues/60) | Closed |
| 12 | QA-0005 | 8 | Low | Maintainability | Confirmed | Redundant local `@import("record.zig")` in `encryptAndWriteToFile` | encryption.zig:186 | [#61](https://gitlab.com/devnw/zig/wal/-/issues/61) | Closed |
| 13 | QA-0015 | 8 | Low | Maintainability | Confirmed | `verifyCrc` helper in `recovery.zig` logically belongs in `record.zig` | recovery.zig:204-216 | [#62](https://gitlab.com/devnw/zig/wal/-/issues/62) | Closed |
| 14 | QA-0007 | 8 | Low | Testing | Confirmed | No test coverage for `FilenameTooLong` error in compaction | compaction.zig:81-82 | [#63](https://gitlab.com/devnw/zig/wal/-/issues/63) | Closed |
| 15 | QA-0013 | 8 | Low | Documentation | Confirmed | Several public structs have undocumented fields | wal.zig, record.zig | [#64](https://gitlab.com/devnw/zig/wal/-/issues/64) | Closed |

## Triaged False Positives

The following were flagged during review but confirmed as not-issues:

1. **appendBatch encrypted buffer overlap (flagged as Critical)**: The plaintext scratch region and ciphertext destination overlap in the second+ iteration of multi-record encrypted batches. Verified as a **false positive**: AES-GCM in CTR mode uses XOR-based block encryption where `dst == src` is the standard in-place pattern. Zig's `Aes256Gcm.encrypt` processes blocks sequentially (read src block, XOR with keystream, write to dst block), making same-pointer aliasing safe. Previously triaged in SECURITY_REVIEW_NOTES.md.

2. **Magic bytes format detection collision**: Theoretical false positive where a plaintext record could match the "ZIGWALE\0" magic pattern. Requires LSN upper bits = 0x5A494757 and payload_len = 0x00454C41 (~4.3 MB). Extremely unlikely in practice and only affects iterator behavior when encryption_key is non-null but the record is plaintext — an internally inconsistent state. Accepted risk.

3. **Integration/scenario tests missing `link_libc`** (Review 3 — rejected): Flagged by automated scan because the unit test step has `.link_libc = true` and integration/scenario steps do not. However, libc is only required for `extern "c" fn setenv` in encryption.zig test blocks, which are not compiled when importing `wal` as a module dependency. Integration tests pass successfully without `link_libc`. False positive.

## Codebase Metrics

| Metric | Value |
|--------|-------|
| Total source lines (src/) | ~3,870 (includes colocated unit tests) |
| Total test lines (tests/ + bench/) | ~1,540 |
| Test-to-source ratio | 0.40 |
| Unit tests | 129 pass + 1 skip (per branch audit-closure-2026-06-11; verify with `zig build test`) |
| Integration + scenario tests | 39 passing (per Review 7) |
| Largest file | `wal.zig` (~966 lines) |
| Modules | 11 (root, wal, record, recovery, compaction, encryption, atomic, iterator, checkpoint, observability, observability_init) |
| Modules with zero unit tests | 0 |
