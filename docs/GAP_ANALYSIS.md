# Gap Analysis

> **Source of truth:** [GitLab Issues](https://gitlab.com/devnw/zig/wal/-/issues?label_name%5B%5D=security)
> filtered by label `security`. This file mirrors findings status.
>
> **Last updated:** 2026-03-30 (Parallelism & concurrency gap analysis + spice integration review)

## Summary

Fourteen adversarial code reviews have been performed on this codebase.

**Review 1** (2026-03-21): 7 findings (SEC-0001 through SEC-0007). All 7 have been
**resolved and closed**. Primary themes: cryptographic hygiene (empty AAD, key
zeroization) and defensive parsing (unbounded allocation, overlapping buffers).

**Review 2** (2026-03-21): 11 additional findings (SEC-0008 through SEC-0018). 9 have
been **resolved and closed**, 2 marked **Won't Do** (CI/CD and pre-commit concerns
handled via separate controls). Primary themes: error-path robustness, plaintext
residue zeroization, CI/CD supply chain, and defense-in-depth hardening.

**Review 3** (2026-03-21): 5 additional findings (SEC-0019 through SEC-0023). All 5 have
been **resolved and closed**. Primary themes: residual plaintext zeroization gaps in batch
path, filesystem durability (directory fsync), file permission tightening on open, and
defensive validation in recovery and release builds.

**Review 4** (2026-03-21): 5 additional findings (SEC-0024 through SEC-0028). All 5 have
been **resolved and closed**. Primary themes: iterator plaintext residue, release-mode
buffer validation gaps, stack key material hygiene, compaction CRC skip documentation,
and sync policy consistency.

**Review 5** (2026-03-21): 3 additional findings (SEC-0029 through SEC-0031). All 3 have
been **resolved and closed**. Primary themes: missed zeroization in recovery/compaction
decryption buffers (same root cause as SEC-0024), LSN pre-increment before write
durability, and theoretical sync counter overflow.

**Review 6** (2026-03-21): 1 additional finding (SEC-0032). It has been
**resolved and closed**. Primary theme: double-free in Iterator encrypted
error paths introduced by SEC-0024 remediation.

**Review 7** (2026-03-22): **Zero new findings.** Comprehensive adversarial review
covering cryptographic correctness (AES-256-GCM nonce management, AAD binding, key
lifecycle, in-place decryption), memory safety (double-free, use-after-free, integer
overflow, buffer overflow, errdefer patterns), denial-of-service (crafted inputs,
infinite loops, resource exhaustion), and CI/CD pipeline security. Four parallel
analysis passes (crypto, memory safety, DoS/input validation, CI/CD). Two candidate
findings were evaluated and rejected as duplicates of previously triaged false
positives (appendBatch buffer overlap, magic byte detection collision). Automated scans
(gitleaks, trufflehog, semgrep) confirmed zero secrets/vulnerabilities.

**Review 8** (2026-03-22): 2 new findings (SEC-0033, SEC-0034). Both have been
**resolved and closed**. Full-scope security and delivery-pipeline review with 4
parallel adversarial analysis agents (crypto, memory safety, DoS/input validation,
CI/CD supply chain) and 6 automated scanners (gitleaks, trufflehog, semgrep, trivy
fs+config, checkov — all zero findings). SEC-0033 identified an integer overflow in
the encrypted blob_len `@intCast` when payloads approach u32 max (~4 GiB); fixed with
pre-`@intCast` bounds checks and a new `PayloadTooLarge` error. SEC-0034 identified
unanchored regex patterns in the gitleaks allowlist; fixed with directory-boundary
anchoring.

**Review 9** (2026-03-22): 1 new finding (SEC-0035). Full adversarial code review and
delivery-pipeline review with 4 parallel analysis agents (crypto, memory safety,
DoS/input validation, CI/CD supply chain) and 6 automated scanners (gitleaks 8.30.0,
trufflehog 3.92.5, semgrep 1.150.0, trivy 0.69.0, checkov 3.2.499 — all zero
findings). checkov passed all 13 GitLab CI checks. SEC-0035 identified a double-close
on file descriptors in `finalizeTempFile` and `atomicWriteFile` when `rename()` fails
after the fd is already closed — triggering `unreachable` (UB in release builds). Three
additional candidate findings triaged as non-issues (decrypt-path @intCast bounded by
MAX_RECORD_SIZE, batch sync counter cast infeasible to overflow, total_size sum overflow
impossible on 64-bit). Six CI/CD candidates triaged as Won't Do or non-security issues.
Confirmed all 34 prior findings remain correctly remediated.

**Review 10** (2026-03-22): 2 new findings (SEC-0036, SEC-0037). Both have been
**resolved and closed**. Full adversarial code review and delivery-pipeline review with
4 parallel analysis agents (crypto, memory safety, DoS/input validation, CI/CD supply
chain) and 6 automated scanners (gitleaks 8.30.0, trufflehog 3.92.5, semgrep 1.150.0,
trivy 0.69.0, checkov 3.2.499 — all zero findings). SEC-0036 identified a missed
plaintext zeroization in the iterator's encrypted record skip path — when a decrypted
record's LSN is below `from_lsn`, the duped payload is freed without `secureZero` (same
class as SEC-0024/SEC-0029); fixed with `encryption.secureZero` before free. SEC-0037
identified a double-close on a stale fd in `deinit` when `reopenOrPoison` fails to
reopen the file after `compact()` closes it — same CWE as SEC-0035 but a different root
cause (poisoned state retains the stale closed fd); fixed with a `poisoned` guard in
`deinit` and fd-close-before-poison invariant in `reopenOrPoison`. Two additional
candidates triaged as non-issues (sync_every_n=0 previously triaged as harmless, seekBy
i64 cast guard-dependent but safe). Confirmed all 35 prior findings remain correctly
remediated.

**Review 11** (2026-03-22): 3 new findings (SEC-0038, SEC-0039, SEC-0040). All 3 have
been **resolved and closed**. Full-scope adversarial security review and
delivery-pipeline review with 8 automated scanners (gitleaks 8.30.0, trufflehog
3.92.5, semgrep 1.150.0, trivy 0.69.0 fs+config, syft 1.41.1 + grype 0.107.0,
osv-scanner 2.3.2, shellcheck 0.9.0 — all zero application-level findings). SEC-0038
identified a cryptographic downgrade where encrypted WAL mode silently accepted
plaintext record injection; fixed by rejecting records that lack encryption magic when
a key is configured in recovery, iteration, and compaction. SEC-0039 identified
unguarded `@intCast` overflow in `decryptRecord` and `decryptRecordInPlace`; fixed
with bounds checks before cast. SEC-0040 identified the absence of fuzz testing; fixed
by adding `std.testing.fuzz` targets for all binary parsing entrypoints. One additional
candidate finding triaged as a non-issue. Confirmed all 37 prior findings remain
correctly remediated.

**Review 12** (2026-03-22): **Zero new findings.** Full-scope adversarial security review
and delivery-pipeline review with 8 automated scanners (gitleaks 8.30.0, trufflehog
3.92.5, semgrep 1.150.0, trivy 0.69.0 fs+config, syft 1.41.1 + grype 0.107.0,
osv-scanner 2.3.2, shellcheck 0.9.0 — all zero application-level findings). Four
parallel manual adversarial analysis agents (crypto, memory safety, DoS/input
validation, CI/CD supply chain) identified zero new genuine findings. All candidate
findings were triaged as either false positives (appendBatch buffer overlap, iterator
seekBy loop, atomicWriteFile filename validation) or duplicates of previously
established Won't Do items (CI toolchain hash pinning, apt version pinning, CI
component SHA pinning, pre-commit hook enforcement). Confirmed all 40 prior findings
remain correctly remediated.

**Review 13** (2026-03-22): **Zero new findings.** Full-scope adversarial security review
and delivery-pipeline review with 7 automated scanners (gitleaks 8.30.0, trufflehog
3.92.5, semgrep 1.150.0, trivy 0.69.0 fs+config, checkov 3.2.499 — all zero findings).
Four parallel manual adversarial analysis agents (crypto, memory safety, DoS/input
validation, CI/CD supply chain) identified zero new genuine findings. All candidate
findings were triaged as either false positives (appendBatch buffer overlap — previously
triaged in Reviews 2, 7, and 12) or duplicates of previously established Won't Do items
(CI toolchain hash pinning). Additional manual grep verification of all `@intCast`,
`@truncate`, `@panic`, and `@unreachable` sites confirmed all are properly guarded.
Confirmed all 40 prior findings remain correctly remediated.

**Review 14** (2026-03-22): **Zero new findings.** Deep adversarial security review
identified 1 Medium, 6 Low, and 2 Informational findings -- all previously tracked under
existing SEC IDs (SEC-0004, SEC-0005, SEC-0007, SEC-0009, SEC-0011, SEC-0018, SEC-0020,
SEC-0026, SEC-0029). F-1 (TOCTOU in temp file creation) confirmed as SEC-0011 -- no fix
available in Zig std without O_TMPFILE+linkat. Won't Do items SEC-0014 and SEC-0016
confirmed correctly scoped out. Three consecutive zero-new-finding reviews (Reviews 12,
13, and 14) confirm convergence.

Automated scans (gitleaks, trufflehog, semgrep, trivy, syft+grype, osv-scanner, checkov)
returned zero application-level findings across all fourteen reviews.

All 110 unit tests, 25 integration/scenario tests, and 4 fuzz tests pass at Debug,
ReleaseSafe, ReleaseFast, and ReleaseSmall optimization levels (139 total). No Critical
or High severity findings were found in any review. Three consecutive zero-new-finding
reviews (12, 13, 14) confirm convergence.

**Parallelism Review** (2026-03-30): 8 gaps identified (PAR-0001 through PAR-0008).
3 **closed** with code changes (spice integration, RwLock, parallel batch serialization),
2 **Won't Do** (compaction/recovery scans are I/O-bound and architecturally sequential),
3 **closed** with documentation updates.

## Stack-Ranked Findings

| Rank | Severity | Score | Finding | Component | Confidence | GitLab | Status |
|------|----------|-------|---------|-----------|------------|--------|--------|
| 1 | Medium | 24 | AES-256-GCM uses empty AAD — framing metadata not authenticated | `encryption.zig` | Confirmed | [#18](https://gitlab.com/devnw/zig/wal/-/issues/18) | **Closed** |
| 2 | Medium | 24 | Encryption key not zeroized on WAL/Iterator deinit | `wal.zig` | Confirmed | [#19](https://gitlab.com/devnw/zig/wal/-/issues/19) | **Closed** |
| 3 | Medium | 24 | compact() error paths leave WAL in unusable state | `wal.zig` | Confirmed | [#25](https://gitlab.com/devnw/zig/wal/-/issues/25) | **Closed** |
| 4 | Low | 16 | decryptRecordInPlace overlapping buffers for payloads >24B | `encryption.zig` | Confirmed | [#20](https://gitlab.com/devnw/zig/wal/-/issues/20) | **Closed** |
| 5 | Low | 16 | Unbounded allocation from untrusted blob_len/payload_len | `recovery.zig` / `compaction.zig` / `wal.zig` | Confirmed | [#21](https://gitlab.com/devnw/zig/wal/-/issues/21) | **Closed** |
| 6 | Low | 12 | Predictable temp filename enables symlink attack | `compaction.zig` / `atomic.zig` | Confirmed | [#22](https://gitlab.com/devnw/zig/wal/-/issues/22) | **Closed** |
| 7 | Low | 12 | Plaintext residue not zeroized in encryption stack buffers | `encryption.zig` | Confirmed | [#26](https://gitlab.com/devnw/zig/wal/-/issues/26) | **Closed** |
| 8 | Info | 8 | Example file uses removed Zig 0.15.x API | `examples/basic.zig` | Confirmed | [#23](https://gitlab.com/devnw/zig/wal/-/issues/23) | **Closed** |
| 9 | Info | 8 | .gitignore missing secret file patterns | `.gitignore` | Confirmed | [#27](https://gitlab.com/devnw/zig/wal/-/issues/27) | **Closed** |
| 10 | Info | 8 | TOCTOU race in SEC-0005 temp file pre-delete | `compaction.zig` / `atomic.zig` | Confirmed | [#28](https://gitlab.com/devnw/zig/wal/-/issues/28) | **Closed** |
| 11 | Medium | 20 | CODEOWNERS contains placeholder username — review enforcement disabled | `CODEOWNERS` | Confirmed | [#30](https://gitlab.com/devnw/zig/wal/-/issues/30) | **Closed** |
| 12 | Medium | 20 | CI cache key allows cross-branch poisoning | `.gitlab-ci.yml` | Suspected | [#31](https://gitlab.com/devnw/zig/wal/-/issues/31) | **Won't Do** |
| 13 | Low | 12 | WAL files created with default permissions (world-readable) | `wal.zig` / `compaction.zig` / `atomic.zig` | Confirmed | [#32](https://gitlab.com/devnw/zig/wal/-/issues/32) | **Closed** |
| 14 | Low | 12 | check-yaml pre-commit hook uses --unsafe flag | `.pre-commit-config.yaml` | Confirmed | [#33](https://gitlab.com/devnw/zig/wal/-/issues/33) | **Won't Do** |
| 15 | Info | 4 | GCM nonce collision risk undocumented | `encryption.zig` | Confirmed | [#24](https://gitlab.com/devnw/zig/wal/-/issues/24) | **Closed** |
| 16 | Info | 4 | Hardcoded encryption key in benchmark code | `bench/main.zig` | Confirmed | [#29](https://gitlab.com/devnw/zig/wal/-/issues/29) | **Closed** |
| 17 | Info | 4 | SECURITY.md references GitHub instead of GitLab | `SECURITY.md` | Confirmed | [#34](https://gitlab.com/devnw/zig/wal/-/issues/34) | **Closed** |
| 18 | Info | 4 | loadKeyFromEnv does not zeroize key in error paths | `encryption.zig` | Confirmed | [#35](https://gitlab.com/devnw/zig/wal/-/issues/35) | **Closed** |
| 19 | Info | 8 | appendBatch plaintext residue not zeroized in heap buffer | `wal.zig` | Confirmed | [#36](https://gitlab.com/devnw/zig/wal/-/issues/36) | **Closed** |
| 20 | Info | 4 | No directory fsync after atomic rename | `atomic.zig` / `compaction.zig` | Confirmed | [#37](https://gitlab.com/devnw/zig/wal/-/issues/37) | **Closed** |
| 21 | Info | 8 | Existing WAL files not tightened to 0o600 on open | `wal.zig` | Confirmed | [#38](https://gitlab.com/devnw/zig/wal/-/issues/38) | **Closed** |
| 22 | Info | 4 | Recovery does not validate LSN monotonicity | `recovery.zig` | Confirmed | [#39](https://gitlab.com/devnw/zig/wal/-/issues/39) | **Closed** |
| 23 | Info | 4 | appendBatch debug.assert on empty payloads is no-op in release | `wal.zig` | Confirmed | [#40](https://gitlab.com/devnw/zig/wal/-/issues/40) | **Closed** |
| 24 | Info | 16 | Iterator readEncryptedEntry does not zeroize decrypted plaintext | `wal.zig` | Confirmed | [#41](https://gitlab.com/devnw/zig/wal/-/issues/41) | **Closed** |
| 25 | Low | 12 | Public serializeInto/encryptIntoSlice use debug.assert (no-op in release) | `record.zig` / `encryption.zig` | Confirmed | [#42](https://gitlab.com/devnw/zig/wal/-/issues/42) | **Closed** |
| 26 | Info | 8 | Key material transient copies on stack not zeroized | `wal.zig` | Confirmed | [#43](https://gitlab.com/devnw/zig/wal/-/issues/43) | **Closed** |
| 27 | Info | 8 | Compaction scan skips CRC validation on plaintext records | `compaction.zig` | Confirmed | [#44](https://gitlab.com/devnw/zig/wal/-/issues/44) | **Closed** |
| 28 | Info | 8 | appendBatch ignores sync_every_n, unconditionally syncs | `wal.zig` | Confirmed | [#45](https://gitlab.com/devnw/zig/wal/-/issues/45) | **Closed** |
| 29 | Info | 16 | Recovery/compaction decryption buffers not zeroized before free | `recovery.zig` / `compaction.zig` | Confirmed | [#46](https://gitlab.com/devnw/zig/wal/-/issues/46) | **Closed** |
| 30 | Low | 12 | LSN pre-incremented before write — stale on partial write error | `wal.zig` | Confirmed | [#47](https://gitlab.com/devnw/zig/wal/-/issues/47) | **Closed** |
| 31 | Info | 4 | appendBatch sync counter u32 overflow at ~4 billion appends | `wal.zig` | Confirmed | [#48](https://gitlab.com/devnw/zig/wal/-/issues/48) | **Closed** |
| 32 | Medium | 24 | Double-free in Iterator.readEncryptedEntry error paths (SEC-0024 regression) | `wal.zig` | Confirmed | [#49](https://gitlab.com/devnw/zig/wal/-/issues/49) | **Closed** |
| 33 | Medium | 16 | Encrypted blob_len @intCast overflow for payloads near u32 max | `encryption.zig` | Confirmed | [#99](https://gitlab.com/devnw/zig/wal/-/issues/99) | **Closed** |
| 34 | Low | 8 | Gitleaks allowlist regex patterns lack path anchoring | `.gitleaks.toml` | Confirmed | [#100](https://gitlab.com/devnw/zig/wal/-/issues/100) | **Closed** |
| 35 | Low | 12 | Double-close on fd in finalizeTempFile/atomicWriteFile when rename fails | `compaction.zig` / `atomic.zig` | Confirmed | [#101](https://gitlab.com/devnw/zig/wal/-/issues/101) | **Closed** |
| 36 | Info | 16 | Iterator skip-path plaintext not zeroized before free | `iterator.zig` | Confirmed | [#102](https://gitlab.com/devnw/zig/wal/-/issues/102) | **Closed** |
| 37 | Medium | 32 | Double-close on stale fd when reopenOrPoison fails after compact | `wal.zig` | Confirmed | [#103](https://gitlab.com/devnw/zig/wal/-/issues/103) | **Closed** |
| 38 | Low | 24 | Encrypted WAL mode accepts plaintext record injection (downgrade) | `recovery.zig` / `iterator.zig` / `compaction.zig` | Confirmed | [#104](https://gitlab.com/devnw/zig/wal/-/issues/104) | **Closed** |
| 39 | Info | 8 | decryptRecord/decryptRecordInPlace @intCast overflow for oversized blobs | `encryption.zig` | Confirmed | [#105](https://gitlab.com/devnw/zig/wal/-/issues/105) | **Closed** |
| 40 | Info | 8 | No fuzz testing infrastructure for binary format parsing | `record.zig` / `encryption.zig` / `recovery.zig` | Confirmed | [#106](https://gitlab.com/devnw/zig/wal/-/issues/106) | **Closed** |

## Scoring

Score = Impact (1-5) x Likelihood (1-5) x 4. Maximum = 100.

## Won't Do

- **CI toolchain download without hash verification** — Handled via separate
  controls outside this library. See `docs/GAP_ANALYSIS_RESOLVED.md` for
  documented decision.
- **Docker image digest pinning** — Handled via separate controls outside this
  library.
- **Pre-commit hooks** — Handled via separate controls outside this library.
  This includes SEC-0016 (check-yaml `--unsafe` flag).
- **CI cache key cross-branch poisoning (SEC-0014)** — CI/CD cache policy is
  handled via separate organizational controls outside this library.
- **CI component SHA pinning** — Same as above.

## Full Codebase Audit Summary (2026-03-22)

Five-phase audit covering all four domains: requirements gap analysis, code quality review,
performance review, and adversarial security review.

### Repository
- **Project:** wal (Write-Ahead Log)
- **Platform:** GitLab (gitlab.com/devnw/zig/wal)
- **Languages:** Zig 0.15.1+
- **Scope:** Entire repo (9 source modules, ~4,100 LOC)
- **Test suite:** 99 unit + 25 integration + 4 fuzz = 128 tests, all passing at 4 optimization levels

### Domain Results

#### Gap Analysis

| Status | Count | Percentage |
|--------|-------|-----------|
| Implemented | 135 | 93.1% |
| Won't Do/Fix | 8 | 5.5% |
| Deferred | 0 | 0% |
| Partial | 0 | 0% |
| Not Implemented | 0 | 0% |

138 numbered findings across GAP (1-7), SEC (1-40), QA (1-68), PERF (1-23). All Gap-ID
namespaces contiguous. All severity classifications confirmed appropriate. Zero new gaps.

#### Code Quality

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 11 |
| Medium | 35 |
| Low | 22 |

68 total findings across 6 reviews. **All 68 closed.**
- **QA-0068** (Score 48): README appendBatch sync claim corrected ([#138](https://gitlab.com/devnw/zig/wal/-/issues/138)) — Closed
- **QA-0067** (Score 24): filename now stores owned copy, freed in deinit ([#137](https://gitlab.com/devnw/zig/wal/-/issues/137)) — Closed

#### Performance

| PerfSeverity | Count |
|-------------|-------|
| P1 | 1 |
| P2 | 9 |
| P3 | 13 |

23 total findings across 7 reviews. **All 23 closed**, 0 deferred, **0 open**.
- **PERF-0023** (Score 48): CI benchmark regression gate added ([#136](https://gitlab.com/devnw/zig/wal/-/issues/136)) — Closed
- **PERF-0013** (Score 24): Checkpoint sidecar for O(1) recovery ([#109](https://gitlab.com/devnw/zig/wal/-/issues/109)) — Closed
- **PERF-0014** (Score 20): Zero-copy compaction via copy_file_range ([#110](https://gitlab.com/devnw/zig/wal/-/issues/110)) — Closed

#### Security

| Risk Level | Count |
|-----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 7 |
| Low | 14 |
| Info | 19 |

40 total findings across 14 reviews. **All 40 closed.** 0 new findings. 2 Won't Do (SEC-0014,
SEC-0016). Three consecutive zero-new-finding reviews (12, 13, 14) confirm convergence.
**Immediate actions:** 0 (no secret rotations, no active vulnerabilities).

### Cross-Domain Summary

| Domain | Findings | Issues Created | Issues Closed | Open |
|--------|----------|---------------|---------------|------|
| Gap Analysis | 145 reqs | 0 | 0 | 0 |
| Quality | 68 | 2 (#137, #138) | 2 (#137, #138) | 0 |
| Performance | 23 | 1 (#136) | 1 (#136) | 0 |
| Security | 40 | 0 | 9 (stale tracker sync) | 0 |
| **Total** | **171 findings** | **3** | **12** | **0** |

### Docs Updated

| File | Domain | Action |
|------|--------|--------|
| docs/GAP_ANALYSIS.md | Security + Audit | Review 14 + full audit summary |
| docs/QUALITY_GAP_ANALYSIS.md | Quality | Review 6 (2 new findings) |
| docs/PERF_GAP_ANALYSIS.md | Performance | Review 7 (1 new finding) |
| docs/SECURITY_REVIEW_NOTES.md | Security | Review 14 section |

### Open Findings

**Zero open findings.** All 3 previously open items have been closed:
- QA-0068 (Score 48): Closed — README corrected
- PERF-0023 (Score 48): Closed — CI bench stage added
- QA-0067 (Score 24): Closed — filename now owned

**Deferred items:** None — PERF-0013 and PERF-0014 have been implemented with configuration options.

### Positive Observations

1. **Zero external dependencies** — eliminates third-party supply chain risk entirely
2. **Comptime assertions** — format invariants enforced at compile time across 5 modules
3. **Errdefer discipline** — correct cleanup on all error paths, no leaks detected
4. **Poisoned-WAL pattern** — prevents use-after-error with explicit state tracking
5. **SEC-0038 plaintext injection defense** — all 3 record consumers reject unencrypted records when key configured
6. **Key zeroization** — `secureZero` applied to all 25 key material sites across 5 files
7. **Test coverage** — 1.51 test-to-source ratio; fuzz tests cover all binary parsing entrypoints
8. **Module independence** — lower modules have zero cross-dependencies; only `wal.zig` imports all

### Tracker Reconciliation

9 GitLab issues from security Reviews 1-2 (#25, #26, #27, #28, #29, #30, #32, #34, #35) were
remediated in code and documented as "Closed" but never closed on the GitLab tracker. All 9
closed during this audit with verification evidence. All tracker/docs discrepancies are now
resolved.

### Blockers

None. All audit phases completed successfully across all 4 domains.

### Audit Methodology

| Phase | Agents | Duration |
|-------|--------|----------|
| 1. Orientation | gap-collector, quality-inventory, perf-context, security-inventory | Parallel |
| 2. Scanning | gap-scanner, quality-scanner, perf-scanner, security-scanner | Parallel |
| 3. Deep Analysis | gap-detector, quality-reviewer, perf-reviewer, security-reviewer | Parallel |
| 4. Tracking | gap-sync, quality-issue-tracker, perf-issue-tracker, security-issue-tracker | Parallel |
| 5. Unified Summary | Merged all domain results into this section | Sequential |

---

## Findings Detail — Review 14

**Zero new findings.** Deep adversarial security review identified 9 findings — all previously
tracked under existing SEC IDs.

### Review 14 Scope

Deep adversarial code review focused on:
- Cryptographic key material lifecycle (Options struct, loadKeyFromEnv, nonce management)
- TOCTOU race conditions in temp file operations
- Input validation on write path (MAX_RECORD_SIZE)
- Plaintext residue in reuse buffers
- Filesystem durability (directory fsync)

### Finding Mapping — Review 14

| Phase 3 ID | Severity | Finding | Existing SEC | GitLab | Status |
|-------------|----------|---------|--------------|--------|--------|
| F-1 | Medium | TOCTOU in temp file creation (symlink race) | SEC-0011 | [#28](https://gitlab.com/devnw/zig/wal/-/issues/28) | Closed (no fix in Zig std) |
| F-2 | Low | No directory fsync after rename | SEC-0020 | [#37](https://gitlab.com/devnw/zig/wal/-/issues/37) | Closed |
| C-1 | Low | Key persists in Options struct on caller stack | SEC-0026 | [#43](https://gitlab.com/devnw/zig/wal/-/issues/43) | Closed |
| C-3 | Low | loadKeyFromEnv doesn't clear env var | SEC-0018 | [#35](https://gitlab.com/devnw/zig/wal/-/issues/35) | Closed |
| F-4 | Low | Predictable temp file name | SEC-0005 | [#22](https://gitlab.com/devnw/zig/wal/-/issues/22) | Closed |
| I-2 | Low | 16 MiB MAX_RECORD_SIZE allocation | SEC-0004 | [#21](https://gitlab.com/devnw/zig/wal/-/issues/21) | Closed |
| I-3 | Low | No MAX_RECORD_SIZE on write path | SEC-0004 | [#21](https://gitlab.com/devnw/zig/wal/-/issues/21) | Closed (by design) |
| C-2 | Info | No nonce counter enforcement | SEC-0007 | [#24](https://gitlab.com/devnw/zig/wal/-/issues/24) | Closed |
| M-2 | Info | Reuse buffer tail not fully zeroized | SEC-0009/SEC-0029 | [#26](https://gitlab.com/devnw/zig/wal/-/issues/26) / [#46](https://gitlab.com/devnw/zig/wal/-/issues/46) | Closed |

### Won't Do Confirmation — Review 14

SEC-0014 (CI cache key cross-branch poisoning) and SEC-0016 (check-yaml `--unsafe` flag)
confirmed correctly scoped out. No change to Won't Do policy.

---

## Findings Detail — Review 13

**Zero new findings.** All candidate findings triaged below.

### Automated Scan Results — Review 13

| Tool | Version | Findings |
|------|---------|----------|
| gitleaks | 8.30.0 | 0 |
| trufflehog | 3.92.5 | 0 |
| semgrep | 1.150.0 (p/default) | 0 |
| trivy fs+misconfig | 0.69.0 | 0 vulns, 0 misconfigs |
| checkov | 3.2.499 (gitlab_ci) | 14 passed, 0 failed |
| shellcheck | 0.9.0 | N/A (no .sh files) |
| hadolint | 2.14.0 | N/A (no Dockerfiles) |

### Manual Review Coverage — Review 13

Four parallel adversarial analysis agents covered:

1. **Cryptographic correctness:** AES-256-GCM nonce generation, AAD binding, key lifecycle, in-place decryption overlap safety, tag verification — all correct. All prior remediation patterns (SEC-0001, SEC-0002, SEC-0033) verified in-place.

2. **Memory safety:** All `@intCast` sites verified with upstream bounds checks. All allocator patterns (alloc/free/errdefer) verified. No `@truncate` in production code. All `@panic` and `@unreachable` sites are intentional (buffer invariant violations, impossible-by-construction error codes).

3. **DoS / input validation:** All scan loops have guaranteed termination. MAX_RECORD_SIZE enforced at all read-path entry points. LSN monotonicity enforced in recovery.

4. **CI/CD supply chain:** Pipeline structure unchanged. Zero external dependencies. SEC-0034 gitleaks anchoring verified. checkov passes all checks.

### Triaged Non-Findings — Review 13

1. **appendBatch encrypted scratch buffer overlap (memory safety agent):** Same false
   positive as Reviews 2, 7, and 12 — standard in-place AES-GCM (ciphertext dest ==
   plaintext src at final record). The gap between write cursor and scratch area is
   always ≥ 40 bytes (encryption overhead).

2. **CI toolchain download hash verification (CI/CD agent):** Duplicate of Won't Do —
   handled via separate organizational controls.

---

## Findings Detail — Review 12

**Zero new findings.** All candidate findings triaged below.

### Triaged Non-Findings — Review 12

1. **appendBatch encrypted scratch buffer overlap (memory safety agent):** Claimed
   `pt_start = total_size - rec_size` causes buffer corruption with variable-sized
   payloads. **False positive** — the gap between write cursor and scratch area is
   always ≥ 40 bytes (encryption overhead), and for the final record ciphertext and
   plaintext coincide (standard in-place AES-GCM). Previously triaged in Reviews 2 and 7.

2. **Iterator seekBy infinite loop (DoS agent):** Claimed `seekBy` could fail silently
   causing an infinite loop. **False positive** — `seekBy` uses `try` (errors
   propagate to caller), and `payload_len` is bounded by MAX_RECORD_SIZE (16 MiB) at
   line 114 of `iterator.zig`.

3. **atomicWriteFile filename validation (DoS agent):** Claimed missing filename length
   validation. **False positive** — `atomic.zig` uses a 256-byte `BoundedArray` and
   returns `error.FilenameTooLong` when the temp filename exceeds it.

4. **CI toolchain download hash verification (CI/CD agent):** Duplicate of Won't Do —
   handled via separate controls.

5. **apt package version pinning (CI/CD agent):** Duplicate of Won't Do — CI/CD
   configuration concern handled externally.

6. **CI component SHA pinning vs semver tags (CI/CD agent):** Duplicate of Won't Do —
   CI/CD configuration concern handled externally.

7. **Pre-commit hook enforcement (CI/CD agent):** Duplicate of Won't Do — handled
   via separate controls.

---

## Findings Detail — Review 11

### SEC-0038: Encrypted WAL mode accepts plaintext record injection (Low, Score 24) — **Closed**

**Evidence:** `src/recovery.zig:113`, `src/iterator.zig:73`, `src/compaction.zig:131`. All three scan paths shared the same pattern:

```zig
if (key != null and encryption.isEncrypted(&peek_buf)) {
    // encrypted record path
} else {
    // plaintext record path — ACCEPTED even when key is present
}
```

When a `WriteAheadLog` was configured with an encryption key, these paths accepted both encrypted and plaintext records.

**Impact:** Data tampering. An attacker with file-write access but without the encryption key could inject arbitrary data into the WAL.

**Score:** Impact 3 x Likelihood 2 x 4 = 24 (Low)

**CWE:** CWE-757 (Selection of Less-Secure Algorithm During Negotiation), CWE-311 (Missing Encryption of Sensitive Data)

**GitLab:** [#104](https://gitlab.com/devnw/zig/wal/-/issues/104)

**Remediation applied:** Added an `else if (key != null)` branch in all three scan paths (`recovery.zig`, `iterator.zig`, `compaction.zig`) that stops scanning / returns null when the encryption key is configured but the record lacks the encryption magic bytes. This prevents plaintext record injection into encrypted WALs. Updated mixed-mode migration tests in `tests/scenarios/encryption.zig` to verify the secure behavior (plaintext records are rejected when a key is present). Added 2 new recovery tests and 1 new iterator test for SEC-0038. All 79 unit tests, 25 integration/scenario tests, and 4 fuzz tests pass.

---

### SEC-0039: decryptRecord/decryptRecordInPlace @intCast overflow for oversized blobs (Info, Score 8) — **Closed**

**Evidence:** `src/encryption.zig:319` (`decryptRecord`) and `src/encryption.zig:358` (`decryptRecordInPlace`):

```zig
const expected_blob_len: u32 = @intCast(blob.len - BLOB_LEN_SIZE);
```

Both public decrypt functions contained an unguarded `@intCast` that could overflow `u32` on 64-bit systems when `blob.len > maxInt(u32) + 4` (~4.3 GiB).

**Score:** Impact 2 x Likelihood 1 x 4 = 8 (Info)

**CWE:** CWE-190 (Integer Overflow or Wraparound)

**GitLab:** [#105](https://gitlab.com/devnw/zig/wal/-/issues/105)

**Remediation applied:** Added `if (remaining > std.math.maxInt(u32)) return error.InvalidEncryptedRecord;` bounds check before the `@intCast` in both `decryptRecord` and `decryptRecordInPlace`. Added a unit test (`SEC-0039: u32 overflow bounds check arithmetic`) that verifies the boundary arithmetic and exercises both functions with crafted mismatched blob_len values.

---

### SEC-0040: No fuzz testing infrastructure for binary format parsing (Info, Score 8) — **Closed**

**Evidence:** The library parses binary data from potentially untrusted WAL files but had no `std.testing.fuzz` targets.

**Score:** Impact 2 x Likelihood 1 x 4 = 8 (Info)

**CWE:** CWE-703 (Improper Check or Handling of Exceptional Conditions)

**GitLab:** [#106](https://gitlab.com/devnw/zig/wal/-/issues/106)

**Remediation applied:** Added `tests/fuzz.zig` with 4 fuzz test targets covering `record.deserialize`, `encryption.decryptRecord`, `encryption.decryptRecordInPlace`, and `encryption.isEncrypted`. Added `test-fuzz` build step in `build.zig`. Tests exercise all binary parsing entrypoints with arbitrary byte sequences using Zig 0.15.2's `std.testing.fuzz` API. In deterministic mode (regular test runner) all 4 targets pass immediately; under `--fuzz` flag they generate random inputs continuously.

### Triaged Non-Findings — Review 11

1. **Pre-commit hook rev tag pinning vs SHA:** Pre-commit hooks pin at tags (e.g., `rev: v5.0.0`) not commit SHAs. However, pre-commit hooks run locally on developer machines — the CI pipeline `skip` config (`skip: [zig-fmt, zig-build, zig-test]`) prevents Zig-specific hooks from running in CI. This is a local development convenience, not a CI supply chain concern. The git tag immutability assumption is reasonable for well-known pre-commit hook repos.

2. **Grype SBOM scan matches for host system:** `syft + grype` reported CVEs in the host system's glibc (e.g., CVE-2023-4911). These are host-OS vulnerabilities, not application vulnerabilities. The Zig library has zero external dependencies and is statically compiled.

---

## Findings Detail — Review 10

### SEC-0036: Iterator skip-path plaintext not zeroized before free (Info, Score 16) — **Closed**

**Evidence:** `src/iterator.zig:92-94`. When an encrypted record is decrypted and its LSN is at or below `from_lsn`, the `payload_copy` allocation is freed without `secureZero`:

```zig
if (e.lsn <= self.from_lsn) {
    self.allocator.free(e.payload);  // no secureZero before free
    continue;
}
```

`e.payload` is produced by `self.allocator.dupe(u8, rec.payload)` at line 167 inside `readEncryptedEntry`. The blob_buf containing the full decrypted record IS correctly zeroized (SEC-0024 fix at line 168), but the duped payload — a separate heap allocation containing the raw plaintext payload bytes — is freed without clearing.

Contrast with the plaintext path (lines 113-115): plaintext records below `from_lsn` are skipped via `seekBy` — the payload bytes are never read into memory. For encrypted records, decryption is required to read the LSN, so the payload is necessarily allocated and then discarded.

**Impact:** Decrypted payload bytes from encrypted WAL records accumulate in freed heap memory. An attacker with a separate heap memory disclosure or use-after-free primitive could read these bytes.

**Score:** Impact 2 × Likelihood 2 × 4 = 16 (Info)

**CWE:** CWE-244 (Improper Clearing of Heap Data Before Release)

**GitLab:** [#102](https://gitlab.com/devnw/zig/wal/-/issues/102)

**Remediation applied:** Added `encryption.secureZero(@constCast(e.payload))` before `self.allocator.free(e.payload)` in the iterator's encrypted record skip path (`iterator.zig:94`). This matches the pattern used in all other decryption-path zeroization fixes (SEC-0024, SEC-0029, SEC-0032). All 75 unit tests and 25 integration tests pass at all 4 optimization levels.

### SEC-0037: Double-close on stale fd when reopenOrPoison fails after compact (Medium, Score 32) — **Closed**

**Evidence:** `src/wal.zig:307-347`. `compact()` closes `self.file` at line 312 before calling `compaction.compact()`. If the subsequent `reopenOrPoison()` (line 323 or 328) fails at `openFile` (line 340), the catch block sets `self.poisoned = true` and returns without assigning a new value to `self.file`. The field retains the stale (already-closed) fd. When `deinit()` is later called (line 138), it unconditionally calls `self.file.close()`, which double-closes the stale fd.

Zig's `std.posix.close` treats EBADF as `unreachable` — UB in ReleaseFast/ReleaseSmall, panic in Debug/ReleaseSafe. In the worst case, the OS could have recycled the fd number for an unrelated file, and `close()` would silently close it, causing data corruption in other subsystems.

**Impact:** UB in production builds. Potential fd-reuse corruption of unrelated files.

**Score:** Impact 4 × Likelihood 2 × 4 = 32 (Medium). Requires both a compaction + a file-open failure (unusual filesystem conditions: permissions change, mount removed, disk full).

**CWE:** CWE-675 (Multiple Operations on Resource in Single-Operation Context)

**GitLab:** [#103](https://gitlab.com/devnw/zig/wal/-/issues/103)

**Remediation applied:** Two-part fix:

1. **`deinit` (wal.zig:138):** Added `if (!self.poisoned)` guard around `self.file.close()`. When the WAL is poisoned, the fd is known to be stale (already closed), so the close is skipped.

2. **`reopenOrPoison` (wal.zig:346-354):** Established the invariant that when `poisoned = true`, `self.file` always holds a stale (closed) fd. If `openFile` fails, the old fd is already closed and `self.file` is not reassigned — invariant holds. If `openFile` succeeds but `seekFromEnd` fails, the newly opened fd is explicitly closed before setting `poisoned = true` — ensuring the invariant holds in both failure paths.

This prevents the double-close that would trigger `unreachable` (UB) in ReleaseFast/ReleaseSmall or panic in Debug/ReleaseSafe. All 75 unit tests and 25 integration tests pass at all 4 optimization levels.

### Triaged Non-Findings — Review 10

1. **`sync_every_n = 0` forces sync-every-write:** Previously triaged in Review 9 as harmless. The comparison `appends_since_sync >= 0` is always true for u32, causing fdatasync on every append — equivalent to the default `sync_every_n = 1`. This is the safest possible behavior for a misconfigured value. Not a security vulnerability.

2. **`seekBy` i64 cast guard dependency (compaction.zig:171, iterator.zig:114):** The @intCast to i64 is safe because MAX_RECORD_SIZE (16 MiB) is enforced upstream. Even without the guard, u32_max + 4 ≈ 4.3 billion fits within i64 range. No exploitable bug.

---

## Findings Detail — Review 9

### SEC-0035: Double-close on fd in finalizeTempFile/atomicWriteFile when rename fails (Low, Score 12) — **Closed**

**Evidence:** `src/compaction.zig:65-70` (`finalizeTempFile`) and `src/atomic.zig:41-50` (`atomicWriteFile`). Both functions closed the file descriptor before calling `dir.rename()`. Callers have `errdefer { tmp.close(); dir.deleteFile(...) catch {}; }` blocks that fire when the error propagates.

Sequence when `rename()` failed (before fix):
1. `tmp.close()` — closes the fd
2. `dir.rename(tmp_name, filename)` — fails, error propagates
3. Caller's `errdefer` fires `tmp.close()` again on the already-closed fd

Zig's `std.posix.close()` treats `EBADF` as `unreachable`:
- **Debug/ReleaseSafe:** panic during error handling
- **ReleaseFast/ReleaseSmall:** undefined behavior

**Impact:** If `rename()` failed after close (e.g., cross-device error, read-only filesystem), the error-recovery path triggered UB in release builds or a panic in safe builds.

**Remediation applied:** Reordered both functions to rename-before-close. On POSIX, `rename()` operates on directory entries — the fd remains valid across rename. If rename fails, the fd is still open and the caller's errdefer closes it safely. If rename succeeds, close runs normally after the rename. Updated `finalizeTempFile` (compaction.zig:64-72) and `atomicWriteFile` (atomic.zig:46-54) with comments documenting the ordering rationale. All 75 unit tests and 25 integration tests pass at Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.

**CWE:** CWE-675 (Multiple Operations on Resource in Single-Operation Context)

---

## Findings Detail — Review 8

### SEC-0033: Encrypted blob_len @intCast overflow for payloads near u32 max (Medium, Score 16) — **Closed**

**Evidence:** `src/encryption.zig:180` (`encryptRecord`) and `src/encryption.zig:213` (`encryptInto`). Both computed `blob_len: u32 = @intCast(MAGIC_SIZE + NONCE_SIZE + TAG_SIZE + plaintext.len)` which is `36 + plaintext.len`. When the plaintext (a serialized WAL record) is produced from a payload near `MAX_PAYLOAD_SIZE` (u32 max), the expression `36 + (HEADER_SIZE + payload.len + CRC_SIZE) = 36 + 16 + payload.len` exceeds u32 range.

**Impact:** In ReleaseFast/ReleaseSmall (where `@intCast` safety checks are elided), the blob_len field is silently truncated, causing the encrypted record to be written with a wrong blob_len. On recovery, `readEncryptedBlob` reads an incorrect number of bytes, and the record cannot be decrypted. Data corruption and silent data loss for encrypted WAL records with payloads near 4 GiB. In Debug/ReleaseSafe, a runtime panic occurs.

**Remediation applied:** Added bounds check before `@intCast` in both `encryptRecord` and `encryptInto`. `encryptRecord` now returns `error.PayloadTooLarge` (added to `EncryptionError` set). `encryptInto` uses `@panic` consistent with the SEC-0025 buffer-size pattern (void return, programming error). New `PayloadTooLarge` error variant documents the limit: plaintext must be ≤ maxInt(u32) - 36. New unit test verifies boundary arithmetic.

**CWE:** CWE-190 (Integer Overflow or Wraparound), CWE-130 (Improper Handling of Length Parameter Inconsistency)

---

### SEC-0034: Gitleaks allowlist regex patterns lack path anchoring (Low, Score 8) — **Closed**

**Evidence:** `.gitleaks.toml:11-14`. The allowlist used unanchored regex patterns:

```toml
paths = [
    '''\.zig-cache''',   # matches any path containing ".zig-cache"
    '''zig-out''',       # matches any path containing "zig-out"
    '''\.git''',         # matches .git, .github, .gitlab, .gitignore, .git-credentials
]
```

The `\.git` pattern matched any path containing the substring `.git`, including `.github/`, `.gitlab/`, `.gitignore`, and potentially secret files like `.git-credentials`. A secret committed in a file whose path coincidentally matched would be suppressed.

**Impact:** Reduced effectiveness of secret scanning. A secret in a path containing `.github` or similar would not be flagged.

**Remediation applied:** Anchored all three patterns to directory boundaries using `(^|/)..(/|$)` so they only match the exact directory names, not substrings.

**CWE:** CWE-798 (Use of Hard-Coded Credentials — suppression risk)

---

## Findings Detail — Review 1

### SEC-0001: Empty AAD in AES-256-GCM (Medium, Score 24) — **Closed**

**Evidence:** `src/encryption.zig` — `Aes256Gcm.encrypt` and `Aes256Gcm.decrypt` used empty AAD (`&.{}`). The framing metadata (blob_len + magic) was not covered by the GCM authentication tag.

**Impact:** Attacker with file access could modify blob_len to cause record boundary confusion during recovery/compaction scan without breaking the tag.

**Remediation applied:** Pass `blob[OFF_BLOB_LEN..OFF_NONCE]` (12 bytes: blob_len + magic) as AAD to both encrypt and decrypt in all code paths including `encryptRecord`, `encryptInto`, `decryptRecord`, and `decryptRecordInPlace`. In-place decrypt copies AAD to stack before overwriting. **Breaking change** to on-disk format. All existing tests pass (they create fresh WAL files each run).

---

### SEC-0002: Encryption key not zeroized on deinit (Medium, Score 24) — **Closed**

**Evidence:** `src/wal.zig` — `WriteAheadLog.deinit()` and `Iterator.deinit()` only closed the file handle, leaving key material in freed memory.

**Impact:** Key material persists in freed memory, recoverable via core dump, /proc/pid/mem, or swap.

**Remediation applied:** Added `encryption.secureZero()` calls in both `WriteAheadLog.deinit()` and `Iterator.deinit()`. The `secureZero()` function uses volatile pointer writes to prevent compiler elision (Zig 0.15.2 lacks `std.crypto.utils.secureZero`). Two new tests verify key bytes are zeroed after deinit.

---

### SEC-0003: Overlapping buffers in decryptRecordInPlace (Low, Score 16) — **Closed**

**Evidence:** `src/encryption.zig` — comment incorrectly said "non-overlapping with ciphertext at offset 40+" but for plaintext >24 bytes the destination overlaps the source. No tests covered payloads >24 bytes through the encrypted path.

**Impact:** Relied on undocumented stdlib behaviour. Likely safe in practice but silent corruption risk.

**Remediation applied:** Corrected the misleading comment to accurately document that the source is always 40 bytes ahead of the destination (safe for AES-GCM's in-place semantics). Added 2 new scenario tests in `tests/scenarios/encryption.zig` covering payload sizes 25, 64, 128, 256, 1024, and 4096 bytes through both the write/reopen/recovery and batch paths.

---

### SEC-0004: Unbounded allocation from untrusted record sizes (Low, Score 16) — **Closed**

**Evidence:** Multiple locations allocated `payload_len` or `blob_len` bytes without upper bound, enabling OOM from crafted WAL files.

**Impact:** DoS via OOM. Requires local file access.

**Remediation applied:** Added `MAX_RECORD_SIZE` constant (16 MiB) in `record.zig`. Added bounds checks in 7 locations across `recovery.zig` (encrypted + plaintext paths), `compaction.zig` (encrypted + plaintext paths), `wal.zig` (iterator encrypted + plaintext paths), and `record.zig` (`readPayloadAndVerify`). All overflow-sized records are treated as end-of-valid-log or skipped.

---

### SEC-0005: Predictable temp filename (Low, Score 12) — **Closed**

**Evidence:** `src/compaction.zig` and `src/atomic.zig` created temp files at predictable paths (`{filename}.tmp`) without checking for pre-existing symlinks.

**Impact:** File overwrite if attacker has dir write access.

**Remediation applied:** Added `dir.deleteFile(tmp_name) catch {};` before every `dir.createFile(tmp_name, ...)` call in all three locations: compaction empty-file path, compaction bulk-copy path, and `atomicWriteFile`. This removes any pre-existing file (including symlinks) before creating the temp file.

---

### SEC-0006: Broken example file (Info, Score 8) — **Closed**

**Evidence:** `examples/basic.zig` was a template placeholder using `std.io.getStdOut().writer()` and commented-out skeleton code. Not compiled by build.zig so CI did not catch it.

**Remediation applied:** Rewrote `examples/basic.zig` as a complete working example demonstrating append, iterate, close/reopen (crash recovery), and compaction using the actual WAL API.

---

### SEC-0007: Nonce collision risk undocumented (Info, Score 4) — **Closed**

**Evidence:** `src/encryption.zig` used random 96-bit nonces without documenting the birthday-bound limit.

**Impact:** Users unaware of the ~2^32 encryption limit per key could silently degrade security.

**Remediation applied:** Added "Nonce management" section to the `encryption.zig` module doc comment documenting the 2^32 birthday bound, the consequences of nonce collision (plaintext XOR leak, tag forgery), and the recommendation to rotate keys before reaching this limit.

---

## Findings Detail — Review 2

### SEC-0008: compact() error paths leave WAL unusable (Medium, Score 24) — **Closed**

**Evidence:** `src/wal.zig` — `compact()` unconditionally closes the file handle before calling `compaction.compact()`. If the reopen after compaction (error or success path) failed, `self.file` was left in a closed/invalid state and the WAL became unusable.

**Impact:** If the error-path reopen fails (e.g., transient filesystem error), subsequent `append()` calls will attempt to write to a closed file handle, causing a panic or silent data loss.

**Remediation applied:** Added a `poisoned: bool` field to `WriteAheadLog`. In `compact()`, both the error-path and success-path reopens now catch failures and set `self.poisoned = true`, returning `error.WalPoisoned`. The `append()`, `appendBatch()`, `sync()`, and `compact()` methods all check the poisoned flag at entry and return `error.WalPoisoned` immediately if set. This prevents any use of the WAL after an unrecoverable file-handle failure.

---

### SEC-0009: Plaintext residue not zeroized in encryption stack buffers (Low, Score 12) — **Closed**

**Evidence:** `src/encryption.zig` — `encryptAndWriteToFile()` used stack-allocated buffers `pt_buf` and `enc_buf` to hold plaintext and ciphertext. Neither was zeroized before the function returned.

**Impact:** Plaintext payload data persists in freed stack frames, recoverable via core dump, `/proc/pid/mem`, or swap.

**Remediation applied:** Added `defer secureZero(&pt_buf)` and `defer secureZero(&enc_buf)` to the stack path. For the heap path, wrapped `allocator.free` in a `defer` block that calls `secureZero` on the buffer before freeing. Both plaintext and ciphertext buffers are now scrubbed on all exit paths.

---

### SEC-0010: .gitignore missing secret file patterns (Low, Score 8) — **Closed**

**Evidence:** `.gitignore` did not include patterns for common secret/credential file types.

**Impact:** Accidental commit of secret material if a developer places a key file or `.env` in the repository tree.

**Remediation applied:** Added `.env`, `.env.*`, `*.key`, `*.pem`, `*.p12`, `*.pfx`, `*.secret` patterns to `.gitignore`.

---

### SEC-0011: TOCTOU race in SEC-0005 temp file pre-delete (Info, Score 8) — **Closed**

**Evidence:** `src/compaction.zig` and `src/atomic.zig` — The SEC-0005 remediation has a narrow TOCTOU window between delete and create.

**Impact:** Extremely narrow race window. A fully race-free solution would require `O_TMPFILE` + `linkat()` (Linux-specific) which is not available in Zig's `std.fs` API.

**Remediation applied:** Added inline comments at all three call sites documenting the residual TOCTOU window as a known limitation of Zig's stdlib. No code change needed — the current approach is the best available. Consider upgrading if `O_TMPFILE` support is added to `std.fs` in the future.

---

### SEC-0012: Hardcoded encryption key in benchmark code (Info, Score 4) — **Closed**

**Evidence:** `bench/main.zig` — contained a hardcoded 32-byte key `{0x01..0x20}` without any warning comment.

**Impact:** Minimal — benchmark code only. Could set a bad example for users who copy benchmark code.

**Remediation applied:** Added prominent `/// NOT FOR PRODUCTION USE` doc comment to `makeKey()` explaining the key is deterministic for reproducible benchmarks and must not be used in production.

---

### SEC-0013: CODEOWNERS contains placeholder username (Medium, Score 20) — **Closed**

**Evidence:** `CODEOWNERS:3` — `* @your-username` was a template placeholder.

**Impact:** GitLab's CODEOWNERS-based merge request approval enforcement was non-functional.

**Remediation applied:** Replaced `@your-username` with `@devnw` in `CODEOWNERS`.

---

### SEC-0014: CI cache key allows cross-branch poisoning (Medium, Score 20) — **Won't Do**

**Evidence:** `.gitlab-ci.yml:48` — `key: "zig-${ZIG_VERSION}"`. The cache key is based only on the Zig version, not on the branch or pipeline source.

**Impact:** A malicious MR pipeline could poison the Zig toolchain cache with modified binaries.

**Resolution:** Won't Do. CI/CD cache policy is handled via separate organizational controls outside this library. See the Won't Do section above.

---

### SEC-0015: WAL files created with default permissions (Low, Score 12) — **Closed**

**Evidence:** `src/wal.zig`, `src/compaction.zig`, `src/atomic.zig` — All `createFile` calls used default permissions (`0644` — world-readable).

**Impact:** For encrypted WALs, ciphertext is readable by all local users, broadening the attack surface.

**Remediation applied:** Added `mode = 0o600` (owner-only read/write) to all `createFile` calls: WAL file creation in `wal.zig:init()`, both temp file creation sites in `compaction.zig:compact()`, and `atomic.zig:atomicWriteFile()`.

---

### SEC-0016: check-yaml pre-commit hook uses --unsafe flag (Low, Score 12) — **Won't Do**

**Evidence:** `.pre-commit-config.yaml:20` — `args: [--unsafe]`.

**Impact:** A malicious YAML file with a `!!python/object` tag could execute arbitrary code on the developer's machine during the pre-commit check.

**Resolution:** Won't Do. Pre-commit hook configuration is handled via separate organizational controls outside this library. See the Won't Do section above.

---

### SEC-0017: SECURITY.md references GitHub instead of GitLab (Info, Score 4) — **Closed**

**Evidence:** `SECURITY.md:11` — referenced "GitHub issues" instead of "GitLab issues."

**Impact:** Confuses security reporters or suggests the policy is a stale template.

**Remediation applied:** Changed "GitHub issues" to "GitLab issues" in `SECURITY.md`.

---

### SEC-0018: loadKeyFromEnv does not zeroize key in error paths (Info, Score 4) — **Closed**

**Evidence:** `src/encryption.zig` — If `hexToBytes` partially writes to the stack-local `key` before returning `error.InvalidKey`, partial key material remained on the stack. Additionally, `std.posix.getenv` returns a pointer into the process environment.

**Impact:** Key material persists in environment memory and potentially on the stack in error paths.

**Remediation applied:** Added `errdefer secureZero(&key);` after the `var key` declaration to zeroize on error. Added doc comment noting that `std.posix.getenv` returns a pointer into the environment block and callers should clear the variable after loading for minimal key exposure.

---

## Findings Detail — Review 3

### SEC-0019: appendBatch plaintext residue not zeroized in heap buffer (Info, Score 8) — **Closed**

**Evidence:** `src/wal.zig:188-212` — `appendBatch()` allocates a heap buffer to assemble all records. In the encrypted path, plaintext records are serialized into the end of this buffer (scratch space at `buf[pt_start..]`) before encryption into the front. The buffer is freed without `secureZero()`.

**Impact:** Plaintext payload data persists in freed heap memory, recoverable via core dump, `/proc/pid/mem`, or swap. Analogous to SEC-0009 but in the batch write path.

**Remediation applied:** Changed `defer self.allocator.free(buf)` to a defer block that calls `encryption.secureZero(buf)` before `free` when encryption is active. Only zeroizes when `self.options.encryption_key != null` to avoid unnecessary overhead in plaintext mode.

---

### SEC-0020: No directory fsync after atomic rename (Info, Score 4) — **Closed**

**Evidence:** `src/atomic.zig:50`, `src/compaction.zig:168`, `src/compaction.zig:212` — All three `dir.rename()` calls lack a subsequent directory fsync. The data file is fsynced before rename, but the directory metadata update is not explicitly flushed.

**Impact:** On filesystems with `data=writeback` or non-journaling filesystems, the rename may not be durable after power loss. The pre-compaction WAL could reappear, causing duplicate record processing. Not a security vulnerability per se, but a data integrity gap.

**Remediation applied:** Documented as a known limitation of Zig's `std.fs.Dir` API. `Dir` opens directories with `O_PATH` (for efficiency), which does not support `fsync()`. Opening a separate `O_RDONLY` fd for the directory is not possible without knowing the directory's absolute path (which the caller does not provide). On ext4 with the default `data=ordered` mode, directory renames are journaled and durable without an explicit fsync. Added inline comments at all three rename sites documenting this gap. Consider upgrading if future Zig versions add `Dir.sync()`.

---

### SEC-0021: Existing WAL files not tightened to 0o600 on open (Info, Score 8) — **Closed**

**Evidence:** `src/wal.zig:78` — `openFile` path does not check or tighten permissions on existing files. The SEC-0015 fix only applies to `createFile` (new files). Existing WAL files with world-readable permissions remain world-readable until the first compaction.

**Impact:** For encrypted WALs, ciphertext is readable by unprivileged local users, broadening the attack surface.

**Remediation applied:** Added `std.posix.fchmod(file.handle, 0o600) catch {};` after both the `openFile` and `createFile` paths in `init()`. The `catch {}` allows silent failure on non-POSIX platforms or when the caller is not the file owner. New test verifies a file created with 0o644 is tightened to 0o600 on WAL init.

---

### SEC-0022: Recovery does not validate LSN monotonicity (Info, Score 4) — **Closed**

**Evidence:** `src/recovery.zig:147` and `:182` — `last_lsn` is updated without checking that the new LSN is strictly greater than the previous one. For plaintext WALs, CRC32 is trivially forgeable, so an attacker with file write access can inject records with arbitrary LSNs.

**Impact:** The WAL could resume from a wrong LSN after recovery, violating the monotonicity guarantee. Only affects plaintext mode (encrypted WALs are protected by AES-GCM authentication).

**Remediation applied:** Added `if (info.record_count > 0 and lsn <= info.last_lsn) break;` at both the encrypted (line 148) and plaintext (line 184) record paths in `recoverWithKey()`. Non-monotonic LSNs are now treated as corruption, stopping the scan at the last valid monotonic record. New test verifies that a crafted WAL with non-monotonic LSNs stops recovery at the correct boundary.

---

### SEC-0023: appendBatch debug.assert on empty payloads is no-op in release (Info, Score 4) — **Closed**

**Evidence:** `src/wal.zig:175` — `std.debug.assert(payloads.len > 0)` is a no-op in `ReleaseFast` and `ReleaseSmall`. An empty payloads slice would cause an unnecessary fdatasync and return a stale LSN.

**Impact:** API contract violation in release builds. No data corruption or security breach.

**Remediation applied:** Replaced `std.debug.assert(payloads.len > 0)` with a runtime check `if (payloads.len == 0) return error.EmptyBatch;` so the guard is enforced at all optimization levels. New test verifies the error is returned for empty payloads and LSN is not advanced.

---

## Findings Detail — Review 4

### SEC-0024: Iterator readEncryptedEntry does not zeroize decrypted plaintext (Info, Score 16) — **Closed**

**Evidence:** `src/wal.zig:465-496` — `readEncryptedEntry` calls `decryptRecordInPlace` which writes plaintext into the front of `blob_buf`. The payload is duped out (line 492), then `blob_buf` is freed (line 496) without calling `secureZero`. Error paths at lines 473, 481, 488, and 494 also free without zeroization.

**Impact:** Decrypted WAL payloads persist in freed heap memory until the allocator reuses the region. Recoverable via core dump or process memory access. Analogous to SEC-0009 (stack buffers) and SEC-0019 (batch heap buffer), which were both remediated with `secureZero` calls.

**Remediation applied:** Added `encryption.secureZero(blob_buf)` before every `self.allocator.free(blob_buf)` call in `readEncryptedEntry` — 5 sites total (torn write, decrypt error, deserialize error, dupe error, and success path). Consistent with SEC-0009/SEC-0019 remediation pattern.

---

### SEC-0025: Public serializeInto/encryptIntoSlice use debug.assert for buffer size (Low, Score 12) — **Closed**

**Evidence:** `src/record.zig:107` — `std.debug.assert(buf.len >= HEADER_SIZE + payload.len + CRC_SIZE)`. `src/encryption.zig:142` — `std.debug.assert(buf.len >= total_len)`. Both are `pub` functions (`serializeInto` and `encryptIntoSlice`). The assertions are compiled out in `ReleaseFast` and `ReleaseSmall`.

**Impact:** Passing a too-small buffer in release builds results in silent out-of-bounds writes. All internal callers compute correct sizes, so this requires external API misuse. Analogous to SEC-0023 (same pattern in `appendBatch`).

**Remediation applied:** Replaced `std.debug.assert` with unconditional `if (!cond) @panic("...")` in both `serializeInto` (`record.zig`) and `encryptInto` (`encryption.zig`). `@panic` triggers in all build modes including ReleaseFast/ReleaseSmall, preventing silent out-of-bounds writes. Function signatures unchanged (`void` return).

---

### SEC-0026: Key material transient copies on stack not zeroized (Info, Score 8) — **Closed**

**Evidence:** `src/wal.zig:74` — `init` takes `options: Options` by value. The `Options` struct contains `encryption_key: ?[32]u8`. Stack copies in the caller's frame and `init`'s frame persist after return. The struct-level copy IS zeroized in `deinit` (line 119), but transient stack copies are not.

**Impact:** Key material persists on the stack until overwritten by unrelated function calls. Requires process memory access to exploit. Full mitigation is difficult without compiler cooperation.

**Remediation applied:** Added comprehensive doc comments to `Options` struct documenting the by-value copy behaviour, that Zig does not guarantee stack copy zeroization, and that callers should zeroize their own key material after calling `init`. Includes a code example. The `WriteAheadLog.deinit` zeroizes its internal copy. Full mitigation would require compiler support or API redesign (accept key by pointer) which is out of scope for a defense-in-depth Info finding.

---

### SEC-0027: Compaction scan skips CRC validation on plaintext records (Info, Score 8) — **Closed**

**Evidence:** `src/compaction.zig:66` — "No CRC validation is performed during scanning." Lines 131-151: plaintext path reads header, extracts LSN, seeks past payload+CRC. Encrypted records get implicit validation via GCM auth tag (line 120), but plaintext records are not validated.

**Impact:** A corrupted plaintext record written after `init` (never validated by recovery) could be bulk-copied into the compacted file, preserving the corruption. Requires filesystem corruption between write and compact. The assumption that `recovery.recover` has validated all records does not hold for records written after initialization.

**Remediation applied:** Expanded the doc comment on `compact()` to prominently explain why CRC validation is intentionally skipped (recovery validates all records on WAL open; compaction runs after recovery; re-validating would double I/O; encrypted records get implicit GCM tag validation). The limitation for post-init corrupted records is documented. Adding CRC validation in the scan phase was considered but rejected as it would negate the performance benefit of the seek-only scan and the risk requires filesystem corruption between write and compact.

---

### SEC-0028: appendBatch ignores sync_every_n, unconditionally syncs (Info, Score 8) — **Closed**

**Evidence:** `src/wal.zig:232-235` — `appendBatch` always calls `fdatasync` and resets `appends_since_sync = 0` when `manual_sync` is false, regardless of `sync_every_n`. Compare to single `append` path (lines 158-163) which correctly accumulates and thresholds.

**Impact:** Performance anomaly. Users relying on `sync_every_n > 1` for batched workloads see more fsync calls than configured. The unconditional sync is safer than under-syncing but violates the configured contract.

**Remediation applied:** Changed `appendBatch` sync logic to accumulate `payloads.len` into `appends_since_sync` and check against `sync_every_n` threshold before issuing `fdatasync`, consistent with the `append()` single-record path. Uses `@intCast(payloads.len)` for the u32 counter.

---

## Findings Detail — Review 5

### SEC-0029: Recovery/compaction decryption buffers not zeroized before free (Info, Score 16) — **Closed**

**Evidence:** `src/recovery.zig:125` — `defer allocator.free(blob_buf)` frees the decryption buffer without calling `secureZero`. `src/compaction.zig:117` — same pattern: `defer allocator.free(blob_buf)` without zeroization.

**Impact:** Decrypted plaintext from encrypted WAL records persists in freed heap memory in both the recovery and compaction paths. Recoverable via core dump, `/proc/pid/mem`, or swap. Same root cause as SEC-0024 (iterator path), SEC-0009 (encryption stack buffers), and SEC-0019 (batch heap buffer), all of which were remediated with `secureZero` calls.

**Remediation applied:** Replaced `defer allocator.free(blob_buf)` with a defer block that calls `encryption.secureZero(blob_buf)` before `allocator.free(blob_buf)` in both `recovery.zig:recoverWithKey` and `compaction.zig:compact`. Consistent with the established SEC-0009/0019/0024 remediation pattern.

---

### SEC-0030: LSN pre-incremented before write — stale on partial write error (Low, Score 12) — **Closed**

**Evidence:** `src/wal.zig:153` — `self.current_lsn += 1` executes BEFORE the write at line 155. If the write fails (disk full, I/O error), `current_lsn` has already advanced. The next successful `append` will skip the failed LSN, creating a gap. In `appendBatch` (lines 224-226), the entire LSN range is pre-allocated before any writes occur.

**Impact:** After a write error, `current_lsn` reflects an LSN that was never durably written. This creates LSN gaps in the WAL. For the single `append` path, the gap is 1 LSN. For `appendBatch`, the gap could be up to `payloads.len` LSNs. The file cursor position after a partial `writeAll` failure is also indeterminate — subsequent appends may write at an unexpected offset.

**Remediation applied:** In `append()`, the LSN is now computed tentatively (`current_lsn + 1`) and only committed to `self.current_lsn` after a successful write. On write error, the file is seeked back to the pre-write position and truncated via `ftruncate` to discard any partial data. In `appendBatch()`, the same pattern is applied: LSNs are computed into a local variable during serialization, and `self.current_lsn` is only advanced after the single `writeAll` succeeds. On error, the file is truncated and the LSN remains unchanged.

---

### SEC-0031: appendBatch sync counter u32 overflow at ~4 billion appends (Info, Score 4) — **Closed**

**Evidence:** `src/wal.zig:250` — `self.appends_since_sync += @intCast(payloads.len)`. The field `appends_since_sync` is `u32`. If `sync_every_n` is set very high (or `manual_sync` is toggled between calls), the counter could theoretically overflow after ~4 billion appends without a sync. The `@intCast` from `usize` is safety-checked in Debug/ReleaseSafe but wraps in ReleaseFast/ReleaseSmall.

**Impact:** Extremely theoretical. Requires ~4 billion appends without a single sync, which is operationally implausible. In ReleaseFast, overflow would cause the counter to wrap, potentially triggering an extra sync (safe) or delaying a sync (minor durability window).

**Remediation applied:** Changed both `append()` and `appendBatch()` to use Zig's saturating addition operator (`+|=`) for the `appends_since_sync` counter. This caps at `maxInt(u32)` instead of wrapping, ensuring the counter always triggers a sync when it reaches the threshold rather than silently wrapping past it.

---

## Findings Detail — Review 6

### SEC-0032: Double-free in Iterator.readEncryptedEntry error paths (Medium, Score 24) — **Closed**

**Evidence:** `src/wal.zig:500-553` — `readEncryptedEntry()` has `errdefer self.allocator.free(blob_buf)` on line 511. The SEC-0024 remediation added manual `encryption.secureZero(blob_buf)` + `self.allocator.free(blob_buf)` calls in three `catch |err| { ... return err; }` blocks (decryptRecordInPlace at line 526, record.deserialize at line 533, allocator.dupe at line 540). When these error paths execute `return err`, the `errdefer` also fires, freeing `blob_buf` a second time.

**Impact:** Heap corruption via double-free. In debug builds with Zig's general-purpose allocator, this triggers a panic. In release builds with other allocators, this causes undefined behavior — potential for heap metadata corruption and exploitation. Requires encrypted WAL mode + a corrupted record that passes initial format checks but fails decryption, deserialization, or triggers OOM during payload copy. Recovery normally truncates corrupt records before iteration, so exploitation requires file corruption between recovery and iteration.

**Remediation applied:** Upgraded `errdefer self.allocator.free(blob_buf)` to `errdefer { encryption.secureZero(blob_buf); self.allocator.free(blob_buf); }` — consolidating both SEC-0024 zeroization and memory freeing into a single errdefer block. Removed the manual `secureZero` + `free` calls from all three error-return catch blocks (they are now handled by the errdefer). The null-return path (torn write) and success path retain their manual cleanup since `errdefer` does not fire for non-error returns.

---

## Geode Extraction Metadata

This repository is the intended home for the reusable WAL core, but the Geode review found that part of the current boundary is still mixed with Geode-specific server and storage integration.

### Geode Boundary

Move/own here:

| Geode source | Why it belongs in `wal` |
|---|---|
| `src/wal.zig:18`, `:32` | WAL record types and payload model |
| `src/wal.zig:112`, `:124`, `:223`, `:315`, `:325`, `:455`, `:575`, `:592` | Core append/sync/replay/truncate/checkpoint logic |
| `src/wal.zig:834`, `:847`, `:852` | Global lifecycle wrapper around the WAL core |

Keep in Geode or split into adapter code:

| Geode source | Why it stays |
|---|---|
| `src/server/server_init.zig:127`, `:128`, `:129`, `:130`, `:263`, `:264`, `:269`, `:271`, `:286`, `:294`, `:296` | Server startup/shutdown, recovery orchestration, and mutation-hook installation are product lifecycle concerns |
| `src/graph_store.zig:4274`, `:4305`, `:4335`, `:4454`, `:4478` | Graph-store mutation callbacks and persistence hooks are Geode storage adapters |

### Geode Tests And Benchmarks

| Geode reference | Purpose |
|---|---|
| `tests/test_wal.zig:15`, `:29`, `:58`, `:117`, `:148`, `:189`, `:255`, `:280`, `:309`, `:324`, `:366`, `:397`, `:431`, `:449`, `:477` | Core correctness, recovery, checkpoint, thresholds, and mutation-hook behavior |
| `build.zig:2077`, `:2078`, `:2079`, `:2080` | Geode build wiring for WAL tests |
| `benchmarks/benchmark_audit_latency.zig:166`, `:167`, `:245`, `:247`, `:265`, `:267` | WAL fsync/order latency benchmark reference |

### Current Assessment

- Reusable core: strong.
- Geode-specific pieces still mixed in: server lifecycle, graph-store hooks, and env-based key sourcing in `src/wal.zig:86` through `:121`.
- Migration priority: keep the append/replay/checkpoint core here, but ensure Geode-specific hook installation remains adapter code.

## Parallelism & Concurrency Gap Analysis (2026-03-30)

> **Scope:** Full review of parallelism, concurrency primitives, multiplexing
> patterns, and integration with the `spice` heartbeat-scheduling library.
>
> **Method:** Manual review of all source files, build configuration, dependency
> manifest, and cross-reference with the `spice` library at
> `~/src/devnw/zig/spice`.
>
> **Last updated:** 2026-03-30 (All gaps resolved)

### Executive Summary

All 8 parallelism gaps have been resolved. The WAL now integrates `spice` as a
dependency, uses `std.Thread.RwLock` for read-write separation, and supports
optional parallel batch serialization via heartbeat-scheduled fork/join. Two
gaps (PAR-0003, PAR-0004) were closed as Won't Do after analysis showed the
scan phases are I/O-bound and architecturally sequential.

### Concurrency Architecture (Post-Closure)

| Aspect | State |
|--------|-------|
| Threading model | `std.Thread.RwLock` per instance — exclusive for writes, shared for reads (PAR-0005) |
| Lock granularity | Fine — read-only getters use shared locks, mutating methods use exclusive locks |
| Reader-writer separation | Yes — `currentLsn`, `bytesSinceCompact`, `iterator` use `lockShared` |
| Parallel serialization | Opt-in via `Options.thread_pool: ?*spice.ThreadPool` (PAR-0002) |
| Spice dependency | `build.zig.zon` declares `spice` as path dependency `../spice` (PAR-0001) |
| Iterator isolation | Unchanged — opens independent file handle, shared lock only for key snapshot |
| Multiplexing | Not applicable — documented as caller responsibility (PAR-0006) |

### Stack-Ranked Gaps — Final Status

| ID | Severity | Gap | Status | Resolution |
|----|----------|-----|--------|------------|
| PAR-0001 | High | `spice` not integrated as a dependency | **Closed** | Added to `build.zig.zon` and wired in `build.zig` for lib, test, and check targets |
| PAR-0002 | High | Batch append serializes record encoding sequentially | **Closed** | Implemented parallel fork/join serialization via `spice.ThreadPool.call` with recursive divide-and-conquer. Opt-in via `Options.thread_pool`. 3 new tests (plaintext, encrypted, caller LSNs) |
| PAR-0003 | Medium | Compaction CRC verification is sequential | **Won't Do** | Compaction intentionally skips CRC verification (SEC-0027). Scan phase is I/O-bound sequential header reading. No CPU-bound work to parallelize |
| PAR-0004 | Medium | Recovery scan is single-threaded | **Won't Do** | Recovery must stop at the first corrupt record for correct truncation semantics. Scan is fundamentally sequential by design. I/O is the bottleneck, not CRC computation |
| PAR-0005 | Medium | Coarse mutex prevents concurrent reads and writes | **Closed** | Replaced `std.Thread.Mutex` with `std.Thread.RwLock`. Read-only getters and iterator use `lockShared`/`unlockShared` |
| PAR-0006 | Low | No multiplexed I/O for multi-WAL scenarios | **Closed** | Documented in `DESIGN.md` §6: each instance is independent, callers use external orchestration |
| PAR-0007 | Low | Iterator does not benefit from read-ahead parallelism | **Closed** | Documented as potential future enhancement in `DESIGN.md` §6. Iterator I/O is sequential by nature; prefetch benefit is marginal for typical record sizes |
| PAR-0008 | Info | `volatile` in `encryption.zig` is for zeroization, not concurrency | **Closed** | Already self-documenting in code comments. No confusion risk |

### Closure Details

#### PAR-0001: Spice Integrated — CLOSED

**Changes:**
- `build.zig.zon`: Added `.spice = .{ .path = "../spice" }` dependency
- `build.zig`: Wired `spice_module` into lib, unit test, and check targets
- All 110 unit tests pass with the new dependency

#### PAR-0002: Batch Append Parallelism — CLOSED

**Changes:**
- `wal.zig`: Added `Options.thread_pool: ?*spice.ThreadPool = null`
- `wal.zig`: Added `ParallelSerializeCtx`, `SerializeRange` structs and
  `parallelSerializeRecords` recursive fork/join function
- `wal.zig`: `appendBatchWithLsnsLocked` now uses parallel path when
  `thread_pool` is non-null and batch size > 1
- Parallel path pre-computes per-record buffer offsets, allocates dedicated
  per-record plaintext scratch for encrypted mode, then uses
  `ThreadPool.call` with divide-and-conquer (threshold: 4 records)
- Sequential path unchanged — `thread_pool = null` (default) gives identical
  behavior to the original code
- 3 new tests: plaintext batch, encrypted batch, caller-provided LSNs

#### PAR-0003: Compaction Parallelism — WON'T DO

**Reason:** Compaction intentionally skips CRC verification (SEC-0027). The
scan phase only reads 12-byte headers to extract LSNs and seeks past
payload+CRC. This is I/O-bound sequential reading, not CPU-bound. The
bulk-copy phase is already optimized with zero-copy `copy_file_range(2)` on
Linux (PERF-0014).

#### PAR-0004: Recovery Parallelism — WON'T DO

**Reason:** Recovery must stop at the first corrupt record for correct
truncation semantics (`valid_end` is the last valid record boundary). This
requires strictly sequential CRC validation — records cannot be verified out
of order because a failure at record N invalidates all subsequent records
regardless of their CRC status. The I/O (sequential file reads) is the
bottleneck, not CRC computation. Checkpoint-accelerated recovery (PERF-0013)
already minimizes the scan window on clean shutdowns.

#### PAR-0005: RwLock — CLOSED

**Changes:**
- `wal.zig`: Replaced `mu: std.Thread.Mutex` with `mu: std.Thread.RwLock`
- Read-only getters (`currentLsn`, `bytesSinceCompact`) use `lockShared`/`unlockShared`
- `iterator` uses `lockShared` to snapshot encryption key
- All mutating methods (`append*`, `sync`, `compact`) use `lock`/`unlock` (exclusive)
- All 110 unit tests + 25 integration tests pass at all 4 optimization levels

#### PAR-0006/0007/0008: Documentation — CLOSED

**Changes:**
- `DESIGN.md` §6 updated from "NOT thread-safe" to comprehensive thread
  safety and parallelism documentation
- Multi-WAL orchestration pattern documented (PAR-0006)
- Iterator read-ahead documented as potential future enhancement (PAR-0007)
- `@volatileCast` usage already self-documenting in code (PAR-0008)
- `CLAUDE.md` updated: test count, thread safety, spice dependency
