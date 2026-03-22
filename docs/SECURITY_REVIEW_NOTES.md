# Security Review Notes

## Review 1

> **Date:** 2026-03-21
> **Reviewer:** Adversarial code review agent
> **Scope:** Full codebase, CI/CD pipeline, runtime assumptions
> **Baseline:** Zig 0.15.1 / Linux 6.17.0 / commit d182c8a (main)

### Methodology

1. **Orientation** — Enumerated all 40 tracked files, identified languages, trust boundaries, and external integrations
2. **Threat model** — Identified 3 threat actors (malicious caller, local attacker, supply chain) and 3 trust boundaries (caller/library, library/filesystem, library/environment)
3. **Automated scans** — gitleaks (0 leaks), semgrep (0 findings), git history for sensitive files (clean)
4. **Manual adversarial review** — Line-by-line review of all 7 source modules (~2,600 LOC), CI config, build system, examples, and test suites
5. **Scoring** — Impact (1-5) x Likelihood (1-5) x 4 = Score (max 100)

### Finding Summary

| Severity | Count | Score Range |
|----------|-------|-------------|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 2 | 24 |
| Low | 3 | 12-16 |
| Info | 2 | 4-8 |
| **Total** | **7** | |

**Status:** All 7 findings resolved and closed (SEC-0001 through SEC-0007).

---

## Review 2

> **Date:** 2026-03-21
> **Reviewer:** Adversarial code review agent (second pass)
> **Scope:** Full codebase + CI/CD pipeline + delivery supply chain
> **Baseline:** Post-remediation of Review 1 findings (all 7 closed)

### Methodology

1. **Orientation** — Re-inventoried repository (40 tracked files, ~2,600 LOC Zig, CI/CD config, build system)
2. **Repo inventory** — Languages: Zig (100% application code), YAML (CI), Makefile. Zero external dependencies (`build.zig.zon`). No Dockerfiles, IaC, or network code.
3. **Threat model** — Refined from Review 1: focused on error-path robustness, residual memory exposure, and defense-in-depth gaps
4. **Automated scans** — 6 tools, all clean:

| Tool | Version | Scope | Result |
|------|---------|-------|--------|
| gitleaks | 8.24.0 | Git history | 0 leaks |
| trufflehog | 3.88.28 | Git + filesystem | 0 secrets |
| semgrep | 1.116.0 | Zig source (auto rules) | 0 findings |
| trivy fs | 0.61.0 | Filesystem + config | 0 vulns |
| grype (via syft SBOM) | 0.87.1 | Dependencies | 0 vulns (0 packages) |
| checkov | 3.2.354 | CI/CD config | 0 findings (no supported IaC) |

5. **Manual adversarial review** — Focused on: error paths and state consistency, memory/buffer hygiene after remediation, TOCTOU and race conditions in file operations, CI/CD supply chain, git configuration hygiene
6. **Scoring** — Same formula: Impact (1-5) x Likelihood (1-5) x 4

### Finding Summary

| Severity | Count | Score Range |
|----------|-------|-------------|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 3 | 20-24 |
| Low | 4 | 8-12 |
| Info | 4 | 4-8 |
| **Total** | **11** | |

**Status:** 9 findings resolved and closed. 2 marked Won't Do (CI/CD concerns handled via separate controls).

### Triaged False Positives

The deep adversarial review agent flagged `appendBatch` encrypted scratch-space overlap
as Critical (Score 80). This was verified as a **false positive**: the overlap pattern
is standard in-place AES-GCM encryption (ciphertext dest == plaintext src at offset 40),
which `Aes256Gcm.encrypt` explicitly supports. For different-sized payloads, dst is always
behind src by exactly 40 bytes (safe forward-copy). Confirmed by prior session analysis.

### Positive Observations (both reviews)

- **Zero external dependencies** — eliminates supply chain risk from third-party packages
- **CRC integrity on all records** — detects corruption before returning data to callers
- **Atomic compaction** — temp+fsync+rename pattern prevents partial rewrites
- **Stack allocation for hot paths** — reduces heap exposure for small payloads
- **Clean secret scan** — no hardcoded keys, tokens, or credentials in source or git history
- **Comprehensive test suite** — 65 tests across unit, integration, and scenario categories
- **Encryption opacity test** — verifies ciphertext doesn't contain plaintext
- **AAD authentication** — framing metadata now covered by GCM tag (post-Review 1)
- **Key zeroization** — encryption keys scrubbed from memory on deinit (post-Review 1)
- **Bounded allocation** — 16 MiB MAX_RECORD_SIZE prevents OOM from crafted files (post-Review 1)

### Areas Not Applicable

The following security domains are not relevant to this library:

- **Network security** — no network I/O
- **Authentication/Authorization** — no user accounts or access control (library-level)
- **SQL/NoSQL injection** — no database queries
- **XSS/CSRF** — no web interface
- **Container security** — no Dockerfiles or container images
- **IaC security** — no Terraform, Helm, or Kubernetes manifests
- **Secret management infrastructure** — key loading is a convenience helper; real secret management is the caller's responsibility

---

## Review 3

> **Date:** 2026-03-21
> **Reviewer:** Adversarial code review agent (third pass)
> **Scope:** Full codebase + CI/CD pipeline + delivery supply chain
> **Baseline:** Post-remediation of Reviews 1 & 2 (16 closed, 2 won't do)

### Methodology

1. **Orientation** — Re-inventoried repository (41 tracked files, ~2,600 LOC Zig)
2. **Automated scans** — 7 tools:

| Tool | Version | Scope | Result |
|------|---------|-------|--------|
| gitleaks | 8.30.0 | Git history (14 commits) | 0 leaks |
| trufflehog | 3.92.5 | Git + filesystem | 0 secrets |
| semgrep | 1.150.0 | Zig source (generic+yaml rules) | 1 finding (false positive — test key in unit test) |
| trivy fs | 0.69.0 | Filesystem + vulns | 0 vulns (0 packages) |
| trivy config | 0.69.0 | CI/CD + config | 0 misconfigurations |
| checkov | 3.2.499 | CI/CD config | 0 findings |
| shellcheck | 0.9.0 | (no .sh files) | N/A |

3. **Manual adversarial review** — Deep analysis of all source modules focusing on:
   - Post-remediation residual gaps (SEC-0009 fix completeness in batch path)
   - Filesystem durability semantics (fsync, rename, directory sync)
   - Permission handling across file lifecycle
   - Recovery parser robustness (LSN validation)
   - Release-mode vs debug-mode behavioral differences
4. **Scoring** — Same formula: Impact (1-5) x Likelihood (1-5) x 4

### Finding Summary

| Severity | Count | Score Range |
|----------|-------|-------------|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 0 | — |
| Low | 0 | — |
| Info | 5 | 4-8 |
| **Total** | **5** | |

**Status:** All 5 findings open (SEC-0019 through SEC-0023). GitLab issues #36-#40 created.

### Triaged False Positives — Review 3

**Semgrep generic.secrets.gitleaks.generic-api-key**: Flagged `src/encryption.zig:467` (the hex string `"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"` in a `loadKeyFromEnv` unit test). This is a sequential test key (0x00..0x1F) with zero entropy — not a real secret.

### Positive Observations — Review 3

All Review 1 & 2 remediations verified in-place:
- **AAD authentication** — blob_len + magic used as AAD in all encrypt/decrypt paths
- **Key zeroization** — secureZero in WAL.deinit, Iterator.deinit, loadKeyFromEnv errdefer
- **Plaintext zeroization** — stack and heap buffers in encryptAndWriteToFile properly zeroed
- **Poisoned state** — compact() error paths set poisoned flag, all write ops check it
- **Bounded allocation** — MAX_RECORD_SIZE enforced in all read paths
- **File permissions** — 0o600 on all createFile calls
- **CODEOWNERS** — correctly set to @devnw
- **Secret patterns** — .gitignore covers common credential file types

### Key Observations

The 5 new findings are all Info severity. The codebase has strong security posture for a library of this nature:
- Zero external dependencies eliminates supply chain risk
- All prior Critical/High/Medium findings have been remediated
- The remaining gaps are defense-in-depth hardening items
- The batch path zeroization gap (SEC-0019) is the most actionable quick win

See `docs/GAP_ANALYSIS.md` for full details and GitLab issue links.

---

## Review 4

> **Date:** 2026-03-21
> **Reviewer:** Adversarial code review agent (fourth pass)
> **Scope:** Full codebase + CI/CD pipeline + delivery supply chain
> **Baseline:** Post-remediation of Reviews 1-3 (21 closed, 2 won't do)

### Methodology

1. **Orientation** — Re-inventoried repository (41 tracked files, ~2,800 LOC Zig)
2. **Automated scans** — 7 tools:

| Tool | Version | Scope | Result |
|------|---------|-------|--------|
| gitleaks | 8.30.0 | Git history (14 commits) | 0 leaks |
| trufflehog | 3.92.5 | Git + filesystem | 0 secrets |
| semgrep | 1.150.0 | Zig source (generic+yaml rules) | 1 finding (false positive — test key, same as Review 3) |
| trivy fs | 0.69.0 | Filesystem + vulns | 0 vulns |
| checkov | 3.2.499 | CI/CD config | 8 passed, 0 failed |
| shellcheck | 0.9.0 | (no .sh files) | N/A |
| osv-scanner | available | (no lockfiles) | N/A |

3. **Deep manual adversarial review** — Focused on:
   - Iterator decryption path memory hygiene (plaintext residue)
   - `debug.assert` / safety-checked cast patterns across all `pub` functions
   - Key material lifecycle through stack copies and by-value passing
   - Compaction integrity assumptions vs. post-init write corruption
   - Sync policy consistency between append and appendBatch
   - `appendBatch` encrypted buffer layout overlap analysis (verified safe)
4. **Scoring** — Same formula: Impact (1-5) x Likelihood (1-5) x 4

### Finding Summary

| Severity | Count | Score Range |
|----------|-------|-------------|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 0 | — |
| Low | 1 | 12 |
| Info | 4 | 8-16 |
| **Total** | **5** | |

**Status:** All 5 findings open (SEC-0024 through SEC-0028). GitLab issues #41-#45 created.

### Triaged False Positives — Review 4

**appendBatch encrypted buffer overlap (candidate SEC-0024):** The deep review agent flagged the encrypted batch buffer layout as a HIGH severity data corruption bug, claiming ciphertext overwrites plaintext in the scratch region for batches of 3+ records. Verified as **FALSE POSITIVE**: mathematical analysis confirms `encryptInto`'s overhead (40 bytes) always ends exactly at `pt_start`, and the ciphertext region either precedes or coincides with the plaintext region. AES-GCM CTR mode supports in-place encryption (ct == plaintext). Confirmed by 3 passing tests: `tests/scenarios/encryption.zig:96` (3 small payloads), `:348` (64/128/256-byte payloads), and `src/wal.zig:847` (3-record encrypted batch).

**Semgrep generic.secrets.gitleaks.generic-api-key**: Same false positive as Review 3 — sequential test key `0x00..0x1F` in `loadKeyFromEnv` unit test.

**Integer overflow on total_size**: Theoretical overflow on 32-bit systems, but Zig's safety-checked arithmetic panics in Debug/ReleaseSafe. Library targets 64-bit (u64 LSN, u64 file_end). Not actionable.

**CRC-32 not cryptographic**: Known design constraint documented in SEC-0022. CRC detects accidental corruption, not adversarial modification. Encrypted mode provides tamper resistance via GCM.

**Filename injection / path traversal**: FALSE POSITIVE. `std.fs.Dir` operations resolve relative to directory handle. Zig rejects null bytes. No shell interpretation.

### Positive Observations — Review 4

All Reviews 1-3 remediations verified in-place and functioning correctly:
- SEC-0001 AAD authentication: `blob_len + magic` used as AAD in all 4 encrypt/decrypt paths
- SEC-0002 Key zeroization: `secureZero` in WAL.deinit, Iterator.deinit, loadKeyFromEnv errdefer
- SEC-0009/0019 Plaintext zeroization: stack/heap buffers in encryptAndWriteToFile and appendBatch properly zeroed
- SEC-0015/0021 File permissions: 0o600 on createFile + fchmod on openFile
- SEC-0022 LSN monotonicity: enforced in both encrypted/plaintext recovery paths
- SEC-0023 EmptyBatch: runtime error in appendBatch, not debug.assert
- Automated scans clean across all 7 tools (consistent across 4 reviews)
- Zero external dependencies (build.zig.zon has empty dependencies)
- Checkov CI/CD scan: 8 checks passed, 0 failed

### Key Observations

The 5 new findings are all Info/Low severity. After 4 adversarial reviews and 28 total findings, the codebase has a strong security posture:
- Zero Critical or High findings in any review
- 21 of 23 actionable findings remediated and closed
- Remaining 5 findings (Review 4) are defense-in-depth hardening items
- SEC-0024 (iterator plaintext residue) is the most actionable quick win — consistent with the SEC-0009/0019 remediation pattern

See `docs/GAP_ANALYSIS.md` for full details and GitLab issue links.

---

## Review 5

> **Date:** 2026-03-21
> **Reviewer:** Adversarial code review agent (fifth pass)
> **Scope:** Full codebase + CI/CD pipeline + delivery supply chain
> **Baseline:** Post-remediation of Reviews 1-4 (26 closed, 2 won't do)

### Methodology

1. **Orientation** — Re-inventoried repository (41 tracked files, ~2,800 LOC Zig)
2. **Repo inventory** — Languages: Zig (100% application code), YAML (CI), Makefile. Zero external dependencies. No Dockerfiles, IaC, or network code.
3. **Threat model** — Refined from Reviews 1-4: focused on residual zeroization gaps in remaining decryption paths, write-error state consistency, and integer overflow in counter fields.
4. **Automated scans** — 7 tools:

| Tool | Version | Scope | Result |
|------|---------|-------|--------|
| gitleaks | 8.30.0 | Git history | 0 leaks |
| trufflehog | 3.92.5 | Git + filesystem | 0 secrets |
| semgrep | 1.150.0 | Zig source (generic+yaml rules) | 1 finding (false positive — test key, same as Reviews 3-4) |
| trivy fs | 0.69.0 | Filesystem + vulns | 0 vulns |
| checkov | 3.2.499 | CI/CD config | 8 passed, 0 failed |
| grype (via syft SBOM) | 0.87.1 | Dependencies | 0 vulns (0 packages); 152 host glibc matches ignored |
| shellcheck | 0.9.0 | (no .sh files) | N/A |

5. **Deep manual adversarial review** — Line-by-line review of all source modules (~2,800 LOC) with focus on:
   - Residual zeroization gaps in recovery and compaction decryption paths (SEC-0024 pattern)
   - Write-error state consistency (LSN advancement vs. durable writes)
   - Integer overflow in sync counter fields across optimization levels
   - Cross-module consistency of remediation patterns from Reviews 1-4
6. **Scoring** — Same formula: Impact (1-5) x Likelihood (1-5) x 4

### Finding Summary

| Severity | Count | Score Range |
|----------|-------|-------------|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 0 | — |
| Low | 1 | 12 |
| Info | 2 | 4-16 |
| **Total** | **3** | |

**Status:** All 3 findings resolved and closed (SEC-0029 through SEC-0031). GitLab issues #46-#48 closed.

### Triaged False Positives — Review 5

**Semgrep generic.secrets.gitleaks.generic-api-key**: Same false positive as Reviews 3-4 — sequential test key `0x00..0x1F` in `loadKeyFromEnv` unit test at `src/encryption.zig:470`.

**grype host glibc matches (152)**: All matches are against the host system's glibc library, not project dependencies. This project has zero external dependencies (`build.zig.zon` has empty dependencies). Not actionable.

### Positive Observations — Review 5

All Reviews 1-4 remediations verified in-place and functioning correctly:
- SEC-0001 AAD authentication: `blob_len + magic` used as AAD in all encrypt/decrypt paths
- SEC-0002 Key zeroization: `secureZero` in WAL.deinit, Iterator.deinit, loadKeyFromEnv errdefer
- SEC-0009/0019/0024 Plaintext zeroization: stack buffers, batch heap buffer, and iterator blob_buf all scrubbed
- SEC-0015/0021 File permissions: 0o600 on createFile + fchmod on openFile
- SEC-0022 LSN monotonicity: enforced in both encrypted/plaintext recovery paths
- SEC-0023 EmptyBatch: runtime error, not debug.assert
- SEC-0025 Buffer panics: unconditional `@panic` in serializeInto and encryptInto
- SEC-0028 Sync consistency: appendBatch now respects sync_every_n threshold
- Automated scans clean across all 7 tools (consistent across 5 reviews)
- Zero external dependencies (build.zig.zon has empty dependencies)

### Key Observations

The 3 new findings are all Info/Low severity. After 5 adversarial reviews and 31 total findings, the codebase has a strong security posture:
- Zero Critical or High findings in any review
- 26 of 29 actionable findings remediated and closed
- 2 Won't Do (CI/CD concerns handled via separate controls)
- Remaining 3 findings are defense-in-depth hardening items
- SEC-0029 (recovery/compaction zeroization) is the most actionable — same pattern as SEC-0024
- Diminishing returns: each review finds fewer and lower-severity issues

See `docs/GAP_ANALYSIS.md` for full details and GitLab issue links.

---

## Review 6

> **Date:** 2026-03-21
> **Reviewer:** Adversarial code review agent (sixth pass)
> **Scope:** Full codebase + CI/CD pipeline + delivery supply chain
> **Baseline:** Post-remediation of Reviews 1-5 (29 closed, 2 won't do)

### Methodology

1. **Orientation** — Re-inventoried repository (41 tracked files, ~3,950 LOC Zig)
2. **Automated scans** — 7 tools:

| Tool | Version | Scope | Result |
|------|---------|-------|--------|
| gitleaks | 8.30.0 | Git history | 0 leaks |
| trufflehog | 3.92.5 | Git + filesystem | 0 secrets |
| semgrep | 1.150.0 | Zig source (generic+yaml rules) | 1 finding (false positive — test key, same as Reviews 3-5) |
| trivy fs | 0.69.0 | Filesystem + vulns | 0 vulns |
| checkov | 3.2.499 | CI/CD config | 8 passed, 0 failed |
| grype (via syft SBOM) | 0.107.0 | Dependencies | 0 vulns (0 packages); 152 host glibc matches ignored |
| shellcheck | 0.9.0 | (no .sh files) | N/A |

3. **Deep manual adversarial review** — Line-by-line review of all source modules, test suites, CI config, and build system (~3,950 LOC total) with focus on:
   - Regression analysis: verifying SEC-0024 remediation didn't introduce new bugs
   - Memory lifecycle correctness: `errdefer` vs manual cleanup interaction patterns
   - All prior remediation patterns verified in-place
4. **Scoring** — Same formula: Impact (1-5) x Likelihood (1-5) x 4

### Finding Summary

| Severity | Count | Score Range |
|----------|-------|-------------|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 1 | 24 |
| Low | 0 | — |
| Info | 0 | — |
| **Total** | **1** | |

**Status:** Finding resolved and closed (SEC-0032). GitLab issue #49 closed.

### Triaged False Positives — Review 6

**Semgrep generic.secrets.gitleaks.generic-api-key**: Same false positive as Reviews 3-5 — sequential test key `0x00..0x1F` in `loadKeyFromEnv` unit test at `src/encryption.zig:470`.

**grype host glibc matches (152)**: All matches are against the host system's glibc library (`glibc@2.42-0ubuntu3.1`), not project dependencies. This project has zero external dependencies. Not actionable.

### Positive Observations — Review 6

All Reviews 1-5 remediations verified in-place and functioning correctly:
- SEC-0001 AAD authentication: verified in all encrypt/decrypt paths
- SEC-0002 Key zeroization: verified in WAL.deinit, Iterator.deinit, loadKeyFromEnv
- SEC-0009/0019/0024/0029 Plaintext zeroization: all paths verified (encryption stack, batch heap, iterator, recovery, compaction)
- SEC-0015/0021 File permissions: 0o600 on createFile + fchmod on openFile
- SEC-0022 LSN monotonicity: enforced in both encrypted/plaintext recovery paths
- SEC-0025 Buffer panics: unconditional `@panic` in serializeInto and encryptInto
- SEC-0030 LSN post-increment: verified in both append and appendBatch
- SEC-0031 Saturating addition: verified in both append and appendBatch sync counters
- Automated scans clean across all 7 tools (consistent across 6 reviews)
- Zero external dependencies (build.zig.zon has empty dependencies)

### Key Observations

After 6 adversarial reviews and 32 total findings, the codebase has a strong security posture:
- Zero Critical or High findings in any review
- 30 of 32 findings remediated and closed
- 2 Won't Do (CI/CD concerns handled via separate controls)
- The single new finding (SEC-0032) was a regression from a prior remediation (SEC-0024), not an original design flaw
- Diminishing returns confirmed: 6th review found only 1 issue, and it was a fix-induced regression

See `docs/GAP_ANALYSIS.md` for full details and GitLab issue links.

## Review 7

> **Date:** 2026-03-22
> **Reviewer:** Adversarial code review agent
> **Finding Summary:** Zero new findings. See Review 7 notes in GAP_ANALYSIS.md.

## Review 8

> **Date:** 2026-03-22
> **Reviewer:** Adversarial code review agent (full-scope security + delivery-pipeline)
> **Scope:** Full codebase, CI/CD pipeline, supply chain, automated scans, manual adversarial review
> **Baseline:** Zig 0.15.1 / Linux 6.17.0 / commit d182c8a (main) + uncommitted quality/security fixes

### Methodology

1. **Orientation** — `git status`, `git remote`, `glab repo view`, full file enumeration
2. **Repo inventory** — 8 source modules (~2,900 LOC), 3 test suites, 1 benchmark, 1 example, CI pipeline with 7 security/quality components
3. **Threat model** — Assets: WAL data (opaque payloads, possibly PII), encryption keys; Trust boundaries: caller/library, library/filesystem, library/environment, CI pipeline
4. **Automated scans** (all tools present, all zero findings):
   - gitleaks 8.30.0: 14 commits scanned, 0 leaks
   - trufflehog: 0 findings (filesystem mode)
   - semgrep (p/default, 81 rules): 0 findings on 41 files
   - trivy 0.69.0 filesystem: 0 vulnerabilities (zero deps)
   - trivy config: 0 misconfigurations
   - checkov: 0 failed checks
5. **Manual adversarial review** — 4 parallel analysis agents:
   - Cryptographic correctness & key lifecycle
   - Memory safety & integer overflow
   - DoS & input validation
   - CI/CD & supply chain
6. **Scoring** — Impact(1-5) × Likelihood(1-5) × 4

### Finding Summary

| Severity | Count | Score Range |
|----------|-------|-------------|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 1 | 16 |
| Low | 1 | 8 |
| Info | 0 | — |
| **Total** | **2** | |

**Status:** 2 findings (SEC-0033, SEC-0034). Both **resolved and closed**.

### Automated Scan Results — Review 8

| Tool | Version | Findings |
|------|---------|----------|
| gitleaks | 8.30.0 | 0 |
| trufflehog | latest | 0 |
| semgrep | latest (p/default) | 0 (81 rules, 41 files) |
| trivy fs | 0.69.0 | 0 |
| trivy config | 0.69.0 | 0 |
| checkov | latest | 0 |
| shellcheck | 0.9.0 | N/A (no .sh files) |

### New Findings — Review 8

#### SEC-0033: Encrypted blob_len @intCast overflow for payloads near u32 max (Medium, Score 16)

**Evidence:** `src/encryption.zig:180` and `src/encryption.zig:213`. Both `encryptRecord` and `encryptInto` compute `blob_len: u32 = @intCast(36 + plaintext.len)`. When `plaintext.len` > `std.math.maxInt(u32) - 36`, the computation overflows u32. In ReleaseFast/ReleaseSmall, `@intCast` safety checks are removed causing silent truncation and corrupted blob_len on disk, making the record unrecoverable. In Debug/ReleaseSafe, it panics.

**Root cause:** The write path allows payloads up to `MAX_PAYLOAD_SIZE` (u32 max) via `serializeInto`, but the encrypted framing adds 36 bytes overhead which pushes `blob_len` past u32 range.

**Impact:** Data corruption — encrypted records written with near-max payloads cannot be recovered. CWE-190.

**Fix:** Add bounds check before `@intCast`, or enforce `MAX_RECORD_SIZE` on the write path.

**GitLab:** [#99](https://gitlab.com/devnw/zig/wal/-/issues/99)

#### SEC-0034: Gitleaks allowlist regex patterns lack path anchoring (Low, Score 8)

**Evidence:** `.gitleaks.toml:11-14`. Patterns like `\.git` match any path containing `.git` as a substring, including `.github/`, `.gitlab/`, `.gitignore`, and `.git-credentials`. A secret in such a path would be silently suppressed.

**Root cause:** Missing regex anchoring (no `^`, `$`, or `/` boundaries).

**Fix:** Anchor patterns: `(^|/)\.git(/|$)`

**GitLab:** [#100](https://gitlab.com/devnw/zig/wal/-/issues/100)

### Triaged Non-Findings — Review 8

1. **Memory safety:** All `@intCast` sites verified — protected by prior bounds checks. errdefer patterns correct. No new double-free, UAF, or buffer overflow issues.

2. **DoS / input validation:** All scan loops have guaranteed termination. `sync_every_n=0` is harmless. No infinite loops from crafted files.

3. **CI pipeline branch restrictions, artifact integrity, check-yaml --unsafe:** Covered by existing Won't Do decisions for CI/CD organizational controls.

### Positive Observations — Review 8

- 8th adversarial review found only 2 new issues (1 Medium, 1 Low) — strong diminishing returns
- All 32 prior security findings remain correctly remediated
- Zero Critical or High findings across all 8 reviews
- 6 automated scanning tools all report zero findings
- Zero external dependencies

See `docs/GAP_ANALYSIS.md` for the full stack-ranked findings table.

---

## Review 9

**Date:** 2026-03-22
**Scope:** Full adversarial code review + delivery-pipeline review (9th review)
**Methodology:** 4 parallel adversarial analysis agents (cryptographic correctness, memory safety, DoS/input validation, CI/CD supply chain) + 6 automated scanners + manual code review of all 8 source modules

### Finding Summary

| Severity | Count | Score Range |
|----------|-------|-------------|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 0 | — |
| Low | 1 | 12 |
| Info | 0 | — |
| **Total** | **1** | |

**Status:** 1 new finding (SEC-0035), **resolved and closed**. All 35 findings (SEC-0001 through SEC-0035) now remediated.

### SEC-0035: Double-close on fd in finalizeTempFile/atomicWriteFile when rename fails (Low, Score 12) — **Closed**

**Evidence:** `compaction.zig:65-70` and `atomic.zig:41-50`. Both closed the fd before `dir.rename()`. If rename failed, caller errdefer double-closed the fd. Zig's `std.posix.close()` treats EBADF as `unreachable` — UB in ReleaseFast/ReleaseSmall, panic in Debug/ReleaseSafe.

**Score:** Impact 3 × Likelihood 1 × 4 = 12 (Low). Same-directory rename almost never fails on POSIX, but UB is unconditional when it does.

**Remediation:** Reordered both functions to rename-before-close. On POSIX, rename operates on directory entries — the fd remains valid. If rename fails, the fd is still open for the errdefer. All tests pass at all optimization levels.

**CWE:** CWE-675 (Multiple Operations on Resource in Single-Operation Context)

**GitLab:** [#101](https://gitlab.com/devnw/zig/wal/-/issues/101)

### Automated Scan Results — Review 9

| Tool | Version | Findings |
|------|---------|----------|
| gitleaks | 8.30.0 | 0 |
| trufflehog | 3.92.5 | 0 |
| semgrep | 1.150.0 (p/default) | 0 |
| trivy fs+misconfig | 0.69.0 | 0 vulns, 0 misconfigs |
| checkov | 3.2.499 (gitlab_ci) | 13 passed, 0 failed |
| shellcheck | 0.9.0 | N/A (no .sh files) |

### Manual Review Coverage — Review 9

**Cryptographic review:**
- AES-256-GCM nonce generation (random 96-bit), AAD binding (blob_len+magic), tag verification — all correct
- Key lifecycle: loading (loadKeyFromEnv with errdefer zeroize), storage (Options struct), zeroization (deinit, secureZero), error-path handling — all correct
- SEC-0033 remediation verified: bounds check before @intCast in both encryptRecord and encryptInto
- In-place decryption overlap safety (decryptRecordInPlace) — previously verified, remains correct
- No timing side channels in security-critical comparisons (GCM tag verification delegated to stdlib)

**Memory safety review:**
- All @intCast sites verified: encryption.zig:188/:226 (bounded by SEC-0033 check), :319/:358 (bounded by MAX_RECORD_SIZE), compaction.zig:168 (bounded by MAX_RECORD_SIZE check at :158), record.zig:123 (bounded by MAX_PAYLOAD_SIZE check at :115), wal.zig:275 (u32 cast of slice.len, infeasible to overflow)
- All allocator patterns (alloc/free/errdefer) verified across all modules — no leaks, double-frees, or UAF
- All `catch {}` sites are in error-recovery paths (SEC-0005 pre-delete, SEC-0021 best-effort fchmod, SEC-0030 truncation rollback)
- No `@truncate`, `@bitCast`, or `@ptrCast` in production code (only one `@truncate` in test code)

**DoS / input validation review:**
- All scan loops (recovery, compaction, iterator) have guaranteed termination conditions
- MAX_RECORD_SIZE enforced at all read-path entry points (7 locations)
- LSN monotonicity enforced in recovery (SEC-0022)
- File descriptor leak analysis: all open/close paths balanced (init errdefer, deinit, iterator.deinit, compaction defer). Note: SEC-0035 (double-close in finalize/atomic rename error path) found during extended triage

**CI/CD supply chain review:**
- Pipeline structure: 7 included CI components at semver tags (Won't Do: SHA pinning)
- SEC-0034 remediation verified: gitleaks allowlist patterns now directory-anchored
- No secrets in pipeline config, no overprivileged runners, no unprotected artifact paths
- checkov passes all 13 GitLab CI checks with 0 failures

### Triaged Non-Findings — Review 9

1. **@intCast in decryptRecord/decryptRecordInPlace (encryption.zig:319/:358):** Converts `blob.len - BLOB_LEN_SIZE` to u32. Safe because all callers go through `readEncryptedBlob` which caps at MAX_RECORD_SIZE (16 MiB, fits in u32). External callers passing >4 GiB blobs would fail the @intCast in safe modes; in release modes the subsequent blob_len comparison would fail, preventing corruption. Flagged by both crypto and memory safety agents — triage confirmed.

2. **@intCast(payloads.len) in appendBatch (wal.zig:275):** Casts usize to u32 for the sync counter. A batch with >4 billion entries is operationally infeasible (slice header alone would be ~64 GiB). The saturating add (+|=) after the cast handles cumulative overflow per SEC-0031. Flagged by memory safety agent — triage confirmed.

3. **appendBatch total_size overflow (wal.zig:214-222):** The sum uses usize (u64 on 64-bit, guaranteed by comptime assert at record.zig:44-46). Cannot overflow in practice; the allocator would OOM first. Flagged by DoS agent — triage confirmed.

4. **Compaction scan lacks LSN monotonicity check:** DoS agent noted recovery enforces SEC-0022 monotonicity but compaction does not. Non-issue: compaction runs after recovery (all records already validated), and compaction correctness only requires per-record LSN comparison against the watermark, not ordering. Same design rationale as SEC-0027 (CRC skip in compaction).

5. **CI/CD candidates (6 items):** CI/CD agent flagged: no `workflow:rules`, unused build artifact, cached toolchain not re-verified, check-todos hook exits 0, gitleaks allowlist redundancy, commitizen major bump mapping. All fall under existing Won't Do policy (CI controls handled via separate organizational controls) or are non-security issues (commitizen config, gitleaks redundancy already fixed by SEC-0034).

### Positive Observations — Review 9

- 9th adversarial review with 4 parallel agents found 1 new low-severity issue (SEC-0035) and confirmed 3 prior triages + 6 CI/CD non-findings
- All 34 prior security findings (SEC-0001 through SEC-0034) remain correctly remediated
- SEC-0033 and SEC-0034 (found in Review 8) both properly closed with code fixes and tests
- Zero Critical or High findings across all 9 reviews
- 75 unit tests and 25 integration/scenario tests pass at all 4 optimization levels
- 6 automated scanning tools report zero findings
- Zero external dependencies (build.zig.zon has empty dependencies)
- checkov validates 13/13 GitLab CI checks

See `docs/GAP_ANALYSIS.md` for the full stack-ranked findings table.

---

## Review 10

**Date:** 2026-03-22
**Scope:** Full adversarial code review + delivery-pipeline review (10th review)
**Methodology:** 4 parallel adversarial analysis agents (cryptographic correctness, memory safety, DoS/input validation, CI/CD supply chain) + 6 automated scanners + manual triage of all agent candidates

### Finding Summary

| Severity | Count | Score Range |
|----------|-------|-------------|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 1 | 32 |
| Low | 0 | — |
| Info | 1 | 16 |
| **Total** | **2** | |

**Status:** 2 new findings (SEC-0036, SEC-0037), both **resolved and closed**. All 37 findings (SEC-0001 through SEC-0037) are now remediated.

### SEC-0036: Iterator skip-path plaintext not zeroized before free (Info, Score 16) — **Closed**

**Evidence:** `src/iterator.zig:92-94`. When `Iterator.next()` decrypts an encrypted record and determines its LSN is at or below `from_lsn`, the duped payload allocation is freed without `secureZero`:

```zig
if (e.lsn <= self.from_lsn) {
    self.allocator.free(e.payload);  // no secureZero before free
    continue;
}
```

The blob_buf containing the full decrypted record is correctly zeroized at line 168 (SEC-0024 fix), but the `payload_copy` returned by `self.allocator.dupe(u8, rec.payload)` at line 167 is a separate heap allocation. When discarded in the skip path, the plaintext bytes remain in freed heap memory.

**Score:** Impact 2 × Likelihood 2 × 4 = 16 (Info). Same class as SEC-0024/SEC-0029 — requires a separate memory disclosure primitive for exploitation.

**CWE:** CWE-244 (Improper Clearing of Heap Data Before Release)

**GitLab:** [#102](https://gitlab.com/devnw/zig/wal/-/issues/102)

**Remediation:** Added `encryption.secureZero(@constCast(e.payload))` before `self.allocator.free(e.payload)` in the iterator skip path (`iterator.zig:94`). Matches the established zeroization pattern from SEC-0024/SEC-0029/SEC-0032.

### SEC-0037: Double-close on stale fd when reopenOrPoison fails after compact (Medium, Score 32) — **Closed**

**Evidence:** `src/wal.zig:307-347`. `compact()` closes `self.file` at line 312. If `reopenOrPoison()` (line 323 or 328) fails at `openFile` (line 340), `self.poisoned = true` is set but `self.file` retains the stale closed fd. When `deinit()` is later called (line 138), it unconditionally calls `self.file.close()` — double-close on a stale fd.

```zig
// compact() line 312: fd closed
self.file.close();
// ...
// reopenOrPoison() line 340-342: openFile fails
self.file = self.dir.openFile(...) catch {
    self.poisoned = true;
    return;  // self.file still holds the old closed fd!
};
// ...
// deinit() line 138: double-close → EBADF → unreachable → UB
self.file.close();
```

Zig's `std.posix.close` treats EBADF as `unreachable` — UB in ReleaseFast/ReleaseSmall, panic in Debug/ReleaseSafe. The recycled fd could belong to another subsystem, causing silent data corruption.

**Score:** Impact 4 × Likelihood 2 × 4 = 32 (Medium). Requires compaction + file-open failure (unusual filesystem conditions).

**CWE:** CWE-675 (Multiple Operations on Resource in Single-Operation Context)

**GitLab:** [#103](https://gitlab.com/devnw/zig/wal/-/issues/103)

**Remediation:** Two-part fix: (1) `deinit` now guards `self.file.close()` with `if (!self.poisoned)` — when poisoned, the fd is known stale. (2) `reopenOrPoison` establishes an invariant: when setting `poisoned = true`, `self.file` always holds a stale (closed) fd. If `openFile` fails, the old fd was already closed by `compact()`. If `seekFromEnd` fails, the newly opened fd is explicitly closed before poisoning. This eliminates the double-close UB in all paths.

### Automated Scan Results — Review 10

| Tool | Version | Findings |
|------|---------|----------|
| gitleaks | 8.30.0 | 0 (14 commits) |
| trufflehog | 3.92.5 | 0 |
| semgrep | 1.150.0 (p/default) | 0 |
| trivy fs | 0.69.0 | 0 vulns, 0 secrets |
| trivy config | 0.69.0 | 0 misconfigs |
| checkov | 3.2.499 (gitlab_ci) | 13 passed, 0 failed |

### Manual Review Coverage — Review 10

**Cryptographic review (agent):**
- AES-256-GCM nonce generation, AAD binding, tag verification — all correct
- Key lifecycle (loading, storage, zeroization, error paths) — all correct
- SEC-0033 remediation verified: bounds checks in encryptRecord and encryptInto
- appendBatch scratch-region aliasing formally proved safe (40-byte gap between encrypted output frontier and plaintext scratch for every record)
- SEC-0035 rename-before-close fix verified correct in both atomic.zig and compaction.zig
- **New finding:** SEC-0036 (iterator skip-path plaintext not zeroized)

**Memory safety review (agent):**
- All @intCast sites verified safe (bounded by upstream guards or type limits)
- appendBatch encrypted scratch-region overlap proved safe analytically
- Stack buffer sizing verified across all modules
- All `undefined` variables fully written before consumption
- **New finding:** SEC-0037 (double-close on stale fd when reopenOrPoison fails at openFile after compact closes the fd)

**DoS / input validation review (agent):**
- All scan loops (recovery, compaction, iterator) have guaranteed termination
- MAX_RECORD_SIZE enforced at all read-path entry points
- SEC-0035 fix verified in both call sites
- seekBy i64 cast bounded by upstream MAX_RECORD_SIZE guard
- sync_every_n=0: confirmed harmless (previously triaged)
- Encrypted record detection false positive: requires LSN ~5×10^18, unreachable

**CI/CD supply chain review (agent):**
- Zero external Zig dependencies
- No secrets in pipeline configuration
- No privileged runners, no deployment stages
- Gitleaks allowlist anchoring (SEC-0034) verified correct
- CODEOWNERS (SEC-0017) verified correct
- All CI components from project's own CI catalog
- checkov 13/13 GitLab CI checks pass

### Triaged Non-Findings — Review 10

1. **`sync_every_n = 0` forces sync-every-write (DoS agent):** Previously triaged in Review 9. The u32 comparison `appends_since_sync >= 0` is always true, causing fdatasync on every append — equivalent to `sync_every_n = 1` (the default, safest behavior). Not a security issue.

2. **`seekBy` i64 cast guard dependency (DoS agent):** The @intCast to i64 at compaction.zig:171 and iterator.zig:114 is safe because MAX_RECORD_SIZE (16 MiB) is enforced 3-5 lines above each call. Even without the guard, u32_max + 4 ≈ 4.3 billion fits within i64. Informational only.

3. **CLAUDE.md discloses internal repository paths (CI/CD agent):** CLAUDE.md references sibling repos (Geode, Raft) under the devnw org. The org name is already public in CI component URLs. This is an information hygiene observation, not a security vulnerability. No GitLab issue.

4. **ZIG_VERSION variable override by Developer-level user (CI/CD agent):** A Developer could override `ZIG_VERSION` at pipeline trigger time. Falls under CI/CD access control handled via organizational controls (same category as hash pinning Won't Do). Invalid versions would fail download; tests would catch anomalies. No GitLab issue.

5. **appendBatch encrypted scratch buffer overlap (DoS agent):** The scratch region overlaps with encryption output for the last record. Verified safe: the overlap is always forward (destination before source), same pattern as SEC-0003. The 40-byte ENCRYPTION_OVERHEAD gap ensures no corruption. Both crypto and memory safety agents independently proved this correct.

### Positive Observations — Review 10

- 10th adversarial review with 4 parallel agents found 2 new issues (1 Medium, 1 Info) — SEC-0037 is noteworthy as it's the same CWE as SEC-0035 but a different root cause
- All 35 prior security findings (SEC-0001 through SEC-0035) remain correctly remediated
- Memory safety agent verified all allocator patterns, @intCast sites, and errdefer chains clean
- appendBatch encrypted scratch-region aliasing formally proved safe (independently by both crypto and memory safety agents)
- Zero Critical or High findings across all 10 reviews
- 75 unit tests and 25 integration/scenario tests pass at all 4 optimization levels
- 6 automated scanning tools report zero findings
- Zero external dependencies
- checkov validates 13/13 GitLab CI checks

See `docs/GAP_ANALYSIS.md` for the full stack-ranked findings table.

---

## Review 11

> **Date:** 2026-03-22
> **Reviewer:** Adversarial security code-review agent
> **Scope:** Full codebase, CI/CD pipeline, delivery pipeline, runtime assumptions
> **Baseline:** Zig 0.15.1 / Linux 6.17.0-19-generic / commit 9f1c73b (main)

### Methodology

1. **Orientation** — `git rev-parse`, `glab repo view`, `git ls-files`, `find` to enumerate all 45 tracked + untracked files
2. **Automated scans** — 8 tools:
   - gitleaks 8.30.0: 14 commits scanned, 0 leaks (308 KB)
   - trufflehog 3.92.5: 0 findings
   - semgrep 1.150.0: 81 rules on 41 files, 0 findings
   - trivy 0.69.0 (fs): 0 vulnerabilities, 0 secrets
   - trivy 0.69.0 (config): 0 misconfigurations
   - syft 1.41.1 + grype 0.107.0: SBOM generated, host-only CVEs (no app dependencies)
   - osv-scanner 2.3.2: 0 package sources found (correct — zero dependencies)
   - shellcheck 0.9.0: available (no .sh files in repo)
3. **Manual adversarial review** — Full line-by-line review of all 8 source modules (~2,800 LOC), CI config, build.zig, build.zig.zon, pre-commit config, gitleaks config, Makefile, examples, benchmarks, and tests
4. **Scoring** — Impact (1-5) x Likelihood (1-5) x 4 = Score (max 100)

### Tool Versions

| Tool | Version | Path |
|------|---------|------|
| gitleaks | 8.30.0 | /usr/local/bin/gitleaks |
| trufflehog | 3.92.5 | /usr/local/bin/trufflehog |
| semgrep | 1.150.0 | ~/.local/bin/semgrep |
| syft | 1.41.1 | ~/.local/bin/syft |
| grype | 0.107.0 | ~/.local/bin/grype |
| trivy | 0.69.0 | ~/.local/bin/trivy |
| osv-scanner | 2.3.2 | /usr/local/bin/osv-scanner |
| shellcheck | 0.9.0 | ~/.local/bin/shellcheck |
| snyk | NOT FOUND | — |
| hadolint | available | ~/.local/bin/hadolint (no Dockerfiles) |
| checkov | available | ~/.local/bin/checkov (not re-run — prior results current) |
| bandit | available | ~/.local/bin/bandit (Python — not applicable) |

### Finding Summary

| Severity | Count | Score Range |
|----------|-------|-------------|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 0 | — |
| Low | 1 | 24 |
| Info | 2 | 8 |

### New Findings

1. **SEC-0038** (Low, Score 24): Encrypted WAL mode silently accepts plaintext record injection. Recovery, iteration, and compaction fall through to plaintext parsing when the encryption magic is absent, even when an encryption key is configured. GitLab [#104](https://gitlab.com/devnw/zig/wal/-/issues/104).

2. **SEC-0039** (Info, Score 8): `decryptRecord` and `decryptRecordInPlace` contain unguarded `@intCast(blob.len - BLOB_LEN_SIZE)` — same class as SEC-0033 but on the decrypt side. Internal callers protected by MAX_RECORD_SIZE; public API exposed. GitLab [#105](https://gitlab.com/devnw/zig/wal/-/issues/105).

3. **SEC-0040** (Info, Score 8): No fuzz testing infrastructure for binary format parsers. Zig's `std.testing.fuzz` not used despite parsing untrusted binary input. GitLab [#106](https://gitlab.com/devnw/zig/wal/-/issues/106).

### Triaged Non-Findings

1. **Pre-commit hook rev tag pinning vs SHA** — Local developer convenience; CI skips Zig hooks. Non-issue.
2. **Grype host-system CVEs** — syft+grype reported glibc CVEs from the host OS. Zero application dependencies.

### Cumulative Status (Post-Review 11)

- 40 total findings across 11 reviews (SEC-0001 through SEC-0040)
- 40 resolved and closed (SEC-0038, SEC-0039, SEC-0040 closed in this review)
- 0 Critical or High severity findings in any review
- 8 automated scanning tools report zero application-level findings
- 79 unit tests + 25 integration/scenario tests + 4 fuzz tests pass at all 4 optimization levels
- Zero external dependencies

See `docs/GAP_ANALYSIS.md` for the full stack-ranked findings table.

---

## Review 12

> **Date:** 2026-03-22
> **Reviewer:** Adversarial security code-review agent
> **Scope:** Full codebase, CI/CD pipeline, delivery pipeline, runtime assumptions
> **Baseline:** Zig 0.15.1 / Linux 6.17.0-19-generic / commit 9f1c73b (main)

### Methodology

1. **Orientation** — `git rev-parse`, `git ls-files`, `find` to enumerate all tracked + untracked files
2. **Automated scans** — 8 tools:
   - gitleaks 8.30.0: 14 commits scanned, 0 leaks
   - trufflehog 3.92.5: 0 findings
   - semgrep 1.150.0: 0 findings
   - trivy 0.69.0 (fs): 0 vulnerabilities, 0 secrets
   - trivy 0.69.0 (config): 0 misconfigurations
   - syft 1.41.1 + grype 0.107.0: SBOM generated, host-only CVEs (no app dependencies)
   - osv-scanner 2.3.2: 0 package sources found (correct — zero dependencies)
   - shellcheck 0.9.0: available (no .sh files in repo)
3. **Manual adversarial review** — 4 parallel analysis agents:
   - Cryptographic correctness (AES-256-GCM, nonce management, AAD binding, key lifecycle)
   - Memory safety (buffer overlaps, double-free, use-after-free, integer overflow)
   - DoS / input validation (crafted inputs, infinite loops, resource exhaustion)
   - CI/CD supply chain (pipeline config, dependency management, build system)
4. **Scoring** — Impact (1-5) x Likelihood (1-5) x 4 = Score (max 100)

### Tool Versions

| Tool | Version | Path |
|------|---------|------|
| gitleaks | 8.30.0 | /usr/local/bin/gitleaks |
| trufflehog | 3.92.5 | /usr/local/bin/trufflehog |
| semgrep | 1.150.0 | ~/.local/bin/semgrep |
| syft | 1.41.1 | ~/.local/bin/syft |
| grype | 0.107.0 | ~/.local/bin/grype |
| trivy | 0.69.0 | ~/.local/bin/trivy |
| osv-scanner | 2.3.2 | /usr/local/bin/osv-scanner |
| shellcheck | 0.9.0 | ~/.local/bin/shellcheck |

### Finding Summary

| Severity | Count | Score Range |
|----------|-------|-------------|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 0 | — |
| Low | 0 | — |
| Info | 0 | — |
| **Total** | **0** | |

**Status:** Zero new findings. All candidate findings triaged as false positives or Won't Do duplicates.

### Triaged Non-Findings

1. **appendBatch encrypted scratch buffer overlap** — Memory safety agent flagged `pt_start = total_size - rec_size` as buffer corruption risk. False positive: gap between write cursor and scratch area is always ≥ 40 bytes (encryption overhead). For the final record, ciphertext and plaintext coincide — standard in-place AES-GCM. Previously triaged in Reviews 2 and 7.

2. **Iterator seekBy infinite loop** — DoS agent claimed `seekBy` could fail silently. False positive: `seekBy` uses `try` (errors propagate), and `payload_len` is bounded by MAX_RECORD_SIZE (16 MiB) at `iterator.zig:114`.

3. **atomicWriteFile filename validation** — DoS agent flagged missing filename length validation. False positive: `atomic.zig` uses a 256-byte `BoundedArray` and returns `error.FilenameTooLong`.

4. **CI toolchain download hash verification** — Won't Do duplicate.
5. **apt package version pinning** — Won't Do duplicate.
6. **CI component SHA pinning** — Won't Do duplicate.
7. **Pre-commit hook enforcement** — Won't Do duplicate.

### Cumulative Status (Post-Review 12)

- 40 total findings across 12 reviews (SEC-0001 through SEC-0040)
- 40 resolved and closed
- 0 open findings
- 0 Critical or High severity findings in any review
- 8 automated scanning tools report zero application-level findings across all 12 reviews
- 79 unit tests + 25 integration/scenario tests + 4 fuzz tests pass at all 4 optimization levels (108 total)
- Zero external dependencies

See `docs/GAP_ANALYSIS.md` for the full stack-ranked findings table.

---

## Review 13

> **Date:** 2026-03-22
> **Reviewer:** Adversarial code review agent (thirteenth pass)
> **Scope:** Full codebase + CI/CD pipeline + delivery supply chain
> **Baseline:** Post-remediation of Reviews 1-12 (40 closed, 0 open)

### Methodology

1. **Orientation** — Re-inventoried repository, confirmed scope unchanged from Review 12
2. **Automated scans** — 7 tools:

| Tool | Version | Scope | Result |
|------|---------|-------|--------|
| gitleaks | 8.30.0 | Git history | 0 leaks |
| trufflehog | 3.92.5 | Git + filesystem | 0 secrets |
| semgrep | 1.150.0 | Zig source (p/default) | 0 findings |
| trivy fs | 0.69.0 | Filesystem + vulns | 0 vulns |
| trivy config | 0.69.0 | Misconfigurations | 0 misconfigs |
| checkov | 3.2.499 | CI/CD config (gitlab_ci) | 14 passed, 0 failed |
| shellcheck | 0.9.0 | (no .sh files) | N/A |

3. **Deep manual adversarial review** — 4 parallel analysis agents:
   - Cryptographic correctness & key lifecycle
   - Memory safety & integer overflow
   - DoS & input validation
   - CI/CD & supply chain
4. **Additional manual verification** — grep-based audit of all `@intCast`, `@truncate`, `@panic`, and `@unreachable` sites across all source modules
5. **Scoring** — Same formula: Impact (1-5) x Likelihood (1-5) x 4

### Finding Summary

| Severity | Count | Score Range |
|----------|-------|-------------|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 0 | — |
| Low | 0 | — |
| Info | 0 | — |
| **Total** | **0** | |

**Status:** Zero new findings. All candidate findings triaged as false positives or Won't Do duplicates.

### Triaged Non-Findings — Review 13

1. **appendBatch encrypted scratch buffer overlap** — Memory safety agent flagged `pt_start = total_size - rec_size` as buffer corruption risk. False positive: gap between write cursor and scratch area is always ≥ 40 bytes (encryption overhead). For the final record, ciphertext and plaintext coincide — standard in-place AES-GCM. Previously triaged in Reviews 2, 7, and 12.

2. **CI toolchain download hash verification** — Won't Do duplicate. Handled via separate organizational controls.

### Cumulative Status (Post-Review 13)

- 40 total findings across 13 reviews (SEC-0001 through SEC-0040)
- 40 resolved and closed
- 0 open findings
- 0 Critical or High severity findings in any review
- 7 automated scanning tools report zero application-level findings across all 13 reviews
- 79 unit tests + 25 integration/scenario tests + 4 fuzz tests pass at all 4 optimization levels (108 total)
- Zero external dependencies
- Two consecutive zero-finding reviews (Reviews 12 and 13) confirm convergence

See `docs/GAP_ANALYSIS.md` for the full stack-ranked findings table.
