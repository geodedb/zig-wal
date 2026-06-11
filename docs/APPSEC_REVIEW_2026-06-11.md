# Application Security Review — Zig WAL Library

- **Target:** `gitlab.com/devnw/zig/wal` working tree at commit `ef6cb13` (branch `main`)
- **Reviewer role:** Defensive, evidence-first appsec code review
- **Frameworks:** OWASP Top 10:2025, CIS Controls v8.1.2
- **Date:** 2026-06-11

---

## 1. Scope and Assumptions

**Reviewed (read directly from disk):**

- `src/`: `atomic.zig`, `checkpoint.zig`, `compaction.zig`, `encryption.zig`, `iterator.zig`, `observability.zig`, `observability_init.zig`, `record.zig`, `recovery.zig`, `root.zig`, `wal.zig`
- `build.zig`, `build.zig.zon`
- `tests/fuzz.zig`, `tests/integration.zig` (entry points), colocated unit tests
- `.gitlab-ci.yml`
- `scripts/detect_diamond_deps.py`, `scripts/sync_diamond_deps.py`, `scripts/sync_diamond_deps.sh`
- Prior-findings docs: `docs/GAP_ANALYSIS_RESOLVED.md`, `docs/SECURITY_REVIEW_NOTES.md` (SEC-0001…SEC-0040 + NEW-1/3/6 series)

**Trust boundary (per `<auth_model>`):** caller-supplied opaque payloads; the on-disk WAL/checkpoint/temp files (which may be corrupted, truncated, or maliciously crafted); and the caller-supplied AES-256-GCM key. No network, no auth, no multi-tenant isolation — this is an embedded library consumed by Geode and Raft.

**Assumptions:**

- The dominant attacker model is **malicious/corrupted file parsing** (untrusted deserialization) plus **AEAD misuse** and **integer/length arithmetic** in the framing layer. I prioritized those.
- The library is single-process; concurrency safety is via an internal `std.Io.RwLock` (note: `CLAUDE.md` still says `std.Thread.RwLock` — doc drift, not a vulnerability).
- I did not execute the build, fuzzer, or tests (no untrusted-code execution / sandbox per hard rules). All findings are from source reading and cross-referencing.
- The `bench/` directory and `tests/scenarios/*` bodies were not exhaustively read; `examples/basic.zig` was not load-bearing for any finding.

**Not reviewed in depth:** the first-party transitive dependencies `thread_pool` and `otel` themselves (only their pinning/provenance in `build.zig.zon`); GitLab CI catalog components `@v1.7.1` (third-party include contents).

---

## 2. Executive Summary

- **No Critical or High findings.** Consistent with the prior 9 internal review rounds, the core parse/recover/encrypt paths are unusually well-hardened: oversized-length DoS limits (SEC-0004), AAD-bound GCM tags (SEC-0001), LSN monotonicity enforcement (SEC-0022), plaintext-injection rejection on encrypted WALs (SEC-0038), partial-write truncation (SEC-0030), key zeroization (SEC-0002), and 0o600 file permissions (SEC-0015/0021) are all present and tested.
- **Highest-risk new finding (Medium):** `WriteAheadLog.truncateAfter` performs a **state-mutating** forward scan that **omits all integrity validation** — no CRC check, no AEAD verification, no LSN monotonicity, and an LSN parse that is **semantically wrong on encrypted WALs** (it reads `blob_len`+magic as the LSN). A crafted or corrupt tail can drive truncation to an attacker-influenced offset, silently discarding or retaining the wrong records. It also has **zero test coverage**. (A01/A08/CWE-353)
- **Supply-chain provenance mismatch (Medium):** `build.zig.zon` pins `otel` at human-readable tag `?ref=v0.1.10`, but the pinned commit `a1afbfe6` is actually otel **v0.1.9** (confirmed against the upstream checkout) and the recorded content hash is `otel-0.1.9-…`. The tag label and the cryptographic pin disagree, undermining the audit trail. (A03/A08/CWE-1357)
- **Several Low/Info hardening items:** weaker length bound in `truncateAfter` vs. recovery; stale `record_count = 0` checkpoint position hint written on every clean shutdown; a misleading code comment in `decryptRecordInPlace` and an incorrect comment in the iterator skip path; `loadKeyFromEnv` reliance on `std.c.getenv` (not thread-safe, key persists in environ).
- **Overall confidence: High** for the absence of memory-safety / injection / crypto-correctness bugs in the reviewed scope; **Medium** for completeness of the supply-chain assessment (dependency bodies not audited).

I cannot and do not declare the code "secure"; the statement is: **no confirmed Critical/High vulnerabilities were found in the reviewed scope**, with the Medium/Low items below.

---

## 3. Findings Table

| ID | Severity | Confidence | Title | Location | OWASP 2025 | Status |
|----|----------|-----------|-------|----------|-----------|--------|
| AS-01 | Medium | High | `truncateAfter` mutates file with no integrity validation; wrong LSN parse on encrypted WALs | `src/wal.zig:789-842` | A08 / A01 | Open |
| AS-02 | Medium | Medium | `otel` dependency tag (`v0.1.10`) disagrees with pinned commit/hash (`v0.1.9`) | `build.zig.zon:11-15` | A03 / A08 | Open |
| AS-03 | Low | High | `truncateAfter` uses a weaker length bound than recovery (`payload_len > MAX_RECORD_SIZE`) | `src/wal.zig:813` | A10 | Open |
| AS-04 | Low | Medium | Checkpoint persisted with `record_count = 0` on every clean shutdown (defense-in-depth weakened) | `src/wal.zig:300-306` | A08 | Open |
| AS-05 | Low | Medium | `loadKeyFromEnv` via `getenv`: not thread-safe; key string persists in process environ | `src/encryption.zig:472-488` | A04 | Open (partially documented) |
| AS-06 | Info | High | Misleading/incorrect comments in `decryptRecordInPlace` and iterator skip path | `src/encryption.zig:444`, `src/iterator.zig:141` | — | Open |
| AS-07 | Info | High | `sync_diamond_deps.py --apply` auto-commits/pushes/re-tags sibling repos and trusts `zig fetch` hash | `scripts/sync_diamond_deps.py:360-521` | A08 | Open (by design; document) |

No prior **resolved** item (GAP-0001…0007, SEC-0001…SEC-0040, NEW-1/3/6) is re-reported. Spot-verified that several claimed remediations are genuinely present in code: SEC-0038 plaintext-injection rejection (`recovery.zig:242`, `iterator.zig:145`, `compaction.zig:236`), SEC-0022 monotonicity (`recovery.zig:238,280`), SEC-0001 AAD binding (`encryption.zig:269,303,406,438`), SEC-0004 size caps (`record.zig:246`, `encryption.zig:140,193`), SEC-0030 write-truncation (`wal.zig:411-435,659-666`), SEC NEW-1 checkpoint monotonicity seed (`recovery.zig:119-122`), SEC NEW-3 mid-record checkpoint fallback (`wal.zig:243-249`).

---

## 4. Finding Details

### AS-01 — `truncateAfter` mutates the WAL with no integrity validation; LSN parse is wrong on encrypted WALs (Medium, High)

**Evidence** — `src/wal.zig:789-842`:

```zig
while (true) {
    const bytes_read = self.file.readPositionalAll(io, &header_buf, valid_end) catch break;
    if (bytes_read < record.HEADER_SIZE) break;

    const lsn = std.mem.readInt(u64, header_buf[0..8], .little);
    const payload_len = std.mem.readInt(u32, header_buf[8..12], .little);

    if (payload_len > record.MAX_RECORD_SIZE) break;       // only guard

    const record_size = record.HEADER_SIZE + payload_len + record.CRC_SIZE;
    const record_end = valid_end + record_size;
    if (lsn > after_lsn) break;

    valid_end = record_end;       // advance trusting on-disk payload_len
    last_lsn = lsn;
}
try self.file.setLength(io, valid_end);   // <-- destructive
```

Unlike `recovery.recover*` (which verifies CRC at `recovery.zig:160,266`, enforces LSN monotonicity at `recovery.zig:238,280`, and rejects plaintext on encrypted WALs at `recovery.zig:242`), `truncateAfter` does **none** of these. It walks the file using only the self-described `payload_len`, then calls `setLength` to discard the tail.

Two distinct problems compound:

1. **No integrity / monotonicity check.** If any record header in the scanned region is corrupt (torn write, bit-rot) or crafted, `valid_end` advances by an attacker-/corruption-controlled `record_size`. The function can land `valid_end` mid-record or skip past a record boundary, so the subsequent `setLength` truncates at a position that does not correspond to a valid record edge — silently corrupting the log or discarding committed data.
2. **Encrypted-WAL semantics are simply wrong.** On an encrypted WAL the on-disk layout is `[blob_len u32][magic 8][nonce 12]…`. `truncateAfter` ignores `self.options.encryption_key` entirely and reinterprets the first 8 bytes (`blob_len` ++ first 4 magic bytes `"ZIGW"`) as a little-endian `u64` "LSN", and bytes 8-12 (`"ALE\0"`) as `payload_len`. The comparison `lsn > after_lsn` and the stride math are therefore meaningless, so truncation occurs at an effectively arbitrary offset.

**Attack scenario (non-destructive, scoped):** An attacker (or a benign torn write) who can influence the bytes of the WAL tail — e.g., the file is on shared storage, or a prior crash left a partially-written record — causes a consumer's later `truncateAfter(after_lsn)` call to truncate at the wrong boundary. On an encrypted WAL, *any* `truncateAfter` call already truncates at a wrong boundary because of the LSN-parse bug. Result: silent loss or retention of records across the truncation point, breaking the WAL's durability/correctness contract (in a Raft consumer, log-tail truncation correctness is safety-critical).

**Impact:** Integrity violation of the durable log (A08 — Software/Data Integrity; CWE-353 Missing Support for Integrity Check / CWE-754 Improper Check of Exceptional Conditions). For an encrypted WAL it is a functional-correctness defect that manifests on every call. No memory-safety impact (bounds are respected; `setLength` only shrinks within the existing file).

**Root cause:** `truncateAfter` reimplements a forward scan instead of reusing the validated `recovery` scan, and the reimplementation predates / omits the encryption-aware and CRC-aware logic that recovery has. It is also untested (`grep` finds only a doc-comment reference, no test in `tests/` or `src/`).

**Remediation (concrete):**

- Drive the truncation scan through the same validated machinery used by recovery so CRC, AEAD, monotonicity, and the encrypted/plaintext split are all honored. Minimal approach: add an `up_to` / `stop_at_lsn` variant to `recovery.recoverWithKey` that stops at the first record with `lsn > after_lsn` and returns its `valid_end`, then have `truncateAfter` call it with `self.options.encryption_key`:

```zig
const info = if (self.options.encryption_key) |*key|
    try recovery_mod.recoverUpToWithKey(self.allocator, self.file, after_lsn, key)
else
    try recovery_mod.recoverUpTo(self.allocator, self.file, after_lsn);
try self.file.setLength(io, info.valid_end);
```

- At minimum, immediately bound the same way recovery does (`record.HEADER_SIZE + payload_len + record.CRC_SIZE > record.MAX_RECORD_SIZE`, see AS-03) **and** verify each record's CRC before advancing, **and** branch on `encryption_key` to use `isEncrypted` + `decryptRecordInPlace` + `record.deserialize` to recover the true inner LSN, exactly as `recovery.zig:222-241` does.

**Regression tests / verification:**

- Add `truncateAfter` tests covering: (a) plaintext WAL with a corrupt-CRC record before `after_lsn` → truncation must stop at the last valid record; (b) **encrypted** WAL → `truncateAfter(N)` keeps exactly LSNs ≤ N and is byte-identical to writing only those records; (c) torn-write tail; (d) `after_lsn = 0` empties the file; (e) round-trip: `truncateAfter` then reopen + `iterator` yields the expected set.
- Property test: for any sequence of appends, `truncateAfter(k)` followed by reopen must equal the prefix of records with LSN ≤ k.

**References:** OWASP A08; CWE-353; CIS v8.1.2 (secure design principles, application testing). Contrast with the already-correct `compaction` rationale (SEC-0027): compaction is allowed to skip CRC *because it runs immediately after a validating recovery scan on open*; `truncateAfter` is a caller-invokable operation with no such precondition, so the SEC-0027 rationale does **not** transfer to it.

---

### AS-02 — `otel` dependency: tag label disagrees with pinned commit and content hash (Medium, Medium)

**Evidence** — `build.zig.zon:11-15`:

```zig
.otel = .{
    .url = "git+https://gitlab.com/devnw/zig/otel.git?ref=v0.1.10#a1afbfe672d5c0894969d0aa49efa7a66510eda3",
    .hash = "otel-0.1.9-B0v3ltxeNgB4mGDRS7r1dapusir8f7_ISb-MvzYltW1h",
    .lazy = true,
},
```

Cross-checked against the upstream checkout: at commit `a1afbfe6…`, `otel/build.zig.zon` declares `.version = "0.1.9"`. So the `?ref=v0.1.10` label and the `.hash = "otel-0.1.9-…"` pin describe **different versions**. The Zig package manager resolves by **commit + hash**, so the build pulls otel **0.1.9**; the `v0.1.10` tag string is purely cosmetic provenance that is incorrect.

**Attack scenario:** This is primarily an **integrity-of-the-record / auditability** problem rather than a direct exploit. An operator or SBOM consumer reading `build.zig.zon` will believe otel `v0.1.10` is in use, while the artifact is `0.1.9`. If a future maintainer "fixes" the hash to match the `v0.1.10` tag without re-reviewing, or if the `v0.1.10` tag is later force-moved upstream, the mismatch masks which code is actually compiled. Because `otel` is `lazy = true` and only resolved under `-Dwith_otel=true`, the blast radius is limited to telemetry-enabled builds.

**Impact:** Supply-chain provenance integrity gap (A03 Software Supply Chain Failures; A08; CWE-1357 Reliance on Insufficiently Trustworthy Component metadata). Low exploitability, but it weakens the SBOM/dependency-scan audit trail that the CI pipeline is designed to provide.

**Root cause:** The convergence re-tag of otel (`v0.1.10` → commit `a1afbfe6`) did not bump otel's internal `.version` field, which remains `0.1.9`; the Zig package hash embeds that internal version.

**Remediation:**

- Make the three fields self-consistent. Either (a) re-release otel with its internal `.version` bumped to match the tag, and re-pin; or (b) accept and document the ecosystem convention that convergence patch tags do not bump the internal version (in which case add tooling that understands it).
- Add a CI check (extend `detect_diamond_deps.py` or a new lint) that parses each dependency's `?ref=vX.Y.Z` and the `.hash = "<name>-X.Y.Z-…"` prefix and **fails if the versions disagree**.

**Verification:** `zig fetch <url-with-ref>` and confirm the printed hash equals the `.hash` field; confirm the `?ref` tag resolves to the same commit recorded after `#`.

**References:** OWASP A03/A08; CIS v8.1.2 Control 2 (software inventory) / Control 16.11 (third-party components, trusted/supported, severity rating).

---

### AS-03 — `truncateAfter` length bound is weaker than the recovery bound (Low, High)

**Evidence** — `src/wal.zig:813`:

```zig
if (payload_len > record.MAX_RECORD_SIZE) break;
```

Recovery and the iterator guard on the **total** record size instead (`src/recovery.zig:153,257`, `src/iterator.zig:159`):

```zig
if (record.HEADER_SIZE + tail_len > record.MAX_RECORD_SIZE) break;     // recovery
```

`MAX_RECORD_SIZE` is 16 MiB. The `truncateAfter` guard accepts a `payload_len` of up to exactly `MAX_RECORD_SIZE` (plus header+CRC overhead), i.e. a record up to ~16 MiB **+ 16 bytes**, whereas recovery rejects anything whose total exceeds 16 MiB. The two code paths disagree on what counts as "oversized."

**Impact:** Low. Because `payload_len` is a `u32` (max ~4 GiB) and the guard caps it at 16 MiB, there is no integer overflow on `record_size`/`record_end` (both fit comfortably in `usize`/`u64`). The concrete consequence is only a 16-byte boundary inconsistency and a missed-defense-in-depth alignment with the canonical limit. This finding is largely subsumed by the AS-01 remediation (routing through recovery), but is called out separately because the bound is wrong even in the plaintext path.

**Remediation:** Use the same total-size check as recovery:

```zig
if (@as(usize, payload_len) + record.HEADER_SIZE + record.CRC_SIZE > record.MAX_RECORD_SIZE) break;
```

(Best resolved by deleting the bespoke scan entirely per AS-01.)

**References:** A10 Mishandling of Exceptional Conditions; CWE-1284 (improper validation of quantity); CIS v8.1.2 code-level checks.

---

### AS-04 — Checkpoint written with `record_count = 0` on every clean shutdown (Low, Medium)

**Evidence** — `src/wal.zig:300-306`:

```zig
checkpoint_mod.writeCheckpoint(self.dir, self.filename, .{
    .last_lsn = self.current_lsn,
    .valid_end = self.file_end,
    .record_count = 0, // record_count not tracked by WAL; checkpoint serves as position hint
}) catch {};
```

The recovery layer specifically defends against a `record_count = 0` checkpoint enabling a non-monotonic record to bypass the LSN guard — `recovery.zig:119-122` seeds `record_count = 1` when `last_lsn > 0`, and there is a dedicated test (`recovery.zig:841` "rejects non-monotonic LSN at checkpoint boundary (SEC NEW-1)"). So the live exploit path is already closed.

**Impact:** Low. The defensive seed in `recoverFromWithKey` neutralizes the immediate risk. However, persisting a value known to be incorrect (`record_count = 0` even when the log is non-empty) means the on-disk checkpoint is structurally untruthful, and any future consumer of `record_count` (e.g., metrics, or a code path that doesn't apply the NEW-1 seed) would inherit the SEC NEW-1 weakness. This is a latent defense-in-depth gap, not a current vulnerability.

**Remediation:** Track an authoritative `record_count` on the WAL (increment in `appendWithLsnLocked` and `appendBatchWithLsnsLocked`, set from `info.record_count` in `init`) and write the true value, so the checkpoint is internally consistent and the NEW-1 seed becomes belt-and-suspenders rather than load-bearing. If tracking is undesirable, document the field as "position hint only; never trusted for monotonicity" at the `Checkpoint` type and assert the seed in `recoverFrom*`.

**References:** A08; CWE-1325/CWE-665 (improper initialization of state); CIS v8.1.2 secure design.

---

### AS-05 — `loadKeyFromEnv` via `getenv`: not thread-safe; key string persists in process environment (Low, Medium)

**Evidence** — `src/encryption.zig:472-488`:

```zig
const hex_str_z: [*:0]const u8 = std.c.getenv(name_buf[0..env_var.len :0]) orelse return null;
const hex_str = std.mem.sliceTo(hex_str_z, 0);
if (hex_str.len != 64) return error.InvalidKey;
var key: [32]u8 = undefined;
errdefer secureZero(&key);
_ = std.fmt.hexToBytes(&key, hex_str) catch return error.InvalidKey;
return key;
```

The function already documents (lines 469-471) that the hex key persists in the environment block. Two residual points:

1. `std.c.getenv` is **not thread-safe** with concurrent `setenv`/`putenv` in the same process; a caller that mutates environment variables on another thread while loading the key could read a torn/dangling pointer. For a library this is a caller-contract caveat worth surfacing in the doc and in `CLAUDE.md`.
2. The decoded `key` is returned **by value** into a `[32]u8`, copied to the caller's stack/`Options`, and the original 64-char hex string remains in `environ` for process lifetime. The struct-level `Options` note (`wal.zig:25-40`, SEC-0026) already advises zeroizing the caller copy.

The hex decode is not constant-time, but this compares a *configuration* key against a fixed-length format (not a secret-equality check against attacker input), so the timing channel is not meaningful here.

**Impact:** Low. Key material exposure window in `environ` (CWE-526 Cleartext Storage in Environment) and a theoretical thread-safety read hazard (CWE-362). Largely mitigated by existing documentation and `secureZero` on error/`deinit`.

**Remediation:** In the doc comment, add: "Not safe to call concurrently with environment mutation; load the key once during single-threaded startup." Recommend (and optionally provide a helper for) `unsetenv` of the variable immediately after a successful load. Consider a `loadKeyFromReader`/`loadKeyFromBytes` API so consumers can source keys from a KMS/file/secret store without ever placing them in `environ`.

**References:** A04 Cryptographic Failures; CWE-526, CWE-362; CIS v8.1.2 Control 3 (data protection), Control 16 (secret storage).

---

### AS-06 — Misleading/incorrect comments in crypto and iterator paths (Info, High)

**Evidence:**

- `src/encryption.zig:444-446`: "For payloads >24 bytes the destination overlaps the ciphertext source…". The actual overlap threshold is `plaintext_len > OFF_CIPHERTEXT (40)`, i.e. a blob larger than 80 bytes — not 24. The safety conclusion is still correct (AES-GCM is counter-mode; the ciphertext source at offset 40 is always *ahead* of the destination at offset 0, so in-place sequential decryption never reads clobbered bytes), but the cited constant is wrong and could mislead a future maintainer reasoning about the overlap.
- `src/iterator.zig:141`: comment claims "blob_buf already secureZero'd+freed inside readEncryptedEntry" for the skipped-record path. `readEncryptedEntry` uses `readEncryptedBlobReuse`, which **retains** the reusable buffer for the next iteration; it is neither freed nor zeroized per-record there. The buffer *is* correctly zeroized+freed once in `Iterator.deinit` (`iterator.zig:239-243`), so there is no leak — but the comment misdescribes the lifecycle.

**Impact:** Informational. No runtime defect; correctness and memory hygiene are intact. The risk is purely that inaccurate comments around security-sensitive crypto/zeroization code increase the chance of a future regression.

**Remediation:** Fix the overlap threshold comment to reference `OFF_CIPHERTEXT (40)`; correct the iterator comment to state that the reuse buffer is retained across iterations and zeroized+freed in `deinit`.

**References:** CIS v8.1.2 secure SDLC (accurate documentation); no CWE.

---

### AS-07 — `sync_diamond_deps.py --apply` auto-commits/pushes/re-tags sibling repos and trusts `zig fetch` output (Info, High)

**Evidence** — `scripts/sync_diamond_deps.py`:

- In `--cascade --apply` (maintainer mode), the tool runs `git checkout -B`, `git commit`, `git tag -a`, and **`git push origin <branch>` / `git push origin <tag>`** across every discovered sibling repo under `$DEVNW_SIBLING_BASES` (lines 433-485).
- `zig_pkg_hash` (lines 220-228) takes whatever hash `zig fetch` prints and writes it directly into `build.zig.zon` (`rewrite_pin`, lines 231-262) without comparing it to an expected/known value — it trusts the network fetch.
- Sibling discovery (lines 130-158) and URL derivation (`_url_for`, lines 161-172) are driven by on-disk repo contents and the `origin` remote; a malicious sibling checkout placed under the configured base could inject a crafted `.name`/URL.

The **default / pre-commit** path is the read-only `detect_diamond_deps.py` and `local_resolve` (no pushes), so routine contributor workflows are safe. The push/tag behavior only triggers under explicit `--cascade --apply`.

**Impact:** Informational for *this* repo's security posture (the dangerous path is opt-in, maintainer-only, and not invoked by CI). Worth flagging because: (1) a tool that auto-pushes and re-tags many repositories is high-blast-radius if run with the wrong `$DEVNW_SIBLING_BASES` or against an attacker-seeded sibling directory; (2) it pins dependency hashes from unverified `zig fetch` output (TOFU), so a compromised intermediate registry/host during a cascade could get its hash committed.

**Remediation (advisory):** Document the trust assumptions of `--apply` prominently (it pushes to remotes and re-tags). Consider: requiring an explicit allow-list of sibling repo paths rather than scanning `$DEVNW_SIBLING_BASES`; verifying each fetched hash against an expected value or a signed manifest before `rewrite_pin`; and a `--dry-run`-by-default posture (it already defaults to dry run — keep it). Not a code change required for this library to ship.

**References:** A03/A08; CWE-494 (download of code without integrity check, conceptually); CIS v8.1.2 Control 16 (secure tooling).

---

## 5. Secure Design Notes (positive controls observed)

The codebase reflects a mature, defense-in-depth posture. Confirmed-present controls:

- **Untrusted-input DoS limits:** `MAX_RECORD_SIZE` (16 MiB) caps allocations in `record.readPayloadAndVerify` (`record.zig:246`), `encryption.readEncryptedBlob*` (`encryption.zig:140,193`), recovery (`recovery.zig:153,257`), iterator (`iterator.zig:159`), and compaction (`compaction.zig:249`). A `comptime` assert guards `usize` headroom on 32-bit targets (`record.zig:75-77`).
- **AEAD done right:** AES-256-GCM with a per-record OS-CSPRNG 96-bit nonce (`encryption.zig:262,297`), the framing metadata (`blob_len`+magic) bound as **AAD** on both encrypt and decrypt (`encryption.zig:269,303,406,438`, SEC-0001), tag verified via `Aes256Gcm.decrypt … catch return error.DecryptionFailed` (`encryption.zig:407,447`), documented nonce-collision key-rotation guidance at 2^32 records (`encryption.zig:19-30`), and bounds-checked `u32` `blob_len` to prevent overflow (`encryption.zig:251,289,387,429`, SEC-0033/0039).
- **Integrity & ordering on recovery:** CRC over header+payload (`record.zig:158,181,268-271`), LSN monotonicity rejection (`recovery.zig:238,280`, SEC-0022), and rejection of plaintext records when a key is configured — preventing plaintext-injection into an encrypted WAL (`recovery.zig:242`, `iterator.zig:145`, `compaction.zig:236`, SEC-0038).
- **Crash consistency:** atomic temp+fsync+rename (`atomic.zig:35-68`, `compaction.zig:70-75`), partial-write truncation with LSN-advances-only-after-write (`wal.zig:411-449,659-682`, SEC-0030), rename-before-close to avoid double-close/EBADF UB (`atomic.zig:53-59`, SEC-0035), and a `poisoned` state that fails closed when the fd can't be reopened (`wal.zig:768-776`, SEC-0008/0037).
- **TOCTOU/symlink mitigation:** pre-delete of stale temp files before create (`atomic.zig:44`, `compaction.zig:62`, SEC-0005) with an explicitly documented residual narrow window (SEC-0011) and acknowledgment that the fully race-free `O_TMPFILE+linkat` is unavailable in Zig std.
- **Key hygiene & least privilege:** `secureZero` on keys, plaintext scratch, and reuse buffers (`encryption.zig:101-105`, `wal.zig:307,545-547`, `iterator.zig:240,245`, SEC-0002/0009/0019/0029); new files created 0o600 and existing files tightened to 0o600 (`wal.zig:207,216`, SEC-0015/0021).
- **Checkpoint robustness:** CRC-protected 28-byte sidecar (`checkpoint.zig:79,100-102`), mid-record/forged-checkpoint fallback to full scan (`wal.zig:243-249`, SEC NEW-3), checkpoint invalidation after compaction/truncate (`wal.zig:753-756,837-840`).
- **Fuzzing & CI security:** `tests/fuzz.zig` targets the four binary-parsing entry points (`deserialize`, `decryptRecord`, `decryptRecordInPlace`, `isEncrypted`); CI runs SAST, dependency scanning, gitleaks/secrets, SBOM generate+scan, and installs the Zig toolchain with a **SHA-256 check against the signed ziglang.org index** (`.gitlab-ci.yml:38-77`).
- **Supply-chain self-defense:** the diamond-dependency detector (`detect_diamond_deps.py`) is a thoughtful guard against the exact multi-version-link hazard that bit the geode/otel stack.

---

## 6. Coverage Gaps and Questions

- **Dependency bodies not audited.** `thread_pool` v0.2.5 and `otel` (0.1.9) source were not reviewed; only their pinning was. The parallel `appendBatch` path (`wal.zig:556-637`) hands raw pointers/lengths to thread-pool workers — its memory safety depends on `thread_pool`'s `submitBatch`/`WaitGroup` semantics, which were not verified.
- **Tests not executed.** The claimed pass counts and the fuzzer's crash-free status are unverified by this review; AS-01's "no `truncateAfter` test" is from source `grep`, which is conclusive for absence.
- **`tests/scenarios/*` bodies** (crash/compaction/encryption/caller_lsn) were not read in full; they may exercise `truncateAfter` indirectly, but the build wiring (`build.zig:120-140`) and `grep` found no direct `truncateAfter` test.
- **Open question (AS-02):** Was `v0.1.10` of otel ever tagged, and at which commit? Resolving this determines whether the fix is "advance the pin to a real 0.1.10" or "relabel to 0.1.9."
- **Open question (AS-01):** Which consumers call `truncateAfter`, and do any of them use it on **encrypted** WALs? A Raft log consumer truncating uncommitted tail entries is the obvious caller; if it runs encrypted, AS-01's encrypted-path bug is actively reachable and should be re-rated upward.
- **Directory-fsync durability gap (SEC-0020)** is documented and accepted (Zig std opens dirs with `O_PATH`); concur it is a platform limitation, not a code defect, but note it remains a real durability edge on non-journaling filesystems.

---

## 7. Prioritized Next Actions

1. **Fix AS-01 (Medium).** Route `truncateAfter` through the validated recovery scan (CRC + AEAD + monotonicity + encryption-aware LSN). Add the missing test matrix, especially the encrypted-WAL case. This is the only finding with plausible data-integrity impact and it is currently untested. Confirm whether any encrypted-WAL consumer calls it (re-rate if so).
2. **Fix AS-02 (Medium).** Reconcile the `otel` `?ref` tag with the pinned commit/hash so all three agree; add a CI lint that fails on `ref` vs `hash` version disagreement (small extension to `detect_diamond_deps.py`).
3. **Fix AS-03 (Low)** as part of the AS-01 rewrite (use the total-size bound).
4. **Address AS-04 (Low):** track and persist a truthful `record_count`, or formally document the field as a non-trusted hint and assert the NEW-1 seed.
5. **Harden AS-05 (Low):** document the `getenv` thread-safety/persistence caveats and offer a non-`environ` key-loading API.
6. **Tidy AS-06 (Info):** correct the two misleading comments in `encryption.zig` and `iterator.zig`.
7. **Document AS-07 (Info):** make the push/tag blast radius and TOFU hash behavior of `sync_diamond_deps.py --apply` explicit; consider an allow-list and hash verification.
8. **Housekeeping:** align `CLAUDE.md` ("`std.Thread.RwLock`") with the actual `std.Io.RwLock`; ensure `scripts/__pycache__/` is git-ignored.

No Critical or High actions are required before shipping; the items above are correctness/hardening and supply-chain-hygiene improvements.
