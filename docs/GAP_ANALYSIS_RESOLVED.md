# Gap Analysis — Resolved

> **Source of truth:** [GitLab Issues](https://gitlab.com/devnw/zig/wal/-/issues?label_name%5B%5D=gap&state=closed)
> filtered by label `gap`, state `closed`. This file contains resolved/invalidated gaps
> moved out of `docs/GAP_ANALYSIS.md`.
>
> **Last updated:** 2026-03-21

## Resolved Gaps

### GAP-0001: README Quick Start uses non-compiling API signature

- **GitLab issue:** [#1](https://gitlab.com/devnw/zig/wal/-/issues/1) (Closed)
- **Category:** Docs
- **Severity:** High
- **Resolution:** Fixed. Updated `README.md` Quick Start and encryption examples to use correct `init(allocator, dir, filename, options)` signature with proper `dir` handle opening, `defer dir.close()`, `defer iter.deinit()`, and correct variable names.
- **Evidence:** `README.md` lines 57-81 now match `WriteAheadLog.init` signature in `src/wal.zig`.

---

### GAP-0002: DESIGN.md spec diverges from implementation

- **GitLab issue:** [#2](https://gitlab.com/devnw/zig/wal/-/issues/2) (Closed)
- **Category:** Docs
- **Severity:** Medium
- **Resolution:** Fixed. Updated `docs/DESIGN.md` section 3.4 Public API to match implementation: `init(allocator, dir, filename, options)`, `Iterator.Entry` type, fallible `iterator()`, `Iterator.deinit()`, corrected `loadKeyFromEnv` signature, and `{filename}.tmp` in section 4.3.
- **Evidence:** All function signatures in DESIGN.md match corresponding implementations.

---

### GAP-0003: Missing test: mixed plaintext/encrypted WAL

- **GitLab issue:** [#3](https://gitlab.com/devnw/zig/wal/-/issues/3) (Closed)
- **Category:** Test
- **Severity:** Medium
- **Resolution:** Fixed. Added 2 integration tests in `tests/scenarios/encryption.zig`:
  1. `encryption: mixed plaintext then encrypted WAL migration` — writes 3 plaintext, reopens with key, writes 2 encrypted, verifies all 5 readable.
  2. `encryption: compaction of mixed plaintext/encrypted WAL` — writes 2 plaintext + 2 encrypted, compacts at LSN 2, verifies only encrypted records remain.
- **Evidence:** `zig build test-integration --summary all` — 18/18 tests pass.

---

### GAP-0004: Missing test: loadKeyFromEnv not unit tested

- **GitLab issue:** [#4](https://gitlab.com/devnw/zig/wal/-/issues/4) (Closed)
- **Category:** Test
- **Severity:** Medium
- **Resolution:** Fixed. Added 4 unit tests in `src/encryption.zig` covering all `loadKeyFromEnv` code paths: env not set, invalid hex, wrong length, and valid 64-hex-char key. Required `link_libc = true` in build.zig for `setenv`/`unsetenv` access.
- **Evidence:** `zig build test --summary all` — 43/43 tests pass (was 39 before).

---

### GAP-0005: compaction.zig hardcodes std.heap.page_allocator

- **GitLab issue:** [#5](https://gitlab.com/devnw/zig/wal/-/issues/5) (Closed)
- **Category:** Code Quality
- **Severity:** Medium
- **Resolution:** Fixed. Added `allocator: std.mem.Allocator` as first parameter to `compact()`. Replaced all `std.heap.page_allocator` usage with the passed allocator. Updated `WriteAheadLog.compact()` to pass `self.allocator`. Updated all 4 test call sites.
- **Evidence:** `grep -rn 'page_allocator' src/compaction.zig` returns no matches.

---

### GAP-0006: Stale doc comment references internal "Task 8"

- **GitLab issue:** [#6](https://gitlab.com/devnw/zig/wal/-/issues/6) (Closed)
- **Category:** Code Quality
- **Severity:** Low
- **Resolution:** Fixed. Removed `/// Encryption integration is handled by Task 8; this field is reserved.` from `src/wal.zig:25`.
- **Evidence:** `grep -rn 'Task [0-9]' src/` returns no matches.

---

### GAP-0007: Missing performance benchmarks

- **GitLab issue:** [#7](https://gitlab.com/devnw/zig/wal/-/issues/7) (Closed)
- **Category:** Performance
- **Severity:** Low
- **Resolution:** Fixed. Created `bench/main.zig` with 9 benchmarks covering append throughput (64B/1KB/64KB), recovery time, and compaction time — each for both plaintext and encrypted modes. Added `bench` step to `build.zig` (ReleaseFast) and `bench` target to `Makefile`.
- **Evidence:** `zig build bench` runs successfully and outputs timing results.

---

## Won't Do

### CI/CD hash and Docker tag pinning

- **Category:** CI/CD
- **Resolution:** Won't Do. These controls are handled via different mechanisms outside this repository (CI pipeline configuration, container registry policies). Not applicable to this library.

### Pre-commit hooks

- **Category:** CI/CD
- **Resolution:** Won't Do. Pre-commit hook management is handled separately from the library codebase. The Makefile includes `pre-commit-install` and `pre-commit` targets for convenience, but hook enforcement is an operational concern, not a code gap. This includes SEC-0016 (check-yaml `--unsafe` flag).

### CI cache key cross-branch poisoning (SEC-0014)

- **GitLab issue:** [#31](https://gitlab.com/devnw/zig/wal/-/issues/31)
- **Category:** CI/CD
- **Resolution:** Won't Do. CI/CD cache policy is handled via separate organizational controls outside this library.

### CI component SHA pinning

- **Category:** CI/CD
- **Resolution:** Won't Do. CI/CD component pinning is handled via separate organizational controls outside this library.
