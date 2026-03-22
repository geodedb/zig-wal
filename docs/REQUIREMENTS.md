# Requirements

Last updated: 2026-03-21

## Scope

This repository owns the reusable WAL core extracted from Geode. It does not own Geode server lifecycle orchestration or graph-store persistence-hook wiring.

## Functional Requirements

| ID | Requirement | Geode evidence |
|---|---|---|
| WAL-REQ-001 | The library SHALL expose WAL record types and payload formats. | `src/wal.zig:18`, `:32` |
| WAL-REQ-002 | The library SHALL expose WAL lifecycle operations: init, append, sync, replay, truncate, checkpoint, and threshold checks. | `src/wal.zig:112`, `:124`, `:223`, `:315`, `:325`, `:455`, `:575`, `:592` |
| WAL-REQ-003 | The library MAY expose a global lifecycle wrapper for applications that want it. | `src/wal.zig:834`, `:847`, `:852` |
| WAL-REQ-004 | The library SHALL NOT own Geode server startup/shutdown orchestration. | `src/server/server_init.zig:127` through `:130`, `:263` through `:297` stay in Geode |
| WAL-REQ-005 | The library SHALL NOT own Geode graph-store callback/hook integration in its initial extraction boundary. | `src/graph_store.zig:4274`, `:4305`, `:4335`, `:4454`, `:4478` stay in Geode or an adapter |

## Packaging Requirements

| ID | Requirement | Geode evidence |
|---|---|---|
| WAL-PKG-001 | The reusable core SHALL remain separable from Geode mutation-hook wiring. | `src/graph_store.zig:4305`, `:4335` |
| WAL-PKG-002 | Env-based key loading SHALL be documented as a current packaging coupling or converted to explicit configuration. | `src/wal.zig:86` through `:121` |

## Test Requirements

| ID | Requirement | Geode evidence |
|---|---|---|
| WAL-TEST-001 | Preserve WAL init/append/replay/checkpoint/threshold unit coverage. | `tests/test_wal.zig:15`, `:29`, `:58`, `:117`, `:148`, `:189`, `:255`, `:280`, `:309`, `:324`, `:366`, `:397`, `:431`, `:449`, `:477` |
| WAL-TEST-002 | Preserve Geode build integration for the WAL test target. | `build.zig:2077`, `:2078`, `:2079`, `:2080` |
| WAL-TEST-003 | Preserve the WAL ordering/latency benchmark reference. | `benchmarks/benchmark_audit_latency.zig:166`, `:167`, `:245`, `:247`, `:265`, `:267` |

## Documentation Requirements

- Document the separation between WAL core behavior and Geode server/storage adapters.
- Document checkpoint and replay semantics.
- Document the current encryption/key-loading behavior and whether it remains env-based.

## Migration Requirements

1. Keep the append/replay/checkpoint core in this library.
2. Leave Geode server-init and graph-store hook installation outside the core boundary.
3. Repoint Geode to consume this repo for the core without moving product orchestration here.
