# Gap Analysis

> **Source of truth:** [GitLab Issues](https://gitlab.com/devnw/zig/wal/-/issues?label_name%5B%5D=gap)
> filtered by label `gap`. This file mirrors OPEN gaps only.
>
> **Last updated:** 2026-03-21

## Gaps

_All gaps have been resolved. See [GAP_ANALYSIS_RESOLVED.md](GAP_ANALYSIS_RESOLVED.md) for details._

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
