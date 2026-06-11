# Benchmark Results

Performance baselines and per-commit snapshots for the WAL library.

## Files

- `baseline.json` — Current accepted performance baseline. Regressions are detected against this file.
- `<commit-sha>.json` — Per-commit result snapshots via `make bench-save`.

## JSON Schema (version 1)

```json
{
  "version": 1,
  "timestamp": "ISO 8601",
  "git_commit": "short SHA",
  "system": { "os": "linux", "arch": "x86_64" },
  "tiers": [
    {
      "name": "1K",
      "record_count": 1000,
      "payload_size": 64,
      "append_ops_sec": 0,
      "batch_ops_sec": 0,
      "batch_parallel_ops_sec": 0,
      "iterate_ops_sec": 0,
      "recovery_ms": 0,
      "compact_ms": 0,
      "append_enc_ops_sec": 0,
      "batch_enc_ops_sec": 0,
      "iterate_enc_ops_sec": 0,
      "recovery_enc_ms": 0
    }
  ]
}
```

## Usage

```bash
make bench                 # Run basic benchmarks (existing)
make scale-bench           # Run scale benchmarks, display table
make bench-save            # Run and save to results/<SHA>.json
make bench-baseline        # Save current results as new baseline
make bench-compare         # Compare current run against baseline
```

## Regression Detection

Default threshold: 20%. A metric FAILs if:

- **Throughput** (higher is better): decreases by more than threshold
- **Latency** (lower is better): increases by more than threshold

Custom threshold: `zig build compare-bench -- baseline.json current.json 25`
