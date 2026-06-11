# wal - Zig Library Makefile
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024-2025 CodePros

.PHONY: all build test test-unit test-integration clean check fmt help dev ci bench
.PHONY: scale-bench bench-save bench-baseline bench-compare
.PHONY: test-debug test-release-safe test-release-fast test-release-small test-all-optimizations
.PHONY: test-fuzz security-scan release
.PHONY: pre-commit-install pre-commit pre-commit-run

# Default target: build and run tests
all: build test-unit
	@echo "✅ All builds and tests completed successfully!"

# Build the library
build:
	@echo "🔨 Building wal..."
	@zig build

# Compile the example (guards against API drift in examples/basic.zig, QA-0077)
example:
	@echo "🔧 Building example..."
	@zig build example

# Run all tests
test: test-unit test-integration
	@echo "✅ All tests completed"

# Run unit tests only
test-unit:
	@echo "🧪 Running unit tests..."
	@zig build test --summary all

# Run integration tests only
test-integration:
	@echo "🔗 Running integration tests..."
	@zig build test-integration --summary all

# Run basic performance benchmarks.
# -Doptimize=ReleaseFast also compiles the deps (thread_pool) optimized; the
# WAL module itself is already forced to ReleaseFast in build.zig (PERF-0031).
bench:
	@echo "Running benchmarks..."
	@zig build bench -Doptimize=ReleaseFast

# Run multi-tier scale benchmarks (JSON to stdout, table to stderr)
scale-bench:
	@zig build scale-bench -Doptimize=ReleaseFast 2>/dev/null

# Run scale benchmarks and save results to bench/results/<git-sha>.json
bench-save:
	@zig build scale-bench -Doptimize=ReleaseFast 2>/dev/null > bench/results/$$(git rev-parse --short HEAD).json
	@echo "Saved to bench/results/$$(git rev-parse --short HEAD).json"

# Save current results as the new accepted baseline
bench-baseline:
	@zig build scale-bench -Doptimize=ReleaseFast 2>/dev/null > bench/results/baseline.json
	@echo "Saved to bench/results/baseline.json"

# Run scale benchmarks and compare against baseline (exit 1 on regression)
bench-compare:
	@zig build scale-bench -Doptimize=ReleaseFast 2>/dev/null > /tmp/wal-current-bench.json
	@zig build compare-bench -- bench/results/baseline.json /tmp/wal-current-bench.json

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	@rm -rf zig-cache zig-out .zig-cache

# Check for compilation errors (fast, no codegen)
check:
	@echo "🔍 Checking for compilation errors..."
	@zig build check

# Format source code
fmt:
	@echo "📝 Formatting code..."
	@zig fmt src/ tests/ bench/ examples/ build.zig

# Quick development iteration loop
dev: fmt check test-unit
	@echo "✅ Development checks passed"

# Full CI pipeline (clean slate)
ci: clean build example test
	@echo "✅ CI pipeline passed"

# Release optimization level tests
test-release-safe:
	@echo "🧪 Testing with ReleaseSafe..."
	@zig build test -Doptimize=ReleaseSafe --summary all

test-release-fast:
	@echo "🧪 Testing with ReleaseFast..."
	@zig build test -Doptimize=ReleaseFast --summary all

test-release-small:
	@echo "🧪 Testing with ReleaseSmall..."
	@zig build test -Doptimize=ReleaseSmall --summary all

test-debug:
	@echo "🧪 Testing with Debug..."
	@zig build test -Doptimize=Debug --summary all

test-all-optimizations: test-debug test-release-safe test-release-fast test-release-small
	@echo "✅ All optimization levels passed"

# Fuzz tests for binary parsing entrypoints (QA-0058, SEC-0040)
test-fuzz:
	@echo "🔀 Running fuzz tests..."
	@zig build test-fuzz --summary all

# Security scanning (CI parity — runs local scanners if available)
security-scan:
	@echo "🔒 Running security scans..."
	@command -v gitleaks >/dev/null 2>&1 && gitleaks detect --source . --no-git || echo "gitleaks not installed, skipping"
	@command -v trufflehog >/dev/null 2>&1 && trufflehog filesystem . --no-update || echo "trufflehog not installed, skipping"
	@echo "✅ Security scan complete"

# Release build (mirrors CI release stage)
release:
	@echo "📦 Building release..."
	@zig build -Doptimize=ReleaseFast
	@echo "✅ Release build complete"

# Pre-commit hook management
pre-commit-install:
	@echo "📦 Installing pre-commit hooks..."
	@pre-commit install
	@pre-commit install --hook-type commit-msg
	@pre-commit install --hook-type pre-push

pre-commit:
	@echo "🔍 Running pre-commit checks..."
	@pre-commit run --all-files

pre-commit-run: pre-commit

# Display help
help:
	@echo "wal - Zig Library"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Development:"
	@echo "  all                  Build and run tests (default)"
	@echo "  build                Build the library"
	@echo "  dev                  Quick iteration: fmt + check + test"
	@echo "  ci                   Full CI: clean + build + test"
	@echo ""
	@echo "Testing:"
	@echo "  test                 Run all tests"
	@echo "  test-unit            Run unit tests only"
	@echo "  test-integration     Run integration tests only"
	@echo "  test-release-safe    Test with ReleaseSafe"
	@echo "  test-release-fast    Test with ReleaseFast"
	@echo "  test-release-small   Test with ReleaseSmall"
	@echo "  test-all-optimizations  Test all optimization levels"
	@echo "  test-fuzz            Run fuzz tests"
	@echo "  bench                Run basic performance benchmarks"
	@echo "  scale-bench          Run multi-tier scale benchmarks"
	@echo "  bench-save           Save scale bench results to results/<SHA>.json"
	@echo "  bench-baseline       Save current results as new baseline"
	@echo "  bench-compare        Compare current run against baseline"
	@echo ""
	@echo "Code Quality:"
	@echo "  fmt                  Format source code"
	@echo "  check                Check for compilation errors"
	@echo "  pre-commit           Run pre-commit hooks"
	@echo "  pre-commit-install   Install pre-commit hooks"
	@echo ""
	@echo "Security:"
	@echo "  security-scan        Run local security scanners"
	@echo ""
	@echo "Release:"
	@echo "  release              Build release binary"
	@echo ""
	@echo "Maintenance:"
	@echo "  clean                Remove build artifacts"
	@echo "  help                 Show this help message"
