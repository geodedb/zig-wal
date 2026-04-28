// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");

const Import = std.Build.Module.Import;
const OptimizeMode = std.builtin.OptimizeMode;

const Deps = struct {
    thread_pool_mod: *std.Build.Module,
    /// Shared `build_options` module so every consumer module resolves to
    /// the SAME instance. Required by the otel seam (`@import("build_options")`)
    /// and shared with the named `observability` module so the file
    /// doesn't get pulled into two module trees.
    build_options_mod: *std.Build.Module,
    /// Shared `observability` named module. Imported by the public
    /// `wal` module + every test root that exercises the seam (so the
    /// source file stays in a single module tree).
    observability_mod: *std.Build.Module,
    /// Optional otel module. `null` when `-Dwith_otel=false`. When
    /// non-null, every consumer that wants telemetry imports it as
    /// `@import("otel")` — but call sites should generally go through
    /// the named `observability` seam instead.
    otel_mod: ?*std.Build.Module,
    /// Optional bootstrap helper module (`observability_init`). Only
    /// non-null when `-Dwith_otel=true`. The public `wal` module imports
    /// this so the in-process init helper is reachable from caller
    /// binaries via `wal.observability_init`.
    observability_init_mod: ?*std.Build.Module,
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // -Dwith_otel: compile in otel instrumentation. OFF by default;
    // when off the otel dependency is never resolved and the seam
    // collapses to a comptime-known no-op (verified by
    // otel/scripts/verify-consumer-noop.sh).
    const with_otel = b.option(
        bool,
        "with_otel",
        "Compile in otel instrumentation (off by default; zero overhead when off)",
    ) orelse false;

    const deps = loadDeps(b, target, optimize, with_otel);

    // Main library module
    const module = b.addModule("wal", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = allocImports(b, &.{
            .{ .name = "thread_pool", .module = deps.thread_pool_mod },
            .{ .name = "observability", .module = deps.observability_mod },
            .{ .name = "build_options", .module = deps.build_options_mod },
        }),
    });
    if (deps.observability_init_mod) |init_mod| {
        module.addImport("observability_init", init_mod);
    }
    if (deps.otel_mod) |otel_mod| {
        module.addImport("otel", otel_mod);
    }

    // Unit tests (run tests defined in the module itself)
    const test_step = b.step("test", "Run unit tests");
    const unit_tests = b.addTest(.{
        .root_module = createRootModule(b, "src/root.zig", target, optimize, deps, true),
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    test_step.dependOn(&run_unit_tests.step);

    addObservabilityTests(b, target, optimize, module, deps, test_step);

    // Integration tests (separate test file with module import)
    const integration_step = b.step("test-integration", "Run integration tests");
    const integration_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/integration.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = allocImports(b, &.{
                .{ .name = "wal", .module = module },
            }),
        }),
    });
    const run_integration_tests = b.addRunArtifact(integration_tests);
    integration_step.dependOn(&run_integration_tests.step);

    // Scenario tests
    const scenario_files = [_][]const u8{
        "tests/scenarios/crash.zig",
        "tests/scenarios/compaction.zig",
        "tests/scenarios/encryption.zig",
        "tests/scenarios/caller_lsn.zig",
    };
    for (scenario_files) |scenario_path| {
        const scenario_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path(scenario_path),
                .target = target,
                .optimize = optimize,
                .link_libc = true,
                .imports = allocImports(b, &.{
                    .{ .name = "wal", .module = module },
                }),
            }),
        });
        const run_scenario = b.addRunArtifact(scenario_tests);
        integration_step.dependOn(&run_scenario.step);
    }

    // Fuzz tests (SEC-0040)
    const fuzz_step = b.step("test-fuzz", "Run fuzz tests for binary parsing entrypoints");
    const fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/fuzz.zig"),
            .target = target,
            .optimize = optimize,
            .imports = allocImports(b, &.{
                .{ .name = "wal", .module = module },
            }),
        }),
    });
    const run_fuzz_tests = b.addRunArtifact(fuzz_tests);
    fuzz_step.dependOn(&run_fuzz_tests.step);

    // Benchmark executable
    const bench_step = b.step("bench", "Run performance benchmarks");
    const bench_exe = b.addExecutable(.{
        .name = "bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/main.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .link_libc = true,
            .imports = allocImports(b, &.{
                .{ .name = "wal", .module = module },
            }),
        }),
    });
    const run_bench = b.addRunArtifact(bench_exe);
    bench_step.dependOn(&run_bench.step);

    // Scale benchmark with JSON output (multi-tier)
    const scale_bench_step = b.step("scale-bench", "Run multi-tier scale benchmarks (JSON to stdout)");
    const scale_bench_exe = b.addExecutable(.{
        .name = "scale-bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/scale_bench.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .link_libc = true,
            .imports = allocImports(b, &.{
                .{ .name = "wal", .module = module },
                .{ .name = "thread_pool", .module = deps.thread_pool_mod },
            }),
        }),
    });
    b.installArtifact(scale_bench_exe);
    const run_scale_bench = b.addRunArtifact(scale_bench_exe);
    if (b.args) |args| run_scale_bench.addArgs(args);
    scale_bench_step.dependOn(&run_scale_bench.step);

    // Benchmark comparison tool (regression detection)
    const compare_bench_step = b.step("compare-bench", "Compare benchmark results for regressions");
    const compare_bench_exe = b.addExecutable(.{
        .name = "compare-bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/compare.zig"),
            .target = target,
            .optimize = .ReleaseFast,
        }),
    });
    const run_compare_bench = b.addRunArtifact(compare_bench_exe);
    if (b.args) |args| run_compare_bench.addArgs(args);
    compare_bench_step.dependOn(&run_compare_bench.step);

    // Check step for IDE integration (fast syntax validation)
    const check_step = b.step("check", "Check for compilation errors");
    const check = b.addTest(.{
        .root_module = createRootModule(b, "src/root.zig", target, optimize, deps, true),
    });
    check_step.dependOn(&check.step);

    // Example compilation check (QA-0033)
    const example_step = b.step("example", "Build example");
    const example_exe = b.addExecutable(.{
        .name = "basic-example",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/basic.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = allocImports(b, &.{
                .{ .name = "wal", .module = module },
            }),
        }),
    });
    example_step.dependOn(&example_exe.step);
}

fn loadDeps(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: OptimizeMode,
    with_otel: bool,
) Deps {
    const tp_dep = b.dependency("thread_pool", .{
        .target = target,
        .optimize = optimize,
    });

    // Materialize ONE shared `build_options` module. Each consumer module
    // imports the SAME module instance via `addImport` to avoid Zig's
    // "file exists in modules X and X0" error when two independent
    // `addOptions` modules end up sharing a transitive file path.
    //
    // The `package_name` option exists to disambiguate the generated
    // `options.zig`. `b.addOptions()` content-hashes its output to pick
    // a cache path; if two packages in the same build graph (e.g. wal
    // and a consumer that also only sets `with_otel = false`) emit
    // identical bytes, they collapse to the SAME cache file and Zig
    // rejects it as "one file root of two modules". Tagging by package
    // name keeps the bytes unique per package.
    const build_options = b.addOptions();
    build_options.addOption([]const u8, "package_name", "wal");
    build_options.addOption(bool, "with_otel", with_otel);
    const build_options_mod = build_options.createModule();

    // Observability seam (otel). Declared as a SHARED NAMED MODULE so
    // every consumer (lib, tests, example, benchmarks, plus the seam
    // tests) resolves to the same source file via
    // `@import("observability")`. Using relative
    // `@import("observability.zig")` from each module would trip Zig's
    // "file exists in modules X and Y" error because the file would be
    // pulled into multiple module trees. The seam's `enabled` flag
    // tracks `build_options.with_otel`; when off, every helper compiles
    // to a comptime-known no-op and the otel dependency is never
    // resolved. The optional `otel` import is wired below inside the
    // `if (with_otel)` block.
    const observability_mod = b.addModule("observability", .{
        .root_source_file = b.path("src/observability.zig"),
        .target = target,
        .optimize = optimize,
        .imports = allocImports(b, &.{
            .{ .name = "build_options", .module = build_options_mod },
        }),
    });

    // Gated otel dependency. The `lazy = true` entry in build.zig.zon
    // means Zig only fetches the package when this branch executes;
    // with the flag off the dependency is never resolved and the
    // produced artifacts contain zero otel symbols (verified by
    // otel/scripts/verify-consumer-noop.sh).
    var otel_mod: ?*std.Build.Module = null;
    var observability_init_mod: ?*std.Build.Module = null;
    if (with_otel) {
        if (b.lazyDependency("otel", .{
            .target = target,
            .optimize = optimize,
        })) |otel_dep| {
            const m = otel_dep.module("otel");
            otel_mod = m;
            // The seam itself imports `otel` when enabled.
            observability_mod.addImport("otel", m);

            // Bootstrap helper. Only registered when `-Dwith_otel=true`
            // so the disabled build never compiles otel-touching code.
            // Gated from root.zig via
            // `if (observability.enabled) @import("observability_init")`.
            observability_init_mod = b.addModule("observability_init", .{
                .root_source_file = b.path("src/observability_init.zig"),
                .target = target,
                .optimize = optimize,
                .imports = allocImports(b, &.{
                    .{ .name = "otel", .module = m },
                    .{ .name = "observability", .module = observability_mod },
                }),
            });
        }
    }

    return .{
        .thread_pool_mod = tp_dep.module("thread_pool"),
        .build_options_mod = build_options_mod,
        .observability_mod = observability_mod,
        .otel_mod = otel_mod,
        .observability_init_mod = observability_init_mod,
    };
}

fn allocImports(b: *std.Build, imports: []const Import) []Import {
    return b.allocator.dupe(Import, imports) catch @panic("out of memory");
}

/// Build a root-shaped module (rooted at `src/root.zig` or similar) that
/// includes all standard wal imports plus the seam wiring. Centralised so
/// the unit-test target and the check step share identical module wiring.
fn createRootModule(
    b: *std.Build,
    root_source_file: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: OptimizeMode,
    deps: Deps,
    link_libc: bool,
) *std.Build.Module {
    const mod = b.createModule(.{
        .root_source_file = b.path(root_source_file),
        .target = target,
        .optimize = optimize,
        .link_libc = link_libc,
        .imports = allocImports(b, &.{
            .{ .name = "thread_pool", .module = deps.thread_pool_mod },
            .{ .name = "observability", .module = deps.observability_mod },
            .{ .name = "build_options", .module = deps.build_options_mod },
        }),
    });
    if (deps.observability_init_mod) |m| mod.addImport("observability_init", m);
    if (deps.otel_mod) |m| mod.addImport("otel", m);
    return mod;
}

// ============================================================================
// Observability seam tests
// ============================================================================
//
// Two test targets:
//
//   - `observability_disabled_test.zig` runs under BOTH flag values. Each
//     test inside it is skip-guarded via
//     `if (wal.observability.enabled) return error.SkipZigTest;`
//     so the disabled-mode invariants only fire when the flag is off.
//
//   - `observability_enabled_test.zig` is registered under both flag
//     values too, but every test inside it skips when the flag is off.
//     The `otel` import is wired only when `with_otel = true`; the stub
//     branch in the test file (`const otel = if (build_options.with_otel) ...`)
//     ensures the file still compiles cleanly under the disabled build.
fn addObservabilityTests(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: OptimizeMode,
    wal_mod: *std.Build.Module,
    deps: Deps,
    test_step: *std.Build.Step,
) void {
    // Disabled-mode no-op tests. Verifies `build_options.with_otel == false`
    // is the default and that the seam's public surface returns a
    // comptime-known no-op when otel is off.
    const disabled_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/observability_disabled_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = allocImports(b, &.{
                .{ .name = "wal", .module = wal_mod },
                .{ .name = "build_options", .module = deps.build_options_mod },
            }),
        }),
    });
    const run_disabled_tests = b.addRunArtifact(disabled_tests);
    test_step.dependOn(&run_disabled_tests.step);

    // Enabled-mode smoke test. Skips under -Dwith_otel=false; under
    // -Dwith_otel=true it installs an in-memory recorder, drives one
    // wal span through the seam, and asserts the recorder captured it.
    const enabled_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/observability_enabled_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = allocImports(b, &.{
                .{ .name = "wal", .module = wal_mod },
                .{ .name = "build_options", .module = deps.build_options_mod },
            }),
        }),
    });
    if (deps.otel_mod) |m| enabled_tests.root_module.addImport("otel", m);
    const run_enabled_tests = b.addRunArtifact(enabled_tests);
    test_step.dependOn(&run_enabled_tests.step);
}
