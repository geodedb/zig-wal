// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Thread-pool dependency (work-stealing parallelism — PAR-0001)
    const tp_dep = b.dependency("thread_pool", .{
        .target = target,
        .optimize = optimize,
    });
    const tp_module = tp_dep.module("thread_pool");

    // Main library module
    const module = b.addModule("wal", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "thread_pool", .module = tp_module },
        },
    });

    // Unit tests (run tests defined in the module itself)
    const test_step = b.step("test", "Run unit tests");
    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "thread_pool", .module = tp_module },
            },
        }),
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    test_step.dependOn(&run_unit_tests.step);

    // Integration tests (separate test file with module import)
    const integration_step = b.step("test-integration", "Run integration tests");
    const integration_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/integration.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "wal", .module = module },
            },
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
                .imports = &.{
                    .{ .name = "wal", .module = module },
                },
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
            .imports = &.{
                .{ .name = "wal", .module = module },
            },
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
            .imports = &.{
                .{ .name = "wal", .module = module },
            },
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
            .imports = &.{
                .{ .name = "wal", .module = module },
                .{ .name = "thread_pool", .module = tp_module },
            },
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
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "thread_pool", .module = tp_module },
            },
        }),
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
            .imports = &.{
                .{ .name = "wal", .module = module },
            },
        }),
    });
    example_step.dependOn(&example_exe.step);
}
