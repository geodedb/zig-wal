// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Verifies the no-op invariant when `-Dwith_otel=false` (the default).
//!
//! wal publishes its public surface as the `wal` module rooted at
//! `src/root.zig`. The seam is exposed as `wal.observability` so this test
//! drives the disabled-mode invariants through the public root.

const std = @import("std");
const wal = @import("wal");

test "build_options.with_otel exists and defaults to false" {
    const build_options = @import("build_options");
    try std.testing.expect(@hasDecl(build_options, "with_otel"));
    // The "default" assertion only holds for the disabled build. When
    // the operator forces -Dwith_otel=true this test runs against the
    // enabled module and must skip rather than misreport the default.
    if (build_options.with_otel) return error.SkipZigTest;
    try std.testing.expectEqual(false, build_options.with_otel);
}

test "observability.enabled tracks build_options.with_otel" {
    const build_options = @import("build_options");
    try std.testing.expectEqual(build_options.with_otel, wal.observability.enabled);
}

test "wal span helper is a no-op when otel disabled" {
    if (wal.observability.enabled) return error.SkipZigTest;
    var span = wal.observability.startWalSpan("append");
    wal.observability.endWalSpan(span, true, 0);
    // Belt-and-suspenders: callers may also invoke `span.end(null)`
    // directly. The seam's `endWalSpan` already covers the lifecycle;
    // this line just verifies the no-op fallback signature matches the
    // real API's `Span.end(?u64) void`.
    span.end(null);
}
