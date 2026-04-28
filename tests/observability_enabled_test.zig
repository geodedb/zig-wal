// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Verifies one wal operation span lands in an in-memory recorder when
//! `-Dwith_otel=true`. Skips under the disabled build.
//!
//! NOTE: deviation from template — we exercise the seam directly via
//! the in-memory recorder rather than driving a real WAL operation.
//! Engine paths require a temp directory + open file handle + recovery
//! bootstrap; the seam's behaviour is identical:
//! `startWalSpan` -> `endWalSpan` enters and leaves one tracer span.
//!
//! The `otel` module is only added to this test root when
//! `-Dwith_otel=true`. To compile cleanly under both flag values we
//! gate the otel-namespace identifiers behind `comptime if (enabled)`
//! and stub the alias to an empty struct when the flag is off — that
//! branch is dead code in the disabled build but the import resolves.

const std = @import("std");
const build_options = @import("build_options");
const wal = @import("wal");

const otel = if (build_options.with_otel) @import("otel") else struct {};

test "one wal.* operation span recorded when otel enabled" {
    if (!wal.observability.enabled) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    var resource = try otel.sdk.resource.defaultResource(allocator);
    defer resource.deinit();
    try resource.attributes.putString(otel.semconv.service_name, "wal-test");

    var recorder = otel.exporters.in_memory.Recorder.init(allocator);
    defer recorder.deinit();
    var tp = try otel.sdk.trace.TracerProvider.init(allocator, .{
        .resource = &resource,
        .default_exporter = recorder.spanExporter(),
    });
    defer tp.deinit();

    var tracer = tp.tracer(.{ .name = "wal-test" });
    wal.observability.global.tracer = &tracer;
    defer wal.observability.global.tracer = null;

    const span = wal.observability.startWalSpan("append");
    wal.observability.endWalSpan(span, true, 1024);

    try tp.forceFlush(1_000);
    try std.testing.expectEqual(@as(usize, 1), recorder.spans.items.len);

    // Verify span name shape: "wal.{operation}".
    const recorded = recorder.spans.items[0];
    try std.testing.expectEqualStrings("wal.append", recorded.name);

    // Verify the db.system + db.operation attributes landed on the
    // span. The in-memory recorder stores attributes as `[]KV`
    // (string-stringified key/value pairs) — see
    // otel/src/exporters/in_memory.zig.
    var found_system: ?[]const u8 = null;
    var found_op: ?[]const u8 = null;
    for (recorded.attribute_kv) |kv| {
        if (std.mem.eql(u8, kv.key, "db.system")) {
            found_system = kv.value;
        } else if (std.mem.eql(u8, kv.key, "db.operation")) {
            found_op = kv.value;
        }
    }
    const system_value = found_system orelse return error.MissingDbSystemAttribute;
    try std.testing.expectEqualStrings("wal", system_value);
    const op_value = found_op orelse return error.MissingDbOperationAttribute;
    try std.testing.expectEqualStrings("append", op_value);
}
