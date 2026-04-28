// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! observability.zig — single-file otel seam for wal.
//!
//! When `build_options.with_otel == false`, every public function in this
//! file collapses to a comptime-known no-op so the optimizer eliminates
//! the call site entirely. When true, calls forward to the appropriate
//! `otel.api.trace` helper.
//!
//! INVARIANT: every emit is `catch {}`-discarded. A failing exporter
//! never reaches the caller — telemetry must never break a durable WAL
//! write.
//!
//! NOTE: deviation from template — WAL operations don't fit the HTTP
//! `instrumentation.http.startClientSpan` shape (HTTP method/url is
//! lossy for a local durable-write engine). We expose a domain-specific
//! `startWalSpan(operation)` helper that constructs a span via
//! `otel.api.trace.Tracer.startSpan` directly with a db-shaped span name
//! (`"wal.{operation}"`) and the `db.system="wal"` / `db.operation`
//! semantic conventions.

const std = @import("std");
const build_options = @import("build_options");

pub const enabled: bool = build_options.with_otel;

const otel = if (enabled) @import("otel") else struct {};

/// Opaque handle for an in-flight operation. When disabled, this is a
/// zero-sized struct the optimizer drops entirely. The no-op fallback's
/// `end` signature MUST match `otel.api.trace.Span.end(?u64) void` so
/// callers can write `span.end(null)` regardless of `enabled` state.
pub const Span = if (enabled) otel.api.trace.Span else struct {
    pub fn end(self: @This(), _: ?u64) void {
        _ = self;
    }
};

/// Start a span for a WAL engine operation.
///
/// Span shape:
///   - name: `"wal.{operation}"` (e.g. `"wal.append"`, `"wal.commit"`,
///     `"wal.replay"`, `"wal.checkpoint"`, `"wal.truncate"`).
///   - kind: `.client` (the WAL engine acts as a client to its
///     underlying file/page subsystem; the OpenTelemetry `db.*`
///     semantic conventions specify `client` for the calling side of a
///     database interaction).
///   - attributes:
///       * `db.system = "wal"`
///       * `db.operation = operation`
///
/// `operation` MUST be a string literal or a slice whose lifetime
/// outlives the span. The SDK dupes the span name into the span arena,
/// but the `db.operation` attribute is stored by reference at the
/// stringified value layer; using a stable string keeps the recorder
/// safe from dangling slices.
pub fn startWalSpan(operation: []const u8) Span {
    if (!enabled) return Span{};
    const tracer = global.tracer orelse return Span{};
    // Compose the span name on the stack; the SDK dupes the name into
    // the span arena, so a pointer to a stack buffer is safe here.
    var name_buf: [128]u8 = undefined;
    const span_name = std.fmt.bufPrint(
        name_buf[0..],
        "wal.{s}",
        .{operation},
    ) catch "wal";
    const span = tracer.startSpan(.empty(), span_name, .{ .kind = .client }) catch return Span{};
    // Best-effort attribute attachment. Failures (OOM in the attribute
    // set) cannot block the WAL operation — telemetry is non-fatal.
    span.setStringAttribute("db.system", "wal") catch {};
    span.setStringAttribute("db.operation", operation) catch {};
    return span;
}

/// Close a WAL span, recording success/failure plus an optional
/// `wal.bytes_written` attribute for size-trackable operations.
///
/// On `ok = true` we set status `.ok`; on `ok = false` we set status
/// `.error_` with an empty description (callers who have an error
/// message can attach it via `span.setStatus` before calling this
/// helper). When `bytes_written > 0` we attach the OpenTelemetry-flavored
/// `wal.bytes_written` attribute. Callers typically pair this with
/// `defer span.end(null)` at the call site so the span is always ended
/// regardless of which path is taken. `setStatus` + `end` are idempotent
/// for status reporting (only the first status write wins; the deferred
/// `end(null)` is a redundant no-op).
pub fn endWalSpan(span: Span, ok: bool, bytes_written: u64) void {
    if (!enabled) return;
    if (bytes_written > 0) {
        span.setIntAttribute("wal.bytes_written", @intCast(bytes_written)) catch {};
    }
    if (ok) {
        span.setStatus(.ok, "");
    } else {
        // `StatusCode` uses `@"error"` (escaped keyword) for the
        // failure variant — see otel/src/api/trace.zig:35.
        span.setStatus(.@"error", "");
    }
    span.end(null);
}

/// Set once at process start by `observability_init.Otel.installGlobals`.
/// Only referenced when `enabled == true`; otherwise the optimizer drops
/// the whole struct.
pub const global = if (enabled) struct {
    pub var tracer: ?*otel.api.trace.Tracer = null;
    pub var meter: ?*otel.api.metrics.Meter = null;
} else struct {};
