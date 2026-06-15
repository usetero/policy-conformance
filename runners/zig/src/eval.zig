const std = @import("std");
const policy = @import("policy_zig");

const FieldRef = policy.FieldRef;
const MetricFieldRef = policy.MetricFieldRef;
const TraceFieldRef = policy.TraceFieldRef;

const proto = policy.proto;
const LogRecord = proto.logs.LogRecord;
const Metric = proto.metrics.Metric;
const Span = proto.trace.Span;
const KeyValue = proto.common.KeyValue;
const AnyValue = proto.common.AnyValue;
const InstrumentationScope = proto.common.InstrumentationScope;
const Resource = proto.resource.Resource;

// ─── Context types ───────────────────────────────────────────────────
// Wrap OTel records with parent resource/scope pointers so eval can access
// resource_attributes and scope_attributes from the parent containers.

pub const LogContext = struct {
    record: *LogRecord,
    resource: ?*Resource,
    scope: ?*InstrumentationScope,
    allocator: std.mem.Allocator,
    resource_schema_url: []const u8,
    scope_schema_url: []const u8,
};

pub const MetricContext = struct {
    metric: *const Metric,
    datapoint_attributes: []const KeyValue,
    resource: ?*const Resource,
    scope: ?*const InstrumentationScope,
    resource_schema_url: []const u8,
    scope_schema_url: []const u8,
};

pub const TraceContext = struct {
    span: *Span,
    resource: ?*const Resource,
    scope: ?*const InstrumentationScope,
    allocator: std.mem.Allocator,
    resource_schema_url: []const u8,
    scope_schema_url: []const u8,
};

// ─── Attribute helpers ───────────────────────────────────────────────

fn findAttributePath(attrs: []const KeyValue, path: []const []const u8) ?[]const u8 {
    if (path.len == 0) return null;
    for (attrs) |kv| {
        if (!std.mem.eql(u8, kv.key, path[0])) continue;
        if (path.len == 1) {
            return anyValueString(kv.value);
        }
        // Traverse into nested kvlist
        const av = kv.value orelse return null;
        const inner = av.value orelse return null;
        switch (inner) {
            .kvlist_value => |kvlist| return findAttributePath(kvlist.values.items, path[1..]),
            else => return null,
        }
    }
    return null;
}

/// Walk the attribute path looking only at presence (not value type).
/// Returns true if the path resolves to a key at the right depth, regardless
/// of whether the leaf value is a string, int, bool, or other AnyValue kind.
fn findAttributePathExists(attrs: []const KeyValue, path: []const []const u8) bool {
    if (path.len == 0) return false;
    for (attrs) |kv| {
        if (!std.mem.eql(u8, kv.key, path[0])) continue;
        if (path.len == 1) return true;
        const av = kv.value orelse return false;
        const inner = av.value orelse return false;
        switch (inner) {
            .kvlist_value => |kvlist| return findAttributePathExists(kvlist.values.items, path[1..]),
            else => return false,
        }
    }
    return false;
}

fn anyValueString(val: ?AnyValue) ?[]const u8 {
    const v = val orelse return null;
    const inner = v.value orelse return null;
    return switch (inner) {
        .string_value => |s| if (s.len == 0) null else s,
        else => null,
    };
}

// ─── Typed value helpers (equals/gt/gte/lt/lte) ──────────────────────
// The engine prefers `accessor.typed_value` for the typed matchers so that
// non-string values (bool/int/double/bytes) match by type. Identifier fields
// (trace_id/span_id) are already raw bytes here because the runner decodes
// them via `bytes_as_hex`, so they map straight to TypedValue.bytes.

const TypedValue = policy.TypedValue;

fn typedStr(s: []const u8) ?TypedValue {
    return if (s.len == 0) null else TypedValue{ .string = s };
}

fn typedBytes(b: []const u8) ?TypedValue {
    return if (b.len == 0) null else TypedValue{ .bytes = b };
}

/// Identifier fields (trace_id/span_id) are held as lowercase-hex strings, so
/// decode them to raw bytes for the typed `equals`/hex byte comparison. The
/// decoded bytes are allocated in the per-request arena. Returns null (a
/// non-match) for empty or non-hex values.
fn typedHexBytes(allocator: std.mem.Allocator, hex_str: []const u8) ?TypedValue {
    if (hex_str.len == 0 or hex_str.len % 2 != 0) return null;
    const out = allocator.alloc(u8, hex_str.len / 2) catch return null;
    _ = std.fmt.hexToBytes(out, hex_str) catch return null;
    return TypedValue{ .bytes = out };
}

fn anyValueTyped(val: ?AnyValue) ?TypedValue {
    const v = val orelse return null;
    const inner = v.value orelse return null;
    return switch (inner) {
        .string_value => |s| TypedValue{ .string = s },
        .bool_value => |b| TypedValue{ .bool = b },
        .int_value => |i| TypedValue{ .int = i },
        .double_value => |d| TypedValue{ .double = d },
        .bytes_value => |b| TypedValue{ .bytes = b },
        else => null, // array/kvlist/strindex → absent (non-match, fail-open)
    };
}

fn findAttributePathTyped(attrs: []const KeyValue, path: []const []const u8) ?TypedValue {
    if (path.len == 0) return null;
    for (attrs) |kv| {
        if (!std.mem.eql(u8, kv.key, path[0])) continue;
        if (path.len == 1) return anyValueTyped(kv.value);
        const av = kv.value orelse return null;
        const inner = av.value orelse return null;
        switch (inner) {
            .kvlist_value => |kvlist| return findAttributePathTyped(kvlist.values.items, path[1..]),
            else => return null,
        }
    }
    return null;
}

fn resourceAttrs(resource: ?*const Resource) []const KeyValue {
    const r = resource orelse return &.{};
    return r.attributes.items;
}

fn scopeAttrs(scope: ?*const InstrumentationScope) []const KeyValue {
    const s = scope orelse return &.{};
    return s.attributes.items;
}

fn attrKey(path: anytype) ?[]const u8 {
    return if (path.path.items.len > 0) path.path.items[0] else null;
}

// ─── Log field accessor ──────────────────────────────────────────────

pub fn logFieldAccessor(ctx: *const anyopaque, field: FieldRef) ?[]const u8 {
    const lc: *const LogContext = @ptrCast(@alignCast(ctx));
    return switch (field) {
        .log_field => |lf| switch (lf) {
            .LOG_FIELD_BODY => blk: {
                const body = lc.record.body orelse break :blk null;
                const inner = body.value orelse break :blk null;
                break :blk switch (inner) {
                    .string_value => |s| if (s.len == 0) null else s,
                    else => null,
                };
            },
            .LOG_FIELD_SEVERITY_TEXT => nonEmpty(lc.record.severity_text),
            .LOG_FIELD_TRACE_ID => nonEmpty(lc.record.trace_id),
            .LOG_FIELD_SPAN_ID => nonEmpty(lc.record.span_id),
            .LOG_FIELD_EVENT_NAME => nonEmpty(lc.record.event_name),
            .LOG_FIELD_RESOURCE_SCHEMA_URL => nonEmpty(lc.resource_schema_url),
            .LOG_FIELD_SCOPE_SCHEMA_URL => nonEmpty(lc.scope_schema_url),
            else => null,
        },
        .log_attribute => |attr| findAttributePath(lc.record.attributes.items, attr.path.items),
        .resource_attribute => |attr| findAttributePath(resourceAttrs(lc.resource), attr.path.items),
        .scope_attribute => |attr| findAttributePath(scopeAttrs(lc.scope), attr.path.items),
    };
}

// ─── Metric field accessor ───────────────────────────────────────────

pub fn metricFieldAccessor(ctx: *const anyopaque, field: MetricFieldRef) ?[]const u8 {
    const mc: *const MetricContext = @ptrCast(@alignCast(ctx));
    return switch (field) {
        .metric_field => |mf| switch (mf) {
            .METRIC_FIELD_NAME => nonEmpty(mc.metric.name),
            .METRIC_FIELD_DESCRIPTION => nonEmpty(mc.metric.description),
            .METRIC_FIELD_UNIT => nonEmpty(mc.metric.unit),
            .METRIC_FIELD_SCOPE_NAME => if (mc.scope) |s| nonEmpty(s.name) else null,
            .METRIC_FIELD_SCOPE_VERSION => if (mc.scope) |s| nonEmpty(s.version) else null,
            .METRIC_FIELD_RESOURCE_SCHEMA_URL => nonEmpty(mc.resource_schema_url),
            .METRIC_FIELD_SCOPE_SCHEMA_URL => nonEmpty(mc.scope_schema_url),
            else => null,
        },
        .datapoint_attribute => |attr| findAttributePath(mc.datapoint_attributes, attr.path.items),
        .resource_attribute => |attr| findAttributePath(resourceAttrs(mc.resource), attr.path.items),
        .scope_attribute => |attr| findAttributePath(scopeAttrs(mc.scope), attr.path.items),
        .metric_type => |requested_type| blk: {
            const data = mc.metric.data orelse break :blk null;
            const actual_type: @TypeOf(requested_type) = switch (data) {
                .gauge => .METRIC_TYPE_GAUGE,
                .sum => .METRIC_TYPE_SUM,
                .histogram => .METRIC_TYPE_HISTOGRAM,
                .exponential_histogram => .METRIC_TYPE_EXPONENTIAL_HISTOGRAM,
                .summary => .METRIC_TYPE_SUMMARY,
            };
            break :blk if (actual_type == requested_type) @tagName(requested_type) else null;
        },
        .aggregation_temporality => |requested_at| blk: {
            const data = mc.metric.data orelse break :blk null;
            const actual_at = switch (data) {
                .sum => |s| s.aggregation_temporality,
                .histogram => |h| h.aggregation_temporality,
                .exponential_histogram => |eh| eh.aggregation_temporality,
                else => break :blk null,
            };
            break :blk if (@intFromEnum(actual_at) == @intFromEnum(requested_at)) @tagName(requested_at) else null;
        },
    };
}

// ─── Trace field accessor ────────────────────────────────────────────

pub fn traceFieldAccessor(ctx: *const anyopaque, field: TraceFieldRef) ?[]const u8 {
    const tc: *const TraceContext = @ptrCast(@alignCast(ctx));
    return switch (field) {
        .trace_field => |tf| switch (tf) {
            .TRACE_FIELD_NAME => nonEmpty(tc.span.name),
            .TRACE_FIELD_TRACE_ID => nonEmpty(tc.span.trace_id),
            .TRACE_FIELD_SPAN_ID => nonEmpty(tc.span.span_id),
            .TRACE_FIELD_PARENT_SPAN_ID => nonEmpty(tc.span.parent_span_id),
            .TRACE_FIELD_TRACE_STATE => nonEmpty(tc.span.trace_state),
            .TRACE_FIELD_SCOPE_NAME => if (tc.scope) |s| nonEmpty(s.name) else null,
            .TRACE_FIELD_SCOPE_VERSION => if (tc.scope) |s| nonEmpty(s.version) else null,
            .TRACE_FIELD_RESOURCE_SCHEMA_URL => nonEmpty(tc.resource_schema_url),
            .TRACE_FIELD_SCOPE_SCHEMA_URL => nonEmpty(tc.scope_schema_url),
            else => null,
        },
        .span_attribute => |attr| findAttributePath(tc.span.attributes.items, attr.path.items),
        .resource_attribute => |attr| findAttributePath(resourceAttrs(tc.resource), attr.path.items),
        .scope_attribute => |attr| findAttributePath(scopeAttrs(tc.scope), attr.path.items),
        .span_kind => |requested_kind| blk: {
            // Compare by integer value — OTel SpanKind and policy SpanKind share values
            break :blk if (@intFromEnum(tc.span.kind) == @intFromEnum(requested_kind))
                @tagName(requested_kind)
            else
                null;
        },
        .span_status => |requested_status| blk: {
            const status = tc.span.status orelse break :blk null;
            // OTel StatusCode and policy SpanStatusCode share integer values
            break :blk if (@intFromEnum(status.code) == @intFromEnum(requested_status))
                @tagName(requested_status)
            else
                null;
        },
        .event_name => |requested_name| blk: {
            for (tc.span.events.items) |evt| {
                if (evt.name.len > 0 and std.mem.eql(u8, evt.name, requested_name)) {
                    break :blk evt.name;
                }
            }
            break :blk null;
        },
        .event_attribute, .link_trace_id => null,
    };
}

// ─── Trace exists / set primitives ──────────────────────────────────

pub fn traceFieldExists(ctx: *const anyopaque, field: TraceFieldRef) bool {
    const tc: *const TraceContext = @ptrCast(@alignCast(ctx));
    return switch (field) {
        .trace_field => |tf| switch (tf) {
            .TRACE_FIELD_NAME => tc.span.name.len > 0,
            .TRACE_FIELD_TRACE_ID => tc.span.trace_id.len > 0,
            .TRACE_FIELD_SPAN_ID => tc.span.span_id.len > 0,
            .TRACE_FIELD_PARENT_SPAN_ID => tc.span.parent_span_id.len > 0,
            .TRACE_FIELD_TRACE_STATE => tc.span.trace_state.len > 0,
            .TRACE_FIELD_SCOPE_NAME => if (tc.scope) |s| s.name.len > 0 else false,
            .TRACE_FIELD_SCOPE_VERSION => if (tc.scope) |s| s.version.len > 0 else false,
            .TRACE_FIELD_RESOURCE_SCHEMA_URL => tc.resource_schema_url.len > 0,
            .TRACE_FIELD_SCOPE_SCHEMA_URL => tc.scope_schema_url.len > 0,
            else => false,
        },
        .span_attribute => |attr| findAttributePathExists(tc.span.attributes.items, attr.path.items),
        .resource_attribute => |attr| findAttributePathExists(resourceAttrs(tc.resource), attr.path.items),
        .scope_attribute => |attr| findAttributePathExists(scopeAttrs(tc.scope), attr.path.items),
        .span_kind => |requested| @intFromEnum(tc.span.kind) == @intFromEnum(requested),
        .span_status => |requested| blk: {
            const status = tc.span.status orelse break :blk false;
            break :blk @intFromEnum(status.code) == @intFromEnum(requested);
        },
        .event_name => |requested| blk: {
            for (tc.span.events.items) |evt| {
                if (std.mem.eql(u8, evt.name, requested)) break :blk true;
            }
            break :blk false;
        },
        .event_attribute, .link_trace_id => false,
    };
}

pub fn traceSet(ctx: *anyopaque, field: TraceFieldRef, value: []const u8) void {
    const tc: *TraceContext = @ptrCast(@alignCast(ctx));
    switch (field) {
        .trace_field => |tf| {
            if (tf == .TRACE_FIELD_TRACE_STATE) {
                // The engine writes the raw threshold hex value; merge it into
                // the W3C tracestate as ot=th:VALUE.
                const merged = mergeOTTracestate(tc.allocator, tc.span.trace_state, value) catch return;
                tc.span.trace_state = merged;
            }
        },
        else => {},
    }
}

fn mergeOTTracestate(allocator: std.mem.Allocator, tracestate: []const u8, th_value: []const u8) std.mem.Allocator.Error![]const u8 {
    // Build "ot=th:VALUE" or merge into existing tracestate
    var ot_parts: std.ArrayListUnmanaged(u8) = .empty;
    defer ot_parts.deinit(allocator);
    var other_vendors: std.ArrayListUnmanaged(u8) = .empty;
    defer other_vendors.deinit(allocator);

    if (tracestate.len > 0) {
        var vendors = std.mem.splitScalar(u8, tracestate, ',');
        while (vendors.next()) |vendor_raw| {
            const vendor = std.mem.trim(u8, vendor_raw, " ");
            if (vendor.len == 0) continue;
            if (std.mem.startsWith(u8, vendor, "ot=")) {
                const ot_value = vendor[3..];
                var parts = std.mem.splitScalar(u8, ot_value, ';');
                while (parts.next()) |part_raw| {
                    const part = std.mem.trim(u8, part_raw, " ");
                    if (part.len == 0) continue;
                    // Skip existing th: sub-key
                    if (std.mem.startsWith(u8, part, "th:")) continue;
                    if (ot_parts.items.len > 0) try ot_parts.appendSlice(allocator, ";");
                    try ot_parts.appendSlice(allocator, part);
                }
            } else {
                if (other_vendors.items.len > 0) try other_vendors.appendSlice(allocator, ",");
                try other_vendors.appendSlice(allocator, vendor);
            }
        }
    }

    // Build result: ot=[existing_subkeys;]th:VALUE[,other_vendors]
    var result: std.ArrayListUnmanaged(u8) = .empty;
    errdefer result.deinit(allocator);
    try result.appendSlice(allocator, "ot=");
    if (ot_parts.items.len > 0) {
        try result.appendSlice(allocator, ot_parts.items);
        try result.appendSlice(allocator, ";");
    }
    try result.appendSlice(allocator, "th:");
    try result.appendSlice(allocator, th_value);
    if (other_vendors.items.len > 0) {
        try result.appendSlice(allocator, ",");
        try result.appendSlice(allocator, other_vendors.items);
    }
    return result.items;
}

// ─── Helpers ─────────────────────────────────────────────────────────

fn nonEmpty(s: []const u8) ?[]const u8 {
    return if (s.len == 0) null else s;
}

// ─── Log exists / set / delete / move primitives ─────────────────────

pub fn logFieldExists(ctx: *const anyopaque, field: FieldRef) bool {
    const lc: *const LogContext = @ptrCast(@alignCast(ctx));
    return switch (field) {
        .log_field => |lf| switch (lf) {
            .LOG_FIELD_BODY => blk: {
                // Mirror the `value` accessor: empty string body counts as
                // missing. Non-string body kinds (kvlist, int, etc.) still
                // count as present.
                const body = lc.record.body orelse break :blk false;
                const inner = body.value orelse break :blk false;
                break :blk switch (inner) {
                    .string_value => |s| s.len > 0,
                    else => true,
                };
            },
            .LOG_FIELD_SEVERITY_TEXT => lc.record.severity_text.len > 0,
            .LOG_FIELD_TRACE_ID => lc.record.trace_id.len > 0,
            .LOG_FIELD_SPAN_ID => lc.record.span_id.len > 0,
            .LOG_FIELD_EVENT_NAME => lc.record.event_name.len > 0,
            .LOG_FIELD_RESOURCE_SCHEMA_URL => lc.resource_schema_url.len > 0,
            .LOG_FIELD_SCOPE_SCHEMA_URL => lc.scope_schema_url.len > 0,
            else => false,
        },
        .log_attribute => |attr| findAttributePathExists(lc.record.attributes.items, attr.path.items),
        .resource_attribute => |attr| findAttributePathExists(resourceAttrs(lc.resource), attr.path.items),
        .scope_attribute => |attr| findAttributePathExists(scopeAttrs(lc.scope), attr.path.items),
    };
}

pub fn logSet(ctx: *anyopaque, field: FieldRef, value: []const u8) void {
    const lc: *LogContext = @ptrCast(@alignCast(ctx));
    _ = mutSet(lc, field, value, true);
}

pub fn logDelete(ctx: *anyopaque, field: FieldRef) bool {
    const lc: *LogContext = @ptrCast(@alignCast(ctx));
    return mutRemove(lc, field);
}

pub fn logMove(ctx: *anyopaque, from: FieldRef, to: []const u8) void {
    const lc: *LogContext = @ptrCast(@alignCast(ctx));
    // Engine pre-resolves upsert semantics (calling delete first when needed);
    // here we simply relocate the value if the source attribute exists.
    _ = mutMoveAttr(lc, from, to);
}

// ─── Metric exists primitive ─────────────────────────────────────────

pub fn metricFieldExists(ctx: *const anyopaque, field: MetricFieldRef) bool {
    const mc: *const MetricContext = @ptrCast(@alignCast(ctx));
    return switch (field) {
        .metric_field => |mf| switch (mf) {
            .METRIC_FIELD_NAME => mc.metric.name.len > 0,
            .METRIC_FIELD_DESCRIPTION => mc.metric.description.len > 0,
            .METRIC_FIELD_UNIT => mc.metric.unit.len > 0,
            .METRIC_FIELD_SCOPE_NAME => if (mc.scope) |s| s.name.len > 0 else false,
            .METRIC_FIELD_SCOPE_VERSION => if (mc.scope) |s| s.version.len > 0 else false,
            .METRIC_FIELD_RESOURCE_SCHEMA_URL => mc.resource_schema_url.len > 0,
            .METRIC_FIELD_SCOPE_SCHEMA_URL => mc.scope_schema_url.len > 0,
            else => false,
        },
        .datapoint_attribute => |attr| findAttributePathExists(mc.datapoint_attributes, attr.path.items),
        .resource_attribute => |attr| findAttributePathExists(resourceAttrs(mc.resource), attr.path.items),
        .scope_attribute => |attr| findAttributePathExists(scopeAttrs(mc.scope), attr.path.items),
        .metric_type => |requested| blk: {
            const data = mc.metric.data orelse break :blk false;
            const actual: @TypeOf(requested) = switch (data) {
                .gauge => .METRIC_TYPE_GAUGE,
                .sum => .METRIC_TYPE_SUM,
                .histogram => .METRIC_TYPE_HISTOGRAM,
                .exponential_histogram => .METRIC_TYPE_EXPONENTIAL_HISTOGRAM,
                .summary => .METRIC_TYPE_SUMMARY,
            };
            break :blk actual == requested;
        },
        .aggregation_temporality => |requested| blk: {
            const data = mc.metric.data orelse break :blk false;
            const actual = switch (data) {
                .sum => |s| s.aggregation_temporality,
                .histogram => |h| h.aggregation_temporality,
                .exponential_histogram => |eh| eh.aggregation_temporality,
                else => break :blk false,
            };
            break :blk @intFromEnum(actual) == @intFromEnum(requested);
        },
    };
}

// ─── Typed value accessors ───────────────────────────────────────────

pub fn logTypedValue(ctx: *const anyopaque, field: FieldRef) ?TypedValue {
    const lc: *const LogContext = @ptrCast(@alignCast(ctx));
    return switch (field) {
        .log_field => |lf| switch (lf) {
            .LOG_FIELD_BODY => anyValueTyped(lc.record.body),
            .LOG_FIELD_SEVERITY_TEXT => typedStr(lc.record.severity_text),
            .LOG_FIELD_TRACE_ID => typedHexBytes(lc.allocator, lc.record.trace_id),
            .LOG_FIELD_SPAN_ID => typedHexBytes(lc.allocator, lc.record.span_id),
            .LOG_FIELD_EVENT_NAME => typedStr(lc.record.event_name),
            .LOG_FIELD_RESOURCE_SCHEMA_URL => typedStr(lc.resource_schema_url),
            .LOG_FIELD_SCOPE_SCHEMA_URL => typedStr(lc.scope_schema_url),
            else => null,
        },
        .log_attribute => |attr| findAttributePathTyped(lc.record.attributes.items, attr.path.items),
        .resource_attribute => |attr| findAttributePathTyped(resourceAttrs(lc.resource), attr.path.items),
        .scope_attribute => |attr| findAttributePathTyped(scopeAttrs(lc.scope), attr.path.items),
    };
}

pub fn metricTypedValue(ctx: *const anyopaque, field: MetricFieldRef) ?TypedValue {
    const mc: *const MetricContext = @ptrCast(@alignCast(ctx));
    return switch (field) {
        .datapoint_attribute => |attr| findAttributePathTyped(mc.datapoint_attributes, attr.path.items),
        .resource_attribute => |attr| findAttributePathTyped(resourceAttrs(mc.resource), attr.path.items),
        .scope_attribute => |attr| findAttributePathTyped(scopeAttrs(mc.scope), attr.path.items),
        // name/description/unit/type/temporality/scope are string-valued.
        else => if (metricFieldAccessor(ctx, field)) |s| TypedValue{ .string = s } else null,
    };
}

pub fn traceTypedValue(ctx: *const anyopaque, field: TraceFieldRef) ?TypedValue {
    const tc: *const TraceContext = @ptrCast(@alignCast(ctx));
    return switch (field) {
        .trace_field => |tf| switch (tf) {
            .TRACE_FIELD_TRACE_ID => typedHexBytes(tc.allocator, tc.span.trace_id),
            .TRACE_FIELD_SPAN_ID => typedHexBytes(tc.allocator, tc.span.span_id),
            .TRACE_FIELD_PARENT_SPAN_ID => typedHexBytes(tc.allocator, tc.span.parent_span_id),
            .TRACE_FIELD_NAME => typedStr(tc.span.name),
            .TRACE_FIELD_TRACE_STATE => typedStr(tc.span.trace_state),
            else => if (traceFieldAccessor(ctx, field)) |s| TypedValue{ .string = s } else null,
        },
        .span_attribute => |attr| findAttributePathTyped(tc.span.attributes.items, attr.path.items),
        .resource_attribute => |attr| findAttributePathTyped(resourceAttrs(tc.resource), attr.path.items),
        .scope_attribute => |attr| findAttributePathTyped(scopeAttrs(tc.scope), attr.path.items),
        else => if (traceFieldAccessor(ctx, field)) |s| TypedValue{ .string = s } else null,
    };
}

// ─── Static accessor templates ───────────────────────────────────────

pub const log_accessor: policy.LogAccessor = .{
    .value = logFieldAccessor,
    .exists = logFieldExists,
    .typed_value = logTypedValue,
    .set = logSet,
    .delete = logDelete,
    .move = logMove,
};

pub const metric_accessor: policy.MetricAccessor = .{
    .value = metricFieldAccessor,
    .exists = metricFieldExists,
    .typed_value = metricTypedValue,
};

pub const trace_accessor: policy.TraceAccessor = .{
    .value = traceFieldAccessor,
    .exists = traceFieldExists,
    .typed_value = traceTypedValue,
    .set = traceSet,
};

fn mutRemove(lc: *LogContext, field: FieldRef) bool {
    switch (field) {
        .log_field => |lf| {
            switch (lf) {
                .LOG_FIELD_BODY => {
                    const hit = lc.record.body != null;
                    lc.record.body = null;
                    return hit;
                },
                .LOG_FIELD_SEVERITY_TEXT => {
                    const hit = lc.record.severity_text.len > 0;
                    lc.record.severity_text = &.{};
                    return hit;
                },
                .LOG_FIELD_TRACE_ID => {
                    const hit = lc.record.trace_id.len > 0;
                    lc.record.trace_id = &.{};
                    return hit;
                },
                .LOG_FIELD_SPAN_ID => {
                    const hit = lc.record.span_id.len > 0;
                    lc.record.span_id = &.{};
                    return hit;
                },
                .LOG_FIELD_EVENT_NAME => {
                    const hit = lc.record.event_name.len > 0;
                    lc.record.event_name = &.{};
                    return hit;
                },
                else => return false,
            }
        },
        .log_attribute => |attr| return removeAttr(&lc.record.attributes, attrKey(attr)),
        .resource_attribute => |attr| {
            if (lc.resource) |r| return removeAttr(&r.attributes, attrKey(attr));
            return false;
        },
        .scope_attribute => |attr| {
            if (lc.scope) |s| return removeAttr(&s.attributes, attrKey(attr));
            return false;
        },
    }
}

fn mutSet(lc: *LogContext, field: FieldRef, value: []const u8, _: bool) bool {
    switch (field) {
        .log_field => |lf| {
            switch (lf) {
                .LOG_FIELD_BODY => {
                    lc.record.body = .{ .value = .{ .string_value = value } };
                    return true;
                },
                .LOG_FIELD_SEVERITY_TEXT => {
                    lc.record.severity_text = value;
                    return true;
                },
                .LOG_FIELD_TRACE_ID => {
                    lc.record.trace_id = value;
                    return true;
                },
                .LOG_FIELD_SPAN_ID => {
                    lc.record.span_id = value;
                    return true;
                },
                .LOG_FIELD_EVENT_NAME => {
                    lc.record.event_name = value;
                    return true;
                },
                else => return false,
            }
        },
        .log_attribute => |attr| return setAttr(lc.allocator, &lc.record.attributes, attrKey(attr), value),
        .resource_attribute => |attr| {
            if (lc.resource) |r| return setAttr(lc.allocator, &r.attributes, attrKey(attr), value);
            return false;
        },
        .scope_attribute => |attr| {
            if (lc.scope) |s| return setAttr(lc.allocator, &s.attributes, attrKey(attr), value);
            return false;
        },
    }
}

/// Move an attribute value from `from` to `to`. The engine has already
/// pre-resolved upsert semantics (it will have called delete on the target
/// when upsert=true; it skips this call entirely when upsert=false and the
/// target exists), so we only need to relocate the source.
fn mutMoveAttr(lc: *LogContext, from: FieldRef, to: []const u8) bool {
    const attrs = switch (from) {
        .log_attribute => &lc.record.attributes,
        .resource_attribute => if (lc.resource) |r| &r.attributes else return false,
        .scope_attribute => if (lc.scope) |s| &s.attributes else return false,
        .log_field => return false,
    };
    const key = switch (from) {
        .log_attribute => |attr| attrKey(attr),
        .resource_attribute => |attr| attrKey(attr),
        .scope_attribute => |attr| attrKey(attr),
        .log_field => return false,
    };
    const k = key orelse return false;

    const src_idx = findAttrIndex(attrs.items, k) orelse return false;
    var moved = attrs.orderedRemove(src_idx);
    moved.key = to;

    attrs.append(lc.allocator, moved) catch return false;
    return true;
}

fn removeAttr(attrs: *std.ArrayListUnmanaged(KeyValue), key: ?[]const u8) bool {
    const k = key orelse return false;
    const idx = findAttrIndex(attrs.items, k) orelse return false;
    _ = attrs.orderedRemove(idx);
    return true;
}

fn setAttr(allocator: std.mem.Allocator, attrs: *std.ArrayListUnmanaged(KeyValue), key: ?[]const u8, value: []const u8) bool {
    const k = key orelse return false;
    if (findAttrIndex(attrs.items, k)) |idx| {
        // Always overwrite when key exists. The engine handles "don't overwrite"
        // checks (e.g. add with upsert=false) before calling the mutator.
        attrs.items[idx].value = .{ .value = .{ .string_value = value } };
        return true;
    }
    attrs.append(allocator, .{ .key = k, .value = .{ .value = .{ .string_value = value } } }) catch return false;
    return true;
}

fn findAttrIndex(attrs: []const KeyValue, key: []const u8) ?usize {
    for (attrs, 0..) |kv, i| {
        if (std.mem.eql(u8, kv.key, key)) return i;
    }
    return null;
}
