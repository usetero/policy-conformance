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
    record: *const LogRecord,
    resource: ?*const Resource,
    scope: ?*const InstrumentationScope,
};

pub const MetricContext = struct {
    metric: *const Metric,
    datapoint_attributes: []const KeyValue,
    resource: ?*const Resource,
    scope: ?*const InstrumentationScope,
};

pub const TraceContext = struct {
    span: *const Span,
    resource: ?*const Resource,
    scope: ?*const InstrumentationScope,
};

// ─── Attribute helpers ───────────────────────────────────────────────

fn findAttribute(attrs: []const KeyValue, key: []const u8) ?[]const u8 {
    for (attrs) |kv| {
        if (std.mem.eql(u8, kv.key, key)) {
            return anyValueString(kv.value);
        }
    }
    return null;
}

fn anyValueString(val: ?AnyValue) ?[]const u8 {
    const v = val orelse return null;
    const inner = v.value orelse return null;
    return switch (inner) {
        .string_value => |s| if (s.len == 0) null else s,
        else => null,
    };
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
            else => null,
        },
        .log_attribute => |attr| blk: {
            const key = attrKey(attr) orelse break :blk null;
            break :blk findAttribute(lc.record.attributes.items, key);
        },
        .resource_attribute => |attr| blk: {
            const key = attrKey(attr) orelse break :blk null;
            break :blk findAttribute(resourceAttrs(lc.resource), key);
        },
        .scope_attribute => |attr| blk: {
            const key = attrKey(attr) orelse break :blk null;
            break :blk findAttribute(scopeAttrs(lc.scope), key);
        },
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
            else => null,
        },
        .datapoint_attribute => |attr| blk: {
            const key = attrKey(attr) orelse break :blk null;
            break :blk findAttribute(mc.datapoint_attributes, key);
        },
        .resource_attribute => |attr| blk: {
            const key = attrKey(attr) orelse break :blk null;
            break :blk findAttribute(resourceAttrs(mc.resource), key);
        },
        .scope_attribute => |attr| blk: {
            const key = attrKey(attr) orelse break :blk null;
            break :blk findAttribute(scopeAttrs(mc.scope), key);
        },
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
            else => null,
        },
        .span_attribute => |attr| blk: {
            const key = attrKey(attr) orelse break :blk null;
            break :blk findAttribute(tc.span.attributes.items, key);
        },
        .resource_attribute => |attr| blk: {
            const key = attrKey(attr) orelse break :blk null;
            break :blk findAttribute(resourceAttrs(tc.resource), key);
        },
        .scope_attribute => |attr| blk: {
            const key = attrKey(attr) orelse break :blk null;
            break :blk findAttribute(scopeAttrs(tc.scope), key);
        },
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
        .event_name, .event_attribute, .link_trace_id => null,
    };
}

// ─── Helpers ─────────────────────────────────────────────────────────

fn nonEmpty(s: []const u8) ?[]const u8 {
    return if (s.len == 0) null else s;
}
