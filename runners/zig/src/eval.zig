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

// ─── Trace field mutator ────────────────────────────────────────────

const TraceMutateOp = policy.TraceMutateOp;

pub fn traceFieldMutator(ctx: *anyopaque, op: TraceMutateOp) bool {
    const tc: *TraceContext = @ptrCast(@alignCast(ctx));
    switch (op) {
        .set => |s| {
            switch (s.field) {
                .trace_field => |tf| {
                    if (tf == .TRACE_FIELD_TRACE_STATE) {
                        // The engine writes the raw threshold hex value.
                        // We must merge it into the W3C tracestate as ot=th:VALUE.
                        tc.span.trace_state = mergeOTTracestate(tc.allocator, tc.span.trace_state, s.value);
                        return true;
                    }
                },
                else => {},
            }
        },
        else => {},
    }
    return false;
}

fn mergeOTTracestate(allocator: std.mem.Allocator, tracestate: []const u8, th_value: []const u8) []const u8 {
    // Build "ot=th:VALUE" or merge into existing tracestate
    var ot_parts: std.ArrayListUnmanaged(u8) = .empty;
    var other_vendors: std.ArrayListUnmanaged(u8) = .empty;

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
                    if (ot_parts.items.len > 0) ot_parts.appendSlice(allocator, ";") catch {};
                    ot_parts.appendSlice(allocator, part) catch {};
                }
            } else {
                if (other_vendors.items.len > 0) other_vendors.appendSlice(allocator, ",") catch {};
                other_vendors.appendSlice(allocator, vendor) catch {};
            }
        }
    }

    // Build result: ot=[existing_subkeys;]th:VALUE[,other_vendors]
    var result: std.ArrayListUnmanaged(u8) = .empty;
    result.appendSlice(allocator, "ot=") catch {};
    if (ot_parts.items.len > 0) {
        result.appendSlice(allocator, ot_parts.items) catch {};
        result.appendSlice(allocator, ";") catch {};
    }
    result.appendSlice(allocator, "th:") catch {};
    result.appendSlice(allocator, th_value) catch {};
    if (other_vendors.items.len > 0) {
        result.appendSlice(allocator, ",") catch {};
        result.appendSlice(allocator, other_vendors.items) catch {};
    }
    return result.items;
}

// ─── Helpers ─────────────────────────────────────────────────────────

fn nonEmpty(s: []const u8) ?[]const u8 {
    return if (s.len == 0) null else s;
}

// ─── Log field mutator ───────────────────────────────────────────────

const MutateOp = policy.MutateOp;

pub fn logFieldMutator(ctx: *anyopaque, op: MutateOp) bool {
    const lc: *LogContext = @ptrCast(@alignCast(ctx));
    switch (op) {
        .remove => |field| return mutRemove(lc, field),
        .set => |s| return mutSet(lc, s.field, s.value, s.upsert),
        .rename => |r| return mutRename(lc, r.from, r.to, r.upsert),
    }
}

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

fn mutRename(lc: *LogContext, from: FieldRef, to: []const u8, upsert: bool) bool {
    const attrs = switch (from) {
        .log_attribute => &lc.record.attributes,
        .resource_attribute => if (lc.resource) |r| &r.attributes else return false,
        .scope_attribute => if (lc.scope) |s| &s.attributes else return false,
        .log_field => return false, // renaming fixed fields not supported
    };
    const key = switch (from) {
        .log_attribute => |attr| attrKey(attr),
        .resource_attribute => |attr| attrKey(attr),
        .scope_attribute => |attr| attrKey(attr),
        .log_field => return false,
    };
    const k = key orelse return false;

    // Find and remove source
    const src_idx = findAttrIndex(attrs.items, k) orelse return false;
    const src_val = attrs.items[src_idx].value;

    // Check if target exists
    if (!upsert) {
        if (findAttrIndex(attrs.items, to) != null) return true; // blocked
    }

    // Remove source
    _ = attrs.orderedRemove(src_idx);

    // Remove existing target if upsert
    if (upsert) {
        if (findAttrIndex(attrs.items, to)) |ti| {
            _ = attrs.orderedRemove(ti);
        }
    }

    // Add renamed entry
    attrs.append(lc.allocator, .{ .key = to, .value = src_val }) catch return false;
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
