//! OTLP projection and mutation at the host/library boundary.

const std = @import("std");
const policy = @import("policy_zig");
const proto = @import("otel_proto");
const Redactions = @import("redact.zig").Redactions;

const ValueRef = policy.ValueRef;
const Selector = policy.source.Selector;
const KeyValue = proto.common.KeyValue;
const AnyValue = proto.common.AnyValue;
const Resource = proto.resource.Resource;
const InstrumentationScope = proto.common.InstrumentationScope;

pub const LogContext = struct {
    record: *proto.logs.LogRecord,
    resource: ?*Resource,
    scope: ?*InstrumentationScope,
    allocator: std.mem.Allocator,
    resource_schema_url: []const u8,
    scope_schema_url: []const u8,
};

pub const MetricContext = struct {
    metric: *proto.metrics.Metric,
    datapoint_attributes: []const KeyValue,
    resource: ?*Resource,
    scope: ?*InstrumentationScope,
    resource_schema_url: []const u8,
    scope_schema_url: []const u8,
};

pub const TraceContext = struct {
    span: *proto.trace.Span,
    resource: ?*Resource,
    scope: ?*InstrumentationScope,
    resource_schema_url: []const u8,
    scope_schema_url: []const u8,
};

pub const Projector = struct {
    values: []ValueRef,
    scratch: []u8,
    cursor: usize = 0,

    pub fn init(allocator: std.mem.Allocator, field_count: u16) !Projector {
        return .{
            .values = try allocator.alloc(ValueRef, field_count),
            .scratch = try allocator.alloc(u8, @as(usize, field_count) * 64),
        };
    }

    pub fn deinit(self: *Projector, allocator: std.mem.Allocator) void {
        allocator.free(self.values);
        allocator.free(self.scratch);
        self.* = undefined;
    }

    pub fn logs(self: *Projector, image: *const policy.PolicyImage, context: *const LogContext) ![]const ValueRef {
        self.begin();
        for (self.values, 0..) |*value, raw| {
            const index: u16 = @intCast(raw);
            const field = try image.field(index);
            value.* = if (field.signal == .log)
                try self.projectLog(field, try image.fieldName(index), context)
            else
                .missing;
        }
        return self.values;
    }

    pub fn metrics(
        self: *Projector,
        image: *const policy.PolicyImage,
        context: *const MetricContext,
    ) ![]const ValueRef {
        self.begin();
        for (self.values, 0..) |*value, raw| {
            const index: u16 = @intCast(raw);
            const field = try image.field(index);
            value.* = if (field.signal == .metric)
                try self.projectMetric(field, try image.fieldName(index), context)
            else
                .missing;
        }
        return self.values;
    }

    pub fn traces(self: *Projector, image: *const policy.PolicyImage, context: *const TraceContext) ![]const ValueRef {
        self.begin();
        for (self.values, 0..) |*value, raw| {
            const index: u16 = @intCast(raw);
            const field = try image.field(index);
            value.* = if (field.signal == .trace)
                try self.projectTrace(field, try image.fieldName(index), context)
            else
                .missing;
        }
        return self.values;
    }

    fn begin(self: *Projector) void {
        self.cursor = 0;
        @memset(self.values, .missing);
    }

    fn projectLog(
        self: *Projector,
        field: policy.image.Field,
        name: []const u8,
        context: *const LogContext,
    ) !ValueRef {
        const selector = std.enums.fromInt(Selector, field.selector_id) orelse return .missing;
        return switch (selector) {
            .log_field => switch (try parseEnum(name)) {
                1 => anyValue(context.record.body),
                2 => stringValue(context.record.severity_text),
                3 => self.identifier(field, context.record.trace_id),
                4 => self.identifier(field, context.record.span_id),
                5 => stringValue(context.record.event_name),
                10 => stringValue(context.resource_schema_url),
                11 => stringValue(context.scope_schema_url),
                else => .missing,
            },
            .log_attribute => attributeValue(context.record.attributes.items, name),
            .resource_attribute => attributeValue(resourceAttributes(context.resource), name),
            .scope_attribute => attributeValue(scopeAttributes(context.scope), name),
            else => .missing,
        };
    }

    fn projectMetric(
        _: *Projector,
        field: policy.image.Field,
        name: []const u8,
        context: *const MetricContext,
    ) !ValueRef {
        const selector = std.enums.fromInt(Selector, field.selector_id) orelse return .missing;
        return switch (selector) {
            .metric_field => switch (try parseEnum(name)) {
                1 => stringValue(context.metric.name),
                2 => stringValue(context.metric.description),
                3 => stringValue(context.metric.unit),
                10 => stringValue(context.resource_schema_url),
                11 => stringValue(context.scope_schema_url),
                12 => if (context.scope) |scope| stringValue(scope.name) else .missing,
                13 => if (context.scope) |scope| stringValue(scope.version) else .missing,
                else => .missing,
            },
            .datapoint_attribute => attributeValue(context.datapoint_attributes, name),
            .resource_attribute => attributeValue(resourceAttributes(context.resource), name),
            .scope_attribute => attributeValue(scopeAttributes(context.scope), name),
            .metric_type => if (metricType(context.metric) == try parseEnum(name)) stringValue(name) else .missing,
            .aggregation_temporality => if (metricTemporality(context.metric)) |actual|
                if (actual == try parseEnum(name)) stringValue(name) else .missing
            else
                .missing,
            else => .missing,
        };
    }

    fn projectTrace(
        self: *Projector,
        field: policy.image.Field,
        name: []const u8,
        context: *const TraceContext,
    ) !ValueRef {
        const selector = std.enums.fromInt(Selector, field.selector_id) orelse return .missing;
        return switch (selector) {
            .trace_field => switch (try parseEnum(name)) {
                1 => stringValue(context.span.name),
                2 => self.identifier(field, context.span.trace_id),
                3 => self.identifier(field, context.span.span_id),
                4 => self.identifier(field, context.span.parent_span_id),
                5 => stringValue(context.span.trace_state),
                10 => stringValue(context.resource_schema_url),
                11 => stringValue(context.scope_schema_url),
                12 => if (context.scope) |scope| stringValue(scope.name) else .missing,
                13 => if (context.scope) |scope| stringValue(scope.version) else .missing,
                else => .missing,
            },
            .span_attribute => attributeValue(context.span.attributes.items, name),
            .resource_attribute => attributeValue(resourceAttributes(context.resource), name),
            .scope_attribute => attributeValue(scopeAttributes(context.scope), name),
            .span_kind => if (@intFromEnum(context.span.kind) == try parseEnum(name)) stringValue(name) else .missing,
            .span_status => if (context.span.status) |status|
                if (@intFromEnum(status.code) == try parseEnum(name)) stringValue(name) else .missing
            else if (try parseEnum(name) == 0)
                stringValue(name)
            else
                .missing,
            .event_name => for (context.span.events.items) |event| {
                if (std.mem.eql(u8, event.name, name)) break stringValue(name);
            } else .missing,
            else => .missing,
        };
    }

    fn identifier(self: *Projector, field: policy.image.Field, bytes: []const u8) ValueRef {
        if (bytes.len == 0) return .missing;
        if (field.value_kind == .bytes) return .{ .bytes = bytes };
        const needed = bytes.len * 2;
        if (self.cursor + needed > self.scratch.len) return .missing;
        const output = self.scratch[self.cursor..][0..needed];
        self.cursor += needed;
        _ = std.fmt.bufPrint(output, "{x}", .{bytes}) catch return .missing;
        return .{ .string = output };
    }
};

pub fn applyLogActions(
    image: *const policy.PolicyImage,
    worker: *policy.WorkerState,
    context: *LogContext,
    redactions: *Redactions,
) !void {
    var matched = policy.MatchedPolicyIterator.init(image, worker);
    while (matched.next()) |policy_index| {
        var actions = policy.ActionIterator.initPolicy(image, policy_index) orelse continue;
        while (actions.next()) |action| {
            const field_index = action.field_index orelse continue;
            const field = try image.field(field_index);
            const name = try image.fieldName(field_index);
            switch (action.opcode) {
                .remove => _ = remove(context, field, name),
                .redact => if (action.flags & policy.source.adapter.action_flag_regex != 0) {
                    const current = currentString(context, field, name) orelse continue;
                    if (try redactions.replace(context.allocator, action.action_index, current)) |replacement| {
                        _ = replaceExisting(context, field, name, replacement);
                    }
                } else {
                    _ = replaceExisting(context, field, name, action.value);
                },
                .rename => _ = rename(context, field, name, action.value, action.flags & 1 != 0),
                .add => _ = set(context, field, name, action.value, action.flags & 1 != 0),
                .extension => {},
            }
        }
    }
}

fn currentString(context: *LogContext, field: policy.image.Field, name: []const u8) ?[]const u8 {
    const selector = std.enums.fromInt(Selector, field.selector_id) orelse return null;
    if (selector == .log_field) {
        if ((parseEnum(name) catch return null) != 1) return null;
        const body = context.record.body orelse return null;
        return switch (body.value orelse return null) {
            .string_value => |value| value,
            else => null,
        };
    }
    const attributes = mutableAttributes(context, selector) orelse return null;
    const index = findAttributeIndex(attributes.items, firstPath(name)) orelse return null;
    const value = attributes.items[index].value orelse return null;
    return switch (value.value orelse return null) {
        .string_value => |text| text,
        else => null,
    };
}

fn replaceExisting(context: *LogContext, field: policy.image.Field, name: []const u8, value: []const u8) bool {
    const selector = std.enums.fromInt(Selector, field.selector_id) orelse return false;
    if (selector == .log_field) {
        if ((parseEnum(name) catch return false) != 1 or context.record.body == null) return false;
        context.record.body = .{ .value = .{ .string_value = value } };
        return true;
    }
    const attributes = mutableAttributes(context, selector) orelse return false;
    const index = findAttributeIndex(attributes.items, firstPath(name)) orelse return false;
    attributes.items[index].value = .{ .value = .{ .string_value = value } };
    return true;
}

fn anyValue(value: ?AnyValue) ValueRef {
    const item = value orelse return .missing;
    return switch (item.value orelse return .missing) {
        .string_value => |text| stringValue(text),
        .bool_value => |boolean| .{ .boolean = boolean },
        .int_value => |number| .{ .signed = number },
        .double_value => |number| .{ .float = number },
        .bytes_value => |bytes| if (bytes.len == 0) .missing else .{ .bytes = bytes },
        .array_value, .kvlist_value, .string_value_strindex => .{ .boolean = true },
    };
}

fn stringValue(value: []const u8) ValueRef {
    return if (value.len == 0) .missing else .{ .string = value };
}

fn attributeValue(attributes: []const KeyValue, encoded_path: []const u8) ValueRef {
    var current = attributes;
    var parts = std.mem.splitScalar(u8, encoded_path, 0);
    while (parts.next()) |segment| {
        const item = findAttribute(current, segment) orelse return .missing;
        if (parts.peek() == null) return anyValue(item.value);
        const selected = item.value orelse return .missing;
        const value = selected.value orelse return .missing;
        current = switch (value) {
            .kvlist_value => |list| list.values.items,
            else => return .missing,
        };
    }
    return .missing;
}

fn findAttribute(attributes: []const KeyValue, key: []const u8) ?KeyValue {
    for (attributes) |item| if (std.mem.eql(u8, item.key, key)) return item;
    return null;
}

fn findAttributeIndex(attributes: []const KeyValue, key: []const u8) ?usize {
    for (attributes, 0..) |item, index| if (std.mem.eql(u8, item.key, key)) return index;
    return null;
}

fn resourceAttributes(resource: ?*const Resource) []const KeyValue {
    return if (resource) |value| value.attributes.items else &.{};
}

fn scopeAttributes(scope: ?*const InstrumentationScope) []const KeyValue {
    return if (scope) |value| value.attributes.items else &.{};
}

fn parseEnum(name: []const u8) !i32 {
    return std.fmt.parseInt(i32, name, 10);
}

fn metricType(metric: *const proto.metrics.Metric) i32 {
    const data = metric.data orelse return 0;
    return switch (data) {
        .gauge => 1,
        .sum => 2,
        .histogram => 3,
        .exponential_histogram => 4,
        .summary => 5,
    };
}

fn metricTemporality(metric: *const proto.metrics.Metric) ?i32 {
    const data = metric.data orelse return null;
    return switch (data) {
        .sum => |value| @intFromEnum(value.aggregation_temporality),
        .histogram => |value| @intFromEnum(value.aggregation_temporality),
        .exponential_histogram => |value| @intFromEnum(value.aggregation_temporality),
        else => null,
    };
}

fn mutableAttributes(context: *LogContext, selector: Selector) ?*std.ArrayList(KeyValue) {
    return switch (selector) {
        .log_attribute => &context.record.attributes,
        .resource_attribute => if (context.resource) |resource| &resource.attributes else null,
        .scope_attribute => if (context.scope) |scope| &scope.attributes else null,
        else => null,
    };
}

fn remove(context: *LogContext, field: policy.image.Field, name: []const u8) bool {
    const selector = std.enums.fromInt(Selector, field.selector_id) orelse return false;
    if (selector == .log_field) {
        return switch (parseEnum(name) catch return false) {
            1 => if (context.record.body != null) blk: {
                context.record.body = null;
                break :blk true;
            } else false,
            else => false,
        };
    }
    const attributes = mutableAttributes(context, selector) orelse return false;
    const index = findAttributeIndex(attributes.items, firstPath(name)) orelse return false;
    _ = attributes.orderedRemove(index);
    return true;
}

fn set(context: *LogContext, field: policy.image.Field, name: []const u8, value: []const u8, upsert: bool) bool {
    const selector = std.enums.fromInt(Selector, field.selector_id) orelse return false;
    if (selector == .log_field) {
        if ((parseEnum(name) catch return false) != 1) return false;
        if (!upsert and context.record.body != null) return false;
        context.record.body = .{ .value = .{ .string_value = value } };
        return true;
    }
    const attributes = mutableAttributes(context, selector) orelse return false;
    const key = firstPath(name);
    if (findAttributeIndex(attributes.items, key)) |index| {
        if (!upsert) return false;
        attributes.items[index].value = .{ .value = .{ .string_value = value } };
        return true;
    }
    attributes.append(context.allocator, .{ .key = key, .value = .{ .value = .{ .string_value = value } } }) catch
        return false;
    return true;
}

fn rename(context: *LogContext, field: policy.image.Field, name: []const u8, to: []const u8, upsert: bool) bool {
    const selector = std.enums.fromInt(Selector, field.selector_id) orelse return false;
    const attributes = mutableAttributes(context, selector) orelse return false;
    const source = findAttributeIndex(attributes.items, firstPath(name)) orelse return false;
    var moved = attributes.orderedRemove(source);
    if (findAttributeIndex(attributes.items, to)) |target| {
        if (!upsert) {
            attributes.insert(context.allocator, source, moved) catch {};
            return false;
        }
        _ = attributes.orderedRemove(target);
    }
    moved.key = to;
    attributes.append(context.allocator, moved) catch return false;
    return true;
}

fn firstPath(name: []const u8) []const u8 {
    return name[0 .. std.mem.indexOfScalar(u8, name, 0) orelse name.len];
}
