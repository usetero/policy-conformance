const std = @import("std");
const policy = @import("policy_zig");
const o11y = @import("o11y");

const PolicyRegistry = policy.Registry;
const PolicyEngine = policy.PolicyEngine;
const FileProvider = policy.FileProvider;
const FieldRef = policy.FieldRef;
const MetricFieldRef = policy.MetricFieldRef;
const TraceFieldRef = policy.TraceFieldRef;
const FilterDecision = policy.FilterDecision;

// ─── JSON Types ──────────────────────────────────────────────────────

const Input = struct {
    signal_type: []const u8,
    records: std.json.Value,
};

const ResultEntry = struct {
    record_id: []const u8,
    decision: []const u8,
    matched_policy_ids: []const []const u8,
};

// ─── Record types ────────────────────────────────────────────────────

const LogRecord = struct {
    id: []const u8,
    body: []const u8 = "",
    severity_text: []const u8 = "",
    trace_id: []const u8 = "",
    span_id: []const u8 = "",
    attributes: std.json.ObjectMap = undefined,
    resource_attributes: std.json.ObjectMap = undefined,
    scope_attributes: std.json.ObjectMap = undefined,
    has_attributes: bool = false,
    has_resource_attributes: bool = false,
    has_scope_attributes: bool = false,
};

const MetricRecord = struct {
    id: []const u8,
    name: []const u8 = "",
    description: []const u8 = "",
    unit: []const u8 = "",
    metric_type: []const u8 = "",
    aggregation_temporality: []const u8 = "",
    datapoint_attributes: std.json.ObjectMap = undefined,
    resource_attributes: std.json.ObjectMap = undefined,
    scope_attributes: std.json.ObjectMap = undefined,
    has_datapoint_attributes: bool = false,
    has_resource_attributes: bool = false,
    has_scope_attributes: bool = false,
};

const TraceRecord = struct {
    id: []const u8,
    name: []const u8 = "",
    trace_id: []const u8 = "",
    span_id: []const u8 = "",
    parent_span_id: []const u8 = "",
    trace_state: []const u8 = "",
    span_kind: []const u8 = "",
    span_status: []const u8 = "",
    attributes: std.json.ObjectMap = undefined,
    resource_attributes: std.json.ObjectMap = undefined,
    scope_attributes: std.json.ObjectMap = undefined,
    has_attributes: bool = false,
    has_resource_attributes: bool = false,
    has_scope_attributes: bool = false,
};

// ─── Field Accessors ─────────────────────────────────────────────────

fn logFieldAccessor(ctx: *const anyopaque, field: FieldRef) ?[]const u8 {
    const rec: *const LogRecord = @ptrCast(@alignCast(ctx));
    return switch (field) {
        .log_field => |lf| switch (lf) {
            .LOG_FIELD_BODY => nonEmpty(rec.body),
            .LOG_FIELD_SEVERITY_TEXT => nonEmpty(rec.severity_text),
            .LOG_FIELD_TRACE_ID => nonEmpty(rec.trace_id),
            .LOG_FIELD_SPAN_ID => nonEmpty(rec.span_id),
            else => null,
        },
        .log_attribute => |attr| blk: {
            if (!rec.has_attributes) break :blk null;
            const key = if (attr.path.items.len > 0) attr.path.items[0] else break :blk null;
            const val = rec.attributes.get(key) orelse break :blk null;
            break :blk jsonString(val);
        },
        .resource_attribute => |attr| blk: {
            if (!rec.has_resource_attributes) break :blk null;
            const key = if (attr.path.items.len > 0) attr.path.items[0] else break :blk null;
            const val = rec.resource_attributes.get(key) orelse break :blk null;
            break :blk jsonString(val);
        },
        .scope_attribute => |attr| blk: {
            if (!rec.has_scope_attributes) break :blk null;
            const key = if (attr.path.items.len > 0) attr.path.items[0] else break :blk null;
            const val = rec.scope_attributes.get(key) orelse break :blk null;
            break :blk jsonString(val);
        },
    };
}

fn metricFieldAccessor(ctx: *const anyopaque, field: MetricFieldRef) ?[]const u8 {
    const rec: *const MetricRecord = @ptrCast(@alignCast(ctx));
    return switch (field) {
        .metric_field => |mf| switch (mf) {
            .METRIC_FIELD_NAME => nonEmpty(rec.name),
            .METRIC_FIELD_DESCRIPTION => nonEmpty(rec.description),
            .METRIC_FIELD_UNIT => nonEmpty(rec.unit),
            else => null,
        },
        .datapoint_attribute => |attr| blk: {
            if (!rec.has_datapoint_attributes) break :blk null;
            const key = if (attr.path.items.len > 0) attr.path.items[0] else break :blk null;
            const val = rec.datapoint_attributes.get(key) orelse break :blk null;
            break :blk jsonString(val);
        },
        .resource_attribute => |attr| blk: {
            if (!rec.has_resource_attributes) break :blk null;
            const key = if (attr.path.items.len > 0) attr.path.items[0] else break :blk null;
            const val = rec.resource_attributes.get(key) orelse break :blk null;
            break :blk jsonString(val);
        },
        .scope_attribute => |attr| blk: {
            if (!rec.has_scope_attributes) break :blk null;
            const key = if (attr.path.items.len > 0) attr.path.items[0] else break :blk null;
            const val = rec.scope_attributes.get(key) orelse break :blk null;
            break :blk jsonString(val);
        },
        .metric_type => nonEmpty(rec.metric_type),
        .aggregation_temporality => nonEmpty(rec.aggregation_temporality),
    };
}

fn traceFieldAccessor(ctx: *const anyopaque, field: TraceFieldRef) ?[]const u8 {
    const rec: *const TraceRecord = @ptrCast(@alignCast(ctx));
    return switch (field) {
        .trace_field => |tf| switch (tf) {
            .TRACE_FIELD_NAME => nonEmpty(rec.name),
            .TRACE_FIELD_TRACE_ID => nonEmpty(rec.trace_id),
            .TRACE_FIELD_SPAN_ID => nonEmpty(rec.span_id),
            .TRACE_FIELD_PARENT_SPAN_ID => nonEmpty(rec.parent_span_id),
            .TRACE_FIELD_TRACE_STATE => nonEmpty(rec.trace_state),
            else => null,
        },
        .span_attribute => |attr| blk: {
            if (!rec.has_attributes) break :blk null;
            const key = if (attr.path.items.len > 0) attr.path.items[0] else break :blk null;
            const val = rec.attributes.get(key) orelse break :blk null;
            break :blk jsonString(val);
        },
        .resource_attribute => |attr| blk: {
            if (!rec.has_resource_attributes) break :blk null;
            const key = if (attr.path.items.len > 0) attr.path.items[0] else break :blk null;
            const val = rec.resource_attributes.get(key) orelse break :blk null;
            break :blk jsonString(val);
        },
        .scope_attribute => |attr| blk: {
            if (!rec.has_scope_attributes) break :blk null;
            const key = if (attr.path.items.len > 0) attr.path.items[0] else break :blk null;
            const val = rec.scope_attributes.get(key) orelse break :blk null;
            break :blk jsonString(val);
        },
        .span_kind => |requested_kind| blk: {
            // Return the span's kind string only if it matches the requested enum
            const kind_str = nonEmpty(rec.span_kind) orelse break :blk null;
            const requested_str = @tagName(requested_kind);
            break :blk if (std.mem.eql(u8, kind_str, requested_str)) kind_str else null;
        },
        .span_status => |requested_status| blk: {
            // Return the span's status string only if it matches the requested enum
            const status_str = nonEmpty(rec.span_status) orelse break :blk null;
            const requested_str = @tagName(requested_status);
            break :blk if (std.mem.eql(u8, status_str, requested_str)) status_str else null;
        },
        .event_name, .event_attribute, .link_trace_id => null,
    };
}

fn nonEmpty(s: []const u8) ?[]const u8 {
    return if (s.len == 0) null else s;
}

fn jsonString(val: std.json.Value) ?[]const u8 {
    return switch (val) {
        .string => |s| s,
        else => null,
    };
}

// ─── JSON parsing helpers ────────────────────────────────────────────

fn getString(obj: std.json.ObjectMap, key: []const u8) []const u8 {
    const val = obj.get(key) orelse return "";
    return switch (val) {
        .string => |s| s,
        else => "",
    };
}

fn parseLogRecord(obj: std.json.ObjectMap) LogRecord {
    var rec = LogRecord{
        .id = getString(obj, "id"),
        .body = getString(obj, "body"),
        .severity_text = getString(obj, "severity_text"),
        .trace_id = getString(obj, "trace_id"),
        .span_id = getString(obj, "span_id"),
    };
    if (obj.get("attributes")) |v| {
        if (v == .object) {
            rec.attributes = v.object;
            rec.has_attributes = true;
        }
    }
    if (obj.get("resource_attributes")) |v| {
        if (v == .object) {
            rec.resource_attributes = v.object;
            rec.has_resource_attributes = true;
        }
    }
    if (obj.get("scope_attributes")) |v| {
        if (v == .object) {
            rec.scope_attributes = v.object;
            rec.has_scope_attributes = true;
        }
    }
    return rec;
}

fn parseMetricRecord(obj: std.json.ObjectMap) MetricRecord {
    var rec = MetricRecord{
        .id = getString(obj, "id"),
        .name = getString(obj, "name"),
        .description = getString(obj, "description"),
        .unit = getString(obj, "unit"),
        .metric_type = getString(obj, "metric_type"),
        .aggregation_temporality = getString(obj, "aggregation_temporality"),
    };
    if (obj.get("datapoint_attributes")) |v| {
        if (v == .object) {
            rec.datapoint_attributes = v.object;
            rec.has_datapoint_attributes = true;
        }
    }
    if (obj.get("resource_attributes")) |v| {
        if (v == .object) {
            rec.resource_attributes = v.object;
            rec.has_resource_attributes = true;
        }
    }
    if (obj.get("scope_attributes")) |v| {
        if (v == .object) {
            rec.scope_attributes = v.object;
            rec.has_scope_attributes = true;
        }
    }
    return rec;
}

fn parseTraceRecord(obj: std.json.ObjectMap) TraceRecord {
    var rec = TraceRecord{
        .id = getString(obj, "id"),
        .name = getString(obj, "name"),
        .trace_id = getString(obj, "trace_id"),
        .span_id = getString(obj, "span_id"),
        .parent_span_id = getString(obj, "parent_span_id"),
        .trace_state = getString(obj, "trace_state"),
        .span_kind = getString(obj, "span_kind"),
        .span_status = getString(obj, "span_status"),
    };
    if (obj.get("attributes")) |v| {
        if (v == .object) {
            rec.attributes = v.object;
            rec.has_attributes = true;
        }
    }
    if (obj.get("resource_attributes")) |v| {
        if (v == .object) {
            rec.resource_attributes = v.object;
            rec.has_resource_attributes = true;
        }
    }
    if (obj.get("scope_attributes")) |v| {
        if (v == .object) {
            rec.scope_attributes = v.object;
            rec.has_scope_attributes = true;
        }
    }
    return rec;
}

// ─── Decision mapping ────────────────────────────────────────────────

fn mapDecision(decision: FilterDecision) []const u8 {
    return switch (decision) {
        .keep => "keep",
        .drop => "drop",
        .unset => "no_match",
    };
}

// The Zig engine's evaluate() returns PolicyResult.dropped with empty
// matched_policy_ids for drop decisions, but it still populates the
// policy_id_buf passed in. We use a sentinel to detect how many entries
// were actually written.
const sentinel: []const u8 = &.{0xFF};

fn initPolicyIdBuf(buf: *[16][]const u8) void {
    for (buf) |*slot| {
        slot.* = sentinel;
    }
}

fn countMatchedIds(buf: *const [16][]const u8) usize {
    for (buf, 0..) |slot, i| {
        if (slot.ptr == sentinel.ptr) return i;
    }
    return buf.len;
}

// ─── Output writing ──────────────────────────────────────────────────

fn writeOutput(allocator: std.mem.Allocator, path: []const u8, results: []const ResultEntry) !void {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);

    const writer = buf.writer(allocator);

    try writer.writeAll("{\n  \"results\": [\n");
    for (results, 0..) |r, i| {
        try writer.writeAll("    {\n");
        try writer.print("      \"record_id\": \"{s}\",\n", .{r.record_id});
        try writer.print("      \"decision\": \"{s}\",\n", .{r.decision});
        try writer.writeAll("      \"matched_policy_ids\": [");
        for (r.matched_policy_ids, 0..) |pid, j| {
            if (j > 0) try writer.writeAll(", ");
            try writer.print("\"{s}\"", .{pid});
        }
        try writer.writeAll("]\n    }");
        if (i < results.len - 1) try writer.writeByte(',');
        try writer.writeByte('\n');
    }
    try writer.writeAll("  ]\n}\n");

    const file = try std.fs.cwd().createFile(path, .{});
    defer file.close();
    try file.writeAll(buf.items);
}

// ─── Core evaluation logic ───────────────────────────────────────────

const CallbackContext = struct {
    registry: *PolicyRegistry,

    fn handleUpdate(ctx: *anyopaque, update: policy.PolicyUpdate) !void {
        const self: *CallbackContext = @ptrCast(@alignCast(ctx));
        try self.registry.updatePolicies(update.policies, update.provider_id, .file);
    }
};

fn run(allocator: std.mem.Allocator, pol_path: []const u8, in_path: []const u8, out_path: []const u8) !void {
    // Set up event bus
    var noop_bus: o11y.NoopEventBus = undefined;
    noop_bus.init();

    // Set up registry
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Load policies via FileProvider
    const provider = try FileProvider.init(allocator, noop_bus.eventBus(), "conformance", pol_path);
    defer provider.deinit();

    var cb_ctx = CallbackContext{ .registry = &registry };
    try provider.subscribe(.{
        .context = @ptrCast(&cb_ctx),
        .onUpdate = CallbackContext.handleUpdate,
    });

    // Create engine
    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    // Read and parse input
    const input_data = try std.fs.cwd().readFileAlloc(allocator, in_path, 10 * 1024 * 1024);
    defer allocator.free(input_data);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, input_data, .{});
    defer parsed.deinit();

    const root = parsed.value.object;
    const signal_type = getString(root, "signal_type");
    const records_val = root.get("records") orelse return error.MissingRecords;
    const records = switch (records_val) {
        .array => |a| a.items,
        else => return error.InvalidRecords,
    };

    // Evaluate each record
    var results: std.ArrayList(ResultEntry) = .empty;
    defer {
        for (results.items) |r| {
            allocator.free(r.matched_policy_ids);
        }
        results.deinit(allocator);
    }

    var policy_id_buf: [16][]const u8 = undefined;

    if (std.mem.eql(u8, signal_type, "log")) {
        for (records) |rec_val| {
            const obj = switch (rec_val) {
                .object => |o| o,
                else => continue,
            };
            var rec = parseLogRecord(obj);
            initPolicyIdBuf(&policy_id_buf);
            const result = engine.evaluate(.log, @ptrCast(&rec), logFieldAccessor, null, &policy_id_buf);
            const matched_count = if (result.matched_policy_ids.len > 0) result.matched_policy_ids.len else countMatchedIds(&policy_id_buf);
            const matched = try allocator.dupe([]const u8, policy_id_buf[0..matched_count]);
            try results.append(allocator, .{
                .record_id = rec.id,
                .decision = mapDecision(result.decision),
                .matched_policy_ids = matched,
            });
        }
    } else if (std.mem.eql(u8, signal_type, "metric")) {
        for (records) |rec_val| {
            const obj = switch (rec_val) {
                .object => |o| o,
                else => continue,
            };
            var rec = parseMetricRecord(obj);
            initPolicyIdBuf(&policy_id_buf);
            const result = engine.evaluate(.metric, @ptrCast(&rec), metricFieldAccessor, null, &policy_id_buf);
            const matched_count = if (result.matched_policy_ids.len > 0) result.matched_policy_ids.len else countMatchedIds(&policy_id_buf);
            const matched = try allocator.dupe([]const u8, policy_id_buf[0..matched_count]);
            try results.append(allocator, .{
                .record_id = rec.id,
                .decision = mapDecision(result.decision),
                .matched_policy_ids = matched,
            });
        }
    } else if (std.mem.eql(u8, signal_type, "trace")) {
        for (records) |rec_val| {
            const obj = switch (rec_val) {
                .object => |o| o,
                else => continue,
            };
            var rec = parseTraceRecord(obj);
            initPolicyIdBuf(&policy_id_buf);
            const result = engine.evaluate(.trace, @ptrCast(&rec), traceFieldAccessor, null, &policy_id_buf);
            const matched_count = if (result.matched_policy_ids.len > 0) result.matched_policy_ids.len else countMatchedIds(&policy_id_buf);
            const matched = try allocator.dupe([]const u8, policy_id_buf[0..matched_count]);
            try results.append(allocator, .{
                .record_id = rec.id,
                .decision = mapDecision(result.decision),
                .matched_policy_ids = matched,
            });
        }
    } else {
        return error.UnknownSignalType;
    }

    // Write output
    try writeOutput(allocator, out_path, results.items);
}

// ─── Main ────────────────────────────────────────────────────────────

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse args
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var policies_path: ?[]const u8 = null;
    var input_path: ?[]const u8 = null;
    var output_path: ?[]const u8 = null;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--policies") and i + 1 < args.len) {
            i += 1;
            policies_path = args[i];
        } else if (std.mem.eql(u8, args[i], "--input") and i + 1 < args.len) {
            i += 1;
            input_path = args[i];
        } else if (std.mem.eql(u8, args[i], "--output") and i + 1 < args.len) {
            i += 1;
            output_path = args[i];
        }
    }

    const pol_path = policies_path orelse {
        std.debug.print("usage: runner-zig --policies <path> --input <path> --output <path>\n", .{});
        std.process.exit(1);
    };
    const in_path = input_path orelse {
        std.debug.print("usage: runner-zig --policies <path> --input <path> --output <path>\n", .{});
        std.process.exit(1);
    };
    const out_path = output_path orelse {
        std.debug.print("usage: runner-zig --policies <path> --input <path> --output <path>\n", .{});
        std.process.exit(1);
    };

    run(gpa.allocator(), pol_path, in_path, out_path) catch |err| {
        std.debug.print("error: {}\n", .{err});
        std.process.exit(1);
    };
}

// ─── Tests ───────────────────────────────────────────────────────────

test "no memory leaks with FileProvider" {
    const allocator = std.testing.allocator;

    // Write a temporary policies file
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const pol_file = try tmp_dir.dir.createFile("policies.json", .{});
    try pol_file.writeAll(
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "drop-debug",
        \\      "name": "drop-debug",
        \\      "log": {
        \\        "match": [{ "log_field": "body", "regex": "debug" }],
        \\        "keep": "none"
        \\      }
        \\    }
        \\  ]
        \\}
    );
    pol_file.close();

    const input_file = try tmp_dir.dir.createFile("input.json", .{});
    try input_file.writeAll(
        \\{
        \\  "signal_type": "log",
        \\  "records": [
        \\    {
        \\      "id": "r1",
        \\      "body": "debug message",
        \\      "severity_text": "DEBUG",
        \\      "trace_id": "",
        \\      "span_id": "",
        \\      "attributes": {},
        \\      "resource_attributes": {},
        \\      "scope_attributes": {}
        \\    },
        \\    {
        \\      "id": "r2",
        \\      "body": "info message",
        \\      "severity_text": "INFO",
        \\      "trace_id": "",
        \\      "span_id": "",
        \\      "attributes": {},
        \\      "resource_attributes": {},
        \\      "scope_attributes": {}
        \\    }
        \\  ]
        \\}
    );
    input_file.close();

    var pol_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    var in_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    var out_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const pol_path = try tmp_dir.dir.realpath("policies.json", &pol_path_buf);
    const in_path = try tmp_dir.dir.realpath("input.json", &in_path_buf);

    // Build output path in the same tmp dir
    const out_rel = "output.json";
    _ = try tmp_dir.dir.createFile(out_rel, .{});
    const out_path = try tmp_dir.dir.realpath(out_rel, &out_path_buf);

    try run(allocator, pol_path, in_path, out_path);
}
