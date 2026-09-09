//! Conformance host for the immutable policy image runtime.

const std = @import("std");
const policy = @import("policy_zig");
const proto = @import("otel_proto");
const projection = @import("projection.zig");
const RegexSet = @import("regex_backend.zig").RegexSet;
const Redactions = @import("redact.zig").Redactions;

const LogsData = proto.logs.LogsData;
const MetricsData = proto.metrics.MetricsData;
const TracesData = proto.trace.TracesData;

const json_options: std.json.ParseOptions = .{ .ignore_unknown_fields = true };
const protobuf_options: proto.protobuf.json.Options = .{
    .emit_oneof_field_name = false,
    .hex_bytes_fields = &.{ "trace_id", "span_id", "parent_span_id" },
};

const Signal = enum { log, metric, trace };

const Runtime = struct {
    allocator: std.mem.Allocator,
    parsed_policies: []policy.proto.policy.Policy,
    prepared: policy.source.PreparedProgram,
    image_storage: []u8,
    workspace: []u8,
    worker_storage: []u8,
    image: policy.PolicyImage,
    worker: policy.WorkerState,
    projector: projection.Projector,
    regex: RegexSet,
    redactions: Redactions,

    fn init(allocator: std.mem.Allocator, policy_bytes: []const u8) !Runtime {
        const parsed_policies = try policy.source.parseAuthoringBytes(allocator, policy_bytes);
        errdefer policy.source.freePolicies(allocator, parsed_policies);
        var prepared = try policy.source.adapter.prepare(allocator, parsed_policies, 0x7465_726f);
        errdefer prepared.deinit();

        var matcher_count: usize = 0;
        var action_count: usize = 0;
        var string_bytes: usize = 0;
        for (prepared.program.policies) |item| {
            matcher_count += item.matchers.len;
            action_count += item.actions.len;
            for (item.matchers) |matcher| {
                string_bytes += matcher.field.name.len;
                string_bytes += switch (matcher.value) {
                    .string, .float => |value| value.len,
                    else => 0,
                };
            }
            for (item.actions) |action| {
                if (action.field) |field| string_bytes += field.name.len;
                string_bytes += action.value.len;
            }
        }
        const field_capacity = @max(matcher_count + action_count, 1);
        const image_capacity = @max(
            @as(usize, policy.image.header_bytes) +
                prepared.program.policies.len * policy.image.policy_bytes +
                field_capacity * policy.image.field_bytes +
                matcher_count * policy.image.matcher_bytes +
                action_count * policy.image.action_bytes + string_bytes,
            128,
        );
        const capacity: policy.Capacity = .{
            .max_connections = 1,
            .worker_count = 1,
            .max_policies = @intCast(@max(prepared.program.policies.len, 1)),
            .max_fields = @intCast(field_capacity),
            .max_matchers = @intCast(matcher_count),
            .max_actions = @intCast(action_count),
            .max_image_bytes = @intCast(image_capacity),
            .max_record_bytes = 10 * 1024 * 1024,
            .max_context_bytes = 1,
            .max_group_bytes = 4096,
            .journal_events_per_worker = 1,
            .extension_queue_bytes = 0,
        };
        const image_storage = try allocator.alloc(u8, capacity.max_image_bytes);
        errdefer allocator.free(image_storage);
        const workspace = try allocator.alloc(u8, policy.PolicyCompiler.requiredWorkspace(capacity));
        errdefer allocator.free(workspace);
        var compiler = try policy.PolicyCompiler.init(capacity, workspace, image_storage);
        const compiled = try compiler.compile(prepared.program);
        const image = try policy.PolicyImage.open(compiled);

        const worker_storage = try allocator.alloc(u8, policy.WorkerState.requiredBytes(capacity));
        errdefer allocator.free(worker_storage);
        const worker = try policy.WorkerState.init(worker_storage, capacity);
        var projector = try projection.Projector.init(allocator, image.header.field_count);
        errdefer projector.deinit(allocator);
        var regex = try RegexSet.init(allocator, &image);
        errdefer regex.deinit();
        var redactions = try Redactions.init(allocator, &image);
        errdefer redactions.deinit();

        return .{
            .allocator = allocator,
            .parsed_policies = parsed_policies,
            .prepared = prepared,
            .image_storage = image_storage,
            .workspace = workspace,
            .worker_storage = worker_storage,
            .image = image,
            .worker = worker,
            .projector = projector,
            .regex = regex,
            .redactions = redactions,
        };
    }

    fn deinit(self: *Runtime) void {
        self.redactions.deinit();
        self.regex.deinit();
        self.projector.deinit(self.allocator);
        self.allocator.free(self.worker_storage);
        self.allocator.free(self.workspace);
        self.allocator.free(self.image_storage);
        self.prepared.deinit();
        policy.source.freePolicies(self.allocator, self.parsed_policies);
        self.* = undefined;
    }

    fn engine(self: *Runtime) policy.PolicyEngine {
        return .init(&self.image, &self.worker);
    }

    fn context(self: *Runtime, signal: policy.image.Signal, sequence: u64, key: []const u8) policy.EvalContext {
        return .{
            .image_epoch = 1,
            .worker_id = 0,
            .record_sequence = sequence,
            .timestamp_ns = 0,
            .signal = signal,
            .record_key = key,
            .regex = self.regex.backend(),
        };
    }
};

fn processLogs(allocator: std.mem.Allocator, runtime: *Runtime, input: []const u8) ![]const u8 {
    var parsed = try proto.protobuf.json.decodeOpts(LogsData, input, json_options, protobuf_options, allocator);
    defer parsed.deinit();
    var data = parsed.value;
    const data_allocator = parsed.arena.allocator();
    var sequence: u64 = 0;
    for (data.resource_logs.items) |*resource_logs| {
        const resource = if (resource_logs.resource) |*value| value else null;
        for (resource_logs.scope_logs.items) |*scope_logs| {
            const scope = if (scope_logs.scope) |*value| value else null;
            var index: usize = 0;
            while (index < scope_logs.log_records.items.len) {
                const record = &scope_logs.log_records.items[index];
                var context: projection.LogContext = .{
                    .record = record,
                    .resource = resource,
                    .scope = scope,
                    .allocator = data_allocator,
                    .resource_schema_url = resource_logs.schema_url,
                    .scope_schema_url = scope_logs.schema_url,
                };
                const values = try runtime.projector.logs(&runtime.image, &context);
                const key = if (record.trace_id.len != 0) record.trace_id else logKey(record);
                const decision = runtime.engine().evaluate(values, runtime.context(.log, sequence, key));
                sequence += 1;
                if (decision.verdict == .drop) {
                    _ = scope_logs.log_records.orderedRemove(index);
                } else {
                    try projection.applyLogActions(
                        &runtime.image,
                        &runtime.worker,
                        &context,
                        &runtime.redactions,
                    );
                    index += 1;
                }
            }
        }
    }
    pruneLogs(&data);
    return data.jsonEncode(.{}, protobuf_options, allocator);
}

fn processMetrics(allocator: std.mem.Allocator, runtime: *Runtime, input: []const u8) ![]const u8 {
    var parsed = try proto.protobuf.json.decodeOpts(MetricsData, input, json_options, protobuf_options, allocator);
    defer parsed.deinit();
    var data = parsed.value;
    var sequence: u64 = 0;
    for (data.resource_metrics.items) |*resource_metrics| {
        const resource = if (resource_metrics.resource) |*value| value else null;
        for (resource_metrics.scope_metrics.items) |*scope_metrics| {
            const scope = if (scope_metrics.scope) |*value| value else null;
            var metric_index: usize = 0;
            while (metric_index < scope_metrics.metrics.items.len) {
                const metric = &scope_metrics.metrics.items[metric_index];
                if (metric.data) |*metric_data| switch (metric_data.*) {
                    inline else => |*variant| {
                        var point_index: usize = 0;
                        while (point_index < variant.data_points.items.len) {
                            var context: projection.MetricContext = .{
                                .metric = metric,
                                .datapoint_attributes = variant.data_points.items[point_index].attributes.items,
                                .resource = resource,
                                .scope = scope,
                                .resource_schema_url = resource_metrics.schema_url,
                                .scope_schema_url = scope_metrics.schema_url,
                            };
                            const values = try runtime.projector.metrics(&runtime.image, &context);
                            const decision = runtime.engine().evaluate(
                                values,
                                runtime.context(.metric, sequence, metric.name),
                            );
                            sequence += 1;
                            if (decision.verdict == .drop) {
                                _ = variant.data_points.orderedRemove(point_index);
                            } else {
                                point_index += 1;
                            }
                        }
                    },
                };
                if (metric.data != null and dataPointCount(metric) == 0) {
                    _ = scope_metrics.metrics.orderedRemove(metric_index);
                } else {
                    metric_index += 1;
                }
            }
        }
    }
    pruneMetrics(&data);
    return data.jsonEncode(.{}, protobuf_options, allocator);
}

fn processTraces(allocator: std.mem.Allocator, runtime: *Runtime, input: []const u8) ![]const u8 {
    var parsed = try proto.protobuf.json.decodeOpts(TracesData, input, json_options, protobuf_options, allocator);
    defer parsed.deinit();
    var data = parsed.value;
    const data_allocator = parsed.arena.allocator();
    var sequence: u64 = 0;
    for (data.resource_spans.items) |*resource_spans| {
        const resource = if (resource_spans.resource) |*value| value else null;
        for (resource_spans.scope_spans.items) |*scope_spans| {
            const scope = if (scope_spans.scope) |*value| value else null;
            var index: usize = 0;
            while (index < scope_spans.spans.items.len) {
                const span = &scope_spans.spans.items[index];
                const context: projection.TraceContext = .{
                    .span = span,
                    .resource = resource,
                    .scope = scope,
                    .resource_schema_url = resource_spans.schema_url,
                    .scope_schema_url = scope_spans.schema_url,
                };
                const values = try runtime.projector.traces(&runtime.image, &context);
                var eval_context = runtime.context(.trace, sequence, span.trace_id);
                eval_context.trace_state = span.trace_state;
                const decision = runtime.engine().evaluate(values, eval_context);
                sequence += 1;
                if (decision.verdict == .drop) {
                    _ = scope_spans.spans.orderedRemove(index);
                } else {
                    var trace_state_buffer: [512]u8 = undefined;
                    if (decision.updateTraceState(&trace_state_buffer, span.trace_state)) |trace_state| {
                        span.trace_state = try data_allocator.dupe(u8, trace_state);
                    }
                    index += 1;
                }
            }
        }
    }
    pruneTraces(&data);
    return data.jsonEncode(.{}, protobuf_options, allocator);
}

fn writeStats(io: std.Io, path: []const u8, runtime: *Runtime) !void {
    var output: std.Io.Writer.Allocating = .init(runtime.allocator);
    defer output.deinit();
    try output.writer.writeAll("{\"policies\":[");
    var written: usize = 0;
    for (runtime.prepared.program.policies, 0..) |item, index| {
        const hits = runtime.worker.stats.hits[index];
        const misses = runtime.worker.stats.misses[index];
        if (hits == 0 and misses == 0) continue;
        if (written != 0) try output.writer.writeByte(',');
        if (misses == 0) {
            try output.writer.print("{{\"policy_id\":\"{s}\",\"hits\":{d}}}", .{ item.id, hits });
        } else {
            try output.writer.print(
                "{{\"policy_id\":\"{s}\",\"hits\":{d},\"misses\":{d}}}",
                .{ item.id, hits, misses },
            );
        }
        written += 1;
    }
    try output.writer.writeAll("]}");
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = output.written() });
}

fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    policies_path: []const u8,
    input_path: []const u8,
    output_path: []const u8,
    stats_path: []const u8,
    signal: Signal,
) !void {
    const policy_bytes = try std.Io.Dir.cwd().readFileAlloc(io, policies_path, allocator, .limited(10 * 1024 * 1024));
    defer allocator.free(policy_bytes);
    var runtime = try Runtime.init(allocator, policy_bytes);
    defer runtime.deinit();

    const input = try std.Io.Dir.cwd().readFileAlloc(io, input_path, allocator, .limited(10 * 1024 * 1024));
    defer allocator.free(input);
    const output = switch (signal) {
        .log => try processLogs(allocator, &runtime, input),
        .metric => try processMetrics(allocator, &runtime, input),
        .trace => try processTraces(allocator, &runtime, input),
    };
    defer allocator.free(output);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = output_path, .data = output });
    try writeStats(io, stats_path, &runtime);
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var policies_path: ?[]const u8 = null;
    var input_path: ?[]const u8 = null;
    var output_path: ?[]const u8 = null;
    var stats_path: ?[]const u8 = null;
    var signal: ?Signal = null;
    var index: usize = 1;
    while (index < args.len) : (index += 1) {
        if (index + 1 >= args.len) break;
        const value = args[index + 1];
        if (std.mem.eql(u8, args[index], "--policies")) policies_path = value else if (std.mem.eql(u8, args[index], "--input")) input_path = value else if (std.mem.eql(u8, args[index], "--output")) output_path = value else if (std.mem.eql(u8, args[index], "--stats")) stats_path = value else if (std.mem.eql(u8, args[index], "--signal")) {
            signal = std.meta.stringToEnum(Signal, value);
        } else if (std.mem.eql(u8, args[index], "--server")) {
            return error.HttpProviderMovedToHost;
        }
        index += 1;
    }
    run(
        init.gpa,
        init.io,
        policies_path orelse return error.MissingPolicies,
        input_path orelse return error.MissingInput,
        output_path orelse return error.MissingOutput,
        stats_path orelse return error.MissingStats,
        signal orelse return error.MissingSignal,
    ) catch |err| {
        std.debug.print("error: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn logKey(record: *const proto.logs.LogRecord) []const u8 {
    const body = record.body orelse return record.severity_text;
    const value = body.value orelse return record.severity_text;
    return switch (value) {
        .string_value => |text| text,
        else => record.severity_text,
    };
}

fn dataPointCount(metric: *const proto.metrics.Metric) usize {
    const data = metric.data orelse return 0;
    return switch (data) {
        inline else => |variant| variant.data_points.items.len,
    };
}

fn pruneLogs(data: *LogsData) void {
    for (data.resource_logs.items) |*resource| {
        var index: usize = 0;
        while (index < resource.scope_logs.items.len) {
            if (resource.scope_logs.items[index].log_records.items.len == 0) {
                _ = resource.scope_logs.orderedRemove(index);
            } else index += 1;
        }
    }
    var index: usize = 0;
    while (index < data.resource_logs.items.len) {
        if (data.resource_logs.items[index].scope_logs.items.len == 0) {
            _ = data.resource_logs.orderedRemove(index);
        } else index += 1;
    }
}

fn pruneMetrics(data: *MetricsData) void {
    for (data.resource_metrics.items) |*resource| {
        var index: usize = 0;
        while (index < resource.scope_metrics.items.len) {
            if (resource.scope_metrics.items[index].metrics.items.len == 0) {
                _ = resource.scope_metrics.orderedRemove(index);
            } else index += 1;
        }
    }
    var index: usize = 0;
    while (index < data.resource_metrics.items.len) {
        if (data.resource_metrics.items[index].scope_metrics.items.len == 0) {
            _ = data.resource_metrics.orderedRemove(index);
        } else index += 1;
    }
}

fn pruneTraces(data: *TracesData) void {
    for (data.resource_spans.items) |*resource| {
        var index: usize = 0;
        while (index < resource.scope_spans.items.len) {
            if (resource.scope_spans.items[index].spans.items.len == 0) {
                _ = resource.scope_spans.orderedRemove(index);
            } else index += 1;
        }
    }
    var index: usize = 0;
    while (index < data.resource_spans.items.len) {
        if (data.resource_spans.items[index].scope_spans.items.len == 0) {
            _ = data.resource_spans.orderedRemove(index);
        } else index += 1;
    }
}
