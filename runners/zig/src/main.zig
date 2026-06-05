const std = @import("std");
const policy = @import("policy_zig");
const o11y = @import("o11y");
const eval = @import("eval.zig");

const PolicyRegistry = policy.Registry;
const PolicyEngine = policy.PolicyEngine;
const FilterDecision = policy.FilterDecision;
const FileProvider = policy.FileProvider;
const HttpProvider = policy.HttpProvider;

const proto = policy.proto;
const LogsData = proto.logs.LogsData;
const MetricsData = proto.metrics.MetricsData;
const TracesData = proto.trace.TracesData;

// ─── Stats output ────────────────────────────────────────────────────

const PolicyStat = struct {
    policy_id: []const u8,
    hits: i64,
    misses: i64,
};

fn writeStats(allocator: std.mem.Allocator, io: std.Io, path: []const u8, registry: *PolicyRegistry) !void {
    const snapshot = registry.getSnapshot() orelse return;

    var stats: std.ArrayListUnmanaged(PolicyStat) = .empty;
    defer stats.deinit(allocator);

    for (snapshot.policies, 0..) |p, i| {
        const s = snapshot.getStats(@intCast(i)) orelse continue;
        const counters = s.readAndReset();
        if (counters.hits > 0 or counters.misses > 0) {
            try stats.append(allocator, .{ .policy_id = p.id, .hits = counters.hits, .misses = counters.misses });
        }
    }

    std.mem.sort(PolicyStat, stats.items, {}, struct {
        fn lessThan(_: void, a: PolicyStat, b: PolicyStat) bool {
            return std.mem.order(u8, a.policy_id, b.policy_id) == .lt;
        }
    }.lessThan);

    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    const writer = &out.writer;

    try writer.writeAll("{\"policies\":[");
    for (stats.items, 0..) |st, i| {
        if (i > 0) try writer.writeByte(',');
        if (st.misses > 0) {
            try writer.print("{{\"policy_id\":\"{s}\",\"hits\":{d},\"misses\":{d}}}", .{ st.policy_id, st.hits, st.misses });
        } else {
            try writer.print("{{\"policy_id\":\"{s}\",\"hits\":{d}}}", .{ st.policy_id, st.hits });
        }
    }
    try writer.writeAll("]}");

    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = out.written() });
}

// ─── Signal processing ──────────────────────────────────────────────

const json_opts: std.json.ParseOptions = .{
    .ignore_unknown_fields = true,
};

// protobuf 5.0.0 JSON encode options: standard proto3 mapping (oneof fields
// emitted without a wrapper) and bytes rendered as lowercase hex — OTel/JSON
// encodes traceId/spanId as hex. Decode honours the `tl_bytes_as_hex`
// thread-local, set once in main()/tests before decoding.
const pb_encode_opts: proto.protobuf.json.Options = .{
    .emit_oneof_field_name = false,
    .bytes_as_hex = true,
};

fn processLogs(allocator: std.mem.Allocator, io: std.Io, engine: PolicyEngine, input_data: []const u8) ![]const u8 {
    var parsed = try LogsData.jsonDecode(input_data, json_opts, allocator);
    defer parsed.deinit();
    var data = parsed.value;
    const data_allocator = parsed.arena.allocator();

    // Scratch for transform temporaries. Writes into decoded OTLP data use the
    // JSON parse arena because it owns the decoded protobuf tree.
    var transform_arena = std.heap.ArenaAllocator.init(allocator);
    defer transform_arena.deinit();

    // Evaluate each log record, mark dropped ones
    for (data.resource_logs.items) |*rl| {
        const resource = if (rl.resource) |*r| r else null;
        for (rl.scope_logs.items) |*sl| {
            const scope = if (sl.scope) |*s| s else null;
            var i: usize = 0;
            while (i < sl.log_records.items.len) {
                var ctx = eval.LogContext{
                    .record = &sl.log_records.items[i],
                    .resource = resource,
                    .scope = scope,
                    .allocator = data_allocator,
                    .resource_schema_url = rl.schema_url,
                    .scope_schema_url = sl.schema_url,
                };
                var policy_id_buf: [16][]const u8 = undefined;
                const result = engine.evaluate(.log, &eval.log_accessor, @ptrCast(&ctx), &policy_id_buf, .{
                    .scratch = transform_arena.allocator(),
                    .io = io,
                });
                if (result.decision == .drop) {
                    _ = sl.log_records.orderedRemove(i);
                } else {
                    i += 1;
                }
            }
        }
    }

    // Prune empty scope containers
    for (data.resource_logs.items) |*rl| {
        var i: usize = 0;
        while (i < rl.scope_logs.items.len) {
            if (rl.scope_logs.items[i].log_records.items.len == 0) {
                _ = rl.scope_logs.orderedRemove(i);
            } else {
                i += 1;
            }
        }
    }

    // Prune empty resource containers
    {
        var i: usize = 0;
        while (i < data.resource_logs.items.len) {
            if (data.resource_logs.items[i].scope_logs.items.len == 0) {
                _ = data.resource_logs.orderedRemove(i);
            } else {
                i += 1;
            }
        }
    }

    return data.jsonEncode(.{}, pb_encode_opts, allocator);
}

fn processMetrics(allocator: std.mem.Allocator, io: std.Io, engine: PolicyEngine, input_data: []const u8) ![]const u8 {
    var parsed = try MetricsData.jsonDecode(input_data, json_opts, allocator);
    defer parsed.deinit();
    var data = parsed.value;

    for (data.resource_metrics.items) |*rm| {
        const resource = if (rm.resource) |*r| r else null;
        for (rm.scope_metrics.items) |*sm| {
            const scope = if (sm.scope) |*s| s else null;
            var i: usize = 0;
            while (i < sm.metrics.items.len) {
                const metric = &sm.metrics.items[i];
                // Get datapoint attributes from the first datapoint
                const dp_attrs = getDatapointAttrs(metric);
                var ctx = eval.MetricContext{
                    .metric = metric,
                    .datapoint_attributes = dp_attrs,
                    .resource = resource,
                    .scope = scope,
                    .resource_schema_url = rm.schema_url,
                    .scope_schema_url = sm.schema_url,
                };
                var policy_id_buf: [16][]const u8 = undefined;
                const result = engine.evaluate(.metric, &eval.metric_accessor, @ptrCast(&ctx), &policy_id_buf, .{
                    .io = io,
                });
                if (result.decision == .drop) {
                    _ = sm.metrics.orderedRemove(i);
                } else {
                    i += 1;
                }
            }
        }
    }

    // Prune empty containers
    for (data.resource_metrics.items) |*rm| {
        var i: usize = 0;
        while (i < rm.scope_metrics.items.len) {
            if (rm.scope_metrics.items[i].metrics.items.len == 0) {
                _ = rm.scope_metrics.orderedRemove(i);
            } else {
                i += 1;
            }
        }
    }
    {
        var i: usize = 0;
        while (i < data.resource_metrics.items.len) {
            if (data.resource_metrics.items[i].scope_metrics.items.len == 0) {
                _ = data.resource_metrics.orderedRemove(i);
            } else {
                i += 1;
            }
        }
    }

    return data.jsonEncode(.{}, pb_encode_opts, allocator);
}

fn processTraces(allocator: std.mem.Allocator, io: std.Io, engine: PolicyEngine, input_data: []const u8) ![]const u8 {
    var parsed = try TracesData.jsonDecode(input_data, json_opts, allocator);
    defer parsed.deinit();
    var data = parsed.value;
    const data_allocator = parsed.arena.allocator();

    // Scratch for transform temporaries. Writes into decoded OTLP data use the
    // JSON parse arena because it owns the decoded protobuf tree.
    var transform_arena = std.heap.ArenaAllocator.init(allocator);
    defer transform_arena.deinit();

    for (data.resource_spans.items) |*rs| {
        const resource = if (rs.resource) |*r| r else null;
        for (rs.scope_spans.items) |*ss| {
            const scope = if (ss.scope) |*s| s else null;
            var i: usize = 0;
            while (i < ss.spans.items.len) {
                var ctx = eval.TraceContext{
                    .span = &ss.spans.items[i],
                    .resource = resource,
                    .scope = scope,
                    .allocator = data_allocator,
                    .resource_schema_url = rs.schema_url,
                    .scope_schema_url = ss.schema_url,
                };
                var policy_id_buf: [16][]const u8 = undefined;
                const result = engine.evaluate(.trace, &eval.trace_accessor, @ptrCast(&ctx), &policy_id_buf, .{
                    .scratch = transform_arena.allocator(),
                    .io = io,
                });
                if (result.decision == .drop) {
                    _ = ss.spans.orderedRemove(i);
                } else {
                    i += 1;
                }
            }
        }
    }

    // Prune empty containers
    for (data.resource_spans.items) |*rs| {
        var i: usize = 0;
        while (i < rs.scope_spans.items.len) {
            if (rs.scope_spans.items[i].spans.items.len == 0) {
                _ = rs.scope_spans.orderedRemove(i);
            } else {
                i += 1;
            }
        }
    }
    {
        var i: usize = 0;
        while (i < data.resource_spans.items.len) {
            if (data.resource_spans.items[i].scope_spans.items.len == 0) {
                _ = data.resource_spans.orderedRemove(i);
            } else {
                i += 1;
            }
        }
    }

    return data.jsonEncode(.{}, pb_encode_opts, allocator);
}

fn getDatapointAttrs(metric: *const proto.metrics.Metric) []const proto.common.KeyValue {
    const data = metric.data orelse return &.{};
    return switch (data) {
        .gauge => |g| if (g.data_points.items.len > 0) g.data_points.items[0].attributes.items else &.{},
        .sum => |s| if (s.data_points.items.len > 0) s.data_points.items[0].attributes.items else &.{},
        .histogram => |h| if (h.data_points.items.len > 0) h.data_points.items[0].attributes.items else &.{},
        .exponential_histogram => |eh| if (eh.data_points.items.len > 0) eh.data_points.items[0].attributes.items else &.{},
        .summary => |s| if (s.data_points.items.len > 0) s.data_points.items[0].attributes.items else &.{},
    };
}

// ─── Core ────────────────────────────────────────────────────────────

const Signal = enum { log, metric, trace };

fn run(allocator: std.mem.Allocator, io: std.Io, pol_path: ?[]const u8, server_url: ?[]const u8, in_path: []const u8, out_path: []const u8, stats_path: ?[]const u8, signal: Signal) !void {
    var noop_bus: o11y.NoopEventBus = undefined;
    noop_bus.init(io);

    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const file_provider: ?*FileProvider = if (pol_path) |pp|
        try FileProvider.init(allocator, io, noop_bus.eventBus(), .{ .id = "conformance", .path = pp })
    else
        null;

    const http_provider: ?*HttpProvider = if (server_url) |url|
        try HttpProvider.init(allocator, io, noop_bus.eventBus(), .{ .id = "conformance", .url = url, .poll_interval_seconds = 60 })
    else
        null;
    if (file_provider) |fp| {
        defer fp.deinit();
        try registry.subscribe(.{ .file = fp });
        defer fp.shutdown();

        try evaluate(allocator, io, &registry, noop_bus.eventBus(), in_path, out_path, signal);
        try writeStats(allocator, io, stats_path.?, &registry);
    } else if (http_provider) |hp| {
        defer hp.deinit();
        try registry.subscribe(.{ .http = hp });
        defer hp.shutdown();

        try evaluate(allocator, io, &registry, noop_bus.eventBus(), in_path, out_path, signal);
        registry.flushStats();
        try hp.fetchAndNotify();
    } else {
        return error.NoProvider;
    }
}

/// evaluate evaluates the policies for the given data.
/// INVARIANT: Caller must flush the registry stats after calling.
fn evaluate(allocator: std.mem.Allocator, io: std.Io, registry: *PolicyRegistry, bus: *o11y.EventBus, in_path: []const u8, out_path: []const u8, signal: Signal) !void {
    const engine = PolicyEngine.init(bus, registry);

    const input_data = try std.Io.Dir.cwd().readFileAlloc(io, in_path, allocator, .limited(10 * 1024 * 1024));
    defer allocator.free(input_data);

    const output = switch (signal) {
        .log => try processLogs(allocator, io, engine, input_data),
        .metric => try processMetrics(allocator, io, engine, input_data),
        .trace => try processTraces(allocator, io, engine, input_data),
    };
    defer allocator.free(output);

    // Write output
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = out_path, .data = output });
}

// ─── Main ────────────────────────────────────────────────────────────

pub fn main(init: std.process.Init) !void {
    // Zig 0.16 "Juicy Main": the process-provided gpa (leak-checked in Debug)
    // for the run, and the process arena for argv (freed automatically on exit).
    const allocator = init.gpa;

    // OTel/JSON encodes bytes fields (traceId, spanId, …) as lowercase hex.
    // protobuf 5.0.0 reads this thread-local during decode; encode passes it via
    // pb_encode_opts. Single-threaded runner, so set once for the whole run.
    proto.protobuf.json.tl_bytes_as_hex = true;

    const args = try init.minimal.args.toSlice(init.arena.allocator());

    var policies_path: ?[]const u8 = null;
    var server_url: ?[]const u8 = null;
    var input_path: ?[]const u8 = null;
    var output_path: ?[]const u8 = null;
    var stats_path: ?[]const u8 = null;
    var signal: ?Signal = null;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--policies") and i + 1 < args.len) {
            i += 1;
            policies_path = args[i];
        } else if (std.mem.eql(u8, args[i], "--server") and i + 1 < args.len) {
            i += 1;
            server_url = args[i];
        } else if (std.mem.eql(u8, args[i], "--input") and i + 1 < args.len) {
            i += 1;
            input_path = args[i];
        } else if (std.mem.eql(u8, args[i], "--output") and i + 1 < args.len) {
            i += 1;
            output_path = args[i];
        } else if (std.mem.eql(u8, args[i], "--stats") and i + 1 < args.len) {
            i += 1;
            stats_path = args[i];
        } else if (std.mem.eql(u8, args[i], "--signal") and i + 1 < args.len) {
            i += 1;
            if (std.mem.eql(u8, args[i], "log")) {
                signal = .log;
            } else if (std.mem.eql(u8, args[i], "metric")) {
                signal = .metric;
            } else if (std.mem.eql(u8, args[i], "trace")) {
                signal = .trace;
            } else {
                std.debug.print("unknown signal: {s}\n", .{args[i]});
                std.process.exit(1);
            }
        }
    }

    const remote_mode = server_url != null;

    const usage = "usage: runner-zig (--policies <path> | --server <url>) --input <path> --output <path> --signal <log|metric|trace> [--stats <path>]\n";

    if (policies_path == null and server_url == null) {
        std.debug.print("{s}", .{usage});
        std.process.exit(1);
    }
    const inp = input_path orelse {
        std.debug.print("{s}", .{usage});
        std.process.exit(1);
    };
    const out = output_path orelse {
        std.debug.print("{s}", .{usage});
        std.process.exit(1);
    };
    if (!remote_mode and stats_path == null) {
        std.debug.print("{s}", .{usage});
        std.process.exit(1);
    }
    const sig = signal orelse {
        std.debug.print("{s}", .{usage});
        std.process.exit(1);
    };

    run(allocator, init.io, policies_path, server_url, inp, out, stats_path, sig) catch |err| {
        std.debug.print("error: {}\n", .{err});
        std.process.exit(1);
    };
}

// ─── Tests ───────────────────────────────────────────────────────────

test "no memory leaks" {
    proto.protobuf.json.tl_bytes_as_hex = true;

    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.writeFile(std.Options.debug_io, .{ .sub_path = "policies.json", .data =
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
    });

    try tmp_dir.dir.writeFile(std.Options.debug_io, .{ .sub_path = "input.json", .data =
        \\{
        \\  "resourceLogs": [
        \\    {
        \\      "resource": { "attributes": [] },
        \\      "scopeLogs": [
        \\        {
        \\          "scope": {},
        \\          "logRecords": [
        \\            {
        \\              "body": { "stringValue": "debug message" },
        \\              "severityText": "DEBUG",
        \\              "attributes": []
        \\            },
        \\            {
        \\              "body": { "stringValue": "info message" },
        \\              "severityText": "INFO",
        \\              "attributes": []
        \\            }
        \\          ]
        \\        }
        \\      ]
        \\    }
        \\  ]
        \\}
    });

    var pol_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    var in_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    var out_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    var stats_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const pol_path = pol_path_buf[0..try tmp_dir.dir.realPathFile(std.Options.debug_io, "policies.json", &pol_path_buf)];
    const in_path = in_path_buf[0..try tmp_dir.dir.realPathFile(std.Options.debug_io, "input.json", &in_path_buf)];

    try tmp_dir.dir.writeFile(std.Options.debug_io, .{ .sub_path = "output.json", .data = "" });
    const out_path = out_path_buf[0..try tmp_dir.dir.realPathFile(std.Options.debug_io, "output.json", &out_path_buf)];

    try tmp_dir.dir.writeFile(std.Options.debug_io, .{ .sub_path = "stats.json", .data = "" });
    const stats_path = stats_path_buf[0..try tmp_dir.dir.realPathFile(std.Options.debug_io, "stats.json", &stats_path_buf)];

    try run(allocator, std.Options.debug_io, pol_path, null, in_path, out_path, stats_path, .log);
}

test "log transform appends to non-empty scope attributes" {
    proto.protobuf.json.tl_bytes_as_hex = true;

    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.writeFile(std.Options.debug_io, .{ .sub_path = "policies.json", .data =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "add-scope-attr",
        \\      "name": "add-scope-attr",
        \\      "log": {
        \\        "match": [{ "log_field": "body", "regex": "^.*$" }],
        \\        "keep": "all",
        \\        "transform": {
        \\          "add": [{ "scope_attribute": "processed", "value": "true" }]
        \\        }
        \\      }
        \\    }
        \\  ]
        \\}
    });

    try tmp_dir.dir.writeFile(std.Options.debug_io, .{ .sub_path = "input.json", .data =
        \\{
        \\  "resourceLogs": [
        \\    {
        \\      "resource": { "attributes": [] },
        \\      "scopeLogs": [
        \\        {
        \\          "scope": {
        \\            "attributes": [
        \\              { "key": "existing", "value": { "stringValue": "present" } }
        \\            ]
        \\          },
        \\          "logRecords": [
        \\            {
        \\              "body": { "stringValue": "request processed" },
        \\              "severityText": "INFO",
        \\              "attributes": []
        \\            }
        \\          ]
        \\        }
        \\      ]
        \\    }
        \\  ]
        \\}
    });

    var pol_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    var in_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    var out_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    var stats_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const pol_path = pol_path_buf[0..try tmp_dir.dir.realPathFile(std.Options.debug_io, "policies.json", &pol_path_buf)];
    const in_path = in_path_buf[0..try tmp_dir.dir.realPathFile(std.Options.debug_io, "input.json", &in_path_buf)];

    try tmp_dir.dir.writeFile(std.Options.debug_io, .{ .sub_path = "output.json", .data = "" });
    const out_path = out_path_buf[0..try tmp_dir.dir.realPathFile(std.Options.debug_io, "output.json", &out_path_buf)];

    try tmp_dir.dir.writeFile(std.Options.debug_io, .{ .sub_path = "stats.json", .data = "" });
    const stats_path = stats_path_buf[0..try tmp_dir.dir.realPathFile(std.Options.debug_io, "stats.json", &stats_path_buf)];

    try run(allocator, std.Options.debug_io, pol_path, null, in_path, out_path, stats_path, .log);

    const output = try std.Io.Dir.cwd().readFileAlloc(std.Options.debug_io, out_path, allocator, .limited(1024 * 1024));
    defer allocator.free(output);
    try std.testing.expect(std.mem.containsAtLeast(u8, output, 1, "\"key\":\"existing\""));
    try std.testing.expect(std.mem.containsAtLeast(u8, output, 1, "\"key\":\"processed\""));
    try std.testing.expect(std.mem.containsAtLeast(u8, output, 1, "\"stringValue\":\"true\""));
}
