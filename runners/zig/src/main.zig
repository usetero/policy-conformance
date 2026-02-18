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
};

fn writeStats(allocator: std.mem.Allocator, path: []const u8, registry: *PolicyRegistry) !void {
    const snapshot = registry.getSnapshot() orelse return;

    var stats: std.ArrayListUnmanaged(PolicyStat) = .empty;
    defer stats.deinit(allocator);

    for (snapshot.policies, 0..) |p, i| {
        const s = snapshot.getStats(@intCast(i)) orelse continue;
        const counters = s.readAndReset();
        if (counters.hits > 0) {
            try stats.append(allocator, .{ .policy_id = p.id, .hits = counters.hits });
        }
    }

    std.mem.sort(PolicyStat, stats.items, {}, struct {
        fn lessThan(_: void, a: PolicyStat, b: PolicyStat) bool {
            return std.mem.order(u8, a.policy_id, b.policy_id) == .lt;
        }
    }.lessThan);

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(allocator);
    const writer = buf.writer(allocator);

    try writer.writeAll("{\"policies\":[");
    for (stats.items, 0..) |st, i| {
        if (i > 0) try writer.writeByte(',');
        try writer.print("{{\"policy_id\":\"{s}\",\"hits\":{d}}}", .{ st.policy_id, st.hits });
    }
    try writer.writeAll("]}");

    const file = try std.fs.cwd().createFile(path, .{});
    defer file.close();
    try file.writeAll(buf.items);
}

// ─── Signal processing ──────────────────────────────────────────────

const json_opts: std.json.ParseOptions = .{
    .ignore_unknown_fields = true,
};

fn processLogs(allocator: std.mem.Allocator, engine: PolicyEngine, input_data: []const u8) ![]const u8 {
    var parsed = try LogsData.jsonDecode(input_data, json_opts, allocator);
    defer parsed.deinit();
    var data = parsed.value;

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
                };
                var policy_id_buf: [16][]const u8 = undefined;
                const result = engine.evaluate(.log, @ptrCast(&ctx), eval.logFieldAccessor, null, &policy_id_buf);
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

    return data.jsonEncode(.{}, allocator);
}

fn processMetrics(allocator: std.mem.Allocator, engine: PolicyEngine, input_data: []const u8) ![]const u8 {
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
                };
                var policy_id_buf: [16][]const u8 = undefined;
                const result = engine.evaluate(.metric, @ptrCast(&ctx), eval.metricFieldAccessor, null, &policy_id_buf);
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

    return data.jsonEncode(.{}, allocator);
}

fn processTraces(allocator: std.mem.Allocator, engine: PolicyEngine, input_data: []const u8) ![]const u8 {
    var parsed = try TracesData.jsonDecode(input_data, json_opts, allocator);
    defer parsed.deinit();
    var data = parsed.value;

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
                };
                var policy_id_buf: [16][]const u8 = undefined;
                const result = engine.evaluate(.trace, @ptrCast(&ctx), eval.traceFieldAccessor, null, &policy_id_buf);
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

    return data.jsonEncode(.{}, allocator);
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

fn run(allocator: std.mem.Allocator, pol_path: ?[]const u8, server_url: ?[]const u8, in_path: []const u8, out_path: []const u8, stats_path: ?[]const u8, signal: Signal) !void {
    var noop_bus: o11y.NoopEventBus = undefined;
    noop_bus.init();

    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const file_provider: ?*FileProvider = if (pol_path) |pp|
        try FileProvider.init(allocator, noop_bus.eventBus(), .{ .id = "conformance", .path = pp })
    else
        null;

    const http_provider: ?*HttpProvider = if (server_url) |url|
        try HttpProvider.init(allocator, noop_bus.eventBus(), .{ .id = "conformance", .url = url, .poll_interval_seconds = 60 })
    else
        null;

    if (file_provider) |fp| {
        defer fp.deinit();
        try registry.subscribe(.{ .file = fp });
        defer fp.shutdown();
        return runInner(allocator, &registry, noop_bus.eventBus(), null, in_path, out_path, stats_path, signal);
    } else if (http_provider) |hp| {
        defer hp.deinit();
        try registry.subscribe(.{ .http = hp });
        defer hp.shutdown();
        return runInner(allocator, &registry, noop_bus.eventBus(), hp, in_path, out_path, stats_path, signal);
    } else {
        return error.NoProvider;
    }
}

fn runInner(allocator: std.mem.Allocator, registry: *PolicyRegistry, bus: *o11y.EventBus, http_provider: ?*HttpProvider, in_path: []const u8, out_path: []const u8, stats_path: ?[]const u8, signal: Signal) !void {
    const engine = PolicyEngine.init(bus, registry);

    const input_data = try std.fs.cwd().readFileAlloc(allocator, in_path, 10 * 1024 * 1024);
    defer allocator.free(input_data);

    // Use standard protobuf JSON mapping (oneof fields emitted without wrapper)
    proto.protobuf.json.pb_options.emit_oneof_field_name = false;

    const output = switch (signal) {
        .log => try processLogs(allocator, engine, input_data),
        .metric => try processMetrics(allocator, engine, input_data),
        .trace => try processTraces(allocator, engine, input_data),
    };
    defer allocator.free(output);

    // Write output
    const out_file = try std.fs.cwd().createFile(out_path, .{});
    defer out_file.close();
    try out_file.writeAll(output);

    if (http_provider) |hp| {
        // Flush atomic stats to the provider, then trigger an immediate sync
        registry.flushStats();
        hp.fetchAndNotify() catch {};
    } else if (stats_path) |sp| {
        try writeStats(allocator, sp, registry);
    }
}

// ─── Main ────────────────────────────────────────────────────────────

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

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

    run(allocator, policies_path, server_url, inp, out, stats_path, sig) catch |err| {
        std.debug.print("error: {}\n", .{err});
        std.process.exit(1);
    };
}

// ─── Tests ───────────────────────────────────────────────────────────

test "no memory leaks" {
    const allocator = std.testing.allocator;

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
    );
    input_file.close();

    var pol_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    var in_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    var out_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    var stats_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const pol_path = try tmp_dir.dir.realpath("policies.json", &pol_path_buf);
    const in_path = try tmp_dir.dir.realpath("input.json", &in_path_buf);

    _ = try tmp_dir.dir.createFile("output.json", .{});
    const out_path = try tmp_dir.dir.realpath("output.json", &out_path_buf);

    _ = try tmp_dir.dir.createFile("stats.json", .{});
    const stats_path = try tmp_dir.dir.realpath("stats.json", &stats_path_buf);

    try run(allocator, pol_path, null, in_path, out_path, stats_path, .log);
}
