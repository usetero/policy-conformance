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

// ─── Tracing events ──────────────────────────────────────────────────
// Emitted through the o11y EventBus at debug level. Each Started/Completed
// pair is a timed span: the bus stamps `elapsed=<dur>` on completion so you
// can see which phase dominates. Span names derive from the type name
// (RunStarted -> "run", JsonDecodeStarted -> "json.decode").
//
// Tracing is OFF by default (NoopEventBus). Enable it for a profiling run:
//   POLICY_TRACE=1 ./zig-out/bin/runner-zig --policies ... --input ... --signal log
// Timing lines go to stdout; the runner writes its results to files, so they
// never collide. To rank the slowest methods across a run:
//   POLICY_TRACE=1 ./runner-zig ... | grep elapsed | sort -t= -k4 -h

const RunStarted = struct { signal: []const u8 };
const RunCompleted = struct { signal: []const u8 };

const PolicyLoadStarted = struct { provider: []const u8 };
const PolicyLoadCompleted = struct { provider: []const u8 };

const InputReadStarted = struct { path: []const u8 };
const InputReadCompleted = struct { bytes: usize };

const JsonDecodeStarted = struct { signal: []const u8 };
const JsonDecodeCompleted = struct { signal: []const u8, resources: usize };

const SignalEvaluateStarted = struct { signal: []const u8 };
const SignalEvaluateCompleted = struct { signal: []const u8, evaluated: usize, dropped: usize };

const JsonEncodeStarted = struct { signal: []const u8 };
const JsonEncodeCompleted = struct { signal: []const u8, bytes: usize };

const OutputWriteStarted = struct { path: []const u8 };
const OutputWriteCompleted = struct { bytes: usize };

const StatsWriteStarted = struct {};
const StatsWriteCompleted = struct { policies: usize };

// Teardown phases. These run in deferred cleanup after the work is done, so
// they fall outside the per-signal spans above but still inside the top-level
// `run` span — useful for explaining a large run total that the work phases
// don't account for (e.g. a provider's poll thread join).
const ProviderShutdownStarted = struct { provider: []const u8 };
const ProviderShutdownCompleted = struct { provider: []const u8 };

const ProviderDeinitStarted = struct { provider: []const u8 };
const ProviderDeinitCompleted = struct { provider: []const u8 };

const RegistryDeinitStarted = struct {};
const RegistryDeinitCompleted = struct {};

// ─── Stats output ────────────────────────────────────────────────────

const PolicyStat = struct {
    policy_id: []const u8,
    hits: i64,
    misses: i64,
};

fn writeStats(allocator: std.mem.Allocator, io: std.Io, bus: *o11y.EventBus, path: []const u8, registry: *PolicyRegistry) !void {
    const snapshot = registry.getSnapshot() orelse return;

    var stats: std.ArrayListUnmanaged(PolicyStat) = .empty;
    defer stats.deinit(allocator);

    var span = bus.started(.debug, StatsWriteStarted{});
    defer span.completed(StatsWriteCompleted{ .policies = stats.items.len });

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

fn processLogs(allocator: std.mem.Allocator, io: std.Io, bus: *o11y.EventBus, engine: PolicyEngine, input_data: []const u8) ![]const u8 {
    var decode_span = bus.started(.debug, JsonDecodeStarted{ .signal = "log" });
    var parsed = try LogsData.jsonDecode(input_data, json_opts, allocator);
    defer parsed.deinit();
    var data = parsed.value;
    const data_allocator = parsed.arena.allocator();
    decode_span.completed(JsonDecodeCompleted{ .signal = "log", .resources = data.resource_logs.items.len });

    // Scratch for transform temporaries. Writes into decoded OTLP data use the
    // JSON parse arena because it owns the decoded protobuf tree.
    var transform_arena = std.heap.ArenaAllocator.init(allocator);
    defer transform_arena.deinit();

    // Evaluate each log record, mark dropped ones
    var eval_span = bus.started(.debug, SignalEvaluateStarted{ .signal = "log" });
    var evaluated: usize = 0;
    var dropped: usize = 0;
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
                evaluated += 1;
                if (result.decision == .drop) {
                    _ = sl.log_records.orderedRemove(i);
                    dropped += 1;
                } else {
                    i += 1;
                }
            }
        }
    }
    eval_span.completed(SignalEvaluateCompleted{ .signal = "log", .evaluated = evaluated, .dropped = dropped });

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

    var encode_span = bus.started(.debug, JsonEncodeStarted{ .signal = "log" });
    const output = try data.jsonEncode(.{}, pb_encode_opts, allocator);
    encode_span.completed(JsonEncodeCompleted{ .signal = "log", .bytes = output.len });
    return output;
}

fn processMetrics(allocator: std.mem.Allocator, io: std.Io, bus: *o11y.EventBus, engine: PolicyEngine, input_data: []const u8) ![]const u8 {
    var decode_span = bus.started(.debug, JsonDecodeStarted{ .signal = "metric" });
    var parsed = try MetricsData.jsonDecode(input_data, json_opts, allocator);
    defer parsed.deinit();
    var data = parsed.value;
    decode_span.completed(JsonDecodeCompleted{ .signal = "metric", .resources = data.resource_metrics.items.len });

    var eval_span = bus.started(.debug, SignalEvaluateStarted{ .signal = "metric" });
    var evaluated: usize = 0;
    var dropped: usize = 0;
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
                evaluated += 1;
                if (result.decision == .drop) {
                    _ = sm.metrics.orderedRemove(i);
                    dropped += 1;
                } else {
                    i += 1;
                }
            }
        }
    }
    eval_span.completed(SignalEvaluateCompleted{ .signal = "metric", .evaluated = evaluated, .dropped = dropped });

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

    var encode_span = bus.started(.debug, JsonEncodeStarted{ .signal = "metric" });
    const output = try data.jsonEncode(.{}, pb_encode_opts, allocator);
    encode_span.completed(JsonEncodeCompleted{ .signal = "metric", .bytes = output.len });
    return output;
}

fn processTraces(allocator: std.mem.Allocator, io: std.Io, bus: *o11y.EventBus, engine: PolicyEngine, input_data: []const u8) ![]const u8 {
    var decode_span = bus.started(.debug, JsonDecodeStarted{ .signal = "trace" });
    var parsed = try TracesData.jsonDecode(input_data, json_opts, allocator);
    defer parsed.deinit();
    var data = parsed.value;
    const data_allocator = parsed.arena.allocator();
    decode_span.completed(JsonDecodeCompleted{ .signal = "trace", .resources = data.resource_spans.items.len });

    // Scratch for transform temporaries. Writes into decoded OTLP data use the
    // JSON parse arena because it owns the decoded protobuf tree.
    var transform_arena = std.heap.ArenaAllocator.init(allocator);
    defer transform_arena.deinit();

    var eval_span = bus.started(.debug, SignalEvaluateStarted{ .signal = "trace" });
    var evaluated: usize = 0;
    var dropped: usize = 0;
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
                evaluated += 1;
                if (result.decision == .drop) {
                    _ = ss.spans.orderedRemove(i);
                    dropped += 1;
                } else {
                    i += 1;
                }
            }
        }
    }
    eval_span.completed(SignalEvaluateCompleted{ .signal = "trace", .evaluated = evaluated, .dropped = dropped });

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

    var encode_span = bus.started(.debug, JsonEncodeStarted{ .signal = "trace" });
    const output = try data.jsonEncode(.{}, pb_encode_opts, allocator);
    encode_span.completed(JsonEncodeCompleted{ .signal = "trace", .bytes = output.len });
    return output;
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

fn run(allocator: std.mem.Allocator, io: std.Io, pol_path: ?[]const u8, server_url: ?[]const u8, in_path: []const u8, out_path: []const u8, stats_path: ?[]const u8, signal: Signal, trace_enabled: bool) !void {
    // Each o11y span instantiates a comptime span-name derivation (eventName).
    // run() opens enough spans that their cumulative comptime branches exceed
    // the default 1000-branch quota, so raise it for this function's analysis.
    @setEvalBranchQuota(10_000);

    // Tracing is opt-in (POLICY_TRACE, read from the process environment in
    // main) so default conformance runs stay silent and pay no event-bus
    // overhead. When enabled, route everything through a StdioEventBus at debug
    // level so the per-phase spans actually emit.
    var noop_bus: o11y.NoopEventBus = undefined;
    var stdio_bus: o11y.StdioEventBus = undefined;
    const bus: *o11y.EventBus = if (trace_enabled) blk: {
        stdio_bus.init(io);
        const b = stdio_bus.eventBus();
        b.setLevel(.debug);
        break :blk b;
    } else blk: {
        noop_bus.init(io);
        break :blk noop_bus.eventBus();
    };

    var run_span = bus.started(.debug, RunStarted{ .signal = @tagName(signal) });
    defer run_span.completed(RunCompleted{ .signal = @tagName(signal) });

    var registry = PolicyRegistry.init(allocator, bus);
    defer {
        var s = bus.started(.debug, RegistryDeinitStarted{});
        registry.deinit();
        s.completed(RegistryDeinitCompleted{});
    }

    const file_provider: ?*FileProvider = if (pol_path) |pp|
        try FileProvider.init(allocator, io, bus, .{ .id = "conformance", .path = pp })
    else
        null;

    const http_provider: ?*HttpProvider = if (server_url) |url|
        try HttpProvider.init(allocator, io, bus, .{ .id = "conformance", .url = url, .poll_interval_seconds = 60 })
    else
        null;
    if (file_provider) |fp| {
        defer {
            var s = bus.started(.debug, ProviderDeinitStarted{ .provider = "file" });
            fp.deinit();
            s.completed(ProviderDeinitCompleted{ .provider = "file" });
        }
        var load_span = bus.started(.debug, PolicyLoadStarted{ .provider = "file" });
        try registry.subscribe(.{ .file = fp });
        load_span.completed(PolicyLoadCompleted{ .provider = "file" });
        defer {
            var s = bus.started(.debug, ProviderShutdownStarted{ .provider = "file" });
            fp.shutdown();
            s.completed(ProviderShutdownCompleted{ .provider = "file" });
        }

        try evaluate(allocator, io, &registry, bus, in_path, out_path, signal);
        try writeStats(allocator, io, bus, stats_path.?, &registry);
    } else if (http_provider) |hp| {
        defer {
            var s = bus.started(.debug, ProviderDeinitStarted{ .provider = "http" });
            hp.deinit();
            s.completed(ProviderDeinitCompleted{ .provider = "http" });
        }
        var load_span = bus.started(.debug, PolicyLoadStarted{ .provider = "http" });
        try registry.subscribe(.{ .http = hp });
        load_span.completed(PolicyLoadCompleted{ .provider = "http" });
        defer {
            var s = bus.started(.debug, ProviderShutdownStarted{ .provider = "http" });
            hp.shutdown();
            s.completed(ProviderShutdownCompleted{ .provider = "http" });
        }

        try evaluate(allocator, io, &registry, bus, in_path, out_path, signal);
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

    var read_span = bus.started(.debug, InputReadStarted{ .path = in_path });
    const input_data = try std.Io.Dir.cwd().readFileAlloc(io, in_path, allocator, .limited(10 * 1024 * 1024));
    defer allocator.free(input_data);
    read_span.completed(InputReadCompleted{ .bytes = input_data.len });

    const output = switch (signal) {
        .log => try processLogs(allocator, io, bus, engine, input_data),
        .metric => try processMetrics(allocator, io, bus, engine, input_data),
        .trace => try processTraces(allocator, io, bus, engine, input_data),
    };
    defer allocator.free(output);

    // Write output
    var write_span = bus.started(.debug, OutputWriteStarted{ .path = out_path });
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = out_path, .data = output });
    write_span.completed(OutputWriteCompleted{ .bytes = output.len });
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

    // Enable o11y tracing when POLICY_TRACE is present in the environment.
    const trace_enabled = init.environ_map.get("POLICY_TRACE") != null;

    run(allocator, init.io, policies_path, server_url, inp, out, stats_path, sig, trace_enabled) catch |err| {
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

    try run(allocator, std.Options.debug_io, pol_path, null, in_path, out_path, stats_path, .log, false);
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

    try run(allocator, std.Options.debug_io, pol_path, null, in_path, out_path, stats_path, .log, false);

    const output = try std.Io.Dir.cwd().readFileAlloc(std.Options.debug_io, out_path, allocator, .limited(1024 * 1024));
    defer allocator.free(output);
    try std.testing.expect(std.mem.containsAtLeast(u8, output, 1, "\"key\":\"existing\""));
    try std.testing.expect(std.mem.containsAtLeast(u8, output, 1, "\"key\":\"processed\""));
    try std.testing.expect(std.mem.containsAtLeast(u8, output, 1, "\"stringValue\":\"true\""));
}
