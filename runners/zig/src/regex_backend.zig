//! Optional Vectorscan backend owned by the conformance host.

const std = @import("std");
const policy = @import("policy_zig");

const c = @cImport({
    @cInclude("hs/hs.h");
});

pub const RegexSet = struct {
    database: ?*c.hs_database_t = null,
    scratch: ?*c.hs_scratch_t = null,

    pub fn init(allocator: std.mem.Allocator, image: *const policy.PolicyImage) !RegexSet {
        var count: usize = 0;
        for (0..image.header.matcher_count) |raw| {
            const matcher = try image.matcher(@intCast(raw));
            if (matcher.opcode == .regex) count += 1;
        }
        if (count == 0) return .{};

        const expressions = try allocator.alloc([*:0]const u8, count);
        defer allocator.free(expressions);
        const flags = try allocator.alloc(c_uint, count);
        defer allocator.free(flags);
        const ids = try allocator.alloc(c_uint, count);
        defer allocator.free(ids);
        const owned = try allocator.alloc([:0]u8, count);
        defer allocator.free(owned);
        var initialized: usize = 0;
        defer for (owned[0..initialized]) |expression| allocator.free(expression);

        var cursor: usize = 0;
        for (0..image.header.matcher_count) |raw| {
            const matcher_id: u32 = @intCast(raw);
            const matcher = try image.matcher(matcher_id);
            if (matcher.opcode != .regex) continue;
            owned[cursor] = try allocator.dupeZ(u8, try image.matcherConstant(matcher_id));
            initialized += 1;
            expressions[cursor] = owned[cursor].ptr;
            flags[cursor] = @as(c_uint, @intCast(c.HS_FLAG_SINGLEMATCH)) |
                (if (matcher.caseInsensitive()) @as(c_uint, @intCast(c.HS_FLAG_CASELESS)) else 0);
            ids[cursor] = matcher_id;
            cursor += 1;
        }

        var database: ?*c.hs_database_t = null;
        var compile_error: ?*c.hs_compile_error_t = null;
        const result = c.hs_compile_multi(
            expressions.ptr,
            flags.ptr,
            ids.ptr,
            @intCast(count),
            c.HS_MODE_BLOCK,
            null,
            &database,
            &compile_error,
        );
        if (compile_error) |details| _ = c.hs_free_compile_error(details);
        if (result != c.HS_SUCCESS) return error.RegexCompileFailed;
        errdefer _ = c.hs_free_database(database);

        var scratch: ?*c.hs_scratch_t = null;
        if (c.hs_alloc_scratch(database, &scratch) != c.HS_SUCCESS) return error.RegexScratchFailed;
        return .{ .database = database, .scratch = scratch };
    }

    pub fn deinit(self: *RegexSet) void {
        if (self.scratch) |scratch| _ = c.hs_free_scratch(scratch);
        if (self.database) |database| _ = c.hs_free_database(database);
        self.* = undefined;
    }

    pub fn backend(self: *RegexSet) ?policy.runtime.RegexBackend {
        if (self.database == null) return null;
        return .{ .context = self, .required_scratch_bytes = 0, .scanFn = scan };
    }

    fn scan(context: *anyopaque, matcher_id: u32, value: []const u8, _: []u8) bool {
        const self: *RegexSet = @ptrCast(@alignCast(context));
        var match: Match = .{ .wanted = matcher_id };
        const result = c.hs_scan(
            self.database,
            value.ptr,
            @intCast(value.len),
            0,
            self.scratch,
            onMatch,
            &match,
        );
        return match.found and (result == c.HS_SUCCESS or result == c.HS_SCAN_TERMINATED);
    }

    const Match = struct {
        wanted: u32,
        found: bool = false,
    };

    fn onMatch(id: c_uint, _: c_ulonglong, _: c_ulonglong, _: c_uint, context: ?*anyopaque) callconv(.c) c_int {
        const match: *Match = @ptrCast(@alignCast(context.?));
        if (id != match.wanted) return 0;
        match.found = true;
        return 1;
    }
};
