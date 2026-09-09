//! Host-side regex replacement for redact action opcodes.

const std = @import("std");
const policy = @import("policy_zig");
const Regex = @import("regex");

pub const Redactions = struct {
    allocator: std.mem.Allocator,
    rules: []?Rule,

    pub fn init(allocator: std.mem.Allocator, image: *const policy.PolicyImage) !Redactions {
        const rules = try allocator.alloc(?Rule, image.header.action_count);
        errdefer allocator.free(rules);
        @memset(rules, null);
        errdefer for (rules) |*rule| if (rule.*) |*value| value.deinit();
        for (0..image.header.action_count) |raw| {
            const action_index: u32 = @intCast(raw);
            const action = try image.action(action_index);
            if (action.opcode != .redact or action.flags & policy.source.adapter.action_flag_regex == 0) continue;
            const encoded = try image.actionValue(action_index);
            const separator = std.mem.indexOfScalar(u8, encoded, 0) orelse return error.InvalidRedactAction;
            const re = Regex.compile(allocator, encoded[0..separator], .{}) catch return error.InvalidRedactRegex;
            rules[action_index] = .{ .re = re, .replacement = encoded[separator + 1 ..] };
        }
        return .{ .allocator = allocator, .rules = rules };
    }

    pub fn deinit(self: *Redactions) void {
        for (self.rules) |*rule| if (rule.*) |*value| value.deinit();
        self.allocator.free(self.rules);
        self.* = undefined;
    }

    pub fn replace(
        self: *Redactions,
        allocator: std.mem.Allocator,
        action_index: u32,
        input: []const u8,
    ) !?[]const u8 {
        const rule = if (self.rules[action_index]) |*value| value else return null;
        var output: std.ArrayList(u8) = .empty;
        errdefer output.deinit(allocator);
        var cursor: usize = 0;
        var count: usize = 0;
        var matches = rule.re.findAllCaptures(input);
        while (matches.next()) |captures| {
            const span = captures.span();
            if (span.start < cursor) continue;
            try output.appendSlice(allocator, input[cursor..span.start]);
            try expand(allocator, &output, input, captures, rule.replacement);
            count += 1;
            if (span.end > cursor) {
                cursor = span.end;
            } else if (span.start < input.len) {
                try output.append(allocator, input[span.start]);
                cursor = span.start + 1;
            } else break;
        }
        if (count == 0) {
            output.deinit(allocator);
            return null;
        }
        try output.appendSlice(allocator, input[cursor..]);
        return try output.toOwnedSlice(allocator);
    }

    const Rule = struct {
        re: Regex,
        replacement: []const u8,

        fn deinit(self: *Rule) void {
            self.re.deinit();
            self.* = undefined;
        }
    };
};

fn expand(
    allocator: std.mem.Allocator,
    output: *std.ArrayList(u8),
    input: []const u8,
    captures: Regex.Captures,
    template: []const u8,
) !void {
    var cursor: usize = 0;
    while (cursor < template.len) {
        const dollar = std.mem.indexOfScalarPos(u8, template, cursor, '$') orelse {
            try output.appendSlice(allocator, template[cursor..]);
            return;
        };
        try output.appendSlice(allocator, template[cursor..dollar]);
        if (dollar + 1 == template.len) {
            try output.append(allocator, '$');
            return;
        }
        const next = template[dollar + 1];
        if (next == '$') {
            try output.append(allocator, '$');
            cursor = dollar + 2;
            continue;
        }
        if (next == '{') {
            const close = std.mem.indexOfScalarPos(u8, template, dollar + 2, '}') orelse {
                try output.appendSlice(allocator, template[dollar..]);
                return;
            };
            const name = template[dollar + 2 .. close];
            if (parseIndex(name)) |index| {
                if (captures.get(index)) |match| try output.appendSlice(allocator, match.bytes(input));
            } else if (captures.name(name)) |match| {
                try output.appendSlice(allocator, match.bytes(input));
            }
            cursor = close + 1;
            continue;
        }
        if (std.ascii.isDigit(next)) {
            var end = dollar + 2;
            if (end < template.len and std.ascii.isDigit(template[end])) end += 1;
            if (parseIndex(template[dollar + 1 .. end])) |index| {
                if (captures.get(index)) |match| try output.appendSlice(allocator, match.bytes(input));
            }
            cursor = end;
            continue;
        }
        try output.append(allocator, '$');
        cursor = dollar + 1;
    }
}

fn parseIndex(value: []const u8) ?u8 {
    if (value.len == 0) return null;
    for (value) |byte| if (!std.ascii.isDigit(byte)) return null;
    const index = std.fmt.parseInt(u8, value, 10) catch return null;
    return if (index <= 99) index else null;
}
