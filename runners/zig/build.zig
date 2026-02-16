const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const policy_dep = b.dependency("policy_zig", .{
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "runner-zig",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "policy_zig", .module = policy_dep.module("policy_zig") },
                .{ .name = "o11y", .module = policy_dep.module("observability") },
            },
        }),
    });
    exe.root_module.link_libc = true;
    exe.root_module.linkSystemLibrary("hs", .{});

    b.installArtifact(exe);

    // Test step
    const test_step = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "policy_zig", .module = policy_dep.module("policy_zig") },
                .{ .name = "o11y", .module = policy_dep.module("observability") },
            },
        }),
    });
    test_step.root_module.link_libc = true;
    test_step.root_module.linkSystemLibrary("hs", .{});

    const run_tests = b.addRunArtifact(test_step);
    const test_cmd = b.step("test", "Run unit tests");
    test_cmd.dependOn(&run_tests.step);
}
