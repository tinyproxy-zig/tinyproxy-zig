const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // zio: coroutine and async io
    const zio_mod = b.dependency("zio", .{}).module("zio");

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe_mod.addImport("zio", zio_mod);

    const exe = b.addExecutable(.{
        .name = "tinyproxy",
        .root_module = exe_mod,
    });

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);

    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const child_test_mod = b.createModule(.{
        .root_source_file = b.path("src/child.zig"),
        .target = target,
        .optimize = optimize,
    });
    child_test_mod.addImport("zio", zio_mod);

    const child_tests = b.addTest(.{
        .name = "child-tests",
        .root_module = child_test_mod,
    });
    const child_run = b.addRunArtifact(child_tests);

    const proxy_test_mod = b.createModule(.{
        .root_source_file = b.path("src/proxy.zig"),
        .target = target,
        .optimize = optimize,
    });
    proxy_test_mod.addImport("zio", zio_mod);

    const proxy_tests = b.addTest(.{
        .name = "proxy-tests",
        .root_module = proxy_test_mod,
    });
    const proxy_run = b.addRunArtifact(proxy_tests);

    const relay_test_mod = b.createModule(.{
        .root_source_file = b.path("src/relay.zig"),
        .target = target,
        .optimize = optimize,
    });
    relay_test_mod.addImport("zio", zio_mod);

    const relay_tests = b.addTest(.{
        .name = "relay-tests",
        .root_module = relay_test_mod,
    });
    const relay_run = b.addRunArtifact(relay_tests);

    const config_test_mod = b.createModule(.{
        .root_source_file = b.path("src/config_parser.zig"),
        .target = target,
        .optimize = optimize,
    });

    const config_tests = b.addTest(.{
        .name = "config-tests",
        .root_module = config_test_mod,
    });
    const config_run = b.addRunArtifact(config_tests);

    const tinyproxy_test_mod = b.createModule(.{
        .root_source_file = b.path("src/config_tinyproxy.zig"),
        .target = target,
        .optimize = optimize,
    });

    const tinyproxy_tests = b.addTest(.{
        .name = "tinyproxy-config-tests",
        .root_module = tinyproxy_test_mod,
    });
    const tinyproxy_run = b.addRunArtifact(tinyproxy_tests);

    const http_test_mod = b.createModule(.{
        .root_source_file = b.path("src/http.zig"),
        .target = target,
        .optimize = optimize,
    });
    http_test_mod.addImport("zio", zio_mod);

    const http_tests = b.addTest(.{
        .name = "http-tests",
        .root_module = http_test_mod,
    });
    const http_run = b.addRunArtifact(http_tests);

    const test_step = b.step("test", "Run tests");

    test_step.dependOn(&child_run.step);
    test_step.dependOn(&proxy_run.step);
    test_step.dependOn(&relay_run.step);
    test_step.dependOn(&config_run.step);
    test_step.dependOn(&tinyproxy_run.step);
    test_step.dependOn(&http_run.step);
}
