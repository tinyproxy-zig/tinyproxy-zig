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

    const main_test_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    main_test_mod.addImport("zio", zio_mod);

    const main_tests = b.addTest(.{
        .name = "main-tests",
        .root_module = main_test_mod,
    });
    const main_run = b.addRunArtifact(main_tests);

    const conf_test_mod = b.createModule(.{
        .root_source_file = b.path("src/conf.zig"),
        .target = target,
        .optimize = optimize,
    });

    const conf_tests = b.addTest(.{
        .name = "conf-tests",
        .root_module = conf_test_mod,
    });
    const conf_run = b.addRunArtifact(conf_tests);

    const config_test_mod = b.createModule(.{
        .root_source_file = b.path("src/config.zig"),
        .target = target,
        .optimize = optimize,
    });

    const config_tests = b.addTest(.{
        .name = "config-tests",
        .root_module = config_test_mod,
    });
    const config_run = b.addRunArtifact(config_tests);

    const log_test_mod = b.createModule(.{
        .root_source_file = b.path("src/log.zig"),
        .target = target,
        .optimize = optimize,
    });

    const log_tests = b.addTest(.{
        .name = "log-tests",
        .root_module = log_test_mod,
    });
    const log_run = b.addRunArtifact(log_tests);

    const acl_test_mod = b.createModule(.{
        .root_source_file = b.path("src/acl.zig"),
        .target = target,
        .optimize = optimize,
    });

    const acl_tests = b.addTest(.{
        .name = "acl-tests",
        .root_module = acl_test_mod,
    });
    const acl_run = b.addRunArtifact(acl_tests);

    const auth_test_mod = b.createModule(.{
        .root_source_file = b.path("src/auth.zig"),
        .target = target,
        .optimize = optimize,
    });

    const auth_tests = b.addTest(.{
        .name = "auth-tests",
        .root_module = auth_test_mod,
    });
    const auth_run = b.addRunArtifact(auth_tests);

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
    test_step.dependOn(&main_run.step);
    test_step.dependOn(&conf_run.step);
    test_step.dependOn(&config_run.step);
    test_step.dependOn(&log_run.step);
    test_step.dependOn(&acl_run.step);

    const signals_test_mod = b.createModule(.{
        .root_source_file = b.path("src/signals.zig"),
        .target = target,
        .optimize = optimize,
    });
    const signals_tests = b.addTest(.{
        .name = "signals-tests",
        .root_module = signals_test_mod,
    });
    const signals_run = b.addRunArtifact(signals_tests);
    test_step.dependOn(&signals_run.step);

    const upstream_test_mod = b.createModule(.{
        .root_source_file = b.path("src/upstream.zig"),
        .target = target,
        .optimize = optimize,
    });
    const upstream_tests = b.addTest(.{
        .name = "upstream-tests",
        .root_module = upstream_test_mod,
    });
    const upstream_run = b.addRunArtifact(upstream_tests);
    test_step.dependOn(&upstream_run.step);

    test_step.dependOn(&auth_run.step);
    test_step.dependOn(&http_run.step);
}
