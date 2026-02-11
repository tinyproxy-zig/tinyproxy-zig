const std = @import("std");
const zio = @import("zio");

const acl = @import("acl.zig");
const conf_parser = @import("conf.zig");
const daemon = @import("daemon.zig");
const logger = @import("log.zig");
const Config = @import("config.zig").Config;
const request = @import("request.zig");
const socket = @import("socket.zig");
const stats = @import("stats.zig");

const log = std.log.scoped(.@"tinyproxy/child");

/// Error response for denied connections
const ERROR_403_DENIED = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 20\r\nConnection: close\r\n\r\nAccess denied by ACL";
const ERROR_503_BUSY = "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 20\r\nConnection: close\r\n\r\nProxy at max clients";

var server: zio.net.Server = undefined;

/// Active connection counter (atomic for thread safety)
var active_connections: std.atomic.Value(usize) = std.atomic.Value(usize).init(0);

pub fn listen_socket(_: *zio.Runtime, config: *Config) !void {
    const ip = try zio.net.IpAddress.parseIp(config.listen, config.port);
    server = try ip.listen(.{ .kernel_backlog = 1024, .reuse_address = true });
    log.info("listening on {s}:{d}", .{ config.listen, config.port });

    // Drop privileges after binding (allows binding to privileged ports as root)
    if (config.user != null or config.group != null) {
        daemon.dropPrivileges(config.user, config.group) catch |err| {
            log.err("Failed to drop privileges: {}", .{err});
            return err;
        };
        if (config.user) |u| {
            log.info("Dropped privileges to user: {s}", .{u});
        }
    }
}

/// Accept a connection via zio's event loop (used as a spawned task for select).
fn doAccept() !zio.net.Stream {
    return server.accept();
}

/// Watch for SIGHUP and log reload requests.
/// Installing a zio.Signal handler prevents the default terminate action.
fn reloadWatcher() void {
    var sig = zio.Signal.init(.hangup) catch return;
    defer sig.deinit();
    while (true) {
        sig.wait() catch return;
        log.info("Configuration reload requested (SIGHUP) — not yet implemented", .{});
    }
}

/// Watch for SIGUSR1 and log rotation requests.
fn logRotateWatcher() void {
    var sig = zio.Signal.init(.user1) catch return;
    defer sig.deinit();
    while (true) {
        sig.wait() catch return;
        log.info("Log rotation requested (SIGUSR1) — not yet implemented", .{});
    }
}

pub fn main_loop(rt: *zio.Runtime, config: *Config, config_path: []const u8) !void {
    _ = config_path; // Unused for now (needed for config reload support)
    log.info("main_loop: starting main loop", .{});

    // Auxiliary signal watchers (prevent default termination for SIGHUP/SIGUSR1)
    var reload_handle = try rt.spawn(reloadWatcher, .{});
    var logrotate_handle = try rt.spawn(logRotateWatcher, .{});
    defer {
        reload_handle.cancel();
        logrotate_handle.cancel();
    }

    // Shutdown signals — used in select to race against accept
    var sig_term = try zio.Signal.init(.terminate);
    defer sig_term.deinit();
    var sig_int = try zio.Signal.init(.interrupt);
    defer sig_int.deinit();

    while (true) {
        // Spawn accept as a task so we can race it against shutdown signals
        var accept_handle = try rt.spawn(doAccept, .{});
        defer accept_handle.cancel();

        const result = zio.select(.{
            .conn = &accept_handle,
            .term = &sig_term,
            .int = &sig_int,
        }) catch {
            log.info("Main loop interrupted, exiting...", .{});
            break;
        };

        switch (result) {
            .term, .int => {
                log.info("Shutdown requested, exiting...", .{});
                break;
            },
            .conn => |accept_result| {
                const stream = accept_result catch |err| {
                    log.err("accept failed: {}", .{err});
                    continue;
                };

                stats.global.recordOpen();

                // Check MaxClients limit
                const current_connections = active_connections.load(.acquire);
                if (current_connections >= config.max_clients) {
                    log.info("MaxClients ({d}) reached, rejecting connection", .{config.max_clients});
                    stats.global.recordRefused();
                    stream.writeAll(ERROR_503_BUSY, .none) catch {};
                    stream.close();
                    stats.global.recordClose();
                    continue;
                }

                // Check ACL if rules are configured
                if (config.acl.hasRules()) {
                    const client_addr = stream.socket.address.toStd();

                    const action = config.acl.check(client_addr);
                    if (action == .deny) {
                        log.info("Connection denied by ACL from {f}", .{stream.socket.address.ip});
                        stats.global.recordRefused();
                        stream.writeAll(ERROR_403_DENIED, .none) catch {};
                        stream.close();
                        stats.global.recordClose();
                        continue;
                    }
                }

                // Set socket timeout for idle connections
                if (config.idle_timeout > 0) {
                    socket.set_socket_timeout(stream.socket.handle, config.idle_timeout) catch |err| {
                        log.warn("Failed to set socket timeout: {}", .{err});
                    };
                }

                // Increment active connections
                _ = active_connections.fetchAdd(1, .monotonic);

                // Spawn connection handler
                _ = try rt.spawn(handleConnectionWithCounter, .{ rt, stream, config });

                // Yield to allow the handler task to start
                try rt.yield();
            },
        }
    }

    // Wait briefly for active connection handlers to drain (max 2s)
    {
        var attempts: u32 = 0;
        while (active_connections.load(.acquire) > 0 and attempts < 20) : (attempts += 1) {
            rt.sleep(.fromMilliseconds(100)) catch break;
        }
        const remaining = active_connections.load(.acquire);
        if (remaining > 0) {
            log.info("Shutting down with {d} active connections", .{remaining});
        }
    }

    log.info("Main loop exited", .{});
}

/// Wrapper that handles connection and decrements counter on completion
fn handleConnectionWithCounter(rt: *zio.Runtime, stream: zio.net.Stream, config: *const Config) void {
    defer {
        _ = active_connections.fetchSub(1, .monotonic);
        stats.global.recordClose();
    }
    request.handle_connection(rt, stream, config) catch |err| {
        log.err("Connection handler error: {}", .{err});
    };
}

pub fn accept_once(_: *zio.Runtime) !void {
    const stream = try server.accept();
    stream.close();
}

test "accepts one connection" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const rt = try zio.Runtime.init(gpa.allocator(), .{ .executors = .exact(1) });
    defer rt.deinit();

    var ready = zio.ResetEvent.init;

    var test_config = Config.init(gpa.allocator());
    test_config.listen = "127.0.0.1";
    test_config.port = 18080;
    defer test_config.deinit();

    var server_task = try rt.spawn(struct {
        fn run(rt2: *zio.Runtime, ready2: *zio.ResetEvent, config: *Config) !void {
            try listen_socket(rt2, config);
            ready2.set();
            try accept_once(rt2);
        }
    }.run, .{ rt, &ready, &test_config });

    try ready.wait();

    const addr = try zio.net.IpAddress.parseIp4("127.0.0.1", 18080);
    var stream = try addr.connect(.{});
    stream.close();

    try server_task.join();
}
