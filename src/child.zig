const std = @import("std");
const zio = @import("zio");

const acl = @import("acl.zig");
const conf_parser = @import("conf.zig");
const daemon = @import("daemon.zig");
const signals = @import("signals.zig");
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

pub fn listen_socket(rt: *zio.Runtime, config: *Config) !void {
    const ip = try zio.net.IpAddress.parseIp(config.listen, config.port);
    server = try ip.listen(rt, .{ .kernel_backlog = 1024 });
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

pub fn main_loop(rt: *zio.Runtime, config: *Config, config_path: []const u8) !void {
    // Get server socket fd for polling
    const server_fd = server.socket.handle;

    while (true) {
        // Check for shutdown before accepting
        if (signals.shouldShutdown()) {
            log.info("Shutdown requested, exiting...", .{});
            break;
        }

        // Use poll to wait on either server socket or wakeup pipe
        // Use the system pollfd struct directly
        const c = std.c;

        var fds = [2]c.pollfd{
            .{ .fd = server_fd, .events = 0x001, .revents = 0 }, // POLLIN = 0x001
            .{ .fd = signals.wakeupFd(), .events = 0x001, .revents = 0 },
        };

        // Wait indefinitely until either fd is ready
        const poll_timeout: i32 = -1; // Infinite timeout
        while (true) {
            const nev = blk: {
                const rc = c.poll(&fds, 2, poll_timeout);
                if (rc < 0) {
                    const err = std.posix.errno(rc);
                    if (err == .INTR) {
                        // Check shutdown again and retry
                        if (signals.shouldShutdown()) {
                            log.info("Shutdown requested (EINTR), exiting...", .{});
                            return;
                        }
                        continue;
                    }
                    log.err("Poll failed: {}", .{err});
                    return error.PollFailed;
                }
                break :blk @as(usize, @intCast(rc));
            };

            if (nev == 0) {
                // Timeout (shouldn't happen with infinite timeout)
                continue;
            }

            break;
        }

        // Check which fd is ready
        if (fds[1].revents != 0) {
            // Wakeup pipe is readable - drain it and check flags
            signals.drainWakeupPipe();

            if (signals.shouldShutdown()) {
                log.info("Shutdown requested via signal, exiting...", .{});
                break;
            }

            // Handle reload/rotate flags
            if (signals.shouldRotateLog()) {
                log.info("Received SIGUSR1, rotating logs...", .{});
                if (config.log_file) |path| {
                    logger.reopen(path) catch |err| {
                        log.err("Failed to reopen log: {}", .{err});
                    };
                } else {
                    log.info("Log rotation ignored (logging to stderr)", .{});
                }
            }
            if (signals.shouldReload()) {
                log.info("Received SIGHUP, reloading config...", .{});
                conf_parser.reloadConfig(config, config_path) catch |err| {
                    log.err("Config reload failed: {}", .{err});
                };
            }

            // If not shutdown, loop back to poll again
            continue;
        }

        if (fds[0].revents != 0) {
            // Server socket is readable - accept connection
            const stream = server.accept(rt) catch |err| {
                if (err == error.Canceled) {
                    log.info("Task cancelled, shutting down...", .{});
                    return error.Canceled;
                }
                log.err("Accept failed: {}", .{err});
                continue;
            };

            // Check shutdown one more time
            if (signals.shouldShutdown()) {
                log.info("Shutdown requested, closing connection and exiting...", .{});
                stream.close(rt);
                break;
            }

            stats.global.recordOpen();

            // Check MaxClients limit
            const current_connections = active_connections.load(.acquire);
            if (current_connections >= config.max_clients) {
                log.info("MaxClients ({d}) reached, rejecting connection", .{config.max_clients});
                stats.global.recordRefused();
                stream.writeAll(rt, ERROR_503_BUSY, .none) catch {};
                stream.close(rt);
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
                    stream.writeAll(rt, ERROR_403_DENIED, .none) catch {};
                    stream.close(rt);
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
            _ = active_connections.fetchAdd(1, .release);

            var handle = try rt.spawn(handleConnectionWithCounter, .{ rt, stream, config });
            handle.detach(rt);
        }
    }

    log.info("Main loop exited", .{});
}

/// Wrapper that handles connection and decrements counter on completion
fn handleConnectionWithCounter(rt: *zio.Runtime, stream: zio.net.Stream, config: *const Config) void {
    defer {
        _ = active_connections.fetchSub(1, .release);
        stats.global.recordClose();
    }
    request.handle_connection(rt, stream, config) catch |err| {
        log.debug("Connection handler error: {}", .{err});
    };
}

pub fn accept_once(rt: *zio.Runtime) !void {
    const stream = try server.accept(rt);
    stream.close(rt);
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

    try ready.wait(rt);

    const addr = try zio.net.IpAddress.parseIp4("127.0.0.1", 18080);
    var stream = try addr.connect(rt, .{});
    stream.close(rt);

    try server_task.join(rt);
}
