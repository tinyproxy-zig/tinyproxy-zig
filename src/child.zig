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
const builtin = @import("builtin");

/// Error response for denied connections
const ERROR_403_DENIED = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 20\r\nConnection: close\r\n\r\nAccess denied by ACL";
const ERROR_503_BUSY = "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 20\r\nConnection: close\r\n\r\nProxy at max clients";

var server: zio.net.Server = undefined;

/// Active connection counter (atomic for thread safety)
var active_connections: std.atomic.Value(usize) = std.atomic.Value(usize).init(0);

pub fn listen_socket(_: *zio.Runtime, config: *Config) !void {
    const ip = try zio.net.IpAddress.parseIp(config.listen, config.port);
    server = try ip.listen(.{ .kernel_backlog = 1024 });
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

/// Accept with signal-aware blocking using the self-pipe trick
/// Returns null if shutdown was requested
fn acceptWithSignalCheck() !?zio.net.Stream {
    if (builtin.os.tag == .windows) {
        return server.accept() catch |err| {
            if (err == error.Canceled) return null;
            return err;
        };
    }

    const listen_fd = server.socket.handle;
    const wakeup_fd = signals.wakeupFd();

    // Ensure listening socket is non-blocking (idempotent)
    {
        const flags = std.posix.fcntl(listen_fd, std.posix.F.GETFL, 0) catch |err| {
            log.err("Failed to get socket flags: {}", .{err});
            return error.SocketFailed;
        };
        _ = std.posix.fcntl(listen_fd, std.posix.F.SETFL, flags | 0x0004) catch {}; // O_NONBLOCK
    }

    while (true) {
        if (signals.shouldShutdown()) return null;

        // Poll: listen socket OR wakeup pipe
        var fds = [_]std.posix.pollfd{
            .{ .fd = listen_fd, .events = std.posix.POLL.IN, .revents = 0 },
            .{ .fd = wakeup_fd, .events = std.posix.POLL.IN, .revents = 0 },
        };

        // 1 second timeout for periodic shutdown checks
        const rc = std.posix.poll(&fds, 1000) catch |err| {
            log.err("poll failed: {}", .{err});
            return error.PollFailed;
        };

        if (rc == 0) continue; // Timeout, check shutdown again

        // Signal received?
        if (fds[1].revents != 0) {
            signals.drainWakeupPipe();
            if (signals.shouldShutdown()) return null;
            continue; // SIGHUP/SIGUSR1, keep accepting
        }

        // Incoming connection?
        if (fds[0].revents != 0) {
            var peer_addr: std.posix.sockaddr = undefined;
            var peer_addr_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);

            const client_fd = std.posix.accept(listen_fd, &peer_addr, &peer_addr_len, 0) catch |err| {
                if (err == error.WouldBlock) continue; // Spurious wakeup
                return err;
            };

            // Get peer address for zio stream
            var addr_buf: [@sizeOf(std.net.Address)]u8 = undefined;
            var addr_len: std.posix.socklen_t = @sizeOf(std.net.Address);
            std.posix.getpeername(client_fd, @ptrCast(&addr_buf), &addr_len) catch {};

            const std_addr = @as(*align(1) const std.net.Address, @ptrCast(&addr_buf)).*;
            const zio_addr = zio.net.Address.fromStd(std_addr);

            return zio.net.Stream{
                .socket = .{
                    .handle = client_fd,
                    .address = zio_addr,
                },
            };
        }
    }
}

pub fn main_loop(rt: *zio.Runtime, config: *Config, config_path: []const u8) !void {
    _ = config_path; // Unused for now (needed for config reload support)
    log.info("main_loop: starting main loop", .{});

    while (true) {
        // Accept with signal-aware blocking
        const stream_opt = try acceptWithSignalCheck();
        const stream = stream_opt orelse {
            log.info("Shutdown requested, exiting...", .{});
            break;
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

        // Increment active connections (use monotonic modification for consistency)
        _ = active_connections.fetchAdd(1, .monotonic);

        // Spawn connection handler
        _ = try rt.spawn(handleConnectionWithCounter, .{ rt, stream, config });

        // Yield to allow the handler task to start
        try rt.yield();
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
