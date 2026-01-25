const std = @import("std");
const mem = std.mem;
const net = std.net;
const posix = std.posix;
const zio = @import("zio");

const Config = @import("config.zig").Config;

pub fn opensock(host: []u8, port: u16, bind_to: []u8) void {
    _ = host;
    _ = port;
    _ = bind_to;
}

/// Connect to target with optional local address binding.
/// If bind_addr is provided, the socket is bound to that local address before connecting.
pub fn connectWithBind(
    rt: *zio.Runtime,
    target_addr: zio.net.IpAddress,
    bind_addr: ?[]const u8,
) !zio.net.Stream {
    // If no bind address, use standard connect
    if (bind_addr == null) {
        return target_addr.connect(rt, .{});
    }

    const bind_ip = bind_addr.?;

    // Determine address family from target
    const family: posix.sa_family_t = target_addr.any.family;

    // Create socket
    const sock = try posix.socket(family, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    errdefer posix.close(sock);

    // Parse and bind to local address
    const local_addr = zio.net.IpAddress.parseIp(bind_ip, 0) catch {
        // If parsing fails, just proceed without bind
        return connectSocket(rt, sock, target_addr);
    };

    // Bind to local address (port 0 = OS assigns ephemeral port)
    const bind_sockaddr: *const posix.sockaddr = @ptrCast(&local_addr.any);
    const bind_len: posix.socklen_t = if (family == posix.AF.INET6) @sizeOf(posix.sockaddr.in6) else @sizeOf(posix.sockaddr.in);
    posix.bind(sock, bind_sockaddr, bind_len) catch {
        // Bind failure is non-fatal, continue without bind
        return connectSocket(rt, sock, target_addr);
    };

    return connectSocket(rt, sock, target_addr);
}

fn connectSocket(_: *zio.Runtime, sock: posix.socket_t, target_addr: zio.net.IpAddress) !zio.net.Stream {
    const target_sockaddr: *const posix.sockaddr = @ptrCast(&target_addr.any);
    const family = target_addr.any.family;
    const addr_len: posix.socklen_t = if (family == posix.AF.INET6) @sizeOf(posix.sockaddr.in6) else @sizeOf(posix.sockaddr.in);

    // Set non-blocking for async connect
    try set_socket_nonblocking(sock);

    // Initiate async connect
    posix.connect(sock, target_sockaddr, addr_len) catch |err| switch (err) {
        error.WouldBlock => {
            // Connection in progress, wait for it using poll
            var pollfd = [_]posix.pollfd{.{
                .fd = sock,
                .events = posix.POLL.OUT,
                .revents = 0,
            }};

            // Poll with timeout (30 seconds)
            const result = posix.poll(&pollfd, 30000) catch |poll_err| {
                posix.close(sock);
                return poll_err;
            };

            if (result == 0) {
                posix.close(sock);
                return error.ConnectionTimedOut;
            }

            // Check for errors
            if (pollfd[0].revents & posix.POLL.ERR != 0) {
                posix.close(sock);
                return error.ConnectionRefused;
            }

            // Check socket error using getsockopt
            var so_error: c_int = 0;
            posix.getsockopt(sock, posix.SOL.SOCKET, posix.SO.ERROR, @as([*]u8, @ptrCast(&so_error))[0..@sizeOf(c_int)]) catch {
                posix.close(sock);
                return error.ConnectionRefused;
            };

            if (so_error != 0) {
                posix.close(sock);
                return error.ConnectionRefused;
            }
        },
        else => {
            posix.close(sock);
            return err;
        },
    };

    // Wrap in zio Stream
    return .{
        .socket = .{
            .handle = sock,
            .address = .{ .ip = target_addr },
        },
    };
}

/// get peer (remote) address from the socket
pub fn get_peer_addr(sock: posix.socket_t, addr: *net.Address) void {
    var addr_len: posix.socklen_t = @sizeOf(net.Address);
    posix.getpeername(sock, &addr.any, &addr_len) catch unreachable;
}

/// get local address from the socket and format to string (IP only, no port)
/// Returns the formatted string, or null on error
pub fn get_local_addr_str(sock: posix.socket_t, buf: []u8) ?[]const u8 {
    var storage: posix.sockaddr.storage = undefined;
    var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    posix.getsockname(sock, @ptrCast(&storage), &addr_len) catch return null;

    // Get address family and format IP only (without port)
    const family = storage.family;
    if (family == posix.AF.INET) {
        const addr4: *const posix.sockaddr.in = @ptrCast(&storage);
        const bytes: *const [4]u8 = @ptrCast(&addr4.addr);
        return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ bytes[0], bytes[1], bytes[2], bytes[3] }) catch return null;
    } else if (family == posix.AF.INET6) {
        const addr6: *const posix.sockaddr.in6 = @ptrCast(&storage);
        // Format IPv6 address - simplified version
        return std.fmt.bufPrint(buf, "{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
            addr6.addr[0],  addr6.addr[1],  addr6.addr[2],  addr6.addr[3],
            addr6.addr[4],  addr6.addr[5],  addr6.addr[6],  addr6.addr[7],
            addr6.addr[8],  addr6.addr[9],  addr6.addr[10], addr6.addr[11],
            addr6.addr[12], addr6.addr[13], addr6.addr[14], addr6.addr[15],
        }) catch return null;
    }
    return null;
}

/// set the socket send and receive timeout
pub fn set_socket_timeout(sock: posix.socket_t, idle_timeout: u32) !void {
    var timespec: posix.timespec = .{
        .sec = idle_timeout,
        .nsec = 0,
    };
    try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.SNDTIMEO, mem.asBytes(&timespec));
    try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, mem.asBytes(&timespec));
}

/// set the socket to blocking
pub fn set_socket_blocking(sock: posix.socket_t) !void {
    const flags = try posix.fcntl(sock, posix.F.GETFL, 0);

    // reinterpret the flags into posix.O, clear NONBLOCK, and cast back to usize
    var oflags: posix.O = @bitCast(@as(u32, @intCast(flags)));
    oflags.NONBLOCK = false;
    const new_flags: usize = @intCast(@as(u32, @bitCast(oflags)));

    _ = try posix.fcntl(sock, posix.F.SETFL, new_flags);
}

/// set the socket to non-blocking
pub fn set_socket_nonblocking(sock: posix.socket_t) !void {
    const flags = try posix.fcntl(sock, posix.F.GETFL, 0);

    // reinterpret the flags into posix.O, set NONBLOCK, and cast back to usize
    var oflags: posix.O = @bitCast(@as(u32, @intCast(flags)));
    oflags.NONBLOCK = true;
    const new_flags: usize = @intCast(@as(u32, @bitCast(oflags)));

    _ = try posix.fcntl(sock, posix.F.SETFL, new_flags);
}
