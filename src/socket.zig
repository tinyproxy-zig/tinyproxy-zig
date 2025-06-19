const std = @import("std");
const mem = std.mem;
const net = std.net;
const posix = std.posix;

const runtime = @import("runtime.zig");

/// get peer (remote) address from the socket
pub fn get_peer_addr(sock: posix.socket_t, addr: *net.Address) void {
    var addr_len: posix.socklen_t = @sizeOf(net.Address);
    posix.getpeername(sock, &addr.any, &addr_len) catch unreachable;
}

/// set the socket send and receive timeout
pub fn set_socket_timeout(sock: posix.socket_t) !void {
    const conf = runtime.runtime.config;

    var timespec: posix.timespec = .{
        .sec = conf.idle_timeout,
        .nsec = 0,
    };
    try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.SNDTIMEO, mem.asBytes(&timespec));
    try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, mem.asBytes(&timespec));
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

/// set the socket to blocking
pub fn set_socket_blocking(sock: posix.socket_t) !void {
    const flags = try posix.fcntl(sock, posix.F.GETFL, 0);

    // reinterpret the flags into posix.O, clear NONBLOCK, and cast back to usize
    var oflags: posix.O = @bitCast(@as(u32, @intCast(flags)));
    oflags.NONBLOCK = false;
    const new_flags: usize = @intCast(@as(u32, @bitCast(oflags)));

    _ = try posix.fcntl(sock, posix.F.SETFL, new_flags);
}
