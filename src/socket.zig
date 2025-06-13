const std = @import("std");
const mem = std.mem;
const net = std.net;
const posix = std.posix;

const runtime = @import("runtime.zig");

pub fn get_peer_addr(sock: posix.socket_t, addr: *net.Address) void {
    var addr_len: posix.socklen_t = @sizeOf(net.Address);
    posix.getpeername(sock, &addr.any, &addr_len) catch unreachable;
}

pub fn set_socket_timeout(sock: posix.socket_t) !void {
    const conf = runtime.runtime.config;

    var timespec: posix.timespec = .{
        .sec = conf.idle_timeout,
        .nsec = 0,
    };
    try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.SNDTIMEO, mem.asBytes(&timespec));
    try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, mem.asBytes(&timespec));
}
