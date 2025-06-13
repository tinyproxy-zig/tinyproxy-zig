const std = @import("std");
const mem = std.mem;
const net = std.net;
const posix = std.posix;

pub fn get_peer_addr(sock: posix.socket_t, addr: *net.Address) void {
    var addr_len: posix.socklen_t = @sizeOf(net.Address);
    posix.getpeername(sock, &addr.any, &addr_len) catch unreachable;
}

pub fn set_socket_timeout(sock: posix.socket_t, timeout_sec: u32) !void {
    var timespec: posix.timespec = .{
        .sec = timeout_sec,
        .nsec = 0,
    };
    try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.SNDTIMEO, mem.asBytes(&timespec));
    try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, mem.asBytes(&timespec));
}
