const std = @import("std");

pub fn get_peer_addr(sock: std.posix.socket_t, addr: *std.net.Address) void {
    var addr_len: std.posix.socklen_t = @sizeOf(std.net.Address);
    std.posix.getpeername(sock, &addr.any, &addr_len) catch unreachable;
}
