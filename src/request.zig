const std = @import("std");

const ziro = @import("ziro");
const aio = ziro.asyncio;

const Connection = @import("connection.zig").Connection;
const runtime = @import("runtime.zig");
const socket = @import("socket.zig");

const log = std.log.scoped(.@"tinyproxy/request");

pub const Request = struct {
    method: []u8,
    protocol: []u8,
    host: []u8,
    port: u16,
    path: []u8,
};

const HTTP_RESPONSE = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 13\r\nContent-Type: text/plain\r\n\r\nHello World\r\n";

pub fn handle_connection(conn: *Connection) !void {
    defer conn.client_conn.close() catch unreachable;

    const config = runtime.runtime.config;

    socket.get_peer_addr(conn.client_conn.tcp.fd, &conn.client_addr);
    log.info("connect (file descriptor: {}): {any}", .{ conn.client_conn.tcp.fd, conn.client_addr });

    try socket.set_socket_timeout(conn.client_conn.tcp.fd, config.idle_timeout);

    var buf: [1024]u8 = undefined;

    while (true) {
        _ = conn.client_conn.read(.{ .slice = &buf }) catch |e| {
            log.err("client read error: {any}", .{e});
            return;
        };

        _ = conn.client_conn.write(.{ .slice = HTTP_RESPONSE }) catch |e| {
            log.err("client write error: {any}", .{e});
            return;
        };
    }
}
