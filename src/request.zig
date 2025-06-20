const std = @import("std");

const ziro = @import("ziro");
const aio = ziro.asyncio;

const Connection = @import("connection.zig").Connection;
const network = @import("network.zig");
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

/// This is the main drive for each connection.
pub fn handle_connection(conn: *Connection) !void {
    defer conn.client_conn.close() catch unreachable;

    socket.get_peer_addr(conn.client_conn.tcp.fd, &conn.client_addr);
    log.info("connect (file descriptor: {}): {any}", .{ conn.client_conn.tcp.fd, conn.client_addr });

    try socket.set_socket_timeout(conn.client_conn.tcp.fd);

    // TODO: connection_loops()

    // TODO: check_acl()

    read_request_line(conn) catch {
        return;
    };

    // TODO: get all headers from the client in a big hash

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

/// Read the first line from the client (the request line for HTTP connections).
/// The request line is allocated from the heap, ownership has been transfered to the caller.
fn read_request_line(conn: *Connection) !void {
    const fd = conn.client_conn.tcp.fd;
    const len = network.readline(fd, &conn.request_line) catch |e| {
        log.err("read_request_line error: {any}", .{e});
        return;
    };
    if (len == 0) {
        log.err("read_request_line: client (file descriptor: {}) closed socket before read", .{fd});
        return;
    }

    // TODO: handle when the line only contains '\n'

    log.info("request (file descriptor {}): {s}", .{ fd, conn.request_line });
}
