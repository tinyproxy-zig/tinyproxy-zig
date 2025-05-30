const std = @import("std");

const log = std.log.scoped(.@"tinyproxy/child");

var server: std.net.Server = undefined;

pub fn listen_sockets(addr: []const u8, port: u16) !void {
    const address = try std.net.Address.parseIp(addr, port);
    server = try address.listen(.{ .kernel_backlog = 1024 });
}

pub fn main_loop() !void {
    var buf: [1024]u8 = undefined;
    while (true) {
        const conn = try server.accept();
        defer conn.stream.close();

        log.info("client connected: {any}", .{conn.address});

        const len = try conn.stream.read(&buf);

        log.info("client data: len = {}, content = {any}", .{ len, buf[0..len] });
    }
}
