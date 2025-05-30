const std = @import("std");

const log = std.log.scoped(.@"tinyproxy/child");

var server: std.net.Server = undefined;

pub fn listen_sockets(addr: []const u8, port: u16) !void {
    const address = try std.net.Address.parseIp(addr, port);
    server = try address.listen(.{ .kernel_backlog = 1024 });
}

pub fn main_loop() !void {
    while (true) {
        const conn = try server.accept();
        log.info("client connect: {any}", .{conn.address});
        conn.stream.close();
    }
}
