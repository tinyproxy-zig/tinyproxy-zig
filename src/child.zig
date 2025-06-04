const std = @import("std");

const log = std.log.scoped(.@"tinyproxy/child");

var server: std.net.Server = undefined;

pub fn listen_sockets(addr: []const u8, port: u16) !void {
    const address = try std.net.Address.parseIp(addr, port);
    server = try address.listen(.{ .kernel_backlog = 1024 });
}

fn child_thread(conn: std.net.Server.Connection) !void {
    defer conn.stream.close();

    const tid = std.Thread.getCurrentId();

    var buf: [1024]u8 = undefined;
    const len = try conn.stream.read(&buf);
    log.info("tid = {any}, client data: len = {}", .{ tid, len });
}

pub fn main_loop() !void {
    while (true) {
        const conn = try server.accept();
        log.info("client connected: {any}", .{conn.address});

        const t = try std.Thread.spawn(.{}, child_thread, .{conn});
        t.detach();
    }
}
