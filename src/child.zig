const std = @import("std");
const zio = @import("zio");

const request = @import("request.zig");

const log = std.log.scoped(.@"tinyproxy/child");

var server: zio.net.Server = undefined;

pub fn listen_socket(rt: *zio.Runtime, addr: []const u8, port: u16) !void {
    const ip = try zio.net.IpAddress.parseIp(addr, port);
    server = try ip.listen(rt, .{ .kernel_backlog = 1024 });
    log.info("listening on {s}:{d}", .{ addr, port });
}

pub fn main_loop(rt: *zio.Runtime) !void {
    while (true) {
        const stream = try server.accept(rt);
        var handle = try rt.spawn(request.handle_connection, .{ rt, stream }, .{});
        handle.detach(rt);
    }
}

pub fn accept_once(rt: *zio.Runtime) !void {
    const stream = try server.accept(rt);
    stream.close(rt);
}

test "accepts one connection" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const rt = try zio.Runtime.init(gpa.allocator(), .{ .num_executors = 1 });
    defer rt.deinit();

    var ready = zio.ResetEvent.init;

    var server_task = try rt.spawn(struct {
        fn run(rt2: *zio.Runtime, ready2: *zio.ResetEvent) !void {
            try listen_socket(rt2, "127.0.0.1", 18080);
            ready2.set();
            try accept_once(rt2);
        }
    }.run, .{ rt, &ready }, .{});

    try ready.wait(rt);

    const addr = try zio.net.IpAddress.parseIp4("127.0.0.1", 18080);
    var stream = try addr.connect(rt);
    stream.close(rt);

    try server_task.join(rt);
}
