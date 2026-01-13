const std = @import("std");
const zio = @import("zio");

test "relay copies both directions" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const rt = try zio.Runtime.init(gpa.allocator(), .{ .num_executors = 1 });
    defer rt.deinit();

    const addr = try zio.net.IpAddress.parseIp4("127.0.0.1", 19001);
    var server = try addr.listen(rt, .{});
    defer server.close(rt);

    var ready = zio.ResetEvent.init;

    var relay_task = try rt.spawn(struct {
        fn run(rt2: *zio.Runtime, srv: *zio.net.Server, ready2: *zio.ResetEvent) !void {
            ready2.set();
            var a = try srv.accept(rt2);
            defer a.close(rt2);
            var b = try srv.accept(rt2);
            defer b.close(rt2);
            try copy_bidi(rt2, a, b);
        }
    }.run, .{ rt, &server, &ready }, .{});

    try ready.wait(rt);
    var client_a = try addr.connect(rt);
    var client_b = try addr.connect(rt);

    try client_a.writeAll(rt, "PING");
    var out_a: [4]u8 = undefined;
    _ = try client_b.read(rt, &out_a);
    try std.testing.expectEqualStrings("PING", &out_a);

    try client_b.writeAll(rt, "PONG");
    var out_b: [4]u8 = undefined;
    _ = try client_a.read(rt, &out_b);
    try std.testing.expectEqualStrings("PONG", &out_b);

    client_a.close(rt);
    client_b.close(rt);
    try relay_task.join(rt);
}

pub fn copy_one(rt: *zio.Runtime, src: zio.net.Stream, dst: zio.net.Stream) !void {
    var from = src;
    var to = dst;
    var buf: [8192]u8 = undefined;
    while (true) {
        const n = try from.read(rt, &buf);
        if (n == 0) break;
        try to.writeAll(rt, buf[0..n]);
    }
}

pub fn copy_bidi(rt: *zio.Runtime, a: zio.net.Stream, b: zio.net.Stream) !void {
    var a_to_b = try rt.spawn(copy_one, .{ rt, a, b }, .{});
    var b_to_a = try rt.spawn(copy_one, .{ rt, b, a }, .{});
    try a_to_b.join(rt);
    try b_to_a.join(rt);
}
