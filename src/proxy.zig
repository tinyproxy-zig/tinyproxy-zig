const std = @import("std");
const zio = @import("zio");

fn upstream(rt: *zio.Runtime, ready: *zio.ResetEvent) !void {
    const addr = try zio.net.IpAddress.parseIp4("127.0.0.1", 19000);
    var server = try addr.listen(rt, .{});
    defer server.close(rt);
    ready.set();

    var stream = try server.accept(rt);
    defer stream.close(rt);

    var buf: [256]u8 = undefined;
    _ = try stream.read(rt, &buf);
    try stream.writeAll(rt, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");
}

test "forward proxy relays response" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const rt = try zio.Runtime.init(gpa.allocator(), .{ .num_executors = 1 });
    defer rt.deinit();

    var ready = zio.ResetEvent.init;
    var upstream_task = try rt.spawn(upstream, .{ rt, &ready }, .{});
    try ready.wait(rt);

    const response = try forward_once(rt, "127.0.0.1", 19000);
    defer rt.allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "200 OK") != null);
    try upstream_task.join(rt);
}

pub fn forward_once(rt: *zio.Runtime, host: []const u8, port: u16) ![]u8 {
    const addr = try zio.net.IpAddress.parseIp(host, port);
    var stream = try addr.connect(rt);
    defer stream.close(rt);

    try stream.writeAll(rt, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");

    var buf: [1024]u8 = undefined;
    const n = try stream.read(rt, &buf);
    return try rt.allocator.dupe(u8, buf[0..n]);
}
