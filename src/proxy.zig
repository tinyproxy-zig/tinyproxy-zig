const std = @import("std");
const zio = @import("zio");

fn upstream(_: *zio.Runtime, ready: *zio.ResetEvent) !void {
    const addr = try zio.net.IpAddress.parseIp4("127.0.0.1", 19000);
    var server = try addr.listen(.{ .reuse_address = true });
    defer server.close();
    ready.set();

    var stream = try server.accept();
    defer stream.close();

    var buf: [256]u8 = undefined;
    _ = try stream.read(&buf, .none);
    try stream.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK", .none);
}

test "forward proxy relays response" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const rt = try zio.Runtime.init(gpa.allocator(), .{ .executors = .exact(1) });
    defer rt.deinit();

    var ready = zio.ResetEvent.init;
    var upstream_task = try rt.spawn(upstream, .{ rt, &ready });
    try ready.wait();

    const response = try forward_once(rt, "127.0.0.1", 19000);
    defer rt.allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "200 OK") != null);
    try upstream_task.join();
}

pub fn forward_once(rt: *zio.Runtime, host: []const u8, port: u16) ![]u8 {
    const addr = try zio.net.IpAddress.parseIp(host, port);
    var stream = try addr.connect(.{});
    defer stream.close();

    try stream.writeAll("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", .none);

    var buf: [1024]u8 = undefined;
    const n = try stream.read(&buf, .none);
    return try rt.allocator.dupe(u8, buf[0..n]);
}
