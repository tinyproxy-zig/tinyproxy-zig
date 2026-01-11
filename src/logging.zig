const std = @import("std");
const logging = @import("logging.zig");

pub const AccessEvent = struct {
    client: []const u8,
    method: []const u8,
    host: []const u8,
    status: u16,
    bytes: usize,
};

pub fn formatAccess(buf: []u8, ev: AccessEvent) ![]u8 {
    return std.fmt.bufPrint(buf, "{s} {s} {s} {} {}", .{
        ev.client,
        ev.method,
        ev.host,
        ev.status,
        ev.bytes,
    });
}

test "format access log" {
    var buf: [128]u8 = undefined;
    const out = try logging.formatAccess(&buf, .{
        .client = "127.0.0.1",
        .method = "GET",
        .host = "example.com",
        .status = 200,
        .bytes = 2,
    });
    try std.testing.expect(std.mem.indexOf(u8, out, "GET") != null);
}
