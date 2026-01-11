const std = @import("std");
const zio = @import("zio");

pub const LineReader = struct {
    allocator: std.mem.Allocator,
    max_len: usize,
    buf: [4096]u8 = undefined,
    start: usize = 0,
    end: usize = 0,

    pub fn init(allocator: std.mem.Allocator, max_len: usize) LineReader {
        return .{ .allocator = allocator, .max_len = max_len };
    }

    pub fn deinit(self: *LineReader) void {
        _ = self;
    }

    pub fn readLine(self: *LineReader, rt: *zio.Runtime, stream: *zio.net.Stream) ![]u8 {
        var out = std.ArrayList(u8).empty;
        errdefer out.deinit(self.allocator);

        while (true) {
            if (self.start == self.end) {
                self.start = 0;
                self.end = try stream.read(rt, &self.buf);
                if (self.end == 0) return error.EndOfStream;
            }

            const slice = self.buf[self.start..self.end];
            if (std.mem.indexOfScalar(u8, slice, '\n')) |pos| {
                const chunk = slice[0 .. pos + 1];
                try out.appendSlice(self.allocator, chunk);
                self.start += pos + 1;
                break;
            }

            try out.appendSlice(self.allocator, slice);
            self.start = self.end;

            if (out.items.len > self.max_len) return error.LineTooLong;
        }

        return try out.toOwnedSlice(self.allocator);
    }
};

fn server_task(rt: *zio.Runtime, ready: *zio.ResetEvent) !void {
    const addr = try zio.net.IpAddress.parseIp4("127.0.0.1", 18081);
    var server = try addr.listen(rt, .{});
    defer server.close(rt);
    ready.set();

    var stream = try server.accept(rt);
    defer stream.close(rt);

    var reader = LineReader.init(rt.allocator, 1024);
    defer reader.deinit();

    const line = try reader.readLine(rt, &stream);
    defer rt.allocator.free(line);

    try std.testing.expectEqualStrings("GET / HTTP/1.1\r\n", line);
}

test "line reader reads one line" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const rt = try zio.Runtime.init(gpa.allocator(), .{ .num_executors = 1 });
    defer rt.deinit();

    var ready = zio.ResetEvent.init;
    var server = try rt.spawn(server_task, .{ rt, &ready }, .{});
    try ready.wait(rt);

    const addr = try zio.net.IpAddress.parseIp4("127.0.0.1", 18081);
    var client = try addr.connect(rt);
    defer client.close(rt);

    try client.writeAll(rt, "GET / HTTP/1.1\r\n");
    try server.join(rt);
}
