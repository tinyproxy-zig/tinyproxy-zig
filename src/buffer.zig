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

    pub fn read(self: *LineReader, rt: *zio.Runtime, stream: *zio.net.Stream, out: []u8) !usize {
        if (out.len == 0) return 0;
        if (self.start < self.end) {
            const available = self.end - self.start;
            const n = @min(available, out.len);
            std.mem.copyForwards(u8, out[0..n], self.buf[self.start .. self.start + n]);
            self.start += n;
            return n;
        }
        return stream.read(rt, out);
    }

    pub fn read_exact(self: *LineReader, rt: *zio.Runtime, stream: *zio.net.Stream, out: []u8) !void {
        var offset: usize = 0;
        while (offset < out.len) {
            const n = try self.read(rt, stream, out[offset..]);
            if (n == 0) return error.EndOfStream;
            offset += n;
        }
    }

    /// Flush any buffered data to the given writer stream.
    /// Returns the number of bytes flushed.
    pub fn flush_to(self: *LineReader, rt: *zio.Runtime, writer: *zio.net.Stream) !usize {
        if (self.start >= self.end) return 0;
        const buffered = self.buf[self.start..self.end];
        try writer.writeAll(rt, buffered);
        const flushed = buffered.len;
        self.start = self.end;
        return flushed;
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

fn server_read_buffered(rt: *zio.Runtime, ready: *zio.ResetEvent) !void {
    const addr = try zio.net.IpAddress.parseIp4("127.0.0.1", 18084);
    var server = try addr.listen(rt, .{});
    defer server.close(rt);
    ready.set();

    var stream = try server.accept(rt);
    defer stream.close(rt);

    var reader = LineReader.init(rt.allocator, 1024);
    defer reader.deinit();

    const line = try reader.readLine(rt, &stream);
    defer rt.allocator.free(line);

    var buf: [4]u8 = undefined;
    const n = try reader.read(rt, &stream, &buf);
    try std.testing.expectEqual(@as(usize, 4), n);
    try std.testing.expectEqualStrings("BODY", &buf);
}

test "line reader reads buffered bytes" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const rt = try zio.Runtime.init(gpa.allocator(), .{ .num_executors = 1 });
    defer rt.deinit();

    var ready = zio.ResetEvent.init;
    var server = try rt.spawn(server_read_buffered, .{ rt, &ready }, .{});
    try ready.wait(rt);

    const addr = try zio.net.IpAddress.parseIp4("127.0.0.1", 18084);
    var client = try addr.connect(rt);
    defer client.close(rt);

    try client.writeAll(rt, "GET / HTTP/1.1\r\nBODY");
    try server.join(rt);
}

fn server_read_exact(rt: *zio.Runtime, ready: *zio.ResetEvent) !void {
    const addr = try zio.net.IpAddress.parseIp4("127.0.0.1", 18085);
    var server = try addr.listen(rt, .{});
    defer server.close(rt);
    ready.set();

    var stream = try server.accept(rt);
    defer stream.close(rt);

    var reader = LineReader.init(rt.allocator, 1024);
    defer reader.deinit();

    const line = try reader.readLine(rt, &stream);
    defer rt.allocator.free(line);

    var buf: [5]u8 = undefined;
    try reader.read_exact(rt, &stream, &buf);
    try std.testing.expectEqualStrings("HELLO", &buf);
}

test "line reader read_exact fills buffer" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const rt = try zio.Runtime.init(gpa.allocator(), .{ .num_executors = 1 });
    defer rt.deinit();

    var ready = zio.ResetEvent.init;
    var server = try rt.spawn(server_read_exact, .{ rt, &ready }, .{});
    try ready.wait(rt);

    const addr = try zio.net.IpAddress.parseIp4("127.0.0.1", 18085);
    var client = try addr.connect(rt);
    defer client.close(rt);

    try client.writeAll(rt, "GET / HTTP/1.1\r\nHELLO");
    try server.join(rt);
}
