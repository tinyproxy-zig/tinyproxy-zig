const std = @import("std");
const zio = @import("zio");
const buffer = @import("buffer.zig");

/// Maximum number of headers allowed per request (DoS protection)
pub const MAX_HEADERS: usize = 100;

pub const HttpError = error{
    BadRequest,
    InvalidHeader,
    InvalidContentLength,
    InvalidChunk,
    TooManyHeaders,
    InvalidMethod,
};

pub const HttpVersion = enum {
    http09,
    http10,
    http11,
};

pub const RequestLine = struct {
    method: []const u8,
    uri: []const u8,
    version: HttpVersion,
};

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const HttpMessage = struct {
    allocator: std.mem.Allocator,
    headers: std.StringHashMap([]const u8),
    header_list: std.ArrayList(Header),
    content_length: ?usize = null,
    is_chunked: bool = false,

    pub fn init(allocator: std.mem.Allocator) HttpMessage {
        return .{
            .allocator = allocator,
            .headers = std.StringHashMap([]const u8).init(allocator),
            .header_list = std.ArrayList(Header).empty,
        };
    }

    pub fn body_reader(self: *const HttpMessage) BodyReader {
        if (self.is_chunked) {
            return .{ .mode = .chunked, .remaining = 0 };
        }
        if (self.content_length) |len| {
            if (len == 0) return .{ .mode = .none, .remaining = 0 };
            return .{ .mode = .length, .remaining = len };
        }
        return .{ .mode = .none, .remaining = 0 };
    }

    pub fn deinit(self: *HttpMessage) void {
        for (self.header_list.items) |header| {
            self.allocator.free(header.name);
            self.allocator.free(header.value);
        }
        self.headers.deinit();
        self.header_list.deinit(self.allocator);
    }
};

pub const BodyMode = enum {
    none,
    length,
    chunked,
};

pub const BodyReader = struct {
    mode: BodyMode,
    remaining: usize,

    pub fn copy_raw_to(
        self: *BodyReader,
        reader: *buffer.LineReader,
        rt: *zio.Runtime,
        stream: *zio.net.Stream,
        writer: anytype,
    ) !void {
        switch (self.mode) {
            .none => return,
            .length => {
                var remaining = self.remaining;
                var buf: [buffer.IO_BUFFER_SIZE]u8 = undefined;
                while (remaining > 0) {
                    const to_read = @min(remaining, buf.len);
                    const n = try reader.read(rt, stream, buf[0..to_read]);
                    if (n == 0) return error.EndOfStream;
                    try writer.writeAll(buf[0..n], .none);
                    remaining -= n;
                }
                self.remaining = 0;
            },
            .chunked => {
                var buf: [buffer.IO_BUFFER_SIZE]u8 = undefined;
                while (true) {
                    const size_line = try reader.readLine(rt, stream);
                    defer reader.allocator.free(size_line);
                    try writer.writeAll(size_line, .none);

                    const size_trim = std.mem.trimRight(u8, size_line, "\r\n");
                    const semi = std.mem.indexOfScalar(u8, size_trim, ';') orelse size_trim.len;
                    const size_str = std.mem.trim(u8, size_trim[0..semi], " \t");
                    if (size_str.len == 0) return error.InvalidChunk;
                    const chunk_size = std.fmt.parseInt(usize, size_str, 16) catch return error.InvalidChunk;

                    if (chunk_size == 0) {
                        while (true) {
                            const trailer = try reader.readLine(rt, stream);
                            defer reader.allocator.free(trailer);
                            try writer.writeAll(trailer, .none);
                            const trailer_trim = std.mem.trimRight(u8, trailer, "\r\n");
                            if (trailer_trim.len == 0) break;
                        }
                        break;
                    }

                    var remaining = chunk_size;
                    while (remaining > 0) {
                        const to_read = @min(remaining, buf.len);
                        try reader.read_exact(rt, stream, buf[0..to_read]);
                        try writer.writeAll(buf[0..to_read], .none);
                        remaining -= to_read;
                    }

                    var crlf: [2]u8 = undefined;
                    try reader.read_exact(rt, stream, &crlf);
                    if (!std.mem.eql(u8, &crlf, "\r\n")) return error.InvalidChunk;
                    try writer.writeAll(&crlf, .none);
                }
            },
        }
    }
};

pub fn parse_request_line(line: []const u8) HttpError!RequestLine {
    const trimmed = std.mem.trimRight(u8, line, "\r\n");
    var parts = std.mem.splitScalar(u8, trimmed, ' ');
    const method = parts.next() orelse return error.BadRequest;

    // Validate method length (RFC 2616: 1-20 chars, RFC 7231: token up to 255)
    if (method.len == 0 or method.len > 255) return error.InvalidMethod;

    const uri = parts.next() orelse return error.BadRequest;
    const version_opt = parts.next();
    if (version_opt == null) {
        if (!std.ascii.eqlIgnoreCase(method, "GET")) return error.BadRequest;
        return .{ .method = method, .uri = uri, .version = .http09 };
    }

    const version = version_opt.?;
    if (!std.ascii.startsWithIgnoreCase(version, "HTTP/")) return error.BadRequest;
    if (std.ascii.eqlIgnoreCase(version, "HTTP/1.0")) {
        return .{ .method = method, .uri = uri, .version = .http10 };
    }
    if (std.ascii.eqlIgnoreCase(version, "HTTP/1.1")) {
        return .{ .method = method, .uri = uri, .version = .http11 };
    }
    return error.BadRequest;
}

pub fn read_headers(
    allocator: std.mem.Allocator,
    reader: *buffer.LineReader,
    rt: *zio.Runtime,
    stream: *zio.net.Stream,
) !HttpMessage {
    var message = HttpMessage.init(allocator);
    errdefer message.deinit();

    while (true) {
        const line = try reader.readLine(rt, stream);
        defer allocator.free(line);
        const trimmed = std.mem.trimRight(u8, line, "\r\n");
        if (trimmed.len == 0) break;

        const colon = std.mem.indexOfScalar(u8, trimmed, ':') orelse return error.InvalidHeader;
        const name_raw = std.mem.trim(u8, trimmed[0..colon], " \t");
        const value_raw = std.mem.trim(u8, trimmed[colon + 1 ..], " \t");
        if (name_raw.len == 0) return error.InvalidHeader;

        const name = try allocator.dupe(u8, name_raw);
        for (name) |*c| c.* = std.ascii.toLower(c.*);
        const value = try allocator.dupe(u8, value_raw);

        // Check header limit BEFORE appending to prevent bypass
        if (message.header_list.items.len >= MAX_HEADERS) {
            allocator.free(name);
            allocator.free(value);
            return error.TooManyHeaders;
        }

        try message.header_list.append(allocator, .{ .name = name, .value = value });
        try message.headers.put(name, value);

        if (std.mem.eql(u8, name, "content-length")) {
            message.content_length = std.fmt.parseInt(usize, value_raw, 10) catch return error.InvalidContentLength;
        } else if (std.mem.eql(u8, name, "transfer-encoding")) {
            var it = std.mem.splitScalar(u8, value_raw, ',');
            while (it.next()) |token| {
                const part = std.mem.trim(u8, token, " \t");
                if (std.ascii.eqlIgnoreCase(part, "chunked")) {
                    message.is_chunked = true;
                    break;
                }
            }
        }
    }

    return message;
}

test "parse request line http11" {
    const line = "GET /path HTTP/1.1\r\n";
    const req = try parse_request_line(line);
    try std.testing.expectEqualStrings("GET", req.method);
    try std.testing.expectEqualStrings("/path", req.uri);
    try std.testing.expect(req.version == .http11);
}

const TestWriter = struct {
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,

    pub fn writeAll(self: *TestWriter, data: []const u8, _: anytype) !void {
        try self.list.appendSlice(self.allocator, data);
    }
};

fn content_length_server(rt: *zio.Runtime, server: *zio.net.Server) !void {
    var stream = try server.accept();
    defer stream.close();

    var reader = buffer.LineReader.init(rt.allocator, buffer.MAX_LINE_LENGTH);
    defer reader.deinit();

    const line = try reader.readLine(rt, &stream);
    defer rt.allocator.free(line);
    _ = try parse_request_line(line);

    var message = try read_headers(rt.allocator, &reader, rt, &stream);
    defer message.deinit();

    try std.testing.expectEqual(@as(?usize, 5), message.content_length);

    var body = std.ArrayList(u8).empty;
    defer body.deinit(rt.allocator);
    var writer = TestWriter{ .list = &body, .allocator = rt.allocator };
    var body_reader = message.body_reader();
    try body_reader.copy_raw_to(&reader, rt, &stream, &writer);

    try std.testing.expectEqualStrings("hello", body.items);
}

test "read content-length body" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const rt = try zio.Runtime.init(gpa.allocator(), .{ .executors = .exact(1) });
    defer rt.deinit();

    const addr = try zio.net.IpAddress.parseIp4("127.0.0.1", 18082);
    var server = try addr.listen(.{});
    defer server.close();

    var server_task = try rt.spawn(content_length_server, .{ rt, &server });

    var client = try addr.connect(.{});
    defer client.close();

    try client.writeAll(
        "POST /submit HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "Content-Length: 5\r\n" ++
            "\r\n" ++
            "hello",
        .none,
    );

    try server_task.join();
}

fn chunked_server(rt: *zio.Runtime, server: *zio.net.Server) !void {
    var stream = try server.accept();
    defer stream.close();

    var reader = buffer.LineReader.init(rt.allocator, buffer.MAX_LINE_LENGTH);
    defer reader.deinit();

    const line = try reader.readLine(rt, &stream);
    defer rt.allocator.free(line);
    _ = try parse_request_line(line);

    var message = try read_headers(rt.allocator, &reader, rt, &stream);
    defer message.deinit();

    try std.testing.expect(message.is_chunked);

    var body = std.ArrayList(u8).empty;
    defer body.deinit(rt.allocator);
    var writer = TestWriter{ .list = &body, .allocator = rt.allocator };
    var body_reader = message.body_reader();
    try body_reader.copy_raw_to(&reader, rt, &stream, &writer);

    try std.testing.expectEqualStrings(
        "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n",
        body.items,
    );
}

test "read chunked body" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const rt = try zio.Runtime.init(gpa.allocator(), .{ .executors = .exact(1) });
    defer rt.deinit();

    const addr = try zio.net.IpAddress.parseIp4("127.0.0.1", 18083);
    var server = try addr.listen(.{});
    defer server.close();

    var server_task = try rt.spawn(chunked_server, .{ rt, &server });

    var client = try addr.connect(.{});
    defer client.close();

    try client.writeAll(
        "POST /chunked HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "Transfer-Encoding: chunked\r\n" ++
            "\r\n" ++
            "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n",
        .none,
    );

    try server_task.join();
}
