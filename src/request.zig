const std = @import("std");
const zio = @import("zio");

const buffer = @import("buffer.zig");
const http = @import("http.zig");
const relay = @import("relay.zig");

const HTTP_PORT: u16 = 80;
const HTTPS_PORT: u16 = 443;

pub const Request = struct {
    method: []u8,
    protocol: []u8,
    host: []u8,
    port: u16,
    path: []u8,
};

pub fn handle_connection(rt: *zio.Runtime, client: zio.net.Stream) !void {
    var stream = client;
    defer stream.close(rt);

    var reader = buffer.LineReader.init(rt.allocator, 8192);
    defer reader.deinit();

    const req_line = try reader.readLine(rt, &stream);
    defer rt.allocator.free(req_line);

    var message = try http.read_headers(rt.allocator, &reader, rt, &stream);
    defer message.deinit();

    const req = try process_request_line(rt.allocator, req_line, &message.headers);
    defer free_request(rt.allocator, req);

    const addr = zio.net.IpAddress.parseIp(req.host, req.port) catch blk: {
        const list = try std.net.getAddressList(rt.allocator, req.host, req.port);
        defer list.deinit();
        if (list.addrs.len == 0) return error.UnknownHostName;
        break :blk zio.net.IpAddress.fromStd(list.addrs[0]);
    };
    var upstream = try addr.connect(rt);
    defer upstream.close(rt);

    if (std.ascii.eqlIgnoreCase(req.method, "CONNECT")) {
        try stream.writeAll(rt, "HTTP/1.1 200 Connection Established\r\n\r\n");
        _ = try reader.flush_to(rt, &upstream);
        try relay.copy_bidi(rt, stream, upstream);
        return;
    }

    const request_line = try std.fmt.allocPrint(rt.allocator, "{s} {s} {s}\r\n", .{
        req.method,
        req.path,
        req.protocol,
    });
    defer rt.allocator.free(request_line);

    try upstream.writeAll(rt, request_line);
    for (message.header_list.items) |header| {
        if (std.mem.eql(u8, header.name, "proxy-connection")) continue;
        try upstream.writeAll(rt, header.name);
        try upstream.writeAll(rt, ": ");
        try upstream.writeAll(rt, header.value);
        try upstream.writeAll(rt, "\r\n");
    }
    try upstream.writeAll(rt, "\r\n");

    var body_reader = message.body_reader();
    try body_reader.copy_raw_to(&reader, rt, &stream, &upstream);
    try relay.copy_one(rt, upstream, stream);
}

fn strip_username_password(host: []u8) usize {
    const at_pos = std.mem.indexOf(u8, host, "@") orelse return host.len;
    const src_start = at_pos + 1;
    const bytes_to_copy = host.len - src_start;
    std.mem.copyForwards(u8, host[0..bytes_to_copy], host[src_start..]);
    return bytes_to_copy;
}

fn strip_return_port(host: []u8) struct { port: u16, new_len: usize } {
    const colon_pos = std.mem.lastIndexOf(u8, host, ":") orelse return .{ .port = 0, .new_len = host.len };
    const after_colon = host[colon_pos + 1 ..];
    if (std.mem.indexOf(u8, after_colon, "]") != null) {
        return .{ .port = 0, .new_len = host.len };
    }

    const port_str = std.mem.trim(u8, after_colon, " \t\r\n\x00");
    const port = std.fmt.parseInt(u16, port_str, 10) catch return .{ .port = 0, .new_len = host.len };
    return .{ .port = port, .new_len = colon_pos };
}

fn extract_url(allocator: std.mem.Allocator, url: []const u8, default_port: u16, req: *Request) !void {
    const slash_pos = std.mem.indexOf(u8, url, "/");

    const host_part = if (slash_pos) |pos| url[0..pos] else url;
    const path_part = if (slash_pos) |pos| url[pos..] else "/";

    var host_buffer = try allocator.dupe(u8, host_part);
    errdefer allocator.free(host_buffer);

    const path_buffer = try allocator.dupe(u8, path_part);
    errdefer allocator.free(path_buffer);

    var host_len = strip_username_password(host_buffer);
    const port_result = strip_return_port(host_buffer[0..host_len]);
    host_len = port_result.new_len;
    const port = if (port_result.port != 0) port_result.port else default_port;

    if (host_len > 2 and host_buffer[0] == '[') {
        const bracket_end = std.mem.lastIndexOf(u8, host_buffer[0..host_len], "]");
        if (bracket_end) |end_pos| {
            const content_len = end_pos - 1;
            std.mem.copyForwards(u8, host_buffer[0..content_len], host_buffer[1..end_pos]);
            host_len = content_len;
        }
    }

    host_buffer = allocator.realloc(host_buffer, host_len) catch host_buffer;

    req.host = host_buffer;
    req.path = path_buffer;
    req.port = port;
}

pub fn process_request_line(
    allocator: std.mem.Allocator,
    line: []const u8,
    headers: *const std.StringHashMap([]const u8),
) !*Request {
    const req_line = try http.parse_request_line(line);
    const req = try allocator.create(Request);
    errdefer allocator.destroy(req);

    const protocol = switch (req_line.version) {
        .http09 => "HTTP/0.9",
        .http10 => "HTTP/1.0",
        .http11 => "HTTP/1.1",
    };

    if (req_line.version == .http09) {
        try extract_url(allocator, req_line.uri, HTTP_PORT, req);
        req.method = try allocator.dupe(u8, req_line.method);
        req.protocol = try allocator.dupe(u8, protocol);
        return req;
    }

    if (std.ascii.startsWithIgnoreCase(req_line.uri, "http://")) {
        try extract_url(allocator, req_line.uri[7..], HTTP_PORT, req);
    } else if (std.ascii.eqlIgnoreCase(req_line.method, "CONNECT")) {
        try extract_url(allocator, req_line.uri, HTTPS_PORT, req);
    } else {
        const host_header = headers.get("host") orelse return error.BadRequest;
        var host_parts = std.mem.splitScalar(u8, host_header, ':');
        const host_part = host_parts.next() orelse return error.BadRequest;
        const port_str = host_parts.next();
        const port = if (port_str) |p| std.fmt.parseInt(u16, p, 10) catch HTTP_PORT else HTTP_PORT;

        const host_port_str = if (port_str) |_|
            try std.fmt.allocPrint(allocator, "{s}:{d}", .{ host_part, port })
        else
            try allocator.dupe(u8, host_part);
        defer allocator.free(host_port_str);

        try extract_url(allocator, host_port_str, port, req);
        allocator.free(req.path);
        req.path = try allocator.dupe(u8, req_line.uri);
    }

    req.method = try allocator.dupe(u8, req_line.method);
    req.protocol = try allocator.dupe(u8, protocol);

    return req;
}

pub fn free_request(allocator: std.mem.Allocator, req: *Request) void {
    allocator.free(req.method);
    allocator.free(req.protocol);
    allocator.free(req.host);
    allocator.free(req.path);
    allocator.destroy(req);
}

test "process_request with absolute URL" {
    var headers = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer headers.deinit();

    const req_line = "GET http://example.com/hello HTTP/1.1";
    const req = try process_request_line(std.testing.allocator, req_line, &headers);
    defer free_request(std.testing.allocator, req);

    try std.testing.expectEqualStrings("GET", req.method);
    try std.testing.expectEqualStrings("example.com", req.host);
    try std.testing.expectEqualStrings("/hello", req.path);
    try std.testing.expectEqual(@as(u16, 80), req.port);
}
