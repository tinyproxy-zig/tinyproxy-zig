const std = @import("std");
const zio = @import("zio");

const buffer = @import("buffer.zig");
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

    var header_lines = std.ArrayList([]u8).empty;
    defer {
        for (header_lines.items) |line| {
            rt.allocator.free(line);
        }
        header_lines.deinit(rt.allocator);
    }

    var headers = std.StringHashMap([]u8).init(rt.allocator);
    defer headers.deinit();

    const req_line = try reader.readLine(rt, &stream);
    defer rt.allocator.free(req_line);

    while (true) {
        const line = try reader.readLine(rt, &stream);
        const header_line = std.mem.trimRight(u8, line, "\r\n");
        if (header_line.len == 0) {
            rt.allocator.free(line);
            break;
        }

        var skip_forward = false;
        if (std.mem.indexOfScalar(u8, header_line, ':')) |pos| {
            const name = std.mem.trim(u8, header_line[0..pos], " \t");
            const value = std.mem.trim(u8, header_line[pos + 1 ..], " \t");

            if (std.ascii.eqlIgnoreCase(name, "Host")) {
                try headers.put("Host", @constCast(value));
            }

            if (std.ascii.eqlIgnoreCase(name, "Proxy-Connection")) {
                skip_forward = true;
            }
        }

        if (skip_forward) {
            rt.allocator.free(line);
            continue;
        }

        try header_lines.append(rt.allocator, line);
    }

    const req_line_trim = std.mem.trimRight(u8, req_line, "\r\n");
    const req = try process_request_line(rt.allocator, req_line_trim, &headers);
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
        try relay.copy_bidi(rt, stream, upstream);
        return;
    }

    const protocol = std.mem.trimRight(u8, req.protocol, "\r\n");
    const request_line = try std.fmt.allocPrint(rt.allocator, "{s} {s} {s}\r\n", .{
        req.method,
        req.path,
        protocol,
    });
    defer rt.allocator.free(request_line);

    try upstream.writeAll(rt, request_line);
    for (header_lines.items) |line| {
        try upstream.writeAll(rt, line);
    }
    try upstream.writeAll(rt, "\r\n");

    try relay.copy_bidi(rt, stream, upstream);
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
    headers: *std.StringHashMap([]u8),
) !*Request {
    var parts = std.mem.splitScalar(u8, line, ' ');

    const method_part = parts.next() orelse return error.BadRequest;
    const url_part = parts.next() orelse return error.BadRequest;
    const protocol_part = parts.next();

    const req = try allocator.create(Request);
    errdefer allocator.destroy(req);

    if (protocol_part == null) {
        if (!std.ascii.eqlIgnoreCase(method_part, "GET")) return error.BadRequest;
        try extract_url(allocator, url_part, HTTP_PORT, req);
        req.method = try allocator.dupe(u8, method_part);
        req.protocol = try allocator.dupe(u8, "HTTP/0.9");
        return req;
    }

    const protocol = protocol_part.?;
    if (!std.ascii.startsWithIgnoreCase(protocol, "HTTP/")) return error.BadRequest;

    if (std.ascii.startsWithIgnoreCase(url_part, "http://")) {
        try extract_url(allocator, url_part[7..], HTTP_PORT, req);
    } else if (std.ascii.eqlIgnoreCase(method_part, "CONNECT")) {
        try extract_url(allocator, url_part, HTTPS_PORT, req);
    } else {
        const host_header = headers.get("Host") orelse headers.get("host") orelse return error.BadRequest;
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
        req.path = try allocator.dupe(u8, url_part);
    }

    req.method = try allocator.dupe(u8, method_part);
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
    var headers = std.StringHashMap([]u8).init(std.testing.allocator);
    defer headers.deinit();

    const req_line = "GET http://example.com/hello HTTP/1.1";
    const req = try process_request_line(std.testing.allocator, req_line, &headers);
    defer free_request(std.testing.allocator, req);

    try std.testing.expectEqualStrings("GET", req.method);
    try std.testing.expectEqualStrings("example.com", req.host);
    try std.testing.expectEqualStrings("/hello", req.path);
    try std.testing.expectEqual(@as(u16, 80), req.port);
}
