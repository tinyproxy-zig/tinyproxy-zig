const std = @import("std");
const zio = @import("zio");

const anonymous = @import("anonymous.zig");
const buffer = @import("buffer.zig");
const Config = @import("config.zig").Config;
const connect_ports = @import("connect_ports.zig");
const headers = @import("headers.zig");
const html_error = @import("html_error.zig");
const http = @import("http.zig");
const relay = @import("relay.zig");
const reverse = @import("reverse.zig");
const socket = @import("socket.zig");
const socks = @import("socks.zig");
const stats = @import("stats.zig");
const transparent = @import("transparent.zig");
const upstream_mod = @import("upstream.zig");

const log = std.log.scoped(.@"tinyproxy/request");

const HTTP_PORT: u16 = 80;
const HTTPS_PORT: u16 = 443;

pub const Request = struct {
    method: []u8,
    protocol: []u8,
    host: []u8,
    port: u16,
    path: []u8,
    version: http.HttpVersion = .http11,
};

/// Fallback error responses (used when config-based error pages unavailable)
const ERROR_403_CONNECT = "HTTP/1.1 403 Forbidden\r\nContent-Length: 28\r\n\r\nCONNECT to port not allowed\n";
const ERROR_403_FILTERED = "HTTP/1.1 403 Forbidden\r\nContent-Length: 16\r\n\r\nFiltered by rule\n";
const ERROR_403_REVERSE_ONLY = "HTTP/1.1 403 Forbidden\r\nContent-Length: 38\r\n\r\nForward proxy disabled (ReverseOnly)\n";
const ERROR_502 = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 21\r\n\r\nProxy handshake failed\n";

/// Send an error response using configured ErrorFile or default template
fn sendErrorResponse(
    rt: *zio.Runtime,
    stream: *zio.net.Stream,
    config: *const Config,
    err: html_error.HttpError,
    detail: []const u8,
) !void {
    // Try to use custom error file first
    if (config.error_files.get(@intFromEnum(err))) |error_file| {
        if (loadErrorFile(rt.allocator, error_file)) |content| {
            defer rt.allocator.free(content);
            var header_buf: [256]u8 = undefined;
            const header = std.fmt.bufPrint(&header_buf, "HTTP/1.1 {s}\r\nContent-Type: text/html\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{
                err.statusLine(),
                content.len,
            }) catch unreachable;
            try stream.writeAll(header, .none);
            try stream.writeAll(content, .none);
            return;
        }
    }

    // Try default error file
    if (config.default_error_file) |default_file| {
        if (loadErrorFile(rt.allocator, default_file)) |content| {
            defer rt.allocator.free(content);
            var header_buf: [256]u8 = undefined;
            const header = std.fmt.bufPrint(&header_buf, "HTTP/1.1 {s}\r\nContent-Type: text/html\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{
                err.statusLine(),
                content.len,
            }) catch unreachable;
            try stream.writeAll(header, .none);
            try stream.writeAll(content, .none);
            return;
        }
    }

    // Fall back to default HTML template
    const body = html_error.renderErrorPage(rt.allocator, err, .{
        .detail = detail,
    }) catch {
        // Ultimate fallback: simple text response
        var buf: [512]u8 = undefined;
        const response = html_error.buildSimpleResponse(err, &buf) catch ERROR_502;
        try stream.writeAll(response, .none);
        return;
    };
    defer rt.allocator.free(body);

    var header_buf: [256]u8 = undefined;
    const header = std.fmt.bufPrint(&header_buf, "HTTP/1.1 {s}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{
        err.statusLine(),
        body.len,
    }) catch unreachable;
    try stream.writeAll(header, .none);
    try stream.writeAll(body, .none);
}

fn loadErrorFile(allocator: std.mem.Allocator, path: []const u8) ?[]u8 {
    const file = std.fs.cwd().openFile(path, .{}) catch return null;
    defer file.close();
    const stat = file.stat() catch return null;
    if (stat.size > 1024 * 1024) return null; // Max 1MB
    return file.readToEndAlloc(allocator, 1024 * 1024) catch null;
}

fn appendAddHeaders(message: *http.HttpMessage, config: *const Config) !void {
    if (!config.add_headers_initialized) return;
    if (config.add_headers.items.len == 0) return;

    for (config.add_headers.items) |entry| {
        if (message.header_list.items.len >= http.MAX_HEADERS) break;

        const name = try message.allocator.dupe(u8, entry.name);
        errdefer message.allocator.free(name);
        const value = try message.allocator.dupe(u8, entry.value);
        errdefer message.allocator.free(value);

        try message.header_list.append(message.allocator, .{ .name = name, .value = value });
        if (!message.headers.contains(name)) {
            try message.headers.put(name, value);
        }
    }
}

/// Handle an incoming client connection
pub fn handle_connection(rt: *zio.Runtime, client: zio.net.Stream, config: *const Config) !void {
    var stream = client;
    defer stream.close();

    var reader = buffer.LineReader.init(rt.allocator, 8192);
    defer reader.deinit();

    const req_line = try reader.readLine(rt, &stream);
    defer rt.allocator.free(req_line);

    var message = try http.read_headers(rt.allocator, &reader, rt, &stream);
    defer message.deinit();

    // Check authentication if configured
    if (config.auth.hasCredentials()) {
        const auth_header = message.headers.get("proxy-authorization");
        if (!config.auth.verify(auth_header)) {
            // Send 407 Proxy Authentication Required
            const auth_mod = @import("auth.zig");
            var response_buf: [512]u8 = undefined;
            const response = auth_mod.build407Response(config.auth.realm, &response_buf) catch {
                try stream.writeAll("HTTP/1.1 407 Proxy Authentication Required\r\nConnection: close\r\n\r\n", .none);
                return;
            };
            try stream.writeAll(response, .none);
            return;
        }
    }

    // Try transparent proxy fallback if normal parsing fails due to missing Host
    var transparent_buf: [64]u8 = undefined;

    const req = process_request_line(rt.allocator, req_line, &message.headers) catch |err| blk: {
        if (err == error.BadRequest and config.transparent) {
            // Try to get original destination from intercepted connection
            if (transparent.getOriginalDest(stream.socket.handle, &transparent_buf)) |dest| {
                // Parse just the request line for method and path
                const parsed = http.parse_request_line(req_line) catch {
                    return err;
                };
                const req_obj = rt.allocator.create(Request) catch return err;
                req_obj.* = .{
                    .method = rt.allocator.dupe(u8, parsed.method) catch return err,
                    .protocol = rt.allocator.dupe(u8, "HTTP/1.1") catch return err,
                    .host = rt.allocator.dupe(u8, dest.host) catch return err,
                    .port = dest.port,
                    .path = rt.allocator.dupe(u8, parsed.uri) catch return err,
                    .version = parsed.version,
                };
                break :blk req_obj;
            }
        }
        return err;
    };
    defer free_request(rt.allocator, req);

    // Record request statistics
    stats.global.recordRequest();

    // Check if this is a stats page request
    if (config.stat_host) |stat_host| {
        if (std.ascii.eqlIgnoreCase(req.host, stat_host)) {
            try sendStatsResponse(rt, &stream, config);
            return;
        }
    }

    // Check URL/domain filter
    if (config.filter_initialized and config.filter.enabled) {
        // Build URL for filter matching
        const filter_url = try std.fmt.allocPrint(rt.allocator, "http://{s}:{d}{s}", .{ req.host, req.port, req.path });
        defer rt.allocator.free(filter_url);

        if (config.isFiltered(filter_url)) {
            try stream.writeAll(ERROR_403_FILTERED, .none);
            return;
        }
    }

    // Check for reverse proxy rewrite (with optional magic cookie support)
    var is_reverse_proxy = false;
    var reverse_path_prefix: ?[]const u8 = null;
    if (config.reverse_initialized and config.reverse.hasMapping()) {
        // Get cookie header for magic cookie lookup
        const cookie_header = message.headers.get("cookie");
        if (config.reverse.rewriteWithMagic(req.path, cookie_header)) |magic_result| {
            const rw = magic_result.result;
            reverse_path_prefix = magic_result.path_prefix;
            // Rewrite the request for reverse proxy
            // Free old host and replace with reverse target
            rt.allocator.free(req.host);
            req.host = try rt.allocator.dupe(u8, rw.host);
            req.port = rw.port;
            // Path is kept from the rewrite result (remaining after prefix)
            rt.allocator.free(req.path);
            req.path = try rt.allocator.dupe(u8, rw.path);
            is_reverse_proxy = true;
        } else if (config.reverse.reverse_only) {
            // ReverseOnly mode: reject requests that don't match any mapping
            try stream.writeAll(ERROR_403_REVERSE_ONLY, .none);
            return;
        }
    }

    // CONNECT method handling with port restrictions
    if (std.ascii.eqlIgnoreCase(req.method, "CONNECT")) {
        // Check if port is allowed
        const check = connect_ports.checkConnectPort(config, req.port);
        if (check == .denied) {
            try stream.writeAll(ERROR_403_CONNECT, .none);
            return;
        }

        const conn_res = try connectTarget(rt, req, config, stream.socket.handle);
        var upstream = conn_res.stream;
        defer upstream.close();

        if (conn_res.proxy) |p| {
            switch (p.proxy_type) {
                .http => {
                    const connect_cmd = try std.fmt.allocPrint(rt.allocator, "CONNECT {s}:{d} HTTP/1.1\r\nHost: {s}:{d}\r\n\r\n", .{ req.host, req.port, req.host, req.port });
                    defer rt.allocator.free(connect_cmd);
                    try upstream.writeAll(connect_cmd, .none);

                    var buf: [4096]u8 = undefined;
                    const n = try upstream.read(&buf, .none);
                    if (n == 0) return error.ProxyConnectionClosed;

                    const response = buf[0..n];
                    if (std.mem.indexOf(u8, response, " 200 ") == null) {
                        try stream.writeAll(ERROR_502, .none);
                        return;
                    }
                },
                .socks4, .socks5 => {
                    socks.connect(rt, &upstream, p.proxy_type, p.user, p.pass, req.host, req.port) catch {
                        try stream.writeAll(ERROR_502, .none);
                        return;
                    };
                },
            }
        }

        try stream.writeAll("HTTP/1.1 200 Connection established\r\nProxy-agent: tinyproxy\r\n\r\n", .none);
        _ = try reader.flush_to(rt, &upstream);
        try relay.copy_bidi(rt, stream, upstream);
        return;
    }

    // Regular HTTP request
    const conn_res = try connectTarget(rt, req, config, stream.socket.handle);
    var upstream = conn_res.stream;
    defer upstream.close();

    if (conn_res.proxy) |p| {
        switch (p.proxy_type) {
            .http => {
                const abs_url = try std.fmt.allocPrint(rt.allocator, "http://{s}:{d}{s}", .{ req.host, req.port, req.path });
                rt.allocator.free(req.path);
                req.path = abs_url;
            },
            .socks4, .socks5 => {
                socks.connect(rt, &upstream, p.proxy_type, p.user, p.pass, req.host, req.port) catch {
                    try stream.writeAll(ERROR_502, .none);
                    return;
                };
            },
        }
    }

    try appendAddHeaders(&message, config);

    // Remove hop-by-hop and explicit connection headers first.
    headers.removeHopByHop(&message);
    // Host is sent explicitly like tinyproxy C.
    headers.removeHeader(&message, "host");

    // Apply anonymous mode filtering (only whitelist + essential).
    anonymous.filterHeaders(&message, config);

    // Add Via header after filtering so it is always included.
    const via_config = headers.ViaConfig{
        .proxy_name = config.via_proxy_name,
        .disable_via = config.disable_via_header,
    };
    try headers.addViaHeader(&message, req.version, via_config);

    const request_line = try std.fmt.allocPrint(rt.allocator, "{s} {s} {s}\r\n", .{
        req.method,
        req.path,
        req.protocol,
    });
    defer rt.allocator.free(request_line);

    try upstream.writeAll(request_line, .none);
    try writeHostHeader(rt, &upstream, req);
    try upstream.writeAll("Connection: close\r\n", .none);

    // Add X-Tinyproxy header with client IP if enabled
    if (config.xtinyproxy) {
        var ip_buf: [64]u8 = undefined;
        const ip_str = std.fmt.bufPrint(&ip_buf, "{f}", .{stream.socket.address.ip}) catch "";
        if (ip_str.len > 0) {
            try upstream.writeAll("X-Tinyproxy: ", .none);
            try upstream.writeAll(ip_str, .none);
            try upstream.writeAll("\r\n", .none);
        }
    }

    for (message.header_list.items) |header| {
        try upstream.writeAll(header.name, .none);
        try upstream.writeAll(": ", .none);
        try upstream.writeAll(header.value, .none);
        try upstream.writeAll("\r\n", .none);
    }
    try upstream.writeAll("\r\n", .none);

    var body_reader = message.body_reader();
    try body_reader.copy_raw_to(&reader, rt, &stream, &upstream);

    // Process and forward response with proper header handling
    try processServerResponse(
        rt,
        upstream,
        stream,
        config,
        req,
        if (is_reverse_proxy and config.reverse.reverse_magic) reverse_path_prefix else null,
    );
}

/// Process server response: parse headers, remove hop-by-hop, add Via, rewrite Location/Refresh
fn processServerResponse(
    rt: *zio.Runtime,
    upstream: zio.net.Stream,
    client: zio.net.Stream,
    config: *const Config,
    req: *const Request,
    magic_path_prefix: ?[]const u8,
) !void {
    var from = upstream;
    var to = client;

    // Read response into buffer
    var response_reader = buffer.LineReader.init(rt.allocator, 8192);
    defer response_reader.deinit();

    // Read status line
    const status_line = try response_reader.readLine(rt, &from);
    defer rt.allocator.free(status_line);

    // Parse response headers
    var resp_message = try http.read_headers(rt.allocator, &response_reader, rt, &from);
    defer resp_message.deinit();

    // Process response headers: remove hop-by-hop
    headers.removeHopByHop(&resp_message);

    // Add Via header to response
    const via_config = headers.ViaConfig{
        .proxy_name = config.via_proxy_name,
        .disable_via = config.disable_via_header,
    };
    try headers.addViaHeader(&resp_message, req.version, via_config);

    // Rewrite Location/Refresh headers if ReverseBaseURL is configured
    if (config.reverse_initialized and config.reverse.base_url != null) {
        rewriteLocationHeader(&resp_message, config, rt.allocator) catch {};
    }

    // Inject ReverseMagic Set-Cookie if needed
    if (magic_path_prefix) |prefix| {
        var cookie_buf: [128]u8 = undefined;
        if (reverse.ReverseProxy.buildMagicCookie(prefix, &cookie_buf)) |cookie| {
            const cookie_name = rt.allocator.dupe(u8, "set-cookie") catch |err| {
                // Allocation failed - skip cookie injection
                log.debug("Failed to allocate cookie name: {}", .{err});
                return;
            };
            errdefer rt.allocator.free(cookie_name);

            const cookie_value = rt.allocator.dupe(u8, cookie) catch |err| {
                // Allocation failed - clean up and skip
                log.debug("Failed to allocate cookie value: {}", .{err});
                rt.allocator.free(cookie_name);
                return;
            };
            errdefer rt.allocator.free(cookie_value);

            resp_message.header_list.append(rt.allocator, .{ .name = cookie_name, .value = cookie_value }) catch |err| {
                // Append failed - clean up allocations
                log.debug("Failed to append cookie header: {}", .{err});
                rt.allocator.free(cookie_name);
                rt.allocator.free(cookie_value);
                return;
            };
            // Ownership transferred to header_list - don't free
        }
    }

    // Write status line
    try to.writeAll(status_line, .none);
    try to.writeAll("\r\n", .none);

    // Write processed headers
    for (resp_message.header_list.items) |header| {
        try to.writeAll(header.name, .none);
        try to.writeAll(": ", .none);
        try to.writeAll(header.value, .none);
        try to.writeAll("\r\n", .none);
    }
    try to.writeAll("\r\n", .none);

    // Forward any buffered body data
    if (response_reader.end > response_reader.start) {
        try to.writeAll(response_reader.buf[response_reader.start..response_reader.end], .none);
    }

    // Forward remaining body
    var buf: [8192]u8 = undefined;
    while (true) {
        const n = try from.read(&buf, .none);
        if (n == 0) break;
        try to.writeAll(buf[0..n], .none);
    }
}

/// Rewrite Location and Refresh headers based on ReverseBaseURL
fn rewriteLocationHeader(msg: *http.HttpMessage, config: *const Config, allocator: std.mem.Allocator) !void {
    const base_url = config.reverse.base_url orelse return;

    // Find and rewrite Location header
    for (msg.header_list.items) |*header| {
        if (std.ascii.eqlIgnoreCase(header.name, "location") or
            std.ascii.eqlIgnoreCase(header.name, "refresh"))
        {
            // Check if value contains an absolute URL that should be rewritten
            // For Location headers pointing to backend servers, prepend base_url
            if (std.mem.startsWith(u8, header.value, "http://") or
                std.mem.startsWith(u8, header.value, "https://"))
            {
                // Extract path from absolute URL
                const url = header.value;
                var rest: []const u8 = url;
                if (std.mem.indexOf(u8, rest, "://")) |idx| {
                    rest = rest[idx + 3 ..];
                }
                if (std.mem.indexOfScalar(u8, rest, '/')) |path_start| {
                    const path = rest[path_start..];
                    // Rewrite to base_url + path
                    const new_value = std.fmt.allocPrint(allocator, "{s}{s}", .{
                        std.mem.trimRight(u8, base_url, "/"),
                        path,
                    }) catch continue;
                    allocator.free(header.value);
                    header.value = new_value;
                    _ = msg.headers.remove(header.name);
                    msg.headers.put(header.name, new_value) catch {};
                }
            }
        }
    }
}

fn sendStatsResponse(rt: *zio.Runtime, stream: *zio.net.Stream, config: *const Config) !void {
    // Use custom template if configured, otherwise use default
    const body = if (config.stat_file) |template_path|
        try stats.global.renderFromTemplate(rt.allocator, template_path)
    else
        try stats.global.renderHtml(rt.allocator);
    defer rt.allocator.free(body);

    var header_buf: [256]u8 = undefined;
    const header = std.fmt.bufPrint(&header_buf, "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{body.len}) catch unreachable;

    try stream.writeAll(header, .none);
    try stream.writeAll(body, .none);
}

fn writeHostHeader(_: *zio.Runtime, upstream: *zio.net.Stream, req: *const Request) !void {
    const is_ipv6 = std.mem.indexOfScalar(u8, req.host, ':') != null;
    const include_port = req.port != HTTP_PORT and req.port != HTTPS_PORT;

    try upstream.writeAll("Host: ", .none);
    if (is_ipv6) try upstream.writeAll("[", .none);
    try upstream.writeAll(req.host, .none);
    if (is_ipv6) try upstream.writeAll("]", .none);
    if (include_port) {
        var port_buf: [6]u8 = undefined;
        const port_str = try std.fmt.bufPrint(&port_buf, "{d}", .{req.port});
        try upstream.writeAll(":", .none);
        try upstream.writeAll(port_str, .none);
    }
    try upstream.writeAll("\r\n", .none);
}

fn strip_username_password(host: []u8) usize {
    const at_pos = std.mem.indexOf(u8, host, "@") orelse return host.len;
    if (at_pos + 1 >= host.len) return host.len; // Bounds check
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
    header_map: *const std.StringHashMap([]const u8),
) !*Request {
    const req_line = try http.parse_request_line(line);
    const req = try allocator.create(Request);
    errdefer allocator.destroy(req);

    const protocol = switch (req_line.version) {
        .http09 => "HTTP/0.9",
        .http10 => "HTTP/1.0",
        .http11 => "HTTP/1.1",
    };

    req.version = req_line.version;

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
        const host_header = header_map.get("host") orelse return error.BadRequest;
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
    var header_map = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer header_map.deinit();

    const req_line = "GET http://example.com/hello HTTP/1.1";
    const req = try process_request_line(std.testing.allocator, req_line, &header_map);
    defer free_request(std.testing.allocator, req);

    try std.testing.expectEqualStrings("GET", req.method);
    try std.testing.expectEqualStrings("example.com", req.host);
    try std.testing.expectEqualStrings("/hello", req.path);
    try std.testing.expectEqual(@as(u16, 80), req.port);
}

test "append addheader entries to message" {
    const allocator = std.testing.allocator;

    var config = Config.init(allocator);
    defer config.deinit();
    try config.addHeader("X-Test", "123");

    var message = http.HttpMessage.init(allocator);
    defer message.deinit();

    const name = try allocator.dupe(u8, "X-Test");
    const value = try allocator.dupe(u8, "abc");
    try message.header_list.append(allocator, .{ .name = name, .value = value });
    try message.headers.put(name, value);

    try appendAddHeaders(&message, &config);

    try std.testing.expectEqual(@as(usize, 2), message.header_list.items.len);
    try std.testing.expectEqualStrings("X-Test", message.header_list.items[0].name);
    try std.testing.expectEqualStrings("abc", message.header_list.items[0].value);
    try std.testing.expectEqualStrings("X-Test", message.header_list.items[1].name);
    try std.testing.expectEqualStrings("123", message.header_list.items[1].value);
}

fn connectTarget(rt: *zio.Runtime, req: *const Request, config: *const Config, client_socket: std.posix.socket_t) !struct { stream: zio.net.Stream, proxy: ?*const upstream_mod.UpstreamProxy } {
    const proxy = if (config.upstream_initialized) config.upstream.findUpstream(req.host) else null;

    // Resolve target (proxy or direct)
    const target_host = if (proxy) |p| p.host else req.host;
    const target_port = if (proxy) |p| p.port else req.port;

    const addr = zio.net.IpAddress.parseIp(target_host, target_port) catch blk: {
        const list = try std.net.getAddressList(rt.allocator, target_host, target_port);
        defer list.deinit();
        if (list.addrs.len == 0) return error.UnknownHostName;
        break :blk zio.net.IpAddress.fromStd(list.addrs[0]);
    };

    // Determine bind address: BindSame takes precedence over Bind
    var local_addr_buf: [64]u8 = undefined;
    const bind_addr: ?[]const u8 = if (config.bind_same)
        socket.get_local_addr_str(client_socket, &local_addr_buf)
    else
        config.bind_addr;

    // Connect with optional local address binding
    const stream = try socket.connectWithBind(rt, addr, bind_addr);
    return .{ .stream = stream, .proxy = proxy };
}
