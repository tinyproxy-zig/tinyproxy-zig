const std = @import("std");

const ziro = @import("ziro");
const aio = ziro.asyncio;

const Connection = @import("connection.zig").Connection;
const network = @import("network.zig");
const runtime = @import("runtime.zig");
const socket = @import("socket.zig");
const text = @import("text.zig");

const log = std.log.scoped(.@"tinyproxy/request");

/// Codify the test for the carriage return and new line characters.
inline fn checkCRLF(header: []const u8) bool {
    return (header.len == 1 and header[0] == '\n') or
        (header.len == 2 and header[0] == '\r' and header[1] == '\n');
}

/// Codify the test for header fields folded over multiple lines.
inline fn checkLWS(header: []const u8) bool {
    return header.len > 0 and (header[0] == ' ' or header[0] == '\t');
}

/// Take a host string and if there is a username/password part, strip it off.
/// Modifies the host string in-place and returns the new length.
fn strip_username_password(host: []u8) usize {
    // Find the '@' character
    const at_pos = std.mem.indexOf(u8, host, "@") orelse return host.len;

    // Copy everything after '@' to the beginning
    const src_start = at_pos + 1;
    const bytes_to_copy = host.len - src_start;

    // Use copyForwards to handle overlapping memory safely
    std.mem.copyForwards(u8, host[0..bytes_to_copy], host[src_start..]);

    return bytes_to_copy;
}

/// Take a host string and if there is a port part, strip it off and return the port number.
/// For www.host.com:8001, this strips ":8001" and returns 8001.
/// Modifies the host string in-place and returns the port or 0 if no valid port found.
fn strip_return_port(host: []u8) struct { port: u16, new_len: usize } {
    // Find the last ':' character
    const colon_pos = std.mem.lastIndexOf(u8, host, ":") orelse return .{ .port = 0, .new_len = host.len };

    // Check for IPv6 style literals - if there's a ']' after the ':', it's IPv6
    const after_colon = host[colon_pos + 1 ..];
    if (std.mem.indexOf(u8, after_colon, "]") != null) {
        return .{ .port = 0, .new_len = host.len };
    }

    // Try to parse the port number
    const port_str = std.mem.trim(u8, after_colon, " \t\r\n\x00");
    const port = std.fmt.parseInt(u16, port_str, 10) catch return .{ .port = 0, .new_len = host.len };

    // Valid port found, return it and the new host length (without port part)
    return .{ .port = port, .new_len = colon_pos };
}

/// Pull the information out of the URL line.
/// This expects urls with the initial '<proto>://' part stripped and hence can handle
/// http urls, (proxied) ftp:// urls and https-requests that come in without the proto:// part via CONNECT.
fn extract_url(allocator: std.mem.Allocator, url: []const u8, default_port: u16, request: *Request) !void {
    // Split the URL on the slash to separate host from path
    const slash_pos = std.mem.indexOf(u8, url, "/");

    var host_part: []const u8 = undefined;
    var path_part: []const u8 = undefined;

    if (slash_pos) |pos| {
        host_part = url[0..pos];
        path_part = url[pos..];
    } else {
        host_part = url;
        path_part = "/";
    }

    // Allocate and copy host and path
    var host_buffer = allocator.dupe(u8, host_part) catch return error.OutOfMemory;
    errdefer allocator.free(host_buffer);

    const path_buffer = allocator.dupe(u8, path_part) catch {
        allocator.free(host_buffer);
        return error.OutOfMemory;
    };
    errdefer allocator.free(path_buffer);

    // Remove the username/password if they're present
    var host_len = strip_username_password(host_buffer);

    // Find a proper port in www.site.com:8001 URLs
    const port_result = strip_return_port(host_buffer[0..host_len]);
    host_len = port_result.new_len;
    const port = if (port_result.port != 0) port_result.port else default_port;

    // Remove any surrounding '[' and ']' from IPv6 literals
    if (host_len > 2 and host_buffer[0] == '[') {
        const bracket_end = std.mem.lastIndexOf(u8, host_buffer[0..host_len], "]");
        if (bracket_end) |end_pos| {
            // Move content between brackets to the beginning
            const content_len = end_pos - 1;
            std.mem.copyForwards(u8, host_buffer[0..content_len], host_buffer[1..end_pos]);
            host_len = content_len;
        }
    }

    // Resize host buffer to actual length
    host_buffer = allocator.realloc(host_buffer, host_len) catch host_buffer;

    // Set request fields
    request.host = host_buffer;
    request.path = path_buffer;
    request.port = port;
}

/// Read the first line from the client (the request line for HTTP connections).
/// The request line is allocated from the heap, ownership has been transfered to the caller.
fn read_request_line(conn: *Connection) !void {
    const allocator = runtime.runtime.allocator;
    const fd = conn.client_conn.tcp.fd;

    retry: while (true) {
        const len = network.readline(fd, &conn.request_line) catch |e| {
            log.err("read_request_line error: {any}", .{e});
            return;
        };

        if (len <= 0) {
            log.err("read_request_line: client (fd: {}) closed socket before read.", .{fd});
            return;
        }

        // Strip the new line and carriage return from the string
        const chars_removed = text.chomp(conn.request_line[0..len]) catch |e| {
            log.err("chomp error: {any}", .{e});
            return;
        };

        // If the number of characters removed is the same as the length then it was a blank line.
        // Free the buffer and try again (since we're looking for a request line.)
        if (chars_removed == len) {
            allocator.free(conn.request_line);
            continue :retry;
        }

        // Successfully got a non-blank request line
        break;
    }

    log.info("request (fd: {}): {s}", .{ fd, conn.request_line });
}

/// Add header to the hashmap, parsing key:value pairs.
///
/// Take a complete header line and break it apart (into a key and the data.)
/// Now insert this information into the hashmap for the connection so it
/// can be retrieved and manipulated later.
///
/// @param headers The hashmap to insert the header into.
/// @param header_data The header line to parse.
fn add_header_to_connection(headers: *std.StringHashMap([]u8), header_data: []const u8) !void {
    const allocator = runtime.runtime.allocator;

    // Find the colon separator
    const colon_pos = std.mem.indexOf(u8, header_data, ":") orelse return;

    // Extract key and value
    const key = std.mem.trim(u8, header_data[0..colon_pos], " \t\r\n");
    const value = std.mem.trim(u8, header_data[colon_pos + 1 ..], " \t\r\n");

    // Allocate copies for the hashmap
    const key_copy = try allocator.dupe(u8, key);
    const value_copy = try allocator.dupe(u8, value);

    // Add to hashmap
    try headers.put(key_copy, value_copy);
}

/// Define maximum number of headers that we accept.
/// This should be big enough to handle legitimate cases,
/// but limited to avoid DoS.
const MAX_HEADERS = 10000;

/// Read all the headers from the stream
fn get_all_headers(client_conn: aio.TCP, headers: *std.StringHashMap([]u8)) !void {
    const allocator = runtime.runtime.allocator;
    const fd = client_conn.tcp.fd;

    var line: []u8 = &.{};
    var header: ?[]u8 = null;
    var len: usize = 0;
    var double_cgi = false;

    defer {
        if (header) |h| allocator.free(h);
    }

    for (0..MAX_HEADERS) |_| {
        const linelen = network.readline(fd, &line) catch |e| {
            log.err("get_all_headers readline error: {any}", .{e});
            if (header) |h| {
                allocator.free(h);
                header = null;
            }
            return e;
        };
        defer {
            if (line.len > 0) allocator.free(line);
        }

        if (linelen == 0) {
            if (header) |h| {
                allocator.free(h);
                header = null;
            }
            return error.ConnectionClosed;
        }

        // Get the actual line content (excluding null terminator)
        const line_content = line[0..linelen];

        // If we received a CR LF or a non-continuation line, then add
        // the accumulated header field, if any, to the hashmap, and reset it.
        if (checkCRLF(line_content) or !checkLWS(line_content)) {
            if (!double_cgi and len > 0) {
                if (header) |h| {
                    add_header_to_connection(headers, h[0..len]) catch |e| {
                        log.err("Failed to add header to connection: {any}", .{e});
                        allocator.free(h);
                        header = null;
                        return e;
                    };
                    allocator.free(h);
                    header = null;
                }
            }
            len = 0;
        }

        // If we received just a CR LF on a line, the headers are finished.
        if (checkCRLF(line_content)) {
            if (header) |h| {
                allocator.free(h);
                header = null;
            }
            return;
        }

        // BUG FIX: The following code detects a "Double CGI"
        // situation so that we can handle the nonconforming system.
        // This problem was found when accessing cgi.ebay.com, and it
        // turns out to be a wider spread problem as well.
        //
        // If "Double CGI" is in effect, duplicate headers are ignored.
        if (linelen >= 5 and std.ascii.startsWithIgnoreCase(line_content, "HTTP/")) {
            double_cgi = true;
        }

        // Append the new line to the current header field.
        if (header) |h| {
            const tmp = allocator.realloc(h, len + linelen) catch |e| {
                allocator.free(h);
                header = null;
                return e;
            };
            header = tmp;
        } else {
            header = allocator.alloc(u8, linelen) catch |e| {
                return e;
            };
        }

        if (header) |h| {
            @memcpy(h[len .. len + linelen], line_content);
            len += linelen;
        }
    }

    // If we get here, this means we reached MAX_HEADERS count.
    // Bail out with error.
    if (header) |h| {
        allocator.free(h);
        header = null;
    }
    return error.TooManyHeaders;
}

const HTTP_PORT: u16 = 80;
const HTTPS_PORT: u16 = 443;

pub const Request = struct {
    method: []u8,
    protocol: []u8,
    host: []u8,
    port: u16,
    path: []u8,
};

/// Break the request line apart and figure out where to connect and build a new request line.
/// Finally connect to the remote server.
fn process_request(conn: *Connection, headers: std.StringHashMap([]u8)) !*Request {
    const allocator = runtime.runtime.allocator;
    const request_line = conn.request_line;

    // Parse request line: METHOD URL PROTOCOL
    var parts = std.mem.splitScalar(u8, request_line, ' ');

    const method_part = parts.next() orelse {
        log.err("process_request: bad request on method part", .{});
        return error.BadRequest;
    };
    const url_part = parts.next() orelse {
        log.err("process_request: bad request on url part", .{});
        return error.BadRequest;
    };
    const protocol_part = parts.next();

    // Create request structure
    const request = try allocator.create(Request);
    errdefer allocator.destroy(request);

    // Handle HTTP/0.9 GET requests (only method and URL)
    if (protocol_part == null) {
        if (!std.ascii.eqlIgnoreCase(method_part, "GET")) {
            return error.BadRequest;
        }
        // HTTP/0.9 GET request - no protocol specified
        try extract_url(allocator, url_part, HTTP_PORT, request);
        request.method = try allocator.dupe(u8, method_part);
        request.protocol = try allocator.dupe(u8, "HTTP/0.9");
        return request;
    }

    const protocol = protocol_part.?;

    // Validate HTTP protocol
    if (!std.ascii.startsWithIgnoreCase(protocol, "HTTP/")) {
        log.err("process_request: bad request on protocol part", .{});
        return error.BadRequest;
    }

    // Parse protocol version
    const version_part = protocol[5..];
    var version_parts = std.mem.splitScalar(u8, version_part, '.');
    const major_str = version_parts.next() orelse {
        log.err("process_request: bad request on major version part", .{});
        return error.BadRequest;
    };
    const minor_str = version_parts.next() orelse {
        log.err("process_request: bad request on minor version part", .{});
        return error.BadRequest;
    };

    // Trim null terminators that might be left after chomp
    const major_trimmed = std.mem.trimRight(u8, major_str, "\x00");
    const minor_trimmed = std.mem.trimRight(u8, minor_str, "\x00");

    const major = std.fmt.parseInt(u32, major_trimmed, 10) catch {
        log.err("process_request: bad request on major version part", .{});
        return error.BadRequest;
    };
    const minor = std.fmt.parseInt(u32, minor_trimmed, 10) catch {
        log.err("process_request: bad request on minor version part", .{});
        return error.BadRequest;
    };

    // Basic validation of HTTP version
    if (major != 1 or (minor != 0 and minor != 1)) {
        log.warn("Unsupported HTTP version: {}.{}", .{ major, minor });
    }

    // Parse URL based on method and URL format
    if (std.ascii.startsWithIgnoreCase(url_part, "http://")) {
        // Full HTTP URL
        const url_without_scheme = url_part[7..]; // Skip "http://"
        try extract_url(allocator, url_without_scheme, HTTP_PORT, request);
    } else if (std.ascii.eqlIgnoreCase(method_part, "CONNECT")) {
        // CONNECT method - URL is host:port
        try extract_url(allocator, url_part, HTTPS_PORT, request);
    } else {
        // Relative URL - need Host header for host info
        const host_header = headers.get("Host") orelse headers.get("host") orelse return error.BadRequest;

        // Parse host header for host:port
        var host_parts = std.mem.splitScalar(u8, host_header, ':');
        const host_part = host_parts.next() orelse {
            log.err("process_request: bad request on host part", .{});
            return error.BadRequest;
        };
        const port_str = host_parts.next();

        const port = if (port_str) |p|
            std.fmt.parseInt(u16, p, 10) catch HTTP_PORT
        else
            HTTP_PORT;

        // For relative URLs, construct a host:port string and extract
        const host_port_str = if (port_str) |_|
            try std.fmt.allocPrint(allocator, "{s}:{d}", .{ host_part, port })
        else
            try allocator.dupe(u8, host_part);
        defer allocator.free(host_port_str);

        try extract_url(allocator, host_port_str, port, request);
        // Override path with the original URL part for relative URLs
        allocator.free(request.path);
        request.path = try allocator.dupe(u8, url_part);
    }

    // Set method and protocol
    request.method = try allocator.dupe(u8, method_part);
    request.protocol = try allocator.dupe(u8, protocol);

    return request;
}

const HTTP_RESPONSE = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 13\r\nContent-Type: text/plain\r\n\r\nHello World\r\n";

/// This is the main drive for each connection.
pub fn handle_connection(conn: *Connection) !void {
    defer conn.client_conn.close() catch unreachable;

    const allocator = runtime.runtime.allocator;
    var got_headers: bool = false;

    socket.get_peer_addr(conn.client_conn.tcp.fd, &conn.client_addr);

    // TODO: BindSame

    log.info("connect (fd: {}): {any}", .{ conn.client_conn.tcp.fd, conn.client_addr });

    try socket.set_socket_timeout(conn.client_conn.tcp.fd);

    // TODO: connection_loops()

    // TODO: check_acl()

    read_request_line(conn) catch {
        return;
    };

    // get all headers from the client in a big hashmap
    var headers = std.StringHashMap([]u8).init(allocator);
    defer {
        // Free all allocated keys and values
        var iterator = headers.iterator();
        while (iterator.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        headers.deinit();
    }
    get_all_headers(conn.client_conn, &headers) catch |e| {
        log.err("get_all_headers error: {any}", .{e});
        return;
    };
    got_headers = true;

    // TODO: basic auth

    // TODO: add custom headers

    // TODO: (*) call process_request() for METHOD, URL

    const request = try process_request(conn, headers);
    defer {
        // Free request structure and its fields
        allocator.free(request.method);
        allocator.free(request.protocol);
        allocator.free(request.host);
        allocator.free(request.path);
        allocator.destroy(request);
    }

    // TODO: (*) establish connection to remote

    // TODO: connect upstream

    // TODO: (*) connect directly

    // TODO: connect securely (through CONNECT)

    // TODO: (*) call process_client_headers()

    // TODO: (*) call process_server_headers() OR send_connect_method_response()

    // TODO: (*) call relay_connection()

    // TODO: (*) final log: closed connection between local client (fd:{}) and remove server (fd:{})

    var buf: [1024]u8 = undefined;

    try socket.set_socket_nonblocking(conn.client_conn.tcp.fd);

    while (true) {
        _ = conn.client_conn.write(.{ .slice = HTTP_RESPONSE }) catch |e| {
            log.err("client write error: {any}", .{e});
            return;
        };
        _ = conn.client_conn.read(.{ .slice = &buf }) catch |e| {
            log.err("client read error: {any}", .{e});
            return;
        };
    }
}
