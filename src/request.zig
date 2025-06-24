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

    var line: []u8 = undefined;
    var header: ?[]u8 = null;
    var len: usize = 0;
    var double_cgi = false;

    defer {
        if (header) |h| allocator.free(h);
    }

    for (0..MAX_HEADERS) |_| {
        const linelen = network.readline(fd, &line) catch |e| {
            log.err("get_all_headers readline error: {any}", .{e});
            if (header) |h| allocator.free(h);
            return e;
        };
        defer allocator.free(line);

        if (linelen == 0) {
            if (header) |h| allocator.free(h);
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
            if (header) |h| allocator.free(h);
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
    if (header) |h| allocator.free(h);
    return error.TooManyHeaders;
}

pub const Request = struct {
    method: []u8,
    protocol: []u8,
    host: []u8,
    port: u16,
    path: []u8,
};

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
    // TODO: remove below log for headers later
    {
        var iterator = headers.iterator();
        while (iterator.next()) |entry| {
            log.debug("header: {s}: {s}", .{ entry.key_ptr.*, entry.value_ptr.* });
        }
    }
    got_headers = true;

    // TODO: basic auth

    // TODO: add custom headers

    // TODO: (*) call process_request() for METHOD, URL

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
