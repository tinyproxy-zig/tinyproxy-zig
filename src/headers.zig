//! HTTP Header Processing Module
//!
//! Handles hop-by-hop header removal, Via header addition, and header filtering
//! for HTTP proxy operations per RFC 2616/7230.

const std = @import("std");
const http = @import("http.zig");

/// Hop-by-hop headers that MUST be removed when forwarding requests/responses.
/// Per RFC 2616 Section 13.5.1 and RFC 7230 Section 6.1
/// Note: transfer-encoding is NOT removed because we forward chunked body as-is.
/// If we were to dechunk, we would need to remove TE and set Content-Length.
pub const hop_by_hop_headers = [_][]const u8{
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    // "transfer-encoding", // Preserved: we forward chunked body as-is
    "upgrade",
    "proxy-connection", // Non-standard but widely used
};

/// Headers that should be preserved even when listed in Connection header.
/// These are essential for proxy operation.
const preserved_headers = [_][]const u8{
    "host",
    "content-length",
    "content-type",
    "transfer-encoding",
};

/// Check if a header name is a hop-by-hop header (case-insensitive).
pub fn isHopByHop(name: []const u8) bool {
    for (hop_by_hop_headers) |hop| {
        if (std.ascii.eqlIgnoreCase(name, hop)) {
            return true;
        }
    }
    return false;
}

/// Check if a header should be preserved (not removed even if in Connection).
fn isPreserved(name: []const u8) bool {
    for (preserved_headers) |p| {
        if (std.ascii.eqlIgnoreCase(name, p)) {
            return true;
        }
    }
    return false;
}

/// Parse Connection header value to extract additional headers to remove.
/// Connection header can specify: close, keep-alive, or comma-separated header names.
/// Returns a list of header names that should also be treated as hop-by-hop.
pub fn parseConnectionHeader(
    allocator: std.mem.Allocator,
    value: []const u8,
) !std.ArrayList([]const u8) {
    var result = std.ArrayList([]const u8).empty;
    errdefer {
        for (result.items) |name| allocator.free(name);
        result.deinit(allocator);
    }

    const separators = "()<>@,;:\\\"/[]?={} \t";
    var it = std.mem.tokenizeAny(u8, value, separators);
    while (it.next()) |token| {
        if (token.len == 0) continue;

        // Skip connection options (not header names)
        if (std.ascii.eqlIgnoreCase(token, "close")) continue;
        if (std.ascii.eqlIgnoreCase(token, "keep-alive")) continue;

        // Skip already known hop-by-hop headers
        if (isHopByHop(token)) continue;

        // Skip preserved headers
        if (isPreserved(token)) continue;

        // This is a header name to remove
        const name = try allocator.dupe(u8, token);
        try result.append(allocator, name);
    }

    return result;
}

fn containsIgnoreCase(list: []const []const u8, name: []const u8) bool {
    for (list) |existing| {
        if (std.ascii.eqlIgnoreCase(existing, name)) return true;
    }
    return false;
}

/// Remove all headers with a given name (case-insensitive).
pub fn removeHeader(message: *http.HttpMessage, name: []const u8) void {
    var i: usize = message.header_list.items.len;
    while (i > 0) {
        i -= 1;
        const header = message.header_list.items[i];
        if (!std.ascii.eqlIgnoreCase(header.name, name)) continue;
        _ = message.headers.remove(header.name);
        message.allocator.free(header.name);
        message.allocator.free(header.value);
        _ = message.header_list.orderedRemove(i);
    }
}

/// Remove hop-by-hop headers from an HttpMessage.
/// Also removes any headers specified in the Connection header.
pub fn removeHopByHop(message: *http.HttpMessage) void {
    // First, check Connection header for additional headers to remove
    var extra_to_remove = std.ArrayList([]const u8).empty;
    defer {
        for (extra_to_remove.items) |name| {
            message.allocator.free(name);
        }
        extra_to_remove.deinit(message.allocator);
    }

    if (message.headers.get("connection")) |conn_value| {
        var parsed = parseConnectionHeader(message.allocator, conn_value) catch
            std.ArrayList([]const u8).empty;
        defer parsed.deinit(message.allocator);
        for (parsed.items) |name| {
            if (containsIgnoreCase(extra_to_remove.items, name)) {
                message.allocator.free(name);
                continue;
            }
            extra_to_remove.append(message.allocator, name) catch {
                message.allocator.free(name);
            };
        }
    }

    if (message.headers.get("proxy-connection")) |conn_value| {
        var parsed = parseConnectionHeader(message.allocator, conn_value) catch
            std.ArrayList([]const u8).empty;
        defer parsed.deinit(message.allocator);
        for (parsed.items) |name| {
            if (containsIgnoreCase(extra_to_remove.items, name)) {
                message.allocator.free(name);
                continue;
            }
            extra_to_remove.append(message.allocator, name) catch {
                message.allocator.free(name);
            };
        }
    }

    // Remove headers from the list (iterate backwards to safely remove)
    var i: usize = message.header_list.items.len;
    while (i > 0) {
        i -= 1;
        const header = message.header_list.items[i];
        var should_remove = isHopByHop(header.name);

        // Check if in extra removal list
        if (!should_remove) {
            for (extra_to_remove.items) |extra| {
                if (std.ascii.eqlIgnoreCase(header.name, extra)) {
                    should_remove = true;
                    break;
                }
            }
        }

        if (should_remove) {
            // Remove from hash map
            _ = message.headers.remove(header.name);
            // Free memory
            message.allocator.free(header.name);
            message.allocator.free(header.value);
            // Remove from list
            _ = message.header_list.orderedRemove(i);
        }
    }
}

/// Via header proxy identifier.
pub const ViaConfig = struct {
    /// Proxy name to use in Via header (e.g., "tinyproxy")
    proxy_name: ?[]const u8 = null,
    /// Whether to disable Via header entirely
    disable_via: bool = false,
};

/// Add or append to Via header for request/response.
/// Format: Via: 1.1 proxy-name (or received-protocol received-by [comment])
pub fn addViaHeader(
    message: *http.HttpMessage,
    http_version: http.HttpVersion,
    config: ViaConfig,
) !void {
    if (config.disable_via) return;

    var hostname_buf: [std.posix.HOST_NAME_MAX]u8 = undefined;
    const proxy_name = config.proxy_name orelse blk: {
        const hostname = std.posix.gethostname(&hostname_buf) catch break :blk "unknown";
        break :blk hostname;
    };
    const via_comment = "tinyproxy";
    const version_str = switch (http_version) {
        .http09 => "0.9",
        .http10 => "1.0",
        .http11 => "1.1",
    };

    // Build the new Via value
    const new_via = try std.fmt.allocPrint(
        message.allocator,
        "{s} {s} ({s})",
        .{ version_str, proxy_name, via_comment },
    );
    errdefer message.allocator.free(new_via);

    // Check if Via header already exists
    if (message.headers.get("via")) |existing| {
        // Append to existing Via header
        const combined = try std.fmt.allocPrint(
            message.allocator,
            "{s}, {s}",
            .{ existing, new_via },
        );
        message.allocator.free(new_via);

        // Update the header value
        // Find and update in header_list
        for (message.header_list.items) |*header| {
            if (std.mem.eql(u8, header.name, "via")) {
                message.allocator.free(header.value);
                header.value = combined;
                try message.headers.put(header.name, combined);
                return;
            }
        }
    } else {
        // Add new Via header
        const name = try message.allocator.dupe(u8, "via");
        errdefer message.allocator.free(name);

        try message.header_list.append(message.allocator, .{
            .name = name,
            .value = new_via,
        });
        try message.headers.put(name, new_via);
    }
}

/// Process client request headers before forwarding to upstream.
/// - Removes hop-by-hop headers
/// - Adds Via header
pub fn processClientHeaders(
    message: *http.HttpMessage,
    http_version: http.HttpVersion,
    via_config: ViaConfig,
) !void {
    removeHopByHop(message);
    removeHeader(message, "host");
    try addViaHeader(message, http_version, via_config);
}

/// Process server response headers before forwarding to client.
/// - Removes hop-by-hop headers
/// - Adds Via header
pub fn processServerHeaders(
    message: *http.HttpMessage,
    http_version: http.HttpVersion,
    via_config: ViaConfig,
) !void {
    removeHopByHop(message);
    try addViaHeader(message, http_version, via_config);
}

/// Write headers to a writer (for forwarding).
/// Does not include the final empty line (caller should add \r\n).
pub fn writeHeaders(
    message: *const http.HttpMessage,
    writer: anytype,
) !void {
    for (message.header_list.items) |header| {
        try writer.writeAll(header.name);
        try writer.writeAll(": ");
        try writer.writeAll(header.value);
        try writer.writeAll("\r\n");
    }
}

// ============================================================================
// Tests
// ============================================================================

test "isHopByHop detects hop-by-hop headers" {
    try std.testing.expect(isHopByHop("Connection"));
    try std.testing.expect(isHopByHop("connection"));
    try std.testing.expect(isHopByHop("PROXY-CONNECTION"));
    try std.testing.expect(isHopByHop("Keep-Alive"));
    try std.testing.expect(!isHopByHop("Transfer-Encoding")); // Preserved: forwarded as-is
    try std.testing.expect(!isHopByHop("Content-Type"));
    try std.testing.expect(!isHopByHop("Host"));
    try std.testing.expect(!isHopByHop("Accept"));
}

test "parseConnectionHeader extracts header names" {
    const allocator = std.testing.allocator;

    // Test with custom header names
    var result = try parseConnectionHeader(allocator, "close, X-Custom-Header, keep-alive");
    defer {
        for (result.items) |name| allocator.free(name);
        result.deinit(allocator);
    }

    try std.testing.expectEqual(@as(usize, 1), result.items.len);
    try std.testing.expectEqualStrings("X-Custom-Header", result.items[0]);
}

test "parseConnectionHeader ignores known hop-by-hop" {
    const allocator = std.testing.allocator;

    var result = try parseConnectionHeader(allocator, "close, connection, upgrade");
    defer {
        for (result.items) |name| allocator.free(name);
        result.deinit(allocator);
    }

    try std.testing.expectEqual(@as(usize, 0), result.items.len);
}

test "removeHopByHop removes hop-by-hop headers" {
    const allocator = std.testing.allocator;

    var message = http.HttpMessage.init(allocator);
    defer message.deinit();

    // Add some headers
    const host_name = try allocator.dupe(u8, "host");
    const host_value = try allocator.dupe(u8, "example.com");
    try message.header_list.append(allocator, .{ .name = host_name, .value = host_value });
    try message.headers.put(host_name, host_value);

    const conn_name = try allocator.dupe(u8, "connection");
    const conn_value = try allocator.dupe(u8, "keep-alive");
    try message.header_list.append(allocator, .{ .name = conn_name, .value = conn_value });
    try message.headers.put(conn_name, conn_value);

    const proxy_conn_name = try allocator.dupe(u8, "proxy-connection");
    const proxy_conn_value = try allocator.dupe(u8, "close");
    try message.header_list.append(allocator, .{ .name = proxy_conn_name, .value = proxy_conn_value });
    try message.headers.put(proxy_conn_name, proxy_conn_value);

    const accept_name = try allocator.dupe(u8, "accept");
    const accept_value = try allocator.dupe(u8, "text/html");
    try message.header_list.append(allocator, .{ .name = accept_name, .value = accept_value });
    try message.headers.put(accept_name, accept_value);

    // Remove hop-by-hop headers
    removeHopByHop(&message);

    // Check results
    try std.testing.expectEqual(@as(usize, 2), message.header_list.items.len);
    try std.testing.expect(message.headers.get("host") != null);
    try std.testing.expect(message.headers.get("accept") != null);
    try std.testing.expect(message.headers.get("connection") == null);
    try std.testing.expect(message.headers.get("proxy-connection") == null);
}

test "addViaHeader adds new Via header" {
    const allocator = std.testing.allocator;

    var message = http.HttpMessage.init(allocator);
    defer message.deinit();

    try addViaHeader(&message, .http11, .{ .proxy_name = "test-proxy" });

    const via = message.headers.get("via");
    try std.testing.expect(via != null);
    try std.testing.expectEqualStrings("1.1 test-proxy (tinyproxy)", via.?);
}

test "addViaHeader appends to existing Via" {
    const allocator = std.testing.allocator;

    var message = http.HttpMessage.init(allocator);
    defer message.deinit();

    // Add initial Via header
    const via_name = try allocator.dupe(u8, "via");
    const via_value = try allocator.dupe(u8, "1.0 upstream-proxy");
    try message.header_list.append(allocator, .{ .name = via_name, .value = via_value });
    try message.headers.put(via_name, via_value);

    // Add our Via
    try addViaHeader(&message, .http11, .{ .proxy_name = "tinyproxy" });

    const via = message.headers.get("via");
    try std.testing.expect(via != null);
    try std.testing.expectEqualStrings("1.0 upstream-proxy, 1.1 tinyproxy (tinyproxy)", via.?);
}

test "addViaHeader respects disable_via" {
    const allocator = std.testing.allocator;

    var message = http.HttpMessage.init(allocator);
    defer message.deinit();

    try addViaHeader(&message, .http11, .{ .disable_via = true });

    try std.testing.expect(message.headers.get("via") == null);
}
