//! Reverse Proxy Module for tinyproxy-zig
//!
//! Maps URL paths to backend servers for reverse proxy functionality.
//!
//! Config example:
//!   ReversePath "/api" "http://api-server:8080/"
//!   ReversePath "/static" "http://cdn:80/"
//!   ReverseOnly Yes
//!   ReverseMagic Yes
//!   ReverseBaseURL "http://proxy.example.com/"
//!
//! ReverseMagic uses cookies to track which backend a client should be
//! routed to, useful when backend sites return absolute URLs.

const std = @import("std");

/// Cookie name used for ReverseMagic tracking
pub const REVERSE_COOKIE = "TinyproxyReversePath";

/// A single reverse proxy path mapping
pub const ReversePath = struct {
    /// URL path prefix to match (e.g., "/api")
    path: []const u8,
    /// Target URL to forward to (e.g., "http://api-server:8080/")
    url: []const u8,
};

/// Result of URL rewriting
pub const RewriteResult = struct {
    /// New target host
    host: []const u8,
    /// New target port
    port: u16,
    /// New request path
    path: []const u8,
    /// Whether to use HTTPS
    is_https: bool,
};

/// Reverse proxy configuration and logic
pub const ReverseProxy = struct {
    allocator: std.mem.Allocator,
    /// Registered path mappings
    paths: std.ArrayList(ReversePath),
    /// Only allow reverse proxy requests (reject forward proxy)
    reverse_only: bool = false,
    /// Enable magic cookie tracking for absolute URL handling
    reverse_magic: bool = false,
    /// Base URL for cookie path rewriting (optional)
    base_url: ?[]const u8 = null,
    base_url_owned: bool = false,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .paths = std.ArrayList(ReversePath).empty,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.paths.items) |entry| {
            self.allocator.free(entry.path);
            self.allocator.free(entry.url);
        }
        self.paths.deinit(self.allocator);

        if (self.base_url_owned) {
            if (self.base_url) |url| self.allocator.free(url);
        }
    }

    /// Add a path mapping
    /// path: URL prefix to match (e.g., "/api")
    /// url: Target URL (e.g., "http://api-server:8080/")
    pub fn addPath(self: *Self, path: []const u8, url: []const u8) !void {
        const path_copy = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(path_copy);
        const url_copy = try self.allocator.dupe(u8, url);
        errdefer self.allocator.free(url_copy);

        try self.paths.append(self.allocator, .{
            .path = path_copy,
            .url = url_copy,
        });
    }

    /// Set base URL
    pub fn setBaseUrl(self: *Self, url: []const u8) !void {
        const url_copy = try self.allocator.dupe(u8, url);
        if (self.base_url_owned) {
            if (self.base_url) |old| self.allocator.free(old);
        }
        self.base_url = url_copy;
        self.base_url_owned = true;
    }

    /// Check if there are any reverse proxy mappings configured
    pub fn hasMapping(self: *const Self) bool {
        return self.paths.items.len > 0;
    }

    /// Extract reverse proxy path from cookie header value.
    /// Cookie format: "name=value; name2=value2"
    /// Returns the path prefix if TinyproxyReversePath cookie is found.
    pub fn extractMagicCookie(cookie_header: []const u8) ?[]const u8 {
        var iter = std.mem.splitSequence(u8, cookie_header, "; ");
        while (iter.next()) |cookie| {
            if (std.mem.startsWith(u8, cookie, REVERSE_COOKIE)) {
                if (std.mem.indexOfScalar(u8, cookie, '=')) |eq_pos| {
                    const value = cookie[eq_pos + 1 ..];
                    if (value.len > 0) return value;
                }
            }
        }
        return null;
    }

    /// Build Set-Cookie header value for ReverseMagic tracking.
    /// Returns the cookie string to be added to response headers.
    pub fn buildMagicCookie(path_prefix: []const u8, buf: []u8) ?[]const u8 {
        // Format: TinyproxyReversePath=/api; Path=/
        const result = std.fmt.bufPrint(buf, "{s}={s}; Path=/", .{
            REVERSE_COOKIE,
            path_prefix,
        }) catch return null;
        return result;
    }

    /// Try to rewrite using magic cookie if normal path match fails.
    /// This handles requests to URLs that don't match any path prefix
    /// but have a magic cookie indicating the original mapping.
    pub fn rewriteWithMagic(
        self: *const Self,
        request_path: []const u8,
        cookie_header: ?[]const u8,
    ) ?struct { result: RewriteResult, path_prefix: []const u8 } {
        // First try normal path matching
        for (self.paths.items) |mapping| {
            if (std.mem.startsWith(u8, request_path, mapping.path)) {
                if (parseUrl(mapping.url)) |parsed| {
                    const remaining = request_path[mapping.path.len..];
                    return .{
                        .result = .{
                            .host = parsed.host,
                            .port = parsed.port,
                            .path = if (remaining.len > 0) remaining else "/",
                            .is_https = parsed.is_https,
                        },
                        .path_prefix = mapping.path,
                    };
                }
            }
        }

        // If magic is enabled and we have a cookie, try cookie-based routing
        if (self.reverse_magic) {
            if (cookie_header) |cookie| {
                if (extractMagicCookie(cookie)) |cookie_path| {
                    // Find the mapping for this cookie path
                    for (self.paths.items) |mapping| {
                        if (std.mem.eql(u8, mapping.path, cookie_path)) {
                            if (parseUrl(mapping.url)) |parsed| {
                                return .{
                                    .result = .{
                                        .host = parsed.host,
                                        .port = parsed.port,
                                        .path = request_path,
                                        .is_https = parsed.is_https,
                                    },
                                    .path_prefix = mapping.path,
                                };
                            }
                        }
                    }
                }
            }
        }

        return null;
    }

    /// Try to match and rewrite a request path
    /// Returns null if no mapping matches
    pub fn rewrite(self: *const Self, request_path: []const u8) ?RewriteResult {
        for (self.paths.items) |mapping| {
            if (std.mem.startsWith(u8, request_path, mapping.path)) {
                // Parse the target URL
                if (parseUrl(mapping.url)) |parsed| {
                    // Compute the remaining path after the prefix
                    const remaining = request_path[mapping.path.len..];

                    // Combine target URL path with remaining path
                    // Target URL path typically ends with /, remaining doesn't start with /
                    return .{
                        .host = parsed.host,
                        .port = parsed.port,
                        .path = if (remaining.len > 0) remaining else "/",
                        .is_https = parsed.is_https,
                    };
                }
            }
        }
        return null;
    }

    /// Parse a URL into components
    fn parseUrl(url: []const u8) ?struct {
        host: []const u8,
        port: u16,
        path: []const u8,
        is_https: bool,
    } {
        var is_https = false;
        var rest: []const u8 = url;

        // Check scheme
        if (std.mem.startsWith(u8, rest, "https://")) {
            is_https = true;
            rest = rest[8..];
        } else if (std.mem.startsWith(u8, rest, "http://")) {
            rest = rest[7..];
        } else {
            return null; // Invalid scheme
        }

        // Find path start
        const path_start = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
        const host_port = rest[0..path_start];
        const path = if (path_start < rest.len) rest[path_start..] else "/";

        // Parse host and port
        if (std.mem.lastIndexOfScalar(u8, host_port, ':')) |colon| {
            // Check if it's IPv6 address
            if (std.mem.indexOfScalar(u8, host_port[colon + 1 ..], ']') != null) {
                // IPv6 without port
                return .{
                    .host = host_port,
                    .port = if (is_https) 443 else 80,
                    .path = path,
                    .is_https = is_https,
                };
            }

            const port_str = host_port[colon + 1 ..];
            const port = std.fmt.parseInt(u16, port_str, 10) catch {
                return .{
                    .host = host_port,
                    .port = if (is_https) 443 else 80,
                    .path = path,
                    .is_https = is_https,
                };
            };

            return .{
                .host = host_port[0..colon],
                .port = port,
                .path = path,
                .is_https = is_https,
            };
        }

        return .{
            .host = host_port,
            .port = if (is_https) 443 else 80,
            .path = path,
            .is_https = is_https,
        };
    }
};

// ============================================================================
// Tests
// ============================================================================

test "ReverseProxy basic rewrite" {
    const allocator = std.testing.allocator;

    var rp = ReverseProxy.init(allocator);
    defer rp.deinit();

    try rp.addPath("/api", "http://backend:8080/");

    const result = rp.rewrite("/api/users");
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("backend", result.?.host);
    try std.testing.expectEqual(@as(u16, 8080), result.?.port);
    try std.testing.expectEqualStrings("/users", result.?.path);
    try std.testing.expect(!result.?.is_https);
}

test "ReverseProxy no match" {
    const allocator = std.testing.allocator;

    var rp = ReverseProxy.init(allocator);
    defer rp.deinit();

    try rp.addPath("/api", "http://backend:8080/");

    const result = rp.rewrite("/other/path");
    try std.testing.expect(result == null);
}

test "ReverseProxy https target" {
    const allocator = std.testing.allocator;

    var rp = ReverseProxy.init(allocator);
    defer rp.deinit();

    try rp.addPath("/secure", "https://secure-backend.example.com/");

    const result = rp.rewrite("/secure/login");
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("secure-backend.example.com", result.?.host);
    try std.testing.expectEqual(@as(u16, 443), result.?.port);
    try std.testing.expect(result.?.is_https);
}

test "ReverseProxy multiple mappings" {
    const allocator = std.testing.allocator;

    var rp = ReverseProxy.init(allocator);
    defer rp.deinit();

    try rp.addPath("/api", "http://api-server:8080/");
    try rp.addPath("/static", "http://cdn:80/assets/");
    try rp.addPath("/", "http://default:80/");

    // Should match /api first
    const api_result = rp.rewrite("/api/v1/users");
    try std.testing.expect(api_result != null);
    try std.testing.expectEqualStrings("api-server", api_result.?.host);

    // Should match /static
    const static_result = rp.rewrite("/static/image.png");
    try std.testing.expect(static_result != null);
    try std.testing.expectEqualStrings("cdn", static_result.?.host);
}

test "ReverseProxy hasMapping" {
    const allocator = std.testing.allocator;

    var rp = ReverseProxy.init(allocator);
    defer rp.deinit();

    try std.testing.expect(!rp.hasMapping());

    try rp.addPath("/api", "http://backend:8080/");
    try std.testing.expect(rp.hasMapping());
}

test "ReverseProxy parseUrl" {
    // Test via rewrite which uses parseUrl internally
    const allocator = std.testing.allocator;

    var rp = ReverseProxy.init(allocator);
    defer rp.deinit();

    // HTTP with port
    try rp.addPath("/a", "http://host:9000/path/");
    const r1 = rp.rewrite("/a/test");
    try std.testing.expect(r1 != null);
    try std.testing.expectEqualStrings("host", r1.?.host);
    try std.testing.expectEqual(@as(u16, 9000), r1.?.port);

    // Clear for next test
    for (rp.paths.items) |entry| {
        allocator.free(entry.path);
        allocator.free(entry.url);
    }
    rp.paths.clearRetainingCapacity();

    // HTTPS without port (default 443)
    try rp.addPath("/b", "https://secure.host/");
    const r2 = rp.rewrite("/b/data");
    try std.testing.expect(r2 != null);
    try std.testing.expectEqual(@as(u16, 443), r2.?.port);
    try std.testing.expect(r2.?.is_https);
}

test "extractMagicCookie parses cookie header" {
    // Single cookie
    const result1 = ReverseProxy.extractMagicCookie("TinyproxyReversePath=/api");
    try std.testing.expect(result1 != null);
    try std.testing.expectEqualStrings("/api", result1.?);

    // Multiple cookies
    const result2 = ReverseProxy.extractMagicCookie("session=abc123; TinyproxyReversePath=/static; other=value");
    try std.testing.expect(result2 != null);
    try std.testing.expectEqualStrings("/static", result2.?);

    // No magic cookie
    const result3 = ReverseProxy.extractMagicCookie("session=abc123; other=value");
    try std.testing.expect(result3 == null);

    // Empty value
    const result4 = ReverseProxy.extractMagicCookie("TinyproxyReversePath=");
    try std.testing.expect(result4 == null);
}

test "buildMagicCookie formats Set-Cookie header" {
    var buf: [128]u8 = undefined;
    const result = ReverseProxy.buildMagicCookie("/api", &buf);
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("TinyproxyReversePath=/api; Path=/", result.?);
}

test "rewriteWithMagic uses cookie fallback" {
    const allocator = std.testing.allocator;

    var rp = ReverseProxy.init(allocator);
    defer rp.deinit();
    rp.reverse_magic = true;

    try rp.addPath("/api", "http://api-server:8080/");

    // Normal path match works
    const result1 = rp.rewriteWithMagic("/api/users", null);
    try std.testing.expect(result1 != null);
    try std.testing.expectEqualStrings("api-server", result1.?.result.host);
    try std.testing.expectEqualStrings("/api", result1.?.path_prefix);

    // Cookie-based routing for non-matching path
    const cookie = "TinyproxyReversePath=/api";
    const result2 = rp.rewriteWithMagic("/some/other/path", cookie);
    try std.testing.expect(result2 != null);
    try std.testing.expectEqualStrings("api-server", result2.?.result.host);
    try std.testing.expectEqualStrings("/some/other/path", result2.?.result.path);

    // No match without cookie
    const result3 = rp.rewriteWithMagic("/some/other/path", null);
    try std.testing.expect(result3 == null);
}
