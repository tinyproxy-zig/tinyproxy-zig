//! Upstream Proxy Management
//!
//! Handles parsing and selection of upstream proxies (HTTP/SOCKS).
//! Support for NoUpstream exceptions.

const std = @import("std");
const acl = @import("acl.zig");
const HostSpec = acl.HostSpec;

pub const ProxyType = enum {
    http,
    socks4,
    socks5,
};

pub const UpstreamProxy = struct {
    proxy_type: ProxyType,
    host: []const u8,
    port: u16,
    user: ?[]const u8 = null,
    pass: ?[]const u8 = null,
    match: ?HostSpec = null, // Optional target domain/IP match
};

pub const UpstreamManager = struct {
    allocator: std.mem.Allocator,
    proxies: std.ArrayList(UpstreamProxy),
    no_upstream: std.ArrayList(HostSpec),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .proxies = .empty,
            .no_upstream = .empty,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.proxies.items) |p| {
            self.allocator.free(p.host);
            if (p.user) |u| self.allocator.free(u);
            if (p.pass) |pw| self.allocator.free(pw);
            if (p.match) |m| m.deinit(self.allocator);
        }
        self.proxies.deinit(self.allocator);

        for (self.no_upstream.items) |item| {
            item.deinit(self.allocator);
        }
        self.no_upstream.deinit(self.allocator);
    }

    /// Add a NoUpstream rule
    pub fn addNoUpstream(self: *Self, spec_str: []const u8) !void {
        // Strip quotes if present
        const trimmed = std.mem.trim(u8, spec_str, " \t\"'");
        const spec = try HostSpec.parse(self.allocator, trimmed);
        try self.no_upstream.append(self.allocator, spec);
    }

    /// Add an Upstream rule
    /// Format: type (user:pass@)?host:port [domain]
    pub fn addUpstream(self: *Self, value: []const u8) !void {
        var iter = std.mem.tokenizeAny(u8, value, " \t");

        // 1. Type
        const type_str = iter.next() orelse return error.InvalidUpstreamFormat;
        const proxy_type: ProxyType = if (std.ascii.eqlIgnoreCase(type_str, "http")) .http else if (std.ascii.eqlIgnoreCase(type_str, "socks4")) .socks4 else if (std.ascii.eqlIgnoreCase(type_str, "socks5")) .socks5 else return error.InvalidProxyType;

        // 2. Address (user:pass@host:port)
        const addr_str = iter.next() orelse return error.InvalidUpstreamFormat;

        var user: ?[]const u8 = null;
        var pass: ?[]const u8 = null;
        var host_port_str = addr_str;

        // Check for user:pass@
        if (std.mem.lastIndexOfScalar(u8, addr_str, '@')) |at_pos| {
            const auth_part = addr_str[0..at_pos];
            host_port_str = addr_str[at_pos + 1 ..];

            if (std.mem.indexOfScalar(u8, auth_part, ':')) |colon_pos| {
                user = try self.allocator.dupe(u8, auth_part[0..colon_pos]);
                pass = try self.allocator.dupe(u8, auth_part[colon_pos + 1 ..]);
            } else {
                user = try self.allocator.dupe(u8, auth_part);
            }
        }
        errdefer {
            if (user) |u| self.allocator.free(u);
            if (pass) |p| self.allocator.free(p);
        }

        // Parse host:port
        const colon_pos = std.mem.lastIndexOfScalar(u8, host_port_str, ':') orelse return error.InvalidUpstreamAddress;
        if (colon_pos == 0) return error.InvalidUpstreamAddress;

        const host_part = host_port_str[0..colon_pos];
        const port_part = host_port_str[colon_pos + 1 ..];

        const host = try self.allocator.dupe(u8, host_part);
        errdefer self.allocator.free(host);

        const port = std.fmt.parseInt(u16, port_part, 10) catch return error.InvalidPort;

        // 3. Optional Match Spec
        var match: ?HostSpec = null;
        if (iter.next()) |match_str| {
            // Strip quotes
            const trimmed_match = std.mem.trim(u8, match_str, "\"'");
            match = try HostSpec.parse(self.allocator, trimmed_match);
        }
        errdefer if (match) |m| m.deinit(self.allocator);

        try self.proxies.append(self.allocator, .{
            .proxy_type = proxy_type,
            .host = host,
            .port = port,
            .user = user,
            .pass = pass,
            .match = match,
        });
    }

    /// Find the best upstream for a given host
    pub fn findUpstream(self: *const Self, host: []const u8) ?*const UpstreamProxy {
        // 1. Check NoUpstream rules
        for (self.no_upstream.items) |spec| {
            if (spec.matchesHost(host)) return null;
        }

        // 2. Check Upstream rules in order
        for (self.proxies.items) |*p| {
            if (p.match) |spec| {
                if (spec.matchesHost(host)) return p;
            } else {
                // Default upstream matches everything not already excluded or matched?
                // Tinyproxy treats upstream without domain as default.
                // We return it.
                return p;
            }
        }

        return null;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "UpstreamManager basic http" {
    var mgr = UpstreamManager.init(std.testing.allocator);
    defer mgr.deinit();

    try mgr.addUpstream("http 127.0.0.1:8080");

    const p = mgr.findUpstream("example.com");
    try std.testing.expect(p != null);
    try std.testing.expectEqual(ProxyType.http, p.?.proxy_type);
    try std.testing.expectEqualStrings("127.0.0.1", p.?.host);
    try std.testing.expectEqual(8080, p.?.port);
}

test "UpstreamManager auth and matching" {
    var mgr = UpstreamManager.init(std.testing.allocator);
    defer mgr.deinit();

    // Specific rule for .onion
    try mgr.addUpstream("socks5 user:pass@127.0.0.1:9050 .onion");

    // Default rule
    try mgr.addUpstream("http 10.0.0.1:3128");

    // Check .onion
    const p1 = mgr.findUpstream("secret.onion");
    try std.testing.expect(p1 != null);
    try std.testing.expectEqual(ProxyType.socks5, p1.?.proxy_type);
    try std.testing.expectEqualStrings("user", p1.?.user.?);
    try std.testing.expectEqualStrings("pass", p1.?.pass.?);

    // Check others
    const p2 = mgr.findUpstream("google.com");
    try std.testing.expect(p2 != null);
    try std.testing.expectEqual(ProxyType.http, p2.?.proxy_type);
    try std.testing.expectEqualStrings("10.0.0.1", p2.?.host);
}

test "UpstreamManager no upstream" {
    var mgr = UpstreamManager.init(std.testing.allocator);
    defer mgr.deinit();

    try mgr.addNoUpstream(".local");
    try mgr.addUpstream("http 10.0.0.1:8080");

    const p1 = mgr.findUpstream("my.local");
    try std.testing.expect(p1 == null);

    const p2 = mgr.findUpstream("google.com");
    try std.testing.expect(p2 != null);
}
