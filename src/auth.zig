//! HTTP Basic Authentication Module for tinyproxy-zig
//!
//! Implements RFC 7617 HTTP Basic Authentication.
//! Supports multiple username/password pairs.
//!
//! Usage:
//!   var auth = BasicAuth.init(allocator);
//!   defer auth.deinit();
//!   try auth.addUser("user", "password");
//!   if (!auth.verify(auth_header)) {
//!       try sendAuthRequired(stream, rt, auth.realm);
//!       return;
//!   }

const std = @import("std");

/// HTTP Basic Authentication handler
pub const BasicAuth = struct {
    /// Username -> Password hash map
    credentials: std.StringHashMap([]const u8),
    /// Realm for WWW-Authenticate header
    realm: []const u8 = "tinyproxy",
    realm_owned: bool = false,
    /// Allocator for dynamic allocations
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Initialize an empty BasicAuth
    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .credentials = std.StringHashMap([]const u8).init(allocator),
            .allocator = allocator,
        };
    }

    /// Set a custom realm
    pub fn setRealm(self: *Self, realm: []const u8) !void {
        const duped = try self.allocator.dupe(u8, realm);
        if (self.realm_owned) {
            self.allocator.free(@constCast(self.realm));
        }
        self.realm = duped;
        self.realm_owned = true;
    }

    /// Add a username/password pair
    pub fn addUser(self: *Self, user: []const u8, pass: []const u8) !void {
        const user_duped = try self.allocator.dupe(u8, user);
        errdefer self.allocator.free(user_duped);

        const pass_duped = try self.allocator.dupe(u8, pass);
        errdefer self.allocator.free(pass_duped);

        // Remove old entry if exists
        if (self.credentials.fetchRemove(user_duped)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value);
        }

        try self.credentials.put(user_duped, pass_duped);
    }

    /// Check if any credentials are configured
    pub fn hasCredentials(self: *const Self) bool {
        return self.credentials.count() > 0;
    }

    /// Verify the Authorization header
    /// Returns true if valid credentials, false otherwise
    pub fn verify(self: *const Self, auth_header: ?[]const u8) bool {
        const header = auth_header orelse return false;

        // Must start with "Basic "
        if (!std.ascii.startsWithIgnoreCase(header, "Basic ")) {
            return false;
        }

        const encoded = std.mem.trim(u8, header[6..], " \t");
        if (encoded.len == 0) return false;

        // Decode Base64 with larger buffer for long credentials
        // Base64 encoded data is 4/3 the size of decoded, so max input is ~4300 bytes
        var decoded_buf: [4096]u8 = undefined;
        const decoded = base64Decode(encoded, &decoded_buf) catch return false;

        // Split into user:password
        const colon_pos = std.mem.indexOfScalar(u8, decoded, ':') orelse return false;
        const user = decoded[0..colon_pos];
        const pass = decoded[colon_pos + 1 ..];

        // Verify credentials
        if (self.credentials.get(user)) |stored_pass| {
            return std.mem.eql(u8, pass, stored_pass);
        }

        return false;
    }

    /// Free all resources
    pub fn deinit(self: *Self) void {
        var it = self.credentials.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.credentials.deinit();

        if (self.realm_owned) {
            self.allocator.free(@constCast(self.realm));
        }
    }
};

/// Base64 decode (RFC 4648)
fn base64Decode(encoded: []const u8, dest: []u8) ![]u8 {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    var out_idx: usize = 0;
    var buf: u32 = 0;
    var buf_len: u3 = 0;

    for (encoded) |c| {
        if (c == '=') break; // Padding
        if (c == ' ' or c == '\t' or c == '\n' or c == '\r') continue; // Skip whitespace

        const val: u6 = blk: {
            for (alphabet, 0..) |a, i| {
                if (c == a) break :blk @intCast(i);
            }
            return error.InvalidBase64;
        };

        buf = (buf << 6) | val;
        buf_len += 1;

        if (buf_len == 4) {
            if (out_idx + 3 > dest.len) return error.NoSpaceLeft;
            dest[out_idx] = @intCast((buf >> 16) & 0xFF);
            dest[out_idx + 1] = @intCast((buf >> 8) & 0xFF);
            dest[out_idx + 2] = @intCast(buf & 0xFF);
            out_idx += 3;
            buf = 0;
            buf_len = 0;
        }
    }

    // Handle remaining bytes
    switch (buf_len) {
        2 => {
            if (out_idx + 1 > dest.len) return error.NoSpaceLeft;
            dest[out_idx] = @intCast((buf >> 4) & 0xFF);
            out_idx += 1;
        },
        3 => {
            if (out_idx + 2 > dest.len) return error.NoSpaceLeft;
            dest[out_idx] = @intCast((buf >> 10) & 0xFF);
            dest[out_idx + 1] = @intCast((buf >> 2) & 0xFF);
            out_idx += 2;
        },
        else => {},
    }

    return dest[0..out_idx];
}

/// Build a 407 Proxy Authentication Required response
pub fn build407Response(realm: []const u8, buf: []u8) ![]u8 {
    return std.fmt.bufPrint(buf,
        \\HTTP/1.1 407 Proxy Authentication Required
        \\Proxy-Authenticate: Basic realm="{s}"
        \\Content-Type: text/html
        \\Content-Length: 42
        \\Connection: close
        \\
        \\<html><body>Authentication required</body>
    , .{realm});
}

// ============================================================================
// Tests
// ============================================================================

test "BasicAuth add and verify user" {
    var auth = BasicAuth.init(std.testing.allocator);
    defer auth.deinit();

    try auth.addUser("admin", "secret123");

    // Valid credentials (base64 of "admin:secret123")
    try std.testing.expect(auth.verify("Basic YWRtaW46c2VjcmV0MTIz"));

    // Wrong password
    try std.testing.expect(!auth.verify("Basic YWRtaW46d3JvbmdwYXNz"));

    // Wrong user
    try std.testing.expect(!auth.verify("Basic dXNlcjpzZWNyZXQxMjM="));

    // No header
    try std.testing.expect(!auth.verify(null));

    // Invalid scheme
    try std.testing.expect(!auth.verify("Bearer token123"));
}

test "BasicAuth multiple users" {
    var auth = BasicAuth.init(std.testing.allocator);
    defer auth.deinit();

    try auth.addUser("alice", "password1");
    try auth.addUser("bob", "password2");

    // base64 of "alice:password1"
    try std.testing.expect(auth.verify("Basic YWxpY2U6cGFzc3dvcmQx"));

    // base64 of "bob:password2"
    try std.testing.expect(auth.verify("Basic Ym9iOnBhc3N3b3JkMg=="));
}

test "base64 decode" {
    var buf: [64]u8 = undefined;

    // "Hello" -> "SGVsbG8="
    const result1 = try base64Decode("SGVsbG8=", &buf);
    try std.testing.expectEqualStrings("Hello", result1);

    // "user:pass" -> "dXNlcjpwYXNz"
    const result2 = try base64Decode("dXNlcjpwYXNz", &buf);
    try std.testing.expectEqualStrings("user:pass", result2);

    // "admin:secret123" -> "YWRtaW46c2VjcmV0MTIz"
    const result3 = try base64Decode("YWRtaW46c2VjcmV0MTIz", &buf);
    try std.testing.expectEqualStrings("admin:secret123", result3);
}

test "build 407 response" {
    var buf: [512]u8 = undefined;
    const response = try build407Response("tinyproxy", &buf);

    try std.testing.expect(std.mem.indexOf(u8, response, "407 Proxy Authentication Required") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "realm=\"tinyproxy\"") != null);
}

test "BasicAuth hasCredentials" {
    var auth = BasicAuth.init(std.testing.allocator);
    defer auth.deinit();

    try std.testing.expect(!auth.hasCredentials());

    try auth.addUser("user", "pass");

    try std.testing.expect(auth.hasCredentials());
}
