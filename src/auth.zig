//! HTTP Basic Authentication Module for tinyproxy-zig
//!
//! Implements RFC 7617 HTTP Basic Authentication.
//! Supports multiple username/password pairs with optional password hashing.
//!
//! Usage:
//!   var auth = BasicAuth.init(allocator);
//!   defer auth.deinit();
//!   try auth.addUser("user", "password");
//!   try auth.addUserHashed("admin", "{SHA256}hashed_password_here");
//!   if (!auth.verify(auth_header)) {
//!       try sendAuthRequired(stream, rt, auth.realm);
//!       return;
//!   }

const std = @import("std");

const SHA256_DIGEST_LENGTH = 32;

/// Password storage format
const PasswordFormat = enum {
    /// Plain text password (default, backward compatible)
    plain,
    /// SHA-256 hash in hex format: {SHA256}hexstring
    sha256,
};

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

    /// Add a username/password pair (plain text, backward compatible)
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

    /// Add a username with pre-hashed password (SHA-256 hex format)
    /// Hash format: {SHA256}hex_digest
    pub fn addUserHashed(self: *Self, user: []const u8, hashed_pass: []const u8) !void {
        const user_duped = try self.allocator.dupe(u8, user);
        errdefer self.allocator.free(user_duped);

        const pass_duped = try self.allocator.dupe(u8, hashed_pass);
        errdefer self.allocator.free(pass_duped);

        // Remove old entry if exists
        if (self.credentials.fetchRemove(user_duped)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value);
        }

        try self.credentials.put(user_duped, pass_duped);
    }

    /// Add a username/password pair and store as SHA-256 hash
    pub fn addUserWithHash(self: *Self, user: []const u8, pass: []const u8) !void {
        const hash = try self.hashPassword(pass);
        errdefer self.allocator.free(hash);

        const user_duped = try self.allocator.dupe(u8, user);
        errdefer self.allocator.free(user_duped);

        // Remove old entry if exists
        if (self.credentials.fetchRemove(user_duped)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value);
        }

        // hash ownership is transferred to the hashmap
        try self.credentials.put(user_duped, hash);
    }

    /// Hash a password using SHA-256
    /// Returns: {SHA256}hex_digest format
    fn hashPassword(self: *Self, password: []const u8) ![]u8 {
        var digest: [SHA256_DIGEST_LENGTH]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(password, &digest, .{});

        // Format: {SHA256} + hex digest (64 chars)
        const formatted = try self.allocator.alloc(u8, 8 + SHA256_DIGEST_LENGTH * 2);
        @memcpy(formatted[0..8], "{SHA256}");

        // Convert digest to hex string manually
        const hex_chars = "0123456789abcdef";
        for (digest, 0..) |byte, i| {
            formatted[8 + i * 2] = hex_chars[byte >> 4];
            formatted[8 + i * 2 + 1] = hex_chars[byte & 0x0f];
        }
        return formatted;
    }

    /// Check if any credentials are configured
    pub fn hasCredentials(self: *const Self) bool {
        return self.credentials.count() > 0;
    }

    /// Verify the Authorization header
    /// Returns true if valid credentials, false otherwise
    /// Uses constant-time comparison to prevent timing attacks
    /// Supports both plain text and SHA-256 hashed passwords
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

        // Verify credentials using constant-time comparison
        if (self.credentials.get(user)) |stored_pass| {
            return verifyPassword(stored_pass, pass);
        }

        return false;
    }

    /// Verify a password against stored value (plain or hashed)
    fn verifyPassword(stored: []const u8, provided: []const u8) bool {
        const format = detectPasswordFormat(stored);

        return switch (format) {
            .plain => cryptoEq(u8, provided, stored),
            .sha256 => {
                // stored format: {SHA256}hex_digest
                if (stored.len < 9) return false; // {SHA256} + at least 1 char

                var digest: [SHA256_DIGEST_LENGTH]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(provided, &digest, .{});

                const hex_digest = stored[8..];
                if (hex_digest.len != SHA256_DIGEST_LENGTH * 2) return false;

                // Constant-time hex comparison
                var i: usize = 0;
                var result: u8 = 0;
                while (i < SHA256_DIGEST_LENGTH) : (i += 1) {
                    const upper = std.fmt.charToDigit(hex_digest[i * 2], 16) catch return false;
                    const lower = std.fmt.charToDigit(hex_digest[i * 2 + 1], 16) catch return false;
                    const stored_byte = (upper << 4) | lower;
                    result |= digest[i] ^ stored_byte;
                }
                return result == 0;
            },
        };
    }

    /// Detect password format from stored value
    fn detectPasswordFormat(stored: []const u8) PasswordFormat {
        if (std.mem.startsWith(u8, stored, "{SHA256}")) {
            return .sha256;
        }
        return .plain;
    }

    /// Constant-time equality check to prevent timing attacks
    inline fn cryptoEq(comptime T: type, a: []const T, b: []const T) bool {
        if (a.len != b.len) return false;
        var result: T = 0;
        for (a, 0..) |x, i| {
            result |= x ^ b[i];
        }
        return result == 0;
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

test "BasicAuth SHA-256 hashed password" {
    var auth = BasicAuth.init(std.testing.allocator);
    defer auth.deinit();

    // Add user with SHA-256 hashed password
    // Hash of "secret123": fcf730b6d95236ecd3c9fc2d92d7b6b2bb061514961aec041d6c7a7192f592e4
    try auth.addUserHashed("alice", "{SHA256}fcf730b6d95236ecd3c9fc2d92d7b6b2bb061514961aec041d6c7a7192f592e4");

    // base64 of "alice:secret123"
    try std.testing.expect(auth.verify("Basic YWxpY2U6c2VjcmV0MTIz"));

    // Wrong password
    try std.testing.expect(!auth.verify("Basic YWxpY2U6d3JvbmdwYXNz"));
}

test "BasicAuth addUserWithHash" {
    var auth = BasicAuth.init(std.testing.allocator);
    defer auth.deinit();

    try auth.addUserWithHash("bob", "password123");

    // base64 of "bob:password123"
    try std.testing.expect(auth.verify("Basic Ym9iOnBhc3N3b3JkMTIz"));

    // Wrong password
    try std.testing.expect(!auth.verify("Basic Ym9iOnBhc3N3b3Jk"));
}

test "BasicAuth mixed plain and hashed passwords" {
    var auth = BasicAuth.init(std.testing.allocator);
    defer auth.deinit();

    // Plain text password
    try auth.addUser("plain_user", "plain_pass");

    // Hashed password (hash of "hash_pass")
    // 4c3c07ef6d98b08f7099dac843f0d556de7e42d133b9505c20444fd70b34e500
    try auth.addUserHashed("hash_user", "{SHA256}4c3c07ef6d98b08f7099dac843f0d556de7e42d133b9505c20444fd70b34e500");

    // base64 of "plain_user:plain_pass"
    try std.testing.expect(auth.verify("Basic cGxhaW5fdXNlcjpwbGFpbl9wYXNz"));

    // base64 of "hash_user:hash_pass"
    try std.testing.expect(auth.verify("Basic aGFzaF91c2VyOmhhc2hfcGFzcw=="));

    // Wrong passwords should fail
    try std.testing.expect(!auth.verify("Basic cGxhaW5fdXNlcjp3cm9uZw=="));
    try std.testing.expect(!auth.verify("Basic aGFzaF91c2VyOndyb25n"));
}
