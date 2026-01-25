//! CONNECT Port Restriction Module
//!
//! Restricts which ports can be accessed via the HTTP CONNECT method.
//! This prevents abuse of the proxy for accessing arbitrary services.

const std = @import("std");
const Config = @import("config.zig").Config;
const PortRange = @import("config.zig").PortRange;

/// Common secure ports that should typically be allowed for CONNECT
pub const common_ssl_ports = [_]u16{
    443, // HTTPS
    563, // NNTPS
    636, // LDAPS
    853, // DNS over TLS
    993, // IMAPS
    995, // POP3S
};

/// Check if a port should be allowed for CONNECT based on config.
/// Returns an error with the reason if denied.
pub const ConnectCheckResult = union(enum) {
    allowed: void,
    denied: DenyReason,
};

pub const DenyReason = enum {
    port_not_in_whitelist,
    port_zero,
    port_privileged, // For future use with config option
};

/// Check if CONNECT to a specific port is allowed
pub fn checkConnectPort(config: *const Config, port: u16) ConnectCheckResult {
    // Port 0 is never valid
    if (port == 0) {
        return .{ .denied = .port_zero };
    }

    // Check against config whitelist
    if (!config.isConnectPortAllowed(port)) {
        return .{ .denied = .port_not_in_whitelist };
    }

    return .{ .allowed = {} };
}

/// Parse a port specification string (e.g., "443", "8000-9000")
pub fn parsePortSpec(spec: []const u8) !PortRange {
    const trimmed = std.mem.trim(u8, spec, " \t\r\n");

    // Check for range (contains '-')
    if (std.mem.indexOfScalar(u8, trimmed, '-')) |dash_pos| {
        const min_str = std.mem.trim(u8, trimmed[0..dash_pos], " \t");
        const max_str = std.mem.trim(u8, trimmed[dash_pos + 1 ..], " \t");

        const min = std.fmt.parseInt(u16, min_str, 10) catch return error.InvalidPortSpec;
        const max = std.fmt.parseInt(u16, max_str, 10) catch return error.InvalidPortSpec;

        if (min > max) return error.InvalidPortRange;
        if (min == 0) return error.InvalidPortSpec;

        return .{ .min = min, .max = max };
    }

    // Single port
    const port = std.fmt.parseInt(u16, trimmed, 10) catch return error.InvalidPortSpec;
    if (port == 0) return error.InvalidPortSpec;

    return PortRange.single(port);
}

/// Format a deny reason as a human-readable string
pub fn formatDenyReason(reason: DenyReason) []const u8 {
    return switch (reason) {
        .port_not_in_whitelist => "Port not in allowed list for CONNECT",
        .port_zero => "Invalid port 0",
        .port_privileged => "Privileged port not allowed",
    };
}

/// Add common SSL ports to config whitelist
pub fn addCommonSslPorts(config: *Config) !void {
    for (common_ssl_ports) |port| {
        try config.allowConnectPort(port);
    }
}

// ============================================================================
// Tests
// ============================================================================

test "checkConnectPort with empty config allows all" {
    const allocator = std.testing.allocator;
    var config = Config.init(allocator);
    defer config.deinit();

    try std.testing.expectEqual(ConnectCheckResult{ .allowed = {} }, checkConnectPort(&config, 443));
    try std.testing.expectEqual(ConnectCheckResult{ .allowed = {} }, checkConnectPort(&config, 80));
    try std.testing.expectEqual(ConnectCheckResult{ .allowed = {} }, checkConnectPort(&config, 8080));
}

test "checkConnectPort denies port 0" {
    const allocator = std.testing.allocator;
    var config = Config.init(allocator);
    defer config.deinit();

    const result = checkConnectPort(&config, 0);
    try std.testing.expect(result == .denied);
    try std.testing.expectEqual(DenyReason.port_zero, result.denied);
}

test "checkConnectPort with whitelist" {
    const allocator = std.testing.allocator;
    var config = Config.init(allocator);
    defer config.deinit();

    try config.allowConnectPort(443);
    try config.allowConnectPort(563);

    try std.testing.expectEqual(ConnectCheckResult{ .allowed = {} }, checkConnectPort(&config, 443));
    try std.testing.expectEqual(ConnectCheckResult{ .allowed = {} }, checkConnectPort(&config, 563));

    const denied = checkConnectPort(&config, 80);
    try std.testing.expect(denied == .denied);
    try std.testing.expectEqual(DenyReason.port_not_in_whitelist, denied.denied);
}

test "checkConnectPort with range" {
    const allocator = std.testing.allocator;
    var config = Config.init(allocator);
    defer config.deinit();

    try config.allowConnectPortRange(8000, 9000);

    try std.testing.expectEqual(ConnectCheckResult{ .allowed = {} }, checkConnectPort(&config, 8000));
    try std.testing.expectEqual(ConnectCheckResult{ .allowed = {} }, checkConnectPort(&config, 8500));
    try std.testing.expectEqual(ConnectCheckResult{ .allowed = {} }, checkConnectPort(&config, 9000));

    const denied = checkConnectPort(&config, 7999);
    try std.testing.expect(denied == .denied);
}

test "parsePortSpec single port" {
    const range = try parsePortSpec("443");
    try std.testing.expectEqual(@as(u16, 443), range.min);
    try std.testing.expectEqual(@as(u16, 443), range.max);
}

test "parsePortSpec range" {
    const range = try parsePortSpec("8000-9000");
    try std.testing.expectEqual(@as(u16, 8000), range.min);
    try std.testing.expectEqual(@as(u16, 9000), range.max);
}

test "parsePortSpec invalid" {
    try std.testing.expectError(error.InvalidPortSpec, parsePortSpec("abc"));
    try std.testing.expectError(error.InvalidPortSpec, parsePortSpec("0"));
    try std.testing.expectError(error.InvalidPortRange, parsePortSpec("9000-8000"));
}

test "addCommonSslPorts" {
    const allocator = std.testing.allocator;
    var config = Config.init(allocator);
    defer config.deinit();

    try addCommonSslPorts(&config);

    try std.testing.expectEqual(ConnectCheckResult{ .allowed = {} }, checkConnectPort(&config, 443));
    try std.testing.expectEqual(ConnectCheckResult{ .allowed = {} }, checkConnectPort(&config, 993));

    const denied = checkConnectPort(&config, 80);
    try std.testing.expect(denied == .denied);
}
