//! Anonymous Mode Module
//!
//! When enabled, only whitelisted headers are forwarded to upstream servers.
//! This helps hide client information and provides privacy.

const std = @import("std");
const http = @import("http.zig");
const Config = @import("config.zig").Config;

/// Essential headers that are ALWAYS allowed regardless of whitelist
/// These are required for HTTP to function correctly
const essential_headers = [_][]const u8{
    "content-length",
    "content-type",
    "transfer-encoding",
};

/// Headers that are always blocked in anonymous mode
/// Even if explicitly whitelisted, these reveal client identity
/// Note: 'via' is NOT blocked here - we add our own Via header after filtering
pub const always_blocked_headers = [_][]const u8{
    "x-forwarded-for",
    "x-real-ip",
    "x-client-ip",
    "forwarded",
    "client-ip",
};

/// Check if a header is always blocked
fn isAlwaysBlocked(name: []const u8) bool {
    for (always_blocked_headers) |blocked| {
        if (std.ascii.eqlIgnoreCase(name, blocked)) {
            return true;
        }
    }
    return false;
}

/// Check if a header is essential (always allowed)
fn isEssential(name: []const u8) bool {
    for (essential_headers) |essential| {
        if (std.ascii.eqlIgnoreCase(name, essential)) {
            return true;
        }
    }
    return false;
}

/// Filter headers based on anonymous mode whitelist.
/// Removes headers not in the whitelist.
/// Only whitelist + essential headers are kept.
pub fn filterHeaders(message: *http.HttpMessage, config: *const Config) void {
    if (!config.anonymous_enabled) return;
    if (config.anonymous_headers.count() == 0) return;

    // Iterate backwards to safely remove
    var i: usize = message.header_list.items.len;
    while (i > 0) {
        i -= 1;
        const header = message.header_list.items[i];

        // Check if header should be kept
        const should_keep = blk: {
            // Always block certain headers (identity-revealing)
            if (isAlwaysBlocked(header.name)) break :blk false;

            // Essential headers are always allowed (HTTP needs them)
            if (isEssential(header.name)) break :blk true;

            // Only whitelist + essential
            if (config.isAnonymousHeaderAllowed(header.name)) break :blk true;
            break :blk false;
        };

        if (!should_keep) {
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

/// Get a list of headers that would be removed in anonymous mode (for logging)
pub fn getBlockedHeaders(
    allocator: std.mem.Allocator,
    message: *const http.HttpMessage,
    config: *const Config,
) !std.ArrayList([]const u8) {
    var blocked = std.ArrayList([]const u8).empty;
    errdefer {
        // Free all allocated strings before deinit
        for (blocked.items) |name| {
            allocator.free(name);
        }
        blocked.deinit(allocator);
    }

    if (!config.anonymous_enabled) return blocked;
    if (config.anonymous_headers.count() == 0) return blocked;

    for (message.header_list.items) |header| {
        const would_block = blk: {
            if (isAlwaysBlocked(header.name)) break :blk true;
            if (isEssential(header.name)) break :blk false;

            if (config.isAnonymousHeaderAllowed(header.name)) break :blk false;
            break :blk true;
        };

        if (would_block) {
            const name = try allocator.dupe(u8, header.name);
            try blocked.append(allocator, name);
        }
    }

    return blocked;
}

// ============================================================================
// Tests
// ============================================================================

test "anonymous mode disabled does nothing" {
    const allocator = std.testing.allocator;

    var config = Config.init(allocator);
    defer config.deinit();
    config.anonymous_enabled = false;

    var message = http.HttpMessage.init(allocator);
    defer message.deinit();

    // Add some headers
    const ua_name = try allocator.dupe(u8, "user-agent");
    const ua_value = try allocator.dupe(u8, "Mozilla/5.0");
    try message.header_list.append(allocator, .{ .name = ua_name, .value = ua_value });
    try message.headers.put(ua_name, ua_value);

    filterHeaders(&message, &config);

    // Should still have the header
    try std.testing.expectEqual(@as(usize, 1), message.header_list.items.len);
}

test "anonymous mode filters non-whitelisted headers" {
    const allocator = std.testing.allocator;

    var config = Config.init(allocator);
    defer config.deinit();
    config.anonymous_enabled = true;
    try config.allowAnonymousHeader("Accept");

    var message = http.HttpMessage.init(allocator);
    defer message.deinit();

    // Add Host (not whitelisted; removed)
    const host_name = try allocator.dupe(u8, "host");
    const host_value = try allocator.dupe(u8, "example.com");
    try message.header_list.append(allocator, .{ .name = host_name, .value = host_value });
    try message.headers.put(host_name, host_value);

    // Add User-Agent (not whitelisted)
    const ua_name = try allocator.dupe(u8, "user-agent");
    const ua_value = try allocator.dupe(u8, "Mozilla/5.0");
    try message.header_list.append(allocator, .{ .name = ua_name, .value = ua_value });
    try message.headers.put(ua_name, ua_value);

    // Add Accept (whitelisted)
    const accept_name = try allocator.dupe(u8, "accept");
    const accept_value = try allocator.dupe(u8, "text/html");
    try message.header_list.append(allocator, .{ .name = accept_name, .value = accept_value });
    try message.headers.put(accept_name, accept_value);

    filterHeaders(&message, &config);

    // Should only have whitelisted Accept
    try std.testing.expectEqual(@as(usize, 1), message.header_list.items.len);
    try std.testing.expect(message.headers.get("host") == null);
    try std.testing.expect(message.headers.get("accept") != null);
    try std.testing.expect(message.headers.get("user-agent") == null);
}

test "anonymous mode blocks x-forwarded-for even if whitelisted" {
    const allocator = std.testing.allocator;

    var config = Config.init(allocator);
    defer config.deinit();
    config.anonymous_enabled = true;

    // Try to whitelist X-Forwarded-For
    try config.allowAnonymousHeader("X-Forwarded-For");

    var message = http.HttpMessage.init(allocator);
    defer message.deinit();

    const xff_name = try allocator.dupe(u8, "x-forwarded-for");
    const xff_value = try allocator.dupe(u8, "192.168.1.1");
    try message.header_list.append(allocator, .{ .name = xff_name, .value = xff_value });
    try message.headers.put(xff_name, xff_value);

    filterHeaders(&message, &config);

    // Should be blocked
    try std.testing.expectEqual(@as(usize, 0), message.header_list.items.len);
}

test "anonymous mode custom whitelist" {
    const allocator = std.testing.allocator;

    var config = Config.init(allocator);
    defer config.deinit();
    config.anonymous_enabled = true;

    // Add custom header to whitelist
    try config.allowAnonymousHeader("X-Custom-Header");

    var message = http.HttpMessage.init(allocator);
    defer message.deinit();

    const custom_name = try allocator.dupe(u8, "x-custom-header");
    const custom_value = try allocator.dupe(u8, "custom-value");
    try message.header_list.append(allocator, .{ .name = custom_name, .value = custom_value });
    try message.headers.put(custom_name, custom_value);

    filterHeaders(&message, &config);

    // Should be kept
    try std.testing.expectEqual(@as(usize, 1), message.header_list.items.len);
}
