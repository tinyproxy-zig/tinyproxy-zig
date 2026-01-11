const std = @import("std");
const Config = @import("config.zig").Config;

const sample =
    "Port 8888\n" ++
    "Listen 0.0.0.0\n" ++
    "Timeout 120\n" ++
    "MaxClients 25\n";

test "parse tinyproxy.conf subset" {
    var cfg = try parseText(std.testing.allocator, sample);
    defer cfg.deinit();

    try std.testing.expectEqual(@as(u16, 8888), cfg.port);
    try std.testing.expectEqualStrings("0.0.0.0", cfg.listen);
    try std.testing.expectEqual(@as(u32, 120), cfg.idle_timeout);
    try std.testing.expectEqual(@as(usize, 25), cfg.max_clients);
}

pub fn parseText(allocator: std.mem.Allocator, text: []const u8) !Config {
    _ = allocator;
    var cfg = Config.init();
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;

        if (std.mem.startsWith(u8, line, "Port ")) {
            cfg.port = try std.fmt.parseInt(u16, line[5..], 10);
        } else if (std.mem.startsWith(u8, line, "Listen ")) {
            cfg.listen = line[7..];
        } else if (std.mem.startsWith(u8, line, "Timeout ")) {
            cfg.idle_timeout = try std.fmt.parseInt(u32, line[8..], 10);
        } else if (std.mem.startsWith(u8, line, "MaxClients ")) {
            cfg.max_clients = try std.fmt.parseInt(usize, line[11..], 10);
        }
    }
    return cfg;
}
