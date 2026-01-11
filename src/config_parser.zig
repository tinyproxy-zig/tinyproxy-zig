const std = @import("std");
const Config = @import("config.zig").Config;

const sample =
    "[core]\n" ++
    "listen = 127.0.0.1\n" ++
    "port = 8080\n" ++
    "idle_timeout = 60\n" ++
    "max_clients = 50\n";

test "parse simple config" {
    var cfg = try parseText(std.testing.allocator, sample);
    defer cfg.deinit();

    try std.testing.expectEqualStrings("127.0.0.1", cfg.listen);
    try std.testing.expectEqual(@as(u16, 8080), cfg.port);
    try std.testing.expectEqual(@as(u32, 60), cfg.idle_timeout);
    try std.testing.expectEqual(@as(usize, 50), cfg.max_clients);
}

pub fn parseText(allocator: std.mem.Allocator, text: []const u8) !Config {
    _ = allocator;
    var cfg = Config.init();
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        if (line[0] == '[') continue;

        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = std.mem.trim(u8, line[0..eq], " \t");
        const val = std.mem.trim(u8, line[eq + 1 ..], " \t");

        if (std.mem.eql(u8, key, "listen")) {
            cfg.listen = val;
        } else if (std.mem.eql(u8, key, "port")) {
            cfg.port = try std.fmt.parseInt(u16, val, 10);
        } else if (std.mem.eql(u8, key, "idle_timeout")) {
            cfg.idle_timeout = try std.fmt.parseInt(u32, val, 10);
        } else if (std.mem.eql(u8, key, "max_clients")) {
            cfg.max_clients = try std.fmt.parseInt(usize, val, 10);
        }
    }
    return cfg;
}
