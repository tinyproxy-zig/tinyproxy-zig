const std = @import("std");

const zio = @import("zio");

const child = @import("child.zig");
const Config = @import("config.zig").Config;

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const conf = Config.init();
    const zrt = try zio.Runtime.init(allocator, .{ .num_executors = 1 });
    defer zrt.deinit();

    var handle = try zrt.spawn(main_task, .{ zrt, &conf }, .{});
    try handle.join(zrt);
}

fn main_task(rt: *zio.Runtime, conf: *const Config) !void {
    try child.listen_socket(rt, conf.listen, conf.port);
    try child.main_loop(rt);
}
