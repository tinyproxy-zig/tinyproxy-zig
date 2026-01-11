const std = @import("std");

const zio = @import("zio");

const child = @import("child.zig");
const Config = @import("config.zig").Config;
const runtime_mod = @import("runtime.zig");
const Runtime = runtime_mod.Runtime;

pub fn main() !void {
    // init allocator
    var dbgalloc = std.heap.DebugAllocator(.{
        // .verbose_log = true,
    }).init;
    defer _ = dbgalloc.deinit();
    const allocator = dbgalloc.allocator();

    var conf = Config.init();
    var rt = try Runtime.init(allocator, .{ .config = &conf });
    defer rt.deinit();

    var handle = try rt.zio_rt.spawn(main_task, .{ rt.zio_rt }, .{});
    try handle.join(rt.zio_rt);
}

fn main_task(rt: *zio.Runtime) !void {
    const conf = runtime_mod.runtime.config.*;
    try child.listen_socket(rt, conf.listen, conf.port);
    try child.main_loop(rt);
}
