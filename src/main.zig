const std = @import("std");

const ziro = @import("ziro");
const aio = ziro.asyncio;

const child = @import("child.zig");
const config = @import("config.zig");
const Config = config.Config;
const runtime = @import("runtime.zig");
const Runtime = @import("runtime.zig").Runtime;
const RuntimeOptions = @import("runtime.zig").RuntimeOptions;

const log = std.log.scoped(.tinyproxy);

const STACK_SIZE = 1024 * 64; // default stack size for coroutine, in KB

pub fn main() !void {
    // init allocator
    var dbgalloc = std.heap.DebugAllocator(.{
        // .verbose_log = true,
    }).init;
    defer _ = dbgalloc.deinit();
    const allocator = dbgalloc.allocator();

    // init runtime
    var conf = Config.init();
    const options = RuntimeOptions{
        .stack_size = STACK_SIZE,
        .config = &conf,
    };
    var rt = try Runtime.init(allocator, options);
    defer rt.deinit();

    // run main coroutine
    try aio.run(rt.executor, main_coro, .{}, null);
}

fn main_coro() !void {
    const conf = runtime.runtime.config.*;
    try child.listen_socket(conf.listen, conf.port);
    try child.main_loop();
}
