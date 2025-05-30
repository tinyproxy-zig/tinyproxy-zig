const std = @import("std");

const child = @import("child.zig");

const log = std.log.scoped(.tinyproxy);

const LISTEN_ADDR: []const u8 = "127.0.0.1";
const LISTEN_PORT: u16 = 9999;

pub fn main() !void {
    log.info("listening on {s}:{}", .{LISTEN_ADDR, LISTEN_PORT});
    try child.listen_sockets(LISTEN_ADDR, LISTEN_PORT);
    try child.main_loop();
}
