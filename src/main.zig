const std = @import("std");

const child = @import("child.zig");

const log = std.log.scoped(.tinyproxy);

pub fn main() !void {
    log.info("listening on 127.0.0.1:9900", .{});
    try child.listen_sockets("127.0.0.1", 9900);
    try child.main_loop();
}
