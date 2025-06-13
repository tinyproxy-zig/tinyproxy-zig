const std = @import("std");

const ziro = @import("ziro");
const aio = ziro.asyncio;

const Connection = @import("connection.zig").Connection;
const Pool = @import("pool.zig").Pool;
const PoolKind = @import("pool.zig").PoolKind;
const request = @import("request.zig");
const runtime = @import("runtime.zig");
const socket = @import("socket.zig");

const log = std.log.scoped(.@"tinyproxy/child");
const CLIENT_COUNT: usize = 128;

/// a listening socket server
/// TODO: will be a list of listening socket servers
var server: aio.TCP = undefined;

/// a list of `Child` objects
var childs: Pool(Child) = undefined;
var released: std.ArrayListUnmanaged(usize) = undefined;

const Child = struct {
    coro: ziro.Frame = undefined,
    conn: Connection,
    done: bool = false,
    index: usize,
};

/// create a listening socker server
/// TODO: move to socket module
pub fn listen_socket(addr: []const u8, port: u16) !void {
    const address = try std.net.Address.parseIp(addr, port);
    server = try aio.TCP.init(runtime.runtime.executor, address);
    try server.bind(address);
    try server.listen(1024);
    log.info("listening on {any}", .{address});
}

fn collect_coro() !void {
    while (true) {
        try collect_childs();
        try aio.sleep(null, 1000 * 5); // sleep 5s
    }
}

fn collect_childs() !void {
    var iter = childs.iterator();
    while (iter.next()) |child| {
        if (child.done) {
            const index = child.index;
            childs.release(index);
            try released.append(runtime.runtime.allocator, index);
            child.coro.deinit();
        }
    }
}

/// accept new connections and dispatch them through coroutine worker
pub fn main_loop() !void {
    defer server.close() catch unreachable;

    const allocator = runtime.runtime.allocator;

    childs = try Pool(Child).init(allocator, CLIENT_COUNT, PoolKind.grow);
    errdefer childs.deinit();
    defer childs.deinit();

    released = try std.ArrayListUnmanaged(usize).initCapacity(allocator, CLIENT_COUNT);
    errdefer released.deinit(allocator);
    defer released.deinit(allocator);

    // create a coroutine to collect childs coroutines
    var coro = try ziro.xasync(collect_coro, .{}, null);
    defer coro.deinit();

    while (true) {
        const client_conn = try server.accept();

        const index = blk: {
            if (released.pop()) |index| {
                break :blk childs.borrow_assume_unset(index);
            } else {
                break :blk try childs.borrow();
            }
        };

        const child = childs.get_ptr(index);
        child.* = .{
            .done = false,
            .conn = Connection.init(client_conn),
            .index = index,
        };

        // create coroutine to handle new connection
        _ = try ziro.xasync(child_coro, .{child}, null);
    }
}

fn child_coro(child: *Child) !void {
    defer child.done = true;

    child.coro = ziro.xframe();

    // dispatch request
    try request.handle_connection(&child.conn);
}
