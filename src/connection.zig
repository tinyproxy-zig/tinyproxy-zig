const std = @import("std");

const ziro = @import("ziro");
const aio = ziro.asyncio;

const runtime = @import("runtime.zig");

pub const Connection = struct {
    client_conn: aio.TCP = undefined,
    server_conn: aio.TCP = undefined,
    /// the request line (first line) from the client
    request_line: []u8 = &.{},
    /// A Content-Length value from the remote server
    content_length: struct {
        client: u64,
        server: u64,
    } = undefined,
    /// store client's IP address
    client_addr: std.net.Address = undefined,
    /// store server's IP address (for BindSame)
    server_addr: std.net.Address = undefined,
    /// store the incoming request's HTTP protocol
    protocol: struct {
        major: u32,
        minor: u32,
    } = undefined,

    const Self = @This();

    pub fn init(client_conn: aio.TCP) Self {
        return .{
            .client_conn = client_conn,
        };
    }

    pub fn deinit(self: *Self) void {
        const allocator = runtime.runtime.allocator;

        if (self.request_line.len > 0) {
            allocator.free(self.request_line);
        }

        allocator.destroy(self);
    }
};
