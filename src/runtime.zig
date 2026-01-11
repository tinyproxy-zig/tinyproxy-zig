const std = @import("std");

const zio = @import("zio");

const Config = @import("config.zig").Config;

/// global runtime environment
pub threadlocal var runtime: Runtime = undefined;

pub const Runtime = struct {
    allocator: std.mem.Allocator,
    zio_rt: *zio.Runtime,
    config: *Config,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, options: RuntimeOptions) !Self {
        const zrt = try zio.Runtime.init(allocator, .{ .num_executors = 1 });
        runtime = .{ .allocator = allocator, .zio_rt = zrt, .config = options.config };
        return runtime;
    }

    pub fn deinit(self: *Self) void {
        self.zio_rt.deinit();
    }
};

pub const RuntimeOptions = struct {
    config: *Config,
};

test "runtime init and deinit" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var conf = Config.init();
    var rt = try Runtime.init(gpa.allocator(), .{ .config = &conf });
    defer rt.deinit();
}
