const std = @import("std");

const ziro = @import("ziro");
const aio = ziro.asyncio;

const Config = @import("config.zig").Config;

/// global runtime environment
pub threadlocal var runtime: Runtime = undefined;

pub const Runtime = struct {
    allocator: std.mem.Allocator,
    executor: *aio.Executor,
    config: *Config,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, options: RuntimeOptions) !Self {
        const executor = try allocator.create(aio.Executor);

        executor.* = try aio.Executor.init(allocator);

        aio.initEnv(.{
            .executor = executor,
            .stack_allocator = allocator,
            .default_stack_size = options.stack_size,
        });

        runtime = .{
            .allocator = allocator,
            .executor = executor,
            .config = options.config,
        };

        return runtime;
    }

    pub fn deinit(self: *Self) void {
        self.executor.deinit(self.allocator);
        self.allocator.destroy(self.executor);
    }
};

// default stack size 2MB
const default_stack_size: usize = 2 * 1024 * 1024;

pub const RuntimeOptions = struct {
    stack_size: usize = default_stack_size,
    config: *Config,
};
