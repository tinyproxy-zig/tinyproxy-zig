/// hold all the configuration time information
pub const Config = struct {
    listen: []const u8 = "127.0.0.1",
    port: u16 = 9999,
    max_clients: usize = 100,

    const Self = @This();

    pub fn init() Self {
        return .{};
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    /// reload config file
    pub fn reload(config_file: []u8, config: *Config) void {
        _ = config_file;
        _ = config;
    }
};
