const zio = @import("zio");

pub const Connection = struct {
    client: zio.net.Stream,
    server: ?zio.net.Stream = null,
};
