//! Signal setup for tinyproxy-zig
//!
//! Signal handling (SIGTERM, SIGINT, SIGHUP, SIGUSR1) is done via zio.Signal
//! which integrates with the event loop. This module only handles SIGPIPE
//! (which must be ignored globally via sigaction).

const std = @import("std");
const builtin = @import("builtin");

/// Ignore SIGPIPE to prevent broken pipe crashes on write to closed sockets.
/// All other signals are handled via zio.Signal in child.main_loop.
pub fn setup() !void {
    if (builtin.os.tag == .windows) return;

    const empty_mask = std.posix.sigemptyset();
    const sigpipe_action = std.posix.Sigaction{
        .handler = .{ .handler = std.posix.SIG.IGN },
        .mask = empty_mask,
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.PIPE, &sigpipe_action, null);
}

pub fn cleanup() void {
    // No resources to clean up — zio.Signal handles its own lifecycle.
}
