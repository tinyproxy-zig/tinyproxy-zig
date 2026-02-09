//! Signal Handler Module for tinyproxy-zig
//!
//! Uses POSIX signal handlers with the self-pipe trick to wake up the accept loop.

const std = @import("std");
const builtin = @import("builtin");

// Use C write for async-signal-safety
const c = @cImport({
    @cInclude("unistd.h");
});

/// Signal flags
var reload_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);
var rotate_log_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);
var shutdown_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

/// Wakeup pipe for self-pipe trick
var wakeup_pipe: [2]std.posix.fd_t = undefined;

pub fn shouldReload() bool {
    return reload_flag.swap(false, .seq_cst);
}

pub fn shouldRotateLog() bool {
    return rotate_log_flag.swap(false, .seq_cst);
}

pub fn shouldShutdown() bool {
    return shutdown_flag.load(.acquire);
}

pub fn requestReload() void {
    reload_flag.store(true, .seq_cst);
}

pub fn requestRotateLog() void {
    rotate_log_flag.store(true, .seq_cst);
}

/// Get the read end of the wakeup pipe for use with select/poll
pub fn wakeupFd() std.posix.fd_t {
    return wakeup_pipe[0];
}

/// Setup signal handlers and wakeup pipe
pub fn setup() !void {
    if (builtin.os.tag == .windows) {
        return; // Not supported on Windows
    }

    // Create pipe for self-pipe trick
    wakeup_pipe = try std.posix.pipe();

    // Set write end to non-blocking (O_NONBLOCK = 0x0004 is standardized)
    const write_flags = std.posix.fcntl(wakeup_pipe[1], std.posix.F.GETFL, 0) catch unreachable;
    _ = std.posix.fcntl(wakeup_pipe[1], std.posix.F.SETFL, write_flags | 0x0004) catch {};

    // Also set read end to non-blocking
    const read_flags = std.posix.fcntl(wakeup_pipe[0], std.posix.F.GETFL, 0) catch unreachable;
    _ = std.posix.fcntl(wakeup_pipe[0], std.posix.F.SETFL, read_flags | 0x0004) catch {};

    const empty_mask = std.posix.sigemptyset();

    // SIGHUP - Reload configuration
    const sighup_action = std.posix.Sigaction{
        .handler = .{ .handler = handleSighup },
        .mask = empty_mask,
        .flags = 0, // Don't use SA_RESTART so syscalls can be interrupted
    };
    std.posix.sigaction(std.posix.SIG.HUP, &sighup_action, null);

    // SIGUSR1 - Rotate log file
    const sigusr1_action = std.posix.Sigaction{
        .handler = .{ .handler = handleSigusr1 },
        .mask = empty_mask,
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.USR1, &sigusr1_action, null);

    // SIGTERM - Graceful shutdown
    const sigterm_action = std.posix.Sigaction{
        .handler = .{ .handler = handleSigterm },
        .mask = empty_mask,
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.TERM, &sigterm_action, null);

    // SIGINT - Interrupt (Ctrl+C)
    const sigint_action = std.posix.Sigaction{
        .handler = .{ .handler = handleSigterm },
        .mask = empty_mask,
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &sigint_action, null);

    // Ignore SIGPIPE
    const sigpipe_action = std.posix.Sigaction{
        .handler = .{ .handler = std.posix.SIG.IGN },
        .mask = empty_mask,
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.PIPE, &sigpipe_action, null);
}

/// Drain the wakeup pipe (call after select/poll indicates it's readable)
pub fn drainWakeupPipe() void {
    var buf: [16]u8 = undefined;
    while (true) {
        const n = std.posix.read(wakeup_pipe[0], &buf) catch |err| switch (err) {
            error.WouldBlock => return,
            else => return,
        };
        if (n == 0) return;
    }
}

/// Cleanup signal handlers
pub fn cleanup() void {
    if (builtin.os.tag == .windows) return;
    std.posix.close(wakeup_pipe[0]);
    std.posix.close(wakeup_pipe[1]);
}

/// Write a single byte to the wakeup pipe (async-signal-safe)
fn writeWakeup() void {
    const byte = [_]u8{1};
    _ = c.write(wakeup_pipe[1], &byte, 1);
}

fn handleSighup(sig: c_int) callconv(.c) void {
    _ = sig;
    reload_flag.store(true, .seq_cst);
    writeWakeup();
}

fn handleSigusr1(sig: c_int) callconv(.c) void {
    _ = sig;
    rotate_log_flag.store(true, .seq_cst);
    writeWakeup();
}

fn handleSigterm(sig: c_int) callconv(.c) void {
    _ = sig;
    shutdown_flag.store(true, .seq_cst);
    writeWakeup();
}

test "signal flags" {
    reload_flag.store(false, .seq_cst);
    try std.testing.expect(!shouldReload());

    requestReload();
    try std.testing.expect(shouldReload());
    try std.testing.expect(!shouldReload());

    rotate_log_flag.store(false, .seq_cst);
    try std.testing.expect(!shouldRotateLog());

    requestRotateLog();
    try std.testing.expect(shouldRotateLog());
    try std.testing.expect(!shouldRotateLog());
}
