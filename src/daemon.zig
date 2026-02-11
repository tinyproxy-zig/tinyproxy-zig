//! Daemon Mode Support for tinyproxy-zig
//!
//! Provides daemonization, PID file management, and privilege dropping.
//!
//! Usage:
//!   const daemon = @import("daemon.zig");
//!   try daemon.daemonize();
//!   try daemon.writePidFile("/var/run/tinyproxy.pid");
//!   try daemon.dropPrivileges("nobody", "nogroup");

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

pub const DaemonError = error{
    ForkFailed,
    SetsidFailed,
    ChdirFailed,
    UserNotFound,
    GroupNotFound,
    SetgidFailed,
    SetuidFailed,
    PidFileCreateFailed,
    PidFileWriteFailed,
};

/// Daemonize the process (fork, setsid, close standard file descriptors)
pub fn daemonize() DaemonError!void {
    if (builtin.os.tag == .windows) {
        // Windows doesn't support Unix daemonization
        return;
    }

    // First fork
    const pid1 = posix.fork() catch return error.ForkFailed;
    if (pid1 > 0) {
        // Parent exits
        posix.exit(0);
    }

    // Create new session (become session leader)
    _ = posix.setsid() catch return error.SetsidFailed;

    // Second fork to prevent acquiring a controlling terminal
    const pid2 = posix.fork() catch return error.ForkFailed;
    if (pid2 > 0) {
        // First child exits
        posix.exit(0);
    }

    // Change working directory to root to avoid blocking unmount
    std.posix.chdir("/") catch return error.ChdirFailed;

    // Close standard file descriptors and redirect to /dev/null
    redirectToDevNull();
}

fn redirectToDevNull() void {
    const dev_null = std.fs.openFileAbsolute("/dev/null", .{ .mode = .read_write }) catch return;
    defer dev_null.close();

    const null_fd = dev_null.handle;

    // Redirect stdin, stdout, stderr to /dev/null
    posix.dup2(null_fd, posix.STDIN_FILENO) catch {};
    posix.dup2(null_fd, posix.STDOUT_FILENO) catch {};
    posix.dup2(null_fd, posix.STDERR_FILENO) catch {};
}

/// Write PID file
pub fn writePidFile(path: []const u8) !void {
    const file = std.fs.cwd().createFile(path, .{
        .mode = 0o644,
    }) catch return error.PidFileCreateFailed;
    defer file.close();

    const pid = if (builtin.os.tag != .windows) std.os.linux.getpid() else 0;
    var buf: [32]u8 = undefined;
    const pid_str = std.fmt.bufPrint(&buf, "{d}\n", .{pid}) catch return error.PidFileWriteFailed;

    file.writeAll(pid_str) catch return error.PidFileWriteFailed;
}

/// Remove PID file
pub fn removePidFile(path: []const u8) void {
    std.fs.cwd().deleteFile(path) catch {};
}

/// Drop privileges by switching to specified user and group
pub fn dropPrivileges(user: ?[]const u8, group: ?[]const u8) DaemonError!void {
    if (builtin.os.tag == .windows) {
        return;
    }

    // Drop group first (must do before dropping user privileges)
    if (group) |g| {
        const gid = getGroupId(g) catch return error.GroupNotFound;
        posix.setgid(gid) catch return error.SetgidFailed;
        // Also set supplementary groups
        setgroups(gid) catch {};
    }

    // Drop user privileges
    if (user) |u| {
        const uid = getUserId(u) catch return error.UserNotFound;
        posix.setuid(uid) catch return error.SetuidFailed;
    }
}

fn getUserId(name: []const u8) !posix.uid_t {
    // Use libc getpwnam for user lookup
    const c = @cImport({
        @cInclude("pwd.h");
    });

    // Create null-terminated string
    var name_buf: [256]u8 = undefined;
    if (name.len >= name_buf.len) return error.UserNotFound;
    @memcpy(name_buf[0..name.len], name);
    name_buf[name.len] = 0;

    const pw = c.getpwnam(&name_buf);
    if (pw == null) return error.UserNotFound;
    return pw.*.pw_uid;
}

fn getGroupId(name: []const u8) !posix.gid_t {
    // Use libc getgrnam for group lookup
    const c = @cImport({
        @cInclude("grp.h");
    });

    // Create null-terminated string
    var name_buf: [256]u8 = undefined;
    if (name.len >= name_buf.len) return error.GroupNotFound;
    @memcpy(name_buf[0..name.len], name);
    name_buf[name.len] = 0;

    const gr = c.getgrnam(&name_buf);
    if (gr == null) return error.GroupNotFound;
    return gr.*.gr_gid;
}

fn setgroups(gid: posix.gid_t) !void {
    // Use libc setgroups to clear supplementary groups
    const c = @cImport({
        @cInclude("grp.h");
        @cInclude("unistd.h");
    });

    const groups = [_]posix.gid_t{gid};
    const rc = c.setgroups(1, &groups);
    if (rc != 0) {
        // EPERM can happen when already dropped privileges - ignore
        // Also silently ignore EINVAL (on some systems when gid == current gid)
        const errno: std.c.E = @enumFromInt(std.c._errno().*);
        if (errno == .PERM or errno == .INVAL) return;
        return error.SetgidFailed;
    }
}

// ============================================================================
// Tests
// ============================================================================

test "daemon module compiles" {
    // Basic compile test - actual daemon functionality requires root privileges
    if (builtin.os.tag == .windows) return;

    // Test that functions exist and compile
    _ = daemonize;
    _ = writePidFile;
    _ = removePidFile;
    _ = dropPrivileges;
}
