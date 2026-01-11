# tinyproxy-zig Implementation Roadmap

> Created: 2026-01-11  
> Status: Approved  
> Author: AI Assistant + Project Owner

## Overview

This document outlines the phased implementation plan for tinyproxy-zig, a Zig implementation of the tinyproxy HTTP/HTTPS proxy daemon using the zio async I/O framework.

## Current Status

### Completed Features

| Module | Status | Description |
|--------|--------|-------------|
| `main.zig` | ✅ Done | zio-based main entry |
| `child.zig` | ✅ Done | Listen socket, accept connections, spawn coroutines |
| `request.zig` | ✅ Done | HTTP request parsing, CONNECT tunnel, forwarding |
| `relay.zig` | ✅ Done | Bidirectional data relay |
| `buffer.zig` | ✅ Done | Line reader |
| `config.zig` | 🚧 Skeleton | Basic config structure only |
| `runtime.zig` | ✅ Done | zio runtime wrapper |

### Core Proxy Functionality Implemented

1. **HTTP Forward Proxy** - Parse absolute URLs, forward requests
2. **HTTPS CONNECT Tunnel** - Establish TCP tunnels
3. **Basic HTTP Header Handling** - Host header, Proxy-Connection filtering

---

## Phase 1: Infrastructure (Week 1)

### 1.1 Configuration System (`src/conf.zig`)

**Goal**: Implement tinyproxy-compatible configuration file parsing with runtime reload support.

**Data Structure**:

```zig
pub const Config = struct {
    // Network configuration
    listen_addrs: std.ArrayList([]const u8),
    port: u16 = 8888,
    bind_addrs: ?std.ArrayList([]const u8) = null,
    
    // Connection control
    max_clients: u32 = 100,
    idle_timeout: u32 = 600,
    
    // Logging
    log_file: ?[]const u8 = null,
    log_level: LogLevel = .info,
    use_syslog: bool = false,
    
    // User/Group (daemon mode)
    user: ?[]const u8 = null,
    group: ?[]const u8 = null,
    
    // Via header
    via_proxy_name: ?[]const u8 = null,
    disable_via_header: bool = false,
    
    // Extensible fields for Phase 2-4
    // filter, acl, upstream, reverse, auth...
    
    pub fn load(allocator: Allocator, path: []const u8) !Config { ... }
    pub fn deinit(self: *Config) void { ... }
};
```

**Config File Format** (tinyproxy compatible):

```
Port 8888
Listen 127.0.0.1
MaxClients 100
Timeout 600
LogFile "/var/log/tinyproxy.log"
```

**Tasks**:
- [ ] 1.1.1 Define Config struct with all fields
- [ ] 1.1.2 Implement config file tokenizer
- [ ] 1.1.3 Implement directive parser
- [ ] 1.1.4 Add config reload support (SIGHUP)

### 1.2 Logging System (`src/log.zig`)

**Goal**: Unified logging interface supporting file, syslog, and stderr.

```zig
pub const LogLevel = enum { err, warning, notice, info, debug };

pub fn init(config: *const Config) !void { ... }
pub fn log(level: LogLevel, comptime fmt: []const u8, args: anytype) void { ... }
pub fn deinit() void { ... }
```

**Tasks**:
- [ ] 1.2.1 Define LogLevel enum
- [ ] 1.2.2 Implement file logging
- [ ] 1.2.3 Implement stderr fallback
- [ ] 1.2.4 Add log rotation support (SIGUSR1)

---

## Phase 2: Core Proxy Enhancement (Weeks 2-3)

### 2.1 HTTP Message Parsing (`src/http.zig`)

**Goal**: Complete HTTP parsing with chunked encoding and Content-Length handling.

```zig
pub const HttpMessage = struct {
    headers: std.StringHashMap([]const u8),
    content_length: ?usize = null,
    is_chunked: bool = false,
    
    pub fn parse(allocator: Allocator, reader: anytype) !HttpMessage { ... }
    pub fn getHeader(self: *const HttpMessage, name: []const u8) ?[]const u8 { ... }
    pub fn deinit(self: *HttpMessage) void { ... }
};

pub const RequestLine = struct {
    method: []const u8,
    uri: []const u8,
    version: HttpVersion,
};

pub const HttpVersion = enum { http10, http11 };
```

**Tasks**:
- [ ] 2.1.1 Implement HttpMessage struct
- [ ] 2.1.2 Parse request/status line
- [ ] 2.1.3 Handle chunked transfer encoding
- [ ] 2.1.4 Handle Content-Length body reading

### 2.2 Header Processing (`src/headers.zig`)

**Goal**: Handle hop-by-hop headers, add/remove/modify headers.

```zig
const hop_by_hop_headers = [_][]const u8{
    "Connection", "Keep-Alive", "Proxy-Authenticate",
    "Proxy-Authorization", "TE", "Trailers",
    "Transfer-Encoding", "Upgrade", "Proxy-Connection",
};

pub fn removeHopByHop(headers: *std.StringHashMap([]const u8)) void { ... }
pub fn addViaHeader(headers: *std.StringHashMap([]const u8), config: *const Config) !void { ... }
pub fn processClientHeaders(headers: *std.StringHashMap([]const u8), config: *const Config) !void { ... }
pub fn processServerHeaders(headers: *std.StringHashMap([]const u8), config: *const Config) !void { ... }
```

**Tasks**:
- [ ] 2.2.1 Implement hop-by-hop header removal
- [ ] 2.2.2 Implement Via header addition
- [ ] 2.2.3 Implement Connection header parsing
- [ ] 2.2.4 Add AddHeader config directive support

### 2.3 Anonymous Mode (`src/anonymous.zig`)

**Goal**: Forward only whitelisted headers to hide client information.

```zig
pub const AnonymousConfig = struct {
    allowed_headers: std.StringHashMap(void),
    
    pub fn init(allocator: Allocator) AnonymousConfig { ... }
    pub fn allow(self: *AnonymousConfig, header: []const u8) !void { ... }
    pub fn isAllowed(self: *const AnonymousConfig, header: []const u8) bool { ... }
};

pub fn filterHeaders(headers: *std.StringHashMap([]const u8), config: *const AnonymousConfig) void { ... }
```

**Tasks**:
- [ ] 2.3.1 Implement AnonymousConfig struct
- [ ] 2.3.2 Add Anonymous config directive
- [ ] 2.3.3 Integrate into request processing pipeline

---

## Phase 3: Access Control (Weeks 4-5)

### 3.1 ACL Access Control (`src/acl.zig`)

**Goal**: IP address/subnet-based Allow/Deny rules.

```zig
pub const AclAction = enum { allow, deny };

pub const AclEntry = struct {
    action: AclAction,
    spec: HostSpec,
};

pub const HostSpec = union(enum) {
    ip4: std.net.Ip4Address,
    ip4_cidr: struct { addr: std.net.Ip4Address, prefix_len: u5 },
    ip6: std.net.Ip6Address,
    ip6_cidr: struct { addr: std.net.Ip6Address, prefix_len: u7 },
    hostname: []const u8,
};

pub const Acl = struct {
    entries: std.ArrayList(AclEntry),
    
    pub fn init(allocator: Allocator) Acl { ... }
    pub fn addRule(self: *Acl, rule: []const u8, action: AclAction) !void { ... }
    pub fn check(self: *const Acl, client_addr: std.net.Address) AclAction { ... }
    pub fn deinit(self: *Acl) void { ... }
};
```

**Config Example**:
```
Allow 127.0.0.1
Allow 192.168.0.0/16
Deny 0.0.0.0/0
```

**Tasks**:
- [ ] 3.1.1 Implement HostSpec union parsing
- [ ] 3.1.2 Implement CIDR matching
- [ ] 3.1.3 Implement Acl.check() logic
- [ ] 3.1.4 Integrate into connection acceptance

### 3.2 Basic Auth (`src/auth.zig`)

**Goal**: HTTP Basic Authentication with multiple users.

```zig
pub const BasicAuth = struct {
    credentials: std.StringHashMap([]const u8),
    realm: []const u8 = "tinyproxy",
    
    pub fn init(allocator: Allocator) BasicAuth { ... }
    pub fn addUser(self: *BasicAuth, user: []const u8, pass: []const u8) !void { ... }
    pub fn verify(self: *const BasicAuth, auth_header: ?[]const u8) bool { ... }
    pub fn deinit(self: *BasicAuth) void { ... }
};

pub fn sendAuthRequired(stream: *zio.net.Stream, rt: *zio.Runtime, realm: []const u8) !void { ... }
```

**Tasks**:
- [ ] 3.2.1 Implement Base64 decode
- [ ] 3.2.2 Implement credential verification
- [ ] 3.2.3 Send 407 response
- [ ] 3.2.4 Add BasicAuth config directive

### 3.3 Connect Port Restriction (`src/connect_ports.zig`)

**Goal**: Restrict ports accessible via CONNECT method.

```zig
pub const ConnectPorts = struct {
    allowed: std.ArrayList(PortRange),
    
    pub const PortRange = struct { min: u16, max: u16 };
    
    pub fn init(allocator: Allocator) ConnectPorts { ... }
    pub fn allow(self: *ConnectPorts, port_spec: []const u8) !void { ... }
    pub fn isAllowed(self: *const ConnectPorts, port: u16) bool { ... }
};
```

**Config Example**:
```
ConnectPort 443
ConnectPort 563
ConnectPort 8000-9000
```

**Tasks**:
- [ ] 3.3.1 Implement port range parsing
- [ ] 3.3.2 Implement port check
- [ ] 3.3.3 Integrate into CONNECT handling

### 3.4 URL/Domain Filtering (`src/filter.zig`)

**Goal**: Regex/fnmatch-based URL filtering with blacklist/whitelist modes.

```zig
pub const FilterMode = enum { default_allow, default_deny };
pub const FilterType = enum { regex, fnmatch };

pub const Filter = struct {
    patterns: std.ArrayList(Pattern),
    mode: FilterMode = .default_allow,
    filter_type: FilterType = .regex,
    case_sensitive: bool = false,
    
    pub fn init(allocator: Allocator) Filter { ... }
    pub fn loadFromFile(self: *Filter, path: []const u8) !void { ... }
    pub fn check(self: *const Filter, url: []const u8) bool { ... }
    pub fn deinit(self: *Filter) void { ... }
};
```

**Tasks**:
- [ ] 3.4.1 Implement pattern file parsing
- [ ] 3.4.2 Implement fnmatch matching
- [ ] 3.4.3 Implement regex matching (use std regex or simple glob)
- [ ] 3.4.4 Integrate into request processing

---

## Phase 4: Advanced Proxy Modes (Weeks 6-8)

### 4.1 Upstream Proxy (`src/upstream.zig`)

**Goal**: Support HTTP/SOCKS4/SOCKS5 upstream proxies.

```zig
pub const ProxyType = enum { none, http, socks4, socks5 };

pub const UpstreamProxy = struct {
    host: []const u8,
    port: u16,
    proxy_type: ProxyType,
    user: ?[]const u8 = null,
    pass: ?[]const u8 = null,
    target: ?HostSpec = null,
};

pub const UpstreamManager = struct {
    proxies: std.ArrayList(UpstreamProxy),
    no_upstream: std.ArrayList(HostSpec),
    
    pub fn init(allocator: Allocator) UpstreamManager { ... }
    pub fn addUpstream(self: *UpstreamManager, spec: []const u8) !void { ... }
    pub fn addNoUpstream(self: *UpstreamManager, domain: []const u8) !void { ... }
    pub fn getUpstream(self: *const UpstreamManager, host: []const u8) ?*const UpstreamProxy { ... }
    pub fn deinit(self: *UpstreamManager) void { ... }
};
```

**Config Example**:
```
Upstream http 192.168.1.1:8080
Upstream socks5 user:pass@proxy.example.com:1080 ".onion"
NoUpstream "192.168.0.0/16"
NoUpstream ".local"
```

**Tasks**:
- [ ] 4.1.1 Implement upstream config parsing
- [ ] 4.1.2 Implement HTTP CONNECT to upstream
- [ ] 4.1.3 Implement SOCKS4 protocol
- [ ] 4.1.4 Implement SOCKS5 protocol with auth
- [ ] 4.1.5 Implement NoUpstream matching

### 4.2 Reverse Proxy (`src/reverse.zig`)

**Goal**: Map URL paths to backend servers.

```zig
pub const ReversePath = struct {
    path: []const u8,
    upstream_url: []const u8,
};

pub const ReverseProxy = struct {
    paths: std.ArrayList(ReversePath),
    only_reverse: bool = false,
    magic_cookie: bool = false,
    base_url: ?[]const u8 = null,
    
    pub fn init(allocator: Allocator) ReverseProxy { ... }
    pub fn addPath(self: *ReverseProxy, path: []const u8, url: []const u8) !void { ... }
    pub fn rewriteUrl(self: *const ReverseProxy, request_url: []const u8) ?RewriteResult { ... }
    pub fn deinit(self: *ReverseProxy) void { ... }
};

pub const RewriteResult = struct {
    new_host: []const u8,
    new_port: u16,
    new_path: []const u8,
};
```

**Config Example**:
```
ReversePath "/api" "http://api-server:8080/"
ReversePath "/static" "http://cdn:80/"
ReverseOnly Yes
```

**Tasks**:
- [ ] 4.2.1 Implement path matching
- [ ] 4.2.2 Implement URL rewriting
- [ ] 4.2.3 Handle ReverseOnly mode
- [ ] 4.2.4 Implement magic cookie tracking

### 4.3 Transparent Proxy (`src/transparent.zig`)

**Goal**: Get original destination from socket (requires `SO_ORIGINAL_DST`).

```zig
pub const TransparentProxy = struct {
    enabled: bool = false,
    
    pub fn getOriginalDest(client_fd: std.posix.fd_t) !?std.net.Address { ... }
};
```

**Tasks**:
- [ ] 4.3.1 Implement Linux SO_ORIGINAL_DST
- [ ] 4.3.2 Implement BSD pf support (optional)
- [ ] 4.3.3 Integrate into request processing

---

## Phase 5: Operations & Production (Weeks 9-10)

### 5.1 Statistics Page (`src/stats.zig`)

**Goal**: Display runtime statistics via special URL.

```zig
pub const Stats = struct {
    connections_opened: std.atomic.Value(u64) = .{ .raw = 0 },
    connections_closed: std.atomic.Value(u64) = .{ .raw = 0 },
    connections_refused: std.atomic.Value(u64) = .{ .raw = 0 },
    connections_denied: std.atomic.Value(u64) = .{ .raw = 0 },
    bytes_sent: std.atomic.Value(u64) = .{ .raw = 0 },
    bytes_received: std.atomic.Value(u64) = .{ .raw = 0 },
    start_time: i64,
    
    pub fn init() Stats { ... }
    pub fn record(self: *Stats, event: StatEvent) void { ... }
    pub fn renderHtml(self: *const Stats, allocator: Allocator) ![]const u8 { ... }
};
```

**Tasks**:
- [ ] 5.1.1 Implement Stats struct with atomics
- [ ] 5.1.2 Implement HTML rendering
- [ ] 5.1.3 Add StatHost config directive

### 5.2 Signal Handling (`src/signals.zig`)

**Goal**: Graceful shutdown, config reload, log rotation.

```zig
pub const SignalHandler = struct {
    should_quit: std.atomic.Value(bool) = .{ .raw = false },
    should_reload: std.atomic.Value(bool) = .{ .raw = false },
    
    pub fn init() !SignalHandler { ... }
    pub fn install(self: *SignalHandler) !void { ... }
};
```

**Tasks**:
- [ ] 5.2.1 Install SIGTERM/SIGINT handlers
- [ ] 5.2.2 Install SIGHUP for config reload
- [ ] 5.2.3 Install SIGUSR1 for log rotation

### 5.3 Daemon Mode (`src/daemon.zig`)

**Goal**: Background execution, PID file, privilege dropping.

```zig
pub fn daemonize() !void { ... }
pub fn writePidFile(path: []const u8) !void { ... }
pub fn dropPrivileges(user: ?[]const u8, group: ?[]const u8) !void { ... }
```

**Tasks**:
- [ ] 5.3.1 Implement daemonize (fork, setsid)
- [ ] 5.3.2 Implement PID file management
- [ ] 5.3.3 Implement setuid/setgid

### 5.4 Error Pages (`src/html_error.zig`)

**Goal**: Return friendly HTML error pages.

```zig
pub const HttpError = enum(u16) {
    bad_request = 400,
    unauthorized = 401,
    forbidden = 403,
    not_found = 404,
    proxy_auth_required = 407,
    request_timeout = 408,
    bad_gateway = 502,
    service_unavailable = 503,
    gateway_timeout = 504,
};

pub fn sendError(rt: *zio.Runtime, stream: *zio.net.Stream, err: HttpError, config: *const Config) !void { ... }
```

**Tasks**:
- [ ] 5.4.1 Implement default error templates
- [ ] 5.4.2 Add ErrorFile config directive
- [ ] 5.4.3 Implement template variable substitution

---

## Source File Structure

```
tinyproxy-zig/
├── build.zig
├── build.zig.zon
├── AGENTS.md
├── README.md
├── docs/
│   └── plans/
│       └── 2026-01-11-implementation-roadmap.md
├── openspec/
│   ├── AGENTS.md
│   ├── project.md
│   ├── specs/
│   └── changes/
└── src/
    ├── main.zig
    ├── runtime.zig
    │
    │── # Phase 1: Infrastructure
    ├── conf.zig
    ├── log.zig
    │
    │── # Phase 2: Core Proxy
    ├── child.zig
    ├── request.zig
    ├── http.zig
    ├── headers.zig
    ├── anonymous.zig
    ├── buffer.zig
    ├── relay.zig
    │
    │── # Phase 3: Access Control
    ├── acl.zig
    ├── auth.zig
    ├── connect_ports.zig
    ├── filter.zig
    │
    │── # Phase 4: Advanced Proxy
    ├── upstream.zig
    ├── reverse.zig
    ├── transparent.zig
    ├── socks.zig
    │
    │── # Phase 5: Operations
    ├── stats.zig
    ├── signals.zig
    ├── daemon.zig
    ├── html_error.zig
    │
    │── # Utilities
    ├── network.zig
    ├── text.zig
    └── hostspec.zig
```

---

## Design Principles

1. **Zig Standard Library Style**: Use `error union`, `optional`, avoid global state
2. **Minimal Testing**: Core functionality only, manual curl testing
3. **Modular Design**: One feature per file, clear interfaces
4. **Configuration-Driven**: All features controllable via config file
5. **tinyproxy Compatibility**: Same config format, same behavior

---

## Success Criteria

- [ ] All tinyproxy config directives supported
- [ ] Forward proxy works with curl and browsers
- [ ] CONNECT tunnel works for HTTPS
- [ ] ACL correctly blocks/allows by IP
- [ ] Upstream proxy chains work (HTTP + SOCKS5)
- [ ] Stats page accessible
- [ ] Graceful shutdown on SIGTERM
- [ ] Config reload on SIGHUP
