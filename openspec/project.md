# Project Context

## Purpose

Implement a lightweight HTTP/HTTPS proxy daemon in Zig, with full feature parity
to tinyproxy (C version). Designed for small networks where a larger proxy would
be resource intensive.

**Goals:**
- Feature parity with tinyproxy
- High performance via zio coroutines
- Clean, idiomatic Zig codebase
- Easy to configure and deploy

**Non-Goals:**
- SOCKS proxy server (only SOCKS upstream support)
- HTTP/2 or HTTP/3 support
- Caching proxy functionality

## Tech Stack

- **Zig 0.15.2**: Primary language
- **zio**: Coroutine runtime and async I/O
- **Reference**: tinyproxy 1.11.x (C implementation)

## Project Conventions

### Code Style

- Follow Zig standard library conventions
- Use `error union` for fallible operations
- Prefer explicit over implicit
- No global mutable state in library code
- Document public APIs with `///` comments

### File Organization

- One module per file
- Test code in same file as implementation
- Config-related types in `conf.zig`
- HTTP parsing in `http.zig`

### Error Handling

```zig
// Preferred: explicit error sets
pub const ConfigError = error{
    FileNotFound,
    InvalidSyntax,
    UnknownDirective,
};

// Use error union returns
pub fn load(path: []const u8) ConfigError!Config { ... }
```

### Naming Conventions

| Type | Convention | Example |
|------|------------|---------|
| Types/Structs | PascalCase | `HttpMessage`, `AclEntry` |
| Functions | snake_case | `parse_request`, `check_acl` |
| Constants | snake_case | `default_port`, `max_clients` |
| Files | snake_case | `connect_ports.zig` |

## Testing Strategy

- **Minimal testing**: only core functionality
- Unit tests in same file as implementation
- Integration tests via manual `curl` commands
- No mocking framework required

## Git Workflow

- **Branching**: `main` for stable, `dev/*` for features
- **Commits**: Conventional commits in English
  - `feat(upstream): add SOCKS5 support`
  - `fix(acl): handle IPv6 CIDR correctly`
- **PR**: One feature per PR, link to openspec change if applicable

## Domain Context

### HTTP Proxy Modes

1. **Forward Proxy**: Client explicitly configures proxy
2. **Transparent Proxy**: Traffic redirected via firewall rules
3. **Reverse Proxy**: Maps URL paths to backend servers
4. **Upstream Proxy**: Chain through another proxy (HTTP/SOCKS)

### Key tinyproxy Features to Implement

| Feature | Priority | Phase |
|---------|----------|-------|
| Forward proxy (HTTP/HTTPS) | P0 | Done |
| Configuration file | P0 | 1 |
| Logging | P0 | 1 |
| ACL | P0 | 3 |
| Basic Auth | P1 | 3 |
| URL Filter | P1 | 3 |
| Upstream proxy | P1 | 4 |
| Reverse proxy | P2 | 4 |
| Transparent proxy | P2 | 4 |
| Stats page | P2 | 5 |

## Important Constraints

- **Single-threaded**: zio uses cooperative scheduling
- **No TLS termination**: CONNECT tunneling only for HTTPS
- **Linux/macOS focus**: Windows support via zio is available but not prioritized
- **Memory**: Target low memory footprint (<10MB RSS typical)

## External Dependencies

| Dependency | Purpose | Version |
|------------|---------|---------|
| zio | Async I/O runtime | latest main |
| zig std | Standard library | 0.15.2 |

## Reference Materials

- [tinyproxy GitHub](https://github.com/tinyproxy/tinyproxy)
- [zio Documentation](https://lalinsky.github.io/zio/)
- [HTTP/1.1 RFC 7230-7235](https://datatracker.ietf.org/doc/html/rfc7230)
