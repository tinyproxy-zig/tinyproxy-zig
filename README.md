# tinyproxy-zig

A Zig implementation of the [tinyproxy](https://github.com/tinyproxy/tinyproxy) HTTP/HTTPS proxy daemon.

Built on top of the [zio](https://github.com/lalinsky/zio) coroutine and async I/O framework.

## Design

- **Single-threaded coroutine model**: one coroutine per connection
- **Async I/O**: zio provides io_uring (Linux), kqueue (macOS), epoll fallback
- **Feature parity goal**: implement all tinyproxy features in idiomatic Zig

## Features

### Phase 1: Infrastructure
- [ ] Configuration file parsing (tinyproxy compatible)
- [ ] Logging system (file, syslog, stderr)

### Phase 2: Core Proxy
- [x] Forward proxy (HTTP)
- [x] HTTPS CONNECT tunnel
- [ ] HTTP header processing (Via, hop-by-hop removal)
- [ ] Anonymous mode
- [ ] Custom headers (AddHeader)

### Phase 3: Access Control
- [ ] ACL (Allow/Deny by IP/subnet)
- [ ] Basic Auth
- [ ] Connect port restriction
- [ ] URL/domain filtering

### Phase 4: Advanced Proxy Modes
- [ ] Upstream proxy (HTTP/SOCKS4/SOCKS5)
- [ ] Reverse proxy
- [ ] Transparent proxy

### Phase 5: Production
- [ ] Statistics page
- [ ] Signal handling (graceful shutdown, config reload)
- [ ] Daemon mode
- [ ] Custom error pages

## Quick Start

### Build

```shell
zig build
```

### Run

```shell
zig build run
```

Proxy will listen on `127.0.0.1:9999` (see `src/config.zig`).

### Test

```shell
# Run unit tests
zig build test

# Test HTTP proxy
curl -x http://127.0.0.1:9999 http://example.com

# Test HTTPS tunnel
curl -x http://127.0.0.1:9999 https://example.com

# Benchmark
wrk -c 100 -t 4 http://127.0.0.1:9999
```

## Development

See [docs/plans/2026-01-11-implementation-roadmap.md](docs/plans/2026-01-11-implementation-roadmap.md) for detailed implementation plan.

### Project Structure

```
src/
├── main.zig          # Entry point
├── runtime.zig       # zio runtime wrapper
├── child.zig         # Connection accept loop
├── request.zig       # Request handling
├── relay.zig         # Bidirectional data relay
├── buffer.zig        # Line reader
├── config.zig        # Configuration (WIP)
└── ...
```

### Debugging

Use `mitmproxy` for HTTP layer inspection or `wireshark` for TCP layer.

## License

MIT License - Copyright Dacheng Gao
