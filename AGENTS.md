# Agent Development Guide

## Project Overview

**tinyproxy-zig** is a Zig implementation of the tinyproxy HTTP/HTTPS proxy daemon,
built on top of the zio coroutine and async I/O framework.

## Tech Stack

- **Language**: Zig 0.15.2
- **Async Runtime**: zio (stackful coroutines + io_uring/kqueue/epoll)
- **Reference**: tinyproxy (C version) - functionality parity goal

## Code Style

- Follow Zig standard library conventions strictly
- Use `error union` and `optional` for error handling
- Avoid global mutable state (use dependency injection)
- Naming: `snake_case` for functions/variables, `PascalCase` for types
- Documentation: use `///` doc comments for public APIs

## Architecture

- **Single-threaded coroutine model**: one coroutine per connection
- **Modular design**: each feature is a separate `.zig` file
- **Configuration-driven**: all features controllable via config file

## Key Modules

| Module | Purpose |
|--------|---------|
| `request.zig` | Main request handling logic |
| `conf.zig` | Configuration parsing |
| `acl.zig` | Access control lists |
| `upstream.zig` | Upstream proxy support |
| `filter.zig` | URL filtering |

## Implementation Phases

| Phase | Focus | Status |
|-------|-------|--------|
| Phase 1 | Configuration, Logging | 🚧 In Progress |
| Phase 2 | HTTP Enhancement, Headers, Anonymous | Not Started |
| Phase 3 | ACL, Auth, Filter, Connect Ports | Not Started |
| Phase 4 | Upstream, Reverse, Transparent Proxy | Not Started |
| Phase 5 | Stats, Signals, Daemon, Error Pages | Not Started |

See `docs/plans/2026-01-11-implementation-roadmap.md` for detailed plan.

## Testing

- Minimal testing strategy: core functionality only
- Run tests: `zig build test`
- Manual testing: `curl -x http://127.0.0.1:9999 http://example.com`

## Common Tasks

### Adding a new feature

1. Create `src/<feature>.zig`
2. Add config options to `conf.zig`
3. Integrate into `request.zig` processing pipeline
4. Update README.md feature checklist

### Debugging

- Use `std.log.scoped` for module-specific logging
- Enable debug allocator in `main.zig`

## Reference Repositories

- **tinyproxy (C)**: `../../tinyproxy` - functionality reference
- **zio**: `../zio` - async I/O library

<!-- OPENSPEC:START -->
## OpenSpec Instructions

These instructions are for AI assistants working in this project.

Always open `@/openspec/AGENTS.md` when the request:
- Mentions planning or proposals (words like proposal, spec, change, plan)
- Introduces new capabilities, breaking changes, architecture shifts, or big performance/security work
- Sounds ambiguous and you need the authoritative spec before coding

Use `@/openspec/AGENTS.md` to learn:
- How to create and apply change proposals
- Spec format and conventions
- Project structure and guidelines

Keep this managed block so 'openspec update' can refresh the instructions.

<!-- OPENSPEC:END -->