# tinyproxy in zig

Tinyproxy is a lightweight http(s) proxy daemon.
Rewrite tinyproxy in zig for fun.

### Design

- single thread: one connection, one coroutine
- ziro based coroutine, libxev based async io

### Features

- [ ] forward proxy
- [ ] upstream
- [ ] transparent proxy
- [ ] reverse proxy
- [ ] filter
- [ ] custom header
- [ ] acl
- [ ] basic auth
- [ ] stats
- [ ] logging
- [ ] config
