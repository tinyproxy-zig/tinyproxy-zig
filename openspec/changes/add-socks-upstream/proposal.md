# Change: Add SOCKS upstream support

## Why
Upstream SOCKS4/5 chaining is required for feature parity with tinyproxy and
enables proxying through SOCKS gateways (e.g., Tor, SSH dynamic forwarders).

## What Changes
- Add SOCKS4a and SOCKS5 upstream handshake support
- Support SOCKS5 no-auth and username/password auth
- Map SOCKS handshake failures to proxy 502 errors
- Add minimal unit tests for SOCKS handshake encoding

## Impact
- Affected specs: upstream
- Affected code: `src/request.zig`, `src/socks.zig` (new)
