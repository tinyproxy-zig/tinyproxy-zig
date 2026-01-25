## Context
Add SOCKS4a and SOCKS5 upstream support while preserving tinyproxy-compatible
behavior and existing request flow.

## Goals / Non-Goals
- Goals: SOCKS4a connect, SOCKS5 connect with no-auth and user/pass auth
- Non-Goals: SOCKS server mode, UDP ASSOCIATE, BIND, GSSAPI

## Decisions
- Decision: implement protocol logic in a new `src/socks.zig` module
- Decision: keep `src/request.zig` responsible for selecting upstream and
  mapping errors to 502

## Risks / Trade-offs
- Risk: protocol parsing errors on short reads → treat as protocol errors

## Migration Plan
- Add module and integrate into upstream connect path; no config changes

## Open Questions
- None
