## Context
The proxy currently parses request lines and a limited set of headers directly in `src/request.zig`. This approach cannot safely handle request bodies because buffered bytes after header parsing are lost, and there is no structured representation of headers.

## Goals / Non-Goals
- Goals:
  - Parse HTTP/1.0 and HTTP/1.1 request lines and headers into a structured `HttpMessage`.
  - Support request bodies via `Content-Length` and `Transfer-Encoding: chunked`.
  - Preserve buffered bytes while switching from header parsing to body streaming.
- Non-Goals:
  - HTTP/2 or keep-alive support.
  - Response parsing or header rewriting (handled in later phases).

## Decisions
- Decision: Normalize header names to lowercase and keep an ordered header list for forwarding.
- Decision: Implement a `BodyReader` that enforces Content-Length or chunked parsing and forwards raw chunk framing.
- Decision: Extend `LineReader` with buffered `read`/`read_exact` to consume leftover bytes after header parsing.

## Risks / Trade-offs
- No keep-alive handling; connections are still one-request-per-connection.
- Lowercased header names may slightly alter casing when forwarded, but remain HTTP-compliant.

## Migration Plan
- Replace `request.zig` parsing to call `http.zig` parsing and body streaming.
- No configuration or user-facing behavior changes.

## Open Questions
- None.
