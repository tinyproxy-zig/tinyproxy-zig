# Change: Add HTTP message parsing

## Why
Current request handling only parses the request line and a subset of headers, and it cannot safely read request bodies (Content-Length or chunked) without losing buffered data.

## What Changes
- Add `src/http.zig` with `HttpMessage` parsing and a body reader supporting Content-Length and chunked transfer encoding.
- Extend `src/buffer.zig` `LineReader` with buffered `read`/`read_exact`.
- Replace `src/request.zig` parsing to use `http.zig` and stream request bodies to upstream.
- Register `src/http.zig` tests in `build.zig`.

## Impact
- Affected specs: `http-message-parsing`
- Affected code: `src/http.zig`, `src/request.zig`, `src/buffer.zig`, `build.zig`
