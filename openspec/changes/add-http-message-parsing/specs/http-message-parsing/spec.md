## ADDED Requirements

### Requirement: Parse request line and headers
The system SHALL parse HTTP/1.0 and HTTP/1.1 request lines and headers into a structured representation with normalized header names.

#### Scenario: Parse basic request
- **WHEN** a request line and headers are received over a client connection
- **THEN** the method, request target, version, and headers are available via the parsed message

### Requirement: Handle request bodies with Content-Length or chunked transfer encoding
The system SHALL read and forward request bodies using Content-Length or chunked transfer encoding, preserving chunk framing.

#### Scenario: Content-Length body
- **WHEN** a request includes a valid Content-Length header
- **THEN** exactly that number of bytes are read and forwarded to upstream

#### Scenario: Chunked body
- **WHEN** a request includes Transfer-Encoding: chunked
- **THEN** chunk sizes and data are read and forwarded until the terminating chunk
