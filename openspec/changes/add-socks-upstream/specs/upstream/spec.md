## ADDED Requirements

### Requirement: SOCKS4a Upstream Connect
The system SHALL support SOCKS4a upstream proxies when configured with
`Upstream socks4 ...`.

#### Scenario: SOCKS4a domain connect
- **WHEN** upstream proxy type is `socks4` and the target host is a domain name
- **THEN** the proxy MUST send a SOCKS4a CONNECT request with a fake IP and
  the domain name, and complete the SOCKS4a handshake before forwarding traffic

### Requirement: SOCKS5 Upstream Connect
The system SHALL support SOCKS5 upstream proxies when configured with
`Upstream socks5 ...`.

#### Scenario: SOCKS5 no-auth connect
- **WHEN** upstream proxy type is `socks5` and no credentials are configured
- **THEN** the proxy MUST negotiate the no-auth method and complete the SOCKS5
  CONNECT handshake before forwarding traffic

#### Scenario: SOCKS5 user/pass connect
- **WHEN** upstream proxy type is `socks5` and user/password are configured
- **THEN** the proxy MUST negotiate username/password auth and complete the
  SOCKS5 CONNECT handshake before forwarding traffic

### Requirement: SOCKS Upstream Failure Handling
The system SHALL treat SOCKS handshake failures as upstream connection errors.

#### Scenario: SOCKS handshake failure
- **WHEN** a SOCKS4a/5 handshake fails
- **THEN** the proxy MUST respond with a 502 error to the client
