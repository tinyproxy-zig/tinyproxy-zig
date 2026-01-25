## ADDED Requirements

### Requirement: Configure additional request headers
The system SHALL support the `AddHeader` directive to append configured header name/value pairs to outgoing HTTP requests.

#### Scenario: Append configured header
- **WHEN** configuration includes `AddHeader X-Test 123`
- **THEN** forwarded requests include `X-Test: 123`

#### Scenario: Preserve quoted values
- **WHEN** configuration includes `AddHeader X-Note "hello world"`
- **THEN** forwarded requests include `X-Note: hello world`

### Requirement: Allow duplicate header names
The system SHALL append headers without removing existing headers with the same name.

#### Scenario: Duplicate header name
- **WHEN** configuration includes `AddHeader X-Test 123` and the client sends `X-Test: abc`
- **THEN** the forwarded request includes both header entries
