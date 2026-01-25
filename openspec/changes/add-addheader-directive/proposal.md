# Change: Add AddHeader directive support

## Why
The config parser accepts `AddHeader` but ignores it, so users cannot inject custom headers into forwarded requests as tinyproxy allows.

## What Changes
- Add config storage for `AddHeader` name/value pairs.
- Parse `AddHeader <name> <value>` with quoted strings.
- Append configured headers to outgoing requests before anonymous filtering.
- Add tests for parsing and header injection.

## Impact
- Affected specs: `addheader-directive`
- Affected code: `src/config.zig`, `src/conf.zig`, `src/request.zig`
