# Change: add config reload on SIGHUP

## Why
Config reload is wired to SIGHUP but not implemented, so runtime changes cannot be applied without restart.

## What Changes
- Implement config reload to re-parse the config file and apply updates for new connections only.
- Keep existing config if reload fails and log the error.

## Impact
- Affected specs: config-reload
- Affected code: src/config.zig, src/child.zig, src/main.zig
