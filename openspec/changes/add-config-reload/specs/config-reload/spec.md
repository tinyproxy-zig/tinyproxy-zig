## ADDED Requirements
### Requirement: Reload configuration on SIGHUP
The system SHALL reload the configuration file when a SIGHUP signal is received and apply it to new connections only.

#### Scenario: Successful reload
- **WHEN** the process receives SIGHUP and the config file is valid
- **THEN** the configuration is reloaded and new connections use updated settings

#### Scenario: Reload fails
- **WHEN** the process receives SIGHUP and the config file is invalid
- **THEN** the existing configuration remains active and an error is logged
