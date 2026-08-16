# Changelog

All notable changes to the NetExec-RS (`nxc-rs`) project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Secure TLS Defaults**: SSL/TLS verification enabled by default; added `--insecure` flag to disable when targeting unverified endpoints.
- **Platform Directory Resolution**: Integrated `dirs` crate to resolve platform-standard config/cache directories (`%APPDATA%/nxc` on Windows, `~/.local/share/nxc` on Linux/macOS) with backward-compatibility for legacy `~/.nxc`.
- **Safe Mode**: Added `--safe-mode` / `--enum-only` flags to restrict execution to non-intrusive enumeration.
- **Structured JSON Logging**: Added `--json-log` flag for machine-parsable JSON tracing events.
- **Relay Health Probe**: Added HTTP `/health` and `/status` probe endpoint for the NTLM relay server.
- **Secret Scanning CI**: Added automated Gitleaks secret leak detection in GitHub Actions workflows.
- **Architecture Documentation**: Added `docs/architecture.md` detailing crate boundaries and security designs.

### Security & Hardening
- **Cryptographic Memory Hygiene**: Applied `Zeroize` and `#[zeroize(drop)]` across credentials and loot tables in `nxc-db`.
- **Export Sanitization**: Added atomic file operations, CSV formula injection neutralization, and path traversal validation.
- **Test Sanitization**: Replaced sample fixture credentials with synthetic constants.
- **Graceful Termination**: Added SIGINT/Ctrl+C interrupt handling with flush for running tasks and SQLite database state.
