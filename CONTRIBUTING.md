# Contributing to NetExec-RS

Thank you for your interest in contributing to NetExec-RS! We welcome all contributions, from code to documentation to bug reports.

## Getting Started

### Prerequisites

To build and test NetExec-RS, you will need:
- [Rust](https://www.rust-lang.org/tools/install) (latest stable version)
- `cargo` (comes with Rust)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/thrive-spectrexq/nxc-rs.git
   cd nxc-rs
   ```

2. Build the project:
   ```bash
   cargo build
   ```

## Development Workflow

### Project Structure

NetExec-RS is organized as a Rust workspace:
- `nxc-rs/nxc`: The core CLI tool.
- `nxc-rs/auth`: Authentication engines (NTLM, Kerberos, etc.).
- `nxc-rs/protocols`: Protocol handlers (SMB, LDAP, WinRM, etc.).
- `nxc-rs/modules`: Post-exploitation modules.
- `nxc-rs/db`: Database management.
- `nxc-rs/targets`: Target parsing and management.

### Running Tests

Before submitting a PR, ensure all tests pass:
```bash
cargo test
```

### Adding a New Protocol

If you're adding a new protocol, follow the patterns in `nxc-rs/protocols`. Ensure you implement the necessary traits for authentication and execution.

### Coding Standards

- Use `cargo fmt` to format your code.
- Ensure your code is well-documented with doc comments.
- Avoid `unsafe` code unless absolutely necessary.

## Submitting a Pull Request

1. Create a branch for your feature or bug fix:
   ```bash
   git checkout -b your-feature-name
   ```
2. Make your changes and commit them with descriptive messages.
3. Push your branch to GitHub.
4. Open a Pull Request using the provided PR template.

## Community

- Report bugs or request features via [GitHub Issues](https://github.com/thrive-spectrexq/nxc-rs/issues).
- Discuss ideas in the [GitHub Discussions](https://github.com/thrive-spectrexq/nxc-rs/discussions).

Happy hacking!
