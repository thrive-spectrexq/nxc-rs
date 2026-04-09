# Installation Guide

NetExec-RS provides bleeding-edge offensive capabilities packaged as a single statically compiled binary.

## Recommended: One-Line Install Script

For rapid deployment on Debian/Ubuntu/Kali or macOS, use the automated installer:

```bash
curl -sSf https://raw.githubusercontent.com/thrive-spectrexq/nxc-rs/master/install.sh | bash
```

For Windows (PowerShell):
```powershell
iex (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/thrive-spectrexq/nxc-rs/master/install.ps1')
```

## Native Compilation (Source)

If you are a developer, want to contribute, or need to run specific branches, you must compile from source. NetExec-RS takes advantage of bleeding-edge Rust features.

### Prerequisites
1. **Rust Toolchain:** Version `1.94.0` or higher.
   - Install via [rustup.rs](https://rustup.rs/): `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
2. **System Dependencies (Linux only):**
   - Debian/Ubuntu: `sudo apt install build-essential libssl-dev pkg-config`
   - Fedora: `sudo dnf install gcc openssl-devel pkg-config`

### Build Steps

1. **Clone the repository:**
   ```bash
   git clone https://github.com/thrive-spectrexq/nxc-rs.git
   cd nxc-rs
   ```

2. **Build the Workspace:**
   ```bash
   # Build debug binaries (fastest compile time, heavier binary)
   cargo build --workspace

   # Build production binaries (optimized, stripped)
   cargo build --release --workspace
   ```

3. **Execution:**
   - The primary binary will be placed at `target/release/nxc`.
   - Run it directly: `./target/release/nxc --help`
   - Or install it globally on your path:
     ```bash
     cargo install --path nxc-rs/nxc
     ```

## Docker Deployment

For sandboxed or ephemeral CI/CD environments, NetExec-RS publishes an official Docker image.

```bash
# Pull the latest edge build
docker pull ghcr.io/thrive-spectrexq/nxc-rs:latest

# Run against a target
docker run --rm -it ghcr.io/thrive-spectrexq/nxc-rs:latest smb 192.168.1.0/24 -u admin -p 'Password123!'
```
