#!/bin/bash

# NetExec-RS (nxc) Installer for Linux and macOS
# This script installs the Rust toolchain if missing and builds nxc from source.

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}◈ NetExec-RS Installer ◈${NC}"

# 1. Check for Rust
if ! command -v cargo &> /dev/null; then
    echo -e "${BLUE}[*] Rust not found. Installing via rustup...${NC}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
else
    echo -e "${GREEN}[+] Rust is already installed.${NC}"
fi

# 2. Build
echo -e "${BLUE}[*] Building NetExec-RS (nxc) in release mode...${NC}"
cargo build --release --package nxc

# 3. Install
INSTALL_DIR="/usr/local/bin"
BINARY_PATH="target/release/nxc"

if [ -f "$BINARY_PATH" ]; then
    echo -e "${BLUE}[*] Installing binary to $INSTALL_DIR (may require sudo)...${NC}"
    if [ -w "$INSTALL_DIR" ]; then
        cp "$BINARY_PATH" "$INSTALL_DIR/nxc"
    else
        sudo cp "$BINARY_PATH" "$INSTALL_DIR/nxc"
    fi
    echo -e "${GREEN}[+] NetExec-RS (nxc) installed successfully!${NC}"
    echo -e "${GREEN}[+] Usage: nxc --help${NC}"
else
    echo -e "${RED}[!] Build failed. Binary not found at $BINARY_PATH${NC}"
    exit 1
fi
