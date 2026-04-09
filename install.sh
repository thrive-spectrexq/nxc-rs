#!/bin/bash

# NetExec-RS (nxc) Installer for Linux and macOS
# This script downloads the latest pre-compiled binary from GitHub.

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

REPO="thrive-spectrexq/nxc-rs"

echo -e "${BLUE}◈ NetExec-RS Installer ◈${NC}"

# 1. Detect OS & Architecture
OS_TYPE=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH_TYPE=$(uname -m)

if [[ "$ARCH_TYPE" != "x86_64" ]]; then
    echo -e "${RED}[!] Error: Only x86_64 architecture is currently supported via this script.${NC}"
    echo -e "${BLUE}[*] Please build from source manually using 'cargo build'.${NC}"
    exit 1
fi

case "$OS_TYPE" in
    linux*)  ASSET_NAME="nxc-linux-amd64" ;;
    darwin*) ASSET_NAME="nxc-macos-amd64" ;;
    *)
        echo -e "${RED}[!] Error: Unsupported OS ($OS_TYPE).${NC}"
        exit 1
        ;;
esac

# 2. Download
DOWNLOAD_URL="https://github.com/$REPO/releases/latest/download/$ASSET_NAME"
echo -e "${BLUE}[*] Downloading latest release ($ASSET_NAME)...${NC}"

TEMP_FILE=$(mktemp)
curl -L -sSf "$DOWNLOAD_URL" -o "$TEMP_FILE"

# 3. Install
INSTALL_DIR="/usr/local/bin"
echo -e "${BLUE}[*] Installing binary to $INSTALL_DIR (may require sudo)...${NC}"

if [ -w "$INSTALL_DIR" ]; then
    cp "$TEMP_FILE" "$INSTALL_DIR/nxc"
    chmod +x "$INSTALL_DIR/nxc"
else
    sudo cp "$TEMP_FILE" "$INSTALL_DIR/nxc"
    sudo chmod +x "$INSTALL_DIR/nxc"
fi

rm "$TEMP_FILE"

echo -e "${GREEN}[+] NetExec-RS (nxc) installed successfully!${NC}"
echo -e "${GREEN}[+] Usage: nxc --help${NC}"
