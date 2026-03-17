#!/bin/bash
# NetSage + NetExec-RS — One-Line Installer
# Repository: https://github.com/thrive-spectrexq/netsage

set -e

echo "◈ Installing NetSage + NetExec-RS..."

# 1. Dependency Checks
if ! command -v cargo &> /dev/null; then
    echo "❌ Error: Rust (cargo) is not installed. Please install it from https://rustup.rs/"
    exit 1
fi

# 2. Clone Repository
NETSAGE_DIR="$HOME/.netsage"
if [ -d "$NETSAGE_DIR" ]; then
    echo "📂 Updating existing installation..."
    cd "$NETSAGE_DIR"
    git pull
else
    echo "📥 Cloning repository..."
    git clone https://github.com/thrive-spectrexq/netsage.git "$NETSAGE_DIR"
    cd "$NETSAGE_DIR"
fi

# 3. Check for libpcap
if [ "$(uname)" == "Darwin" ]; then
    echo "🍎 Detected macOS. Ensuring libpcap is available..."
elif [ "$(uname)" == "Linux" ]; then
    if ! ldconfig -p | grep libpcap &> /dev/null; then
        echo "⚠️ Warning: libpcap not found. Network capture may require libpcap installed."
        echo "   Try: sudo apt-get install libpcap-dev (Ubuntu/Debian) or sudo dnf install libpcap-devel (Fedora)"
    fi
fi

# 4. Build and Install Binaries
echo "🦀 Building NetExec-RS (this may take a few minutes)..."
cargo install --path crates/netsage

echo ""
echo "✅ NetSage + NetExec-RS installed successfully!"
echo "--------------------------------------------------"
echo "Next Steps:"
echo "1. Set your API key:"
echo "   export GEMINI_API_KEY=\"your_key_here\""
echo "2. Create a NETWORK.md file for network context."
echo "3. Run 'nxc' for the interactive TUI."
echo "4. Run 'nxc smb --help' for protocol CLI mode."
echo ""
echo "Examples:"
echo "   nxc smb 192.168.1.0/24 -u admin -p Password123"
echo "   nxc ldap dc01.corp.local -u user -p pass -M bloodhound"
echo "--------------------------------------------------"
