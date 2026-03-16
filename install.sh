#!/bin/bash
# NetSage One-Line Installer
# Repository: https://github.com/thrive-spectrexq/netsage

set -e

echo "🚀 Installing NetSage..."

# 1. Dependency Checks
if ! command -v cargo &> /dev/null; then
    echo "❌ Error: Rust (cargo) is not installed. Please install it from https://rustup.rs/"
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 is not installed."
    exit 1
fi

# 2. Clone Repository
NETSAGE_DIR="$HOME/.netsage"
if [ -d "$NETSAGE_DIR" ]; then
    echo "📂 Updating existing NetSage installation..."
    cd "$NETSAGE_DIR"
    git pull
else
    echo "📥 Cloning NetSage repository..."
    git clone https://github.com/thrive-spectrexq/netsage.git "$NETSAGE_DIR"
    cd "$NETSAGE_DIR"
fi

# 3. Setup Python Tool Engine
echo "🐍 Setting up Python Tool Engine..."
python3 -m venv "$NETSAGE_DIR/venv"
source "$NETSAGE_DIR/venv/bin/activate"
pip install --upgrade pip
if [ -f "python/requirements.txt" ]; then
    pip install -r python/requirements.txt
else
    pip install "python/."
fi

# 4. Check for libpcap
if [ "$(uname)" == "Darwin" ]; then
    # macOS
    echo "🍎 Detected macOS. Ensuring libpcap is available..."
elif [ "$(uname)" == "Linux" ]; then
    # Linux
    if ! ldconfig -p | grep libpcap &> /dev/null; then
        echo "⚠️ Warning: libpcap not found. Network capture may require libpcap installed."
        echo "   Try: sudo apt-get install libpcap-dev (Ubuntu/Debian) or sudo dnf install libpcap-devel (Fedora)"
    fi
fi

# 5. Build and Install Rust Binary
echo "🦀 Building NetSage (this may take a few minutes)..."
cargo install --path crates/netsage

echo ""
echo "✅ NetSage installed successfully!"
echo "--------------------------------------------------"
echo "Next Steps:"
echo "1. Set your API key:"
echo "   export ANTHROPIC_API_KEY=\"your_key_here\""
echo "2. Create a NETWORK.md file for network context."
echo "3. Run 'netsage' anywhere in your terminal."
echo "4. Distributed Mode:"
echo "   - Server: netsage --server"
echo "   - Node:   netsage --node <server_ip>:9090"
echo "--------------------------------------------------"
