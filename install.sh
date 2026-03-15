#!/bin/bash
# NetSage One-Line Installer

set -e

echo "Installing NetSage v0.1.0..."

# Create local directories
mkdir -p ~/.netsage/python-engine

# [MOCK] Clone/Download repository
# git clone https://github.com/example/netsage ~/.netsage/src

# Setup Python environment
echo "Setting up Python Tool Engine..."
python3 -m venv ~/.netsage/venv
source ~/.netsage/venv/bin/activate
pip install -r requirements.txt

# [MOCK] Build/Install Rust Binary
# cargo install --path ~/.netsage/src/crates/netsage

echo "NetSage installed successfully!"
echo "Run 'netsage' to begin."
