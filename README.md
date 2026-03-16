# NetSage: AI-Powered Network Intelligence

NetSage is a next-generation AI network intelligence tool that lives in your terminal. It brings conversational, agentic investigation to the command line — enabling engineers, security analysts, and SREs to diagnose, monitor, and reason about networks.

## Features
- **Multi-Model Support**: Integrated with **Anthropic Claude**, **OpenAI GPT**, and **Google Gemini**.
- **Natural Language Interaction**: "Why is my latency to 8.8.8.8 spiking?"
- **Autonomous Tooling**: Automatically runs ping, traceroute, nmap, and tcpdump.
- **Topology Visualization**: Real-time ASCII network mapping (`Ctrl+T`).
- **Audit Logging**: Every action recorded in a SQLite session store.
- **Safety**: Three approval modes (Read-Only, Supervised, Autonomous).

## Installation

```bash
curl -sSL https://raw.githubusercontent.com/thrive-spectrexq/netsage/master/install.sh | bash
```

1. Set your API key in your environment:
   - **Windows (PowerShell)**: `$env:GEMINI_API_KEY = "your_key_here"`
   - **Linux/macOS**: `export GEMINI_API_KEY=your_key_here`
2. Create a `NETWORK.md` file in your project root for context.
3. Select your provider in `config.toml`:
   ```toml
   [core]
   provider = "gemini"
   model = "gemini-3.1-pro"
   ```
4. Run `cargo build` and then the binary.

### Windows Build Requirements
To build NetSage on Windows, you must have the **Npcap SDK** installed so that the packet engine can link against `wpcap.lib`.
1. Download the **Npcap SDK** from [nmap.org/npcap/](https://nmap.org/npcap/).
2. Extract it and set the `LIB` environment variable to point to the `Lib\x64` folder.

## Key Commands
- `q`: Quit.
- `Ctrl+T`: Toggle Topology View.
- `/clear`: Clear investigation history.
- `/export`: Generate a Markdown report from the current session.

## Architecture
- **Rust Core**: Ratatui TUI, Agent Loop, Packet Engine.
- **Python Sidecar**: Scapy, Nmap, Paramiko, NAPALM.
- **Brain**: Powered by Claude 4.6 Sonnet.
