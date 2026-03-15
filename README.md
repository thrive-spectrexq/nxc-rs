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
curl -sSL https://netsage.dev/install.sh | bash
```

## Quick Start

1. Set your API key: 
   - `export ANTHROPIC_API_KEY=...`
   - or `export OPENAI_API_KEY=...`
   - or `export GEMINI_API_KEY=...`
2. Create a `NETWORK.md` file in your project root for context.
3. Select your provider in `config.toml`.
4. Run `netsage`.

## Key Commands
- `q`: Quit.
- `Ctrl+T`: Toggle Topology View.
- `/clear`: Clear investigation history.
- `/export`: Generate a Markdown report from the current session.

## Architecture
- **Rust Core**: Ratatui TUI, Agent Loop, Packet Engine.
- **Python Sidecar**: Scapy, Nmap, Paramiko, NAPALM.
- **Brain**: Powered by Claude 3.5 Sonnet.
