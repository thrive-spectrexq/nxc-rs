# Telegram C2 (APEX-REAPER)

NetExec-RS includes a built-in Telegram Bot engine that essentially turns the binary into a full Command & Control (C2) and team-server infrastructure framework.

## Activating the APEX-REAPER Server

1. **Get an API Token:** Talk to [@BotFather](https://t.me/BotFather) on Telegram and create a new bot to get your API Token.
2. **Configure Environment:** Create a `.env` file in the root of the project directory or export it as an environment variable:
   ```env
   TELEGRAM_BOT_TOKEN="your_token_here"
   ```
3. **Launch the Server:** Run the Telegram daemon mode on a host you want acting as your operational hub.
   ```bash
   nxc telegram
   ```

## Using the Telegram Bot

Once the bot starts, send it a private message or add it to a secure team channel. The bot acts as an interactive shell for the entire framework.

### Core Commands

*   `/ping` - Ensure the host backend is alive.
*   `/dns <target>` - Perform quick tactical DNS resolution from the C2 host.
*   `/geo <ip>` - IP Geolocation lookup.

### Execution Commands

You can run full NetExec-RS jobs exactly as you would on the CLI. The bot processes it, streams execution, and formats output.

*   `/run smb 192.168.1.0/24 -u Admin -p Password123`
*   `/run ldap 10.10.10.5 -u svc_account -p secret -M bloodhound`

### Interactive Tools

*   `/shell` - Spawns a multi-turn interactive session. Any standard bash/PowerShell command you type is automatically forwarded to the target via the protocol set.
*   `/ai <prompt>` - Invokes the Autonomous AI Orchestrator within the Telegram chat for natural-language ops.

### Reconnaissance Shortcuts

If you have valid credentials stored in the `nxc.db`, you can use these shortcuts to immediately dump data:
*   `/shares` - Dump all network shares on a known target.
*   `/users` - Dump LDAP/SAM users.
*   `/groups` - Dump Active Directory group structures.

> [!CAUTION]
> **OPSEC Warning:** All bot traffic flows through Telegram servers. While TLS encrypted, do not send highly sensitive plaintext passwords or client-identifying PII through Telegram chats.
