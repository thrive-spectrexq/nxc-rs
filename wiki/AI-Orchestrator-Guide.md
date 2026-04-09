# Autonomous AI Orchestrator (Elite Reaper)

NetExec-RS includes **Elite Reaper**, a massive integrated AI framework powered by Google Gemini and other LLMs. It is designed to act as an autonomous offensive orchestrator, allowing operators to conduct complex campaigns using natural language.

## Launching the AI Agent

You can engage the AI from two vectors:
1. **Direct CLI:**
   ```bash
   nxc ai "List all Domain Admins on 10.0.0.1"
   ```
2. **Telegram Bot:**
   ```
   /ai Scan the 192.168.5.0/24 subnet for IPMI interfaces and dump HASHS
   ```

## Under the Hood: Tool Execution

When you issue a prompt, the AI does *not* just reply with text. The `nxc-ai` crate binds the internal NetExec-RS execution engine directly to the AI as a native function via `ProtocolTool`. 

1. **Reasoning:** Local models analyze the request.
2. **Execution:** The AI constructs an API call firing the `nxc-protocols` engine.
3. **Ingestion:** The AI digests the raw JSON logs and terminal output from the protocol.
4. **Loop:** If it finds a vulnerability, it might chain another module automatically!

## Multi-Turn Conversations

By default, the engine drops you into a conversational shell if you don't provide a direct argument.

```
$ nxc ai
[Elite Reaper v0.4.0 Activated]
Reaper> Start by checking smb signing on 10.10.10.0/24
... (Scans and gives output)
Reaper> Ok, I see 10.10.10.5 doesn't require signing. Let's try to pass-the-hash there using user Administrator and hash 31d6...
... (Executes the pass the hash attack automatically)
```

## OpSec and AI Constraints

> [!WARNING]  
> The AI is constrained by `SafeToAutoRun` logic. It is programmed to freely scan and query systems (LDAP/SMB unauthenticated or with provided creds). However, it will **ask for explicit confirmation** before doing something destructive like dropping an Empire payload or altering the remote registry.
