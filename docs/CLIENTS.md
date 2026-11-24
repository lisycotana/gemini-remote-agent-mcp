# Client Integration Guide (Web & Desktop)

`gemini-remote-agent-mcp` supports **Dual Transport**:

- **Streamable HTTP (`--transport http`)** for **Gemini Web Custom Apps** and remote Gemini CLI over HTTPS + OAuth 2.1.
- **Stdio (`--transport stdio`)** for local desktop/terminal clients (**Gemini CLI**, **Claude Desktop**, **Cursor**, **Windsurf**, **VS Code**) with zero network ports.

You can generate ready-to-paste snippets at any time:

```bash
uv run remote-agent-mcp --check
uv run remote-agent-mcp --print-client-config gemini-cli
uv run remote-agent-mcp --print-client-config gemini-cli-http
uv run remote-agent-mcp --print-client-config claude-desktop
uv run remote-agent-mcp --print-client-config cursor
uv run remote-agent-mcp --print-client-config gemini-web
```

---

## 1. Gemini Web Custom App (+ Optional Auto-Approval Helper)

1. Run the server in stateless Streamable HTTP mode with OAuth 2.1 enabled (`MCP_AUTH_ENABLED=true`, `MCP_STATELESS_HTTP=true`, `MCP_JSON_RESPONSE=true`).
2. Expose `http://127.0.0.1:8000` over HTTPS (e.g., Tailscale Funnel or Cloudflare Tunnel) and add `https://<your-domain>/mcp` under **Settings → Connected apps → Add custom app**.
3. **Working around repeated approval prompts**: Gemini Web currently prompts on write/exec actions and may reset permissions if "Always allow" is clicked inside the chat popup. If you pair this server with a browser helper such as [KenEasy-Gemini-MCP-Auto-Helper](https://github.com/ngiken/KenEasy-Gemini-MCP-Auto-Helper), enable the **server-side circuit breaker** as a second safety net:

```dotenv
MCP_MAX_TOOL_CALLS_PER_MINUTE=60
MCP_MAX_REPEAT_MUTATIONS=5
# Optional: flip to true when you want strictly read-only exploration
MCP_READ_ONLY_MODE=false
```

---

## 2. Gemini CLI (Desktop / Terminal)

Add to `~/.gemini/settings.json` (local `stdio` mode — no tunnel or OAuth needed):

```json
{
  "mcpServers": {
    "gemini-remote-agent": {
      "command": "uv",
      "args": ["run", "--project", "/path/to/gemini-remote-agent-mcp", "remote-agent-mcp", "--transport", "stdio"],
      "env": {
        "MCP_WORKSPACE_ROOT": "/path/to/your/workspace",
        "MCP_AUTH_ENABLED": "false"
      },
      "trust": false
    }
  }
}
```

Or connect Gemini CLI to a remote instance over Streamable HTTP:

```json
{
  "mcpServers": {
    "gemini-remote-agent": {
      "httpUrl": "https://mcp.example.com/mcp",
      "trust": false
    }
  }
}
```

---

## 3. Claude Desktop / Cursor / VS Code

Use the same `stdio` entry in `claude_desktop_config.json` or `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "gemini-remote-agent": {
      "command": "uv",
      "args": ["run", "--project", "/path/to/gemini-remote-agent-mcp", "remote-agent-mcp", "--transport", "stdio"],
      "env": {
        "MCP_WORKSPACE_ROOT": "/path/to/your/workspace",
        "MCP_AUTH_ENABLED": "false"
      }
    }
  }
}
```
