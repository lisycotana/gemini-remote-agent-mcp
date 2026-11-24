# Gemini Remote MCP Auto-Approval Helper (MV3 Extension)

A lightweight, zero-dependency Chrome/Edge Manifest V3 companion extension designed for `gemini-remote-agent-mcp` on `https://gemini.google.com/*`.

## Features

- **Bug-Safe Default (`Allow Once first`)**: Prioritizes clicking *Allow once / 允许一次* to avoid Gemini Web's known issue where clicking *Always allow* inside the chat popup resets settings back to *Always ask*. You can optionally switch to *Always Allow first*.
- **4-Language Matching + Exclusion Guard**: Supports English, 简体中文, 繁體中文, and 日本語 while strictly blocking destructive terms (*Delete, Remove, Deny, Cancel*).
- **Shadow DOM Piercing**: Handles Gemini's Material Web Components buttons.
- **6-Layer Circuit Breaker**: Quota/error stop, streaming settle delay, cooldown, per-task cap, daily cap, and stagnant-output detection, plus a one-click **Emergency Stop**.
- **Hold-to-Drag HUD & Keepalive**: Auto dark/light floating status badge, MV3 keepalive alarm, tab discard protection, and one-click MCP `/healthz` probe.

## Install (Developer Mode)

1. Open `chrome://extensions/` or `edge://extensions/`.
2. Enable **Developer mode**.
3. Click **Load unpacked** and select this `extension/` folder.
4. Open `https://gemini.google.com/` and toggle the helper from the popup or floating HUD.

> Pair with server-side guards (`MCP_MAX_TOOL_CALLS_PER_MINUTE=60`, `MCP_MAX_REPEAT_MUTATIONS=5`) for defense-in-depth.
