# Project instructions

This is a remote-machine MCP server for Gemini's custom-app connector.

- Keep Python 3.11 compatibility and the MCP Python SDK v1 API.
- Treat command execution as a privileged boundary. Application path checks alone are not a command sandbox; public deployments must use OAuth and OS isolation.
- Preserve workspace-relative tool paths and never return secrets or host log paths to clients.
- Every file mutation must return a unified diff and use optimistic concurrency checks when replacing an existing file.
- Run the unit tests and the real Streamable HTTP MCP integration test before declaring completion.
