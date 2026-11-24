# Gemini Remote Agent MCP: implementation plan

## Scope and architecture

The deliverable is a standard MCP Streamable HTTP resource server, not a browser
extension or an SSH wrapper. Gemini supplies the conversation UI; this project
supplies workspace tools. A reverse tunnel supplies HTTPS and an external OIDC
provider issues OAuth tokens.

- 12 tools: discovery/read, exact edits, command jobs, and Git inspection/recovery.
- Read/write/exec OAuth scopes are checked independently at each tool boundary.
- Paths are workspace-relative, sensitive-file filtered, and symlink constrained.
- Atomic UTF-8 writes preserve existing permissions and return unified diffs.
- Long jobs have process-tree cleanup, concurrency limits, and incremental logs.
- Public execution requires an OS sandbox; `sandbox_mode=none` is not isolation.

## Delivery order

1. Implement path security, file tools, process management, and Git tools.
2. Add JWT/OAuth discovery and scoped authorization with a real MCP ASGI app.
3. Exercise tools through an MCP client, not only direct Python function calls.
4. Add Linux service/tunnel examples and verified Gemini connector instructions.

## Acceptance tests

- Reject traversal, absolute paths, symlink escape, denied files, and stale hashes.
- Verify atomic create/edit/overwrite and useful diff output.
- Verify command timeout, output truncation, background polling, and process kill.
- Verify protected-resource discovery, JWT issuer/audience/subject, and scope denial.
- Initialize/list/call over Streamable HTTP using the official MCP client.
- Check Windows development support and Linux bubblewrap construction separately.

## Deliberate limitations

- No interactive PTY, IDE diff pane, or custom Gemini user interface is promised.
- OAuth client registration/authorization is delegated to the identity provider.
- Secret redaction reduces accidental exposure but is not a data-loss-prevention guarantee.
- Background jobs are in-memory and do not survive an MCP server restart.
