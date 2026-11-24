# Security checklist

## Before exposing the service

- Use a dedicated, non-sudo OS account with access only to the intended workspace.
- Enable OAuth, issuer/audience validation, an explicit subject allowlist, and HTTPS.
- Do not put OAuth client secrets in the MCP environment; they belong at Gemini and the IdP.
- Use `bwrap` or an equivalently reviewed container/VM boundary for shell commands.
- Keep network disabled unless dependency downloads are necessary.
- Set `MCP_TRANSPORT_ALLOWED_HOSTS` to the public hostname, not a wildcard.
- Store audit/job files outside the workspace with owner-only permissions.
- Back up the project independently. Git restore is not a backup system.

## Understand the limits

A caller allowed to run commands can modify any file available to the sandbox and
execute programs. Tool annotations are user-interface hints, not security controls.
Workspace path filtering does not stop a shell from reading a host file when
`sandbox_mode=none`. Output redaction is best-effort and can be bypassed by encoding.
OAuth scopes limit tool classes, not individual commands or paths.

## Incident response

Stop the public tunnel and MCP service, revoke the OAuth client and active tokens,
terminate remaining background processes, preserve audit logs, rotate credentials
that may have entered shell output or Gemini history, and restore the workspace from
a trusted backup. Review both the IdP logs and the service audit log before reconnecting.
