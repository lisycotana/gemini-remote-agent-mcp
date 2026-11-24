param(
    [string]$Workspace = "$env:USERPROFILE\gemini-workspace",
    [int]$Port = 8787
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$env:PYTHONPATH = Join-Path $ProjectRoot "src"
$env:MCP_WORKSPACE_ROOT = $Workspace
$env:MCP_HOST = "127.0.0.1"
$env:MCP_PORT = [string]$Port
$env:MCP_STATELESS_HTTP = "true"
$env:MCP_JSON_RESPONSE = "true"
$env:MCP_SESSION_IDLE_TIMEOUT = "7776000"
$env:MCP_SSE_RETRY_INTERVAL = "15000"
$env:MCP_AUTH_ENABLED = "true"
$env:MCP_LOCAL_OAUTH_PROVIDER = "true"
$publicOrigin = if ($env:MCP_PUBLIC_ORIGIN) { $env:MCP_PUBLIC_ORIGIN.TrimEnd("/") } else { "https://mcp.example.com" }
$publicHost = ([System.Uri]$publicOrigin).Authority
$env:MCP_RESOURCE_URL = "$publicOrigin/mcp"
$env:MCP_TRANSPORT_ALLOWED_HOSTS = "[`"$publicHost`",`"127.0.0.1:$Port`",`"localhost:$Port`"]"
$env:MCP_TRANSPORT_ALLOWED_ORIGINS = "[`"$publicOrigin`",`"http://127.0.0.1:$Port`"]"
$env:MCP_SANDBOX_MODE = "none"
$env:MCP_AUDIT_LOG_PATH = "$env:LOCALAPPDATA\GeminiRemoteMCP\audit.jsonl"
$env:MCP_JOBS_DIR = "$env:LOCALAPPDATA\GeminiRemoteMCP\jobs"

New-Item -ItemType Directory -Force -Path $Workspace, $env:MCP_JOBS_DIR | Out-Null
Write-Host "Workspace: $Workspace"
Write-Host "Local endpoint: http://127.0.0.1:$Port/mcp"
Write-Host "Public endpoint: $env:MCP_RESOURCE_URL"
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $Python)) {
    throw "Project virtual environment not found: $Python. Run 'py -3.13 -m venv .venv' and '.venv\Scripts\python.exe -m pip install -e .' in $ProjectRoot first."
}
& $Python -m remote_agent_mcp.server
