$ServerScript = Join-Path $PSScriptRoot "start-local.ps1"
$MonitorScript = Join-Path $PSScriptRoot "watch-connection.ps1"

Write-Host "Starting MCP server in a separate window..." -ForegroundColor Cyan
Start-Process -FilePath "powershell.exe" `
    -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-File", "`"$ServerScript`"" `
    -WorkingDirectory (Split-Path -Parent $PSScriptRoot) `
    -WindowStyle Normal

& $MonitorScript
