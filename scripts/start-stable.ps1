$ErrorActionPreference = "Stop"
$Watchdog = Join-Path $PSScriptRoot "watchdog.ps1"
$HealthUrl = "http://127.0.0.1:8787/healthz"

Start-Process -FilePath "powershell.exe" `
    -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", "`"$Watchdog`"" `
    -WorkingDirectory (Split-Path -Parent $PSScriptRoot) `
    -WindowStyle Hidden

$healthy = $false
for ($attempt = 0; $attempt -lt 40; $attempt++) {
    Start-Sleep -Milliseconds 500
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri $HealthUrl -TimeoutSec 2
        if ($response.StatusCode -eq 200) {
            $healthy = $true
            break
        }
    } catch {
    }
}
if (-not $healthy) {
    throw "MCP did not become healthy. Check $env:LOCALAPPDATA\GeminiRemoteMCP\watchdog.log"
}
Write-Host "MCP watchdog is running; crashes restart automatically after 5 seconds." -ForegroundColor Green
Write-Host "Health: $HealthUrl"
Write-Host "Status: powershell -ExecutionPolicy Bypass -File `"$PSScriptRoot\watch-connection.ps1`""
