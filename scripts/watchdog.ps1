param(
    [int]$RestartDelaySeconds = 5
)

$ErrorActionPreference = "Continue"
$createdNew = $false
$mutex = [System.Threading.Mutex]::new($true, "Local\GeminiRemoteMCPWatchdog", [ref]$createdNew)
if (-not $createdNew) {
    exit 0
}

$LogDirectory = Join-Path $env:LOCALAPPDATA "GeminiRemoteMCP"
$EventLog = Join-Path $LogDirectory "watchdog.log"
$ServerLog = Join-Path $LogDirectory "server.log"
$ServerErrorLog = Join-Path $LogDirectory "server-error.log"
$ServerScript = Join-Path $PSScriptRoot "start-local.ps1"
New-Item -ItemType Directory -Force -Path $LogDirectory | Out-Null

function Write-WatchdogEvent([string]$Message) {
    $entry = "{0} {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Add-Content -LiteralPath $EventLog -Value $entry -Encoding utf8
}

try {
    Write-WatchdogEvent "Watchdog started (PID $PID)."
    while ($true) {
        foreach ($path in @($EventLog, $ServerLog, $ServerErrorLog)) {
            if ((Test-Path -LiteralPath $path) -and (Get-Item -LiteralPath $path).Length -gt 5MB) {
                Move-Item -LiteralPath $path -Destination "$path.1" -Force
            }
        }
        Write-WatchdogEvent "Starting MCP server."
        try {
            $process = Start-Process -FilePath "powershell.exe" `
                -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$ServerScript`"" `
                -WorkingDirectory (Split-Path -Parent $PSScriptRoot) `
                -WindowStyle Hidden -Wait -PassThru `
                -RedirectStandardOutput $ServerLog -RedirectStandardError $ServerErrorLog
            Write-WatchdogEvent "MCP server exited with code $($process.ExitCode); restarting in ${RestartDelaySeconds}s."
        } catch {
            Write-WatchdogEvent "MCP launcher failed: $($_.Exception.Message); restarting in ${RestartDelaySeconds}s."
        }
        Start-Sleep -Seconds $RestartDelaySeconds
    }
} finally {
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}
