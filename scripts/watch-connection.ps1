param(
    [string]$PublicUrl = $(if ($env:MCP_PUBLIC_ORIGIN) { $env:MCP_PUBLIC_ORIGIN } else { "https://mcp.example.com" }),
    [int]$LocalPort = 8787,
    [int]$IntervalSeconds = 5,
    [int]$TimeoutSeconds = 8
)

$ErrorActionPreference = "SilentlyContinue"
$PublicUrl = $PublicUrl.TrimEnd("/")
$LogDirectory = Join-Path $env:LOCALAPPDATA "GeminiRemoteMCP"
$LogPath = Join-Path $LogDirectory "connection-status.log"
New-Item -ItemType Directory -Force -Path $LogDirectory | Out-Null
$previousStatuses = @{}

function Test-LocalServer {
    $connection = Get-NetTCPConnection -LocalPort $LocalPort -State Listen -ErrorAction SilentlyContinue
    if (-not $connection) {
        return @{ Status = "DOWN"; Detail = "port $LocalPort is not listening" }
    }

    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$LocalPort/healthz" `
            -TimeoutSec $TimeoutSeconds -SkipHttpErrorCheck
        if ($response.StatusCode -eq 200) {
            return @{ Status = "OK"; Detail = "healthz HTTP 200" }
        }
        return @{ Status = "WARN"; Detail = "unexpected HTTP $($response.StatusCode)" }
    } catch {
        return @{ Status = "DOWN"; Detail = $_.Exception.Message }
    }
}

function Test-PublicEndpoint {
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri "$PublicUrl/healthz" `
            -TimeoutSec $TimeoutSeconds -SkipHttpErrorCheck
        if ($response.StatusCode -eq 200) {
            return @{ Status = "OK"; Detail = "healthz HTTP 200" }
        }
        if ($response.StatusCode -eq 502) {
            return @{ Status = "BAD"; Detail = "HTTP 502 (Funnel proxy/backend failure)" }
        }
        return @{ Status = "WARN"; Detail = "unexpected HTTP $($response.StatusCode)" }
    } catch {
        return @{ Status = "DOWN"; Detail = $_.Exception.Message }
    }
}

function Get-FunnelStatus {
    $tailscale = Get-Command tailscale -ErrorAction SilentlyContinue
    if (-not $tailscale) {
        return @{ Status = "WARN"; Detail = "tailscale command not found" }
    }
    $status = (& tailscale funnel status 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) {
        return @{ Status = "BAD"; Detail = ($status.Trim() -split "\r?\n")[0] }
    }
    if ($status -match [regex]::Escape($PublicUrl) -and $status -match "127\.0\.0\.1:$LocalPort") {
        return @{ Status = "OK"; Detail = "enabled -> 127.0.0.1:$LocalPort" }
    }
    return @{ Status = "BAD"; Detail = "missing expected Funnel mapping" }
}

while ($true) {
    $results = [ordered]@{
        "LOCAL" = Test-LocalServer
        "FUNNEL" = Get-FunnelStatus
        "PUBLIC" = Test-PublicEndpoint
    }
    $now = Get-Date
    Clear-Host
    Write-Host "Gemini MCP connection monitor  |  Ctrl+C to stop" -ForegroundColor Cyan
    Write-Host "Updated: $($now.ToString('yyyy-MM-dd HH:mm:ss'))  |  Every ${IntervalSeconds}s"
    Write-Host "Log: $LogPath" -ForegroundColor DarkGray
    Write-Host ""

    foreach ($name in $results.Keys) {
        $result = $results[$name]
        $color = if ($result.Status -eq "OK") { "Green" } elseif ($result.Status -eq "WARN") { "Yellow" } else { "Red" }
        Write-Host ("{0,-7} {1,-5} {2}" -f $name, $result.Status, $result.Detail) -ForegroundColor $color

        if ($previousStatuses[$name] -and $previousStatuses[$name] -ne $result.Status) {
            $entry = "{0} {1}: {2} -> {3} ({4})" -f `
                $now.ToString("yyyy-MM-dd HH:mm:ss"), $name, $previousStatuses[$name], `
                $result.Status, $result.Detail
            Add-Content -LiteralPath $LogPath -Value $entry -Encoding utf8
        }
        $previousStatuses[$name] = $result.Status
    }

    Write-Host ""
    if ($results.LOCAL.Status -ne "OK") {
        Write-Host "Diagnosis: local MCP server is unavailable. Restart scripts\start-local.ps1." -ForegroundColor Red
    } elseif ($results.FUNNEL.Status -ne "OK") {
        Write-Host "Diagnosis: local server is healthy, but Tailscale Funnel is not configured." -ForegroundColor Yellow
    } elseif ($results.PUBLIC.Status -ne "OK") {
        Write-Host "Diagnosis: local server is healthy. Failure is in Tailscale/public network path." -ForegroundColor Yellow
    } else {
        Write-Host "All checks passed. OAuth remains enabled for /mcp." -ForegroundColor Green
    }
    Start-Sleep -Seconds $IntervalSeconds
}
