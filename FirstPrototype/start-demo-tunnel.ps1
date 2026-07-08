param(
    [int]$FrontendPort = 3000,
    [int]$BackendPort = 8000
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$BackendDir = Join-Path $Root "backend"
$FrontendDir = Join-Path $Root "frontend"
$FrontendUrl = "http://localhost:$FrontendPort"

if (-not (Test-Path (Join-Path $BackendDir "main.py"))) {
    throw "Backend entrypoint not found. Run this script from the FirstPrototype folder."
}

if (-not (Test-Path (Join-Path $FrontendDir "package.json"))) {
    throw "Frontend package.json not found. Run this script from the FirstPrototype folder."
}

$PythonExe = Join-Path $BackendDir "venv\Scripts\python.exe"
if (-not (Test-Path $PythonExe)) {
    $PythonExe = "python"
}

Write-Host "Starting backend on http://localhost:$BackendPort ..."
$BackendProcess = Start-Process `
    -FilePath $PythonExe `
    -ArgumentList "main.py" `
    -WorkingDirectory $BackendDir `
    -PassThru `
    -WindowStyle Hidden

Write-Host "Starting frontend on $FrontendUrl ..."
$FrontendProcess = Start-Process `
    -FilePath "npm" `
    -ArgumentList "run", "dev", "--", "--host", "0.0.0.0", "--port", "$FrontendPort" `
    -WorkingDirectory $FrontendDir `
    -PassThru `
    -WindowStyle Hidden

try {
    Start-Sleep -Seconds 6

    $LocalCloudflared = Join-Path $Root "tools\cloudflared.exe"
    $Cloudflared = Get-Command cloudflared -ErrorAction SilentlyContinue
    if (-not $Cloudflared -and (Test-Path $LocalCloudflared)) {
        $Cloudflared = [PSCustomObject]@{ Source = $LocalCloudflared }
    }
    if ($Cloudflared) {
        Write-Host "Opening Cloudflare Quick Tunnel for $FrontendUrl ..."
        Write-Host "Share the generated trycloudflare.com URL with SUS participants."
        & $Cloudflared.Source tunnel --url $FrontendUrl
        exit $LASTEXITCODE
    }

    $Ngrok = Get-Command ngrok -ErrorAction SilentlyContinue
    if ($Ngrok) {
        Write-Host "Opening ngrok tunnel for $FrontendUrl ..."
        Write-Host "Share the generated forwarding URL with SUS participants."
        & $Ngrok.Source http $FrontendPort
        exit $LASTEXITCODE
    }

    Write-Host "No tunnel tool found."
    Write-Host "Recommended quick install: install cloudflared, then rerun this script."
    Write-Host "Manual tunnel command after install: cloudflared tunnel --url $FrontendUrl"
    Write-Host "Local demo URL: $FrontendUrl"
}
finally {
    if ($FrontendProcess -and -not $FrontendProcess.HasExited) {
        Stop-Process -Id $FrontendProcess.Id -Force
    }
    if ($BackendProcess -and -not $BackendProcess.HasExited) {
        Stop-Process -Id $BackendProcess.Id -Force
    }
}
