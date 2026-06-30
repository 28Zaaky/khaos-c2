# LegitC2 team server — Windows start script
# Usage:
#   .\start.ps1          -> HTTPS port 8443 (cert.pem / key.pem)
#   .\start.ps1 -Dev     -> HTTP  port 8000 (local testing)

param([switch]$Dev)

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

if ($Dev) {
    Write-Host "[start] DEV mode — HTTP 0.0.0.0:8000"
    & "venv\Scripts\python.exe" -m uvicorn main:app `
        --host 0.0.0.0 `
        --port 8000 `
        --log-level info
} else {
    if (-not (Test-Path "cert.pem") -or -not (Test-Path "key.pem")) {
        Write-Error "cert.pem / key.pem not found — run gen_cert.ps1 first"
        exit 1
    }
    Write-Host "[start] PROD mode — HTTPS 0.0.0.0:8443"
    & "venv\Scripts\python.exe" -m uvicorn main:app `
        --host 0.0.0.0 `
        --port 8443 `
        --ssl-certfile cert.pem `
        --ssl-keyfile  key.pem `
        --log-level info
}
