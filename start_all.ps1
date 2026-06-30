# LegitC2 — Lance le serveur + l'UI en arrière-plan
# Usage:
#   .\start_all.ps1        -> Serveur HTTPS 8443 + UI (npm run dev)
#   .\start_all.ps1 -Dev   -> Serveur HTTP  8000 + UI (npm run dev)
#   Ctrl+C pour tout arrêter

param([switch]$Dev)

$root = Split-Path -Parent $MyInvocation.MyCommand.Path

# --- Tuer les instances existantes ---
foreach ($port in @(8443, 8000, 3000)) {
    $pids = (netstat -ano | Select-String ":$port\s") |
            ForEach-Object { ($_ -split '\s+')[-1] } |
            Sort-Object -Unique
    foreach ($pid in $pids) {
        if ($pid -match '^\d+$' -and $pid -ne '0') {
            Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
            Write-Host "[*] Processus $pid sur :$port arrêté." -ForegroundColor DarkYellow
        }
    }
}
Start-Sleep -Milliseconds 500

# --- Serveur ---
Write-Host "[*] Démarrage du serveur..." -ForegroundColor Cyan
if ($Dev) {
    $serverJob = Start-Job -ScriptBlock {
        param($r)
        Set-Location "$r\server"
        & "venv\Scripts\python.exe" -m uvicorn main:app --host 0.0.0.0 --port 8000 --log-level info
    } -ArgumentList $root
} else {
    $serverJob = Start-Job -ScriptBlock {
        param($r)
        Set-Location "$r\server"
        & "venv\Scripts\python.exe" -m uvicorn main:app --host 0.0.0.0 --port 8443 --ssl-certfile cert.pem --ssl-keyfile key.pem --log-level info
    } -ArgumentList $root
}

# --- UI ---
Write-Host "[*] Démarrage de l'UI..." -ForegroundColor Cyan
$uiJob = Start-Job -ScriptBlock {
    param($r)
    Set-Location "$r\ui"
    npm run dev
} -ArgumentList $root

Write-Host "[+] Serveur (Job $($serverJob.Id)) et UI (Job $($uiJob.Id)) lancés en arrière-plan." -ForegroundColor Green
Write-Host "    Logs en direct : Receive-Job -Id <id> -Keep" -ForegroundColor DarkGray
Write-Host "    Arrêter tout   : Stop-Job $($serverJob.Id), $($uiJob.Id)" -ForegroundColor DarkGray
Write-Host ""
Write-Host "[*] Affichage des logs (Ctrl+C pour quitter)..." -ForegroundColor Yellow

try {
    while ($true) {
        Receive-Job -Job $serverJob | ForEach-Object { Write-Host "[server] $_" }
        Receive-Job -Job $uiJob    | ForEach-Object { Write-Host "[ui]     $_" }
        Start-Sleep -Milliseconds 500
    }
} finally {
    Write-Host "`n[*] Arrêt..." -ForegroundColor Yellow
    Stop-Job  $serverJob, $uiJob
    Remove-Job $serverJob, $uiJob
    Write-Host "[+] Arrêté." -ForegroundColor Green
}
