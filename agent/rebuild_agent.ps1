$AgentDir = $PSScriptRoot
$Make     = "C:\msys64\usr\bin\make.exe"

Set-Location $AgentDir

# Kill agent if running, wait for OS to release file lock
Stop-Process -Name "agent" -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 800

# Step 1: regen obfuscation config + fresh EVS_KEY (polymorphisme par build)
Write-Host "[*] Generation config (EVS_KEY aleatoire)..." -ForegroundColor Cyan
$cfg_out = & $Make config 2>&1
$cfg_err = $cfg_out | Select-String -Pattern "error:" | Where-Object { $_ -notmatch "0 error" }
if ($cfg_err) {
    Write-Host "[!] Erreur config :" -ForegroundColor Red
    $cfg_err | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
    exit 1
}
$cfg_out | Select-String "\[ok\]|EVS_KEY" | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkCyan }

# Step 2: compile
Write-Host "[*] Compilation..." -ForegroundColor Cyan
$output = & $Make lean 2>&1
$errors = $output | Select-String -Pattern "error:" | Where-Object { $_ -notmatch "0 error" }

if ($errors) {
    Write-Host "[!] Erreurs de compilation :" -ForegroundColor Red
    $errors | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
    exit 1
}

$ok = $output | Select-String -Pattern "\[ok\]"
if ($ok) {
    Write-Host "[+] $ok" -ForegroundColor Green
} else {
    Write-Host "[?] Compilation terminee (verifier manuellement)" -ForegroundColor Yellow
    $output | Select-String -Pattern "warning:|error:" | ForEach-Object { Write-Host "    $_" }
}
