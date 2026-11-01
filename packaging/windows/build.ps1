# Cleanroom — Windows build script (PowerShell)
# Run from the repository root inside a venv that has the app requirements
# plus pyinstaller:
#   .\packaging\windows\build.ps1
# Produces dist\Cleanroom.exe

$ErrorActionPreference = "Stop"
$root = (Resolve-Path "$PSScriptRoot\../..").Path
Set-Location $root

if (-not (Test-Path "$root\venv")) {
    python -m venv venv
}
& "$root\venv\Scripts\python.exe" -m pip install -q -r requirements.txt pyinstaller
if ($LASTEXITCODE -ne 0) { throw "pip install failed" }

& "$root\venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean `
    packaging/windows/cleanroom.spec
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed" }

# first-run convenience: pre-install the Playwright Chromium for this user
& "$root\venv\Scripts\python.exe" -m playwright install chromium

Write-Host ""
Write-Host "Built: $root\dist\Cleanroom.exe"
Write-Host "Requirements on the target machine:"
Write-Host "  - WireGuard for Windows (https://download.wireguard.com/windows/)"
Write-Host "  - wg.exe + wireguard.exe on PATH or in 'C:\Program Files\WireGuard'"
Write-Host "  - The Playwright Chromium is downloaded per-user on first launch"
Write-Host "    (or pre-seed it with:  python -m playwright install chromium)"
