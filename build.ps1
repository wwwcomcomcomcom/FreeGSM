# Build FreeGSM into a single self-elevating .exe.
#
#   powershell -ExecutionPolicy Bypass -File .\build.ps1
#
# Output: dist\FreeGSM.exe  (prompts for UAC on launch; WinDivert needs admin)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "Installing dependencies..." -ForegroundColor Cyan
python -m pip install -r requirements.txt pyinstaller | Out-Null

# Locate the WinDivert binaries bundled inside pydivert so we can embed them.
$dllDir = python -c "import os, pydivert; print(os.path.join(os.path.dirname(pydivert.__file__), 'windivert_dll'))"
$dll = Join-Path $dllDir "WinDivert64.dll"
$sys = Join-Path $dllDir "WinDivert64.sys"
if (-not (Test-Path $dll) -or -not (Test-Path $sys)) {
    throw "WinDivert binaries not found in pydivert at $dllDir"
}
Write-Host "Embedding WinDivert from $dllDir" -ForegroundColor Cyan

# pydivert loads the driver from <pkg>/windivert_dll/, so place both files there.
$dest = "pydivert/windivert_dll"

python -m PyInstaller `
    --onefile `
    --uac-admin `
    --name FreeGSM `
    --icon freegsm.ico `
    --clean --noconfirm `
    --add-binary "$dll;$dest" `
    --add-binary "$sys;$dest" `
    --collect-submodules h2 `
    --collect-submodules hpack `
    --collect-submodules hyperframe `
    run.py

Write-Host "`nDone -> dist\FreeGSM.exe" -ForegroundColor Green
