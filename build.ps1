# Build FreeGSM (Rust) into a distributable folder.
#
#   powershell -ExecutionPolicy Bypass -File .\build.ps1
#
# Output: dist\FreeGSM.exe  + WinDivert.dll + WinDivert64.sys
#   * FreeGSM.exe self-elevates via an embedded UAC manifest (release build).
#   * WinDivert.dll is the user-mode library, compiled from the vendored 2.2.2
#     source by the `windivert` crate at build time.
#   * WinDivert64.sys is the SIGNED kernel driver -- a driver cannot be
#     self-signed, so we ship WinDivert's official 2.2.2 signed binary (the same
#     one pydivert bundles, which matches the compiled DLL version).

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "Building release binary (this enables opt-level=z + LTO)..." -ForegroundColor Cyan
cargo build --release
if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

$dist = Join-Path $PSScriptRoot "dist"
New-Item -ItemType Directory -Force $dist | Out-Null
Copy-Item "target\release\FreeGSM.exe" $dist -Force

# 1) WinDivert.dll -- compiled from the vendored source under target\release\build.
$dll = Get-ChildItem "target\release\build" -Recurse -Filter "WinDivert.dll" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $dll) { throw "Compiled WinDivert.dll not found under target\release\build" }
Copy-Item $dll.FullName $dist -Force
Write-Host "Bundled WinDivert.dll  <- $($dll.FullName)" -ForegroundColor Cyan

# 2) WinDivert64.sys -- the signed kernel driver (v2.2.2).
$sysPath = $null
try {
    $pyDir = python -c "import os, pydivert; print(os.path.join(os.path.dirname(pydivert.__file__), 'windivert_dll'))" 2>$null
    if ($pyDir) {
        $cand = Join-Path $pyDir "WinDivert64.sys"
        if (Test-Path $cand) { $sysPath = $cand }
    }
} catch {}
if (-not $sysPath) {
    # Fallback: a windivert\ folder checked into the repo.
    $cand = Join-Path $PSScriptRoot "windivert\WinDivert64.sys"
    if (Test-Path $cand) { $sysPath = $cand }
}
if (-not $sysPath) {
    throw "Signed WinDivert64.sys (v2.2.2) not found. Install pydivert (pip install pydivert) or place WinDivert64.sys in .\windivert\"
}
Copy-Item $sysPath $dist -Force
Write-Host "Bundled WinDivert64.sys (signed)  <- $sysPath" -ForegroundColor Cyan

$exe = Get-Item (Join-Path $dist "FreeGSM.exe")
Write-Host ""
Write-Host ("Done -> dist\   FreeGSM.exe = {0:N2} MB (+ WinDivert.dll + WinDivert64.sys)" -f ($exe.Length / 1MB)) -ForegroundColor Green
Write-Host "Launch dist\FreeGSM.exe (it prompts for UAC; all three files must stay together)." -ForegroundColor Green
