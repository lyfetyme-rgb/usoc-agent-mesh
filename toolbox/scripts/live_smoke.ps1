# Read-only local smoke for the USOC mesh.
# No network, no secrets, no writes. Run from toolbox/scripts/.
# Usage: ./live_smoke.ps1

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Push-Location $Root
try {
    Write-Host "== agents doctor ==" -ForegroundColor Cyan
    python -m agents doctor; if ($LASTEXITCODE -ne 0) { throw "doctor failed" }

    Write-Host "== integrity digest ==" -ForegroundColor Cyan
    python -m agents integrity --check; if ($LASTEXITCODE -ne 0) { throw "integrity failed" }

    Write-Host "== test suite ==" -ForegroundColor Cyan
    python -m pytest -q; if ($LASTEXITCODE -ne 0) { throw "pytest failed" }

    Write-Host "SMOKE: PASS" -ForegroundColor Green
    exit 0
} catch {
    Write-Host "SMOKE: FAIL - $($_.Exception.Message)" -ForegroundColor Red
    exit 1
} finally {
    Pop-Location
}
