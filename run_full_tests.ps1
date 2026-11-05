param(
    [string]$PythonExe = "",
    [switch]$IncludeDemos
)

$ErrorActionPreference = "Stop"
$RootDir = $PSScriptRoot
Set-Location -LiteralPath $RootDir

if (-not $PythonExe) {
    $VenvPy = Join-Path $RootDir ".venv\Scripts\python.exe"
    if (Test-Path -LiteralPath $VenvPy) {
        $PythonExe = $VenvPy
    } else {
        $PythonExe = "python"
    }
}

$FoundryDir = Join-Path $RootDir "tools\foundry"
$env:PATH = "$FoundryDir;$env:PATH"
$env:FORENSICS_OFFLINE = "1"
$env:AI_PROVIDER = "none"
$env:ANCHOR_CHAIN_ID = "31337"
$env:ANCHOR_RPC_URL = "http://127.0.0.1:8545"
$env:PYTHONUTF8 = "1"
$env:PYDANTIC_AI_NO_BANNER = "1"

Write-Host "==============================================================================="
Write-Host "Blockchain + AI Digital Forensics (v6.0) - Full Offline Test Runner"
Write-Host "Working Directory: $RootDir"
Write-Host "Python Interpreter: $PythonExe"
Write-Host "==============================================================================="

# 1. Pre-flight Canonical Database Invariance
$VerifyScript = Join-Path $RootDir "verify_integrity.ps1"
& powershell -NoProfile -ExecutionPolicy Bypass -File $VerifyScript -CanonicalOnly
if ($LASTEXITCODE -ne 0) { exit 1 }

# 2. Full Foundry Smart Contract Test Suite (All 7 Suites / 175 Tests)
Write-Host "`n[1/3] Running Full Foundry Smart Contract Test Suite..."
$ForgeBin = Join-Path $FoundryDir "forge.exe"
& $ForgeBin test --root contracts
if ($LASTEXITCODE -ne 0) { Write-Error "Foundry test suite failed"; exit 1 }

# 3. Full Pytest Regression & Challenger Suite
Write-Host "`n[2/3] Running Full Pytest Suite..."
$TempBase = Join-Path ([System.IO.Path]::GetTempPath()) ("forensics_full_" + [guid]::NewGuid().ToString("N").Substring(0, 8))
try {
    & $PythonExe -m pytest tests --basetemp="$TempBase" -v --tb=short
    if ($LASTEXITCODE -ne 0) { Write-Error "Full Pytest suite failed"; exit 1 }
} finally {
    if (Test-Path -LiteralPath $TempBase) {
        Remove-Item -LiteralPath $TempBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# 4. Optional Live End-to-End Demos (D1, D2, D3)
if ($IncludeDemos) {
    Write-Host "`n[2b/3] Executing End-to-End Demos D1, D2, and D3..."
    & $PythonExe scripts\demo_d1_evm.py
    if ($LASTEXITCODE -ne 0) { Write-Error "Demo D1 failed"; exit 1 }
    & $PythonExe scripts\demo_d2_host.py
    if ($LASTEXITCODE -ne 0) { Write-Error "Demo D2 failed"; exit 1 }
    & $PythonExe scripts\demo_d3_adversarial.py
    if ($LASTEXITCODE -ne 0) { Write-Error "Demo D3 failed"; exit 1 }
}

# 5. Post-flight Canonical Database Bitwise Invariance
Write-Host "`n[3/3] Verifying post-test canonical database bitwise invariance..."
& powershell -NoProfile -ExecutionPolicy Bypass -File $VerifyScript -CanonicalOnly
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "`n==============================================================================="
Write-Host "FULL TEST SUITE PASSED SUCCESSFULLY (EXIT CODE 0)"
Write-Host "==============================================================================="
exit 0
