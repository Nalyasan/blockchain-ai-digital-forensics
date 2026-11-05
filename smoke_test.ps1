param(
    [string]$PythonExe = ""
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
Write-Host "Blockchain + AI Digital Forensics (v6.0) - Isolated Portable Smoke Test"
Write-Host "Working Directory: $RootDir"
Write-Host "Python Interpreter: $PythonExe"
Write-Host "==============================================================================="

# 1. Cryptographic Integrity Check
$VerifyScript = Join-Path $RootDir "verify_integrity.ps1"
$ShaSums = Join-Path $RootDir "SHA256SUMS.txt"
if (Test-Path -LiteralPath $ShaSums) {
    Write-Host "`n[1/5] Verifying full package SHA256SUMS.txt and canonical databases..."
    & powershell -NoProfile -ExecutionPolicy Bypass -File $VerifyScript
} else {
    Write-Host "`n[1/5] Verifying canonical database SHA-256 invariance..."
    & powershell -NoProfile -ExecutionPolicy Bypass -File $VerifyScript -CanonicalOnly
}
if ($LASTEXITCODE -ne 0) { exit 1 }

# 2. CLI Entrypoint Smoke
Write-Host "`n[2/5] Checking CLI entrypoints..."
& $PythonExe -m forensics.cli --help | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Error "forensics.cli --help failed"; exit 1 }
& $PythonExe collector.py --help | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Error "collector.py --help failed"; exit 1 }
Write-Host "[PASS] CLI entrypoints responsive"

# 3. Foundry Smart Contract & Real BN254 Pairing Verification
Write-Host "`n[3/5] Running Foundry Smart Contract & Real Halo2 BN254 Pairing Suite..."
$ForgeBin = Join-Path $FoundryDir "forge.exe"
& $ForgeBin test --root contracts --match-path test/Halo2RealVerifier.t.sol
if ($LASTEXITCODE -ne 0) { Write-Error "Foundry Halo2RealVerifier tests failed"; exit 1 }
Write-Host "[PASS] Foundry real BN254 KZG pairing & tamper rejection verified"

# 4. Isolated Pytest Multi-Component Smoke Suite
Write-Host "`n[4/5] Running Isolated Pytest Multi-Component Smoke Suite..."
$TempBase = Join-Path ([System.IO.Path]::GetTempPath()) ("forensics_smoke_" + [guid]::NewGuid().ToString("N").Substring(0, 8))
try {
    $SmokeTests = @(
        "tests/test_evaluation_portable.py",
        "tests/test_endpoint_acquisition.py",
        "tests/test_adversarial_did.py",
        "tests/test_xai_shapley.py",
        "tests/test_mitre_mapping.py"
    )
    $ExistingTests = @()
    foreach ($t in $SmokeTests) {
        if (Test-Path -LiteralPath (Join-Path $RootDir $t)) {
            $ExistingTests += $t
        }
    }
    & $PythonExe -m pytest $ExistingTests --basetemp="$TempBase" -q
    if ($LASTEXITCODE -ne 0) { Write-Error "Pytest smoke suite failed"; exit 1 }
} finally {
    if (Test-Path -LiteralPath $TempBase) {
        Remove-Item -LiteralPath $TempBase -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# 5. Post-Smoke Canonical Database Invariance Check
Write-Host "`n[5/5] Verifying post-smoke canonical database bitwise invariance..."
& powershell -NoProfile -ExecutionPolicy Bypass -File $VerifyScript -CanonicalOnly
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "`n==============================================================================="
Write-Host "SMOKE TEST PASSED (EXIT CODE 0)"
Write-Host "==============================================================================="
exit 0
