param(
    [switch]$SkipVenv,
    [switch]$InstallMlZkmlOnline,
    [string]$PythonExe = "python"
)

$ErrorActionPreference = "Stop"
$RootDir = $PSScriptRoot
Set-Location -LiteralPath $RootDir

Write-Host "==============================================================================="
Write-Host "Blockchain + AI Digital Forensics (v6.0) - Portable Offline Setup"
Write-Host "Working Directory: $RootDir"
Write-Host "==============================================================================="

# 1. Initialize .env from .env.example ONLY when .env does not exist
$EnvFile = Join-Path $RootDir ".env"
$EnvExample = Join-Path $RootDir ".env.example"
if (-not (Test-Path -LiteralPath $EnvFile)) {
    if (-not (Test-Path -LiteralPath $EnvExample)) {
        Write-Error "Missing .env.example template in $RootDir"
        exit 1
    }
    Copy-Item -LiteralPath $EnvExample -Destination $EnvFile
    Write-Host "[OK] Created offline .env configuration from .env.example"
} else {
    Write-Host "[OK] Existing .env preserved untouched"
}

# 2. Verify bundled Foundry toolchain & seed offline Solc 0.8.24 cache if absent
$FoundryDir = Join-Path $RootDir "tools\foundry"
foreach ($Bin in @("forge.exe", "anvil.exe", "cast.exe")) {
    $BinPath = Join-Path $FoundryDir $Bin
    if (-not (Test-Path -LiteralPath $BinPath)) {
        Write-Error "Missing bundled Foundry binary: $BinPath"
        exit 1
    }
    $VerLine = (& $BinPath --version | Select-Object -First 1)
    Write-Host "[OK] Bundled Foundry tool: $Bin ($VerLine)"
}
$BundledSolc = Join-Path $FoundryDir "solc-0.8.24.exe"
if ((Test-Path -LiteralPath $BundledSolc) -and $env:APPDATA) {
    $SvmTargetDir = Join-Path $env:APPDATA "svm\0.8.24"
    $SvmTargetBin = Join-Path $SvmTargetDir "solc-0.8.24"
    if (-not (Test-Path -LiteralPath $SvmTargetBin)) {
        New-Item -ItemType Directory -Force -Path $SvmTargetDir | Out-Null
        Copy-Item -LiteralPath $BundledSolc -Destination $SvmTargetBin -Force
        Write-Host "[OK] Seeded offline Solidity compiler cache: $SvmTargetBin"
    } else {
        Write-Host "[OK] Offline Solidity 0.8.24 compiler available"
    }
}

# 3. Verify Python >= 3.11
$PyCheck = & $PythonExe -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}'); raise SystemExit(0 if sys.version_info >= (3, 11) else 1)"
if ($LASTEXITCODE -ne 0) {
    Write-Error "Python 3.11+ (64-bit) is required. Detected: $PyCheck"
    exit 1
}
Write-Host "[OK] Python interpreter verified: $PyCheck"

if ($SkipVenv) {
    Write-Host "[INFO] -SkipVenv specified; using active Python environment without creating .venv."
    exit 0
}

# 4. Create isolated .venv and install offline wheelhouse
$VenvDir = Join-Path $RootDir ".venv"
$WheelsDir = Join-Path $RootDir "wheels"
$ReqBase = Join-Path $RootDir "requirements.txt"
$ReqMlZkml = Join-Path $RootDir "requirements-ml-zkml.lock.txt"

if (-not (Test-Path -LiteralPath $VenvDir)) {
    Write-Host "[*] Creating virtual environment at $VenvDir ..."
    & $PythonExe -m venv $VenvDir
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to create virtual environment at $VenvDir"
        exit 1
    }
}

$VenvPip = Join-Path $VenvDir "Scripts\pip.exe"
$VenvPy = Join-Path $VenvDir "Scripts\python.exe"

if (Test-Path -LiteralPath $WheelsDir) {
    Write-Host "[*] Installing 101 pinned core dependencies offline from wheels/ ..."
    & $VenvPip install --no-index --find-links="$WheelsDir" -r "$ReqBase"
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Offline wheel installation failed for requirements.txt"
        exit 1
    }
    Write-Host "[OK] Installed 101 core offline packages into .venv"

    $EzklWheel = Get-ChildItem -LiteralPath $WheelsDir -Filter "ezkl-*.whl" -ErrorAction SilentlyContinue
    if ($EzklWheel) {
        Write-Host "[*] Detected extended ML/ZKML wheels in wheels/; installing offline ..."
        & $VenvPip install --no-index --find-links="$WheelsDir" -r "$ReqMlZkml"
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Offline installation failed for requirements-ml-zkml.lock.txt"
            exit 1
        }
        Write-Host "[OK] Installed extended ML/ZKML packages offline"
    } elseif ($InstallMlZkmlOnline) {
        Write-Host "[*] Installing extended ML/ZKML lockfile from package index (-InstallMlZkmlOnline) ..."
        & $VenvPip install -r "$ReqMlZkml"
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Online installation failed for requirements-ml-zkml.lock.txt"
            exit 1
        }
        Write-Host "[OK] Installed extended ML/ZKML packages"
    } else {
        Write-Host "[NOTE] Extended ML/ZKML wheels (torch/onnx/ezkl) are not bundled in wheels/."
        Write-Host "       Core Forensics, Rule Engine, pure-Python ML/XAI, Custody/DID, and Foundry Halo2Verifier.sol tests run 100% offline."
        Write-Host "       For live Python EZKL proof generation inside .venv, add wheels for requirements-ml-zkml.lock.txt or pass -InstallMlZkmlOnline."
    }
} else {
    Write-Warning "No wheels/ directory found at $WheelsDir. Place offline wheels in wheels/ before running offline install."
}

& $VenvPy -c "import forensics, pydantic, pytest, cryptography; print('[OK] Core Python imports verified inside .venv')"
if ($LASTEXITCODE -ne 0) {
    Write-Error "Import sanity check failed inside .venv"
    exit 1
}

Write-Host "==============================================================================="
Write-Host "PORTABLE SETUP COMPLETED SUCCESSFULLY"
Write-Host "Next steps:"
Write-Host "  1. .\verify_integrity.ps1"
Write-Host "  2. .\smoke_test.ps1"
Write-Host "  3. .\run_full_tests.ps1"
Write-Host "==============================================================================="
exit 0
