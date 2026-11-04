@echo off
setlocal enabledelayedexpansion

echo ===============================================================================
echo Blockchain + AI Forensics: Standalone Isolated Test Runner
echo ===============================================================================

set "ROOT_DIR=%~dp0"
cd /d "%ROOT_DIR%"

set "FORENSICS_OFFLINE=1"
set "AI_PROVIDER=none"
set "ANCHOR_CHAIN_ID=31337"
set "ANCHOR_RPC_URL=http://127.0.0.1:8545"
set "PYTHONUTF8=1"
set "PYDANTIC_AI_NO_BANNER=1"

echo.
echo [1/2] Running Foundry Smart Contract Test Suite...
"%ROOT_DIR%tools\foundry\forge.exe" test --root contracts
if errorlevel 1 (
    echo [ERROR] Foundry tests failed!
    exit /b 1
)

echo.
echo [2/2] Running Pytest Isolated Regression Suite...
python -m pytest tests --basetemp="%ROOT_DIR%tmp_pytest_run" -v
if errorlevel 1 (
    echo [ERROR] Pytest suite failed!
    exit /b 1
)

echo.
echo ===============================================================================
echo ALL TEST SUITES PASSED SUCCESSFULLY!
echo ===============================================================================
