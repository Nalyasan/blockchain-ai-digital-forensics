@echo off
setlocal enabledelayedexpansion

echo ===============================================================================
echo Blockchain + AI Forensics: Offline Environment Setup
echo ===============================================================================

set "ROOT_DIR=%~dp0"
cd /d "%ROOT_DIR%"

if not exist "%ROOT_DIR%venv" (
    echo Creating virtual environment in %ROOT_DIR%venv...
    python -m venv "%ROOT_DIR%venv"
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment! Ensure Python 3.13 64-bit is installed.
        exit /b 1
    )
)

echo Installing pinned dependencies from offline wheels directory...
"%ROOT_DIR%venv\Scripts\pip.exe" install --no-index --find-links="%ROOT_DIR%wheels" -r "%ROOT_DIR%requirements.txt"
if errorlevel 1 (
    echo [ERROR] Failed to install offline dependencies!
    exit /b 1
)

echo.
echo ===============================================================================
echo ENVIRONMENT SETUP COMPLETE!
echo Activate via:   venv\Scripts\activate.bat
echo Run tests via:  run_tests.bat
echo Run eval via:   run_evaluation.bat
echo ===============================================================================
