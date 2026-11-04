@echo off
setlocal enabledelayedexpansion

echo ===============================================================================
echo Blockchain + AI Forensics: Standalone Empirical Evaluation Runner
echo ===============================================================================

set "ROOT_DIR=%~dp0"
cd /d "%ROOT_DIR%"

set "FORENSICS_OFFLINE=1"
set "AI_PROVIDER=none"
set "PYTHONUTF8=1"

echo.
echo [1/3] Replaying Euler DAI Incident Evaluation...
python scripts\evaluate.py --mode incident --data data\real_p4.db --incident euler --unit all --output results\evaluation\euler
if errorlevel 1 (
    echo [ERROR] Euler incident evaluation failed!
    exit /b 1
)

echo.
echo [2/3] Replaying Curve alETH Incident Evaluation...
python scripts\evaluate.py --mode incident --data data\real_p4.db --incident curve --unit all --output results\evaluation\curve
if errorlevel 1 (
    echo [ERROR] Curve incident evaluation failed!
    exit /b 1
)

echo.
echo [3/3] Running Benchmark Regression Evaluation...
python scripts\evaluate.py --mode benchmark --data data\benchmark_p6.db --output results\evaluation\benchmark
if errorlevel 1 (
    echo [ERROR] Benchmark evaluation failed!
    exit /b 1
)

echo.
echo ===============================================================================
echo ALL EVALUATIONS COMPLETED SUCCESSFULLY! Summaries in results\evaluation\
echo ===============================================================================
