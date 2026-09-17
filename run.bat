@echo off
title ConfigScore Security Scanner
echo =================================================================
echo        ConfigScore: Website Security Scanner & Fixer
echo =================================================================
echo.
echo Checking Python environment...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not found in your system PATH.
    echo Please install Python 3.8+ from https://python.org and check "Add Python to PATH".
    pause
    exit /b
)

echo Starting ConfigScore...
python run.py
pause
