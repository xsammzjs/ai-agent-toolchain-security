@echo off
title Dependency Vulnerability Scanner - Quick Start
cd /d "%~dp0"

echo ============================================
echo   Dependency Vulnerability Scanner
echo   One-click start, first run installs deps
echo ============================================
echo.

REM ---- [1/4] check python ----
where python >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Python not found.
  echo   Please install Python 3.13 first and check "Add Python to PATH".
  echo   Download: https://www.python.org/downloads/
  echo.
  pause
  exit /b 1
)

for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo [1/4] Python detected: %PYVER%

REM ---- [2/4] create venv if missing ----
if not exist ".venv\Scripts\python.exe" (
  echo [2/4] Creating virtual environment .venv ...
  python -m venv .venv
  if errorlevel 1 (
    echo [ERROR] Failed to create venv. Check Python installation.
    echo.
    pause
    exit /b 1
  )
) else (
  echo [2/4] Virtual environment exists, skip.
)

REM ---- [3/4] install dependencies if missing ----
".venv\Scripts\python.exe" -c "import streamlit, requests, nvdlib, docx, reportlab, packaging, dotenv" >nul 2>nul
if errorlevel 1 (
  echo [3/4] Installing dependencies, first run only, 2-5 min ...
  ".venv\Scripts\python.exe" -m pip install --upgrade pip -q
  ".venv\Scripts\python.exe" -m pip install -r requirements.txt
  if errorlevel 1 (
    echo [ERROR] pip install failed. Check network and run again.
    echo.
    pause
    exit /b 1
  )
) else (
  echo [3/4] Dependencies ready, skip.
)

REM ---- [4/4] check .env ----
if not exist ".env" (
  echo.
  echo [WARN] .env not found. App will still run, but:
  echo   - NVD queries will be slow, anonymous limit about 6s each
  echo   - AI features will be disabled
  echo   - See 运行说明.md to fill API keys if needed
)

echo.
echo [4/4] Starting web UI ... open http://localhost:8501 in browser
echo       Close this window to stop the service.
echo.
".venv\Scripts\python.exe" -m streamlit run main.py
pause
