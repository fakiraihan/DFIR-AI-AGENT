@echo off
echo ========================================
echo AI Agent DFIR - Quick Start
echo ========================================
echo.

REM Check if in correct directory
if not exist "backend\main.py" (
    echo Error: Please run this script from FirstPrototype folder
    echo Current directory: %CD%
    pause
    exit /b 1
)

echo [1/5] Checking Python...
python --version
if errorlevel 1 (
    echo Error: Python not found in PATH
    pause
    exit /b 1
)

echo.
echo [2/5] Checking Ollama...
ollama list
if errorlevel 1 (
    echo Warning: Ollama not running or not installed
    echo Please install Ollama from: https://ollama.ai
    echo.
)

echo.
echo [3/5] Setting up virtual environment...
if not exist "backend\venv" (
    echo Creating virtual environment...
    cd backend
    python -m venv venv
    cd ..
)

echo Activating virtual environment...
call backend\venv\Scripts\activate.bat

echo.
echo [4/5] Installing dependencies...
cd backend
pip install -q -r requirements.txt
if errorlevel 1 (
    echo Error installing dependencies
    pause
    exit /b 1
)

echo.
echo [5/5] Starting test pipeline...
echo.
python test_pipeline.py

echo.
echo ========================================
echo Test completed!
echo ========================================
echo.
echo To start the API server, run:
echo   cd backend
echo   python main.py
echo.
echo Then open: http://localhost:8000/docs
echo.

pause
