@echo off
TITLE NetGuard - Network Security Monitor
COLOR 0A

REM Always run from the project folder, even when launched as Administrator
cd /d "%~dp0"

REM Self-elevate so Windows hosts-file and firewall operations work reliably.
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo.
echo  ====================================================
echo   ^| NetGuard - Real-Time Network Security Monitor ^|
echo  ====================================================
echo.

REM Use project virtual environment if available
set "PYTHON=%~dp0.venv\Scripts\python.exe"
if not exist "%PYTHON%" (
    set "PYTHON=python"
)

REM Check Python installation
"%PYTHON%" --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found. Please install Python 3.9+
    echo         https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [1/3] Installing dependencies...
"%PYTHON%" -m pip install -r requirements.txt -q
if %errorlevel% neq 0 (
    echo [WARN] Some packages may have failed to install.
)

echo [2/3] Starting backend server...
start "NetGuard Backend" /min cmd /c "cd /d "%~dp0" && "%PYTHON%" main.py"

REM Wait for backend to start
echo       Waiting for backend to initialize...
timeout /t 3 /nobreak >nul

echo [3/3] Launching frontend...
cd /d "%~dp0"
"%PYTHON%" main_window.py %*

echo.
echo [*] NetGuard closed. Backend may still be running.
pause
