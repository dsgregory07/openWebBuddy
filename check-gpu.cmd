@echo off
REM Double-click after a reboot to check whether the NVIDIA GPU recovered and whether
REM Ollama is using it, with a tokens/sec benchmark. Only needs Ollama running.
setlocal
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0check-gpu.ps1" %*
echo.
pause
