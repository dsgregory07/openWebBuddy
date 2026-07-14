@echo off
REM Double-click to fully shut down openWebBuddy (OpenWebUI + tool bridge + Ollama),
REM so nothing is left running after you're done. Graceful: asks each process to exit
REM before force-killing anything that refuses.
setlocal
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0openWebBuddy.ps1" stop-all
echo.
echo ---------------------------------------------
echo Everything is stopped. You can close this window.
pause
