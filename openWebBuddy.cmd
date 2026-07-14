@echo off
REM Double-click launcher for openWebBuddy on Windows.
REM Double-clicking a .ps1 only opens it in an editor; this .cmd actually runs it,
REM with the right execution policy. Pass start/stop/status/restart as an argument,
REM or just double-click (defaults to start).
setlocal
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0openWebBuddy.ps1" %*
echo.
echo ---------------------------------------------
echo Done. You can close this window.
pause
