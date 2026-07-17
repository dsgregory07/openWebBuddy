@echo off
REM Double-click to watch GPU utilization, VRAM, and what Ollama has loaded, live.
REM Leave this open in one window while you chat. Press Ctrl+C to stop.
setlocal
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0watch-gpu.ps1" %*
