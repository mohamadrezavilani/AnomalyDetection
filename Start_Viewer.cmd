@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0viewer_performance\viewer.ps1" -Action Start %*
exit /b %ERRORLEVEL%
