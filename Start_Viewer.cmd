@echo off
rem Byte-pinned Windows launcher; preserve committed CRLF.
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0viewer_performance\viewer.ps1" -Action Start %*
exit /b %ERRORLEVEL%
