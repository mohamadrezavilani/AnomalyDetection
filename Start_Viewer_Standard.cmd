@echo off
rem Byte-pinned Windows launcher; preserve committed CRLF.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\viewer.ps1" -Action Start %*
exit /b %ERRORLEVEL%
