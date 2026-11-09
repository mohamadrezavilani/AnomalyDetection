@echo off
setlocal
set "AD_PY=%~dp0..\.venv\Scripts\python.exe"
if not exist "%AD_PY%" set "AD_PY=python"
"%AD_PY%" "%~dp0run_anomaly.py" worker-start
exit /b %errorlevel%
