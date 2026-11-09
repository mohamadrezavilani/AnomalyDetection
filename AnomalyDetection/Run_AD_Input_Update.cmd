@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "PYTHONUTF8=1"
if not exist "%~dp0Install_Update.py" goto :missing_zip

if defined P24_PROJECT goto :check_project
set "P24_PROJECT=%USERPROFILE%\PycharmProjects\TestProject\pishkhan24"
if not exist "%P24_PROJECT%\AnomalyDetection\RELEASE_MANIFEST.json" set "P24_PROJECT=C:\Users\Administrator\PycharmProjects\TestProject\pishkhan24"
:check_project
for %%I in ("%P24_PROJECT%\.") do set "P24_PROJECT=%%~fI"
if not exist "%P24_PROJECT%\AnomalyDetection\RELEASE_MANIFEST.json" goto :missing_project

if defined P24_PYTHON goto :check_python
for %%I in ("%P24_PROJECT%\..\.venv\Scripts\python.exe") do set "P24_PYTHON=%%~fI"
if not exist "%P24_PYTHON%" set "P24_PYTHON=%P24_PROJECT%\.venv\Scripts\python.exe"
:check_python
if not exist "%P24_PYTHON%" goto :missing_python

"%P24_PYTHON%" -B "%~dp0Install_Update.py" --project "%P24_PROJECT%" --startup-seconds 240
set "P24_RC=%ERRORLEVEL%"
pause
exit /b %P24_RC%

:missing_zip
echo EXTRACT_THE_COMPLETE_ZIP_FIRST
goto :invalid
:missing_project
echo P24_INSTALLED_PROJECT_NOT_FOUND
goto :invalid
:missing_python
echo P24_VENV_NOT_FOUND
:invalid
pause
exit /b 2
