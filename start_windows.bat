@echo off
cd /d "%~dp0"
if exist "dist\WiFi-Sense-NetDiag.exe" (
  start "" "dist\WiFi-Sense-NetDiag.exe"
  exit /b
)
if not exist ".venv\Scripts\python.exe" py -3.12 -m venv .venv
if errorlevel 1 goto error
.venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 goto error
.venv\Scripts\python.exe main.py %*
if errorlevel 1 goto error
exit /b
:error
echo Avvio non riuscito. Leggere il messaggio sopra.
pause
