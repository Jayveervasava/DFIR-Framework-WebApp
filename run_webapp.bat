@echo off
cd /d "%~dp0"
title CP-DFIR Investigation Console (web application)
set PY=
where python >nul 2>&1 && set PY=python
if "%PY%"=="" where py >nul 2>&1 && set PY=py
if "%PY%"=="" goto nopython
%PY% -c "import networkx, Evtx, boto3, psutil, flask, waitress" >nul 2>&1
if errorlevel 1 (
  echo Installing required packages. This happens only once and needs internet.
  %PY% -m pip install -r requirements.txt
)
echo.
echo  ==========================================================
echo     CP-DFIR Investigation Console
echo     Browser apne aap khulega:  http://127.0.0.1:5000
echo     To stop, close this window (or press Ctrl+C)
echo  ----------------------------------------------------------
echo     Live triage me Windows Security log bhi chahiye to
echo     is file par Right-click -^> "Run as administrator"
echo  ==========================================================
echo.
%PY% webapp\app.py
pause
goto :eof
:nopython
echo Python not found. Install it from python.org/downloads and tick "Add python.exe to PATH".
pause
