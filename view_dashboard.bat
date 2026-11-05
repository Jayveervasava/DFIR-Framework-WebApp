@echo off
cd /d "%~dp0"
set PY=
where python >nul 2>&1 && set PY=python
if "%PY%"=="" where py >nul 2>&1 && set PY=py
if "%PY%"=="" (
  echo Python not found. Install it from python.org/downloads.
  pause
  exit /b
)
if not exist results\evaluation.json (
  echo Run option 2 ^(Full evaluation^) in run.bat first; then this dashboard will be built.
  pause
  exit /b
)
%PY% make_dashboard.py
