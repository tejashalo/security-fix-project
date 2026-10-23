@echo off
title VibeGuard - keep this window open
cd /d "%~dp0"
set "NODE="
where node >nul 2>nul && set "NODE=node"
if not defined NODE for /d %%D in ("%USERPROFILE%\.nodejs\node-v*") do if exist "%%D\node.exe" set "NODE=%%D\node.exe"
if not defined NODE if exist "%ProgramFiles%\nodejs\node.exe" set "NODE=%ProgramFiles%\nodejs\node.exe"
if not defined NODE if exist "%LOCALAPPDATA%\Programs\nodejs\node.exe" set "NODE=%LOCALAPPDATA%\Programs\nodejs\node.exe"
if not defined NODE (
  echo.
  echo Node.js was not found. Download the LTS version from https://nodejs.org, install it, then double-click this file again.
  echo.
  pause
  exit /b 1
)
echo Starting VibeGuard...
rem open the browser 2 seconds later, once the server is listening
start "" /b cmd /c "timeout /t 2 /nobreak >nul & start http://localhost:3000"
"%NODE%" server\index.js
echo.
echo VibeGuard stopped. If you see an error above, send a screenshot.
pause
