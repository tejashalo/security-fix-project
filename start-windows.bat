@echo off
title VibeGuard - keep this window open
cd /d "%~dp0"
where node >nul 2>nul || (echo. & echo Node.js is not installed. Download the LTS version from https://nodejs.org, install it, then double-click this file again. & echo. & pause & exit /b 1)
echo Starting VibeGuard...
rem open the browser 2 seconds later, once the server is listening
start "" /b cmd /c "timeout /t 2 /nobreak >nul & start http://localhost:3000"
node server\index.js
echo.
echo VibeGuard stopped. If you see an error above, send a screenshot.
pause
