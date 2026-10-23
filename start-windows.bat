@echo off
title VibeGuard
where node >nul 2>nul || (echo Node.js is not installed. Get it from https://nodejs.org and run this again. & pause & exit /b 1)
echo Starting VibeGuard at http://localhost:3000 ...
start "" http://localhost:3000
node "%~dp0server\index.js"
pause
