@echo off
title Push VibeGuard to GitHub
cd /d "%~dp0"
where git >nul 2>nul || (echo Git is not installed. Get it from https://git-scm.com/download/win and run this again. & pause & exit /b 1)
git remote set-url origin https://github.com/tejashalo/security-fix-project.git
git push -u origin main
if errorlevel 1 (echo. & echo Push failed - send a screenshot of this window.) else (echo. & echo Done! Open https://github.com/tejashalo/security-fix-project)
pause
