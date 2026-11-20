@echo off
cd /d "%~dp0"
where node >nul 2>nul || (echo Node.js is not installed. Download it from https://nodejs.org (LTS) and run this again. & pause & exit /b 1)
node server.js
pause
