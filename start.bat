@echo off
cd /d %~dp0
set PORT=3000
set ADMIN_KEY=admin123
npm install
npm start
pause
