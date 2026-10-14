@echo off
chcp 65001 >nul
setlocal
if exist "%~dp0WorkBuddyAccountHub.exe" (
  start "" "%~dp0WorkBuddyAccountHub.exe"
  exit /b 0
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0启动源码.ps1"
if errorlevel 1 pause
endlocal
