@echo off
setlocal
cd /d "%~dp0"
for /f "delims=" %%A in ('cd') do set "GITBASH=C:\Program Files\Git\bin\bash.exe"
if not exist "%GITBASH%" (
  echo Git Bash not found at C:\Program Files\Git\bin\bash.exe
  echo Install Git for Windows: https://gitforwindows.org/
  pause
  exit /b 1
)
"%GITBASH%" deploy-auto.sh
pause
