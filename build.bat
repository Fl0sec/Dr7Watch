@echo off
setlocal
pushd "%~dp0"

where cl >nul 2>nul
if errorlevel 1 (
  echo [error] Run this script from an x64 Native Tools Command Prompt for Visual Studio.
  exit /b 1
)

if not exist build mkdir build

set CFLAGS=/nologo /TC /std:c17 /O2 /W4 /WX /GS /guard:cf /utf-8 /MT

cl %CFLAGS% /LD /Fo:build\ /Fe:build\dr7watch_sensor.dll ^
  src\sensor\sensor.c src\sensor\stubs.c /link /guard:cf
if errorlevel 1 exit /b 1

cl %CFLAGS% /Fo:build\ /Fe:build\dr7watch.exe src\watch\watch.c /link /guard:cf
if errorlevel 1 exit /b 1

cl %CFLAGS% /Fo:build\ /Fe:build\syscall_trace.exe etw\syscall_trace.c /link /guard:cf advapi32.lib
exit /b %errorlevel%
