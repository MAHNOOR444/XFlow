@echo off
setlocal
echo ========================================================
echo               xFlow Running Google Unit Tests
echo ========================================================

if not exist "build\Release\unit_tests.exe" (
    echo [ERROR] unit_tests.exe not found! Please run build.bat first.
    exit /b 1
)

build\Release\unit_tests.exe
endlocal
