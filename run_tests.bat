@echo off
setlocal

if not exist "build\Release\unit_tests.exe" (
    echo unit_tests.exe not found. Please build first.
    exit /b 1
)

build\Release\unit_tests.exe
endlocal
