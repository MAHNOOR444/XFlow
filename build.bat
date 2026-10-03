@echo off
setlocal
echo ========================================================
echo               xFlow Automated Build Script
echo ========================================================

set "VS_CMAKE=C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"

if exist "%VS_CMAKE%" (
    set "CMAKE_EXE=%VS_CMAKE%"
) else (
    set "CMAKE_EXE=cmake"
)

echo [1/2] Configuring with CMake...
"%CMAKE_EXE%" -S . -B build -G "Visual Studio 17 2022" -A x64
if %ERRORLEVEL% neq 0 (
    echo [ERROR] CMake configuration failed!
    exit /b %ERRORLEVEL%
)

echo.
echo [2/2] Compiling Release binaries...
"%CMAKE_EXE%" --build build --config Release
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Compilation failed!
    exit /b %ERRORLEVEL%
)

echo.
echo [SUCCESS] Build completed successfully!
echo Executables are located in: build\Release\
endlocal
