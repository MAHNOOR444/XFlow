@echo off
setlocal

set "VS_CMAKE=C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"

if exist "%VS_CMAKE%" (
    set "CMAKE_EXE=%VS_CMAKE%"
) else (
    set "CMAKE_EXE=cmake"
)

echo Configuring CMake...
"%CMAKE_EXE%" -S . -B build -G "Visual Studio 17 2022" -A x64
if %ERRORLEVEL% neq 0 (
    echo CMake configuration failed.
    exit /b %ERRORLEVEL%
)

echo Building Release binaries...
"%CMAKE_EXE%" --build build --config Release
if %ERRORLEVEL% neq 0 (
    echo Compilation failed.
    exit /b %ERRORLEVEL%
)

echo Build finished successfully.
endlocal
