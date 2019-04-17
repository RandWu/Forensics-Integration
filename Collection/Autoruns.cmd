@echo off
rem simply call the autorunsc
autorunsc -a * -h -c -s > registry.csv

rem check error level
if %ERRORLEVEL% EQU 0 (
    echo Registry collection is done successfully.
    exit /b 0
) else (
    echo The collection of registry encounter errors.
    setlocal
    set errorcode=%ERRORLEVEL%
    exit /b %errorcode%
)