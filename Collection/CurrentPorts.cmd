@echo off
call config.cmd
rem collect first csv
cports.exe /scomma cports_begin.csv
rem use gui program to log changes automatically

start cports.exe /StartAsHidden 1 /LogChanges 1 /LogFilename cports.log /AutoRefresh 1 
rem TODO: Find more 'corrrect' way to perform pause or sleep
rem timeout /T 10 not work, as the ping delay is approximately close to 1 sec
ping 127.0.0.1 -n %CurrentPortsDuration% -w 1000 >nul
rem TODO: Find more 'correct' way to terminate the program
taskkill /f /im cports.exe

rem collect second csv
cports.exe /scomma cports_end.csv

rem check error level
if %ERRORLEVEL% EQU 0 (
    echo Current Ports collection is done successfully.
    exit /b 0
) else (
    echo The collection of the current port encounter errors.
    setlocal
    set errorcode=%ERRORLEVEL%
    exit /b %errorcode%
)
