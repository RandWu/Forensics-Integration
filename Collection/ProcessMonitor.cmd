@echo off 
call config.cmd
rem begin collection
start Procmon.exe  /BackingFile procmon.pml /AcceptEula /Minimized
ping 127.0.0.1 -n %ProcessMonitortDuration% -w 1000 >nul
Procmon.exe /Terminate

rem Convert format to csv/xml
Procmon.exe /OpenLog procmon.pml /SaveAs procmon.csv
Procmon.exe /OpenLog procmon.pml /SaveAs procmon.xml

if %ERRORLEVEL% EQU 0 (
    echo Process Monitor collection is done successfully.
    exit /b 0
) else (
    echo The collection of the Process Monitor encounter errors.
    setlocal
    set errorcode=%ERRORLEVEL%
    exit /b %errorcode%
)

