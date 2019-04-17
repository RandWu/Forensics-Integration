@echo off
rem call wmic to get process id, parent process id and then hash the process
rem First get process path in order to get hash
rem for /f "skip=1 delims=" %A in (
rem   'wmic path win32_service where "name like 'TeamViewer%'" get pathname ^ pipe findstr /r /v "^$"'
rem ) do set POSITION=%A
setlocal enabledelayedexpansion
rem wmic /output:%~dp0processPath.txt process get ExecutablePath
REM for /f "skip=1 delims=" %%i in ('wmic process get ExecutablePath ^| findstr /r /v "^$"') do (
REM     if [%%i] == [] (
REM         echo nothing
REM     ) else (
REM         echo hasthing
REM         echo [%%i] >> tmp.txt
REM     )
REM )
chcp
wmic /output:processPath.txt process get ExecutablePath/FORMAT:CSV
cscript //NoLogo getProcessCommandLine.vbs > processList.csv
REM wmic /output:processList.csv process get ProcessId,ExecutablePath,Name,ParentProcessId /FORMAT:CSV
REM wmic /output:processCmd.txt process get CommandLine /FORMAT:csv
type processPath.txt > 2222.txt
for /f "skip=2 tokens=1-4 delims=," %%a in (2222.txt) do (
      echo(%%b>>tmp.txt)
for /f "usebackq tokens=* delims=" %%a in ("tmp.txt") do (echo(%%a)>>path.txt
echo test
REM for /f "tokens=1-4 delims=," %%a in (processList.csv) do (
REM       echo(%%d>>haha.txt)
REM for /f "usebackq tokens=* delims=" %%a in ("tmp.txt") do (echo(%%a)>>path.txt
REM findstr /v /r /c:"^$" /c:"^\ *$" /c:"^\	*$" "processPath.txt" >> "tmp.txt"

if %ERRORLEVEL% NEQ 0 echo ERROR
rem Use certutil -hashfile filename to get the md5 hash
if exist processPath.txt (
    echo exist!
) else (
    echo error!
    exit /b 999
)

for /f "usebackq tokens=* delims=" %%a in ("path.txt") do (
    echo "%%a"
    CertUtil -hashfile "%%a" MD5 >>original.txt
    CertUtil -hashfile "%%a" MD5 | find /i /v "md5" | find /i /v "certutil" >> md5.txt
)
del 2222.txt
del tmp.txt