@echo off
call %~dp0config.cmd
rem change directory to tshark location 
setlocal
cd %~dp0
cd
rem start capturing
%~dp0tcpdump -i %NetworkInterface% -c %NetworkByPacket% -w %~dp0packet.pcap
rem move to root directory

cd %~dp0

rem check error level
if %ERRORLEVEL% EQU 0 (
    echo Packets collection is done successfully.
    exit /b 0
) else (
    echo The collection of packets encounter errors.
    setlocal
    set errorcode=%ERRORLEVEL%
    exit /b %errorcode%
)