@echo off
echo Initializing...
cd %~dp0
cd
rem Initializing local variables
setlocal
set isValid=1
set haserror=0

echo Checking if needed files exist
rem Checking if all files are exists.
if not exist cports.exe (
    echo Program not found: Cports.exe
    set isValid=0
)
if not exist Procmon.exe (
    echo Program not found: Procmon.exe
    set isValid=0
)
if not exist autorunsc.exe (
    echo Program not found: autorunsc.exe
)
if %isValid% EQU 0 (
    echo Missing some files, Make sure all of those programs are in the working diretory.
    echo The current working directory of this script is 
    cd
    echo Fatal Error: Missing files
    rem set error code to 2, no such files or directory
    exit /b 2
)
rem Start collecting
rem start current ports (call external cmd)
call CurrentPorts.cmd
if %ERRORLEVEL% NEQ 0 (
    set %haserror%=1
)
rem start process monitor
call ProcessMonitor.cmd
if %ERRORLEVEL% NEQ 0 (
    set %haserror%=1
)
rem start get process list info
call getProcess.cmd
if %ERRORLEVEL% NEQ 0 (
    set %haserror%=1
)
echo end process
rem start capture packets
call sudo.cmd cmd /c %~dp0tshark.cmd
if %ERRORLEVEL% NEQ 0 (
    set %haserror%=1
)
rem start autorun capture
call Autoruns.cmd
if %ERRORLEVEL% NEQ 0 (
    set %haserror%=1
)

call sudo.cmd cmd /c %~dp0getLogs.cmd

ping localhost -n 10 >nul
echo collection ends

echo Calculating md5
CertUtil -hashfile cports_begin.csv MD5 > "Evidences.MD5"
CertUtil -hashfile cports_end.csv >> "Evidences.MD5"
CertUtil -hashfile CurrentPortsChangeLog.log >> "Evidences.MD5"
CertUtil -hashfile processPath.txt >> "Evidences.MD5"
CertUtil -hashfile processList.csv >> "Evidences.MD5"
CertUtil -hashfile md5.txt >> "Evidences.MD5"
CertUtil -hashfile original.txt >> "Evidences.MD5"
CertUtil -hashfile path.txt >> "Evidences.MD5"
CertUtil -hashfile procmon.pml >> "Evidences.MD5"
CertUtil -hashfile procmon.csv >> "Evidences.MD5"
CertUtil -hashfile procmon.xml >> "Evidences.MD5"
CertUtil -hashfile packet.pcap >> "Evidences.MD5"
CertUtil -hashfile flow.txt >> "Evidences.MD5"
CertUtil -hashfile registry.csv >> "Evidences.MD5"
CertUtil -hashfile Security.etvs >> "Evidences.MD5"
rem CertUtil -hashfile >> "Evidences.MD5"
echo all hashes of evidences stored in "./evidence/Evidence.MD5"
move Evidences.MD5 ./evidence/Evidences.MD5

rem Ending process
rem moving cports evidences
cd
move cports_begin.csv ./evidence/CurrentPorts/cports_begin.csv
move cports_end.csv ./evidence/CurrentPorts/cports_end.csv
move cports.log ./evidence/CurrentPorts/CurrentPortsChangeLog.log
rem moving process list file
move processPath.txt ./evidence/Wmic/processPath.txt
move processList.csv ./evidence/Wmic/processList.csv
move md5.txt ./evidence/Wmic/md5.txt
move original.txt ./evidence/Wmic/original.txt
move path.txt ./evidence/Wmic/path.txt
rem move processMD5.txt ./evidence/Wmic/processMD5
rem moving process monitor files
move procmon.pml ./evidence/ProcessMonitor/procmon.pml
move procmon.csv ./evidence/ProcessMonitor/procmon.csv
move procmon.xml ./evidence/ProcessMonitor/procmon.xml
rem moving wireshark files
move packet.pcap ./evidence/Wireshark/packet.pcap
rem moving Autoruns
move registry.csv ./evidence/Autoruns/registry.csv

ping localhost -n 5 >nul
move Security.evts ./evidence/Events/Security.etvs

if %haserror% EQU 1 (
    echo some of the programs encounter errors, please check again.
) else (
    echo the collection has ended successfully.
)
pause