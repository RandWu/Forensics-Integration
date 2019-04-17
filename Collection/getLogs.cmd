wevtutil epl Security %~dp0Security.evts
%~dp0LogParser.exe -i:EVT "select * from %~dp0Security.evts" -o:CSV >%~dp0Security.csv
rem LogParser.exe -i:EVT "select * from Security.evts" -o:CSV >Security.csv
