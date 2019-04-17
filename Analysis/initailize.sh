rm cports_begin.csv
rm cports_end.csv
rm flow.txt
rm CurrentPortsChangeLog.log
rm md5.txt
rm original.txt
rm packet.pcap
rm path.txt
rm processCmd.txt
rm processList.csv
rm processPath.txt
rm procmon.csv
rm procmon.pml
rm procmon.xml
rm registry.csv
rm Security.csv
rm Security.etvs


cp ../Collection/evidence/CurrentPorts/* ./ #To hide freaking MSDOS \r
cp ../Collection/evidence/ProcessMonitor/* ./ #
cp ../Collection/evidence/Wireshark/* ./ #
cp ../Collection/evidence/Wmic/* ./ #
cp ../Collection/evidence/Autoruns/* ./ #
cp ../Collection/evidence/Events/* ./ #
rm Case.db #/mnt/e/oldCaseDB/$(date -Iseconds)_Case.db

md5sum ../Collection/evidence/CurrentPorts/* ./ #To hide freaking MSDOS \r
md5sum ../Collection/evidence/ProcessMonitor/* ./ #
md5sum ../Collection/evidence/Wireshark/* ./ #
md5sum ../Collection/evidence/Wmic/* ./ #
md5sum ../Collection/evidence/Autoruns/* ./ #
md5sum ../Collection/evidence/Events/* ./ #

python3 Analysis.py -f
