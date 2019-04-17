
import sys  
import socket  
import struct  
  
filename = r'D:\\test.pcap'
ipaddr = '140.117.194.49'  
direction = 'in'  
  
packed = socket.inet_aton(ipaddr)  
ip32 = struct.unpack("!L", packed)[0]  
  
file = open(filename, "rb")   
  
pcaphdrlen = 24  
pkthdrlen=16  
pkthdrlen1=14  
iphdrlen=20  
tcphdrlen=20  
stdtcp = 20  
total = 0  
pos = 0  
  
start_seq = 0  
end_seq = 0  
cnt = 0  
  
# Read 24-bytes pcap header  
data = file.read(pcaphdrlen)  
(tag, maj, min, tzone, ts, ppsize, lt) = struct.unpack("=L2p2pLLLL", data)  
  
# 具体的LinkType细节，请看：  
# http://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html#appendixBlockCodes  
if lt == 0x71:  
    pkthdrlen1 = 16  
else:  
    pkthdrlen1 = 14  
  
ipcmp = 0  
  
# Read 16-bytes packet header  
data = file.read(pkthdrlen)  
  
while data:  
    (sec, microsec, iplensave, origlen) = struct.unpack("=LLLL", data)  
  
    # read link  
    link = file.read(pkthdrlen1)  
      
    # read IP header  
    data = file.read(iphdrlen)  
    (vl, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr) = struct.unpack(">ssHHHssHLL", data)  
    iphdrlen = ord(vl) & 0x0F   
    iphdrlen *= 4  
  
    # read TCP standard header  
    tcpdata = file.read(stdtcp)   
    (sport, dport, seq, ack_seq, pad1, win, check, urgp) = struct.unpack(">HHLLHHHH", tcpdata)  
    tcphdrlen = pad1 & 0xF000  
    tcphdrlen = tcphdrlen >> 12  
    tcphdrlen = tcphdrlen*4  
      
    if direction == 'out':  
        ipcmp = saddr  
    else:  
        ipcmp = daddr  
  
    if ipcmp == ip32:  
        cnt += 1  
        total += tot_len  
        total -= iphdrlen + tcphdrlen  
        if start_seq == 0:  # BUG?  
            start_seq = seq  
        end_seq = seq  
  
    # skip data  
    skip = file.read(iplensave-pkthdrlen1-iphdrlen-stdtcp)
  
    # read next packet  
    pos += 1  
    data = file.read(pkthdrlen)  
  
# 打印出实际传输的字节数，以及本应该传输的字节数  
print( pos, cnt, 'Actual:'+str(total),  'ideal:'+str(end_seq-start_seq))  