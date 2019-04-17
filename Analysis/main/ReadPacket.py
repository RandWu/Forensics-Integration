import pypcap.ethernet as Reader
from main.Functionize import Forensic
from pypcap import pcap


class ReadPacket(object):
    '''
    This function read and analyze the packet
    '''


    def __init__(self, obj=None):
        '''
        Constructor
        Receive : object
        '''
        self.forensic = Forensic()
        if(obj is not None and isinstance(obj, ReadPacket)):
            self = obj 
    
    def read(self,path):
        '''
        This method will read packet if path is valid, return something
        else return false
        '''
        if(not self.forensic.isVaildPath(path)):
            return False
        return Reader.tcp_streams_from_file(path)
    

read = ReadPacket()
path = r'D:\\test.pcap'
# for stream in read.read(path):
#     print(stream.sent_data())
pcap_file = pcap.PcapFile(r'D:\\test.pcap')
p = pcap_file.next_packet()
while p != None:
    if(not p.incl_len == p.orig_len):
        print("The capture length is not the same as the original packet!! This may cause some errors")
    print(p.incl_len , p.orig_len)
    print(p.ts_usec)
    p = pcap_file.next_packet()

for items in Reader.tcp_streams_from_file(path):
    print(items.sent_data())
    print(items.recv_data())