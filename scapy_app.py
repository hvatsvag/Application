# Setting up a simple scapy application to see if snort is working

import sys

import logging
from tabnanny import verbose

logger = logging.getLogger("scapy")
logger.setLevel(logging.INFO)


from scapy.all import *
'''
class Test(Packet):
    name = "Test packet"
    fields_desc = [ ShortField("test1", 1),
                    ShortField("test2", 2) ]

def make_test(x,y):
    return Ether()/IP()/Test(test1=x,test2=y)

class Disney(Packet):
    name = "DisneyPacket "
    fields_desc=[ ShortField("mickey",5),
                 XByteField("minnie",3) ,
                 IntEnumField("donald" , 1 ,
                      { 1: "happy", 2: "cool" , 3: "angry" } ) ]
'''                      

def main():
    '''
    target_ip = "192.168.86.1"
    target_port = 80

    ip = IP(dst=target_ip)
    tcp = TCP(sport=RandShort(), dport=target_port, flags="S")
    raw = Raw(b"X"*1024)
    p = ip / tcp / raw

    send(p, loop=1, verbose=0)
    '''
    raw = Raw(b"X"*1024)
    a=IP(ttl=10)
    print(a.summary())
    print(a.src)
    a.src = "188.120.225.17"
    print(a.src, a.proto)
    a.proto = "tcp"
    print(a.src, a.proto)
    a.dst = "192.168.86.36"
    a.port = "80"
    print(a.summary())
    send(a)
    send(IP(dst="192.168.86.1", src="5.135.162.217")/TCP(dport=[9001,9030,693], sport=[9001,9030,693])/raw,inter=0.5)
    send(IP(dst="192.168.86.1", src="46.22.128.133")/TCP(dport=[21,8888,21], sport=[21,8888,21])/raw,inter=0.5)
    send(IP(dst="192.168.86.1", src="176.31.75.101")/TCP(dport=[8880,8880,8880], sport=[8880,8880,8880])/raw,inter=0.5)
    send(IP(dst="192.168.86.1", src="190.105.235.232")/TCP(dport=[8095,2087,2086], sport=[8095,2087,2086])/raw,inter=0.5)
    send(IP(dst="192.168.86.1", src="144.76.153.36")/TCP(dport=[135,135,135], sport=[135,135,135])/raw,inter=0.5)





if __name__ == "__main__":
    #interact(mydict=globals(), mybanner="Test add-on v3.14")
    main()