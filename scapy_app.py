
from scapy.all import *
                  

def scappy_app_main():
    
    send(IP(dst="192.168.86.1", src="5.135.162.217")/TCP(dport=[9001,9030,693], sport=[9001,9030,693])/raw,inter=0.5)
    send(IP(dst="192.168.86.1", src="46.22.128.133")/TCP(dport=[21,8888,21], sport=[21,8888,21])/raw,inter=0.5)
    send(IP(dst="192.168.86.1", src="176.31.75.101")/TCP(dport=[8880,8880,8880], sport=[8880,8880,8880])/raw,inter=0.5)
    send(IP(dst="192.168.86.1", src="190.105.235.232")/TCP(dport=[8095,2087,2086], sport=[8095,2087,2086])/raw,inter=0.5)
    send(IP(dst="192.168.86.1", src="144.76.153.36")/TCP(dport=[135,135,135], sport=[135,135,135])/raw,inter=0.5)





if __name__ == "__main__":
    #interact(mydict=globals(), mybanner="Test add-on v3.14")
    scappy_app_main()