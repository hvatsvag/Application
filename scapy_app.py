import asyncio
from setup_db import get_snort_count, snort_return_values, create_connection
from scapy.all import *
import random
                  

async def scappy_app_main(conn):

    program_running = True
    raw = Raw(b"X"*1024)
    while program_running:
        count = get_snort_count(conn)
        #print(count)
        
        random_rule = str(random.randint(1, count))
        
        
        
        #print(random_string)
        snort_info = snort_return_values(conn, random_rule)
        #print("Info is", snort_info)
        for i in snort_info:
            protocol = i[0]
            
            ip_address = i[1]
            ports = i[2]
            
            #print("The ports are", ports)
            #print(type(ports))
            if protocol == "tcp":
                send(IP(dst="10.0.0.138", src=ip_address)/TCP(dport=ports, sport=ports)/raw,inter=0.5)
            else:
                send(IP(dst="10.0.0.138", src=ip_address)/UDP(dport=ports, sport=ports)/raw,inter=0.5)
        await asyncio.sleep(600)
    
    #send(IP(dst="192.168.86.1", src="5.135.162.217")/TCP(dport=[9001,9030,693], sport=[9001,9030,693])/raw,inter=0.5)
    #send(IP(dst="192.168.86.1", src="46.22.128.133")/TCP(dport=[21,8888,21], sport=[21,8888,21])/raw,inter=0.5)
    #send(IP(dst="192.168.86.1", src="176.31.75.101")/TCP(dport=[8880,8880,8880], sport=[8880,8880,8880])/raw,inter=0.5)
    #send(IP(dst="192.168.86.1", src="190.105.235.232")/TCP(dport=[8095,2087,2086], sport=[8095,2087,2086])/raw,inter=0.5)
    #send(IP(dst="192.168.86.1", src="144.76.153.36")/TCP(dport=[135,135,135], sport=[135,135,135])/raw,inter=0.5)





if __name__ == "__main__":
    #interact(mydict=globals(), mybanner="Test add-on v3.14")
    database = r"./database.db"

    conn = create_connection(database)
    asyncio.run(scappy_app_main(conn))