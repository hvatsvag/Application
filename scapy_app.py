import asyncio
from setup_db import create_connection_async, get_snort_count, snort_return_values, create_connection
from scapy.all import *
import random

database = r"./database.db"                  

async def scappy_app_main():
    conn = await create_connection_async(database)
    program_running = True
    raw = Raw(b"X"*1024)

    count = await asyncio.create_task(get_snort_count(conn))
        #print(count)

    random_rule = []
    for i in range(3):    
        random_rule.append(random.randint(1, count))
        
        
        
        #print(random_string)
    snort_info = await asyncio.create_task(snort_return_values(conn, random_rule))
        #print("Info is", snort_info)
    ipv4_list = []
    for i in snort_info:
        protocol = i[0]
            
        ip_address = i[1]
        ipv4_list.append(ip_address)
        ports = i[2]
            
            #print("The ports are", ports)
            #print(type(ports))
        if protocol == "tcp":
            send(IP(dst="10.0.0.138", src=ip_address)/TCP(dport=ports, sport=ports)/raw,inter=0.5)
        else:
            send(IP(dst="10.0.0.138", src=ip_address)/UDP(dport=ports, sport=ports)/raw,inter=0.5)
    return ipv4_list
    #await asyncio.sleep(600)
    
    #send(IP(dst="192.168.86.1", src="5.135.162.217")/TCP(dport=[9001,9030,693], sport=[9001,9030,693])/raw,inter=0.5)
    #send(IP(dst="192.168.86.1", src="46.22.128.133")/TCP(dport=[21,8888,21], sport=[21,8888,21])/raw,inter=0.5)
    #send(IP(dst="192.168.86.1", src="176.31.75.101")/TCP(dport=[8880,8880,8880], sport=[8880,8880,8880])/raw,inter=0.5)
    #send(IP(dst="192.168.86.1", src="190.105.235.232")/TCP(dport=[8095,2087,2086], sport=[8095,2087,2086])/raw,inter=0.5)
    #send(IP(dst="192.168.86.1", src="144.76.153.36")/TCP(dport=[135,135,135], sport=[135,135,135])/raw,inter=0.5)





if __name__ == "__main__":
    #interact(mydict=globals(), mybanner="Test add-on v3.14")
    database = r"./database.db"

    
    asyncio.run(scappy_app_main())