import asyncio
from setup_db import create_connection_async, get_snort_count, snort_return_values
from scapy.all import *
import random



database = r"./database.db"                  

async def scappy_package_simulation(conn):
    count = await asyncio.create_task(get_snort_count(conn))
    random_rule = []
    for i in range(3):    
        random_rule.append(random.randint(1, count))
    snort_info = await asyncio.create_task(snort_return_values(conn, random_rule))
    ipv4_list = []
    for i in snort_info:
        
        protocol = i[0]
        ip_address = i[1]
        ipv4_list.append(ip_address)
        ports_raw = i[2]
        ports = []

        print(ports_raw)
        for i in range(len(ports_raw)):
            if ports_raw[i] != "[" and ports_raw[i] != "]":
                ports.append(int(ports_raw[i]))
        

        if protocol == "tcp" or protocol == "TCP":
            raw = Raw(b"X"*1024)
            send(IP(dst="192.168.86.1", src=ip_address)/TCP(dport=ports, sport=ports)/raw,inter=0.5)
        elif protocol == "UDP" or protocol == "udp":
            raw = Raw(b"X"*1024)
            send(IP(dst="192.168.86.1", src=ip_address)/UDP(dport=ports, sport=ports)/raw,inter=0.5)
        else: 
            raw = Raw(b"X"*1024)
            send(IP(dst="192.168.86.1", src=ip_address)/UDP(dport=ports, sport=ports)/raw,inter=0.5)
            raw = Raw(b"X"*1024)
            send(IP(dst="192.168.86.1", src=ip_address)/TCP(dport=ports, sport=ports)/raw,inter=0.5)            
    return ipv4_list


async def scappy_app_main():
    conn = await asyncio.create_task(create_connection_async(database))
    asyncio.create_task(scappy_package_simulation(conn))


if __name__ == "__main__":
    asyncio.run(scappy_app_main())