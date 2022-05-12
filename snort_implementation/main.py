import asyncio
from setup_db import reset_snort_table, collect_ipv4_for_snort, collect_snort_info, add_multiple_snort, collect_compressed_snort_info

async def reset_snort(conn):
    await asyncio.create_task(reset_snort_table(conn))
    await asyncio.create_task(reset_rule_table())

    
async def async_snort(conn):
    ACTIVE_FUNCTIONS = True
    while True:
        if ACTIVE_FUNCTIONS == False:
            
            print("Sleeping, snort")
            await asyncio.sleep(60)

            print("Done sleeping, snort")
            ACTIVE_FUNCTIONS = True
        ipv4_snort_list = await asyncio.create_task(collect_ipv4_for_snort(conn))
        ip_dict, content_id_dict = await asyncio.create_task(collect_snort_info(conn, ipv4_snort_list))
        await asyncio.create_task(snort_entry_creation(conn, ip_dict, content_id_dict))
        #await asyncio.create_task(insert_snort_info(conn))
        
        ACTIVE_FUNCTIONS = False

async def snort_entry_creation(conn, ip_dict, content_id_dict):
    snort_list = []
    count = 0
    for i in ip_dict:
        count += 1
        info = {
            'ipv4': None,
            'transport': {},
            'Port': {},
            'content_id': ""
        }
        info["ipv4"] = ip_dict[i]['ipv4']
        for m in ip_dict[i]['content_id']:
            info["content_id"] += f"{m},"
            for j in content_id_dict[m]["Port"]:
                info["Port"][j] = j
            for k in content_id_dict[m]["transport"]:
                info["transport"][k] = k
        transport = []
        ports_list = "["
        for j in info["transport"]:
            transport.append(j)
        if len(transport) == 0:
            transport = ["ip"]
        for k in info["Port"]:
            ports_list += f"{info['Port'][k]},"
        ports_list = ports_list.strip(",")
        ports_list += "]"
        if ports_list == "[]":
            ports_list = "any"
        msg = f"Alert, this ip {info['ipv4']} has been found malicios"#, se STIX files {info['content_id']}"    
        for l in transport:
            if info["ipv4"] != "01.01.01.01" and info["ipv4"] != "1.1.1.1":
                snort_list.append([info["ipv4"], msg, info["content_id"], ports_list, l])
    if len(snort_list) > 0:
        await asyncio.create_task(add_multiple_snort(conn, snort_list))
    await asyncio.create_task(insert_snort_rules(conn))


async def insert_snort_rules(conn):
    info_dict = await asyncio.create_task(collect_compressed_snort_info(conn))
    count = 1000001
    ipv4_list_ip = "["
    ipv4_list_udp = "["
    ipv4_list_tcp = "["
    insert_info = ""
    count_ipv4 = 0

    

    for i in info_dict:
        for j in info_dict[i]["ipv4src"]:
            count_ipv4 += 1
            for k in info_dict[i]["ipv4src"][j]["protocols"]:
                if k == "ip":
                    ipv4_list_ip += f"{j},"
                    

                if k == "udp":
                    ipv4_list_udp += f"{j},"
                    
                if k == "tcp":
                    ipv4_list_tcp += f"{j},"
            if count_ipv4 >= 500:
                print(f"done with {count_ipv4}")
                count, aditional_insert_info, ipv4_list_ip, ipv4_list_udp, ipv4_list_tcp = await asyncio.create_task(make_rules(count, info_dict[i]["Ports"], ipv4_list_ip, ipv4_list_udp, ipv4_list_tcp))
                insert_info += aditional_insert_info
                count_ipv4 = 0

        count, aditional_insert_info, ipv4_list_ip, ipv4_list_udp, ipv4_list_tcp = await asyncio.create_task(make_rules(count, info_dict[i]["Ports"], ipv4_list_ip, ipv4_list_udp, ipv4_list_tcp))
        insert_info += aditional_insert_info   
        #print(f"done with {count_ipv4}")
        count_ipv4 = 0
                
    await asyncio.create_task(reset_rule_table())
    
    f = open ("c:/Snort/rules/local.rules", "a")
    
        
    f.write(insert_info)    
    f.close()

async def make_rules(count, info_dict, ipv4_list_ip, ipv4_list_udp, ipv4_list_tcp):
    insert_info = ""
    if ipv4_list_ip != "[":
        ipv4_list_ip = ipv4_list_ip.strip(",")
        insert_info += f'alert IP {ipv4_list_ip}] {info_dict} -> any any (msg:"This IP address has been found malicious";sid:{count})\n'
        count += 1 
    if ipv4_list_udp != "[":
        ipv4_list_udp = ipv4_list_udp.strip(",")
        insert_info += f'alert UDP {ipv4_list_udp}] {info_dict} -> any any (msg:"This IP address has been found malicious";sid:{count})\n'
        count += 1
    if ipv4_list_tcp != "[":
        ipv4_list_tcp = ipv4_list_tcp.strip(",")
        insert_info += f'alert TCP {ipv4_list_tcp}] {info_dict} -> any any (msg:"This IP address has been found malicious";sid:{count})\n'
        count += 1
    ipv4_list_ip = "["
    ipv4_list_udp = "["
    ipv4_list_tcp = "["
    

    return count, insert_info, ipv4_list_ip, ipv4_list_udp, ipv4_list_tcp



async def reset_rule_table():
    f = open ("c:/Snort/rules/local.rules", "w")
    insert_info = '''
# Copyright 2001-2022 Sourcefire, Inc. All Rights Reserved.
#
# This file contains (i) proprietary rules that were created, tested and certified by
# Sourcefire, Inc. (the "VRT Certified Rules") that are distributed under the VRT
# Certified Rules License Agreement (v 2.0), and (ii) rules that were created by
# Sourcefire and other third parties (the "GPL Rules") that are distributed under the
# GNU General Public License (GPL), v2.
# 
# The VRT Certified Rules are owned by Sourcefire, Inc. The GPL Rules were created
# by Sourcefire and other third parties. The GPL Rules created by Sourcefire are
# owned by Sourcefire, Inc., and the GPL Rules not created by Sourcefire are owned by
# their respective creators. Please see http://www.snort.org/snort/snort-team/ for a
# list of third party owners and their respective copyrights.
# 
# In order to determine what rules are VRT Certified Rules or GPL Rules, please refer
# to the VRT Certified Rules License Agreement (v2.0).
#
#-------------
# LOCAL RULES
#-------------




# Test of app


'''
    f.write(insert_info)
    f.close()