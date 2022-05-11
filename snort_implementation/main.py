import asyncio
from setup_db import insert_snort_info, reset_snort_table

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
        await asyncio.create_task(insert_snort_info(conn))
        
        ACTIVE_FUNCTIONS = False

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


async def insert_snort(info_dict):
    count = 1000001
    ipv4_list_ip = "["
    ipv4_list_udp = "["
    ipv4_list_tcp = "["
    insert_info = ""
    count_ipv4 = 0

    await asyncio.create_task(reset_rule_table())

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
        print(f"done with {count_ipv4}")
        count_ipv4 = 0
                
    
    
    f = open ("c:/Snort/rules/local.rules", "a")
    
        
    f.write(insert_info)    
    f.close()

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