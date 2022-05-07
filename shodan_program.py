# This is a 
from datetime import datetime, timedelta
from msilib.schema import Error
import shodan
from shodan import Shodan
from shodan.cli.helpers import get_api_key
import time
import aiohttp

import json
import asyncio



api = shodan.Shodan('xxA9iJHbQHyWApr4bPfnGAYbttCEJn6o')

async def shodan_search(ipv4):
    #time_now = datetime.now()
    #result = api.search(ipv4)
    #print("Time for response is", datetime.now() - time_now)
    return api.host(ipv4)

async def check_ipv4(entry):#, filter_type):
    info_list = []
    try_list = "["
    count_list = 0
    return_error = None
    before_search = datetime.now()
    if entry != None:
        

        try:
                #print(i)
            j = [["", None, ""], entry[1], entry[2]]
                #print(i[0])
                #loop = asyncio.get_running_loop
                # Search Shodan
                #time_search = datetime.now()
                #results = await asyncio.create_task(shodan_search(i[0]))
                #results = await task
                #print(f"{api.search(i[0])}")
                #results = await  api.search(i[0])
                #results = api.search(i[0])
                #results2 = await asyncio.wait(api.search(i[0]), return_when=asyncio.ALL_COMPLETED)
                #print("Before shodan search", datetime.now(), i[0])
                #while datetime.now() < before_search +  timedelta(seconds=1):
                #    print("Sleeping")
                #    await asyncio.sleep(0.1)
                
            results = await shodan_search(entry[0])
            before_search = datetime.now()
            print("The shodan search did take", (datetime.now() - before_search), "And the time is", datetime.now())
                #print(results)
                #print(results2)
            
            if results != None:
                additional_info = ""
                j[0][0] = "found data"
                    
                        
                j[0][1] = json.dumps(results)
                        
                j[0][2] = entry[0]
                        
                entry = j
            else:
                j[0][0] = "No info in shodan"
                j[0][2] = entry[0]
            
            
                #while datetime.now() < time_search + timedelta(seconds=1):
                #    await asyncio.sleep(0.1)
                #    print("Sleeping")
            entry = j
            
            
        #except shodan.APIError as e:
        #    print('Error: {}'.format(e))
        #    print("the IP that caused the problem was", i[0])
        except Exception as e:
            print("Somthing wrong", e, entry[0], (datetime.now() - before_search))
            if str(e) == "Unable to connect to Shodan" or str(e) == "Request rate limit reached (1 request/ second). Please wait a second before trying again and slow down your API calls.":
                print(e)
                return None
            entry = [["An error occured: " + str(e), None, entry[0]], entry[1], entry[2]]
            
                #print([i])
            return entry
                #info_list.append(i)
                #pass   
            
            #print(try_list)
    #print("List after search is", list)    
    return entry

async def insert_snort(info_ist):
    f = open ("c:/Snort/rules/local.rules", "a")
    insert_info = ""
    for i in info_ist:
        insert_info += f'alert {i["protocol"]} {i["ipv4_src"]} {i["port_src"]} -> any any (msg:'
        insert_info += '"'
        insert_info += f'{i["msg"]}'
        insert_info += '";'
        insert_info += f'sid:{i["sid"]};)\n'
        #print(insert_info)
        
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

# This setup works
#alert icmp any any <> any any (msg:"Testing ICMP alert"; sid:1000001;)
#alert udp any any <> any any (msg:"Testing UDP alert"; sid:1000002;)
#alert tcp any any <> any any (msg:"Testing TCP alert"; sid:1000003;)


# Trying to make new rules, works well
#alert tcp 195.88.54.16 any -> any any (msg:"oh no, somone is trying to connect to VG :-O";sid:1000001;)
#alert tcp 54.201.153.149 any -> any any (msg:"Attempt Attack, be worned, shield up, call the cops"; sid:1000002;)
#alert icmp 54.201.153.149 any -> any any (msg:"Attempt Attack, be worned, shield up, call the cops"; sid:1000003;)
#alert tcp 195.88.55.37 any -> any any (msg:"oh no, somone is trying to connect to aftenbladet :-O";sid:1000004;)
#alert tcp 99.83.190.102 any -> any any (msg:"oh no, somone is trying to connect to Apply :-O";sid:1000005;)


# Test of app


'''
    f.write(insert_info)
    f.close()