# This is a 
from datetime import datetime, timedelta
from msilib.schema import Error
import shodan
from shodan import Shodan
from shodan.cli.helpers import get_api_key
import time

import json
import asyncio


api = shodan.Shodan('giaq9oOq9mtRdjzyXv17duRoa4TkR9Ib')

async def shodan_search(ipv4):
    time_now = datetime.now()
    result = api.search(ipv4)
    print("Time for response is", datetime.now() - time_now)
    return result

async def check_ipv4(list):#, filter_type):
    info_list = []
    try_list = "["
    count_list = 0
    if list != None:
        try:
            for i in list:
                j = [[["", None, ""], i[1], i[2]]]
            
                # Search Shodan
                time_search = datetime.now()
                #results = await asyncio.create_task(shodan_search(i[0]))
                #results = await task
                #print(f"{api.search(i[0])}")
                results = api.search(i[0])
                #results2 = await asyncio.wait(api.search(i[0]), return_when=asyncio.ALL_COMPLETED)
                
                print(results)
                #print(results2)
                count = 0
                if results['total'] != 0:
                    for result in results['matches']:
                        if count > 0:
                            j.append([["", None, i[0]], i[1], i[2]])
                        j[count][0][1] = json.dumps(result)
                        j[count][0][0] += result['data'] + "\n"
                        j[count][0][2] = i[0]
                        count += 1
                    i = j
                else:
                    j[count][0][0] = "No info in shodan"
                    j[count][0][2] = i[0]
                info_list.append(i)
                i = j
                #while datetime.now() < time_search + timedelta(seconds=1):
                #    await asyncio.sleep(0.1)
                #    print("Sleeping")
                list[count_list] = i
                count_list += 1    
                if count_list % 10 == 0:
                    print(f"Showdan has searched {count_list} IP addresses")
        #except shodan.APIError as e:
        #    print('Error: {}'.format(e))
        #    print("the IP that caused the problem was", i[0])
        except Exception as e:
            print("Somthing wrong", e)
            pass   
            #print(try_list)
        
    return list

def insert_snort(info):
    f = open ("c:/Snort/rules/local.rules", "a")
    insert_info = f'alert {info["protocol"]} {info["ipv4_src"]} {info["port_src"]} -> any any (msg:'
    insert_info += '"'
    insert_info += f'{info["msg"]}'
    insert_info += '";'
    insert_info += f'sid:{info["sid"]};)\n'
    #print(insert_info)
    f.write(insert_info)
    f.close()