# This is a 
import shodan
from shodan import Shodan
from shodan.cli.helpers import get_api_key
import time
import json


api = shodan.Shodan('giaq9oOq9mtRdjzyXv17duRoa4TkR9Ib')

def check_ipv4(list):#, filter_type):
    info_list = []
    try_list = "["
    count_list = 0
    if list != None:
        try:
            for i in list:
                j = [[["", None], i[1], i[2]]]
            
                    # Search Shodan
                results = api.search(i[0])
                #print("spacy_id is", i[0])
                #print("This is the whole list", list)
                try_list += f"{i[0], }"
                count = 0
                if results['total'] != 0:
                    #i[0] = [i[0], [0]]
                        # Show the results
                    
                    #print('Results found: {}'.format(results['total']))
                    #data_info = ""
                    
                    for result in results['matches']:
                        if count > 0:
                            j.append([["", None], i[1], i[2]])
                        j[count][0][1] = json.dumps(result)
                        j[count][0][0] += result['data'] + "\n"
                        #print(type(j[count][0][1]))
                        #print(data_info)
                        #r_data = json.dumps(result, indent=4)
                        #print("This is r_data", r_data)
                        #print('')
                        count += 1
                        #print(j)
                    i = j
                    #i[0] = data_info
                    #print(i[0])
                else:
                    j[count][0][0] = "No info in shodan"
                info_list.append(i)
                i = j
                #print(len(info_list))
                time.sleep(1)
                #print("i in loop is", i)
                #print("after one loop list is", list)
                list[count_list] = i
                #print("after one and other insert loop list is", list)
                count_list += 1    
        except:
            pass   
            #print(try_list)
        
    return list

def insert_snort(info):
    f = open ("c:/Snort/rules/local.rules", "a")
    insert_info = f'alert {info["protocol"]} {info["ipv4_src"]} {info["port_src"]} -> {info["destination"]} {info["port"]} (msg:'
    insert_info += '"'
    insert_info += f'{info["msg"]}'
    insert_info += '";'
    insert_info += f'sid:{info["sid"]};)\n'
    #print(insert_info)
    f.write(insert_info)
    f.close()