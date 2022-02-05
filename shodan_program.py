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
    for i in list:
        try:
                # Search Shodan
            results = api.search(i[0])
            #print("spacy_id is", i[0])
            #print("This is the whole list", list)
            try_list += f"{i[0], }"
            if results['total'] != 0:
                #i[0] = [i[0], [0]]
                    # Show the results
                
                #print('Results found: {}'.format(results['total']))
                #data_info = ""
                i[0] = ""
                for result in results['matches']:
                    i[0] += ('IP: {}'.format(result)) + "\n"
                    i[0] += result['data'] + "\n"
                    #print(data_info)
                    #r_data = json.dumps(result, indent=4)
                    #print("This is r_data", r_data)
                    #print('')
                #i[0] = data_info
                #print(i[0])
            else:
                i[0] = "No info in shodan"
            info_list.append(i)
            print(len(info_list))
        except shodan.APIError as e:
            print('Error: {}'.format(e))
            i[0] = "Error when handling"
        #print(try_list)
        time.sleep(1)
    return info_list

def insert_snort(info):
    f = open ("c:/Snort/rules/local.rules", "a")
    insert_info = f'alert {info["protocol"]} {info["ipv4_src"]} {info["port_src"]} -> {info["destination"]} {info["port"]} (msg:'
    insert_info += '"'
    insert_info += f'{info["msg"]}'
    insert_info += '";'
    insert_info += f'sid:{info["sid"]};)\n'
    print(insert_info)
    f.write(insert_info)
    f.close()