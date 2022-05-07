from http import client
from msilib.schema import Error
from multiprocessing.connection import Client, wait
from socket import timeout
#from urllib.error import HTTPError
import PySimpleGUI as sg
import spacy
from setup_db import add_spacy_list, create_connection_async, get_text_content, collect_stix_info, add_spacy, \
    get_all_label_spacy, get_ipv4_spacy, add_shodan, add_snort, insert_snort_info,\
    get_highest_content, get_name_content, add_content, get_total_content, reset_snort_table, get_all_ipv4_spacy, \
    get_status_info, add_content_list
import sqlite3
from cabby import create_client
from cabby.exceptions import HTTPError, UnsuccessfulStatusError, ServiceNotFoundError, NotSupportedError, \
NoURIProvidedError, InvalidResponseError, ClientException
import stix2viz
from stix2elevator import elevate
from stix2elevator.options import initialize_options, set_option_value
from spacy_prog import find_relevant_info, find_relevant_spacy, find_relevant_spacy_list, find_relevant_spacy_stix
import time
from shodan_program import check_ipv4, insert_snort, reset_rule_table
from multiprocessing import Process
import datetime
from datetime import datetime, timedelta
import asyncio
from taxii2client.v20 import Server, Collection, as_pages
import json
from scapy_app import scappy_app_main

 
ACTIVE_TIME = None
CLIENT = None
SERVICES = None
COLLECTIONS = None
ACTIVE_FUNCTIONS = None


database = r"./database.db"

conn = None

async def spacy_processing(content_list, conn):
    
        found_info = False
        count_entrys = 0
        
        #list_of_entrys = find_relevant_spacy_list(content_list)
        

        # Trying out with json files
        task = asyncio.create_task(find_relevant_spacy_stix(content_list))
        
        #task = asyncio.create_task(find_relevant_spacy_list(content_list))
        
        list_of_entrys = await task
        result_list = []
        number = 0
        if list_of_entrys != None:
            for j in list_of_entrys:
                number +=1
                found_info = False
                ipv4_content = {
                    #'content_id': {'type': 'content_id', 'content': {j[1]: j[1]}},
                    'Port': {'type': "Port", 'content': {}},
                    'transport': {'type': "transport", 'content': {}},
                    'ipv4': {'type': "ipv4", 'content': {}}
                }
                
                count_entrys += 1
                #ports = {}
                for ent in j[0].ents:
                    if ent.label_ == "transport":
                        ipv4_content["transport"]["content"][ent.text] = ent.text
                        #result_list.append([ent.text, ent.label_, j[1]])
                        #print(ent.text, ent.label_)
                        #await asyncio.sleep(0.001)
                        found_info = True
                for k in j[2]:
                    if k[0] == "Port" or k[0] == "port" or k[0] == "Ports" or k[0] == "ipv4 and port":
                        replacing = "}{,"
                        info = k[1]
                        info = info.split("}")
                        info = info[0]
                        #print(info)
                        for l in replacing:
                            info = info.replace(l, "")
                        info = info.split(":")
                        for l in info:
                            l = l.split()
                            for m in l:
                                try:
                                    trynum = int(m)
                                    ipv4_content["Port"]["content"][str(m)] = m
                                    #result_list.append([m, "Port", j[1]])
                                    #print(m, "Port")
                                    #await asyncio.sleep(0.001)
                                    found_info = True
                                    #ports[m] = m
                                except:
                                    pass
                    elif k[0] == "ipv4":
                        ipv4_content["ipv4"]["content"][k[1]] = k[1]
                        #result_list.append([k[1], k[0], j[1]])
                        #print(k[1], k[0])
                        #await asyncio.sleep(0.001)
                        found_info = True
                if found_info != True:    
                    result_list.append([f"Document has been processed {number}", "Document has been processed", j[1]])
                for i in ipv4_content:
                    for n in ipv4_content[i]:
                        #print(n)
                        if n == "content":
                            for o in ipv4_content[i][n]:
                                #print(o)
                                result_list.append([o, i, j[1]])                
                
            await asyncio.create_task(add_spacy_list(conn, result_list))
        else:
            print("No info found")
        #await asyncio.sleep(0.1)


async def async_spacy():
    content_list = await asyncio.create_task(get_text_content(conn))
    print("Length is ", len(content_list))
    processed_stix_files = 0
    #for i in range(int(len(content_list) / 1000) + 1):
            #while processed_stix_files < len(content_list):
    list_slice = []
    if (processed_stix_files + 1000) <= len(content_list):
        list_slice = content_list[processed_stix_files:(processed_stix_files + 1000)]
    else:
        list_slice = content_list[processed_stix_files:]
    task_spacy_process = asyncio.create_task(spacy_processing(list_slice))
    processed_stix_files += len(list_slice)  
    await task_spacy_process
    print("Done with Spacy")
    ACTIVE_FUNCTIONS = True        

    await asyncio.sleep(1)

async def async_spacy_auto(conn):
    ACTIVE_FUNCTIONS = True
    check_time = datetime.now()
    while ACTIVE_FUNCTIONS == True:
        
        content_list = await asyncio.create_task(get_text_content(conn))
        content_list2 = content_list[:(len(content_list) // 2)]
        print(len(content_list2), "is the length of the first list")
        content_list = content_list[(len(content_list) // 2):]
        print(len(content_list), "is the length of the second list")
        if len(content_list) == 0:
            list_ipv4 = await asyncio.create_task(get_ipv4_spacy(conn, 'ipv4'))
            '''
            if len(list_ipv4) == 0:
                await asyncio.create_task(auto_poll(conn))
            else:
                await asyncio.sleep(120)
            '''
            await asyncio.sleep(1800)
        
        task_spacy_process = asyncio.create_task(spacy_processing(content_list, conn))
        if len(content_list2) != 0:
            task_spacy_process2 = asyncio.create_task(spacy_processing(content_list2, conn))
            await task_spacy_process2
        await task_spacy_process
        
        print("Done with Spacy")     

        await asyncio.sleep(1)

async def total_run():
    layout = [
        [sg.Button('Program running')]
    ]

    window = sg.Window('Program running', layout)

    

    while True:
        event, value = window.read(timeout=100)
        if event == sg.WIN_CLOSED:
            break
        await asyncio.sleep(1)
    window.close()

async def shodan_program():
    layout = [
        [sg.Button('Test IPv4 in Shodan'), sg.Text(key='-SHODAN_OUT-')]
    ]

    window = sg.Window('For Shodan', layout)

    while True:
        event, value = window.read(timeout=100)
        if event == sg.WIN_CLOSED:
            break
        if event == 'Test IPv4 in Shodan':
            count = 0
            
            content = 1
            shodan_time = datetime.now()
            while content == 1:
                await shodan_time > shodan_time + timedelta(seconds=1)
                shodan_time = datetime.now()
                #print("trying Shodan")
                list_ipv4 = await asyncio.create_task(get_ipv4_spacy(conn, 'ipv4'))
                info_list = await asyncio.create_task(check_ipv4(list_ipv4))
                
                await asyncio.create_task(add_shodan(conn, info_list))
                count += 1
                print(f"done running {count}")
                content = len(list_ipv4)
            window['-SHODAN_OUT-'].update("IPv4's tested")
    
    window.close()

async def testing_fast_showdan(list1):
    
    task_shodan = asyncio.create_task(check_ipv4(list1))   
    info_list = await task_shodan
    add_shodan(conn, info_list)
    

async def async_shodan_all():
    SHODONTIME = datetime.now()
    start_time = datetime.now()
    list_ipv4 = await asyncio.create_task(get_all_ipv4_spacy(conn, 'ipv4'))
    count = 0
    done = 0
    tasks = []
    for i in list_ipv4:
        while datetime.now() < SHODONTIME +  timedelta(seconds=1):
            print("Sleeping")
            await asyncio.sleep(0.1)
            
        SHODONTIME = datetime.now()
        print(SHODONTIME)
        count += 1
        print(count)
        await testing_fast_showdan([i])
        #tasks.append(task)
        if count % 100 == 0:
            print(count, "searches performed in", datetime.now() - start_time, "seconds")
    await asyncio.sleep(600)
    #executor = concurrent.futures
    #while list_ipv4:
    #    for i in list_ipv4:
    #        j = i
    #        count += 1
    #        print(count)
    #        await asyncio.sleep(1)
    #        task = asyncio.create_task(testing_fast_showdan([j]))
        

    #await count = done
    #info_list = await task_showdan
    #add_shodan(conn, info_list)
    #spacy_list = len(list_ipv4)
    #await asyncio.sleep(0.001)

async def auto_scapy():
    while True:
        await asyncio.sleep(300)
        await asyncio.create_task(scappy_app_main())

async def async_shodan(conn):
    time_search = datetime.now()
    spacy_list = 10
    ACTIVE_FUNCTIONS = True
    while spacy_list != 0:
        while ACTIVE_FUNCTIONS == False:
            print("sleeping")
            await asyncio.sleep(300)
            print("Done Sleeping, shodan")
            ACTIVE_FUNCTIONS = True
        list_ipv4 = await asyncio.create_task(get_ipv4_spacy(conn, 'ipv4'))
        print("Shodan ok")
        #print("Time since last shodan search", datetime.now() - time_search)

        
        result_list = []
        for i in list_ipv4:
            while datetime.now() < time_search +  timedelta(seconds=0.55):
                #print("Sleeping")
                await asyncio.sleep(0.01)
            task_showdan = asyncio.create_task(check_ipv4(i))
            
            j = await task_showdan
            time_search = datetime.now()
            if j != None:
                result_list.append(j)
            else:
                continue
        #info_list = await check_ipv4(list_ipv4)
        await asyncio.create_task(add_shodan(conn, result_list))
        spacy_list = len(list_ipv4)
        #print("Spacy list is", spacy_list)
        if spacy_list == 0 or spacy_list == None:
            print("Setting Active to false")
            ACTIVE_FUNCTIONS = False
            spacy_list = 1
        #print("Spacy list is", spacy_list)
        
        #print(spacy_list)
        #print(spacy_list)
        #await asyncio.sleep(0.001)

async def get_clients():
    
    clients = []
    
    client1 = create_client(
        'otx.alienvault.com',
        use_https=True,
        discovery_path='/taxii/discovery')
    
    collections1 = client1.get_collections()
    client2 = create_client(
        'open.taxiistand.com',
        use_https=True,
        discovery_path='/services/discovery')
    collections2 = client2.get_collections()
    for i in collections2:
        if i.name == "vxvault":
            collections2 = [i]
    client3 = create_client(
        'hailataxii.com',
        discovery_path='/taxii-discovery-service')     
    client3.set_auth(username="guest", password="guest")
    servises = client3.discover_services()
    collections3 = client3.get_collections()
    clients.append([client1, collections1
    ])
    clients.append([client2, collections2
    ])
    clients.append([client3, collections3])
    return clients
'''
async def poll_alienvault():
    client = create_client(
        'otx.alienvault.com',
        use_https=True,
        discovery_path='/taxii/discovery')
    
    client.get_collections()

    highest_id = get_highest_content(conn, "user_AlienVault")
    total_count = get_total_content(conn, "user_AlienVault")
    if total_count == None:
        total_count = 0
    
    newest_date = get_name_content(conn, highest_id)
    print(f"newest date is {newest_date} and the source_name is user_AlienVault. The id is {highest_id}")
    content_blocks = client.poll(collection_name="user_AlienVault", begin_date=newest_date)

    NUMBER_OF_MSGS = 100
    tmp_cnt_msg = 0
    list_of_ents = []

    for block in content_blocks:
        cnt = block.content

        if (tmp_cnt_msg) % 100 == 0:
            print(f"getting block {tmp_cnt_msg} user_AlienVault with timestamp {block.timestamp}")
            #await asyncio.sleep(0.001)
        list_of_ents.append([str(block.timestamp), cnt, "user_AlienVault"])
        tmp_cnt_msg += 1
        if tmp_cnt_msg >= NUMBER_OF_MSGS:
            print(f"Got {tmp_cnt_msg} files from user_AlienVault")
            break
        if len(list_of_ents) > 9:
            for k in list_of_ents:
                add_content(conn, k[0], k[1], k[2])
            list_of_ents = []
            await asyncio.sleep(0.001)
    print("Done with", "user_AlienVault")
    await asyncio.sleep(0.001)
'''       

async def poll_taxii2client(collection):
    list_of_ents = []
    #highest_id = get_highest_content(conn, collection.title)
    total_count = await asyncio.create_task(get_total_content(conn, collection.title))
    print(total_count)

    for bundle in as_pages(collection.get_objects, per_request=500):
        for info in bundle["objects"]:
            try:
                list_of_ents.append([info["created"], info, collection.title])
            except KeyError as err:
                list_of_ents.append([info["created"], info, "Unknown"])
                pass

        await asyncio.sleep(0.000000001)
        print("adding files", len(list_of_ents))
        for k in list_of_ents:
            print(k)
            #await asyncio.sleep(10)
            await asyncio.create_task(add_content(conn, k[0], json.dumps(k[1]), k[2]))
        list_of_ents = []
        print("Done adding files")
        await asyncio.sleep(0.001)
        

async def auto_poll_taxii2client():
    ACTIVE_FUNCTIONS = True
    #clients_task = asyncio.create_task(get_clients())
    #clients = await clients_task
    while ACTIVE_FUNCTIONS == True:
        server = Server("https://cti-taxii.mitre.org/taxii/")
        api_root = server.api_roots[0]
        collections = api_root.collections
        for i in collections:
            await asyncio.create_task(poll_taxii2client(i))
            await asyncio.sleep(100)
        await asyncio.sleep(1)

async def collection_poll_auto(conn, client, collection):
    print("The collection is", collection)
    print("The client is ", client)
    highest_id = await asyncio.create_task(get_highest_content(conn, collection.name))
    print("The highest id is", highest_id, collection)
    total_count = await asyncio.create_task(get_total_content(conn, collection.name))
    print("Total count is", total_count, collection)
    if total_count == None:
        total_count = 0
    newest_date = None
    if total_count != 0:
        newest_date = await asyncio.create_task(get_name_content(conn, highest_id))
    content_blocks = None
    if client.host != "hailataxii.com":
        content_blocks = client.poll(collection_name=collection.name, begin_date=newest_date)
    else:
        content_blocks = client.poll(collection_name=collection.name)
    NUMBER_OF_MSGS = 400000
    tmp_cnt_msg = 0
    list_of_ents = []
    count_scipp = 0
    if client.host == "hailataxii.com": #collection.name != "vxvault" and collection.name != "user_AlienVault":
        count_scipp = total_count
    try:    
        for block in content_blocks:
            cnt = block.content
            if count_scipp % 10000 == 0 and count_scipp != 0:
                print("Skip for", collection.name, "is", count_scipp)
                await asyncio.sleep(0.01)
            if count_scipp > 0:
                count_scipp -= 1
                continue
            
                        
            if (tmp_cnt_msg) % 500 == 0:
                print(f"getting block {tmp_cnt_msg} {collection.name} with timestamp {block.timestamp}")
                
                await asyncio.create_task(add_content_list(conn, list_of_ents))
                list_of_ents = []
                #await asyncio.sleep(0.000001)
            list_of_ents.append([str(block.timestamp), cnt, collection.name])
            tmp_cnt_msg += 1
            if tmp_cnt_msg >= NUMBER_OF_MSGS:
                print(f"Got {tmp_cnt_msg} files from {collection.name}")
                break
            #if tmp_cnt_msg % 100000 == 0:
            #    await asyncio.sleep(7200)
    except HTTPError as err:
        print(err)
        pass
    except ServiceNotFoundError as err:
        print(err)
        pass
    except NoURIProvidedError as err:
        print(err)
        pass
    except InvalidResponseError as err:
        print(err)
        pass
    except ClientException as err:
        print(err)
        pass
    print("Done with", collection.name)
    await asyncio.sleep(0.001)
    if len(list_of_ents) > 0:
        
        await asyncio.create_task(add_content_list(conn, list_of_ents))


async def auto_poll(conn):
    #await asyncio.sleep(7200)
    ACTIVE_FUNCTIONS = True
    clients = await asyncio.create_task(get_clients())
    print("Got all")
    while ACTIVE_FUNCTIONS == True:
        ACTIVE_FUNCTIONS = False
        print("Inside while loop")
        for i in clients:
            j = i
            for server in j[1]:
                this_server = server
                print(this_server.name)
                await asyncio.create_task(collection_poll_auto(conn, j[0], this_server))
        


async def reset_snort(conn):
    await asyncio.create_task(reset_snort_table(conn))
    await asyncio.create_task(reset_rule_table())
    
    
    #await asyncio.sleep(0.001)
                
    
async def async_snort(conn):
    ACTIVE_FUNCTIONS = True
    action = True

    while True:
        if ACTIVE_FUNCTIONS == False:
            
            print("Sleeping, snort")
            await asyncio.sleep(120)

            print("Done sleeping, snort")
            ACTIVE_FUNCTIONS = True
        await asyncio.create_task(insert_snort_info(conn))
        
        ACTIVE_FUNCTIONS = False
        




async def poll_max():
    
    layout = [
        [sg.Button('Poll maximum from all available collections'), sg.Text(key='-POLL_OUT-')]
    ]

    window = sg.Window('For poll max', layout)

    while True:
        event, value = window.read(timeout=100)
        if event == sg.WIN_CLOSED:
            break
        if event == 'Poll maximum from all available collections':
            CLIENT = create_client(
                'hailataxii.com',
                discovery_path='/taxii-discovery-service')
            #print(CLIENT)
            CLIENT.set_auth(username="guest", password="guest")
            SERVICES = CLIENT.discover_services()
            COLLECTIONS = CLIENT.get_collections()
            for j in COLLECTIONS:
                if j.name != "guest.blutmagie_de_torExits":
                    continue
                await asyncio.create_task(collect_stix_info(conn, CLIENT, j.name, 819987))
            window['-POLL_OUT-'].update('Polled up to 500000 from each collection')

    window.close()





async def main_program():

    layout = [
        #[sg.Button('Create client taxiistand'), sg.Text(key='-CONNECT_OUTPUT-')],
        #[sg.Button('Taxiistand auth'), sg.Text(key='-TAXII_AUTH-')],
        [sg.Button('Create client alien'), sg.Text(key='-CONNECT_OUTPUT_ALIEN-')],
        [sg.Button('Create client hailataxii'), sg.Text(key='-CONNECT_OUTPUT_HAILATAXII-')],
        [sg.Button('Discover services'), sg.Text(key='-DISCOVER_OUTPUT-')],
        [sg.Button('Get collections'), sg.Text(key='-COLLECTIONS_OUTPUT-')],
        [sg.Button('Store sources'), sg.Text(key='-STORE_SOURCES-')],
        [sg.Button('Poll lots'), sg.Text(key='-POLL_LOTS-')],
        [sg.Button('Run shodan with IPv4 search')],
        [sg.Button('Reset Snort'), sg.Text(key='-TRY_SNORT-')],
        [sg.Button('Scapy run'), sg.Text(key='-SCAPY_RUN-')],
        [sg.Text(key='-STATUS-', size=[30, 20])]
    ]

    conn = await create_connection_async(database)
    print(conn)

    ACTIVE_FUNCTIONS = False
    await asyncio.create_task(reset_snort(conn))
    SHODONTIME = datetime.now()
    print(SHODONTIME, "This is SHODON_TIME")
    window = sg.Window('The program', layout)
    ACTIVE_TIME = datetime.now()
    print(ACTIVE_TIME)
    snort_task = asyncio.create_task(async_snort(conn))
    #await snort_task
    shodan_task_run = asyncio.create_task(async_shodan(conn))
    #await shodan_task_run
    spacy_background_run = asyncio.create_task(async_spacy_auto(conn))
    #await spacy_background_run
    #task_auto_poll = asyncio.create_task(auto_poll(conn))
    #await task_auto_poll
    #task_auto_scapy = asyncio.create_task(scappy_app_main())
    

    info_string = ""
    
    
    #await shodan_task_run
    while True:
        
        event, value = window.read(timeout=100)
        if event == sg.WIN_CLOSED:
            break
        
        



        elif event == 'Create client alien':
            CLIENT = create_client(
                'otx.alienvault.com',
                use_https=True,
                discovery_path='/taxii/discovery')
            print(CLIENT)
            if CLIENT != None:
                window['-CONNECT_OUTPUT_ALIEN-'].update('Created')

            '''
            # Could not get this one to work
            elif event == 'Create client limo':
                CLIENT = create_client(
                    'limo.anomali.com',
                    use_https=True,
                    discovery_path='/api/v1/taxii/taxii-discovery-service/')
                print(CLIENT)
                if CLIENT != None:
                    window['-CONNECT_OUTPUT_LIMO-'].update('Created')
            '''

        elif event == 'Create client hailataxii':
            CLIENT = create_client(
                'hailataxii.com',
                discovery_path='/taxii-discovery-service')
            #print(CLIENT)
            CLIENT.set_auth(username="guest", password="guest")
            if CLIENT != None:
                window['-CONNECT_OUTPUT_HAILATAXII-'].update('Created')

        elif event == 'Discover services':
            SERVICES = CLIENT.discover_services()
            if SERVICES != None:
                window['-DISCOVER_OUTPUT-'].update('Discovered')
        elif event == 'Get collections':
            COLLECTIONS = CLIENT.get_collections()
            col_string = ''
            for i in COLLECTIONS:
                col_string += i.name + '\n'
                #print(i)
            if col_string != None:
                window['-COLLECTIONS_OUTPUT-'].update(col_string)
            
        elif event == 'Store sources':
            added_source = ''
            
            for i in COLLECTIONS:
                await asyncio.create_task(add_source(conn, i.name))
                added_source += i.name + '\n'
            window['-STORE_SOURCES-'].update(added_source)

        elif event == 'Poll lots':
            for j in COLLECTIONS:
                if j.name == "guest.blutmagie_de_torExits":
                    task = asyncio.create_task(collect_stix_info(conn, CLIENT, j.name, 819987))
            #window['-POLL_LOTS-'].update('Polled up to 1000000 from each collection')
            #snort_task = asyncio.create_task(async_snort())
            #shodan_task_run = asyncio.create_task(async_shodan())
            #spacy_background_run = asyncio.create_task(async_spacy_auto())
            #task_auto_poll = asyncio.create_task(auto_poll())

        elif event == 'Run shodan with IPv4 search':
            task = asyncio.create_task(shodan_program())
            await task
            




        



        

        elif event == 'Reset Snort':
            '''
            info = {
                "ipv4_src": "",
                "msg": "",
                "sid": "1000000"
            }
            '''


            
            snort_task_run = asyncio.create_task(reset_snort(conn))
            await snort_task_run

            window['-TRY_SNORT-'].update(f"Tried to reset Snort")
        
        elif datetime.now() > ACTIVE_TIME + timedelta(minutes=5):
            ACTIVE_TIME = datetime.now()
            print(ACTIVE_TIME)
            info = await asyncio.create_task(get_status_info(conn))
            
            for i in info:
                info_string = i + "\n" + info_string
            info_string = "\n" + f"{datetime.now()}" + "\n" + info_string
            window['-STATUS-'].update(info_string)
            
        
        elif event == 'Scapy run': #datetime.now() > (ACTIVE_TIME):# + timedelta(minutes=30)):
            
            ipv4_list = await asyncio.create_task(scappy_app_main())
            string_output = ""
            for i in ipv4_list:
                string_output += i + "\n"
            window['-SCAPY_RUN-'].update(string_output)
        await asyncio.sleep(0.001)
    #await spacy_task_run


            

        



    window.close()

#p1 = Process(target=asyncio.run(main_program()))
#p2 = Process(target=shodan_program)
#p3 = Process(target=poll_max)
#p4 = Process(target=run_spacy)
#p7 = Process(target=asyncio.run(total_run()))


if __name__ == "__main__":
    
    asyncio.run(main_program())
    