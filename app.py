from http import client
from msilib.schema import Error
from multiprocessing.connection import Client, wait
from socket import timeout
#from urllib.error import HTTPError
import PySimpleGUI as sg
import spacy
from setup_db import create_connection, add_source, get_text_content, collect_stix_info, add_spacy, delete_entry_content, \
    clean_spacy_list, get_all_label_spacy, clean_content_list, get_ipv4_spacy, add_shodan, add_snort, insert_snort_info, get_text_content_spacy2, \
    get_text_content_spacy2, add_spacy2, get_highest_content, get_name_content, add_content, get_total_content, reset_snort_table, get_all_ipv4_spacy, \
    get_status_info, insert_snort_info_test
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

conn = create_connection(database)

async def spacy_processing(content_list):
    
        found_info = False
        count_entrys = 0
        
        #list_of_entrys = find_relevant_spacy_list(content_list)
        

        # Trying out with json files
        task = asyncio.create_task(find_relevant_spacy_stix(content_list))
        
        #task = asyncio.create_task(find_relevant_spacy_list(content_list))
        
        list_of_entrys = await task
        if list_of_entrys != None:
            for j in list_of_entrys:
                count_entrys += 1
                #ports = {}
                for ent in j[0].ents:
                    if ent.label_ == "transport":
                        add_spacy(conn, ent.text, ent.label_, (j[1]))
                        #print(ent.text, ent.label_)
                        #await asyncio.sleep(0.001)
                        found_info = True
                for k in j[2]:
                    if k[0] == "Port" or k[0] == "port" or k[0] == "Ports" or k[0] == "ipv4 and port":
                        replacing = "}{,"
                        info = k[1]
                        #print(info)
                        for l in replacing:
                            info = info.replace(l, "")
                        info = info.split(":")
                        for l in info:
                            l = l.split()
                            for m in l:
                                try:
                                    trynum = int(m)
                                    add_spacy(conn, m, "Port", j[1])
                                    #print(m, "Port")
                                    #await asyncio.sleep(0.001)
                                    found_info = True
                                    #ports[m] = m
                                except:
                                    pass
                    elif k[0] != "URL":
                        add_spacy(conn, k[1], k[0], (j[1]))
                        #print(k[1], k[0])
                        #await asyncio.sleep(0.001)
                        found_info = True
                                
                if found_info == False:
                    add_spacy(conn, "no info found in this document", "No info", j[1])
                #await asyncio.sleep(0.00001)
        else:
            print("No info found")
        #await asyncio.sleep(0.1)


async def async_spacy():
    content_list = get_text_content(conn)
    print("Length is ", len(content_list))
    processed_stix_files = 0
    for i in range(int(len(content_list) / 1000) + 1):
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

async def async_spacy_auto():
    ACTIVE_FUNCTIONS = True
    while ACTIVE_FUNCTIONS == True:
        content_list = get_text_content(conn)
        print("Length is ", len(content_list))
        if len(content_list) == 0:
            await asyncio.sleep(180)
        
        task_spacy_process = asyncio.create_task(spacy_processing(content_list))
        await task_spacy_process
        print("Done with Spacy")     

        #await asyncio.sleep(1)

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
                list_ipv4 = get_ipv4_spacy(conn, 'ipv4')
                info_list = check_ipv4(list_ipv4)
                
                add_shodan(conn, info_list)
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
    list_ipv4 = get_all_ipv4_spacy(conn, 'ipv4')
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
        scappy_app_main()

async def async_shodan():
    time_search = datetime.now()
    spacy_list = 10
    ACTIVE_FUNCTIONS = True
    while spacy_list != 0:
        while ACTIVE_FUNCTIONS == False:
            print("sleeping")
            await asyncio.sleep(300)
            print("Done Sleeping")
            ACTIVE_FUNCTIONS = True
        list_ipv4 = get_ipv4_spacy(conn, 'ipv4')
        #print("Time since last shodan search", datetime.now() - time_search)

        
        result_list = []
        for i in list_ipv4:
            while datetime.now() < time_search +  timedelta(seconds=0.8):
                #print("Sleeping")
                await asyncio.sleep(0.01)
            task_showdan = asyncio.create_task(check_ipv4([i]))
            time_search = datetime.now()
            j = await task_showdan
            result_list.append(j)
        #info_list = await check_ipv4(list_ipv4)
        add_shodan(conn, result_list)
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
    
    
    clients.append([client1, collections1
    ])
    clients.append([client2, collections2
    ])
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
    total_count = get_total_content(conn, collection.title)
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
            add_content(conn, k[0], json.dumps(k[1]), k[2])
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
            task_collection = asyncio.create_task(poll_taxii2client(i))
            await asyncio.sleep(100)
        await asyncio.sleep(1)
 

async def auto_poll():
    await asyncio.sleep(7200)
    ACTIVE_FUNCTIONS = True
    clients_task = asyncio.create_task(get_clients())
    clients = await clients_task
    while ACTIVE_FUNCTIONS == True:
        
        for i in range(len(clients)):
            await asyncio.sleep(0.001)
            print("printing collections", clients[i][1])
            for j in clients[i][1]:
                
                highest_id = get_highest_content(conn, j.name)
                total_count = get_total_content(conn, j.name)
                if total_count == None:
                    total_count = 0
                newest_date = get_name_content(conn, highest_id)
                    
                print(f"newest date is {newest_date} and the source_name is {j.name}. The id is {highest_id}")
                content_blocks = clients[i][0].poll(collection_name=j.name, begin_date=newest_date)
                NUMBER_OF_MSGS = 5000
                tmp_cnt_msg = 0
                list_of_ents = []
                count_scipp = 0
                try:    
                    for block in content_blocks:
                    
                        count_scipp += 1
                        cnt = block.content
                        
                        if count_scipp % 1000 == 0:
                            print("count is", count_scipp)
                            await asyncio.sleep(0.001)
                        if count_scipp <= total_count and j.name != "vxvault" and j.name != "user_AlienVault":
                            continue
                        if (tmp_cnt_msg) % 10 == 0:
                            print(f"getting block {tmp_cnt_msg} {j.name} with timestamp {block.timestamp}")
                            for k in list_of_ents:
                                add_content(conn, k[0], k[1], k[2])
                            list_of_ents = []
                            await asyncio.sleep(0.001)
                        list_of_ents.append([str(block.timestamp), cnt, j.name])
                        tmp_cnt_msg += 1
                        if tmp_cnt_msg >= NUMBER_OF_MSGS:
                            print(f"Got {tmp_cnt_msg} files from {j.name}")
                            break
                except HTTPError as err:
                    print(err)
                    continue
                except ServiceNotFoundError as err:
                    print(err)
                    continue
                except NoURIProvidedError as err:
                    print(err)
                    continue
                except InvalidResponseError as err:
                    print(err)
                    continue
                except ClientException as err:
                    print(err)
                    continue
                print("Done with", j.name)
                await asyncio.sleep(0.001)
                if len(list_of_ents) > 0:
                    for k in list_of_ents:
                        add_content(conn, k[0], k[1], k[2])
                
        await asyncio.sleep(14400)
            
 

async def reset_snort():
    reset_snort_table(conn)
    reset_rule_table()
    #task = asyncio.create_task(insert_snort_info(conn))
    
    #await asyncio.sleep(0.001)
                
    
async def async_snort():
    ACTIVE_FUNCTIONS = True
    action = True
    while True:
        if ACTIVE_FUNCTIONS == False:
            print("Sleeping")
            await asyncio.sleep(120)
            print("Done sleeping")
            ACTIVE_FUNCTIONS = True
        task = asyncio.create_task(insert_snort_info_test(conn))
        await task
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
                if j.name == "guest.EmergineThreats_rules" or j.name == "system.Default":
                    continue
                collect_stix_info(conn, CLIENT, j.name, 500000)
            window['-POLL_OUT-'].update('Polled up to 500000 from each collection')

    window.close()

def run_spacy():
    layout = [
        [sg.Button('Run spacy on stix files'), sg.Text(key='-SPACY_OUT-')]
    ]

    window = sg.Window('For spacy', layout)

    while True:
        event, value = window.read(timeout=100)
        if event == sg.WIN_CLOSED:
            break
        
        if event == 'Run spacy on stix files':
            for i in range(20):
                #print('Getting 2000 stix files for spacy')
                content_list = get_text_content(conn)
                processed_stix_files = 0
                while (processed_stix_files + 1000) < len(content_list):
                    
                    #print("Inside While loop")
                    list_slice = content_list[processed_stix_files:(processed_stix_files + 1000)]
                    print(f"Length of listslice is {len(list_slice)}")
                    print(f"Processing stix fil {processed_stix_files} to {(processed_stix_files + 1000)} in range {len(content_list)}")
                    list_of_entrys = find_relevant_spacy_list(list_slice)
                    if list_of_entrys != None:
                        for j in list_of_entrys:
                            ports = {}
                            for ent in j[0].ents:
                                if ent.label_ == "transport":
                                    add_spacy(conn, ent.text, ent.label_, (j[1]))
                            for k in j[2]:
                                if k[0] == "Port" or k[0] == "Ports" or k[0] == "ipv4 and port":
                                    replacing = "}{,"
                                    info = k[1]
                                    for l in replacing:
                                        info = info.replace(l, "")
                                    info = info.split(":")
                                    for l in info:
                                        l = l.split()
                                        for m in l:
                                            try:
                                                trynum = int(m)
                                                add_spacy(conn, m, "Port", j[1])
                                                ports[m] = m
                                            except:
                                                pass
                                elif k[0] != "URL":
                                    add_spacy(conn, k[1], k[0], (j[1]))
                    processed_stix_files += 1000
                list_slice = content_list[processed_stix_files:]
                if len(list_slice) > 0:
                    print("inside if statement")
                    print(f"Length of listslice is {len(list_slice)}")
                    print(f"Processing stix fil {processed_stix_files} to {len(content_list)} in range {len(content_list)}")
                    list_of_entrys = find_relevant_spacy_list(list_slice)
                    if list_of_entrys != None:
                        for j in list_of_entrys:
                            ports = {}
                            for ent in j[0].ents:
                                if ent.label_ == "transport":
                                    add_spacy(conn, ent.text, ent.label_, (j[1]))
                            for k in j[2]:
                                if k[0] == "Port" or k[0] == "Ports" or k[0] == "ipv4 and port":
                                    replacing = "}{,"
                                    info = k[1]
                                    for l in replacing:
                                        info = info.replace(l, "")
                                    info = info.split(":")
                                    for l in info:
                                        l = l.split()
                                        for m in l:
                                            try:
                                                trynum = int(m)
                                                add_spacy(conn, m, "Port", j[1])
                                                ports[m] = m
                                            except:
                                                pass
                                elif k[0] != "URL":
                                    add_spacy(conn, k[1], k[0], (j[1]))
            #clean_spacy_list(conn)
            window['-SPACY_OUT-'].update('Spacy worked trough up to 250 000 files')





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
        [sg.Button('Total run'), sg.Text(key='-TOTAL_RUN-')],
        [sg.Button('Poll many')],
        [sg.Button('Run spacy')],
        [sg.Text(key='-STATUS-', size=[30, 20])]
    ]

    ACTIVE_FUNCTIONS = False
    SHODONTIME = datetime.now()
    print(SHODONTIME, "This is SHODON_TIME")
    window = sg.Window('The program', layout)
    ACTIVE_TIME = datetime.now()
    print(ACTIVE_TIME)
    snort_task = asyncio.create_task(async_snort())
    shodan_task_run = asyncio.create_task(async_shodan())
    
    spacy_background_run = asyncio.create_task(async_spacy_auto())
    task_auto_poll = asyncio.create_task(auto_poll())
    #task_auto_scapy = asyncio.create_task(scappy_app_main(conn))
    

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
                add_source(conn, i.name)
                added_source += i.name + '\n'
            window['-STORE_SOURCES-'].update(added_source)

        elif event == 'Poll lots':
            for j in COLLECTIONS:
                task = asyncio.create_task(collect_stix_info(conn, CLIENT, j.name, 100000000))
            #window['-POLL_LOTS-'].update('Polled up to 1000000 from each collection')
            #snort_task = asyncio.create_task(async_snort())
            #shodan_task_run = asyncio.create_task(async_shodan())
            #spacy_background_run = asyncio.create_task(async_spacy_auto())
            #task_auto_poll = asyncio.create_task(auto_poll())

        elif event == 'Run shodan with IPv4 search':
            task = asyncio.create_task(shodan_program())
            await task
            



        elif event == 'Poll many':
            p3.start()
        
        elif event == 'Run spacy':
            p4.start()


        

        elif event == 'Reset Snort':
            '''
            info = {
                "ipv4_src": "",
                "msg": "",
                "sid": "1000000"
            }
            '''


            
            snort_task_run = asyncio.create_task(reset_snort())
            await snort_task_run

            window['-TRY_SNORT-'].update(f"Tried to reset Snort")
        
        elif datetime.now() > ACTIVE_TIME + timedelta(minutes=1):
            ACTIVE_TIME = datetime.now()
            print(ACTIVE_TIME)
            info = get_status_info(conn)
            
            for i in info:
                info_string = i + "\n" + info_string
            info_string = "\n" + f"{datetime.now()}" + "\n" + info_string
            window['-STATUS-'].update(info_string)
            
        
        elif event == 'Total run': #datetime.now() > (ACTIVE_TIME):# + timedelta(minutes=30)):
            
            snort_task = asyncio.create_task(async_snort())
            shodan_task_run = asyncio.create_task(async_shodan())
            spacy_background_run = asyncio.create_task(async_spacy_auto())
            task_auto_poll = asyncio.create_task(auto_poll())
            
        await asyncio.sleep(0.001)
    #await spacy_task_run


            

        



    window.close()

p1 = Process(target=asyncio.run(main_program()))
#p2 = Process(target=shodan_program)
p3 = Process(target=poll_max)
p4 = Process(target=run_spacy)
p7 = Process(target=asyncio.run(total_run()))


if __name__ == "__main__":
    asyncio.run(main_program())
    