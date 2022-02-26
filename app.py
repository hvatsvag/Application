from http import client
from multiprocessing.connection import Client
from socket import timeout
import PySimpleGUI as sg
from setup_db import create_connection, add_source, get_text_content, collect_stix_info, add_spacy, delete_entry_content, \
    clean_spacy_list, get_all_label_spacy, clean_content_list, get_ipv4_spacy, add_shodan, add_snort, insert_snort_info, get_text_content_spacy2, \
    get_text_content_spacy2, add_spacy2, get_ipv4_spacy2
import sqlite3
from cabby import create_client
import stix2viz
from stix2elevator import elevate
from stix2elevator.options import initialize_options, set_option_value
from spacy_prog import find_relevant_info, find_relevant_spacy, find_relevant_spacy_list, find_relevant_spacy_stix
import time
from shodan_program import check_ipv4, insert_snort
from multiprocessing import Process
 

CLIENT = None
SERVICES = None
COLLECTIONS = None

database = r"./database.db"

conn = create_connection(database)

def shodan_program():
    layout = [
        [sg.Button('Test IPv4 in Shodan'), sg.Text(key='-SHODAN_OUT-')]
    ]

    window = sg.Window('For Shodan', layout)

    while True:
        event, value = window.read(timeout=100)
        if event == sg.WIN_CLOSED:
            break
        if event == 'Test IPv4 in Shodan':
            for i in range(100000):
                print("trying Shodan")
                list_ipv4 = get_ipv4_spacy(conn, 'ipv4')
                info_list = check_ipv4(list_ipv4)
                print(len(info_list))
                add_shodan(conn, info_list)
            window['-SHODAN_OUT-'].update("IPv4's tested")
    
    window.close()

def shodan_program_spacy2():
    layout = [
        [sg.Button('Test IPv4 in Shodan'), sg.Text(key='-SHODAN_OUT-')]
    ]

    window = sg.Window('For Shodan', layout)

    while True:
        event, value = window.read(timeout=100)
        if event == sg.WIN_CLOSED:
            break
        if event == 'Test IPv4 in Shodan':
            for i in range(100000):
                print("trying Shodan")
                list_ipv4 = get_ipv4_spacy2(conn, 'ipv4')
                info_list = check_ipv4(list_ipv4)
                print(len(info_list))
                add_shodan(conn, info_list)
            window['-SHODAN_OUT-'].update("IPv4's tested")
    
    window.close()


def poll_max():
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
                collect_stix_info(conn, CLIENT, j.name, 200000)
            window['-POLL_OUT-'].update('Polled up to 200000 from each collection')

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
                            for ent in j[0].ents:
                                if ent.label_ == "transport":
                                    add_spacy(conn, ent.text, ent.label_, (j[1]))
                            for k in j[2]:
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
                            for ent in j[0].ents:
                                if ent.label_ == "transport":
                                    add_spacy(conn, ent.text, ent.label_, (j[1]))
                            for k in j[2]:
                                add_spacy(conn, k[1], k[0], (j[1]))
            #clean_spacy_list(conn)
            window['-SPACY_OUT-'].update('Spacy worked trough up to 250 000 files')

def run_spacy2():
    layout = [
        [sg.Button('Run spacy on stix files, where IP addresses are active'), sg.Text(key='-SPACY_OUT-')]
    ]

    window = sg.Window('For spacy', layout)

    while True:
        event, value = window.read(timeout=100)
        if event == sg.WIN_CLOSED:
            break
        
        if event == 'Run spacy on stix files, where IP addresses are active':
            for i in range(5):
                print('Getting all stix files for spacy2')
                content_list = get_text_content_spacy2(conn)
                processed_stix_files = 0
                while (processed_stix_files + 1000) < len(content_list):
                    
                    print("Inside While loop")
                    list_slice = content_list[processed_stix_files:(processed_stix_files + 1000)]
                    print(f"Length of listslice is {len(list_slice)}")
                    print(f"Processing stix fil {processed_stix_files} to {(processed_stix_files + 1000)} in range {len(content_list)}")
                    list_of_entrys = find_relevant_spacy_stix(list_slice)
                    if list_of_entrys != None:
                        for j in list_of_entrys:
                            for ent in j[0].ents:
                                if ent.label_ == "transport":
                                    add_spacy2(conn, ent.text, ent.label_, (j[1]))
                            for k in j[2]:
                                if k[0] != "URL":
                                    add_spacy2(conn, k[1], k[0], (j[1]))
                    processed_stix_files += 1000
                    time.sleep(100)
                list_slice = content_list[processed_stix_files:]
                if len(list_slice) > 0:
                    print("inside if statement")
                    print(f"Length of listslice is {len(list_slice)}")
                    print(f"Processing stix fil {processed_stix_files} to {len(content_list)} in range {len(content_list)}")
                    list_of_entrys = find_relevant_spacy_stix(list_slice)
                    if list_of_entrys != None:
                        for j in list_of_entrys:
                            for ent in j[0].ents:
                                if ent.label_ == "transport":
                                    add_spacy2(conn, ent.text, ent.label_, (j[1]))
                            for k in j[2]:
                                if k[0] != "URL":
                                    add_spacy2(conn, k[1], k[0], (j[1]))
            #clean_spacy_list(conn)
            window['-SPACY_OUT-'].update('Spacy worked trough up to 250 000 files')



def main_program():

    layout = [
        [sg.Button('Create client taxiistand'), sg.Text(key='-CONNECT_OUTPUT-')],
        [sg.Button('Taxiistand auth'), sg.Text(key='-TAXII_AUTH-')],
        [sg.Button('Create client alien'), sg.Text(key='-CONNECT_OUTPUT_ALIEN-')],
        [sg.Button('Create client hailataxii'), sg.Text(key='-CONNECT_OUTPUT_HAILATAXII-')],
        [sg.Button('Discover services'), sg.Text(key='-DISCOVER_OUTPUT-')],
        [sg.Button('Get collections'), sg.Text(key='-COLLECTIONS_OUTPUT-')],
        [sg.Button('Store sources'), sg.Text(key='-STORE_SOURCES-')],
        [sg.Button('Poll lots'), sg.Text(key='-POLL_LOTS-')],
        [sg.Button('Run shodan with IPv4 search')],
        [sg.Button('Run shodan with IPv4 search spacy2')],
        [sg.Button('Try Snort'), sg.Text(key='-TRY_SNORT-')],
        [sg.Button('Poll many')],
        [sg.Button('Run spacy')],
        [sg.Button('Run spacy2')]
    ]



    window = sg.Window('The program', layout)

    while True:
        event, value = window.read(timeout=100)
        if event == sg.WIN_CLOSED:
            break
        elif event == 'Create client taxiistand':
            CLIENT = create_client(
                'open.taxiistand.com',
                use_https=True,
                discovery_path='/services/discovery')
            print(CLIENT)
            if CLIENT != None:
                #CLIENT.set_auth(username='guest', password='guest')
                window['-CONNECT_OUTPUT-'].update('Created')

        elif event == 'Taxiistand auth':

            CLIENT.set_auth(username="guest", password="guest")



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
                collect_stix_info(conn, CLIENT, j.name, 100000000)
            window['-POLL_LOTS-'].update('Polled up to 1000000 from each collection')


        elif event == 'Run shodan with IPv4 search':
            p2.start()

        elif event == 'Run shodan with IPv4 search spacy2':
            p6.start()

        elif event == 'Poll many':
            p3.start()
        
        elif event == 'Run spacy':
            p4.start()

        elif event == 'Run spacy2':
            p5.start()

        elif event == 'Try Snort':
            '''
            info = {
                "ipv4_src": "",
                "msg": "",
                "sid": "1000000"
            }
            '''


            
            insert_snort_info(conn)
            window['-TRY_SNORT-'].update(f"Tried to update Snort")





    window.close()

p1 = Process(target=main_program)
p2 = Process(target=shodan_program)
p3 = Process(target=poll_max)
p4 = Process(target=run_spacy)
p5 = Process(target=run_spacy2)
p6 = Process(target=shodan_program_spacy2)

if __name__ == "__main__":
    p1.start()