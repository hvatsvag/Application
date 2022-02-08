from http import client
from multiprocessing.connection import Client
from socket import timeout
import PySimpleGUI as sg
from setup_db import create_connection, add_source, get_text_content, collect_stix_info, add_spacy, delete_entry_content, \
    clean_spacy_list, get_all_label_spacy, clean_content_list, get_ipv4_spacy, add_shodan, add_snort, insert_snort_info
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
            for i in range(100):
                print("trying Shodan")
                list_ipv4 = get_ipv4_spacy(conn, 'ipv4')
                info_list = check_ipv4(list_ipv4)
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
            for j in COLLECTIONS:
                collect_stix_info(conn, CLIENT, j.name, 10000000)
            window['-POLL_OUT-'].update('Polled up to 1000000 from each collection')

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
            for i in range(5):
                print('Getting 2000 stix files for spacy')
                content_list = get_text_content(conn)
                list_of_entrys = find_relevant_spacy_stix(content_list)
                if list_of_entrys != None:
                    for j in list_of_entrys:
                        for ent in j[0].ents:
                            if ent.text != "rules.emergingthreats.net" and ent.label_ != "DATE":
                                add_spacy(conn, ent.text, ent.label_, (j[1]))
            clean_spacy_list(conn)
            window['-SPACY_OUT-'].update('Spacy worked trough up to 250 000 files')
           

    window.close()

def main_program():

    layout = [
        [sg.Button('Create client taxiistand'), sg.Text(key='-CONNECT_OUTPUT-')],
        [sg.Button('Taxiistand auth'), sg.Text(key='-TAXII_AUTH-')],
        [sg.Button('Create client alien'), sg.Text(key='-CONNECT_OUTPUT_ALIEN-')],
        [sg.Button('Create client hailataxii'), sg.Text(key='-CONNECT_OUTPUT_HAILATAXII-')],
        [sg.Button('Discover services'), sg.Text(key='-DISCOVER_OUTPUT-')],
        [sg.Button('Get collections'), sg.Text(key='-COLLECTIONS_OUTPUT-')],
        [sg.Button('Store sources'), sg.Text(key='-STORE_SOURCES-')],
        [sg.Button('Print IPv4 shodan')],
        [sg.Button('Try Snort'), sg.Text(key='-TRY_SNORT-')],
        [sg.Button('Poll many')],
        [sg.Button('Run spacy')]
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




        elif event == 'Print IPv4 shodan':
            p2.start()

        elif event == 'Poll many':
            p3.start()
        
        elif event == 'Run spacy':
            p4.start()

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

if __name__ == "__main__":
    p1.start()