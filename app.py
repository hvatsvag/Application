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
 

CLIENT = None
SERVICES = None
COLLECTIONS = None

database = r"./database.db"

conn = create_connection(database)



layout = [
    [sg.Button('Create client taxiistand'), sg.Text(key='-CONNECT_OUTPUT-')],
    [sg.Button('Taxiistand auth'), sg.Text(key='-TAXII_AUTH-')],
    [sg.Button('Create client alien'), sg.Text(key='-CONNECT_OUTPUT_ALIEN-')],
    [sg.Button('Create client hailataxii'), sg.Text(key='-CONNECT_OUTPUT_HAILATAXII-')],
    [sg.Button('Discover services'), sg.Text(key='-DISCOVER_OUTPUT-')],
    [sg.Button('Get collections'), sg.Text(key='-COLLECTIONS_OUTPUT-')],
    [sg.Button('Store sources'), sg.Text(key='-STORE_SOURCES-')],
    [sg.Button('Find relevant info'), sg.Text(key='-SPACY_COLLECT-')],
    [sg.Button('Find relevant info list'), sg.Text(key='-SPACY_COLLECT_LIST-')],
    [sg.Button('Find relevant info list no json'), sg.Text(key='-SPACY_COLLECT_LIST_NJS-')],
    [sg.Button('Print IPv4 list'), sg.Text(key='-PRINT_IPV4-')],
    [sg.Button('Print URL list'), sg.Text(key='-PRINT_URL-')],
    [sg.Button('Print IPv4 shodan'), sg.Text(key='-PRINT_IPV4_SHODAN-')],
    [sg.Button('Try Snort'), sg.Text(key='-TRY_SNORT-')],
    #[sg.Button('Find relevant info failed list'), sg.Text(key='-SPACY_COLLECT_LIST_FAILED-')],
    [sg.Button('Store vxvault data'), sg.Text(key='-COLLECT_VX-')],
    [sg.Button('Store hailataxii.guest.Lehigh_edu data'), sg.Text(key='-COLLECT_H_LEIGH-')],
    [sg.Button('Store hailataxii.guest.CyberCrime_Tracker data'), sg.Text(key='-COLLECT_H_CyberCrime-')],
    [sg.Button('Store hailataxii.guest.MalwareDomainList_Hostlist data'), sg.Text(key='-COLLECT_H_MALWARE-')],
    [sg.Button('Store hailataxii.hailataxii.guest.blutmagie_de_torExits data'), sg.Text(key='-COLLECT_H_BLUTMAGIE-')],
    [sg.Button('Store hailataxii.guest.dshield_BlockList data'), sg.Text(key='-COLLECT_H_DSHIELD-')],
    [sg.Button('Store hailataxii.guest.Abuse_ch data'), sg.Text(key='-COLLECT_H_ABUSE-')],
    [sg.Button('Store hailataxii.guest.phishtank_com data'), sg.Text(key='-COLLECT_H_PHISHTANK-')],
    [sg.Button('Store hailataxii.guest.dataForLast_7daysOnly data'), sg.Text(key='-COLLECT_H_7DAYS-')],
    [sg.Button('Store hailataxii.guest.EmergineThreats_rules data'), sg.Text(key='-COLLECT_H_EMERGINE-')],
    [sg.Button('Store vxvault new window')]
]



window = sg.Window('The program', layout)
win2_active = False

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

    elif event == 'Store vxvault data':
        counter_getdata = 0
        for i in range(1):
            window['-COLLECT_VX-'].update('')
            for j in COLLECTIONS:
                #if j.name != 'vxvault' and j.name != 'hailataxii.guest.CyberCrime_Tracker' and j.name != 'hailataxii.guest.MalwareDomainList_Hostlist':
                if j.name != 'guest.dshield_BlockList':
                    counter_getdata += 1
                    print(f"Trying to connect to {j.name}")
                    collect_stix_info(conn, CLIENT, j.name, 50)
                    window['-COLLECT_VX-'].update('Data added 200, for each')

    elif event == 'Store hailataxii.guest.Lehigh_edu data':
        str_h_leigh = ""
        for i in range(100):
        
            collect_stix_info(conn, CLIENT, 'hailataxii.guest.Lehigh_edu', 2000000)
            str_h_leigh += "Data added 2000000"
            window['-COLLECT_H_LEIGH-'].update(str_h_leigh)

    elif event == 'Store hailataxii.guest.CyberCrime_Tracker data':
        str_h_leigh = ""
        for i in range(100):
            
            collect_stix_info(conn, CLIENT, 'hailataxii.guest.CyberCrime_Tracker', 2000000)
            str_h_leigh += "Data added 2000000"
            window['-COLLECT_H_CyberCrime-'].update(str_h_leigh)
        ''' 
        window['-COLLECT_H_CyberCrime-'].update('')
        collect_stix_info(conn, CLIENT, 'hailataxii.guest.CyberCrime_Tracker', 2000000)
        window['-COLLECT_H_CyberCrime-'].update('Data added 2000000')
        '''
        

    elif event == 'Store hailataxii.guest.MalwareDomainList_Hostlist data':
        window['-COLLECT_H_MALWARE-'].update('')
        collect_stix_info(conn, CLIENT, 'hailataxii.guest.MalwareDomainList_Hostlist', 200)
        window['-COLLECT_H_MALWARE-'].update('Data added 200')

    elif event == 'Store hailataxii.hailataxii.guest.blutmagie_de_torExits data':
        window['-COLLECT_H_BLUTMAGIE-'].update('')
        collect_stix_info(conn, CLIENT, 'hailataxii.guest.blutmagie_de_torExits', 200)
        window['-COLLECT_H_BLUTMAGIE-'].update('Data added 200')

    elif event == 'Store hailataxii.guest.dshield_BlockList data':
        window['-COLLECT_H_DSHIELD-'].update('')
        collect_stix_info(conn, CLIENT, 'hailataxii.guest.dshield_BlockList', 200)
        window['-COLLECT_H_DSHIELD-'].update('Data added 200')

    elif event == 'Store hailataxii.guest.Abuse_ch data':
        window['-COLLECT_H_ABUSE-'].update('')
        collect_stix_info(conn, CLIENT, 'hailataxii.guest.Abuse_ch', 200)
        window['-COLLECT_H_ABUSE-'].update('Data added 200')

    elif event == 'Store hailataxii.guest.phishtank_com data':
        window['-COLLECT_H_PHISHTANK-'].update('')
        collect_stix_info(conn, CLIENT, 'hailataxii.guest.phishtank_com', 200)
        window['-COLLECT_H_PHISHTANK-'].update('Data added 200')

    elif event == 'Store hailataxii.guest.dataForLast_7daysOnly data':
        window['-COLLECT_H_7DAYS-'].update('')
        collect_stix_info(conn, CLIENT, 'hailataxii.guest.dataForLast_7daysOnly', 200)
        window['-COLLECT_H_7DAYS-'].update('Data added 200')

    elif event == 'Store hailataxii.guest.EmergineThreats_rules data':
        window['-COLLECT_H_EMERGINE-'].update('')
        collect_stix_info(conn, CLIENT, 'hailataxii.guest.EmergineThreats_rules', 200)
        window['-COLLECT_H_EMERGINE-'].update('Data added 200')

    elif event == 'Find relevant info':
        #spacy_working = ""
        for i in range(1):
            content_list = get_text_content(conn)
            #print(text_content)
            for j in content_list:
                print("\n\n\n\n\nThis is j\n\n\n\n\n",j[0], j[1])
                text_description = find_relevant_info(j[0])
                #text_description = find_relevant_info(text_content)
                #print(text_description)
                if text_description != None:
                    entrys = find_relevant_spacy(text_description)
                    #print(entrys)
                    for ent in entrys.ents:
                        
                        spacy_info = ent.text, ent.label_
                        print(spacy_info)
                        add_spacy(conn, ent.text, ent.label_, (j[1]))
                        print(ent.text, ent.label_, (j[1]))
        window['-SPACY_COLLECT-'].update(f"Done finding information")

    elif event == 'Find relevant info list':
        #spacy_working = ""
        times = 1
        for i in range(times):
            content_list = get_text_content(conn)
            #print(text_content)
            list_of_entrys, delete_list = find_relevant_spacy_list(content_list)
            #print("The length of list_of_entrys is", len(list_of_entrys))
            if len(delete_list) > 0:
                #print(delete_list)
                delete_entry_content(conn, delete_list)
            list_of_done = []
                #print("\n\n\n\n\nThis is j\n\n\n\n\n",j[1])
            if list_of_entrys != None:
                for j in list_of_entrys:
                    #print("j is", j, type(j))
                    for ent in j[0].ents:
                        if ent.text != "rules.emergingthreats.net":

                            #print("ent is", ent.text, ent.label_, (j[1]))
                            add_spacy(conn, ent.text, ent.label_, (j[1]))
                            #print(ent.text, ent.label_, (j[1]))
                    list_of_done.append(j[1])
                    #print(entrys)
            #print(len(list_of_entrys))
            #print(list_of_done)
        clean_spacy_list(conn)    
        clean_content_list(conn)
        
        print("done cleaning")
        window['-SPACY_COLLECT_LIST-'].update(f"number of docs evaluated was {len(content_list)*times}")

    elif event == 'Find relevant info list no json':
        #spacy_working = ""
        times = 1
        for i in range(times):
            for j in COLLECTIONS:
                #if j.name != 'vxvault' and j.name != 'hailataxii.guest.CyberCrime_Tracker' and j.name != 'hailataxii.guest.MalwareDomainList_Hostlist':
                if j.name != 'guest.dshield_BlockList' and j.name != 'guest.Abuse_ch':
                    #counter_getdata += 1
                    #print(f"Trying to connect to {j.name}")
                    collect_stix_info(conn, CLIENT, j.name, 500000)
                    #window['-COLLECT_VX-'].update('Data added 25, for each')
                for i in range(20):
                    content_list = get_text_content(conn)
                    #print(text_content)
                    list_of_entrys = find_relevant_spacy_stix(content_list)
                    #print("The length of list_of_entrys is", len(list_of_entrys))
                    #list_of_done = []
                        #print("\n\n\n\n\nThis is j\n\n\n\n\n",j[1])
                    if list_of_entrys != None:
                        for j in list_of_entrys:
                            #print("j is", j, type(j))
                            for ent in j[0].ents:
                                if ent.text != "rules.emergingthreats.net" and ent.label_ != "DATE":

                                    #print("ent is", ent.text, ent.label_, (j[1]))
                                    add_spacy(conn, ent.text, ent.label_, (j[1]))
                                    #print(ent.text, ent.label_, (j[1]))
                            #list_of_done.append(j[1])
                            #print(entrys)
                
                '''
                list_of_entrys, delete_list = find_relevant_spacy_list(content_list)
                #print("The length of list_of_entrys is", len(list_of_entrys))
                if len(delete_list) > 0:
                    #print(delete_list)
                    delete_entry_content(conn, delete_list)
                #list_of_done = []
                    #print("\n\n\n\n\nThis is j\n\n\n\n\n",j[1])
                if list_of_entrys != None:
                    for j in list_of_entrys:
                        #print("j is", j, type(j))
                        for ent in j[0].ents:
                            if ent.text != "rules.emergingthreats.net":

                                #print("ent is", ent.text, ent.label_, (j[1]))
                                add_spacy(conn, ent.text, ent.label_, (j[1]))
                                #print(ent.text, ent.label_, (j[1]))
                        #list_of_done.append(j[1])
                '''

                #print(len(list_of_entrys))
                #print(list_of_done)
                clean_spacy_list(conn)    
                clean_content_list(conn)
                
                print("done cleaning")
                for i in range(1000):
                    list_ipv4 = get_ipv4_spacy(conn, 'ipv4')
                    info_list = check_ipv4(list_ipv4)
                    add_shodan(conn, info_list)
                #insert_snort_info(conn)
                print("Done shodan")
                insert_snort_info(conn)
                #time.sleep(100)
        window['-SPACY_COLLECT_LIST_NJS-'].update(f"number of docs evaluated was {len(content_list)*times}")

    elif event == 'Print IPv4 list':
        print_string = ""
        important_list = get_all_label_spacy(conn, 'ipv4')
        for i in important_list:
            print_string += i + ", "
        print(print_string)
        window['-PRINT_IPV4-'].update(f"Printed in terminal")

    elif event == 'Print IPv4 shodan':
        for i in range(1):
            list_ipv4 = get_ipv4_spacy(conn, 'ipv4')
            info_list = check_ipv4(list_ipv4)
            add_shodan(conn, info_list)
        window['-PRINT_IPV4_SHODAN-'].update(f"Printed in terminal")

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

    elif event == 'Print URL list':
        print_string = ""
        important_list = get_all_label_spacy(conn, 'URL')
        for i in important_list:
            print_string += i + ", "
        print(print_string)
        window['-PRINT_URL-'].update(f"Printed in terminal")
    '''
    elif event == 'Find relevant info failed list':
        #spacy_working = ""
        
        content_list = get_text_content_failed(conn)
        #print(text_content)
        list_of_entrys = find_relevant_spacy_list_failed(content_list)
        
        if list_of_entrys != None:
            for j in list_of_entrys:
                print("\n\n\n This is the important information\n\n\n\n", j[0])
                #print("j is", j, type(j))
                try:

                    for ent in j[0].ents:
                        #print("ent is", ent, type(ent))
                        add_spacy(conn, ent.text, ent.label_, (j[1]))
                except:
                    continue
                 #print(entrys)
        window['-SPACY_COLLECT_LIST_FAILED-'].update(f"number of docs evaluated was {len(content_list)}")
    '''



    if not win2_active and event == 'Store vxvault new window':
        win2_active = True
        layout2 = [
            [sg.Button('Store vxvault data2'), sg.Text(key='-COLLECT_VX2-')],
        ]
        win2 = sg.Window('Window2', layout2)

    if win2_active:
        event2, value2 = win2.read(timeout=100)
        if event2 == sg.WIN_CLOSED:
            win2_active = False
            win2.close()
        if event2 == 'Store vxvault data2':
            vx_string = ""
            for i in range(3):
                
                #win2['-COLLECT_VX2-'].update('')
                collect_stix_info(conn, CLIENT, "vxvault", 20000)
                vx_string += "Data added 2000\n"
                win2['-COLLECT_VX2-'].update(vx_string)



window.close()
