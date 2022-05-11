
import PySimpleGUI as sg

from setup_db import create_connection_async, get_status_info


import datetime
from datetime import datetime, timedelta
import asyncio


from snort_implementation.main import *
from scapy_implementation.main import *
from cabby_implementation.main import *
from spacy_implementation.main import *
from shodan_implementation.main import *


 
ACTIVE_TIME = None

database = r"./database.db"

conn = None

async def main_program():

    layout = [
        [sg.Button('Reset Snort'), sg.Text(key='-TRY_SNORT-')],
        [sg.Button('Scapy run'), sg.Text(key='-SCAPY_RUN-')],
        [sg.Text(key='-STATUS-', size=[30, 20])]
    ]

    conn = await create_connection_async(database)

    await asyncio.create_task(reset_snort(conn))
    SHODONTIME = datetime.now()
    print(SHODONTIME, "This is SHODON_TIME")
    window = sg.Window('The program', layout)
    ACTIVE_TIME = datetime.now()
    print(ACTIVE_TIME)
    asyncio.create_task(async_snort(conn))
    asyncio.create_task(async_shodan(conn))
    asyncio.create_task(async_spacy_auto(conn))
    info_string = ""
    while True:
        
        event, value = window.read(timeout=100)
        if event == sg.WIN_CLOSED:
            break
        elif event == 'Reset Snort':
            snort_task_run = asyncio.create_task(reset_snort())
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
            
            ipv4_list = await asyncio.create_task(scappy_package_simulation(conn))
            string_output = ""
            for i in ipv4_list:
                string_output += i + "\n"
            window['-SCAPY_RUN-'].update(string_output)
        await asyncio.sleep(0.001)

    window.close()




if __name__ == "__main__":
    
    asyncio.run(main_program())
    