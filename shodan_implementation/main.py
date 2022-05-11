import datetime
from datetime import datetime, timedelta
import asyncio
from setup_db import get_ipv4_spacy, add_shodan
from shodan_implementation.search_shodan import check_ipv4




async def async_shodan(conn):
    time_search = datetime.now()
    spacy_list = 10
    ACTIVE_FUNCTIONS = True
    while spacy_list != 0:
        while ACTIVE_FUNCTIONS == False:
            print("sleeping")
            await asyncio.sleep(60)
            print("Done Sleeping, shodan")
            ACTIVE_FUNCTIONS = True
        list_ipv4 = await asyncio.create_task(get_ipv4_spacy(conn, 'ipv4'))
        print("Shodan ok")
        result_list = []
        for i in list_ipv4:
            while datetime.now() < time_search +  timedelta(seconds=0.6):
                await asyncio.sleep(0.01)
            task_showdan = asyncio.create_task(check_ipv4(i))
            j = await task_showdan
            time_search = datetime.now()
            if j != None:
                result_list.append(j)
            else:
                continue
        await asyncio.create_task(add_shodan(conn, result_list))
        spacy_list = len(list_ipv4)
        if spacy_list == 0 or spacy_list == None:
            print("Setting Active to false")
            ACTIVE_FUNCTIONS = False
            spacy_list = 1

