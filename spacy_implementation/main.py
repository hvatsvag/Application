import asyncio
from setup_db import get_ipv4_spacy, get_text_content, add_spacy_list
from cabby_implementation.main import auto_poll
from spacy_implementation.spacy_prog import find_relevant_spacy_stix



async def async_spacy_auto(conn):
    ACTIVE_FUNCTIONS = True
    while ACTIVE_FUNCTIONS == True:
        
        content_list = await asyncio.create_task(get_text_content(conn))
        content_list2 = content_list[:(len(content_list) // 2)]
        print(len(content_list2), "is the length of the first list")
        content_list = content_list[(len(content_list) // 2):]
        print(len(content_list), "is the length of the second list")
        if len(content_list) == 0:
            list_ipv4 = await asyncio.create_task(get_ipv4_spacy(conn, 'ipv4'))
            
            if len(list_ipv4) == 0:
                await asyncio.create_task(auto_poll(conn))
            else:
                await asyncio.sleep(300)
            
            #await asyncio.sleep(1800)
        
        task_spacy_process = asyncio.create_task(spacy_processing(conn, content_list, content_list2))
        
        await task_spacy_process
        
        print("Done with Spacy")     

        await asyncio.sleep(1)


async def spacy_processing(conn, content_list, content_list2):
        found_info = False
        task = asyncio.create_task(find_relevant_spacy_stix(content_list))
        task2 = asyncio.create_task(find_relevant_spacy_stix(content_list2))
        list_of_entrys = await task
        list_of_entrys2 = await task2
        list_of_entrys = list_of_entrys + list_of_entrys2
        result_list = []
        number = 0
        if list_of_entrys != None:
            for j in list_of_entrys:
                number +=1
                found_info = False
                ipv4_content = {
                    'Port': {'type': "Port", 'content': {}},
                    'transport': {'type': "transport", 'content': {}},
                    'ipv4': {'type': "ipv4", 'content': {}}
                }
                for ent in j[0].ents:
                    if ent.label_ == "transport":
                        ipv4_content["transport"]["content"][ent.text] = ent.text
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
                                    found_info = True
                                except:
                                    pass
                    elif k[0] == "ipv4":
                        ipv4_content["ipv4"]["content"][k[1]] = k[1]
                        found_info = True
                if found_info != True:    
                    result_list.append([f"Document has been processed {number}", "Document has been processed", j[1]])
                for i in ipv4_content:
                    for n in ipv4_content[i]:
                        if n == "content":
                            for o in ipv4_content[i][n]:
                                result_list.append([o, i, j[1]])                
            await asyncio.create_task(add_spacy_list(conn, result_list))
        else:
            print("No info found")