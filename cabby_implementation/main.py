import asyncio
from cabby import create_client
from cabby.exceptions import HTTPError, ServiceNotFoundError, NoURIProvidedError, InvalidResponseError, ClientException
from taxii2client.v20 import Server, as_pages
from setup_db import get_total_content, add_content_list, get_highest_content, get_name_content
import json


async def auto_poll(conn):
    ACTIVE_FUNCTIONS = True
    clients = await asyncio.create_task(get_clients())
    print("Got all")
    while ACTIVE_FUNCTIONS == True:
        ACTIVE_FUNCTIONS = False
        print("Inside while loop")
        for i in clients:
            j = i
            for server in j[1]:
                print(server.name)
                await asyncio.create_task(collection_poll_auto(conn, j[0], server))

async def get_clients():
    
    clients = []
    try:
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
    except: # This has been set up to avoid error when server breake connection, does not seem like there is a error handling this.
        pass
     


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
    NUMBER_OF_MSGS = 200
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
            
                        
            if (tmp_cnt_msg) % 100 == 0:
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
    except: # This has been set up to avoid error when server breake connection, does not seem like there is a error handling this.
        pass
    

    print("Done with", collection.name)
    await asyncio.sleep(0.001)
    if len(list_of_ents) > 0:
        
        await asyncio.create_task(add_content_list(conn, list_of_ents))






async def poll_taxii2client(conn, collection):
    list_of_ents = []
    total_count = await asyncio.create_task(get_total_content(collection.title))
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
        await asyncio.create_task(add_content_list(conn, list_of_ents))
        
        list_of_ents = []
        print("Done adding files")
        await asyncio.sleep(0.001)


async def auto_poll_taxii2client():
    while True:
        server = Server("https://cti-taxii.mitre.org/taxii/")
        api_root = server.api_roots[0]
        collections = api_root.collections
        for i in collections:
            await asyncio.create_task(poll_taxii2client(i))
            await asyncio.sleep(100)
        await asyncio.sleep(1)