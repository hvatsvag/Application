import shodan
import datetime
from datetime import datetime
import json



api = shodan.Shodan('PUT YOUR KEY IN HERE')

async def shodan_search(ipv4):
    #time_now = datetime.now()
    #result = api.search(ipv4)
    #print("Time for response is", datetime.now() - time_now)
    return api.host(ipv4)

async def check_ipv4(entry):#, filter_type):
    info_list = []
    try_list = "["
    count_list = 0
    return_error = None
    before_search = datetime.now()
    if entry != None:
        

        try:
                #print(i)
            j = [["", None, ""], entry[1], entry[2]]
                #print(i[0])
                #loop = asyncio.get_running_loop
                # Search Shodan
                #time_search = datetime.now()
                #results = await asyncio.create_task(shodan_search(i[0]))
                #results = await task
                #print(f"{api.search(i[0])}")
                #results = await  api.search(i[0])
                #results = api.search(i[0])
                #results2 = await asyncio.wait(api.search(i[0]), return_when=asyncio.ALL_COMPLETED)
                #print("Before shodan search", datetime.now(), i[0])
                #while datetime.now() < before_search +  timedelta(seconds=1):
                #    print("Sleeping")
                #    await asyncio.sleep(0.1)
                
            results = await shodan_search(entry[0])
            before_search = datetime.now()
            print("The shodan search did take", (datetime.now() - before_search), "And the time is", datetime.now())
                #print(results)
                #print(results2)
            
            if results != None:
                additional_info = ""
                j[0][0] = "found data"
                    
                        
                j[0][1] = json.dumps(results)
                        
                j[0][2] = entry[0]
                        
                entry = j
            else:
                j[0][0] = "No info in shodan"
                j[0][2] = entry[0]
            
            
                #while datetime.now() < time_search + timedelta(seconds=1):
                #    await asyncio.sleep(0.1)
                #    print("Sleeping")
            entry = j
            
            
        #except shodan.APIError as e:
        #    print('Error: {}'.format(e))
        #    print("the IP that caused the problem was", i[0])
        except Exception as e:
            print("Somthing wrong", e, entry[0], (datetime.now() - before_search))
            if str(e) == "Unable to connect to Shodan" or str(e) == "Request rate limit reached (1 request/ second). Please wait a second before trying again and slow down your API calls.":
                print(e)
                return None
            entry = [["An error occured: " + str(e), None, entry[0]], entry[1], entry[2]]
            
                #print([i])
            return entry
                #info_list.append(i)
                #pass   
            
            #print(try_list)
    #print("List after search is", list)    
    return entry