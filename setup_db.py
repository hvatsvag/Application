from socket import timeout
import sqlite3
from aiosqlite import Error
from datetime import datetime
#from datetime import datetime
from cabby import exceptions as cabby_err
import json
from shodan_program import insert_snort
import asyncio
import aiosqlite



database = r"./database.db"

def create_connection(db_file):
    """ create a database connection to the SQLite database
        specified by db_file
    :param db_file: database file
    :return: Connection object or None
    """
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except Error as e:
        print(e, e.args[0])

    return conn

async def create_connection_async(db_file):
    """ create a database connection to the SQLite database
        specified by db_file
    :param db_file: database file
    :return: Connection object or None
    """
    conn = None
    try:
        conn = await aiosqlite.connect(db_file)
        
        return conn
    except Error as e:
        print(e, e.args[0])
        

    return conn



async def create_table(conn, create_table_sql):
    """ create a table from the create_table_sql statement
    :param conn: Connection object
    :param create_table_sql: a CREATE TABLE statement
    :return:
    """
    try:
        await conn.execute(create_table_sql)
        #await cursor
        #c = conn.cursor()
        #c.execute(create_table_sql)
    except Error as e:
        print(e, e.args[0])
        
sql_create_content_table = """CREATE TABLE IF NOT EXISTS content (
                                content_id INTeger PRIMARY KEY autoincrement,
                                name varchar(255) not null,
                                content_text varchar not null,
                                source varchar(255) not null
                            );"""



sql_create_spacy_table = """CREATE TABLE IF NOT EXISTS spacy (
                                info_id INTeger PRIMARY KEY autoincrement,
                                info varchar(255) not null,
                                info_label varchar(255) not null,
                                content_id integer not null,
                                foreign key (content_id) references content (content_id)
                            );"""




sql_create_shodan_table = """CREATE TABLE IF NOT EXISTS shodan (
                                shodan_id INTeger PRIMARY KEY autoincrement,
                                info varchar(255) not null,
                                additional_info varchar(255),
                                info_label varchar(255) not null,
                                info_spacy varchar(255) not null,
                                spacy_id integer not null,
                                foreign key (spacy_id) references spacy (info_id)
                            );"""

sql_create_snort_table = """CREATE TABLE IF NOT EXISTS snort (
                                sid INTeger PRIMARY KEY autoincrement,
                                protocol varchar(255) not null,
                                ipv4_src varchar(255) not null,
                                port_src varchar(255) not null,
                                msg varchar(255) not null,
                                content_id integer not null
                            );"""




async def add_indexes(conn):
    '''
    :param conn:
    
    '''
    list_of_index_sqls = [
        "CREATE INDEX IF NOT EXISTS 'InfoId_infoLabel' ON 'spacy' ('info_label', 'info')",
        "CREATE INDEX IF NOT EXISTS 'contentId_cource' ON 'content' ('content_id', 'source')",
        "CREATE INDEX IF NOT EXISTS 'infoSpacy_info' ON 'shodan' ('info_spacy', 'info')",
        "CREATE INDEX IF NOT EXISTS 'ipv4' ON 'snort' ('ipv4_src')"
    ]

    try:
        
        async with conn.cursor() as c:
            for i in list_of_index_sqls:
                await c.execute(i)
            await c.execute('commit')
    except Error as e:
        
        print(e, e.args[0])
        pass

        
async def add_content(conn, name, text, source):
    """
    Add a new source into the content table
    :param conn:
    :param name:
    :param text:
    :param source:
    
    """

    sql = ''' INSERT INTO content(name, content_text, source) VALUES(?, ?, ?) '''
    #cur = conn.cursor()
    try:
        
        await conn.execute(sql, (name, text, source))
        await conn.commit()
    except Error as e:
        
        print(e, e.args[0])
        pass

async def add_content_list(conn, content_list):
    """
    Add a new source into the content table
    :param conn:
    :param name:
    :param text:
    :param source:
    
    """

    sql = ''' INSERT INTO content(name, content_text, source) VALUES(?, ?, ?) '''
    #cur = conn.cursor()
    try:
        
        async with conn.cursor() as c:
            await c.executemany(sql, [(x[0], x[1], x[2]) for x in content_list])
            await c.execute('commit')
    except Error as e:
        
        print(e, e.args[0])
        pass


async def add_spacy(conn, info, info_label, content_id):
    """
    Add a new source into the spacy table
    :param conn:
    :param info:
    :param info_label:
    
    :param content_id:
    
    """

    sql = ''' INSERT INTO spacy(info, info_label, content_id) VALUES(?, ?, ?) '''
    #cur = conn.cursor()
    try:
        
        await conn.execute(sql, (info, info_label, content_id))
        await conn.commit()
    except Error as e:
        
        print(e, e.args[0])
        pass

async def add_spacy_list(conn, list_spacy):
    """
    Add a new source into the spacy table
    :param conn:
    :param info:
    :param info_label:
    
    :param content_id:
    
    """
    #print(list_spacy)
    sql = ''' INSERT INTO spacy(info, info_label, content_id) VALUES(?, ?, ?) '''
    try:
        async with conn.cursor() as c:
            await c.executemany(sql, [(x[0], x[1], x[2]) for x in list_spacy])
            await c.execute('COMMIT')
    except Error as e:
        
        print(e, "add_spacy_list", e.args[0])
        pass
    '''
    for i in list_spacy:
        [info, info_label, content_id] = i
        try:
        
            await conn.execute(sql, (info, info_label, content_id))
        
        except Error as e:
        
            print(e)
            pass
    await conn.commit()
    '''

async def add_shodan(conn, info_list):
    """
    Add a new source into the spacy table
    :param conn:
    :param list with structure [info, label, info_id] or [[info, [shodan_info], info_spacy], label, info_id]:
    :param info_label:
    :param content_id:
    
    """
    sql = ' INSERT INTO shodan(info, additional_info, info_label, info_spacy, spacy_id) VALUES(?, ?, ?, ?, ?) '
    #cur = conn.cursor()
    try:
        async with conn.cursor() as c:
            await c.executemany(sql, [(i[0][0], i[0][1], i[1], i[0][2], i[2]) for i in info_list])
            await c.execute('commit')
        '''
        for i in info_list:
        #print("I is", i)
        #print(i)
        #if i[0] != 'No info in shodan':
            for j in i:
            #print("j is",j)
                if j[0][2] == "":
                    continue
                sql = ' INSERT INTO shodan(info, additional_info, info_label, info_spacy, spacy_id) VALUES(?, ?, ?, ?, ?) '
                await conn.execute(sql, (j[0][0], j[0][1], j[1], j[0][2], j[2]))
                #print(type(j[0][1]), "This is the type inserted")  
        await conn.commit()  
        '''                        
    except Error as e:
        #conn.commit()     
        print(e, e.args[0])
        pass
        '''
        Tryed to fix this
        else:
            try:
                sql = ' INSERT INTO shodan(info, info_label, spacy_id) VALUES(?, ?, ?) '
                cur.execute(sql, (i[0], i[1], i[2]))
                    
            except Error as e:
                print(e)
        '''        
    


async def add_snort(conn, ipv4, msg, content_id, port_src="any", protocol="any"):
    #print(f"ipv4=", {ipv4}, "msg:", {msg}, "content_id:", {content_id}, "port_src:", {port_src}, "protocol:", {protocol}, "destination:", {destination}, "port:", {port})
    """
    Add a new source into the source table
    
    param:  protocol
    param:  ipv4_src
    param:  port_src
    param:  destination
    param:  port
    param:  msg
    param:  content_id

    
    """

    sql = ''' INSERT INTO snort(protocol, ipv4_src, port_src, msg, content_id) VALUES(?,?,?,?,?) '''
    #cur = conn.cursor()
    
    try:
        if ipv4 != "" and content_id != "":
            await conn.execute(sql, (protocol, ipv4, port_src, msg, content_id))
            cursor = await conn.execute('select sid from snort where sid=(select max(sid) from snort)')
            cur = await cursor.fetchone()

            info = {
                    "sid": "1000000",
                    "protocol": protocol,
                    "ipv4_src": ipv4,
                    "port_src": port_src,
                    "msg": msg
                }
            #print(info)
            for row in cur:
                (sid, ) = row
                info["sid"] = str(int(info["sid"]) + sid)
            #print(info)
            
            insert_snort(info)
            #info["sid"] = str(int(info["sid"]) + 1)
            await conn.commit()
    except Error as e:
        
        print(e, e.args[0])
        pass

async def add_multiple_snort(conn, list_snort):
    #print(f"ipv4=", {ipv4}, "msg:", {msg}, "content_id:", {content_id}, "port_src:", {port_src}, "protocol:", {protocol}, "destination:", {destination}, "port:", {port})
    """
    Add multiple new source into the source table, each element contain:
    
    param:  protocol
    param:  ipv4_src
    param:  port_src
    param:  destination
    param:  port
    param:  msg
    param:  content_id

    
    """

    sql = ''' INSERT INTO snort(protocol, ipv4_src, port_src, msg, content_id) VALUES(?,?,?,?,?) '''

    try:
        async with conn.cursor() as c:
            await c.executemany(sql, [(i[4], i[0], i[3], i[1], i[2]) for i in list_snort])
            await c.execute('COMMIT')
    except Error as e:
        
        print(e, "add_multiple_snort", e.args[0])
        pass
    cursor = await conn.execute('select sid from snort where sid=(select max(sid) from snort)')
    row = await cursor.fetchone()
    (sid, ) = row
    this_sid = 1000000 + sid
    await conn.commit()
    #cur = conn.cursor()
    info_list = []
    for i in list_snort:
        if i[0] != "" and i[2] != "":
            info = {
                    "sid": this_sid,
                    "protocol": i[4],
                    "ipv4_src": i[0],
                    "port_src": i[3],
                    "msg": i[1]
            }

            info_list.append(info)
            this_sid -= 1
       
    await insert_snort(info_list)
                #info["sid"] = str(int(info["sid"]) + 1)
        
        




async def get_highest_content(conn, source):
    try:
        #cur = conn.cursor()
        sql = 'select max(content_id) from content where source=(?)'
        cursor = await conn.execute(sql, (source,))
        row = await cursor.fetchone()
        print(row)
        if 0 in row:
            await cursor.close()
            return 0
        (content_id_stix,) = row
        content_id = content_id_stix
        #for row in rows:
        #    (content_id_stix,) = row
        #    content_id = content_id_stix
        await cursor.close()
        return content_id

    except Error as e:
        print(e, e.args[0])
        pass

async def get_total_content(conn, source):
    try:
        #cur = conn.cursor()
        sql = 'select count(*) from content where source=(?)'
        cursor = await conn.execute(sql, (source,))
        row = await cursor.fetchone()
        #count = None
        #if 0 in rows:
        #    return 0
        (count_total,) = row
        count = count_total
        #print("count is", count)
        #for row in rows:
        #    (this_count,) = row
        #    count = this_count
        await cursor.close()
        return count
    except Error as e:
        print(e, e.args[0])
        pass

async def get_all_ipv4_spacy(conn, label):
    try:
        
        list_of_info = []
        #cur = conn.cursor()
        cursor = await conn.execute('select max(shodan_id) from shodan')
        test1 = await cursor.fetchone()
        (result,) = test1
        test = result
        await cursor.close()
        sql = ""
        if test != None:
            sql = 'select info, max(info_id) from spacy where info_label=(?) and info not in (select distinct(info_spacy) from shodan) group by info'
        else:
            sql = 'select info, max(info_id) from spacy where info_label=(?) group by info'
        cursor = await conn.execute(sql, (label,))
        rows = await cursor.fetchall()
        for row in rows:
            (info, info_id) = row
            list_of_info.append([info, label, info_id])
        await cursor.close()
        return list_of_info
    except Error as e:
        print(e, e.args[0])
        pass    

async def get_ipv4_spacy(conn, label):
    
    
    try:
        
        list_of_info = []
        #cur = conn.cursor()
        test1 = None
        async with conn.cursor() as c:

            await c.execute('select max(shodan_id) from shodan')
            test1 = await c.fetchone()
        
        sql = ""
        if None in test1:
            sql = 'select info, info_id from spacy where info_label=(?) limit 100'
        else:
            sql = 'select info, info_id from spacy where info_label=(?) and info not in (select distinct(info_spacy) from shodan) group by info limit 100'
        
        #await cursor.close()
        
        async with conn.cursor() as c:
            
            await c.execute(sql, (label,))
            rows = await c.fetchall()
            for row in rows:
                (info, info_id) = row
                list_of_info.append([info, label, info_id])
        #await cursor.close()
        #if list_of_info
        return list_of_info
    except Error as e:
        print(e, e.args[0])
        pass    

async def get_snort_count(conn):
    try:
        #cur = conn.cursor()
        cursor = await conn.execute('select count(*) from snort')
        row = await cursor.fetchone()
        (this_count,) = row
        count = this_count
        await cursor.close()
        return count
    except Error as e:
        print(e, e.args[0])
        pass

async def snort_return_values(conn, id_list):
    values = []
    try:
        #cur = conn.cursor()
        #print(id_list)
        result_sign = ','.join('?' for i in range(len(id_list)))
        sql = f'select protocol, ipv4_src, port_src from snort where sid in ({result_sign})'
        cursor = await conn.execute(sql, id_list)
        rows = await cursor.fetchall()
        for row in rows:
            (protocol, ipv4_src, port_src) = row
            print(protocol, ipv4_src, port_src)
            if port_src == "any":
                port_src = [80, 443]
            values.append([protocol, ipv4_src, port_src])
        await cursor.close()
        #print(values)
        return values
    except Error as e:
        print(e, e.args[0])
        pass

async def get_all_label_spacy(conn, description):
    try:
        table_of_content = []
        #cur = conn.cursor()
        sql = 'select info from spacy where info_label=(?)'
        cursor = await conn.execute(sql, (description,))
        rows = await cursor.fetchall()
        for row in rows:
            (info,) = row
            table_of_content.append(info)
        await cursor.close()    
        return table_of_content
    except Error as e:
        print(e, e.args[0])
        pass

async def fix_port(conn):
    id_list = []
    rows = None
    async with conn.cursor() as c:
        await c.execute("select info_id, info from spacy where info_label='transport'")
        rows = await c.fetchall()
    for row in rows:
        (info_id, info) = row
        try:
            test_num = int(info)
            id_list.append(info_id)
        except:
            pass
    result_sign = ','.join('?' for i in range(len(id_list)))
    sql = f"update spacy set info_label='Port' where info_id in ({result_sign})"
    async with conn.cursor() as c:
        await c.execute(sql, id_list)
        await c.execute('commit')

        
async def get_text_content(conn):
    
    
    
    try:
        #cur = conn.cursor()
        
        sql = "select content_text, content_id from content WHERE content_id > (select max(content_id) from spacy)"
        
        sql = sql + " limit 4000"
        print(sql)
            
        
        #
        async with conn.cursor() as c:
            await c.execute(sql)
            rows = await c.fetchall()
            content_list = []
            #print(len(cur))
            if None in rows:
                return content_list
            for row in rows:
                (content_text, content_id) = row
                content_list.append([content_text, content_id])
            #print(len(content_list))
        #print(len(content_list))
        #await cursor.close()
        return content_list
    except Error as e:
        print(e, e.args[0])
        pass

async def get_status_info(conn):
    tables = ["content", "spacy", "shodan", "snort"]
    #cur = conn.cursor()
    
    results = []
    for i in tables:
        try:
            sql = f"select count(*) from {i}"
            async with conn.cursor() as c:
                await c.execute(sql)
                row = await c.fetchone()
            #print(row)
                (count, ) = row  
                results.append(f"{i} has {count} entryes in it's table")
            #await cursor.close()
        except Error as e:
            print(e, e.args[0])
            pass
    try:
        sql = "select count(*) from content WHERE content_id not in (select content_id from spacy)"
        async with conn.cursor() as c:
            await c.execute(sql)
            row = await c.fetchone()
            (count, ) = row  
            results.append(f"The amount of files left to process is {count}")
        #await cursor.close()
    except Error as e:
        print(e, e.args[0])
        pass
    try:
        sql = "select count(distinct(info)) from spacy where info_label=('ipv4') and info not in (select distinct(info_spacy) from shodan)"
        async with conn.cursor() as c:
            await c.execute(sql)
            row = await c.fetchone()
            (count, ) = row  
            results.append(f"The amount of IPv4 addresses left to search is {count}")
            #await cursor.close()
    except Error as e:
        print(e, e.args[0])
        pass
    #print(results)
    return results

async def extract_results(conn, list_servers):
    #cur = conn.cursor()
    list_sql = [
        ["select count(content_id) from content where source=(?)", "The amount of files stored in"],
        ["select count(DISTINCT(content_id)) from content where content_id in (select content_id from spacy where info in (select info_spacy from shodan where info='found data')) and source=(?)", "STIX files containing active IPv4 addresses"],
        ["select count(distinct(info)) from spacy where content_id in (select content_id from content where source=(?)) and info_label='ipv4'", "Total IPv4 addresses found"],
        ["select count(distinct(content_id)) from spacy where content_id in (select content_id from content where source=(?)) and info_label='Port'", "Total STIX files where PORTs are found"],
        ["select count(distinct(content_id)) from spacy where content_id in (select content_id from content where source=(?)) and info_label='transport'", "Total STIX files where transport protocols are found"],
        ["select count(distinct(info)) from spacy where content_id in (select content_id from content where source=(?)) and info_label='ipv4' and info in (select info_spacy from shodan where info='found data')", "Active IPv4 affresses found"]
        

    ]
    for i in list_servers:
        print(i)
        for j in list_sql:
            try:
                sql = j[0]
                cursor = await conn.execute(sql, (i,))
                row = await cursor.fetchone()
                (count, ) = row
                
                    
                print(j[1], i, count)
                await cursor.close()
            except Error as e:
                print(e, e.args[0])
                pass
        print()





async def get_name_content(conn, content_id):
    
    
    
    try:
        #cur = conn.cursor()
        sql = 'select name from content where content_id=(?)'
        cursor = await conn.execute(sql, (content_id,))
        row = await cursor.fetchone()
        (this_name,) = row
        name = this_name
        
        await cursor.close()
        return name
    except Error as e:
        print(e, e.args[0])
        pass     

async def get_all_content(conn, content_id):
    
    
    
    try:
        #cur = conn.cursor()
        sql = 'select * from content where content_id=(?)'
        cursor = await conn.execute(sql, (content_id,))
        rows = await cursor.fetchone()
        content = None
        for row in rows:
            (content_id, name, content_text, source) = row
            #print("This is the content of the entry", name, content_text, source)
            content = [name, content_text, source]
        await cursor.close()
        return content[0], content[1], content[2]
        
    except Error as e:
        print(e, e.args[0])
        pass
        

        
async def collect_stix_info(conn, client, source_name, NUMBER):
    try:
        #
        # content_blocks = None
        #cnts = []
        highest_id = await asyncio.create_task(get_highest_content(conn, source_name))

        #if source_name == "vxvault" or source_name == "hailataxii.guest.CyberCrime_Tracker" or source_name == "hailataxii.guest.MalwareDomainList_Hostlist" or source_name == "hailataxii.guest.Abuse_ch":
        #    return

        #print(f"the highest id is {highest_id} and the source_name is {source_name}")

        newest_date = await asyncio.create_task(get_name_content(conn, highest_id))
        print(f"newest date is {newest_date} and the source_name is {source_name}. The id is {highest_id}")

        
        content_blocks = client.poll(collection_name=source_name)#, begin_date=newest_date)
        if source_name == "user_AlienVault" or source_name == "vxvault":
            content_blocks = client.poll(collection_name=source_name, begin_date=newest_date)

        NUMBER_OF_MSGS = NUMBER
        tmp_cnt_msg = 0
        list_of_ents = []
        for block in content_blocks:
            cnt = block.content
            #cnts.append([cnt, str(block.timestamp)])
            if (tmp_cnt_msg + 1) % 1000 == 0:
                print(f"getting block {tmp_cnt_msg + 1} {source_name} with timestamp {block.timestamp}")
            list_of_ents.append([str(block.timestamp), cnt, source_name])
            #add_content(conn, str(block.timestamp), cnt, source_name)


            tmp_cnt_msg += 1
            if tmp_cnt_msg % 1000 == 0:
                for i in list_of_ents:
                    task = await asyncio.create_task(add_content(conn, i[0], i[1], i[2]))
                list_of_ents = []
                await asyncio.sleep(1)
            if tmp_cnt_msg >= NUMBER_OF_MSGS:
                print(f"Got {tmp_cnt_msg} files from {source_name}")
                #for i in list_of_ents:
                #    add_content(conn, i[0], i[1], i[2])
                break
        if tmp_cnt_msg % 1000 == 0:
            for i in list_of_ents:
                task = await asyncio.create_task(add_content(conn, i[0], i[1], i[2]))
        #for ecnt in cnts:
        #    add_content(conn, ecnt[1], ecnt[0], source_name)
        #for i in list_of_ents:
            
    except Error as e:
        print(e, e.args[0])
        pass



         

   

   

async def reset_snort_table(conn):
    #cur = conn.cursor()

    try:
        await conn.execute('drop table snort')
        await conn.commit()
    except Error as e:
        print(e, e.args[0])
        pass
    await asyncio.create_task(create_table(conn, sql_create_snort_table))
    


async def insert_snort_info(conn):
    #cur = conn.cursor()
    # First, fint the amount of IPv4 addresses that need to be put into the snort table
    #print(conn)
    try:
        sql = ""
        result = "" 
        async with conn.cursor() as c:
            await c.execute('select max(sid) from snort')
            rows = await c.fetchone()
        #print(rows)
            if None in rows:
                sql = ' select distinct(info) from spacy where info in (select distinct(info_spacy) from shodan where info in ("found data") )'
            else:
                sql =' select distinct(info) from spacy where info in (select distinct(info_spacy) from shodan where info in ("found data") and info_spacy not in (select ipv4_src from snort) )'
        #await cursor.close()
        print("Searching for IPv4 addresses", datetime.now())
        
            
        result = []
        async with conn.cursor() as c:
            await c.execute(sql)
            rows = await c.fetchall()
        #print("Search for IPv4 addresses queried", datetime.now())
            msg = ""
        #ports_list = "["
            ip_dict = {}
            content_id_dict = {}
            snort_list = []


            for row in rows:
                (info, ) = row
                result.append(info)
        #await cursor.close()
        result_sign = ','.join('?' for i in range(len(result)))
        #result = str(result)
        #result = result.replace("[", "")
        #result = result.replace("]", "")
        print("IPv4 addresses extracted", datetime.now(), "\n And ready to find relevant info")
        sql = (f'select content_id, info, info_label from spacy where content_id in (select distinct(content_id) from spacy where info in ({result_sign}))')
        
        async with conn.cursor() as c:
            await c.execute(sql, result)
            rows = await c.fetchall()
            for row in rows:
                (content_id, info, info_label) = row
                if content_id not in content_id_dict:
                    content_id_dict[content_id] = {"Port": {}, "transport": {}}
                if info_label == "Port":
                    content_id_dict[content_id]["Port"][info] = info
                elif info_label == "transport":
                    content_id_dict[content_id]["transport"][info] = info
                elif info_label == "ipv4":
                    
                    if info not in ip_dict:
                        if info in result:
                            ip_dict[info] = {'content_id': {}, 'ipv4': info}
                        else:
                            continue
                    ip_dict[info]['content_id'][content_id] = content_id
        #await cursor.close()
        print("Info added to dictionarys", datetime.now())
        count = 0
        for i in ip_dict:
            count += 1
            info = {
                'ipv4': None,
                'transport': {},
                'Port': {},
                'content_id': ""
            }
            info["ipv4"] = ip_dict[i]['ipv4']
            for i in ip_dict[i]['content_id']:
                info["content_id"] += f"{i},"
                for j in content_id_dict[i]["Port"]:
                    info["Port"][j] = j
                for k in content_id_dict[i]["transport"]:
                    info["transport"][k] = k
                transport = []
                ports_list = "["
                for j in info["transport"]:
                    transport.append(j)
                if len(transport) == 0:
                    transport = ["tcp", "udp", "ip"]
                for k in info["Port"]:
                    ports_list += f"{info['Port'][k]},"
                ports_list = ports_list.strip(",")
                ports_list += "]"
                if ports_list == "[]":
                    ports_list = "any"
            msg = f"Alert, this ip {info['ipv4']} has been found malicios"#, se STIX files {info['content_id']}"
            if len(msg) > 2040:
                msg = msg[:2040]
            for l in transport:
                snort_list.append([info["ipv4"], msg, info["content_id"], ports_list, l])
            if count % 1000 == 0:
                print(count, "documents has been added to snort list processing")
                await asyncio.create_task(add_multiple_snort(conn, snort_list))
                snort_list = [] 
        
        if len(snort_list) > 0:
            await asyncio.create_task(add_multiple_snort(conn, snort_list))
    except Error as e:
        print(e, e.args[0])
        pass    

    


        
async def setup():
    conn = await asyncio.create_task(create_connection_async(database))
    if conn is not None:
        #reset_snort_table(conn)
        await asyncio.create_task(insert_snort_info(conn))
        #await asyncio.create_task(fix_port(conn))
        
        await asyncio.create_task(create_table(conn, sql_create_content_table))
        await asyncio.create_task(create_table(conn, sql_create_spacy_table))
        #create_table(conn, sql_create_content_failed_table)
        await asyncio.create_task(create_table(conn, sql_create_shodan_table))
        await asyncio.create_task(create_table(conn, sql_create_snort_table))
        
        await asyncio.create_task(add_indexes(conn))
        
        
        await asyncio.create_task(extract_results(conn, ["vxvault", "user_AlienVault", "guest.CyberCrime_Tracker", "guest.EmergineThreats_rules", "guest.EmergingThreats_rules", \
            "guest.MalwareDomainList_Hostlist", "guest.Abuse_ch", "guest.Lehigh_edu", "guest.blutmagie_de_torExits", "guest.dataForLast_7daysOnly", \
            "guest.phishtank_com", "system.Default"]))
            
        await conn.close()


if __name__ == '__main__':
    # If executed as main, this will create tables and insert initial data
    asyncio.run(setup())