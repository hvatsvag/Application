from aiosqlite import Error
from datetime import datetime
import asyncio
import aiosqlite



database = r"./database.db"

# Creates a connection to the database. If the database do not exist, it creates the database with tables and indexes
async def create_connection_async(db_file):

    """ create a database connection to the SQLite database
        specified by db_file
    :param db_file: database file
    :return: Connection object or None
    """
    conn = None
    from os.path import isfile
    if not isfile(db_file):
        try:
            conn = await aiosqlite.connect(db_file, uri=True)
        except Error as e:
            print(e)
        await asyncio.create_task(setup_tables(conn))
    
    else:
        try:
            conn = await aiosqlite.connect(db_file, uri=True)
            
            return conn
        except Error as e:
            print(e)
            

    return conn


# Used to create tables in the sqlite3 database
async def create_table(conn, create_table_sql):
    """ create a table from the create_table_sql statement
    :param conn: Connection object
    :param create_table_sql: a CREATE TABLE statement
    :return:
    """
    try:
        async with conn.cursor() as c:
            await c.execute(create_table_sql)
            await c.close()
        #await cursor
        #c = conn.cursor()
        #c.execute(create_table_sql)
    except Error as e:
        print(e)
        
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



# Uset to set up indexes that increase query speed.
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
        
        print(e)
        pass

        

# used to insert STIX files into the content table. Used in the cabby_implementation/main.py in the function collection_poll_auto that collect STIX files.
async def add_content_list(conn, content_list):
    """
    Add a new source into the content table
    :param conn:
    :param name:
    :param text:
    :param source:
    
    """

    sql = ''' INSERT INTO content(name, content_text, source) VALUES(?, ?, ?) '''
    try:
        
        async with conn.cursor() as c:
            await c.executemany(sql, [(x[0], x[1], x[2]) for x in content_list])
            await c.execute('commit')
    except Error as e:
        print(e)
        pass



# Used to insert a list of information into the spacy table from the spacy_processing function in spacy_implementation/main.py
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
        
        print(e)
        pass
    

# This function is used to add content into the shodan table from the function async_shodan in shodan_implementation/main.py
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
    except Error as e:
        #conn.commit()     
        print(e, e.args[0])
        pass
     
    
# This function is used to add content to the snort table. Activated by snort_entry_creation in snort_implementation/main.py
async def add_multiple_snort(conn, list_snort):
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
            await c.close()
    except Error as e:
        print(e, "add_multiple_snort", e.args[0])
        pass

# Used to collect info used for compressed snort rules. Used bu function insert_snort_rules in snort_implementation/main.py
async def collect_compressed_snort_info(conn):
    info_content = {}
    try:
        async with conn.cursor() as c:
            await c.execute('select protocol, ipv4_src, port_src from snort')
            rows = await c.fetchall()
            for row in rows:
                (protocol, ipv4src, port_src) = row
                if port_src not in info_content:
                    info_content[port_src] = {
                        "Ports": port_src,
                        "ipv4src": {}
                    }
                if ipv4src not in info_content[port_src]["ipv4src"]:
                    info_content[port_src]["ipv4src"][ipv4src] = {"ipv4src": ipv4src, "protocols": {}}
                if protocol not in info_content[port_src]["ipv4src"][ipv4src]["protocols"]:
                    info_content[port_src]["ipv4src"][ipv4src]["protocols"][protocol] = protocol
            await c.close()
    except Error as e:
        print(e)
        pass
    return info_content

        
        



# This function returns the highest content id for a source in the content table. Returns 0 if there are no entries for the source.
# This number is used in the collection_poll_auto function in cabby_implementation/main.py
async def get_highest_content(conn, source):
    sql = 'select max(content_id) from content where source=(?)'
    try:
        async with conn.cursor() as c:
            await c.execute(sql, (source,))
            row = await c.fetchone()
            print(row)
            if 0 in row:
                await c.close()
                return 0
            (content_id_stix,) = row
            content_id = content_id_stix

            await c.close()
            return content_id

    except Error as e:
        print(e)
        pass

# This function returns the highest content id for a source in the content table. Returns None if there are no entries for the source.
# This number is used in the collection_poll_auto function in cabby_implementation/main.py
async def get_total_content(conn, source):
    sql = 'select count(*) from content where source=(?)'
    try:
        async with conn.cursor() as c:
            await c.execute(sql, (source,))
            row = await c.fetchone()
            (count_total,) = row
            count = count_total
            await c.close()
            return count
    except Error as e:
        print(e)
        pass

# This function is used to collect IPv4 addresses that shal be used in the spacy implementation. Used in the function async_shodan.
# Also used in async_spacy_auto in spacy_implementation, if it return 0 and no STIX files are ready to be processed, it initiate new download/poll.
async def get_ipv4_spacy(conn, label):
    try:
        list_of_info = []
        test1 = None
        async with conn.cursor() as c:

            await c.execute('select max(shodan_id) from shodan')
            test1 = await c.fetchone()
        sql = ""
        if None in test1:
            sql = 'select info, info_id from spacy where info_label=(?) group by info limit 30'
        else:
            sql = 'select info, info_id from spacy where info_label=(?) and info not in (select distinct(info_spacy) from shodan) group by info limit 30'
        async with conn.cursor() as c:
            await c.execute(sql, (label,))
            rows = await c.fetchall()
            for row in rows:
                (info, info_id) = row
                list_of_info.append([info, label, info_id])
        return list_of_info
    except Error as e:
        print(e)
        pass    

# This function is used in scappy_package_simulation in scapy_implementation/main.py, and is used for deciding max when picking snort entries whith randint.
async def get_snort_count(conn):
    try:
        async with conn.cursor() as c:
            await c.execute('select count(*) from snort')
            row = await c.fetchone()
            (this_count,) = row
            count = this_count
            await c.close()
            return count
    except Error as e:
        print(e)
        pass

# This function is used in scappy_package_simulation in scapy_implementation/main.py, and is used collect infor for creating packages.
async def snort_return_values(conn, id_list):
    values = []
    try:
        result_sign = ','.join('?' for i in range(len(id_list)))
        sql = f'select protocol, ipv4_src, port_src from snort where sid in ({result_sign})'
        async with conn.cursor() as c:
            await c.execute(sql, id_list)
            rows = await c.fetchall()
            for row in rows:
                (protocol, ipv4_src, port_src) = row
                print(protocol, ipv4_src, port_src)
                if port_src == "any":
                    port_src = [80, 443]
                values.append([protocol, ipv4_src, port_src])
            await c.close()
        #print(values)
        return values
    except Error as e:
        print(e)
        pass


# This function is used to colelct STIX files to use in async_spacy_auto in spacy_implementation/main.py
#  The function first check if there is any entries in the spacy table, to decide which query to use.      
async def get_text_content(conn):
    content_list = []
    try:
        test1 = None
        async with conn.cursor() as c:

            await c.execute('select max(content_id) from spacy')
            test1 = await c.fetchone()
        sql = ""
        if None in test1:
            sql = 'select content_text, content_id from content'
        else:
            sql = "select content_text, content_id from content WHERE content_id > (select max(content_id) from spacy)"
        
        sql = sql + " limit 4000"
        print(sql)

        async with conn.cursor() as c:
            await c.execute(sql)
            rows = await c.fetchall()
            
            if None in rows:
                return content_list
            for row in rows:
                (content_text, content_id) = row
                content_list.append([content_text, content_id])

        return content_list
    except Error as e:
        print(e)
        pass


# This is a series of queries used to sequentially collect info about the program, which is displayed in the GUI (app.py).
async def get_status_info(conn):
    tables = ["content", "spacy", "shodan", "snort"]
    results = []
    for i in tables:
        try:
            sql = f"select count(*) from {i}"
            async with conn.cursor() as c:
                await c.execute(sql)
                row = await c.fetchone()
                (count, ) = row  
                results.append(f"{i} has {count} entryes in it's table")
                await c.close()
        except Error as e:
            print(e)
            pass
    try:
        sql = "select count(*) from content WHERE content_id not in (select content_id from spacy)"
        async with conn.cursor() as c:
            await c.execute(sql)
            row = await c.fetchone()
            (count, ) = row  
            results.append(f"The amount of files left to process is {count}")
            await c.close()
    except Error as e:
        print(e)
        pass
    try:
        sql = "select count(distinct(info)) from spacy where info_label=('ipv4') and info not in (select distinct(info_spacy) from shodan)"
        async with conn.cursor() as c:
            await c.execute(sql)
            row = await c.fetchone()
            (count, ) = row  
            results.append(f"The amount of IPv4 addresses left to search is {count}")
            await c.close()
    except Error as e:
        print(e)
        pass
    #print(results)
    return results

# This function has been initiated manually to collect infor used in the report.
async def extract_results(list_servers):
    conn = await asyncio.create_task(create_connection_async(database))
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




# This function is used to collect the date and time for a specified STIX file in the content table. Used in collection_poll_auto function in cabby_implementation/main.py
async def get_name_content(conn, content_id):
    sql = 'select name from content where content_id=(?)'
    try:
        async with conn.cursor() as c:
            await c.execute(sql, (content_id,))
            row = await c.fetchone()
            (this_name,) = row
            name = this_name
            await c.close()
            return name
    except Error as e:
        print(e, e.args[0])
        pass     



   
# Used to reset the snort table. This is sequentially done to make sure that info from all STIX files are used when inserting into the snort table
async def reset_snort_table(conn):
    

    try:
        async with conn.cursor() as c:
            await c.execute('drop table snort')
            await c.execute('commit')
    except Error as e:
        print(e)
        pass
    await asyncio.create_task(create_table(conn, sql_create_snort_table))
    
# This function returns a list of IPv4 addresses that have got data when searched for in shodan.io, unless the data contain
# HTTP/1.1 301 Moved Permanently or HTTP/1.1 302 Moved or already is in the snort table. 
# This is used when desiding what IPv4 addresses to create rules for snort. used by async_snort function in snort_implementation/main.py
async def collect_ipv4_for_snort(conn):
    try:
        sql = ""
        result = "" 
        async with conn.cursor() as c:
            await c.execute('select max(sid) from snort')
            row = await c.fetchone()
            if None in row:
                sql = 'select distinct(info) from spacy where info in (select distinct(info_spacy) from shodan where info in ("found data") and shodan_id not in (select shodan_id from shodan where additional_info like "%HTTP/1.1 301 Moved Permanently%" or additional_info like "%HTTP/1.1 302 Moved%" ) )'
            else:
                sql =' select distinct(info) from spacy where info in (select distinct(info_spacy) from shodan where info in ("found data") and info_spacy not in (select ipv4_src from snort) and shodan_id not in (select shodan_id from shodan where additional_info like "%HTTP/1.1 301 Moved Permanently%" or additional_info like "%HTTP/1.1 302 Moved%"  ))'
            await c.close()
        print("Searching for IPv4 addresses", datetime.now())
        result = []
        async with conn.cursor() as c:
            await c.execute(sql)
            rows = await c.fetchall()
            for row in rows:
                (info, ) = row
                result.append(info)
        return result
    except Error as e:
        print(e)
        pass

# This function creates to dicts that is used by snort_entry_creation in snort_implementation/main.py do create rules with as spesiffic information as possible.
async def collect_snort_info(conn, ipv4_list):
    

    ip_dict = {}
    content_id_dict = {}
    
    result_sign = ','.join('?' for i in range(len(ipv4_list)))
    print("IPv4 addresses extracted", datetime.now(), "\n And ready to find relevant info")
    sql = (f'select content_id, info, info_label from spacy where content_id in (select distinct(content_id) from spacy where info in ({result_sign}))')
    try:    
        async with conn.cursor() as c:
            await c.execute(sql, ipv4_list)
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
                        if info in ipv4_list:
                            ip_dict[info] = {'content_id': {}, 'ipv4': info}
                        else:
                            continue
                    ip_dict[info]['content_id'][content_id] = content_id
            await c.close()
        #await cursor.close()
        print("Info added to dictionarys", datetime.now())
        return ip_dict, content_id_dict
        
    except Error as e:
        print(e)
        pass    


# Function used to set up the database manually, if running setup_db manually        
async def setup():
    conn = await asyncio.create_task(create_connection_async(database))
    await asyncio.create_task(setup_tables(conn))
    await conn.close()

# Function to set up all tables needed in the database, as well as indexes needed.     
async def setup_tables(conn):
    if conn is not None:
        await asyncio.create_task(create_table(conn, sql_create_content_table))
        await asyncio.create_task(create_table(conn, sql_create_spacy_table))
        await asyncio.create_task(create_table(conn, sql_create_shodan_table))
        await asyncio.create_task(create_table(conn, sql_create_snort_table))
        await asyncio.create_task(add_indexes(conn))
        '''
        await asyncio.create_task(extract_results(["vxvault", "user_AlienVault", "guest.CyberCrime_Tracker", "guest.EmergineThreats_rules", "guest.EmergingThreats_rules", \
            "guest.MalwareDomainList_Hostlist", "guest.Abuse_ch", "guest.Lehigh_edu", "guest.blutmagie_de_torExits", "guest.dataForLast_7daysOnly", \
            "guest.phishtank_com", "system.Default"]))
        '''  
        #await conn.close()


if __name__ == '__main__':
    # If executed as main, this will create tables and insert initial data
    asyncio.run(setup())