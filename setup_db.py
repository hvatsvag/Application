from socket import timeout
import sqlite3
from sqlite3 import Error
from datetime import datetime
#from datetime import datetime
from cabby import exceptions as cabby_err
import json


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
        print(e)

    return conn

sql_create_source_table = """CREATE TABLE IF NOT EXISTS sources (
                                source_id INTeger PRIMARY KEY autoincrement,
                                name varchar(255) not null unique
                            );"""

def create_table(conn, create_table_sql):
    """ create a table from the create_table_sql statement
    :param conn: Connection object
    :param create_table_sql: a CREATE TABLE statement
    :return:
    """
    try:
        c = conn.cursor()
        c.execute(create_table_sql)
    except Error as e:
        print(e)
        
sql_create_content_table = """CREATE TABLE IF NOT EXISTS content (
                                content_id INTeger PRIMARY KEY autoincrement,
                                name varchar(255) not null unique,
                                content_text varchar not null,
                                source varchar(255) not null,
                                foreign key (source) references sources (name)
                            );"""

sql_create_content_failed_table = """CREATE TABLE IF NOT EXISTS content_failed (
                                cf_id INTeger PRIMARY KEY autoincrement,
                                name varchar(255) not null unique,
                                content_text varchar not null,
                                source varchar(255) not null,
                                foreign key (source) references sources (name)
                            );"""

sql_create_spacy_table = """CREATE TABLE IF NOT EXISTS spacy (
                                info_id INTeger PRIMARY KEY autoincrement,
                                info varchar(255) not null unique,
                                info_label varchar(255) not null,
                                content_id integen not null,
                                foreign key (content_id) references content (content_id)
                            );"""


sql_create_shodan_table = """CREATE TABLE IF NOT EXISTS shodan (
                                shodan_id INTeger PRIMARY KEY autoincrement,
                                info varchar(255) not null,
                                info_label varchar(255) not null,
                                spacy_id integen not null,
                                foreign key (spacy_id) references spacy (info_id)
                            );"""

sql_create_snort_table = """CREATE TABLE IF NOT EXISTS snort (
                                sid INTeger PRIMARY KEY autoincrement,
                                protocol varchar(255) not null,
                                ipv4_src varchar(255) not null,
                                port_src varchar(255) not null,
                                destination varchar(255) not null,
                                port varchar(255) not null,
                                msg varchar(255) not null,
                                content_id integer not null
                            );"""


def add_source(conn, name):
    """
    Add a new source into the source table
    :param conn:
    :param name:
    
    """

    sql = ''' INSERT INTO sources(name) VALUES(?) '''
    try:
        cur = conn.cursor()
        cur.execute(sql, (name,))
        conn.commit()
    except Error as e:
        print(e)
        
def add_content(conn, name, text, source):
    """
    Add a new source into the content table
    :param conn:
    :param name:
    :param text:
    :param source:
    
    """

    sql = ''' INSERT INTO content(name, content_text, source) VALUES(?, ?, ?) '''
    try:
        cur = conn.cursor()
        cur.execute(sql, (name, text, source))
        conn.commit()
    except Error as e:
        print(e)




def add_spacy(conn, info, info_label, content_id):
    """
    Add a new source into the spacy table
    :param conn:
    :param info:
    :param info_label:
    :param content_id:
    
    """

    sql = ''' INSERT INTO spacy(info, info_label, content_id) VALUES(?, ?, ?) '''
    try:
        cur = conn.cursor()
        cur.execute(sql, (info, info_label, content_id))
        conn.commit()
    except Error as e:
        print(e)


def add_shodan(conn, info_list):
    """
    Add a new source into the spacy table
    :param conn:
    :param list with structure [info, label, info_id] or [[info, [shodan_info]], label, info_id]:
    :param info_label:
    :param content_id:
    
    """

    cur = conn.cursor()
    for i in info_list:
        print(i)
        if i[0] != 'No info in shodan':
            for j in i[0][1]:
                print(j, i[1], i[2])
                try:
                    sql = ''' INSERT INTO shodan(info, info_label, spacy_id) VALUES(?, ?, ?) '''
                    cur.execute(sql, (j, i[1], i[2]))
                    
                except Error as e:
                    print(e)
        else:
            try:
                sql = ''' INSERT INTO shodan(info, info_label, spacy_id) VALUES(?, ?, ?) '''
                cur.execute(sql, (i[0], i[1], i[2]))
                    
            except Error as e:
                print(e)
    conn.commit()


def add_snort(conn, ipv4, msg, content_id, port_src="any", protocol="any", destination="any", port="any"):
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

    sql = ''' INSERT INTO snort(protocol, ipv4_src, port_src, destination, port, msg, content_id) VALUES(?,?,?,?,?,?,?) '''
    try:
        cur = conn.cursor()
        cur.execute(sql, (protocol, ipv4, port_src, destination, port, msg, content_id))
        cur.execute('select max(sid) from snort')
        conn.commit()
        for row in cur:
            (sid, ) = row
            if sid == None:
                sid = 0
            print(sid)
            return sid
    except Error as e:
        print(e)





def get_highest_content(conn, source):
    try:
        cur = conn.cursor()
        sql = 'select info from content where source=(?)'
        cur.execute(sql, (source,))
        for row in cur:
            (content_id,) = row
            return content_id
    except Error as e:
        print(e)

def get_ipv4_spacy(conn, label):
    
    
    try:
        test = None
        list_of_info = []
        cur = conn.cursor()
        test1 = cur.execute('select max(shodan_id) from shodan')
        for row in test1:
            (id, ) = row
            test = id
            print("test = ", test)
        sql = ""
        if test != None:
            sql = 'select info, info_id from spacy where info_label=(?) and info_id not in (select distinct(spacy_id) from shodan) and info_id > (select max(spacy_id) from shodan) limit 50'
        else:
            sql = 'select info, info_id from spacy where info_label=(?) limit 50'
        cur.execute(sql, (label,))
        for row in cur:
            (info, info_id) = row
            list_of_info.append([info, label, info_id])
        return list_of_info
    except Error as e:
        print(e)    

def get_all_label_spacy(conn, description):
    try:
        table_of_content = []
        cur = conn.cursor()
        sql = 'select info from spacy where info_label=(?)'
        cur.execute(sql, (description,))
        for row in cur:
            (info,) = row
            table_of_content.append(info)
        return table_of_content
    except Error as e:
        print(e)    
    
        
def get_text_content(conn):
    
    
    
    try:
        cur = conn.cursor()
        test = None
        test1 = cur.execute('select max(content_id) from spacy')
        for row in test1:
            (id, ) = row
            test = id
            print("test = ", test)
        sql = ""
        if test == None:
            sql = "select content_text, content_id from content WHERE content_id not in (select content_id from spacy) limit 10000000"
        else:
            sql = "select content_text, content_id from content WHERE content_id > (select max(content_id) from spacy) limit 10000000"
        
        #
        cur.execute(sql)
        content_list = []
        #print(len(cur))
        for row in cur:
            (content_text, content_id) = row
            content_list.append([content_text, content_id])
            #print(len(content_list))
        #print(len(content_list))
        return content_list
    except Error as e:
        print(e)


def get_text_content_failed(conn):
    
    
    
    try:
        cur = conn.cursor()
        #sql = 'select content_text from content where content_id=(?)'
        sql = 'select content_text, cf_id from content_failed'
        cur.execute(sql)#, (content_id,))
        content_list = []
        for row in cur:
            (content_text, content_id) = row
            content_list.append([content_text, content_id])
        return content_list
    except Error as e:
        print(e)
        

def get_name_content(conn, content_id):
    
    
    
    try:
        cur = conn.cursor()
        sql = 'select name from content where content_id=(?)'
        cur.execute(sql, (content_id,))
        for row in cur:
            (name,) = row
            return name
    except Error as e:
        print(e)        

def get_all_content(conn, content_id):
    
    
    
    try:
        cur = conn.cursor()
        sql = 'select * from content where content_id=(?)'
        cur.execute(sql, (content_id,))
        for row in cur:
            (content_id, name, content_text, source) = row
            print("This is the content of the entry", name, content_text, source)
            return name, content_text, source
        conn.commit()
    except Error as e:
        print(e)        
        
def collect_stix_info_first_time(conn, client, source_name, NUMBER):
    try:
        content_blocks = client.poll(collection_name=source_name)
        NUMBER_OF_MSGS = NUMBER
        tmp_cnt_msg = 0
        for block in content_blocks:
            cnt = block.content
            print(f"getting block {tmp_cnt_msg + 1}")
            add_content(conn, str(block.timestamp), cnt, source_name)
            tmp_cnt_msg += 1
            if tmp_cnt_msg >= NUMBER_OF_MSGS:
                break
    except Exception as e:
        print(e)
        pass
    except:
        pass
        
def collect_stix_info(conn, client, source_name, NUMBER):
    try:
        #
        # content_blocks = None
        #cnts = []
        highest_id = get_highest_content(conn, source_name)

        if source_name == "vxvault" or source_name == "hailataxii.guest.CyberCrime_Tracker" or source_name == "hailataxii.guest.MalwareDomainList_Hostlist" or source_name == "hailataxii.guest.Abuse_ch":
            return

        #print(f"the highest id is {highest_id} and the source_name is {source_name}")

        newest_date = get_name_content(conn, highest_id)
        print(f"newest date is {newest_date} and the source_name is {source_name}")

        
        content_blocks = client.poll(collection_name=source_name)#, begin_date=newest_date)

        NUMBER_OF_MSGS = NUMBER
        tmp_cnt_msg = 0
        list_of_ents = []
        for block in content_blocks:
            cnt = block.content
            #cnts.append([cnt, str(block.timestamp)])
            print(f"getting block {tmp_cnt_msg + 1} {source_name} with timestamp {block.timestamp}")
            list_of_ents.append([str(block.timestamp), cnt, source_name])
            #add_content(conn, str(block.timestamp), cnt, source_name)


            tmp_cnt_msg += 1
            if tmp_cnt_msg >= NUMBER_OF_MSGS:
                #print(f"Got {tmp_cnt_msg} files from {source_name}")
                break
        #for ecnt in cnts:
        #    add_content(conn, ecnt[1], ecnt[0], source_name)
        for i in list_of_ents:
            add_content(conn, i[0], i[1], i[2])
    except:
        print("Failed because of some reason")
        pass
    '''
    except cabby_err.HTTPError(502) as e:
        print(e)
        pass

    except Exception as argument:
        print('This is the argument', argument)
        pass
    '''

def delete_entry_content(conn, content_id_list):
    cur = conn.cursor()
    for i in content_id_list:
        print("This is i", i)
        try:
            name, content_text, source = get_all_content(conn, i[1])
            sql1 = ''' INSERT INTO content_failed(name, content_text, source) VALUES(?, ?, ?) '''
            cur.execute(sql1, (name, content_text, source))
            sql = 'delete from content where content_id=(?)'
            cur.execute(sql, (i,))
            conn.commit()
        except Error as e:
            print(e)   
         

def clean_content_list(conn):
    cur = conn.cursor()
    try:
        cur.execute('delete from content where content_id not in (select distinct(content_id) from spacy)')
        #cur.execute(sql1, (name, content_text, source))
        #sql = 'delete from content where content_id=(?)'
        #cur.execute(sql, (i,))
        conn.commit()
    except Error as e:
        print(e)        

def clean_spacy_list(conn):
    cur = conn.cursor()
    try:
        cur.execute('delete from spacy where content_id not in (select distinct(content_id) from spacy where info_label=("URL") or info_label=("ipv4"))')
        #cur.execute(sql1, (name, content_text, source))
        #sql = 'delete from content where content_id=(?)'
        #cur.execute(sql, (i,))
        conn.commit()
    except Error as e:
        print(e)        


        
def setup():
    conn = create_connection(database)
    if conn is not None:
        create_table(conn, sql_create_source_table)
        create_table(conn, sql_create_content_table)
        create_table(conn, sql_create_spacy_table)
        create_table(conn, sql_create_content_failed_table)
        create_table(conn, sql_create_shodan_table)
        create_table(conn, sql_create_snort_table)
        conn.close()


if __name__ == '__main__':
    # If executed as main, this will create tables and insert initial data
    setup()