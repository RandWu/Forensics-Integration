import os
import csv
import sqlite3
import database as db
import utilities as util

# If you have any encoding error, change this value!!
__ENCODING = "cp950" # For CHT, BIG 5

# Accessible variables
# List of suspicious PID by count
suspiciousPID = list()
# List of suspicious Name by count
suspiciousName = list()
# List of abused ports by count
suspiciousPort = list()
# List of program that listening port
listeningProgram = list()
# Suspicious name by change log during specific seconds
suspiciousNameByChange = list()
# Program not in standard program area
nonStandardArea = list()
# keywords
cports_keywords_hits = str()
change_keywords_hits = str()

def network_main(cports_files: str, change_list_path: str, config: dict, conn: sqlite3.Connection, cursor: sqlite3.Cursor, keyword = None):
    '''
    Entry function of the network analysis, in order to mudulization.
    cports_files: The file path of the CurrPorts snapshot csv.
    change_list_path: The file path of the change log.
    config: The configuration
    conn, cursor: database related

    return: The parsed list of dict
    '''
    cports, changes = __network_parser(cports_files, change_list_path)
    __create_db(cports, changes, conn, cursor)
    __network_analysis(config, cports, changes)
    if keyword:
        global cports_keywords_hits
        cports_keywords_hits = util.keyword_search(cports, keyword)
        # print("kkk", type(util.keyword_search(cports, keyword)), "FUCK")
        global change_keywords_hits
        change_keywords_hits = util.keyword_search(changes, keyword)
    return cports, changes


def __network_parser(cports_files: str, change_list_path: str):
    '''
    This function reads data from CSV of cports, and its log change files
    cports_files: The connection state of one moment
    change_list: The connection changes during some seconds
    '''
    # Prepared for list of dict cports
    cports = dict()
    cports_list = list()
    # Check file exists
    if not os.path.isfile(cports_files):
        raise FileNotFoundError("The specific cports files not found")
    else:
        try:
            with open(cports_files, mode='r', newline="", encoding=__ENCODING) as csv_file:
                csv_reader = csv.reader(csv_file, delimiter=",")
                for row in csv_reader:
                    #Mapping to the dictionary and add to list
                    cports['processName'] = row[0]
                    cports['processID'] = row[1]
                    cports['protocol'] = row[2]
                    cports['localPort'] = row[3]
                    cports['localAddress'] = row[5]
                    cports['remotePort'] = row[6]
                    cports['remoteAddress'] = row[8]
                    cports['state'] = row[10]
                    cports['processPath'] = row[11]
                    # If path is like C:\Windows, consider it as System program.
                    if 'C:\\Windows\\'.lower() in cports['processPath'].lower():
                        cports['pathType'] = 'System folder'
                    elif 'Appdata'.lower() in cports['processPath'].lower():
                        cports['pathType'] = 'Temp folder'
                    elif 'C:\\Users'.lower() in cports['processPath'].lower():
                        cports['pathType'] = 'User folder'
                    elif 'C:\\Program Files'.lower() in cports['processPath'].lower():
                        cports['pathType'] = 'Program Files'
                    else:
                        # Some file path in Cports are only the process name.
                        cports['pathType'] = "OTHERS"

                    #cport[''] = row[]
                    #cport[''] = row[]
                    cports_list.append(cports.copy())
        except UnicodeDecodeError:
            print("An decoding problem... Please edit the encoding in network_analysis.py")
            exit(1000)

    # Change list parser
    change_list = list()
    # Check file exists
    if not os.path.isfile(change_list_path):
        change_list = [{'None':False}]
    else:
        try:
            with open(change_list_path, mode='r', newline="", encoding=__ENCODING) as csv_file:
                csv_reader = csv.reader(csv_file, delimiter=' ')
                tmp_dict = dict()
                for row in csv_reader:
                    tmp = list(filter(None, row))
                    tmp_dict['date'] = tmp[0] + ' ' + tmp[1] + ' ' + tmp[2]
                    tmp_dict['status'] = tmp[3]
                    tmp_dict['programName'] = tmp[4]
                    tmp_dict['protocol'] = tmp[5]
                    tmp_dict['source'] = tmp[6]
                    tmp_dict['destination'] = tmp[7]
                    change_list.append(tmp_dict.copy())
        except UnicodeDecodeError:
            pass
    return cports_list, change_list

def __create_db(cports: list, changes: list, conn: sqlite3.Connection, cursor: sqlite3.Cursor):
    '''
    This function writes data to sqlite
    cports, changes: result from parser
    conn, cursor: database related
    '''
    cursor.execute('DELETE FROM CPORTS')
    sqlStr = db.genBaseSqlStr(cports, 'CPORTS')
    for item in cports:
        values = (int(item['processID']), item['processName'], item['protocol'],
        item['localPort'], item['localAddress'], item['remotePort'],
        item['remoteAddress'], item['state'], item['processPath'],item['pathType'])
        db.insertTable(cursor, sqlStr, values)
    db.commit(conn)
    
    cursor.execute('DELETE FROM CPORTS_CHANGELIST')
    sqlStr = db.genBaseSqlStr(changes, 'CPORTS_CHANGELIST')
    for item in changes:
        values = (item['programName'], item['date'], item['status'], 
        item['protocol'], item['source'], item['destination'])
        db.insertTable(cursor, sqlStr, values)
    db.commit(conn)
    return 

def __network_analysis(config: dict, cports: list, changes: list):
    '''
    This function read configs and analyze the network logs
    config: configurations from config.yaml
    cports: result from parser
    changes: result from parser
    '''
    # Sorted by PID
    pIDCount = util.countToDict(util.sortDictOfList(cports, 'processID'), 'processID')
    # Sorted by name
    nameCount = util.countToDict(util.sortDictOfList(cports, 'processName'), 'processName')
    # Sorted by remote ports
    portsCount = util.countToDict(util.sortDictOfList(cports, 'remotePort'), 'remotePort')
    # Sorted by name
    logChangeCount = util.countToDict(util.sortDictOfList(changes, 'programName'), 'programName')

    # Detect single process who made lots of connection by PID
    for k in pIDCount:
        if pIDCount[k] >= config['Network']['MaxConnectionAsSuspicious']:
            # k is PID, we need to use that PID to search
            global suspiciousPID
            suspiciousPID = suspiciousPID + util.keyword_search(cports, k)
    # Detect single process who made lots of connection by name
    for k in nameCount:
        if nameCount[k] >= config['Network']['MaxConnectionAsSuspicious']:
            global suspiciousName
            suspiciousName = suspiciousName + util.keyword_search(cports, k)
    # Detect single ports connection
    for k in portsCount:
        if portsCount[k] >= config['Network']['MaxSameDestinationConnection'] and k != '':
            global suspiciousPort
            suspiciousPort = suspiciousPort + util.keyword_search(cports, k, 'remotePort')
    # Detect single process made large connection within specific seconds
    for k in logChangeCount:
        if logChangeCount[k] >= config['Network']['MaxChange']:
            global suspiciousNameByChange
            suspiciousNameByChange = suspiciousNameByChange + util.keyword_search(changes, k)
    # Detect program listening port
    for k in cports:
        # State is listening, and not connected to localhost.
        if k['state'] == 'Listening' and k['localPort'] != '' and k['remoteAddress'] not in ('0.0.0.0', '::'):
            listeningProgram.append(k)
    for k in cports:
        if k['pathType'] != 'System' and k['pathType'] != 'Program Files':
            nonStandardArea.append(k)

    return