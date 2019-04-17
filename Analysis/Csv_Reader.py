# ------------------------------------------------------------------------------------------------------------------- #
# --------------------------------------- Import -------------------------------------------------------------------- #
import yaml
import xml
import csv
import errno, os, sys
import requests
import sqlite3
import signal
from Xml2dict import XmlDictConfig
from time import sleep
# --------------------------------------- End of Import --------------------------------------------------------------#

# --------------------------------------- Variables ----------------------------------------------------------------- #
# Signal handling
original_sigInt = signal.getsignal(signal.SIGINT) # original sigint handler
# Database related
conn = None #connector
cursor = None 
# Config file variables
config = dict() # Configuration as global
VIRUSTOTAL_API_KEY = '' #API keys
# For cports use
cports_begin = list() # Global cports report, begin
cports_end = list() # Global cports report, end
cports_change = list() # Global change list
suspiciousPID = list()
suspiciousName = list()
suspiciousAbusePort = list() # The ports lots of connection used
suspiciousNameByChange = list() #By change list
listening_type = False 
# For registry
registry = list() # All registry
autorunProgram = list()
registryNoCompany = list()
registryAppInit = list()
registryHijacks = list()
# For process 
procmonXML = None # procmon result by reading XML format
proccsv = None # procmon result by reading csv format
running_md5 = None # the md5 of running process
a_process_list = None # The current process run in victim machine
processMaxThreadName = list()
processMaxChildName = list()
processCallCmd = list()
processTreeList = list()
processRunInTemp = list()
processRunInUserFolder = list()
parentProblem = False
# For logs
logs = None # All log type

# --------------------------------------- End of Variables ---------------------------------------------------------- #

# --------------------------------------- Pre-processing function --------------------------------------------------- #
def handler(sig, frame):
    '''
    This function handle SIGINT, which is keyboard Interrupt known as Ctrl+C
    Internal use only
    '''
    print("接收到鍵盤中斷，請問您要做什麼？")
    print("1. 終止現在的工作，回到主選單")
    print("2. 終止本程式")
    print("3. 取消")
    # Return original sigint handler
    signal.signal(signal.SIGINT, original_sigInt)
    while True:
        try:
            n = str(input("請輸入您的選擇： "))
            if n == '1':
                main(conn, cursor)
            elif n == '2':
                die()
            elif n == '3':
                break
            else:
                print("請輸入正確選項。")
                sleep(3)
        except KeyboardInterrupt:
            print("\n請不要激動好嗎？")
    signal.signal(signal.SIGINT, handler)

def read_yaml(file_path: str)->dict:
    '''
    This function read Configuation Files
    Must be YAML format
    '''
    if not os.path.isfile(file_path):
        return [{'error':'No such file'}]
    with open(file_path, mode='r', newline="") as yml_file:
        config = yaml.load(yml_file)
    return config


def cport_reader(file_path: str)->list:
    '''
    This function read csv and store into Dictionary
    receive: String of valid path
    return : list of dictionary of the connection state
    '''
    #Variable
    cport = dict()
    cport_list = list()
    if not os.path.isfile(file_path):
        return [{'error':'No such file'}]
    with open(file_path, mode='r', newline="", encoding="cp950") as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=",")
        for row in csv_reader:
            #Mapping to the dictionary and add to list
            cport['processName'] = row[0]
            cport['processID'] = row[1]
            cport['protocol'] = row[2]
            cport['localPort'] = row[3]
            cport['localAddress'] = row[5]
            cport['remotePort'] = row[6]
            cport['remoteAddress'] = row[8]
            cport['state'] = row[10]
            cport['processPath'] = row[11]
            if 'C:\\Windows\\'.lower() in cport['processPath'].lower():
                cport['pathType'] = 'System'
            elif 'Appdata'.lower() in cport['processPath'].lower():
                cport['pathType'] = 'UserTemp'
            elif 'C:\\Users'.lower() in cport['processPath'].lower():
                cport['pathType'] = 'User'
            elif 'C:\\Program Files'.lower() in cport['processPath'].lower():
                cport['pathType'] = 'Installed'
            else:
                cport['pathType'] = cport['processPath']

            #cport[''] = row[]
            #cport[''] = row[]
            cport_list.append(cport.copy())
    return cport_list

def autoruns_reader(file_path: str)->list:
    '''
    This function will read csv and load into Dictionary
    receive: string of the valid path name
    return : list of dictionary of autoruns or None when failed
    '''
    registry_list = list()
    if not os.path.isfile(file_path):
        return [{'error':'No such file'}]
    #The autoruns output is utf16...
    with open(file_path, mode='r', newline="", encoding='utf16') as csv_file:
        csv_reader = csv.DictReader(csv_file, fieldnames=None, restkey='undefined')
        for row in csv_reader:
            registry_list.append(row.copy())
    return registry_list

def cport_change_list(file_path: str)->list:
    '''
    This function will read the log file and store into dictionary
    receive: string of the valid path name
    return : list of dictionary
    '''
    change_list = list()
    if not os.path.isfile(file_path):
        return [{'error':'No such file'}]
    with open(file_path, mode='r', newline="", encoding='cp950') as csv_file:
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
    return change_list

def flow_list(file_path: str)->list:
    '''
    This function will read the output of wireshark into dictionary
    receive: string of valid path name
    return : list of dictionary
    '''
    aList = list()
    if not os.path.isfile(file_path):
        return [{'error':'No such file'}]
    with open(file_path, mode='r', newline="") as csv_file:
        tmp_dict = dict()
        csv_reader = csv.reader(csv_file, delimiter=' ')
        for row in csv_reader:
            tmp = list(filter(None, row))
            tmp_dict['sequence'] = tmp[0]
            tmp_dict['timestamp'] = tmp[1]
            tmp_dict['soruceIPorMAC'] = tmp[2]
            tmp_dict['destinationIP'] = tmp[4]
            tmp_dict['protocol'] = tmp[5]
            tmp_dict['size'] = tmp[6]
            tmp_dict['other'] = tmp[7:]
            aList.append(tmp_dict.copy())
    return aList

def process_list(file_path: str, cmd_path: str)->list:
    '''
    This function will read the wmic output into dictionary
    receive: string of valid path name
    return : list of dictionary
    '''
    a_process_list = list()
    if not os.path.isfile(file_path):
        return [{'error':'No such file'}]
    #wmic output is utf16? I can't believe it...
    with open(file_path, mode='r', newline="", encoding='cp950') as csv_file:
        namespace = ('Name','ProcessId', 'ParentProcessId', 'Path')
        csv_reader = csv.DictReader(
            csv_file, fieldnames=namespace, restkey='CommandLine', delimiter=',')
        for row in csv_reader:
            a_process_list.append(row.copy())

    return a_process_list
# Process Monitor
def process_reader(file_path: str)->dict:
    '''
    Read the process monitor, the format must be CSV
    receive: string of valid path
    return : list of dictionary
    '''
    aDict = list()
    if not os.path.isfile(file_path):
        return [{'error':'No such file'}]
    with open(file_path, mode='r', newline="", encoding= 'UTF-8') as csv_file:
        namespace = ('Time of Day', 'Process Name', 'PID', 'Operation', 'Path', 'Result', 'Detail', 'Image Path')
        csv_reader = csv.DictReader(csv_file, fieldnames=namespace, restkey='undefined', delimiter=',')
        next(csv_reader)
        for row in csv_reader:
            aDict.append(row.copy())
        return aDict
                
def process_xml_reader(file_path: str)->dict:
    '''
    Read process monitor in XML format
    receive: string of valid path
    return : list of dictionary
    '''
    # aList = list()
    if not os.path.isfile(file_path):
        return [{'error':'No such file'}]
    tree = xml.etree.ElementTree.parse(file_path)
    root= tree.getroot()
    xml2Dict = XmlDictConfig(root)
    return xml2Dict

def read_log(file_path: str)->list:
    '''
    Read Windows Event Log, only Security part read, and must be CSV format
    receive: string of valid path
    return : list of dictionary
    '''
    aDict = list()
    if not os.path.isfile(file_path):
        return [{'error':'No such file'}]
    with open(file_path, mode='r', newline="", encoding='cp950') as csv_file:
        # namespace = ('EventLog', 'RecordNumber', 'TimeGenerated', 'TimeWritten', 'EventID', 'EventType', 'EventTypeName', 'EventCategory', 'EventCategoryName',)
        csv_reader = csv.DictReader(csv_file, fieldnames=None, restkey='Undefined')
        for row in csv_reader:
            if row['EventID'] != None:
                aDict.append(row.copy())
        return aDict

def read_md5_list(file_path: str, program_path:str)->list:
    '''
    Read MD5 from CertUtil output
    file_path: The CertUtil result
    Program_Path: The WMIC output that collected running process executable path
    return: list of {path:md5} dict
    '''
    running_md5 = list()
    md5 = list()
    paths = list()
    # All running program path
    with open(program_path, mode='r', newline="", encoding='cp950') as aFile:
        paths = aFile.readlines()
        paths = [x.strip() for x in paths]
    # CertUtil result
    with open(file_path, mode='r', newline="", encoding='cp950') as aFile:
        for line in aFile:
            # If no such file error occur
            if 'CertUtil:' in line and '0x80070002' in line:
                md5.append('No such file')
                try:
                    # Skip the 'CertUtil: Fail'
                    next(aFile)
                # If end of file
                except StopIteration:
                    break
            # Skip first line in one pattern of the output format, 'MD5 of %path%:'
            elif 'MD5' in line:
                pass               
            # Get MD5, which is second line in a pattern
            elif len(str(line).strip()) == 32: 
                md5.append(str(line).strip())
                try:
                    # Skip the third pattern, 'CertUtil: Dump finished successfully'
                    next(aFile)
                # if end of file
                except StopIteration:
                    break
            # If something should't happen happened...
            else:
                raise ValueError('Unexpected value found')
    # MD5 is gotten by paths in collection part, which must be the same value
    if len(paths) != len(md5):
        raise ValueError('Data may be corruption')
    counter = 0
    for item in paths:
        running_md5.append({'path':item, 'md5':md5[counter]})
        counter += 1
    # Remove duplicate dict in list 
    running_md5 = [dict(t) for t in set([tuple(d.items()) for d in running_md5])]
    return running_md5
    

# Just a print test
def readDict(dictionary_list: list, keyName = None):
    '''
    Print dict
    dictionary_list: List of dictionary
    keyName: Default prints all values of dict, or specific value only
    '''
    for item in dictionary_list:
        if keyName is None: 
            for k in item.keys():
                print(k, ' : ', item[k])
            print('')
        else:
            print(item[keyName])

def __sortDict(aList: list, keyName)->list:
    '''
    Sort list of dict by key
    aList: List if dict
    keyName: Key to sort
    return: Sorted list of dict
    '''
    return sorted(aList, key=lambda k: k[keyName])

# Function to count    
def __countToDict(sortedList: list, keyName)->dict:
    '''
    Count the same value in list of dict by keyName
    aList: List if dict
    keyName: Key to sort
    return: The count
    '''
    count = dict()
    tmp = None
    for item in sortedList:
        if item[keyName] != tmp:
            tmp = item[keyName]
            count[str(tmp)] = 1
        else:
            count[str(tmp)] += 1
    return count

# Function to find the index

def __findIndex(aList : list, key, value):
    '''
    Find the first index of the exact key and value
    aList: list of dict
    key: Key name to query
    value: wanted value
    return: The index of exact key value, -1 if no one matched
    '''
    index = 0
    for i in aList:
        if i[key] == value:
            return index
        index += 1
    return -1

# --------------------------------------- End of pre-processing function -------------------------------------------- #
# --------------------------------------- Connect to Sqlite --------------------------------------------------------- #
# This function creat all tables
def dbInit(cursor: sqlite3.Cursor):
    '''
    Creat database sql texts
    '''
    # Create Cports table
    createSqlStr = "CREATE TABLE CPORTS \
    (ProcessID INT NOT NULL, \
    ProcessName TEXT NOT NULL, \
    Protocol TEXT, \
    LocalPort TEXT, \
    LocalAddress TEXT, \
    RemotePort TEXT, \
    RemoteAddress TEXT,\
    State TEXT, \
    ProcessPath TEXT,\
    PathType TEXT);"
    createTable(cursor, createSqlStr)

    # Create Cports change table
    createSqlStr = "CREATE TABLE CPORTS_CHANGELIST \
    (ProcessName TEXT NOT NULL, \
    Date TEXT, \
    Status TEXT, \
    Protocol TEXT, \
    Source TEXT, \
    Destination TEXT);"
    createTable(cursor, createSqlStr)

    # Create process monitor table
    createSqlStr = "CREATE TABLE PROCMON_BEHAVIOR \
    (ProcessID INT NOT NULL, \
    ProcessName TEXT NOT NULL, \
    Date TEXT, \
    Operation TEXT, \
    Path TEXT, \
    Result TEXT, \
    Detail TEXT, \
    ImagePath TEXT);"
    createTable(cursor, createSqlStr)

    # Create autoruns table
    createSqlStr = "CREATE TABLE REGISTRY \
    (Entry TEXT NOT NULL, \
    EntryLocation TEXT NOT NULL, \
    Time TEXT, \
    LaunchString TEXT, \
    Company TEXT, \
    Description TEXT, \
    Category TEXT,\
    MD5 TEXT, \
    PESHA1 TEXT);"
    createTable(cursor, createSqlStr)

    # Create log table
    createSqlStr = "CREATE TABLE LOG \
    (EventID INT NOT NULL, \
    TimeWritten TEXT, \
    EventType INT, \
    EventTypeName TEXT,\
    EventCategory INT, \
    String TEXT, \
    Message TEXT);"
    createTable(cursor, createSqlStr)

# Connect to offline sqlite
def connect(databaseName: str): 
    '''
    Connect to sqlite
    databaseName: The path of database
    return: Connector and Cursor object of that database
    '''
    conn = sqlite3.connect(databaseName)
    cursor = conn.cursor()
    return conn, cursor

# Dynamic generate insert sql base
def genBaseSqlStr(data: list, tableName:str):
    '''
    Generate base sql string programmatically
    data: a list of dict
    tableName: Table name
    return: The base SQL string
    '''
    sqlStr = "INSERT INTO {} VALUES (".format(tableName)
    length = len(data[0])
    for k in range(length):
        if k == length - 1:
            sqlStr += "?)"
        else:
            sqlStr += "?,"
    return sqlStr

def createTable(cursor: sqlite3.Cursor, sqlStr: str):
    cursor.execute(sqlStr)

def insertTable(cursor: sqlite3.Cursor, sqlStr: str, values: tuple):
    cursor.execute(sqlStr,values)

def selectTable(cursor: sqlite3.Cursor, sqlStr: str):
    cursor.execute(sqlStr)

def commitAndClose(conn: sqlite3.Connection):
    conn.commit()
    conn.close()
# --------------------------------------- End of connecting to sqlite ----------------------------------------------- #
# --------------------------------------- Analyzing Cports Result --------------------------------------------------- #
# Begin to analyze network
def analyzeNetwork(cports_begin: list, cports_end: list, change_log: list):
    report= ''
    # Sorted by ProcessID
    pIDCount = __countToDict(__sortDict(cports_begin, 'processID'), 'processID')
    # Sorted by ProcessName
    nameCount = __countToDict(__sortDict(cports_begin, 'processName'), 'processName')
    # Sorted by RemotePorts
    portsCount = __countToDict(__sortDict(cports_begin, 'remotePort'), 'remotePort')
    # Log change
    logChangeCount = __countToDict(__sortDict(change_log, 'programName'), 'programName')

    # Detect single process who made lots of connection by PID
    for k in pIDCount:
        if pIDCount[k] >= config['Network']['MaxConnectionAsSuspicious']:
            report += 'PID 【{}】 is suspicious because it created {} connection.\n'.format(k, pIDCount[k])
            suspiciousPID.append(k)
    # Detect single process who made lots of connection by name
    for k in nameCount:
        if nameCount[k] >= config['Network']['MaxConnectionAsSuspicious']:
            report += 'Name 【{}】 is suspicious because it created {} connection.\n'.format(k, nameCount[k])
            suspiciousName.append(k)
    # Detect single ports connection
    for k in portsCount:
        if portsCount[k] >= config['Network']['MaxSameDestinationConnection'] and k != '':
            report += 'Port 【{}】 may be abused for Dos because there are {} connection through this port.\n'.format(k, portsCount[k])
            suspiciousAbusePort.append(k)
    # Detect single process made large connectio within specific seconds
    for k in logChangeCount:
        if logChangeCount[k] >= config['Network']['MaxChange']:
            report += 'Name 【{}】 may be suspicious because it create/end connection {} times.\n'.format(k,logChangeCount[k])
            suspiciousNameByChange.append(k)
    # Detect program listening port
    for k in cports_begin:
        if k['state'] == 'Listening' and k['localPort'] != '' and k['remoteAddress'] not in ('0.0.0.0', '::'):
            global listening_type
            listening_type = True
            report += 'Program 【{}】 is listening port 【{}】, and the remote address is 【{}】\n'.format(k['ProcessID'], k['localPort'], k['remoteAddress'])
            suspiciousPID.append(k['processID'])
    for k in cports_begin: 
        if k['pathType'] == 'User' or k['pathType'] == 'UserTemp':
            # global listening_type
            listening_type = True
            report += 'program 【{}】 is at 【{}】 diretory trying to make connection to 【{}】, which is suspicious\n'.format(k['processName'], k['pathType'], k['remoteAddress'])
    return report

def analyzeProcess(procmon: list, processList: list, procmonCSV: dict):
    # Sort procmon list by PID
    # procmonByPID = __sortDict(procmon, 'PID')
    # pIDCount = __countToDict(procmonByPID, 'PID')
    # Sort by Name (To prevent fork)
    # procmonByName = __sortDict(procmon, 'Process Name')
    # nameCount = __countToDict(procmonByName, 'Process Name')
    # Sort by operation
    report = ""
    procmonByOperation = __sortDict(procmon, 'Operation')
    # Count Threads create
    threadCreateList = list()
    processCreateList = list()
    for item in procmonByOperation:
        if item['Operation'] == 'Thread Create':
            threadCreateList.append(item.copy())
        elif item['Operation'] == 'Process Create':
            processCreateList.append(item.copy())
    threadCount = __countToDict(__sortDict(threadCreateList, 'Process Name'), 'Process Name')
    childCount = __countToDict(__sortDict(processCreateList, 'Process Name'), 'Process Name')
    for k in threadCount:
        if threadCount[k] >= config['Process']['MaxThreadCount']:
            report += 'Name 【{}】 is suspicious because it create {} threads in collection duration.\n'.format(k, threadCount[k])
            processMaxThreadName.append(k)
    for k in childCount:
        if childCount[k] >= config['Process']['MaxChildrenCount']:
            report += 'Name 【{}】 is suspicious because it forked {} child processes in collection duration.\n'.format(k, childCount[k])
            processMaxChildName.append(k)  
    for item in processCreateList:
        if 'cmd.exe' in item['Path'] or 'powershell.exe' in item['Path']:
            report += "--------------CALL CMD OR POWERSHELL--------------\n"
            report += "PID 【{}】, name 【{}】, called cmd or powershell. It may execute some scripts.\n".format(item['PID'], item['Process Name'])
            report += "Child process PID and Path: 【{}】\n".format(item['Detail'])
            processCallCmd.append(item)

    for i in processList:
        tmp = list()
        tmp.append(i)
        # j = i['ParentProcessId']
        # # Generate process tree list
        # while True:
        #     index = __findIndex(processList, 'ProcessId', j)
        #     if index == -1:
        #         break
        #     else:
        #         tmp.append(processList[index].copy())
        #         j = processList[index]['ParentProcessId']
        # processTreeList.append(tmp)
        # Check parent
        if i['Name'] in config['Process']['KnownParent'].keys():
            index = __findIndex(processList, 'ProcessId', i['ParentProcessId'])
            if index != -1 and processList[index]['Name'] != config['Process']['KnownParent'][i['Name']]:
                global parentProblem
                parentProblem = True
                report += "【{}】's parent process should be 【{}】, but 【{}】 instead".format(i['Name'], config['Process']['KnownParent'][i['Name']], processList[index]['Name'])
        # Check Any path is in User directory or Temp
        if 'Appdata'.lower() in i['Path'].lower() or 'Temp'.lower() in i['Path'].lower():
            processRunInTemp.append(i)
            report += "【{}】 is run under 【{}】, which is not standard location\n".format(i['Name'], i['Path'])
        if 'C:\\Users\\'.lower() in i['Path'].lower():
            processRunInUserFolder.append(i)
            report += "【{}】 is run under 【{}】, which is user diretory.\n".format(i['Name'], i['Path'])

    return report

# Begin to analyze registry
def analyzeRegistry(autoruns: list):
    md5List = list()
    for item in autoruns:
        # Check start up 
        if item['Entry Location'] == 'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run':
            autorunProgram.append(item)
            md5List.append(item['MD5'])
        # Check signed
        if item['Company'] == '' and item['Launch String'] != '':
            registryNoCompany.append(item)
            md5List.append(item['MD5'])
        # Check Appinit dll injection
        if item['Entry Location'] == 'HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows':
            registryAppInit.append(item)
            md5List.append(item['MD5'])
        # Check if image hijacked
        if item['Category'] == 'Hijacks':
            registryHijacks.append(item)
            md5List.append(item['MD5'])
    return list(set(md5List))

def virustatal(url = None, md5 = None):
    apikey = "9214be5db0d726c3eeca2c25ba286272cd9726f1cc4e44b2cf3b5e80f7bcdccd"
    if url is not None:
        params = {'apikey': apikey, 'resource': url}
        headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent" : "gzip,  IDSLab"
        }
        response = requests.post('https://www.virustotal.com/vtapi/v2/url/report', data=params)
        json_response = response.json()
    elif md5 is not None:
        params = {'apikey': apikey, 'resource': md5}
        headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent" : "gzip,  IDSLab"
        }
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',params=params, headers=headers)
        json_response = response.json()
        return json_response
    else:
        return {'Error': False}

def die():
    exit(2)

# User Interact function
def main(conn: sqlite3.Connection, cursor: sqlite3.Cursor, configuration = None): 
    global config
    config = configuration
    signal.signal(signal.SIGINT, handler)
    runFull = True
    while True:
        print("請選擇您想要的動作")
        print("1. 進行完整分析")
        print("2. 只進行網路連線分析")
        print("3. 只進行處理程序行為分析")
        print("4. 只進行登錄檔分析")
        print("5. 只進行 Windos Event Log 分析")
        print("6. 關鍵字搜索 - 請先進行完整分析")
        print("7. 離開本系統")
        
        n = 0
        signal.signal(signal.SIGINT, original_sigInt)
        try:
            n = int(input("請輸入您想要的操作: "))
        except ValueError:
            print("請輸入正確的選項。")
            sleep(3)
        except KeyboardInterrupt:
            print("\n即將終止本程式")
            die()
        signal.signal(signal.SIGINT, handler)

        if n == 1:
            network_part(conn, cursor)
            process_part(conn, cursor)
            registry_part(conn, cursor)
            log_part(conn, cursor)
            runFull = True
        elif n == 2:
            network_part(conn, cursor)
        elif n == 3:
            process_part(conn, cursor)
        elif n == 4:
            registry_part(conn, cursor)
        elif n == 5:
            log_part(conn, cursor)
        elif n == 6:
            if runFull == False:
                print("請先執行一次完整分析。")
            else:
                keyword_search()
        elif n == 7:
            print("即將終止本程式...")
            die() 

def network_part(conn: sqlite3.Connection, cursor: sqlite3.Cursor):
    global cports_begin
    cports_begin = cport_reader('cports_begin.csv')
    global cports_end
    cports_end = cport_reader('cports_end.csv')
    global cports_change
    cports_change = cport_change_list('CurrentPortsChangeLog.log')
    result = analyzeNetwork(cports_begin, cports_end, cports_change)
    # Empty all records first
    cursor.execute('DELETE FROM CPORTS')
    # Write Cports to sqlite
    byPid = __sortDict(cports_end, 'processID')
    sqlStr = genBaseSqlStr(cports_end, 'CPORTS')
    for item in byPid:
        values = (int(item['processID']), item['processName'], item['protocol'],
        item['localPort'], item['localAddress'], item['remotePort'],
        item['remoteAddress'], item['state'], item['processPath'],item['pathType'])
        insertTable(cursor, sqlStr, values)
    conn.commit()
    # Write change list to sqlite
    byName = __sortDict(cports_change, 'programName')
    sqlStr = genBaseSqlStr(cports_change, 'CPORTS_CHANGELIST')
    for item in byName:
        values = (item['programName'], item['date'], item['status'], 
        item['protocol'], item['source'], item['destination'])
        insertTable(cursor, sqlStr, values)
    conn.commit()
    # print report
    print('# --------------------------------------- begin of report -------------------------------------------------------------#')
    print("Network Analysis:")
    if len(suspiciousPID) + len(suspiciousName) + len(suspiciousAbusePort) + len(suspiciousNameByChange) == 0:
        print('No obviously suspicous program found!!')
    else:
        print('!!! SOME SUSPICIOUS PROGRAM FOUND !!!')
        print(result) 

# Analyze process monitor data
def process_part(conn: sqlite3.Connection, cursor: sqlite3.Cursor):
    global procmonXML
    procmonXML = process_xml_reader('procmon.xml')
    global proccsv
    proccsv = process_reader('procmon.csv')
    global a_process_list
    a_process_list = process_list('processList.csv', 'processCmd.txt') 
    result = analyzeProcess(proccsv, a_process_list, procmonXML['processlist'])
    # MD5 of running process
    global running_md5
    running_md5 = read_md5_list('original.txt', 'path.txt')
    # Empty all records first
    cursor.execute('DELETE FROM PROCMON_BEHAVIOR')
    # Write process monitor data into 
    byPid = __sortDict(proccsv, 'PID')
    sqlStr = genBaseSqlStr(proccsv, 'PROCMON_BEHAVIOR')
    for item in byPid:
        values = (int(item['PID']), item['Process Name'], item['Time of Day'], 
        item['Operation'], item['Path'], item['Result'], item['Detail'], item['Image Path'])
        insertTable(cursor, sqlStr, values)
    conn.commit()
    # Print Report
    print("\nProcess Analysis:")
    if len(processMaxThreadName) + len(processCallCmd) + len(processMaxChildName) + parentProblem + len(processRunInTemp) + len(processRunInUserFolder) == 0:
        print('No obviously suspicous program found!!')
    else:
        print('!!! SOME SUSPICIOUS PROGRAM FOUND !!!')
        print(result)
        del result
    # Upload MD5 to virustotal
    print("上傳MD5雜湊到VirusTotal比對？")
    print("1. 上傳所有MD5雜湊")
    print("2. 上傳非系統目錄類的程序雜湊")
    print("3. 上傳非系統目錄類以及Program File底下的程序雜湊")
    print("4. 不要上傳任何雜湊")
    signal.signal(signal.SIGINT, original_sigInt)
    s = '4'
    try:
        s = '2'
        # s = str(input("請輸入您的選擇： "))
    except KeyboardInterrupt:
        pass
    signal.signal(signal.SIGINT, handler)
    if s == '1':
        for item in running_md5:
            if len(item['md5']) >= 32:
                print("Upload hash {} to VT".format(item['md5']))
                # report.append(dict(virustatal(md5 = item)))
                report = dict(virustatal(md5 = item['md5']))
                print(item['path']," Virus Total result : ",report['positives'], "/" , report['total'])
                sleep(16)
            else:
                pass 
    elif s == '2':
        for item in running_md5:
            if len(item['md5']) >= 32 and 'C:\\Windows'.lower() not in item['path'].lower():
                print("Upload hash {} to VT".format(item['md5']))
                # report.append(dict(virustatal(md5 = item)))
                report = dict(virustatal(md5 = item['md5']))
                print(item['path']," Virus Total result : ",report['positives'], "/" , report['total'])
                sleep(16)
            else:
                pass 
    elif s == '3':
        for item in running_md5:
            if len(item['md5']) >= 32 and 'C:\\Windows'.lower() not in item['path'].lower() and 'C:\\Program Files'.lower() not in item['path'].lower():
                print("Upload hash {} to VT".format(item['md5']))
                # report.append(dict(virustatal(md5 = item)))
                report = dict(virustatal(md5 = item['md5']))
                print(item['path']," Virus Total result : ",report['positives'], "/" , report['total'])
                sleep(16)
            else:
                pass 
    else:
        pass
    
    # for item in processTreeList:
    #     tmp = item[::-1]
    #     for k in tmp:
    #         print(k['Name'] + "->", end='')
    #     print('')
    
def registry_part(conn: sqlite3.Connection, cursor: sqlite3.Cursor):
    global registry
    registry = autoruns_reader('registry.csv')
    md5 = analyzeRegistry(registry)

    # Write registry to database
    registry_all = autoruns_reader('registry.csv')
    registry = list()
    for item in registry_all:
        aDict = {k:item[k] for k in ('Entry','Entry Location','Time', 'Launch String', 'Company', 'Description', 'Category', 'MD5', 'PESHA-1') if k in item}
        registry.append(aDict)
    sqlStr = genBaseSqlStr(registry, 'REGISTRY')
    for item in registry:
        values = (item['Entry'], item['Entry Location'], item['Time'], 
        item['Launch String'], item['Company'], item['Description'],
        item['Category'], item['MD5'], item['PESHA-1'])
        insertTable(cursor, sqlStr, values)
    conn.commit()

    print("\nRegistry Analysis:")
    report = ""
    if len(autorunProgram) + len(registryAppInit) + len(registryHijacks) + len(registryNoCompany) == 0:
        print('!!! SOME SUSPICIOUS PROGRAM FOUND !!!')
    else: 
        report += "--------------Register At Logon--------------\n"
        for k in autorunProgram:
            report += "Image Path 【{}】 had been registered to start at logon.\n".format(k['Image Path'])
            report += "Launch string is 【{}】\n".format(k['Launch String'])  
        report += "--------------No Company Registry--------------\n"
        for k in registryNoCompany:
            report += "Key 【{}】 has no company name\n".format(k['Launch String'])
        report += "--------------AppInit DLL Injection--------------\n"
        for k in registryAppInit:            
            report += "AppInit Detected!!\n"
        report += "--------------Image hijacked--------------\n"
        for k in registryHijacks:            
            report += "The hijacked image is 【{}】".format(k['Entry'])
            report += "by the image at【{}】\n".format(k['Launch String'])
    print(report)
    del report

    # s = str(input("是否上傳可疑登錄檔雜湊到VT？ (Y/N) "))
    s = 'y'
    if s.lower() == 'y':
        for item in md5:
            if len(item) >= 32:
                print("Upload hash {} to VT".format(item))
                # report.append(dict(virustatal(md5 = item)))
                item = dict(virustatal(md5 = item))
                print("Virus Total result : ",item['positives'], "/" , item['total'])
                sleep(16)
            else:
                pass
    else:
        pass

def log_part(conn, cursor):
    global logs
    logs = read_log('Security.csv')
    sqlStr = genBaseSqlStr([['']*7], 'LOG')
    for item in logs:
        # print((item['Strings'].replace(r"\r\n",",")).replace(r"\t", " "))
        values = (item['EventID'], item['TimeWritten'], item['EventType'],
        item['EventTypeName'], item['EventCategory'], 
        (item['Strings'].replace(r"\r","").replace(r"\n",",")).replace(r"\t", " "), 
        item['Message'])
        # print(sqlStr)
        insertTable(cursor, sqlStr, values)
    conn.commit()
    conn.close()

def keyword_search():
    signal.signal(signal.SIGINT, original_sigInt)
    while True:
        search_hit = list()
        print("您想搜尋什麼？")
        print("1. 全域查詢 --Not implemented")
        print("2. IP地址")
        print("3. 處理程序名稱")
        print("4. PID查詢")
        print("5. 登錄檔 Entry 查詢")
        print("6. Log ID 查詢")
        print("7. 回到主畫面")
        s = '7'
        try:
            s = str(input("請輸入您要的選項？"))
        except KeyboardInterrupt:
            break
        if s == '1':
            print("Not implemented")
        # For ip lookup
        elif s == '2':
            # Search IP
            s = str(input("請問您要搜尋甚麼:  "))
            for k in cports_begin:
                if s in k['localAddress'] or s in k['remoteAddress']:
                    search_hit.append(k)
            for k in cports_end:
                if s in k['localAddress'] or s in k['remoteAddress']:
                    search_hit.append(k)
            for k in cports_change:
                if s in k['source'] or s in k['destination']:
                    search_hit.append(k)
            print("Keyword hit!!")
            readDict(search_hit)
        # For ProcessName lookup
        elif s == '3':
            # Search by process Name
            try:
                s = str(input("請問您要搜尋甚麼: "))
            except KeyboardInterrupt:
                break
            for k in proccsv:
                if s in k['Process Name'] or s in k['Path']:
                    search_hit.append(k)
            for k in a_process_list:
                if s in k['Name']:
                    search_hit.append(k)
            for k in cports_begin:
                if s in k['processName']:
                    search_hit.append(k)
            for k in cports_end:
                if s in k['processName']:
                    search_hit.append(k)
            for k in cports_change:
                if s in k['programName']:
                    search_hit.append(k)
            for k in registry:
                if s in k['Launch String']:
                    search_hit.append(k)
            print("Keyword hit!!")
            readDict(search_hit)
        # Search by Process ID
        elif s == '4':
            try:
                s = int(input("請問您要搜尋甚麼: "))
            except KeyboardInterrupt:
                break
            except ValueError:
                print("int only")
                break
            for k in proccsv:
                if s == int(k['PID']):
                    search_hit.append(k)
            for k in a_process_list:
                if s == int(k['ProcessId']):
                    search_hit.append(k)
            for k in cports_begin:
                if s == int(k['processID']):
                    search_hit.append(k)
            for k in cports_end:
                if s == int(k['processID']):
                    search_hit.append(k)
            print("Keyword hit!!")
            readDict(search_hit)  
        elif s == '5':
            try:
                s = str(input("請問您要搜尋甚麼: "))
            except KeyboardInterrupt:
                break
            for k in registry:
                if s in k['Entry Location']:
                    search_hit.append(k)
            print("Keyword hit!!")
            readDict(search_hit)
        elif s == '6':
            try:
                s = str(input("請問您要搜尋甚麼: "))
            except KeyboardInterrupt:
                break
            for k in logs:
                if s == k['EventID']:
                    search_hit.append(k)
            print("Keyword hit!!")
            readDict(search_hit)
        elif s == '7':
            break
        input("請按任一鍵繼續...")
        del search_hit
    signal.signal(signal.SIGINT, handler)

if __name__ == "__main__":
    print("#########################################")
    print("#            Rand's Forensic            #")
    print("#########################################")

    print("初始化資料庫")
    # Load config
    config = read_yaml('config.yml')
    # Connect offline sqlite
    conn, cursor = connect('Case.db')
    # Creat database
    dbInit(cursor)
    # User Interface
    main(conn, cursor)
    die()
    # readDict(cport_reader('cports_begin.csv'))
    # readDict(autoruns_reader('registry.csv'))
    # readDict(cport_change_list('CurrentPortsChangeLog.log'))
    # readDict(flow_list('flow.txt'))
    # readDict(process_list('processList.csv')) #TODO: Bug fix
    # readDict(process_reader('procmon.csv'))
    # readDict(read_log('Security.csv'))
    # readDict(test['processlist']['process'])           