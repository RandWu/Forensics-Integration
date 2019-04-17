import os
import sqlite3
import csv
import database as db
import utilities as util

# If you have any encoding error, change this value!!
__WMIC_ENCODING = "cp950" # For CHT, BIG 5
__PROCMON__ENCODING = "UTF-8"

# Accessible Variable
threadCreateList = list()
childCreateList = list()
processMaxThread = list()
processMaxChild = list()
processCallScript = list()
processInSysFolder = list()
processInInstalledFolder = list()
processInUserFolder = list()
processInNonStandardFolder = list()
processInOtherFolder = list()
processWrongParent = list()
wmic_keywords_hits = list()
procmon_keywords_hits = list()

def process_main(wmic_path:str, procmon_path:str, config: dict, conn: sqlite3.Connection, cursor: sqlite3.Cursor, keyword: str = None, vtaction: str = None):
    '''
    Entry function of the process analysis, in order to mudulization.
    wmic_path: The file path of the wmic result csv.
    procmon_path: The file path of procmon result csv
    config: The configuration
    conn, cursor: database related
    '''
    wmic, procmon = __process_parser(wmic_path, procmon_path)
    __create_db(wmic, procmon, conn, cursor)
    __process_analysis(config, wmic, procmon)
    if keyword:
        global wmic_keywords_hits
        wmic_keywords_hits = util.keyword_search(wmic, keyword)
        global procmon_keywords_hits
        procmon_keywords_hits = util.keyword_search(procmon, keyword)
    if vtaction:
        pass
    return wmic, procmon

def __process_parser(wmic_path:str, procmon_path:str):
    '''
    This function reads wmic csv and procmon csv and turns into list of dict
    wmic_path: path to wmic csv
    procmon_path: path to procmon csv
    '''
    # Read wmic csv
    a_process_list = list()
    # Check path
    if not os.path.isfile(wmic_path):
        a_process_list = [{'None':False}]
    else:
        try:
            with open(wmic_path, mode='r', newline="", encoding=__WMIC_ENCODING) as csv_file:
                namespace = ('Name','ProcessId', 'ParentProcessId', 'Path')
                csv_reader = csv.DictReader(
                    csv_file, fieldnames=namespace, restkey='CommandLine', delimiter=',')
                for row in csv_reader:
                    tmp = ""
                    count = 0
                    for item in row['CommandLine']:
                        if count == 0:
                            tmp = item # a.exe -a -b -c haha
                            count = 1
                        else:
                            tmp = tmp + "," + str(item) # a.exe -a -b -c haha, baba, mama
                    row['CommandLine'] = str(tmp)
                    a_process_list.append(row.copy())
        except UnicodeDecodeError:
            print("An decoding problem... Please edit the wmic encoding in process_analysis.py")
            exit(1000)

    process_behavior = list()
    if not os.path.isfile(procmon_path):
        process_behavior = [{'None':False}]
    else:
        try:
            with open(procmon_path, mode='r', newline="", encoding=__PROCMON__ENCODING) as csv_file:
                namespace = ('Time of Day', 'Process Name', 'PID', 'Operation', 'Path', 'Result', 'Detail', 'Image Path')
                csv_reader = csv.DictReader(csv_file, fieldnames=namespace, restkey='undefined', delimiter=',')
                next(csv_reader)
                for row in csv_reader:
                    process_behavior.append(row.copy())
        except UnicodeDecodeError:
            print("An decoding problem... Please edit the procmon encoding in process_analysis.py")
            exit(1000)
    return a_process_list, process_behavior

def __create_db(wmic: list, procmon: list, conn: sqlite3.Connection, cursor: sqlite3.Cursor):
    '''
    This function writes data into sqlite
    wmic: wmic result from parser
    procmon: wmic result from parser
    conn, cursor: database related
    '''
    cursor.execute('DELETE FROM PROCESS_LIST')
    sqlStr = db.genBaseSqlStr(wmic, "PROCESS_LIST")
    for item in wmic:
        values = (int(item['ProcessId']), item['Name'], int(item['ParentProcessId']),
        item['Path'], item['CommandLine'])
        db.insertTable(cursor, sqlStr, values)
    db.commit(conn)

    cursor.execute('DELETE FROM PROCMON_BEHAVIOR')
    sqlStr = db.genBaseSqlStr(procmon, 'PROCMON_BEHAVIOR')
    for item in procmon:
        values = (int(item['PID']), item['Process Name'], item['Time of Day'], 
        item['Operation'], item['Path'], item['Result'], item['Detail'], item['Image Path'])
        db.insertTable(cursor, sqlStr, values)
    db.commit(conn)


def __process_analysis(config: dict, wmic: list, procmon: list):
    '''
    This function analyzes data from collection
    config: configuration
    wmic: result from parser
    procmon: result from parser
    '''
    # Config location
    sysPath = config['Process']['SystemFolder']
    insPath = config['Process']['Installed']
    userPath = config['Process']['User']
    nonStandard = config['Process']['Temp']
    # Sorted by operation
    procmonByOperation = util.sortDictOfList(procmon, 'Operation')
    # for counting
    global threadCreateList
    global childCreateList
    for item in procmonByOperation:
        if item['Operation'] == 'Thread Create':
            threadCreateList.append(item.copy())
        elif item['Operation'] == 'Process Create':
            childCreateList.append(item.copy())
    threadCount = util.countToDict(util.sortDictOfList(threadCreateList, "PID"), "PID")
    childCount = util.countToDict(util.sortDictOfList(childCreateList, "PID"), "PID")
    # Match with configuratuin
    for k in threadCount:
        if threadCount[k] >= config['Process']['MaxThreadCount']:
            processMaxThread.append(k)
    for k in childCount:
        if childCount[k] >= config['Process']['MaxChildrenCount']:
            processMaxChild.append(k)
    for k in childCreateList:
        for suspiciousChild in config['Process']['SuspiciousChild']:
            if suspiciousChild in k['Path']:
                processCallScript.append(k)
    for k in wmic:
        # Check parent
        if k['Name'].lower() in config['Process']['KnownParent'].keys():
            # Check the known parent-child relationship
            index = util.findIndex(wmic, 'ProcessId', k['ParentProcessId'])
            # match {Child:Parent} or not, a little complicated.
            if index != -1 and wmic[index]['Name'].lower() != config['Process']['KnownParent'][k['Name'].lower()]:
                processWrongParent.append(k)
        # Check file location
        # flag: if the process belongs at least one of category
        flag = False
        # Check if in System Path
        for l in sysPath:
            if str(l).lower() in k['Path'].lower():
                flag = True
                processInSysFolder.append(k)
                break
        if flag:
            continue
        # Check if in program files path
        for l in insPath:
            if str(l).lower() in k['Path'].lower():
                processInInstalledFolder.append(k)
                flag = True
                break
        if flag:
            continue
        # Check if under user folder
        for l in userPath:
            if str(l).lower() in k['Path'].lower():
                # Check if in non-standard
                for m in nonStandard:
                    if str(m).lower() in k['Path'].lower():
                        flag = True
                        processInNonStandardFolder.append(k)
                        break
                    else :
                        flag = True
                        processInUserFolder.append(k)
                        break
        if flag:
            continue
        else:
            processInOtherFolder.append(k)