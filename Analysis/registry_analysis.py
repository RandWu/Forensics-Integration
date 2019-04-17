import os
import csv
import sqlite3
import database as db
import utilities as util

# If you have any encoding error, change this value!!
__ENCODING = "utf16"
# Accessible Variable
registryAutoruns = list()
registryNotSign = list()
registryAppInit = list()
registryCategoryToCheck = list()
keywords_hits = list()

def registry_main(autoruns_path: str, config: dict, conn: sqlite3.Connection, cursor: sqlite3.Cursor, keyword: str = None, vtaction: str = None):
    '''
    Entry function of the registry analysis, in order to mudulization.
    autoruns The file path of the autoruns result csv.
    config: The configuration
    conn, cursor: database related
    '''
    autoruns = __registry_parser(autoruns_path)
    __create_db(autoruns, conn, cursor)
    __registry_analysis(config, autoruns)
    if keyword:
        global keywords_hits
        keywords_hits = util.keyword_search(autoruns, keyword)
    if vtaction:
        pass
    return autoruns

def __registry_parser(autoruns_path: str):
    '''
    This function will read csv and load into Dictionary
    autoruns_path: string of the valid path name
    '''
    registry_list = list()
    if not os.path.isfile(autoruns_path):
        raise FileNotFoundError("{} not found",format(autoruns_path))
    #The autoruns output is utf16...
    with open(autoruns_path, mode='r', newline="", encoding=__ENCODING) as csv_file:
        csv_reader = csv.DictReader(csv_file, fieldnames=None, restkey='undefined')
        for row in csv_reader:
            registry_list.append(row.copy())
    return registry_list

def __create_db(autoruns: list, conn: sqlite3.Connection, cursor: sqlite3.Cursor):
    registry = list()
    for item in autoruns:
        aDict = {k:item[k] for k in ('Entry','Entry Location','Time', 'Launch String', 'Company', 'Description', 'Signer','Category', 'MD5', 'PESHA-1') if k in item}
        registry.append(aDict)
    if len(registry) == 0:
        return
    sqlStr = db.genBaseSqlStr(registry, 'REGISTRY')
    for item in registry:
        values = (item['Entry'], item['Entry Location'], item['Time'], 
        item['Launch String'], item['Company'], item['Signer'], item['Description'],
        item['Category'], item['MD5'], item['PESHA-1'])
        db.insertTable(cursor, sqlStr, values)
    db.commit(conn)

def __registry_analysis(config, autoruns):
    for item in autoruns:
        # Check start up
        if config['Registry']["StartUp"] in item['Entry Location']:
            registryAutoruns.append(item)
        # Check signed
        if item['Signer'] == '' or "Not verified" in item['Signer']:
            registryNotSign.append(item)
        if item['Entry Location'] in config['Registry']["AppInit"]:
            registryAppInit.append(item)
        if item['Category'] in config['Registry']['CategoryToCheck']:
            registryCategoryToCheck.append(item)