import os
import csv
import sqlite3
import database as db
import utilities as util

# Encoding
__ENCODING = 'cp950'

# Accessible Variables
logs_hit = list()
keywords_hits = list()

def log_main(logs_path: str, config: dict, conn: sqlite3.Connection, cursor: sqlite3.Cursor, keyword = None):
    logs = __log_parser(logs_path)
    if logs == [{'None':False}]:
        return logs
    __create_db(logs, conn, cursor)
    __log_analysis(config, logs)
    if keyword:
        global keywords_hits
        keywords_hits = util.keyword_search(logs, keyword)
    return logs

def __log_parser(logs_path: str):
    aDict = list()
    if not os.path.isfile(logs_path):
        return [{'None':False}]
    try:
        with open(logs_path, mode='r', newline="", encoding=__ENCODING) as csv_file:
            # namespace = ('EventLog', 'RecordNumber', 'TimeGenerated', 'TimeWritten', 'EventID', 'EventType', 'EventTypeName', 'EventCategory', 'EventCategoryName',)
            csv_reader = csv.DictReader(csv_file, fieldnames=None, restkey='Undefined')
            for row in csv_reader:
                if row['EventID'] != None:
                    aDict.append(row.copy())
            return aDict
    except UnicodeDecodeError:
        print("An decoding problem... Please edit the encoding in log_analysis.py")
        exit(1000)

def __create_db(logs: list, conn: sqlite3.Connection, cursor: sqlite3.Cursor):
    sqlStr = db.genBaseSqlStr([['']*7], 'LOG')
    for item in logs:
        # print((item['Strings'].replace(r"\r\n",",")).replace(r"\t", " "))
        values = (item['EventID'], item['TimeWritten'], item['EventType'],
        item['EventTypeName'], item['EventCategory'], 
        (item['Strings'].replace(r"\r","").replace(r"\n",",")).replace(r"\t", " "), 
        item['Message'])
        db.insertTable(cursor, sqlStr, values)
    db.commit(conn)

def __log_analysis(config, logs):
    for item in logs:
        for log_id in config['Log']['LogID']:
            if item['EventID'] == str(log_id):
                logs_hit.append(item)