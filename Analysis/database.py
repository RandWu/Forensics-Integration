import sqlite3

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

    # Create process list table
    createSqlStr = "CREATE TABLE PROCESS_LIST \
    (ProcessID INT NOT NULL, \
    Name TEXT, \
    ParentProcessID INT, \
    Path TEXT, \
    Commandline TEXT);"
    createTable(cursor, createSqlStr)

    # Create autoruns table
    createSqlStr = "CREATE TABLE REGISTRY \
    (Entry TEXT NOT NULL, \
    EntryLocation TEXT NOT NULL, \
    Time TEXT, \
    LaunchString TEXT, \
    Company TEXT, \
    Signer TEXT, \
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

def commit(conn: sqlite3.Connection):
    conn.commit()

def close(conn: sqlite3.Connection):
    conn.close()