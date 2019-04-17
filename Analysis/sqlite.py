# import sqlite3

# def connect(databaseName: str):
#     nonlocal conn 
#     conn = sqlite3.connect(databaseName)
#     cursor = conn.cursor()
#     return conn, cursor

# def createTable(cursor: sqlite3.Cursor, sqlStr: str):
#     cursor.execute(sqlStr)

# def insertTable(cursor: sqlite3.Cursor, sqlStr: str):
#     cursor.execute(sqlStr)

# def selectTable(cursor: sqlite3.Cursor, sqlStr: str):
#     cursor.execute(sqlStr)

# def commitAndClose(conn: sqlite3.Connection):
#     conn.commit()
#     conn.close()