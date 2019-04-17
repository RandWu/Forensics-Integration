# Your Virustotal API key
import requests
import os
from math import inf
import xlsxwriter as xlsx
APIKEY = "bd1d1a86903cab3313941d34067c0d2b1116a3646df65721600611b000bc5897"
# MINE "9214be5db0d726c3eeca2c25ba286272cd9726f1cc4e44b2cf3b5e80f7bcdccd"

def sortDictOfList(aList: list, keyName)->list:
    '''
    Sort list of dict by key
    aList: List if dict
    keyName: Key to sort
    return: Sorted list of dict
    '''
    return sorted(aList, key=lambda k: k[keyName])

def countToDict(sortedList: list, keyName)-> dict:
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

def findIndex(aList: list, key, value):
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

def virusTotal(url:str = None, md5:str = None):
    apikey = APIKEY
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

def keyword_parser(file_path: str, types: str = 'plaintext', delimeter: str = None, encoding: str = 'utf8'):
    '''
    Parse the keyword list
    file_path: path of the keyword list
    types: List format
    delimeter: delimeter of the keyword list
    encoding: encoding of the keyword list
    '''
    if not os.path.isfile(file_path):
        raise FileNotFoundError("{} is not found!".format(file_path))
    # If type is 'plaintext', the delimeter will set to '\n'
    keyword_list = list()
    if types.lower() == 'plaintext':
        with open(file_path, mode='r', encoding= encoding) as aFile:
            for keyword in aFile.readlines():
                # Need to remove fucking \r\n
                keyword_list.append(keyword.replace("\r", "").replace("\n",""))
    elif types.lower() == 'csv':
        raise NotImplementedError("This methodology is not implemented!")
    else:
        raise TypeError("Wrong Type!!")
    return keyword_list.copy()

def keyword_search(aList: list, keywords, keyName: str = None):
    '''
    Search keywords, of course
    aList: Actually, a list of dicts
    keywords: words you want to search
    '''
    # Hits, a list of dict
    hits = list()
    # If string type, covert to one element list
    if type(keywords) is str:
        temp = list()
        temp.append(keywords)
        keyword_list = temp.copy()
        del temp
    else:
        keyword_list = keywords

    # Iterate and find the hit
    for keyword in keyword_list:
        for aDict in aList:
            if not keyName:
                for key in aDict.keys():
                    if aDict[key] != None and keyword == aDict[key]:
                        hits.append(aDict)
            else:
                if aDict[keyName] != None and keyword == aDict[keyName]:
                    hits.append(aDict)
    return hits.copy()

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

def writeToExcel(worksheet: xlsx.worksheet, keys: tuple, data: list, row = 0, col = 0,maxRow = inf, maxCol = inf):
    '''
    This function write list of dict to Excel file
    worksheet: xlsx worksheet to write into
    keys: a tuple of keys because keys() would randomize the keys
    data: List of dict
    row: row to start
    col: col to start
    maxRow: Maximum row counts
    maxCol: Maximum column counts

    return
    row: The cursor of the row, int type
    col: The cursor of the col, int type
    '''
    # Write the header
    for key in keys:
        worksheet.write(row, col, key)
        col += 1
    col = 0
    row += 1

    for k in data:
        # Check if exceed max value of row
        if row > maxRow:
            break
        # now k is a dictionary
        for key in keys:
            # Check if exceed the max value of col
            if col > maxCol:
                break
            # now key is one of index of k, iterate and fill in xlsx
            worksheet.write(row, col, k[key])
            # After write, the col plus 1
            col += 1
            # Then iterate all keys
        # After one section done, cols need to rewind
        col = 0
        # And go to next row
        row += 1
    return row, col

def mutipleListOfDictCount(counter: dict, toBeItered: dict, key: str)->dict:
    aList = list()
    # Remove duplicated target
    for element in toBeItered:
        if element[key] not in aList:
            aList.append(element[key])
    # Count to dict, {key:count}
    for element in aList:
        if element not in counter.keys():
            counter[element] = 1
        else:
            counter[element] += 1
    return counter

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
            print(line)
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
                continue  
            elif '0x80070002' in line:
                md5.append('Permission Denied')
                try:
                    # Skip the 'CertUtil: Fail'
                    next(aFile)
                # If end of file
                except StopIteration:
                    break                
            # Get MD5, which is second line in a pattern
            elif len(str(line).strip().replace(" ", "")) == 32:
                md5.append(str(line).strip().replace(" ", ""))
                try:
                    # Skip the third pattern, 'CertUtil: Dump finished successfully'
                    next(aFile)
                # if end of file
                except StopIteration:
                    break
            # If something should't happen happened...
            else:
                print(line)
                raise ValueError('Unexpected value found')
    # MD5 is gotten by paths in collection part, which must be the same value
    if len(paths) != len(md5):
        print(len(paths), len(md5))
        for a in paths:
            print(a)
        for b in md5:
            print(b)    
        raise ValueError('Data may be corruption')
    counter = 0
    for item in paths:
        running_md5.append({'path':item, 'md5':md5[counter]})
        counter += 1
    # Remove duplicate dict in list 
    running_md5 = [dict(t) for t in set([tuple(d.items()) for d in running_md5])]
    return running_md5