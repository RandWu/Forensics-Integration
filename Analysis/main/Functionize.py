import csv
import errno, os, sys
import requests
import hashlib
from main.MyExcept import NoSuchAlgorithmException

class Forensic(object):
    '''
    classdocs
    This is a class of this work
    '''
    # variables
    data = []
    data2 = []
    cmdList = []
    procName = "ProcessName"
    pid = "PID"
    proto = "Protocol"
    localPortName = "LocalPortName"
    rip = "RemoteIP"
    rPortName = "RemotePortName"
    rHostName = "RemoteHostName"
    procsvc = "ProcessService"
    procArgs = "ProcessArgument"
    flag = "Flag"
    MD5 = 'md5'
    SHA1 = 'sha1'
    SHA256 = 'sha256'
    #URL = "https://www.virustotal.com/vtapi/v2/file/scan"
    #APIKey = '9214be5db0d726c3eeca2c25ba286272cd9726f1cc4e44b2cf3b5e80f7bcdccd'

    def __init__(self, forensicObject = None):
        '''
        Constructor
        Receive : self type of object
        '''
        if(forensicObject is None or not isinstance(forensicObject, Forensic)):
            pass
        else :
            pass
    
    def read_csv(self, filepath:str) -> dict:
        '''
        This function will read csv and load it in Dictionary
        receive: string of valid path name
        return : dictionary of process
        '''
        if(not os.path.isfile(filepath)):
            return None
        with open(filepath, mode = "r",  newline = "") as csvFile:
            csvReader = csv.reader(csvFile, delimiter = ",")
            for row in csvReader:
            # Create hash table of data and store in list
                aDict = {self.procName:"", self.pid:0, self.proto:"", self.localPortName:"", self.rip:"", self.rPortName:"", self.rHostName:"", 
                         self.procsvc:"", self.procArgs:[], self.flag:False}
                aDict[self.procName] = row[0]
                aDict[self.pid] = row[1]
                aDict[self.proto] = row[2]
                aDict[self.localPortName] = row[3] + "-" + row[4]
                aDict[self.rip] = row[8]
                aDict[self.rPortName] = row[7] + "-" + row[6]
                aDict[self.rHostName] = row[9]
                aDict[self.procsvc] = row[18]
                aDict[self.procArgs] = []
                self.data.append(aDict)
        return self.data
    
    def readAutorun(self, filepath:str) -> dict:
        '''
        This function will read csv and load in Dictionary
        receive: string of valid path name
        return : dictionary of process
        '''
        firstTime = True
        if(not os.path.isfile(filepath)):
            return None
        with open(filepath, mode = "r", newline = "", encoding = 'utf16') as csvFile:
            csvReader = csv.reader(csvFile, delimiter = ",")
            for row in csvReader:
                if(firstTime): 
                    firstTime = False
                    continue
#                 try:
#                     print(row)
#                 except UnicodeEncodeError:
#                     continue
                aDict = {}
                aDict["Entry_Location"] = row[1]
                aDict["Entry"] = row[2]
                aDict["Category"] = row[4]
                aDict["Company"] = row[7]
                aDict["Image_path"] = row[8]
                aDict["Launch_String"] = row[10]
                self.data2.append(aDict)
        return self.data2
    
    def loadCustomBlackList(self, path:str):
        '''
        This function read custom blacklist, expected csv
        receive : string of valid path
        return  : dictionary of black list or None if failed
        '''
        if(not os.path.isfile(path)):
            return None
        with open(path, mode = 'r', newline = "") as csvFile:
            blackList = []
            CSVReader = csv.reader(csvFile)
            for row in CSVReader:
                blackList.append(row)
        return blackList
    
    def loadDefaultBlackList(self):
        '''
        This function load default blacklist
        '''
        return list()
    
    def uploadVirusTotal(self, fileName:str, filePath:str, apikey:str):
        '''
        This function upload file to virus total
        Note the maximum size is 32MB
        And with this method the priority is lowest
        Do NOT re-send file repeatedly
        receive: filename:str, filePath:str, apiKey:str
        return : jsonObject:dictionary
        return : {'error':False} if file does not exist
        '''
        params = {'apikey': apikey}
        try:
            files = {'file': (fileName, open(filePath, 'rb'))}
        except IOError:
            return {'error':False}
        response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
        json_response = response.json()
        return json_response
    
    def retrieveReport(self, resource:str, apikey:str):
        params = {'apikey': apikey, 'resource': resource}
        headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent" : "gzip,  IDSLab"
        }
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',params=params, headers=headers)
        json_response = response.json()
        return json_response
    
    def getCmd(self, filePath:str):
        cmdList = []
        cmdFile = open(filePath,'r')
        for line in cmdFile:
            cmdList.append(line.split())
        del cmdList[0]
        
        for aDict in self.data:
            for cmd in cmdList:
                #print(cmd)
                if aDict[self.procName] in cmd[0]:
                    if aDict[self.procArgs] is None:
                        #print(aDict[self.procName] + " is None")
                        break
                    aDict[self.procArgs].append(cmd)
                    aDict[self.flag] = True
                else:
                    aDict[self.procArgs] = None
                    aDict[self.flag] = False
        return aDict
    
    def hash(self, algorithm:str, f):
        '''
        Hash function for virus total
        '''
        if(algorithm == self.MD5):
            hash_md5 = hashlib.md5()
            for chunck in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunck)
            return hash_md5.hexdigest()
        elif(algorithm == self.SHA1):
            hash_sha1 = hashlib.sha1()
            for chunck in iter(lambda: f.read(4069), b""):
                hash_sha1.update(chunck)
            return hash_sha1.hexdigest()
        elif(algorithm == self.SHA256):
            hash_sha256 = hashlib.sha256()
            for chunck in iter(lambda: f.read(4069), b""):
                hash_sha256.update(chunck)
            return hash_sha256.hexdigest()
        else:
            raise NoSuchAlgorithmException("This algorithm doesn't exist or not be implemented yet.")
    
    def isVaildPath(self,filePath:str) -> bool:
        '''
        This function check the file path is valid or not
        receive: string
        return : boolean
        True means the path is valid, False otherwise
        '''
        ERROR_INVAILD_NAME = 123 #Magic Number
        try:
            #Check the path is string object or is but empty
            if (not isinstance(filePath, str) or not filePath):
                return False
            # Strip this pathname's Windows-specific drive specifier (e.g., `C:\`)
            # if any. Since Windows prohibits path components from containing `:`
            # characters, failing to strip this `:`-suffixed prefix would
            # erroneously invalidate all valid absolute Windows pathnames.
            _, filePath = os.path.splitdrive(filePath)
            # Directory guaranteed to exist. If the current OS is Windows, this is
            # the drive to which Windows was installed (e.g., the "%HOMEDRIVE%"
            # environment variable); else, the typical root directory.            
            rootDirName = os.environ.get('HOMEDRIVE', 'C:') \
                if (sys.platform == 'win32') else os.path.sep
            assert os.path.isdir(rootDirName)
            # Append a path separator to this directory if needed.
            rootDirName = rootDirName.rstrip(os.path.sep) + os.path.sep
            # Test whether each path component split from this pathname is valid or
            # not, ignoring non-existent and non-readable path components.
            for pathNamePart in filePath.split(os.path.sep):
                try:
                    os.lstat(rootDirName + pathNamePart)
                except OSError as exc:
                    if (hasattr(exc, 'winerror')):
                        if(exc.winerror == ERROR_INVAILD_NAME):
                            return False
                    elif ( exc.errno in {errno.ENAMETOOLONG, errno.ERANGE}):
                        return False
        # If a "TypeError" exception was raised, it almost certainly has the
        # error message "embedded NUL character" indicating an invalid pathname.
        except TypeError:
            return False
        else:
            return True       
        
if(__name__ == "__main__"):
    a = Forensic()
    for item in (a.readAutorun(r"D:\\testCase\\Adware1\\autoruns.csv")):
        print(item)
    pass                                                                 