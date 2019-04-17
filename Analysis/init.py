import yaml
import database as db
import os
from time import sleep
import sqlite3
import network_analysis as network
import process_analysis as process
import registry_analysis as registry
import log_analysis as logs
import Csv_Reader as interactive_mode
import utilities as util
import xlsxwriter as xlsx
from yattag import Doc
from datetime import date


FULL_ANALYSIS = 0
NETWORK_ANALYSIS = 1
PROCESS_ANALYSIS = 2
REGISTRY_ANALYSIS = 3
LOG_ANALYSIS = 4
INTERACTIVE = 5


def read_yaml(file_path: str)-> dict:
    '''
    This function read configuation files
    Must be YAML format
    '''
    if not os.path.isfile(file_path):
        return [{'error':'No such file'}]
    with open(file_path, mode='r', newline="") as yml_file:
        config = yaml.load(yml_file)
    return config

def correlate(cports, changes, wmic, procmon, registry, logs):
    pass

def mainFunc(action: int, vtaction: str = None, keyword: str = None):
    '''
    This is main function
    action, what the function do
    vtaction, Upload to vistotal
    keyword, the keyword search
    '''
    print("#########################################")
    print("#      Automatically Forensic Tool      #")
    print("#########################################")
    config = read_yaml('config.yml')
    conn, cursor = db.connect('Case.db')
    db.dbInit(cursor)
    cports = []
    change = []
    wmic = []
    procmon = []
    autoruns = []
    events = []
    if action == FULL_ANALYSIS:
        cports, change = network.network_main('cports_begin.csv', 'CurrentPortsChangeLog.log', config, conn, cursor, keyword = keyword)
        wmic, procmon = process.process_main('processList.csv', 'procmon.csv', config, conn, cursor, keyword = keyword)
        autoruns = registry.registry_main('registry.csv', config, conn, cursor, keyword= keyword)
        events = logs.log_main('Security.csv', config, conn, cursor, keyword = keyword)
    elif action == NETWORK_ANALYSIS:
        network.network_main('cports_begin.csv', 'CurrentPortsChangeLog.log', config, conn, cursor, keyword = keyword)
    elif action == PROCESS_ANALYSIS:
        wmic, procmon = process.process_main('processList.csv', 'procmon.csv', config, conn, cursor, keyword = keyword)
    elif action == REGISTRY_ANALYSIS:
        autoruns = registry.registry_main('registry.csv', config, conn, cursor, keyword= keyword)
    elif action == LOG_ANALYSIS:
        events = logs.log_main('Security.csv', config, conn, cursor, keyword = keyword)
    elif action == INTERACTIVE:
        interactive_mode.main(conn, cursor, config)
    else:
        return
    # Correlate
    # Count process ID number
    susPID = dict()
    susPID = util.mutipleListOfDictCount(susPID, network.suspiciousPID, 'processID')
    susPID = util.mutipleListOfDictCount(susPID, network.suspiciousPort, 'processID')
    susPID = util.mutipleListOfDictCount(susPID, network.listeningProgram, 'processID')
    for element in process.processMaxThread:
        if element not in susPID.keys():
            susPID[element] = 1
        else:
            susPID[element] += 1
    for element in process.processMaxChild:
        if element not in susPID.keys():
            susPID[element] = 1
        else:
            susPID[element] += 1
    susPID = util.mutipleListOfDictCount(susPID, process.processCallScript, 'PID')
    susPID = util.mutipleListOfDictCount(susPID, process.processInUserFolder, 'ProcessId')
    susPID = util.mutipleListOfDictCount(susPID, process.processInNonStandardFolder, 'ProcessId')
    susPID = util.mutipleListOfDictCount(susPID, process.processWrongParent, 'ProcessId')
    print(susPID)
    malReg = list()
    vtResult = list()
    susReg = list()
    # Get suspicious registry
    for k in registry.registryAutoruns:
        if k['MD5'] != '':
            vt = util.virusTotal(None,k['MD5'])
            sleep(1)
            if vt['response_code'] == 0:
                vt['positives'] = "HASH NOT FOUND!!"
                vt['total'] = ""
                malReg.append(k)
                vtResult.append(vt)
                continue
            print(vt['positives'])
            if vt['positives'] > 0:
                malReg.append(k)
                vtResult.append(vt)
            elif k['Signer'] == '' or "Not verified" in k['Signer']:
                susReg.append(k)
            else:
                pass
    for k in registry.registryAppInit:
        if k['MD5'] != '':
            vt = util.virusTotal(None,k['MD5'])
            sleep(1)
            print(vt['positives'])
            if vt['positives'] > 0:
                malReg.append(k)
                vtResult.append(vt)
            elif k['Signer'] == '' or "Not verified" in k['Signer']:
                susReg.append(k)
            else:
                pass
    for k in registry.registryCategoryToCheck:
        if k['MD5'] != '':
            vt = util.virusTotal(None,k['MD5'])
            sleep(1)
            print(vt['positives'])
            if vt['positives'] > 0:
                malReg.append(k)
                vtResult.append(vt)
            elif k['Signer'] == '' or "Not verified" in k['Signer']:
                susReg.append(k)
            else:
                pass
    running_md5 = util.read_md5_list('original.txt', 'path.txt')
    malProcess = list()
    for k in running_md5:
        if k['md5'] == 'No such file':
            k['vtresult'] = "FILE DELETED!!"
            malProcess.append(k)
            continue
        try:
            result = util.virusTotal(None, k['md5'])
            if result['response_code'] == 0:
                k['vtresult'] = "hash not found!!"
                malProcess.append(k)
                continue
            if result == {'Error': False}:
                print("Some problem happened when trying to upload hash of {} to VT".format(k['path']))
            if result["positives"] > 0:
                k['vtresult'] = "{}/{}".format(result["positives"], result["total"])
                malProcess.append(k)
        except KeyError:
            print("KeyError happened in uploading process md5 to VT, var k = {}".format(k))
            continue

        
    # Generate report
    # Generate final report
    doc, tag, text = Doc().tagtext()
    doc.asis('<!DOCTYPE html>')
    with tag('html'): # Generate <html></html> tag
        with tag('head'): # Generate <head></head> tag
            with tag('style'): # Generate basic style
                style = "table {\
                    font-family: arial, sans-serif;\
                    border-collapse: collapse;\
                    width: 100%;\
                }\
                td, th {\
                    border: 1px solid #dddddd;\
                    text-align: left;\
                    padding: 8px;\
                }\
                    tr:nth-child(even) {\
                    background-color: #dddddd;\
                }"
                text(style)
        with tag('body'): # Generate malicious registry
            with tag('font', ('size','60')):
                text("Malicious Registry") 
            with tag('h2'):
                text('Registry info')
            with tag('table'):
                keys = ("Entry", "Entry Location", "Launch String", "Signer", "VirusTotal")
                with tag('tr'):
                    for key in keys:
                        with tag('th'):
                            text(key)
                indice = 0
                for regKey in malReg:
                    with tag('tr'):
                        for key in keys:
                            if key == "VirusTotal":
                                with tag('td'):
                                    text("{}/{}".format(vtResult[indice]['positives'], vtResult[indice]['total']))
                                    indice += 1
                            else:
                                with tag('td'):
                                    text(regKey[key])
            with tag('font', ('size','60')):
                text('Suspicious process')
                with tag('br'):
                    pass
            for pid in susPID:
                count = 1
                with tag('font', ('size','20')):
                    text('-------------------------------------------------------------------------------')
                    with tag('br'):
                        pass
                    text('Process ID: {}'.format(pid))
                proc = util.keyword_search(wmic, str(pid), 'ProcessId')
                with tag('table'):
                    keys = ("ProcessId", "Name", "ParentProcessId", "CommandLine")
                    with tag('tr'):
                        for key in keys:
                            with tag('th'):
                                text(key)
                    with tag('tr'):
                        for key in keys:
                            with tag('td'):
                                if len(proc) == 0:
                                    text('Process terminated before recording.')
                                else:
                                    text(proc[0][key])
                for item in network.suspiciousPID:
                    if pid in item['processID']:
                        text("{}. {} created too many connection.".format(count, pid))
                        count += 1
                        with tag('br'):
                            pass
                        break
                for item in network.suspiciousPort:
                    if pid in item['processID']:
                        text("{}. {} used abused port {}.".format(count, pid, item['remotePort']))
                        count += 1
                        with tag('br'):
                            pass
                        break
                for item in network.listeningProgram:
                    if pid in item['processID']:
                        text("{}. {} listening port {} and connect to {}.".format(count, pid, item['localPort'], item['remoteAddress']))
                        count += 1
                        with tag('br'):
                            pass
                        break
                if pid in process.processMaxThread:
                    text("{}. {} created too many thread".format(count, pid))
                    count += 1
                    with tag('br'):
                            pass
                if pid in process.processMaxChild:
                    text("{}. {} created too many children".format(count, pid))
                    count += 1
                    with tag('br'):
                            pass
                for item in process.processCallScript:
                    if pid in item['PID']:
                        text("{}. {} called scripts, detail: {}.".format(count, pid, item['Detail']))
                        count += 1
                        with tag('br'):
                            pass
                        break
                for item in process.processInUserFolder:
                    if pid in item['ProcessId']:
                        text("{}. {} executable in user folder, {}.".format(count, pid, item['Path']))
                        count += 1
                        with tag('br'):
                            pass
                        break
                for item in process.processInNonStandardFolder:
                    if pid in item['ProcessId']:
                        text("{}. {} executable in temp or appdata, {}.".format(count, pid, item['Path']))
                        count += 1
                        with tag('br'):
                            pass
                        break
                for item in process.processWrongParent:
                    if pid in item['ProcessId']:
                        text("{}. {} has strange parent process {}.".format(count, pid, item['ParentProcessId']))
                        count += 1
                        with tag('br'):
                            pass
                        break
                with tag('br'):
                    pass
                with tag('br'):
                    pass

            with tag('font', ('size','40')):
                text("Malicious/Suspicious Running Process")
            with tag('table'):
                keys = ("path", "md5", "vtresult")
                with tag('tr'):
                    for key in keys:
                        with tag('th'):
                            text(key)
                for k in malProcess:
                    with tag('tr'):
                        for key in keys:
                            with tag('td'):
                                print(k[key])
                                text(str(k[key]).strip())

            with tag('br'):
                pass
            with tag('br'):
                pass

            with tag('font', ('size','40')):
                text("Suspicious Log IDs")
            with tag('table'):
                keys = ("EventID", "EventTypeName", "Message", "TimeGenerated" )
                with tag('tr'):
                    for key in keys:
                        with tag('th'):
                            text(key)
                for log in logs.logs_hit:
                    with tag('tr'):
                        for key in keys:
                            with tag('td'):
                                text(log[key])

    print(doc.getvalue(), file= open("./reports/Final_report_{}.html".format(str(date.today()).replace('-','_')), "w"))
    doc, tag, text = Doc().tagtext()
    
    
    
    #Generate header
    doc.asis('<!DOCTYPE html>')
    with tag('html'): # Generate <html></html> tag
        with tag('head'): # Generate <head></head> tag
            with tag('style'): # Generate basic style
                style = "table {\
                    font-family: arial, sans-serif;\
                    border-collapse: collapse;\
                    width: 100%;\
                }\
                td, th {\
                    border: 1px solid #dddddd;\
                    text-align: left;\
                    padding: 8px;\
                }\
                    tr:nth-child(even) {\
                    background-color: #dddddd;\
                }"
                text(style)
        with tag('body'): # generate <body></body>
            if len(network.suspiciousPID) != 0: # Check if suspicious PID found
                keys = ("processID", "processName", "localAddress", "localPort",
                "remoteAddress", "remotePort", "state", "protocol", "pathType",
                "processPath")
                with tag('h2'):
                    text("processes that made too many connections")
                with tag('table'):
                    with tag('tr'):
                        for key in keys:
                            with tag('th'): # Create table header
                                text(key)
                    for aDict in network.suspiciousPID:
                        with tag('tr'):
                            for key in keys:
                                with tag('td'):
                                    text(aDict[key])
            if len(network.suspiciousPort) != 0:
                keys = ("remotePort", "processID", "processName", "localAddress", 
                "localPort", "remoteAddress", "state", "protocol", "pathType",
                "processPath")
                with tag('h2'):
                    text("Remote Ports that used by too many processes")
                with tag('p'):
                    text("Some malware like ssh brute force will keep trying the port from different host.")
                with tag('table'):
                    with tag('tr'):
                        for key in keys:
                            with tag('th'):
                                text(key)
                    for aDict in util.sortDictOfList(network.suspiciousPort, 'remotePort'):
                        with tag('tr'):
                            for key in keys:
                                with tag('td'):
                                    text(aDict[key])
                # portsCount = util.countToDict(util.sortDictOfList(cports, 'remotePort'), 'remotePort')
            if len(network.listeningProgram) != 0:
                keys = ("state", "processID", "processName", "localAddress", 
                "localPort", "remoteAddress", "remotePort",  "protocol", "pathType",
                "processPath")
                with tag('h2'):
                    text("Program that has listening state")
                with tag('p'):
                    text("A Program that listening no localhost, check service/ program you run...")
                with tag('table'):
                    with tag('tr'):
                        for key in keys:
                            with tag('th'):
                                text(key)
                    for aDict in network.listeningProgram:
                        with tag('tr'):
                            for key in keys:
                                with tag('td'):
                                    text(aDict[key])
            if len(network.nonStandardArea) != 0:
                keys = ("pathType","processPath", "processID", "processName", 
                "localAddress", "localPort", "remoteAddress", "remotePort", "state",
                 "protocol")
                with tag('h2'):
                    text("Program from non-standard location")
                with tag('p'):
                    text("Program should run in Program Files or somewhere users' program folder")
                with tag('table'):
                    with tag('tr'):
                        for key in keys:
                            with tag('th'):
                                text(key)
                    for aDict in network.nonStandardArea:
                        with tag('tr'):
                            for key in keys:
                                with tag('td'):
                                    text(aDict[key])

    print(doc.getvalue(), file= open("./reports/network_report_{}.html".format(str(date.today()).replace('-','_')), "w"))

    doc, tag, text = Doc().tagtext()
    doc.asis('<!DOCTYPE html>')
    with tag('html'): # Generate <html></html> tag
        with tag('head'): # Generate <head></head> tag
            with tag('style'): # Generate basic style
                style = "table {\
                    font-family: arial, sans-serif;\
                    border-collapse: collapse;\
                    width: 100%;\
                }\
                td, th {\
                    border: 1px solid #dddddd;\
                    text-align: left;\
                    padding: 8px;\
                }\
                    tr:nth-child(even) {\
                    background-color: #dddddd;\
                }"
                text(style)
        with tag('body'): # generate <body></body>
            if len(process.processMaxChild) != 0: # Check if suspicious PID found
                keys = ("PID", "Process Name", "Time of Day", "Path" ,"Detail", "Result")
                with tag('font', ('size','80')):
                    text("Processes that created too many child in period")
                for pid in process.processMaxChild:
                    with tag('h2'):
                        text("Process ID: {}".format(pid))
                    with tag('p'):
                        text("Which create the following child processes")
                    with tag('table'):
                        children = util.keyword_search(process.childCreateList, pid)
                        with tag('tr'):
                            for key in keys:
                                with tag('th'): # Create table header
                                    text(key)
                        for child in children:
                            with tag('tr'):
                                for key in keys:
                                    with tag('td'):
                                        if child[key] is None:
                                            text("None")
                                        else:
                                            text(child[key])
            if len(process.processMaxThread) != 0:
                keys = ("PID", "Process Name", "Time of Day", "Path" ,"Detail", "Result")
                with tag('font',('size', '80')):
                    text("Processes that created too many thread")
                for pid in process.processMaxThread:
                    with tag('h2'):
                        text("Process ID: {}".format(pid))
                    with tag('p'):
                        text("Which create the following thread")
                    with tag('table'):
                        children = util.keyword_search(process.threadCreateList, pid)
                        with tag('tr'):
                            for key in keys:
                                with tag('th'): # Create table header
                                    text(key)
                        for child in children:
                            with tag('tr'):
                                for key in keys:
                                    with tag('td'):
                                        if child[key] is None:
                                            text("None")
                                        else:
                                            text(child[key])
            if len(process.processCallScript) != 0:
                keys = ("PID", "Process Name", "Time of Day", "Path" ,"Detail", "Result")
                with tag('font',('size', '80')):
                    text("Processes called some script")
                with tag('table'):
                    with tag('tr'):
                        for key in keys:
                            with tag('th'): # Create table header
                                text(key)
                    for aProcess in process.processCallScript:
                        with tag('tr'):
                            for key in keys:
                                with tag('td'):
                                    if aProcess[key] is None:
                                        text("None")
                                    else:
                                        text(aProcess[key])
            if len(process.processWrongParent) != 0:
                keys = ("ProcessId", "Name", "ParentProcessId", "CommandLine")
                with tag('font',('size', '80')):
                    text("Processes' parents not normal")
                with tag('table'):
                    with tag('tr'):
                        for key in keys:
                            with tag('th'): # Create table header
                                text(key)
                    for aProcess in process.processWrongParent:
                        with tag('tr'):
                            for key in keys:
                                with tag('td'):
                                    if aProcess[key] is None:
                                        text("None")
                                    else:
                                        text(aProcess[key])
            with tag('font',('size', '80')):
                text("Processes list")
            with tag('table'):
                keys = ("ProcessId", "Name", "ParentProcessId", "CommandLine", "VirusTotal")
                with tag('tr'):
                    for key in keys:
                        with tag('th'): # Create table header
                            text(key)
                for aProcess in wmic:
                    with tag('tr'):
                        for key in keys[:4]:
                            with tag('td'):
                                if aProcess[key] is None:
                                    text("None")
                                else:
                                    text(aProcess[key])                                             
    
    print(doc.getvalue(), file= open("./reports/process_report_{}.html".format(str(date.today()).replace('-','_')), "w"))
    
    doc, tag, text = Doc().tagtext()
    doc.asis('<!DOCTYPE html>')
    with tag('html'): # Generate <html></html> tag
        with tag('head'): # Generate <head></head> tag
            with tag('style'): # Generate basic style
                style = "table {\
                    font-family: arial, sans-serif;\
                    border-collapse: collapse;\
                    width: 100%;\
                }\
                td, th {\
                    border: 1px solid #dddddd;\
                    text-align: left;\
                    padding: 8px;\
                }\
                    tr:nth-child(even) {\
                    background-color: #dddddd;\
                }"
                text(style)
        with tag('body'):
            keys = ("Entry", "Category", "Entry Location", "Launch String","Description","Profile", "Signer", "MD5")
            if len(registry.registryAutoruns) != 0:
                with tag('font', ('size','80')):
                    text("Registry Autorun")
                with tag('table'):
                    with tag('tr'):
                        for key in keys:
                            with tag('th'): # Create table header
                                text(key)
                        for reg in registry.registryAutoruns:    
                            with tag('tr'):
                                for key in keys:
                                    with tag('td'):
                                        if reg[key] is None:
                                            text("None")
                                        else:
                                            text(reg[key])
            if len(registry.registryAppInit) != 0:
                with tag('font', ('size','80')):
                    text("Registry Autorun")
                with tag('table'):
                    with tag('tr'):
                        for key in keys:
                            with tag('th'): # Create table header
                                text(key)
                        for reg in registry.registryAppInit:    
                            with tag('tr'):
                                for key in keys:
                                    with tag('td'):
                                        if reg[key] is None:
                                            text("None")
                                        else:
                                            text(reg[key])
            if len(registry.registryNotSign) != 0:
                with tag('font', ('size','80')):
                    text("Registry Autorun")
                with tag('table'):
                    with tag('tr'):
                        for key in keys:
                            with tag('th'): # Create table header
                                text(key)
                        for reg in registry.registryNotSign:    
                            with tag('tr'):
                                for key in keys:
                                    with tag('td'):
                                        if reg[key] is None:
                                            text("None")
                                        else:
                                            text(reg[key])
    print(doc.getvalue(), file= open("./reports/registry_report_{}.html".format(str(date.today()).replace('-','_')), "w"))

    # Old
    # row = 0
    # col = 0

    # print("---------- Analysis Result ----------")
    # print("---------- Network Analysis ---------")
    # print("Suspicious PID")
    # util.readDict(network.suspiciousPID)
    # print("Suspicious process name")
    # util.readDict(network.suspiciousName)
    # print("Suspicious name by change")
    # util.readDict(network.suspiciousNameByChange)
    # print("Suspicious ports that may be abused")
    # util.readDict(network.suspiciousPort)
    # print("Program may listen")
    # util.readDict(network.listeningProgram)
    # print("Program in Non-standard area made connection")
    # util.readDict(network.nonStandardArea)
    # if keyword:
    #     workbook = xlsx.Workbook("keyword_hits.xlsx")
    #     cports_hits = workbook.add_worksheet("keyword_hits")
    #     if len(network.cports_keywords_hits) > 0:
    #         keys = ("processID", "processName", "state", 
    #                 "remoteAddress","remotePort","localAddress", 
    #                 "localPort", "protocol", "processPath", "pathType")
    #         util.writeToExcel(worksheet=cports_hits, keys=keys, data=network.cports_keywords_hits, maxRow=50)
    #     if len(network.change_keywords_hits) > 0:
    #         keys = ("date", "programName", "status", "protocol", "source", "destination")
    #         util.writeToExcel(workbook.add_worksheet("change_list_hits"), keys, network.change_keywords_hits)

    #     # util.readDict(network.cports_keywords_hits)
    #     # util.readDict(network.change_keywords_hits)

    
    # print("---------- process Analysis ---------")
    # print("Process made lots of threads")
    # util.readDict(process.processMaxThread)
    # print("Process made lots of children")
    # util.readDict(process.processMaxChild)
    # print("Process may execute script")
    # util.readDict(process.processCallScript)
    # print("Process in System folder")
    # util.readDict(process.processInSysFolder)
    # print("Process in normal prgram files")
    # util.readDict(process.processInInstalledFolder)
    # print("Process under user diretory")
    # util.readDict(process.processInUserFolder)
    # print("Process under strange location")
    # util.readDict(process.processInNonStandardFolder)
    # print("Process under undefined area")
    # util.readDict(process.processInOtherFolder)
    # print("Process has wrong parent process")
    # util.readDict(process.processWrongParent)
    # if keyword:
    #     print("Process hits")
    #     util.readDict(process.procmon_keywords_hits)
    #     util.readDict(process.wmic_keywords_hits)

    # print("---------- Registry Analysis --------")
    # print("Registry autoruns at logon")
    # util.readDict(registry.registryAutoruns)
    # print("Registry not signed")
    # util.readDict(registry.registryNotSign)
    # print("Registry Appinit")
    # util.readDict(registry.registryAppInit)
    # print("Category to check results")
    # util.readDict(registry.registryCategoryToCheck)
    # if keyword:
    #     print("hits")
    #     util.readDict(registry.keywords_hits)

    # print("---------- Logs Analysis ------------")
    # if keyword:
    #     util.readDict(logs.keywords_hits)