from main.Functionize import Forensic
from time import sleep
from main.Yaml import YMLReader

apikey = '9214be5db0d726c3eeca2c25ba286272cd9726f1cc4e44b2cf3b5e80f7bcdccd'
blacklist = list()
forensic = Forensic()
print("\nreading yml file.\n")
yml = YMLReader()
items = yml.readConfig(yml.load(r"D:\config.yml"))
print(items)

print("reading cport file.\n\n")
cportDict = forensic.read_csv(items.get('cport_path'))
for item in (cportDict):
    print(item)

print("\nreading autoruns file.\n")
autoDict = forensic.readAutorun(items.get('Autoruns'))
for item in autoDict:
    print(item)

#In this part, searching blacklist
black = open(items.get('blacklist'),mode = "r")
for aItem in autoDict:
    for bItem in cportDict:
        #print("{} is in {} : {}".format(bItem['ProcessName'],aItem['Image_path'],(bItem['ProcessName'] in aItem['Image_path'])))
        if(bItem['ProcessName'] in aItem['Image_path']):
            print( bItem['RemoteHostName'])
            bItem['Flag'] += 1
            for something in black:
                #print(something)
                #print(bItem['RemoteHostName'])
                print("{} connected to {}, is it blacklist? {}".format(bItem['ProcessName'], bItem['RemoteHostName'], something in bItem['RemoteHostName']))
                if(something in bItem['RemoteHostName']):
                    bItem['Flag'] +=1
        black.seek(0)
        ...   
    if(aItem['Company'] == ''):
        print("Notice: {} is registered in {}, but the company name is empty.".format(aItem['Image_path'], aItem['Category']))
        ...
    
print(cportDict)
   
# aDict = forensic.getCmd(items.get('cmd_path'))
# print(aDict)
# while(True):
#     a = input("Do you want to upload custom blacklist? (N ): ")
#     if(a.capitalize() == 'Y'):
#         path = input("Enter the black list Path, which is csv")
#         tmp = forensic.loadCustomBlackList(path)
#         if(tmp == None):
#             print("try again")
#             continue
#         else:
#             print("Load successful")
#             blacklist = tmp
#             del tmp 
#             break
#     elif(a.capitalize() == 'N'):
#         blacklist = forensic.loadDefaultBlackList()
#         break
#     else:
#         print("Please try again")
# while(True):
#     a = input("Upload to virus total ?? : (N)")
#     if(a.capitalize() == 'Y'):
#         json = forensic.uploadVirusTotal('CastleCheat.exe', "D:\CastleCheat.exe", apikey)
#         break
#     elif (a.capitalize() == 'N'):
#         json = None
#         break
#     else:
#         print("Try again")
# if(json == None):
#     exit()
# if (json == {'error':False}):
#     print('Failed to open file')
#     exit()
# else:
#     print(json['verbose_msg'] + ":" + str(json['response_code']))
#     sleep(200)
#     response_json = forensic.retrieveReport(json['scan_id'], apikey)
#     print(response_json)
#     print(str(response_json['positives']) + "/" + str(response_json['total']))
# sleep(20)
# print(forensic.retrieveReport(forensic.hash(forensic.SHA256, open("D:\\test.exe","rb")), apikey)['positives'])
