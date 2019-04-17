class PendMove(object):
    '''
    This class is about to execute and parse the result
    '''


    def __init__(self, file:str = None):
        '''
        Constructor
        '''
        self.pendinglist = []
        if(file is not None):
            pass
        else:
            pass
        
    def parser(self, filePath:str) -> str:
        '''
        The method will parse the file or input string.
        And return the result as string
        '''
        file = open(filePath,"r")
        content = file.read()
        content_list = content.split("\n")
        proc = []
        target = []
        for item in content_list:
            if("Source:" not in item and "Target:" not in item):
                pass
            elif("Source:" in item):
                proc.append(item)
            else:
                target.append(item)
        
        for index, item in enumerate(proc):
            tmp = {}
            tmp["process"] = proc[index]
            tmp["target"] = target[index]
            self.pendinglist.append(tmp)
        del tmp
        return self.pendinglist
        
if(__name__ == "__main__"):
    a = PendMove(r'D:\\autorun.csv')
    for item in (a.parser(r'D:\\testPendMove.txt')):
        print(item)