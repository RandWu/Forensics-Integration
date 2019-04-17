import yaml
from main.Functionize import Forensic
from main.MyExcept import PathInvaildException

class YMLReader(object):
    '''
    The class will read the yaml config
    '''

    def __init__(self,obj = None):
        '''
        Constructor
        '''
        self.forensic = Forensic()
        if (obj is not None and isinstance(obj, YMLReader)):
            pass
    
    def load(self, path:str):    
        if(self.forensic.isVaildPath(path)):
            self.stream = open(path,"r")
            return self.stream
        else:
            raise PathInvaildException("Path is not valid.")
        
    def reload(self, path:str=None):
        if (path is not None and isinstance(path, str)):
            return self.load(path)
        else:
            return None
        
    def readConfig(self, stream):
        items = {}
        docs = yaml.load_all(stream)
        for doc in docs:
            for k, v in doc.items():
                print(k," -> " , v, "  ->", type(v))
                items[k] = v
            print("\n")
        return items
        
    def __clone(self):
        return self    
    
    def __str__(self, *args, **kwargs):
        return "This function is not printable"