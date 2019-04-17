class NoSuchAlgorithmException(Exception):
    '''
    This is customer exception
    '''
    message = ''
    def __init__(self, message:str):
        super(NoSuchAlgorithmException, self).__init__(message)
        self.message = message
    
    def toString(self):
        return self.message
    
    def clone(self):
        return self

class PathInvaildException(Exception):
    '''
    This is customized exception
    '''
    
    def __init__ (self, message:str):
        super(PathInvaildException, self).__init__(message)
        self.message = message    
    
    def toString(self):
        return self.message
    
    def clone(self):
        return self