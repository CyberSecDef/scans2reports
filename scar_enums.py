from enum import Enum

class TestResultOptions(Enum):
    add     = 'add'
    convert = 'convert'
    close   = 'close'
    
    def __str__(self):
        return self.value
        
        
class MitigationStatementOptions(Enum):
    blank = 'blank'
    poam  = 'poam'
    ckl   = 'ckl'
    both  = 'both'
    
    def __str__(self):
        return self.value