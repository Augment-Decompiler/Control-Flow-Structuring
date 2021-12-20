#coding:utf-8
#from Decompiler import *
from os import stat

current_ident = 0

class token:
    '''
    token{
        's': str
        'i': indent_level + current_ident
        'n': ''   print: '\n' + ' '*k* indent 
    }
    '''
    def __init__(self, xtype, value=None):
        self.type = xtype
        self.value = value
    
    def debugInfo(self):
        return f"{self.type} : {self.value}\n"

class Program:
    def __init__(self):
        self.states = []
        self.current_ident = 2
        
    def pp(self):
        result = ''
        for state in self.states:
            for t in state.token_list:
                if isinstance(t, token):
                    if t.type == 's':
                        result += t.value
                    if t.type == 'i':
                        self.current_ident += t.value
                    if t.type == 'n':
                        result += '\n'+ " "*2*self.current_ident
                if isinstance(t, Program) or isinstance(t, BaseState):
                    t.current_ident = self.current_ident
                    result += str(t)
                if isinstance(t, str):
                    result += str(t)
        #print(result)
        return result

    def __str__(self):
        return self.pp()
    
    def __repr__(self):
        return self.__str__()
    
    def debugInfo(self):
        return ''.join([state.debugInfo() for state in self.states])
    
class BaseState:
    def __init__(self):
        self.token_list = []
        self.current_ident = 2
    
    def __str__(self):
        return self.pp()
    
    def pp(self):
        result = ''
        for t in self.token_list:
            if isinstance(t, token):
                if t.type == 's':
                    result += t.value
                if t.type == 'i':
                    self.current_ident += t.value
                if t.type == 'n':
                    result += '\n'+ " "*2*self.current_ident
            if isinstance(t, Program) or isinstance(t, BaseState):
                    t.current_ident = self.current_ident
                    result += str(t)
        return result

    def debugInfo(self):
        return ''.join([token.debugInfo() for token in self.token_list])

class BlockState(BaseState):
    def __init__(self, index):
        super(BlockState, self).__init__()
        self.index = index
        self.token_list=[token('s',f'block{self.index}')]
    
    def isVar(self):
        self.token_list=[token('s',f'block{self.index}')]
        
class IFUniState(BaseState):
    def __init__(self, var, p):
        super(IFUniState, self).__init__()
        self.var = var 
        self.p = p
        l= [ 
            token('s', 'if(') ,
            self.var,
            token('s', ')'),
            token('n') ,
            token('s','{') ,
            token('i', 2) ,
            token('n') ,
            self.p,
            token('i', -2) ,
            token('n') , 
            token('s','}') ,  
            token('n') 
        ]
        self.token_list = l


class IFBinState(BaseState):
    def __init__(self, var, p1, p2):
        super(IFBinState, self).__init__()
        self.var = var
        self.p1 = p1
        self.p2 = p2
        l= [ 
            token('s', 'if(') ,
            self.var,
            token('s', ')'),
            token('n') ,
            token('s','{') ,
            token('i', 2) ,
            token('n') ,
            self.p1,
            token('i', -2) ,
            token('n') , 
            token('s','}') ,  
            token('n') ,
            token('s', "else"),
            token('n'),
            token('s', '{'),
            token('i', 2) ,
            token('n') ,
            self.p2,
            token('i', -2) ,
            token('n') , 
            token('s','}') 
        ]
        self.token_list = l


class WhileState(BaseState):
    def __init__(self, var , p):
        super(WhileState, self).__init__()
        self.var = var
        self.p = p
        l= [ 
            token('s', 'while(') ,
            self.var,
            token('s', ')'),
            token('n') ,
            token('s','{') ,
            token('i', 2) ,
            token('n') ,
            self.p,
            token('i', -2) ,
            token('n') , 
            token('s','}')  
        ]
        self.token_list = l


class DoWhileState(BaseState):
    def __init__(self, var , p):
        super(DoWhileState, self).__init__()
        self.var = var
        self.p = p
        l= [ 
            token('s', 'do') ,
            token('n') ,
            token('s','{') ,
            token('i', 2) ,
            token('n') ,
            self.p,
            token('i', -2) ,
            token('n') , 
            token('s','}') ,  
            token('n') ,
            token('s', 'while('),
            self.var,
            token('s', ')'),
        ]
        self.token_list = l

    
class SequenceState(BaseState):
    def __init__(self, p1, p2):
        super(SequenceState, self).__init__()
        l= [ 
            p1,
            token('n'),
            p2,
        ]
        self.token_list = l
    
class SimpleWhileState(BaseState):
    def __init__(self, var):
        self.var = var
        super(SimpleWhileState, self).__init__()
        l= [ 
            token('s', 'while(') ,
            self.var,
            token('s', ')'),
            token('s','{ ') ,
            token('s','}') 
        ]
        self.token_list = l

class BreakState(BaseState):
    def __init__(self, var):
        self.var = var
        super(BreakState, self).__init__()
        l= [ 
            token('s', 'if(') ,
            self.var,
            token('s', ')'),
            token('s','  ') ,
            token('s', 'break;')
        ]
        self.token_list = l

class ContinueState(BaseState):
    def __init__(self, var):
        self.var = var
        super(ContinueState, self).__init__()
        l= [ 
            token('s', 'if(') ,
            self.var,
            token('s', ')'),
            token('s','  ') ,
            token('s', 'continue;') 
        ]
        self.token_list = l


if __name__ ==  "__main__":
    pass