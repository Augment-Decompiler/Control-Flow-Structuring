#coding: utf-8
from enum import Enum, unique


absType = Enum("absType", ("SEQUENCE", "SIMPLEWHILE", "IFTHEN", "IFTHENELSE", "BREAK", "CONTINUE", "WHILE", "DOWHILE", "ACSESEREGION"))

class ABSBlock:
    def __init__(self, t= None) -> None:
        self.type = t 
        self.data = None
