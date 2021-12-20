#coding:utf-8

class Loop:
    # h: a LoopPart of header node
    # b: List<LoopPart> of body nodes
    def __init__(self, h , b , multi) -> None:
        self.header = h
        self.body = b
        self.isMultiExit = multi 
    
    def debugInfo(self):
        sb = ""
        sb += "==== loop information ====\n"
        sb += f"header : {self.header},body : {self.body}, isMultiExit : {self.isMultiExit}"
        return sb

class LoopPart:
    def __init__(self, index, header = False, tail = False , brk = False , cont = False , outEnt = False) -> None:
        self.index = index
        self.isHeader = header
        self.isTail = tail
        self.isBreak = brk
        self.isContinue = cont
        self.hasOutsideEntry = outEnt
    
    def debugInfo(self):
        sb = ""
        sb +=  f"Id = {self.index} : "
        if self.isHeader == True :  sb += ", isHeader"
        if self.isBreak == True : sb += ", isBreak"
        if self.isContinue == True: sb += ", isContinue"
        if self.isTail == True: sb += ", isTail"
        if self.hasOutsideEntry == True: sb += ", HasOutsideEntry"
        return sb


    