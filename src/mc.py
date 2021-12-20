import ida_lines
import ida_idaapi
import ida_kernwin
import ida_hexrays
import ida_hexrays as hr
import copy

from idautils import * 
from idaapi import * 
from idc import *
from mc_helper import *


class Mblock(mblock_t):
    def __init__(self, m : mblock_t):
        #super().__init__(*args, **kwargs) 
        self.__dict__ = m.__dict__
        self.id = self.serial

#in order to  compute a decision block where it's a condition jump, we use microcode 
class MicroCode():
    def __init__(self, ea, mmat_level = 0):
        self.func = get_func(ea)
        self.mba = get_func_microcode(self.func, mmat_level)
        
        #spend much time to construct cfg, but if mmat_level >=3, build_graph call is not needed
        self.mba.build_graph()

        self.blocks = [Mblock(self.mba.get_mblock(i)) for i in range(self.mba.qty)]
        return 
    
    def DebugMblock(self, mb):
        if mb.head:
            print((hex(mb.head.ea), hex(mb.tail.ea)))
        
    def MapBlockToMblocks(self, block):
        result = []
        for i in range(self.mba.qty):
            if self.blocks[i].head == None:
                continue
            if (self.blocks[i].head.ea >= block.start_ea and self.blocks[i].tail.ea <= idc.prev_head(block.end_ea)) :
                result.append(i)
        return sorted(result)

    def GetMblockSuccsByIndex(self, i):
        nsucc = self.blocks[i].nsucc()
        result = [self.blocks[i].succ(j) for j in range(nsucc)]
        return result
    
    @staticmethod
    def GetMblockSuccsByMblock(mb):
        return [mb.succ(i) for i in range(mb.nsucc())]

    @staticmethod
    def GetMblockPredsByMblock(mb):
        return [mb.pred(i) for i in range(mb.npred())]
    
    def GetEdgeLableByMblock(self, blockA, blockB):
        try:
            childsA = self.GetMblockSuccsByMblock(blockA)
        except:
            return None
        try:
            if is_mcode_jcond(blockA.tail.opcode):
                if childsA[0].serial == blockB.serial  :   return "true"
                if childsA[1].serial == blockB.serial  :   return "false" 
            return None
        except:
            return None
    
    #compute the edge A->B is true or false
    def GetEdgeLable(self, blockA, blockB):
        idxA = self.MapBlockToMblocks(blockA)
        idxB = self.MapBlockToMblocks(blockB)
        try:
            childsA = self.GetMblockSuccsByIndex(idxA[-1])
        except:
            return None
        if len(idxA)>0:
            mb = self.blocks[idxA[-1]] 
            if is_mcode_jcond(mb.tail.opcode):
                '''
                if mb.tail.opcode == m_jcnd:
                    if mb.tail.l.t == mop_r and mb.tail.l.r == mr_zf:  #if zero
                        if idxB == childsA[0]:   return "true"
                        if idxB == childsA[1]:   return "false"

                if mb.tail.opcode == m_jnz:
                    if mb.tail.l.t == mop_r and mb.tail.l.r == mr_zf:  # not equal zero
                        if idxB == childsA[0]:   return "true"
                        if idxB == childsA[1]:   return "false"   
                '''
                if childsA[0] in idxB :   return "true"
                if childsA[1] in idxB:   return "false" 
        return None
                        
                        






                



