#coding:utf-8
from TreeNode import *
import copy
from idautils import CodeRefsFrom
import idc
from idc_bc695 import GetFlags

class Helper:
    def __init__(self) -> None:
        pass

    @staticmethod 
    def Unblock(index, blocked, blockMap):
        blocked.remove(index)
        for (item1, item2) in blockMap:
            if item1 == index:
                Helper.Unblock(item2, blocked, blockMap)
            blockMap.remove((item1, item2))
    
    @staticmethod
    def ListUnion(a, b):
        result = []
        result += copy.deepcopy(a)
        for i in b:
            if i not in a:
                result.append(i)
        return result

    @staticmethod
    def ListIntersection(a, b):
        result = []
        for i in a:
            if i in b:
                result.append(i)
        return result

    @staticmethod
    def ListChanged(before, after):
        if len(before) != len(after):
            return True
        diff = False
        for i in before:
            if i not in after:
                diff = True 
                break
        return diff

    @staticmethod
    def AddPath(t, path):
        #print(t.text)
        if len(path) > 0:
            t2 = None
            found = False
            for t3 in t.nodes:
                if t3.text == str(path[0]):
                    t2 = t3
                    found = True
                    break
            if found == False:
                t2 = TreeNode(str(path[0]))
                #t2.Name = t2.text
            tmp = []
            for i in range(1, len(path)):
                tmp.append(path[i])
            if t2!= None : t2 = Helper.AddPath(t2, tmp)
            if found == False and t2!=None:
                t.nodes.append(t2)
        return t
    
    @staticmethod
    # t is dominator tree
    def ADominatesB(a, b, t):  
        tmp = t
        if t.text != str(a):
            res = t.treeFind(str(a))
            if len(res)!=1:
                #print(res)
                return False
            tmp = res[0]
        
        if len(tmp.treeFind(str(b))) !=1:
            return False
        return True
    
    @staticmethod
    def ListContained(inner, outer):
        if len(inner) > len(outer): return False
        for i in inner:
            if i not in outer:
                return False
        return True
    
    @staticmethod
    #move index from a to b
    def ListMoveIndex(index, a, b):
        for i in range(len(a)):
            if a[i] == index:
                del a[i]
                break
        b.append(index)
       
    @staticmethod
    #just for debug
    def DebugBB(bb):
        bbtype = {0: "fcb_normal", 1: "fcb_indjump", 2: "fcb_ret", 3: "fcb_cndret",
                4: "fcb_noret", 5: "fcb_enoret", 6: "fcb_extern", 7: "fcb_error"}
        print("ID: %d, Start: 0x%x, End: 0x%x, Last instruction: 0x%x, Size: %d, "
            "Type: %s" % (bb.id, bb.start_ea, bb.end_ea, idc.prev_head(bb.end_ea),
                            (bb.end_ea - bb.start_ea), bbtype[bb.type]))
    
    
            

            

