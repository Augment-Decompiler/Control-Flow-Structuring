#coding:utf-8

class TreeNode:
    def __init__(self, text) -> None:
        self.text = text
        self.nodes = []
        self.parent = None  
        return 

    def treeFind(self, t):
        result = []
        #print(f"find {t}")
        if t == self.text:
            result.append(self)
            return result
        if len(self.nodes) == 0:
            return result
        for x in self.nodes:
            result += x.treeFind(t)   
        return result

    def debugInfo(self):
        if len(self.nodes) == 0:
            return ""
        buf = str(self.text) + "\n"
        buf +=  str([x.text for x in self.nodes]) + "\n"
        for x in self.nodes:
            buf += x.debugInfo()
        return buf