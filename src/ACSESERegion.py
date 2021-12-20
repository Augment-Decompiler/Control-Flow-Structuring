#coding:utf-8
from graph import *
class ACSESERegion:
    def __init__(self, gr) -> None:
        self.graph = gr  #the graph is DAG
        self.decNodes = []   #branch node 
        self.codeNodes = []  #code code
        for i in range(self.graph.node_num):
            if len(self.graph.getChildren(i)) > 1:
                self.decNodes.append(i)
            else:
                self.codeNodes.append(i)