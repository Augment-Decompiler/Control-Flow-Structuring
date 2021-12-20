from idautils import * 
from idaapi import * 
from idc import *
import copy
from Helper import *
from Loop import *
from TreeNode import *
from mc import *

class Node:
    #option means the same the graph option
    def __init__(self, d = None, id=-1, option =2) -> None:
        self.visited = False
        self.id = id
        self.data = d
        self.option = option

    def succs(self):
        if self.option ==1:
            return [Node(bb , bb.id) for bb in self.data.succs()]
        if self.option ==2:
            return [bb for bb in MicroCode.GetMblockSuccsByMblock(self.data)]

    def preds(self):
        if self.option ==1:
            return [Node(bb , bb.id) for bb in self.data.preds()]
        if self.option ==2:
            return [bb for bb in MicroCode.GetMblockPredsByMblock(self.data)]

class Edge:
    def __init__(self, s , e , t) -> None:
        self.start = s
        self.end = e
        self.backEdge = False
        self.text = t 

class BaseGraph:
    def __init__(self):
        self.nodes = []
        self.edges = []
        self.node_num = 0
        self.func = None

class VirtualBlock(BasicBlock):
    def __init__(self, id):
        self.start_ea = 0xdeadbeef
        self.end_ea = 0xdeadbeef
        self.id = id

class MicroCodeGraph(BaseGraph):
    def __init_nodes(self):
        return [Node(bb, bb.serial) for bb in  self.mba.blocks]
    
    def __init_edges(self):
        result = []
        for i in range(self.node_num):
            for succ_index in self.nodes[i].succs():
                for j in range(self.node_num):
                    if self.mba.blocks[succ_index].serial == self.nodes[j].id:
                        text = self.mba.GetEdgeLableByMblock(self.nodes[i].data , self.nodes[j].data)
                        result.append(Edge(i, j, text))
        return result
        
    def __init__(self,ea):
        self.func = get_func(ea)
        self.mba = MicroCode(ea)
        self.nodes =  self.__init_nodes()
        self.node_num = len(self.nodes)
        self.edges =  self.__init_edges()
        self.nodes = sorted(self.nodes, key=lambda x: x.id)

class IDAGraph(BaseGraph):
    def __init_nodes(self):
        fc =  FlowChart(self.func)
        return [Node(bb, bb.id) for bb in fc]
    
    def __init_edges(self):
        result = []
        for i in range(self.node_num):
            for succ_node in self.nodes[i].succs():
                for j in range(self.node_num):
                    if succ_node.id == self.nodes[j].id:
                        text = self.mba.GetEdgeLable(self.nodes[i].data , self.nodes[j].data)
                        result.append(Edge(i, j, text))
        
        # find return node
        ret_node =  []
        for i in range(self.node_num):
            if len(self.nodes[i].succs()) == 0:
                ret_node.append(i)

        # if there is multi return node, we add a empty node as their succusor
        if len(ret_node) >1 :
            #print("multi return node")
            vnode = VirtualBlock(self.node_num)
            exit_node = Node(vnode, self.node_num)
            self.node_num +=1
            self.nodes.append(exit_node)
            for node in ret_node:
                result.append(Edge(node, exit_node.id, "return"))
            
        #print(self.node_num)
        #print([node.id for node in self.nodes])
        return result

    def __init__(self, ea):
        self.func = get_func(ea)
        self.mba = MicroCode(ea)
        self.nodes =  self.__init_nodes()
        self.node_num = len(self.nodes)
        self.edges =  self.__init_edges()
        self.nodes = sorted(self.nodes, key=lambda x: x.id)

'''
construct by what:
     1.ida's flowchart  :
          exit tail call problem
     2.ida's microcode cfg 
'''
class Graph_Builder:
    def __init__(self, ea):
        self.func_ea = ea
    
    def Select(self, option = 2):
        if option == 1 :
            return IDAGraph(self.func_ea)
        if option == 2:
            return MicroCodeGraph(self.func_ea)
        if option == 3:
            pass
        return
