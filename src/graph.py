#coding:utf-8
from TreeNode import TreeNode
from Loop import LoopPart
from idautils import * 
from idaapi import * 
from idc import *
import copy
from Helper import *
from Loop import *
from TreeNode import *
from Graph_Builder import *

f = open(r'b.log', r'w')
sys.stdout = f

class graph(BaseGraph):
    def __init__(self, func_ea=None, option=2) -> None:
        self.func_ea = func_ea
        if func_ea == None:
            self.nodes = []
            self.edges = []
            self.node_num = 0
        else:
            gb = Graph_Builder(func_ea)
            gb = gb.Select(option)           
            self.func = gb.func
            self.nodes =  gb.nodes
            self.node_num = gb.node_num
            self.edges =  gb.edges
            self.nodes = gb.nodes
        return

    def invertEdges(self):
        for e in self.edges:
            tmp = e.start
            e.start = e.end
            e.end = tmp
        reversed(self.nodes)

    def invertGraph(self):
        maxId  = self.node_num -1  
        for e in self.edges:
            t = maxId - e.start
            e.start = maxId - e.end
            e.end = t
        tmp = []
        for i in range(maxId,-1,-1):
            tmp.append(self.nodes[i])
        self.nodes = tmp

    def setAllNodes(self , visited):
        for n in self.nodes:
            n.visited = visited
    
    def setAllEdges(self, back):
        for e in self.edges:
            e.backEdge = back

    def getChildren(self, index):
        #return sorted(node.succs(), key=lambda x: x.id)
        result = []
        for e in self.edges:
            if e.start == index:
                result.append(e.end)
        result.sort()
        return result
            
    def getParents(self, index):
        #return sorted(node.preds(), key=lambda x: x.id)
        result = []
        for e in self.edges:
            if e.end == index:
                result.append(e.start)
        result.sort()
        return result

    #-------------------------------------------------
    def DFSSCC(self, index , finished):
        self.nodes[index].visited = True
        childs = self.getChildren(index) 
        #print(f"{index} : {childs}")
        for child in childs:
            if self.nodes[child].visited == False:
                self.DFSSCC(child , finished)
        finished.append(index)

    def getSCC(self, index):
        result  = []
        result.append(index)
        self.nodes[index].visited = True
        childs = self.getChildren(index) 
        for child in childs:
            if child >= self.node_num:
                print(f"index is : {index}, child is {child}, node_num is {self.node_num}")
            if self.nodes[child].visited == False:
                result += self.getSCC(child)
        return result
    
    # Kosaraju algorithm
    def getAllSCC(self):
        result = []
        finished = []
        self.setAllNodes(False)

        #use ida's cfg
        for i in range(self.node_num):
            if self.nodes[i].visited == False:
                self.DFSSCC(i , finished)

        self.invertEdges()
        self.setAllNodes(False)
        
        finished.reverse()
        for i in finished:
            if self.nodes[i].visited == False:
                result.append(self.getSCC(i))
            
        self.invertEdges()
        #just for debug
        '''
        for scc in result:
            print([x for x in scc])
        '''
        return result
    #-------------------------------------------------

    def getAllSimpleLoops(self, component):
        result = []
        #compute all backedge
        self.getOrder(True)
        #get all backedge head nodes 
        hnodes = []
        for e in self.edges:
            if e.backEdge == True and e.end not in hnodes:
                hnodes.append(e.end)
        
        cyclist  = self.getAllSimpleCyclePaths(component)
        for hnode in hnodes:
            if hnode in component:
                simplePaths = []
                for path in cyclist:
                    if hnode not in path:
                        continue
                    # find the hnode and hnode's cycle path
                    skip = False

                    # if other cycle's head node in this cycle path, skip it
                    for hn2 in hnodes:
                        if hn2 != hnode and hn2 in path:
                            skip = True
                            break
                    if skip == True:
                        continue

                    #if not include other cycle's head node    
                    simplePaths.append(path)
                
                if len(simplePaths) == 0:
                    continue
                loopParts = []
                loopParts.append(hnode)
                for path in simplePaths:
                    loopParts = Helper.ListUnion(loopParts, path)
                result.append(loopParts)
        return  result
    
    def getAllSimpleCyclePaths(self, component):
        result = []
        self.setAllNodes(False)

        for index in component:
            self.DFSSimpleCycles(component, index, index , [] , [] , [] , result)
            self.nodes[index].visited = True        
        self.setAllNodes(True)
        return result
    

    # don't understand it clearly
    def DFSSimpleCycles(self, component, sindex , index , stack, blocked, blockMap , result):
        foundCycle = False
        stack.append(index)
        blocked.append(index)
        childs = self.getChildren(index)
        for child in childs:
            if self.nodes[child].visited == False and child in component:
                if child == sindex:
                     result.append(copy.deepcopy(stack))
                     foundCycle = True
                else:
                    if child not in blocked and self.DFSSimpleCycles(component, sindex , child , stack, blocked , blockMap, result) ==True:
                        foundCycle =True

        if foundCycle == True:
            Helper.Unblock(index ,blocked, blockMap)
        else:
            for child in childs:
                if self.nodes[child].visited == False and child in component:
                    blockMap.append((index, child))        
        stack.remove(index)
        return foundCycle

    #-------------------------------------------------
    def getOrder(self, post):
        result = []
        self.setAllNodes(False)
        self.setAllEdges(False)
        for i in range(self.node_num):
            if self.nodes[i].visited == False:
                self.DFSOrder(i , [] , result, post)
        return result
    
    def DFSOrder(self , index , stack , result , post):
        self.nodes[index].visited = True
        if post == False : result.append(index)
        stack.append(index)
        childs = self.getChildren(index)
        for child in childs:
            if self.nodes[child].visited == False:
                self.DFSOrder(child, stack, result, post)
            else:
                if child in stack:
                    for e in self.edges:
                        if index == e.start and e.end == child and post:
                            e.backEdge = True 

        if post == True: result.append(index)
        stack.remove(index)     
    
    def getTopogicalOrder(self):
        result = []
        self.setAllNodes(False)
        while True:
            found = False
            for i in range(self.node_num):
                if self.nodes[i].visited  == False:
                    found2 = False
                    for e in self.edges:
                        if e.end == i and self.nodes[e.start].visited == False:
                            found2 = True
                            break
                    if found2 == False:
                        self.nodes[i].visited = True
                        result.append(i)
                        found = True
                        break
            if found == False:
                break 
        return result 

    #------------------------------------------------- 
    def getLoopInformation(self, loop):
        b = []
        h = LoopPart(loop[0], True)
        childs = self.getChildren(loop[0])    #handle header node
        exits =  []
        for child in childs:
            if child not in loop:
                h.isBreak = True
                if child not in exits: exits.append(child)
        
        #handle other nodes
        for i in range(1, len(loop)):
            childs = self.getChildren(loop[i])
            isContinue = False
            isBreak = False
            isTail = True
            for child in childs:
                if child == h.index:
                    isContinue = True
                else:
                    if child in loop:
                        isTail = False
                    else:
                        isBreak = True
                        if child not in exits: exits.append(child)
            
            hasOutsideEntry = False
            parents = self.getParents(loop[i])
            for p in parents:
                if p not in loop:
                    hasOutsideEntry = True
            b.append(LoopPart(loop[i], False, isTail , isBreak, isContinue, hasOutsideEntry))
        return Loop(h, b, len(exits)>1 )
    #------------------------------------------------- 

    def removeEdge(self, s, e):
        for e in self.edges:
            if e.start == s and e.end == e:
                self.edges.remove(e)
                break 
    
    def removeNode(self, index):
        #print(f"del nodes {index}, id is {self.nodes[index].id}")
        del self.nodes[index]

        '''
        for e in self.edges:
            if e.start == index  or e.end == index:
                self.edges.remove(e)
        '''
        #compare two code snippets and remember something
        i = 0 
        while i < len(self.edges):
            #print(i)
            if self.edges[i].start == index or self.edges[i].end == index:
                del self.edges[i]
                i-=1
            i+=1
            
        self.node_num = len(self.nodes)
        
        '''
        for i in range(self.node_num):
            if self.nodes[i].id >  index:
                self.nodes[i].id -=1 
        '''

        for e in self.edges:
            if e.start > index: e.start -=1
            if e.end > index:   e.end -=1 
    #------------------------------------------------- 
    # here is a algorithm to compute sese  
    # in real world, there is very few sese regions if no transform operations
    def getAllSESERegions(self):
        domTree = self.getDominatorTree(False)
        #print([hex(node.data.start_ea) for node in self.nodes])   
        #print(domTree.debugInfo())
        postDomTree = self.getDominatorTree(True)
        #print(postDomTree.debugInfo())
        result = []
        for i in range(self.node_num):
            for j in range(self.node_num):
                '''
                if i==0 and j==6:
                    print(Helper.ADominatesB(0, 1, domTree))
                    print(Helper.ADominatesB(i, j, domTree))
                    print(Helper.ADominatesB(j, i, postDomTree))
                    print(len(self.getChildren(j)))
                    print(len(self.getParents(i)))
                '''
                if i!=j and Helper.ADominatesB(i, j, domTree)  \
                        and Helper.ADominatesB(j, i, postDomTree) \
                        and len(self.getChildren(j)) < 2 \
                        and len(self.getParents(i)) < 2:
                    region = []
                    self.DFSRegionParts(i, region , j)
                    region.append(j)
                    result.append(region)
        return result
    
    def getDominatorTree(self, post = False):
        if post == True: self.invertGraph()
        postOrder = self.getOrder(True)
        if post == True: self.setAllEdges(False)
        tree = TreeNode("PostDominator Tree") if post == True else TreeNode("Dominator Tree")
        dominators = []
        
        for i in range(self.node_num):
            tmp = []
            for j in range(self.node_num):
                tmp.append(j)
            dominators.append(tmp)
        
        #just for debug
        '''
        for i in range(len(dominators)):
            print(f"{i} : {dominators[i]}")
        print("---------------------------------")
        '''  
        changed = True
        while changed:
            changed = False
            for current in postOrder :
                currDoms =  []
                pred = self.getParents(current)
                if len(pred) >  0:
                    currDoms = dominators[pred[0]]
                    for j in pred: 
                        currDoms = Helper.ListIntersection(currDoms, dominators[j])
                else: 
                    currDoms = []
                
                if current not in currDoms:
                    currDoms.append(current)
                if Helper.ListChanged(dominators[current], currDoms) == True :
                    dominators[current] = currDoms
                    changed = True

        #write test code
        if post == True:
            self.invertGraph()
            for i in range(len(dominators)):
                for j in range(len(dominators[i])):
                    dominators[i][j] = self.node_num - 1 - dominators[i][j]
        
        #just for debug
        '''
        for i in range(len(dominators)):
            print(f"{i} : {dominators[i]}")
        print("-------------------")
        '''
        for l in dominators:
            tree = Helper.AddPath(tree, l)
        return tree
    
    def DFSRegionParts(self, current, stack, end):
        if current in stack: return
        stack.append(current)
        childs = self.getChildren(current)
        for c in childs:
            if c!=end:
                self.DFSRegionParts(c, stack, end)

    #-------------------------------------------------
    #cut out all nodes in idxList to a new graph
    def getCutOut(self, idxList):
        result = graph()
        idxTrans = [-1 for _ in range(self.node_num)]
        for i in idxList:
            idxTrans[i] = result.node_num
            result.nodes.append(self.nodes[i])
            result.node_num +=1
        
        for e in self.edges:
            if e.start in idxList and e.end in idxList:
                copy = Edge(idxTrans[e.start], idxTrans[e.end], e.text)
                copy.backEdge = e.backEdge
                result.edges.append(copy)
        return result
    
    #-------------------------------------------------
    def isCyclic(self):
        white = []
        grey = []
        black = []
        for i in range(self.node_num):
            white.append(i)
        while len(white) > 0:
            if self.DFSCycleCheck(white[0], white, grey, black) == True:
                return True
        return False
    
    def DFSCycleCheck(self, current, white, grey, black):
        Helper.ListMoveIndex(current, white, grey)
        neighbours = self.getChildren(current)
        for i in neighbours:
            if i in black: continue
            if i in grey: return True
            if self.DFSCycleCheck(i, white, grey, black) == True: return True
        Helper.ListMoveIndex(current, grey, black)
        return False
    
    #--------------------------------------------------------------
    def getAllReachingPaths(self, idx):
        result = []
        self.DFSReachingPath(idx, 0, [], result)
        return result
    
    def DFSReachingPath(self, target, current, path, stack):
        path.append(current)
        childs = self.getChildren(current)
        for child in childs:
            npath = []
            npath += path  #add all node idx in path
            if child == target:
                npath.append(target)
                stack.append(npath)
                continue
            if child in path:
                continue
            self.DFSReachingPath(target, child, npath, stack)
        

          
if __name__ ==  "__main__":
    auto_wait()
    all_ea = []
    for segea in Segments():
        if get_segm_name(segea) == ".text":
            all_ea = [func for func in Functions(get_segm_start(segea), get_segm_end(segea))]
        
    #just for test
    #ea = 0x11550 #0x9130 #0x11550
    all_ea = [0x9130]
    
    for ea in all_ea:
        g = graph(ea)
        g.getAllSCC()
        # test dominator tree
        #tree = g.getDominatorTree()
        #print(tree.debugInfo())
        
        #test a dominator b
        #test getAllSESERegions
        #print(f"{hex(ea)} : ")
        print(g.getAllSESERegions())
    qexit(0)
