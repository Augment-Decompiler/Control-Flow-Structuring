#coding:utf-8
from  graph import *
from ABSBlock import *
from ACSESERegion import *
from mc import *
from ContextFree import *

class Decompiler:
    def __init__(self , ea) -> None:
        self.func = get_func(ea)
        self.func_ea = ea
        self.graph = graph(ea)
        self.reductionCounter = 1
        self.reductionLog = ""
    
    def LogReduction(self, a):
        self.reductionLog += f"{self.reductionCounter}  : {a} \n"
        self.reductionCounter +=1

    def FindSimpleLoops(self):
        SCCs = self.graph.getAllSCC()
        gLoops = []  #List of Class Loop
        for component in SCCs :
            if len(component) > 1: # discussion the node >=2 
                loops = self.graph.getAllSimpleLoops(component)
                for loop in loops:
                    gLoops.append(self.graph.getLoopInformation(loop))
        order = self.graph.getOrder(True)
        
        #just for debug
        '''
        print(loops)
        print(gLoops[0].debugInfo())
        '''
        for idxHead in order:
            for loop in gLoops:
                #sese loop region and only have a body node 
                if loop.header.index == idxHead and loop.isMultiExit == False and len(loop.body) ==1 and loop.body[0].hasOutsideEntry == False:
                    idxTail = loop.body[0].index
                    abs = ABSBlock()
                    #if header node is break,then is while 
                    if loop.header.isBreak:
                        childs = self.graph.getChildren(idxTail)
                        if len(childs)!=1: 
                            abs2 = ABSBlock(absType.BREAK)
                            for child in childs:
                                if child != idxHead: # break
                                    self.graph.removeEdge(idxTail, child)

                            abs2.data = self.graph.nodes[idxTail].data
                            self.graph.nodes[idxTail].data = abs2
                            self.LogReduction("Break Reduction : " + str(idxTail))
                        abs = ABSBlock(absType.WHILE)
                        self.LogReduction("While Reduction : " + str(idxHead) + "<-" + str(idxTail))

                    else: #do while
                        childs = self.graph.getChildren(idxTail)
                        if len(childs) !=2: #thin about it     1 infinite loop   >2 not discussion
                            continue
                        for child in childs:
                            if child != idxHead:
                                self.graph.edges.append(Edge(idxHead, child , "branch"))
                        abs = ABSBlock(absType.DOWHILE)
                        self.LogReduction("Do-While Reduction : " + str(idxHead) + " <-" + str(idxTail))
                    
                    tmp = [self.graph.nodes[idxHead].data, self.graph.nodes[idxTail].data]
                    abs.data = tmp
                    self.graph.nodes[idxHead].data = abs
                    self.graph.removeNode(idxTail)
                    return True    
        return False
    
    def FindSimpleWhile(self):
        order = self.graph.getOrder(True)
        for idx in order:
            childs = self.graph.getChildren(idx)
            if len(childs) ==2 and idx in childs:   
                j = 0
                while j < len(self.graph.edges):
                    if self.graph.edges[j].start == idx and self.graph.edges[j].end == idx:
                        del self.graph.edges[j]
                        break
                abs = ABSBlock(absType.SIMPLEWHILE)
                abs.data = self.graph.nodes[idx].data
                self.graph.nodes[idx].data = abs
                self.LogReduction("Simple While Reduction: " + str(idx))
                return True
        return False
    
    def FindSequences(self):
        order = self.graph.getOrder(True)
        for idx in order:
            childs = self.graph.getChildren(idx)
            if len(childs)==1 and childs[0]!=idx:
                idx2 = childs[0]
                childs2 = self.graph.getChildren(idx2)
                parents2 = self.graph.getParents(idx2)
                if len(parents2)==1 and len(childs2) < 2:
                    if len(childs2)==1 and (childs2[0] == idx or childs2[0] == idx2):
                        continue
                    abs = ABSBlock(absType.SEQUENCE)
                    tmp = [self.graph.nodes[idx].data, self.graph.nodes[idx2].data]
                    abs.data = tmp
                    if len(childs2) == 1:
                        for e in self.graph.edges:
                            if e.start == idx2:
                                e.start = idx 
                    self.graph.nodes[idx].data = abs
                    self.graph.removeNode(idx2)
                    self.LogReduction("Sequences Reduction: " + str(idx ) + "<-" + str(idx2))
                    return True
        return False        

    def FindIfThen(self):
        order = self.graph.getOrder(True)
        for idxHead in order:
            idxThen = idxAfter = -1
            childs = self.graph.getChildren(idxHead)
            if len(childs) == 2: #have two child
                parents0 = self.graph.getParents(childs[0])
                parents1 = self.graph.getParents(childs[1])
                if len(parents0) == 1:  
                    tmp = self.graph.getChildren(childs[0])
                    if len(tmp)==1 and tmp[0]== childs[1]:
                        idxThen = childs[0]
                        idxAfter = childs[1]
                else:
                    if len(parents1) == 1:
                        tmp = self.graph.getChildren(childs[1])
                        if len(tmp)==1 and tmp[0]== childs[0]:
                            idxThen = childs[1]
                            idxAfter = childs[0]
                
                if idxAfter!=-1 and idxThen!=-1 and idxAfter!=idxHead:
                    abs = ABSBlock(absType.IFTHEN)
                    tmp = [self.graph.nodes[idxHead].data, self.graph.nodes[idxThen].data]
                    abs.data = tmp
                    self.graph.nodes[idxHead].data = abs
                    self.graph.removeNode(idxThen)
                    self.LogReduction("If-Then Reduction: " + str(idxHead) + "<-" + str(idxThen))
                    return True
        return False
    
    def FindIfThenElse(self):
        order = self.graph.getOrder(True)
        for idxHead in order:
            idxThen = idxElse = idxAfter = -1
            childs = self.graph.getChildren(idxHead)
            if len(childs)==2 :
                parents0 = self.graph.getParents(childs[0])
                parents1 = self.graph.getParents(childs[1])
                childs0 = self.graph.getChildren(childs[0])
                childs1 = self.graph.getChildren(childs[1])
                if len(parents0)==1 and len(parents1)==1 and len(childs0)==1 and len(childs1)==1 and childs0[0] == childs1[0]:
                    for e in self.graph.edges:
                        if e.start == idxHead and e.end == childs[0]:
                            if e.text == "true":
                                print("found true")
                                idxThen  = childs[0]
                                idxElse  = childs[1]
                                idxAfter = childs0[0]
                            else:
                                idxThen  = childs[1]
                                idxElse  = childs[0]
                                idxAfter = childs0[0]
                            break 
                    
                    if idxAfter != -1 and idxThen != -1 and idxElse != -1 and idxAfter != idxHead :
                        abs = ABSBlock(absType.IFTHENELSE)
                        tmp = [self.graph.nodes[idxHead].data, self.graph.nodes[idxThen].data, self.graph.nodes[idxElse].data]
                        abs.data = tmp
                        self.graph.nodes[idxHead].data = abs
                        self.graph.edges.append(Edge(idxHead, idxAfter, "branch"))
                        if idxThen > idxElse:
                            self.graph.removeNode(idxThen)
                            self.graph.removeNode(idxElse)
                        else:                             
                            self.graph.removeNode(idxElse)
                            self.graph.removeNode(idxThen)
                        self.LogReduction("If-Then-Else Reduction: " + str(idxHead) + "<-" + str(idxThen) + ", " + str(idxHead) + "<-" + str(idxElse))
                        return True
                
                # here I don't think it's a good idea
                if len(parents0) == 1 and len(parents1) == 1 and len(childs0) == 0 and len(childs1) == 0:
                    for e in self.graph.edges:
                        if e.start == idxHead and e.end == childs[0]:
                            if e.text == "true":
                                print("found true again")
                                idxThen  = childs[0]
                                idxElse  = childs[1]
                            else:
                                idxThen  = childs[1]
                                idxElse  = childs[0]
                            break 
                    
                    if  idxThen != -1 and idxElse != -1:
                        abs = ABSBlock(absType.IFTHENELSE)
                        tmp = [self.graph.nodes[idxHead].data, self.graph.nodes[idxThen].data, self.graph.nodes[idxElse].data]
                        abs.data = tmp
                        self.graph.nodes[idxHead].data = abs
                        if idxThen > idxElse:
                            self.graph.removeNode(idxThen)
                            self.graph.removeNode(idxElse)
                        else:                             
                            self.graph.removeNode(idxElse)
                            self.graph.removeNode(idxThen)
                        self.LogReduction("If-Then-Else Reduction: " + str(idxHead) + "<-" + str(idxThen) + ", " + str(idxHead) + "<-" + str(idxElse))
                        #print("???")
                        return True
        return False
    
    def FindLoopParts(self):
        SCCs = self.graph.getAllSCC()
        gLoops = []
        for component in SCCs:
            if len(component) > 1:
                loops = self.graph.getAllSimpleLoops(component)
                for loop in loops:
                    gLoops.append(self.graph.getLoopInformation(loop))
        
        order = self.graph.getOrder(True)
        for idx in order:
            for loop in gLoops:
                if loop.isMultiExit == False:
                    for part in loop.body:
                        if part.index == idx:
                            #need to think carefully
                            #idx is continue body
                            if part.hasOutsideEntry == False and part.isTail == False and part.isHeader == False and part.isContinue == True and part.isBreak == False:
                                childs = self.graph.getChildren(idx)
                                if len(childs) != 2: break   #why? because isTail is False
                                for j in range(len(self.graph.edges)):
                                    if self.graph.edges[j].start == idx and self.graph.edges[j].end == loop.header.index:
                                        del self.graph.edges[j]
                                        break
                                abs = ABSBlock(absType.CONTINUE)
                                abs.data = self.graph.nodes[idx].data
                                self.graph.nodes[idx].data = abs
                                self.LogReduction("Continue Reduction: " + str(idx))
                                return True
                            
                            #idx is break body
                            if part.hasOutsideEntry == False and part.isTail == False and part.isHeader == False and part.isContinue == False and part.isBreak == True:
                                childs = self.graph.getChildren(idx)
                                if len(childs) != 2: break   #why? because isTail is False
                                isFirst = False
                                for part2 in loop.body:
                                    if part2.index == childs[0]: #childs[0] in loop and childs[1] not
                                        isFirst = True
                                        break
                                if isFirst == True:
                                    for j in range(len(self.graph.edges)):
                                        if self.graph.edges[j].start == idx and self.graph.edges[j].end == childs[1]:
                                            del self.graph.edges[j]
                                            break
                                else:
                                    for j in range(len(self.graph.edges)):
                                        if self.graph.edges[j].start == idx and self.graph.edges[j].end == childs[0]:
                                            del self.graph.edges[j]
                                            break
                                abs = ABSBlock(absType.BREAK)
                                abs.data = self.graph.nodes[idx].data
                                self.graph.nodes[idx].data = abs
                                self.LogReduction("Break Reduction: " + str(idx))
                                return True
        return False
    
    def FindACSESERegions(self):
        regions = self.graph.getAllSESERegions()
        for i in range(len(regions)):
            containerOther = False
            for j in range(len(regions)):
                if i!=j and Helper.ListContained(regions[j], regions[i]):
                    containerOther = True
                    break
            if containerOther == True: continue

            #cut subgraph that is sese regions and no containerOther
            gr = self.graph.getCutOut(regions[i])
            #print(f"the subgraph is a cycle : {gr.isCyclic()}")
            if gr.isCyclic() == True: continue #no hanlde cycle in sese region
            gr.nodes[0] = Node(gr.nodes[0].data, gr.nodes[0].id)  
            abs = ABSBlock(absType.ACSESEREGION)
            abs.data = ACSESERegion(gr)
            self.graph.nodes[regions[i][0]].data = abs
            first = regions[i][0]
            last = regions[i][len(regions[i])-1]
            if len(self.graph.getChildren(last)) > 0:
                self.graph.edges.append(Edge(regions[i][0], self.graph.getChildren(last)[0], "branch"))
            del regions[i][0]
            regions[i].sort(reverse = True)
            for j in regions[i]:
                self.graph.removeNode(j)
            self.LogReduction("ACSESE Region Reduction: " + str(first) + "<-" + str(last))
            return True
        return False

    #--------------------------------------------------------------
    def SimplefyGraph(self):
        found = True
        while found == True:
            found = False
            if self.FindSimpleWhile()== True: 
                found = True
                #print(self.reductionLog)
            if self.FindSequences() == True: 
                found = True
                #print(self.reductionLog)
            if self.FindIfThen() == True: 
                found = True
                #print(self.reductionLog)
            if self.FindIfThenElse() == True: 
                found = True
                #print(self.reductionLog)
            if self.FindLoopParts() == True: 
                found = True
                #print(self.reductionLog) 
            if self.FindSimpleLoops() == True: 
                found = True
                #print(self.reductionLog)
            if found == False and self.FindACSESERegions() == True: 
                found = True
                #print("find sese ")
                #print(self.reductionLog)
    
    def CompileOut(self):
        sb = ""
        sb += f"void {get_func_name(self.func_ea)}() \n"
        sb += "{\n\t"
        p =  self.PrintBlock(self.graph.nodes[0].data)
        sb += p.pp()
        sb += "\n}\n"
        #print(p.debugInfo())
        return sb
    
    def CompileOutNoSESE(self):
        sb = ""
        sb += f"void {get_func_name(self.func_ea)}() \n"
        sb += "{\n\t"
        for i in range(len(self.graph.nodes)):
            sb += "\n\t" + f"node [{i}] :\n\t"
            p =  self.PrintBlock(self.graph.nodes[i].data)
            sb += p.pp()
        sb += "\n}\n"
        #print(p.debugInfo())
        return sb

    #--------------------------------------------------------------
    def PrintBlock(self, data):
        p = Program()
        if isinstance(data, ABSBlock):
            p.states += self.PrintAbsBlock(data)
            
        if isinstance(data, Mblock):
            p.states.append(self.PrintCodeBlock(data))
        return p
    
    def PrintAbsBlock(self, block):
        s = []
        if block.type == absType.SEQUENCE:
            l = block.data
            assert(len(l)==2)
            p1 = self.PrintBlock(l[0])
            p2 = self.PrintBlock(l[1])
            s.append(SequenceState(p1, p2))

        if block.type == absType.SIMPLEWHILE:
            var = self.PrintCodeBlock(block.data)
            #var.isVar()
            s.append(SimpleWhileState(var))

        if block.type == absType.BREAK:
            var = self.PrintCodeBlock(block.data)
            #var.isVar()
            s.append(BreakState(var))

        if block.type == absType.CONTINUE:
            var = self.PrintCodeBlock(block.data)
            #var.isVar()
            s.append(ContinueState(var))

        if block.type == absType.IFTHEN:
            l = block.data
            assert(len(l)==2)
            var = self.PrintCodeBlock(l[0])
            #print("debug:")
            #print(var.pp())
            p = self.PrintBlock(l[1])
            s.append(IFUniState(var, p))

        if block.type == absType.IFTHENELSE:
            l = block.data
            assert(len(l)==3)
            var = self.PrintCodeBlock(l[0])
            #var.isVar()
            p1 = self.PrintBlock(l[1])
            p2 = self.PrintBlock(l[2])
            s.append(IFBinState(var, p1 ,p2))
            
        if block.type == absType.WHILE:
            l = block.data
            assert(len(l)==2)
            var = self.PrintCodeBlock(l[0])
            #var.isVar()
            p1 = self.PrintBlock(l[1])
            s.append(WhileState(var, p1))
            
        if block.type == absType.DOWHILE:
            l = block.data
            assert(len(l)==2)
            var = self.PrintCodeBlock(l[1])
            #var.isVar()
            p1 = self.PrintBlock(l[0])
            s.append(DoWhileState(var, p1))

        if block.type == absType.ACSESEREGION:
            p1 = self.PrintACSESEBlock(block)
            s += p1.states
        return s
    
    def PrintCodeBlock(self, block): 
        return BlockState(block.id)

    def PrintACSESEBlock(self, block):
        result = Program()
        region = block.data #ACSESERegion(block.data)
        gr = region.graph
        order = gr.getTopogicalOrder()
        for i in range(len(order)-1):
            idx = order[i]
            if idx in region.codeNodes: 
                paths = gr.getAllReachingPaths(idx)
                var = BaseState() 
                # var = ""
                if len(paths) == 1:
                    var.token_list += [self.ConditionPathToExpression(paths[0], region)]
                else:
                    for path in paths:
                        if len(var.token_list)!=0:
                            #var += str(token('s', " || "))
                            #var += str(token('n'))
                            var.token_list +=  [token('s', " || ")]
                        #var += str(token('s', "(")) + self.ConditionPathToExpression(path, region) + str(token('s', ")"))
                        var.token_list += [self.ConditionPathToExpression(path, region)]
                p1 = self.PrintBlock(gr.nodes[idx].data)
                result.states.append(IFUniState(var,p1))
                
        p2 = self.PrintBlock(region.graph.nodes[order[len(order)-1]].data) #handle last node
        result.states += p2.states
        return result
    
    def ConditionPathToExpression(self, path, region):
        sb = ""
        for i in range(len(path)-1):
            if path[i] in region.decNodes and path[i+1] in region.codeNodes:
                cond = False
                for e in region.graph.edges:
                    if e.start == path[i] and e.end == path[i+1]:
                        cond = (e.text == "true")
                        break
                if len(sb)!=0: sb+=" && "
                tmp = "" if cond == True else "!"
                sb += tmp + "Block" + str(region.graph.nodes[path[i]].data.id)
        return token('s', sb)

if __name__ == "__main__":
    auto_wait()
    all_ea = []
    for segea in Segments():
        if get_segm_name(segea) == ".text":
            all_ea = [func for func in Functions(get_segm_start(segea), get_segm_end(segea))]

    #f0c0 is a good example
    all_ea = [0x11380]#[0x91a0] #[0xf1a0]
    #test 2 for test all simplefygraph function
    for ea in all_ea:
        d = Decompiler(ea)
        print("----------------------------")   
        d.SimplefyGraph()
        print(d.reductionLog)
        if  len(d.graph.nodes) > 1:
            print(f"After SimplefyGraph , node's number is {len(d.graph.nodes)}")
            print("[-] Reduction have bugs!!!\n")
            res = d.CompileOutNoSESE()
            print(res)
        else:
            res  = d.CompileOut()
            print(res)
    qexit(0)





