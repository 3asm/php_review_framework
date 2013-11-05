import core
import parser
import vulndb

import phply.phpast
from utils import prettyText



class TaintSymbolTable():

    symbolTable = dict()

    def __init__(self,userInputParams = vulndb.V_USERINPUT):
        self.userInputParams = userInputParams
        if self.userInputParams != vulndb.V_USERINPUT:
            for p in self.userInputParams.keys():
                self.symbolTable[phply.phpast.Variable(p.name)] = 1
        #print prettyText("[GTST] User Params: '%s'" % self.userInputParams,'yellow')
        #print self.symbolTable

    def addElement(self,blob):
        if blob in self.symbolTable.keys():
            #print "[*] (%s) is in Taint Symbol Table" % blob
            pass
        else:
            blob.lineno = 0
            if isinstance(blob, phply.phpast.ArrayOffset):
                #if isinstance(blob.node,core.Variable) and isinstance(blob.node.name,str):
                if isinstance(blob.node,phply.phpast.Variable):
                    if  blob.node.name in [v for v in self.userInputParams if self.userInputParams[v] == 'ANY']:
                        if not blob.node in self.symbolTable.keys():
                            blob.node.lineno = 0
                            self.symbolTable[blob.node] = 1
                    elif blob.node.name in [v for v in self.userInputParams if self.userInputParams[v] == 'DEP' ]:
                        self.symbolTable[blob] = 1
                        blob.node.lineno = 0
                        self.symbolTable[blob.node] = 1
                    elif blob.node.name in [v for v in self.userInputParams if self.userInputParams[v] != 'ANY' ] and blob.expr in self.userInputParams[blob.node.name]:
                        self.symbolTable[blob] = 1
                        blob.node.lineno = 0
                        self.symbolTable[blob.node] = 1
                    else:
                        self.symbolTable[blob] = 0
                else:
                    self.symbolTable[blob] = 0
            elif isinstance(blob, phply.phpast.Variable):
                if blob.name in self.userInputParams:
                    self.symbolTable[blob] = 1
                else:
                    self.symbolTable[blob] = 0



    def addAssignment(self,blob):
        #print prettyText("[GTST] Assign: '%s' = '%s'" % (str(blob.node), str(blob.expr)),'blue')
        nodes = core.search.search(blob.node,core.filters.classFilter,vulndb.T_VARS)
        exprs = core.search.search(blob.expr,core.filters.classFilter,vulndb.T_VARS)

        #TODO: still need to implement function assignment
        #functions = core.search.search(blob.expr,core.filters.classFilter,phply.phpast.FunctionCall)
        #print prettyText("==+==",'red')
        #print "Nodes: %s" % str(nodes)
        #print "Exprs: %s" % str(exprs)

        if nodes != None and exprs != None:
            for v in nodes:
                for e in exprs:
                    try:
                        #if v in symbol table, else do nothing
                        if self.inSymbolTable(v):
                            v2 = self.inSymbolTable(v)
                            #if e in symbol table, propagate tain
                            if self.inSymbolTable(e):
                                e2 = self.inSymbolTable(e)
                                #propagate direct taint
                                self.symbolTable[v2] += self.symbolTable[e2]
                                #propagate taint for elements of array
                                if isinstance(v, phply.phpast.ArrayOffset):
                                    if self.inSymbolTable(v.node):
                                        v3 = self.inSymbolTable(v.node)
                                        self.symbolTable[v3] += self.symbolTable[v2]

                            elif isinstance(e, phply.phpast.ArrayOffset):
                                if self.inSymbolTable(e.node):
                                    e2 = self.inSymbolTable(e.node)
                                    self.symbolTable[v2] += self.symbolTable[e2]
                                    if isinstance(v, phply.phpast.ArrayOffset):
                                        if self.inSymbolTable(v.node):
                                            v3 = self.inSymbolTable(v.node)
                                            self.symbolTable[v3] += self.symbolTable[v2]

                            else:
                                
                                print prettyText("Case 3", 'red')
                                print self
                            
                    except KeyError, e:
                        ###TODO correct this !!!
                        #print "[GTST] v: %s |||| v.node: %s" % (str(v),str(v.node))
                        print prettyText("[-] Key Error (Unexpected error, Bug) :%s" % str(e),['red','bold'])
        #at the end, push taint to elements of an array
        for elmt in self.symbolTable:
            if isinstance(elmt, phply.phpast.Variable):
                for elmt2 in self.symbolTable:
                    if isinstance(elmt2, phply.phpast.ArrayOffset):
                        if elmt2.node == elmt:
                            self.symbolTable[elmt2] += self.symbolTable[elmt]



    def inSymbolTable(self,blob):
        #prepare element to compare
        elmtB = blob
        elmtB.lineno = 0
        for elmt in self.symbolTable:
            if elmt == elmtB:
                return elmt
            

    def getTaint(self,blob):
        if blob in self.symbolTable.keys():
            blob.lineno = 0
            for k in self.symbolTable:
                if k == blob:
                    return self.symbolTable[k]
            #weird bug here
            #return self.symbolTable[blob]
        elif isinstance(blob,phply.phpast.ArrayOffset) and blob.node in self.symbolTable:
            return self.symbolTable[blob.node]
        else:
            #print "[-] %s not in Taint Symbol Table" % str(blob)
            pass


    def __str__(self):
        a = ''
        for v in self.symbolTable:
            
            if self.symbolTable[v] == 0:
                hilight_color = ['red']
            else:
                hilight_color = ['red', 'bold']
            
            #variables
            if isinstance(v, phply.phpast.Variable):
                try:
                    name = v.name
                    a += prettyText("[*] " + str(name) + " (Variable): ",['cyan'])+prettyText(str(self.symbolTable[v]) + "\n",hilight_color)
                except AttributeError:
                    #weir variables
                    name = v
                    a += prettyText("[*] " + str(name) ,['cyan']) + prettyText(" (Variable_complex): ",['yellow'])+prettyText(str(self.symbolTable[v]) + "\n",hilight_color)
            
            #arrays
            elif isinstance(v, phply.phpast.ArrayOffset):
                try:
                    name = v.node.name
                    a += prettyText("[*] " + str(name) + "[" + str(v.expr) + "] (ArrayOffset): ",['cyan','bold'])+prettyText(str(self.symbolTable[v]) + "\n",hilight_color)
                except AttributeError:
                    #complicated arrays
                    name = v
                    a += prettyText("[*] " + str(name),['cyan','bold']) + prettyText(" (ArrayOffset_Complex): ",['yellow','bold']) + prettyText(str(self.symbolTable[v]) + "\n",hilight_color)
        return a
