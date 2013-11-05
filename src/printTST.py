import parser
from core.ast import *
import phply
from core.search import search
from core.filters import classFilter, functionFilter
from taint.taint import *
import sys
import os
import vulndb

# p = "/home/asm/Documents/Aptana Studio 3 Workspace/code_review_framework/samples/webERP/CopyBOM.php"
path = os.path.abspath(sys.argv[1])
# path = os.path.abspath(p)



f = parser.PHPFile(path)
functions = search(f,classFilter, phply.phpast.Function) 
#print functions
for l in functions:
    paramsList = search(l,classFilter, phply.phpast.FormalParameter)
    functionInputParams = dict()
    for p in paramsList:
        functionInputParams[p] = "ANY"
        
    print functionInputParams
    tst = generateTST(l,functionInputParams)
    print tst
    
    #search a method and propagate taint
    for kcat in vulndb.A_F_ALL.keys():
        cat = vulndb.A_F_ALL[kcat]
        print prettyText('[*] Category: %s' % kcat,'red')
        for e in cat:
            print prettyText('[*] Method: %s' % str(e),'blue')
            functions = search(l, functionFilter, e)
            print '-'*5
            for f in functions:
                for pos in cat[e]:
                    print str(f.params[pos].node) + ':' + str(tst.getTaint(f.params[pos].node))
                    if tst.getTaint(f.params[pos].node) > 0:
                        print prettyText("[+] FOUND: %s" % str(l.name), 'green')
            print '-'*5
    
    
    
    print "="*10
