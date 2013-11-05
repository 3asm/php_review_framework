import parser
from core.ast import *
import sys

path = sys.argv[1]

f = parser.PHPFile(path)
f.printAST()
f.printCode()
'''
n = f.parsed_content[1].node.nodes[0]
print n
print getUID(n,f.parsed_content)
uid =  [1,0,0,0]
#print getNodeByUID(uid, f.parsed_content)
parent = getParent(n, f.parsed_content)
print parent
granparent = getParent(parent, f.parsed_content)
print granparent
grangranparent = getParent(granparent, f.parsed_content)
print grangranparent
gran3parent = getParent(grangranparent, f.parsed_content)
print gran3parent
gran4parent = getParent(gran3parent, f.parsed_content)
print gran4parent
'''