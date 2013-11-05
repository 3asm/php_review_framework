import parser
from core.ast import *
import sys
import taint.taint

path = sys.argv[1]

f = parser.PHPFile(path)
#f.printAST()
f.printCode()
tst = taint.taint.generateTST(f.parsed_content)
print tst