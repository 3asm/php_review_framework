import parser
from core.ast import *
from taint.taint import *
import sys
import os

#p = "/home/asm/Documents/Aptana Studio 3 Workspace/code_review_framework/samples/webERP/CopyBOM.php"
path = os.path.abspath(sys.argv[1])
#path = os.path.abspath(p)



f = parser.PHPFile(path)
tst = generateTST(f)
print tst
