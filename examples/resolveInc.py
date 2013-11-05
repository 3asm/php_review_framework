import parser
from core.ast import *
import sys
import taint.taint

#python resolveInc.py '/home/asm/Documents/Aptana Studio 3 Workspace/code_review_framework/samples/phpMyAdmin-3.5.2.2-english' '/libraries/export/odt.php'
projectPath = sys.argv[1]
filePath = sys.argv[2]
print "[+] Project Path: %s" % projectPath
print "[+] File Path: %s" % filePath
project = parser.PHPProject(projectPath)
file = project.pages[filePath]


lstFiles =  taint.taint.resolveInclude(project, file)
for l in lstFiles:
    print l.file_name