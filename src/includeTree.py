import parser
from core.ast import *
import sys
import taint.taint
import os

projectPath = os.path.abspath(sys.argv[1])
#projectPath = '/home/asm/exp/2.web/cms_source_code/wordpress/'

print "[*] Project Path: %s" % projectPath
project = parser.PHPProject(projectPath)

treeInc = dict()

for k in project.pages.keys():
    print "[*] Analysing '%s'" % str(k)
    p = project[k]
    lst = taint.taint.resolveInclude(project, p)
    lstName = []
    for l in lst:
        lstName.append(l.file_name.replace(project.folder_name, '',1))
        
    treeInc[k] = lstName
    
print "[+] Done"
#print treeInc


try:
    import pydot
    
    graph = pydot.Dot(graph_type='digraph')
    print "[*] Generating SVG Graph ..."
    
    #add nodes
    for k in treeInc:
        #print str(k)
        if treeInc[k] == []:
            node = pydot.Node(k, style="filled", fillcolor="red")
        else:
            node = pydot.Node(k)
        graph.add_node(node)
        
    #add edges   
    for k in treeInc:
        for e in treeInc[k]:
            #print "\t\t-- %s" % str(e)
            graph.add_edge(pydot.Edge(k, e))
    
    graph.write_svg("/tmp/treeInc.svg")
    print "[+] SVG created, open /tmp/treeInc.svg"
    
    
except ImportError:
    print "[-] Error: Pydot not installed"
    print "[-] try: apt-get install python-pydot"
    exit()





