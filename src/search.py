import sys

import parser
from core.search import search
from core.filters import functionClassFilter
import vulndb

from utils import prettyText



def analyse(path):
    print prettyText("[*] Parsing Project at %s ..." % path,'blue')
    p = parser.PHPProject(path)
    print prettyText("[*] Parsing Completed !",'blue')

    print prettyText("[*] Searching for dangerous methods",'blue')
    for category in vulndb.A_F_ALL.keys():
        print prettyText("[**] Category: %s" % category,['yellow','bold'])
        for method in vulndb.A_F_ALL[category].keys():
            print prettyText("[***] Method: %s" % str(method),['yellow'])
            found = search(p,functionClassFilter,method)
            print parseFound(found,vulndb.A_F_ALL[category][method])


def searchMethod(path,method):
    print prettyText("[*] Parsing Project at %s ..." % path,'blue')
    p = parser.PHPProject(path)
    print prettyText("[*] Parsing Completed !",'blue')
    print prettyText("[***] Method: %s" % str(method),['yellow'])
    found = search(p,functionClassFilter,method)
    print parseFound(found,"Custom")


def parseFound(found, params):
    output = ''
    for k in found.keys():
        for l in found[k]:
            output = output + prettyText(k,'magenta') + prettyText(':','cyan') + prettyText(l.lineno, 'green') + prettyText(': ','cyan') + prettyText(l, 'white') + prettyText(str(params),'red') + '\n'

    return output


def usage():
    u =  "%s <PHP_Project_Path>" % sys.argv[0]
    u += "<PHP_Project_Path> <Method_Name>"
    return u


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print prettyText(usage(),'blue')
    else:
        #analyse(sys.argv[1])
        project = sys.argv[1]
        method = sys.argv[2]
        searchMethod(project, method)
