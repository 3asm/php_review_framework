import sys

import parser
from core.search import search
from core.filters import functionMethodFilter

from utils import prettyText



def analyse(path, method):
    print prettyText("[*] Parsing Project at %s ..." % path,'blue')
    p = parser.PHPProject(path)
    print prettyText("[*] Parsing Completed !",'blue')

    print prettyText("[*] Searching for calls to %s" % method,'blue')
    found = search(p,functionMethodFilter,method)
    print parseFound(found)
    


def parseFound(found):
    output = ''
    for k in found.keys():
        for l in found[k]:
            output = output + prettyText(k,'magenta') + prettyText(':','cyan') + prettyText(l.lineno, 'green') + prettyText(': ','cyan') + prettyText(l, 'white') + '\n'

    return output


def usage():
    u =  "%s <PHP_Project_Path> <Method/Function Name>" % sys.argv[0]
    return u


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print prettyText(usage(),'blue')
    else:
        analyse(sys.argv[1], sys.argv[2])
