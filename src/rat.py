import sys
import os
import argparse


import parser
from core.search import search
from core.filters import functionClassFilter, classFilter, functionFilter
import vulndb
from taint.taint import *

import phply

from utils import prettyText



def analyse(path):
    print prettyText("[*] Parsing Project at %s ..." % path,'blue')
    p = parser.PHPProject(path)
    print prettyText("[*] Parsing Completed !",'blue')

    '''
    print prettyText("[*] Searching for dangerous methods",'blue')
    for category in vulndb.A_F_ALL.keys():
        print prettyText("[**] Category: %s" % category,['yellow','bold'])
        for method in vulndb.A_F_ALL[category].keys():
            print prettyText("[***] Method: %s" % str(method),['yellow'])
            found = search(p,functionClassFilter,method)
            print parseFound(found,vulndb.A_F_ALL[category][method])
    '''    
    print prettyText("[*] Searching for dangerous methods inheritence",'blue')
    files = search(p,classFilter, phply.phpast.Function) 
    for name in files:
        print prettyText('[*] File: %s' % name,['yellow','bold'])
        functions = files[name]
        #print functions
        for l in functions:
            paramsList = search(l,classFilter, phply.phpast.FormalParameter)
            functionInputParams = dict()
            for p in paramsList:
                functionInputParams[p] = "ANY"
                
            #print functionInputParams
            tst = generateTST(l,functionInputParams)
            #print tst
            
            #search a method and propagate taint
            for kcat in vulndb.A_F_ALL.keys():
                cat = vulndb.A_F_ALL[kcat]
                #print prettyText('[*] Category: %s' % kcat,'red')
                for e in cat:
                    #print prettyText('[*] Method: %s' % str(e),'blue')
                    functions = search(l, functionFilter, e)
                    #print '-'*5
                    for f in functions:
                        for pos in cat[e]:
                            try:
                                #print prettyText('[*] FOUND : ' + str(f.params[pos].node) + ':' + str(tst.getTaint(f.params[pos].node)), 'green')
                                if tst.getTaint(f.params[pos].node) > 0:
                                    print '-'*5
                                    print prettyText('[*] Category: %s' % kcat,'red')
                                    print prettyText('[*] Method: %s' % str(e),'blue')
                                    print prettyText("[+] FOUND: %s" % str(l.name), 'green')
                                    print '-'*5
                            except IndexError, AttributeError:
                                print prettyText('[!] ERROR: %s' % str(f), 'red')
                    #print '-'*5




def parseFound(found, params):
    output = ''
    for k in found.keys():
        for l in found[k]:
            output = output + prettyText(k,'magenta') + prettyText(':','cyan') + prettyText(l.lineno, 'green') + prettyText(': ','cyan') + prettyText(l, 'white') + prettyText(str(params),'red') + '\n'

    return output


def usage():
    u =  "%s <PHP_Project_Path>" % sys.argv[0]
    return u


if __name__ == '__main__':
    
    parser = argparse.ArgumentParser()
    
    
    if len(sys.argv) < 2:
        print prettyText(usage(),'blue')
    else:
        analyse(os.path.abspath(sys.argv[1]))
