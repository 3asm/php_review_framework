import core.search
import core.filters
import parser
import vulndb
from tst import TaintSymbolTable
from utils import prettyText
import utils

import phply
import os



def generateTST(context_tree, userInputParams = None):

    s_var =  core.search.search(context_tree,core.filters.classFilter,vulndb.T_VARS)
    s_assignment =  core.search.search(context_tree,core.filters.classFilter,phply.phpast.Assignment)
    
    '''
    print prettyText("[GTST] Variables :",'yellow')
    for l in s_var:
        print prettyText("\t[GTST] %s" % str(l),'yellow')
    print prettyText("[GTST] Assignments :", 'magenta')
    for l in s_assignment:
        print prettyText("\t[GTST] %s" % str(l), 'magenta')
    '''
    #TODO:taint doesnt test for filtering functions
    if not userInputParams:
        tst = TaintSymbolTable()
    else: 
        tst = TaintSymbolTable(userInputParams)

    #print prettyText("[GTST] Adding Variables",'green')
    for v in s_var:
        #print prettyText("[GTST] Adding %s" % str(v),['yellow','bold'])
        tst.addElement(v)

    #print prettyText("[+GTST] Final Taint Symbol Table",'white')
    #print tst
    
    #print prettyText("[GTST] Adding Assignments", ['blue','bold'])
    for a in s_assignment:
        #print prettyText("[GTST] Assignment %s" % str(a), 'cyan')
        tst.addAssignment(a)

    #print  prettyText("[+GTST] Final Taint Symbol Table",'white')
    #print tst

    return tst





#TODO:replace error messages with exceptions
#TODO:implement logger for debugging
def resolveInclude(project,page):
    """
    This function returns all pages that are included in page, search is done in project
    """
    #extract include and require statements
    listInc = core.search.search(page,core.filters.classFilter,[phply.phpast.Include,phply.phpast.Require])

    currentPageName = page.file_name.replace(project.folder_name,'')
    currentDirName = os.path.dirname(currentPageName)

    # return page list
    incPageList = []

    for blob in listInc:
        fileName = blob.expr

        if type(fileName) is str:
            
            if fileName.startswith('.'):
                fileName = fileName[1:]
    
            if not fileName.startswith('/'):
                fileName = '/' + fileName
             
            realFileName = os.path.join( currentDirName, fileName.split('/')[-1])
            
            if realFileName in project.pages.keys():
                print prettyText("[+] Found %s (%s)" % (fileName, realFileName), 'green')
                incPageList.append(project.pages[realFileName])
            elif fileName in project.pages.keys():
                print prettyText("[+] Found II %s (%s)" % (fileName, realFileName), ['green','bold'])
                incPageList.append(project.pages[fileName])
            else:
                '''
                #searching for filename only, might return false positives
                
                lstSimilars = utils.mostSimilar(fileName, project.pages.keys())
                found = False
                
                for l in lstSimilars:
                    print "[***] FOUND %s === %s (%s)" % (fileName, l, currentDirName)
                    incPageList.append(project.pages[l])
                    found = True
                
                if not found:
                    print prettyText("[-] Not found %s (%s)" % (fileName, currentDirName), 'red')
                '''
                print prettyText("[-] Not found %s (%s)" % (fileName, realFileName), 'red')
        else:
            
            #incStrs = core.search.search(fileName, core.filters.classFilter, str)
            
            print prettyText("[-] Resolving this Include is not implemented yet !", 'yellow')
            print prettyText("[-] Blob: ", 'yellow') + prettyText("%s" % str(blob), 'blue')
            #print prettyText("[-] str: ", 'yellow') + prettyText("%s" % str(incStrs), 'blue')
            
    return incPageList


#TODO: not test yet
#extracts the Context of a Blob (slow & simple version)
def extractContext(blob,page):
    uid = core.ast.getUID(blob,page)
    print uid
    for currentIndice in range(len(uid), -1, -1):
        for currentValue in range(uid[currentIndice], -1, -1):
            print "%s :: %s" % (currentIndice, currentValue)
    
    


