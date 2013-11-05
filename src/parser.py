import phply
from phply import phplex
from phply.phpparse import parser
from phply.phpast import *

import os
from pprint import *
import vulndb

#terminal-py
from utils import prettyText


###
# Code Parsing
###
#TODO: make parsing multi-threaded

class PHPFile():
    def __init__(self,file_name):
        self.file_name = file_name
        try:
            o = open(file_name,'r')
            self.file_content = o.read()
            #o.close()
            try:
                lexer = phplex.lexer.clone()
                self.parsed_content = parser.parse(self.file_content, lexer=lexer)
                resolve_magic_constants(self.parsed_content)
                print prettyText("[+] SUCCESS parsing %s" % self.file_name,'green')
            except Exception, err:
                print prettyText("[-] ERROR parsing %s (%s)" % (self.file_name, str(err)),'red')
                self.parsed_content = []
        except Exception, err:
            print prettyText("[-] ERROR openning file: %s (%s)" % (self.file_name, str(err)),'yellow')
        """
        try:
		    lexer = phplex.lexer.clone()
		    self.parsed_content = parser.parse(self.file_content, lexer=lexer)
 		    resolve_magic_constants(self.parsed_content)
            print "[+] SUCCESS parsing %s" % self.file_name
        except:
            print "[-] ERROR parsing %s" % self.file_name
            self.parsed_content = []

        """


    ##TODO see pygments for code hilighting 
    def printCode(self,printlineno=True):
        if printlineno:
            codes = self.file_content.split('\n')
            lineno = 1
            for l in codes:
                print prettyText(lineno,'green') + prettyText(': ','cyan') + prettyText(l,'white')
                lineno += 1
        else:
            print self.file_content



    def printAST(self):
        print self._print_ast(self.parsed_content, [])
    
    def _print_ast(self, page, indice):
        ret = ''
        i = 0
        #print prettyText("[*] Start for %s" % str(indice),'red')
        if page != None:
            if isinstance(page,list):
                #print prettyText("[**] List %s" % str(page),'yellow')
                for l in page:
                    cur = list(indice)
                    cur.append(i)
                    i = i + 1
                    ret = ret + self._print_ast(l, cur)
            elif isinstance(page, phply.phpast.Node):
                #print prettyText("[**]\t Node %s" % str(page), 'blue')
                ret = prettyText(str(indice),'red') + '\t' * len(indice) + prettyText(str(type(page)),'green') + '\n'
                j = 0
                for k in page.__dict__.keys():
                    if k != 'lineno':
                        l = page.__dict__[k]
                        cur = list(indice)
                        cur.append(j)
                        j = j + 1
                        #print prettyText("[**]\t Node cur : %s || j : %s" % (str(cur), str(j-1)), ['blue', 'bold'])
                        ret = ret + self._print_ast(l,cur)
            else:
                #print prettyText("[**] Other %s" % str(page), 'white')
                ret = prettyText(str(indice),'red') + '\t' * len(indice) + prettyText(str(type(page)),'blue') + prettyText(':','cyan') + str(page) + '\n'
        return ret
    
    
    def print_lineno(self,lineno):
        print self.file_content.split('\n')[lineno+1]


class PHPProject():

    def __init__(self,folder_name,extension_list=vulndb.D_EXT_LIST):
        self.folder_name = os.path.abspath(folder_name)
        self.extension_list = extension_list
        self.pages = dict()
        file_list = []
        #list file with extension in folder
        for r, ds, fs in os.walk(folder_name):
            for file in fs:
                fileName, fileExtension = os.path.splitext(file)
                if fileExtension in extension_list:
                    #file_list.append(os.path.join(r,file))
                    fullpath = os.path.join(r,file)
                    self.pages[fullpath.split(self.folder_name)[1]] = PHPFile(fullpath)
        """
        print "[*] FILE LIST"
        pprint(file_list)
        for file in file_list:
            #print "[+] Parsing %s" % file
            self.pages[file.split(self.folder_name)[1]] = PHPFile(file)
        """


    def __listfiles__(self):
        return self.pages.keys()

    def __getitem__(self,key):
        if key in self.pages:
            return self.pages[key]
        else:
            return None


    def __setitem__(self,key,value):
        if isinstance(value, PHPFile):
            self.pages[key] = value
        else:
            raise TypeError



