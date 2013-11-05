import phply
from phply import phplex
from phply.phpparse import parser
from phply.phpast import *

import parser
import vulndb
import taint

from utils import prettyText

###
# Search Functions
###

def search(object,filter,filter_args):
    """ *returns the corresponding search function"""
    if isinstance(object,parser.PHPProject):
        return searchProject(object,filter,filter_args)
    elif isinstance(object,parser.PHPFile):
        return searchPage(object,filter,filter_args)
    elif isinstance(object,phply.phpast.Node):
        return searchBlob(object,filter,filter_args)
    elif isinstance(object,list):
        return searchList(object,filter,filter_args)
    else:
        #TODO:replace it with an exception
        #raise TypeError
        #print prettyText("[-] ERROR: object type is not valid '%s':%s" % (str(object), str(type(object))),['red','bold'])
        return None

def searchProject(project, filter, filter_args):
    """ *returns a dictionnay with the filename as key and the list of blobs as value """
    dret = dict()
    for file in project.pages:
        page = project.pages[file]
        if page != None:
            ret = searchPage(page, filter, filter_args)
            if ret != []:
                dret[file] = ret
    return dret

def searchPage(page, filter, filter_args):
    """ *returns a list of blobs per page """
    lret = list()
    if page != None:
        for blob in page.parsed_content:
            lret = lret + searchBlob(blob, filter, filter_args)
            #if we found an occurence in this file, no need to change the value
    return lret


def searchList(lst, filter, filter_args):
    """ *returns a list of blobs per page """
    lret = list()
    if lst != []:
        for blob in lst:
            lret = lret + searchBlob(blob, filter, filter_args)
            #if we found an occurence in this file, no need to change the value
    return lret


def searchBlob(blob, filter, filter_args):
    """ *apply the filter method to search for patterns """
    """ *apply action method on the blob that meets the filter criteria """
    """ *returns a list of blob """
    #print "[*] searching ... %s" % str(blob)
    lret = list()
    if blob != None:
        if filter(blob, filter_args):
            #print "[+] FOUND at %s" % blob.lineno
            lret.append(blob)
            for elmt in blob.__dict__.values():
                lret = lret + searchBlob(elmt, filter, filter_args)
            return lret
        elif isinstance(blob, phply.phpast.Node):
            for elmt in blob.__dict__.values():
                lret = lret + searchBlob(elmt, filter, filter_args)
            return lret
        elif isinstance(blob, list):
            for elmt in blob:
                lret = lret + searchBlob(elmt, filter, filter_args)
            return lret
    return lret




