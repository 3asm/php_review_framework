import phply
from phply import phplex
from phply.phpparse import parser
from phply.phpast import *

import parser
import vulndb
import taint

from utils import prettyText



###
# Tree like functions
###

def get_predecessor(page,blob):
    def get_predecessor_filter(blob,var):
        if type(blob) is list:
            #print '[L] List ==> %s' % str(blob)
            for l in blob:
                #print '[L*] Testing %s <==> %s' % (str(l),str(var))
                if l == var and l.lineno == var.lineno:
                    return True
        elif isinstance(blob, phply.phpast.Node):
            #print '[N] Node ==> %s' % str(blob)
            for elmt in blob.fields:
                #print '[N*] Testing %s <==> %s' % (str(blob.__getattribute__(elmt)),str(var))
                if blob.__getattribute__(elmt) == var and blob.__getattribute__(elmt).lineno == var.lineno:
                    return True
        return False

    return searchPage(page,get_predecessor_filter,blob)

def get_child(blob):
    child = []
    t_child = []
    # if it is a blob, extract fields
    if isinstance(blob,phply.phpast.Node):
        for item in blob.fields:
            param = blob.__getattribute__(item)
            #if child is a list, run get_child again
            if isinstance(param,list):
                for elmt in param:
                    t_child = []
                    if isinstance(elmt,phply.phpast.Node):
                        t_child.append(elmt)
                child.extend(t_child)
            #if it is a blob, add it
            elif isinstance(param, phply.phpast.Node):
                child.append(param)
    child.sort(key=lambda x: x.lineno)
    return child


###
# Variable tainting
###


#TODO:replace error messages with exceptions
#TODO:implement logger for debugging
def resolve_includes(project,page):
    """
    This function returns all pages that are included in page, search is done in project
    """
    #extract include and require statements
    list_includes = searchPage(page,class_filter,[phply.phpast.Include,phply.phpast.Require])

    # return page list
    include_page_list = []

    for blob in list_includes:
        file_name = blob.expr

        if file_name.startswith('.'):
            file_name = file_name[1:]

        if not file_name.startswith('/'):
            file_name = '/' + file_name

        if type(file_name) is str:
            if file_name in project.pages.keys():
                print "[+] Found %s" % file_name
                include_page_list.append(project.pages[file_name])
            else:
                print "[-] Not found %s" % file_name
        else:
            print '-='*8
            print "[-] Resolving this include is not implemented yet !"
            print "[-] Blob: %s" % str(blob)
            print '-='*8

    return include_page_list
##

##
def extract_tree_context(blob,page):
    """
    Extract all blob of data that have impact on the blob in the page
    blob: blob to search for
    page: page of the blob
    return a list of blob in order top down
    """
    def cycle(iterable):
        for elmt in iterable:
            if isinstance(elmt,phply.phpast.Node) or isinstance(elmt,list):
                yield elmt

    def navigate_table(lst,blob):
        context_tree = []
        #print "[*] lst: %s" % str(lst)
        if search(lst,blob_in,blob):
            print "[+] Blob is in List!"
            blob_cycle = cycle(lst)
            blob_current = blob_cycle.next()
            running = True
            while running:
                try:
                    output = search(blob_current,blob_in,blob)

                    #print "[+] Output:\n\t%s\n\t\t\tin\n\t%s" % (str(output), str(blob_current))
                    if search(blob_current,blob_in,blob) == []:
                        print "[*] Adding blob %s" % str(blob_current)
                        context_tree.append(blob_current)
                        blob_current = blob_cycle.next()
                    else:
                        childs = get_child(blob_current)
                        #is it one of the childs
                        #it it is done, add parent
                        for c in childs:
                            if isinstance(c,phply.phpast.Node) and c == blob and c.lineno == blob.lineno:
                                print "[+] Found !"
                                running = False
                                context_tree.append(blob_current)

                        if running:
                            print "[*] Going into Childs\n\t\tCurrent: %s\n\t\tBlob: %s" % (blob_current, blob)
                            t_tree = navigate_table(childs,blob)
                            print "[+] t_tree: %s" % str(t_tree)
                            if t_tree:
                                context_tree.extend(t_tree)
                            running = False
                except StopIteration:
                    print "[-] Iteration Done !"
                    running = False
            return context_tree
    context_tree = navigate_table(page.parsed_content,blob)
    return context_tree
##

##
def extract_taint_table(context_tree):

    s_var =  search(context_tree,class_filter,vulndb.T_VARS)
    s_assignment =  search(context_tree,class_filter,phply.phpast.Assignment)

    #TODO:taint doesnt test for filtering functions

    taint_st = taint_symbol_table.taint_symbol_table()


    print "[*] Adding Variables"
    for v in s_var:
        print "[*] Adding %s" % str(v)
        taint_st.add_element(v)

    print "[+] Final Taint Symbol Table"
    print taint_st
    print "[*] Adding Assignments"
    for a in s_assignment:
        print "[*] Assignment %s" % str(a)
        taint_st.add_assignment(a)

    print "[+] Final Taint Symbol Table"
    print taint_st

    return taint_st


def is_page_vulnerable(page, vuln_signature):
    for k in vuln_signature:
        function_calls = search(page,function_filter, k)
        if function_calls:
            for c in function_calls:
                #TODO: context_tree seems to have a bug !!!!!!!!!!!
                #tree_context = extract_tree_context(c, page)
                #taint_table = extract_taint_table(tree_context)
                taint_table = extract_taint_table(page)
                indices = vuln_signature[k]
                print "[*] Indices %s" % str(indices)
                for i in indices:
                    dangerous_variable = search(c.params[i],class_filter,phply.phpast.Variable)
                    print "[*] Dangerous Vars: %s" % str(dangerous_variable)
                    for v in dangerous_variable:
                        taint = taint_table.get_taint(v)
                        print "[*] Taint for (%s) is %s" % (str(v),str(taint))
                        if int(taint) > 0:
                            print "[++] Potential Vulnerability"

