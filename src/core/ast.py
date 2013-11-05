import phply

from utils import prettyText


def getChild(node):
    if isinstance(node, list):
        return list
    elif isinstance(node, phply.phpast.Node):
        return node.__dict__.values()
    
def getParent(node, page):
    #print "GetParent Node: " + str(node)
    uid = getUID(node, page)
    #print "Current UID: " + str(uid)
    if uid != []:
        uid.pop()
        #print "Parent UID: " + str(uid)
        if uid == []:
            return page
        else:
            return getNodeByUID(uid, page)
    else:
        return page

   
def getUID(node, page):
    return _getUID(node, page, [])
    
def _getUID(node, page, indice): 
        ret = []
        i = 0
        if page != None:
            if isinstance(page,list):
                if node == page:
                    return indice
                elif node in page:
                    indice.append(page.index(node))
                    return indice
                else:
                    for l in page:
                        cur = list(indice)
                        cur.append(i)
                        i = i + 1
                        ret = ret + _getUID(node, l, cur)
            elif isinstance(page, phply.phpast.Node):
                if page == node:
                    return indice
                else:
                    j = 0
                    for k in page.__dict__.keys():
                        if k != 'lineno':
                            l = page.__dict__[k]
                            cur = list(indice)
                            cur.append(j)
                            j = j + 1
                            ret = ret + _getUID(node, l, cur)
        return ret
    
    
def getNodeByUID(uid, page):
    uid.reverse()
    return _getNodeByUID(uid, page)
 
    
def _getNodeByUID(uid, page):
    cur = ''
    #print prettyText(str(uid), 'red') + prettyText(page, 'green')
    if len(uid) > 0:
        indexor = uid.pop()
        if isinstance(page, list):
            cur = page[indexor]
            #print prettyText(str(uid), 'red') + "|| List: " + prettyText(str(cur), 'blue')
            return _getNodeByUID(uid, cur)
        elif isinstance(page, phply.phpast.Node):
            cur = page.__dict__.values()[indexor]
            #print prettyText(str(uid), 'red') + "|| Node: " + prettyText(str(cur), 'blue')
            return _getNodeByUID(uid, cur)
    else:
        #print prettyText(str(uid), 'red') + prettyText(page, 'green')
        return  page  
        
    
    