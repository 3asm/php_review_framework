


#allow printing in colors in the terminal if supported
try:
    import terminal

    def prettyText(text,design):
        if isinstance(design,str):
            return terminal.AnsiText(text,[design])
        elif isinstance(design,list):
            return terminal.AnsiText(text,design)
        else:
            return text

except ImportError, e:

    def prettyText(text,design):
        return text





#calclute the weight of similitude of two folder names
def calSimilitude(pathA, pathB):
    lstA = pathA.split('/')[1:]
    lstB = pathB.split('/')[1:]
    
    score = 0
    for l in lstA:
        if l in lstB:
            score += 1
                     
    return score



def calSimilitudeEx(pathA, pathB):
    lstA = pathA.split('/')[1:]
    lstB = pathB.split('/')[1:]
    
    score = 0
    #we changed order of lstA and lstB
    for l in lstB:
        if l in lstA:
            score += 1
        else:
            score -= 1
            
    return score


#return most similar, if similitude is 0, [] is returned, else, all potential values
def mostSimilar(path, lstPath):
    
    scoreTable = dict()
    
    for p in lstPath:
        scoreTable[p] = calSimilitude(path, p)
        
    maxValue = max(scoreTable.values())
    
    if maxValue == 0:
        return  []
    else:
        lstMatch = [k for k in scoreTable.keys() if scoreTable[k] == maxValue]
        if len(lstMatch) > 1:
            scoreTableEx = dict()
            for p in lstMatch:
                scoreTableEx[p] = calSimilitudeEx(path, p)
                
            return [k for k in scoreTableEx.keys() if scoreTableEx[k] == max(scoreTableEx.values())]
              
        else:
            return lstMatch
        
        
    
