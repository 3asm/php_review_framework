import phply

# class_filter(blob, [phply.phpast.Variable, phply.phpast.Include])
def classFilter(blob, var):
	if isinstance(var,list):
		for v in var:
			if type(blob) is v:
				return True
	else:
		if type(blob) is var:
			return True

	return False



# function_filter(blob, 'system')
def functionFilter(blob, var):
	if type(blob) is phply.phpast.FunctionCall:
		if isinstance(var, list):
			if blob.name in var:
				return True
		else:
			if blob.name == var:
				return True
	return False

def methodFilter(blob, var):
	if type(blob) is phply.phpast.MethodCall:
		if isinstance(var, list):
			if blob.name in var:
				return True
		else:
			if blob.name == var:
				return True
	return False

def functionMethodFilter(blob, var):
	if type(blob) is phply.phpast.MethodCall:
		if isinstance(var, list):
			if blob.name in var:
				return True
		else:
			if blob.name == var:
				return True
	if type(blob) is phply.phpast.FunctionCall:
		if isinstance(var, list):
			if blob.name in var:
				return True
		else:
			if blob.name == var:
				return True
	return False

def blobIn(blob,var):
	if blob == var and blob.lineno == var.lineno:
		return True
	return False



def functionClassFilter(blob,var):
	try:
		if issubclass(var,phply.phpast.Node):
			return classFilter(blob, var)
	except TypeError:
		return functionFilter(blob,var)




