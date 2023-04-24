import json
from functools import reduce

def SureType(Val, Type):
	ValType = type(Val)
	if ValType == Type:
		return Val
	else:
		if Type == bytes:
			return Val.encode()
		if Type == list:
			return [Val]

# Merge b into a | <https://stackoverflow.com/a/7205107>
def DictMerge(a:dict, b:dict, path=None):
	if path is None: path = []
	for key in b:
		if key in a:
			# Different value-key
			if isinstance(a[key], dict) and isinstance(b[key], dict):
				DictMerge(a[key], b[key], path + [str(key)])
			# Same key, same value
			elif a[key] == b[key]:
				pass
			# Same key, different value
			else:
				a[key] = b[key]
		else:
			a[key] = b[key]
	return a

def MakeStringOpts(Opts:dict):
	New = ''
	for Key in Opts:
		New += f',{Key}={Opts[Key]}'
	return New[1:]

def TryJsonLoadS(Text:str):
	return json.loads(Text) if Text else {}

# Check username valid by UNIX standard
def IsUsernameValid(Name:str):
	if len(Name) > 31 or Name[0] in '0123456789':
		return False
	for c in Name:
		if not c in 'qwfpbjluyarstgmneiozxcdvkh0123456789-_':
			return False
	return Name
