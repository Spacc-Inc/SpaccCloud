import json, os
from SpaccCloudIncludes.Utils import *

def FileReadTouch(Path:str, Mode:str='r'):
	if not os.path.exists(Path):
		with open(Path, 'w') as File:
			pass
	with open(Path, Mode) as File:
		return File.read()

def JsonLoadF(Path:str):
	return TryJsonLoadS(FileReadTouch(Path))
