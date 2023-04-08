#!/usr/bin/env python3
import json, os
from functools import reduce
from hashlib import sha256
from random import choice
from secrets import token_urlsafe
from time import time
import bcrypt
from Crypto.Cipher import AES
from flask import Flask, Response, request
from urllib.request import urlopen, Request

App = Flask(__name__)
Page = ''
Session = {}
DbFile = 'Database.json'
Db = {}
DbDefault = '''
{
	"Conf": {
		"Host": "0.0.0.0",
		"Port": 8080,
		"Debug": false
	},
	"Service": {
		"Registration": false,
		"SessionDuration": 7776000
	},
	"Users": {}
}
'''

Motds = '''
SpaccCloud is WIP :/
It's an amazing day for Spacc.
We do NOT value ($$$) your data.
Could u try to NOT spacc the server today? Pretty please?
Is this really a cloud if the Raspi stays at the solid state of matter?
Why are you even using this?
[sysadmin]: I wish SpaccCloud didn't use encryption and I could just browse the photos of you in thigh highs
Refrain from feeding Him.
If your spacc decryption key falls into a hole? Your problem lmaooo, back it up now!
We don't support the ANTANI protocol :(
'''

@App.route('/')
@App.route('/app')
@App.route('/app/')
def Index():
	return (Page
		).replace('{{App.js}}', open('./App.js', 'r').read()
		).replace('{{MotdText}}', choice(Motds.strip().splitlines())
		).replace('{{ServiceJson}}', json.dumps(Db['Service'])
		), 200, {"Content-Type": "text/html; charset=utf-8"}

@App.route('/api', methods=['POST'])
@App.route('/api/', methods=['POST'])
def Api():
	Data = request.get_json()
	m = Data['Method']
	if m == 'CreateSession': return ApiCreateSession(Data)
	elif m == 'RenewSession': return ApiRenewSession(Data)
	elif m == 'Register' and Db['Service']['Registration']: return ApiRegister(Data)
	else: return JsonRes(Code=400)

def ApiCreateSession(Data:dict):
	if Data['Username'] in Db['Users'] and bcrypt.checkpw(
			Data['Password'].encode(),
			Db['Users'][Data['Username']]['Password'].encode()):
		Token = MkToken(Data['Username'])
		Session['Tokens'].update({Token: Data['Username']})
		Session['Users'][Data['Username']] += [Token]
		return JsonRes({"Token": Token})
	else:
		return JsonRes(Code=401)

def ApiRenewSession(Data:dict):
	if 'Token' in Data:
		if Data['Token'] in Session['Tokens']:
			User = Session['Tokens'].pop(Data['Token'])
			NewToken = MkToken(User)
			Session['Tokens'].update({NewToken: User})
			Session['Users'][User] += [NewToken]
			return JsonRes({"Token": NewToken})
		else:
			return JsonRes(Code=401)
	else:
		return JsonRes(Code=400)

def ApiRegister(Data:dict):
	User = Data['Username'][:32]
	if not User in Db['Users']:
		PwHashed = bcrypt.hashpw(Data['Password'].encode(), bcrypt.gensalt(10)).decode()
		Db['Users'].update({User: {"Password": PwHashed}})
		Session['Users'][User] += [Token]
		with open(DbFile, 'w') as File:
			json.dump(Db, File, indent='\t')
		return JsonRes(Code=201)
	else:
		return JsonRes(Code=409)

def JsonRes(Data:dict={}, Code:int=200):
	return json.dumps(Data), Code, {"Content-Type": "application/json; charset=utf-8"}

def MkToken(User=None):
	User = f'{User}-' if User else ''
	return f'{User}{token_urlsafe(16)}-{int(time())}'

def MkCliOpts(Opts:dict):
	Cli = ''
	for Key in Opts:
		Cli += f',{Key}={Opts[Key]}'
	return Cli[1:]

def CryptMount(InOpts:dict, Mount:bool=True):
	if Mount: # As opposed to Umount
		Opts = {
			"key": "passphrase", # "passphrase_passwd": "passwd", # "ecryptfs_sig": "0123456789abcdef",
			"ecryptfs_cipher": "aes", "ecryptfs_key_bytes": 16,
			"ecryptfs_passthrough": "no", "ecryptfs_enable_filename_crypto": "yes",
		}
		Opts.update(InOpts)
		Opts.update({"ecryptfs_fnek_sig": Opts['ecryptfs_sig']})
		CliOpts = f'-t ecryptfs -o "{MkCliOpts(Opts)},ecryptfs_unlink_sigs"'
	return os.system(f'''
	{'' if Mount else 'u'}mount \
	{CliOpts if Mount else ''} \
	{InOpts['Dir']+'.enc' if Mount else ''} {InOpts['Dir']}.mnt \
	'''.strip())

# Merge dict b into a | https://stackoverflow.com/a/7205107
def merge(a:dict, b:dict, path=None):
	if path is None: path = []
	for key in b:
		if key in a:
			# Different value-key
			if isinstance(a[key], dict) and isinstance(b[key], dict):
				merge(a[key], b[key], path + [str(key)])
			# Same key, same value
			elif a[key] == b[key]:
				pass
			# Same key, different value
			else:
				a[key] = b[key]
		else:
			a[key] = b[key]
	return a

def FileReadTouch(Path, Mode='r'):
	if not os.path.exists(Path):
		with open(Path, 'w') as File:
			pass
	with open(Path, Mode) as File:
		return File.read()

def TryJsonLoadS(Text):
	return json.loads(Text) if Text else {}

def JsonLoadF(Path):
	return TryJsonLoadS(FileReadTouch(Path))

if __name__ == '__main__':
	if os.geteuid() != 0:
		print("This service must run as root. Exiting.")
		exit(1)
	os.chdir(os.path.dirname(os.path.abspath(__file__)))

	Db = merge(json.loads(DbDefault), JsonLoadF(DbFile))
	#with open(DbFile, 'w') as File:
	#	json.dump(Db, File, indent='\t')

	Session = merge({"Tokens": {}, "Users": {}}, JsonLoadF('Session.json'))
	for User in Db['Users'].keys():
		Session['Users'].update({User: []})

	Page = (open('./App.html', 'r').read()
		).replace('{{bcrypt.js}}', open('./bcrypt.min.js', 'r').read())

	if Db['Conf']['Debug']:
		App.run(host=Db['Conf']['Host'], port=Db['Conf']['Port'], debug=True)
	else:
		from waitress import serve
		serve(App, host=Db['Conf']['Host'], port=Db['Conf']['Port'])
