#!/usr/bin/env python3
import json, os
from random import choice
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
		"Registration": false
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
		).replace('{{MotdText}}', choice(Motds.strip().splitlines())
		).replace('{{ServiceJson}}', json.dumps(Db['Service'])
		), 200, {"Content-Type": "text/html; charset=utf-8"}

@App.route('/api', methods=['POST'])
@App.route('/api/', methods=['POST'])
def Api():
	Data = request.get_json()
	m = Data['Method']
	if m == 'CreateSession': return ApiCreateSession(Data)
	elif m == 'CheckSession': return ApiCheckSession(Data)
	elif m == 'Register' and Db['Service']['Registration']: return ApiRegister(Data)
	else: return JsonRes(Code=400)

def ApiCreateSession(Data):
	if Data['Username'] in Db['Users'] and bcrypt.checkpw(
			Data['Password'].encode(),
			Db['Users'][Data['Username']]['Password'].encode()):
		return JsonRes()
	else:
		return JsonRes(Code=401)

def ApiCheckSession(Data):
	if Data['Token'] in Session['Tokens']:
		return JsonRes()
	else:
		return JsonRes(Code=401)

def ApiRegister(Data):
	if not Data['Username'] in Db['Users']:
		PwHashed = bcrypt.hashpw(Data['Password'].encode(), bcrypt.gensalt(10)).decode()
		Db.update({"Users": {Data['Username']: {"Password": PwHashed}}})
		with open(DbFile, 'w') as File:
			json.dump(Db, File, indent='\t')
		return JsonRes(Code=201)
	else:
		return JsonRes(Code=409)

def JsonRes(Json:dict={}, Code:int=200):
	return json.dumps(Json), Code, {"Content-Type": "application/json; charset=utf-8"}

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

if __name__ == '__main__':
	if os.geteuid() != 0:
		print("This service must run as root. Exiting.")
		exit(1)
	os.chdir(os.path.dirname(os.path.abspath(__file__)))

	with open(DbFile, 'r') as File:
		DbLoad = json.load(File)
	Db.update(json.loads(DbDefault))
	Db.update(DbLoad)
	with open(DbFile, 'w') as File:
		json.dump(Db, File, indent='\t')

	Page = (open('./App.html', 'r').read()
		).replace('{{App.js}}', open('./App.js', 'r').read()
		).replace('{{bcrypt.js}}', open('./bcrypt.min.js', 'r').read())

	if Db['Conf']['Debug']:
		App.run(host=Db['Conf']['Host'], port=Db['Conf']['Port'], debug=True)
	else:
		from waitress import serve
		serve(App, host=Db['Conf']['Host'], port=Db['Conf']['Port'])
