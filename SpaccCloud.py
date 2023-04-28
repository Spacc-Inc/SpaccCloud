#!/usr/bin/env python3
import bcrypt, json, os
from random import choice
from re import match as RegexMatch
from secrets import compare_digest, token_urlsafe
from traceback import format_exc as Traceback
from flask import Flask, Response, request
from urllib.request import urlopen, Request
from SpaccCloudIncludes.Files import *
from SpaccCloudIncludes.Secrets import *
from SpaccCloudIncludes.Utils import *

App = Flask(__name__)
Spa, WfmInject = '', ''
Session = {}
DbFile = 'Database.json'
Db = {}
DbDefault = '''
{
	"Server": {
		"Host": "localhost",
		"Port": 8560,
		"StorageBase": "./Clouds",
		"WfmAdmin": "admin:admin"
	},
	"Service": {
		"Debug": false,
		"Url": "//127.0.0.1:8560",
		"WfmUrl": "//127.0.0.1:7580",
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

Strings = {
	"UsernameRequirements": """
* Max length: 31 chars
* Allowed chars:
  * Letters
  * Underscore (_)
  * Numbers (not as the first char)
  * Dash (-) (not as the first char)
	"""
}

@App.route('/')
@App.route('/app')
@App.route('/app/')
def Index():
	if Db['Service']['Debug']:
		LoadSpa()
	return (Spa
		).replace('{{MotdText}}', choice(Motds.strip().splitlines())
		).replace('{{ServiceJson}}', json.dumps(Db['Service'])
		), 200, {"Content-Type": "text/html; charset=utf-8"}

@App.route('/WfmInject.js')
def WfmInjectJs():
	if Db['Service']['Debug']:
		LoadWfmInject()
	return (WfmInject
		).replace('{{ServiceJson}}', json.dumps(Db['Service'])
		), 200, {"Content-Type": "text/javascript; charset=utf-8"}

@App.route('/api', methods=['POST'])
@App.route('/api/', methods=['POST'])
def Api():
	Data = request.get_json()
	m = Data['Method']
	if m == 'OpenSession': return ApiOpenSession(Data)
	elif m == 'CloseSession': return ApiCloseSession(Data)
	elif m == 'RenewSession': return ApiRenewSession(Data)
	elif m == 'Register' and Db['Service']['Registration']: return ApiRegister(Data)
	else: return JsonRes(Code=400)

def ApiOpenSession(Data:dict):
	User = FormatUsername(Data['Username'])
	Passwd = Data['Password']
	if User in Db['Users'] and bcrypt.checkpw(
			Passwd.encode(),
			Db['Users'][User]['Password'].encode()):
		KeyDec = Db['Users'][User]['Storage']['Key']
		KeyDec = AesCrypt(KeyDec[0], Passwd[60-32:], Nonce=KeyDec[1], StrEnc=True, StrDec=False)[0].decode()
		Token = MakeToken(User)
		SessionStore(Token, User)
		#CryptMount({"User": User, "passphrase_passwd": KeyDec, "ecryptfs_sig": ""})
		return JsonRes({"Token": Token})
	else:
		return JsonRes({"Notice": "Incorrect login data. Recheck it and retry."}, Code=401)

def ApiCloseSession(Data:dict):
	Token = HashToken(Data['Token'])
	if Token in Session['Tokens']:
		SessionClose(Data['Token'])
		return JsonRes(Code=200)
	else:
		return JsonRes(Code=401)

def ApiRenewSession(Data:dict):
	if 'Token' in Data:
		OldToken = HashToken(Data['Token'])
		if OldToken in Session['Tokens']:
			User = SessionClose(OldToken)
			NewToken = MakeToken(User)
			SessionStore(NewToken, User)
			return JsonRes({"Token": NewToken})
		else:
			return JsonRes(Code=401)
	else:
		return JsonRes(Code=400)

def ApiRegister(Data:dict):
	User = FormatUsername(Data['Username'])
	if not IsUsernameValid(User):
		return JsonRes({"Notice": f"Invalid username. Please respect the UNIX regex ([a-z_][a-z0-9_-]{{0,30}}): {Strings['UsernameRequirements']}"}, Code=422)
	if not User in Db['Users']:
		Passwd = Data['Password']
		PwHashed = bcrypt.hashpw(Passwd.encode(), bcrypt.gensalt(10)).decode()
		PwEnc = token_urlsafe(64)[:63] # Max len for ecryptfs password is 64 chars
		KeyEnc = AesCrypt(PwEnc, Passwd[60-32:], StrEnc=True)
		# Create cloud user directories
		for Sub in ('Public', 'Secret', 'Secret.Crypto'):
			os.makedirs(f"{Db['Server']['StorageBase'].removesuffix('/')}/{User}/{Sub}", exist_ok=True)
		Sig = CmdRun('yes "" | ' + CryptMountCmd({"User": User, "passphrase_passwd": PwEnc}) + '| grep ecryptfs_sig').strip().split('=')[1]
		Db['Users'].update({User: {"Password": PwHashed, "Storage": {"Key": KeyEnc, "Sig": Sig}}})
		Session['Users'].update({User: []})
		WriteInDbFile({"Users": Db['Users']})
		#SessionStore(Token, User)
		#with open(DbFile, 'w') as File:
		#	json.dump(DictMerge(Db), File, indent='\t')
		return JsonRes({"Notice": "Registration successful. You can now log-in."}, Code=201)
	else:
		return JsonRes({"Notice": "An account with this username already exists."}, Code=409)

def JsonRes(Data:dict={}, Code:int=200):
	return json.dumps(Data), Code, {"Content-Type": "application/json; charset=utf-8"}

#def SessionCheck(Token:str):
#	return compare_digest(Token, Token)

def WriteInDbFile(Dict:dict):
	OldFileDb = JsonLoadF(DbFile)
	with open(DbFile, 'w') as File:
		json.dump(DictMerge(OldFileDb, Dict), File, indent='\t')

def SessionStore(Token:str, User:str):
	Session['Tokens'].update({HashToken(Token): User})
	Session['Users'][User] += [HashToken(Token)]

def SessionClose(Token:str, Rehash:bool=False):
	if Rehash:
		Token = HashToken(Token)
	try:
		User = Session['Tokens'].pop(Token)
		Session['Users'][User].remove(Token)
		return User
	except Exception:
		return None

def CryptMountCmd(InOpts:dict, Mount:bool=True):
	SBase = Db['Server']['StorageBase']
	if Mount: # As opposed to Umount
		Opts = {
			"ecryptfs_sig": "", "key": "passphrase", # "passphrase_passwd": "passwd",
			"ecryptfs_cipher": "aes", "ecryptfs_key_bytes": 16,
			"ecryptfs_passthrough": "no", "ecryptfs_enable_filename_crypto": "yes",
		}
		Opts.update(InOpts)
		Opts.update({"ecryptfs_fnek_sig": Opts['ecryptfs_sig']})
		CliOpts = f'-t ecryptfs -o "{MakeStringOpts(Opts)},ecryptfs_unlink_sigs"'
	return f'''
	{'' if Mount else 'u'}mount \
	{CliOpts if Mount else ''} \
	{(SBase+'/'+InOpts['User']+'/Secret.Crypto') if Mount else ''} {SBase}/{InOpts['User']}/Secret \
	'''.strip()

# Change password of Wfm admin if it might still be on dangerous default
def WfmAdminReset():
	if Db['Server']['WfmAdmin'] == 'admin:admin':
		try:
			Url = Db["Service"]["WfmUrl"]
			if Url.startswith('//'):
				Url = f'http:{Url}'
			Login = Db['Server']['WfmAdmin']
			Username = Login.split(':')[0]
			OldPassword = ':'.join(Login.split(':')[1:])
			NewPassword = token_urlsafe(128)
			Auth = urlopen(Request(f'{Url}/api/login', data=json.dumps({"username": Username, "password": OldPassword}).encode())).read().decode()
			Headers = {"Cookie": f"auth={Auth}", "X-Auth": Auth}
			AdminUser = None
			for User in json.loads(urlopen(Request(f'{Url}/api/users', headers=Headers)).read().decode()):
				if User['username'] == Username:
					AdminUser = User
					break
			AdminUser['password'] = NewPassword
			if urlopen(Request(f'{Url}/api/users/{AdminUser["id"]}', headers=Headers, data=json.dumps({"what": "user", "which": ["all"], "data": AdminUser}).encode(), method='PUT')).code == 200:
				WriteInDbFile({"Server": {"WfmAdmin": f"{Username}:{NewPassword}"}})
		except Exception:
			print(Traceback())

def LoadSpa():
	global Spa
	Spa = (open('./App.html', 'r').read()
		).replace('{{Service.WfmUrl}}', Db['Service']['WfmUrl']
		).replace('{{App.js}}', open('./App.js', 'r').read()
		).replace('{{bcrypt.js}}', open('./bcrypt.min.js', 'r').read())
	Spa = ErudaInject(Spa)

def LoadWfmInject():
	global WfmInject
	WfmInject = open('./WfmInject.js', 'r').read()
	WfmInject = ErudaInject(WfmInject)

def ErudaInject(Base):
	Inj = (open('./Eruda.js', 'r').read() if Db['Service']['Debug'] else '')
	return Base.replace('{{Eruda.js}}', Inj)

if __name__ == '__main__':
	if os.geteuid() != 0:
		print("This service must run as root. Exiting.")
		exit(1)
	os.chdir(os.path.dirname(os.path.abspath(__file__)))

	Db = DictMerge(json.loads(DbDefault), JsonLoadF(DbFile))
	#with open(DbFile, 'w') as File:
	#	json.dump(Db, File, indent='\t')

	Session = DictMerge({"Tokens": {}, "Users": {}}, JsonLoadF('Session.json'))
	for User in Db['Users'].keys():
		Session['Users'].update({User: []})

	LoadSpa()
	WfmAdminReset()

	if Db['Service']['Debug']:
		App.run(host=Db['Server']['Host'], port=Db['Server']['Port'], debug=True)
	else:
		from waitress import serve
		serve(App, host=Db['Server']['Host'], port=Db['Server']['Port'])
