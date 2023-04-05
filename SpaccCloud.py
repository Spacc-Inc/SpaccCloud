#!/usr/bin/env python3
import json
import os
from random import choice
import bcrypt
from Crypto.Cipher import AES
from flask import Flask, Response, request
from urllib.request import urlopen, Request

App = Flask(__name__)
Db = {}

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
	return str(open('./App.html', 'r').read()
		).replace('{{bcrypt.js}}', open('./bcrypt.min.js', 'r').read()
		).replace('{{MotdText}}', choice(Motds.strip().splitlines())
		).replace('{{ServiceJson}}', json.dumps(Db['Service']))

@App.route('/api', methods=['POST'])
@App.route('/api/', methods=['POST'])
def Api():
	Data = request.get_json()
	print(Data)
	return Data

def ApiLogin():
	pass

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

	with open('SpaccCloudDb.json', 'r') as f:
		Db = json.load(f)

	if Db['Conf']['Debug']:
		App.run(host=Db['Conf']['Host'], port=Db['Conf']['Port'], debug=True)
	else:
		from waitress import serve
		serve(App, host=Db['Conf']['Host'], port=Db['Conf']['Port'])
