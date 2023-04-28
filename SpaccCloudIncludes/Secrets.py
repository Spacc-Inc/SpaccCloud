import bcrypt
from base64 import b85encode, b85decode
from hashlib import sha256
from secrets import compare_digest, token_urlsafe
from time import time
from Crypto.Cipher import AES
from SpaccCloudIncludes.Utils import *

def MakeToken(User:str=None):
	User = f'{User}-' if User else ''
	return f'{User}{int(time())}/{token_urlsafe(128)}'

def HashToken(Token:str):
	if Token:
		Frags = Token.split('/')
		if len(Frags) > 1:
			return f'{Frags[0]}/{sha256(Frags[1].encode()).hexdigest()}'

def AesCrypt(Data, Key, Nonce=None, StrEnc:bool=False, StrDec:bool=True):
	Data = SureType(Data, bytes)
	Key = SureType(Key, bytes)
	if Nonce:
		Nonce = SureType(Nonce, bytes)
	if StrEnc and Nonce:
		Data = b85decode(Data)
		Nonce = b85decode(Nonce)
	if Nonce: # Decrypt
		Crypto = AES.new(Key, AES.MODE_EAX, Nonce)
		Data = Crypto.decrypt(Data)
	else: # Encrypt
		Crypto = AES.new(Key, AES.MODE_EAX)
		Data = Crypto.encrypt(Data)
	Nonce = Crypto.nonce
	if StrEnc and StrDec:
		Data = b85encode(Data).decode()
		Nonce = b85encode(Nonce).decode()
	return Data, Nonce
