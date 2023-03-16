#!/usr/bin/env python3
import json
from random import choice
import bcrypt
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
[sysadmin]: I wish SpaccCloud didn't use encryption and I could just browse your photos in thigh highs
Refrain from feeding Him.
If your spacc decryption key falls into a hole? Your problem lmao
We don't support the ANTANI protocol :(
'''

@App.route('/')
def Index():
	return str('''
	<head>
		<style>
			html, body { margin: 0px; padding: 0px; border: none; overflow-x: none; }
			/* iframe { width: 100%; height: 100%; } */
			.Modal { position: absolute; top: 0px; right: 0px; }
			#BarTop, #FrameSplash, #FrameNojs, #FrameDashboard, #FrameWfm { width: 100vw; border: none; }
			#FrameSplash { height: auto; text-align: center; }
			#BarTop { height: 2em; }
			#FrameNojs, #FrameDashboard, #FrameWfm { height: calc(100vh - 2em); }
		</style>
		<script>{{bcrypt.js}}</script>
	</head>
	<body onload="(function(){ FrameWfm.src = '//' + window.location.hostname + ':7580'; })()">
		<div id="FrameSplash">
			<h2>SpaccCloud</h2>
			<p>{{MotdText}}</p>
			<div id="FormLogin">
				<input type="text" placeholder="Username"/>
				<input type="password" placeholder="Password"/>
				<label> <input type="checkbox"/> Remember me </label>
				<input type="button" value="Login"/>
			</div>
			<h3>Features</h3>
			<p>The offerings are bountiful this year:</p>
			<ul>
				<li>✅ Free as in freedom, but also free of charge (note: no refunds, stop asking)</li>
				<li>✅ Hosted on crappy unstable hardware, with no redundancy whatsoever</li>
				<li>✅ Slow data transfers thanks to WiFi 2.4 GHz and USB 2.0 backend</li>
				<li>✅ Encryption at rest, to protect you from HDD thieves</li>
				<li>✅ Temporary design, since we haven't completed this yet</li>
				<li>✅ Handcrafted and hosted by Octt at Spacc Inc.</li>
			</ul>
		</div>
		<div id="FrameDashboard" hidden="true">
			<div id="BarTop">
				<p>{{MotdText}}</p>
				<button id="BtnOptions">...</button>
				<details>
					<summary>...</summary>
					<button id="BtnLogInOut">Log[in|out]</button>
					<button id="BtnSettings">Settings</button>
					<button id="BtnAbout">About</button>
				</details>
			</div>
			<iframe id="FrameWfm"></iframe>
		</div>
		<div id="FrameNojs">
			<h2>Well</h2>
			<p>JavaScript is required to use this app.</p>
		</div>
		<script>
			var Session = {};

			function SpawnModal(Content, Cancellable) {
				Cancellable = Cancellable || true;
				var New = document.createElement('div');
				New.className = "Modal";
				New.innerHTML = `
					${Content}
				`;
				document.body.append(New);
				return New;
			};

			function Login() {
				var [Username, Password, Remember] = FormLogin.querySelectorAll('input');
				// check with the server
				// if a session is granted, hide splash and show dashboard
				//FrameSplash.hidden = true;
				//FrameDashboard.hidden = false;
			};

			function Logout() {
				Session = {};
				FrameDashboard.hidden = true;
				FrameSplash.hidden = false;
			};

			BtnLogInOut.onclick = function(){
				Session ? Logout() : Login();
			};

			FrameNojs.hidden = true;

			SpawnModal(`
			<p>
				About SpaccCloud
				<br/>
				etc etc etc
			</p>
			`);
		</script>
	</body>
	'''
	).replace('{{bcrypt.js}}', open('bcrypt.min.js', 'r').read()
	).replace('{{MotdText}}', choice(Motds.strip().splitlines())
	)

#@App.route('/Wfm')
#@App.route('/Wfm/static/<Path>')
#def FromWfm(Path:str=''):
#	Url = 'http://localhost:7580'
#	if Path:
#		Sub = Path.split('/')[0]
#		Url += f'/static'
#		for s in Sub.split('_'):
#			Url += f'/{s}'
#		Url += Path[len(Sub):]
#	print(Url)
#	Rq = urlopen(Request(Url))
#	if not Path:
#		return Rq.read().decode(
#			).replace('="/static/', '="/Wfm/static/'
#			).replace('="/Wfm/static/css/', '="/Wfm/static/css_'
#			).replace('="/Wfm/static/img/', '="/Wfm/static/img_'
#			).replace('="/Wfm/static/img/icons/', '="/Wfm/static/img_icons_'
#			).replace('="/Wfm/static/js/', '="/Wfm/static/js_')
#	else:
#		return Response(Rq.read(), mimetype=Rq.headers['Content-Type'])

#@App.route('/Wfm/static/<Path>')
#def FromWfmStatic(Path:str):
#	return FromWfm(f'static/{Path}')

if __name__ == '__main__':
	with open('SpaccCloudDb.json', 'r') as f:
		Db = json.load(f)

	if Db['Conf']['Debug']:
		App.run(host=Db['Conf']['Host'], port=Db['Conf']['Port'], debug=True)
	else:
		from waitress import serve
		serve(App, host=Db['Conf']['Host'], port=Db['Conf']['Port'])
