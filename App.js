var Service = {{ServiceJson}};
var Session = {};

function SpawnModal(Content, Cancellable) {
	Cancellable = Cancellable || true;
	var New = document.createElement('div');
	New.className = "Modal";
	New.innerHTML = Content;
	document.body.append(New);
	return New;
};

function DoLogin(Signup) {
	var [Username, Password, Remember] = FormLogin.querySelectorAll('input');
	[Username, Password, Remember] = [Username.value, Password.value, Remember.checked];
	if (Username && Password) {
		Password = dcodeIO.bcrypt.hashSync(Password, '$2a$10$m8O.rNTwFHZmPc1QdlamSO'); // Never change salt
		// check with the server
		var Req = new XMLHttpRequest();
		Req.onreadystatechange = function(){
			if (Req.readyState == 4) {
				if (Req.status == 200) {
					// if remember, set token in LocalStorage; else, in SessionStorage
					//JSON.parse(Req.responseText);
					FrameSplash.hidden = true;
					FrameDashboard.hidden = false;
				} else
				if (this.status == 401) {
					alert("Incorrect login data. Recheck it and retry.")
				};
			};
		};
		Req.open('POST', '/api', true);
		Req.setRequestHeader('Content-Type', 'application/json');
		Req.send(JSON.stringify({Method: (Signup ? "Register" : "CreateSession"), Username: Username, Password: Password}));
	};
};

function Logout() {
	Session = {};
	FrameDashboard.hidden = true;
	FrameSplash.hidden = false;
};

FrameNojs.remove();
FormLogin.hidden = false;
SpawnModal(`
<p>
	About SpaccCloud
	<br/>
	etc etc etc
</p>
`);

if (Service.Registration) {
	FormLogin.innerHTML += `<input disabled="true" type="button" value="Signup"/>`;
	FormLogin.querySelector('input[value="Signup"]').onclick = function(){ DoLogin(true); };
};

window.addEventListener('load', function(){
	FrameWfm.src = `//${window.location.hostname}:7580`;

	FormLogin.querySelectorAll('input[placeholder="Username"], input[placeholder="Password"]').forEach(function(El){
		['onchange', 'oninput', 'onpaste'].forEach(function(Prop){
			El[Prop] = function(){
				var [Username, Password, _] = FormLogin.querySelectorAll('input');
				FormLogin.querySelectorAll('input[value="Login"], input[value="Signup"]').forEach(function(El){
					El.disabled = !(Username.value && Password.value);
				});
			};
		});
	});

	FormLogin.querySelector('input[value="Login"]').onclick = function(){ DoLogin(false); };
});
