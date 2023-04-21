var Service = {{ServiceJson}};
var Session = {};

function ReadCookie(Key) {
	var Value;
	document.cookie.split('; ').forEach(function(Cookie){
		if (Cookie.startsWith(`${Key}=`)) {
			Value = Cookie.split('=')[1];
		};
	});
	return Value;
};

function SpawnModal(Content, Cancellable) {
	Cancellable = Cancellable || true;
	var New = document.createElement('div');
	New.className = "Modal";
	New.innerHTML = Content;
	document.body.append(New);
	return New;
};

function JsonReq(Data, Call) {
	var Req = new XMLHttpRequest();
	Req.onreadystatechange = Call;
	Req.open('POST', '/api', true);
	Req.setRequestHeader('Content-Type', 'application/json');
	Req.send(JSON.stringify(Data));
};

function DoLogin(Signup) {
	var [Username, Password, Remember] = FormLogin.querySelectorAll('input');
	[Username, Password, Remember] = [Username.value, Password.value, Remember.checked];
	if (Username && Password) {
		Password = dcodeIO.bcrypt.hashSync(Password, '$2a$10$m8O.rNTwFHZmPc1QdlamSO'); // Never change salt
		JsonReq({Method: (Signup ? "Register" : "OpenSession"), Username: Username, Password: Password}, function(){
			if (this.readyState == 4) {
				var Res = JSON.parse(this.responseText);
				if (this.status == 200) {
					Session.Token = Res.Token;
					document.cookie = `Token=${Session.Token}${Remember ? '; max-age='+Service.SessionDuration : ''}`;
					if (Remember) {
						document.cookie = `TokenMaxAge=${Service.SessionDuration}; max-age=${Service.SessionDuration}`;
					};
					FrameSplash.hidden = true;
					FrameDashboard.hidden = false;
				} else
				if (this.status == 401) {
					alert(Res.Notice);
				};
			};
		});
	};
};

function Logout() {
	Session = {};
	FrameDashboard.hidden = true;
	FrameSplash.hidden = false;
};

FrameNojs.remove();
FormLogin.hidden = false;

if (Service.Registration) {
	FormLogin.innerHTML += `<input disabled="true" type="button" value="Signup"/>`;
	FormLogin.querySelector('input[value="Signup"]').onclick = function(){ DoLogin(true); };
};

// Try to relogin with Token if it's saved (and at the same time renew it)
Session.Token = ReadCookie('Token');
JsonReq({Method: "RenewSession", Token: Session.Token}, function(){
	if (this.readyState == 4 && this.status == 200) {
		Session.Token = JSON.parse(this.responseText).Token;
		var MaxAge = ReadCookie('TokenMaxAge');
		document.cookie = `Token=${Session.Token}${MaxAge ? '; max-age='+MaxAge : ''}`;
		if (MaxAge) {
			document.cookie = `TokenMaxAge=${MaxAge}; max-age=${MaxAge}`;
		};
		FrameSplash.hidden = true;
		FrameDashboard.hidden = false;
	};
	// if not 200, then Token expired
});

window.addEventListener('load', function(){
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
