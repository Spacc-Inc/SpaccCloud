(function(){
	if (!Service) {
		var Service = SpaccCloudService;
	};
	if (Service.Debug /*&& new URLSearchParams(window.location.hash).get('#Eruda')*/) {
		var El = document.createElement('script');
		El.src = 'https://cdn.jsdelivr.net/npm/eruda';
		document.body.appendChild(El);
		El.onload = function(){ eruda.init(); };
	};
})();
