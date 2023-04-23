// [This file must be injected into the HTML served by File Browser (<https://filebrowser.org/>)]
// [Rules for nginx reverse proxy]:
// | sub_filter '</body>' '<script src="//OUR_SERVER/WfmInject.js"></script></body>';
// | sub_filter_once on;

var SpaccService = {{ServiceJson}};

window.addEventListener('message', function(Ev){
	[ SpaccService.Url,
	  `http:${SpaccService.Url}`,
	  `https:${SpaccService.Url}`,
	].forEach(function(Url){
		if (Ev.origin.toLowerCase() === Url.toLowerCase()) {
			console.log(Ev.data);
		};
	});
});

{{Eruda.js}}
