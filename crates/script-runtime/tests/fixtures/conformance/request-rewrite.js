// Request script: rewrite URL and headers.
var headers = $request.headers;
headers["X-NetworkCore"] = "1";
delete headers["Cookie"];
$done({ url: $request.url.replace("/v1/", "/v2/"), headers: headers });
