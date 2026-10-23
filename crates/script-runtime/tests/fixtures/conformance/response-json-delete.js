// Typical ad-removal response script: parse, delete a key, return the body.
var body = JSON.parse($response.body);
delete body.ad;
body.mode = $argument;
$done({ body: JSON.stringify(body) });
