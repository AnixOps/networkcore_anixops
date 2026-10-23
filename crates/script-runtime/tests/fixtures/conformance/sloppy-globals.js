// Loon scripts often assign undeclared globals; scripts run as sloppy-mode code.
obj = JSON.parse($response.body);
obj.vip = true;
console.log("patched", obj);
$done({ body: JSON.stringify(obj), status: "HTTP/1.1 201 Created" });
