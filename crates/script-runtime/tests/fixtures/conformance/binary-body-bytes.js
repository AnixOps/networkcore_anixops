// Quantumult X scripts return `bodyBytes`, an ArrayBuffer.
var view = new Uint8Array($response.bodyBytes);
$done({ bodyBytes: view.buffer.slice(1) });
