// Protobuf-style response script under binary-body-mode: read the bytes,
// drop the first field, return a Uint8Array.
var bytes = $response.body;
if (!(bytes instanceof Uint8Array) || !($response.bodyBytes instanceof ArrayBuffer)) {
  throw new Error("binary body is not a Uint8Array");
}
var out = new Uint8Array(bytes.length - 2);
out.set(bytes.subarray(2));
$done({ body: out });
