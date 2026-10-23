// Request script answering without contacting the origin.
$done({
  response: {
    status: 200,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ blocked: $request.method })
  }
});
