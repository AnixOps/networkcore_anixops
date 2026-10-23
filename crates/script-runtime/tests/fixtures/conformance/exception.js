// An uncaught exception fails the dispatch without a mutation.
JSON.parse($response.body).missing.field = 1;
$done({ body: "unreachable" });
