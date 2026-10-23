// Environment globals scripts use to detect the host.
$done({
  body: [
    typeof $loon,
    $loon.indexOf("NetworkCore/") === 0,
    $script.type,
    $script.name,
    typeof $response,
    typeof $httpClient.post
  ].join(",")
});
