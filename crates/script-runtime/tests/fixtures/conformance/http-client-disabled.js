// $httpClient is disabled by default; the callback sees the error.
$httpClient.get({ url: "https://remote.example.test/data", timeout: 1000 }, function (error, response, data) {
  $done({ body: error ? "error:" + (response === null) : "ok:" + data });
});
