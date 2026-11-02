// A Quantumult X-only script gets $task.fetch; with the HTTP client disabled
// the promise rejects with { error }.
$task.fetch({ url: "https://remote.example.test/data", method: "POST", body: "x" }).then(
  function (response) {
    $done({ body: "resolved:" + response.statusCode });
  },
  function (reason) {
    $done({ body: "rejected:" + typeof reason.error });
  }
);
