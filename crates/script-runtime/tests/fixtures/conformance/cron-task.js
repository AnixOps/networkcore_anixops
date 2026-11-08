// Scheduled run: no $request or $response, so a script that both captures a
// cookie and checks in takes its check-in branch. `$done()` changes nothing.
var count = Number($persistentStore.read("runs") || "0") + 1;
$persistentStore.write(String(count), "runs");
$notification.post(
  "Check-in",
  $script.type,
  [typeof $request, typeof $response, typeof $event, $argument].join(",")
);
$done({ body: "ignored", response: { status: 500 } });
