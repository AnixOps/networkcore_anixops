// Quantumult X store and notification APIs share Loon's backing store; a
// script that uses $task and never names the Loon global also gets $task.
var count = Number($prefs.valueForKey("counter") || "0") + 1;
$prefs.setValueForKey(String(count), "counter");
$prefs.removeValueForKey("obsolete");
$notify("Counter", "qx", "count=" + count, { "open-url": "https://example.test/qx" });
$done({ body: [count, $response.statusCode, typeof $task].join(",") });
