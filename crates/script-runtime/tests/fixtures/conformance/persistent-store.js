// Counter in the persistent store, plus a notification and a default-key write.
var count = Number($persistentStore.read("counter") || "0") + 1;
var stored = $persistentStore.write(String(count), "counter");
$persistentStore.write("default");
$persistentStore.remove("obsolete");
$notification.post("Counter", "networkcore", "count=" + count, { openUrl: "https://example.test/" });
$done({ body: String(stored) + ":" + $persistentStore.read("missing") });
