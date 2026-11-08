// Event script: `$event.name` names the event.
$notification.post($script.type, $event.name, typeof $request);
$done();
