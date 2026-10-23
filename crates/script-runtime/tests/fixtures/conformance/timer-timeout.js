// A timer beyond the dispatch timeout never fires.
setTimeout(function () {
  $done({ body: "too late" });
}, 60000);
