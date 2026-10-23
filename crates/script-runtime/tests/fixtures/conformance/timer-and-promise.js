// $done from a promise continuation scheduled by a timer.
setTimeout(function (suffix) {
  Promise.resolve("later").then(function (value) {
    $done({ body: value + suffix });
  });
}, 5, "!");
