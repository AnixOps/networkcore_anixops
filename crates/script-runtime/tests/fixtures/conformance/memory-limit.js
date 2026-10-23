// Unbounded allocation stops at the heap limit.
var chunks = [];
for (;;) {
  chunks.push(new Array(65536).fill("networkcore"));
}
