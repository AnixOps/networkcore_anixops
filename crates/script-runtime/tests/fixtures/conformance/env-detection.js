// Host detection as cross-client helpers (Env.js) do it: $task is checked
// before $loon, so such scripts must not see $task.
function getEnv() {
  if (typeof $environment !== "undefined" && $environment["surge-version"]) return "Surge";
  if (typeof $environment !== "undefined" && $environment["stash-version"]) return "Stash";
  if (typeof module !== "undefined" && module.exports) return "Node.js";
  if (typeof $task !== "undefined") return "Quantumult X";
  if (typeof $loon !== "undefined") return "Loon";
  if (typeof $rocket !== "undefined") return "Shadowrocket";
  return "unknown";
}
$done({ body: getEnv() });
