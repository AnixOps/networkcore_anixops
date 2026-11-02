// NetworkCore script prelude. Every engine binding evaluates this file
// unchanged before the user script. It builds the Loon-compatible `$`-API on
// top of one host function; the semantics live in Rust (`ScriptHost`).
(function (global) {
  "use strict";

  var host = global.__nc_host;
  delete global.__nc_host;

  function call(op, payload) {
    return host(op, payload === undefined ? "" : String(payload));
  }

  function text(value) {
    return value === undefined || value === null ? "" : String(value);
  }

  function define(name, value) {
    Object.defineProperty(global, name, {
      value: value,
      writable: true,
      configurable: true,
      enumerable: false
    });
  }

  var context = JSON.parse(call("context"));

  define("$request", context.request);
  if (context.response) {
    // Quantumult X scripts read `statusCode`, Loon and Surge `status`.
    if (context.response.statusCode === undefined) {
      context.response.statusCode = context.response.status;
    }
    define("$response", context.response);
  }
  define("$argument", context.argument);
  define("$loon", context.environment);
  define("$script", {
    name: context.scriptName,
    type: context.phase === "response" ? "http-response" : "http-request",
    startTime: new Date()
  });

  define("$done", function (value) {
    var payload;
    try {
      payload = JSON.stringify(value === undefined || value === null ? {} : value);
    } catch (error) {
      payload = undefined;
    }
    call("done", payload === undefined ? "null" : payload);
  });

  define("$persistentStore", {
    read: function (key) {
      var value = call("store.read", text(key));
      return value === undefined || value === null ? null : value;
    },
    write: function (value, key) {
      return call("store.write", JSON.stringify({ key: text(key), value: text(value) })) === "true";
    },
    remove: function (key) {
      return call("store.remove", text(key)) === "true";
    }
  });

  define("$notification", {
    post: function (title, subtitle, content, attach) {
      var url = "";
      if (typeof attach === "string") {
        url = attach;
      } else if (attach && typeof attach === "object") {
        url = text(attach.openUrl || attach["open-url"] || attach.url);
      }
      call("notify", JSON.stringify({
        title: text(title),
        subtitle: text(subtitle),
        content: text(content),
        url: url
      }));
    }
  });

  // Quantumult X equivalents of the store and notification APIs. They do not
  // change host detection: scripts tell Quantumult X apart by `$task`.
  define("$prefs", {
    valueForKey: function (key) {
      return global.$persistentStore.read(key);
    },
    setValueForKey: function (value, key) {
      return global.$persistentStore.write(value, key);
    },
    removeValueForKey: function (key) {
      return global.$persistentStore.remove(key);
    },
    removeAllValues: function () {
      return false;
    }
  });

  define("$notify", function (title, subtitle, content, options) {
    var url = "";
    if (typeof options === "string") {
      url = options;
    } else if (options && typeof options === "object") {
      url = text(options["open-url"] || options.openUrl || options.url);
    }
    global.$notification.post(title, subtitle, content, url);
  });

  function format(args) {
    var parts = [];
    for (var i = 0; i < args.length; i++) {
      var item = args[i];
      if (typeof item === "string") {
        parts.push(item);
        continue;
      }
      try {
        var json = JSON.stringify(item);
        parts.push(json === undefined ? String(item) : json);
      } catch (error) {
        parts.push(String(item));
      }
    }
    return parts.join(" ");
  }

  function log() {
    call("log", format(arguments));
  }

  define("console", { log: log, info: log, warn: log, error: log, debug: log });

  var timers = {};

  define("setTimeout", function (callback, delay) {
    if (typeof callback !== "function") {
      return 0;
    }
    var args = Array.prototype.slice.call(arguments, 2);
    var id = Number(call("timer.set", String(Number(delay) || 0)));
    if (id > 0) {
      timers[id] = function () {
        callback.apply(undefined, args);
      };
    }
    return id;
  });

  define("clearTimeout", function (id) {
    if (timers[id]) {
      delete timers[id];
      call("timer.clear", String(id));
    }
  });

  var callbacks = {};

  function request(method, options, callback) {
    var opts = typeof options === "string" ? { url: options } : options || {};
    var body = opts.body;
    if (body !== undefined && body !== null && typeof body !== "string") {
      body = JSON.stringify(body);
    }
    var id = Number(call("http.request", JSON.stringify({
      method: method,
      url: text(opts.url),
      headers: opts.headers || {},
      body: body === undefined || body === null ? null : body,
      timeout: Number(opts.timeout) || 0
    })));
    if (typeof callback === "function") {
      callbacks[id] = callback;
    }
  }

  var client = {};
  ["get", "post", "put", "delete", "head", "options", "patch"].forEach(function (method) {
    client[method] = function (options, callback) {
      request(method.toUpperCase(), options, callback);
    };
  });
  define("$httpClient", client);

  // Quantumult X `$task.fetch`. Defined only for scripts written for
  // Quantumult X alone (see `run_script`): cross-client scripts check `$task`
  // first and would otherwise take their Quantumult X branch.
  Object.defineProperty(global, "__nc_quantumult", {
    value: function () {
      define("$task", {
        fetch: function (options) {
          var opts = typeof options === "string" ? { url: options } : options || {};
          return new Promise(function (resolve, reject) {
            request(text(opts.method || "GET").toUpperCase(), opts, function (error, response, body) {
              if (error !== null && error !== undefined) {
                reject({ error: String(error) });
              } else {
                resolve({
                  statusCode: response.status,
                  status: response.status,
                  headers: response.headers,
                  body: body
                });
              }
            });
          });
        }
      });
      delete global.__nc_quantumult;
    },
    writable: false,
    configurable: true,
    enumerable: false
  });

  Object.defineProperty(global, "__nc_dispatch", {
    value: function (event) {
      if (event.kind === "timer") {
        var timer = timers[event.id];
        if (timer) {
          delete timers[event.id];
          timer();
        }
        return;
      }
      if (event.kind === "http") {
        var callback = callbacks[event.id];
        delete callbacks[event.id];
        if (!callback) {
          return;
        }
        if (event.error !== null && event.error !== undefined) {
          callback(event.error, null, null);
        } else {
          callback(
            null,
            { status: event.status, statusCode: event.status, headers: event.headers },
            event.body
          );
        }
      }
    },
    writable: false,
    configurable: false,
    enumerable: false
  });
})(globalThis);
