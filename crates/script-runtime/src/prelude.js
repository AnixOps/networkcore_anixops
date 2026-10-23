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
