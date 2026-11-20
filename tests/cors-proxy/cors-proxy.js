// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: cors-proxy.js
//
// ---------------------------------------------------------------------------
// CORS (and, when asked, TLS) in front of a test-stack service that sends no
// CORS headers of its own.
//
// One copy runs per service (see the compose files): walt.id's issuer-api2
// (7005 in front of 7006), walt.id's verifier-api2 (7003 in front of 7004),
// and the Polaris OpenID4VP verifier (7010, https, #423). Nothing here is
// specific to any of them; it forwards every method, path and body untouched.
//
// Those services install no CORS support, which is fine for a server-side
// wallet and fatal for a browser-based one: without
// `Access-Control-Allow-Origin` the browser refuses to hand the response to
// the page, so the debugger could not read an issuer's metadata, let alone
// POST a Credential Request.
//
// So the wallet talks to this, and the service's own address setting names it
// — walt.id's `baseUrl` / `urlPrefix`, Polaris's `--public-base-url`: every
// URL the service publishes or hands a wallet is built from that base, and
// they have to be URLs a browser can actually use. Nothing is rewritten here —
// the service already believes it lives at this address.
//
// It lived in waltid/ and read WALTID_* names until #431, when it had become a
// general test-stack shim. The old names are still read, with a warning, for
// one release.
//
// CONFIGURATION (environment)
//
//   CORS_PROXY_UPSTREAM          host:port of the service. Default
//                                localhost:7006. Was WALTID_UPSTREAM.
//   CORS_PROXY_PORT              the port to serve. Default 7005. Was
//                                WALTID_PROXY_PORT.
//   CORS_PROXY_TLS_CERT_FILE,
//   CORS_PROXY_TLS_KEY_FILE      when both are set, serve HTTPS with that pair.
//   CORS_PROXY_UPSTREAM_TLS      "1" to speak HTTPS to the upstream, so a
//                                service that serves only HTTPS can be fronted
//                                without being run in a weaker mode. Its
//                                certificate is VERIFIED, against the system
//                                store plus NODE_EXTRA_CA_CERTS, or against
//   CORS_PROXY_UPSTREAM_CA_FILE  this PEM bundle when it is set.
//   CORS_PROXY_ALLOWED_ORIGINS   comma- or space-separated origins whose
//                                requests get an `Access-Control-Allow-Origin`.
//                                Default `*`, which is the explicit test-stack
//                                choice: these are throwaway services on a
//                                private network. With a list, a listed Origin
//                                is echoed with `Vary: Origin`, and an
//                                unlisted one gets no CORS headers (and a 403
//                                to its preflight).
//   CORS_PROXY_ALLOW_CREDENTIALS "1" to send
//                                `Access-Control-Allow-Credentials: true`.
//                                Only with an origin list: a browser refuses
//                                credentials alongside `*`, so that
//                                combination stops the proxy at startup.
//   CORS_PROXY_DEBUG             "1" for the Entering/Leaving trace.
//
// GET /__proxy/health answers 200 from the proxy itself, without touching the
// upstream, so a healthcheck can ask whether THIS is up separately from
// whether the service behind it is.
//
// No dependencies, so it runs on a stock node image with nothing installed.
// It also exports its pieces, so tests/cors_proxy_engine.js can drive the real
// handler in process; it only listens when run as the main module.
// ---------------------------------------------------------------------------
var http = require("http");
var https = require("https");
var fs = require("fs");

// The Entering/Leaving logging convention (see the repo-root CLAUDE.md)
// wants a `log` here, and bunyan is not reachable from this file:
// it runs on a bare node image with no install step.
// So this is the same call shape backed by console. Debug output is off by
// default, so an ordinary run stays quiet; CORS_PROXY_DEBUG=1 follows a call
// through. Note the methods below are the one place the convention cannot
// apply — a log line inside log.debug() is infinite recursion.
var DEBUG = process.env.CORS_PROXY_DEBUG === "1";
var LOG_TAG = "[cors-proxy]";
var log = {
  debug: function () {
    if (!DEBUG) return;
    console.log.apply(console,
      [LOG_TAG].concat(Array.prototype.slice.call(arguments)));
  },
  info: function () {
    console.log.apply(console,
      [LOG_TAG].concat(Array.prototype.slice.call(arguments)));
  },
  warn: function () {
    console.warn.apply(console,
      [LOG_TAG].concat(Array.prototype.slice.call(arguments)));
  },
  error: function () {
    console.error.apply(console,
      [LOG_TAG].concat(Array.prototype.slice.call(arguments)));
  }
};

var HEALTH_PATH = "/__proxy/health";

// Every method a fronted service has been seen to need: walt.id's management
// API uses PUT and DELETE, and a method missing here fails the preflight with
// a "CORS error" that names nothing.
var ALLOWED_METHODS = "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS";

// What the preflight allows when the browser does not say what it will send.
// When it does (Access-Control-Request-Headers), that list is reflected
// instead, so a `DPoP` header or an unusual `Accept` does not fail a
// preflight nobody wrote a rule for.
var DEFAULT_ALLOWED_HEADERS = "Content-Type, Authorization";

// Response headers a browser hides from the page unless they are exposed —
// and a wallet reads every one of these: a Location after a redirect-shaped
// answer, WWW-Authenticate on a 401, DPoP-Nonce when the server demands a
// fresh nonce (RFC 9449 section 8), Link and Retry-After from a deferred or
// rate-limited endpoint.
var EXPOSED_HEADERS = "Content-Type, Location, WWW-Authenticate, " +
    "DPoP-Nonce, Link, Retry-After";

// A header list as RFC 9110 spells one: tokens separated by commas. Anything
// else in Access-Control-Request-Headers is not reflected.
var HEADER_TOKEN = "[!#$%&'*+.^_`|~0-9A-Za-z-]+";
var HEADER_LIST = new RegExp("^" + HEADER_TOKEN + "(\\s*,\\s*" +
    HEADER_TOKEN + ")*$");

// `logLine`, not `log`: this file already had a request logger of its own when
// the console-backed `log` above was added, and both were called `log`. A
// function declaration and a `var` of the same name are ONE binding, so the
// object assignment above won and every call here became "log is not a
// function" — thrown from server.listen()'s callback, which killed the proxy
// at startup. The only symptom was a connection refused on 7005/7003, so all
// four walt.id interoperability tests failed at their first fetch, naming
// walt.id rather than this file.
function logLine(message) {
  log.debug("Entering logLine().");
  // One line per call, so a failing browser request can be traced to what the
  // service actually answered. Timestamped: this is a container log read after
  // the fact, and `docker logs` adds none of its own by default.
  console.log(new Date().toISOString() + "  " + LOG_TAG + " " + message);
  log.debug("Leaving logLine().");
}

// The new name, else the name this file read before #431, which is noted so
// startup can warn about it.
function setting(env, name, oldName, deprecated) {
  log.debug("Entering setting(). " + name);
  if (env[name] !== undefined && env[name] !== "") {
    log.debug("Leaving setting(). " + name + " is set.");
    return env[name];
  }
  if (oldName && env[oldName] !== undefined && env[oldName] !== "") {
    deprecated.push(oldName + " (use " + name + ")");
    log.debug("Leaving setting(). " + oldName + " is set.");
    return env[oldName];
  }
  log.debug("Leaving setting(). Unset.");
  return "";
}

// The whole configuration, read from an environment-shaped object. Throws on
// a combination that cannot work, so the proxy stops at startup naming it
// rather than serving answers a browser will refuse.
function readConfig(env) {
  log.debug("Entering readConfig().");
  var deprecated = [];
  var upstream = setting(env, "CORS_PROXY_UPSTREAM", "WALTID_UPSTREAM",
      deprecated) || "localhost:7006";
  var portText = setting(env, "CORS_PROXY_PORT", "WALTID_PROXY_PORT",
      deprecated);
  var port = portText === "" ? 7005 : parseInt(portText, 10);
  if (isNaN(port) || port < 0 || port > 65535) {
    log.debug("Leaving readConfig(). Bad port.");
    throw new Error("cors-proxy: CORS_PROXY_PORT '" + portText +
        "' is not a port number.");
  }
  var upstreamTls = env.CORS_PROXY_UPSTREAM_TLS === "1";
  var colon = upstream.lastIndexOf(":");
  var upstreamHost = colon === -1 ? upstream : upstream.slice(0, colon);
  var upstreamPort = colon === -1 ? (upstreamTls ? 443 : 80) :
      parseInt(upstream.slice(colon + 1), 10);
  if (!upstreamHost || isNaN(upstreamPort)) {
    log.debug("Leaving readConfig(). Bad upstream.");
    throw new Error("cors-proxy: CORS_PROXY_UPSTREAM '" + upstream +
        "' is not host:port.");
  }
  var origins = (env.CORS_PROXY_ALLOWED_ORIGINS || "*").split(/[\s,]+/)
    .filter(function (o) {
      return o !== "";
    });
  var anyOrigin = origins.indexOf("*") !== -1;
  var credentials = env.CORS_PROXY_ALLOW_CREDENTIALS === "1";
  if (credentials && anyOrigin) {
    log.debug("Leaving readConfig(). Credentials with *.");
    throw new Error("cors-proxy: CORS_PROXY_ALLOW_CREDENTIALS=1 needs " +
        "CORS_PROXY_ALLOWED_ORIGINS to name the origins: a browser refuses " +
        "a credentialed response whose Access-Control-Allow-Origin is *.");
  }
  var tlsCert = env.CORS_PROXY_TLS_CERT_FILE || "";
  var tlsKey = env.CORS_PROXY_TLS_KEY_FILE || "";
  if ((tlsCert === "") !== (tlsKey === "")) {
    log.debug("Leaving readConfig(). Half a TLS pair.");
    throw new Error("cors-proxy: CORS_PROXY_TLS_CERT_FILE and " +
        "CORS_PROXY_TLS_KEY_FILE are set together or not at all.");
  }
  log.debug("Leaving readConfig().");
  return {
    upstream: upstreamHost + ":" + upstreamPort,
    upstreamHost: upstreamHost,
    upstreamPort: upstreamPort,
    upstreamTls: upstreamTls,
    upstreamCaFile: env.CORS_PROXY_UPSTREAM_CA_FILE || "",
    port: port,
    tlsCertFile: tlsCert,
    tlsKeyFile: tlsKey,
    anyOrigin: anyOrigin,
    allowedOrigins: anyOrigin ? [] : origins,
    allowCredentials: credentials,
    deprecated: deprecated
  };
}

// Adds `value` to a comma-separated Vary without repeating a member.
function addVary(res, value) {
  log.debug("Entering addVary(). " + value);
  var current = res.getHeader("Vary");
  var members = current ? String(current).split(/\s*,\s*/) : [];
  value.split(/\s*,\s*/).forEach(function (v) {
    var present = members.some(function (m) {
      return m.toLowerCase() === v.toLowerCase();
    });
    if (!present && v !== "") members.push(v);
  });
  res.setHeader("Vary", members.join(", "));
  log.debug("Leaving addVary().");
}

// Sets the CORS headers this request is owed, and returns whether its Origin
// is allowed. A request with no Origin at all is not a cross-origin browser
// request (a healthcheck, a server-side client) and is always forwarded.
function applyCors(config, req, res) {
  log.debug("Entering applyCors().");
  var origin = req.headers.origin;
  var allowed;
  if (config.anyOrigin) {
    res.setHeader("Access-Control-Allow-Origin", "*");
    allowed = true;
  } else {
    // The answer depends on the Origin, so a cache must key on it whether or
    // not this one is allowed.
    addVary(res, "Origin");
    allowed = !!origin && config.allowedOrigins.indexOf(origin) !== -1;
    if (allowed) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      if (config.allowCredentials) {
        res.setHeader("Access-Control-Allow-Credentials", "true");
      }
    }
  }
  if (allowed) {
    res.setHeader("Access-Control-Expose-Headers", EXPOSED_HEADERS);
  }
  log.debug("Leaving applyCors(). allowed=" + allowed);
  return allowed;
}

// A preflight is answered here rather than forwarded: the services behind
// this have no route for OPTIONS and would 404 it, which the browser reads as
// "not allowed" and then never sends the real request.
function answerPreflight(req, res, allowed) {
  log.debug("Entering answerPreflight().");
  if (!allowed) {
    res.writeHead(403, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      error: "origin_not_allowed",
      error_description: "The origin " + (req.headers.origin || "(none)") +
          " is not in CORS_PROXY_ALLOWED_ORIGINS."
    }));
    logLine("403 OPTIONS " + req.url + " (origin " +
        (req.headers.origin || "(none)") + " not allowed)");
    log.debug("Leaving answerPreflight(). Origin refused.");
    return;
  }
  var requested = req.headers["access-control-request-headers"];
  if (requested && HEADER_LIST.test(requested.trim())) {
    res.setHeader("Access-Control-Allow-Headers", requested.trim());
    addVary(res, "Access-Control-Request-Headers");
  } else {
    res.setHeader("Access-Control-Allow-Headers", DEFAULT_ALLOWED_HEADERS);
  }
  res.setHeader("Access-Control-Allow-Methods", ALLOWED_METHODS);
  res.setHeader("Access-Control-Max-Age", "86400");
  res.writeHead(204);
  res.end();
  logLine("204 OPTIONS " + req.url + " (preflight answered here)");
  log.debug("Leaving answerPreflight().");
}

function answerHealth(config, res) {
  log.debug("Entering answerHealth().");
  res.writeHead(200, { "Content-Type": "application/json",
                       "Cache-Control": "no-store" });
  res.end(JSON.stringify({ status: "ok", upstream: config.upstream,
                           upstreamTls: config.upstreamTls }));
  log.debug("Leaving answerHealth().");
}

// The request handler for one configuration. Returned as a closure so a test
// can build several proxies in one process.
function createHandler(config) {
  log.debug("Entering createHandler().");
  var transport = config.upstreamTls ? https : http;
  var upstreamCa = config.upstreamCaFile ?
    fs.readFileSync(config.upstreamCaFile) : undefined;

  function handle(req, res) {
    log.debug("Entering handle(). " + req.method + " " + req.url);
    var allowed = applyCors(config, req, res);

    if (req.method === "OPTIONS") {
      answerPreflight(req, res, allowed);
      log.debug("Leaving handle(). Preflight.");
      return;
    }
    if (req.method === "GET" && req.url === HEALTH_PATH) {
      answerHealth(config, res);
      log.debug("Leaving handle(). Health.");
      return;
    }

    var headers = Object.assign({}, req.headers);
    // The upstream must see a Host it accepts; it is addressed by its own
    // name.
    headers.host = config.upstream;

    var options = {
      host: config.upstreamHost,
      port: config.upstreamPort,
      method: req.method,
      path: req.url,
      headers: headers
    };
    if (config.upstreamTls) {
      options.servername = config.upstreamHost;
      if (upstreamCa) options.ca = upstreamCa;
    }

    var upstream = transport.request(options, function (answer) {
      // Whatever the service said, plus the CORS headers already set. Its own
      // CORS headers would otherwise arrive twice, which a browser rejects.
      // Its Vary is MERGED with the one set above rather than replacing it,
      // or a cache would serve one origin's answer to another.
      Object.keys(answer.headers).forEach(function (name) {
        var lower = name.toLowerCase();
        if (lower.indexOf("access-control-") === 0) return;
        if (lower === "vary") {
          addVary(res, [].concat(answer.headers[name]).join(", "));
          return;
        }
        res.setHeader(name, answer.headers[name]);
      });
      res.writeHead(answer.statusCode);
      answer.pipe(res);
      logLine(answer.statusCode + " " + req.method + " " + req.url);
    });

    upstream.on("error", function (e) {
      // The upstream is not there, not there yet, or (in TLS mode) presented
      // a certificate that does not verify. 502 with a readable reason beats
      // a socket hangup the browser reports as a network error.
      //
      // "service" rather than naming one: a copy of this proxy fronts each of
      // several, and a 502 naming the wrong one sends whoever reads it
      // looking at the wrong container.
      logLine("502 " + req.method + " " + req.url + " — upstream " +
          config.upstream + ": " + e.message);
      if (!res.headersSent) {
        res.writeHead(502, { "Content-Type": "application/json" });
      }
      res.end(JSON.stringify({
        error: "upstream_unavailable",
        error_description: "The service at " + config.upstream +
            " did not answer: " + e.message
      }));
    });

    req.pipe(upstream);
    log.debug("Leaving handle().");
  }

  log.debug("Leaving createHandler().");
  return handle;
}

// A server for one configuration, not yet listening.
function createProxy(config) {
  log.debug("Entering createProxy().");
  var handle = createHandler(config);
  var server = (config.tlsCertFile && config.tlsKeyFile) ?
    https.createServer({ cert: fs.readFileSync(config.tlsCertFile),
                         key: fs.readFileSync(config.tlsKeyFile) }, handle) :
    http.createServer(handle);
  log.debug("Leaving createProxy().");
  return server;
}

function main() {
  log.debug("Entering main().");
  var config = readConfig(process.env);
  config.deprecated.forEach(function (name) {
    log.warn("deprecated setting " + name + "; the old name is read for " +
        "one release.");
  });
  var server = createProxy(config);
  server.listen(config.port, "0.0.0.0", function () {
    logLine("CORS proxy listening on " + (config.tlsCertFile ? "https" :
        "http") + "://0.0.0.0:" + config.port + ", forwarding to " +
        (config.upstreamTls ? "https" : "http") + "://" + config.upstream +
        ", origins " + (config.anyOrigin ? "*" :
          config.allowedOrigins.join(" ")) + ".");
  });
  log.debug("Leaving main().");
}

module.exports = {
  HEALTH_PATH: HEALTH_PATH,
  ALLOWED_METHODS: ALLOWED_METHODS,
  EXPOSED_HEADERS: EXPOSED_HEADERS,
  readConfig: readConfig,
  createHandler: createHandler,
  createProxy: createProxy
};

if (require.main === module) {
  main();
}
