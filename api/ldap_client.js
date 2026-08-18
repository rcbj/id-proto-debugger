// File: ldap_client.js
//
// ---------------------------------------------------------------------------
// The guarded LDAP client behind the eight POST /ldap/* endpoints.
//
// LDAP is not an HTTP protocol. It is BER over a TCP socket (RFC 4511), so a
// browser cannot speak it at all — no `fetch`, no XHR, no WebSocket will
// produce an LDAPMessage — and the whole workflow therefore needs this service
// the way the Kerberos workflow needs `krb5_relay.js`. The page builds the
// operation, this file performs it and reports both halves.
//
// It is NOT a byte relay, and that is the difference from the Kerberos one. The
// caller sends an operation described in JSON (a DN, a filter, a list of
// changes) and this file encodes it with `ldapjs`, so the bytes on the wire are
// this service's and never the caller's. That is a much narrower primitive than
// `POST /krb5/kdc`, and it is what lets the port allowlist below be a
// convenience rather than the only thing standing between this endpoint and a
// port scanner.
//
// The library is the `node-ldapjs` SUBMODULE at the repository root, pinned by
// commit and used UNMODIFIED — `"ldapjs": "file:../node-ldapjs"` in
// api/package.json. The mock STS's embedded directory is built on the same
// submodule, which is deliberate and has one consequence worth stating: an
// interoperability bug that both sides share would be invisible to the test
// suite. `tests/api_ldap.js` is written against RFC 4511's own vocabulary
// (result codes, scopes, change operations) rather than against whatever this
// pair happens to agree on, for that reason.
//
// ---------------------------------------------------------------------------
// WHY api/ssrf_guard.js DOES NOT COVER THIS, AND WHAT IS DONE INSTEAD.
//
// Exactly the reason krb5_relay.js gives: the guard is installed on the shared
// **axios** instance — a request interceptor plus `lookup` and `createConnection`
// hooks on the outbound agents — and `net.connect(port, host)` walks past all of
// it. There is no axios in this path and no agent to hook.
//
// So this is a third enforcement of the same policy for a transport the guard
// has never seen, and like the second one it reuses the guard's DECISION
// (`blockedRangeFor`) rather than its own copy of the ranges. Two
// implementations of an address policy is one implementation and one hole.
//
// Four things bound this client:
//
//  1. **The scheme must be `ldap:` or `ldaps:`.** Not an address policy, so it
//     is not behind the address policy's off switch. `ldapjs` parses the URL
//     itself and would otherwise treat an unknown scheme as a default port.
//  2. **The address policy**, shared with the HTTP and Kerberos sides.
//  3. **Resolve, then connect to the LITERAL** that was checked. A name
//     re-resolved by the OS between the check and the connect is the
//     DNS-rebinding window. For `ldaps:` the ORIGINAL NAME is still handed to
//     TLS as `servername`, or connecting to the literal would break certificate
//     verification — which would be a security hole created by a security
//     control.
//  4. **A port allowlist**, `ldapAllowedPorts`, defaulting to the four assigned
//     ones: 389 (LDAP), 636 (LDAPS), 3268 and 3269 (the Active Directory global
//     catalogue, plain and over TLS).
//
// And the limits, which are the existing settings reused with the reasoning
// unchanged: `connectionTimeout` bounds the name lookup and, separately, the
// connection; `callTimeout` bounds the operation once a connection is up,
// because a directory that has answered is alive and thinking and a large
// subtree search legitimately takes longer than a connect; `maxContentLength`
// caps how much of a search result is accumulated in memory, because a search
// with no filter against a real directory is megabytes and a deadline does not
// bound a size.
//
// ---------------------------------------------------------------------------
// EVERY PATH ANSWERS, AND HERE THE FAILURE PATH IS THE COMMON ONE.
//
// The same rule the Kerberos relay states, for the same reason: pointing this
// at a host that may not be there, or at a DN that may not exist, is the POINT.
// A `NoSuchObject` is not an error in this endpoint's own terms — it is the
// answer, and the caller wants the result code. So the handlers in server.js
// distinguish three things that a naive implementation collapses into one 500:
//
//   * a refusal by THIS service (bad scheme, blocked address, port not allowed)
//     — 400, the caller asked for something this service will not do;
//   * a network failure (no route, refused, timed out) — 502, the caller asked
//     for something reasonable and the far end did not deliver;
//   * an LDAP RESULT CODE from the directory — **200**, with `ok: false` and the
//     code. The operation completed; the answer was "no". Reporting that as a
//     500 would make a debugger unable to show the single most interesting
//     thing about a directory.
// ---------------------------------------------------------------------------

const dns = require('dns');
const net = require('net');
const ldap = require('ldapjs');

// The assigned ports. 389 and 636 are LDAP and LDAPS; 3268 and 3269 are the
// Active Directory global catalogue, which is where a real debugging session
// spends much of its time because it is the only place a forest-wide search
// works.
const DEFAULT_ALLOWED_PORTS = [389, 636, 3268, 3269];

const DEFAULT_CONNECT_TIMEOUT_MS = 5000;
const DEFAULT_CALL_TIMEOUT_MS = 10000;
const DEFAULT_MAX_RESULT_BYTES = 1048576;

// A ceiling on the number of entries this service will accumulate from one
// search, independent of the byte cap. Both are needed: a million one-attribute
// entries is well inside a megabyte of values and is still a million objects to
// build, and a single entry carrying a large `jpegPhoto` is one object and is
// still megabytes. The caller may ask for fewer with the protocol's own
// `sizeLimit`; it may not ask for more.
const DEFAULT_MAX_ENTRIES = 1000;

// The scopes, by their RFC 4511 section 4.5.1.2 names. Spelled out here rather
// than passed through, because ldapjs accepts several aliases for each and a
// debugger that silently reinterpreted `one` as `sub` would report a result set
// that is a SUPERSET of what was asked for — which every assertion about the
// contents still passes, so the mistake is invisible in the one direction that
// makes it hardest to find. It has already happened once, on the mock's side.
const SCOPES = { base: 'base', one: 'one', sub: 'sub' };

// The three modify operations of RFC 4511 section 4.6. Same reasoning: an
// unrecognised operation must be a refusal and never a default.
const MODIFY_OPERATIONS = ['add', 'delete', 'replace'];

function resolvePositiveNumber(value, fallback, name, log) {
  log.debug("Entering resolvePositiveNumber().");
  if (typeof value === 'number' && isFinite(value) && value > 0) {
    log.debug("Leaving resolvePositiveNumber().");
    return value;
  }
  if (value !== undefined && value !== null) {
    log.error('ldap_client: ' + name + ' is not a positive number (' +
              JSON.stringify(value) + '); using ' + fallback + '.');
  }
  log.debug("Leaving resolvePositiveNumber().");
  return fallback;
}

// The port allowlist. A malformed entry is dropped with its reason logged, and
// an allowlist that ends up empty refuses every call — the safe direction, but
// almost certainly a mistake, so it is logged as one.
function resolveAllowedPorts(value, log) {
  log.debug("Entering resolveAllowedPorts().");
  if (value === undefined || value === null) {
    log.debug("Leaving resolveAllowedPorts().");
    return DEFAULT_ALLOWED_PORTS.slice();
  }
  if (value === 'any') {
    // Spelled as a word, like krb5ServicePorts's own "any", so that widening
    // this cannot be a plausible typo. It is far less dangerous here than there
    // — this client sends LDAP it encoded itself, not caller-supplied bytes —
    // but a deployment that wants it should still have said so.
    log.debug("Leaving resolveAllowedPorts(). Any port is allowed.");
    return 'any';
  }
  if (!Array.isArray(value)) {
    log.error('ldap_client: ldapAllowedPorts must be an array of port ' +
              'numbers, or the string "any"; using the default ' +
              DEFAULT_ALLOWED_PORTS.join(', ') + '.');
    log.debug("Leaving resolveAllowedPorts().");
    return DEFAULT_ALLOWED_PORTS.slice();
  }
  const ports = [];
  for (const entry of value) {
    const port = typeof entry === 'number' ? entry : parseInt(entry, 10);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      log.error('ldap_client: ignoring ldapAllowedPorts entry ' +
                JSON.stringify(entry) +
                ' — a port must be an integer from 1 to 65535.');
      continue;
    }
    if (ports.indexOf(port) === -1) ports.push(port);
  }
  if (!ports.length) {
    log.error('ldap_client: ldapAllowedPorts contained no usable ports, so ' +
              'every LDAP call will be refused. That is the safe direction, ' +
              'but it is almost certainly a configuration mistake.');
  }
  log.debug("Leaving resolveAllowedPorts().");
  return ports;
}

// The URL, split into the parts this file needs, with the scheme checked.
//
// Written out rather than taken from `ldap.parseURL`, because the check has to
// happen BEFORE anything is handed to the library: an unknown scheme is
// something this service refuses, and a parser that helpfully defaults one is a
// parser that has already made the decision.
function parseLdapUrl(value) {
  const text = String(value == null ? '' : value).trim();
  const match = /^(ldaps?):\/\/([^/?#]+)(\/.*)?$/i.exec(text);
  if (!match) {
    return { ok: false,
             reason: 'not an LDAP URL. It must begin ldap:// or ldaps://' };
  }
  const scheme = match[1].toLowerCase();
  let authority = match[2];
  // An IPv6 literal is written in brackets, and the colon inside it is not the
  // port separator. Getting this wrong turns ldaps://[::1]:636 into a host of
  // "[" and a port of nothing, which then fails as a DNS error naming a
  // bracket.
  let host;
  let port;
  const v6 = /^\[([^\]]+)\](?::(\d+))?$/.exec(authority);
  if (v6) {
    host = v6[1];
    port = v6[2] ? parseInt(v6[2], 10) : null;
  } else {
    const parts = authority.split(':');
    host = parts[0];
    port = parts.length > 1 ? parseInt(parts[1], 10) : null;
  }
  if (!host) {
    return { ok: false, reason: 'the URL names no host' };
  }
  if (port !== null && (!Number.isInteger(port) || port < 1 || port > 65535)) {
    return { ok: false, reason: 'the port is not a number from 1 to 65535' };
  }
  if (port === null) port = (scheme === 'ldaps') ? 636 : 389;
  return { ok: true, scheme: scheme, host: host, port: port,
           secure: scheme === 'ldaps' };
}

// An LDAP result code with its RFC 4511 appendix A name, from whatever ldapjs
// threw. Both halves matter to a debugger: the number is what an operator's
// runbook is written against, the name is what makes the number readable.
function resultOf(err) {
  if (!err) return { code: 0, name: 'success' };
  const code = (typeof err.code === 'number') ? err.code : null;
  // ldapjs names its error classes after the result code — InvalidCredentials-
  // Error, NoSuchObjectError — so the name is derived from the class rather
  // than from a second table that could disagree with the library's own.
  const name = String(err.name || '')
    .replace(/Error$/, '')
    .replace(/^([A-Z])/, function (c) { return c.toLowerCase(); });
  return { code: code, name: name || 'unknown' };
}

function createLdapClient(appconfig, guard, log, deps) {
  log.debug("Entering createLdapClient().");
  appconfig = appconfig || {};
  const logger = log || { debug() {}, info() {}, warn() {}, error() {} };

  // Injectable for the same reason krb5_relay.js's is: a deadline cannot be
  // tested against a resolver that works, and `dns.lookup` is getaddrinfo, so
  // it ignores `dns.setServers` and cannot be pointed at a black hole from
  // inside the process. `tests/api_ldap.js` passes one that never calls back.
  // Nothing in server.js supplies this.
  const lookup = (deps && deps.lookup) || dns.lookup;
  // Injectable for a different reason: so a test can assert what this file
  // asked the library for without a directory on the other end.
  const createClient = (deps && deps.createClient) || ldap.createClient;

  const allowedPorts = resolveAllowedPorts(appconfig.ldapAllowedPorts, logger);
  const anyPort = allowedPorts === 'any';
  const connectTimeout = resolvePositiveNumber(appconfig.connectionTimeout,
    DEFAULT_CONNECT_TIMEOUT_MS, 'connectionTimeout', logger);
  const callTimeout = resolvePositiveNumber(appconfig.callTimeout,
    DEFAULT_CALL_TIMEOUT_MS, 'callTimeout', logger);
  const maxResultBytes = resolvePositiveNumber(appconfig.maxContentLength,
    DEFAULT_MAX_RESULT_BYTES, 'maxContentLength', logger);
  const maxEntries = resolvePositiveNumber(appconfig.ldapMaxEntries,
    DEFAULT_MAX_ENTRIES, 'ldapMaxEntries', logger);
  // The address policy is the guard's, not a second copy of it.
  const addressPolicyEnabled = !!(guard && guard.enabled);

  logger.info('ldap_client: ports ' +
    (anyPort ? 'ANY (ldapAllowedPorts is "any")'
             : (allowedPorts.join(', ') || '(none — every call is refused)')) +
    '; connect timeout ' + connectTimeout + ' milliseconds; call timeout ' +
    callTimeout + ' milliseconds; result cap ' + maxResultBytes + ' bytes and ' +
    maxEntries + ' entries; address policy ' +
    (addressPolicyEnabled ? 'ENABLED (shared with ssrf_guard)' : 'disabled'));

  function refuse(message, code) {
    const error = new Error(message);
    error.code = code || 'ELDAPREFUSED';
    error.refused = true;
    return error;
  }

  function assertPortAllowed(port) {
    log.debug("Entering assertPortAllowed().");
    if (anyPort) {
      log.debug("Leaving assertPortAllowed(). Any port is allowed.");
      return;
    }
    if (allowedPorts.indexOf(port) === -1) {
      log.debug("Leaving assertPortAllowed(). The port is not allowed.");
      throw refuse('Refusing to connect to port ' + port + '. This service ' +
        'speaks LDAP to LDAP ports only (' +
        (allowedPorts.join(', ') || 'none configured') + '). Add the port to ' +
        'ldapAllowedPorts if this deployment needs it, or set that setting to ' +
        'the string "any".', 'ELDAPPORTNOTALLOWED');
    }
    log.debug("Leaving assertPortAllowed().");
  }

  // Resolve the host and return an address that has passed the policy. A
  // literal is checked directly — node never calls a resolver for one, which is
  // the gap that made the HTTP guard need two hooks rather than one.
  //
  // The lookup is on its own deadline, and it has to be: the connect budget is
  // armed by ldapjs once a socket exists, so until this settles NOTHING is
  // timing the call. That is the same hang `krb5_relay.js` records having hit
  // on a stub resolver waiting out its retries, and the symptom on this
  // endpoint would be identical — a browser waiting on an api that never
  // replies.
  //
  // A late callback is dropped rather than raced: `dns.lookup` runs in the
  // libuv threadpool and cannot be cancelled.
  function resolveAllowedAddress(host) {
    log.debug("Entering resolveAllowedAddress(). host=" + host);
    log.debug("Leaving resolveAllowedAddress(). The promise is pending.");
    return new Promise(function (resolve, reject) {
      const literalFamily = net.isIP(host);
      if (literalFamily) {
        const range = addressPolicyEnabled && guard.blockedRangeFor(host);
        if (range) {
          return reject(refuse('Refusing to open a connection to ' + host +
            ': it is in the blocked range ' + range + '. This service does ' +
            'not connect to loopback or private network addresses. Set ' +
            'blockPrivateNetworkCalls to false in the api configuration if ' +
            'this deployment is meant to — the local and containerized ' +
            'stacks do, because their directory IS a private address.',
            'EBLOCKEDADDRESS'));
        }
        return resolve({ address: host, family: literalFamily,
                         wasLiteral: true });
      }
      let settled = false;
      const deadline = setTimeout(function () {
        if (settled) {
          return;
        }
        settled = true;
        logger.warn('ldap_client: gave up resolving ' + host + ' after ' +
                    connectTimeout + ' milliseconds');
        reject(refuse('Timed out after ' + connectTimeout + ' milliseconds ' +
          'resolving ' + host + '. The name was never turned into an address, ' +
          'so no connection was attempted — this is a DNS problem on the ' +
          'machine running this service rather than anything about the ' +
          'directory. Check the resolver, or give the server by address.',
          'ELDAPDNSTIMEOUT'));
      }, connectTimeout);
      lookup(host, { all: true }, function (err, addresses) {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(deadline);
        if (err) {
          return reject(refuse('Could not resolve ' + host + ': ' +
            err.message + ' (' + err.code + ').', 'ELDAPDNS'));
        }
        const list = Array.isArray(addresses) ? addresses : [addresses];
        for (const entry of list) {
          const range = addressPolicyEnabled &&
            guard.blockedRangeFor(entry.address);
          if (range) {
            logger.warn('ldap_client: refused ' + host + ' -> ' +
                        entry.address + ' (' + range + ')');
            return reject(refuse('Refusing to connect to ' + host +
              ': it resolves to ' + entry.address + ', which is in the ' +
              'blocked range ' + range + '. Note that a name is judged by ' +
              'what it RESOLVES to, so localtest.me and 127.0.0.1.nip.io are ' +
              'caught by the same rule.', 'EBLOCKEDADDRESS'));
          }
        }
        // Connect to the literal that was checked, not to the name.
        // Re-resolving at connect time is the DNS-rebinding window.
        resolve({ address: list[0].address, family: list[0].family,
                  wasLiteral: false });
      });
    });
  }

  // Open a connection and bind it. Resolves with the bound client; the caller
  // is responsible for unbinding it, which `withConnection` below does in a
  // `finally` so that no path can leak a socket.
  function connectAndBind(target, url, bindDn, password, report) {
    log.debug("Entering connectAndBind().");
    log.debug("Leaving connectAndBind(). The promise is pending.");
    return new Promise(function (resolve, reject) {
      let settled = false;
      // The URL given to the library names the ADDRESS that was checked, not
      // the host that was asked for. For ldaps: the original name still has to
      // reach TLS or certificate verification would compare the certificate
      // against an IP address and fail every time — a security control
      // producing a security hole. `servername` is what carries it.
      const dialled = url.scheme + '://' +
        (net.isIPv6(target.address) ? '[' + target.address + ']'
                                    : target.address) +
        ':' + url.port;
      const tlsOptions = url.secure
        ? { servername: url.host,
            // The same choice every other endpoint here offers, for the same
            // reason: a test directory's certificate is self-signed, and
            // refusing it would make the workflow untestable. Only an explicit
            // false disables verification, so a missing or oddly-typed field in
            // a request body cannot quietly stop certificates being checked.
            rejectUnauthorized: report.rejectUnauthorized }
        : undefined;
      let client;
      try {
        client = createClient({
          url: dialled,
          log: logger,
          tlsOptions: tlsOptions,
          connectTimeout: connectTimeout,
          timeout: callTimeout,
          // NO RECONNECTION. ldapjs will otherwise retry a dropped connection
          // behind the caller's back, which is right for a long-lived
          // application client and wrong for a debugger: the whole value here
          // is showing exactly what happened once, and a silent retry turns an
          // intermittent failure into a report that says everything worked.
          reconnect: false,
          // Nothing may sit in a queue either. A queued operation is one whose
          // timing this file did not measure and whose failure it cannot
          // attribute.
          queueDisable: true
        });
      } catch (e) {
        return reject(refuse('Could not create an LDAP client for ' + dialled +
          ': ' + e.message, 'ELDAPCLIENT'));
      }

      function finish(err, value) {
        log.debug("Entering finish().");
        if (settled) {
          log.debug("Leaving finish(). It had already settled.");
          return;
        }
        settled = true;
        if (err) {
          try {
            client.destroy();
          } catch (e) {
            // Already gone. Nothing to do, and nothing worth reporting: the
            // failure the caller is about to be told about is the real one.
          }
          log.debug("Leaving finish(). Rejecting.");
          return reject(err);
        }
        log.debug("Leaving finish(). Resolving.");
        resolve(value);
      }

      // A connection-level failure arrives here rather than on the bind
      // callback, and it is the common one when a host is not listening.
      client.on('error', function (err) {
        finish(refuse('Could not reach the directory at ' + url.host + ':' +
          url.port + (target.wasLiteral ? '' : ' [' + target.address + ']') +
          ': ' + err.message + (err.code ? ' (' + err.code + ')' : '') + '.',
          'ELDAPCONNECT'));
      });
      client.on('connectTimeout', function () {
        finish(refuse('Timed out after ' + connectTimeout + ' milliseconds ' +
          'connecting to ' + target.address + ':' + url.port + '. Nothing ' +
          'accepted a connection — either no directory is listening there, ' +
          'or a firewall is dropping the packets silently.',
          'ELDAPCONNECTTIMEOUT'));
      });

      // THE BIND WAITS FOR THE SOCKET, and this is not optional given
      // `queueDisable` above. ldapjs's client is created in a not-yet-connected
      // state and an operation issued before the `connect` event is either
      // QUEUED or, with the queue off, refused immediately with result code 80
      // and the message "connection unavailable". That refusal looks exactly
      // like a directory answering `other`, so the first working version of
      // this file reported a healthy local server as a failed bind with a code
      // that has nothing to do with credentials. Binding from inside the
      // `connect` handler is what makes queueDisable safe rather than wrong:
      // nothing is ever issued early, so nothing ever needs a queue.
      client.on('connect', function () {
        report.connectedAt = Date.now();
        doBindNow();
      });

      function doBindNow() {
        log.debug("Entering doBindNow().");
        log.debug("Leaving doBindNow(). The bind was issued.");
        client.bind(bindDn, password, onBindResult);
      }

      function onBindResult(err) {
        report.boundAt = Date.now();
        if (err) {
          // A bind that is REFUSED is not a failure of this endpoint: it is the
          // answer, and it is the single most interesting thing a directory
          // says. It is carried out as a value rather than thrown, so the
          // handler can report result code 49 with a 200.
          const result = resultOf(err);
          report.bindResult = result;
          report.bindMessage = err.message;
          log.debug("Leaving the bind callback. The directory refused it: " +
                    result.name + ' (' + result.code + ').');
          return finish(null, { client: client, bound: false });
        }
        report.bindResult = { code: 0, name: 'success' };
        log.debug("Leaving onBindResult(). The bind succeeded.");
        finish(null, { client: client, bound: true });
      }
    });
  }

  // Open, bind, run `body`, unbind. The unbind is in a `finally` and the
  // `destroy` after it is not redundant: `unbind` is itself an LDAP operation
  // and can hang against a server that has stopped answering, in which case the
  // socket is still open and the process still has a descriptor.
  async function withConnection(options, body) {
    log.debug("Entering withConnection().");
    const url = parseLdapUrl(options.url);
    if (!url.ok) {
      log.debug("Leaving withConnection(). The URL was refused.");
      throw refuse('Refusing to use ' + JSON.stringify(options.url) + ': ' +
        url.reason + '. This endpoint speaks LDAP, so the scheme is the one ' +
        'thing about the URL it cannot be flexible about.', 'ELDAPBADURL');
    }
    assertPortAllowed(url.port);
    const target = await resolveAllowedAddress(url.host);

    const report = {
      startedAt: Date.now(),
      connectedAt: null,
      boundAt: null,
      bindResult: null,
      bindMessage: '',
      // Only an explicit false disables certificate verification.
      rejectUnauthorized: options.rejectUnauthorized !== false
    };
    const bindDn = String(options.bindDn == null ? '' : options.bindDn);
    const password = String(options.password == null ? '' : options.password);

    const connection = await connectAndBind(target, url, bindDn, password,
                                            report);
    let outcome;
    try {
      if (!connection.bound) {
        // The bind was refused, so no operation follows it. This is not an
        // error path: the caller asked for an operation, the directory said who
        // it would not let do it, and that answer is the result.
        outcome = { ok: false, result: report.bindResult,
                    diagnosticMessage: report.bindMessage,
                    stoppedAt: 'bind' };
      } else {
        outcome = await body(connection.client);
      }
    } finally {
      try {
        await new Promise(function (resolve) {
          const done = setTimeout(resolve, 1000);
          connection.client.unbind(function () {
            clearTimeout(done);
            resolve();
          });
        });
      } catch (e) {
        logger.warn('ldap_client: the unbind did not complete: ' + e.message);
      }
      try {
        connection.client.destroy();
      } catch (e) {
        // Already closed by the unbind. Expected, and not worth a line.
      }
    }

    const finishedAt = Date.now();
    log.debug("Leaving withConnection(). ok=" + outcome.ok);
    return Object.assign({
      target: {
        url: url.scheme + '://' + url.host + ':' + url.port,
        host: url.host,
        address: target.address,
        port: url.port,
        secure: url.secure,
        resolved: !target.wasLiteral
      },
      bind: {
        dn: bindDn,
        anonymous: bindDn === '',
        // The password is never echoed. Its LENGTH is, because "did the field
        // reach the server at all" is a real question when a bind fails and a
        // debugger that answers it with silence sends people hunting.
        passwordChars: password.length,
        result: report.bindResult
      },
      timing: {
        totalMs: finishedAt - report.startedAt,
        // Split rather than summed, because the two answer different questions
        // and a single number hides which one went wrong: a slow CONNECT is the
        // network, a slow BIND is the directory deciding.
        connectMs: report.connectedAt
          ? report.connectedAt - report.startedAt : null,
        bindMs: (report.boundAt && report.connectedAt)
          ? report.boundAt - report.connectedAt : null
      }
    }, outcome);
  }

  // --- the operations ------------------------------------------------------
  //
  // Each is the same shape: describe what will be sent (so the page can show
  // the request even when the operation fails), perform it, and turn whatever
  // came back into a result code. None of them throws on an LDAP result — see
  // the note at the top of this file.

  function operationPromise(label, fn) {
    log.debug("Entering operationPromise(). label=" + label);
    log.debug("Leaving operationPromise(). The promise is pending.");
    return new Promise(function (resolve) {
      const startedAt = Date.now();
      fn(function (err) {
        const result = resultOf(err);
        resolve({
          ok: !err,
          result: result,
          diagnosticMessage: err ? String(err.message || '') : '',
          operationMs: Date.now() - startedAt
        });
      });
    });
  }

  async function doBind(options) {
    log.debug("Entering doBind().");
    const out = await withConnection(options, function () {
      // The bind IS the operation here, and withConnection has already done it.
      // There is deliberately nothing else: a "test this credential" call that
      // also searched would report a failure that belonged to the search.
      return Promise.resolve({ ok: true, result: { code: 0, name: 'success' },
                               diagnosticMessage: '' });
    });
    log.debug("Leaving doBind().");
    return Object.assign({ operation: 'bind' }, out);
  }

  async function doSearch(options) {
    log.debug("Entering doSearch().");
    const scope = SCOPES[String(options.scope || 'sub').toLowerCase()];
    if (!scope) {
      log.debug("Leaving doSearch(). The scope was refused.");
      throw refuse('Unknown search scope ' + JSON.stringify(options.scope) +
        '. RFC 4511 section 4.5.1.2 has three: base, one and sub.',
        'ELDAPBADSCOPE');
    }
    const filter = String(options.filter || '(objectClass=*)');
    const attributes = Array.isArray(options.attributes)
      ? options.attributes.map(function (a) { return String(a); })
        .filter(function (a) { return a !== ''; })
      : [];
    const clientSizeLimit = parseInt(options.sizeLimit, 10);
    const sizeLimit = Number.isInteger(clientSizeLimit) && clientSizeLimit > 0
      ? Math.min(clientSizeLimit, maxEntries)
      : maxEntries;
    const request = {
      baseDn: String(options.baseDn || ''),
      scope: scope,
      filter: filter,
      attributes: attributes,
      sizeLimit: sizeLimit,
      derefAliases: 0
    };
    const out = await withConnection(options, function (client) {
      return new Promise(function (resolve) {
        const startedAt = Date.now();
        const entries = [];
        let bytes = 0;
        let truncated = null;
        let settled = false;
        function done(payload) {
          if (settled) return;
          settled = true;
          resolve(Object.assign({
            entries: entries,
            entryCount: entries.length,
            truncated: truncated,
            operationMs: Date.now() - startedAt
          }, payload));
        }
        client.search(request.baseDn, {
          scope: scope,
          filter: filter,
          attributes: attributes,
          sizeLimit: sizeLimit
        }, function (err, res) {
          if (err) {
            return done({ ok: false, result: resultOf(err),
                          diagnosticMessage: String(err.message || '') });
          }
          res.on('searchEntry', function (entry) {
            // Two caps, and both are needed — see DEFAULT_MAX_ENTRIES.
            if (entries.length >= maxEntries) {
              truncated = 'this service stopped at ' + maxEntries +
                ' entries (ldapMaxEntries). The directory may have had more.';
              return;
            }
            const flat = { dn: '', attributes: {} };
            const pojo = entry.pojo || {};
            flat.dn = String(pojo.objectName || '');
            (pojo.attributes || []).forEach(function (attr) {
              flat.attributes[attr.type] = (attr.values || [])
                .map(function (v) { return String(v); });
            });
            bytes += JSON.stringify(flat).length;
            if (bytes > maxResultBytes) {
              truncated = 'this service stopped at ' + maxResultBytes +
                ' bytes of results (maxContentLength). The directory may ' +
                'have had more.';
              return;
            }
            entries.push(flat);
          });
          res.on('searchReference', function (referral) {
            // Recorded rather than followed. Chasing a referral means opening a
            // connection to a URL the DIRECTORY chose, which is a
            // server-side request forgery with a specification citation
            // attached — the same reason WS-Federation's `wreqptr` is never
            // dereferenced. The reader is told it happened and where to.
            const uris = (referral.uris || referral.pojo &&
                          referral.pojo.uri || []);
            truncated = 'the directory returned a referral to ' +
              [].concat(uris).join(', ') + ', which this service does NOT ' +
              'follow: it would mean connecting to a URL the directory chose.';
          });
          res.on('error', function (e) {
            // A size-limit result arrives here, and it is an ANSWER rather than
            // a failure: the entries already delivered are real. So the
            // partial result set is kept and the code is reported beside it.
            done({ ok: false, result: resultOf(e),
                   diagnosticMessage: String(e.message || '') });
          });
          res.on('end', function (result) {
            const code = result && typeof result.status === 'number'
              ? result.status : 0;
            done({ ok: code === 0,
                   result: { code: code,
                             name: code === 0 ? 'success' : 'see the code' },
                   diagnosticMessage: '' });
          });
        });
      });
    });
    log.debug("Leaving doSearch().");
    return Object.assign({ operation: 'search', request: request }, out);
  }

  async function doAdd(options) {
    log.debug("Entering doAdd().");
    const dn = String(options.dn || '');
    if (!dn) {
      log.debug("Leaving doAdd(). No DN.");
      throw refuse('An add needs the DN of the entry to create.',
                   'ELDAPNODN');
    }
    const attributes = {};
    Object.keys(options.attributes || {}).forEach(function (name) {
      const value = options.attributes[name];
      attributes[String(name)] = Array.isArray(value)
        ? value.map(function (v) { return String(v); })
        : [String(value)];
    });
    if (!Object.keys(attributes).length) {
      log.debug("Leaving doAdd(). No attributes.");
      throw refuse('An add needs at least one attribute. An entry with no ' +
        'attributes has no objectClass, and every directory refuses that — ' +
        'refusing here names the mistake instead of relaying it.',
        'ELDAPNOATTRIBUTES');
    }
    const out = await withConnection(options, function (client) {
      return operationPromise('add', function (cb) {
        client.add(dn, attributes, cb);
      });
    });
    log.debug("Leaving doAdd().");
    return Object.assign({ operation: 'add',
                           request: { dn: dn, attributes: attributes } }, out);
  }

  async function doDelete(options) {
    log.debug("Entering doDelete().");
    const dn = String(options.dn || '');
    if (!dn) {
      log.debug("Leaving doDelete(). No DN.");
      throw refuse('A delete needs the DN of the entry to remove.',
                   'ELDAPNODN');
    }
    const out = await withConnection(options, function (client) {
      return operationPromise('delete', function (cb) {
        client.del(dn, cb);
      });
    });
    log.debug("Leaving doDelete().");
    return Object.assign({ operation: 'delete', request: { dn: dn } }, out);
  }

  async function doModify(options) {
    log.debug("Entering doModify().");
    const dn = String(options.dn || '');
    if (!dn) {
      log.debug("Leaving doModify(). No DN.");
      throw refuse('A modify needs the DN of the entry to change.',
                   'ELDAPNODN');
    }
    const requested = Array.isArray(options.changes) ? options.changes : [];
    if (!requested.length) {
      log.debug("Leaving doModify(). No changes.");
      throw refuse('A modify needs at least one change (RFC 4511 section ' +
        '4.6).', 'ELDAPNOCHANGES');
    }
    const described = [];
    const changes = [];
    for (const entry of requested) {
      const operation = String((entry && entry.operation) || '').toLowerCase();
      if (MODIFY_OPERATIONS.indexOf(operation) === -1) {
        log.debug("Leaving doModify(). Unknown change operation.");
        throw refuse('Unknown modify operation ' +
          JSON.stringify(entry && entry.operation) + '. RFC 4511 section 4.6 ' +
          'has three: add, delete and replace.', 'ELDAPBADCHANGE');
      }
      const type = String((entry && entry.type) || '');
      if (!type) {
        log.debug("Leaving doModify(). A change names no attribute.");
        throw refuse('Every change has to name an attribute.',
                     'ELDAPBADCHANGE');
      }
      const raw = (entry && entry.values !== undefined) ? entry.values : [];
      const values = (Array.isArray(raw) ? raw : [raw])
        .map(function (v) { return String(v); })
        .filter(function (v) { return v !== ''; });
      described.push({ operation: operation, type: type, values: values });
      changes.push(new ldap.Change({
        operation: operation,
        modification: new ldap.Attribute({ type: type, values: values })
      }));
    }
    const out = await withConnection(options, function (client) {
      return operationPromise('modify', function (cb) {
        client.modify(dn, changes, cb);
      });
    });
    log.debug("Leaving doModify().");
    return Object.assign({ operation: 'modify',
                           request: { dn: dn, changes: described } }, out);
  }

  async function doModifyDn(options) {
    log.debug("Entering doModifyDn().");
    const dn = String(options.dn || '');
    const newRdn = String(options.newRdn || '');
    if (!dn || !newRdn) {
      log.debug("Leaving doModifyDn(). Missing dn or newRdn.");
      throw refuse('A modifyDN needs the entry\'s DN and its new RDN.',
                   'ELDAPNODN');
    }
    const newSuperior = options.newSuperior
      ? String(options.newSuperior) : null;
    const target = newRdn + (newSuperior ? ',' + newSuperior : '');
    const out = await withConnection(options, function (client) {
      return operationPromise('modifyDN', function (cb) {
        client.modifyDN(dn, target, cb);
      });
    });
    log.debug("Leaving doModifyDn().");
    return Object.assign({ operation: 'modifyDN',
                           request: { dn: dn, newRdn: newRdn,
                                      newSuperior: newSuperior,
                                      newDn: target } }, out);
  }

  async function doCompare(options) {
    log.debug("Entering doCompare().");
    const dn = String(options.dn || '');
    const attribute = String(options.attribute || '');
    if (!dn || !attribute) {
      log.debug("Leaving doCompare(). Missing dn or attribute.");
      throw refuse('A compare needs a DN and the attribute to compare.',
                   'ELDAPNODN');
    }
    const value = String(options.value == null ? '' : options.value);
    const out = await withConnection(options, function (client) {
      return new Promise(function (resolve) {
        const startedAt = Date.now();
        client.compare(dn, attribute, value, function (err, matched) {
          // A compare answers compareTrue (6) or compareFalse (5), NEITHER of
          // which is success (0). ldapjs turns that into a boolean and a null
          // error, so `matched` false is an answer and not a failure — a
          // handler that treated it as one would report every non-matching
          // value as a broken directory.
          resolve({
            ok: !err,
            matched: err ? null : !!matched,
            result: err ? resultOf(err)
                        : { code: matched ? 6 : 5,
                            name: matched ? 'compareTrue' : 'compareFalse' },
            diagnosticMessage: err ? String(err.message || '') : '',
            operationMs: Date.now() - startedAt
          });
        });
      });
    });
    log.debug("Leaving doCompare().");
    return Object.assign({ operation: 'compare',
                           request: { dn: dn, attribute: attribute,
                                      value: value } }, out);
  }

  log.debug("Leaving createLdapClient().");
  return {
    bind: doBind,
    search: doSearch,
    add: doAdd,
    del: doDelete,
    modify: doModify,
    modifyDn: doModifyDn,
    compare: doCompare,
    allowedPorts: anyPort ? 'any' : allowedPorts.slice(),
    addressPolicyEnabled: addressPolicyEnabled,
    limits: {
      connectTimeout: connectTimeout,
      callTimeout: callTimeout,
      maxResultBytes: maxResultBytes,
      maxEntries: maxEntries
    },
    scopes: Object.keys(SCOPES),
    modifyOperations: MODIFY_OPERATIONS.slice()
  };
}

module.exports = {
  createLdapClient: createLdapClient,
  parseLdapUrl: parseLdapUrl,
  resolveAllowedPorts: resolveAllowedPorts,
  DEFAULT_ALLOWED_PORTS: DEFAULT_ALLOWED_PORTS.slice(),
  SCOPES: SCOPES,
  MODIFY_OPERATIONS: MODIFY_OPERATIONS.slice()
};
