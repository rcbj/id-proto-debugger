// File: ssrf_guard.js
//
// ---------------------------------------------------------------------------
// Refuse outbound calls to loopback and private address ranges (SSRF guard).
//
// This service exists to make HTTP calls to URLs the CALLER supplies: the
// token, introspection, revocation, device-authorization and userinfo
// endpoints, the SAML ArtifactResolve back-channel, the WS-Trust STS, and the
// generic proxy. Anyone who can reach the api can therefore ask it to fetch a
// URL of their choosing, and it answers with the status, headers and body.
// Pointed at 127.0.0.1, at a neighbour on the deployment's private network, or
// at 169.254.169.254 (the cloud instance metadata service, which hands out
// credentials), that is a server-side request forgery — the api becomes a probe
// inside a network the caller cannot otherwise reach.
//
// So: block those destinations by default, and let a deployment that
// legitimately talks to private hosts turn it off.
//
//   appconfig.blockPrivateNetworkCalls   boolean; DEFAULT ON. Only an explicit
//                                        `false` disables it — a missing or
//                                        misspelled key stays safe. It governs
//                                        the ADDRESS layers only; the scheme
//                                        check below is not configurable.
//   appconfig.blockedAddressRanges       array of RANGES — CIDR blocks
//                                        ("10.0.0.0/8") or first-last pairs
//                                        ("10.0.0.0-10.255.255.255"). Defaults
//                                        to the list below when absent or
//                                        empty. A bare single address is
//                                        refused, with the reason logged: see
//                                        parseRange().
//
// THREE LAYERS, because no one of them is enough:
//
//   0. A SCHEME check, and it is UNCONDITIONAL — the only layer the
//      configuration cannot switch off, because it is not an address policy.
//      axios's Node adapter supports file: and data: as well as http(s), and a
//      `data:` URL is decoded by axios itself and handed straight back, so it
//      never reaches the network and no address rule below can see it. See
//      assertProtocolAllowed().
//
//   1. A request interceptor checks the URL before the call. This is what
//      produces a readable error, naming the host, the address it resolved to
//      and the range that matched.
//
//   2. The http/https AGENTS, which every connection goes through — including
//      REDIRECTS that axios follows on its own. Layer 1 sees only the first
//      URL, so a public host answering `302 Location: http://127.0.0.1:8080/`
//      would walk straight past it. Two hooks are needed here, not one: a
//      custom DNS `lookup` for hosts given as NAMES (which also closes most of
//      the DNS-rebinding window, being the resolution the socket actually
//      connects to), and a wrapped `createConnection` for hosts given as
//      LITERAL ADDRESSES — Node never calls `lookup` for those, and a redirect
//      Location is usually a literal.
//
// What is deliberately NOT here: an allow-list of public hosts (this is a
// debugger — it must reach arbitrary identity providers), and any attempt to
// block by hostname. Names are checked by what they RESOLVE to, so
// `localtest.me`, `127.0.0.1.nip.io` and a hostile DNS record pointing at
// loopback are all caught by the same rule.
// ---------------------------------------------------------------------------
const dns = require('dns');
const net = require('net');
const http = require('http');
const https = require('https');

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "ssrf_guard",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// The only URL schemes this service will fetch. axios's Node adapter also
// supports file: and data: (see platform.protocols), and every URL here comes
// from the caller, so the list is stated rather than inherited.
const ALLOWED_PROTOCOLS = ['http:', 'https:'];

// The default policy: loopback, the RFC 1918 private ranges, link-local (which
// is where cloud metadata lives), carrier-grade NAT, and the IPv6 equivalents.
// A deployment can replace this wholesale with appconfig.blockedAddressRanges.
const DEFAULT_BLOCKED_RANGES = [
  '127.0.0.0/8',        // loopback
  '0.0.0.0/8',
      // "this host on this network" (0.0.0.0 reaches loopback)
  '10.0.0.0/8',         // RFC 1918 private
  '172.16.0.0/12',      // RFC 1918 private
  '192.168.0.0/16',     // RFC 1918 private
  '169.254.0.0/16',     // link-local — includes 169.254.169.254, cloud metadata
  '100.64.0.0/10',      // RFC 6598 carrier-grade NAT
  '192.0.0.0/24',       // IETF protocol assignments
  '198.18.0.0/15',      // benchmarking
  '::1/128',            // IPv6 loopback
  'fe80::/10',          // IPv6 link-local
  'fc00::/7'            // IPv6 unique local
];

// --- address parsing -------------------------------------------------------
// Hand-rolled rather than pulled from a package: this file must not add a
// dependency to a service whose lockfile is already fragile, and the parsing is
// small enough to test exhaustively (see the checks at the bottom of this
// file's commit message and tests/api_ssrf_guard usage).

function parseIPv4(text) {
  log.debug("Entering parseIPv4().");
  const parts = String(text).split('.');
  if (parts.length !== 4) {
    log.debug("Leaving parseIPv4().");
    return null;
  }
  const bytes = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) {
      log.debug("Leaving parseIPv4().");
      return null;
    }
    const n = Number(part);
    if (n > 255) {
      log.debug("Leaving parseIPv4().");
      return null;
    }
    bytes.push(n);
  }
  log.debug("Leaving parseIPv4().");
  return bytes;
}

// Returns 16 bytes, expanding "::" and any trailing IPv4 form
// (::ffff:127.0.0.1).
function parseIPv6(text) {
  log.debug("Entering parseIPv6().");
  let s = String(text);
  // A zone index (fe80::1%eth0) plays no part in which range an address is in.
  const zone = s.indexOf('%');
  if (zone !== -1) s = s.slice(0, zone);
  if (s.indexOf(':') === -1) {
    log.debug("Leaving parseIPv6().");
    return null;
  }

  // A trailing dotted-quad (::ffff:127.0.0.1) is rewritten as the two hex
  // groups it stands for, so the rest of this function has only one form to
  // handle. Getting this wrong is not cosmetic: ::ffff:127.0.0.1 is loopback,
  // and an expansion that puts those bytes in the wrong place lets it through.
  const lastColon = s.lastIndexOf(':');
  const afterLastColon = s.slice(lastColon + 1);
  if (afterLastColon.indexOf('.') !== -1) {
    const v4 = parseIPv4(afterLastColon);
    if (!v4) {
      log.debug("Leaving parseIPv6().");
      return null;
    }
    const hex = function (hi, lo) {
      log.debug("Entering hex().");
      log.debug("Leaving hex().");
      return ((hi << 8) | lo).toString(16);
    };
    s = s.slice(0, lastColon + 1) + hex(v4[0], v4[1]) + ':' + hex(v4[2], v4[3]);
  }

  const halves = s.split('::');
  if (halves.length > 2) {
    log.debug("Leaving parseIPv6().");
    return null;
  }
  const head = halves[0] ? halves[0].split(':') : [];
  const rest = halves.length === 2 ? (halves[1] ?
      halves[1].split(':') : []) : null;

  const groups = [];
  const pushGroup = function (g) {
    log.debug("Entering pushGroup().");
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) {
      log.debug("Leaving pushGroup().");
      return false;
    }
    const n = parseInt(g, 16);
    groups.push((n >> 8) & 0xff, n & 0xff);
    log.debug("Leaving pushGroup().");
    return true;
  };
  for (const g of head) { if (!pushGroup(g)) {
    log.debug("Leaving parseIPv6().");
    return null;
  } }
  if (rest === null) {
    // No "::": the address must be complete.
    if (groups.length !== 16) {
      log.debug("Leaving parseIPv6().");
      return null;
    }
    log.debug("Leaving parseIPv6().");
    return groups;
  }
  const after = [];
  for (const g of rest) {
    const before = groups.length;
    if (!pushGroup(g)) {
      log.debug("Leaving parseIPv6().");
      return null;
    }
    after.push(groups[before], groups[before + 1]);
    groups.length = before;
  }
  const fill = 16 - groups.length - after.length;
  if (fill < 0) {
    log.debug("Leaving parseIPv6().");
    return null;
  }
  log.debug("Leaving parseIPv6().");
  return groups.concat(new Array(fill).fill(0), after);
}

// { bytes, family } for an IPv4 or IPv6 literal, or null. An IPv4-mapped IPv6
// address (::ffff:127.0.0.1) is reduced to its IPv4 form, because that is the
// address the connection actually reaches — a classic way past a naive check.
function toAddress(text) {
  log.debug("Entering toAddress().");
  const version = net.isIP(String(text));
  if (version === 4) {
    const bytes = parseIPv4(text);
    log.debug("Leaving toAddress().");
    return bytes ? { bytes: bytes, family: 4 } : null;
  }
  if (version === 6) {
    const bytes = parseIPv6(text);
    if (!bytes) {
      log.debug("Leaving toAddress().");
      return null;
    }
    const mapped = bytes.slice(0, 10).every(function (b) { return b === 0; }) &&
                   bytes[10] === 0xff && bytes[11] === 0xff;
    if (mapped) {
      log.debug("Leaving toAddress().");
      return { bytes: bytes.slice(12), family: 4 };
    }
    log.debug("Leaving toAddress().");
    return { bytes: bytes, family: 6 };
  }
  // Not a literal: parse it anyway, since net.isIP rejects forms we still want
  // to understand (it is strict about leading zeroes, for instance).
  const v4 = parseIPv4(text);
  if (v4) {
    log.debug("Leaving toAddress().");
    return { bytes: v4, family: 4 };
  }
  const v6 = parseIPv6(text);
  if (v6) {
    log.debug("Leaving toAddress().");
    return { bytes: v6, family: 6 };
  }
  log.debug("Leaving toAddress().");
  return null;
}

function compareBytes(a, b) {
  log.debug("Entering compareBytes().");
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      log.debug("Leaving compareBytes().");
      return a[i] < b[i] ? -1 : 1;
    }
  }
  log.debug("Leaving compareBytes().");
  return 0;
}

// The configuration is a list of RANGES, in either of the two notations an
// operator would reasonably write:
//
//   "10.0.0.0/8"                      a CIDR block
//   "10.0.0.0-10.255.255.255"         first and last address, inclusive
//
// A BARE ADDRESS is refused rather than quietly read as a /32. This list is a
// network policy, and one-address entries in it are almost always a mistake —
// the author meant the block that address sits in. Refusing says so; treating
// it as a single host would silently leave the rest of that network reachable.
// Write "10.1.2.3/32" (or "10.1.2.3-10.1.2.3") to mean exactly one address.
//
// Returns { family, text, kind } plus the bounds for its kind, or
// { error: <reason> } so the caller can say what was wrong with which entry.
function parseRange(entry) {
  log.debug("Entering parseRange().");
  const text = String(entry).trim();
  if (!text) {
    log.debug("Leaving parseRange().");
    return { error: 'empty' };
  }

  const dash = text.indexOf('-');
  if (dash !== -1) {
    const lo = toAddress(text.slice(0, dash).trim());
    const hi = toAddress(text.slice(dash + 1).trim());
    if (!lo || !hi) {
      log.debug("Leaving parseRange().");
      return { error: 'not an address range' };
    }
    if (lo.family !== hi.family) {
      log.debug("Leaving parseRange().");
      return { error: 'mixes IPv4 and IPv6' };
    }
    if (compareBytes(lo.bytes, hi.bytes) > 0) {
      log.debug("Leaving parseRange().");
      return { error: 'starts after it ends' };
    }
    log.debug("Leaving parseRange().");
    return { kind: 'span', family: lo.family, lo: lo.bytes, hi: hi.bytes,
            text: text };
  }

  const slash = text.indexOf('/');
  if (slash === -1) {
    log.debug("Leaving parseRange().");
    return { error: 'is a single address, not a range — write it as a ' +
            'CIDR block ' +
                    '(e.g. "' + text + '/32") or a first-last pair' };
  }
  const address = toAddress(text.slice(0, slash));
  if (!address) {
    log.debug("Leaving parseRange().");
    return { error: 'not an address range' };
  }
  const bits = address.family === 4 ? 32 : 128;
  const prefix = Number(text.slice(slash + 1));
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > bits) {
    log.debug("Leaving parseRange().");
    return { error: 'has a prefix length outside 0-' + bits };
  }
  log.debug("Leaving parseRange().");
  return { kind: 'cidr', family: address.family, bytes: address.bytes,
          prefix: prefix, text: text };
}

function withinRange(address, range) {
  log.debug("Entering withinRange().");
  if (address.family !== range.family) {
    log.debug("Leaving withinRange().");
    return false;
  }
  if (range.kind === 'span') {
    log.debug("Leaving withinRange().");
    return compareBytes(address.bytes, range.lo) >= 0 &&
           compareBytes(address.bytes, range.hi) <= 0;
  }
  let remaining = range.prefix;
  for (let i = 0; i < address.bytes.length && remaining > 0; i++) {
    const take = Math.min(8, remaining);
    const mask = take === 8 ? 0xff : (0xff << (8 - take)) & 0xff;
    if ((address.bytes[i] & mask) !== (range.bytes[i] & mask)) {
      log.debug("Leaving withinRange().");
      return false;
    }
    remaining -= take;
  }
  log.debug("Leaving withinRange().");
  return true;
}

// --- the guard -------------------------------------------------------------

function createGuard(appconfig, log) {
  log.debug("Entering createGuard().");
  appconfig = appconfig || {};
  const logger = log || { debug: function () {
    log.debug("Entering debug().");
    log.debug("Leaving debug().");
  }, info: function () {
    log.debug("Entering info().");
    log.debug("Leaving info().");
  }, warn: function () {
    log.debug("Entering warn().");
    log.debug("Leaving warn().");
  }, error: function () {
    log.debug("Entering error().");
    log.debug("Leaving error().");
  } };
  // Only an explicit false disables the guard: a missing key, a typo or a
  // stringly-typed "false" from an environment must not silently open it.
  const enabled = appconfig.blockPrivateNetworkCalls !== false;
  const configured = Array.isArray(appconfig.blockedAddressRanges) &&
      appconfig.blockedAddressRanges.length
    ? appconfig.blockedAddressRanges
    : DEFAULT_BLOCKED_RANGES;

  const ranges = [];
  for (const entry of configured) {
    const parsed = parseRange(entry);
    if (parsed.error) {
      // Name the entry AND what is wrong with it. A typo in a range is a hole,
      // and a hole nobody is told about is the worst kind.
      logger.error('ssrf_guard: ignoring blocked range "' + entry + '" — it ' +
                   parsed.error + '.');
    } else {
      ranges.push(parsed);
    }
  }
  if (!ranges.length) {
    logger.error('ssrf_guard: no usable ranges in blockedAddressRanges — ' +
                 'nothing will be blocked. ' +
                 'Entries must be CIDR blocks ("10.0.0.0/8") or ' +
                     'first-last pairs ' +
                 '("10.0.0.0-10.255.255.255").');
  }

  function blockedRangeFor(ip) {
    log.debug("Entering blockedRangeFor().");
    const address = toAddress(ip);
    if (!address) {
      log.debug("Leaving blockedRangeFor().");
      return null;
    }
    for (const range of ranges) {
      if (withinRange(address, range)) {
        log.debug("Leaving blockedRangeFor().");
        return range.text;
      }
    }
    log.debug("Leaving blockedRangeFor().");
    return null;
  }

  function blockedError(host, ip, rangeText) {
    log.debug("Entering blockedError().");
    const error = new Error(
      'Refusing to call ' + host + ': it resolves to ' + ip +
          ', which is in the blocked range ' +
      rangeText + '. This service does not make requests to loopback or ' +
          'private network addresses. ' +
      'Set blockPrivateNetworkCalls to false in the api configuration if ' +
          'this deployment is meant to.');
    error.code = 'EBLOCKEDADDRESS';
    error.blockedHost = host;
    error.blockedAddress = ip;
    error.blockedRange = rangeText;
    log.debug("Leaving blockedError().");
    return error;
  }

  // The DNS lookup both agents use, so every connection — including the ones
  // axios makes when it follows a redirect — is checked against the address it
  // is about to connect to.
  function guardedLookup(hostname, options, callback) {
    log.debug("Entering guardedLookup().");
    if (typeof options === 'function') {
      callback = options;
      options = {};
    }
    const opts = Object.assign({}, options || {}, { all: true });
    dns.lookup(hostname, opts, function (err, addresses) {
      if (err) return callback(err);
      const list = Array.isArray(addresses) ? addresses : [addresses];
      for (const entry of list) {
        const ip = entry.address;
        const range = blockedRangeFor(ip);
        if (range) {
          logger.warn('ssrf_guard: refused ' + hostname + ' -> ' + ip + ' (' +
                      range + ')');
          return callback(blockedError(hostname, ip, range));
        }
      }
      // Hand back what the caller asked for: `all` when it wanted all,
      // otherwise the first address, matching dns.lookup's own contract.
      if (options && options.all) return callback(null, list);
      return callback(null, list[0].address, list[0].family);
    });
    log.debug("Leaving guardedLookup().");
  }

  // -------------------------------------------------------------------------
  // Scheme policy: http and https, nothing else.
  //
  // This is not paranoia about exotic URLs — axios's Node adapter really does
  // support more than HTTP. `platform.protocols` is
  // ['http','https','file','data'], and every URL this service fetches comes
  // from its CALLER, so without this:
  //
  //   * a `data:` URL is decoded by axios itself and handed straight back,
  //     which turns these endpoints into a reflector and never touches the
  //     network (so no address policy applies to it);
  //   * a `file:` URL passes axios's own supported-protocol check and then dies
  //     in Node's http transport, which — because these handlers only answer
  //     when an error carries a `response` — left the request hanging rather
  //     than failing.
  //
  // Neither is anything an identity provider endpoint could legitimately be.
  // The two endpoints that already tested the scheme themselves (/samlmetadata,
  // /wstrust) keep doing so and answer 400; this is the floor under all of
  // them, including any added later.
  // -------------------------------------------------------------------------
  function assertProtocolAllowed(url) {
    log.debug("Entering assertProtocolAllowed().");
    let protocol;
    try {
      protocol = new URL(String(url)).protocol;
    } catch (e) {
      // Not an absolute URL. Nothing to judge: axios will fail it on its own,
      // and guessing a scheme here would be inventing policy.
      log.debug("Leaving assertProtocolAllowed().");
      return null;
    }
    if (ALLOWED_PROTOCOLS.indexOf(protocol) >= 0) {
      log.debug("Leaving assertProtocolAllowed().");
      return null;
    }
    const error = new Error('Refusing to call ' + protocol + ' — only ' +
                            ALLOWED_PROTOCOLS.join(' and ') + ' are allowed.');
    error.code = 'EPROTOCOLNOTALLOWED';
    error.blockedProtocol = protocol;
    log.debug("Leaving assertProtocolAllowed().");
    return error;
  }

  // Pre-flight for the interceptor: the same policy, applied to a URL, with the
  // error raised before any socket is opened.
  function assertUrlAllowed(url) {
    log.debug("Entering assertUrlAllowed().");
    log.debug("Leaving assertUrlAllowed().");
    return new Promise(function (resolve, reject) {
      let hostname;
      try {
        hostname = new URL(String(url)).hostname;
      } catch (e) {
        // Not a URL this guard can read (a relative path, say). The request
        // will fail or stay local on its own; there is nothing to check.
        return resolve();
      }
      // A bracketed IPv6 literal arrives as [::1]; URL.hostname keeps the
      // brackets.
      if (hostname.length > 1 && hostname[0] === '[' &&
          hostname[hostname.length - 1] === ']') {
        hostname = hostname.slice(1, -1);
      }
      if (!hostname) return resolve();
      const literal = blockedRangeFor(hostname);
      if (literal) return reject(blockedError(hostname, hostname, literal));
      if (net.isIP(hostname)) return resolve(
          );      // an allowed literal: nothing to resolve
      dns.lookup(hostname, { all: true }, function (err, addresses) {
        if (err) {
          // Unresolvable: the call cannot succeed anyway, and refusing here
          // says why in one line instead of surfacing a socket error later.
          const failure = new Error('Refusing to call ' + hostname +
              ': it does not resolve (' +
                                    err.code + ').');
          failure.code = 'EBLOCKEDADDRESS';
          return reject(failure);
        }
        for (const entry of addresses) {
          const range = blockedRangeFor(entry.address);
          if (range) return reject(blockedError(hostname, entry.address,
              range));
        }
        resolve();
      });
    });
  }

  // The agents check in TWO places, because Node only consults `lookup` when
  // the host is a NAME. A literal address — which is exactly what a redirect to
  // http://127.0.0.1:8080/ carries — is connected to directly, and would sail past
  // a lookup-only guard. So createConnection is wrapped as well, and that is
  // the check that stops literals.
  function guardConnection(options, callback, connect) {
    log.debug("Entering guardConnection().");
    const host = options && (options.host || options.hostname);
    if (host && net.isIP(String(host))) {
      const range = blockedRangeFor(String(host));
      if (range) {
        const error = blockedError(String(host), String(host), range);
        logger.warn('ssrf_guard: refused a connection to ' + host + ' (' +
                    range + ')');
        if (typeof callback === 'function') {
          callback(error);
          log.debug("Leaving guardConnection().");
          return undefined;
        }
        throw error;
      }
    }
    log.debug("Leaving guardConnection().");
    return connect(options, callback);
  }

  /**
   * Build an agent that carries both agent-layer hooks.
   *
   * This is a FACTORY rather than a decorator because `lookup` has to be an
   * agent option, which is read at construction; and it exists as an export
   * because setting `httpsAgent` on an individual axios call REPLACES
   * axios.defaults.httpsAgent, hooks and all. Every call in server.js does that
   * (each one chooses its own rejectUnauthorized), so those calls need a way to
   * ask for an agent that is guarded — otherwise the whole agent layer, and with
   * it the redirect and literal-address checks, is present only on the calls that
   * do not specify an agent.
   *
   * When the guard is disabled it still returns a usable agent, unhooked, so a
   * caller can build one unconditionally.
   *
   * @param {string} protocol - 'http' or 'https'.
   * @param {object} [options] - agent options (rejectUnauthorized, keepAlive, …).
   * @returns {http.Agent|https.Agent}
   */
  function createAgent(protocol, options) {
    log.debug("Entering createAgent().");
    const module_ = protocol === 'https' ? https : http;
    if (!enabled) {
      log.debug("Leaving createAgent().");
      return new module_.Agent(Object.assign({}, options || {}));
    }
    const agent = new module_.Agent(Object.assign({}, options || {},
        { lookup: guardedLookup }));
    agent.createConnection = function (opts, callback) {
      log.debug("Entering createConnection().");
      const self = this;
      log.debug("Leaving createConnection().");
      return guardConnection(opts, callback, function (o, cb) {
        return module_.Agent.prototype.createConnection.call(self, o, cb);
      });
    };
    log.debug("Leaving createAgent().");
    return agent;
  }

  const httpAgent = createAgent('http');
  const httpsAgent = createAgent('https');

  // The URL an axios config will actually fetch.
  function targetOf(config) {
    log.debug("Entering targetOf().");
    log.debug("Leaving targetOf().");
    return config.url && /^[a-z][a-z0-9+.-]*:\/\//i.test(config.url)
      ? config.url
      : (config.baseURL || '') + (config.url || '');
  }

  // Wire the guard into an axios instance.
  //
  // The PROTOCOL check goes on unconditionally, before the enabled test: it is
  // not an address policy, and there is no deployment for which fetching file:
  // or data: is legitimate. The address layers are what
  // blockPrivateNetworkCalls switches off, and the stacks that switch it off
  // still need this.
  function install(axios) {
    log.debug("Entering install().");
    axios.interceptors.request.use(function (config) {
      const refusal = assertProtocolAllowed(targetOf(config));
      if (refusal) {
        logger.warn('ssrf_guard: ' + refusal.message);
        return Promise.reject(refusal);
      }
      return config;
    });
    if (!enabled) {
      logger.warn('ssrf_guard: address policy DISABLED by configuration ' +
                  '(blockPrivateNetworkCalls=false) — this service will call ' +
                      'loopback ' +
                  'and private addresses. The ' + ALLOWED_PROTOCOLS.join('/') +
                  '-only rule still applies.');
      log.debug("Leaving install().");
      return { enabled: false,
              ranges: ranges.map(function (r) { return r.text; }) };
    }
    axios.defaults.httpAgent = httpAgent;
    axios.defaults.httpsAgent = httpsAgent;
    axios.interceptors.request.use(function (config) {
      return assertUrlAllowed(targetOf(config))
                              .then(function () { return config; });
    });
    logger.info('ssrf_guard: enabled; refusing outbound calls to ' +
                ranges.length +
                ' blocked range(s): ' +
                    ranges.map(function (r) { return r.text; }).join(', '));
    log.debug("Leaving install().");
    return { enabled: true,
            ranges: ranges.map(function (r) { return r.text; }) };
  }

  log.debug("Leaving createGuard().");
  return {
    enabled: enabled,
    ranges: ranges.map(function (r) { return r.text; }),
    blockedRangeFor: blockedRangeFor,
    assertUrlAllowed: assertUrlAllowed,
    assertProtocolAllowed: assertProtocolAllowed,
    allowedProtocols: ALLOWED_PROTOCOLS.slice(),
    guardedLookup: guardedLookup,
    createAgent: createAgent,
    httpAgent: httpAgent,
    httpsAgent: httpsAgent,
    install: install
  };
}

module.exports = {
  createGuard: createGuard,
  DEFAULT_BLOCKED_RANGES: DEFAULT_BLOCKED_RANGES,
  // Exported for tests.
  toAddress: toAddress,
  parseRange: parseRange,
  withinRange: withinRange
};
