// File: tls_probe.js
//
// ---------------------------------------------------------------------------
// The TLS / mutual-TLS test connection behind POST /tls/connect.
//
// It exists for the same reason api/krb5_relay.js does: **the browser cannot do
// this, and it is not close.** A page can `fetch()` an https URL, but every
// part of the handshake the PKI workflow is about is either hidden from it or
// owned by the operating system:
//
//   * the client certificate is chosen by the browser's own UI from the
//     browser's own store, so a page cannot present the certificate it just
//     issued, and cannot choose to present none;
//   * the truststore is the platform's, so a page cannot ask "does this chain
//     verify against THIS root and no other" — which is the entire question a
//     private CA raises;
//   * the negotiated version, cipher, ALPN protocol and the server's
//     certificate chain are not exposed to script at all;
//   * and a failed handshake reaches script as a generic network error with the
//     alert — the one piece of information worth having — discarded.
//
// So the page has no TLS option of its own and never will: it asks the api,
// which opens the socket, reports both sides verbatim, and is the only thing
// here that ever sees the private key of the client certificate.
//
// ---------------------------------------------------------------------------
// WHAT BOUNDS IT
//
// This is a caller-directed outbound connection, so it inherits the same policy
// every other outbound call here obeys, and adds one setting of its own:
//
//   * **the address policy**, reused from api/ssrf_guard.js rather than
//     reimplemented — `tls.connect` is a raw socket, so the guard's axios
//     interceptor and agent hooks never see it, exactly as with the Kerberos
//     relay. Two implementations of an address policy is one implementation and
//     one hole, so this asks `guard.blockedRangeFor()` for the decision.
//   * **`tlsAllowedPorts`**, a ninth setting. TLS is spoken on many ports, and
//     unlike the Kerberos relay there is no payload shape to bound this with —
//     a ClientHello to port 22 is a perfectly well-formed ClientHello. So the
//     ports are an allowlist with the usual suspects in it, and `"any"`
//     (spelled
//     as a word, so enabling it cannot be a typo) for a deployment that needs
//     more.
//   * **the three deadlines**, and the lookup gets one of its own for the
//     reason
//     the Kerberos relay records: until a name is an address, neither of the
//     other budgets has started, and an unbounded lookup is an unbounded
//     request. `connectionTimeout` bounds the resolve, then the TCP connect;
//     `callTimeout` bounds the handshake, which is the part that can be slow
//     while being perfectly alive.
//   * **`maxContentLength`**, applied to the certificate chain that comes back.
//     A server may present a chain as large as it likes.
//
// ---------------------------------------------------------------------------
// TWO DESIGN DECISIONS WORTH THE PARAGRAPH
//
// **The handshake is ALWAYS made with `rejectUnauthorized: false`, and the
// verdict is reported rather than enforced.** That looks like the wrong
// default and is the only useful one here: the question this endpoint answers
// is "what does this server present, and does it verify against the truststore
// I chose" — and aborting the handshake on a verification failure throws away
// the chain that would explain it. Node computes `socket.authorized` and
// `socket.authorizationError` either way, so nothing is lost by not aborting
// and the caller gets the certificate, the alert AND the verdict. The response
// says `authorized: false` in as many words; no caller can mistake it for
// success.
//
// **Whether the server ASKED for a client certificate cannot be read off a node
// TLS socket** — there is no event, no property, and the CertificateRequest is
// consumed inside OpenSSL. The only way to find out is to try it both ways, so
// `mutualAuthProbe` does exactly that: one handshake with the client
// certificate and one without, reported side by side. A server that completes
// both does not require one; a server that completes only the first does; a
// server that completes only the second rejected the certificate offered, and
// its alert says why. Guessing from a single connection is what produces the
// "mutual auth is not working" reports that turn out to be a server that never
// asked.
//
// ---------------------------------------------------------------------------
// AND ONE OPTIONAL THIRD THING: ASKING THE SERVER WHAT *IT* SAW.
//
// Everything above is the CLIENT's account of the handshake, and the client is
// the party that already knows what it sent. What it cannot know is which chain
// the server built out of that, which anchor it verified against, what it read
// out of the leaf, or — under TLS 1.3, where the client finishes first —
// whether the certificate was accepted at all. That answer exists only on the
// far end, and the only way to get it back is to ask over the connection that
// was just made, because a second connection is a different connection and
// proves nothing about this one.
//
// So `httpRequest` is an optional `{ path }`: after the handshake, one GET is
// written on the same socket and the response is reported verbatim — status
// line, headers, body. The mock STS's `GET /tls/whoami` answers exactly this
// question and is what the PKI page points at, but nothing here knows or cares
// about that: any server that will answer a GET can be asked.
//
// What bounds it is narrower than the rest of this file and needs no setting of
// its own, for the same reason `POST /krb5/spnego` needs none: the method is
// GET and nothing else, the caller influences the PATH and nothing else, and
// every header is built here. A caller cannot inject a header, a method or a
// body — a path carrying CR or LF is refused rather than escaped, since
// escaping it would mean deciding what the caller meant. The response is capped
// by `maxContentLength`, and the read ends on the close that
// `Connection: close` asks for, on the cap, or on `HTTP_RESPONSE_GRACE_MS` of
// silence.
// ---------------------------------------------------------------------------

const tls = require('tls');
const net = require('net');
const dns = require('dns');

// Ports TLS is commonly spoken on. https, the alternate https ports, LDAPS,
// FTPS, IMAPS/POP3S/SMTPS, AMQPS, IRC over TLS, MQTT over TLS, PostgreSQL and
// MSSQL — the set an operator debugging a private CA plausibly aims at.
const DEFAULT_ALLOWED_PORTS = [443, 636, 989, 990, 993, 995, 1433, 4443, 5061,
                               5432, 5671, 6697, 8443, 8843, 9443, 10443,
                               8883];
const DEFAULT_CONNECT_TIMEOUT_MS = 5000;
const DEFAULT_CALL_TIMEOUT_MS = 10000;
const DEFAULT_MAX_CHAIN_BYTES = 1048576;
// A truststore is a list of anchors, not a certificate store dump. The cap is
// generous for any private PKI and stops a caller handing over a body that
// costs more to parse than the handshake costs to make.
const MAX_TRUST_ANCHORS = 64;
// How long to keep reading after the handshake completes, waiting for the
// post-handshake alert a TLS 1.3 server sends when it rejects the client
// certificate. See the long comment in handshake(): without this wait, every
// TLS 1.3 server looks like one that does not require client authentication.
// The socket is closed as soon as anything arrives, so this is the cost of a
// server that says nothing rather than the cost of every probe.
const POST_HANDSHAKE_GRACE_MS = 750;
// How long to wait for more of an HTTP response after the last byte arrived,
// when `httpRequest` was asked for. It is RESTARTED on every chunk, so a slow
// server is not cut off mid-answer; what it bounds is a server that answers and
// then keeps the socket open despite the `Connection: close` this sends. The
// whole call is still inside `callTimeout` either way.
const HTTP_RESPONSE_GRACE_MS = 2000;
// A path is a path. This is long enough for any query string worth debugging
// and short enough that a caller cannot use it as a body.
const MAX_HTTP_PATH_LENGTH = 2048;

const TLS_VERSIONS = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'];

function resolvePositiveNumber(value, fallback, name, log) {
  log.debug("Entering resolvePositiveNumber().");
  const number = typeof value === 'number' ? value : Number(value);
  if (value === undefined || value === null || !Number.isFinite(number) ||
      number <= 0) {
    if (value !== undefined && value !== null) {
      log.error('tls_probe: ' + name + ' must be a positive number; using ' +
                fallback + '.');
    }
    log.debug("Leaving resolvePositiveNumber(). Default.");
    return fallback;
  }
  log.debug("Leaving resolvePositiveNumber().");
  return number;
}

// The same shape as krb5_relay's, and for the same reasons: a malformed entry
// is dropped with its reason logged, and an allowlist that ends up empty
// refuses every call — safe, but almost certainly a mistake, so it is logged as
// one.
function resolveAllowedPorts(value, log) {
  log.debug("Entering resolveAllowedPorts().");
  if (value === undefined || value === null) {
    log.debug("Leaving resolveAllowedPorts(). Default.");
    return DEFAULT_ALLOWED_PORTS.slice();
  }
  if (!Array.isArray(value)) {
    log.error('tls_probe: tlsAllowedPorts must be an array of port numbers ' +
              'or the string "any"; using the default.');
    log.debug("Leaving resolveAllowedPorts(). Default.");
    return DEFAULT_ALLOWED_PORTS.slice();
  }
  const ports = [];
  for (const entry of value) {
    const port = typeof entry === 'number' ? entry : parseInt(entry, 10);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      log.error('tls_probe: ignoring tlsAllowedPorts entry ' +
                JSON.stringify(entry) +
                ' — a port must be an integer from 1 to 65535.');
      continue;
    }
    if (ports.indexOf(port) === -1) ports.push(port);
  }
  if (!ports.length) {
    log.error('tls_probe: tlsAllowedPorts contained no usable ports, so ' +
              'POST /tls/connect will refuse every call. That is the safe ' +
              'direction, but it is almost certainly a configuration ' +
              'mistake.');
  }
  log.debug("Leaving resolveAllowedPorts().");
  return ports;
}

// Split a bundle of concatenated PEM certificates into individual ones. A
// truststore is nearly always pasted as a bundle, and node's `ca` option takes
// an array — handing it the bundle as one string works for some node versions
// and silently uses only the first certificate on others, which reads as "the
// root I added is not trusted".
function splitPemCertificates(text) {
  const matches = String(text || '').match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  return matches || [];
}

// Undo `Transfer-Encoding: chunked`.
//
// This is the one piece of decoding this file does, and it is not an exception
// to "report the bytes verbatim" — it is what the bytes MEAN. A chunked body is
// framing, not content: node's own HTTP server answers chunked whenever it does
// not know the length in advance, which is most of the time, so a report that
// handed the frames back would be handing back a body no caller can read, with
// hexadecimal lengths interleaved through it. Every HTTP client on earth does
// this before showing anyone a body.
//
// A truncated or malformed stream returns what it managed, with `complete`
// false, because a partial answer from the far end is still an answer about the
// far end.
//
// IT WORKS ON A BUFFER, AND THAT IS NOT AN IMPLEMENTATION DETAIL. A chunk size
// counts BYTES; a JavaScript string is indexed in UTF-16 code units. Decode a
// chunked body as a string and every multi-byte character in it — one em dash
// is three bytes and one character — shifts the end of the chunk earlier than
// the size says, so the decoder walks off the end of one chunk and into the
// framing of the next. The symptom is a body that is *almost* right: valid
// JSON followed by a fragment of hexadecimal, from a server whose only crime
// was writing prose with punctuation in it. Found exactly that way.
function decodeChunked(buffer) {
  const parts = [];
  let at = 0;
  function done(complete) {
    return { buffer: Buffer.concat(parts), complete: complete };
  }
  while (at < buffer.length) {
    const eol = buffer.indexOf('\r\n', at);
    if (eol === -1) return done(false);
    const size = parseInt(
        buffer.toString('latin1', at, eol).split(';')[0].trim(), 16);
    if (!Number.isFinite(size)) return done(false);
    if (size === 0) return done(true);
    const start = eol + 2;
    if (start + size > buffer.length) {
      parts.push(buffer.slice(start));
      return done(false);
    }
    parts.push(buffer.slice(start, start + size));
    at = start + size + 2;
  }
  return done(false);
}

// Read an HTTP/1.1 response off the wire. Deliberately small and deliberately
// NOT a parser: the status line and the headers are split out so the report can
// name them, and the body is handed back as it was sent — chunked framing
// removed, and nothing else touched. This endpoint's whole value is reporting
// what the far end said, and a parser that normalised a body would be reporting
// what it made of it instead.
//
// A response with no blank line in it at all — a server that hung up
// mid-header, or something that is not HTTP — is returned as `raw` with
// `parsed: false`,
// because that is a fact about the far end and not an error here.
function parseHttpResponse(input) {
  // Bytes, for the reason decodeChunked() records at length. A caller with a
  // string is accommodated, since the tests and the log both have one.
  const buffer = Buffer.isBuffer(input)
    ? input : Buffer.from(String(input || ''), 'utf8');
  const separator = buffer.indexOf('\r\n\r\n');
  if (separator === -1) {
    return { parsed: false, raw: buffer.toString('utf8'), statusCode: null,
             statusText: null, httpVersion: null, headers: {}, body: '' };
  }
  // The head is ASCII by definition (RFC 9110 section 5.5), and latin1 is the
  // decoding that cannot throw or substitute on a header that is not.
  const head = buffer.toString('latin1', 0, separator);
  const body = buffer.slice(separator + 4);
  const lines = head.split('\r\n');
  const status = /^HTTP\/(\d(?:\.\d)?)\s+(\d{3})\s*(.*)$/.exec(lines[0] || '');
  const headers = {};
  lines.slice(1).forEach(function (line) {
    const colon = line.indexOf(':');
    if (colon <= 0) return;
    const name = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    // A repeated header is joined rather than overwritten (Set-Cookie is the
    // one that matters), because dropping one silently would misreport what the
    // server sent — which is the only thing this function is for.
    headers[name] = headers[name] === undefined
      ? value : (headers[name] + ', ' + value);
  });
  let payload = body;
  let transferEncoding = null;
  let bodyComplete = true;
  if (/chunked/i.test(headers['transfer-encoding'] || '')) {
    const decoded = decodeChunked(body);
    payload = decoded.buffer;
    bodyComplete = decoded.complete;
    transferEncoding = 'chunked';
  }
  return {
    parsed: !!status,
    statusLine: lines[0] || '',
    httpVersion: status ? status[1] : null,
    statusCode: status ? parseInt(status[2], 10) : null,
    statusText: status ? status[3] : null,
    headers: headers,
    transferEncoding: transferEncoding,
    bodyComplete: bodyComplete,
    body: payload.toString('utf8')
  };
}

function createProbe(appconfig, guard, log, deps) {
  log.debug("Entering createProbe().");
  appconfig = appconfig || {};
  const logger = log || { debug() {}, info() {}, warn() {}, error() {} };

  // Injectable for the same reason the Kerberos relay's is: a deadline cannot
  // be tested against a resolver that works, and `dns.lookup` is getaddrinfo,
  // so it ignores `dns.setServers` and cannot be pointed at a black hole from
  // inside the process. Nothing in server.js passes this.
  const lookup = (deps && deps.lookup) || dns.lookup;
  const connectTls = (deps && deps.connect) || tls.connect;

  const anyPort = appconfig.tlsAllowedPorts === 'any';
  const allowedPorts = anyPort
    ? []
    : resolveAllowedPorts(appconfig.tlsAllowedPorts, logger);
  const connectTimeout = resolvePositiveNumber(appconfig.connectionTimeout,
      DEFAULT_CONNECT_TIMEOUT_MS, 'connectionTimeout', logger);
  const callTimeout = resolvePositiveNumber(appconfig.callTimeout,
      DEFAULT_CALL_TIMEOUT_MS, 'callTimeout', logger);
  const maxChainBytes = resolvePositiveNumber(appconfig.maxContentLength,
      DEFAULT_MAX_CHAIN_BYTES, 'maxContentLength', logger);
  const addressPolicyEnabled = !!(guard && guard.enabled);

  logger.info('tls_probe: ports ' +
    (anyPort ? 'ANY (tlsAllowedPorts is "any")'
      : (allowedPorts.join(', ') || '(none)')) +
    '; connect timeout ' + connectTimeout + ' milliseconds; handshake ' +
    'timeout ' + callTimeout + ' milliseconds; chain cap ' + maxChainBytes +
    ' bytes; address policy ' +
    (addressPolicyEnabled ? 'ENABLED (shared with ssrf_guard)' : 'disabled'));

  function refuse(message, code) {
    const error = new Error(message);
    error.code = code || 'ETLSREFUSED';
    error.refused = true;
    return error;
  }

  function assertPortAllowed(port) {
    logger.debug("Entering assertPortAllowed().");
    if (anyPort) {
      logger.debug("Leaving assertPortAllowed(). Any port is allowed.");
      return;
    }
    if (allowedPorts.indexOf(port) === -1) {
      logger.debug("Leaving assertPortAllowed(). Refused.");
      throw refuse('Refusing to open a TLS connection to port ' + port +
        '. This deployment allows ' + (allowedPorts.join(', ') ||
        'no ports at all') + '. Unlike the Kerberos relay there is no ' +
        'payload shape bounding this endpoint — a ClientHello sent to any ' +
        'port is a well-formed ClientHello — so the ports are an allowlist. ' +
        'Add the port to tlsAllowedPorts, or set it to "any".',
        'ETLSPORTNOTALLOWED');
    }
    logger.debug("Leaving assertPortAllowed().");
  }

  // Resolve the host and return an address that has passed the policy — the
  // same two-case shape the Kerberos relay uses, because node never calls a
  // resolver for a literal and a literal is exactly what an attacker supplies.
  //
  // THE LOOKUP IS ON ITS OWN DEADLINE. Until the name is an address nothing
  // else is timing this call, so a stub resolver waiting out its retries holds
  // the request open for as long as it likes. A late callback is dropped rather
  // than raced: getaddrinfo runs in the libuv threadpool and cannot be
  // cancelled.
  function resolveAllowedAddress(host) {
    logger.debug("Entering resolveAllowedAddress().");
    logger.debug("Leaving resolveAllowedAddress().");
    return new Promise(function (resolve, reject) {
      const literalFamily = net.isIP(host);
      if (literalFamily) {
        const range = addressPolicyEnabled && guard.blockedRangeFor(host);
        if (range) {
          return reject(refuse('Refusing to open a TLS connection to ' + host +
            ': it is in the blocked range ' + range + '. This service does ' +
            'not connect to loopback or private network addresses. Set ' +
            'blockPrivateNetworkCalls to false in the api configuration if ' +
            'this deployment is meant to — the local and containerized ' +
            'stacks do.', 'EBLOCKEDADDRESS'));
        }
        return resolve({ address: host, family: literalFamily,
                        wasLiteral: true });
      }
      let settled = false;
      const deadline = setTimeout(function () {
        if (settled) return;
        settled = true;
        logger.warn('tls_probe: gave up resolving ' + host + ' after ' +
                    connectTimeout + ' milliseconds');
        reject(refuse('Timed out after ' + connectTimeout + ' milliseconds ' +
          'resolving ' + host + '. The name was never turned into an ' +
          'address, so no connection was attempted — this is a DNS problem ' +
          'on the machine running this service rather than anything about ' +
          'the server. Check the resolver, or give the host by address.',
          'ETLSDNSTIMEOUT'));
      }, connectTimeout);
      lookup(host, function (error, address, family) {
        if (settled) return;
        settled = true;
        clearTimeout(deadline);
        if (error) {
          return reject(refuse('Could not resolve ' + host + ': ' +
            error.message, 'ETLSDNS'));
        }
        const range = addressPolicyEnabled && guard.blockedRangeFor(address);
        if (range) {
          return reject(refuse('Refusing to open a TLS connection to ' + host +
            ': it resolves to ' + address + ', which is in the blocked ' +
            'range ' + range + '. A name is judged by what it resolves to, ' +
            'so a hostname pointing at a private address is refused for the ' +
            'same reason the address is.', 'EBLOCKEDADDRESS'));
        }
        resolve({ address: address, family: family, wasLiteral: false });
      });
    });
  }

  // Normalise `httpRequest` into the one shape the socket code accepts, or
  // refuse it by name. The method is GET and is not negotiable, and the path is
  // the ONLY thing a caller contributes to the bytes that go out — everything
  // else in the request is built below. A path carrying CR or LF is refused
  // rather than escaped: escaping means deciding what the caller meant, and
  // what a newline in a request line means is somebody else's header.
  function assertHttpRequest(value) {
    logger.debug("Entering assertHttpRequest().");
    if (value === undefined || value === null || value === false ||
        value === '') {
      logger.debug("Leaving assertHttpRequest(). Not asked for.");
      return undefined;
    }
    const path = typeof value === 'string' ? value
      : String((value && value.path) || '');
    if (!path) {
      logger.debug("Leaving assertHttpRequest(). No path.");
      throw refuse('httpRequest needs a path — the request made over the ' +
        'connection is a GET, and the path is the only part of it a caller ' +
        'chooses.', 'ETLSBADHTTPPATH');
    }
    if (path.charAt(0) !== '/') {
      logger.debug("Leaving assertHttpRequest(). Not absolute.");
      throw refuse('The httpRequest path must start with "/"; got ' +
        JSON.stringify(path) + '. This is a request over a connection that ' +
        'has already been made, so it carries an origin-form path and never ' +
        'a URL.', 'ETLSBADHTTPPATH');
    }
    if (path.length > MAX_HTTP_PATH_LENGTH) {
      logger.debug("Leaving assertHttpRequest(). Too long.");
      throw refuse('The httpRequest path is ' + path.length + ' characters; ' +
        'this endpoint allows ' + MAX_HTTP_PATH_LENGTH + '.',
        'ETLSBADHTTPPATH');
    }
    if (/[\r\n\s]/.test(path)) {
      logger.debug("Leaving assertHttpRequest(). Illegal characters.");
      throw refuse('The httpRequest path contains whitespace, a carriage ' +
        'return or a line feed. It is refused rather than escaped: a newline ' +
        'in a request line is how a caller writes somebody else\'s header, ' +
        'and escaping it would mean guessing which of the two was meant. ' +
        'Percent-encode it.', 'ETLSBADHTTPPATH');
    }
    logger.debug("Leaving assertHttpRequest(). path=" + path);
    return { method: 'GET', path: path };
  }

  function assertVersion(name, value) {
    logger.debug("Entering assertVersion().");
    if (!value) {
      logger.debug("Leaving assertVersion(). Not set.");
      return undefined;
    }
    if (TLS_VERSIONS.indexOf(value) === -1) {
      logger.debug("Leaving assertVersion(). Unknown.");
      throw refuse(name + ' must be one of ' + TLS_VERSIONS.join(', ') +
        '; got ' + JSON.stringify(value) + '.', 'ETLSBADVERSION');
    }
    logger.debug("Leaving assertVersion().");
    return value;
  }

  // Build the `ca` option. An empty result is NOT the same as omitting it:
  // omitting `ca` means node's bundled roots, which is exactly what somebody
  // testing a private CA does not want. So the two cases are separate and the
  // response says which was used.
  function buildTrustStore(options) {
    logger.debug("Entering buildTrustStore().");
    const pasted = [];
    (options.trustCertificates || []).forEach(function (entry) {
      splitPemCertificates(entry).forEach(function (pem) {
        pasted.push(pem);
      });
    });
    if (pasted.length > MAX_TRUST_ANCHORS) {
      logger.debug("Leaving buildTrustStore(). Too many anchors.");
      throw refuse('A truststore of ' + pasted.length + ' certificates was ' +
        'supplied; this endpoint accepts at most ' + MAX_TRUST_ANCHORS + '.',
        'ETLSTRUSTTOOLARGE');
    }
    // The default is the one that makes a private CA testable: anchors were
    // supplied, so those and nothing else. Adding the public roots to a private
    // truststore by default would mean a chain that verifies for a reason the
    // caller did not ask about.
    const useSystem = options.includeSystemRoots === undefined ||
        options.includeSystemRoots === null
      ? pasted.length === 0
      : options.includeSystemRoots === true;
    let anchors;
    if (pasted.length && useSystem) {
      anchors = tls.rootCertificates.concat(pasted);
    } else if (pasted.length) {
      anchors = pasted;
    } else if (useSystem) {
      // `ca` omitted entirely is what selects node's bundled roots.
      anchors = null;
    } else {
      // Explicitly no anchors at all: every chain fails to verify, which is a
      // legitimate thing to ask for ("prove to me this is being checked").
      anchors = [];
    }
    logger.debug("Leaving buildTrustStore(). " + pasted.length +
                 " pasted anchor(s), system roots " +
                 (useSystem ? 'included' : 'excluded'));
    return {
      ca: anchors,
      pastedAnchors: pasted.length,
      systemRoots: useSystem
    };
  }

  function describeCertificate(cert, depth) {
    logger.debug("Entering describeCertificate().");
    if (!cert || !Object.keys(cert).length) {
      logger.debug("Leaving describeCertificate(). Empty.");
      return null;
    }
    const out = {
      depth: depth,
      subject: cert.subject || null,
      issuer: cert.issuer || null,
      subjectAltName: cert.subjectaltname || null,
      infoAccess: cert.infoAccess || null,
      serialNumber: cert.serialNumber || null,
      validFrom: cert.valid_from || null,
      validTo: cert.valid_to || null,
      fingerprint: cert.fingerprint || null,
      fingerprint256: cert.fingerprint256 || null,
      keyUsage: cert.ext_key_usage || null,
      bits: cert.bits || null,
      asn1Curve: cert.asn1Curve || null,
      nistCurve: cert.nistCurve || null,
      pubkeyAlgorithm: cert.pubkey ? 'present' : null,
      pem: cert.raw
        ? '-----BEGIN CERTIFICATE-----\n' +
          (cert.raw.toString('base64').match(/.{1,64}/g) || []).join('\n') +
          '\n-----END CERTIFICATE-----\n'
        : null
    };
    logger.debug("Leaving describeCertificate().");
    return out;
  }

  // Walk the peer chain, honouring the byte cap. `issuerCertificate` is a
  // self-reference at the root, which is what stops the walk.
  function describeChain(socket) {
    logger.debug("Entering describeChain().");
    const out = [];
    let total = 0;
    let truncated = false;
    let cert = socket.getPeerCertificate(true);
    let depth = 0;
    const seen = new Set();
    while (cert && Object.keys(cert).length && depth < 16) {
      const fingerprint = cert.fingerprint256 || String(depth);
      if (seen.has(fingerprint)) break;
      seen.add(fingerprint);
      total += cert.raw ? cert.raw.length : 0;
      if (total > maxChainBytes) {
        truncated = true;
        break;
      }
      out.push(describeCertificate(cert, depth));
      if (!cert.issuerCertificate || cert.issuerCertificate === cert) break;
      cert = cert.issuerCertificate;
      depth += 1;
    }
    logger.debug("Leaving describeChain(). " + out.length + " certificate(s).");
    return { chain: out, truncated: truncated, bytes: total };
  }

  // One handshake. Resolves with a report whether or not the certificate
  // verified; rejects only when there was no handshake to report on.
  function handshake(options, address) {
    logger.debug("Entering handshake(). clientCertificate=" +
                 !!options.clientCertificatePem);
    return new Promise(function (resolve, reject) {
      let settled = false;
      let socket = null;
      // Non-null once the handshake has completed, which is what tells the one
      // 'error' handler below whether an error is a failed handshake or a
      // post-handshake alert about the client certificate. Two error handlers
      // would not do: the first one registered wins, and that is the wrong one.
      let secureReport = null;
      let graceTimer = null;
      const started = Date.now();
      const trust = options.trust;

      function finish(fn, value) {
        if (settled) return;
        settled = true;
        if (value && value.connected) value.usable = handshakeUsable(value);
        clearTimeout(connectDeadline);
        clearTimeout(callDeadline);
        if (graceTimer) clearTimeout(graceTimer);
        if (socket) {
          socket.removeAllListeners();
          try {
            socket.destroy();
          } catch (e) {
            logger.debug('handshake(): destroy: ' + e.message);
          }
        }
        fn(value);
      }

      const connectDeadline = setTimeout(function () {
        finish(reject, refuse('Timed out after ' + connectTimeout +
          ' milliseconds connecting to ' + options.host + ':' + options.port +
          '. Nothing answered on that address and port — this is the connect ' +
          'budget, not the handshake one, so the far end had not accepted a ' +
          'TCP connection at all.', 'ETLSCONNECTTIMEOUT'));
      }, connectTimeout);

      // Armed from the start rather than when the connection comes up, so the
      // whole call is bounded even if 'connect' never fires — and it is the
      // LONGER of the two, so a server that connects and then negotiates
      // slowly is still alive and gets the whole budget. Expressing both with
      // one timer makes whichever is smaller the only one that ever fires.
      const callDeadline = setTimeout(function () {
        finish(reject, refuse('Timed out after ' + callTimeout +
          ' milliseconds completing the TLS handshake with ' + options.host +
          ':' + options.port + '. The connection was accepted, so the far ' +
          'end is there; the handshake did not finish.',
          'ETLSHANDSHAKETIMEOUT'));
      }, callTimeout);

      const connectOptions = {
        host: address.address,
        port: options.port,
        // The name is what SNI and hostname verification use, and it is
        // deliberately separable from the address dialled: testing a
        // certificate for www.example.com against a staging host is precisely
        // the thing a debugger is for.
        servername: options.servername === null ? undefined
          : (options.servername || (net.isIP(options.host) ? undefined
            : options.host)),
        // Reported, never enforced — see the header.
        rejectUnauthorized: false,
        minVersion: options.minVersion,
        maxVersion: options.maxVersion,
        ciphers: options.ciphers || undefined,
        ALPNProtocols: (options.alpnProtocols || []).length
          ? options.alpnProtocols : undefined,
        // The connect budget belongs to the socket; the handshake budget is
        // the timer above.
        timeout: connectTimeout
      };
      if (trust.ca !== null && trust.ca !== undefined) {
        connectOptions.ca = trust.ca;
      }
      if (options.clientCertificatePem) {
        // A CHAIN, leaf first, not just the leaf — and this is the mistake
        // that is easiest to make and hardest to read. A server verifying a
        // client certificate has to build a path from what the client SENT to
        // an anchor it holds; given only the leaf, a server holding just the
        // root cannot bridge the intermediate, and node's server answers by
        // resetting the connection with no alert at all. The far end then
        // looks like it "refused the certificate", when what it could not do
        // was find the issuer. `cert` accepts concatenated PEM, so the page
        // sends the leaf and its intermediates.
        connectOptions.cert = options.clientCertificatePem;
        connectOptions.key = options.clientKeyPem;
        if (options.clientKeyPassphrase) {
          connectOptions.passphrase = options.clientKeyPassphrase;
        }
      }

      try {
        socket = connectTls(connectOptions);
      } catch (e) {
        // A bad key or certificate throws synchronously, and the message
        // ("error:0480006C:PEM routines::no start line") names neither.
        return finish(reject, refuse('Could not start the TLS connection: ' +
          e.message + '. When a client certificate is being presented, this ' +
          'is usually the key or the certificate not being PEM, or the two ' +
          'not being a pair.', 'ETLSCLIENTMATERIAL'));
      }

      socket.on('connect', function () {
        clearTimeout(connectDeadline);
        socket.setTimeout(0);
      });

      socket.on('secureConnect', function () {
        const cipher = socket.getCipher() || {};
        const described = describeChain(socket);
        const report = {
          postHandshakeError: null,
          closedByPeer: false,
          peerData: false,
          connected: true,
          host: options.host,
          address: address.address,
          port: options.port,
          servername: connectOptions.servername || null,
          elapsedMs: Date.now() - started,
          protocol: socket.getProtocol(),
          cipher: { name: cipher.name || null,
                   standardName: cipher.standardName || null,
                   version: cipher.version || null },
          alpnProtocol: socket.alpnProtocol || null,
          authorized: socket.authorized === true,
          authorizationError: socket.authorizationError
            ? String(socket.authorizationError) : null,
          sessionReused: typeof socket.isSessionReused === 'function'
            ? socket.isSessionReused() : null,
          clientCertificateOffered: !!options.clientCertificatePem,
          trustStore: { pastedAnchors: trust.pastedAnchors,
                       systemRoots: trust.systemRoots },
          peerChain: described.chain,
          peerChainTruncated: described.truncated,
          peerChainBytes: described.bytes,
          // Filled in by finish() from handshakeUsable(), so that "did this
          // connection actually work" is decided in ONE place. A caller that
          // reads `connected` instead gets the TLS 1.3 answer wrong — the page
          // did exactly that for one afternoon and reported a completed
          // handshake for a server that had already hung up.
          usable: false
        };
        // ---------------------------------------------------------------
        // A COMPLETED HANDSHAKE IS NOT AN ACCEPTED CLIENT CERTIFICATE, and
        // under TLS 1.3 it usually is not even close.
        //
        // In TLS 1.2 the server validates the client's certificate before it
        // sends Finished, so a refusal lands during the handshake and
        // `secureConnect` never fires. In TLS 1.3 the client sends its
        // Certificate and Finished LAST — the handshake is complete from the
        // client's point of view the moment it has written them — and the
        // server's verdict arrives afterwards, as a post-handshake alert
        // (`bad certificate`, `certificate required`, `unknown ca`).
        //
        // So resolving here would report a successful mutual-authentication
        // connection to a server that rejected the certificate a millisecond
        // later, and the mutual-auth probe would answer "not required" for
        // every TLS 1.3 server on earth — which is exactly what it did before
        // this block existed. The socket is therefore read for a moment: an
        // alert, a close, or the server's first bytes all end the wait, and
        // only silence spends the whole grace period.
        // ---------------------------------------------------------------
        secureReport = report;
        if (options.httpRequest) {
          // A different wait entirely: the socket is not being watched for a
          // rejection, it is being read for an answer. See
          // askOverTheConnection() below.
          askOverTheConnection(report);
          return;
        }
        socket.resume();
        graceTimer = setTimeout(function () {
          finish(resolve, report);
        }, POST_HANDSHAKE_GRACE_MS);
        socket.once('close', function () {
          report.closedByPeer = true;
          finish(resolve, report);
        });
        socket.once('data', function () {
          // Bytes from the far end are the strongest evidence there is that it
          // is content with the connection — which is what tells an accepted
          // client certificate from the hang-up below.
          report.peerData = true;
          finish(resolve, report);
        });
      });

      // Ask the far end what IT saw, over the connection just made.
      //
      // It replaces the post-handshake grace rather than following it, and does
      // its job: a server that rejects the client certificate answers this
      // request with an alert or a hang-up instead of a response, which
      // lands in the 'error' and 'close' handlers exactly as it would have.
      // So a connection that produces an httpResponse has been vouched for by
      // the strongest evidence there is — the far end spoke.
      function askOverTheConnection(report) {
        logger.debug("Entering askOverTheConnection().");
        const request = options.httpRequest;
        // The Host header is the name the caller asked to be verified, falling
        // back to the host dialled — the same name in the SNI extension, so a
        // virtual host routes this request the way it routed the handshake.
        const hostName = connectOptions.servername || options.host;
        const authority = options.port === 443
          ? hostName : hostName + ':' + options.port;
        const headers = {
          'Host': authority,
          'User-Agent': options.userAgent || 'Identity Protocol Debugger',
          'Accept': 'application/json, text/html;q=0.8, */*;q=0.5',
          // This is what makes the end of the response an EVENT rather than a
          // guess. Without it a keep-alive server holds the socket open and
          // this would have to implement Content-Length and chunked decoding to
          // know when to stop — a second HTTP implementation, in the one place
          // whose entire value is reporting bytes verbatim.
          'Connection': 'close'
        };
        report.httpRequest = { method: request.method, path: request.path,
                              headers: headers };
        // BUFFERS, never a string. HTTP framing counts bytes and a string is
        // indexed in code units, so accumulating as text puts every multi-byte
        // character in the body one step out of step with the chunk sizes — see
        // decodeChunked(). Decoding happens once, at the end, over the whole
        // thing, which is also what stops a character split across two TCP
        // segments from being decoded as two replacement characters.
        const received = [];
        let bytes = 0;
        let kept = 0;
        let truncated = false;
        let responseTimer = null;

        function settleWithResponse(reason) {
          if (settled) return;
          const parsed = parseHttpResponse(Buffer.concat(received));
          report.httpResponse = {
            parsed: parsed.parsed,
            statusLine: parsed.statusLine || null,
            httpVersion: parsed.httpVersion,
            statusCode: parsed.statusCode,
            statusText: parsed.statusText,
            headers: parsed.headers,
            // Chunked framing removed, because it is framing and not content —
            // node's own HTTP server answers chunked whenever it does not know
            // the length in advance, which is most of the time.
            transferEncoding: parsed.transferEncoding || null,
            bodyComplete: parsed.bodyComplete !== false,
            body: parsed.body !== undefined ? parsed.body : (parsed.raw || ''),
            bytes: bytes,
            truncated: truncated,
            endedBy: reason
          };
          // Bytes from the far end are the strongest evidence there is that it
          // is content with the connection, which is exactly what the grace
          // period is otherwise waiting to find out.
          if (bytes) report.peerData = true;
          finish(resolve, report);
        }

        function armResponseTimer() {
          if (responseTimer) clearTimeout(responseTimer);
          responseTimer = setTimeout(function () {
            settleWithResponse('silence');
          }, HTTP_RESPONSE_GRACE_MS);
          // Kept on the outer variable as well so finish() clears it — there is
          // one timer slot and only one of the two waits is ever armed.
          graceTimer = responseTimer;
        }

        socket.on('data', function (chunk) {
          bytes += chunk.length;
          if (!truncated) {
            const room = maxChainBytes - kept;
            if (chunk.length > room) {
              truncated = true;
              if (room > 0) {
                received.push(chunk.slice(0, room));
                kept += room;
              }
              logger.warn('tls_probe: the response to ' + request.path +
                          ' passed the ' + maxChainBytes +
                          '-byte cap and was truncated.');
              settleWithResponse('cap');
              return;
            }
            received.push(chunk);
            kept += chunk.length;
          }
          armResponseTimer();
        });
        socket.once('close', function () {
          report.closedByPeer = true;
          settleWithResponse('close');
        });
        socket.once('end', function () {
          // 'end' is the peer's FIN and it arrives BEFORE 'close', so this is
          // the handler that actually runs — which is why it must record the
          // hang-up rather than leaving that to the one below. A TLS 1.3 server
          // rejecting a client certificate closes the socket with no alert at
          // all, so a FIN with no bytes behind it is precisely that refusal;
          // recording it only on 'close' left `usable` true for a server that
          // had answered nothing, which is the exact failure the grace period
          // in the other branch exists to catch. A successful response ends the
          // same way — `Connection: close` asks it to — but has bytes, and
          // handshakeUsable() reads both.
          report.closedByPeer = true;
          settleWithResponse('end');
        });
        armResponseTimer();
        try {
          socket.write(request.method + ' ' + request.path + ' HTTP/1.1\r\n' +
            Object.keys(headers).map(function (name) {
              return name + ': ' + headers[name];
            }).join('\r\n') + '\r\n\r\n');
        } catch (e) {
          // Writing to a socket the far end has already closed. It is not an
          // error about the handshake, which happened and is reported; it is
          // the rejection arriving in its third form.
          logger.debug('askOverTheConnection(): write: ' + e.message);
          settleWithResponse('write-failed');
        }
        logger.debug("Leaving askOverTheConnection().");
      }

      socket.on('timeout', function () {
        finish(reject, refuse('The connection to ' + options.host + ':' +
          options.port + ' timed out before the TCP connection was ' +
          'established.', 'ETLSCONNECTTIMEOUT'));
      });

      socket.on('error', function (error) {
        // An error AFTER the handshake is the TLS 1.3 rejection described
        // above, and it belongs on the report the handshake already produced
        // rather than replacing it — the negotiated version, the cipher and
        // the server's chain are all still true and all still wanted.
        if (secureReport) {
          secureReport.postHandshakeError = { code: error.code || null,
                                             message: error.message,
                                             library: error.library || null,
                                             reason: error.reason || null };
          finish(resolve, secureReport);
          return;
        }
        // A handshake FAILURE is a result, not an absence of one: the alert is
        // the most informative thing this endpoint produces, and it is what
        // says "the server asked for a certificate you did not send" or "the
        // server refused the one you did". So it resolves with a report rather
        // than rejecting.
        finish(resolve, {
          connected: false,
          host: options.host,
          address: address.address,
          port: options.port,
          servername: connectOptions.servername || null,
          elapsedMs: Date.now() - started,
          clientCertificateOffered: !!options.clientCertificatePem,
          trustStore: { pastedAnchors: trust.pastedAnchors,
                       systemRoots: trust.systemRoots },
          error: { code: error.code || null, message: error.message,
                  library: error.library || null,
                  reason: error.reason || null },
          peerChain: [],
          authorized: false,
          authorizationError: null
        });
      });
    });
  }

  // The whole call: validate, resolve, connect — and, when asked, connect a
  // second time without the client certificate so that "does this server
  // require mutual authentication" has an answer rather than an inference.
  async function connect(options) {
    logger.debug("Entering connect().");
    const opts = options || {};
    const host = String(opts.host || '').trim();
    if (!host) {
      logger.debug("Leaving connect(). No host.");
      throw refuse('A host is required.', 'ETLSNOHOST');
    }
    const port = typeof opts.port === 'number' ? opts.port
      : parseInt(opts.port, 10);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      logger.debug("Leaving connect(). Bad port.");
      throw refuse('A port from 1 to 65535 is required; got ' +
        JSON.stringify(opts.port) + '.', 'ETLSBADPORT');
    }
    assertPortAllowed(port);
    const minVersion = assertVersion('minVersion', opts.minVersion);
    const maxVersion = assertVersion('maxVersion', opts.maxVersion);
    if (minVersion && maxVersion &&
        TLS_VERSIONS.indexOf(minVersion) > TLS_VERSIONS.indexOf(maxVersion)) {
      logger.debug("Leaving connect(). Version range is empty.");
      throw refuse('minVersion ' + minVersion + ' is above maxVersion ' +
        maxVersion + ', which allows no version at all.', 'ETLSBADVERSION');
    }
    if (opts.clientCertificatePem && !opts.clientKeyPem) {
      logger.debug("Leaving connect(). Certificate without key.");
      throw refuse('A client certificate was supplied with no private key. ' +
        'Mutual authentication needs both — the certificate is what is sent, ' +
        'the key is what proves it is yours.', 'ETLSNOCLIENTKEY');
    }
    const httpRequest = assertHttpRequest(opts.httpRequest);
    const trust = buildTrustStore(opts);
    const address = await resolveAllowedAddress(host);

    const base = {
      host: host,
      port: port,
      httpRequest: httpRequest,
      userAgent: opts.userAgent,
      servername: opts.servername,
      minVersion: minVersion,
      maxVersion: maxVersion,
      ciphers: opts.ciphers,
      alpnProtocols: opts.alpnProtocols,
      clientCertificatePem: opts.clientCertificatePem,
      clientKeyPem: opts.clientKeyPem,
      clientKeyPassphrase: opts.clientKeyPassphrase,
      trust: trust
    };

    const primary = await handshake(base, address);
    const result = { result: primary };

    if (opts.mutualAuthProbe && opts.clientCertificatePem) {
      const withoutCert = Object.assign({}, base, {
        clientCertificatePem: null, clientKeyPem: null,
        clientKeyPassphrase: null });
      const anonymous = await handshake(withoutCert, address);
      result.withoutClientCertificate = anonymous;
      result.mutualAuth = describeMutualAuth(primary, anonymous);
    }
    logger.debug("Leaving connect().");
    return result;
  }

  // Read the two handshakes as an answer to one question. This is the only
  // place in the service that draws a conclusion rather than reporting a fact,
  // so it says what it is inferring from.
  // "Completed" is not `connected`, and the difference is the whole reason
  // this function is careful. A TLS 1.3 handshake completes before the server
  // has said anything about the client certificate, and a server that then
  // refuses it does one of TWO things — neither of which is visible in the
  // handshake:
  //
  //   * sends a post-handshake alert (`certificate required`, `bad
  //     certificate`, `unknown ca`), or
  //   * simply HANGS UP. Node's own TLS server does exactly this when
  //     `rejectUnauthorized` refuses a client certificate: the socket closes
  //     with no alert at all, and the far end sees an ordinary close.
  //
  // So a connection the peer closed immediately, having sent nothing, is a
  // refusal — while one that is still open after the grace period, or that
  // sent bytes, is a server content to talk. Reading `connected` alone reports
  // both refusals as success.
  function handshakeUsable(report) {
    logger.debug("Entering handshakeUsable().");
    const usable = !!report.connected && !report.postHandshakeError &&
        !(report.closedByPeer && !report.peerData);
    logger.debug("Leaving handshakeUsable(). " + usable);
    return usable;
  }

  // Did we get far enough to be talking TLS to something at all? Used to tell
  // "the server refused this certificate" from "there is nothing there".
  function reachedTls(report) {
    logger.debug("Entering reachedTls().");
    const reached = !!report.connected ||
        !!(report.error && /SSL|TLS|alert|certificate/i.test(
            (report.error.code || '') + ' ' + (report.error.message || '')));
    logger.debug("Leaving reachedTls(). " + reached);
    return reached;
  }

  function describeMutualAuth(withCert, withoutCert) {
    logger.debug("Entering describeMutualAuth().");
    let verdict;
    let detail;
    const offered = handshakeUsable(withCert);
    const anonymous = handshakeUsable(withoutCert);
    const offeredError = withCert.postHandshakeError || withCert.error || {};
    const anonymousError = withoutCert.postHandshakeError ||
        withoutCert.error || {};
    if (offered && !anonymous) {
      verdict = 'required';
      detail = 'The connection worked with the client certificate and did ' +
        'not without it (' + (anonymousError.code || 'the server hung up') +
        '), so the server requires client authentication and accepted this ' +
        'certificate.';
    } else if (offered && anonymous) {
      verdict = 'not-required';
      detail = 'The connection worked both with and without the client ' +
        'certificate, so the server does not require one. It may still have ' +
        'requested it optionally — node does not expose the ' +
        'CertificateRequest, which is why this is measured rather than read.';
    } else if (!offered && anonymous) {
      verdict = 'certificate-rejected';
      detail = 'The connection worked WITHOUT the client certificate and ' +
        'failed with it (' + (offeredError.code || 'the server hung up') +
        '), so the server refused the certificate offered rather than ' +
        'requiring one.';
    } else if (reachedTls(withCert)) {
      verdict = 'required-and-rejected';
      detail = 'Neither connection worked, but both reached a TLS ' +
        'handshake: without a certificate the server answered ' +
        (anonymousError.code || 'by hanging up') + ', and with this one it ' +
        'answered ' + (offeredError.code || 'by hanging up') + '. The server ' +
        'requires client authentication AND refused this certificate — ' +
        'usually because it was issued by a CA the server does not trust.';
    } else {
      verdict = 'unknown';
      detail = 'Neither connection reached a TLS handshake, so nothing can ' +
        'be concluded about client authentication. The errors below are ' +
        'about reaching the server at all.';
    }
    logger.debug("Leaving describeMutualAuth(). " + verdict);
    return { verdict: verdict, detail: detail };
  }

  function limits() {
    logger.debug("Entering limits().");
    logger.debug("Leaving limits().");
    return {
      allowedPorts: anyPort ? 'any' : allowedPorts.slice(),
      connectionTimeoutMs: connectTimeout,
      callTimeoutMs: callTimeout,
      maxChainBytes: maxChainBytes,
      maxTrustAnchors: MAX_TRUST_ANCHORS,
      postHandshakeGraceMs: POST_HANDSHAKE_GRACE_MS,
      tlsVersions: TLS_VERSIONS.slice(),
      addressPolicyEnabled: addressPolicyEnabled,
      mutualAuthProbeAvailable: true,
      // Published so a page can tell an older api from a broken one, the same
      // reason GET /krb5/limits publishes `spnegoEnabled`: a request for
      // something this build cannot do should read as an old build rather than
      // as a server that ignored it.
      httpRequestAvailable: true,
      httpRequestMethod: 'GET',
      httpResponseGraceMs: HTTP_RESPONSE_GRACE_MS,
      maxHttpPathLength: MAX_HTTP_PATH_LENGTH,
      nodeVersion: process.version,
      systemRootCount: tls.rootCertificates.length
    };
  }

  logger.debug("Leaving createProbe().");
  return {
    connect: connect,
    limits: limits,
    // Exported for the tests, which check them without opening a socket.
    splitPemCertificates: splitPemCertificates,
    describeMutualAuth: describeMutualAuth
  };
}

module.exports = {
  createProbe: createProbe,
  DEFAULT_ALLOWED_PORTS: DEFAULT_ALLOWED_PORTS,
  TLS_VERSIONS: TLS_VERSIONS,
  MAX_TRUST_ANCHORS: MAX_TRUST_ANCHORS,
  HTTP_RESPONSE_GRACE_MS: HTTP_RESPONSE_GRACE_MS,
  MAX_HTTP_PATH_LENGTH: MAX_HTTP_PATH_LENGTH,
  splitPemCertificates: splitPemCertificates,
  parseHttpResponse: parseHttpResponse
};
