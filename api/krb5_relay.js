// File: krb5_relay.js
//
// ---------------------------------------------------------------------------
// The guarded byte relay behind POST /krb5/kdc.
//
// Kerberos is not an HTTP protocol. A browser cannot open a TCP socket, so the
// whole workflow needs this service to carry ~500 bytes to port 88 and bring the
// answer back. Everything protocol-shaped happens in the browser; this file
// frames, guards, times and relays, and knows nothing about what it is carrying
// beyond the pre-flight in krb5_frame.js.
//
// ---------------------------------------------------------------------------
// WHY THIS FILE IS NOT COVERED BY api/ssrf_guard.js, AND HAD TO BE WRITTEN.
//
// The guard is installed on the shared **axios** instance: a request interceptor
// plus `lookup` and `createConnection` hooks on the outbound agents. A
// `net.connect(port, host)` walks past all of it — there is no axios in the path
// and no agent to hook. So this is a second, parallel enforcement of the same
// policy for a transport that guard has never seen, and it reuses the guard's
// DECISION (`blockedRangeFor`) rather than reimplementing the ranges, because two
// implementations of an address policy is one implementation and one hole.
//
// Four things bound this endpoint, and all four are load-bearing:
//
//  1. **The address policy**, shared with the HTTP side. `blockPrivateNetworkCalls`
//     and `blockedAddressRanges`, same settings, same ranges.
//  2. **Resolve, then connect to the LITERAL.** The hostname is resolved here and
//     the socket is opened to the address that was checked, not to the name. A
//     name re-resolved by the OS between the check and the connect is the
//     DNS-rebinding window, and it is exactly as narrow here as the guard makes it
//     on the HTTP side.
//  3. **A port allowlist**, which is NEW and which the HTTP endpoints do not need.
//     An HTTP fetcher pointed at port 22 gets nothing; a byte relay pointed at
//     port 22 is a port scanner whose payload the caller chooses. Default 88
//     (Kerberos), 464 (kpasswd) and 749 (kadmin).
//  4. **A message-shape pre-flight**, so the payload must be an AS-REQ, TGS-REQ or
//     AP-REQ before a socket is opened at all. Without it this is a general
//     tunnel; with it, it sends Kerberos to Kerberos ports.
//
// And the limits, which are the same four ideas as the HTTP side and are here for
// the same reasons: a connect budget separate from the whole-call budget (a
// slow-but-alive KDC must not die as readily as a dead address), and a response
// cap applied to the far end's DECLARED length before anything is allocated.
//
// One thing this file must get right that the HTTP handlers got wrong for a long
// time: **the no-response branch must answer.** For this endpoint a network-level
// failure is not the rare case, it is the common one — the whole point is aiming
// it at a host that may not be there. Every path below either resolves or
// rejects, and the caller in server.js answers on both.
// ---------------------------------------------------------------------------

const net = require('net');
const dgram = require('dgram');
const dns = require('dns');
const frame = require('./krb5_frame.js');

const DEFAULT_ALLOWED_PORTS = [88, 464, 749];

// The SERVICE endpoint's ports default to NOTHING, and that is the whole point.
//
// A Kerberos service can be on any port at all — 443, 1433, 389, 5432 — so a port
// allowlist cannot bound this endpoint the way it bounds the KDC one. What bounds it
// is the payload check (api/krb5_frame.js's assertServiceRequest: a GSS
// InitialContextToken naming the Kerberos mechanism and wrapping a well-formed
// AP-REQ, or a bare AP-REQ). That check is strict enough that an HTTP request, a
// Redis command and a TLS handshake all fail it.
//
// Even so, the capability is off by default. `krb5ServicePorts` must be set — the
// local and containerized stacks set it to the mock service's port — so that a
// deployment which has no use for it does not silently acquire the ability to send
// caller-supplied bytes to an arbitrary port. Fail-safe rather than fail-open.
const DEFAULT_SERVICE_PORTS = [];
const DEFAULT_CONNECT_TIMEOUT_MS = 5000;
const DEFAULT_CALL_TIMEOUT_MS = 10000;
const DEFAULT_MAX_REPLY_BYTES = 1048576;

// UDP is bounded far below the TCP cap because a datagram that large does not
// arrive intact anyway, and a KDC that has more to say answers
// KRB_ERR_RESPONSE_TOO_BIG so the client retries over TCP. That error is itself
// something a debugger's user wants to see, which is why UDP is offered at all.
const UDP_RECEIVE_BYTES = 65535;

function resolvePositiveNumber(value, fallback, name, log) {
  if (typeof value === 'number' && isFinite(value) && value > 0) return value;
  if (value !== undefined && value !== null) {
    log.error('krb5_relay: ' + name + ' is not a positive number (' + JSON.stringify(value) +
              '); using ' + fallback + '.');
  }
  return fallback;
}

// The port allowlist. A malformed entry is dropped with its reason logged, and an
// allowlist that ends up empty is an error rather than a silent "allow nothing" or
// — much worse — a silent "allow everything".
function resolveAllowedPorts(value, log) {
  if (value === undefined || value === null) return DEFAULT_ALLOWED_PORTS.slice();
  if (!Array.isArray(value)) {
    log.error('krb5_relay: krb5AllowedPorts must be an array of port numbers; using the default ' +
              DEFAULT_ALLOWED_PORTS.join(', ') + '.');
    return DEFAULT_ALLOWED_PORTS.slice();
  }
  const ports = [];
  for (const entry of value) {
    const port = typeof entry === 'number' ? entry : parseInt(entry, 10);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      log.error('krb5_relay: ignoring krb5AllowedPorts entry ' + JSON.stringify(entry) +
                ' — a port must be an integer from 1 to 65535.');
      continue;
    }
    if (ports.indexOf(port) === -1) ports.push(port);
  }
  if (!ports.length) {
    log.error('krb5_relay: krb5AllowedPorts contained no usable ports, so this relay will refuse ' +
              'every call. That is the safe direction, but it is almost certainly a configuration ' +
              'mistake.');
  }
  return ports;
}

function createRelay(appconfig, guard, log) {
  appconfig = appconfig || {};
  const logger = log || { debug() {}, info() {}, warn() {}, error() {} };

  const allowedPorts = resolveAllowedPorts(appconfig.krb5AllowedPorts, logger);
  // "any" is accepted for the service endpoint, because a real deployment debugging
  // several services genuinely cannot enumerate their ports. It is spelled out as a
  // word rather than expressed as an empty list or a 0, so that switching it on is
  // an unmistakable act rather than a plausible typo.
  const serviceAnyPort = appconfig.krb5ServicePorts === 'any';
  const servicePorts = serviceAnyPort
    ? []
    : (appconfig.krb5ServicePorts === undefined || appconfig.krb5ServicePorts === null
        ? DEFAULT_SERVICE_PORTS.slice()
        : resolveAllowedPorts(appconfig.krb5ServicePorts, logger));
  const connectTimeout = resolvePositiveNumber(appconfig.connectionTimeout, DEFAULT_CONNECT_TIMEOUT_MS,
    'connectionTimeout', logger);
  const callTimeout = resolvePositiveNumber(appconfig.callTimeout, DEFAULT_CALL_TIMEOUT_MS,
    'callTimeout', logger);
  const maxReplyBytes = resolvePositiveNumber(appconfig.maxContentLength, DEFAULT_MAX_REPLY_BYTES,
    'maxContentLength', logger);
  // The address policy is the guard's, not a second copy of it. A relay with its
  // own idea of what is private is a relay that disagrees with the HTTP side.
  const addressPolicyEnabled = !!(guard && guard.enabled);

  logger.info('krb5_relay: KDC ports ' + (allowedPorts.join(', ') || '(none)') +
    '; service ports ' + (serviceAnyPort ? 'ANY (krb5ServicePorts is "any")'
                                         : (servicePorts.join(', ') || 'NONE — POST /krb5/service ' +
                                            'will refuse every call until krb5ServicePorts is set')) +
    '; connect timeout ' + connectTimeout + ' milliseconds; call timeout ' + callTimeout +
    ' milliseconds; reply cap ' + maxReplyBytes + ' bytes; address policy ' +
    (addressPolicyEnabled ? 'ENABLED (shared with ssrf_guard)' : 'disabled'));

  function refuse(message, code) {
    const error = new Error(message);
    error.code = code || 'EKRB5REFUSED';
    error.refused = true;
    return error;
  }

  function assertPortAllowed(port, purpose) {
    if (purpose === 'service') {
      if (serviceAnyPort) return;
      if (!servicePorts.length) {
        throw refuse('POST /krb5/service is not enabled on this deployment. It sends ' +
          'caller-supplied bytes to a caller-supplied port, which is a broader capability than the ' +
          'KDC relay — a Kerberos service can be on any port, so no small allowlist bounds it and ' +
          'the payload check does that work instead. Set krb5ServicePorts to the port(s) you need, ' +
          'or to the string "any".', 'EKRB5SERVICENOTENABLED');
      }
      if (servicePorts.indexOf(port) === -1) {
        throw refuse('Refusing to connect to port ' + port + '. This deployment allows Kerberos ' +
          'service traffic to ' + servicePorts.join(', ') + ' only. Add the port to ' +
          'krb5ServicePorts, or set it to "any".', 'EKRB5PORTNOTALLOWED');
      }
      return;
    }
    if (allowedPorts.indexOf(port) === -1) {
      throw refuse('Refusing to connect to port ' + port + '. This relay carries Kerberos to ' +
        'Kerberos ports only (' + (allowedPorts.join(', ') || 'none configured') + '). It is a raw ' +
        'byte relay, so an unrestricted port would make it a port scanner with a caller-chosen ' +
        'payload. Add the port to krb5AllowedPorts if this deployment needs it.',
        'EKRB5PORTNOTALLOWED');
    }
  }

  // Resolve the host and return an address that has passed the policy. A literal
  // is checked directly — node never calls a DNS resolver for one, which is the
  // gap that made the HTTP guard need two hooks rather than one.
  function resolveAllowedAddress(host) {
    return new Promise(function (resolve, reject) {
      const literalFamily = net.isIP(host);
      if (literalFamily) {
        const range = addressPolicyEnabled && guard.blockedRangeFor(host);
        if (range) {
          return reject(refuse('Refusing to open a TCP connection to ' + host + ': it is in the ' +
            'blocked range ' + range + '. This service does not connect to loopback or private ' +
            'network addresses. Set blockPrivateNetworkCalls to false in the api configuration if ' +
            'this deployment is meant to — the local and containerized stacks do, because their ' +
            'KDC IS a private address.', 'EBLOCKEDADDRESS'));
        }
        return resolve({ address: host, family: literalFamily, wasLiteral: true });
      }
      dns.lookup(host, { all: true }, function (err, addresses) {
        if (err) {
          return reject(refuse('Could not resolve ' + host + ': ' + err.message +
            ' (' + err.code + ').', 'EKRB5DNS'));
        }
        const list = Array.isArray(addresses) ? addresses : [addresses];
        for (const entry of list) {
          const range = addressPolicyEnabled && guard.blockedRangeFor(entry.address);
          if (range) {
            logger.warn('krb5_relay: refused ' + host + ' -> ' + entry.address + ' (' + range + ')');
            return reject(refuse('Refusing to connect to ' + host + ': it resolves to ' +
              entry.address + ', which is in the blocked range ' + range + '. Note that a name is ' +
              'judged by what it RESOLVES to, so localtest.me and 127.0.0.1.nip.io are caught by ' +
              'the same rule.', 'EBLOCKEDADDRESS'));
          }
        }
        // Connect to the literal that was checked, not to the name. Re-resolving
        // at connect time is the DNS-rebinding window.
        resolve({ address: list[0].address, family: list[0].family, wasLiteral: false });
      });
    });
  }

  function sendOverTcp(target, payload, timings) {
    return new Promise(function (resolve, reject) {
      let settled = false;
      let buffer = Buffer.alloc(0);
      const socket = new net.Socket();

      // Two separate deadlines, and they are additive rather than one shadowing
      // the other. A KDC that connects and then thinks for a while must be given
      // until callTimeout; a dead address must fail at connectTimeout. Expressing
      // both with one timer makes whichever is smaller the only one that fires.
      let connectTimer = setTimeout(function () {
        finish(refuse('Timed out after ' + connectTimeout + ' milliseconds trying to reach ' +
          target.address + ':' + target.port + '. Nothing accepted a connection — either no KDC is ' +
          'listening there, or a firewall is dropping the packets silently.', 'EKRB5CONNECTTIMEOUT'));
      }, connectTimeout);
      const callTimer = setTimeout(function () {
        finish(refuse('Timed out after ' + callTimeout + ' milliseconds waiting for a reply from ' +
          target.address + ':' + target.port + '. The connection was established, so something is ' +
          'listening; it did not answer.', 'EKRB5CALLTIMEOUT'));
      }, callTimeout);

      function finish(err, message) {
        if (settled) return;
        settled = true;
        if (connectTimer) { clearTimeout(connectTimer); connectTimer = null; }
        clearTimeout(callTimer);
        socket.destroy();
        if (err) return reject(err);
        resolve(message);
      }

      socket.on('connect', function () {
        // Disarm the CONNECT budget only, leaving the call budget running.
        if (connectTimer) { clearTimeout(connectTimer); connectTimer = null; }
        timings.connectedAt = Date.now();
        socket.write(frame.frameForTcp(payload));
      });

      socket.on('data', function (chunk) {
        buffer = Buffer.concat([buffer, chunk]);
        // The cap is applied to what the far end DECLARED, inside readTcpFrame,
        // before the rest is waited for. Also guard the accumulating buffer, for a
        // sender that never sends a prefix at all.
        if (buffer.length > maxReplyBytes + 4) {
          return finish(refuse('The reply from ' + target.address + ':' + target.port + ' passed ' +
            maxReplyBytes + ' bytes without a complete message. Abandoned.', 'EKRB5REPLYTOOBIG'));
        }
        let read;
        try {
          read = frame.readTcpFrame(buffer, maxReplyBytes);
        } catch (e) {
          return finish(refuse(e.message, 'EKRB5BADFRAME'));
        }
        if (read.complete) finish(null, read.message);
      });

      socket.on('error', function (err) {
        finish(refuse('Could not talk to ' + target.address + ':' + target.port + ': ' +
          err.message + ' (' + err.code + ').', 'EKRB5SOCKET'));
      });

      socket.on('end', function () {
        // A KDC that closes without a complete reply. Distinguished from a
        // timeout, because it means something answered and then gave up.
        finish(refuse('The connection to ' + target.address + ':' + target.port + ' closed after ' +
          buffer.length + ' byte(s), before a complete reply arrived.', 'EKRB5SHORTREPLY'));
      });

      socket.connect({ host: target.address, port: target.port, family: target.family });
    });
  }

  function sendOverUdp(target, payload, timings) {
    return new Promise(function (resolve, reject) {
      let settled = false;
      const socket = dgram.createSocket(target.family === 6 ? 'udp6' : 'udp4');
      const timer = setTimeout(function () {
        finish(refuse('No UDP reply from ' + target.address + ':' + target.port + ' within ' +
          callTimeout + ' milliseconds. UDP is unacknowledged, so this may mean the datagram never ' +
          'arrived. Retry over TCP — which is what a client does anyway when a KDC answers ' +
          'KRB_ERR_RESPONSE_TOO_BIG.', 'EKRB5CALLTIMEOUT'));
      }, callTimeout);

      function finish(err, message) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try { socket.close(); } catch (e) {
          // Already closing: nothing to do, and nothing worth reporting.
        }
        if (err) return reject(err);
        resolve(message);
      }

      socket.on('message', function (msg) {
        timings.connectedAt = timings.connectedAt || Date.now();
        // UDP carries no length prefix: the datagram IS the message.
        if (msg.length > maxReplyBytes) {
          return finish(refuse('The UDP reply is ' + msg.length + ' bytes, over the ' +
            maxReplyBytes + '-byte limit.', 'EKRB5REPLYTOOBIG'));
        }
        finish(null, msg);
      });
      socket.on('error', function (err) {
        finish(refuse('UDP to ' + target.address + ':' + target.port + ' failed: ' + err.message +
          ' (' + err.code + ').', 'EKRB5SOCKET'));
      });
      socket.send(Buffer.from(payload), target.port, target.address, function (err) {
        if (err) {
          finish(refuse('Could not send the UDP datagram to ' + target.address + ':' + target.port +
            ': ' + err.message + '.', 'EKRB5SOCKET'));
        }
      });
    });
  }

  // The whole operation. Every path resolves or rejects — see the note at the top
  // about the no-response branch.
  async function send(options) {
    const opts = options || {};
    const host = String(opts.host || '').trim();
    const port = typeof opts.port === 'number' ? opts.port : parseInt(opts.port, 10);
    const transport = (opts.transport === 'udp') ? 'udp' : 'tcp';
    const payload = Buffer.isBuffer(opts.message) ? opts.message : Buffer.from(opts.message || []);

    logger.debug('Entering krb5_relay.send(). host=' + host + ', port=' + port +
                 ', transport=' + transport + ', purpose=' + (opts.purpose || 'kdc') +
                 ', bytes=' + payload.length);

    if (!host) throw refuse('No KDC host given.', 'EKRB5NOHOST');
    if (!Number.isInteger(port)) {
      throw refuse('The KDC port is not a number: ' + JSON.stringify(opts.port) + '.', 'EKRB5NOPORT');
    }

    // The pre-flight, BEFORE the port check and before any socket: the cheapest
    // and most specific refusal should come first, so a caller sending the wrong
    // bytes is told that rather than being told about ports.
    const purpose = opts.purpose === 'service' ? 'service' : 'kdc';
    let messageName;
    try {
      messageName = purpose === 'service'
        ? frame.assertServiceRequest(payload)
        : frame.assertKerberosRequest(payload);
    } catch (e) {
      throw refuse('Refusing to relay this payload: ' + e.message + ' This endpoint carries Kerberos ' +
        (purpose === 'service' ? 'AP-REQs' : 'KDC requests') +
        ', not arbitrary bytes — see api/krb5_frame.js for why that restriction exists.',
        'EKRB5NOTKERBEROS');
    }
    assertPortAllowed(port, purpose);

    const target = await resolveAllowedAddress(host);
    target.port = port;

    const timings = { startedAt: Date.now(), connectedAt: null };
    const reply = transport === 'udp'
      ? await sendOverUdp(target, payload, timings)
      : await sendOverTcp(target, payload, timings);
    const finishedAt = Date.now();

    const replyName = frame.describeReply(reply);
    logger.info('krb5_relay: ' + messageName + ' (' + payload.length + ' bytes) to ' + host +
      (target.wasLiteral ? '' : ' [' + target.address + ']') + ':' + port + '/' + transport +
      ' -> ' + replyName + ' (' + reply.length + ' bytes) in ' + (finishedAt - timings.startedAt) + 'ms');
    logger.debug('Leaving krb5_relay.send().');

    return {
      request: { message: messageName, bytes: payload.length },
      reply: reply,
      replyMessage: replyName,
      target: {
        host: host,
        address: target.address,
        port: port,
        transport: transport,
        resolved: !target.wasLiteral
      },
      timing: {
        totalMs: finishedAt - timings.startedAt,
        connectMs: timings.connectedAt ? timings.connectedAt - timings.startedAt : null
      }
    };
  }

  return {
    send: send,
    allowedPorts: allowedPorts.slice(),
    servicePorts: serviceAnyPort ? 'any' : servicePorts.slice(),
    serviceEnabled: serviceAnyPort || servicePorts.length > 0,
    addressPolicyEnabled: addressPolicyEnabled,
    limits: {
      connectTimeout: connectTimeout,
      callTimeout: callTimeout,
      maxReplyBytes: maxReplyBytes
    }
  };
}

module.exports = {
  createRelay: createRelay,
  DEFAULT_ALLOWED_PORTS: DEFAULT_ALLOWED_PORTS.slice(),
  DEFAULT_SERVICE_PORTS: DEFAULT_SERVICE_PORTS.slice(),
  resolveAllowedPorts: resolveAllowedPorts
};
