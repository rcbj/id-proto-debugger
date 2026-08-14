// File: krb5_frame.js
//
// ---------------------------------------------------------------------------
// The TCP framing Kerberos uses, and the pre-flight that decides whether a
// payload this service was handed is a Kerberos request at all.
//
// **This file deliberately does not use common/krb5.** The codec over there is
// 3,500 lines and is the right thing for decoding a message; it is the wrong
// thing for deciding whether to open a socket. A guard whose correctness depends
// on a large parser inherits every bug in that parser, and this one runs BEFORE
// any network activity, on bytes supplied by whoever can reach the api. So it
// does the minimum by hand: enough DER to read the outermost tag and length, and
// nothing else.
//
// What the pre-flight is FOR. `POST /krb5/kdc` relays bytes to a host and port
// its caller names. That is a broader primitive than the HTTP endpoints this
// service already has — an HTTP fetcher aimed at port 22 gets nothing useful,
// whereas a byte relay aimed at port 22 is a port scanner with a payload of the
// caller's choosing. Two things bound it: the port allowlist in krb5_relay.js,
// and the requirement here that the payload actually be an AS-REQ, a TGS-REQ or
// an AP-REQ. Together they mean the endpoint can send Kerberos requests to
// Kerberos ports and nothing else to nowhere else.
//
// The length prefix is attacker-controlled in BOTH directions and is handled as
// such: outbound it is computed here rather than taken from the caller, and
// inbound a reply may announce four gigabytes, so the cap is applied before
// anything is allocated. RFC 4120 reserves the prefix's top bit, so a reply that
// sets it is refused rather than interpreted.
// ---------------------------------------------------------------------------

// What a KDC answers, and nothing else. An AP-REQ is deliberately NOT here: it goes
// to a SERVICE, not to a KDC, and the two have different port policies — see
// assertServiceRequest below and api/CLAUDE.md.
const KDC_REQUEST_TAGS = {
  0x6a: 'AS-REQ',      // [APPLICATION 10]
  0x6c: 'TGS-REQ'      // [APPLICATION 12]
};

// What a Kerberos-protected service is presented with. Almost always the GSS-wrapped
// form: a service receives an RFC 2743 InitialContextToken, not a bare AP-REQ.
const SERVICE_REQUEST_TAGS = {
  0x6e: 'AP-REQ',                     // [APPLICATION 14], bare — rare but legal
  0x60: 'GSS-wrapped AP-REQ'          // [APPLICATION 0], the InitialContextToken
};

// The DER-encoded Kerberos v5 mechanism OID, 1.2.840.113554.1.2.2. Written out here
// rather than imported from common/krb5/krb5_gss.js for the same reason this whole
// file avoids that codec: this check runs BEFORE a socket opens, on bytes supplied by
// whoever can reach the api, and a guard should not inherit a large module's bugs.
const KRB5_MECH_OID_DER = Buffer.from([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02]);

// A KDC request is a few hundred bytes to a few kilobytes. A PA-FX-FAST armored
// request with a large PAC can be bigger, so the ceiling is generous — but it is
// a ceiling, because this value bounds what one call can make this service send.
const MAX_REQUEST_BYTES = 64 * 1024;

// The absolute floor on a reply, below which nothing can be a Kerberos message.
const MIN_MESSAGE_BYTES = 2;

// Read the outermost DER tag and length without a parser.
//
// Returns { tag, length, headerLength, totalLength } or throws. Only definite
// lengths of at most four bytes are accepted: an indefinite length is BER rather
// than DER, and in a message being sent to a KDC it means something is
// re-encoding the traffic.
function readOuterTlv(bytes) {
  if (!bytes || bytes.length < MIN_MESSAGE_BYTES) {
    throw new Error('too short to be a Kerberos message (' + (bytes ? bytes.length : 0) + ' bytes)');
  }
  const tag = bytes[0];
  const lengthByte = bytes[1];
  let length;
  let headerLength;
  if (lengthByte < 0x80) {
    length = lengthByte;
    headerLength = 2;
  } else if (lengthByte === 0x80) {
    throw new Error('the outermost element uses an indefinite length, which is BER; Kerberos is DER');
  } else {
    const count = lengthByte & 0x7f;
    if (count > 4) {
      throw new Error('the outermost length field is ' + count + ' bytes, which is not a credible ' +
                      'Kerberos message');
    }
    if (bytes.length < 2 + count) {
      throw new Error('truncated: the outermost length field runs past the end of the payload');
    }
    length = 0;
    for (let i = 0; i < count; i++) length = (length * 256) + bytes[2 + i];
    headerLength = 2 + count;
  }
  return { tag: tag, length: length, headerLength: headerLength, totalLength: headerLength + length };
}

// The pre-flight. Throws with a reason a caller can act on; returns the message
// name on success.
//
// It checks the SHAPE and refuses to guess: a payload whose declared length does
// not match its actual length is either truncated or padded, and relaying either
// would put this service's name on a malformed request in somebody else's KDC log.
function assertSizeAndLength(bytes, name) {
  if (bytes.length > MAX_REQUEST_BYTES) {
    throw new Error('the message is ' + bytes.length + ' bytes; this relay sends at most ' +
                    MAX_REQUEST_BYTES);
  }
  const outer = readOuterTlv(bytes);
  if (outer.totalLength !== bytes.length) {
    throw new Error('the ' + name + ' declares ' + outer.length + ' bytes of content, so the whole ' +
      'message should be ' + outer.totalLength + ' bytes, but ' + bytes.length + ' were supplied. ' +
      'A message this service cannot account for is not one it will relay.');
  }
  return outer;
}

// The pre-flight for POST /krb5/kdc: an AS-REQ or a TGS-REQ, and nothing else.
function assertKerberosRequest(bytes) {
  if (!bytes || !bytes.length) {
    throw new Error('no message to send');
  }
  const name = KDC_REQUEST_TAGS[bytes[0]];
  if (!name) {
    // Name what WAS there, because the commonest mistakes are sending a reply,
    // sending base64 that was never decoded, and sending an AP-REQ to a KDC.
    const looksBase64 = bytes[0] >= 0x30 && bytes[0] <= 0x7a;
    const isServiceRequest = SERVICE_REQUEST_TAGS[bytes[0]];
    throw new Error('this is not a request a KDC answers: the first byte is 0x' +
      bytes[0].toString(16).padStart(2, '0') + ', and it must be 0x6a (AS-REQ) or 0x6c (TGS-REQ)' +
      (isServiceRequest
        ? '. 0x' + bytes[0].toString(16) + ' is ' + isServiceRequest + ', which goes to a SERVICE ' +
          'rather than to a KDC — use POST /krb5/service for that.'
        : looksBase64
          ? '. It looks like text — was it decoded from base64 before being sent?'
          : '.'));
  }
  assertSizeAndLength(bytes, name);
  return name;
}

// The pre-flight for POST /krb5/service.
//
// This endpoint is a BROADER primitive than the KDC one, and deliberately so: a
// Kerberos service can be on any port at all — 443 for HTTP, 1433 for SQL Server,
// 389 for LDAP — so a port allowlist cannot do the work here that it does for the
// KDC. The payload check is therefore what bounds it, and it is strict:
//
//   * a bare AP-REQ, whose declared length must account for every byte; or
//   * an InitialContextToken whose mechanism OID must be Kerberos v5 EXACTLY, whose
//     token id must be 01 00 (AP-REQ), and whose inner AP-REQ must itself be a
//     well-formed [APPLICATION 14] accounting for the remaining bytes.
//
// Nothing else is that shape. An HTTP request, a Redis command, a TLS ClientHello and
// a random byte string all fail it, which is what makes an unrestricted port
// defensible — the payload constraint is doing the bounding. Even so the port list
// defaults to EMPTY (the endpoint refuses everything until configured), because a
// capability this broad should be switched on deliberately rather than inherited.
function assertServiceRequest(bytes) {
  if (!bytes || !bytes.length) {
    throw new Error('no message to send');
  }
  const name = SERVICE_REQUEST_TAGS[bytes[0]];
  if (!name) {
    const isKdcRequest = KDC_REQUEST_TAGS[bytes[0]];
    throw new Error('this is not something a Kerberos service accepts: the first byte is 0x' +
      bytes[0].toString(16).padStart(2, '0') + ', and it must be 0x60 (a GSS InitialContextToken ' +
      'wrapping an AP-REQ) or 0x6e (a bare AP-REQ)' +
      (isKdcRequest
        ? '. 0x' + bytes[0].toString(16) + ' is ' + isKdcRequest + ', which goes to a KDC — use ' +
          'POST /krb5/kdc for that.'
        : '.'));
  }
  const outer = assertSizeAndLength(bytes, name);
  if (bytes[0] === 0x6e) return name;

  // The GSS-wrapped form. Every field is checked, because "0x60 then anything" would
  // make this endpoint a tunnel.
  const value = bytes.subarray(outer.headerLength, bytes.length);
  if (value.length < KRB5_MECH_OID_DER.length + 2) {
    throw new Error('the GSS token is too short to carry a mechanism OID and a token id');
  }
  if (Buffer.compare(value.subarray(0, KRB5_MECH_OID_DER.length), KRB5_MECH_OID_DER) !== 0) {
    // SPNEGO is the OID somebody will actually send here, so it is named.
    const spnego = Buffer.from([0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]);
    const isSpnego = value.length >= spnego.length &&
      Buffer.compare(value.subarray(0, spnego.length), spnego) === 0;
    throw new Error('the GSS token does not name the Kerberos v5 mechanism' +
      (isSpnego
        ? ' — it names SPNEGO (1.3.6.1.5.5.2), which this build does not implement'
        : ' (found ' + value.subarray(0, Math.min(12, value.length)).toString('hex') + ')') + '.');
  }
  const rest = value.subarray(KRB5_MECH_OID_DER.length);
  if (rest[0] !== 0x01 || rest[1] !== 0x00) {
    throw new Error('the GSS token id is ' + rest.subarray(0, 2).toString('hex') +
      ', not 0100 (AP-REQ). A service is presented with an AP-REQ; 0200 is an AP-REP and 0300 is ' +
      'a KRB-ERROR, both of which are answers rather than requests.');
  }
  const inner = rest.subarray(2);
  if (!inner.length || inner[0] !== 0x6e) {
    throw new Error('the GSS token wraps something that is not an AP-REQ (its first byte is 0x' +
      (inner.length ? inner[0].toString(16) : 'nothing') + ', expected 0x6e).');
  }
  const innerOuter = readOuterTlv(inner);
  if (innerOuter.totalLength !== inner.length) {
    throw new Error('the wrapped AP-REQ declares ' + innerOuter.length + ' bytes of content but ' +
      inner.length + ' bytes follow the token id. A payload this service cannot account for is not ' +
      'one it will relay.');
  }
  return name;
}

// The four-byte big-endian length prefix, computed here rather than taken from
// the caller.
function frameForTcp(bytes) {
  const out = Buffer.alloc(4 + bytes.length);
  out.writeUInt32BE(bytes.length, 0);
  Buffer.from(bytes).copy(out, 4);
  return out;
}

// Read a framed reply out of an accumulating buffer.
//
// Returns { complete: false } while more bytes are needed, or
// { complete: true, message, consumed }. Throws if the declared length is one
// this relay will not honour — which is the point: the prefix is the far end's
// claim about how much memory to set aside.
function readTcpFrame(buffer, maxBytes) {
  if (buffer.length < 4) return { complete: false, need: 4 - buffer.length };
  const declared = buffer.readUInt32BE(0);
  // RFC 4120 reserves the top bit of the length field. A reply that sets it is
  // not a long message; it is something this relay should not be talking to.
  if (declared & 0x80000000) {
    throw new Error('the reply\'s length prefix has its top bit set, which RFC 4120 reserves. ' +
                    'This is not a Kerberos reply.');
  }
  if (declared < MIN_MESSAGE_BYTES) {
    throw new Error('the reply announces ' + declared + ' bytes, which cannot be a Kerberos message');
  }
  if (declared > maxBytes) {
    // Refused BEFORE the bytes are read, not measured afterwards. A host that
    // answers promptly and then streams is inside every timeout while this
    // process fills its heap.
    throw new Error('the reply announces ' + declared + ' bytes, over the ' + maxBytes +
      '-byte limit for this relay. Raise maxContentLength in the api configuration if a KDC ' +
      'legitimately answers with more (a large PAC can make a reply big, but not this big).');
  }
  if (buffer.length < 4 + declared) return { complete: false, need: (4 + declared) - buffer.length };
  return { complete: true, message: buffer.subarray(4, 4 + declared), consumed: 4 + declared };
}

// What a reply is, for logging and for the response this service hands back. A
// reply is a KDC-REP or a KRB-ERROR; anything else means the far end is not a
// KDC, and saying which is more useful than a generic failure.
const REPLY_TAGS = {
  0x6b: 'AS-REP',      // [APPLICATION 11]
  0x6d: 'TGS-REP',     // [APPLICATION 13]
  0x6f: 'AP-REP',      // [APPLICATION 15]
  0x7e: 'KRB-ERROR'    // [APPLICATION 30]
};

function describeReply(bytes) {
  if (!bytes || !bytes.length) return null;
  return REPLY_TAGS[bytes[0]] || ('an unrecognised message (first byte 0x' +
    bytes[0].toString(16).padStart(2, '0') + ')');
}

module.exports = {
  KDC_REQUEST_TAGS: KDC_REQUEST_TAGS,
  SERVICE_REQUEST_TAGS: SERVICE_REQUEST_TAGS,
  assertServiceRequest: assertServiceRequest,
  REPLY_TAGS: REPLY_TAGS,
  MAX_REQUEST_BYTES: MAX_REQUEST_BYTES,
  assertKerberosRequest: assertKerberosRequest,
  readOuterTlv: readOuterTlv,
  frameForTcp: frameForTcp,
  readTcpFrame: readTcpFrame,
  describeReply: describeReply
};
