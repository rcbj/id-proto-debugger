// File: krb5_gss.js
//
// ---------------------------------------------------------------------------
// The GSS-API layer: RFC 4121, and the framing a Windows service actually expects.
//
// A bare AP-REQ is not what a service is given. What arrives is an RFC 2743
// InitialContextToken — a `0x60` wrapper, the Kerberos mechanism OID, a two-byte
// token id, and then the AP-REQ — and inside that AP-REQ's Authenticator sits a
// checksum of **type 0x8003**, which is not a checksum of anything. It is a
// structure carrying channel bindings and the GSS flags.
//
// **That checksum is the single most commonly botched field in Kerberos**, and it
// fails in the least helpful way available: a service answers
// KRB_AP_ERR_INAPP_CKSUM, or simply refuses the context, and nothing anywhere says
// "your flags word is in the wrong byte order". So this file writes it out
// explicitly, and tests/krb5_gss_tokens.js pins every byte of it.
//
// Three things here are the ones that go wrong:
//
//  * **0x8003's fields are LITTLE-endian.** The length, the flags, the delegation
//    option and length — all of them, in a protocol whose every other integer is
//    big-endian. Getting this wrong produces a flags word of 0x02000000 where
//    0x00000002 was meant, i.e. a request for delegation where mutual
//    authentication was intended.
//  * **The Bnd field is sixteen ZERO bytes when there are no channel bindings**,
//    not absent and not omitted. A token without it is malformed; a token with a
//    hash of nothing in it is a different token.
//  * **Per-message tokens are keyed by who is speaking.** An initiator signs with
//    key usage 25 and seals with 24; an acceptor uses 23 and 22. Using the wrong
//    pair produces a token the far end cannot verify, and the error names the
//    checksum rather than the direction.
//
// This layer is deliberately SEPARATE from the AP-REQ itself (krb5_messages.js) so
// that SPNEGO — which is a negotiation wrapper around exactly this token — is a
// wrapper to be added later rather than a rewrite. SPNEGO is not implemented here.
// ---------------------------------------------------------------------------

var prim = require("./krb5_primitives.js");
var asn1 = require("./krb5_asn1.js");
var kcrypto = require("./krb5_crypto.js");
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "krb5_gss",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      // No CONFIG_FILE resolvable here — a node caller rather than a bundle.
      return "info";
    }
  })()
});

var toBytes = prim.toBytes;
var concat = prim.concat;

// 1.2.840.113554.1.2.2 — the Kerberos v5 mechanism. Written as the DER-encoded
// OBJECT IDENTIFIER it appears as on the wire, because that is the form every
// comparison against it uses.
var KRB5_MECH_OID_DER = new Uint8Array([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x12, 0x01, 0x02, 0x02]);
var KRB5_MECH_OID = "1.2.840.113554.1.2.2";

// The two-byte token ids of RFC 4121 section 4.1. Big-endian pairs, unlike the
// contents of the 0x8003 checksum below.
var TOK_ID = {
  AP_REQ: [0x01, 0x00],
  AP_REP: [0x02, 0x00],
  KRB_ERROR: [0x03, 0x00],
  MIC: [0x04, 0x04],
  WRAP: [0x05, 0x04]
};

// RFC 4121 section 4.1.1.1. The values a caller sets in the 0x8003 flags word.
var GSS_FLAG = {
  DELEG: 1,
  MUTUAL: 2,
  REPLAY: 4,
  SEQUENCE: 8,
  CONF: 16,
  INTEG: 32
};

var CHECKSUM_TYPE_GSS = 0x8003;

function le16(n) { return new Uint8Array([n & 0xff, (n >>> 8) & 0xff]); }
function le32(n) {
  return new Uint8Array([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff,
      (n >>> 24) & 0xff]);
}
function readLe32(bytes, at) {
  return ((bytes[at]) | (bytes[at + 1] << 8) | (bytes[at +
      2] << 16) | (bytes[at + 3] << 24)) >>> 0;
}
function be64(n) {
  // Sequence numbers are 64-bit big-endian. JavaScript numbers cover the range
  // any real exchange uses; the top four bytes are written explicitly rather
  // than assumed zero.
  log.debug("Entering be64().");
  var hi = Math.floor(n / 0x100000000) >>> 0;
  var lo = (n >>> 0);
  log.debug("Leaving be64().");
  return new Uint8Array([
    (hi >>> 24) & 255, (hi >>> 16) & 255, (hi >>> 8) & 255, hi & 255,
    (lo >>> 24) & 255, (lo >>> 16) & 255, (lo >>> 8) & 255, lo & 255
  ]);
}
function readBe64(bytes, at) {
  var hi = ((bytes[at] << 24) | (bytes[at + 1] << 16) | (bytes[at +
      2] << 8) | bytes[at + 3]) >>> 0;
  var lo = ((bytes[at + 4] << 24) | (bytes[at + 5] << 16) | (bytes[at +
      6] << 8) | bytes[at + 7]) >>> 0;
  return hi * 0x100000000 + lo;
}

// ---------------------------------------------------------------------------
// The 0x8003 checksum: channel bindings and flags, not a checksum.
//
//   Lgth      4 octets, LITTLE-endian, always 16 (the length of Bnd)
//   Bnd       16 octets — the channel bindings, or SIXTEEN ZERO BYTES when none
//   Flags     4 octets, LITTLE-endian
//   DlgOpt    2 octets, little-endian   ] present together, and only when
//   Dlgth     2 octets, little-endian   ] GSS_C_DELEG_FLAG is set
//   Deleg     Dlgth octets             ] — a KRB-CRED with the forwarded ticket
// ---------------------------------------------------------------------------
function buildGssChecksum(options) {
  log.debug("Entering buildGssChecksum().");
  var opts = options || {};
  var flags = 0;
  (opts.flags || []).forEach(function (f) { flags |= f; });
  // Sixteen bytes, and zeros when there are no bindings. Not absent: a token
  // without Bnd is malformed, and a hash of nothing is a different token.
  var bindings = opts.channelBindings ? toBytes(opts.channelBindings) :
      new Uint8Array(16);
  if (bindings.length !== 16) {
    log.debug("Leaving buildGssChecksum().");
    throw new Error("krb5: GSS channel bindings must be exactly 16 bytes, " +
        "got " + bindings.length);
  }
  var parts = [le32(16), bindings, le32(flags)];
  if (opts.delegation) {
    var cred = toBytes(opts.delegation);
    if (!(flags & GSS_FLAG.DELEG)) {
      log.debug("Leaving buildGssChecksum().");
      throw new Error("krb5: a delegated credential was supplied but " +
          "GSS_C_DELEG_FLAG is not set; " +
        "a service reads the flag, so the credential would be ignored");
    }
    // DlgOpt is 1 for a KRB-CRED, per RFC 4121.
    parts.push(le16(1), le16(cred.length), cred);
  }
  if (opts.extensions) parts.push(toBytes(opts.extensions));
  log.debug("Leaving buildGssChecksum().");
  return concat(parts);
}

function parseGssChecksum(bytes) {
  log.debug("Entering parseGssChecksum().");
  var b = toBytes(bytes);
  if (b.length < 24) {
    log.debug("Leaving parseGssChecksum().");
    throw new Error("krb5: a 0x8003 checksum is at least 24 bytes (4 + 16 + " +
        "4), got " + b.length);
  }
  var declared = readLe32(b, 0);
  if (declared !== 16) {
    // The commonest symptom of a big-endian encoder: 16 written the other way
    // is 0x10000000, i.e. 268435456.
    log.debug("Leaving parseGssChecksum().");
    throw new Error("krb5: the 0x8003 checksum declares a bindings length of " +
        declared +
      " rather than 16" + (declared === 0x10000000
        ? " — 16 written BIG-endian. Every integer in this structure is " +
            "little-endian, unlike the " +
          "rest of Kerberos."
        : "."));
  }
  var flags = readLe32(b, 20);
  var out = {
    bindingsLength: declared,
    channelBindings: b.subarray(4, 20),
    hasChannelBindings: !b.subarray(4,
        20).every(function (v) { return v === 0; }),
    flags: flags,
    flagNames: Object.keys(GSS_FLAG).filter(function (name) { return flags & GSS_FLAG[name]; }),
    delegation: null
  };
  var at = 24;
  if ((flags & GSS_FLAG.DELEG) && b.length >= at + 4) {
    var dlgOpt = b[at] | (b[at + 1] << 8);
    var dlgth = b[at + 2] | (b[at + 3] << 8);
    at += 4;
    if (b.length >= at + dlgth) {
      out.delegation = {
        option: dlgOpt,
        credential: b.subarray(at, at + dlgth)
      };
      at += dlgth;
    }
  }
  if (at < b.length) out.extensions = b.subarray(at);
  log.debug("Leaving parseGssChecksum().");
  return out;
}

// ---------------------------------------------------------------------------
// The InitialContextToken (RFC 2743 section 3.1).
//
// Note the shape: this is NOT a normal DER SEQUENCE. It is `[APPLICATION 0]`
// wrapping a bare OID followed by mechanism-defined bytes — the inner token is not
// an ASN.1 element at all, which is why a general-purpose parser makes a mess of it.
// ---------------------------------------------------------------------------
function encodeInitialContextToken(tokId, innerBytes) {
  var inner = concat([new Uint8Array(tokId), toBytes(innerBytes)]);
  var body = concat([KRB5_MECH_OID_DER, inner]);
  return concat([new Uint8Array([0x60]), asn1.encodeLength(body.length), body]);
}

function decodeInitialContextToken(bytes) {
  log.debug("Entering decodeInitialContextToken(). bytes=" +
      toBytes(bytes).length);
  var b = toBytes(bytes);
  if (!b.length || b[0] !== 0x60) {
    throw new Error("krb5: not a GSS InitialContextToken — it must begin " +
        "with 0x60 (" +
      "[APPLICATION 0]), this begins with 0x" +
      (b.length ? b[0].toString(16) : "nothing") +
      (b.length && b[0] === 0x6e
        ? ". 0x6e is a bare AP-REQ: a Windows service expects it WRAPPED in " +
            "this token, not on its own."
        : "."));
  }
  var outer = asn1.readTlv(b, 0);
  var value = outer.value;
  if (value.length < KRB5_MECH_OID_DER.length) {
    throw new Error("krb5: the GSS token is too short to carry a mechanism " +
        "OID");
  }
  var oid = value.subarray(0, KRB5_MECH_OID_DER.length);
  if (!prim.equalConstantTime(oid, KRB5_MECH_OID_DER)) {
    // Naming what was found is the useful part: the SPNEGO OID here means the
    // caller negotiated rather than using Kerberos directly, which is a
    // different (and not yet implemented) mechanism.
    var spnego = new Uint8Array([0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05,
        0x02]);
    var isSpnego = value.length >= spnego.length &&
      prim.equalConstantTime(value.subarray(0, spnego.length), spnego);
    throw new Error("krb5: this GSS token names " +
      (isSpnego ? "the SPNEGO mechanism (1.3.6.1.5.5.2), which this build " +
          "does not implement — " +
                  "it speaks the Kerberos mechanism directly"
                : "a mechanism this build does not know (" + prim.toHex(oid) +
                    ")") + ".");
  }
  var rest = value.subarray(KRB5_MECH_OID_DER.length);
  if (rest.length < 2) {
    throw new Error("krb5: the GSS token carries no token id");
  }
  var id = [rest[0], rest[1]];
  var name = Object.keys(TOK_ID).filter(function (k) {
    return TOK_ID[k][0] === id[0] && TOK_ID[k][1] === id[1];
  })[0] || null;
  log.debug("Leaving decodeInitialContextToken(). tokId=" + (name ||
      prim.toHex(new Uint8Array(id))));
  return {
    tokId: id,
    tokIdName: name,
    mechOid: KRB5_MECH_OID,
    inner: rest.subarray(2)
  };
}

// ---------------------------------------------------------------------------
// Per-message tokens (RFC 4121 section 4.2).
//
// The key usage depends on WHO IS SPEAKING, which is the part that catches people:
// an initiator signs with 25 and seals with 24, an acceptor with 23 and 22. The
// wrong pair produces a token the far end cannot verify and an error that names the
// checksum rather than the direction.
// ---------------------------------------------------------------------------
function usageFor(role, purpose) {
  log.debug("Entering usageFor().");
  if (role !== "initiator" && role !== "acceptor") {
    log.debug("Leaving usageFor().");
    throw new Error('krb5: the GSS role must be "initiator" or "acceptor", ' +
        'got ' + JSON.stringify(role));
  }
  if (purpose === "sign") {
    log.debug("Leaving usageFor().");
    return role === "initiator" ? kcrypto.KEY_USAGE.GSS_INITIATOR_SIGN :
        kcrypto.KEY_USAGE.GSS_ACCEPTOR_SIGN;
  }
  if (purpose === "seal") {
    log.debug("Leaving usageFor().");
    return role === "initiator" ? kcrypto.KEY_USAGE.GSS_INITIATOR_SEAL :
        kcrypto.KEY_USAGE.GSS_ACCEPTOR_SEAL;
  }
  log.debug("Leaving usageFor().");
  throw new Error('krb5: the GSS purpose must be "sign" or "seal"');
}

// The five-flag byte of a per-message token header: bit 0 says the sender is
// the acceptor, bit 1 that the message is sealed, bit 2 that an acceptor subkey
// was used.
function messageFlags(role, sealed, acceptorSubkey) {
  return (role === "acceptor" ? 0x01 : 0x00) | (sealed ? 0x02 :
      0x00) | (acceptorSubkey ? 0x04 : 0x00);
}

// GSS_GetMIC: integrity without confidentiality.
async function getMic(options) {
  log.debug("Entering getMic().");
  var opts = options || {};
  var profile = kcrypto.etypeById(opts.etype);
  var header = concat([
    new Uint8Array(TOK_ID.MIC),
    new Uint8Array([messageFlags(opts.role, false, opts.acceptorSubkey)]),
    new Uint8Array([0xff, 0xff, 0xff, 0xff,
        0xff]),      // five octets of filler
    be64(opts.sequenceNumber || 0)
  ]);
  // The checksum covers the message AND the header — so the flags and the
  // sequence number are protected rather than merely present.
  var checksum = await profile.checksum(opts.key, usageFor(opts.role, "sign"),
    concat([toBytes(opts.message), header]));
  log.debug("Leaving getMic().");
  return concat([header, checksum]);
}

async function verifyMic(options) {
  log.debug("Entering verifyMic().");
  var opts = options || {};
  var token = toBytes(opts.token);
  if (token.length < 16) {
    throw new Error("krb5: a MIC token is at least 16 bytes, got " +
        token.length);
  }
  if (token[0] !== TOK_ID.MIC[0] || token[1] !== TOK_ID.MIC[1]) {
    throw new Error("krb5: this is not a MIC token (its id is 0x" +
      prim.toHex(token.subarray(0, 2)) + ", expected 0404)");
  }
  var profile = kcrypto.etypeById(opts.etype);
  var header = token.subarray(0, 16);
  var given = token.subarray(16);
  // The sender's role is IN the token, and the verifier must use the sender's
  // usage number rather than its own — the commonest way this fails.
  var senderRole = (header[2] & 0x01) ? "acceptor" : "initiator";
  var expected = await profile.checksum(opts.key, usageFor(senderRole, "sign"),
    concat([toBytes(opts.message), header]));
  var ok = prim.equalConstantTime(given, expected);
  log.debug("Leaving verifyMic(). ok=" + ok);
  return {
    ok: ok,
    senderRole: senderRole,
    sequenceNumber: readBe64(header, 8),
    sealed: !!(header[2] & 0x02),
    acceptorSubkey: !!(header[2] & 0x04)
  };
}

// GSS_Wrap with confidentiality.
//
// The construction is unusual and worth stating: the token's own header is
// APPENDED to the plaintext before encryption, then the ciphertext is rotated
// right by RRC bytes. So the header appears twice — once in clear at the front,
// once encrypted at the back — and a receiver compares them. That is what stops
// the clear header being altered.
async function wrap(options) {
  log.debug("Entering wrap().");
  var opts = options || {};
  var profile = kcrypto.etypeById(opts.etype);
  var ec = opts.extraCount || 0;
  var rrc = opts.rrc === undefined ? 0 : opts.rrc;
  var header = concat([
    new Uint8Array(TOK_ID.WRAP),
    new Uint8Array([messageFlags(opts.role, true, opts.acceptorSubkey)]),
    new Uint8Array([0xff]),
    new Uint8Array([(ec >>> 8) & 255, ec & 255]),
    new Uint8Array([(rrc >>> 8) & 255, rrc & 255]),
    be64(opts.sequenceNumber || 0)
  ]);
  var plaintext = concat([toBytes(opts.message), new Uint8Array(ec), header]);
  var ciphertext = await profile.encrypt(opts.key, usageFor(opts.role, "seal"),
      plaintext);
  var rotated = rotateRight(ciphertext, rrc);
  log.debug("Leaving wrap(). bytes=" + (header.length + rotated.length));
  return concat([header, rotated]);
}

async function unwrap(options) {
  log.debug("Entering unwrap().");
  var opts = options || {};
  var token = toBytes(opts.token);
  if (token.length < 16) {
    throw new Error("krb5: a Wrap token is at least 16 bytes, got " +
        token.length);
  }
  if (token[0] !== TOK_ID.WRAP[0] || token[1] !== TOK_ID.WRAP[1]) {
    throw new Error("krb5: this is not a Wrap token (its id is 0x" +
      prim.toHex(token.subarray(0, 2)) + ", expected 0504)");
  }
  var header = token.subarray(0, 16);
  var flags = header[2];
  if (!(flags & 0x02)) {
    throw new Error("krb5: this Wrap token is not sealed (its flags say " +
        "integrity only), so there " +
      "is nothing to decrypt");
  }
  var ec = (header[4] << 8) | header[5];
  var rrc = (header[6] << 8) | header[7];
  var senderRole = (flags & 0x01) ? "acceptor" : "initiator";
  var profile = kcrypto.etypeById(opts.etype);
  var unrotated = rotateLeft(token.subarray(16), rrc);
  var plaintext = await profile.decrypt(opts.key, usageFor(senderRole, "seal"),
      unrotated);
  if (plaintext.length < 16 + ec) {
    throw new Error("krb5: the unwrapped plaintext is too short to contain " +
        "its own header");
  }
  // The header appears twice, and comparing them is what protects the clear
  // copy.
  var trailing = plaintext.subarray(plaintext.length - 16);
  // RRC and EC in the trailing copy are zero on the wire per RFC 4121; compare
  // the fields that must match rather than the whole sixteen bytes.
  var mismatch = trailing[0] !== header[0] || trailing[1] !== header[1] ||
      trailing[2] !== header[2];
  if (mismatch) {
    throw new Error("krb5: the Wrap token's clear header does not match the " +
        "encrypted copy inside " +
      "it, so the header was altered in transit");
  }
  log.debug("Leaving unwrap().");
  return {
    message: plaintext.subarray(0, plaintext.length - 16 - ec),
    senderRole: senderRole,
    sequenceNumber: readBe64(header, 8),
    extraCount: ec,
    rrc: rrc
  };
}

function rotateRight(bytes, count) {
  log.debug("Entering rotateRight().");
  var b = toBytes(bytes);
  if (!b.length || !count) {
    log.debug("Leaving rotateRight().");
    return b;
  }
  var n = count % b.length;
  if (!n) {
    log.debug("Leaving rotateRight().");
    return b;
  }
  log.debug("Leaving rotateRight().");
  return concat([b.subarray(b.length - n), b.subarray(0, b.length - n)]);
}

function rotateLeft(bytes, count) {
  log.debug("Entering rotateLeft().");
  var b = toBytes(bytes);
  if (!b.length || !count) {
    log.debug("Leaving rotateLeft().");
    return b;
  }
  var n = count % b.length;
  if (!n) {
    log.debug("Leaving rotateLeft().");
    return b;
  }
  log.debug("Leaving rotateLeft().");
  return concat([b.subarray(n), b.subarray(0, n)]);
}

module.exports = {
  KRB5_MECH_OID: KRB5_MECH_OID,
  KRB5_MECH_OID_DER: KRB5_MECH_OID_DER,
  TOK_ID: TOK_ID,
  GSS_FLAG: GSS_FLAG,
  CHECKSUM_TYPE_GSS: CHECKSUM_TYPE_GSS,
  buildGssChecksum: buildGssChecksum,
  parseGssChecksum: parseGssChecksum,
  encodeInitialContextToken: encodeInitialContextToken,
  decodeInitialContextToken: decodeInitialContextToken,
  getMic: getMic,
  verifyMic: verifyMic,
  wrap: wrap,
  unwrap: unwrap,
  usageFor: usageFor,
  rotateRight: rotateRight,
  rotateLeft: rotateLeft
};
