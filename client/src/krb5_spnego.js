// File: krb5_spnego.js
//
// ---------------------------------------------------------------------------
// SPNEGO (RFC 4178): the negotiation wrapper, and nothing else.
//
// krb5_gss.js's header says this module would be "a wrapper to be added later
// rather than a rewrite", and that is exactly what this is: it encodes and
// decodes RFC 4178's two messages and knows nothing about Kerberos beyond one
// OID. Everything inside `mechToken` and `responseToken` is somebody else's
// mechanism — here, the InitialContextToken krb5_gss.js already builds.
//
// WHAT SPNEGO IS FOR, in one sentence, because the shape only makes sense once
// you know: a client and a server that each support several authentication
// mechanisms have to agree on one, over a transport (HTTP, SMB, LDAP) that has
// no idea any of this is happening — so the agreement itself is carried in a
// pseudo-mechanism with its own OID, 1.3.6.1.5.5.2.
//
// ---------------------------------------------------------------------------
// THE FOUR THINGS THAT GO WRONG HERE, and every one of them decodes as
// something else rather than failing.
//
//  * **Only the FIRST token is wrapped in an InitialContextToken.** RFC 2743's
//    `0x60` framing carries the SPNEGO OID and then `[0] NegTokenInit`. Every
//    token after it — including the acceptor's very first reply — is a BARE
//    `[1] NegTokenResp`, i.e. bytes beginning `0xa1`, with no OID anywhere.
//    An implementation that wraps the reply produces something no client will
//    read, and one that expects a wrapper on the reply reports "not a GSS
//    token" for a perfectly good answer. See RFC 4178 section 4.2.
//
//  * **mechListMIC covers the MechTypeList, NOT the `[0] MechTypeList`.**
//    RFC 4178 section 5 is explicit and it is the single most commonly botched
//    field in this protocol: the input to GSS_GetMIC is the DER encoding of the
//    *value* of type MechTypeList — the `0x30` SEQUENCE and its OIDs — and not
//    the `0xa0` context tag the field sits behind inside NegTokenInit. Two
//    bytes, and the MIC verifies against nothing if you include them. That is
//    why `mechTypeListDer()` exists as its own exported function and why the
//    encoder returns it: there must be exactly one answer to "what did we
//    sign", shared by the side that signs and the side that checks.
//
//  * **NegTokenInit2 reuses tag [3] for something else.** [MS-SPNG] extends the
//    initial token with `negHints`, which a Windows *acceptor* sends when it
//    speaks first — and it takes tag [3], pushing mechListMIC out to [4]. So a
//    `[3]` on the wire is a MIC in RFC 4178 and a hint structure in Microsoft's
//    version, and a decoder that assumes one reads the other as garbage. This
//    one disambiguates by the tag inside: negHints is a SEQUENCE (0x30), a MIC
//    is an OCTET STRING (0x04). Guessing from the direction of travel would be
//    wrong for exactly the interesting cases.
//
//  * **`reqFlags` is a BIT STRING and is deprecated.** RFC 4178 section 4.2.1
//    says senders SHOULD omit it and receivers MUST ignore it; it survives only
//    for RFC 2478 compatibility. It is decoded here — a capture containing one
//    should not be a parse failure — and never sent.
//
// NO DOM, like every module in common/krb5, so tests/krb5_spnego_codec.js can
// pin every byte offset with no browser. The DER coder is krb5_asn1.js's; the
// OID coder is HERE rather than there because Kerberos's own ASN.1 has no
// OBJECT IDENTIFIER in it at all — krb5_asn1.js names the tag and never encodes
// one. Adding an OID coder to that file for one caller would put SPNEGO's
// grammar in the module that exists to hold RFC 4120's.
// ---------------------------------------------------------------------------

var prim = require("./krb5_primitives.js");
var asn1 = require("./krb5_asn1.js");
var gss = require("./krb5_gss.js");
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "krb5_spnego",
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

// The SPNEGO pseudo-mechanism itself. Written as the DER-encoded OBJECT
// IDENTIFIER it appears as on the wire, for the same reason krb5_gss.js writes
// the Kerberos one that way: every comparison against it uses that form.
var SPNEGO_OID = "1.3.6.1.5.5.2";
var SPNEGO_OID_DER = new Uint8Array([0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05,
    0x02]);

// ---------------------------------------------------------------------------
// The mechanisms worth naming.
//
// A debugger's job here is to say what a mechTypes list MEANS, and the list a
// Windows client sends is four OIDs of which two are the same mechanism and one
// is a wrapper around the other three. Naming them is most of the value.
//
// The MS KRB5 OID is the one people trip over: 1.2.840.48018.1.2.2 differs from
// the real Kerberos OID in ONE arc (48018 against 113554) and is Microsoft's
// long-standing typo, kept for compatibility. A client offers both; an acceptor
// that recognises only one of them still interoperates, which is why the
// mistake survived.
// ---------------------------------------------------------------------------
var MECHS = [
  {
    oid: "1.2.840.113554.1.2.2",
    name: "Kerberos v5",
    note: "RFC 4121's Kerberos mechanism — the one this debugger speaks."
  },
  {
    oid: "1.2.840.48018.1.2.2",
    name: "Kerberos v5 (MS OID)",
    note: "Microsoft's mis-typed Kerberos OID (48018 where 113554 was " +
      "meant), kept for compatibility and still offered by every Windows " +
      "client. Same mechanism, different number."
  },
  {
    oid: "1.2.840.113554.1.2.2.3",
    name: "Kerberos v5 user-to-user",
    note: "user-to-user, where the acceptor has no long-term key of its own " +
      "and the ticket is sealed with a session key instead."
  },
  {
    oid: "1.3.6.1.4.1.311.2.2.10",
    name: "NTLMSSP",
    note: "NTLM. Offered by Windows as the fallback when no Kerberos ticket " +
      "can be obtained — a name that cannot be resolved to an SPN, a machine " +
      "off the domain, or an IP address in the URL rather than a host name."
  },
  {
    oid: "1.3.6.1.4.1.311.2.2.30",
    name: "NEGOEX",
    note: "the extended negotiation mechanism ([MS-NEGOEX]), which " +
      "negotiates again inside SPNEGO."
  },
  {
    oid: "1.3.6.1.5.5.2",
    name: "SPNEGO",
    note: "SPNEGO itself. RFC 4178 section 4.1 says a mechTypes list MUST " +
      "NOT contain it: a negotiation that can select itself does not " +
      "terminate."
  }
];

function mechByOid(oid) {
  log.debug("Entering mechByOid().");
  var found = null;
  MECHS.forEach(function (m) {
    if (m.oid === oid) { found = m; }
  });
  log.debug("Leaving mechByOid(). " + (found ? found.name : "unknown"));
  return found;
}

function mechName(oid) {
  log.debug("Entering mechName().");
  var m = mechByOid(oid);
  log.debug("Leaving mechName().");
  return m ? m.name : "unrecognised mechanism";
}

var KRB5_MECH_OID = gss.KRB5_MECH_OID;
var MS_KRB5_MECH_OID = "1.2.840.48018.1.2.2";

// Both spellings of Kerberos count as Kerberos. An acceptor that treats the MS
// OID as an unknown mechanism refuses every Windows client and reports it as a
// mechanism mismatch.
function isKerberosMech(oid) {
  log.debug("Entering isKerberosMech().");
  var yes = oid === KRB5_MECH_OID || oid === MS_KRB5_MECH_OID;
  log.debug("Leaving isKerberosMech(). " + yes);
  return yes;
}

// ---------------------------------------------------------------------------
// negState. The names are the RFC's own; the meanings are what a reader of a
// capture actually needs, because "accept-incomplete" says nothing about whose
// turn it is.
// ---------------------------------------------------------------------------
var NEG_STATE = {
  ACCEPT_COMPLETED: 0,
  ACCEPT_INCOMPLETE: 1,
  REJECT: 2,
  REQUEST_MIC: 3
};

var NEG_STATE_INFO = {
  0: {
    name: "accept-completed",
    meaning: "the context is established and no further token is needed. On " +
      "HTTP this is the state that comes with the 200."
  },
  1: {
    name: "accept-incomplete",
    meaning: "another token is expected from the other side. On HTTP this is " +
      "a second 401 carrying a challenge rather than a refusal."
  },
  2: {
    name: "reject",
    meaning: "the negotiation has failed and no context exists. The reason " +
      "is NOT in this structure — SPNEGO carries no error detail, which is " +
      "why the mechanism's own error token (a KRB-ERROR here) matters."
  },
  3: {
    name: "request-mic",
    meaning: "the acceptor requires the mechListMIC exchange. Legal only in " +
      "the acceptor's FIRST reply (RFC 4178 section 4.2.2)."
  }
};

function negStateInfo(value) {
  log.debug("Entering negStateInfo().");
  var info = NEG_STATE_INFO[value];
  log.debug("Leaving negStateInfo().");
  return info || {
    name: "unrecognised (" + value + ")",
    meaning: "RFC 4178 defines 0 through 3 only."
  };
}

// ---------------------------------------------------------------------------
// OBJECT IDENTIFIER, both ways.
//
// The first two arcs share one byte as 40*a + b, and every arc after that is
// base 128 with the continuation bit set on all but the last octet. The check
// that matters is the one on the LAST octet's continuation bit: an OID whose
// final byte still has 0x80 set is truncated, and a decoder that ignores it
// returns a plausible number that is not the OID that was sent.
// ---------------------------------------------------------------------------
function encodeOidContent(dotted) {
  log.debug("Entering encodeOidContent(). oid=" + dotted);
  var arcs = String(dotted).split(".").map(function (a) { return Number(a); });
  if (arcs.length < 2 || arcs.some(function (a) {
    return !isFinite(a) || a < 0 || Math.floor(a) !== a;
  })) {
    log.debug("Leaving encodeOidContent(). Bad OID.");
    throw new Error("krb5: " + JSON.stringify(dotted) + " is not an object " +
        "identifier — it needs at least two non-negative integer arcs");
  }
  if (arcs[0] > 2 || (arcs[0] < 2 && arcs[1] > 39)) {
    log.debug("Leaving encodeOidContent(). Out of range.");
    throw new Error("krb5: object identifier " + dotted + " cannot be " +
        "encoded — the first arc must be 0, 1 or 2, and under 2 the second " +
        "arc must be below 40");
  }
  var out = [40 * arcs[0] + arcs[1]];
  for (var i = 2; i < arcs.length; i++) {
    var v = arcs[i];
    var chunk = [v & 0x7f];
    v = Math.floor(v / 128);
    while (v > 0) {
      chunk.unshift((v & 0x7f) | 0x80);
      v = Math.floor(v / 128);
    }
    out = out.concat(chunk);
  }
  log.debug("Leaving encodeOidContent(). " + out.length + " byte(s).");
  return new Uint8Array(out);
}

function encodeOid(dotted) {
  log.debug("Entering encodeOid().");
  var content = encodeOidContent(dotted);
  log.debug("Leaving encodeOid().");
  return asn1.tlv(asn1.TAG.OBJECT_IDENTIFIER, content);
}

function decodeOidContent(bytes) {
  log.debug("Entering decodeOidContent().");
  var b = toBytes(bytes);
  if (!b.length) {
    log.debug("Leaving decodeOidContent(). Empty.");
    throw new Error("krb5: a zero-length OBJECT IDENTIFIER");
  }
  if (b[b.length - 1] & 0x80) {
    // The truncation check. Without it this returns a number, and a number that
    // is wrong in a way nothing downstream can notice.
    log.debug("Leaving decodeOidContent(). Truncated.");
    throw new Error("krb5: this OBJECT IDENTIFIER is truncated — its last " +
        "octet still carries the base-128 continuation bit");
  }
  var first = b[0];
  var arcs = [Math.min(2, Math.floor(first / 40))];
  arcs.push(first - 40 * arcs[0]);
  var value = 0;
  for (var i = 1; i < b.length; i++) {
    value = value * 128 + (b[i] & 0x7f);
    if (!(b[i] & 0x80)) {
      arcs.push(value);
      value = 0;
    }
  }
  log.debug("Leaving decodeOidContent(). " + arcs.length + " arc(s).");
  return arcs.join(".");
}

function decodeOid(element) {
  log.debug("Entering decodeOid().");
  asn1.expectTag(element, asn1.TAG.OBJECT_IDENTIFIER, "an OBJECT IDENTIFIER");
  log.debug("Leaving decodeOid().");
  return decodeOidContent(element.value);
}

// ---------------------------------------------------------------------------
// MechTypeList — and the two bytes that decide whether a MIC verifies.
//
// This is the DER of `MechTypeList ::= SEQUENCE OF MechType`: a 0x30 SEQUENCE
// holding one OID per mechanism, in the initiator's order of preference. It is
// what goes inside NegTokenInit's `[0]`, and — WITHOUT that `[0]` — it is
// exactly the input to GSS_GetMIC for mechListMIC.
//
// One function, called by the encoder and by both MIC paths, because "what did
// we sign" must have one answer. RFC 4178 section 5 spells the distinction out
// because implementations kept getting it wrong; a MIC over the tagged form
// fails to verify and names nothing.
// ---------------------------------------------------------------------------
function mechTypeListDer(oids) {
  log.debug("Entering mechTypeListDer(). " + (oids || []).length + " mech(s).");
  if (!oids || !oids.length) {
    log.debug("Leaving mechTypeListDer(). Empty list.");
    throw new Error("krb5: a SPNEGO mechTypes list may not be empty — RFC " +
        "4178 section 4.1 requires at least one mechanism");
  }
  oids.forEach(function (oid) {
    if (oid === SPNEGO_OID) {
      throw new Error("krb5: a mechTypes list must not contain SPNEGO " +
          "itself (1.3.6.1.5.5.2). RFC 4178 section 4.1 — a negotiation that " +
          "can select itself does not terminate.");
    }
  });
  var der = asn1.encSequence(oids.map(encodeOid));
  log.debug("Leaving mechTypeListDer(). " + der.length + " byte(s).");
  return der;
}

// ---------------------------------------------------------------------------
// NegTokenInit — the initiator's first token, and the only one that is wrapped.
//
//   InitialContextToken ::= [APPLICATION 0] IMPLICIT SEQUENCE {
//     thisMech          MechType,               -- 1.3.6.1.5.5.2
//     innerContextToken ANY }                   -- [0] NegTokenInit
//
//   NegTokenInit ::= SEQUENCE {
//     mechTypes    [0] MechTypeList,
//     reqFlags     [1] ContextFlags  OPTIONAL,  -- deprecated, never sent here
//     mechToken    [2] OCTET STRING  OPTIONAL,  -- the "optimistic" token
//     mechListMIC  [3] OCTET STRING  OPTIONAL }
//
// The mechToken is called optimistic because the initiator sends its preferred
// mechanism's first token BEFORE knowing whether the acceptor will choose that
// mechanism. It is what makes SPNEGO cost no extra round trip in the common
// case, and it is why a Kerberos AP-REQ can ride on the very first request.
// ---------------------------------------------------------------------------
function encodeNegTokenInit(options) {
  log.debug("Entering encodeNegTokenInit().");
  var opts = options || {};
  var mechs = opts.mechTypes || [KRB5_MECH_OID];
  var mechList = mechTypeListDer(mechs);
  var inner = asn1.encSequence([
    asn1.encContext(0, mechList),
    // reqFlags [1] is deliberately never written. RFC 4178 section 4.2.1: send
    // SHOULD omit, receivers MUST ignore. What it used to carry lives in the
    // 0x8003 checksum inside the Kerberos AP-REQ instead, which is where a
    // service actually reads the GSS flags from.
    opts.mechToken
      ? asn1.encContext(2, asn1.encOctetString(toBytes(opts.mechToken)))
      : null,
    opts.mechListMic
      ? asn1.encContext(3, asn1.encOctetString(toBytes(opts.mechListMic)))
      : null
  ].filter(function (part) { return part !== null; }));
  var negTokenInit = asn1.encContext(0, inner);
  var body = concat([SPNEGO_OID_DER, negTokenInit]);
  var token = concat([new Uint8Array([0x60]),
      asn1.encodeLength(body.length), body]);
  log.debug("Leaving encodeNegTokenInit(). " + token.length + " byte(s).");
  return {
    token: token,
    // The bytes a caller has to sign to produce mechListMIC, handed back so no
    // caller has to rebuild them and get the `[0]` wrong.
    mechListDer: mechList,
    mechTypes: mechs.slice()
  };
}

// ---------------------------------------------------------------------------
// NegTokenResp — every token after the first, in BOTH directions.
//
//   NegTokenResp ::= SEQUENCE {
//     negState      [0] ENUMERATED { ... }  OPTIONAL,
//     supportedMech [1] MechType            OPTIONAL,
//     responseToken [2] OCTET STRING        OPTIONAL,
//     mechListMIC   [3] OCTET STRING        OPTIONAL }
//
// It is emitted BARE — `0xa1` and then the SEQUENCE, with no
// InitialContextToken and no OID. RFC 4178 section 4.2: only the first token is
// wrapped. This is the
// half implementations get wrong in the direction that produces a token nothing
// will read, so it is written out here rather than left to a caller.
//
// `supportedMech` is legal only in the acceptor's first reply, and an acceptor
// that repeats it on a later one is telling the initiator to renegotiate.
// ---------------------------------------------------------------------------
function encodeNegTokenResp(options) {
  log.debug("Entering encodeNegTokenResp().");
  var opts = options || {};
  var fields = [];
  if (opts.negState !== undefined && opts.negState !== null) {
    // ENUMERATED is tag 0x0a and shares INTEGER's content encoding, which is
    // why it is written with integerContent() rather than encInteger().
    fields.push(asn1.encContext(0,
        asn1.tlv(0x0a, asn1.integerContent(opts.negState))));
  }
  if (opts.supportedMech) {
    fields.push(asn1.encContext(1, encodeOid(opts.supportedMech)));
  }
  if (opts.responseToken) {
    fields.push(asn1.encContext(2,
        asn1.encOctetString(toBytes(opts.responseToken))));
  }
  if (opts.mechListMic) {
    fields.push(asn1.encContext(3,
        asn1.encOctetString(toBytes(opts.mechListMic))));
  }
  var token = asn1.encContext(1, asn1.encSequence(fields));
  log.debug("Leaving encodeNegTokenResp(). " + token.length + " byte(s).");
  return token;
}

// ---------------------------------------------------------------------------
// Reading whatever arrived.
//
// A `Negotiate` header's payload is one of four things, and telling them apart
// is most of what a debugger has to do here:
//
//   0x60 … SPNEGO OID  → an InitialContextToken carrying NegTokenInit
//   0x60 … krb5 OID    → RAW KERBEROS, not SPNEGO at all. Legal on HTTP and
//                        sent by some clients; a server that only reads SPNEGO
//                        refuses it and blames the ticket.
//   0xa1               → a bare NegTokenResp
//   anything else      → not a negotiation token
//
// The raw-Kerberos case is reported rather than refused, because "this is not
// SPNEGO, it is a bare Kerberos token" is the answer somebody needs.
// ---------------------------------------------------------------------------
function decodeNegotiationToken(bytes) {
  log.debug("Entering decodeNegotiationToken().");
  var b = toBytes(bytes);
  if (!b.length) {
    log.debug("Leaving decodeNegotiationToken(). Empty.");
    throw new Error("krb5: an empty SPNEGO token");
  }
  if (b[0] === 0xa1) {
    var respElement = asn1.readTlv(b, 0);
    log.debug("Leaving decodeNegotiationToken(). NegTokenResp.");
    return decodeNegTokenRespBody(respElement.value, b);
  }
  if (b[0] !== 0x60) {
    log.debug("Leaving decodeNegotiationToken(). Not a token.");
    throw new Error("krb5: this is not a SPNEGO token. It begins with 0x" +
        b[0].toString(16) + "; a negotiation token begins with 0x60 (the " +
        "initiator's first token) or 0xa1 (every token after it)" +
        (b[0] === 0x6e ? ". 0x6e is a bare AP-REQ, which is the Kerberos " +
            "message that belongs INSIDE the mechToken." : "."));
  }
  var outer = asn1.readTlv(b, 0);
  var value = outer.value;
  if (value.length < SPNEGO_OID_DER.length ||
      !prim.equalConstantTime(value.subarray(0, SPNEGO_OID_DER.length),
          SPNEGO_OID_DER)) {
    // Not SPNEGO. Say what it IS, because a bare Kerberos token here is a
    // legitimate client doing something different rather than a broken one.
    var isKrb5 = value.length >= gss.KRB5_MECH_OID_DER.length &&
        prim.equalConstantTime(
            value.subarray(0, gss.KRB5_MECH_OID_DER.length),
            gss.KRB5_MECH_OID_DER);
    if (isKrb5) {
      log.debug("Leaving decodeNegotiationToken(). Raw Kerberos.");
      return {
        kind: "RawKerberos",
        mechOid: KRB5_MECH_OID,
        mechName: "Kerberos v5",
        raw: b,
        // Whether this is a finding or the normal thing DEPENDS ON WHERE IT
        // WAS FOUND, and this module cannot know that — it is handed bytes. So
        // the note gives both readings rather than one: inside a mechToken or
        // a responseToken a bare Kerberos token is exactly right (the
        // negotiation is one layer out), and at the top of an Authorization
        // header it is a client that chose not to negotiate at all.
        note: "An RFC 2743 InitialContextToken naming the Kerberos mechanism " +
          "directly, with no negotiation around it. Inside a SPNEGO " +
          "mechToken or responseToken that is exactly what belongs there — " +
          "the negotiation wrapper is one layer further out. On its own, as " +
          "the whole of an Authorization header, it is a client speaking " +
          "Kerberos rather than negotiating: legal, and what some clients " +
          "send, but a server expecting SPNEGO will refuse it without saying " +
          "why."
      };
    }
    var oidText;
    try {
      oidText = decodeOid(asn1.readTlv(value, 0));
    } catch (e) {
      // Unreadable is worth reporting as the hex it is: the point of naming
      // the mechanism is to identify a client, and a broken OID identifies one
      // just as well as a valid one.
      oidText = "unreadable (" + prim.toHex(value.subarray(0, 16)) + "…)";
    }
    log.debug("Leaving decodeNegotiationToken(). Other mechanism.");
    throw new Error("krb5: this GSS token names " + oidText + " (" +
        mechName(oidText) + "), not SPNEGO (" + SPNEGO_OID + ").");
  }
  var innerTlv = asn1.readTlv(value, SPNEGO_OID_DER.length);
  if (innerTlv.tag !== 0xa0) {
    log.debug("Leaving decodeNegotiationToken(). Wrong inner tag.");
    throw new Error("krb5: a SPNEGO InitialContextToken must carry [0] " +
        "NegTokenInit, and this carries tag 0x" + innerTlv.tag.toString(16) +
        (innerTlv.tag === 0xa1 ? " — a NegTokenResp, which is never wrapped " +
            "in an InitialContextToken (RFC 4178 section 4.2)." : "."));
  }
  var initSeq = asn1.readTlv(innerTlv.value, 0);
  asn1.expectTag(initSeq, asn1.TAG.SEQUENCE, "the NegTokenInit SEQUENCE");
  log.debug("Leaving decodeNegotiationToken(). NegTokenInit.");
  return decodeNegTokenInitBody(initSeq.value, b);
}

function decodeNegTokenInitBody(body, raw) {
  log.debug("Entering decodeNegTokenInitBody().");
  var out = {
    kind: "NegTokenInit",
    mechTypes: [],
    mechTypeNames: [],
    reqFlags: null,
    mechToken: null,
    mechListMic: null,
    negHints: null,
    // The exact bytes a mechListMIC is computed over, sliced out of what
    // arrived rather than re-encoded. Re-encoding would produce a plausible
    // list that verifies against nothing if the sender used a different (still
    // legal) encoding of anything in it.
    mechListDer: null,
    problems: [],
    raw: raw
  };
  var children = asn1.readChildren(body, 1);
  children.forEach(function (field) {
    if (field.tag === 0xa0) {
      var list = asn1.readTlv(field.value, 0);
      asn1.expectTag(list, asn1.TAG.SEQUENCE, "the MechTypeList");
      out.mechListDer = list.raw;
      asn1.readChildren(list.value, 2).forEach(function (oidElement) {
        var oid = decodeOid(oidElement);
        out.mechTypes.push(oid);
        out.mechTypeNames.push(mechName(oid));
        if (oid === SPNEGO_OID) {
          out.problems.push("The mechTypes list contains SPNEGO itself " +
              "(1.3.6.1.5.5.2), which RFC 4178 section 4.1 forbids: a " +
              "negotiation that can select itself does not terminate.");
        }
      });
      return;
    }
    if (field.tag === 0xa1) {
      out.reqFlags = asn1.readTlv(field.value, 0).value;
      out.problems.push("reqFlags is present. RFC 4178 section 4.2.1 " +
          "deprecates it — senders SHOULD omit it and receivers MUST ignore " +
          "it. The flags a service actually reads are in the 0x8003 checksum " +
          "inside the Kerberos AP-REQ.");
      return;
    }
    if (field.tag === 0xa2) {
      out.mechToken = asn1.decOctetString(asn1.readTlv(field.value, 0));
      return;
    }
    if (field.tag === 0xa3) {
      // [3] is mechListMIC in RFC 4178 and negHints in [MS-SPNG]'s
      // NegTokenInit2. Disambiguated by what is inside rather than by who is
      // speaking: a SEQUENCE is negHints, an OCTET STRING is the MIC.
      var inner = asn1.readTlv(field.value, 0);
      if (inner.tag === asn1.TAG.SEQUENCE) {
        out.negHints = decodeNegHints(inner.value);
        out.kind = "NegTokenInit2";
        return;
      }
      out.mechListMic = asn1.decOctetString(inner);
      return;
    }
    if (field.tag === 0xa4) {
      // NegTokenInit2's mechListMIC, displaced by negHints.
      out.mechListMic = asn1.decOctetString(asn1.readTlv(field.value, 0));
      out.kind = "NegTokenInit2";
      return;
    }
    out.problems.push("An unrecognised field with tag 0x" +
        field.tag.toString(16) + " — RFC 4178's NegTokenInit defines [0] " +
        "through [3], and [MS-SPNG]'s NegTokenInit2 adds [4].");
  });
  if (!out.mechTypes.length) {
    out.problems.push("There is no mechTypes list. It is the one mandatory " +
        "field of a NegTokenInit.");
  }
  log.debug("Leaving decodeNegTokenInitBody(). " + out.mechTypes.length +
      " mech(s).");
  return out;
}

// [MS-SPNG]'s hint structure. hintName is the literal string
// "not_defined_in_RFC4178@please_ignore" on every Windows server ever shipped,
// which is worth showing precisely because it looks like a bug and is not.
function decodeNegHints(body) {
  log.debug("Entering decodeNegHints().");
  var hints = { hintName: null, hintAddress: null };
  asn1.readChildren(body, 3).forEach(function (field) {
    if (field.tag === 0xa0) {
      hints.hintName = asn1.decGeneralString(asn1.readTlv(field.value, 0));
      return;
    }
    if (field.tag === 0xa1) {
      hints.hintAddress = asn1.decOctetString(asn1.readTlv(field.value, 0));
    }
  });
  log.debug("Leaving decodeNegHints().");
  return hints;
}

function decodeNegTokenRespBody(body, raw) {
  log.debug("Entering decodeNegTokenRespBody().");
  var seq = asn1.readTlv(body, 0);
  asn1.expectTag(seq, asn1.TAG.SEQUENCE, "the NegTokenResp SEQUENCE");
  var out = {
    kind: "NegTokenResp",
    negState: null,
    negStateName: null,
    negStateMeaning: null,
    supportedMech: null,
    supportedMechName: null,
    responseToken: null,
    mechListMic: null,
    problems: [],
    raw: raw
  };
  asn1.readChildren(seq.value, 1).forEach(function (field) {
    if (field.tag === 0xa0) {
      var enumerated = asn1.readTlv(field.value, 0);
      if (enumerated.tag !== 0x0a && enumerated.tag !== asn1.TAG.INTEGER) {
        out.problems.push("negState is tag 0x" +
            enumerated.tag.toString(16) + " rather than ENUMERATED (0x0a).");
      }
      // decInteger() insists on INTEGER; ENUMERATED shares its content rules,
      // so the value is read through a synthesised INTEGER view rather than by
      // a second implementation of two's complement.
      out.negState = asn1.decInteger({
        tag: asn1.TAG.INTEGER,
        value: enumerated.value
      });
      var info = negStateInfo(out.negState);
      out.negStateName = info.name;
      out.negStateMeaning = info.meaning;
      return;
    }
    if (field.tag === 0xa1) {
      out.supportedMech = decodeOid(asn1.readTlv(field.value, 0));
      out.supportedMechName = mechName(out.supportedMech);
      return;
    }
    if (field.tag === 0xa2) {
      out.responseToken = asn1.decOctetString(asn1.readTlv(field.value, 0));
      return;
    }
    if (field.tag === 0xa3) {
      out.mechListMic = asn1.decOctetString(asn1.readTlv(field.value, 0));
      return;
    }
    out.problems.push("An unrecognised field with tag 0x" +
        field.tag.toString(16) + " — RFC 4178's NegTokenResp defines [0] " +
        "through [3].");
  });
  if (out.negState === NEG_STATE.REJECT && !out.responseToken) {
    out.problems.push("The negotiation was rejected and no mechanism token " +
        "came with it, so nothing here says why. SPNEGO carries no error " +
        "detail of its own — when a server can say more, it says it in the " +
        "mechanism's own error token (a KRB-ERROR).");
  }
  log.debug("Leaving decodeNegTokenRespBody(). negState=" + out.negState);
  return out;
}

// ---------------------------------------------------------------------------
// The mechListMIC, both ways.
//
// It is an ordinary RFC 4121 MIC token over the MechTypeList, and the two
// details that decide whether it verifies are the ones a caller cannot guess:
//
//   * the message is `mechTypeListDer(...)` — the SEQUENCE, not the `[0]`
//     wrapper (RFC 4178 section 5), and
//   * the key is the ESTABLISHED CONTEXT's key, which for a Kerberos AP-REQ
//     carrying a subkey is the subkey, not the ticket's session key. The
//     sequence number is 0: the MIC is the first per-message token of the
//     context, sent before anything has been exchanged over it.
//
// These are wrappers over krb5_gss.js rather than a second implementation, so
// there is one MIC in this codebase and the SPNEGO one cannot drift from the
// per-message one the AP page shows.
// ---------------------------------------------------------------------------
async function computeMechListMic(options) {
  log.debug("Entering computeMechListMic().");
  var opts = options || {};
  var mic = await gss.getMic({
    key: opts.key,
    etype: opts.etype,
    role: opts.role || "initiator",
    acceptorSubkey: !!opts.acceptorSubkey,
    message: opts.mechListDer,
    sequenceNumber: opts.sequenceNumber || 0
  });
  log.debug("Leaving computeMechListMic(). " + mic.length + " byte(s).");
  return mic;
}

async function verifyMechListMic(options) {
  log.debug("Entering verifyMechListMic().");
  var opts = options || {};
  var verdict = await gss.verifyMic({
    key: opts.key,
    etype: opts.etype,
    token: opts.mic,
    message: opts.mechListDer
  });
  log.debug("Leaving verifyMechListMic(). ok=" + verdict.ok);
  return verdict;
}

// ---------------------------------------------------------------------------
// Is a MIC exchange REQUIRED for this negotiation?
//
// RFC 4178 section 5's rule reads as an optimisation and is a downgrade
// defence: the MIC may be skipped only when the mechanism that was selected is
// the one the initiator listed FIRST. If an acceptor picks anything else, an
// attacker editing the mechTypes list on the wire is indistinguishable from an
// acceptor with different preferences — unless the list itself is integrity
// protected, which is what the MIC does.
//
// Returned as a reason rather than a boolean because "optional" and "mandatory"
// are both answers a reader needs explained.
// ---------------------------------------------------------------------------
function micRequirement(mechTypes, selectedMech) {
  log.debug("Entering micRequirement().");
  var list = mechTypes || [];
  if (!selectedMech) {
    log.debug("Leaving micRequirement(). No mechanism selected.");
    return {
      required: true,
      reason: "No mechanism has been selected, so nothing can be assumed " +
        "about the negotiation."
    };
  }
  if (list.length && list[0] === selectedMech) {
    log.debug("Leaving micRequirement(). Optional.");
    return {
      required: false,
      reason: "The selected mechanism (" + mechName(selectedMech) + ") is " +
        "the first one the initiator listed, so RFC 4178 section 5 makes the " +
        "mechListMIC exchange OPTIONAL: there was no downgrade to detect."
    };
  }
  log.debug("Leaving micRequirement(). Required.");
  return {
    required: true,
    reason: "The selected mechanism (" + mechName(selectedMech) + ") is not " +
      "the initiator's first preference (" +
      (list.length ? mechName(list[0]) : "none listed") + "), so RFC 4178 " +
      "section 5 makes the mechListMIC exchange MANDATORY. Without it, an " +
      "attacker who removed the preferred mechanism from the list on the " +
      "wire would be indistinguishable from an acceptor that does not " +
      "support it."
  };
}

module.exports = {
  SPNEGO_OID: SPNEGO_OID,
  SPNEGO_OID_DER: SPNEGO_OID_DER,
  KRB5_MECH_OID: KRB5_MECH_OID,
  MS_KRB5_MECH_OID: MS_KRB5_MECH_OID,
  MECHS: MECHS,
  NEG_STATE: NEG_STATE,
  NEG_STATE_INFO: NEG_STATE_INFO,
  negStateInfo: negStateInfo,
  mechByOid: mechByOid,
  mechName: mechName,
  isKerberosMech: isKerberosMech,
  encodeOid: encodeOid,
  encodeOidContent: encodeOidContent,
  decodeOid: decodeOid,
  decodeOidContent: decodeOidContent,
  mechTypeListDer: mechTypeListDer,
  encodeNegTokenInit: encodeNegTokenInit,
  encodeNegTokenResp: encodeNegTokenResp,
  decodeNegotiationToken: decodeNegotiationToken,
  computeMechListMic: computeMechListMic,
  verifyMechListMic: verifyMechListMic,
  micRequirement: micRequirement
};
