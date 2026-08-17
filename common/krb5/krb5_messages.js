// File: krb5_messages.js
//
// ---------------------------------------------------------------------------
// The Kerberos v5 messages (RFC 4120 section 5), plus the pre-authentication
// and MS-SFU structures the workflow needs.
//
// Every reader returns a plain object with the field names the RFC uses —
// `kdc-options` becomes `kdcOptions`, `enc-part` becomes `encPart` — and keeps
// the raw bytes of anything encrypted so the caller can decrypt it later with a
// key it may not have yet. Every writer takes the same shape back. That
// symmetry is what lets the decoder page re-encode what it read and compare, and
// it is what `tests/krb5_codec.js` uses as its round-trip oracle.
//
// FIVE COMPATIBILITY POINTS, each of which is a thing that only shows up against
// a real KDC:
//
//  * **An AS-REP's enc-part may be tagged EncTGSRepPart.** RFC 4120 section
//    5.4.2 records that implementations exist which encode it as [APPLICATION
//    26] instead of [APPLICATION 25], and requires a client to accept either.
//    An implementation that insists on 25 works against its own mock and fails
//    in the field. `readEncKdcRepPart` therefore accepts both and reports which
//    arrived.
//  * **PA-DATA's fields are tagged [1] and [2], not [0] and [1].** A gratuitous
//    irregularity in the grammar, and one that produces padata a KDC silently
//    ignores — so the AS-REQ looks like it had no pre-authentication at all and
//    the KDC asks for it again.
//  * **The realm is case-sensitive and conventionally upper case.** No layer
//    here folds it, because folding it would hide the commonest configuration
//    error there is.
//  * **A principal's name-type matters.** `krbtgt/REALM` is NT-SRV-INST (2),
//    `host/fqdn` is NT-SRV-HST (3), a user is NT-PRINCIPAL (1). AD is not
//    uniformly strict about this, which is worse than being strict: it works
//    until it does not.
//  * **A Ticket is opaque to its holder.** It is re-encoded byte-for-byte when
//    relayed (into an AP-REQ, or as an additional-ticket in S4U2Proxy), because
//    it is encrypted under a key the client does not have and its DER is covered
//    by a checksum. Every reader here keeps `raw` for exactly that.
// ---------------------------------------------------------------------------

var prim = require("./krb5_primitives.js");
var asn1 = require("./krb5_asn1.js");
var kcrypto = require("./krb5_crypto.js");
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "krb5_messages",
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

// ---------------------------------------------------------------------------
// Constants, named because a bare number in a message builder is unreviewable.
// ---------------------------------------------------------------------------

var PVNO = 5;

var MSG_TYPE = {
  AS_REQ: 10,
  AS_REP: 11,
  TGS_REQ: 12,
  TGS_REP: 13,
  AP_REQ: 14,
  AP_REP: 15,
  SAFE: 20,
  PRIV: 21,
  CRED: 22,
  ERROR: 30
};

var APPLICATION = {
  TICKET: 1,
  AUTHENTICATOR: 2,
  ENC_TICKET_PART: 3,
  AS_REQ: 10,
  AS_REP: 11,
  TGS_REQ: 12,
  TGS_REP: 13,
  AP_REQ: 14,
  AP_REP: 15,
  KRB_CRED: 22,
  ENC_AS_REP_PART: 25,
  ENC_TGS_REP_PART: 26,
  ENC_AP_REP_PART: 27,
  ENC_KRB_PRIV_PART: 28,
  ENC_KRB_CRED_PART: 29,
  KRB_ERROR: 30
};

var NAME_TYPE = {
  UNKNOWN: 0,
  PRINCIPAL: 1,        // a user
  SRV_INST: 2,         // krbtgt/REALM
  SRV_HST: 3,          // host/fqdn — the shape most SPNs take
  SRV_XHST: 4,
  UID: 5,
  X500_PRINCIPAL: 6,
  SMTP_NAME: 7,
  ENTERPRISE: 10       // a UPN; what AD canonicalization is for
};

var PA_TYPE = {
  TGS_REQ: 1,
  ENC_TIMESTAMP: 2,
  PW_SALT: 3,
  ETYPE_INFO: 11,
  ETYPE_INFO2: 19,
  PAC_REQUEST: 128,          // MS-KILE
  FOR_USER: 129,             // MS-SFU, S4U2Self
  FX_COOKIE: 133,            // RFC 6113 FAST
  FX_FAST: 136,
  FX_ERROR: 137,
  ENCRYPTED_CHALLENGE: 138,
  S4U_X509_USER: 130,
  PAC_OPTIONS: 167           // MS-SFU, resource-based constrained delegation
};

var PA_TYPE_NAMES = (function () {
  var out = {};
  Object.keys(PA_TYPE).forEach(function (k) { out[PA_TYPE[k]] = k; });
  return out;
})();

// KDCOptions, RFC 4120 section 5.4.1. Bit 0 is the most significant bit of the
// first octet — see krb5_asn1.js's note on flag order.
var KDC_OPTION = {
  FORWARDABLE: 1,
  FORWARDED: 2,
  PROXIABLE: 3,
  PROXY: 4,
  ALLOW_POSTDATE: 5,
  POSTDATED: 6,
  RENEWABLE: 8,
  OPT_HARDWARE_AUTH: 11,
  CNAME_IN_ADDL_TKT: 14,  // MS-SFU calls this constrained-delegation
  CANONICALIZE: 15,
  REQUEST_ANONYMOUS: 16,
  DISABLE_TRANSITED_CHECK: 26,
  RENEWABLE_OK: 27,
  ENC_TKT_IN_SKEY: 28,
  RENEW: 30,
  VALIDATE: 31
};

var TICKET_FLAG = {
  FORWARDABLE: 1,
  FORWARDED: 2,
  PROXIABLE: 3,
  PROXY: 4,
  MAY_POSTDATE: 5,
  POSTDATED: 6,
  INVALID: 7,
  RENEWABLE: 8,
  INITIAL: 9,
  PRE_AUTHENT: 10,
  HW_AUTHENT: 11,
  TRANSITED_POLICY_CHECKED: 12,
  OK_AS_DELEGATE: 13,
  ENC_PA_REP: 15,
  ANONYMOUS: 16
};

var AP_OPTION = { USE_SESSION_KEY: 1, MUTUAL_REQUIRED: 2 };

// The error catalogue. A debugger's whole value at this point is turning a
// number into the sentence that explains it, so the descriptions say what the
// condition MEANS rather than restating the name.
var ERROR_CODE = {
  0: ["KDC_ERR_NONE", "No error"],
  1: ["KDC_ERR_NAME_EXP", "The client's entry has expired"],
  2: ["KDC_ERR_SERVICE_EXP", "The server's entry has expired"],
  3: ["KDC_ERR_BAD_PVNO", "The KDC does not speak this protocol version"],
  6: ["KDC_ERR_C_PRINCIPAL_UNKNOWN", "No such client principal in this realm " +
      "— check the spelling AND the realm, which is case-sensitive"],
  7: ["KDC_ERR_S_PRINCIPAL_UNKNOWN", "No such service principal — an SPN " +
      "that is not registered, or registered on a different account"],
  8: ["KDC_ERR_PRINCIPAL_NOT_UNIQUE", "More than one entry matches this " +
      "principal (a duplicate SPN)"],
  9: ["KDC_ERR_NULL_KEY", "The principal has no key — often an account that " +
      "has never had a password set"],
  10: ["KDC_ERR_CANNOT_POSTDATE", "A postdated ticket was requested and is " +
      "not allowed"],
  11: ["KDC_ERR_NEVER_VALID", "The requested validity window is empty or " +
      "inverted"],
  12: ["KDC_ERR_POLICY", "Refused by policy — logon hours, workstation " +
      "restrictions, or a disabled account"],
  13: ["KDC_ERR_BADOPTION", "An option in the request cannot be honoured for " +
      "this principal (delegation is a common one)"],
  14: ["KDC_ERR_ETYPE_NOSUPP", "The KDC supports none of the encryption " +
      "types offered. In 2026 this is usually RC4 being disabled, or an " +
      "account whose msDS-SupportedEncryptionTypes excludes AES"],
  15: ["KDC_ERR_SUMTYPE_NOSUPP", "The KDC supports none of the checksum " +
      "types offered"],
  16: ["KDC_ERR_PADATA_TYPE_NOSUPP", "The pre-authentication type is not " +
      "supported — also what AD answers when PKINIT is attempted without a " +
      "certificate it trusts"],
  17: ["KDC_ERR_TRTYPE_NOSUPP", "The transited encoding type is not supported"],
  18: ["KDC_ERR_CLIENT_REVOKED", "The client's credentials are revoked — a " +
      "disabled or locked-out account"],
  19: ["KDC_ERR_SERVICE_REVOKED", "The service's credentials are revoked"],
  20: ["KDC_ERR_TGT_REVOKED", "The TGT has been revoked"],
  21: ["KDC_ERR_CLIENT_NOTYET", "The client is not yet valid"],
  22: ["KDC_ERR_SERVICE_NOTYET", "The server is not yet valid"],
  23: ["KDC_ERR_KEY_EXPIRED", "The password has expired and must be changed"],
  24: ["KDC_ERR_PREAUTH_FAILED", "Pre-authentication failed — the classic " +
      "wrong password, but ALSO what a wrong salt or a clock outside the " +
      "skew produces"],
  25: ["KDC_ERR_PREAUTH_REQUIRED", "Pre-authentication is required. Not a " +
      "failure: the accompanying PA-ETYPE-INFO2 carries the salt and " +
      "iteration count needed to build the real request"],
  26: ["KDC_ERR_SERVER_NOMATCH", "The server and ticket do not match"],
  27: ["KDC_ERR_MUST_USE_USER2USER", "The service requires user-to-user " +
      "authentication"],
  28: ["KDC_ERR_PATH_NOT_ACCEPTED", "The KDC will not accept the transited " +
      "path"],
  29: ["KDC_ERR_SVC_UNAVAILABLE", "The service is unavailable"],
  31: ["KRB_AP_ERR_BAD_INTEGRITY", "Decryption integrity check failed. " +
      "Indistinguishable at this layer from a wrong password, a wrong key " +
      "usage number, a wrong salt or a wrong encoding"],
  32: ["KRB_AP_ERR_TKT_EXPIRED", "The ticket has expired"],
  33: ["KRB_AP_ERR_TKT_NYV", "The ticket is not yet valid"],
  34: ["KRB_AP_ERR_REPEAT", "The request is a replay — the service's replay " +
      "cache has seen this authenticator"],
  35: ["KRB_AP_ERR_NOT_US", "The ticket is not for this service"],
  36: ["KRB_AP_ERR_BADMATCH", "The ticket and the authenticator do not match"],
  37: ["KRB_AP_ERR_SKEW", "The clock skew is too great. AD's default " +
      "tolerance is five minutes; the KDC's own time is in this message's " +
      "stime, so the skew can be measured rather than guessed"],
  38: ["KRB_AP_ERR_BADADDR", "The request is from an address the ticket does " +
      "not permit"],
  39: ["KRB_AP_ERR_BADVERSION", "The protocol version does not match"],
  40: ["KRB_AP_ERR_MSG_TYPE", "An unexpected message type"],
  41: ["KRB_AP_ERR_MODIFIED", "The message was modified in transit"],
  42: ["KRB_AP_ERR_BADORDER", "The message is out of order"],
  44: ["KRB_AP_ERR_BADKEYVER", "The ticket was encrypted with a different " +
      "key version than the service holds — a keytab that is out of date " +
      "with the account's password"],
  45: ["KRB_AP_ERR_NOKEY", "The service has no key of the required type"],
  46: ["KRB_AP_ERR_MUT_FAIL", "Mutual authentication failed"],
  47: ["KRB_AP_ERR_BADDIRECTION", "The message is in the wrong direction"],
  48: ["KRB_AP_ERR_METHOD", "An alternative authentication method is required"],
  49: ["KRB_AP_ERR_BADSEQ", "An incorrect sequence number"],
  50: ["KRB_AP_ERR_INAPP_CKSUM", "The checksum type is inappropriate — this " +
      "is what a wrong 0x8003 GSS checksum looks like"],
  51: ["KRB_AP_PATH_NOT_ACCEPTED", "The path is not accepted"],
  52: ["KRB_ERR_RESPONSE_TOO_BIG", "The reply will not fit in a UDP " +
      "datagram; retry over TCP. Expected rather than exceptional against " +
      "AD, whose PAC makes most replies large"],
  60: ["KRB_ERR_GENERIC", "A generic error — read e-text, which is where the " +
      "KDC says what it actually objected to"],
  61: ["KRB_ERR_FIELD_TOOLONG", "A field is too long for this implementation"],
  62: ["KDC_ERROR_CLIENT_NOT_TRUSTED", "The client certificate is not " +
      "trusted (PKINIT)"],
  63: ["KDC_ERROR_KDC_NOT_TRUSTED", "The KDC certificate is not trusted " +
      "(PKINIT)"],
  64: ["KDC_ERROR_INVALID_SIG", "An invalid signature (PKINIT)"],
  68: ["KDC_ERR_WRONG_REALM", "Wrong realm — with a referral this is " +
      "informational, and the correct realm is in this message"],
  69: ["KRB_AP_ERR_USER_TO_USER_REQUIRED", "User-to-user authentication is " +
      "required"],
  71: ["KDC_ERR_PATH_NOT_ACCEPTED", "The KDC will not accept the transited " +
      "path"],
  76: ["KDC_ERR_PREAUTH_EXPIRED", "The pre-authentication data has expired"],
  93: ["KDC_ERR_MORE_PREAUTH_DATA_REQUIRED", "More pre-authentication is " +
      "required (FAST)"]
};

function describeError(code) {
  var e = ERROR_CODE[code];
  return e ? { code: code, name: e[0], meaning: e[1] }
           : {
             code: code,
             name: "UNKNOWN_ERROR_" + code,
             meaning: "Not a code this codec knows"
           };
}

// ---------------------------------------------------------------------------
// Small shared structures.
// ---------------------------------------------------------------------------

// PrincipalName ::= SEQUENCE { name-type [0] Int32, name-string [1] SEQUENCE OF
// KerberosString }
function encPrincipalName(principal) {
  log.debug("Entering encPrincipalName().");
  var components = Array.isArray(principal.name) ? principal.name :
      [principal.name];
  log.debug("Leaving encPrincipalName().");
  return asn1.encTaggedSequence([
    {
      tag: 0,
      value: asn1.encInteger(principal.type === undefined ?
          NAME_TYPE.PRINCIPAL : principal.type)
    },
    { tag: 1, value: asn1.encSequenceOf(components.map(asn1.encGeneralString)) }
  ]);
}

function readPrincipalName(t) {
  var f = asn1.readTaggedSequence(t.value);
  return {
    type: asn1.decInteger(f[0]),
    name: asn1.decSequenceOf(f[1]).map(asn1.decGeneralString)
  };
}

// "alice", "krbtgt/EXAMPLE.COM", "HTTP/web.example.com" — the display form, and
// the form a user types.
function principalToString(principal, realm) {
  var s = (principal.name || []).join("/");
  return realm ? s + "@" + realm : s;
}

function parsePrincipal(text, defaultType) {
  log.debug("Entering parsePrincipal().");
  var s = String(text).trim();
  var at = s.lastIndexOf("@");
  var realm = null;
  if (at > 0) { realm = s.slice(at + 1); s = s.slice(0, at); }
  var parts = s.split("/").filter(function (p) { return p.length > 0; });
  if (!parts.length) {
    log.debug("Leaving parsePrincipal().");
    throw new Error("krb5: empty principal name");
  }
  var type = defaultType;
  if (type === undefined) {
    // A guess, and the UI must let it be overridden: a two-part name is
    // conventionally a service, and krbtgt is conventionally an instance.
    if (parts.length > 1) type = (parts[0] === "krbtgt") ? NAME_TYPE.SRV_INST :
        NAME_TYPE.SRV_HST;
    else type = NAME_TYPE.PRINCIPAL;
  }
  log.debug("Leaving parsePrincipal().");
  return { type: type, name: parts, realm: realm };
}

// EncryptedData ::= SEQUENCE { etype [0] Int32, kvno [1] UInt32 OPTIONAL,
// cipher [2] OCTET STRING }
function encEncryptedData(d) {
  log.debug("Leaving encEncryptedData().");
  log.debug("Entering encEncryptedData().");
  return asn1.encTaggedSequence([
    { tag: 0, value: asn1.encInteger(d.etype) },
    {
      tag: 1,
      value: (d.kvno === undefined || d.kvno === null) ? null :
          asn1.encInteger(d.kvno)
    },
    { tag: 2, value: asn1.encOctetString(d.cipher) }
  ]);
}

function readEncryptedData(t) {
  var f = asn1.readTaggedSequence(t.value);
  return {
    etype: asn1.decInteger(f[0]),
    etypeName: kcrypto.etypeName(asn1.decInteger(f[0])),
    kvno: f[1] ? asn1.decInteger(f[1]) : null,
    cipher: asn1.decOctetString(f[2])
  };
}

// EncryptionKey ::= SEQUENCE { keytype [0] Int32, keyvalue [1] OCTET STRING }
function encEncryptionKey(k) {
  return asn1.encTaggedSequence([
    { tag: 0, value: asn1.encInteger(k.etype) },
    { tag: 1, value: asn1.encOctetString(k.key) }
  ]);
}

function readEncryptionKey(t) {
  var f = asn1.readTaggedSequence(t.value);
  var etype = asn1.decInteger(f[0]);
  return {
    etype: etype,
    etypeName: kcrypto.etypeName(etype),
    key: asn1.decOctetString(f[1])
  };
}

// Checksum ::= SEQUENCE { cksumtype [0] Int32, checksum [1] OCTET STRING }
// cksumtype is where negative integers show up: -138 is HMAC-MD5.
function encChecksum(c) {
  return asn1.encTaggedSequence([
    { tag: 0, value: asn1.encInteger(c.type) },
    { tag: 1, value: asn1.encOctetString(c.checksum) }
  ]);
}

function readChecksum(t) {
  var f = asn1.readTaggedSequence(t.value);
  return { type: asn1.decInteger(f[0]), checksum: asn1.decOctetString(f[1]) };
}

// PA-DATA ::= SEQUENCE { padata-type [1] Int32, padata-value [2] OCTET STRING }
// NOTE the tag numbers: [1] and [2]. This is the irregularity in the grammar.
function encPaData(pa) {
  return asn1.encTaggedSequence([
    { tag: 1, value: asn1.encInteger(pa.type) },
    { tag: 2, value: asn1.encOctetString(pa.value) }
  ]);
}

function readPaData(t) {
  var f = asn1.readTaggedSequence(t.value);
  var type = asn1.decInteger(f[1]);
  return {
    type: type,
    typeName: PA_TYPE_NAMES[type] || ("PA-" + type),
    value: f[2] ? asn1.decOctetString(f[2]) : new Uint8Array(0)
  };
}

// HostAddress / HostAddresses — carried in tickets and requests, and the reason
// a ticket can be refused for coming from the wrong place.
//
// Most deployments use addressless tickets (Active Directory issues them), so
// it is tempting to read these and never write them. That asymmetry is a bug
// rather than a simplification: this codec has to re-encode a message it
// decoded — the decoder page does exactly that to show a round trip, and a
// relayed request must go back out as it came in — so a field the reader
// understands and the writer drops turns into silently different bytes.
function encHostAddresses(addresses) {
  return asn1.encSequenceOf((addresses || []).map(function (a) {
    return asn1.encTaggedSequence([
      { tag: 0, value: asn1.encInteger(a.type) },
      { tag: 1, value: asn1.encOctetString(a.address) }
    ]);
  }));
}

function readHostAddresses(t) {
  return asn1.decSequenceOf(t).map(function (a) {
    var f = asn1.readTaggedSequence(a.value);
    return { type: asn1.decInteger(f[0]), address: asn1.decOctetString(f[1]) };
  });
}

// A SINGLE HostAddress rather than the SEQUENCE OF. KRB-CRED's s-address and
// r-address are one address each, not a list — encoding them with the plural
// wraps them in an extra SEQUENCE, which decodes as a HostAddress whose type
// field is a whole structure.
function encHostAddress(a) {
  return asn1.encTaggedSequence([
    { tag: 0, value: asn1.encInteger(a.type) },
    { tag: 1, value: asn1.encOctetString(a.address) }
  ]);
}

function readHostAddress(t) {
  var f = asn1.readTaggedSequence(t.value);
  return { type: asn1.decInteger(f[0]), address: asn1.decOctetString(f[1]) };
}

// AuthorizationData ::= SEQUENCE OF SEQUENCE { ad-type [0] Int32, ad-data [1]
// OCTET STRING } The PAC arrives in here, wrapped in AD-IF-RELEVANT. Kept as
// raw bytes on purpose — it is not DER inside, so decoding it belongs to
// krb5_pac.js and not to this module. Use kpac.findPacs() to get at it: looking
// for ad-type 128 at the top level finds nothing on a ticket that has one,
// because AD-IF-RELEVANT is a container.
function readAuthorizationData(t) {
  return asn1.decSequenceOf(t).map(function (a) {
    var f = asn1.readTaggedSequence(a.value);
    return { type: asn1.decInteger(f[0]), data: asn1.decOctetString(f[1]) };
  });
}

function encAuthorizationData(entries) {
  return asn1.encSequenceOf((entries || []).map(function (e) {
    return asn1.encTaggedSequence([
      { tag: 0, value: asn1.encInteger(e.type) },
      { tag: 1, value: asn1.encOctetString(e.data) }
    ]);
  }));
}

// ---------------------------------------------------------------------------
// Ticket.
//
// `raw` is kept because a Ticket must be relayed byte-for-byte: it is encrypted
// under a key its holder does not have, and re-encoding it — even correctly —
// risks a different DER than the one a checksum was computed over.
// ---------------------------------------------------------------------------
function encTicket(ticket) {
  log.debug("Entering encTicket().");
  if (ticket.raw) {
    log.debug("Leaving encTicket().");
    return toBytes(ticket.raw);
  }
  log.debug("Leaving encTicket().");
  return asn1.encApplication(APPLICATION.TICKET, asn1.encTaggedSequence([
    { tag: 0, value: asn1.encInteger(PVNO) },
    { tag: 1, value: asn1.encGeneralString(ticket.realm) },
    { tag: 2, value: encPrincipalName(ticket.sname) },
    { tag: 3, value: encEncryptedData(ticket.encPart) }
  ]));
}

// Accepts either raw bytes or an element already read by the ASN.1 layer (which
// is how it arrives as field [5] of a KDC-REP). Either way `raw` comes out as
// the ticket's ORIGINAL bytes, because that is what must go back on the wire.
function elementBytes(t) {
  if (t instanceof Uint8Array) {
    return t;
  }
  if (t && t.raw) {
    return t.raw;
  }
  throw new Error("krb5: expected bytes or a parsed ASN.1 element");
}

function readTicket(t) {
  log.debug("Entering readTicket().");
  var bytes = elementBytes(t);
  var app = asn1.readApplication(bytes, APPLICATION.TICKET);
  var f = asn1.readTaggedSequence(app.sequence.value);
  log.debug("Leaving readTicket().");
  return {
    tktVno: asn1.decInteger(f[0]),
    realm: asn1.decGeneralString(f[1]),
    sname: readPrincipalName(f[2]),
    encPart: readEncryptedData(f[3]),
    raw: bytes
  };
}

// EncTicketPart ::= [APPLICATION 3] SEQUENCE
function readEncTicketPart(bytes) {
  log.debug("Entering readEncTicketPart().");
  var app = asn1.readApplication(bytes, APPLICATION.ENC_TICKET_PART);
  var f = asn1.readTaggedSequence(app.sequence.value);
  log.debug("Leaving readEncTicketPart().");
  return {
    flags: asn1.bitsFromFlags(asn1.decFlags(f[0])),
    key: readEncryptionKey(f[1]),
    crealm: asn1.decGeneralString(f[2]),
    cname: readPrincipalName(f[3]),
    transited: (function () {
      var tf = asn1.readTaggedSequence(f[4].value);
      return {
        type: asn1.decInteger(tf[0]),
        contents: asn1.decOctetString(tf[1])
      };
    })(),
    authtime: asn1.decKerberosTime(f[5]),
    starttime: f[6] ? asn1.decKerberosTime(f[6]) : null,
    endtime: asn1.decKerberosTime(f[7]),
    renewTill: f[8] ? asn1.decKerberosTime(f[8]) : null,
    caddr: f[9] ? readHostAddresses(f[9]) : null,
    authorizationData: f[10] ? readAuthorizationData(f[10]) : null
  };
}

function encEncTicketPart(p) {
  log.debug("Leaving encEncTicketPart().");
  log.debug("Entering encEncTicketPart().");
  return asn1.encApplication(APPLICATION.ENC_TICKET_PART,
      asn1.encTaggedSequence([
    { tag: 0, value: asn1.encFlags(p.flags) },
    { tag: 1, value: encEncryptionKey(p.key) },
    { tag: 2, value: asn1.encGeneralString(p.crealm) },
    { tag: 3, value: encPrincipalName(p.cname) },
    {
      tag: 4,
      value: asn1.encTaggedSequence([
        {
          tag: 0,
          value: asn1.encInteger((p.transited && p.transited.type) || 0)
        },
        {
          tag: 1,
          value: asn1.encOctetString((p.transited && p.transited.contents) ||
              new Uint8Array(0))
        }
      ])
    },
    { tag: 5, value: asn1.encKerberosTime(p.authtime) },
    { tag: 6, value: p.starttime ? asn1.encKerberosTime(p.starttime) : null },
    { tag: 7, value: asn1.encKerberosTime(p.endtime) },
    { tag: 8, value: p.renewTill ? asn1.encKerberosTime(p.renewTill) : null },
    {
      tag: 9,
      value: (p.caddr && p.caddr.length) ? encHostAddresses(p.caddr) : null
    },
    {
      tag: 10,
      value: p.authorizationData ? encAuthorizationData(p.authorizationData) :
          null
    }
  ]));
}

// ---------------------------------------------------------------------------
// KDC-REQ (AS-REQ / TGS-REQ).
// ---------------------------------------------------------------------------
function encKdcReqBody(body) {
  log.debug("Leaving encKdcReqBody().");
  log.debug("Entering encKdcReqBody().");
  return asn1.encTaggedSequence([
    { tag: 0, value: asn1.encFlags(body.kdcOptions || []) },
    { tag: 1, value: body.cname ? encPrincipalName(body.cname) : null },
    { tag: 2, value: asn1.encGeneralString(body.realm) },
    { tag: 3, value: body.sname ? encPrincipalName(body.sname) : null },
    { tag: 4, value: body.from ? asn1.encKerberosTime(body.from) : null },
    { tag: 5, value: asn1.encKerberosTime(body.till) },
    { tag: 6, value: body.rtime ? asn1.encKerberosTime(body.rtime) : null },
    { tag: 7, value: asn1.encInteger(body.nonce) },
    {
      tag: 8,
      value: asn1.encSequenceOf((body.etypes || []).map(asn1.encInteger))
    },
    {
      tag: 9,
      value: (body.addresses && body.addresses.length)
        ? encHostAddresses(body.addresses) : null
    },
    {
      tag: 10,
      value: body.encAuthorizationData ?
          encEncryptedData(body.encAuthorizationData) : null
    },
    {
      tag: 11,
      value: (body.additionalTickets && body.additionalTickets.length)
        ? asn1.encSequenceOf(body.additionalTickets.map(encTicket)) : null
    }
  ]);
}

function readKdcReqBody(t) {
  log.debug("Entering readKdcReqBody().");
  var f = asn1.readTaggedSequence(t.value);
  log.debug("Leaving readKdcReqBody().");
  return {
    kdcOptions: asn1.bitsFromFlags(asn1.decFlags(f[0])),
    cname: f[1] ? readPrincipalName(f[1]) : null,
    realm: asn1.decGeneralString(f[2]),
    sname: f[3] ? readPrincipalName(f[3]) : null,
    from: f[4] ? asn1.decKerberosTime(f[4]) : null,
    till: asn1.decKerberosTime(f[5]),
    rtime: f[6] ? asn1.decKerberosTime(f[6]) : null,
    nonce: asn1.decInteger(f[7]),
    etypes: asn1.decSequenceOf(f[8]).map(asn1.decInteger),
    addresses: f[9] ? readHostAddresses(f[9]) : null,
    encAuthorizationData: f[10] ? readEncryptedData(f[10]) : null,
    additionalTickets: f[11] ? asn1.decSequenceOf(f[11]).map(readTicket) : null,
    // The encoded body is what a TGS-REQ Authenticator's checksum covers, so it
    // is kept rather than re-encoded later: re-encoding is where a checksum
    // stops matching for no visible reason.
    raw: t.raw
  };
}

function encKdcReq(req) {
  log.debug("Entering encKdcReq().");
  var isTgs = req.msgType === MSG_TYPE.TGS_REQ;
  log.debug("Leaving encKdcReq().");
  return asn1.encApplication(isTgs ? APPLICATION.TGS_REQ : APPLICATION.AS_REQ,
    asn1.encTaggedSequence([
      { tag: 1, value: asn1.encInteger(PVNO) },
      { tag: 2, value: asn1.encInteger(req.msgType) },
      {
        tag: 3,
        value: (req.padata && req.padata.length)
          ? asn1.encSequenceOf(req.padata.map(encPaData)) : null
      },
      {
        tag: 4,
        value: req.reqBody.raw ? toBytes(req.reqBody.raw) :
            encKdcReqBody(req.reqBody)
      }
    ]));
}

function readKdcReq(bytes) {
  log.debug("Entering readKdcReq().");
  var app = asn1.readApplication(bytes);
  if (app.applicationNumber !== APPLICATION.AS_REQ &&
      app.applicationNumber !== APPLICATION.TGS_REQ) {
    throw new Error("krb5: expected AS-REQ [APPLICATION 10] or TGS-REQ " +
        "[APPLICATION 12], found [APPLICATION " +
      app.applicationNumber + "]");
  }
  var f = asn1.readTaggedSequence(app.sequence.value);
  var out = {
    pvno: asn1.decInteger(f[1]),
    msgType: asn1.decInteger(f[2]),
    padata: f[3] ? asn1.decSequenceOf(f[3]).map(readPaData) : [],
    reqBody: readKdcReqBody(f[4])
  };
  if (out.pvno !== PVNO) {
    throw new Error("krb5: protocol version " + out.pvno + ", expected 5");
  }
  log.debug("Leaving readKdcReq(). msgType=" + out.msgType);
  return out;
}

// ---------------------------------------------------------------------------
// KDC-REP (AS-REP / TGS-REP).
// ---------------------------------------------------------------------------
function encKdcRep(rep) {
  log.debug("Entering encKdcRep().");
  var isTgs = rep.msgType === MSG_TYPE.TGS_REP;
  log.debug("Leaving encKdcRep().");
  return asn1.encApplication(isTgs ? APPLICATION.TGS_REP : APPLICATION.AS_REP,
    asn1.encTaggedSequence([
      { tag: 0, value: asn1.encInteger(PVNO) },
      { tag: 1, value: asn1.encInteger(rep.msgType) },
      {
        tag: 2,
        value: (rep.padata && rep.padata.length)
          ? asn1.encSequenceOf(rep.padata.map(encPaData)) : null
      },
      { tag: 3, value: asn1.encGeneralString(rep.crealm) },
      { tag: 4, value: encPrincipalName(rep.cname) },
      { tag: 5, value: encTicket(rep.ticket) },
      { tag: 6, value: encEncryptedData(rep.encPart) }
    ]));
}

function readKdcRep(bytes) {
  log.debug("Entering readKdcRep().");
  var app = asn1.readApplication(bytes);
  if (app.applicationNumber !== APPLICATION.AS_REP &&
      app.applicationNumber !== APPLICATION.TGS_REP) {
    throw new Error("krb5: expected AS-REP [APPLICATION 11] or TGS-REP " +
        "[APPLICATION 13], found [APPLICATION " +
      app.applicationNumber + "]");
  }
  var f = asn1.readTaggedSequence(app.sequence.value);
  var out = {
    pvno: asn1.decInteger(f[0]),
    msgType: asn1.decInteger(f[1]),
    padata: f[2] ? asn1.decSequenceOf(f[2]).map(readPaData) : [],
    crealm: asn1.decGeneralString(f[3]),
    cname: readPrincipalName(f[4]),
    ticket: readTicket(f[5]),
    encPart: readEncryptedData(f[6])
  };
  log.debug("Leaving readKdcRep(). msgType=" + out.msgType);
  return out;
}

// EncKDCRepPart, which arrives as EncASRepPart [APPLICATION 25] or
// EncTGSRepPart [APPLICATION 26].
//
// **Accepting either is a requirement, not a kindness.** RFC 4120 section 5.4.2
// records that implementations encode an AS-REP's enc-part with tag 26. An
// implementation that insists on 25 passes every test against its own mock and
// fails against a real deployment with "cannot decode", which reads as a
// crypto problem.
function readEncKdcRepPart(bytes) {
  log.debug("Entering readEncKdcRepPart().");
  var app = asn1.readApplication(bytes);
  if (app.applicationNumber !== APPLICATION.ENC_AS_REP_PART &&
      app.applicationNumber !== APPLICATION.ENC_TGS_REP_PART) {
    log.debug("Leaving readEncKdcRepPart().");
    throw new Error("krb5: expected EncASRepPart [APPLICATION 25] or " +
        "EncTGSRepPart [APPLICATION 26], found " +
      "[APPLICATION " + app.applicationNumber + "]");
  }
  var f = asn1.readTaggedSequence(app.sequence.value);
  log.debug("Leaving readEncKdcRepPart().");
  return {
    // Which tag actually arrived, so the UI can show that a KDC used the
    // irregular one rather than hiding it.
    taggedAs: app.applicationNumber === APPLICATION.ENC_AS_REP_PART ?
        "EncASRepPart" : "EncTGSRepPart",
    key: readEncryptionKey(f[0]),
    lastReq: asn1.decSequenceOf(f[1]).map(function (lr) {
      var lf = asn1.readTaggedSequence(lr.value);
      return {
        type: asn1.decInteger(lf[0]),
        value: asn1.decKerberosTime(lf[1])
      };
    }),
    nonce: asn1.decInteger(f[2]),
    keyExpiration: f[3] ? asn1.decKerberosTime(f[3]) : null,
    flags: asn1.bitsFromFlags(asn1.decFlags(f[4])),
    authtime: asn1.decKerberosTime(f[5]),
    starttime: f[6] ? asn1.decKerberosTime(f[6]) : null,
    endtime: asn1.decKerberosTime(f[7]),
    renewTill: f[8] ? asn1.decKerberosTime(f[8]) : null,
    srealm: asn1.decGeneralString(f[9]),
    sname: readPrincipalName(f[10]),
    caddr: f[11] ? readHostAddresses(f[11]) : null,
    encryptedPaData: f[12] ? asn1.decSequenceOf(f[12]).map(readPaData) : null
  };
}

function encEncKdcRepPart(p, applicationNumber) {
  log.debug("Leaving encEncKdcRepPart().");
  log.debug("Entering encEncKdcRepPart().");
  return asn1.encApplication(applicationNumber || APPLICATION.ENC_AS_REP_PART,
      asn1.encTaggedSequence([
    { tag: 0, value: encEncryptionKey(p.key) },
    {
      tag: 1,
      value: asn1.encSequenceOf((p.lastReq || []).map(function (lr) {
        return asn1.encTaggedSequence([
          { tag: 0, value: asn1.encInteger(lr.type) },
          { tag: 1, value: asn1.encKerberosTime(lr.value) }
        ]);
      }))
    },
    { tag: 2, value: asn1.encInteger(p.nonce) },
    {
      tag: 3,
      value: p.keyExpiration ? asn1.encKerberosTime(p.keyExpiration) : null
    },
    { tag: 4, value: asn1.encFlags(p.flags) },
    { tag: 5, value: asn1.encKerberosTime(p.authtime) },
    { tag: 6, value: p.starttime ? asn1.encKerberosTime(p.starttime) : null },
    { tag: 7, value: asn1.encKerberosTime(p.endtime) },
    { tag: 8, value: p.renewTill ? asn1.encKerberosTime(p.renewTill) : null },
    { tag: 9, value: asn1.encGeneralString(p.srealm) },
    { tag: 10, value: encPrincipalName(p.sname) },
    {
      tag: 11,
      value: (p.caddr && p.caddr.length) ? encHostAddresses(p.caddr) : null
    },
    {
      tag: 12,
      value: (p.encryptedPaData && p.encryptedPaData.length)
        ? asn1.encSequenceOf(p.encryptedPaData.map(encPaData)) : null
    }
  ]));
}

// ---------------------------------------------------------------------------
// AP-REQ / AP-REP / Authenticator.
// ---------------------------------------------------------------------------
function encAuthenticator(a) {
  log.debug("Leaving encAuthenticator().");
  log.debug("Entering encAuthenticator().");
  return asn1.encApplication(APPLICATION.AUTHENTICATOR, asn1.encTaggedSequence([
    { tag: 0, value: asn1.encInteger(PVNO) },
    { tag: 1, value: asn1.encGeneralString(a.crealm) },
    { tag: 2, value: encPrincipalName(a.cname) },
    { tag: 3, value: a.cksum ? encChecksum(a.cksum) : null },
    { tag: 4, value: asn1.encInteger(a.cusec || 0) },
    { tag: 5, value: asn1.encKerberosTime(a.ctime) },
    { tag: 6, value: a.subkey ? encEncryptionKey(a.subkey) : null },
    {
      tag: 7,
      value: (a.seqNumber === undefined || a.seqNumber === null)
        ? null : asn1.encInteger(a.seqNumber)
    },
    {
      tag: 8,
      value: a.authorizationData ? encAuthorizationData(a.authorizationData) :
          null
    }
  ]));
}

function readAuthenticator(bytes) {
  log.debug("Entering readAuthenticator().");
  var app = asn1.readApplication(bytes, APPLICATION.AUTHENTICATOR);
  var f = asn1.readTaggedSequence(app.sequence.value);
  log.debug("Leaving readAuthenticator().");
  return {
    vno: asn1.decInteger(f[0]),
    crealm: asn1.decGeneralString(f[1]),
    cname: readPrincipalName(f[2]),
    cksum: f[3] ? readChecksum(f[3]) : null,
    cusec: asn1.decInteger(f[4]),
    ctime: asn1.decKerberosTime(f[5]),
    subkey: f[6] ? readEncryptionKey(f[6]) : null,
    seqNumber: f[7] ? asn1.decInteger(f[7]) : null,
    authorizationData: f[8] ? readAuthorizationData(f[8]) : null
  };
}

function encApReq(r) {
  return asn1.encApplication(APPLICATION.AP_REQ, asn1.encTaggedSequence([
    { tag: 0, value: asn1.encInteger(PVNO) },
    { tag: 1, value: asn1.encInteger(MSG_TYPE.AP_REQ) },
    { tag: 2, value: asn1.encFlags(r.apOptions || []) },
    { tag: 3, value: encTicket(r.ticket) },
    { tag: 4, value: encEncryptedData(r.authenticator) }
  ]));
}

function readApReq(bytes) {
  log.debug("Entering readApReq().");
  var app = asn1.readApplication(bytes, APPLICATION.AP_REQ);
  var f = asn1.readTaggedSequence(app.sequence.value);
  log.debug("Leaving readApReq().");
  return {
    pvno: asn1.decInteger(f[0]),
    msgType: asn1.decInteger(f[1]),
    apOptions: asn1.bitsFromFlags(asn1.decFlags(f[2])),
    ticket: readTicket(f[3]),
    authenticator: readEncryptedData(f[4])
  };
}

function encApRep(r) {
  return asn1.encApplication(APPLICATION.AP_REP, asn1.encTaggedSequence([
    { tag: 0, value: asn1.encInteger(PVNO) },
    { tag: 1, value: asn1.encInteger(MSG_TYPE.AP_REP) },
    { tag: 2, value: encEncryptedData(r.encPart) }
  ]));
}

function readApRep(bytes) {
  var app = asn1.readApplication(bytes, APPLICATION.AP_REP);
  var f = asn1.readTaggedSequence(app.sequence.value);
  return {
    pvno: asn1.decInteger(f[0]),
    msgType: asn1.decInteger(f[1]),
    encPart: readEncryptedData(f[2])
  };
}

function encEncApRepPart(p) {
  log.debug("Leaving encEncApRepPart().");
  log.debug("Entering encEncApRepPart().");
  return asn1.encApplication(APPLICATION.ENC_AP_REP_PART,
      asn1.encTaggedSequence([
    { tag: 0, value: asn1.encKerberosTime(p.ctime) },
    { tag: 1, value: asn1.encInteger(p.cusec || 0) },
    { tag: 2, value: p.subkey ? encEncryptionKey(p.subkey) : null },
    {
      tag: 3,
      value: (p.seqNumber === undefined || p.seqNumber === null)
        ? null : asn1.encInteger(p.seqNumber)
    }
  ]));
}

function readEncApRepPart(bytes) {
  var app = asn1.readApplication(bytes, APPLICATION.ENC_AP_REP_PART);
  var f = asn1.readTaggedSequence(app.sequence.value);
  return {
    ctime: asn1.decKerberosTime(f[0]),
    cusec: asn1.decInteger(f[1]),
    subkey: f[2] ? readEncryptionKey(f[2]) : null,
    seqNumber: f[3] ? asn1.decInteger(f[3]) : null
  };
}

// ---------------------------------------------------------------------------
// KRB-ERROR.
// ---------------------------------------------------------------------------
function encKrbError(e) {
  log.debug("Leaving encKrbError().");
  log.debug("Entering encKrbError().");
  return asn1.encApplication(APPLICATION.KRB_ERROR, asn1.encTaggedSequence([
    { tag: 0, value: asn1.encInteger(PVNO) },
    { tag: 1, value: asn1.encInteger(MSG_TYPE.ERROR) },
    { tag: 2, value: e.ctime ? asn1.encKerberosTime(e.ctime) : null },
    {
      tag: 3,
      value: (e.cusec === undefined || e.cusec === null) ? null :
          asn1.encInteger(e.cusec)
    },
    { tag: 4, value: asn1.encKerberosTime(e.stime) },
    { tag: 5, value: asn1.encInteger(e.susec || 0) },
    { tag: 6, value: asn1.encInteger(e.errorCode) },
    { tag: 7, value: e.crealm ? asn1.encGeneralString(e.crealm) : null },
    { tag: 8, value: e.cname ? encPrincipalName(e.cname) : null },
    { tag: 9, value: asn1.encGeneralString(e.realm) },
    { tag: 10, value: encPrincipalName(e.sname) },
    { tag: 11, value: e.eText ? asn1.encGeneralString(e.eText) : null },
    { tag: 12, value: e.eData ? asn1.encOctetString(e.eData) : null }
  ]));
}

function readKrbError(bytes) {
  log.debug("Entering readKrbError().");
  var app = asn1.readApplication(bytes, APPLICATION.KRB_ERROR);
  var f = asn1.readTaggedSequence(app.sequence.value);
  var code = asn1.decInteger(f[6]);
  var out = {
    pvno: asn1.decInteger(f[0]),
    msgType: asn1.decInteger(f[1]),
    ctime: f[2] ? asn1.decKerberosTime(f[2]) : null,
    cusec: f[3] ? asn1.decInteger(f[3]) : null,
    stime: asn1.decKerberosTime(f[4]),
    susec: asn1.decInteger(f[5]),
    errorCode: code,
    error: describeError(code),
    crealm: f[7] ? asn1.decGeneralString(f[7]) : null,
    cname: f[8] ? readPrincipalName(f[8]) : null,
    realm: asn1.decGeneralString(f[9]),
    sname: readPrincipalName(f[10]),
    eText: f[11] ? asn1.decGeneralString(f[11]) : null,
    eData: f[12] ? asn1.decOctetString(f[12]) : null
  };
  // e-data on a PREAUTH_REQUIRED is a SEQUENCE OF PA-DATA and is the whole
  // point of that error: it carries the salt. Decoded here so no caller has to
  // know that, and tolerantly, because on other errors e-data is something else
  // entirely (a TYPED-DATA, or on AD sometimes nothing useful).
  if (out.eData && out.eData.length) {
    try {
      out.eDataPaData = asn1.readChildren(asn1.readTlv(out.eData,
          0).value).map(readPaData);
    } catch (err) {
      out.eDataPaData = null;
      out.eDataNote = "e-data is not a SEQUENCE OF PA-DATA (" + err.message +
          ")";
    }
  }
  log.debug("Leaving readKrbError(). code=" + code + " (" + out.error.name +
      ")");
  return out;
}

// ---------------------------------------------------------------------------
// Pre-authentication payloads.
// ---------------------------------------------------------------------------

// PA-ENC-TS-ENC ::= SEQUENCE { patimestamp [0] KerberosTime, pausec [1]
// Microseconds OPTIONAL }
function encPaEncTsEnc(when, usec) {
  return asn1.encTaggedSequence([
    { tag: 0, value: asn1.encKerberosTime(when) },
    {
      tag: 1,
      value: (usec === undefined || usec === null) ? null :
          asn1.encInteger(usec)
    }
  ]);
}

function readPaEncTsEnc(bytes) {
  var t = asn1.readTlv(bytes, 0);
  var f = asn1.readTaggedSequence(t.value);
  return {
    patimestamp: asn1.decKerberosTime(f[0]),
    pausec: f[1] ? asn1.decInteger(f[1]) : null
  };
}

// ETYPE-INFO2 — the reason KDC_ERR_PREAUTH_REQUIRED is not a failure. The salt
// in here is not guessable (see the header note) and the s2kparams carry the
// iteration count.
function readEtypeInfo2(bytes) {
  log.debug("Entering readEtypeInfo2().");
  var t = asn1.readTlv(bytes, 0);
  log.debug("Leaving readEtypeInfo2().");
  return asn1.readChildren(t.value).map(function (entry) {
    var f = asn1.readTaggedSequence(entry.value);
    var etype = asn1.decInteger(f[0]);
    return {
      etype: etype,
      etypeName: kcrypto.etypeName(etype),
      salt: f[1] ? asn1.decGeneralString(f[1]) : null,
      s2kparams: f[2] ? asn1.decOctetString(f[2]) : null
    };
  });
}

function encEtypeInfo2(entries) {
  log.debug("Leaving encEtypeInfo2().");
  log.debug("Entering encEtypeInfo2().");
  return asn1.encSequenceOf(entries.map(function (e) {
    return asn1.encTaggedSequence([
      { tag: 0, value: asn1.encInteger(e.etype) },
      {
        tag: 1,
        value: e.salt === null || e.salt === undefined ? null :
            asn1.encGeneralString(e.salt)
      },
      { tag: 2, value: e.s2kparams ? asn1.encOctetString(e.s2kparams) : null }
    ]);
  }));
}

// The older ETYPE-INFO, whose salt is an OCTET STRING rather than a
// KerberosString. Read-only: it is what an old KDC sends.
function readEtypeInfo(bytes) {
  log.debug("Entering readEtypeInfo().");
  var t = asn1.readTlv(bytes, 0);
  log.debug("Leaving readEtypeInfo().");
  return asn1.readChildren(t.value).map(function (entry) {
    var f = asn1.readTaggedSequence(entry.value);
    var etype = asn1.decInteger(f[0]);
    return {
      etype: etype,
      etypeName: kcrypto.etypeName(etype),
      salt: f[1] ? asn1.decLatin1(asn1.decOctetString(f[1])) : null
    };
  });
}

// PA-PAC-REQUEST ::= SEQUENCE { include-pac [0] BOOLEAN } — MS-KILE. Being able
// to ask for a ticket WITHOUT a PAC and watch a service's behaviour change is
// one of the more useful things this tool can do.
function encPaPacRequest(include) {
  return asn1.encSequence([asn1.encContext(0, asn1.tlv(0x01,
      new Uint8Array([include ? 0xff : 0x00])))]);
}

function readPaPacRequest(bytes) {
  var t = asn1.readTlv(bytes, 0);
  var f = asn1.readTaggedSequence(t.value);
  return { includePac: f[0] && f[0].value.length > 0 && f[0].value[0] !== 0 };
}

// PA-FOR-USER (MS-SFU, S4U2Self). Its checksum is over the name, realm and
// auth-package with the TGT session key and cksumtype -138, which is why the
// negative-integer support in the DER layer is load-bearing rather than
// theoretical.
function encPaForUser(u) {
  return asn1.encTaggedSequence([
    { tag: 0, value: encPrincipalName(u.userName) },
    { tag: 1, value: asn1.encGeneralString(u.userRealm) },
    { tag: 2, value: encChecksum(u.cksum) },
    { tag: 3, value: asn1.encGeneralString(u.authPackage || "Kerberos") }
  ]);
}

// ---------------------------------------------------------------------------
// KRB-CRED — RFC 4120 section 5.8.1. **Unconstrained delegation.**
//
// This is how a client hands its own ticket-granting ticket to a service so that the
// service can go and get tickets to anything, as the client. Not "as the client for one
// named service" — that is constrained delegation and the KDC polices it. This is
// everything, everywhere, for the ticket's lifetime, and the KDC never sees it happen.
//
// Which is why the interesting parts of this structure are the ones people forget:
//
//  * **It travels in the AP-REQ Authenticator's 0x8003 checksum**, in the Deleg field,
//    when GSS_C_DELEG_FLAG is set — not as a message of its own. See krb5_gss.js, which
//    already carries that field.
//  * **Its enc-part is encrypted at key usage 14** under the AP exchange's subkey (or the
//    session key when there is none), so only the service the client chose can open it.
//  * **The tickets and their session keys are separated.** `tickets` holds the opaque
//    Tickets and the encrypted `ticket-info` holds each one's session key — because a
//    ticket is useless without its key, and that separation is what makes the whole
//    structure safe to put in a checksum field.
//
// Nearly every field of KrbCredInfo is OPTIONAL, and a sender that omits the session key
// has forwarded something unusable. That is checked on read rather than assumed.
// ---------------------------------------------------------------------------
function encKrbCredInfo(info) {
  log.debug("Leaving encKrbCredInfo().");
  log.debug("Entering encKrbCredInfo().");
  return asn1.encTaggedSequence([
    { tag: 0, value: encEncryptionKey(info.key) },
    { tag: 1, value: info.prealm ? asn1.encGeneralString(info.prealm) : null },
    { tag: 2, value: info.pname ? encPrincipalName(info.pname) : null },
    { tag: 3, value: info.flags ? asn1.encFlags(info.flags) : null },
    {
      tag: 4,
      value: info.authtime ? asn1.encKerberosTime(info.authtime) : null
    },
    {
      tag: 5,
      value: info.starttime ? asn1.encKerberosTime(info.starttime) : null
    },
    { tag: 6, value: info.endtime ? asn1.encKerberosTime(info.endtime) : null },
    {
      tag: 7,
      value: info.renewTill ? asn1.encKerberosTime(info.renewTill) : null
    },
    { tag: 8, value: info.srealm ? asn1.encGeneralString(info.srealm) : null },
    { tag: 9, value: info.sname ? encPrincipalName(info.sname) : null },
    {
      tag: 10,
      value: (info.caddr && info.caddr.length) ? encHostAddresses(info.caddr) :
          null
    }
  ]);
}

function readKrbCredInfo(t) {
  log.debug("Entering readKrbCredInfo().");
  var f = asn1.readTaggedSequence(t.value);
  if (!f[0]) {
    log.debug("Leaving readKrbCredInfo().");
    throw new Error("krb5: a KrbCredInfo with no session key. Every other " +
        "field is optional but " +
      "that one is not — a forwarded ticket without its key cannot be used " +
          "for anything.");
  }
  log.debug("Leaving readKrbCredInfo().");
  return {
    key: readEncryptionKey(f[0]),
    prealm: f[1] ? asn1.decGeneralString(f[1]) : null,
    pname: f[2] ? readPrincipalName(f[2]) : null,
    flags: f[3] ? asn1.bitsFromFlags(asn1.decFlags(f[3])) : null,
    authtime: f[4] ? asn1.decKerberosTime(f[4]) : null,
    starttime: f[5] ? asn1.decKerberosTime(f[5]) : null,
    endtime: f[6] ? asn1.decKerberosTime(f[6]) : null,
    renewTill: f[7] ? asn1.decKerberosTime(f[7]) : null,
    srealm: f[8] ? asn1.decGeneralString(f[8]) : null,
    sname: f[9] ? readPrincipalName(f[9]) : null,
    caddr: f[10] ? readHostAddresses(f[10]) : null
  };
}

function encEncKrbCredPart(p) {
  log.debug("Leaving encEncKrbCredPart().");
  log.debug("Entering encEncKrbCredPart().");
  return asn1.encApplication(APPLICATION.ENC_KRB_CRED_PART,
      asn1.encTaggedSequence([
    {
      tag: 0,
      value: asn1.encSequenceOf((p.ticketInfo || []).map(encKrbCredInfo))
    },
    {
      tag: 1,
      value: p.nonce === undefined || p.nonce === null ? null :
          asn1.encInteger(p.nonce)
    },
    { tag: 2, value: p.timestamp ? asn1.encKerberosTime(p.timestamp) : null },
    {
      tag: 3,
      value: p.usec === undefined || p.usec === null ? null :
          asn1.encInteger(p.usec)
    },
    { tag: 4, value: p.sAddress ? encHostAddress(p.sAddress) : null },
    { tag: 5, value: p.rAddress ? encHostAddress(p.rAddress) : null }
  ]));
}

function readEncKrbCredPart(bytes) {
  log.debug("Entering readEncKrbCredPart().");
  var app = asn1.readApplication(bytes, APPLICATION.ENC_KRB_CRED_PART);
  var f = asn1.readTaggedSequence(app.sequence.value);
  log.debug("Leaving readEncKrbCredPart().");
  return {
    ticketInfo: asn1.decSequenceOf(f[0]).map(readKrbCredInfo),
    nonce: f[1] ? asn1.decInteger(f[1]) : null,
    timestamp: f[2] ? asn1.decKerberosTime(f[2]) : null,
    usec: f[3] ? asn1.decInteger(f[3]) : null,
    sAddress: f[4] ? readHostAddress(f[4]) : null,
    rAddress: f[5] ? readHostAddress(f[5]) : null
  };
}

function encKrbCred(c) {
  return asn1.encApplication(APPLICATION.KRB_CRED, asn1.encTaggedSequence([
    { tag: 0, value: asn1.encInteger(PVNO) },
    { tag: 1, value: asn1.encInteger(MSG_TYPE.CRED) },
    { tag: 2, value: asn1.encSequenceOf((c.tickets || []).map(encTicket)) },
    { tag: 3, value: encEncryptedData(c.encPart) }
  ]));
}

function readKrbCred(bytes) {
  log.debug("Entering readKrbCred().");
  var app = asn1.readApplication(bytes, APPLICATION.KRB_CRED);
  var f = asn1.readTaggedSequence(app.sequence.value);
  var msgType = asn1.decInteger(f[1]);
  if (msgType !== MSG_TYPE.CRED) {
    log.debug("Leaving readKrbCred().");
    throw new Error("krb5: this is tagged [APPLICATION 22] but its msg-type " +
        "is " + msgType +
      ", not 22");
  }
  var tickets = asn1.decSequenceOf(f[2]).map(readTicket);
  if (!tickets.length) {
    log.debug("Leaving readKrbCred().");
    throw new Error("krb5: a KRB-CRED carrying no tickets. There is nothing " +
        "to delegate.");
  }
  log.debug("Leaving readKrbCred().");
  return {
    pvno: asn1.decInteger(f[0]),
    msgType: msgType,
    tickets: tickets,
    encPart: readEncryptedData(f[3])
  };
}

// PA-PAC-OPTIONS ([MS-KILE] section 2.2.10, extended by [MS-SFU] section
// 2.2.5).
//
// A SEQUENCE around a KerberosFlags, and the bit that matters here is number 3:
// **resource-based constrained delegation**. It is not decoration. [MS-SFU]
// requires a KDC to answer an S4U2proxy request with KDC_ERR_BADOPTION when
// RBCD is what would authorize it and this bit is absent — so a client that
// knows how to do RBCD but omits the padata gets refused for a reason that says
// nothing about the padata.
//
// Bit order is KerberosFlags order: bit 0 is the MOST significant bit of the
// FIRST octet, so bit 3 is 0x10 of byte 0 rather than 0x08 of anything.
var PAC_OPTION = {
  CLAIMS: 0,
  BRANCH_AWARE: 1,
  FORWARD_TO_FULL_DC: 2,
  RESOURCE_BASED_CONSTRAINED_DELEGATION: 3
};

function encPaPacOptions(bits) {
  return asn1.encTaggedSequence([{ tag: 0, value: asn1.encFlags(bits || []) }]);
}

function readPaPacOptions(bytes) {
  var f = asn1.readTaggedSequence(asn1.readTlv(prim.toBytes(bytes), 0).value);
  return { flags: asn1.bitsFromFlags(asn1.decFlags(f[0])) };
}

function readPaForUser(bytes) {
  var t = asn1.readTlv(bytes, 0);
  var f = asn1.readTaggedSequence(t.value);
  return {
    userName: readPrincipalName(f[0]),
    userRealm: asn1.decGeneralString(f[1]),
    cksum: readChecksum(f[2]),
    authPackage: asn1.decGeneralString(f[3])
  };
}

// ---------------------------------------------------------------------------
// Flag helpers for display and for building.
// ---------------------------------------------------------------------------
function flagNames(table, bits) {
  var byNumber = {};
  Object.keys(table).forEach(function (name) { byNumber[table[name]] = name; });
  return (bits || []).map(function (b) {
    return byNumber[b] ? byNumber[b].toLowerCase().replace(/_/g, "-") : (
        "bit-" + b);
  });
}

function kdcOptionNames(bits) { return flagNames(KDC_OPTION, bits); }
function ticketFlagNames(bits) { return flagNames(TICKET_FLAG, bits); }
function apOptionNames(bits) { return flagNames(AP_OPTION, bits); }

// Which message a buffer holds, without committing to parsing it. Used by the
// decoder page to choose a reader and by the api's relay to decide whether a
// payload is a Kerberos request at all.
var APPLICATION_NAMES = {
  1: "Ticket",
  2: "Authenticator",
  3: "EncTicketPart",
  10: "AS-REQ",
  11: "AS-REP",
  12: "TGS-REQ",
  13: "TGS-REP",
  14: "AP-REQ",
  15: "AP-REP",
  22: "KRB-CRED",
  25: "EncASRepPart",
  26: "EncTGSRepPart",
  27: "EncAPRepPart",
  28: "EncKrbPrivPart",
  29: "EncKrbCredPart",
  30: "KRB-ERROR"
};

function identify(bytes) {
  var n = asn1.peekApplicationNumber(bytes);
  if (n === null) {
    return null;
  }
  return {
    applicationNumber: n,
    name: APPLICATION_NAMES[n] || ("[APPLICATION " + n + "]")
  };
}

// Read whichever KDC message this is — a reply or the error that replaced it.
// Every exchange in this workflow needs this: a KDC answers an AS-REQ with an
// AS-REP or with a KRB-ERROR, and treating the error as a parse failure is how
// KDC_ERR_PREAUTH_REQUIRED ends up looking like a broken codec.
function readKdcResponse(bytes) {
  log.debug("Entering readKdcResponse().");
  var id = identify(bytes);
  if (!id) {
    log.debug("Leaving readKdcResponse().");
    throw new Error("krb5: not a Kerberos message (no [APPLICATION n] tag)");
  }
  if (id.applicationNumber === APPLICATION.KRB_ERROR) {
    log.debug("Leaving readKdcResponse().");
    return { kind: "KRB-ERROR", error: readKrbError(bytes) };
  }
  if (id.applicationNumber === APPLICATION.AS_REP ||
      id.applicationNumber === APPLICATION.TGS_REP) {
    log.debug("Leaving readKdcResponse().");
    return { kind: id.name, rep: readKdcRep(bytes) };
  }
  log.debug("Leaving readKdcResponse().");
  throw new Error("krb5: a KDC answered with " + id.name + ", which is " +
      "neither a reply nor an error");
}

module.exports = {
  PVNO: PVNO,
  MSG_TYPE: MSG_TYPE,
  APPLICATION: APPLICATION,
  APPLICATION_NAMES: APPLICATION_NAMES,
  NAME_TYPE: NAME_TYPE,
  PA_TYPE: PA_TYPE,
  PA_TYPE_NAMES: PA_TYPE_NAMES,
  KDC_OPTION: KDC_OPTION,
  TICKET_FLAG: TICKET_FLAG,
  AP_OPTION: AP_OPTION,
  ERROR_CODE: ERROR_CODE,
  describeError: describeError,
  // principals
  encPrincipalName: encPrincipalName,
  readPrincipalName: readPrincipalName,
  principalToString: principalToString,
  parsePrincipal: parsePrincipal,
  // shared structures
  encEncryptedData: encEncryptedData,
  readEncryptedData: readEncryptedData,
  encEncryptionKey: encEncryptionKey,
  readEncryptionKey: readEncryptionKey,
  encChecksum: encChecksum,
  readChecksum: readChecksum,
  encPaData: encPaData,
  readPaData: readPaData,
  encAuthorizationData: encAuthorizationData,
  readAuthorizationData: readAuthorizationData,
  encHostAddresses: encHostAddresses,
  encHostAddress: encHostAddress,
  readHostAddress: readHostAddress,
  readHostAddresses: readHostAddresses,
  // tickets
  encTicket: encTicket,
  readTicket: readTicket,
  encEncTicketPart: encEncTicketPart,
  readEncTicketPart: readEncTicketPart,
  // KDC exchange
  encKdcReq: encKdcReq,
  readKdcReq: readKdcReq,
  encKdcReqBody: encKdcReqBody,
  readKdcReqBody: readKdcReqBody,
  encKdcRep: encKdcRep,
  readKdcRep: readKdcRep,
  encEncKdcRepPart: encEncKdcRepPart,
  readEncKdcRepPart: readEncKdcRepPart,
  readKdcResponse: readKdcResponse,
  // AP exchange
  encAuthenticator: encAuthenticator,
  readAuthenticator: readAuthenticator,
  encApReq: encApReq,
  readApReq: readApReq,
  encApRep: encApRep,
  readApRep: readApRep,
  encEncApRepPart: encEncApRepPart,
  readEncApRepPart: readEncApRepPart,
  // errors
  encKrbError: encKrbError,
  readKrbError: readKrbError,
  // pre-authentication
  encPaEncTsEnc: encPaEncTsEnc,
  readPaEncTsEnc: readPaEncTsEnc,
  encEtypeInfo2: encEtypeInfo2,
  readEtypeInfo2: readEtypeInfo2,
  readEtypeInfo: readEtypeInfo,
  encPaPacRequest: encPaPacRequest,
  readPaPacRequest: readPaPacRequest,
  encKrbCred: encKrbCred,
  readKrbCred: readKrbCred,
  encEncKrbCredPart: encEncKrbCredPart,
  readEncKrbCredPart: readEncKrbCredPart,
  encKrbCredInfo: encKrbCredInfo,
  readKrbCredInfo: readKrbCredInfo,
  PAC_OPTION: PAC_OPTION,
  encPaPacOptions: encPaPacOptions,
  readPaPacOptions: readPaPacOptions,
  encPaForUser: encPaForUser,
  readPaForUser: readPaForUser,
  // display
  identify: identify,
  kdcOptionNames: kdcOptionNames,
  ticketFlagNames: ticketFlagNames,
  apOptionNames: apOptionNames,
  flagNames: flagNames
};
