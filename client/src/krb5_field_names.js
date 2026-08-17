// File: krb5_field_names.js
//
// ---------------------------------------------------------------------------
// The names RFC 4120 gives the fields, so a byte can be called what the RFC
// calls it.
//
// krb5_ranges.js already says which bytes belong to which ASN.1 element, and it
// names each one the way the encoding does: `[APPLICATION 10] → SEQUENCE →
// [4] → SEQUENCE → [1]`. That is true, and useless to anybody who has not
// memorised the module — the field it names is `cname`, and knowing that is the
// whole reason for looking at the bytes. This module is the missing half: the
// context tag numbers, per structure, with the names from the RFC's own ASN.1.
//
// WHY THE TABLE IS DATA AND NOT DERIVED FROM krb5_messages.js. The encoders
// there carry the same tag numbers, but as positions in argument lists —
// `{ tag: 4, value: ... }` beside a variable called `reqBody`. A name-extractor
// over that would be a parser of this project's own source, which is a great
// deal of machinery to recover something the RFC states in one line per field.
// The cost of a second copy is drift, and drift here is bounded and visible:
// tests/krb5_field_names.js reads a real AS-REQ, AS-REP, TGS-REQ, AP-REQ,
// Ticket, KRB-ERROR and KRB-CRED built by krb5_messages.js and asserts that
// every context tag those encoders emit is named here. A field added to an
// encoder and not to this table fails that test rather than showing up in the
// hex view as an unnamed `[9]`.
//
// NO DOM, like every other module in common/krb5 — the rendering is
// client/src/kerberos_hex.js.
//
// ---------------------------------------------------------------------------
// HOW A NAME IS REACHED, which is the only interesting part.
//
// DER carries no field names: a KDC-REQ-BODY's `till` is on the wire as `[5]`,
// and `[5]` means something different inside every structure. So a name depends
// on where you are, and walking the tree is what tells you. The walker below is
// a four-state machine, and the states are the four shapes an element can have
// in this protocol:
//
//   application   [APPLICATION n] — self-identifying, so it re-roots the naming
//                 wherever it appears. A Ticket inside a KDC-REP is
//                 [APPLICATION 1] and is named from the table, not from its
//                 position.
//   body          the SEQUENCE directly inside an application tag or a field —
//                 it carries the fields but is not itself one, so it takes the
//                 structure's name and adds no path segment.
//   fields        a [k] wrapper inside a body: THIS is where a name comes from.
//   value         what is inside a [k] wrapper. It inherits the field's name,
//                 so hovering the INTEGER inside `[1]` says `pvno` rather than
//                 nothing.
//
// SEQUENCE OF is the fifth shape and the reason `items` exists: `padata [3]
// SEQUENCE OF PA-DATA` is a [3] wrapper, a SEQUENCE, and then one PA-DATA per
// element — so the elements are numbered (`padata[0]`, `padata[1]`) and each
// re-enters the table as its own structure.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "krb5_field_names",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      // No CONFIG_FILE resolvable here — a node caller rather than a bundle.
      return "info";
    }
  })()
});

// ---------------------------------------------------------------------------
// The structures, by the name this module knows them by.
//
// `fields` maps a CONTEXT TAG NUMBER to the field it introduces. A field may
// carry:
//
//   type  the structure its value is, so the walk descends into that table;
//   of    the structure each ELEMENT is, when the field is a SEQUENCE OF.
//
// A field with neither is a primitive — an INTEGER, a KerberosString, an OCTET
// STRING, a BIT STRING — and its value inherits its name.
//
// `positional` is for the one structure here that is not context-tagged: a GSS
// InitialContextToken, whose children are identified by order.
// ---------------------------------------------------------------------------
var TYPES = {
  // -------------------------------------------------------------------------
  // RFC 4120 section 5.4 — the KDC exchanges.
  // -------------------------------------------------------------------------
  "AS-REQ": {
    rfc: "RFC 4120 5.4.1",
    fields: {
      1: { name: "pvno" },
      2: { name: "msg-type" },
      3: { name: "padata", of: "PA-DATA" },
      4: { name: "req-body", type: "KDC-REQ-BODY" }
    }
  },
  "KDC-REQ-BODY": {
    rfc: "RFC 4120 5.4.1",
    fields: {
      0: { name: "kdc-options" },
      1: { name: "cname", type: "PrincipalName" },
      2: { name: "realm" },
      3: { name: "sname", type: "PrincipalName" },
      4: { name: "from" },
      5: { name: "till" },
      6: { name: "rtime" },
      7: { name: "nonce" },
      8: { name: "etype", of: null },
      9: { name: "addresses", of: "HostAddress" },
      10: { name: "enc-authorization-data", type: "EncryptedData" },
      11: { name: "additional-tickets", of: "Ticket" }
    }
  },
  "AS-REP": {
    rfc: "RFC 4120 5.4.2",
    fields: {
      0: { name: "pvno" },
      1: { name: "msg-type" },
      2: { name: "padata", of: "PA-DATA" },
      3: { name: "crealm" },
      4: { name: "cname", type: "PrincipalName" },
      5: { name: "ticket", type: "Ticket" },
      6: { name: "enc-part", type: "EncryptedData" }
    }
  },

  // -------------------------------------------------------------------------
  // RFC 4120 section 5.3 — tickets.
  // -------------------------------------------------------------------------
  "Ticket": {
    rfc: "RFC 4120 5.3",
    fields: {
      0: { name: "tkt-vno" },
      1: { name: "realm" },
      2: { name: "sname", type: "PrincipalName" },
      3: { name: "enc-part", type: "EncryptedData" }
    }
  },
  "EncTicketPart": {
    rfc: "RFC 4120 5.3",
    fields: {
      0: { name: "flags" },
      1: { name: "key", type: "EncryptionKey" },
      2: { name: "crealm" },
      3: { name: "cname", type: "PrincipalName" },
      4: { name: "transited", type: "TransitedEncoding" },
      5: { name: "authtime" },
      6: { name: "starttime" },
      7: { name: "endtime" },
      8: { name: "renew-till" },
      9: { name: "caddr", of: "HostAddress" },
      10: { name: "authorization-data", of: "AuthorizationDataEntry" }
    }
  },
  "TransitedEncoding": {
    rfc: "RFC 4120 5.3",
    fields: {
      0: { name: "tr-type" },
      1: { name: "contents" }
    }
  },
  "EncKDCRepPart": {
    rfc: "RFC 4120 5.4.2",
    fields: {
      0: { name: "key", type: "EncryptionKey" },
      1: { name: "last-req", of: "LastReq" },
      2: { name: "nonce" },
      3: { name: "key-expiration" },
      4: { name: "flags" },
      5: { name: "authtime" },
      6: { name: "starttime" },
      7: { name: "endtime" },
      8: { name: "renew-till" },
      9: { name: "srealm" },
      10: { name: "sname", type: "PrincipalName" },
      11: { name: "caddr", of: "HostAddress" },
      12: { name: "encrypted-pa-data", of: "PA-DATA" }
    }
  },
  "LastReq": {
    rfc: "RFC 4120 5.4.2",
    fields: {
      0: { name: "lr-type" },
      1: { name: "lr-value" }
    }
  },

  // -------------------------------------------------------------------------
  // RFC 4120 section 5.5 — the AP exchange.
  // -------------------------------------------------------------------------
  "AP-REQ": {
    rfc: "RFC 4120 5.5.1",
    fields: {
      0: { name: "pvno" },
      1: { name: "msg-type" },
      2: { name: "ap-options" },
      3: { name: "ticket", type: "Ticket" },
      4: { name: "authenticator", type: "EncryptedData" }
    }
  },
  "Authenticator": {
    rfc: "RFC 4120 5.5.1",
    fields: {
      0: { name: "authenticator-vno" },
      1: { name: "crealm" },
      2: { name: "cname", type: "PrincipalName" },
      3: { name: "cksum", type: "Checksum" },
      4: { name: "cusec" },
      5: { name: "ctime" },
      6: { name: "subkey", type: "EncryptionKey" },
      7: { name: "seq-number" },
      8: { name: "authorization-data", of: "AuthorizationDataEntry" }
    }
  },
  "AP-REP": {
    rfc: "RFC 4120 5.5.2",
    fields: {
      0: { name: "pvno" },
      1: { name: "msg-type" },
      2: { name: "enc-part", type: "EncryptedData" }
    }
  },
  "EncAPRepPart": {
    rfc: "RFC 4120 5.5.2",
    fields: {
      0: { name: "ctime" },
      1: { name: "cusec" },
      2: { name: "subkey", type: "EncryptionKey" },
      3: { name: "seq-number" }
    }
  },

  // -------------------------------------------------------------------------
  // RFC 4120 section 5.9.1 — the error, which on this workflow is the message
  // most often looked at: KDC_ERR_PREAUTH_REQUIRED carries the salt in e-data.
  // -------------------------------------------------------------------------
  "KRB-ERROR": {
    rfc: "RFC 4120 5.9.1",
    fields: {
      0: { name: "pvno" },
      1: { name: "msg-type" },
      2: { name: "ctime" },
      3: { name: "cusec" },
      4: { name: "stime" },
      5: { name: "susec" },
      6: { name: "error-code" },
      7: { name: "crealm" },
      8: { name: "cname", type: "PrincipalName" },
      9: { name: "realm" },
      10: { name: "sname", type: "PrincipalName" },
      11: { name: "e-text" },
      12: { name: "e-data" }
    }
  },

  // -------------------------------------------------------------------------
  // RFC 4120 section 5.8.1 — KRB-CRED, which is unconstrained delegation.
  // -------------------------------------------------------------------------
  "KRB-CRED": {
    rfc: "RFC 4120 5.8.1",
    fields: {
      0: { name: "pvno" },
      1: { name: "msg-type" },
      2: { name: "tickets", of: "Ticket" },
      3: { name: "enc-part", type: "EncryptedData" }
    }
  },
  "EncKrbCredPart": {
    rfc: "RFC 4120 5.8.1",
    fields: {
      0: { name: "ticket-info", of: "KrbCredInfo" },
      1: { name: "nonce" },
      2: { name: "timestamp" },
      3: { name: "usec" },
      4: { name: "s-address", type: "HostAddress" },
      5: { name: "r-address", type: "HostAddress" }
    }
  },
  "KrbCredInfo": {
    rfc: "RFC 4120 5.8.1",
    fields: {
      0: { name: "key", type: "EncryptionKey" },
      1: { name: "prealm" },
      2: { name: "pname", type: "PrincipalName" },
      3: { name: "flags" },
      4: { name: "authtime" },
      5: { name: "starttime" },
      6: { name: "endtime" },
      7: { name: "renew-till" },
      8: { name: "srealm" },
      9: { name: "sname", type: "PrincipalName" },
      10: { name: "caddr", of: "HostAddress" }
    }
  },

  // -------------------------------------------------------------------------
  // RFC 4120 section 5.2 — the small structures every message is built from.
  // -------------------------------------------------------------------------
  "PrincipalName": {
    rfc: "RFC 4120 5.2.2",
    fields: {
      0: { name: "name-type" },
      1: { name: "name-string", of: null }
    }
  },
  "EncryptedData": {
    rfc: "RFC 4120 5.2.9",
    fields: {
      0: { name: "etype" },
      1: { name: "kvno" },
      2: { name: "cipher" }
    }
  },
  "EncryptionKey": {
    rfc: "RFC 4120 5.2.9",
    fields: {
      0: { name: "keytype" },
      1: { name: "keyvalue" }
    }
  },
  "Checksum": {
    rfc: "RFC 4120 5.2.9",
    fields: {
      0: { name: "cksumtype" },
      1: { name: "checksum" }
    }
  },
  "HostAddress": {
    rfc: "RFC 4120 5.2.5",
    fields: {
      0: { name: "addr-type" },
      1: { name: "address" }
    }
  },
  "AuthorizationDataEntry": {
    rfc: "RFC 4120 5.2.6",
    fields: {
      0: { name: "ad-type" },
      1: { name: "ad-data" }
    }
  },
  "PA-DATA": {
    rfc: "RFC 4120 5.2.7",
    fields: {
      1: { name: "padata-type" },
      2: { name: "padata-value" }
    }
  },

  // -------------------------------------------------------------------------
  // The pre-authentication payloads this workflow builds and reads. Each of
  // these arrives inside a padata-value OCTET STRING, so the hex view reaches
  // them only when they are decoded and shown on their own — but the decoder
  // page does exactly that, and naming them costs four lines each.
  // -------------------------------------------------------------------------
  "PA-ENC-TS-ENC": {
    rfc: "RFC 4120 5.2.7.2",
    fields: {
      0: { name: "patimestamp" },
      1: { name: "pausec" }
    }
  },
  "ETYPE-INFO2-ENTRY": {
    rfc: "RFC 4120 5.2.7.5",
    fields: {
      0: { name: "etype" },
      1: { name: "salt" },
      2: { name: "s2kparams" }
    }
  },
  "ETYPE-INFO-ENTRY": {
    rfc: "RFC 4120 5.2.7.4",
    fields: {
      0: { name: "etype" },
      1: { name: "salt" }
    }
  },
  "KERB-PA-PAC-REQUEST": {
    rfc: "MS-KILE 2.2.3",
    fields: {
      0: { name: "include-pac" }
    }
  },
  "PA-FOR-USER": {
    rfc: "MS-SFU 2.2.1",
    fields: {
      0: { name: "userName", type: "PrincipalName" },
      1: { name: "userRealm" },
      2: { name: "cksum", type: "Checksum" },
      3: { name: "auth-package" }
    }
  },
  "PA-PAC-OPTIONS": {
    rfc: "MS-SFU 2.2.10",
    fields: {
      0: { name: "flags" }
    }
  },

  // -------------------------------------------------------------------------
  // RFC 2743 / RFC 4121 — what a SERVICE is actually handed.
  //
  // Not context-tagged: an InitialContextToken is [APPLICATION 0] wrapping an
  // OID, a two-byte token id and then the mechanism's own token, in that order.
  // The AP page's "What went out" is one of these, so without `positional` the
  // most-looked-at message on that page would be three unnamed elements.
  // -------------------------------------------------------------------------
  "GSS-InitialContextToken": {
    rfc: "RFC 2743 3.1",
    positional: [
      { name: "thisMech" },
      { name: "token id" },
      { name: "innerToken", type: null }
    ]
  }
};

// [APPLICATION n] → the structure it is. These numbers are the protocol's own
// and are the same list krb5_messages.js's APPLICATION carries; the two are
// checked against each other by tests/krb5_field_names.js rather than one being
// imported into the other, because this module must stay loadable on its own.
var APPLICATIONS = {
  0: "GSS-InitialContextToken",
  1: "Ticket",
  2: "Authenticator",
  3: "EncTicketPart",
  10: "AS-REQ",
  11: "AS-REP",
  // A TGS-REQ is a KDC-REQ with a different application tag and the same
  // fields, and likewise the reply — named separately so the strip says which
  // exchange this is, since that is the question a reader of a TGS-REQ's bytes
  // most often has.
  12: "TGS-REQ",
  13: "TGS-REP",
  14: "AP-REQ",
  15: "AP-REP",
  20: "KRB-SAFE",
  21: "KRB-PRIV",
  22: "KRB-CRED",
  25: "EncASRepPart",
  26: "EncTGSRepPart",
  27: "EncAPRepPart",
  28: "EncKrbPrivPart",
  29: "EncKrbCredPart",
  30: "KRB-ERROR"
};

// The aliases: structures that ARE another structure under a second name. A
// TGS-REQ is a KDC-REQ, and RFC 4120 section 5.4.2 records that an AS-REP's
// enc-part is encoded with EncTGSRepPart's tag by real implementations — so
// both numbers have to reach the same fields or the hex view would name a
// field on one exchange and refuse to on the other.
var ALIASES = {
  "TGS-REQ": "AS-REQ",
  "TGS-REP": "AS-REP",
  "EncASRepPart": "EncKDCRepPart",
  "EncTGSRepPart": "EncKDCRepPart"
};

function structure(name) {
  log.debug("Entering structure().");
  var resolved = ALIASES[name] || name;
  log.debug("Leaving structure().");
  return TYPES[resolved] || null;
}

function typeForApplication(number) {
  log.debug("Entering typeForApplication().");
  log.debug("Leaving typeForApplication().");
  return APPLICATIONS[number] || null;
}

// The naming context a walk starts from. Nothing is known yet: the first
// element decides, and if it is not an [APPLICATION n] this module has nothing
// to say about it and says so by naming nothing.
function rootContext() {
  log.debug("Entering rootContext().");
  log.debug("Leaving rootContext().");
  return { state: "root", type: null, name: null, index: 0 };
}

// ---------------------------------------------------------------------------
// One step of the walk.
//
// `tag` is the raw ASN.1 tag byte, `position` the element's index among its
// siblings. Returns
//
//   { label, type, context }
//
// where `label` is the path segment this element contributes — **the empty
// string for an element that is structure rather than field**, which is what
// keeps `AS-REQ → req-body → cname` from reading `AS-REQ → SEQUENCE →
// req-body → SEQUENCE → cname` — `type` the structure it is (for the strip to
// name), and `context` what to pass in for its children.
// ---------------------------------------------------------------------------
function step(context, tag, position) {
  log.debug("Entering step().");
  var ctx = context || rootContext();
  var cls = tag & 0xc0;
  var number = tag & 0x1f;

  // An application tag re-roots the naming wherever it turns up, because it
  // says what it is. This is what makes a Ticket inside a KDC-REP, an
  // Authenticator inside an AP-REQ and a decrypted EncTicketPart pasted on its
  // own all name themselves identically.
  if (cls === 0x40) {
    var appType = typeForApplication(number);
    // Name it UNLESS the field that contains it already did. `ticket [5]
    // Ticket` is one thing with two names, and `AS-REP → ticket → Ticket →
    // realm` says the same word twice on the way to the field somebody is
    // actually pointing at. Where nothing named it — the outermost element, an
    // unrecognised context, or a field whose type this table does not declare
    // (a GSS token's innerToken) — the application tag is the only name there
    // is, and it is a good one.
    var namesItself = ctx.state !== "body" && ctx.state !== "fields";
    log.debug("Leaving step(). application " + number + " -> " + appType);
    return {
      label: (namesItself && appType) ? appType : "",
      known: !!appType,
      type: appType,
      // A positional structure has NO wrapper sequence — an
      // InitialContextToken's OID, token id and inner token are the
      // application element's own children — so it goes straight to
      // `positional`. Sending it through `body` swallowed the OID as if it
      // were the wrapper, and the AP-REQ a service is actually handed came out
      // with every field named as a child of the token rather than of itself.
      context: appType
        ? {
            state: (structure(appType) || {}).positional ? "positional" :
                "body",
            type: appType,
            name: appType,
            index: 0
          }
        : { state: "unknown", type: null, name: null, index: 0 }
    };
  }

  if (ctx.state === "body") {
    var here = structure(ctx.type);
    // The SEQUENCE that carries the fields. It contributes no segment: it is
    // the structure the segment above already named.
    if (here && here.positional) {
      log.debug("Leaving step(). positional body.");
      return {
        label: "",
        known: true,
        type: ctx.type,
        context: { state: "positional", type: ctx.type, name: ctx.name,
            index: 0 }
      };
    }
    log.debug("Leaving step(). body.");
    return {
      label: "",
      known: true,
      type: ctx.type,
      context: { state: "fields", type: ctx.type, name: ctx.name, index: 0 }
    };
  }

  if (ctx.state === "positional") {
    var positions = (structure(ctx.type) || {}).positional || [];
    var slot = positions[position] || null;
    log.debug("Leaving step(). positional " + position);
    return {
      label: slot ? slot.name : "",
      known: !!slot,
      type: null,
      context: slot && slot.type
        ? { state: "body", type: slot.type, name: slot.name, index: 0 }
        : { state: "value", type: null, name: slot ? slot.name : null,
            index: 0 }
    };
  }

  if (ctx.state === "fields" && cls === 0x80) {
    var fields = (structure(ctx.type) || {}).fields || {};
    var field = fields[number];
    if (!field) {
      // A tag this table does not know — a field the codec grew, or an
      // extension. It must come back marked `known: false`, and that flag is
      // load-bearing rather than informational: an unrecognised element with
      // an empty label INHERITS its parent's path, so without the flag a
      // stray `[9]` inside a req-body would be shown as `AS-REQ → req-body`
      // and read as that field. An invented name is worse than none because
      // it is believed. tests/krb5_field_names.js takes `nonce` out of this
      // table and requires the coverage check to notice; it did not, until
      // this flag existed.
      log.debug("Leaving step(). unknown field [" + number + "].");
      return {
        label: "",
        known: false,
        type: null,
        context: { state: "unknown", type: null, name: null, index: 0 }
      };
    }
    var childContext;
    if (Object.prototype.hasOwnProperty.call(field, "of")) {
      // SEQUENCE OF: the [k] wrapper holds a SEQUENCE whose elements are the
      // items. Two levels, so `seqof` absorbs the SEQUENCE.
      childContext = { state: "seqof", type: field.of, name: field.name,
          index: 0 };
    } else if (field.type) {
      childContext = { state: "body", type: field.type, name: field.name,
          index: 0 };
    } else {
      childContext = { state: "value", type: null, name: field.name,
          index: 0 };
    }
    log.debug("Leaving step(). field " + field.name);
    return { label: field.name, known: true, type: field.type || null,
        context: childContext };
  }

  if (ctx.state === "seqof") {
    log.debug("Leaving step(). seqof.");
    return {
      label: "",
      known: true,
      type: null,
      context: { state: "items", type: ctx.type, name: ctx.name, index: 0 }
    };
  }

  if (ctx.state === "items") {
    var itemName = (ctx.name || "item") + "[" + position + "]";
    log.debug("Leaving step(). item " + position);
    return {
      label: itemName,
      known: true,
      // `padata[0]` REPLACES `padata` in the path rather than following it:
      // `padata → padata[0]` says the same word twice, and the reason the
      // index exists is to tell one element of the list from another.
      replaces: true,
      type: ctx.type,
      // An item IS the structure's sequence — there is no wrapper around it the
      // way there is around a field's value — so its children are fields
      // directly. Handing back `body` here consumed one level too many and left
      // every member of every SEQUENCE OF unnamed: padata[0]'s own
      // `padata-type` and `padata-value` came out blank, which is precisely the
      // pre-authentication data this workflow exists to look at.
      context: ctx.type
        ? { state: "fields", type: ctx.type, name: itemName, index: 0 }
        : { state: "value", type: null, name: itemName, index: 0 }
    };
  }

  if (ctx.state === "value") {
    // The primitive (or the constructed value of a field with no named type)
    // inside a [k] wrapper. It IS the field, so it keeps the field's name and
    // adds no segment of its own.
    log.debug("Leaving step(). value.");
    return {
      label: "",
      known: true,
      type: null,
      context: { state: "value", type: null, name: ctx.name, index: 0 }
    };
  }

  log.debug("Leaving step(). nothing known.");
  return {
    label: "",
    known: false,
    type: null,
    context: { state: "unknown", type: null, name: null, index: 0 }
  };
}

module.exports = {
  TYPES: TYPES,
  APPLICATIONS: APPLICATIONS,
  ALIASES: ALIASES,
  structure: structure,
  typeForApplication: typeForApplication,
  rootContext: rootContext,
  step: step
};
