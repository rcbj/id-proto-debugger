// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: cborld.js
//
// ---------------------------------------------------------------------------
// CBOR-LD 1.0 (W3C, https://www.w3.org/TR/cbor-ld/): a JSON-LD document
// compressed into CBOR by replacing every term with an integer and every
// value a context types with a shorter encoding. VC Barcodes (#480) is what
// it is for here: a credential small enough for a QR code beside an MRZ, or
// for a PDF417 field on a driver's licence.
//
// INTEROPERABILITY IS DIGITAL BAZAAR'S @digitalbazaar/cborld 8.1.0, AND THE
// DIFFERENCES FROM THE TR ARE ITS. Every published CBOR-LD payload was made
// by that library, and where its code and the TR's prose disagree the
// payloads follow the code. Each such place is marked [LIB] below; the ones
// that change bytes are:
//   * a term id is assigned when a context is first LOADED, in
//     Object.keys(context).sort() order, starting at 100 and stepping by 2
//     (id + 1 marks an array value) — so the numbering depends on the order
//     the walk meets scoped contexts, and a decoder must walk in the same
//     order (it sorts each map's entries by term name to do so);
//   * a URL-typed value equal to ANY term is written as that term's id;
//   * a type-table hit for url, none, xsd:date or xsd:dateTime is a BYTE
//     STRING, big-endian, one byte below 0xFF — so 255 is the two bytes
//     00 FF;
//   * a URL's "scheme" for the codec table is everything before its LAST
//     colon, so https://host:8443/x is not compressed;
//   * a protected term redefined by a property-scoped context keeps the NEW
//     definition.
// tests/cborld_engine.js holds this file to that library byte for byte.
//
// Framing: 0xD9CB1D (tag 51997) [registryEntryId, payload]. Entry 0 is an
// uncompressed CBOR rendering of the JSON; entry 1 is compression with an
// empty type table; any other entry names a type table, and 100 is VC
// Barcodes'. Decoding also reads the two earlier forms the library still
// accepts: tags 0x0600-0x06FF (7.x) and 0x0500/0x0501 (6.x).
//
// Contexts come from the same offline loader the Data Integrity proofs use
// (jsonld_contexts.js): a context nobody shipped or supplied is refused,
// because a different copy of it renumbers every term after it.
//
// NO DOM.
// ---------------------------------------------------------------------------

var cbor = require("./cbor");
var cbytes = require("./crypto_bytes");
var jsonldContexts = require("./jsonld_contexts");
var didLib = require("./did");

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "cborld",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var TAG_1_0 = 51997;
var TAG_LEGACY_RANGE_START = 0x0600;
var TAG_LEGACY_RANGE_END = 0x06ff;
var TAG_LEGACY_UNCOMPRESSED = 0x0500;
var TAG_LEGACY_COMPRESSED = 0x0501;

var XSD_DATE = "http://www.w3.org/2001/XMLSchema#date";
var XSD_DATETIME = "http://www.w3.org/2001/XMLSchema#dateTime";
var MULTIBASE = "https://w3id.org/security#multibase";
var CRYPTOSUITE_STRING = "https://w3id.org/security#cryptosuiteString";

// CBOR-LD section 6.4.1. Terms start at 100.
var KEYWORDS = [
  ["@context", 0], ["@type", 2], ["@id", 4], ["@value", 6],
  ["@direction", 8], ["@graph", 10], ["@included", 12], ["@index", 14],
  ["@json", 16], ["@language", 18], ["@list", 20], ["@nest", 22],
  ["@reverse", 24], ["@base", 26], ["@container", 28], ["@default", 30],
  ["@embed", 32], ["@explicit", 34], ["@none", 36], ["@omitDefault", 38],
  ["@prefix", 40], ["@preserve", 42], ["@protected", 44],
  ["@requireAll", 46], ["@set", 48], ["@version", 50], ["@vocab", 52],
  ["@propagate", 54]
];
var KEYWORD_IDS = new Map(KEYWORDS);
var FIRST_TERM_ID = 100;

// CBOR-LD section 6.5.3.1.
var URL_SCHEMES = [["http://", 1], ["https://", 2], ["urn:uuid:", 3],
                   ["data:", 4], ["did:v1:nym:", 1024], ["did:key:", 1025]];
var SCHEME_ID = new Map(URL_SCHEMES);
var SCHEME_OF_ID = new Map(URL_SCHEMES.map(function (e) {
  return [e[1], e[0]];
}));
var CODEC_SCHEMES = ["http", "https", "urn:uuid", "data", "did:v1:nym",
                     "did:key"];

// The cryptosuite table every Data Integrity registry entry shares.
var CRYPTOSUITES = [["ecdsa-rdfc-2019", 1], ["ecdsa-sd-2023", 2],
                    ["eddsa-rdfc-2022", 3], ["ecdsa-xi-2023", 4]];

// The registry entries this debugger knows, by id. 100 is VC Barcodes
// v1.0's (Examples 10, 17, 23 and 31 there).
var REGISTRY = {
  100: {
    name: "VC Barcodes v1.0",
    table: [
      ["context", [["https://www.w3.org/ns/credentials/v2", 32768],
                   ["https://w3id.org/vc-barcodes/v1", 32769],
                   ["https://w3id.org/utopia/v2", 32770]]],
      [CRYPTOSUITE_STRING, CRYPTOSUITES]
    ]
  }
};

// The 6.x global string table (legacy-singleton only).
var LEGACY_STRINGS = [
  ["https://www.w3.org/ns/activitystreams", 16],
  ["https://www.w3.org/2018/credentials/v1", 17],
  ["https://www.w3.org/ns/did/v1", 18],
  ["https://w3id.org/security/suites/ed25519-2018/v1", 19],
  ["https://w3id.org/security/suites/ed25519-2020/v1", 20],
  ["https://w3id.org/cit/v1", 21], ["https://w3id.org/age/v1", 22],
  ["https://w3id.org/security/suites/x25519-2020/v1", 23],
  ["https://w3id.org/veres-one/v1", 24], ["https://w3id.org/webkms/v1", 25],
  ["https://w3id.org/zcap/v1", 26],
  ["https://w3id.org/security/suites/hmac-2019/v1", 27],
  ["https://w3id.org/security/suites/aes-2019/v1", 28],
  ["https://w3id.org/vaccination/v1", 29],
  ["https://w3id.org/vc-revocation-list-2020/v1", 30],
  ["https://w3id.org/dcc/v1", 31], ["https://w3id.org/vc/status-list/v1", 32],
  ["https://www.w3.org/ns/credentials/v2", 33],
  ["https://w3id.org/security/data-integrity/v1", 48],
  ["https://w3id.org/security/multikey/v1", 49],
  ["https://purl.imsglobal.org/spec/ob/v3p0/context.json", 50],
  ["https://w3id.org/security/data-integrity/v2", 51]
];
// VC Barcodes Example 35: the appContextMap of a 6.x barcode.
var VCB_LEGACY_APP_CONTEXTS = [
  ["https://www.w3.org/ns/credentials/v2", 32768],
  ["https://w3id.org/vc-barcodes/v1", 32769],
  ["https://w3id.org/utopia/v2", 32770]
];

function CborldError(code, message) {
  log.debug("Entering CborldError(). " + code);
  var e = new Error(message);
  e.code = code;
  log.debug("Leaving CborldError().");
  return e;
}

// ---------------------------------------------------------------------------
// Type tables.
// ---------------------------------------------------------------------------

function toMap(table) {
  log.debug("Entering toMap().");
  var out;
  if (table instanceof Map) {
    out = new Map(table);
  } else if (Array.isArray(table)) {
    out = new Map(table);
  } else {
    out = new Map(Object.keys(table || {}).map(function (k) {
      return [k, table[k]];
    }));
  }
  log.debug("Leaving toMap().");
  return out;
}

// { type: { value: int } } in any of Map, entry-array or object form, with
// the three core subtables present (createTypeTable in the library).
function typeTableOf(table) {
  log.debug("Entering typeTableOf().");
  var outer = toMap(table);
  var out = new Map();
  outer.forEach(function (sub, type) {
    out.set(type, toMap(sub));
  });
  ["context", "url", "none"].forEach(function (core) {
    if (!out.has(core)) out.set(core, new Map());
  });
  [XSD_DATE.replace("date", "integer"),
   XSD_DATE.replace("date", "double"),
   XSD_DATE.replace("date", "boolean")].forEach(function (t) {
    if (out.has(t)) {
      log.debug("Leaving typeTableOf(). Literal type.");
      throw CborldError("ERR_UNSUPPORTED_LITERAL_TYPE", "a type table " +
                        "must not have a subtable for " + t + ".");
    }
  });
  log.debug("Leaving typeTableOf().");
  return out;
}

function legacyTypeTable(appContextMap) {
  log.debug("Entering legacyTypeTable().");
  var strings = new Map(LEGACY_STRINGS);
  toMap(appContextMap || []).forEach(function (v, k) {
    strings.set(k, v);
  });
  var out = new Map([["context", strings], ["url", strings],
                     ["none", strings],
                     [CRYPTOSUITE_STRING, new Map(CRYPTOSUITES)]]);
  log.debug("Leaving legacyTypeTable().");
  return out;
}

function reverseOf(table) {
  log.debug("Entering reverseOf().");
  var out = new Map();
  table.forEach(function (sub, type) {
    var r = new Map();
    sub.forEach(function (v, k) {
      r.set(v, k);
    });
    out.set(type, r);
  });
  log.debug("Leaving reverseOf().");
  return out;
}

// The type table for a registry entry: 1 is the empty one, a built-in
// entry is REGISTRY's, and anything else comes from the caller.
function tableFor(id, opts) {
  log.debug("Entering tableFor(). " + id);
  var o = opts || {};
  if (o.typeTable) {
    log.debug("Leaving tableFor(). Supplied.");
    return typeTableOf(o.typeTable);
  }
  if (id === 1) {
    log.debug("Leaving tableFor(). Empty.");
    return typeTableOf([]);
  }
  if (typeof o.typeTableLoader === "function") {
    var loaded = o.typeTableLoader({ registryEntryId: id });
    if (loaded) {
      log.debug("Leaving tableFor(). Loader.");
      return typeTableOf(loaded);
    }
  }
  if (REGISTRY[id]) {
    log.debug("Leaving tableFor(). Built in.");
    return typeTableOf(REGISTRY[id].table);
  }
  log.debug("Leaving tableFor(). Unknown.");
  throw CborldError("ERR_NO_TYPETABLE", "no type table for registry entry " +
                    id + " (this debugger knows " +
                    ["0", "1"].concat(Object.keys(REGISTRY)).join(", ") +
                    "; pass typeTable for another).");
}

// ---------------------------------------------------------------------------
// Contexts and term ids (ContextLoader.js and ActiveContext.js).
// ---------------------------------------------------------------------------

function ContextLoader(documentLoader) {
  log.debug("Entering ContextLoader().");
  this.documentLoader = documentLoader;
  this.contextMap = new Map();
  this.nextTermId = FIRST_TERM_ID;
  this.termToId = new Map(KEYWORD_IDS);
  this.idToTerm = new Map(KEYWORDS.map(function (e) {
    return [e[1], e[0]];
  }));
  log.debug("Leaving ContextLoader().");
}

ContextLoader.prototype.idFor = function (term, plural) {
  log.debug("Entering ContextLoader.idFor().");
  var id = this.termToId.get(term);
  log.debug("Leaving ContextLoader.idFor().");
  if (id === undefined) return term;
  return plural ? id + 1 : id;
};

ContextLoader.prototype.termFor = function (id) {
  log.debug("Entering ContextLoader.termFor().");
  if (typeof id === "string") {
    log.debug("Leaving ContextLoader.termFor(). Uncompressed.");
    return { term: id, plural: false };
  }
  if (typeof id !== "number" || !Number.isInteger(id) || id < 0) {
    log.debug("Leaving ContextLoader.termFor(). Not a term id.");
    throw CborldError("ERR_UNKNOWN_CBORLD_TERM_ID", "a map key " +
                      JSON.stringify(id) + " is neither a term id nor a " +
                      "term.");
  }
  var plural = (id & 1) === 1;
  var term = this.idToTerm.get(plural ? id - 1 : id);
  if (term === undefined) {
    log.debug("Leaving ContextLoader.termFor(). Unknown.");
    throw CborldError("ERR_UNKNOWN_CBORLD_TERM_ID", "term id " + id +
                      " is defined by none of the document's contexts (a " +
                      "different copy of a context renumbers every term " +
                      "after it).");
  }
  log.debug("Leaving ContextLoader.termFor().");
  return { term: term, plural: plural };
};

ContextLoader.prototype.document = async function (url) {
  log.debug("Entering ContextLoader.document(). " + url);
  var got;
  try {
    got = await this.documentLoader(url);
  } catch (e) {
    log.debug("Leaving ContextLoader.document(). Not loaded.");
    throw CborldError("ERR_CONTEXT_NOT_LOADED", "context " + url +
                      " could not be loaded: " + e.message);
  }
  var doc = got && got.document;
  if (typeof doc === "string") doc = JSON.parse(doc);
  if (!doc || typeof doc !== "object" || !doc["@context"]) {
    log.debug("Leaving ContextLoader.document(). No @context.");
    throw CborldError("ERR_CONTEXT_NOT_LOADED", "context " + url +
                      " has no @context member.");
  }
  log.debug("Leaving ContextLoader.document().");
  return doc;
};

ContextLoader.prototype.load = async function (context) {
  log.debug("Entering ContextLoader.load().");
  var entry = this.contextMap.get(context);
  if (entry) {
    log.debug("Leaving ContextLoader.load(). Cached.");
    return entry;
  }
  var ctx = context;
  var url;
  if (typeof context === "string") {
    url = context;
    ctx = (await this.document(url))["@context"];
  }
  if (Array.isArray(ctx)) {
    log.debug("Leaving ContextLoader.load(). Array.");
    throw CborldError("ERR_INVALID_CONTEXT", "context " + (url || "") +
                      " is an array; CBOR-LD loads one context object at " +
                      "a time.");
  }
  log.debug("Leaving ContextLoader.load().");
  return this.add(ctx, url);
};

ContextLoader.prototype.add = async function (context, url) {
  log.debug("Entering ContextLoader.add(). " + (url || "(inline)"));
  var importUrl = context["@import"];
  if (importUrl) {
    var imported = this.contextMap.get(importUrl);
    if (!imported) {
      imported = await this.add((await this.document(importUrl))["@context"],
                                importUrl);
    }
    context = Object.assign({}, imported.context, context);
  }
  var termMap = new Map();
  var entry = { context: context, termMap: termMap };
  var isProtected = !!context["@protected"];
  var keys = Object.keys(context).sort();
  for (var i = 0; i < keys.length; i++) {
    var key = keys[i];
    if (KEYWORD_IDS.has(key)) continue;
    var def = context[key];
    if (def === null) continue;
    if (typeof def === "string") {
      def = { "@id": def };
    } else if (Object.prototype.toString.call(def) !== "[object Object]") {
      log.debug("Leaving ContextLoader.add(). Bad definition.");
      throw CborldError("ERR_INVALID_TERM_DEFINITION", "the definition of " +
                        JSON.stringify(key) + " is neither a string nor " +
                        "an object.");
    }
    termMap.set(key, Object.assign({}, def, { protected: isProtected }));
    if (!this.termToId.has(key)) {
      var id = this.nextTermId;
      this.nextTermId += 2;
      this.termToId.set(key, id);
      this.idToTerm.set(id, key);
    }
  }
  this.contextMap.set(url || context, entry);
  log.debug("Leaving ContextLoader.add().");
  return entry;
};

function ActiveContext(termMap, previous, loader) {
  log.debug("Entering ActiveContext().");
  this.termMap = termMap || new Map();
  this.previous = previous || null;
  this.loader = loader || (previous && previous.loader);
  var typeTerms = ["@type"];
  this.termMap.forEach(function (def, term) {
    if (def["@id"] === "@type") typeTerms.push(term);
  });
  this.typeTerms = typeTerms;
  log.debug("Leaving ActiveContext().");
}

ActiveContext.prototype.definition = function (term) {
  log.debug("Entering ActiveContext.definition().");
  log.debug("Leaving ActiveContext.definition().");
  return this.termMap.get(term) || {};
};

ActiveContext.prototype.embedded = async function (contexts) {
  log.debug("Entering ActiveContext.embedded().");
  var termMap = await updateTermMap(this.termMap, contexts, this.loader,
                                    false, false);
  log.debug("Leaving ActiveContext.embedded().");
  return new ActiveContext(termMap, this);
};

ActiveContext.prototype.propertyScoped = async function (term) {
  log.debug("Entering ActiveContext.propertyScoped().");
  var def = this.termMap.get(term);
  var termMap = await updateTermMap(revertTermMap(this),
                                    def ? def["@context"] : undefined,
                                    this.loader, true, false);
  log.debug("Leaving ActiveContext.propertyScoped().");
  return new ActiveContext(termMap, this);
};

ActiveContext.prototype.typeScoped = async function (types) {
  log.debug("Entering ActiveContext.typeScoped().");
  var sorted = Array.from(types).sort();
  var termMap = this.termMap;
  for (var i = 0; i < sorted.length; i++) {
    var def = termMap.get(sorted[i]);
    termMap = await updateTermMap(termMap, def ? def["@context"] : undefined,
                                  this.loader, false, true);
  }
  log.debug("Leaving ActiveContext.typeScoped().");
  return new ActiveContext(termMap, this);
};

function deepEqual(a, b, top) {
  log.debug("Entering deepEqual().");
  var ao = a && typeof a === "object";
  var bo = b && typeof b === "object";
  if (ao !== bo) {
    log.debug("Leaving deepEqual(). Kinds differ.");
    return false;
  }
  if (!ao) {
    log.debug("Leaving deepEqual(). Scalars.");
    return a === b;
  }
  var ka = Object.keys(a);
  var kb = Object.keys(b);
  if (ka.length !== kb.length) {
    log.debug("Leaving deepEqual(). Key counts differ.");
    return false;
  }
  for (var i = 0; i < ka.length; i++) {
    var k = ka[i];
    if (top && (k === "protected" || k === "propagate")) continue;
    if (!deepEqual(a[k], b[k], false)) {
      log.debug("Leaving deepEqual(). Member differs.");
      return false;
    }
  }
  log.debug("Leaving deepEqual(). Equal.");
  return true;
}

function resolveCurie(activeTermMap, context, value) {
  log.debug("Entering resolveCurie().");
  var current = value;
  for (var guard = 0; guard < 64; guard++) {
    if (current === undefined || current.indexOf(":") === -1) break;
    var parts = current.split(":");
    var prefix = parts.shift();
    var def = context[prefix] !== undefined ? context[prefix] :
        activeTermMap.get(prefix);
    if (def === undefined) break;
    var id = typeof def === "string" ? def : (def && def["@id"]);
    current = id + parts.join(":");
  }
  log.debug("Leaving resolveCurie().");
  return current;
}

function resolveCuries(activeTermMap, context, newTermMap) {
  log.debug("Entering resolveCuries().");
  newTermMap.forEach(function (def, key) {
    if (def["@id"] !== undefined) {
      def["@id"] = resolveCurie(activeTermMap, context, def["@id"]);
    } else {
      var resolved = resolveCurie(activeTermMap, context, key);
      if (resolved.indexOf(":") !== -1) def["@id"] = resolved;
    }
    if (def["@type"] !== undefined) {
      def["@type"] = resolveCurie(activeTermMap, context, def["@type"]);
    }
    if (typeof def["@id"] !== "string") {
      throw CborldError("ERR_INVALID_TERM_DEFINITION", "the @id of " +
                        JSON.stringify(key) + " could not be determined.");
    }
  });
  log.debug("Leaving resolveCuries().");
}

// Non-propagating definitions fall back to the nearest propagating one an
// enclosing context had [LIB: the TR's loop never advances].
function revertTermMap(active) {
  log.debug("Entering revertTermMap().");
  var out = new Map();
  var held = [];
  active.termMap.forEach(function (def, term) {
    if (!def.propagate) {
      held.push(term);
    } else {
      out.set(term, def);
    }
  });
  held.forEach(function (term) {
    var ctx = active;
    var def;
    do {
      ctx = ctx.previous;
      def = ctx ? ctx.termMap.get(term) : undefined;
    } while (def !== undefined && !def.propagate);
    if (def !== undefined) out.set(term, def);
  });
  log.debug("Leaving revertTermMap().");
  return out;
}

async function updateTermMap(activeTermMap, contexts, loader, propertyScope,
                             typeScope) {
  log.debug("Entering updateTermMap().");
  var list = contexts === undefined ? [{}] :
      (Array.isArray(contexts) ? contexts : [contexts]);
  for (var i = 0; i < list.length; i++) {
    var entry = await loader.load(list[i]);
    var context = entry.context;
    var propagate = context["@propagate"] !== undefined &&
        context["@propagate"] !== null ? context["@propagate"] : !typeScope;
    var newTermMap = new Map();
    entry.termMap.forEach(function (v, k) {
      newTermMap.set(k, Object.assign({}, v, { propagate: propagate }));
    });
    resolveCuries(activeTermMap, context, newTermMap);
    activeTermMap.forEach(function (activeDef, term) {
      var def = newTermMap.get(term);
      if (def !== undefined) {
        // [LIB] The library checks a protected term's redefinition and then
        // keeps the NEW definition (its reassignment is to a local).
        if (activeDef.protected && !propertyScope &&
            !deepEqual(def, activeDef, true)) {
          throw CborldError("ERR_PROTECTED_TERM_REDEFINITION",
                            "protected term " + JSON.stringify(term) +
                            " is redefined.");
        }
      } else if (context[term] !== null) {
        newTermMap.set(term, Object.assign({}, activeDef));
      }
    });
    activeTermMap = newTermMap;
  }
  log.debug("Leaving updateTermMap().");
  return activeTermMap;
}

// ---------------------------------------------------------------------------
// Value codecs.
// ---------------------------------------------------------------------------

function tableTypeOf(term, def, termType) {
  log.debug("Entering tableTypeOf().");
  var url = term === "@id" || def["@id"] === "@id" || term === "@type" ||
      def["@id"] === "@type" || termType === "@id" || termType === "@vocab";
  log.debug("Leaving tableTypeOf().");
  return url ? "url" : (termType === undefined ? "none" : termType);
}

function bytesAsUint(n) {
  log.debug("Entering bytesAsUint(). " + n);
  var len = n < 0xff ? 1 : n < 0xffff ? 2 : n < 0xffffffff ? 4 : 8;
  if (!(n < Number.MAX_SAFE_INTEGER)) {
    log.debug("Leaving bytesAsUint(). Too large.");
    throw CborldError("ERR_COMPRESSION_VALUE_TOO_LARGE", n + " is too large.");
  }
  var out = new Uint8Array(len);
  var dv = new DataView(out.buffer);
  if (len === 1) dv.setUint8(0, n);
  if (len === 2) dv.setUint16(0, n);
  if (len === 4) dv.setUint32(0, n);
  if (len === 8) dv.setBigUint64(0, BigInt(n));
  log.debug("Leaving bytesAsUint().");
  return out;
}

function bytesAsInt(n) {
  log.debug("Entering bytesAsInt(). " + n);
  var len = n < 0x7f ? 1 : n < 0x7fff ? 2 : n < 0x7fffffff ? 4 : 8;
  if (!(n < Number.MAX_SAFE_INTEGER)) {
    log.debug("Leaving bytesAsInt(). Too large.");
    throw CborldError("ERR_COMPRESSION_VALUE_TOO_LARGE", n + " is too large.");
  }
  var out = new Uint8Array(len);
  var dv = new DataView(out.buffer);
  if (len === 1) dv.setInt8(0, n);
  if (len === 2) dv.setInt16(0, n);
  if (len === 4) dv.setInt32(0, n);
  if (len === 8) dv.setBigInt64(0, BigInt(n));
  log.debug("Leaving bytesAsInt().");
  return out;
}

function uintOfBytes(b) {
  log.debug("Entering uintOfBytes().");
  var dv = new DataView(b.buffer, b.byteOffset, b.length);
  log.debug("Leaving uintOfBytes().");
  if (b.length === 1) return dv.getUint8(0);
  if (b.length === 2) return dv.getUint16(0);
  if (b.length === 4) return dv.getUint32(0);
  throw CborldError("ERR_UNRECOGNIZED_BYTES", "a " + b.length + "-byte " +
                    "table value (only 1, 2 and 4 are written).");
}

function intOfBytes(b) {
  log.debug("Entering intOfBytes().");
  var dv = new DataView(b.buffer, b.byteOffset, b.length);
  if (b.length === 8) {
    var big = dv.getBigInt64(0);
    if (big > BigInt(Number.MAX_SAFE_INTEGER) ||
        big < -BigInt(Number.MAX_SAFE_INTEGER)) {
      log.debug("Leaving intOfBytes(). Too large.");
      throw CborldError("ERR_COMPRESSION_VALUE_TOO_LARGE", big + " is too " +
                        "large.");
    }
    log.debug("Leaving intOfBytes(). 8 bytes.");
    return Number(big);
  }
  log.debug("Leaving intOfBytes().");
  if (b.length === 1) return dv.getInt8(0);
  if (b.length === 2) return dv.getInt16(0);
  if (b.length === 4) return dv.getInt32(0);
  throw CborldError("ERR_UNRECOGNIZED_BYTES", "a " + b.length + "-byte " +
                    "integer.");
}

function base58Bytes(text) {
  log.debug("Entering base58Bytes().");
  try {
    var b = didLib.base58Decode(text);
    log.debug("Leaving base58Bytes().");
    return b;
  } catch (e) {
    log.debug("Leaving base58Bytes(). Not base58btc.");
    return null;
  }
}

var B64_STD = /^[A-Za-z0-9+/]*={0,2}$/;

function uuidBytes(text) {
  log.debug("Entering uuidBytes().");
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
      .test(text)) {
    log.debug("Leaving uuidBytes(). Not a UUID.");
    throw CborldError("ERR_INVALID_UUID", "urn:uuid:" + text + " is not a " +
                      "UUID (a lower-case urn:uuid value must be one).");
  }
  log.debug("Leaving uuidBytes().");
  return cbytes.hexToBytes(text.replace(/-/g, ""));
}

function uuidText(b) {
  log.debug("Entering uuidText().");
  var h = cbytes.bytesToHex(b);
  log.debug("Leaving uuidText().");
  return h.slice(0, 8) + "-" + h.slice(8, 12) + "-" + h.slice(12, 16) + "-" +
    h.slice(16, 20) + "-" + h.slice(20);
}

function didPart(text) {
  log.debug("Entering didPart().");
  if (text.charAt(0) === "z") {
    var b = base58Bytes(text.slice(1));
    if (b) {
      log.debug("Leaving didPart(). Bytes.");
      return b;
    }
  }
  log.debug("Leaving didPart(). Text.");
  return text;
}

// CBOR-LD section 6.5.3.
function encodeUrl(value, loader) {
  log.debug("Entering encodeUrl().");
  var termId = loader.idFor(value, false);
  if (typeof termId !== "string") {
    log.debug("Leaving encodeUrl(). A term.");
    return termId;
  }
  try {
    new URL(value);
  } catch (e) {
    log.debug("Leaving encodeUrl(). Not a URL.");
    return undefined;
  }
  // [LIB] Everything before the LAST colon.
  var split = value.split(":");
  split.pop();
  var scheme = split.join(":");
  if (CODEC_SCHEMES.indexOf(scheme) === -1) {
    log.debug("Leaving encodeUrl(). No codec for " + scheme + ".");
    return undefined;
  }
  var out;
  if (value.indexOf("https://") === 0) {
    out = [2, value.slice(8)];
  } else if (value.indexOf("http://") === 0) {
    out = [1, value.slice(7)];
  } else if (value.indexOf("urn:uuid:") === 0) {
    var rest = value.slice(9);
    out = [3, rest.toLowerCase() === rest ? uuidBytes(rest) : rest];
  } else if (value.indexOf("data:") === 0) {
    var m = /^data:(.*);base64,(.*)$/.exec(value);
    var data = m && B64_STD.test(m[2]) && m[2].length % 4 === 0 ?
        cbytes.b64ToBytes(m[2]) : null;
    out = data && cbytes.bytesToB64(data) === m[2] ? [4, m[1], data] :
        [4, value.slice(5)];
  } else {
    var prefix = value.indexOf("did:v1:nym:") === 0 ? "did:v1:nym:" :
        "did:key:";
    var parts = value.slice(prefix.length).split("#");
    out = [SCHEME_ID.get(prefix), didPart(parts[0])];
    if (parts.length > 1) out.push(didPart(parts[1]));
  }
  log.debug("Leaving encodeUrl().");
  return out;
}

function decodeUrl(value, loader) {
  log.debug("Entering decodeUrl().");
  if (typeof value === "string") {
    log.debug("Leaving decodeUrl(). Text.");
    return undefined;
  }
  if (!Array.isArray(value)) {
    log.debug("Leaving decodeUrl(). A term id.");
    return loader.termFor(value).term;
  }
  var scheme = SCHEME_OF_ID.get(value[0]);
  var out;
  if ((scheme === "http://" || scheme === "https://") && value.length === 2 &&
      typeof value[1] === "string") {
    out = scheme + value[1];
  } else if (scheme === "urn:uuid:" && value.length === 2 &&
      (typeof value[1] === "string" || value[1] instanceof Uint8Array)) {
    out = scheme + (typeof value[1] === "string" ? value[1] :
                    uuidText(value[1]));
  } else if (scheme === "data:" && value.length === 3 &&
      typeof value[1] === "string" && value[2] instanceof Uint8Array) {
    out = "data:" + value[1] + ";base64," + cbytes.bytesToB64(value[2]);
  } else if (scheme === "data:" && value.length === 2 &&
      typeof value[1] === "string") {
    out = "data:" + value[1];
  } else if ((scheme === "did:v1:nym:" || scheme === "did:key:") &&
      value.length > 1 && value.length <= 3) {
    out = scheme;
    [value[1], value[2]].forEach(function (part, i) {
      if (i === 1 && value.length < 3) return;
      var text = typeof part === "string" ? part :
          "z" + didLib.base58Encode(part);
      out += (i === 1 ? "#" : "") + text;
    });
  }
  if (out === undefined) {
    log.debug("Leaving decodeUrl(). Unknown form.");
    throw CborldError("ERR_UNKNOWN_COMPRESSED_VALUE", "an encoded URL of " +
                      "an unknown form (scheme id " +
                      JSON.stringify(value[0]) + ").");
  }
  log.debug("Leaving decodeUrl().");
  return out;
}

// CBOR-LD section 6.5.6: the multibase header byte, then the decoded bytes.
function encodeMultibase(value) {
  log.debug("Entering encodeMultibase().");
  if (typeof value !== "string") {
    log.debug("Leaving encodeMultibase(). Not text.");
    return undefined;
  }
  var head = value.charAt(0);
  var body;
  if (head === "z") {
    body = base58Bytes(value.slice(1));
  } else if (head === "u" || head === "M") {
    try {
      body = cbytes.b64uToBytes(value.slice(1));
    } catch (e) {
      body = null;
    }
  } else {
    log.debug("Leaving encodeMultibase(). Another base.");
    return undefined;
  }
  if (!body) {
    log.debug("Leaving encodeMultibase(). Undecodable.");
    throw CborldError("ERR_INVALID_MULTIBASE", "multibase value " +
                      JSON.stringify(value.slice(0, 40)) + " does not " +
                      "decode.");
  }
  log.debug("Leaving encodeMultibase().");
  return cbytes.concatBytes(new Uint8Array([head.charCodeAt(0)]), body);
}

function decodeMultibase(value) {
  log.debug("Entering decodeMultibase().");
  if (!(value instanceof Uint8Array) ||
      [0x7a, 0x75, 0x4d].indexOf(value[0]) === -1) {
    log.debug("Leaving decodeMultibase(). Not multibase.");
    return undefined;
  }
  var body = value.subarray(1);
  log.debug("Leaving decodeMultibase().");
  if (value[0] === 0x7a) return "z" + didLib.base58Encode(body);
  if (value[0] === 0x75) return "u" + cbytes.bytesToB64u(body);
  return "M" + cbytes.bytesToB64(body);
}

// CBOR-LD sections 6.5.4 and 6.5.5: seconds since the epoch, kept only when
// they reproduce the text exactly.
function encodeDate(value) {
  log.debug("Entering encodeDate().");
  if (typeof value !== "string" || value.indexOf("T") !== -1) {
    log.debug("Leaving encodeDate(). Not a date.");
    return undefined;
  }
  var parsed = Date.parse(value);
  if (isNaN(parsed)) {
    log.debug("Leaving encodeDate(). Unparseable.");
    return undefined;
  }
  var secs = Math.floor(parsed / 1000);
  var iso = new Date(secs * 1000).toISOString();
  log.debug("Leaving encodeDate().");
  return iso.slice(0, iso.indexOf("T")) === value ? secs : value;
}

function encodeDateTime(value) {
  log.debug("Entering encodeDateTime().");
  if (typeof value !== "string" || value.indexOf("T") === -1) {
    log.debug("Leaving encodeDateTime(). Not a dateTime.");
    return undefined;
  }
  var parsed = Date.parse(value);
  if (isNaN(parsed)) {
    log.debug("Leaving encodeDateTime(). Unparseable.");
    return undefined;
  }
  var secs = Math.floor(parsed / 1000);
  var dot = value.indexOf(".");
  if (dot === -1) {
    var whole = new Date(secs * 1000).toISOString().replace(".000Z", "Z");
    log.debug("Leaving encodeDateTime(). Seconds.");
    return whole === value ? secs : value;
  }
  var ms = parseInt(value.slice(dot + 1), 10);
  var exact = new Date(secs * 1000 + ms).toISOString() === value;
  log.debug("Leaving encodeDateTime(). Milliseconds.");
  return exact ? [secs, ms] : value;
}

function decodeDate(value) {
  log.debug("Entering decodeDate().");
  if (typeof value !== "number") {
    log.debug("Leaving decodeDate(). Not a number.");
    return undefined;
  }
  var iso = new Date(value * 1000).toISOString();
  log.debug("Leaving decodeDate().");
  return iso.slice(0, iso.indexOf("T"));
}

function decodeDateTime(value) {
  log.debug("Entering decodeDateTime().");
  if (typeof value === "number") {
    log.debug("Leaving decodeDateTime(). Seconds.");
    return new Date(value * 1000).toISOString().replace(".000Z", "Z");
  }
  if (Array.isArray(value) && value.length === 2 &&
      (typeof value[0] === "number" || typeof value[1] === "number")) {
    log.debug("Leaving decodeDateTime(). Milliseconds.");
    return new Date(value[0] * 1000 + value[1]).toISOString();
  }
  log.debug("Leaving decodeDateTime(). Not one.");
  return undefined;
}

function Codec(state) {
  log.debug("Entering Codec().");
  this.table = state.table;
  this.reverse = reverseOf(state.table);
  this.loader = state.loader;
  this.legacy = !!state.legacy;
  this.asBytes = ["none", XSD_DATE, XSD_DATETIME];
  if (!this.legacy) this.asBytes.push("url");
  log.debug("Leaving Codec().");
}

Codec.prototype.encode = function (value, term, def, termType) {
  log.debug("Entering Codec.encode().");
  var type = tableTypeOf(term, def, termType);
  if (type === "url" && typeof value !== "string") {
    log.debug("Leaving Codec.encode(). Not a URL string.");
    throw CborldError("ERR_UNSUPPORTED_JSON_TYPE", "the value of " +
                      JSON.stringify(term) + " is a URL and must be a " +
                      "string, not " + typeof value + ".");
  }
  var sub = this.table.get(type);
  if (sub) {
    var hit = sub.get(value);
    if (hit !== undefined) {
      log.debug("Leaving Codec.encode(). Table.");
      return this.asBytes.indexOf(type) !== -1 ? bytesAsUint(hit) : hit;
    }
    if (type !== "none" && Number.isInteger(value)) {
      log.debug("Leaving Codec.encode(). Integer as signed bytes.");
      return bytesAsInt(value);
    }
  }
  var out;
  if (type === "url") out = encodeUrl(value, this.loader);
  if (type === MULTIBASE) out = encodeMultibase(value);
  if (type === XSD_DATE) out = encodeDate(value);
  if (type === XSD_DATETIME) out = encodeDateTime(value);
  log.debug("Leaving Codec.encode().");
  return out === undefined ? value : out;
};

// Answers { value } when the value decodes as a whole; undefined for an
// array the walker recurses into.
Codec.prototype.decode = function (value, term, def, termType) {
  log.debug("Entering Codec.decode().");
  var type = tableTypeOf(term, def, termType);
  var sub = this.reverse.get(type);
  if (sub) {
    var isBytes = value instanceof Uint8Array;
    var bytesForm = this.asBytes.indexOf(type) !== -1;
    var key;
    var useTable = false;
    if (isBytes && bytesForm) {
      useTable = true;
      key = uintOfBytes(value);
    } else if (Number.isInteger(value) && !bytesForm) {
      useTable = true;
      key = value;
    }
    if (useTable) {
      var hit = sub.get(key);
      if (hit !== undefined) {
        log.debug("Leaving Codec.decode(). Table.");
        return { value: hit };
      }
      var legacyTerm = this.legacy && type === "url" &&
          this.loader.idToTerm.has(key);
      if (!legacyTerm) {
        log.debug("Leaving Codec.decode(). Not in the table.");
        throw CborldError("ERR_UNKNOWN_COMPRESSED_VALUE", "compressed " +
                          type + " value " + key + " is not in the type " +
                          "table.");
      }
    } else if (isBytes && type !== "none") {
      log.debug("Leaving Codec.decode(). Signed bytes.");
      return { value: intOfBytes(value) };
    }
  }
  var out;
  if (type === "url") out = decodeUrl(value, this.loader);
  if (type === MULTIBASE) out = decodeMultibase(value);
  if (type === XSD_DATE) out = decodeDate(value);
  if (type === XSD_DATETIME) out = decodeDateTime(value);
  if (out !== undefined) {
    log.debug("Leaving Codec.decode(). Codec.");
    return { value: out };
  }
  log.debug("Leaving Codec.decode().");
  return Array.isArray(value) ? undefined : { value: value };
};

// ---------------------------------------------------------------------------
// The walk (Converter.js, Compressor.js, Decompressor.js).
// ---------------------------------------------------------------------------

async function compressObject(codec, active, input) {
  log.debug("Entering compressObject().");
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    log.debug("Leaving compressObject(). Not an object.");
    throw CborldError("ERR_INVALID_DOCUMENT", "a JSON-LD node object was " +
                      "expected.");
  }
  var output = new Map();
  active = await active.embedded(input["@context"]);
  var context = input["@context"];
  if (context) {
    var plural = Array.isArray(context);
    var encoded = (plural ? context : [context]).map(function (c) {
      if (typeof c !== "string") return c;
      var id = codec.table.get("context").get(c);
      return id === undefined ? c : id;
    });
    output.set(plural ? 1 : 0, plural ? encoded : encoded[0]);
  }
  var types = new Set();
  active.typeTerms.forEach(function (t) {
    if (input[t] !== undefined) {
      [].concat(input[t]).forEach(function (v) {
        types.add(v);
      });
    }
  });
  active = await active.typeScoped(types);
  var keys = Object.keys(input).sort();
  for (var i = 0; i < keys.length; i++) {
    var key = keys[i];
    if (key === "@context") continue;
    var value = input[key];
    var isArray = Array.isArray(value);
    var termId = codec.loader.idFor(key, isArray);
    var def = active.definition(key);
    var valueCtx = await active.propertyScoped(key);
    var values = isArray ? value : [value];
    var outs = [];
    for (var j = 0; j < values.length; j++) {
      outs.push(await compressValue(codec, valueCtx, key, def, values[j]));
    }
    output.set(termId, isArray ? outs : outs[0]);
  }
  log.debug("Leaving compressObject().");
  return output;
}

async function compressValue(codec, active, term, def, value) {
  log.debug("Entering compressValue().");
  if (value === null) {
    log.debug("Leaving compressValue(). null.");
    return null;
  }
  if (typeof value !== "object") {
    log.debug("Leaving compressValue(). Scalar.");
    return codec.encode(value, term, def, def["@type"]);
  }
  if (Array.isArray(value)) {
    var outs = [];
    for (var i = 0; i < value.length; i++) {
      outs.push(await compressValue(codec, active, term, def, value[i]));
    }
    log.debug("Leaving compressValue(). Array.");
    return outs;
  }
  log.debug("Leaving compressValue(). Object.");
  return compressObject(codec, active, value);
}

function mapToObject(value) {
  log.debug("Entering mapToObject().");
  var out = value;
  if (Array.isArray(value)) {
    out = value.map(mapToObject);
  } else if (value instanceof Map) {
    out = {};
    value.forEach(function (v, k) {
      out[k] = mapToObject(v);
    });
  }
  log.debug("Leaving mapToObject().");
  return out;
}

function decodeContext(codec, value) {
  log.debug("Entering decodeContext().");
  if (typeof value !== "number") {
    log.debug("Leaving decodeContext(). Inline or text.");
    return mapToObject(value);
  }
  var url = codec.reverse.get("context").get(value);
  if (url === undefined) {
    log.debug("Leaving decodeContext(). Unknown id.");
    throw CborldError("ERR_UNDEFINED_COMPRESSED_CONTEXT", "context id " +
                      value + " is not in the type table.");
  }
  log.debug("Leaving decodeContext().");
  return url;
}

async function decompressObject(codec, active, input) {
  log.debug("Entering decompressObject().");
  if (!(input instanceof Map)) {
    log.debug("Leaving decompressObject(). Not a map.");
    throw CborldError("ERR_INVALID_DOCUMENT", "a compressed node is a CBOR " +
                      "map; this is " + Object.prototype.toString.call(input) +
                      ".");
  }
  var output = {};
  var one = input.get(0);
  var many = input.get(1);
  if (one) output["@context"] = decodeContext(codec, one);
  if (many) {
    if (one) {
      log.debug("Leaving decompressObject(). Both context keys.");
      throw CborldError("ERR_INVALID_ENCODED_CONTEXT", "both the singular " +
                        "and the plural @context keys are present.");
    }
    if (!Array.isArray(many)) {
      log.debug("Leaving decompressObject(). Plural context not an array.");
      throw CborldError("ERR_INVALID_ENCODED_CONTEXT", "the plural @context " +
                        "value is not an array.");
    }
    output["@context"] = many.map(function (c) {
      return decodeContext(codec, c);
    });
  }
  active = await active.embedded(output["@context"]);
  var types = new Set();
  active.typeTerms.forEach(function (typeTerm) {
    var id = codec.loader.idFor(typeTerm, false);
    if (typeof id === "string") return;
    var raw = input.has(id) ? input.get(id) : input.get(id + 1);
    if (raw === undefined) return;
    var info = codec.loader.termFor(id);
    [].concat(raw).forEach(function (v) {
      var d = codec.decode(v, info.term, active.definition(info.term),
                           "@vocab");
      types.add(d ? d.value : v);
    });
  });
  active = await active.typeScoped(types);
  var entries = [];
  input.forEach(function (value, key) {
    if (key === 0 || key === 1) return;
    var info = codec.loader.termFor(key);
    entries.push({ term: info.term, plural: info.plural, value: value });
  });
  entries.sort(function (a, b) {
    return a.term < b.term ? -1 : a.term > b.term ? 1 : 0;
  });
  for (var i = 0; i < entries.length; i++) {
    var e = entries[i];
    var def = active.definition(e.term);
    var valueCtx = await active.propertyScoped(e.term);
    if (e.plural && !Array.isArray(e.value)) {
      log.debug("Leaving decompressObject(). Plural not an array.");
      throw CborldError("ERR_INVALID_DOCUMENT", "term " +
                        JSON.stringify(e.term) + " has an odd (array) id " +
                        "and a value that is not an array.");
    }
    var values = e.plural ? e.value : [e.value];
    var outs = [];
    for (var j = 0; j < values.length; j++) {
      outs.push(await decompressValue(codec, valueCtx, e.term, def,
                                      values[j]));
    }
    output[e.term] = e.plural ? outs : outs[0];
  }
  log.debug("Leaving decompressObject().");
  return output;
}

async function decompressValue(codec, active, term, def, value) {
  log.debug("Entering decompressValue().");
  if (value === null) {
    log.debug("Leaving decompressValue(). null.");
    return null;
  }
  if (!(value instanceof Map)) {
    var d = codec.decode(value, term, def, def["@type"]);
    if (d) {
      log.debug("Leaving decompressValue(). Value.");
      return d.value;
    }
  }
  if (Array.isArray(value)) {
    var outs = [];
    for (var i = 0; i < value.length; i++) {
      outs.push(await decompressValue(codec, active, term, def, value[i]));
    }
    log.debug("Leaving decompressValue(). Array.");
    return outs;
  }
  log.debug("Leaving decompressValue(). Node.");
  return decompressObject(codec, active, value);
}

// ---------------------------------------------------------------------------
// CBOR, written the way cborg writes it: shortest heads, the shortest float
// that holds the value exactly, and map keys in RFC 8949 section 4.2.1
// order (which cborg's length-first sorter agrees with). Recursive and run
// per item, so it carries no Entering/Leaving pair — the hot-path exception
// the code style allows, stated as it requires.
// ---------------------------------------------------------------------------

function head(major, n) {
  if (n < 24) return [major << 5 | n];
  if (n < 0x100) return [major << 5 | 24, n];
  if (n < 0x10000) return [major << 5 | 25, n >> 8, n & 0xff];
  if (n < 0x100000000) {
    return [major << 5 | 26, (n >>> 24) & 0xff, (n >> 16) & 0xff,
            (n >> 8) & 0xff, n & 0xff];
  }
  var hi = Math.floor(n / 0x100000000);
  var lo = n >>> 0;
  return [major << 5 | 27, (hi >>> 24) & 0xff, (hi >> 16) & 0xff,
          (hi >> 8) & 0xff, hi & 0xff, (lo >>> 24) & 0xff, (lo >> 16) & 0xff,
          (lo >> 8) & 0xff, lo & 0xff];
}

function halfBits(v) {
  var f = new DataView(new ArrayBuffer(4));
  f.setFloat32(0, v);
  var x = f.getUint32(0);
  var sign = (x >>> 16) & 0x8000;
  var exp = ((x >>> 23) & 0xff) - 127 + 15;
  var mant = x & 0x7fffff;
  if (exp <= 0 || exp >= 31 || (mant & 0x1fff)) return null;
  return sign | (exp << 10) | (mant >> 13);
}

function floatParts(v) {
  if (Number.isNaN(v)) return [0xf9, 0x7e, 0x00];
  if (v === Infinity) return [0xf9, 0x7c, 0x00];
  if (v === -Infinity) return [0xf9, 0xfc, 0x00];
  if (Math.fround(v) === v) {
    var h = halfBits(v);
    if (h !== null) return [0xf9, h >> 8, h & 0xff];
    var f = new DataView(new ArrayBuffer(4));
    f.setFloat32(0, v);
    return [0xfa].concat(Array.prototype.slice.call(
      new Uint8Array(f.buffer)));
  }
  var d = new DataView(new ArrayBuffer(8));
  d.setFloat64(0, v);
  return [0xfb].concat(Array.prototype.slice.call(new Uint8Array(d.buffer)));
}

function compareBytes(a, b) {
  var n = Math.min(a.length, b.length);
  for (var i = 0; i < n; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

function encodeParts(v) {
  if (v === null) return [0xf6];
  if (v === undefined) return [0xf7];
  if (v === false) return [0xf4];
  if (v === true) return [0xf5];
  if (v instanceof Uint8Array) {
    return head(2, v.length).concat(Array.prototype.slice.call(v));
  }
  if (typeof v === "number") {
    if (Number.isSafeInteger(v) && !Object.is(v, -0)) {
      return v >= 0 ? head(0, v) : head(1, -1 - v);
    }
    return floatParts(v);
  }
  if (typeof v === "string") {
    var s = new TextEncoder().encode(v);
    return head(3, s.length).concat(Array.prototype.slice.call(s));
  }
  if (Array.isArray(v)) {
    var out = head(4, v.length);
    v.forEach(function (x) {
      out = out.concat(encodeParts(x));
    });
    return out;
  }
  var entries = v instanceof Map ? Array.from(v.entries()) :
      Object.keys(v).map(function (k) {
        return [k, v[k]];
      });
  var encoded = entries.map(function (e) {
    return { k: encodeParts(e[0]), v: encodeParts(e[1]) };
  }).sort(function (a, b) {
    return compareBytes(a.k, b.k);
  });
  var m = head(5, encoded.length);
  encoded.forEach(function (e) {
    m = m.concat(e.k, e.v);
  });
  return m;
}

function cborEncode(v) {
  log.debug("Entering cborEncode().");
  log.debug("Leaving cborEncode().");
  return new Uint8Array(encodeParts(v));
}

function varint(n) {
  log.debug("Entering varint().");
  var out = [];
  while (n >= 0x80) {
    out.push((n & 0x7f) | 0x80);
    n = Math.floor(n / 128);
  }
  out.push(n);
  log.debug("Leaving varint().");
  return out;
}

function unvarint(bytes) {
  log.debug("Entering unvarint().");
  var n = 0;
  var mul = 1;
  for (var i = 0; i < bytes.length; i++) {
    n += (bytes[i] & 0x7f) * mul;
    mul *= 128;
    var last = !(bytes[i] & 0x80);
    if (last !== (i === bytes.length - 1)) {
      log.debug("Leaving unvarint(). Not canonical.");
      throw CborldError("ERR_NOT_CBORLD", "the registry entry id's varint " +
                        "is malformed.");
    }
  }
  log.debug("Leaving unvarint().");
  return n;
}

// ---------------------------------------------------------------------------
// The API.
// ---------------------------------------------------------------------------

function loaderOf(opts) {
  log.debug("Entering loaderOf().");
  log.debug("Leaving loaderOf().");
  return (opts && opts.documentLoader) || jsonldContexts.documentLoader;
}

function prefixFor(format, id) {
  log.debug("Entering prefixFor(). " + format + " " + id);
  var out;
  if (format === "legacy-singleton") {
    out = [0xd9, 0x05, id === 0 ? 0x00 : 0x01];
  } else if (format === "legacy-range") {
    if (id < 128) {
      out = [0xd9, 0x06, id];
    } else {
      var v = varint(id);
      out = [0xd9, 0x06, v[0], 0x82].concat(Array.from(cborEncode(
        new Uint8Array(v.slice(1)))));
    }
  } else {
    out = [0xd9, 0xcb, 0x1d, 0x82].concat(Array.from(cborEncode(id)));
  }
  log.debug("Leaving prefixFor().");
  return new Uint8Array(out);
}

// opts: { registryEntryId (1 by default; 0 is uncompressed, 100 is VC
// Barcodes), typeTable (for an entry this module does not know),
// typeTableLoader, documentLoader, format ("cbor-ld-1.0" by default,
// "legacy-range" or "legacy-singleton"), appContextMap (legacy-singleton
// only) }. Answers the CBOR-LD bytes.
async function encode(doc, opts) {
  log.debug("Entering encode().");
  var o = opts || {};
  var format = o.format || "cbor-ld-1.0";
  if (["cbor-ld-1.0", "legacy-range", "legacy-singleton"]
      .indexOf(format) === -1) {
    log.debug("Leaving encode(). Unknown format.");
    throw CborldError("ERR_INVALID_FORMAT", "format " +
                      JSON.stringify(format) + " is not one of cbor-ld-1.0, " +
                      "legacy-range or legacy-singleton.");
  }
  var id = o.registryEntryId === undefined ? 1 : o.registryEntryId;
  if (format === "legacy-singleton") {
    id = o.compressionMode === 0 ? 0 : 1;
  }
  if (!Number.isInteger(id) || id < 0) {
    log.debug("Leaving encode(). Bad registry id.");
    throw CborldError("ERR_INVALID_REGISTRY_ENTRY_ID", "registryEntryId " +
                      "must be a non-negative integer.");
  }
  var payload;
  if (id === 0) {
    payload = cborEncode(doc);
  } else {
    var legacy = format === "legacy-singleton";
    var table = legacy ? legacyTypeTable(o.appContextMap) : tableFor(id, o);
    var loader = new ContextLoader(loaderOf(o));
    var codec = new Codec({ table: table, loader: loader, legacy: legacy });
    var root = new ActiveContext(new Map(), null, loader);
    var tree = Array.isArray(doc) ? [] : null;
    if (tree) {
      for (var i = 0; i < doc.length; i++) {
        tree.push(await compressObject(codec, root, doc[i]));
      }
    } else {
      tree = await compressObject(codec, root, doc);
    }
    payload = cborEncode(tree);
  }
  log.debug("Leaving encode(). " + payload.length + " payload bytes.");
  return cbytes.concatBytes(prefixFor(format, id), payload);
}

// The framing alone: { format, registryEntryId, compressed, payload }.
function parse(bytes) {
  log.debug("Entering parse().");
  var item;
  try {
    item = cbor.decode(bytes);
  } catch (e) {
    log.debug("Leaving parse(). Not CBOR.");
    throw CborldError("ERR_NOT_CBORLD", "not CBOR: " + e.message);
  }
  if (!(item instanceof cbor.Tagged)) {
    log.debug("Leaving parse(). Untagged.");
    throw CborldError("ERR_NOT_CBORLD", "CBOR-LD begins with a tag; this " +
                      "begins with something else.");
  }
  var tag = item.tag;
  var out;
  if (tag === TAG_1_0) {
    if (!Array.isArray(item.value) || item.value.length !== 2 ||
        !Number.isInteger(item.value[0]) || item.value[0] < 0) {
      log.debug("Leaving parse(). Bad 1.0 framing.");
      throw CborldError("ERR_NOT_CBORLD", "tag 51997 must enclose " +
                        "[registryEntryId, payload].");
    }
    out = { format: "cbor-ld-1.0", registryEntryId: item.value[0],
            payload: item.value[1] };
  } else if (tag >= TAG_LEGACY_RANGE_START && tag <= TAG_LEGACY_RANGE_END) {
    var start = tag - TAG_LEGACY_RANGE_START;
    if (start < 128) {
      out = { format: "legacy-range", registryEntryId: start,
              payload: item.value };
    } else {
      var v = item.value;
      if (!Array.isArray(v) || v.length !== 2 ||
          !(v[0] instanceof Uint8Array)) {
        log.debug("Leaving parse(). Bad legacy-range framing.");
        throw CborldError("ERR_NOT_CBORLD", "a legacy-range tag above " +
                          "0x067F must enclose [varint bytes, payload].");
      }
      out = { format: "legacy-range",
              registryEntryId: unvarint([start].concat(Array.from(v[0]))),
              payload: v[1] };
    }
  } else if (tag === TAG_LEGACY_UNCOMPRESSED ||
      tag === TAG_LEGACY_COMPRESSED) {
    out = { format: "legacy-singleton",
            registryEntryId: tag === TAG_LEGACY_COMPRESSED ? 1 : 0,
            payload: item.value };
  } else {
    log.debug("Leaving parse(). Unknown tag.");
    throw CborldError("ERR_NOT_CBORLD", "tag " + tag + " is not a CBOR-LD " +
                      "tag (51997, 0x0600-0x06FF, 0x0500 or 0x0501).");
  }
  out.compressed = out.registryEntryId !== 0;
  log.debug("Leaving parse(). " + out.format + " " + out.registryEntryId);
  return out;
}

// opts: { documentLoader, typeTable, typeTableLoader, appContextMap }.
// Answers the JSON-LD document.
async function decode(bytes, opts) {
  log.debug("Entering decode().");
  var o = opts || {};
  var framed = parse(bytes);
  if (!framed.compressed) {
    log.debug("Leaving decode(). Uncompressed.");
    return mapToObject(framed.payload);
  }
  var legacy = framed.format === "legacy-singleton";
  var table = legacy ? legacyTypeTable(o.appContextMap) :
      tableFor(framed.registryEntryId, o);
  var loader = new ContextLoader(loaderOf(o));
  var codec = new Codec({ table: table, loader: loader, legacy: legacy });
  var root = new ActiveContext(new Map(), null, loader);
  var out;
  if (Array.isArray(framed.payload)) {
    out = [];
    for (var i = 0; i < framed.payload.length; i++) {
      out.push(await decompressObject(codec, root, framed.payload[i]));
    }
  } else {
    out = await decompressObject(codec, root, framed.payload);
  }
  log.debug("Leaving decode().");
  return out;
}

module.exports = {
  REGISTRY: REGISTRY,
  KEYWORDS: KEYWORDS,
  VCB_LEGACY_APP_CONTEXTS: VCB_LEGACY_APP_CONTEXTS,
  encode: encode,
  decode: decode,
  parse: parse,
  cborEncode: cborEncode
};
