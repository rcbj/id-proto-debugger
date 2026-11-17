// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: bbs2023.js
//
// ---------------------------------------------------------------------------
// The `bbs-2023` Data Integrity cryptosuite, as W3C "Data Integrity BBS
// Cryptosuites v1.0" (vc-di-bbs) defines it — base proof, derived proof and
// the verification of a derived proof — over the selective-disclosure
// functions of VC Data Integrity 1.1 (skolemization, the HMAC-shuffled blank
// node labels, JSON-pointer selection, the mandatory / non-mandatory split).
//
// BBS signs an ORDERED LIST OF MESSAGES and a credential is a graph. RDF
// Dataset Canonicalization (RDFC-1.0) turns one into the other: the document's
// N-Quads, canonically labelled and sorted, are the list. bbs-2023 then
//
//   * relabels every blank node with an HMAC of its canonical label, sorted
//     into b0, b1, ... ("shuffled"), so the labels a verifier sees say nothing
//     about the document they were cut from;
//   * splits the statements by the issuer's MANDATORY POINTERS: the mandatory
//     ones are hashed into the BBS header and are always revealed, the rest
//     are the BBS messages, each one selectively disclosable;
//   * hands the holder a BASE proof (CBOR tag 0xd95d02: the BBS signature,
//     the header, the issuer's public key, the HMAC key and the mandatory
//     pointers), from which the holder makes a DERIVED proof (tag 0xd95d03:
//     the BBS proof, the compressed label map, the mandatory and selective
//     indexes and the presentation header) over a REVEAL DOCUMENT — the
//     credential cut down to the pointers chosen;
//   * has the verifier canonicalize that reveal document itself, relabel it
//     with the label map, split it by the mandatory indexes and run BBS
//     ProofVerify. Nothing the verifier checks is a statement the holder
//     handed over ready-made.
//
// Only the "baseline" feature option is implemented: the anonymous holder
// binding and pseudonym options (tags 0xd95d04 to 0xd95d09) depend on IETF
// drafts the specification marks at risk, and a proof using one is refused by
// name rather than misread.
//
// Until #470 this module built a NON-STANDARD envelope instead —
// {cryptosuite, proof, disclosedStatements, disclosedIndexes, proofOptions},
// the statements handed to the verifier verbatim — which no other
// implementation reads. That shape is gone, and isPreW3cEnvelope() exists only
// so the Verifier can say what it is when one arrives.
//
// Every operation has a pure-JS path: BBS is ./bbs, SHA-256 and HMAC are
// @noble/hashes, and canonicalization is handed a @noble SHA-256 so that
// rdf-canonize never reaches for crypto.subtle (which a page on plain http
// does not have).
//
// No DOM: tests/bbs2023_cryptosuite.js drives it in node against the
// specification's own test vectors and against Digital Bazaar's independent
// implementation, in both directions.
// ---------------------------------------------------------------------------

var jsonld = require("jsonld");
var bbs = require("./bbs");
var bytes = require("./crypto_bytes");
var cbor = require("./cbor");
// The deterministic CBOR ENCODER; cbor.js only decodes.
var mdoc = require("./mdoc");
// base58btc, for the Multikey form of a BBS public key.
var didLib = require("./did");
var nobleSha256 = require("@noble/hashes/sha256").sha256;
var nobleHmac = require("@noble/hashes/hmac").hmac;

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "bbs2023",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var CRYPTOSUITE = "bbs-2023";
var PROOF_TYPE = "DataIntegrityProof";

// The contexts this workflow issues against, served from memory so that signing
// never depends on fetching a context over the network — which would make the
// signature depend on someone else's uptime, and on these pages would be
// blocked by CORS as often as not.
var IDENTITY_CONTEXT_URL = "https://idptools.com/contexts/identity/v1";
var CONTEXTS = {
  "https://www.w3.org/ns/credentials/v2": require(
      "./contexts/credentials_v2.json"),
  "https://www.w3.org/2018/credentials/v1": require(
      "./contexts/credentials_v1.json"),
  // This deployment's own terms. A credential must use a context that DEFINES
  // every claim it carries: canonicalization runs in `safe` mode, which refuses
  // to drop a term that does not expand to an absolute IRI. That refusal is the
  // point — silently dropping one would mean the issuer signs fewer statements
  // than the credential appears to contain, and a verifier would never know.
  "https://idptools.com/contexts/identity/v1": require(
      "./contexts/idptools_identity_v1.json")
};

// ---------------------------------------------------------------------------
// CONTEXTS SUPPLIED AT RUN TIME (2026-11-12).
//
// The set above is what this wallet SHIPS, and it holds only standard
// contexts plus this project's own. An issuer's own vocabulary is not shipped:
// a wallet that baked in each issuer's context would be a wallet built for
// those issuers. So a context an issuer uses is HANDED to the wallet — pasted
// on the presentation page, or given to addContext() by a caller — and kept in
// localStorage so that it survives the page loads of one workflow.
//
// It is still never FETCHED, for the reason the loader below gives: what this
// wallet canonicalizes against is exactly the document somebody supplied, and
// the person who supplied it can see it. A supplied context never replaces a
// shipped one of the same URL.
// ---------------------------------------------------------------------------
var SUPPLIED_CONTEXTS_KEY = "vc_jsonld_contexts";
var suppliedInMemory = {};

function storage() {
  log.debug("Entering storage().");
  try {
    if (typeof localStorage !== "undefined" && localStorage) {
      log.debug("Leaving storage(). localStorage.");
      return localStorage;
    }
  } catch (e) {
    // Storage refused (a sandboxed frame, a private window's quota).
    log.debug("storage(): " + e.message);
  }
  log.debug("Leaving storage(). None; memory only.");
  return null;
}

function storedContexts() {
  log.debug("Entering storedContexts().");
  var store = storage();
  if (!store) {
    log.debug("Leaving storedContexts(). No storage.");
    return {};
  }
  try {
    var parsed = JSON.parse(store.getItem(SUPPLIED_CONTEXTS_KEY) || "{}");
    log.debug("Leaving storedContexts().");
    return (parsed && typeof parsed === "object") ? parsed : {};
  } catch (e) {
    log.debug("Leaving storedContexts(). Unreadable: " + e.message);
    return {};
  }
}

// Every supplied context, url -> document: the stored ones, then the ones
// handed in this process (which win, being the more recent statement).
function suppliedContexts() {
  log.debug("Entering suppliedContexts().");
  log.debug("Leaving suppliedContexts().");
  return Object.assign({}, storedContexts(), suppliedInMemory);
}

// Record a context for `url`. `document` is the JSON-LD document itself, as an
// object or as JSON text, and must carry an "@context". Answers the URL.
function addContext(url, document) {
  log.debug("Entering addContext(). " + url);
  var name = String(url || "").trim();
  // No quote or angle bracket either: a context URL is an IRI, and the
  // presentation page writes it into markup.
  if (!/^https?:\/\/[^\s"'<>`]+$/.test(name)) {
    log.debug("Leaving addContext(). Not a URL.");
    throw new Error("A context is identified by the http(s) URL a " +
        "credential names it by in its @context; got " +
        JSON.stringify(url) + ".");
  }
  if (CONTEXTS[name]) {
    log.debug("Leaving addContext(). Shipped already.");
    throw new Error(name + " is a context this wallet ships; a supplied " +
        "document cannot replace it.");
  }
  var doc = document;
  if (typeof doc === "string") {
    try {
      doc = JSON.parse(doc);
    } catch (e) {
      log.debug("Leaving addContext(). Not JSON.");
      throw new Error("The context for " + name + " is not JSON: " +
          e.message);
    }
  }
  if (!doc || typeof doc !== "object" || !doc["@context"]) {
    log.debug("Leaving addContext(). No @context.");
    throw new Error("The document for " + name + " has no \"@context\" " +
        "member, so it is not a JSON-LD context.");
  }
  suppliedInMemory[name] = doc;
  var store = storage();
  if (store) {
    var all = storedContexts();
    all[name] = doc;
    store.setItem(SUPPLIED_CONTEXTS_KEY, JSON.stringify(all));
  }
  log.debug("Leaving addContext().");
  return name;
}

function removeContext(url) {
  log.debug("Entering removeContext(). " + url);
  delete suppliedInMemory[url];
  var store = storage();
  if (store) {
    var all = storedContexts();
    delete all[url];
    store.setItem(SUPPLIED_CONTEXTS_KEY, JSON.stringify(all));
  }
  log.debug("Leaving removeContext().");
}

function documentLoader(url) {
  log.debug("Entering documentLoader().");
  if (CONTEXTS[url]) {
    log.debug("Leaving documentLoader().");
    return Promise.resolve({ contextUrl: null, documentUrl: url,
                           document: CONTEXTS[url] });
  }
  var supplied = suppliedContexts();
  if (supplied[url]) {
    log.debug("Leaving documentLoader(). Supplied.");
    return Promise.resolve({ contextUrl: null, documentUrl: url,
                           document: supplied[url] });
  }
  // Deliberately not fetched. A context this workflow does not ship, and
  // nobody supplied, is a context whose canonical form cannot be guaranteed
  // to match the other side's.
  log.debug("Leaving documentLoader().");
  return Promise.reject(new Error(
    "bbs-2023 here will only use a JSON-LD context it ships (" +
    Object.keys(CONTEXTS).join(", ") + ") or one it has been given. It " +
    "was asked for " + url + ", which is neither: add that context's " +
    "document on the presentation page (JSON-LD Contexts) and try again."));
}


// ---------------------------------------------------------------------------
// Constants of the cryptosuite.
// ---------------------------------------------------------------------------

// The CBOR tags (major type 6, 16-bit argument 0x5dXX) that begin a decoded
// proofValue. Only the baseline pair is implemented; the others are named so
// a proof using one is refused for what it is.
var BASE_PROOF_HEADER = [0xd9, 0x5d, 0x02];
var DERIVED_PROOF_HEADER = [0xd9, 0x5d, 0x03];
var FEATURE_HEADERS = {
  0x04: "anonymous_holder_binding (base)",
  0x05: "anonymous_holder_binding (derived)",
  0x06: "pseudonym (base)",
  0x07: "pseudonym (derived)",
  0x08: "holder_binding_pseudonym (base)",
  0x09: "holder_binding_pseudonym (derived)"
};

// The multicodec of a BLS12-381 G2 public key (bls12_381-g2-pub, 0xeb) as an
// unsigned varint: the two bytes a Multikey puts before the 96-byte key.
var MULTIKEY_BLS12381_G2 = [0xeb, 0x01];
var BBS_PUBLIC_KEY_LENGTH = 96;
var BBS_SIGNATURE_LENGTH = 80;
var BBS_HEADER_LENGTH = 64;
var HMAC_KEY_LENGTH = 32;

// What an issuer here makes mandatory when it is told nothing else: who
// issued the credential, what it is, and when it is valid. A pointer the
// document does not have is left out rather than failed on.
var DEFAULT_MANDATORY_POINTERS = ["/issuer", "/type", "/validFrom",
                                  "/validUntil"];

var PRE_W3C_ENVELOPE = "this is the pre-W3C non-standard bbs-2023 envelope " +
  "({cryptosuite, proof, disclosedStatements, disclosedIndexes, " +
  "proofOptions}) this debugger's wallet sent before #470. It is not W3C " +
  "Data Integrity BBS Cryptosuites v1.0, where a presentation is a reveal " +
  "document carrying a DataIntegrityProof whose proofValue is a derived " +
  "proof (CBOR tag 0xd95d03), and the verifier rebuilds the statements " +
  "itself rather than being handed them. Refused.";

// The Verifier is the one caller: an object with the old envelope's
// members and none of a JSON-LD document's.
function isPreW3cEnvelope(value) {
  log.debug("Entering isPreW3cEnvelope().");
  var is = !!value && typeof value === "object" && !Array.isArray(value) &&
      value.cryptosuite === CRYPTOSUITE && !value["@context"] &&
      ("disclosedStatements" in value || "disclosedIndexes" in value ||
       "proofOptions" in value);
  log.debug("Leaving isPreW3cEnvelope(). " + is);
  return is;
}

// ---------------------------------------------------------------------------
// Hashing and canonicalization, pure JS.
// ---------------------------------------------------------------------------
function sha256(data) {
  log.debug("Entering sha256().");
  log.debug("Leaving sha256().");
  return nobleSha256(data);
}

function hmacSha256(key, data) {
  log.debug("Entering hmacSha256().");
  log.debug("Leaving hmacSha256().");
  return nobleHmac(nobleSha256, key, data);
}

// rdf-canonize's MessageDigest interface, over @noble's SHA-256. RDFC-1.0
// makes one per blank node per round, so neither method logs — the hot-path
// exception, stated as the style notes require.
function pureJsMessageDigest() {
  var text = "";
  return {
    update: function update(msg) {
      text += msg;
    },
    digest: function digest() {
      return bytes.bytesToHex(nobleSha256(bytes.strBytes(text)));
    }
  };
}

// RDFC-1.0 of a JSON-LD document, or of N-Quads text. `idMap`, when given, is
// filled with input blank node label -> canonical label.
function canonize(input, idMap) {
  log.debug("Entering canonize().");
  var canonizeOptions = { algorithm: "RDFC-1.0",
                          createMessageDigest: pureJsMessageDigest };
  if (idMap) canonizeOptions.canonicalIdMap = idMap;
  var options = { documentLoader: documentLoader, safe: true, base: null,
                  rdfDirection: "i18n-datatype",
                  format: "application/n-quads",
                  canonizeOptions: canonizeOptions };
  if (typeof input === "string") {
    options.inputFormat = "application/n-quads";
  }
  log.debug("Leaving canonize().");
  return jsonld.canonize(input, options).then(function (text) {
    return String(text);
  });
}

// N-Quads text as one string per statement, each ending in "\n".
function nquadLines(text) {
  log.debug("Entering nquadLines().");
  log.debug("Leaving nquadLines().");
  return String(text).split("\n").filter(function (line) {
    return line !== "";
  }).map(function (line) {
    return line + "\n";
  });
}

function withoutPrefix(label) {
  log.debug("Entering withoutPrefix().");
  log.debug("Leaving withoutPrefix().");
  return String(label).indexOf("_:") === 0 ? String(label).slice(2) :
    String(label);
}

// The canonical statements of `input` (a document or N-Quads text), with
// every blank node relabelled by `labelFactory`, which is given the map of
// input label -> canonical label and answers input label -> new label. The
// result is sorted, which the new labels make necessary (VC Data Integrity
// 1.1, labelReplacementCanonicalizeNQuads).
async function relabelledCanonicalStatements(input, labelFactory) {
  log.debug("Entering relabelledCanonicalStatements().");
  var raw = new Map();
  var text = await canonize(input, raw);
  var canonicalIdMap = new Map();
  raw.forEach(function (c14n, from) {
    canonicalIdMap.set(withoutPrefix(from), withoutPrefix(c14n));
  });
  var labelMap = labelFactory(canonicalIdMap);
  var c14nToNew = new Map();
  labelMap.forEach(function (label, from) {
    c14nToNew.set(canonicalIdMap.get(from), label);
  });
  var statements = nquadLines(text).map(function (line) {
    return line.replace(/_:([^\s]+)/g, function (m, label) {
      if (!c14nToNew.has(label)) {
        throw new Error("blank node _:" + label + " has no replacement " +
                        "label.");
      }
      return "_:" + c14nToNew.get(label);
    });
  }).sort();
  log.debug("Leaving relabelledCanonicalStatements(). " + statements.length +
            " statement(s).");
  return { statements: statements, labelMap: labelMap };
}

// bbs-2023's label factory (vc-di-bbs, createShuffledIdLabelMapFunction): the
// HMAC of each canonical label, as multibase base64url, sorted; a node's new
// label is "b" and its position in that order.
function shuffledLabels(hmacKey) {
  log.debug("Entering shuffledLabels().");
  log.debug("Leaving shuffledLabels().");
  return function shuffle(canonicalIdMap) {
    log.debug("Entering shuffle().");
    var hmacIds = new Map();
    canonicalIdMap.forEach(function (c14n, from) {
      hmacIds.set(from, "u" + bytes.bytesToB64u(
        hmacSha256(hmacKey, bytes.strBytes(c14n))));
    });
    var sorted = Array.from(hmacIds.values()).sort();
    var out = new Map();
    hmacIds.forEach(function (id, from) {
      out.set(from, "b" + sorted.indexOf(id));
    });
    log.debug("Leaving shuffle(). " + out.size + " label(s).");
    return out;
  };
}

// The verifier's factory: the label map the derived proof carries, keyed by
// the canonical labels of the reveal document.
function labelsFromMap(labelMap) {
  log.debug("Entering labelsFromMap().");
  log.debug("Leaving labelsFromMap().");
  return function fromMap(canonicalIdMap) {
    log.debug("Entering fromMap().");
    var out = new Map();
    canonicalIdMap.forEach(function (c14n, from) {
      if (!labelMap.has(c14n)) {
        throw new Error("the derived proof's label map has no entry for " +
                        "the reveal document's blank node _:" + c14n +
                        ", so the document is not the one the proof was " +
                        "derived for.");
      }
      out.set(from, labelMap.get(c14n));
    });
    log.debug("Leaving fromMap().");
    return out;
  };
}

// ---------------------------------------------------------------------------
// Skolemization (VC Data Integrity 1.1, section 3.4): every blank node is
// given a temporary IRI so that a JSON pointer selection of the document
// still names the SAME nodes the whole document does.
// ---------------------------------------------------------------------------
var SKOLEM_PREFIX = "urn:bnid:";

function deepCopy(value) {
  log.debug("Entering deepCopy().");
  log.debug("Leaving deepCopy().");
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

// Recursive over every node and value of an expanded document, so it carries
// no Entering/Leaving pair — the hot-path exception; skolemizeExpanded()
// below is its logged entry point.
function skolemizeItems(items, labeler) {
  return items.map(function (element) {
    if (!element || typeof element !== "object" ||
        element["@value"] !== undefined) {
      return deepCopy(element);
    }
    var node = {};
    Object.keys(element).forEach(function (property) {
      var value = element[property];
      node[property] = Array.isArray(value) ?
        skolemizeItems(value, labeler) : skolemizeItems([value], labeler)[0];
    });
    // A list or set object is not a node and has no identifier to give.
    if (node["@list"] !== undefined || node["@set"] !== undefined) {
      return node;
    }
    if (node["@id"] === undefined) {
      node["@id"] = SKOLEM_PREFIX + "_" + labeler.random + "_" +
        (labeler.count++);
    } else if (String(node["@id"]).indexOf("_:") === 0) {
      node["@id"] = SKOLEM_PREFIX + node["@id"].slice(2);
    }
    return node;
  });
}

function skolemizeExpanded(expanded) {
  log.debug("Entering skolemizeExpanded().");
  var labeler = { random: bytes.bytesToHex(bytes.randomBytes(16)),
                  count: 0 };
  log.debug("Leaving skolemizeExpanded().");
  return skolemizeItems(expanded, labeler);
}

// The document expanded and skolemized, and that compacted back under the
// document's own @context — which is what JSON pointers are applied to.
async function skolemize(document) {
  log.debug("Entering skolemize().");
  var expanded = await jsonld.expand(document,
    { documentLoader: documentLoader, safe: true });
  var skolemized = skolemizeExpanded(expanded);
  var compact = await jsonld.compact(skolemized, document["@context"],
    { documentLoader: documentLoader, safe: true });
  log.debug("Leaving skolemize().");
  return { expanded: skolemized, compact: compact };
}

// A skolemized document's N-Quads, the skolem IRIs turned back into blank
// node labels.
async function deskolemizedStatements(document) {
  log.debug("Entering deskolemizedStatements().");
  if (!document) {
    log.debug("Leaving deskolemizedStatements(). Nothing selected.");
    return [];
  }
  var text = await jsonld.toRDF(document, { documentLoader: documentLoader,
    safe: true, rdfDirection: "i18n-datatype",
    format: "application/n-quads" });
  log.debug("Leaving deskolemizedStatements().");
  return nquadLines(text).map(function (line) {
    return line.replace(/<urn:bnid:([^>]+)>/g, "_:$1");
  });
}

// ---------------------------------------------------------------------------
// JSON pointers (RFC 6901) and selection (VC Data Integrity 1.1,
// selectJsonLd).
// ---------------------------------------------------------------------------
function parsePointer(pointer) {
  log.debug("Entering parsePointer(). " + pointer);
  var text = String(pointer);
  if (text !== "" && text.charAt(0) !== "/") {
    log.debug("Leaving parsePointer(). Not a pointer.");
    throw new Error(JSON.stringify(pointer) + " is not a JSON pointer.");
  }
  var out = text.split("/").slice(1).map(function (segment) {
    if (/^(0|[1-9][0-9]*)$/.test(segment)) {
      return parseInt(segment, 10);
    }
    return segment.replace(/~1/g, "/").replace(/~0/g, "~");
  });
  log.debug("Leaving parsePointer().");
  return out;
}

function pointerFor(path) {
  log.debug("Entering pointerFor().");
  log.debug("Leaving pointerFor().");
  return path.map(function (segment) {
    return "/" + String(segment).replace(/~/g, "~0").replace(/\//g, "~1");
  }).join("");
}

// A selection begins with what identifies the object: a non-blank id, and
// its type.
function initialSelection(source, selection) {
  log.debug("Entering initialSelection().");
  var out = selection || {};
  if (source && typeof source.id === "string" &&
      source.id.indexOf("_:") !== 0) {
    out.id = source.id;
  }
  if (source && source.type !== undefined) {
    out.type = source.type;
  }
  log.debug("Leaving initialSelection().");
  return out;
}

function selectPath(document, pointer, path, selection, arrays) {
  log.debug("Entering selectPath(). " + pointer);
  var value = document;
  var selectedParent = selection;
  var selectedValue = selection;
  for (var i = 0; i < path.length; i++) {
    selectedParent = selectedValue;
    var parentValue = value;
    value = (parentValue && typeof parentValue === "object") ?
      parentValue[path[i]] : undefined;
    if (value === undefined) {
      log.debug("Leaving selectPath(). No match.");
      throw new Error("JSON pointer " + JSON.stringify(pointer) +
                      " does not match the document.");
    }
    selectedValue = selectedParent[path[i]];
    if (selectedValue === undefined) {
      if (Array.isArray(value)) {
        selectedValue = [];
        arrays.push(selectedValue);
      } else {
        selectedValue = initialSelection(value);
      }
      selectedParent[path[i]] = selectedValue;
    }
  }
  var chosen;
  if (typeof value !== "object" || value === null) {
    chosen = value;
  } else if (Array.isArray(value)) {
    chosen = deepCopy(value);
  } else {
    chosen = Object.assign({}, selectedValue, deepCopy(value));
  }
  selectedParent[path[path.length - 1]] = chosen;
  log.debug("Leaving selectPath().");
}

// The part of `document` the pointers name, with every object on the way
// keeping its id and type, and the @context kept whole. null when nothing is
// selected.
function selectJsonLd(document, pointers) {
  log.debug("Entering selectJsonLd(). " + pointers.length + " pointer(s).");
  if (!pointers.length) {
    log.debug("Leaving selectJsonLd(). Nothing selected.");
    return null;
  }
  var arrays = [];
  var selection = initialSelection(document,
    { "@context": deepCopy(document["@context"]) });
  for (var i = 0; i < pointers.length; i++) {
    var path = parsePointer(pointers[i]);
    if (!path.length) {
      log.debug("Leaving selectJsonLd(). The whole document.");
      return deepCopy(document);
    }
    selectPath(document, pointers[i], path, selection, arrays);
  }
  // A sparse array from selecting /x/2 but not /x/0 is made dense.
  arrays.forEach(function (array) {
    for (var j = array.length - 1; j >= 0; j--) {
      if (array[j] === undefined) array.splice(j, 1);
    }
  });
  log.debug("Leaving selectJsonLd().");
  return selection;
}

// canonicalizeAndGroup (VC Data Integrity 1.1): the document's relabelled
// canonical statements, and for each named group of pointers the statements
// it selects ("matching", index -> statement) and those it does not.
async function canonicalizeAndGroup(document, labelFactory, groups) {
  log.debug("Entering canonicalizeAndGroup().");
  var skolemized = await skolemize(document);
  var deskolemized = await deskolemizedStatements(skolemized.expanded);
  var canonical = await relabelledCanonicalStatements(deskolemized.join(""),
                                                      labelFactory);
  var out = {};
  var names = Object.keys(groups);
  for (var n = 0; n < names.length; n++) {
    var selection = selectJsonLd(skolemized.compact, groups[names[n]]);
    var selectedRaw = await deskolemizedStatements(selection);
    var selected = selectedRaw.map(function (line) {
      return line.replace(/_:([^\s]+)/g, function (m, label) {
        return "_:" + canonical.labelMap.get(label);
      });
    });
    var matching = new Map();
    var nonMatching = new Map();
    canonical.statements.forEach(function (statement, index) {
      if (selected.indexOf(statement) !== -1) {
        matching.set(index, statement);
      } else {
        nonMatching.set(index, statement);
      }
    });
    out[names[n]] = { matching: matching, nonMatching: nonMatching,
                      deskolemized: selectedRaw };
  }
  log.debug("Leaving canonicalizeAndGroup().");
  return { groups: out, labelMap: canonical.labelMap,
           statements: canonical.statements };
}

// ---------------------------------------------------------------------------
// The two proof values (vc-di-bbs sections 3.2.1 to 3.2.4).
// ---------------------------------------------------------------------------
function startsWith(data, prefix) {
  log.debug("Entering startsWith().");
  for (var i = 0; i < prefix.length; i++) {
    if (data[i] !== prefix[i]) {
      log.debug("Leaving startsWith(). No.");
      return false;
    }
  }
  log.debug("Leaving startsWith(). Yes.");
  return true;
}

function multibaseDecode(proofValue, which) {
  log.debug("Entering multibaseDecode().");
  var text = String(proofValue || "");
  if (text.charAt(0) !== "u") {
    log.debug("Leaving multibaseDecode(). Not base64url.");
    throw new Error("the " + which + " proofValue is not multibase " +
                    "base64url-no-pad (it must begin with \"u\").");
  }
  log.debug("Leaving multibaseDecode().");
  return bytes.b64uToBytes(text.slice(1));
}

// Why a proofValue is not the kind expected, said as precisely as the bytes
// allow.
function headerProblem(data, expected, which) {
  log.debug("Entering headerProblem().");
  if (data[0] === 0xd9 && data[1] === 0x5d && FEATURE_HEADERS[data[2]]) {
    log.debug("Leaving headerProblem(). Feature option.");
    return "the proof uses the " + FEATURE_HEADERS[data[2]] + " feature " +
      "option, which this implementation does not support (only " +
      "baseline).";
  }
  if (data[0] === 0xd9 && data[1] === 0x5d &&
      (data[2] === 0x02 || data[2] === 0x03)) {
    log.debug("Leaving headerProblem(). The other kind.");
    return data[2] === 0x02 ? "this is a BASE proof (0xd95d02), which " +
      "only the holder should ever see; a verifier is given a derived " +
      "proof (0xd95d03)." : "this is a DERIVED proof (0xd95d03), and a " +
      "base proof (0xd95d02) was expected.";
  }
  if (data.length === BBS_SIGNATURE_LENGTH && which === "base") {
    log.debug("Leaving headerProblem(). Raw signature.");
    return "it is a bare 80-byte BBS signature, the pre-W3C non-standard " +
      "base proof; a W3C bbs-2023 base proof is CBOR beginning 0xd95d02.";
  }
  log.debug("Leaving headerProblem().");
  return "it does not begin with the bbs-2023 " + which + " proof header " +
    bytes.bytesToHex(new Uint8Array(expected)) + ".";
}

function isBytes(value, length) {
  log.debug("Entering isBytes().");
  log.debug("Leaving isBytes().");
  return value instanceof Uint8Array &&
    (length === undefined || value.length === length);
}

function isIndexList(value) {
  log.debug("Entering isIndexList().");
  log.debug("Leaving isIndexList().");
  return Array.isArray(value) && value.every(function (v) {
    return Number.isInteger(v) && v >= 0;
  });
}

function checkBaseComponents(c) {
  log.debug("Entering checkBaseComponents().");
  var problem = "";
  if (!isBytes(c.bbsSignature, BBS_SIGNATURE_LENGTH)) {
    problem = "bbsSignature must be " + BBS_SIGNATURE_LENGTH + " bytes";
  } else if (!isBytes(c.bbsHeader, BBS_HEADER_LENGTH)) {
    problem = "bbsHeader must be " + BBS_HEADER_LENGTH + " bytes";
  } else if (!isBytes(c.publicKey, BBS_PUBLIC_KEY_LENGTH)) {
    problem = "publicKey must be " + BBS_PUBLIC_KEY_LENGTH + " bytes";
  } else if (!isBytes(c.hmacKey, HMAC_KEY_LENGTH)) {
    problem = "hmacKey must be " + HMAC_KEY_LENGTH + " bytes";
  } else if (!Array.isArray(c.mandatoryPointers) ||
             !c.mandatoryPointers.every(function (p) {
               return typeof p === "string";
             })) {
    problem = "mandatoryPointers must be an array of strings";
  }
  if (problem) {
    log.debug("Leaving checkBaseComponents(). " + problem);
    throw new Error("malformed bbs-2023 base proof: " + problem + ".");
  }
  log.debug("Leaving checkBaseComponents().");
}

function serializeBaseProofValue(c) {
  log.debug("Entering serializeBaseProofValue().");
  checkBaseComponents(c);
  var body = mdoc.encode([c.bbsSignature, c.bbsHeader, c.publicKey,
                          c.hmacKey, c.mandatoryPointers]);
  log.debug("Leaving serializeBaseProofValue().");
  return "u" + bytes.bytesToB64u(bytes.concatBytes(
    new Uint8Array(BASE_PROOF_HEADER), body));
}

function parseBaseProofValue(proofValue) {
  log.debug("Entering parseBaseProofValue().");
  var data = multibaseDecode(proofValue, "base");
  if (!startsWith(data, BASE_PROOF_HEADER)) {
    log.debug("Leaving parseBaseProofValue(). Wrong header.");
    throw new Error("not a bbs-2023 base proof: " +
                    headerProblem(data, BASE_PROOF_HEADER, "base"));
  }
  var items = cbor.decode(data.slice(BASE_PROOF_HEADER.length));
  if (!Array.isArray(items) || items.length !== 5) {
    log.debug("Leaving parseBaseProofValue(). Not five components.");
    throw new Error("malformed bbs-2023 base proof: the CBOR is not an " +
                    "array of five components.");
  }
  var c = { bbsSignature: items[0], bbsHeader: items[1],
            publicKey: items[2], hmacKey: items[3],
            mandatoryPointers: items[4], featureOption: "baseline" };
  checkBaseComponents(c);
  log.debug("Leaving parseBaseProofValue().");
  return c;
}

// The label map travels as integers: c14nN -> bM becomes N -> M.
function compressLabelMap(labelMap) {
  log.debug("Entering compressLabelMap().");
  var out = new Map();
  labelMap.forEach(function (to, from) {
    var k = /^c14n(\d+)$/.exec(from);
    var v = /^b(\d+)$/.exec(to);
    if (!k || !v) {
      throw new Error("label map entry " + from + " -> " + to + " is not " +
                      "c14nN -> bM.");
    }
    out.set(parseInt(k[1], 10), parseInt(v[1], 10));
  });
  log.debug("Leaving compressLabelMap().");
  return out;
}

function decompressLabelMap(compressed) {
  log.debug("Entering decompressLabelMap().");
  if (!(compressed instanceof Map)) {
    log.debug("Leaving decompressLabelMap(). Not a map.");
    throw new Error("malformed bbs-2023 derived proof: the label map is " +
                    "not a CBOR map.");
  }
  var out = new Map();
  compressed.forEach(function (to, from) {
    if (!Number.isInteger(from) || from < 0 || !Number.isInteger(to) ||
        to < 0) {
      throw new Error("malformed bbs-2023 derived proof: a label map " +
                      "entry is not two non-negative integers.");
    }
    out.set("c14n" + from, "b" + to);
  });
  log.debug("Leaving decompressLabelMap().");
  return out;
}

function checkDerivedComponents(c) {
  log.debug("Entering checkDerivedComponents().");
  var problem = "";
  if (!isBytes(c.bbsProof)) {
    problem = "bbsProof must be a byte string";
  } else if (!isIndexList(c.mandatoryIndexes)) {
    problem = "mandatoryIndexes must be an array of non-negative integers";
  } else if (!isIndexList(c.selectiveIndexes)) {
    problem = "selectiveIndexes must be an array of non-negative integers";
  } else if (!isBytes(c.presentationHeader)) {
    problem = "presentationHeader must be a byte string";
  }
  if (problem) {
    log.debug("Leaving checkDerivedComponents(). " + problem);
    throw new Error("malformed bbs-2023 derived proof: " + problem + ".");
  }
  log.debug("Leaving checkDerivedComponents().");
}

function serializeDerivedProofValue(c) {
  log.debug("Entering serializeDerivedProofValue().");
  checkDerivedComponents(c);
  var body = mdoc.encode([c.bbsProof, compressLabelMap(c.labelMap),
                          c.mandatoryIndexes, c.selectiveIndexes,
                          c.presentationHeader]);
  log.debug("Leaving serializeDerivedProofValue().");
  return "u" + bytes.bytesToB64u(bytes.concatBytes(
    new Uint8Array(DERIVED_PROOF_HEADER), body));
}

function parseDerivedProofValue(proofValue) {
  log.debug("Entering parseDerivedProofValue().");
  var data = multibaseDecode(proofValue, "derived");
  if (!startsWith(data, DERIVED_PROOF_HEADER)) {
    log.debug("Leaving parseDerivedProofValue(). Wrong header.");
    throw new Error("not a bbs-2023 derived proof: " +
                    headerProblem(data, DERIVED_PROOF_HEADER, "derived"));
  }
  var items = cbor.decode(data.slice(DERIVED_PROOF_HEADER.length));
  if (!Array.isArray(items) || items.length !== 5) {
    log.debug("Leaving parseDerivedProofValue(). Not five components.");
    throw new Error("malformed bbs-2023 derived proof: the CBOR is not an " +
                    "array of five components (baseline).");
  }
  var c = { bbsProof: items[0], labelMap: decompressLabelMap(items[1]),
            mandatoryIndexes: items[2], selectiveIndexes: items[3],
            presentationHeader: items[4], featureOption: "baseline" };
  checkDerivedComponents(c);
  log.debug("Leaving parseDerivedProofValue().");
  return c;
}

// ---------------------------------------------------------------------------
// The BBS public key as a Multikey: "z" + base58btc(0xeb01 || key).
// ---------------------------------------------------------------------------
function publicKeyToMultikey(publicKey) {
  log.debug("Entering publicKeyToMultikey().");
  if (!isBytes(publicKey, BBS_PUBLIC_KEY_LENGTH)) {
    log.debug("Leaving publicKeyToMultikey(). Wrong length.");
    throw new Error("a BLS12-381 G2 public key is " +
                    BBS_PUBLIC_KEY_LENGTH + " bytes.");
  }
  log.debug("Leaving publicKeyToMultikey().");
  return "z" + didLib.base58Encode(bytes.concatBytes(
    new Uint8Array(MULTIKEY_BLS12381_G2), publicKey));
}

function multikeyToPublicKey(multibase) {
  log.debug("Entering multikeyToPublicKey().");
  var text = String(multibase || "");
  if (text.charAt(0) !== "z") {
    log.debug("Leaving multikeyToPublicKey(). Not base58btc.");
    throw new Error("a BLS12-381 G2 Multikey is multibase base58btc (\"z\")" +
      (text.charAt(0) === "u" ? "; this is base64url (\"u\"), the pre-W3C " +
       "non-standard encoding of a raw BBS key" : "") + ".");
  }
  var data = didLib.base58Decode(text.slice(1));
  if (!startsWith(data, MULTIKEY_BLS12381_G2) ||
      data.length !== MULTIKEY_BLS12381_G2.length + BBS_PUBLIC_KEY_LENGTH) {
    log.debug("Leaving multikeyToPublicKey(). Not a G2 key.");
    throw new Error("the Multikey is not a BLS12-381 G2 public key " +
                    "(multicodec 0xeb, 96 bytes).");
  }
  log.debug("Leaving multikeyToPublicKey().");
  return data.slice(MULTIKEY_BLS12381_G2.length);
}

// ---------------------------------------------------------------------------
// The proof configuration and its hash.
// ---------------------------------------------------------------------------
function withoutProof(document) {
  log.debug("Entering withoutProof().");
  var out = deepCopy(document);
  delete out.proof;
  log.debug("Leaving withoutProof().");
  return out;
}

// The proof options without proofValue, under the document's @context
// (VC Data Integrity, Proof Configuration).
async function proofHash(document, proof) {
  log.debug("Entering proofHash().");
  var config = deepCopy(proof);
  delete config.proofValue;
  config["@context"] = deepCopy(document["@context"]);
  var text = await canonize(config);
  log.debug("Leaving proofHash().");
  return sha256(bytes.strBytes(text));
}

function asPresentationHeader(value) {
  log.debug("Entering asPresentationHeader().");
  if (value === undefined || value === null) {
    log.debug("Leaving asPresentationHeader(). Empty.");
    return new Uint8Array(0);
  }
  log.debug("Leaving asPresentationHeader().");
  return typeof value === "string" ? bytes.strBytes(value) :
    bytes.asBytes(value);
}

function theProof(secured) {
  log.debug("Entering theProof().");
  var proofs = [].concat((secured && secured.proof) || []);
  var found = proofs.filter(function (p) {
    return p && p.type === PROOF_TYPE && p.cryptosuite === CRYPTOSUITE;
  });
  if (found.length !== 1) {
    log.debug("Leaving theProof(). " + found.length + " found.");
    throw new Error(found.length ? "the document carries " + found.length +
      " bbs-2023 proofs; exactly one is expected." : "the document " +
      "carries no DataIntegrityProof with cryptosuite bbs-2023.");
  }
  log.debug("Leaving theProof().");
  return found[0];
}

// The default mandatory pointers this document has.
function defaultMandatoryPointers(document) {
  log.debug("Entering defaultMandatoryPointers().");
  log.debug("Leaving defaultMandatoryPointers().");
  return DEFAULT_MANDATORY_POINTERS.filter(function (pointer) {
    return document[pointer.slice(1)] !== undefined;
  });
}

// ---------------------------------------------------------------------------
// Create Base Proof (vc-di-bbs 3.3.1 and 3.3.2). The issuer's half.
//
// `options` are the proof options (verificationMethod, proofPurpose, and
// anything else the issuer wants signed; nothing is added — no `created`);
// `keys` is { secretKey (bigint), publicKey (96 bytes), mandatoryPointers
// (default: DEFAULT_MANDATORY_POINTERS the document has), hmacKey (32 bytes,
// default random) }. Answers { credential, mandatory, nonMandatory, ... }.
// ---------------------------------------------------------------------------
async function createBaseProof(unsecured, options, keys) {
  log.debug("Entering createBaseProof().");
  var k = keys || {};
  var document = withoutProof(unsecured);
  var proof = Object.assign({}, options || {});
  delete proof.proofValue;
  delete proof["@context"];
  proof.type = PROOF_TYPE;
  proof.cryptosuite = CRYPTOSUITE;
  if (!proof.proofPurpose) proof.proofPurpose = "assertionMethod";
  var mandatoryPointers = k.mandatoryPointers ||
      defaultMandatoryPointers(document);
  var hmacKey = k.hmacKey || bytes.randomBytes(HMAC_KEY_LENGTH);
  var hash = await proofHash(document, proof);
  var grouped = await canonicalizeAndGroup(document, shuffledLabels(hmacKey),
                                           { mandatory: mandatoryPointers });
  var mandatory = Array.from(grouped.groups.mandatory.matching.values());
  var nonMandatory = Array.from(
    grouped.groups.mandatory.nonMatching.values());
  var mandatoryHash = sha256(bytes.strBytes(mandatory.join("")));
  var bbsHeader = bytes.concatBytes(hash, mandatoryHash);
  var signature = bbs.sign(k.secretKey, k.publicKey, bbsHeader,
                           nonMandatory.map(bytes.strBytes));
  proof.proofValue = serializeBaseProofValue({ bbsSignature: signature,
    bbsHeader: bbsHeader, publicKey: k.publicKey, hmacKey: hmacKey,
    mandatoryPointers: mandatoryPointers });
  var credential = Object.assign({}, document, { proof: proof });
  log.debug("Leaving createBaseProof(). " + mandatory.length +
            " mandatory, " + nonMandatory.length + " selective.");
  return { credential: credential, proofHash: hash,
           mandatoryHash: mandatoryHash, mandatory: mandatory,
           nonMandatory: nonMandatory, bbsHeader: bbsHeader,
           signature: signature, hmacKey: hmacKey,
           mandatoryPointers: mandatoryPointers };
}

// ---------------------------------------------------------------------------
// Add Derived Proof (vc-di-bbs 3.3.3 and 3.3.4). The holder's half.
//
// `options` is { selectivePointers, presentationHeader (bytes or a string,
// UTF-8 encoded; default empty) }. Answers { document: the reveal document
// with its derived proof, mandatoryIndexes, selectiveIndexes,
// statementCount, ... }.
// ---------------------------------------------------------------------------
async function deriveProof(secured, options) {
  log.debug("Entering deriveProof().");
  var o = options || {};
  var proof = theProof(secured);
  var base = parseBaseProofValue(proof.proofValue);
  var selective = (o.selectivePointers || []).slice();
  if (!base.mandatoryPointers.length && !selective.length) {
    log.debug("Leaving deriveProof(). Nothing selected.");
    throw new Error("nothing is selected for disclosure: the base proof " +
                    "has no mandatory pointers and none were chosen.");
  }
  var document = withoutProof(secured);
  var presentationHeader = asPresentationHeader(o.presentationHeader);
  var combined = base.mandatoryPointers.concat(selective);
  var grouped = await canonicalizeAndGroup(document,
    shuffledLabels(base.hmacKey), { mandatory: base.mandatoryPointers,
      selective: selective, combined: combined });
  var g = grouped.groups;
  var mandatoryIndexes = [];
  var relative = 0;
  g.combined.matching.forEach(function (statement, index) {
    if (g.mandatory.matching.has(index)) mandatoryIndexes.push(relative);
    relative++;
  });
  var selectiveIndexes = [];
  relative = 0;
  g.mandatory.nonMatching.forEach(function (statement, index) {
    if (g.selective.matching.has(index)) selectiveIndexes.push(relative);
    relative++;
  });
  var messages = Array.from(g.mandatory.nonMatching.values())
    .map(bytes.strBytes);
  // A wallet that derives from a base proof it never checked reports the
  // issuer's mistake as its own: the verifier's "does not verify". The
  // header binds the proof options and the mandatory statements, the
  // signature the rest.
  var expectedHeader = bytes.concatBytes(await proofHash(document, proof),
    sha256(bytes.strBytes(Array.from(g.mandatory.matching.values())
      .join(""))));
  if (!bytes.bytesEqual(expectedHeader, base.bbsHeader) ||
      !bbs.verify(base.publicKey, base.bbsSignature, base.bbsHeader,
                  messages)) {
    log.debug("Leaving deriveProof(). Base signature invalid.");
    throw new Error("the issuer's base proof does not verify over this " +
                    "credential (altered after issuance, or signed " +
                    "differently), so no derived proof can be made from " +
                    "it.");
  }
  var revealDocument = selectJsonLd(document, combined);
  var revealIds = new Map();
  await canonize(g.combined.deskolemized.join(""), revealIds);
  var labelMap = new Map();
  revealIds.forEach(function (c14n, from) {
    labelMap.set(withoutPrefix(c14n),
                 grouped.labelMap.get(withoutPrefix(from)));
  });
  var bbsProof = bbs.proofGen(base.publicKey, base.bbsSignature,
    base.bbsHeader, presentationHeader, messages, selectiveIndexes);
  var derived = Object.assign({}, proof);
  delete derived["@context"];
  derived.proofValue = serializeDerivedProofValue({ bbsProof: bbsProof,
    labelMap: labelMap, mandatoryIndexes: mandatoryIndexes,
    selectiveIndexes: selectiveIndexes,
    presentationHeader: presentationHeader });
  revealDocument.proof = derived;
  log.debug("Leaving deriveProof(). " + selectiveIndexes.length + " of " +
            messages.length + " selective statement(s) disclosed.");
  return { document: revealDocument, mandatoryIndexes: mandatoryIndexes,
           selectiveIndexes: selectiveIndexes,
           statementCount: messages.length,
           mandatoryCount: g.mandatory.matching.size,
           labelMap: labelMap, presentationHeader: presentationHeader,
           publicKey: base.publicKey };
}

// ---------------------------------------------------------------------------
// Verify Derived Proof (vc-di-bbs 3.3.5, with VC Data Integrity 1.1's
// createVerifyData). The verifier's half, given the issuer's public key —
// which the caller resolves from verificationMethod and ties to the issuer.
//
// Answers { verified, reason, presentationHeader, mandatory, nonMandatory,
// mandatoryIndexes, selectiveIndexes }. Throws only for a call made wrongly;
// a document that does not verify is verified: false with the reason.
// ---------------------------------------------------------------------------
async function verifyDerivedProof(secured, publicKey) {
  log.debug("Entering verifyDerivedProof().");
  var out = { verified: false, reason: "" };
  if (isPreW3cEnvelope(secured)) {
    log.debug("Leaving verifyDerivedProof(). Pre-W3C envelope.");
    return Object.assign(out, { preW3c: true, reason: PRE_W3C_ENVELOPE });
  }
  var proof;
  var parsed;
  try {
    proof = theProof(secured);
    parsed = parseDerivedProofValue(proof.proofValue);
  } catch (e) {
    log.debug("Leaving verifyDerivedProof(). Unreadable proof.");
    return Object.assign(out, { reason: e.message });
  }
  out.presentationHeader = parsed.presentationHeader;
  out.mandatoryIndexes = parsed.mandatoryIndexes;
  out.selectiveIndexes = parsed.selectiveIndexes;
  var document = withoutProof(secured);
  var statements;
  var hash;
  try {
    hash = await proofHash(document, proof);
    statements = (await relabelledCanonicalStatements(document,
      labelsFromMap(parsed.labelMap))).statements;
  } catch (e) {
    log.debug("Leaving verifyDerivedProof(). Canonicalization failed.");
    return Object.assign(out, { reason: "the reveal document could not be " +
      "canonicalized (every context must be one this debugger ships or " +
      "was given, and every term defined): " + e.message });
  }
  var mandatory = [];
  var nonMandatory = [];
  statements.forEach(function (statement, index) {
    if (parsed.mandatoryIndexes.indexOf(index) !== -1) {
      mandatory.push(statement);
    } else {
      nonMandatory.push(statement);
    }
  });
  out.mandatory = mandatory;
  out.nonMandatory = nonMandatory;
  var badIndex = parsed.mandatoryIndexes.some(function (i) {
    return i >= statements.length;
  });
  if (badIndex || mandatory.length !== parsed.mandatoryIndexes.length) {
    log.debug("Leaving verifyDerivedProof(). Bad mandatory indexes.");
    return Object.assign(out, { reason: "the derived proof's " +
      "mandatoryIndexes do not fit the reveal document's " +
      statements.length + " statements." });
  }
  if (nonMandatory.length !== parsed.selectiveIndexes.length) {
    log.debug("Leaving verifyDerivedProof(). Count mismatch.");
    return Object.assign(out, { reason: "the reveal document has " +
      nonMandatory.length + " non-mandatory statement(s) and the proof " +
      "discloses " + parsed.selectiveIndexes.length + "." });
  }
  var ascending = parsed.selectiveIndexes.every(function (v, i, a) {
    return i === 0 || a[i - 1] < v;
  });
  if (!ascending) {
    log.debug("Leaving verifyDerivedProof(). Unsorted indexes.");
    return Object.assign(out, { reason: "the derived proof's " +
      "selectiveIndexes are not strictly ascending." });
  }
  var header = bytes.concatBytes(hash,
    sha256(bytes.strBytes(mandatory.join(""))));
  var ok = false;
  try {
    ok = bbs.proofVerify(publicKey, parsed.bbsProof, header,
                         parsed.presentationHeader,
                         nonMandatory.map(bytes.strBytes),
                         parsed.selectiveIndexes);
  } catch (e) {
    log.debug("verifyDerivedProof(): ProofVerify threw: " + e.message);
    ok = false;
  }
  log.debug("Leaving verifyDerivedProof(). " + ok);
  return Object.assign(out, { verified: ok, reason: ok ? "the BBS proof " +
    "verifies over the " + mandatory.length + " mandatory and " +
    nonMandatory.length + " selectively disclosed statement(s) of the " +
    "reveal document." : "the BBS proof does not verify (a revealed value " +
    "was altered, the presentation header differs, or it was derived from " +
    "a credential signed by another key)." });
}

// ---------------------------------------------------------------------------
// For the wallet: which pointers a credential offers, and which of them a
// DCQL claim path names.
// ---------------------------------------------------------------------------

// Every leaf of the document (a value that is not an object, or an empty
// one), as a JSON pointer with its value. The proof and the @context are not
// claims.
function leafPointers(document) {
  log.debug("Entering leafPointers().");
  var out = [];
  // Recursive over every value of the document, so it carries no
  // Entering/Leaving pair — the hot-path exception.
  var walk = function walk(value, path) {
    if (value !== null && typeof value === "object" &&
        Object.keys(value).length) {
      Object.keys(value).forEach(function (key) {
        var at = Array.isArray(value) ? parseInt(key, 10) : key;
        walk(value[key], path.concat([at]));
      });
      return;
    }
    out.push({ pointer: pointerFor(path), value: value });
  };
  Object.keys(document || {}).forEach(function (key) {
    if (key === "proof" || key === "@context") return;
    walk(document[key], [key]);
  });
  log.debug("Leaving leafPointers(). " + out.length + " leaf/leaves.");
  return out;
}

// The pointers a DCQL claims path (OpenID4VP 1.0 section 7) selects in the
// document: a string names a member, a number an array element, null every
// element. A path that leads nowhere selects nothing.
function claimPointers(document, claimPath) {
  log.debug("Entering claimPointers().");
  var found = [{ value: document, path: [] }];
  (claimPath || []).forEach(function (segment) {
    var next = [];
    found.forEach(function (at) {
      var v = at.value;
      if (segment === null && Array.isArray(v)) {
        v.forEach(function (item, i) {
          next.push({ value: item, path: at.path.concat([i]) });
        });
      } else if (typeof segment === "number" && Array.isArray(v) &&
                 v[segment] !== undefined) {
        next.push({ value: v[segment], path: at.path.concat([segment]) });
      } else if (typeof segment === "string" && v && typeof v === "object" &&
                 !Array.isArray(v) && v[segment] !== undefined) {
        next.push({ value: v[segment], path: at.path.concat([segment]) });
      }
    });
    found = next;
  });
  log.debug("Leaving claimPointers(). " + found.length + ".");
  return found.filter(function (at) {
    return at.path.length;
  }).map(function (at) {
    return pointerFor(at.path);
  });
}

// Whether `pointer` is `under` or inside it.
function pointerWithin(pointer, under) {
  log.debug("Entering pointerWithin().");
  log.debug("Leaving pointerWithin().");
  return pointer === under || pointer.indexOf(under + "/") === 0;
}

module.exports = {
  CRYPTOSUITE: CRYPTOSUITE,
  IDENTITY_CONTEXT_URL: IDENTITY_CONTEXT_URL,
  PROOF_TYPE: PROOF_TYPE,
  DEFAULT_MANDATORY_POINTERS: DEFAULT_MANDATORY_POINTERS,
  PRE_W3C_ENVELOPE: PRE_W3C_ENVELOPE,
  isPreW3cEnvelope: isPreW3cEnvelope,
  createBaseProof: createBaseProof,
  deriveProof: deriveProof,
  verifyDerivedProof: verifyDerivedProof,
  serializeBaseProofValue: serializeBaseProofValue,
  parseBaseProofValue: parseBaseProofValue,
  serializeDerivedProofValue: serializeDerivedProofValue,
  parseDerivedProofValue: parseDerivedProofValue,
  publicKeyToMultikey: publicKeyToMultikey,
  multikeyToPublicKey: multikeyToPublicKey,
  canonize: canonize,
  canonicalizeAndGroup: canonicalizeAndGroup,
  shuffledLabels: shuffledLabels,
  selectJsonLd: selectJsonLd,
  leafPointers: leafPointers,
  claimPointers: claimPointers,
  pointerWithin: pointerWithin,
  documentLoader: documentLoader,
  addContext: addContext,
  removeContext: removeContext,
  suppliedContexts: suppliedContexts,
  SUPPLIED_CONTEXTS_KEY: SUPPLIED_CONTEXTS_KEY
};
