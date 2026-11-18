// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: di_selective.js
//
// ---------------------------------------------------------------------------
// The selective-disclosure functions of W3C VC Data Integrity 1.1, which
// every selective cryptosuite is specified over: bbs-2023 (bbs2023.js) and
// ecdsa-sd-2023 (ecdsa_sd_2023.js).
//
//   * RDFC-1.0 canonicalization, pure JS (an @noble SHA-256 is handed to
//     rdf-canonize so it never reaches for crypto.subtle);
//   * relabelling a document's canonical blank nodes with a label factory
//     (labelReplacementCanonicalizeNQuads), and the factories the suites
//     share: the HMAC labels ecdsa-sd-2023 uses (createHmacIdLabelMapFunction)
//     and the verifier's labels from a label map (createLabelMapFunction).
//     bbs-2023's shuffled factory stays in bbs2023.js, which defines it;
//   * skolemization, so a JSON pointer selection names the same nodes the
//     whole document does;
//   * JSON pointers (RFC 6901) and selectJsonLd;
//   * canonicalizeAndGroup: the document's relabelled statements, split by
//     named groups of pointers into matching and non-matching;
//   * the proof configuration's hash.
//
// It was the middle of bbs2023.js until #476, moved here unchanged except
// for hmacIdLabels(), when ecdsa-sd-2023 needed the same functions: one
// reading of the specification, so the two suites cannot disagree about it.
// bbs2023.js keeps every name it had.
//
// NO DOM.
// ---------------------------------------------------------------------------

var jsonld = require("jsonld");
var bytes = require("./crypto_bytes");
var nobleSha256 = require("@noble/hashes/sha256").sha256;
var nobleHmac = require("@noble/hashes/hmac").hmac;
var jsonldContexts = require("./jsonld_contexts");
var documentLoader = jsonldContexts.documentLoader;

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "di_selective",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

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

// ecdsa-sd-2023's label factory (VC Data Integrity 1.1,
// createHmacIdLabelMapFunction): each canonical label becomes "u" and the
// base64url HMAC of it — unsorted, unlike bbs-2023's shuffle.
function hmacIdLabels(hmacKey) {
  log.debug("Entering hmacIdLabels().");
  log.debug("Leaving hmacIdLabels().");
  return function hmacIds(canonicalIdMap) {
    log.debug("Entering hmacIds().");
    var out = new Map();
    canonicalIdMap.forEach(function (c14n, from) {
      out.set(from, "u" + bytes.bytesToB64u(
        hmacSha256(hmacKey, bytes.strBytes(c14n))));
    });
    log.debug("Leaving hmacIds(). " + out.size + " label(s).");
    return out;
  };
}

module.exports = {
  documentLoader: documentLoader,
  hmacIdLabels: hmacIdLabels,
  SKOLEM_PREFIX: SKOLEM_PREFIX,
  canonicalizeAndGroup: canonicalizeAndGroup,
  canonize: canonize,
  deepCopy: deepCopy,
  deskolemizedStatements: deskolemizedStatements,
  hmacSha256: hmacSha256,
  initialSelection: initialSelection,
  labelsFromMap: labelsFromMap,
  nquadLines: nquadLines,
  parsePointer: parsePointer,
  pointerFor: pointerFor,
  proofHash: proofHash,
  pureJsMessageDigest: pureJsMessageDigest,
  relabelledCanonicalStatements: relabelledCanonicalStatements,
  selectJsonLd: selectJsonLd,
  selectPath: selectPath,
  sha256: sha256,
  skolemize: skolemize,
  skolemizeExpanded: skolemizeExpanded,
  skolemizeItems: skolemizeItems,
  withoutPrefix: withoutPrefix,
  withoutProof: withoutProof
};
