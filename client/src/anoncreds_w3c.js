// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: anoncreds_w3c.js
//
// ---------------------------------------------------------------------------
// The W3C form of AnonCreds (#479): an AnonCreds credential and presentation
// as W3C Verifiable Credential Data Model documents, with a Data Integrity
// proof whose cryptosuite is `anoncreds-2023`, as anoncreds-rs 0.2.3 writes
// them (its W3cCredential and W3cPresentation; Hyperledger AnonCreds
// specification, "AnonCreds in W3C VC format").
//
// IT IS A RE-ENCODING, NOT ANOTHER SIGNATURE SCHEME. The CL signature, the
// primary and predicate proofs and the aggregated proof are exactly the
// legacy objects anoncreds.js makes and checks; the W3C form only moves
// them:
//   * the attribute values into credentialSubject (raw values, an integer
//     as a JSON number),
//   * everything else into a proofValue: "u" + base64url of MessagePack of
//     [kind, object], kind 1 a credential's signature, 2 a credential's
//     sub-proof inside a presentation, 3 the presentation's aggregated proof;
//   * every big number from a decimal string to its big-endian bytes, the
//     ids (schema_id, cred_def_id, rev_reg_id) and c_list (bytes already)
//     excepted.
// So conversion is both ways, and the engine signs and verifies unchanged.
// tests/anoncreds_engine.js holds the bytes to anoncreds-rs's.
//
// NO DOM.
// ---------------------------------------------------------------------------

var msgpack = require("./msgpack");
var anoncreds = require("./anoncreds");
var cbytes = require("./crypto_bytes");

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "anoncreds_w3c",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var CRYPTOSUITE = "anoncreds-2023";
var CONTEXT_V11 = ["https://www.w3.org/2018/credentials/v1",
                   "https://w3id.org/security/data-integrity/v2",
                   { "@vocab": "https://www.w3.org/ns/credentials/" +
                     "issuer-dependent#" }];
var CONTEXT_V20 = ["https://www.w3.org/ns/credentials/v2",
                   "https://w3id.org/security/data-integrity/v2",
                   { "@vocab": "https://www.w3.org/ns/credentials/" +
                     "issuer-dependent#" }];
var IDS = { schema_id: true, cred_def_id: true, rev_reg_id: true };
var KIND = { CREDENTIAL: 1, SUB_PROOF: 2, AGGREGATED: 3 };

// ---------------------------------------------------------------------------
// Numbers: decimal string <-> big-endian bytes.
// ---------------------------------------------------------------------------

function decToBytes(dec) {
  log.debug("Entering decToBytes().");
  var v = BigInt(dec);
  var out = [];
  while (v > BigInt(0)) {
    out.unshift(Number(v & BigInt(255)));
    v >>= BigInt(8);
  }
  log.debug("Leaving decToBytes().");
  return out.length ? out : [0];
}

function bytesToDec(bytes) {
  log.debug("Entering bytesToDec().");
  var v = BigInt(0);
  for (var i = 0; i < bytes.length; i++) {
    v = (v << BigInt(8)) | BigInt(bytes[i]);
  }
  log.debug("Leaving bytesToDec().");
  return v.toString(10);
}

function isByteArray(v) {
  log.debug("Entering isByteArray().");
  var ok = Array.isArray(v) && v.length > 0 && v.every(function (x) {
    return Number.isInteger(x) && x >= 0 && x < 256;
  });
  log.debug("Leaving isByteArray(). " + ok);
  return ok;
}

// The legacy object, with its big numbers as bytes, null members dropped.
function toWire(v, key) {
  log.debug("Entering toWire(). " + key);
  var out = v;
  if (Array.isArray(v)) {
    out = key === "c_list" ? v : v.map(function (x) {
      return toWire(x, key);
    });
  } else if (v && typeof v === "object") {
    out = {};
    Object.keys(v).forEach(function (k) {
      if (v[k] !== null && v[k] !== undefined) out[k] = toWire(v[k], k);
    });
  } else if (typeof v === "string" && /^\d+$/.test(v) && !IDS[key]) {
    out = decToBytes(v);
  }
  log.debug("Leaving toWire().");
  return out;
}

// The inverse: bytes back to decimal strings.
function fromWire(v, key) {
  log.debug("Entering fromWire(). " + key);
  var out = v;
  if (key !== "c_list" && isByteArray(v)) {
    out = bytesToDec(v);
  } else if (Array.isArray(v)) {
    out = key === "c_list" ? v : v.map(function (x) {
      return fromWire(x, key);
    });
  } else if (v && typeof v === "object") {
    out = {};
    Object.keys(v).forEach(function (k) {
      out[k] = fromWire(v[k], k);
    });
  }
  log.debug("Leaving fromWire().");
  return out;
}

function proofValue(kind, object) {
  log.debug("Entering proofValue(). " + kind);
  log.debug("Leaving proofValue().");
  return "u" + cbytes.bytesToB64u(msgpack.encode([kind, object]));
}

function readProofValue(pv, kind) {
  log.debug("Entering readProofValue(). " + kind);
  var s = String(pv || "");
  if (s.charAt(0) !== "u") {
    log.debug("Leaving readProofValue(). Not base64url.");
    throw new Error("an anoncreds-2023 proofValue is multibase base64url " +
                    "(\"u\"); this begins " + JSON.stringify(s.charAt(0)) +
                    ".");
  }
  var v = msgpack.toPlain(msgpack.decode(cbytes.b64uToBytes(s.slice(1))));
  if (!Array.isArray(v) || v.length !== 2 || v[0] !== kind) {
    log.debug("Leaving readProofValue(). Wrong kind.");
    throw new Error("the proofValue is not an anoncreds-2023 [" + kind +
                    ", …] (it is [" + (Array.isArray(v) ? v[0] : "?") +
                    ", …]).");
  }
  log.debug("Leaving readProofValue().");
  return fromWire(v[1], "");
}

function proofOf(doc) {
  log.debug("Entering proofOf().");
  var p = [].concat(doc.proof || []).filter(function (x) {
    return x && x.cryptosuite === CRYPTOSUITE;
  })[0];
  if (!p) {
    log.debug("Leaving proofOf(). None.");
    throw new Error("no DataIntegrityProof with cryptosuite " + CRYPTOSUITE +
                    ".");
  }
  log.debug("Leaving proofOf().");
  return p;
}

// A raw value as credentialSubject carries it: an integer as a number.
function subjectValue(raw) {
  log.debug("Entering subjectValue().");
  var s = String(raw);
  log.debug("Leaving subjectValue().");
  return /^-?\d+$/.test(s) && Number.isSafeInteger(Number(s)) ? Number(s) :
    s;
}

// ---------------------------------------------------------------------------
// Credentials.
// ---------------------------------------------------------------------------

function isW3cCredential(doc) {
  log.debug("Entering isW3cCredential().");
  var ok = !!(doc && typeof doc === "object" && doc.credentialSubject &&
    [].concat(doc.proof || []).some(function (p) {
      return p && p.cryptosuite === CRYPTOSUITE;
    }));
  log.debug("Leaving isW3cCredential(). " + ok);
  return ok;
}

// A processed legacy credential -> its W3C form. opts: { issuerId,
// version ("1.1" by default, as anoncreds-rs; or "2.0"), issued (Date) }.
function toW3cCredential(cred, opts) {
  log.debug("Entering toW3cCredential().");
  var o = opts || {};
  var subject = {};
  Object.keys(cred.values || {}).forEach(function (name) {
    subject[name] = subjectValue(cred.values[name].raw);
  });
  var wire = toWire({ schema_id: cred.schema_id, cred_def_id: cred.cred_def_id,
    rev_reg_id: cred.rev_reg_id, signature: cred.signature,
    signature_correctness_proof: cred.signature_correctness_proof,
    rev_reg: cred.rev_reg, witness: cred.witness }, "");
  var v2 = o.version === "2.0";
  var out = { "@context": v2 ? CONTEXT_V20 : CONTEXT_V11,
              type: ["VerifiableCredential"], issuer: o.issuerId,
              credentialSubject: subject,
              proof: [{ cryptosuite: CRYPTOSUITE, type: "DataIntegrityProof",
                        proofPurpose: "assertionMethod",
                        verificationMethod: cred.cred_def_id,
                        proofValue: proofValue(KIND.CREDENTIAL, wire) }] };
  out[v2 ? "validFrom" : "issuanceDate"] =
    (o.issued || new Date()).toISOString();
  log.debug("Leaving toW3cCredential().");
  return out;
}

// A W3C AnonCreds credential -> the legacy credential the engine uses.
function fromW3cCredential(doc) {
  log.debug("Entering fromW3cCredential().");
  var w = readProofValue(proofOf(doc).proofValue, KIND.CREDENTIAL);
  var values = {};
  Object.keys(doc.credentialSubject || {}).forEach(function (name) {
    if (name === "id") return;
    var raw = String(doc.credentialSubject[name]);
    values[name] = { raw: raw, encoded: anoncreds.encodeAttribute(raw) };
  });
  log.debug("Leaving fromW3cCredential().");
  return { schema_id: w.schema_id, cred_def_id: w.cred_def_id,
           rev_reg_id: w.rev_reg_id || null, values: values,
           signature: w.signature,
           signature_correctness_proof: w.signature_correctness_proof,
           rev_reg: w.rev_reg || null, witness: w.witness || null };
}

// ---------------------------------------------------------------------------
// Presentations.
// ---------------------------------------------------------------------------

function isW3cPresentation(doc) {
  log.debug("Entering isW3cPresentation().");
  var ok = !!(doc && typeof doc === "object" &&
    [].concat(doc.type || []).indexOf("VerifiablePresentation") !== -1 &&
    doc.proof && [].concat(doc.proof).some(function (p) {
      return p && p.cryptosuite === CRYPTOSUITE;
    }));
  log.debug("Leaving isW3cPresentation(). " + ok);
  return ok;
}

// A legacy presentation (and the request it answers) -> its W3C form.
// opts: { issuerIds ({ cred_def_id: issuer }), version }.
function toW3cPresentation(pres, request, opts) {
  log.debug("Entering toW3cPresentation().");
  var o = opts || {};
  var v2 = o.version === "2.0";
  var rp = pres.requested_proof || {};
  var subjects = pres.proof.proofs.map(function () {
    return {};
  });
  Object.keys(rp.revealed_attrs || {}).forEach(function (ref) {
    var at = rp.revealed_attrs[ref];
    var name = ((request.requested_attributes || {})[ref] || {}).name || ref;
    subjects[at.sub_proof_index][name] = subjectValue(at.raw);
  });
  Object.keys(rp.revealed_attr_groups || {}).forEach(function (ref) {
    var g = rp.revealed_attr_groups[ref];
    Object.keys(g.values || {}).forEach(function (name) {
      subjects[g.sub_proof_index][name] = subjectValue(g.values[name].raw);
    });
  });
  Object.keys(rp.predicates || {}).forEach(function (ref) {
    var name = ((request.requested_predicates || {})[ref] || {}).name || ref;
    subjects[rp.predicates[ref].sub_proof_index][name] = true;
  });
  var vcs = pres.proof.proofs.map(function (sub, i) {
    var id = pres.identifiers[i];
    var wire = toWire({ schema_id: id.schema_id, cred_def_id: id.cred_def_id,
      rev_reg_id: id.rev_reg_id, timestamp: id.timestamp,
      sub_proof: sub }, "");
    var vc = { "@context": v2 ? CONTEXT_V20 : CONTEXT_V11,
               type: ["VerifiableCredential"],
               issuer: (o.issuerIds || {})[id.cred_def_id] ||
                 String(id.cred_def_id).split("/")[0],
               credentialSubject: subjects[i],
               proof: { cryptosuite: CRYPTOSUITE, type: "DataIntegrityProof",
                        proofPurpose: "assertionMethod",
                        verificationMethod: id.cred_def_id,
                        proofValue: proofValue(KIND.SUB_PROOF, wire) } };
    vc[v2 ? "validFrom" : "issuanceDate"] = new Date().toISOString();
    return vc;
  });
  var agg = toWire({ aggregated: pres.proof.aggregated_proof }, "");
  log.debug("Leaving toW3cPresentation().");
  return { "@context": v2 ? CONTEXT_V20 : CONTEXT_V11,
           type: ["VerifiablePresentation"], verifiableCredential: vcs,
           proof: { cryptosuite: CRYPTOSUITE, type: "DataIntegrityProof",
                    proofPurpose: "authentication",
                    verificationMethod: (pres.identifiers[0] || {})
                      .cred_def_id,
                    proofValue: proofValue(KIND.AGGREGATED, agg),
                    challenge: request.nonce } };
}

function sameName(a, b) {
  log.debug("Entering sameName().");
  log.debug("Leaving sameName().");
  return anoncreds.attrCommonView(a) === anoncreds.attrCommonView(b);
}

// A W3C presentation -> the legacy presentation anoncreds.js verifies,
// rebuilding requested_proof from the request, each credential's
// credentialSubject and its sub-proof's predicates.
function fromW3cPresentation(doc, request) {
  log.debug("Entering fromW3cPresentation().");
  var vcs = [].concat(doc.verifiableCredential || []);
  var subs = vcs.map(function (vc) {
    return readProofValue(proofOf(vc).proofValue, KIND.SUB_PROOF);
  });
  var agg = readProofValue(proofOf(doc).proofValue, KIND.AGGREGATED);
  if (request && proofOf(doc).challenge !== undefined &&
      String(proofOf(doc).challenge) !== String(request.nonce)) {
    log.debug("Leaving fromW3cPresentation(). Challenge.");
    throw new Error("the presentation's challenge is not the request's " +
                    "nonce.");
  }
  var rp = { revealed_attrs: {}, revealed_attr_groups: {},
             self_attested_attrs: {}, unrevealed_attrs: {}, predicates: {} };
  var find = function (name) {
    for (var i = 0; i < vcs.length; i++) {
      var subject = vcs[i].credentialSubject || {};
      var key = Object.keys(subject).filter(function (k) {
        return sameName(k, name);
      })[0];
      if (key !== undefined && subject[key] !== true) {
        return { index: i, raw: String(subject[key]) };
      }
    }
    return null;
  };
  Object.keys((request || {}).requested_attributes || {}).forEach(
    function (ref) {
      var ask = request.requested_attributes[ref];
      if (ask.names) {
        var values = {};
        var index = null;
        ask.names.forEach(function (n) {
          var hit = find(n);
          if (hit) {
            index = hit.index;
            values[n] = { raw: hit.raw,
                          encoded: anoncreds.encodeAttribute(hit.raw) };
          }
        });
        if (index !== null) {
          rp.revealed_attr_groups[ref] = { sub_proof_index: index,
                                           values: values };
        }
        return;
      }
      var hit = find(ask.name);
      if (hit) {
        rp.revealed_attrs[ref] = { sub_proof_index: hit.index, raw: hit.raw,
          encoded: anoncreds.encodeAttribute(hit.raw) };
      }
    });
  Object.keys((request || {}).requested_predicates || {}).forEach(
    function (ref) {
      var ask = request.requested_predicates[ref];
      for (var i = 0; i < subs.length; i++) {
        var ge = ((subs[i].sub_proof || {}).primary_proof || {}).ge_proofs ||
            [];
        var match = ge.some(function (g) {
          return sameName(g.predicate.attr_name, ask.name) &&
            g.predicate.value === ask.p_value;
        });
        if (match) {
          rp.predicates[ref] = { sub_proof_index: i };
          break;
        }
      }
    });
  log.debug("Leaving fromW3cPresentation().");
  return {
    proof: { proofs: subs.map(function (s) {
      return s.sub_proof;
    }), aggregated_proof: agg.aggregated },
    requested_proof: rp,
    identifiers: subs.map(function (s) {
      return { schema_id: s.schema_id, cred_def_id: s.cred_def_id,
               rev_reg_id: s.rev_reg_id || null,
               timestamp: s.timestamp === undefined ? null : s.timestamp };
    })
  };
}

module.exports = {
  CRYPTOSUITE: CRYPTOSUITE,
  isW3cCredential: isW3cCredential,
  isW3cPresentation: isW3cPresentation,
  toW3cCredential: toW3cCredential,
  fromW3cCredential: fromW3cCredential,
  toW3cPresentation: toW3cPresentation,
  fromW3cPresentation: fromW3cPresentation
};
