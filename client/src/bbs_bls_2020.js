// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: bbs_bls_2020.js
//
// ---------------------------------------------------------------------------
// BbsBlsSignature2020 and BbsBlsSignatureProof2020 (W3C CCG "BBS+ Signatures
// 2020"), the JSON-LD half (#475). bbs_plus_2020.js is the signature scheme;
// this is what a credential's signature COVERS and how a holder derives a
// presentation from it, as @mattrglobal/jsonld-signatures-bbs 1.2.0 — the
// reference implementation of the suite, and what signed the credentials in
// the wild — does it:
//
//   the messages   the canonical (RDFC-1.0) N-Quad statements of the proof
//                  options (the proof without proofValue, read under the
//                  document's @context), then those of the document without
//                  its proof — one message per statement, as UTF-8.
//   deriving       the document's statements with every blank node label
//                  _:c14nN rewritten as the IRI <urn:bnid:_:c14nN>, read
//                  back into JSON-LD and FRAMED with the holder's reveal
//                  frame; the framed document's statements, found in that
//                  rewritten list, are the revealed document messages, and
//                  every proof-options statement is revealed as well. The
//                  derived proof is a BbsBlsSignatureProof2020 carrying a
//                  fresh nonce, base64, and the proof, base64.
//   verifying it   the derived proof's options are the original's: its
//                  type read back as the IRI of BbsBlsSignature2020, nonce
//                  and proofValue left out, read under security/v2 (as
//                  jsonld-signatures reads a proof); and the revealed
//                  document's statements have their urn:bnid IRIs turned
//                  back into blank node labels.
//
// The public key is a 96-byte BLS12-381 G2 point: a Bls12381G2Key2020's
// publicKeyBase58, a did:key with the bls12_381-g2-pub multicodec (0xeb), or
// a publicKeyJwk with crv "Bls12381G2".
//
// Loading this module registers both proof types with data_integrity.js, so
// verifyProof() answers for them. It needs RDFC-1.0 and the jsonld library,
// which data_integrity_rdfc.js registers (and which requires this module).
// NO DOM.
// ---------------------------------------------------------------------------

var dataIntegrity = require("./data_integrity");
var bbsPlus = require("./bbs_plus_2020");
var cbytes = require("./crypto_bytes");
var jsonldContexts = require("./jsonld_contexts");
var didLib = require("./did");

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "bbs_bls_2020",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var SIGNATURE_TYPE = "BbsBlsSignature2020";
var PROOF_TYPE = "BbsBlsSignatureProof2020";
var SIGNATURE_TYPE_IRI = "https://w3id.org/security#BbsBlsSignature2020";
var BBS_CONTEXT = "https://w3id.org/security/bbs/v1";
var NONCE_LENGTH = 50;

function loaderOf(opts) {
  log.debug("Entering loaderOf().");
  log.debug("Leaving loaderOf().");
  return (opts && opts.documentLoader) || jsonldContexts.documentLoader;
}

// RDFC-1.0, as data_integrity.js registers it, split into statements.
function statements(doc, loader) {
  log.debug("Entering statements().");
  log.debug("Leaving statements().");
  return dataIntegrity.rdfc(doc, loader).then(function (text) {
    return text.split("\n").filter(function (line) {
      return line.length > 0;
    });
  });
}

function withoutProof(doc) {
  log.debug("Entering withoutProof().");
  var out = Object.assign({}, doc);
  delete out.proof;
  log.debug("Leaving withoutProof().");
  return out;
}

// The proof options a signature covers: the proof less proofValue (and, for
// a derived proof, less nonce, with its type read as the signature's), under
// the document's @context.
function proofOptions(doc, proof, derived) {
  log.debug("Entering proofOptions().");
  var opts = Object.assign({}, proof);
  delete opts.proofValue;
  opts["@context"] = doc["@context"];
  if (derived) {
    // The type is the signature's, as an absolute IRI — which takes it out
    // of reach of the type-scoped terms bbs/v1 defines for the short name,
    // so the options are read under security/v2 (as jsonld-signatures reads
    // every proof), whose `created`, `proofPurpose` and `verificationMethod`
    // are the same IRIs the signer's statements used.
    delete opts.nonce;
    opts.type = SIGNATURE_TYPE_IRI;
    opts["@context"] = jsonldContexts.SECURITY_V2_URL;
  }
  log.debug("Leaving proofOptions().");
  return opts;
}

function utf8(lines) {
  log.debug("Entering utf8().");
  log.debug("Leaving utf8().");
  return lines.map(function (line) {
    return cbytes.strBytes(line);
  });
}

function b64ToBytes(text) {
  log.debug("Entering b64ToBytes().");
  log.debug("Leaving b64ToBytes().");
  return cbytes.b64ToBytes(String(text || ""));
}

function bytesToB64(bytes) {
  log.debug("Entering bytesToB64().");
  log.debug("Leaving bytesToB64().");
  return cbytes.bytesToB64(bytes);
}

// The 96-byte G2 key a verification method document carries.
function methodKey(method) {
  log.debug("Entering methodKey().");
  var m = method || {};
  if (m.publicKeyBase58) {
    log.debug("Leaving methodKey(). publicKeyBase58.");
    return didLib.base58Decode(m.publicKeyBase58);
  }
  if (m.publicKeyMultibase) {
    log.debug("Leaving methodKey(). publicKeyMultibase.");
    return multikeyBytes(m.publicKeyMultibase);
  }
  if (m.publicKeyJwk && /^Bls12381G2$/i.test(String(m.publicKeyJwk.crv))) {
    log.debug("Leaving methodKey(). publicKeyJwk.");
    return cbytes.b64uToBytes(m.publicKeyJwk.x);
  }
  log.debug("Leaving methodKey(). None.");
  return null;
}

// A z-multibase bls12_381-g2-pub key: varint 0xeb (0xeb 0x01) then 96 bytes.
function multikeyBytes(multibase) {
  log.debug("Entering multikeyBytes().");
  var raw = didLib.base58Decode(String(multibase).slice(1));
  if (String(multibase).charAt(0) !== "z" || raw[0] !== 0xeb ||
      raw[1] !== 0x01 || raw.length !== 98) {
    log.debug("Leaving multikeyBytes(). Not a BLS12-381 G2 key.");
    throw new Error("not a z-multibase BLS12-381 G2 public key (multicodec " +
                    "0xeb, 96 bytes).");
  }
  log.debug("Leaving multikeyBytes().");
  return raw.slice(2);
}

// The issuer's G2 key from a verificationMethod: a did:key in place, any
// other DID through did.js (reading the method as the document has it, since
// did.js's normalized form has no BLS key), an https URL fetched.
function defaultResolveBbsKey(fetchImpl) {
  log.debug("Entering defaultResolveBbsKey().");
  log.debug("Leaving defaultResolveBbsKey().");
  return function resolveBbsKey(vm) {
    log.debug("Entering resolveBbsKey(). " + String(vm).slice(0, 80));
    var url = String(vm || "");
    var did = url.split("#")[0];
    if (/^did:key:z/.test(did)) {
      log.debug("Leaving resolveBbsKey(). did:key.");
      return Promise.resolve(multikeyBytes(did.slice("did:key:".length)));
    }
    if (didLib.isDid(did)) {
      log.debug("Leaving resolveBbsKey(). Resolving the DID.");
      return didLib.resolve(did, { allowHttp: true, fetch: fetchImpl })
        .then(function (res) {
          var doc = res.document || {};
          var all = [].concat(doc.verificationMethod || [],
                              doc.assertionMethod || [],
                              doc.publicKey || []);
          var found = all.filter(function (m) {
            return m && typeof m === "object" && (m.id === url ||
              (url.indexOf("#") >= 0 && m.id === "#" + url.split("#")[1]));
          })[0];
          if (!found) {
            throw new Error("the DID document for " + did + " has no " +
                            "verification method " + url + ".");
          }
          return methodKey(found);
        });
    }
    log.debug("Leaving resolveBbsKey(). Fetching.");
    return didLib.resolveVerificationMethod(url, { allowHttp: false,
      fetch: fetchImpl }).then(function (r) {
      return methodKey(r.method);
    });
  };
}

function resolveKey(opts, vm) {
  log.debug("Entering resolveKey().");
  var o = opts || {};
  var fn = o.resolveBbsKey || defaultResolveBbsKey(o.fetch);
  log.debug("Leaving resolveKey().");
  return Promise.resolve(fn(vm));
}

// The messages a BbsBlsSignature2020 covers.
async function signedMessages(doc, proof, opts) {
  log.debug("Entering signedMessages().");
  var loader = loaderOf(opts);
  var p = await statements(proofOptions(doc, proof, false), loader);
  var d = await statements(withoutProof(doc), loader);
  log.debug("Leaving signedMessages(). " + p.length + " + " + d.length);
  return { proof: p, document: d };
}

// A BbsBlsSignature2020 on `doc`. Answers data_integrity's result shape.
async function verifySignatureProof(doc, proof, opts) {
  log.debug("Entering verifySignatureProof().");
  var out = { valid: false,
              spec: "W3C CCG BBS+ Signatures 2020 (BbsBlsSignature2020)" };
  var msgs;
  try {
    msgs = await signedMessages(doc, proof, opts);
  } catch (e) {
    log.debug("Leaving verifySignatureProof(). Canonicalization.");
    return Object.assign(out, { reason: "canonicalization failed: " +
                                e.message });
  }
  var key;
  try {
    key = await resolveKey(opts, proof.verificationMethod);
  } catch (e) {
    log.debug("Leaving verifySignatureProof(). Key.");
    return Object.assign(out, { reason: "verificationMethod " +
      proof.verificationMethod + " could not be resolved: " + e.message });
  }
  var all = msgs.proof.concat(msgs.document);
  var ok;
  try {
    ok = bbsPlus.verifySignature(key, b64ToBytes(proof.proofValue),
                                 utf8(all));
  } catch (e) {
    log.debug("Leaving verifySignatureProof(). " + e.message);
    return Object.assign(out, { reason: e.message });
  }
  out.valid = ok;
  out.statementCount = all.length;
  if (!ok) {
    out.reason = "the BBS+ signature does not verify over the " +
      all.length + " canonical statements of this credential and its " +
      "proof options.";
  }
  log.debug("Leaving verifySignatureProof(). " + ok);
  return out;
}

// A BbsBlsSignatureProof2020 on a derived `doc`.
async function verifyDerivedProof(doc, proof, opts) {
  log.debug("Entering verifyDerivedProof().");
  var out = { valid: false, derived: true,
              spec: "W3C CCG BBS+ Signatures 2020 " +
                "(BbsBlsSignatureProof2020)" };
  var loader = loaderOf(opts);
  var p;
  var d;
  try {
    p = await statements(proofOptions(doc, proof, true), loader);
    d = (await statements(withoutProof(doc), loader)).map(function (st) {
      return st.replace(/<urn:bnid:(_:c14n[0-9]+)>/g, "$1");
    });
  } catch (e) {
    log.debug("Leaving verifyDerivedProof(). Canonicalization.");
    return Object.assign(out, { reason: "canonicalization failed: " +
                                e.message });
  }
  var key;
  try {
    key = await resolveKey(opts, proof.verificationMethod);
  } catch (e) {
    log.debug("Leaving verifyDerivedProof(). Key.");
    return Object.assign(out, { reason: "verificationMethod " +
      proof.verificationMethod + " could not be resolved: " + e.message });
  }
  var ok = bbsPlus.verifyProof(key, b64ToBytes(proof.proofValue),
                               utf8(p.concat(d)), b64ToBytes(proof.nonce));
  out.valid = ok;
  out.disclosedStatements = d;
  if (!ok) {
    out.reason = "the BBS+ proof does not verify: the " + d.length +
      " disclosed statements, the nonce or the issuer's key are not the " +
      "ones it was made for.";
  }
  log.debug("Leaving verifyDerivedProof(). " + ok);
  return out;
}

// The holder's derivation. `reveal` is a JSON-LD frame naming what to
// disclose (e.g. { "@context": ..., type: ..., credentialSubject:
// { "@explicit": true, given_name: {} } }). Answers the derived credential
// with its BbsBlsSignatureProof2020.
async function deriveProof(doc, reveal, opts) {
  log.debug("Entering deriveProof().");
  var o = opts || {};
  var jsonld = dataIntegrity.jsonldLib();
  var loader = loaderOf(o);
  var proof = [].concat(doc.proof || []).filter(function (pr) {
    return pr && pr.type === SIGNATURE_TYPE;
  })[0];
  if (!proof) {
    log.debug("Leaving deriveProof(). No base proof.");
    throw new Error("the credential carries no " + SIGNATURE_TYPE +
                    " proof to derive from.");
  }
  var msgs = await signedMessages(doc, proof, o);
  var rewritten = msgs.document.map(function (st) {
    return st.replace(/(_:c14n[0-9]+)/g, "<urn:bnid:$1>");
  });
  var expanded = await jsonld.fromRDF(rewritten.join("\n"),
                                      { format: "application/n-quads" });
  var framed = await jsonld.frame(expanded, reveal,
                                  { documentLoader: loader });
  var shown = await statements(framed, loader);
  var proofCount = msgs.proof.length;
  var revealed = msgs.proof.map(function (st, i) {
    return i;
  });
  var missing = [];
  shown.forEach(function (st) {
    var at = rewritten.indexOf(st);
    if (at < 0) {
      missing.push(st);
    } else {
      revealed.push(at + proofCount);
    }
  });
  if (missing.length) {
    log.debug("Leaving deriveProof(). Not in the credential.");
    throw new Error("the reveal frame produced " + missing.length +
                    " statement(s) the credential does not sign: " +
                    missing[0]);
  }
  var key = await resolveKey(o, proof.verificationMethod);
  var nonce = o.nonce ? (typeof o.nonce === "string" ?
      cbytes.strBytes(o.nonce) : o.nonce) :
      cbytes.randomBytes(NONCE_LENGTH);
  var proofBytes = bbsPlus.createProof(key, b64ToBytes(proof.proofValue),
    utf8(msgs.proof.concat(msgs.document)), revealed, nonce);
  var derivedProof = {
    type: PROOF_TYPE,
    created: proof.created,
    nonce: bytesToB64(nonce),
    proofPurpose: proof.proofPurpose,
    proofValue: bytesToB64(proofBytes),
    verificationMethod: proof.verificationMethod
  };
  var out = Object.assign({}, framed);
  out.proof = derivedProof;
  log.debug("Leaving deriveProof(). " + shown.length + " of " +
            msgs.document.length + " document statements disclosed.");
  return { document: out, disclosedStatements: shown,
           statementCount: msgs.document.length };
}

dataIntegrity.registerSuite(SIGNATURE_TYPE, {
  verify: verifySignatureProof
});
dataIntegrity.registerSuite(PROOF_TYPE, {
  verify: verifyDerivedProof
});

module.exports = {
  SIGNATURE_TYPE: SIGNATURE_TYPE,
  PROOF_TYPE: PROOF_TYPE,
  BBS_CONTEXT: BBS_CONTEXT,
  methodKey: methodKey,
  multikeyBytes: multikeyBytes,
  defaultResolveBbsKey: defaultResolveBbsKey,
  signedMessages: signedMessages,
  verifySignatureProof: verifySignatureProof,
  verifyDerivedProof: verifyDerivedProof,
  deriveProof: deriveProof
};
