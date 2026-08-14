// File: bbs2023.js
//
// ---------------------------------------------------------------------------
// The `bbs-2023` Data Integrity cryptosuite: turning a JSON-LD credential into
// the list of messages BBS signs, and back.
//
// BBS signs an ORDERED LIST OF MESSAGES. A credential is a graph. The whole job
// of a Data Integrity cryptosuite is to get deterministically from one to the
// other, so that an issuer and a verifier who have never spoken produce exactly
// the same list. That is what RDF Dataset Canonicalization (RDFC-1.0) is for:
// expand the JSON-LD to RDF quads, canonically label the blank nodes, sort, and
// serialise to N-Quads. Each resulting statement is one BBS message.
//
// Get this wrong by one byte — a different context, a stray trailing newline, a
// different blank node label — and every signature fails while looking exactly
// like a broken signature. So the canonical form is produced by the same
// library (`jsonld`, which uses `rdf-canonize`) on both sides, and
// canonicalizedStatements() is the ONLY place either side is allowed to build
// it.
//
// A deliberate simplification, stated rather than hidden: the full cryptosuite
// separates "mandatory" statements (always disclosed, bound with an extra
// HMAC'd label map) from selectively-disclosable ones. This implements the
// selective-disclosure half only — every statement is a BBS message and the
// holder chooses which to reveal. That is the property the workflow exists to
// demonstrate; a document relying on mandatoryPointers would not be handled
// correctly here, so it is refused rather than silently mis-signed.
// ---------------------------------------------------------------------------

var jsonld = require("jsonld");
var bbs = require("./bbs");

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

function documentLoader(url) {
  log.debug("Entering documentLoader().");
  if (CONTEXTS[url]) {
    log.debug("Leaving documentLoader().");
    return Promise.resolve({ contextUrl: null, documentUrl: url,
                           document: CONTEXTS[url] });
  }
  // Deliberately not fetched. A context this workflow does not ship is a
  // context whose canonical form cannot be guaranteed to match the other
  // side's.
  log.debug("Leaving documentLoader().");
  return Promise.reject(new Error(
    "bbs-2023 here will only sign documents using a context it ships: " +
    Object.keys(CONTEXTS).join(", ") + ". Asked for: " + url));
}

// The canonical N-Quad statements of a document, one string per statement.
// THE single source of the message list, for issuer, holder and verifier alike.
function canonicalizedStatements(doc) {
  log.debug("Entering canonicalizedStatements().");
  log.debug("Leaving canonicalizedStatements().");
  return jsonld.canonize(doc, {
    algorithm: "URDNA2015",
    format: "application/n-quads",
    documentLoader: documentLoader,
    safe: true
  }).then(function (nquads) {
    return String(nquads).split("\n")
                  .filter(function (line) { return line.trim() !== ""; })
      .map(function (line) { return line + "\n"; });
  });
}

// The proof options are signed too, as their own canonical statements, so a
// verifier cannot be fooled about who signed, when, or for what purpose.
function proofConfig(proof) {
  log.debug("Entering proofConfig().");
  var config = {};
  Object.keys(proof).forEach(function (k) {
    if (k !== "proofValue") config[k] = proof[k];
  });
  config["@context"] = proof["@context"];
  log.debug("Leaving proofConfig().");
  return config;
}

function te(s) {
  log.debug("Entering te().");
  log.debug("Leaving te().");
  return new TextEncoder().encode(s);
}

// The BBS `header` binds the proof options to the signature.
function headerFor(proof) {
  log.debug("Entering headerFor().");
  log.debug("Leaving headerFor().");
  return canonicalizedStatements(proofConfig(proof))
                                 .then(function (statements) {
    return te(statements.join(""));
  });
}

function assertNoMandatoryPointers(proof) {
  log.debug("Entering assertNoMandatoryPointers().");
  if (proof && proof.mandatoryPointers && proof.mandatoryPointers.length) {
    throw new Error(
      "this bbs-2023 implementation does not support mandatoryPointers; " +
          "every statement is " +
      "selectively disclosable here. Refusing rather than signing something " +
          "a full implementation " +
      "would read differently.");
  }
  log.debug("Leaving assertNoMandatoryPointers().");
}

// --- issue ------------------------------------------------------------------
// Returns the credential with a base proof attached.
function createBaseProof(unsecured, proofOptions, secretKey, publicKey) {
  log.debug("Entering createBaseProof().");
  assertNoMandatoryPointers(proofOptions);
  var proof = Object.assign({
    "@context": unsecured["@context"],
    type: PROOF_TYPE,
    cryptosuite: CRYPTOSUITE,
    proofPurpose: "assertionMethod"
  }, proofOptions);
  var document = Object.assign({}, unsecured);
  delete document.proof;
  log.debug("Leaving createBaseProof().");
  return Promise.all([canonicalizedStatements(document), headerFor(proof)])
    .then(function (both) {
      var statements = both[0];
      var header = both[1];
      var messages = statements.map(te);
      var signature = bbs.sign(secretKey, publicKey, header, messages);
      var secured = Object.assign({}, document);
      var attached = Object.assign({}, proof);
      delete attached["@context"];
      attached.proofValue = "u" + bytesToB64u(signature);
      secured.proof = attached;
      return { credential: secured, statements: statements, header: header,
              signature: signature };
    });
}

// --- derive -----------------------------------------------------------------
// The holder's half: a fresh proof over the chosen statements only.
function deriveProof(secured, publicKey, disclosedIndexes, presentationHeader) {
  log.debug("Entering deriveProof().");
  var proof = secured.proof || {};
  var document = Object.assign({}, secured);
  delete document.proof;
  var signature = multibaseToBytes(proof.proofValue);
  var reproof = Object.assign({ "@context": secured["@context"] }, proof);
  delete reproof.proofValue;
  log.debug("Leaving deriveProof().");
  return Promise.all([canonicalizedStatements(document), headerFor(reproof)])
    .then(function (both) {
      var statements = both[0];
      var header = both[1];
      var messages = statements.map(te);
      var sorted = disclosedIndexes.slice().sort(function (a, b) { return a -
          b; });
      var derived = bbs.proofGen(publicKey, signature, header,
          presentationHeader, messages, sorted);
      return {
        proof: derived, header: header, statements: statements,
        disclosedIndexes: sorted,
        disclosedStatements: sorted.map(function (i) { return statements[i]; })
      };
    });
}

function verifyDerived(publicKey, derivedProof, header, presentationHeader,
                       disclosedStatements, disclosedIndexes) {
  log.debug("Entering verifyDerived().");
  log.debug("Leaving verifyDerived().");
  return bbs.proofVerify(publicKey, derivedProof, header, presentationHeader,
                         disclosedStatements.map(te),
                         disclosedIndexes.slice().sort(function (a,
                             b) { return a - b; }));
}

// --- base64url --------------------------------------------------------------
function bytesToB64u(bytes) {
  log.debug("Entering bytesToB64u().");
  var bin = "";
  var arr = new Uint8Array(bytes);
  for (var i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  log.debug("Leaving bytesToB64u().");
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
// Multibase base64url ("u" prefix). Kept separate from b64uToBytes for the
// reason recorded in sts/bbs2023.js: a decoder that also strips the prefix,
// plus a caller that strips it too, silently eats a data character whenever the
// payload begins with "u" — about one key in sixty-four, which is exactly the
// kind of bug that passes locally and fails in CI.
function multibaseToBytes(str) {
  log.debug("Entering multibaseToBytes().");
  var text = String(str || "");
  if (text.charAt(0) !== "u") {
    throw new Error('expected multibase base64url (a leading "u"), got: ' +
                    text.slice(0, 12));
  }
  log.debug("Leaving multibaseToBytes().");
  return b64uToBytes(text.slice(1));
}

function b64uToBytes(str) {
  log.debug("Entering b64uToBytes().");
  var s = String(str).replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  var bin = atob(s);
  var out = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  log.debug("Leaving b64uToBytes().");
  return out;
}

module.exports = {
  CRYPTOSUITE: CRYPTOSUITE,
  IDENTITY_CONTEXT_URL: IDENTITY_CONTEXT_URL,
  PROOF_TYPE: PROOF_TYPE,
  canonicalizedStatements: canonicalizedStatements,
  headerFor: headerFor,
  createBaseProof: createBaseProof,
  deriveProof: deriveProof,
  verifyDerived: verifyDerived,
  bytesToB64u: bytesToB64u,
  b64uToBytes: b64uToBytes,
  multibaseToBytes: multibaseToBytes,
  documentLoader: documentLoader
};
