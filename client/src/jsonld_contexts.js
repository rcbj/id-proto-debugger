// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: jsonld_contexts.js
//
// ---------------------------------------------------------------------------
// The JSON-LD contexts every Data Integrity proof in this tree is
// canonicalized against, and the OFFLINE document loader that serves them.
//
// It was the top third of bbs2023.js until 2026-11-17 (#475), when the other
// RDFC-1.0 cryptosuites (eddsa-rdfc-2022, ecdsa-rdfc-2019) and the legacy
// Linked Data proof types (Ed25519Signature2018/2020, JsonWebSignature2020,
// EcdsaSecp256k1Signature2019, BbsBlsSignature2020) arrived and needed the
// same table. One loader, because two loaders that disagree about one context
// produce two canonical forms of one credential and a signature that verifies
// on one page and not on the next.
//
// The security-suite contexts below are byte-for-byte what w3id.org served
// on 2026-11-17, and are the W3C's and the W3C CCG's documents.
// ---------------------------------------------------------------------------

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "jsonld_contexts",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// The contexts this workflow issues against, served from memory so that signing
// never depends on fetching a context over the network — which would make the
// signature depend on someone else's uptime, and on these pages would be
// blocked by CORS as often as not.
var IDENTITY_CONTEXT_URL = "https://idptools.com/contexts/identity/v1";
var CREDENTIALS_V2_URL = "https://www.w3.org/ns/credentials/v2";
var CREDENTIALS_V1_URL = "https://www.w3.org/2018/credentials/v1";
var SECURITY_V2_URL = "https://w3id.org/security/v2";
var DATA_INTEGRITY_V2_URL = "https://w3id.org/security/data-integrity/v2";
var CONTEXTS = {
  "https://www.w3.org/ns/credentials/v2": require(
      "./contexts/credentials_v2.json"),
  "https://www.w3.org/2018/credentials/v1": require(
      "./contexts/credentials_v1.json"),
  // The security vocabulary. v2 imports v1 by reference, and jsonld-signatures
  // canonicalizes a legacy proof's options under v2 when the document names
  // no context of its own.
  "https://w3id.org/security/v1": require("./contexts/security_v1.json"),
  "https://w3id.org/security/v2": require("./contexts/security_v2.json"),
  // DataIntegrityProof and Multikey, for a VCDM 1.1 document (credentials/v2
  // defines both itself).
  "https://w3id.org/security/data-integrity/v1": require(
      "./contexts/data_integrity_v1.json"),
  "https://w3id.org/security/data-integrity/v2": require(
      "./contexts/data_integrity_v2.json"),
  "https://w3id.org/security/multikey/v1": require(
      "./contexts/multikey_v1.json"),
  // The legacy Linked Data proof suites, each with its own context.
  "https://w3id.org/security/suites/ed25519-2018/v1": require(
      "./contexts/ed25519_2018_v1.json"),
  "https://w3id.org/security/suites/ed25519-2020/v1": require(
      "./contexts/ed25519_2020_v1.json"),
  "https://w3id.org/security/suites/jws-2020/v1": require(
      "./contexts/jws_2020_v1.json"),
  "https://w3id.org/security/suites/secp256k1-2019/v1": require(
      "./contexts/secp256k1_2019_v1.json"),
  "https://w3id.org/security/bbs/v1": require("./contexts/bbs_v1.json"),
  // VC Barcodes v1.0 (#480), and the two example vocabularies its test
  // vectors are written in: CBOR-LD numbers terms from these documents, so a
  // barcode decodes only against the exact copy it was encoded with.
  "https://w3id.org/vc-barcodes/v1": require(
      "./contexts/vc_barcodes_v1.json"),
  "https://w3id.org/utopia/v2": require("./contexts/utopia_v2.json"),
  "https://w3id.org/vital-records/v1rc1": require(
      "./contexts/vital_records_v1rc1.json"),
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
    "A Data Integrity proof here is only canonicalized against a JSON-LD " +
    "context this debugger ships (" +
    Object.keys(CONTEXTS).join(", ") + ") or one it has been given. It " +
    "was asked for " + url + ", which is neither: add that context's " +
    "document on the presentation page (JSON-LD Contexts) and try again."));
}

module.exports = {
  IDENTITY_CONTEXT_URL: IDENTITY_CONTEXT_URL,
  CONTEXTS: CONTEXTS,
  SECURITY_V2_URL: SECURITY_V2_URL,
  DATA_INTEGRITY_V2_URL: DATA_INTEGRITY_V2_URL,
  CREDENTIALS_V1_URL: CREDENTIALS_V1_URL,
  CREDENTIALS_V2_URL: CREDENTIALS_V2_URL,
  documentLoader: documentLoader,
  addContext: addContext,
  removeContext: removeContext,
  suppliedContexts: suppliedContexts,
  SUPPLIED_CONTEXTS_KEY: SUPPLIED_CONTEXTS_KEY
};
