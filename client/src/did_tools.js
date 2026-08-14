// File: did_tools.js
//
// ---------------------------------------------------------------------------
// DID Tools — a general-purpose verifier for Decentralized Identifiers
// (W3C DID Core 1.0).
//
// This began as the "Issuer DID Document" pane on VC Issuance step 1, where it
// could only ever be about one DID: the issuer of the credential in hand.
// Nothing about resolving a DID, reading its document, or checking what it is
// linked to is specific to issuance, so it is a page of its own and the wording
// no longer says "issuer".
//
// What it does, in the order the panes appear:
//
//   * RESOLVE a DID. did:jwk and did:key ARE their key — the identifier carries
//     it, so they resolve with no network call at all, and the provenance line
//     says so rather than implying a fetch that never happened. Only did:web
//     has a document to retrieve.
//   * RETRIEVE a document by URL, for one that is not where the method's rules
//     say it should be: a staging host, a tunnel, an unpublished path, or a
//     CORS-friendly proxy. That is a retrieval, not a resolution, and the
//     difference is reported rather than smoothed over.
//   * UPLOAD one from a file, because a host that sends no CORS headers cannot
//     be read by a browser however right the URL is.
//   * verify that a key the document publishes REALLY SIGNED the credential
//     this browser is holding. Resolving a document proves nothing on its own;
//     this is the check that means something.
//   * verify the DOMAIN LINKAGE (DIF Well Known DID Configuration): that an
//     origin and a DID are the same entity. For did:web this is the only
//     non-circular proof, because resolving did:web:example.com means fetching
//     example.com.
//
// It shares the credential in localStorage with the VC workflows and writes
// none of their state, so it can be opened beside them at any point.
// ---------------------------------------------------------------------------

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var metadataClient = require("./metadata_client");
var opMetadata = require("./op_metadata");
var sdJwtVc = require("./sd_jwt_vc");
var vciMetadata = require("./vci_metadata");
var didLib = require("./did");
var urlSafety = require("./url_safety");

var log = bunyan.createLogger({ name: 'did_tools',
                                level: appconfig.LOG_LEVEL || 'info' });

// ---------------------------------------------------------------------------
// This page's own storage keys.
//
// It is INDEPENDENT of the VC workflows by design, and that has to be true of
// the storage as much as of the markup. VC Issuance step 1 keeps its own DID
// pane, where a resolved document IS that workflow's configuration (`did_id`,
// `did_verificationMethod`, and the rest). If this page wrote those same keys,
// resolving a DID here would silently rewrite the issuance configuration and
// Clear here would wipe it — from a page the user opened to look something up.
//
// So every key is prefixed. The element ids are deliberately NOT: they are
// per-document, they cannot collide, and keeping them identical is what let
// this page reuse the pane's markup and logic unchanged.
//
// The one thing read across the boundary is the CREDENTIAL the workflows
// stored, and that is the point of "Verify Signing Key" — it asks whether a key
// this document publishes signed the credential in this browser. It is read,
// never written.
// ---------------------------------------------------------------------------
var KEY_PREFIX = "didtools_";
function storeKey(name) {
  log.debug("Entering storeKey().");
  log.debug("Leaving storeKey().");
  return KEY_PREFIX + name;
}
// Element ids, fixed by did-tools.html.
var DID_ID_FIELD = "did_identifier";
var DID_URL_FIELD = "did_resolution_url";
var ORIGIN_FIELD = "did_tools_origin";
// Storage keys, namespaced. Never pass one of these to val()/setVal(): they
// name nothing in the document, and the failure is silent — an empty field read
// back as "that is not a DID".
var DID_URL_KEY = storeKey(DID_URL_FIELD);
var ORIGIN_KEY = storeKey("origin");

// --- the page's own small helpers -------------------------------------------
function el(id) {
  log.debug("Entering el().");
  log.debug("Leaving el().");
  return document.getElementById(id);
}
function val(id) {
  log.debug("Entering val().");
  var e = el(id);
  log.debug("Leaving val().");
  return e ? e.value : "";
}
function setVal(id, v) {
  log.debug("Entering setVal().");
  var e = el(id);
  if (e) e.value = (v == null ? "" : v);
  log.debug("Leaving setVal().");
}
function esc(v) {
  log.debug("Entering esc().");
  log.debug("Leaving esc().");
  return metadataClient.escapeHtmlText(v);
}

function status(id, text, cls) {
  log.debug("Entering status().");
  var e = el(id);
  if (!e) {
    log.debug("Leaving status().");
    return;
  }
  e.textContent = text;
  e.className = "vc-status" + (cls ? " " + cls : "");
  log.debug("Leaving status().");
}

// The upload route, through the shared reader so this page and the metadata
// panes cannot disagree about what a JSON document is.
function readMetadataFile(evt, statusId, onDocument) {
  log.debug("Entering readMetadataFile().");
  log.debug("Leaving readMetadataFile().");
  return metadataClient.readJsonFile(evt, onDocument, function (text, cls) {
    status(statusId, text, cls);
  });
}

function togglePane(id) {
  log.debug("Entering togglePane().");
  var fs = el(id);
  if (fs) fs.style.display = (fs.style.display === "none") ? "block" : "none";
  log.debug("Leaving togglePane().");
  return false;
}

// ---------------------------------------------------------------------------
// The DID pane (W3C DID Core 1.0).
//
// Modelled on the two metadata panes above — Resolve / Upload / Clear, a table
// of what came back, and the values pushed into Configuration Parameters — with
// one honest difference: only did:web has anything to RETRIEVE. did:jwk and
// did:key ARE their key, so "resolving" them is a local decode, and the
// provenance line says which happened rather than implying a network call that
// never took place.
// ---------------------------------------------------------------------------
var DID_ID_KEY = storeKey(DID_ID_FIELD);

var didDocument = null;

// Push the resolved document into the editable Configuration Parameters fields.
function populateFromDidDocument() {
  log.debug("Entering populateFromDidDocument().");
  var doc = didDocument || {};
  didLib.DID_METADATA.forEach(function (m) {
    var v = doc[m.name];
    var shown = (v === undefined || v === null) ? ""
      : (typeof v === "string" ? v : JSON.stringify(v, null, 2));
    setVal(didLib.idFor(m.name), shown);
    sdJwtVc.set(storeKey(didLib.idFor(m.name)), shown);
    opMetadata.markNotDefined(didLib.idFor(m.name),
      !Object.prototype.hasOwnProperty.call(doc, m.name));
  });
  log.debug("Leaving populateFromDidDocument().");
}

function renderDidTable(provenance) {
  log.debug("Entering renderDidTable().");
  var host = el("did_document_table");
  if (!host) {
    log.debug("Leaving renderDidTable().");
    return;
  }
  host.innerHTML = didDocument
    ? metadataClient.buildInfoTable(didDocument, provenance)
    : "";
  log.debug("Leaving renderDidTable().");
}

function applyDidDocument(doc, provenance, verb, url) {
  log.debug("Entering applyDidDocument().");
  didDocument = doc || null;
  setVal("did_resolution_url", url || "");
  renderDidTable(provenance);
  populateFromDidDocument();
  var methods = didLib.verificationMethods(didDocument || {});
  status("did_status",
    verb + " a DID Document for " + ((didDocument || {}).id || "(no id)") +
        " with " +
    methods.length + " verification method(s): " +
    methods.map(function (m) { return (m.id || "").split("#")[1] ||
                m.id; }).join(", ") +
    ". " + (provenance && provenance.note ? provenance.note : ""), "vc-ok");
  log.debug("Leaving applyDidDocument().");
}

function resolveDid() {
  log.debug("Entering resolveDid().");
  var didValue = val(DID_ID_FIELD).trim();
  sdJwtVc.set(DID_ID_KEY, didValue);
  var parsed = didLib.parse(didValue);
  if (!parsed) {
    status("did_status",
           'That is not a DID. A DID looks like "did:web:example.com", ' +
      '"did:jwk:eyJrdHki…" or "did:key:zDnae…".', "vc-bad");
    log.debug("Leaving resolveDid().");
    return false;
  }
  // did:web over plain http is allowed here because this suite's own issuer
  // runs on it. The method mandates https; a deployed site talking to a real
  // issuer will use it, and the only reason to relax it is a local stack.
  var allowHttp =
      /^https?:\/\/localhost|^http:\/\//.test(String(window.location.origin)) ||
                  /^did:web:(localhost|sts|127\.0\.0\.1)/.test(didValue);
  var url = parsed.method === "web"
    ? (allowHttp ? didLib.didWebToUrlInsecure(didValue) : didLib.didWebToUrl(
        didValue)) : "";
  setVal("did_resolution_url", url);
  status("did_status", parsed.method === "web"
    ? "Retrieving " + url + " …" : "Decoding the " + parsed.method +
        " locally …", "vc-pending");
  log.debug("Leaving resolveDid().");
  return didLib.resolve(didValue, { allowHttp: allowHttp })
    .then(function (r) {
      applyDidDocument(r.document, { url: r.url || "", note: "Source: " +
                       r.from + "." },
        r.url ? "Retrieved" : "Resolved", r.url);
    })
    .catch(function (e) {
      status("did_status", "Could not resolve that DID: " + e.message,
             "vc-bad");
    });
}

// Retrieve a DID Document from the URL in the Document URL field, whatever put
// it there — derived by Resolve above, or typed in by hand.
//
// This is not resolution and does not pretend to be. Resolve takes a DID and
// applies the method's own rules to find the document; this takes a URL and
// fetches it. The distinction is worth keeping because it is the whole reason
// to have the button: a did:web document is not always reachable where the
// method says it should be. It may be on a staging host, behind a tunnel, at a
// path the issuer has not published yet, or reachable only through a
// CORS-friendly proxy — and in each of those cases the DID is right, the URL is
// not the one the method derives, and the document is still the thing you want
// to look at.
//
// One consequence has to be reported rather than enforced. DID Core says a
// RESOLVED document's id MUST equal the DID that was resolved, and did.js
// refuses a mismatch for exactly that reason. Here the caller chose the URL, so
// refusing would defeat the purpose: inspecting a document that identifies
// itself as somebody else is a thing you would come to this pane to do. So a
// mismatch is a NOTE, said plainly, and everything downstream then describes
// the document's own id rather than what happens to be in the DID field.
//
// Everything after the fetch goes through applyDidDocument(), which is what
// makes the rest of the pane behave exactly as it does after a Resolve: the
// table, the Configuration Parameters fields, Verify Issuer Key and Verify
// Domain Linkage all read the same state and need to know nothing about where
// it came from.
function retrieveDidDocument() {
  log.debug("Entering retrieveDidDocument().");
  var url = (val("did_resolution_url") || "").trim();
  sdJwtVc.set(DID_URL_KEY, url);
  if (!url) {
    status("did_status", "Put a document URL in the Document URL field " +
           "first, or press Resolve to " +
      "derive one from a did:web.", "vc-bad");
    log.debug("Leaving retrieveDidDocument(). No URL.");
    return false;
  }
  // The same allowlist the navigation sinks use (client/src/url_safety.js):
  // only http and https. A DID document is fetched, not navigated to, so this
  // is not about script execution — it is that no other scheme can return one,
  // and saying so beats a fetch that fails with something obscure.
  if (!urlSafety.isSafeExternalUrl(url)) {
    status("did_status", 'A DID Document is fetched over http or https; "' +
           url +
      '" is neither.', "vc-bad");
    log.debug("Leaving retrieveDidDocument(). Refused the scheme.");
    return false;
  }

  var didValue = (val(DID_ID_FIELD) || "").trim();
  status("did_status", "Retrieving " + url + " …", "vc-pending");
  log.debug("Leaving retrieveDidDocument(). Fetching " + url);
  return fetch(url, { credentials: "omit" })
    .then(function (r) {
      return r.text().then(function (text) {
        if (!r.ok) throw new Error(url + " answered HTTP " + r.status + ".");
        var doc;
        try {
          doc = JSON.parse(text);
        } catch (e) {
          // An HTML error page from a misconfigured host is the usual cause,
          // and a bare "Unexpected token <" would not say that.
          throw new Error(url + " did not return JSON: " + e.message);
        }
        if (!doc || typeof doc !== "object") {
          throw new Error(url +
                          " returned JSON, but not a DID Document object.");
        }
        return doc;
      });
    })
    .then(function (doc) {
      var note = "Retrieved from " + url +
          ", by URL rather than by resolving the DID.";
      if (!doc.id) {
        note += " This document carries no id, so there is nothing to check it against a DID.";
      } else if (!didValue) {
        // Fill the DID in from the document so the rest of the pane has
        // something to work with — Verify Domain Linkage asks about a DID, not
        // a URL.
        setVal(DID_ID_FIELD, doc.id);
        sdJwtVc.set(DID_ID_KEY, doc.id);
        note += " The Issuer DID field was empty and has been filled in from the document's id.";
      } else if (doc.id !== didValue) {
        note += ' NOTE: this document identifies itself as "' + doc.id +
            '", not "' + didValue +
                '". Resolution would refuse that (DID Core: a resolved ' +
                    'document\'s id MUST be the ' +
                "DID resolved); a retrieval by URL cannot, because you chose " +
                    "the URL. Everything " +
                "below therefore describes " + doc.id + ".";
      }
      applyDidDocument(doc, { url: url, note: note }, "Retrieved", url);
    })
    .catch(function (e) {
      // The browser's own message for a blocked cross-origin read is the bare
      // "Failed to fetch", which says nothing about why — so the likely cause
      // is named and the way round it is offered. Punctuation is added only
      // when the message does not already end in some, because these arrive
      // both ways ("… answered HTTP 404." from above, "Failed to fetch" from
      // the browser).
      var message = e.message;
      if (/Failed to fetch|NetworkError|CORS/i.test(message)) {
        if (!/[.!?]$/.test(message)) message += ".";
        message += " A host that sends no CORS headers cannot be read by a " +
            "browser however right " +
                   "the URL is — fetch it with curl and use Upload instead.";
      }
      status("did_status", "Could not retrieve that document: " + message,
             "vc-bad");
    });
}

function uploadDidDocument() {
  log.debug("Entering uploadDidDocument().");
  var f = el("did_document_file");
  if (f) f.click();
  log.debug("Leaving uploadDidDocument().");
  return false;
}

function onDidFileChange(evt) {
  log.debug("Entering onDidFileChange().");
  log.debug("Leaving onDidFileChange().");
  return readMetadataFile(evt, "did_status", function (doc, name) {
    applyDidDocument(doc, { file: name, note: "Loaded from " + name +
                     ", not resolved." },
      "Loaded", "");
  });
}

function clearDidDocument() {
  log.debug("Entering clearDidDocument().");
  didDocument = null;
  sdJwtVc.set(DID_ID_KEY, "");
  setVal(DID_ID_FIELD, "");
  setVal("did_resolution_url", "");
  renderDidTable(null);
  didLib.DID_METADATA.forEach(function (m) {
    setVal(didLib.idFor(m.name), "");
    sdJwtVc.set(storeKey(didLib.idFor(m.name)), "");
  });
  status("did_status", "Cleared.", "vc-ok");
  log.debug("Leaving clearDidDocument().");
  return false;
}

// Resolving a document proves nothing on its own. What matters is whether a key
// it publishes is the one the issuer actually signed with — so this checks the
// credential in hand against it, rather than reporting a green tick for having
// fetched some JSON.
function verifyDidBinding() {
  log.debug("Entering verifyDidBinding().");
  if (!didDocument) {
    status("did_status", "Resolve or upload a DID Document first.", "vc-bad");
    log.debug("Leaving verifyDidBinding().");
    return false;
  }
  var raw = sdJwtVc.get(sdJwtVc.KEYS.CREDENTIAL) || "";
  if (!raw) {
    status("did_status", "There is no credential in this wallet to check the " +
           "document against. " +
      "Issue one first — this button answers \"is this the key that signed " +
          "it\", which needs " +
      "something signed.", "vc-bad");
    log.debug("Leaving verifyDidBinding().");
    return false;
  }
  var parsed;
  try {
    parsed = sdJwtVc.parseCredential(raw);
  } catch (e) {
    status("did_status", "The credential in this wallet could not be parsed: " +
           e.message, "vc-bad");
    log.debug("Leaving verifyDidBinding().");
    return false;
  }
  var named = parsed.format === sdJwtVc.FORMAT_LDP_VC
    ? ((parsed.document || {}).issuer || "")
    : ((parsed.payload || {}).iss || "");
  if (named && didDocument.id && named !== didDocument.id) {
    status("did_status", "This credential names its issuer as \"" + named +
           "\", but the document " +
      "resolved here describes \"" + didDocument.id +
          "\". They are different subjects, so the " +
      "keys below say nothing about that credential.", "vc-bad");
    log.debug("Leaving verifyDidBinding().");
    return false;
  }
  var keys = didLib.assertionKeys(didDocument);
  if (!keys.length) {
    status("did_status", "This document publishes no key that may assert, so " +
           "nothing here could " +
      "have signed a credential.", "vc-bad");
    log.debug("Leaving verifyDidBinding().");
    return false;
  }
  if (parsed.format === sdJwtVc.FORMAT_LDP_VC) {
    var vm = ((parsed.document || {}).proof || {}).verificationMethod || "";
    var found = keys.filter(function (k) { return k.id === vm; })[0];
    status("did_status", found
      ? "The proof names " + vm + ", and this document publishes it (" +
          found.type + "). " +
        "Step 3 verifies the proof itself against that key."
      : "The proof names " + vm +
          ", which this document does NOT publish. Either the document is " +
        "stale or the credential was signed by something else.", found ?
            "vc-ok" : "vc-bad");
    log.debug("Leaving verifyDidBinding().");
    return false;
  }
  // A JWS-secured credential: check the signature here and now.
  var header = parsed.header || {};
  var key = didLib.keyForKid(didDocument, header.kid);
  if (!key || !key.jwk) {
    status("did_status",
           "No key in this document matches the credential's kid (" +
      (header.kid || "none given") +
       "), or the matching key is not expressed as a JWK.", "vc-bad");
    log.debug("Leaving verifyDidBinding().");
    return false;
  }
  status("did_status", "Verifying the credential signature against " + key.id +
         " …", "vc-pending");
  // verifyJwsWithJwks takes a JWK SET and reports {valid}, so the one key this
  // document named is wrapped as a set of one — verifying against every key in
  // the document would answer a weaker question than "did THIS method sign it".
  metadataClient.verifyJwsWithJwks(parsed.serialized.split("~")[0],
                                   { keys: [key.jwk] },
      "the credential")
    .then(function (verdict) {
      status("did_status", verdict && verdict.valid
        ? "VERIFIED: the credential's signature checks out against " + key.id +
            " from this DID " +
          "Document. The DID really does identify the key that signed it."
        : "The credential's signature does NOT verify against " + key.id +
          ". Resolving a document is not the same as it being the right one.",
        verdict && verdict.valid ? "vc-ok" : "vc-bad");
    })
    .catch(function (e) {
      status("did_status", "The signature could not be checked: " + e.message,
             "vc-bad");
    });
  log.debug("Leaving verifyDidBinding().");
  return false;
}

// ---------------------------------------------------------------------------
// Domain linkage (DIF Well Known DID Configuration).
//
// "Verify Issuer Key" above answers: does this document publish the key that
// signed the credential. This answers the question BEFORE that one, which is
// the one a DID cannot answer about itself: why should this DID be believed to
// be the same party as the https issuer the wallet discovered?
//
// For did:web the appearance of an answer is worse than none. Resolving
// did:web:example.com means fetching example.com, so reading a DID document off
// that origin to decide whether the DID belongs to it is circular. The linkage
// credential is not: the DID signs, with its own key, a credential naming the
// origin, and the verifier checks the signature against the keys the DID
// authorises to assert.
//
// The origin is taken from the CREDENTIAL ISSUER's identifier rather than from
// the DID, because the whole point is to connect the two: deriving the origin
// from the DID would ask whether the DID vouches for itself, which it always
// does.
function verifyDomainLinkage() {
  log.debug("Entering verifyDomainLinkage().");
  var didValue = (val(DID_ID_FIELD) || "").trim() || (didDocument || {}).id ||
      "";
  if (!didValue) {
    status("did_linkage_status",
           "Give a DID first — this checks whether an origin vouches for one.",
           "vc-bad");
    log.debug("Leaving verifyDomainLinkage().");
    return false;
  }
  // The origin whose word is in question, taken from the field so any origin
  // can be asked about. It is defaulted (on load) from the credential issuer
  // this browser last discovered, which is the common case, but it is not
  // limited to it: a linkage is a claim between an origin and a DID, and
  // neither has to have anything to do with a credential.
  var issuer = (val(ORIGIN_FIELD) || "").trim();
  if (!issuer) {
    status("did_linkage_status",
           "Give an origin to check the DID against — the linkage is a claim " +
      "that an ORIGIN and a DID are the same entity, so it takes both.",
          "vc-bad");
    log.debug("Leaving verifyDomainLinkage().");
    return false;
  }
  sdJwtVc.set(ORIGIN_KEY, issuer);
  var origin;
  try {
    origin = new URL(issuer).origin;
  } catch (e) {
    status("did_linkage_status", 'The credential issuer identifier "' + issuer +
           '" is not a URL, so ' +
      "it has no origin to link.", "vc-bad");
    log.debug("Leaving verifyDomainLinkage().");
    return false;
  }
  var allowHttp = /^http:/.test(origin);
  var host = el("did_linkage_table");
  if (host) host.innerHTML = "";
  status("did_linkage_status", "Fetching " +
         didLib.didConfigurationUrl(origin) + " …", "vc-pending");
  didLib.verifyOriginLinkage(origin, didValue, { allowHttp: allowHttp })
    .then(function (result) {
      // Every entry is shown, not only the matching one: an origin may link
      // several DIDs, and one that fails is as interesting as one that passes.
      //
      // Built in the SAME TWO-COLUMN SHAPE as the retrieved-metadata tables
      // above (see metadata_client.buildInfoTable), and that is a layout
      // requirement, not a stylistic one. The .discovery_info_table CSS is what
      // keeps these tables inside their pane, and it does that with
      // table-layout:fixed plus rules on the FIRST and SECOND columns only — a
      // 34% name column and a value column pinned to max-width:0 so it wraps
      // instead of stretching. This was a hand-rolled three-column table with
      // inline width attributes, so its third column had no cap and no
      // overflow-wrap: the checks column, which is the one carrying full DID
      // URLs and origins, was the one column free to push the table past the
      // edge. Measured at a 414px viewport it did exactly that (the wrapper
      // scrolled, 414px of content in a 380px box).
      //
      // So: no inline widths, two columns, and the DID and its verdict share
      // the name cell. The CSS then governs this table exactly as it governs
      // the other two in this pane.
      var rows = result.results.map(function (r) {
        var verdict = '<span class="' + (r.valid ? "vc-ok" : "vc-bad") + '">' +
                      (r.valid ? "verified" : "not verified") + "</span>";
        var checks = r.checks.map(function (c) {
          return '<span class="' + (c.ok ? "vc-ok" : "vc-bad") + '">' + (c.ok ?
              "OK" : "FAILED") +
                 "</span> " + metadataClient.escapeHtmlText(c.name + " — " +
                     c.detail);
        }).join("<br />");
        return "<tr><td>" + metadataClient.escapeHtmlText(r.did || "(no DID)") +
               "<br />" + verdict + "</td><td>" + checks + "</td></tr>";
      }).join("");
      if (host) {
        host.innerHTML = "<table border='2' style='border:2px;'>" +
          "<tr><td><strong>Linked " +
              "DID</strong></td><td><strong>Checks</strong></td></tr>" +
          rows + "</table>";
      }
      status("did_linkage_status", result.linked
        ? "LINKED: " + origin + " and " + didValue +
            " are the same entity, proved by a Domain " +
          "Linkage Credential signed by that DID's own key at " + result.url +
              "."
        : (result.matched.length
            ? "NOT LINKED: " + origin +
                " publishes a Domain Linkage Credential for " + didValue +
              ", but it does not verify. See the checks below."
            : "NOT LINKED: " + result.url + " vouches for " +
              (result.results.length ? result.results.length +
               " other DID(s)" : "no DID") +
              ", not for " + didValue +
                  ". An origin linking some DID has not linked this one."),
        result.linked ? "vc-ok" : "vc-bad");
    })
    .catch(function (e) {
      status("did_linkage_status", "Could not check the domain linkage: " +
             e.message + " (An issuer " +
        "need not publish this document — it is DIF's, not OID4VCI's — so " +
            "its absence is not a " +
        "failure of the credential.)", "vc-bad");
    });
  log.debug("Leaving verifyDomainLinkage().");
  return false;
}

// ---------------------------------------------------------------------------
// The document's members, as an editable table.
//
// Built from DID_METADATA in did.js — the same list, with the same
// descriptions, that the resolved document populates — so the page cannot
// describe a member the module does not know about. Editable on purpose: this
// is where you try a document an issuer has not published yet, or break one
// deliberately to watch the verification refuse it.
// ---------------------------------------------------------------------------
function renderMembersTable() {
  log.debug("Entering renderMembersTable().");
  var host = el("did_members_table");
  if (!host) {
    log.debug("Leaving renderMembersTable(). No host element.");
    return;
  }
  var html = "<table class='vc-config-table'><tbody>";
  html += metadataClient.groupRow("DID Document",
                                  "W3C DID Core 1.0, from the pane above");
  didLib.DID_METADATA.forEach(function (m) {
    html += metadataClient.fieldRow(didLib.idFor(m.name), m.name, m.desc,
                                    m.type);
  });
  html += "</tbody></table>";
  host.innerHTML = html;
  // Whatever a previous visit resolved, so the page opens where it was left.
  didLib.DID_METADATA.forEach(function (m) {
    var stored = sdJwtVc.get(storeKey(didLib.idFor(m.name)));
    if (stored !== null && stored !== undefined) setVal(didLib.idFor(m.name),
        stored);
  });
  log.debug("Leaving renderMembersTable(). " + didLib.DID_METADATA.length +
            " member(s).");
}

// Save the fields this page owns, so a reload does not lose them. The document
// members are written by populateFromDidDocument() as they are resolved; these
// two are typed by hand.
function saveState() {
  log.debug("Entering saveState().");
  sdJwtVc.set(DID_ID_KEY, val(DID_ID_FIELD));
  sdJwtVc.set(DID_URL_KEY, val(DID_URL_FIELD));
  sdJwtVc.set(ORIGIN_KEY, val(ORIGIN_FIELD));
  status("did_save_status", "Saved.", "vc-ok");
  log.debug("Leaving saveState().");
  return false;
}

// What this browser is holding, said plainly, because two of the checks on this
// page are about a credential and are worth nothing without one.
function renderHeldCredential() {
  log.debug("Entering renderHeldCredential().");
  var raw = (sdJwtVc.get(sdJwtVc.KEYS.CREDENTIAL) || "").trim();
  if (!raw) {
    status("did_credential_status",
           "No credential is held in this browser. Resolving and reading a " +
      "document still works; Verify Signing Key needs one, because it asks " +
          "whether a key this " +
      "document publishes actually signed it.", "vc-pending");
    log.debug("Leaving renderHeldCredential(). Nothing held.");
    return;
  }
  var parsed = null;
  try {
    parsed = sdJwtVc.parseCredential(raw);
  } catch (e) {
    status("did_credential_status",
           "A credential is held but could not be parsed: " + e.message,
           "vc-bad");
    log.debug("Leaving renderHeldCredential(). Unparseable.");
    return;
  }
  var named = parsed.format === sdJwtVc.FORMAT_LDP_VC
    ? ((parsed.document || {}).issuer || "")
    : ((parsed.payload || {}).iss || "");
  status("did_credential_status", "Holding a " + parsed.format +
         " credential issued by " +
    (named || "(no issuer named)") + (didLib.isDid(named) ?
     " — which is a DID, so it can be resolved above." :
      " — which is not a DID, so this document describes something else."),
          "vc-ok");
  log.debug("Leaving renderHeldCredential(). format=" + parsed.format);
}

function onload() {
  log.debug("Entering onload().");
  renderMembersTable();

  // Restore what was typed last time, and default the origin from the
  // credential issuer this browser last discovered — the common thing to ask
  // about, without limiting the page to it.
  setVal(DID_ID_FIELD, sdJwtVc.get(DID_ID_KEY) || "");
  setVal(DID_URL_FIELD, sdJwtVc.get(DID_URL_KEY) || "");
  var origin = sdJwtVc.get(ORIGIN_KEY) || "";
  if (!origin) {
    var issuer = sdJwtVc.get(vciMetadata.idFor("credential_issuer")) || "";
    if (issuer) {
      try {
        origin = new URL(issuer).origin;
      } catch (e) {
        // Not a URL, so it has no origin to offer as a default. The field stays
        // empty and the user types one.
        log.debug("onload(): the stored credential issuer is not a URL.");
      }
    }
  }
  setVal(ORIGIN_FIELD, origin);

  renderHeldCredential();
  log.debug("DID Tools ready.");
  log.debug("Leaving onload().");
}

if (typeof window !== "undefined") {
  window.addEventListener("load", onload);
}

module.exports = {
  resolveDid: resolveDid,
  retrieveDidDocument: retrieveDidDocument,
  uploadDidDocument: uploadDidDocument,
  onDidFileChange: onDidFileChange,
  clearDidDocument: clearDidDocument,
  verifyDidBinding: verifyDidBinding,
  verifyDomainLinkage: verifyDomainLinkage,
  renderMembersTable: renderMembersTable,
  renderHeldCredential: renderHeldCredential,
  saveState: saveState,
  togglePane: togglePane,
  onload: onload
};
