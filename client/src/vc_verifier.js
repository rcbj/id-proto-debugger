// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: vc_verifier.js
//
// ---------------------------------------------------------------------------
// THE DEBUGGER AS AN OPENID4VP 1.0 VERIFIER (#364): vc-verifier.html.
//
// This file is the page and nothing else. What a Verifier COMPOSES (the DCQL
// query, the certificate, the signed Request Object, the invocation URI) and
// how it CHECKS an answer are `vp_verifier.js`, which has no DOM so that
// tests/vp_verifier_engine.js can drive all of it in node.
//
// WHY THE API IS INVOLVED. `direct_post` has the wallet POST its answer to a
// `response_uri`, and a request by reference has it GET (or POST) a
// `request_uri`. A page can be neither, so the api hosts both on the page's
// behalf (api/oid4vp_verifier.js, docs/vc-verifier-api.md), exactly as it
// hosts the Shared Signals push receiver. The api is a STORE: the page signs
// the Request Object with a key that never leaves this tab, hands the api the
// compact JWS and the root certificate the leaf's Authority Information
// Access names, and polls for what the wallet sent. Without an api (the static
// sites) the page can still check an answer pasted into pane 4.
//
// NOTHING SECRET IS STORED. The request's private key, the response
// decryption key and the api session's secret live in this page load only;
// VERIFIER_KEYS below is the configuration a reader would otherwise retype.
// ---------------------------------------------------------------------------

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var verifier = require("./vp_verifier");
var qrcode = require("qrcode-generator");

var log = bunyan.createLogger({ name: "vc_verifier",
                                level: appconfig.logLevel });

var API_URL = appconfig.apiUrl || "";
var BACKEND_AVAILABLE = appconfig.backendAvailable !== false;
var POLL_MS = 2000;
// While a wallet waits on a live signature (request_uri_method=post).
var LIVE_POLL_MS = 500;

// The fields remembered across page loads (localStorage, under their ids).
// Configuration only: see the header.
var VERIFIER_KEYS = [
  "vpv_query_id", "vpv_format", "vpv_type", "vpv_claims", "vpv_binding",
  "vpv_dcql", "vpv_client_prefix", "vpv_response_mode", "vpv_delivery",
  "vpv_scheme", "vpv_redirect_uri", "vpv_client_id_typed", "vpv_dc_signed",
  "vpv_trust_anchors"
];

// The trust anchors typed into pane 2, one string per PEM certificate.
// Public certificates, so they are remembered like the other settings.
function trustAnchorsFromPage() {
  log.debug("Entering trustAnchorsFromPage().");
  var found = val("vpv_trust_anchors").match(
    /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [];
  log.debug("Leaving trustAnchorsFromPage(). " + found.length);
  return found;
}

// The label of the type field, per format: what DCQL's `meta` calls it.
var TYPE_LABELS = {
  "dc+sd-jwt": "vct",
  "jwt_vc_json": "type values",
  "mso_mdoc": "doctype",
  "ldp_vc": "type values"
};

// This page load's request: everything verifyResponse() needs, plus the api
// session that hosts it. Null until "Create the request".
var current = null;
var pollTimer = null;

function el(id) {
  log.debug("Entering el().");
  log.debug("Leaving el().");
  return document.getElementById(id);
}

function val(id) {
  log.debug("Entering val(). " + id);
  var e = el(id);
  if (!e) {
    log.debug("Leaving val(). No element.");
    return "";
  }
  if (e.type === "checkbox") {
    log.debug("Leaving val(). A checkbox.");
    return e.checked ? "1" : "";
  }
  log.debug("Leaving val().");
  return String(e.value || "");
}

function setVal(id, v) {
  log.debug("Entering setVal(). " + id);
  var e = el(id);
  if (!e) {
    log.debug("Leaving setVal(). No element.");
    return;
  }
  if (e.type === "checkbox") {
    e.checked = !!v && v !== "0";
    log.debug("Leaving setVal(). A checkbox.");
    return;
  }
  e.value = v;
  log.debug("Leaving setVal().");
}

function setText(id, text, cls) {
  log.debug("Entering setText(). " + id);
  var e = el(id);
  if (!e) {
    log.debug("Leaving setText(). No element.");
    return;
  }
  e.textContent = text;
  e.className = "vc-note vc-status" + (cls ? " " + cls : "");
  log.debug("Leaving setText().");
}

function togglePane(id) {
  log.debug("Entering togglePane().");
  var fs = el(id);
  if (fs) {
    fs.style.display = (fs.style.display === "none") ? "block" : "none";
  }
  log.debug("Leaving togglePane().");
  return false;
}

// ---------------------------------------------------------------------------
// STATE.
// ---------------------------------------------------------------------------
function saveState() {
  log.debug("Entering saveState().");
  try {
    VERIFIER_KEYS.forEach(function (id) {
      var v = val(id);
      if (el(id) && el(id).type === "checkbox") {
        localStorage.setItem(id, v ? "1" : "0");
      } else if (v) {
        localStorage.setItem(id, v);
      } else {
        localStorage.removeItem(id);
      }
    });
  } catch (e) {
    // No storage for this origin. Every field still works; nothing is kept.
    log.debug("saveState(): no storage — " + e.message);
  }
  log.debug("Leaving saveState().");
}

function loadState() {
  log.debug("Entering loadState().");
  try {
    VERIFIER_KEYS.forEach(function (id) {
      var stored = localStorage.getItem(id);
      if (stored !== null && el(id)) {
        setVal(id, stored);
      }
    });
  } catch (e) {
    log.debug("loadState(): no storage — " + e.message);
  }
  log.debug("Leaving loadState().");
}

// ---------------------------------------------------------------------------
// 1. WHAT TO ASK FOR.
// ---------------------------------------------------------------------------

// "address.country" -> ["address", "country"]; a number is an array index and
// `*` every element, as DCQL claims paths have them (section 7).
function pathOf(line) {
  log.debug("Entering pathOf().");
  var path = String(line).trim().split(".").filter(function (one) {
    return one.length > 0;
  }).map(function (one) {
    if (one === "*") {
      return null;
    }
    return /^\d+$/.test(one) ? Number(one) : one;
  });
  log.debug("Leaving pathOf(). " + path.length + " segment(s).");
  return path;
}

// The single credential query the fields describe.
function querySpec() {
  log.debug("Entering querySpec().");
  var format = val("vpv_format") || "dc+sd-jwt";
  var types = val("vpv_type").split(/\s+/).filter(Boolean);
  var spec = {
    id: val("vpv_query_id") || "credential",
    format: format,
    claims: val("vpv_claims").split(/\n/).filter(function (line) {
      return line.trim().length > 0;
    }).map(pathOf),
    requireBinding: !!val("vpv_binding")
  };
  if (format === "dc+sd-jwt") {
    spec.vct = types;
  } else if (format === "mso_mdoc") {
    spec.doctype = types[0] || "";
  } else {
    spec.types = types;
  }
  log.debug("Leaving querySpec(). " + format);
  return spec;
}

function regenerateDcql() {
  log.debug("Entering regenerateDcql().");
  try {
    var dcql = verifier.buildDcql({ queries: [querySpec()] });
    setVal("vpv_dcql", JSON.stringify(dcql, null, 2));
    setText("vpv_dcql_status", "Generated from the fields above.", "vc-ok");
  } catch (e) {
    // Not generated (#468, M4): the query the fields describe is one a
    // Wallet must reject — most often a type field left empty, which
    // Appendix B makes REQUIRED for every format. The last query that WAS
    // generated is cleared, so "Create the request" cannot quietly send a
    // query the fields no longer describe.
    setVal("vpv_dcql", "");
    setText("vpv_dcql_status", "Not generated: " + e.message, "vc-bad");
  }
  saveState();
  log.debug("Leaving regenerateDcql().");
  return false;
}

function showTypeLabel() {
  log.debug("Entering showTypeLabel().");
  var label = el("vpv_type_label");
  if (label) {
    label.textContent = TYPE_LABELS[val("vpv_format")] || "type";
  }
  log.debug("Leaving showTypeLabel().");
}

function formatChanged() {
  log.debug("Entering formatChanged().");
  showTypeLabel();
  regenerateDcql();
  log.debug("Leaving formatChanged().");
  return false;
}

function settingsChanged() {
  log.debug("Entering settingsChanged().");
  // An unsigned request has nothing to fetch by reference: section 5.10's
  // request_uri carries a Request Object, which is signed.
  if (val("vpv_client_prefix") === "redirect_uri") {
    setVal("vpv_delivery", "value");
  }
  var row = el("vpv_client_id_row");
  if (row) {
    row.style.display = val("vpv_client_prefix") === "pre-registered"
      ? "" : "none";
  }
  var mode = val("vpv_response_mode");
  var dcNote = el("vpv_dc_api_note");
  if (dcNote) {
    dcNote.textContent = mode === "dc_api" || mode === "dc_api.jwt"
      ? "Nothing is hosted: the browser hands the request to a wallet " +
        "and the answer comes back to this page."
      : "";
  }
  saveState();
  log.debug("Leaving settingsChanged().");
  return false;
}

// The DCQL as the reader left it in the textarea, which wins over the fields.
function dcqlFromPage() {
  log.debug("Entering dcqlFromPage().");
  var text = val("vpv_dcql").trim();
  if (!text) {
    var built = verifier.buildDcql({ queries: [querySpec()] });
    log.debug("Leaving dcqlFromPage(). Built from the fields.");
    return built;
  }
  var parsed = JSON.parse(text);
  if (!parsed || !Array.isArray(parsed.credentials) ||
      !parsed.credentials.length) {
    log.debug("Leaving dcqlFromPage(). No credentials.");
    throw new Error("The DCQL query has no credentials array.");
  }
  log.debug("Leaving dcqlFromPage().");
  return parsed;
}

// ---------------------------------------------------------------------------
// THE API, which hosts request_uri and response_uri.
// ---------------------------------------------------------------------------
async function apiJson(method, path, body, secret) {
  log.debug("Entering apiJson(). " + method + " " + path);
  var headers = { Accept: "application/json" };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  if (secret) {
    headers.Authorization = "Bearer " + secret;
  }
  var response = await fetch(API_URL + path, {
    method: method, headers: headers,
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  var text = await response.text();
  var json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch (e) {
    log.debug("apiJson(): not JSON.");
    json = null;
  }
  if (!response.ok) {
    var why = (json && (json.error_description || json.error ||
                        (json.errors && json.errors.join("; ")))) ||
              text.slice(0, 200);
    log.debug("Leaving apiJson(). " + response.status);
    throw new Error(method + " " + path + " answered " + response.status +
                    (why ? ": " + why : ""));
  }
  log.debug("Leaving apiJson(). " + response.status);
  return json;
}

async function probeApi() {
  log.debug("Entering probeApi().");
  if (!BACKEND_AVAILABLE || !API_URL) {
    setText("vpv_api_status", "This deployment has no api, so it cannot " +
      "host a request_uri or a response_uri. An answer a wallet produced " +
      "can still be pasted into pane 4 and checked.", "vc-pending");
    log.debug("Leaving probeApi(). No backend.");
    return false;
  }
  try {
    var limits = await apiJson("GET", "/oid4vp/verifier/limits");
    if (limits && limits.enabled === false) {
      setText("vpv_api_status", "The api at " + API_URL + " has its " +
        "Verifier endpoints switched off (oid4vpVerifierEnabled).",
        "vc-bad");
      log.debug("Leaving probeApi(). Disabled.");
      return false;
    }
    setText("vpv_api_status", "The api at " + API_URL + " will host this " +
      "request's request_uri and response_uri.", "vc-ok");
    log.debug("Leaving probeApi(). Available.");
    return true;
  } catch (e) {
    setText("vpv_api_status", "The api at " + API_URL + " did not answer " +
      "(" + e.message + "). Pane 4 still checks a pasted answer.", "vc-bad");
    log.debug("Leaving probeApi(). " + e.message);
    return false;
  }
}

// ---------------------------------------------------------------------------
// 2. HOW TO ASK, and 3. HANDING IT OVER.
// ---------------------------------------------------------------------------
function base64OfBytes(bytes) {
  log.debug("Entering base64OfBytes().");
  var binary = "";
  var view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (var i = 0; i < view.length; i++) {
    binary += String.fromCharCode(view[i]);
  }
  log.debug("Leaving base64OfBytes().");
  return btoa(binary);
}

// A compact JWS's header and payload, pretty-printed, for pane 3.
function decodeJws(compact) {
  log.debug("Entering decodeJws().");
  var parts = String(compact || "").split(".");
  var decode = function (part) {
    var padded = part.replace(/-/g, "+").replace(/_/g, "/");
    while (padded.length % 4 !== 0) {
      padded += "=";
    }
    return JSON.parse(decodeURIComponent(escape(atob(padded))));
  };
  try {
    var text = JSON.stringify({ header: decode(parts[0]),
                                payload: decode(parts[1]) }, null, 2);
    log.debug("Leaving decodeJws().");
    return text;
  } catch (e) {
    log.debug("Leaving decodeJws(). " + e.message);
    return "(not a JWS: " + e.message + ")";
  }
}

// THE PREFIXES THAT NEED A CERTIFICATE. The others sign with a bare key
// (decentralized_identifier, verifier_attestation, pre-registered).
var X509_PREFIXES = ["x509_hash", "x509_san_dns", "redirect_uri"];

// The key a request is signed with, and what a wallet must be given to
// trust it, for one Client Identifier prefix. `dnsName` is the host the
// certificate names; `caIssuersUrl` the api URL serving its root (absent
// under the DC API, where nothing is hosted).
async function makeSigner(prefix, dnsName, caIssuersUrl) {
  log.debug("Entering makeSigner(). " + prefix);
  var signer = { prefix: prefix, attester: null, trust: "" };
  if (X509_PREFIXES.indexOf(prefix) >= 0) {
    // THE CERTIFICATE NEEDS WEB CRYPTO until #463 moves x509.js and
    // key_material.js onto the pure-JS module. Said here by name rather
    // than left to fail as "Cannot read properties of undefined".
    if (typeof crypto === "undefined" || !crypto.subtle) {
      log.debug("Leaving makeSigner(). No secure context.");
      throw new Error("This page is not in a secure context (https or " +
        "localhost), so the browser offers no Web Crypto, and the " +
        "certificate an x509 Client Identifier is signed with cannot be " +
        "made (#463). The decentralized_identifier, verifier_attestation " +
        "and pre-registered prefixes need no certificate.");
    }
    signer.identity = await verifier.makeVerifierIdentity({
      dnsName: dnsName, caIssuersUrl: caIssuersUrl });
    signer.trust = signer.identity.rootPem || "";
  } else {
    signer.identity = await verifier.makeRequestKey();
    if (prefix === "verifier_attestation") {
      signer.attester = await verifier.makeAttester();
      signer.trust = "The attester's keys (trust these):\n" +
        JSON.stringify(signer.attester.jwks, null, 2);
    } else if (prefix === "pre-registered") {
      signer.trust = "The JWKS the wallet must hold for this client_id:\n" +
        JSON.stringify(verifier.preRegisteredJwks(signer.identity), null, 2);
    }
  }
  signer.dnsName = dnsName;
  log.debug("Leaving makeSigner().");
  return signer;
}

function clientIdOf(signer, redirectUri) {
  log.debug("Entering clientIdOf(). " + signer.prefix);
  var id = verifier.clientIdFor(signer.prefix, signer.identity, {
    dnsName: signer.dnsName, redirectUri: redirectUri,
    clientId: val("vpv_client_id_typed").trim() || undefined,
    didMethod: "jwk" });
  if (signer.prefix === "decentralized_identifier") {
    signer.trust = "The Verifier's DID; it resolves with no network:\n" + id;
  }
  log.debug("Leaving clientIdOf(). " + id);
  return id;
}

async function signWith(signer, claims) {
  log.debug("Entering signWith(). " + signer.prefix);
  var jws = await verifier.signRequestObject({
    claims: claims, identity: signer.identity,
    attester: signer.attester || undefined });
  log.debug("Leaving signWith().");
  return jws;
}

// The invocation as a QR code, for a wallet on another device. A request by
// value can be too long for one; the page says so rather than drawing a
// code no camera can read.
function showQr(invocation) {
  log.debug("Entering showQr().");
  var host = el("vpv_qr");
  if (!host) {
    log.debug("Leaving showQr(). No element.");
    return;
  }
  host.innerHTML = "";
  if (!invocation) {
    setText("vpv_qr_note", "");
    log.debug("Leaving showQr(). Nothing to draw.");
    return;
  }
  try {
    var code = qrcode(0, "L");
    code.addData(invocation);
    code.make();
    // createSvgTag() draws rectangles from the bits alone; nothing of the
    // invocation's text reaches the markup.
    host.innerHTML = code.createSvgTag({ cellSize: 4, margin: 4,
                                         scalable: true });
    setText("vpv_qr_note", "Scan with a wallet on another device (" +
      invocation.length + " characters).", "vc-ok");
  } catch (e) {
    setText("vpv_qr_note", "Too long for a QR code (" + invocation.length +
      " characters): hand it over by reference instead.", "vc-pending");
  }
  log.debug("Leaving showQr().");
}

async function createRequest() {
  log.debug("Entering createRequest().");
  saveState();
  stopPolling();
  var mode = val("vpv_response_mode") || "direct_post";
  if (mode === "dc_api" || mode === "dc_api.jwt") {
    log.debug("Leaving createRequest(). The Digital Credentials API.");
    return askThroughDcApi();
  }
  setText("vpv_create_status", "Working …", "vc-pending");
  try {
    var dcql = dcqlFromPage();
    if (!(await probeApi())) {
      throw new Error("There is no api to host the request and the answer.");
    }
    var prefix = val("vpv_client_prefix") || "x509_hash";
    var delivery = prefix === "redirect_uri" ? "value"
      : (val("vpv_delivery") || "reference-get");
    var live = delivery === "reference-post";
    var redirectUri = val("vpv_redirect_uri").trim();
    var create = { liveSigning: live };
    if (redirectUri) {
      create.redirectUri = redirectUri;
    }
    var hosted = await apiJson("POST", "/oid4vp/verifier", create);
    var signer = await makeSigner(prefix,
      new URL(hosted.responseUri).hostname, hosted.caIssuersUrl);
    var encryption = mode === "direct_post.jwt"
      ? await verifier.responseEncryptionKey() : null;
    var clientId = clientIdOf(signer, hosted.responseUri);
    var nonce = verifier.randomToken(16);
    var state = verifier.randomToken(16);
    var claimsInput = {
      clientId: clientId, responseUri: hosted.responseUri,
      responseMode: mode, nonce: nonce, state: state, dcql: dcql,
      encryptionJwk: encryption ? encryption.publicJwk : undefined
    };
    var claims = verifier.requestObjectClaims(claimsInput);
    var requestObject = "";
    var invocation;
    if (prefix === "redirect_uri") {
      // Unsigned, by value: the claims ARE the parameters (section 5.1).
      var params = {};
      Object.keys(claims).forEach(function (name) {
        if (name === "iss" || name === "aud" || name === "iat" ||
            name === "exp" || name === "client_id") {
          return;
        }
        var v = claims[name];
        params[name] = typeof v === "string" ? v : JSON.stringify(v);
      });
      invocation = verifier.authorizationRequestUri({
        scheme: val("vpv_scheme"), clientId: clientId, params: params });
    } else {
      requestObject = await signWith(signer, claims);
      var published = { requestObject: requestObject,
                        redirectUri: redirectUri || undefined };
      if (signer.identity.rootDer) {
        published.caCertificate = base64OfBytes(signer.identity.rootDer);
      }
      await apiJson("PUT", "/oid4vp/verifier/" + hosted.id + "/request",
                    published, hosted.secret);
      invocation = delivery === "value"
        ? verifier.authorizationRequestUri({
          scheme: val("vpv_scheme"), clientId: clientId,
          requestObject: requestObject })
        : verifier.authorizationRequestUri({
          scheme: val("vpv_scheme"), clientId: clientId,
          requestUri: hosted.requestUri,
          requestUriMethod: live ? "post" : undefined,
          // Section 5.1: under post the Verifier SHOULD send its
          // capabilities beside request_uri (#468, M8).
          clientMetadata: live ? claims.client_metadata : undefined });
    }
    current = {
      hosted: hosted,
      identity: signer.identity,
      signer: signer,
      claimsInput: claimsInput,
      live: live,
      session: {
        clientId: clientId, nonce: nonce, state: state,
        responseUri: hosted.responseUri, responseMode: mode, dcql: dcql,
        decryptionJwk: encryption ? encryption.privateJwk : undefined
      },
      after: 0,
      answered: false
    };
    showRequest(invocation, clientId, requestObject, claims);
    setText("vpv_create_status", "The request is ready. Hand it to a " +
      "wallet (pane 3); its answer will appear in pane 4.", "vc-ok");
    startPolling();
  } catch (e) {
    log.warn("createRequest(): " + e.message);
    setText("vpv_create_status", e.message, "vc-bad");
  }
  log.debug("Leaving createRequest().");
  return false;
}

// THE DIGITAL CREDENTIALS API (OpenID4VP 1.0 Appendix A): the browser hands
// the request to a wallet the platform knows, and the answer comes back to
// this page, so nothing is hosted. Unsigned, the Client Identifier is this
// page's origin; signed, the request names its Client Identifier and lists
// this origin in expected_origins.
async function askThroughDcApi() {
  log.debug("Entering askThroughDcApi().");
  saveState();
  stopPolling();
  setText("vpv_create_status", "Working …", "vc-pending");
  try {
    if (typeof navigator === "undefined" || !navigator.credentials ||
        typeof DigitalCredential === "undefined") {
      throw new Error("This browser has no Digital Credentials API " +
        "(navigator.credentials.get with `digital`). It is in recent " +
        "Chromium-based browsers, on a secure origin, with a wallet the " +
        "platform knows.");
    }
    var mode = val("vpv_response_mode");
    if (mode !== "dc_api" && mode !== "dc_api.jwt") {
      mode = "dc_api";
    }
    var signed = !!val("vpv_dc_signed");
    var origin = window.location.origin;
    var dcql = dcqlFromPage();
    var encryption = mode === "dc_api.jwt"
      ? await verifier.responseEncryptionKey() : null;
    var nonce = verifier.randomToken(16);
    var signer = null;
    var clientId;
    if (signed) {
      var prefix = val("vpv_client_prefix") || "x509_hash";
      if (prefix === "redirect_uri") {
        throw new Error("A signed Digital Credentials API request needs a " +
          "Client Identifier a signature can stand for; redirect_uri " +
          "requests are unsigned. Untick \"signed\" to ask as this origin.");
      }
      signer = await makeSigner(prefix, window.location.hostname, undefined);
      clientId = clientIdOf(signer, undefined);
    } else {
      clientId = verifier.clientIdFor("origin", null, { origin: origin });
    }
    var claims = verifier.requestObjectClaims({
      clientId: signed ? clientId : undefined, responseMode: mode,
      nonce: nonce, dcql: dcql,
      encryptionJwk: encryption ? encryption.publicJwk : undefined,
      expectedOrigins: signed ? [origin] : undefined });
    var request = await verifier.dcApiRequest({
      signed: signed, claims: claims,
      identity: signer ? signer.identity : undefined, origin: origin,
      attester: signer && signer.attester ? signer.attester : undefined });
    current = {
      hosted: null, identity: signer ? signer.identity : {}, signer: signer,
      live: false,
      session: { clientId: clientId, nonce: nonce, responseMode: mode,
                 dcql: dcql, origin: origin,
                 decryptionJwk: encryption ? encryption.privateJwk
                                           : undefined },
      after: 0, answered: false
    };
    setVal("vpv_invocation", JSON.stringify(request, null, 2));
    setVal("vpv_client_id", clientId);
    setVal("vpv_request_uri", "");
    setVal("vpv_response_uri", "");
    setVal("vpv_request_object", request.data && request.data.request
      ? decodeJws(request.data.request)
      : JSON.stringify(request.data, null, 2));
    setVal("vpv_root_pem", signer && signer.identity.rootPem || "");
    setVal("vpv_trust_out", signer ? signer.trust : "");
    showQr("");
    clearVerdict();
    setText("vpv_create_status", "Asking the browser for a credential " +
      "(" + request.protocol + ") …", "vc-pending");
    var credential = await navigator.credentials.get({
      digital: { requests: [request] } });
    var data = credential && credential.data;
    if (typeof data === "string") {
      data = JSON.parse(data);
    }
    current.answered = true;
    setText("vpv_create_status", "The wallet answered through the " +
      "browser (" + (credential && credential.protocol || "?") + ").",
      "vc-ok");
    await checkFields(data || {});
  } catch (e) {
    log.warn("askThroughDcApi(): " + e.message);
    setText("vpv_create_status", e.message, "vc-bad");
  }
  log.debug("Leaving askThroughDcApi().");
  return false;
}

// THE SAME-DEVICE FLOW without a redirect_uri (#468, M3). "Open it on this
// device" is the same-device flow, and HAIP 1.0 section 5.1 says of it:
// "Verifiers MUST include redirect_uri in the HTTP response to the Wallet's
// HTTP POST to the response_uri". This page has no HAIP mode, so it says so
// whenever a request is made with none configured: the wallet's browser
// then has nowhere to return to, and the session binding that redirect
// carries (OpenID4VP section 8.2's fresh value) is absent. A QR code
// scanned by another device needs none.
function sameDeviceNote() {
  log.debug("Entering sameDeviceNote().");
  if (val("vpv_redirect_uri").trim()) {
    setText("vpv_same_device_note", "");
    log.debug("Leaving sameDeviceNote(). Configured.");
    return;
  }
  setText("vpv_same_device_note", "No redirect_uri is configured (pane " +
    "2), so a wallet on THIS device has nowhere to send its browser back " +
    "to. For a same-device flow HAIP 1.0 section 5.1 says Verifiers MUST " +
    "include one; a QR code scanned on another device needs none.",
    "vc-pending");
  log.debug("Leaving sameDeviceNote(). Missing.");
}

function showRequest(invocation, clientId, requestObject, claims) {
  log.debug("Entering showRequest().");
  setVal("vpv_invocation", invocation);
  var link = el("vpv_invocation_link");
  if (link) {
    link.href = invocation;
    link.style.display = "inline";
  }
  showQr(invocation);
  sameDeviceNote();
  setVal("vpv_client_id", clientId);
  setVal("vpv_request_uri", requestObject ? current.hosted.requestUri : "");
  setVal("vpv_response_uri", current.hosted.responseUri);
  setVal("vpv_request_object", requestObject ? decodeJws(requestObject)
    : JSON.stringify(claims, null, 2) + "\n(unsigned: sent as parameters)");
  setVal("vpv_root_pem", current.identity.rootPem || "");
  setVal("vpv_trust_out", current.signer ? current.signer.trust : "");
  var list = el("vpv_events");
  if (list) {
    list.innerHTML = "";
  }
  clearVerdict();
  setText("vpv_wait_status", "Waiting for the wallet …", "vc-pending");
  log.debug("Leaving showRequest().");
}

// ---------------------------------------------------------------------------
// 4. WHAT THE WALLET SENT.
// ---------------------------------------------------------------------------
function stopPolling() {
  log.debug("Entering stopPolling().");
  if (pollTimer) {
    window.clearTimeout(pollTimer);
    pollTimer = null;
  }
  log.debug("Leaving stopPolling().");
}

// While the api holds a wallet's POST open for a live signature it waits
// waitMs (15 s by default), so the page polls fast enough to answer in it.
function pollInterval() {
  log.debug("Entering pollInterval().");
  log.debug("Leaving pollInterval().");
  return current && current.live ? LIVE_POLL_MS : POLL_MS;
}

function startPolling() {
  log.debug("Entering startPolling().");
  stopPolling();
  pollTimer = window.setTimeout(poll, pollInterval());
  log.debug("Leaving startPolling().");
}

function eventLine(event) {
  log.debug("Entering eventLine(). " + event.kind);
  var at = event.at ? new Date(event.at).toISOString() + " " : "";
  var text;
  if (event.kind === "request-fetched") {
    text = at + "The wallet fetched the Request Object (" +
      (event.method || "GET") + ")" +
      (event.walletNonce ? ", sending wallet_nonce " + event.walletNonce
                         : "") +
      (event.signingId ? "; the api is holding it open for a Request " +
        "Object signed with that nonce" : "") + "." +
      (event.problem ? " " + event.problem : "");
  } else if (event.kind === "request-signed") {
    text = at + (event.liveSigned
      ? "This page signed a fresh Request Object for that wallet, " +
        "echoing its wallet_nonce."
      : event.httpStatus
        ? "The wallet was answered HTTP " + event.httpStatus + " (" +
          (event.reason || "no reason given") + ")."
        : "The wallet was not given a Request Object signed for it (" +
          (event.reason || "no reason given") + ").");
  } else if (event.kind === "ca-fetched") {
    text = at + "The wallet fetched the Verifier's root certificate from " +
      "the leaf's Authority Information Access URL.";
  } else if (event.kind === "response") {
    text = at + "The wallet posted its answer (" +
      (event.contentType || "?") + "): " +
      Object.keys(event.fields || {}).join(", ") + "." +
      (event.redirectUri ? " It was sent on to " + event.redirectUri +
        " (response_code " + event.responseCode + ", fresh for this " +
        "answer: section 8.2)." : "");
  } else if (event.kind === "response-refused") {
    text = at + "The api refused a POST to response_uri: " +
      (event.problem || "no reason given") + ".";
  } else {
    text = at + event.kind;
  }
  log.debug("Leaving eventLine().");
  return text;
}

// A wallet POSTed to request_uri and the api is holding it open: sign a
// Request Object carrying its wallet_nonce (section 5.10) and hand it over.
// A 404 means the wait ran out and the wallet already has the one signed in
// advance, which the event that follows will say.
async function signLive(event) {
  log.debug("Entering signLive(). " + event.signingId);
  try {
    var input = Object.assign({}, current.claimsInput, {
      walletNonce: event.walletNonce || undefined });
    var claims = verifier.requestObjectClaims(input);
    var jws = await signWith(current.signer, claims);
    await apiJson("PUT", "/oid4vp/verifier/" + current.hosted.id +
                  "/request/" + encodeURIComponent(event.signingId),
                  { requestObject: jws }, current.hosted.secret);
    setVal("vpv_request_object", decodeJws(jws) + "\n(signed live, for " +
           "wallet_nonce " + (event.walletNonce || "none") + ")");
  } catch (e) {
    setText("vpv_wait_status", "Could not sign a live Request Object: " +
            e.message, "vc-bad");
  }
  log.debug("Leaving signLive().");
}

async function poll() {
  log.debug("Entering poll().");
  pollTimer = null;
  if (!current || current.answered || !current.hosted) {
    log.debug("Leaving poll(). Nothing to wait for.");
    return;
  }
  try {
    var got = await apiJson("GET", "/oid4vp/verifier/" + current.hosted.id +
                            "/events?after=" + current.after, undefined,
                            current.hosted.secret);
    var events = (got && got.events) || [];
    if (got && got.next !== undefined) {
      current.after = got.next;
    }
    var list = el("vpv_events");
    var answer = null;
    var toSign = [];
    events.forEach(function (event) {
      if (list) {
        var li = document.createElement("li");
        li.textContent = eventLine(event);
        list.appendChild(li);
      }
      if (event.kind === "request-fetched" && event.signingId) {
        toSign.push(event);
      }
      if (event.kind === "response" && !answer) {
        answer = event;
      }
    });
    var i;
    for (i = 0; i < toSign.length; i++) {
      await signLive(toSign[i]);
    }
    if (answer) {
      current.answered = true;
      setText("vpv_wait_status", "The wallet answered.", "vc-ok");
      await checkFields(answer.fields || {});
      log.debug("Leaving poll(). Answered.");
      return;
    }
  } catch (e) {
    setText("vpv_wait_status", "Waiting for the wallet; the last poll " +
      "failed: " + e.message, "vc-bad");
  }
  pollTimer = window.setTimeout(poll, pollInterval());
  log.debug("Leaving poll(). Still waiting.");
}

async function fetchJson(url) {
  log.debug("Entering fetchJson(). " + url);
  var response = await fetch(url, { headers: { Accept: "application/json" } });
  if (!response.ok) {
    log.debug("Leaving fetchJson(). " + response.status);
    throw new Error("GET " + url + " answered " + response.status);
  }
  var json = await response.json();
  log.debug("Leaving fetchJson().");
  return json;
}

// The status lists' fetcher. The body is handed over as BYTES with its
// Content-Type, not as text: a Status List Token may be a binary CWT, and
// response.text() would turn it into replacement characters before the
// engine could say what it was. vp_verifier.js decodes UTF-8 itself.
async function fetchText(url, opts) {
  log.debug("Entering fetchText(). " + url);
  var accept = (opts && opts.accept) || "*/*";
  var response = await fetch(url, { headers: { Accept: accept } });
  if (!response.ok) {
    log.debug("Leaving fetchText(). " + response.status);
    throw new Error("GET " + url + " answered " + response.status);
  }
  var body = new Uint8Array(await response.arrayBuffer());
  log.debug("Leaving fetchText(). " + body.length + " bytes.");
  return { body: body, contentType: response.headers.get("content-type") ||
    "" };
}

function clearVerdict() {
  log.debug("Entering clearVerdict().");
  var table = el("vpv_checks");
  if (table) {
    table.innerHTML = "";
  }
  setVal("vpv_claims_out", "");
  var out = el("vpv_claims_out");
  if (out) {
    out.textContent = "";
  }
  setText("vpv_verdict", "");
  log.debug("Leaving clearVerdict().");
}

// One row per check, every one of them, built as text: the detail of a check
// often quotes what the wallet sent.
function renderChecks(result) {
  log.debug("Entering renderChecks().");
  clearVerdict();
  var table = el("vpv_checks");
  (result.checks || []).forEach(function (check) {
    if (!table) {
      return;
    }
    var row = table.insertRow(-1);
    row.id = "vpv_check_" + check.id;
    row.className = "vc-check-" + check.status +
      (check.essential && check.status === "skip" ? " vc-check-unperformed" :
       "");
    [check.status.toUpperCase(), check.group || "", check.label || check.id,
     check.detail || ""].forEach(function (text) {
      row.insertCell(-1).textContent = text;
    });
  });
  var failed = (result.checks || []).filter(function (check) {
    return check.status === "fail";
  }).length;
  var total = (result.checks || []).length;
  // Three verdicts (#467, S4). "incomplete" is nothing failed AND an
  // essential check — an issuer proof, an x5c chain's anchor, a holder
  // signature — was not performed. It is not a pass and is not drawn as
  // one: the presentation's authenticity was never established.
  var verdict = result.verdict || (result.ok ? "pass" : "fail");
  if (verdict === "pass") {
    setText("vpv_verdict", "Every check passed (" + total + ").", "vc-ok");
  } else if (verdict === "incomplete") {
    setText("vpv_verdict", "Nothing failed, but " + result.incomplete +
      " essential check" + (result.incomplete === 1 ? "" : "s") +
      " could not be performed, so this presentation is NOT verified " +
      "(the rows marked SKIP that establish authenticity say why).",
      "vc-warn");
  } else {
    setText("vpv_verdict", failed + " of " + total + " checks failed.",
            "vc-bad");
  }
  var out = el("vpv_claims_out");
  if (out) {
    out.textContent = JSON.stringify(result.presentations || [], null, 2);
  }
  log.debug("Leaving renderChecks(). failed=" + failed);
}

async function checkFields(fields) {
  log.debug("Entering checkFields().");
  if (!current) {
    setText("vpv_verdict", "There is no request on this page to check the " +
      "answer against. Create one first: the nonce, the state and the " +
      "client_id an answer is held to are this page's.", "vc-bad");
    log.debug("Leaving checkFields(). No request.");
    return null;
  }
  try {
    var result = await verifier.verifyResponse({
      fields: fields,
      session: Object.assign({}, current.session,
                             { trustAnchors: trustAnchorsFromPage() }),
      fetchJson: fetchJson, fetchText: fetchText,
      now: Math.floor(Date.now() / 1000) });
    renderChecks(result);
    log.debug("Leaving checkFields(). ok=" + result.ok);
    return result;
  } catch (e) {
    setText("vpv_verdict", "The answer could not be checked: " + e.message,
            "vc-bad");
    log.debug("Leaving checkFields(). " + e.message);
    return null;
  }
}

async function checkPasted() {
  log.debug("Entering checkPasted().");
  var text = val("vpv_pasted").trim();
  var fields;
  try {
    fields = text.charAt(0) === "{" ? JSON.parse(text)
                                    : verifier.parseResponse(text).raw;
  } catch (e) {
    setText("vpv_verdict", "That is neither a form body nor JSON: " +
            e.message, "vc-bad");
    log.debug("Leaving checkPasted(). Unreadable.");
    return false;
  }
  await checkFields(fields || {});
  log.debug("Leaving checkPasted().");
  return false;
}

async function reset() {
  log.debug("Entering reset().");
  stopPolling();
  if (current && current.hosted) {
    try {
      await apiJson("DELETE", "/oid4vp/verifier/" + current.hosted.id,
                    undefined, current.hosted.secret);
    } catch (e) {
      log.debug("reset(): the api session was already gone — " + e.message);
    }
  }
  current = null;
  ["vpv_invocation", "vpv_client_id", "vpv_request_uri", "vpv_response_uri",
   "vpv_request_object", "vpv_root_pem", "vpv_trust_out"
  ].forEach(function (id) {
    setVal(id, "");
  });
  var link = el("vpv_invocation_link");
  if (link) {
    link.style.display = "none";
  }
  showQr("");
  setText("vpv_same_device_note", "");
  var list = el("vpv_events");
  if (list) {
    list.innerHTML = "";
  }
  clearVerdict();
  setText("vpv_wait_status", "No request yet.");
  setText("vpv_create_status", "Started over.");
  log.debug("Leaving reset().");
  return false;
}

// The current request, for tests/vc_verifier_page.js, which plays the wallet
// in node and has to know what it is answering. Read-only copies.
function currentRequest() {
  log.debug("Entering currentRequest().");
  if (!current) {
    log.debug("Leaving currentRequest(). None.");
    return null;
  }
  var copy = JSON.parse(JSON.stringify({
    session: Object.assign({}, current.session, { decryptionJwk: undefined }),
    hosted: current.hosted ? {
      id: current.hosted.id, requestUri: current.hosted.requestUri,
      responseUri: current.hosted.responseUri,
      caIssuersUrl: current.hosted.caIssuersUrl } : null,
    trust: current.signer ? current.signer.trust : "",
    invocation: val("vpv_invocation")
  }));
  log.debug("Leaving currentRequest().");
  return copy;
}

function onload() {
  log.debug("Entering onload().");
  loadState();
  showTypeLabel();
  // A DCQL the reader edited by hand is kept; one is generated only when
  // there is none.
  if (!val("vpv_dcql").trim()) {
    regenerateDcql();
  }
  settingsChanged();
  probeApi();
  log.debug("Leaving onload().");
}

if (typeof window !== "undefined") {
  window.addEventListener("load", onload);
}

module.exports = {
  togglePane: togglePane,
  regenerateDcql: regenerateDcql,
  formatChanged: formatChanged,
  settingsChanged: settingsChanged,
  createRequest: createRequest,
  checkPasted: checkPasted,
  askThroughDcApi: askThroughDcApi,
  reset: reset,
  currentRequest: currentRequest,
  onload: onload
};
