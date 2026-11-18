// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: vc_client_auth_pane.js
//
// ---------------------------------------------------------------------------
// The VC issuance workflow's CLIENT AUTHENTICATION pane: the settings on
// step 1, and on every page that calls the token endpoint (step 2's
// pre-authorized code grant, step 4's refresh) the fields that cannot be
// stored. client_auth.js does the work; this is the DOM around it.
//
// What is kept, and where (models/storage/sd_jwt_vc.tsp):
//
//   * the method, the assertion alg, aud choice, kid and typing — ordinary;
//   * private_key_jwt's private key, the Client Attestation, its instance
//     key and a locally generated attester key — KEY MATERIAL, kept only
//     while "Keep the client keys in this browser" is checked (it is by
//     default), and purged the moment it is cleared;
//   * the client SECRET — NEVER (root CLAUDE.md, "State persistence"). It is
//     typed into vc_client_secret on each page that needs it and used for
//     that page load only; secret_storage.js lists the field id so
//     tests/secret_storage_engine.js fails on any write of it.
//
// The method is the one CHOSEN on step 1, and `none` until one is: a
// credentialed method is never picked for the user, because a public
// client (the workflow's default) made to authenticate with a key or
// secret it does not have is refused by every server that checks. The
// authorization server's token_endpoint_auth_methods_supported is shown
// beside the choice and orders nothing.
// ---------------------------------------------------------------------------

var clientAuth = require("./client_auth");
var sdJwtVc = require("./sd_jwt_vc");
var opMetadata = require("./op_metadata");
var provider = require("./crypto_provider");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "vc_client_auth_pane",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var KEYS = {
  METHOD: "sdjwtvc_client_auth_method",
  ALG: "sdjwtvc_client_auth_alg",
  AUDIENCE: "sdjwtvc_client_auth_audience",
  KID: "sdjwtvc_client_auth_kid",
  TYPED: "sdjwtvc_client_auth_typed",
  PRIVATE_JWK: "sdjwtvc_client_private_jwk",
  ATTESTATION: "sdjwtvc_client_attestation",
  INSTANCE_JWK: "sdjwtvc_client_instance_private_jwk",
  ATTESTER_JWK: "sdjwtvc_client_attester_private_jwk",
  SAVE_KEYS: "sdjwtvc_save_client_key",
  CHALLENGE: "sdjwtvc_client_attestation_challenge"
};
var KEY_MATERIAL = [KEYS.PRIVATE_JWK, KEYS.ATTESTATION, KEYS.INSTANCE_JWK,
                    KEYS.ATTESTER_JWK];
var SECRET_FIELD = "vc_client_secret";
var ALGS = ["ES256", "ES384", "ES512", "ES256K", "EdDSA", "PS256", "RS256"];
var KEY_SPECS = { ES256: "ec-p256", ES384: "ec-p384", ES512: "ec-p521",
                  ES256K: "ec-secp256k1", EdDSA: "ed25519", PS256: "rsa-2048",
                  RS256: "rsa-2048" };

function el(id) {
  log.debug("Entering el().");
  log.debug("Leaving el().");
  return document.getElementById(id);
}

function val(id) {
  log.debug("Entering val().");
  var e = el(id);
  log.debug("Leaving val().");
  return e ? String(e.value || "").trim() : "";
}

function esc(s) {
  log.debug("Entering esc().");
  log.debug("Leaving esc().");
  return String(s).replace(/[&<>"]/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;" }[c];
  });
}

// --- what the server says ----------------------------------------------------
function supportedMethods() {
  log.debug("Entering supportedMethods().");
  var raw = sdJwtVc.get("token_endpoint_auth_methods_supported") || "";
  var list = raw.split(/\s*,\s*/).filter(function (m) {
    return m && m !== "-->not defined<--";
  });
  log.debug("Leaving supportedMethods(). " + list.length);
  return list;
}

function issuer() {
  log.debug("Entering issuer().");
  var v = sdJwtVc.get("issuer") || "";
  log.debug("Leaving issuer().");
  return v === "-->not defined<--" ? "" : v;
}

// --- the key-material preference ---------------------------------------------
function keysMayBeStored() {
  log.debug("Entering keysMayBeStored().");
  log.debug("Leaving keysMayBeStored().");
  return sdJwtVc.get(KEYS.SAVE_KEYS) !== "0";
}

function forgetStoredKeys() {
  log.debug("Entering forgetStoredKeys().");
  KEY_MATERIAL.forEach(function (k) {
    sdJwtVc.remove(k);
  });
  log.debug("Leaving forgetStoredKeys().");
}

function keep(key, value) {
  log.debug("Entering keep(). " + key);
  if (KEY_MATERIAL.indexOf(key) !== -1 && !keysMayBeStored()) {
    sdJwtVc.remove(key);
    log.debug("Leaving keep(). Not stored: saving is off.");
    return;
  }
  sdJwtVc.set(key, value);
  log.debug("Leaving keep().");
}

function jsonField(id, storageKey) {
  log.debug("Entering jsonField(). " + id);
  var typed = val(id);
  var text = typed || (keysMayBeStored() ? sdJwtVc.get(storageKey) || "" :
                       "");
  if (!text) {
    log.debug("Leaving jsonField(). Empty.");
    return null;
  }
  try {
    log.debug("Leaving jsonField().");
    return JSON.parse(text);
  } catch (e) {
    log.debug("Leaving jsonField(). Not JSON.");
    throw new Error(id + " is not a JSON Web Key.");
  }
}

// --- the settings -----------------------------------------------------------
// The method the user chose on step 1, or "" when none was chosen.
function chosenMethod() {
  log.debug("Entering chosenMethod().");
  var stored = sdJwtVc.get(KEYS.METHOD);
  log.debug("Leaving chosenMethod().");
  return clientAuth.METHODS.indexOf(stored) !== -1 ? stored : "";
}

function method() {
  log.debug("Entering method().");
  log.debug("Leaving method().");
  return chosenMethod() || "none";
}

// What client_auth.apply() needs, from storage and this page's fields.
function settings() {
  log.debug("Entering settings().");
  var m = val("vc_client_auth_method") || method();
  var s = {
    method: m,
    clientId: sdJwtVc.get("token_client_id") || sdJwtVc.get("client_id") ||
      "",
    secret: el(SECRET_FIELD) ? el(SECRET_FIELD).value : "",
    issuer: issuer(),
    tokenEndpoint: sdJwtVc.get("token_endpoint") || "",
    audienceChoice: val("vc_client_auth_audience") ||
      sdJwtVc.get(KEYS.AUDIENCE) || "issuer",
    alg: val("vc_client_auth_alg") || sdJwtVc.get(KEYS.ALG) || "",
    kid: val("vc_client_auth_kid") || sdJwtVc.get(KEYS.KID) || "",
    typed: (el("vc_client_auth_typed") ? el("vc_client_auth_typed").checked :
            sdJwtVc.get(KEYS.TYPED) !== "0"),
    challenge: sdJwtVc.get(KEYS.CHALLENGE) || ""
  };
  s.signingKey = jsonField("vc_client_private_jwk", KEYS.PRIVATE_JWK);
  s.instanceKey = jsonField("vc_client_instance_jwk", KEYS.INSTANCE_JWK);
  s.attestation = val("vc_client_attestation") ||
    (keysMayBeStored() ? sdJwtVc.get(KEYS.ATTESTATION) || "" : "");
  log.debug("Leaving settings(). " + s.method);
  return s;
}

function save() {
  log.debug("Entering save().");
  var s = settings();
  sdJwtVc.set(KEYS.METHOD, s.method);
  sdJwtVc.set(KEYS.ALG, s.alg);
  sdJwtVc.set(KEYS.AUDIENCE, s.audienceChoice);
  sdJwtVc.set(KEYS.KID, s.kid);
  sdJwtVc.set(KEYS.TYPED, s.typed ? "1" : "0");
  var saveBox = el("vc_save_client_key");
  if (saveBox) {
    sdJwtVc.set(KEYS.SAVE_KEYS, saveBox.checked ? "1" : "0");
    if (!saveBox.checked) forgetStoredKeys();
  }
  if (s.signingKey) keep(KEYS.PRIVATE_JWK, JSON.stringify(s.signingKey));
  if (s.instanceKey) keep(KEYS.INSTANCE_JWK, JSON.stringify(s.instanceKey));
  if (s.attestation) keep(KEYS.ATTESTATION, s.attestation);
  log.debug("Leaving save().");
}

function generateKey(alg) {
  log.debug("Entering generateKey(). " + alg);
  var jwk = provider.exportKey(provider.generateKeyPair(KEY_SPECS[alg] ||
                                                        "ec-p256"), "jwk");
  log.debug("Leaving generateKey().");
  return jwk;
}

function publicOf(jwk) {
  log.debug("Entering publicOf().");
  var out = {};
  ["kty", "crv", "x", "y", "n", "e"].forEach(function (k) {
    if (jwk[k] !== undefined) out[k] = jwk[k];
  });
  log.debug("Leaving publicOf().");
  return out;
}

// Step 1: a new client key (private_key_jwt).
function onGenerateClientKey() {
  log.debug("Entering onGenerateClientKey().");
  var jwk = generateKey(val("vc_client_auth_alg") || "ES256");
  el("vc_client_private_jwk").value = JSON.stringify(jwk);
  el("vc_client_public_jwks").value = JSON.stringify({ keys: [Object.assign(
    publicOf(jwk), val("vc_client_auth_kid") ?
      { kid: val("vc_client_auth_kid") } : {})] }, null, 1);
  save();
  log.debug("Leaving onGenerateClientKey().");
  return false;
}

// Step 1: an instance key and a Client Attestation signed by a LOCAL attester
// key — for a server told to trust that key (its JWKS is shown).
function onMakeAttestation() {
  log.debug("Entering onMakeAttestation().");
  var instance = generateKey("ES256");
  var attester = (keysMayBeStored() &&
                  JSON.parse(sdJwtVc.get(KEYS.ATTESTER_JWK) || "null")) ||
    generateKey("ES256");
  var s = settings();
  log.debug("Leaving onMakeAttestation().");
  return clientAuth.makeAttestation({ attesterKey: attester,
    kid: "debugger-attester", clientId: s.clientId, instanceKey: instance })
    .then(function (jwt) {
      el("vc_client_instance_jwk").value = JSON.stringify(instance);
      el("vc_client_attestation").value = jwt;
      el("vc_client_attester_jwks").value = JSON.stringify({ keys: [
        Object.assign(publicOf(attester), { kid: "debugger-attester",
                                            use: "sig" })] }, null, 1);
      keep(KEYS.ATTESTER_JWK, JSON.stringify(attester));
      save();
      return false;
    });
}

// --- rendering ---------------------------------------------------------------
function optionList(values, chosen, labels) {
  log.debug("Entering optionList().");
  log.debug("Leaving optionList().");
  return values.map(function (v) {
    return "<option value=\"" + esc(v) + "\"" + (v === chosen ?
      " selected" : "") + ">" + esc(labels ? labels[v] : v) + "</option>";
  }).join("");
}

function row(label, control, note) {
  log.debug("Entering row().");
  log.debug("Leaving row().");
  return "<tr><td><label>" + label + "</label></td><td>" + control +
    (note ? "<div class=\"vc-note\">" + note + "</div>" : "") + "</td></tr>";
}

// Show only the rows the chosen method uses.
function showRows() {
  log.debug("Entering showRows().");
  var m = val("vc_client_auth_method") || method();
  var visible = {
    vc_client_secret_row: clientAuth.NEEDS_SECRET.indexOf(m) !== -1,
    vc_client_assertion_rows: m === "client_secret_jwt" ||
      m === "private_key_jwt",
    vc_client_key_rows: m === "private_key_jwt",
    vc_client_attestation_rows: m === "attest_jwt_client_auth"
  };
  Object.keys(visible).forEach(function (id) {
    var nodes = document.querySelectorAll("." + id);
    for (var i = 0; i < nodes.length; i++) {
      nodes[i].style.display = visible[id] ? "" : "none";
    }
  });
  log.debug("Leaving showRows().");
}

// mode "settings" (step 1) or "call" (a page that calls the token endpoint).
// onChange is called whenever anything that changes the request changes.
function render(containerId, mode, onChange) {
  log.debug("Entering render(). " + mode);
  var box = el(containerId);
  if (!box) {
    log.debug("Leaving render(). No container.");
    return;
  }
  var m = method();
  var supported = supportedMethods();
  var full = mode === "settings";
  var stored = keysMayBeStored();
  var html = "<table class=\"vc-token-table\"><tbody>";
  html += row("Client authentication", full ?
    "<select id=\"vc_client_auth_method\">" + optionList(clientAuth.METHODS,
      m, clientAuth.LABELS) + "</select>" :
    "<code id=\"vc_client_auth_method_shown\">" + esc(m) + "</code>",
    (supported.length ? "The authorization server advertises " +
      esc(supported.join(", ")) + "." : "The authorization server's " +
      "metadata names no token_endpoint_auth_methods_supported.") +
    (chosenMethod() ? "" : " Nothing is chosen yet, so the client is " +
      "public (none): choose a method once the client has a credential."));
  html += "<tr class=\"vc_client_secret_row\"><td><label for=\"" +
    SECRET_FIELD + "\">Client secret</label></td><td><input type=\"password\"" +
    " id=\"" + SECRET_FIELD + "\" size=\"40\" autocomplete=\"off\" />" +
    "<div class=\"vc-note\">Typed here for this page load and never stored; " +
    "type it again on any later page that calls the token endpoint." +
    "</div></td></tr>";
  if (full) {
    html += "<tbody class=\"vc_client_assertion_rows\">" +
      row("Assertion alg", "<select id=\"vc_client_auth_alg\">" +
        optionList(["", "HS256", "HS384", "HS512"].concat(ALGS),
                   sdJwtVc.get(KEYS.ALG) || "") + "</select>",
        "Empty: HS256 for client_secret_jwt, the key's own for " +
        "private_key_jwt.") +
      row("Assertion aud", "<select id=\"vc_client_auth_audience\">" +
        optionList(["issuer", "token_endpoint"],
                   sdJwtVc.get(KEYS.AUDIENCE) || "issuer",
                   { issuer: "the issuer identifier (RFC 7523bis-11)",
                     token_endpoint: "the token endpoint URL (RFC 7523)" }) +
        "</select>") +
      row("Explicit typ", "<input type=\"checkbox\" id=\"" +
        "vc_client_auth_typed\"" + (sdJwtVc.get(KEYS.TYPED) !== "0" ?
          " checked" : "") + " /> client-authentication+jwt") +
      row("kid", "<input type=\"text\" id=\"vc_client_auth_kid\" size=\"30\"" +
        " value=\"" + esc(sdJwtVc.get(KEYS.KID) || "") + "\" />") + "</tbody>";
  }
  html += "<tbody class=\"vc_client_key_rows\">" + row("Client private key",
    "<textarea id=\"vc_client_private_jwk\" rows=\"3\" cols=\"60\"" +
    " autocomplete=\"off\"></textarea>" + (full ? " <input class=\"btn2\"" +
    " type=\"button\" id=\"vc_client_key_generate\" value=\"Generate\" />" :
    ""), stored ? "Kept in this browser." : "Not kept: paste it here.") +
    (full ? row("Public JWKS", "<textarea id=\"vc_client_public_jwks\"" +
      " rows=\"4\" cols=\"60\" readonly></textarea>", "Register this with " +
      "the authorization server as the client's jwks.") : "") + "</tbody>";
  html += "<tbody class=\"vc_client_attestation_rows\">" +
    row("Client Attestation", "<textarea id=\"vc_client_attestation\"" +
      " rows=\"3\" cols=\"60\" autocomplete=\"off\"></textarea>" +
      (full ? " <input class=\"btn2\" type=\"button\"" +
        " id=\"vc_client_attestation_make\" value=\"Make one\" />" : ""),
      "draft-ietf-oauth-attestation-based-client-auth-12 (a DRAFT). From " +
      "the wallet provider, or made here by a local attester the server " +
      "must be told to trust.") +
    row("Instance private key", "<textarea id=\"vc_client_instance_jwk\"" +
      " rows=\"3\" cols=\"60\" autocomplete=\"off\"></textarea>",
      "The key the attestation's cnf names; it signs the PoP.") +
    (full ? row("Attester JWKS", "<textarea id=\"vc_client_attester_jwks\"" +
      " rows=\"4\" cols=\"60\" readonly></textarea>", "Only when made " +
      "here: the server must trust this key.") : "") + "</tbody>";
  if (full) {
    html += row("Keep the client keys", "<input type=\"checkbox\"" +
      " id=\"vc_save_client_key\"" + (stored ? " checked" : "") + " />" +
      " in this browser", "Clearing it removes them now.");
  }
  html += "</tbody></table>";
  box.innerHTML = html;
  if (stored) {
    var fill = function (id, key) {
      if (el(id) && sdJwtVc.get(key)) el(id).value = sdJwtVc.get(key);
    };
    fill("vc_client_private_jwk", KEYS.PRIVATE_JWK);
    fill("vc_client_attestation", KEYS.ATTESTATION);
    fill("vc_client_instance_jwk", KEYS.INSTANCE_JWK);
  }
  var changed = function () {
    if (full) save();
    showRows();
    if (onChange) onChange();
  };
  ["vc_client_auth_method", "vc_client_auth_alg", "vc_client_auth_audience",
   "vc_client_auth_typed", "vc_save_client_key"].forEach(function (id) {
    if (el(id)) el(id).addEventListener("change", changed);
  });
  [SECRET_FIELD, "vc_client_auth_kid", "vc_client_private_jwk",
   "vc_client_attestation", "vc_client_instance_jwk"].forEach(function (id) {
    if (el(id)) el(id).addEventListener("input", changed);
  });
  if (el("vc_client_key_generate")) {
    el("vc_client_key_generate").addEventListener("click", function () {
      onGenerateClientKey();
      changed();
    });
  }
  if (el("vc_client_attestation_make")) {
    el("vc_client_attestation_make").addEventListener("click", function () {
      onMakeAttestation().then(changed);
    });
  }
  showRows();
  log.debug("Leaving render().");
}

// The token request with client authentication applied:
// Promise<{ body, headers, text, notes }>.
function applyTo(params, tokenEndpoint) {
  log.debug("Entering applyTo().");
  var s;
  try {
    s = settings();
  } catch (e) {
    log.debug("Leaving applyTo(). " + e.message);
    return Promise.reject(e);
  }
  var base = Object.assign({}, params);
  delete base.client_id;
  log.debug("Leaving applyTo().");
  return clientAuth.apply(s).then(function (applied) {
    var body = Object.assign({}, base, applied.params);
    return { body: body, headers: applied.headers, notes: applied.notes,
             text: clientAuth.describe(s.method, tokenEndpoint ||
               "(no token_endpoint)", base, applied) };
  });
}

// Remember the challenge a response carried (draft -12 section 6.2).
function noteChallenge(headersLower) {
  log.debug("Entering noteChallenge().");
  var c = clientAuth.challengeOf(headersLower);
  if (c) sdJwtVc.set(KEYS.CHALLENGE, c);
  log.debug("Leaving noteChallenge(). " + !!c);
  return c;
}

function headersLowerOf(response) {
  log.debug("Entering headersLowerOf().");
  var out = {};
  if (response && response.headers &&
      typeof response.headers.forEach === "function") {
    response.headers.forEach(function (value, name) {
      out[String(name).toLowerCase()] = value;
    });
  }
  log.debug("Leaving headersLowerOf().");
  return out;
}

// Send a token request through vciWallet.fetchProtected (so DPoP is the same
// code every call uses) with client authentication applied. A server that
// answers use_attestation_challenge is retried ONCE with the challenge it
// sent (draft -12 section 6.1); a challenge on any response is kept for the
// next PoP (section 6.2). Resolves to fetchProtected's result plus
// `applied` (what was sent, secret elided).
// How long one token request may go unanswered before it is abandoned
// with a reason, rather than leaving the page at "Redeeming …" for ever.
var TOKEN_TIMEOUT_MS = 30000;

// One POST, abandoned after TOKEN_TIMEOUT_MS with an error naming the
// stage it was at.
function postBounded(vciWallet, request, stageName) {
  log.debug("Entering postBounded(). " + stageName);
  var controller = typeof AbortController === "function" ?
      new AbortController() : null;
  var timer = null;
  var timedOut = new Promise(function (resolve, reject) {
    timer = setTimeout(function () {
      if (controller) controller.abort();
      reject(new Error("no answer from the token endpoint within " +
        (TOKEN_TIMEOUT_MS / 1000) + " s (" + stageName + "). The request " +
        "was sent and never answered: check that the server is up and that " +
        "its CORS preflight allows the headers this method sends."));
    }, TOKEN_TIMEOUT_MS);
  });
  var sent = vciWallet.fetchProtected(Object.assign({}, request,
    { signal: controller ? controller.signal : undefined }));
  log.debug("Leaving postBounded().");
  return Promise.race([sent, timedOut]).then(function (r) {
    clearTimeout(timer);
    return r;
  }, function (e) {
    clearTimeout(timer);
    throw e;
  });
}

// The authorization server's challenge_endpoint (draft-ietf-oauth-
// attestation-based-client-auth-12 section 6.1, an AS metadata member),
// from the AS document step 1 retrieved; "" when it advertises none.
function challengeEndpoint() {
  log.debug("Entering challengeEndpoint().");
  var doc = null;
  try {
    doc = JSON.parse(sdJwtVc.get(opMetadata.DISCOVERY_INFO_KEY) || "null");
  } catch (e) {
    doc = null;
  }
  var url = doc && typeof doc.challenge_endpoint === "string" ?
      doc.challenge_endpoint : "";
  log.debug("Leaving challengeEndpoint(). " + (url || "none"));
  return url;
}

// POST to the challenge endpoint (section 6.1): { attestation_challenge }.
// Bounded like a token request.
function fetchChallenge(url) {
  log.debug("Entering fetchChallenge(). " + url);
  var controller = typeof AbortController === "function" ?
      new AbortController() : null;
  var timer = setTimeout(function () {
    if (controller) controller.abort();
  }, TOKEN_TIMEOUT_MS);
  log.debug("Leaving fetchChallenge().");
  return fetch(url, { method: "POST",
                      signal: controller ? controller.signal : undefined })
    .then(function (response) {
      return response.json().then(function (body) {
        clearTimeout(timer);
        var c = body && body.attestation_challenge;
        if (!response.ok || typeof c !== "string" || !c) {
          throw new Error("the challenge endpoint " + url + " answered " +
            response.status + " without an attestation_challenge.");
        }
        sdJwtVc.set(KEYS.CHALLENGE, c);
        return c;
      });
    }, function (e) {
      clearTimeout(timer);
      throw new Error("the challenge endpoint " + url + " could not be " +
        "reached: " + e.message);
    });
}

// A fresh challenge from the AS's challenge_endpoint, stored for the next
// PoP, when the metadata names one: resolves to "challenge_endpoint" then,
// and to "" (nothing fetched) otherwise. For callers that build the PoP
// themselves (oauth2_oidc_2.js).
function freshChallenge() {
  log.debug("Entering freshChallenge().");
  var url = challengeEndpoint();
  if (!url) {
    log.debug("Leaving freshChallenge(). No endpoint.");
    return Promise.resolve("");
  }
  log.debug("Leaving freshChallenge().");
  return fetchChallenge(url).then(function () {
    return "challenge_endpoint";
  });
}

// onStage(text), when given, is told each step, so a page's status says
// what it is waiting on.
function sendToken(vciWallet, params, endpoint, context, onStage) {
  log.debug("Entering sendToken().");
  var stage = function (text) {
    log.debug("sendToken() stage: " + text);
    if (typeof onStage === "function") onStage(text);
  };
  var m = method();
  var endpointUrl = m === "attest_jwt_client_auth" ? challengeEndpoint() : "";
  // Where the challenge in a PoP came from, for the stage text.
  var source = "";
  var attempt = function (retry) {
    stage(m === "attest_jwt_client_auth" ? "Signing the Client Attestation " +
      "PoP" + (source ? " with the challenge from " + source : "") +
      (retry ? " (retry)" : "") + " …" : "Applying " + m + " …");
    return applyTo(params, endpoint).then(function (applied) {
      var name = "token request, " + m + (retry ? ", challenge retry" : "");
      stage("Waiting for the token endpoint (" + name + ") …");
      return postBounded(vciWallet, { url: endpoint, method: "POST",
        headers: Object.assign({ "Content-Type":
          "application/x-www-form-urlencoded" }, applied.headers),
        body: vciWallet.encodeForm(applied.body), context: context }, name)
        .then(function (result) {
          noteChallenge(headersLowerOf(result.response));
          var err = result.body && result.body.error;
          if (!retry && err === "use_attestation_challenge" &&
              m === "attest_jwt_client_auth") {
            log.debug("sendToken(): retrying with the server's challenge.");
            var fromHeader = clientAuth.challengeOf(
              headersLowerOf(result.response));
            if (fromHeader) {
              source = "the OAuth-Client-Attestation-Challenge header";
              return attempt(true);
            }
            if (endpointUrl) {
              // Section 6.1: the header is the server's to send and the
              // page's to read only if CORS exposes it; the endpoint is
              // the specification's other source.
              stage("The server asked for a challenge and its header " +
                "could not be read; fetching one from challenge_endpoint …");
              return fetchChallenge(endpointUrl).then(function () {
                source = "challenge_endpoint (the header was not readable)";
                return attempt(true);
              });
            }
            stage("The server asked for a challenge, its " +
              "OAuth-Client-Attestation-Challenge header could not be read " +
              "(not exposed by CORS?) and its metadata names no " +
              "challenge_endpoint; retrying anyway …");
            sdJwtVc.set(KEYS.CHALLENGE, "");
            return attempt(true);
          }
          result.challengeSource = source;
          result.applied = applied;
          return result;
        });
    });
  };
  log.debug("Leaving sendToken().");
  if (endpointUrl) {
    // Up front, so the first PoP already carries one (section 6.1).
    stage("Fetching a challenge from challenge_endpoint …");
    return fetchChallenge(endpointUrl).then(function () {
      source = "challenge_endpoint";
      return attempt(false);
    });
  }
  return attempt(false);
}

module.exports = {
  KEYS: KEYS,
  sendToken: sendToken,
  TOKEN_TIMEOUT_MS: TOKEN_TIMEOUT_MS,
  challengeEndpoint: challengeEndpoint,
  freshChallenge: freshChallenge,
  KEY_MATERIAL: KEY_MATERIAL,
  SECRET_FIELD: SECRET_FIELD,
  method: method,
  chosenMethod: chosenMethod,
  settings: settings,
  render: render,
  applyTo: applyTo,
  noteChallenge: noteChallenge,
  keysMayBeStored: keysMayBeStored
};
