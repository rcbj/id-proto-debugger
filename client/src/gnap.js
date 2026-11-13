// File: gnap.js
//
// The GNAP page. The proofs and the request builder live in
// gnap_client.js and have no DOM. This file is the only one that
// touches the page. A private key stays in this browser. The API
// relay receives a request that is already signed.

'use strict';

var bunyan = require("bunyan");
var engine = require("./gnap_client");

var appconfig = {};
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  appconfig = {};
}

var log = bunyan.createLogger({
  name: "gnap",
  level: appconfig.logLevel || "info"
});
log.info("Log initialized. logLevel=" + log.level());

var API_URL = appconfig.apiUrl || "";
var KEY_STORAGE = "gnap_private_jwk";
var STATE_STORAGE = "gnap_state";

var privateJwk = null;

function status(text, warn) {
  log.debug("Entering status().");
  var node = document.getElementById("gnap_status");
  node.textContent = text || "";
  node.className = warn ? "gnap-warn" : "gnap-note";
  log.debug("Leaving status().");
}

function val(id) {
  log.debug("Entering val(). id=" + id);
  var node = document.getElementById(id);
  log.debug("Leaving val().");
  return node ? String(node.value || "") : "";
}

function setVal(id, text) {
  log.debug("Entering setVal(). id=" + id);
  var node = document.getElementById(id);
  if (node) {
    node.value = text === undefined || text === null ? "" : String(text);
  }
  log.debug("Leaving setVal().");
}

function checked(id) {
  log.debug("Entering checked(). id=" + id);
  var node = document.getElementById(id);
  log.debug("Leaving checked().");
  return !!(node && node.checked);
}

function record() {
  log.debug("Entering record().");
  if (!privateJwk) {
    log.debug("Leaving record(). No key.");
    return null;
  }
  log.debug("Leaving record().");
  return engine.recordFromPrivateJwk(privateJwk, "");
}

function showKey(one) {
  log.debug("Entering showKey().");
  privateJwk = one.privateJwk;
  setVal("gnap_public", JSON.stringify(one.publicJwk, null, 2));
  setVal("gnap_private", JSON.stringify(one.privateJwk, null, 2));
  log.debug("Leaving showKey().");
}

function persist() {
  log.debug("Entering persist().");
  var save = checked("gnap_save_keypair");
  if (save && privateJwk) {
    localStorage.setItem(KEY_STORAGE, JSON.stringify(privateJwk));
  } else {
    localStorage.removeItem(KEY_STORAGE);
  }
  var state = {
    saveKey: save,
    alg: val("gnap_alg"),
    grant: val("gnap_grant"),
    proof: val("gnap_proof"),
    via: val("gnap_via"),
    insecure: checked("gnap_insecure"),
    api: val("gnap_api"),
    request: val("gnap_request"),
    display: val("gnap_display"),
    classId: val("gnap_class"),
    clientNonce: val("gnap_client_nonce"),
    asNonce: val("gnap_as_nonce"),
    continueUri: val("gnap_continue_uri"),
    continueToken: val("gnap_continue_token"),
    manageUri: val("gnap_manage_uri"),
    manageToken: val("gnap_manage_token"),
    accessToken: val("gnap_token")
  };
  localStorage.setItem(STATE_STORAGE, JSON.stringify(state));
  log.debug("Leaving persist().");
}

function loadState() {
  log.debug("Entering loadState().");
  var raw = localStorage.getItem(STATE_STORAGE);
  var state = {};
  if (raw) {
    try {
      state = JSON.parse(raw) || {};
    } catch (e) {
      log.debug("Caught in loadState(): " + e.message);
      state = {};
    }
  }
  if (state.alg) {
    setVal("gnap_alg", state.alg);
  }
  if (state.grant) {
    setVal("gnap_grant", state.grant);
  }
  if (state.proof) {
    setVal("gnap_proof", state.proof);
  }
  if (state.via) {
    setVal("gnap_via", state.via);
  }
  if (state.api) {
    setVal("gnap_api", state.api);
  }
  if (state.request) {
    setVal("gnap_request", state.request);
  }
  if (state.display) {
    setVal("gnap_display", state.display);
  }
  if (state.classId) {
    setVal("gnap_class", state.classId);
  }
  setVal("gnap_client_nonce", state.clientNonce || "");
  setVal("gnap_as_nonce", state.asNonce || "");
  setVal("gnap_continue_uri", state.continueUri || "");
  setVal("gnap_continue_token", state.continueToken || "");
  setVal("gnap_manage_uri", state.manageUri || "");
  setVal("gnap_manage_token", state.manageToken || "");
  setVal("gnap_token", state.accessToken || "");
  var box = document.getElementById("gnap_save_keypair");
  box.checked = state.saveKey !== false;
  var insecure = document.getElementById("gnap_insecure");
  insecure.checked = state.insecure === true;
  if (box.checked) {
    var stored = localStorage.getItem(KEY_STORAGE);
    if (stored) {
      try {
        showKey(engine.recordFromPrivateJwk(JSON.parse(stored), ""));
      } catch (e) {
        log.debug("Caught in loadState() key: " + e.message);
      }
    }
  } else {
    localStorage.removeItem(KEY_STORAGE);
  }
  log.debug("Leaving loadState().");
}

function apiBase() {
  log.debug("Entering apiBase().");
  var typed = val("gnap_api").trim() || API_URL;
  log.debug("Leaving apiBase().");
  return String(typed).replace(/\/+$/, "");
}

async function generate() {
  log.debug("Entering generate().");
  try {
    showKey(await engine.generateKey(val("gnap_alg") || "ES256"));
    persist();
    status("Generated a " + val("gnap_alg") + " key. Register the " +
      "public key with the authorization server, or rely on a " +
      "development-mode server that accepts a new key.");
  } catch (e) {
    log.debug("Caught in generate(): " + e.message);
    status(e.message, true);
  }
  log.debug("Leaving generate().");
  return false;
}

function usePasted() {
  log.debug("Entering usePasted().");
  try {
    var parsed = JSON.parse(val("gnap_private"));
    if (!parsed || !parsed.d && !parsed.k) {
      status("Paste a private JWK. It needs d, or k for a symmetric key.",
        true);
      log.debug("Leaving usePasted(). Not a private key.");
      return false;
    }
    showKey(engine.recordFromPrivateJwk(parsed, ""));
    if (parsed.alg) {
      setVal("gnap_alg", parsed.alg);
    }
    persist();
    status("Using the pasted key.");
  } catch (e) {
    log.debug("Caught in usePasted(): " + e.message);
    status("That private key is not JSON. " + e.message, true);
  }
  log.debug("Leaving usePasted().");
  return false;
}

function onSaveChange() {
  log.debug("Entering onSaveChange().");
  persist();
  status(checked("gnap_save_keypair")
    ? "The private key is stored in this browser."
    : "The private key was removed from this browser's storage.");
  log.debug("Leaving onSaveChange().");
  return false;
}

function fillSample() {
  log.debug("Entering fillSample().");
  var nonce = "n-" + Array.prototype.map.call(
    crypto.getRandomValues(new Uint8Array(8)), function (b) {
      var hex = b.toString(16);
      return hex.length === 1 ? "0" + hex : hex;
    }).join("");
  var finish = window.location.origin + "/gnap.html";
  var body = engine.sampleRequest(finish, nonce);
  setVal("gnap_request", JSON.stringify(body, null, 2));
  setVal("gnap_client_nonce", nonce);
  persist();
  status("Sample request. The finish URI is this page, so an " +
    "approval can return here with the interaction hash.");
  log.debug("Leaving fillSample().");
  return false;
}

function requestBody() {
  log.debug("Entering requestBody().");
  var text = val("gnap_request").trim();
  if (!text) {
    log.debug("Leaving requestBody(). Empty.");
    throw new Error("The grant request is empty.");
  }
  var parsed;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    log.debug("Leaving requestBody(). Not JSON.");
    throw new Error("The grant request is not JSON. " + e.message);
  }
  var one = record();
  if (!one) {
    log.debug("Leaving requestBody(). No key.");
    throw new Error("Generate or paste a client key first.");
  }
  var displayName = val("gnap_display").trim();
  var display = displayName ? {
    name: displayName,
    uri: window.location.origin + "/gnap.html"
  } : null;
  log.debug("Leaving requestBody().");
  return engine.withClient(parsed, one, val("gnap_proof"), display,
    val("gnap_class").trim());
}

async function deliver(prepared) {
  log.debug("Entering deliver().");
  if (val("gnap_via") === "browser") {
    var direct = await fetch(prepared.url, {
      method: prepared.method,
      headers: prepared.headers,
      body: prepared.body ? prepared.body : undefined
    });
    var directText = await direct.text();
    log.debug("Leaving deliver(). Browser " + direct.status);
    return {
      status: direct.status,
      rawBody: directText,
      body: parseJson(directText),
      error: engine.errorOf(parseJson(directText))
    };
  }
  var response = await fetch(apiBase() + "/gnap/call", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      url: prepared.url,
      method: prepared.method,
      headers: prepared.headers,
      body: prepared.body,
      sslValidate: !checked("gnap_insecure")
    })
  });
  var payload = await response.json();
  if (!response.ok) {
    log.debug("Leaving deliver(). API refused.");
    throw new Error(payload.error || ("The API returned " +
      response.status));
  }
  log.debug("Leaving deliver(). API " + payload.status);
  return payload;
}

function parseJson(text) {
  log.debug("Entering parseJson().");
  if (!text) {
    log.debug("Leaving parseJson(). Empty.");
    return null;
  }
  try {
    var parsed = JSON.parse(text);
    log.debug("Leaving parseJson().");
    return parsed;
  } catch (e) {
    log.debug("Leaving parseJson(). Not JSON.");
    return null;
  }
}

function showExchange(prepared, answer) {
  log.debug("Entering showExchange().");
  var signed = prepared.method + " " + prepared.url + "\n";
  Object.keys(prepared.headers).forEach(function (name) {
    signed += name + ": " + prepared.headers[name] + "\n";
  });
  signed += "\n" + (prepared.body || "");
  if (prepared.signatures && prepared.signatures.length) {
    signed += "\n\n--- signature base ---\n";
    prepared.signatures.forEach(function (one) {
      signed += one.label + "\n" + one.base + "\n";
    });
  }
  setVal("gnap_signed", signed);
  var body = answer.body || parseJson(answer.rawBody);
  setVal("gnap_response", "HTTP " + (answer.status || "") + "\n" +
    (answer.rawBody || JSON.stringify(body, null, 2) || ""));
  applyResponse(body || {});
  log.debug("Leaving showExchange().");
}

function setLink(id, url) {
  log.debug("Entering setLink(). id=" + id);
  var node = document.getElementById(id);
  if (!url || !/^https?:\/\//i.test(String(url))) {
    node.removeAttribute("href");
    node.textContent = url ? String(url) : "";
    log.debug("Leaving setLink(). No http URL.");
    return;
  }
  node.href = url;
  node.textContent = url;
  log.debug("Leaving setLink().");
}

function applyResponse(body) {
  log.debug("Entering applyResponse().");
  var cont = body.continue || {};
  if (cont.uri) {
    setVal("gnap_continue_uri", cont.uri);
  }
  if (cont.access_token && cont.access_token.value) {
    setVal("gnap_continue_token", cont.access_token.value);
  }
  var interact = body.interact || {};
  setLink("gnap_redirect", interact.redirect || "");
  var code = document.getElementById("gnap_user_code");
  code.textContent = interact.user_code || "";
  setLink("gnap_user_code_uri", interact.user_code_uri ||
    interact.url || "");
  if (typeof interact.finish === "string") {
    setVal("gnap_as_nonce", interact.finish);
  }
  var token = body.access_token || {};
  if (token.value) {
    setVal("gnap_token", token.value);
  }
  var manage = token.manage || {};
  if (manage.uri) {
    setVal("gnap_manage_uri", manage.uri);
  }
  if (manage.access_token && manage.access_token.value) {
    setVal("gnap_manage_token", manage.access_token.value);
  }
  persist();
  log.debug("Leaving applyResponse().");
}

async function discover() {
  log.debug("Entering discover().");
  try {
    var prepared = await engine.prepare(record() || {
      alg: "ES256",
      kid: "none",
      privateJwk: {},
      publicJwk: {}
    }, "OPTIONS", val("gnap_grant").trim(), { sign: false });
    var answer = await deliver(prepared);
    showExchange(prepared, answer);
    status("Discovery answered HTTP " + answer.status + ".");
  } catch (e) {
    log.debug("Caught in discover(): " + e.message);
    status(e.message, true);
  }
  log.debug("Leaving discover().");
  return false;
}

async function sendGrant() {
  log.debug("Entering sendGrant().");
  try {
    var prepared = await engine.prepare(record(), "POST",
      val("gnap_grant").trim(), {
        json: requestBody(),
        proof: val("gnap_proof")
      });
    var answer = await deliver(prepared);
    showExchange(prepared, answer);
    var code = answer.error || engine.errorOf(answer.body);
    status(code
      ? ("The authorization server refused the grant: " + code +
        (answer.description ? ". " + answer.description : ""))
      : ("Grant response HTTP " + answer.status + "."), !!code);
  } catch (e) {
    log.debug("Caught in sendGrant(): " + e.message);
    status(e.message, true);
  }
  log.debug("Leaving sendGrant().");
  return false;
}

async function continueGrant() {
  log.debug("Entering continueGrant().");
  try {
    var uri = val("gnap_continue_uri").trim();
    if (!uri) {
      status("There is no continuation URI yet.", true);
      log.debug("Leaving continueGrant(). No URI.");
      return false;
    }
    var ref = val("gnap_interact_ref").trim();
    var options = {
      token: val("gnap_continue_token").trim(),
      proof: val("gnap_proof")
    };
    if (ref) {
      options.json = { interact_ref: ref };
    }
    var prepared = await engine.prepare(record(), "POST", uri, options);
    var answer = await deliver(prepared);
    showExchange(prepared, answer);
    var code = answer.error || engine.errorOf(answer.body);
    if (code === "too_fast") {
      var wait = ((answer.body || {}).continue || {}).wait;
      status("The authorization server said too_fast. Wait " +
        (wait || "the number it gave") + " seconds and continue again.",
        true);
    } else {
      status(code ? ("Continuation refused: " + code) :
        ("Continuation HTTP " + answer.status + "."), !!code);
    }
  } catch (e) {
    log.debug("Caught in continueGrant(): " + e.message);
    status(e.message, true);
  }
  log.debug("Leaving continueGrant().");
  return false;
}

async function revokeGrant() {
  log.debug("Entering revokeGrant().");
  try {
    var uri = val("gnap_continue_uri").trim();
    if (!uri) {
      status("There is no continuation URI to revoke.", true);
      log.debug("Leaving revokeGrant(). No URI.");
      return false;
    }
    var prepared = await engine.prepare(record(), "DELETE", uri, {
      token: val("gnap_continue_token").trim(),
      proof: val("gnap_proof")
    });
    var answer = await deliver(prepared);
    showExchange(prepared, answer);
    status("Revocation answered HTTP " + answer.status + ".");
  } catch (e) {
    log.debug("Caught in revokeGrant(): " + e.message);
    status(e.message, true);
  }
  log.debug("Leaving revokeGrant().");
  return false;
}

async function rotateKey() {
  log.debug("Entering rotateKey().");
  try {
    var uri = val("gnap_manage_uri").trim();
    if (!uri) {
      status("The token response has no management URI yet.", true);
      log.debug("Leaving rotateKey(). No URI.");
      return false;
    }
    var next = await engine.generateKey(val("gnap_alg") || "ES256");
    var prepared = await engine.prepare(record(), "POST", uri, {
      token: val("gnap_manage_token").trim(),
      proof: val("gnap_proof"),
      json: { key: engine.keyObject(next, val("gnap_proof")) },
      rotateTo: next
    });
    var answer = await deliver(prepared);
    showExchange(prepared, answer);
    var code = answer.error || engine.errorOf(answer.body);
    if (!code && answer.status >= 200 && answer.status < 300) {
      showKey(next);
      persist();
      status("Rotated the client key. This page now signs with the " +
        "new one.");
    } else {
      status(code ? ("Rotation refused: " + code) :
        ("Rotation answered HTTP " + answer.status + "."), true);
    }
  } catch (e) {
    log.debug("Caught in rotateKey(): " + e.message);
    status(e.message, true);
  }
  log.debug("Leaving rotateKey().");
  return false;
}

async function sendCall() {
  log.debug("Entering sendCall().");
  try {
    var options = {
      proof: val("gnap_proof"),
      token: val("gnap_call_token").trim()
    };
    var text = val("gnap_call_body").trim();
    if (text) {
      options.body = text;
    }
    if (!options.token) {
      delete options.token;
    }
    var prepared = await engine.prepare(record(),
      val("gnap_call_method") || "POST",
      val("gnap_call_url").trim(), options);
    var answer = await deliver(prepared);
    showExchange(prepared, answer);
    status("Call answered HTTP " + answer.status + ".");
  } catch (e) {
    log.debug("Caught in sendCall(): " + e.message);
    status(e.message, true);
  }
  log.debug("Leaving sendCall().");
  return false;
}

function fillIntrospect() {
  log.debug("Entering fillIntrospect().");
  var grant = val("gnap_grant").trim();
  var origin = "";
  try {
    origin = new URL(grant).origin;
  } catch (e) {
    log.debug("Caught in fillIntrospect(): " + e.message);
    status("The grant URL is not a URL.", true);
    log.debug("Leaving fillIntrospect(). Bad URL.");
    return false;
  }
  setVal("gnap_call_method", "POST");
  setVal("gnap_call_url", origin + "/gnap/introspect");
  setVal("gnap_call_body", JSON.stringify({
    access_token: val("gnap_token").trim()
  }));
  setVal("gnap_call_token", "");
  status("Introspection uses the resource server's key, not the " +
    "client key that received the token. Paste that key before Send.");
  log.debug("Leaving fillIntrospect().");
  return false;
}

async function checkFinish() {
  log.debug("Entering checkFinish().");
  try {
    var pasted = val("gnap_finish_url").trim();
    if (pasted) {
      var found = engine.finishFromUrl(pasted);
      if (found.hash) {
        setVal("gnap_hash", found.hash);
      }
      if (found.ref) {
        setVal("gnap_interact_ref", found.ref);
      }
    }
    var expected = await engine.interactionHash(
      val("gnap_client_nonce").trim(),
      val("gnap_as_nonce").trim(),
      val("gnap_interact_ref").trim(),
      val("gnap_grant").trim(),
      "sha-256");
    var got = val("gnap_hash").trim();
    setVal("gnap_hash_expected", expected);
    status(got === expected
      ? "The interaction hash matches."
      : "The interaction hash does not match.", got !== expected);
    persist();
  } catch (e) {
    log.debug("Caught in checkFinish(): " + e.message);
    status(e.message, true);
  }
  log.debug("Leaving checkFinish().");
  return false;
}

function readFinishQuery() {
  log.debug("Entering readFinishQuery().");
  var found = engine.finishFromUrl(window.location.href);
  if (found.hash) {
    setVal("gnap_hash", found.hash);
  }
  if (found.ref) {
    setVal("gnap_interact_ref", found.ref);
  }
  log.debug("Leaving readFinishQuery().");
}

async function init() {
  log.debug("Entering init().");
  if (!val("gnap_api")) {
    setVal("gnap_api", API_URL);
  }
  loadState();
  if (!val("gnap_api")) {
    setVal("gnap_api", API_URL);
  }
  readFinishQuery();
  var returned = val("gnap_hash") && val("gnap_client_nonce") &&
    val("gnap_as_nonce");
  if (returned) {
    await checkFinish();
  }
  var base = apiBase();
  if (base && !returned) {
    try {
      var limits = await fetch(base + "/gnap/limits");
      if (limits.ok) {
        status("The API relay is available. A grant request is signed " +
          "here and forwarded with the body that was signed.");
      }
    } catch (e) {
      log.debug("Caught in init(): " + e.message);
      status("The API relay did not answer. A browser call needs the " +
        "authorization server to allow this origin.");
    }
  }
  log.debug("Leaving init().");
}

window.onload = function () {
  init();
};

module.exports = {
  generate: generate,
  usePasted: usePasted,
  onSaveChange: onSaveChange,
  fillSample: fillSample,
  discover: discover,
  sendGrant: sendGrant,
  continueGrant: continueGrant,
  revokeGrant: revokeGrant,
  rotateKey: rotateKey,
  sendCall: sendCall,
  fillIntrospect: fillIntrospect,
  checkFinish: checkFinish
};
