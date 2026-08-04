// File: vc_issuance_2.js
//
// ---------------------------------------------------------------------------
// SD-JWT VC issuance, step 2: the tokens, the user's approval, and the OID4VCI
// Credential Request.
//
// By the time this page loads, the OIDC Authorization Code flow has run on
// debugger.html / debugger2.html and left its tokens in local storage. This
// page plays the rest of the wallet's part:
//
//   1. generate a holder key pair (in the browser; the private half never
//      leaves it),
//   2. ask the issuer's Nonce Endpoint for a c_nonce,
//   3. sign a proof of possession (typ openid4vci-proof+jwt) with the holder
//      key, naming the credential issuer as its audience,
//   4. POST the Credential Request to the Credential Endpoint with the access
//      token as a Bearer credential,
//   5. keep the SD-JWT VC that comes back and go to step 3.
//
// Steps 2-4 only happen when the user approves.
// ---------------------------------------------------------------------------

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var metadataClient = require("./metadata_client");
var sdJwtVc = require("./sd_jwt_vc");
// The wallet-side mechanics of a Credential Request — keys, nonce, proof, body,
// and reading the response — shared with step 4, which makes the same call to
// refresh the credential (OID4VCI section 14.5).
var vciWallet = require("./vci_wallet");

var log = bunyan.createLogger({ name: 'vc_issuance_2',
                                level: appconfig.LOG_LEVEL || 'info' });

// The request as it currently stands: what step 1 configured, plus what this
// page generates.
var request = {
  config: null,
  // The first holder key, kept under the same names as before: it is the one the
  // page displays and the one a single-credential request binds to.
  holderPublicJwk: null,
  holderPrivateJwk: null,
  // Every key this request binds to, in order — one per proof, one credential
  // per proof (OID4VCI section 8.3). With a batch size of one this is just the
  // holder key above.
  holderKeys: [],
  nonce: "",
  proof: "",
  proofs: [],
  // { publicJwk, privateKey, enc } when the wallet asked for an encrypted
  // response. The private half is a non-extractable Web Crypto key: it stays in
  // the browser and is used only to unwrap the content key.
  encryption: null,
  body: null
};

function el(id) { return document.getElementById(id); }
function setText(id, text) { var e = el(id); if (e) e.textContent = (text == null ? "" : String(text)); }
function setJson(id, value) {
  var e = el(id);
  if (e) e.textContent = (value === null || value === undefined) ? "—" : JSON.stringify(value, null, 2);
}
function setValue(id, v) { var e = el(id); if (e) e.value = (v == null ? "" : v); }
function status(id, text, cls) {
  var e = el(id);
  if (!e) return;
  e.textContent = text;
  e.className = "vc-status" + (cls ? " " + cls : "");
}

// --- the holder key ---------------------------------------------------------
// ES256, because it is what OID4VCI wallets use and what the mock issuer
// advertises in proof_signing_alg_values_supported.
function generateHolderKey() {
  log.debug("Entering generateHolderKey().");
  log.debug("Leaving generateHolderKey().");
  return vciWallet.generateHolderKeyPair()
    .then(function (pair) {
      request.holderPublicJwk = pair.publicJwk;
      request.holderPrivateJwk = pair.privateJwk;
      sdJwtVc.setJson(sdJwtVc.KEYS.HOLDER_JWK, pair.publicJwk);
      sdJwtVc.setJson(sdJwtVc.KEYS.HOLDER_PRIVATE_JWK, pair.privateJwk);
      return pair.publicJwk;
    });
}

function loadOrGenerateHolderKey() {
  var pub = sdJwtVc.getJson(sdJwtVc.KEYS.HOLDER_JWK);
  var priv = sdJwtVc.getJson(sdJwtVc.KEYS.HOLDER_PRIVATE_JWK);
  if (pub && priv) {
    request.holderPublicJwk = pub;
    request.holderPrivateJwk = priv;
    return Promise.resolve(pub);
  }
  return generateHolderKey();
}

// ---------------------------------------------------------------------------
// Keeping — or not keeping — the holder key pair.
//
// The private half has to outlive this page for the workflow to continue: step 4
// needs it to refresh the credential, and the PRESENTATION pages need it to sign
// the Key Binding JWT. That is why it is stored by default, and why turning
// storage off is a real decision rather than a tidy-up. sd_jwt_vc.js enforces the
// choice for every writer (see holderPrivateKeyMayBeStored there); this page is
// where the choice is made and explained.
// ---------------------------------------------------------------------------
function triggerDownload(filename, data, mime) {
  var blob = new Blob([data], { type: mime || 'application/octet-stream' });
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
}

// Both halves, because the point of the file is to be able to put the pair back.
// It is offered whether or not storage is on: with storage off it is the only
// copy there will be, and with storage on it is still the only way to move the
// key to another browser.
function downloadHolderKey() {
  log.debug("Entering downloadHolderKey().");
  var pub = request.holderPublicJwk || sdJwtVc.getJson(sdJwtVc.KEYS.HOLDER_JWK);
  var priv = request.holderPrivateJwk || sdJwtVc.getJson(sdJwtVc.KEYS.HOLDER_PRIVATE_JWK);
  if (!pub && !priv) {
    status("vc_approval_status", "There is no holder key pair to download yet.", "vc-bad");
    log.debug("Leaving downloadHolderKey(). Nothing to download.");
    return false;
  }
  triggerDownload("holder-key-pair.json",
    JSON.stringify({ publicJwk: pub || null, privateJwk: priv || null }, null, 2),
    "application/json");
  log.debug("Leaving downloadHolderKey().");
  return false;
}

// Say what turning it off costs, where and when it is turned off. The
// consequences land on other pages (step 4, and the whole presentation
// workflow), so leaving the user to discover them is not good enough.
function renderHolderKeyStorageNote() {
  log.debug("Entering renderHolderKeyStorageNote().");
  var note = document.getElementById("vc_holder_key_storage_note");
  if (!note) return;
  if (sdJwtVc.holderPrivateKeyMayBeStored()) {
    note.textContent = "Kept in this browser so step 4 and the presentation pages can use it.";
    return;
  }
  // textContent, not innerHTML: a message, not markup.
  note.textContent = "Not saved. Download the key pair now — without the private half in storage, " +
    "step 4 cannot refresh this credential and the presentation pages cannot sign a Key Binding " +
    "JWT, and any earlier generation in Credential History has lost its key too.";
  log.debug("Leaving renderHolderKeyStorageNote().");
}

function onSaveHolderKeyChange() {
  log.debug("Entering onSaveHolderKeyChange().");
  var box = document.getElementById("vc_save_holder_key");
  var on = !box || box.checked;
  // Turning it off purges every stored copy, including the per-generation ones
  // in Credential History — that is the whole point, and it cannot be undone by
  // ticking the box again, which is what the note has to convey BEFORE the fact
  // and the status line reports after it.
  var stripped = sdJwtVc.setHolderKeySaving(on);
  renderHolderKeyStorageNote();
  if (!on) {
    status("vc_approval_status",
      "Holder key saving is off. The stored private key was removed" +
      (stripped ? ", along with the key on " + stripped + " credential history generation(s)" : "") +
      ". Use Download Key Pair to keep a copy.", "vc-bad");
  } else {
    // Re-enabling stores the pair the page is holding right now, if it has one;
    // it cannot bring back what the purge removed.
    if (request.holderPublicJwk) sdJwtVc.setJson(sdJwtVc.KEYS.HOLDER_JWK, request.holderPublicJwk);
    if (request.holderPrivateJwk) sdJwtVc.setJson(sdJwtVc.KEYS.HOLDER_PRIVATE_JWK, request.holderPrivateJwk);
    status("vc_approval_status", "Holder key saving is back on for the key pair on this page.", "vc-ok");
  }
  log.debug("Leaving onSaveHolderKeyChange(). on=" + on + ", stripped=" + stripped);
  return false;
}

function regenerateHolderKey() {
  log.debug("Entering regenerateHolderKey().");
  generateHolderKey().then(function (pub) {
    setJson("vc_holder_jwk", pub);
    // A new key invalidates the proof built for the old one, so build another.
    request.proof = "";
    request.proofs = [];
    request.holderKeys = [];
    setValue("vc_proof_jwt", "");
    renderProofJwt(null);
    setJson("vc_request_body", null);
    setValue("vc_approval_request", "");
    return prepareRequest().then(function (ok) {
      if (ok) {
        status("vc_approval_status",
          "A new holder key pair was generated, and the proof of possession rebuilt for it.", "vc-ok");
      }
    });
  }).catch(function (e) {
    status("vc_approval_status", "Could not generate a holder key pair: " + e.message, "vc-bad");
  });
  log.debug("Leaving regenerateHolderKey().");
  return false;
}

// Extra holder keys for a batch request. The first is the stored holder key, so
// what the page shows stays the key the first credential is bound to; the rest
// live for this request only, which is the honest lifetime — a wallet asking for
// several bindings has several keys.
function holderKeysFor(count) {
  return vciWallet.holderKeysFor(
    { publicJwk: request.holderPublicJwk, privateJwk: request.holderPrivateJwk }, count);
}

// --- the proof of possession ------------------------------------------------
// One proof per key. Every proof carries the same c_nonce — it is the ISSUER's
// nonce for this request, not a per-key value — and each names its own key in
// the header, which is what the issuer binds that credential to.
function signProof(nonce) {
  log.debug("Entering signProof().");
  var wanted = Math.min(requestedBatchSize(), issuerBatchSize());
  log.debug("Leaving signProof(). Signing " + wanted + " proof(s).");
  return holderKeysFor(wanted)
    .then(function (keys) {
      request.holderKeys = keys;
      return vciWallet.signProofs(keys, {
        clientId: sdJwtVc.get("client_id") || "",
        credentialIssuer: request.config.credentialIssuer,
        nonce: nonce
      });
    })
    .then(function (proofs) {
      request.proofs = proofs;
      // The first one is "the" proof the page displays, as it always was.
      request.proof = proofs[0];
      setValue("vc_proof_jwt", request.proof);
      return request.proof;
    });
}

function fetchNonce() {
  log.debug("Entering fetchNonce().");
  log.debug("Leaving fetchNonce().");
  return vciWallet.fetchNonce(request.config.nonceEndpoint)
    .then(function (result) {
      request.nonce = result.nonce;
      if (!result.published) {
        // The Nonce Endpoint is optional. Without one there is no c_nonce to carry.
        setText("vc_nonce", "— (this issuer publishes no nonce_endpoint)");
      } else {
        setText("vc_nonce", request.nonce || "— (the nonce endpoint returned no c_nonce)");
      }
      return request.nonce;
    })
    .catch(function (e) {
      request.nonce = "";
      setText("vc_nonce", "— (could not fetch one: " + e.message + ")");
      throw e;
    });
}

// ---------------------------------------------------------------------------
// Build the whole request up front, so the pane above shows what WILL be sent
// rather than filling in after the fact — by which point this page has already
// handed over to step 3.
//
// A c_nonce is short-lived and single use, so what is built here can go stale
// while the user reads it; approveIssuance() rebuilds and retries once if the
// issuer says so.
// ---------------------------------------------------------------------------
function prepareRequest() {
  log.debug("Entering prepareRequest().");
  if (!request.config.credentialEndpoint) {
    setText("vc_nonce", "— (no issuer is configured)");
    setValue("vc_proof_jwt", "");
    renderProofJwt(null);
    setJson("vc_request_body", null);
    setValue("vc_approval_request", "");
    status("vc_approval_status",
      "No credential_endpoint is configured, so there is no request to build. Retrieve the credential " +
      "issuer metadata in step 1.", "vc-bad");
    return Promise.resolve(false);
  }
  log.debug("Leaving prepareRequest().");
  var wantsEncryption = !!(el("vc_encrypt_response") && el("vc_encrypt_response").checked) ||
                        !!((issuerEncryption() || {}).encryption_required);
  var encryptionReady = wantsEncryption
    ? vciWallet.generateResponseEncryptionKey(chosenEnc())
        .then(function (material) { request.encryption = material; })
    : Promise.resolve().then(function () { request.encryption = null; });
  return encryptionReady
    .then(fetchNonce)
    .then(function (nonce) { return signProof(nonce); })
    .then(function () {
      // Cleared BEFORE the body is built, because buildRequestBody() renders the
      // assembled call itself: leaving the previous run's JWE in place would
      // make unticking the box redisplay a ciphertext that is no longer going to
      // be sent.
      request.encryptedRequest = "";
      buildRequestBody();
      // Encrypting last, because the JWE has to cover the FINISHED body — doing
      // it before the proof is signed would seal an incomplete request. Stored
      // on `request` rather than produced at send time so the pane shows the
      // very bytes that go out, not a second encryption of the same body with a
      // different CEK and IV.
      if (!wantsRequestEncryption()) return true;
      return vciWallet.encryptRequestBody(request.body, requestEncryptionOffer())
        .then(function (jwe) {
          request.encryptedRequest = jwe;
          // Re-render: the call built a moment ago described the plaintext.
          renderAssembledCall();
          return true;
        });
    })
    .catch(function (e) {
      log.error("could not prepare the credential request: " + e.message);
      status("vc_approval_status",
        "Could not prepare the credential request: " + e.message +
        " Approving will try again.", "vc-bad");
      return false;
    });
}

// Which Credential Dataset identifiers the token response granted, if the
// authorization used authorization_details (OID4VCI section 6.2). Stored by
// debugger2.html when it exchanged the code.
function grantedIdentifiers() {
  log.debug("Entering grantedIdentifiers().");
  var details = sdJwtVc.getJson("token_authorization_details");
  var out = [];
  if (Object.prototype.toString.call(details) === "[object Array]") {
    details.forEach(function (d) {
      (((d || {}).credential_identifiers) || []).forEach(function (id) { out.push(id); });
    });
  }
  log.debug("Leaving grantedIdentifiers(). " + out.length + " granted.");
  return out;
}

function buildRequestBody() {
  log.debug("Entering buildRequestBody().");
  // Section 8.2: exactly one of credential_identifier / credential_configuration_id
  // names the credential, and which one is not a choice — a token response that
  // granted credential_identifiers requires one of them and forbids the
  // configuration id.
  var granted = grantedIdentifiers();
  var body = vciWallet.buildRequestBody({
    credentialIdentifier: granted.length ? granted[0] : "",
    credentialConfigurationId: request.config.credentialConfigurationId,
    proofs: request.proofs,
    encryption: request.encryption
  });
  request.body = body;
  setJson("vc_request_body", body);
  renderProofJwt(body);
  renderAssembledCall();
  renderRequestOptions();
  log.debug("Leaving buildRequestBody().");
  return body;
}

// ---------------------------------------------------------------------------
// The three things the wallet decides about the request, and what each means
// against THIS issuer's metadata.
// ---------------------------------------------------------------------------
function issuerBatchSize() {
  var advertised = sdJwtVc.getJson("vci_batch_credential_issuance");
  var size = advertised && Number(advertised.batch_size);
  return size && size > 0 ? size : 1;
}

function issuerEncryption() {
  return sdJwtVc.getJson("vci_credential_response_encryption") || null;
}

// Which content encryption algorithm to ask for. The strongest of what this
// issuer offers, rather than whichever it happens to list first.
function chosenEnc() {
  var offered = (issuerEncryption() || {}).enc_values_supported || [];
  if (offered.indexOf("A256GCM") !== -1) return "A256GCM";
  return offered[0] || "A256GCM";
}

function requestedBatchSize() {
  var wanted = parseInt((el("vc_batch_size") && el("vc_batch_size").value) || "1", 10);
  if (!wanted || wanted < 1) wanted = 1;
  return wanted;
}

function renderRequestOptions() {
  log.debug("Entering renderRequestOptions().");
  var granted = grantedIdentifiers();
  setText("vc_identifier_mode", granted.length
    ? "credential_identifier = " + granted[0] +
      " (the token response granted it, so credential_configuration_id must not be sent)"
    : "credential_configuration_id = " + (request.config.credentialConfigurationId || "—") +
      " (the authorization used a scope, so no credential_identifiers were granted)");

  var batchSize = issuerBatchSize();
  var input = el("vc_batch_size");
  if (input) {
    input.max = String(batchSize);
    if (Number(input.value) > batchSize) input.value = String(batchSize);
    input.disabled = batchSize <= 1;
  }
  setText("vc_batch_note", batchSize > 1
    ? "This issuer accepts up to " + batchSize + " proofs in one request, and returns one credential per proof."
    : "This issuer does not advertise batch_credential_issuance, so one credential per request.");

  var encryption = issuerEncryption();
  var box = el("vc_encrypt_response");
  if (box) box.disabled = !encryption;
  if (!encryption) {
    if (box) box.checked = false;
    setText("vc_encrypt_note",
      "This issuer does not advertise credential_response_encryption, so the response comes back as JSON.");
  } else {
    var algs = (encryption.alg_values_supported || []).join(", ");
    var encs = (encryption.enc_values_supported || []).join(", ");
    setText("vc_encrypt_note",
      "This issuer supports alg " + (algs || "—") + " and enc " + (encs || "—") +
      (encryption.encryption_required ? " and REQUIRES encryption." : ". Encryption is optional.") +
      " This wallet implements RSA-OAEP-256.");
  }

  // The request side. Its availability is decided by the wallet module rather
  // than by reading the metadata here, because the decision is not "is it
  // advertised" — a key with no alg, or an enc this wallet cannot perform, is
  // advertised and still unusable, and section 10 gives the wallet no way to
  // guess past either. requestEncryptionOffer() already reaches that verdict
  // for the module's own use; asking it again here is what keeps the checkbox
  // and the request that gets sent from disagreeing.
  var reqOffer = requestEncryptionOffer();
  var reqBox = el("vc_encrypt_request");
  if (reqBox) reqBox.disabled = !reqOffer.usable;
  if (!reqOffer.usable && reqBox) reqBox.checked = false;
  // Required-but-impossible is the state worth naming: the endpoint cannot be
  // used at all, and saying only "unavailable" would leave the user retrying.
  if (reqOffer.required && !reqOffer.usable) {
    setText("vc_encrypt_request_note",
      "This issuer REQUIRES request encryption and this wallet cannot provide it — " + reqOffer.reason +
      " The Credential Endpoint cannot be used until that is resolved.");
  } else if (reqOffer.usable) {
    // Section 10 makes it the wallet's choice unless required, so the box is
    // ticked for the user rather than forced, except when it is not a choice.
    if (reqOffer.required && reqBox && !reqBox.checked) reqBox.checked = true;
    setText("vc_encrypt_request_note", reqOffer.reason +
      (reqOffer.required
        ? " This issuer REQUIRES it, so it cannot be turned off."
        : " Encryption is optional here; the request goes as application/jwt when ticked.") +
      (reqOffer.skipped && reqOffer.skipped.length
        ? " Other keys were skipped: " + reqOffer.skipped.join(", ") + "."
        : ""));
    if (reqOffer.required && reqBox) reqBox.disabled = true;
  } else {
    setText("vc_encrypt_request_note", reqOffer.reason);
  }
  log.debug("Leaving renderRequestOptions().");
}

// What the issuer published for REQUEST encryption. Step 1 stores each metadata
// member separately under a vci_-prefixed key, so this is the counterpart of
// issuerEncryption() above and not a second way of reading the same thing.
function issuerRequestEncryption() {
  return sdJwtVc.getJson("vci_credential_request_encryption") || null;
}

// The wallet module's verdict on that offer. It takes a metadata-shaped object,
// so the stored member is put back under its own name rather than the module
// growing a second entry point for this page's storage layout.
function requestEncryptionOffer() {
  var published = issuerRequestEncryption();
  return vciWallet.requestEncryptionOffer(
    published ? { credential_request_encryption: published } : {});
}

// Whether the assembled request will actually be encrypted: the box, or the
// issuer insisting. Mirrors how wantsEncryption is decided for the response.
function wantsRequestEncryption() {
  var offer = requestEncryptionOffer();
  if (!offer.usable) return false;
  return offer.required || !!(el("vc_encrypt_request") && el("vc_encrypt_request").checked);
}

// A change to any of them invalidates the assembled request, so it is rebuilt —
// new keys, new proofs, new body.
function onRequestOptionsChange() {
  log.debug("Entering onRequestOptionsChange().");
  status("vc_approval_status", "Rebuilding the request …", "vc-pending");
  prepareRequest().then(function (ready) {
    if (ready) {
      status("vc_approval_status",
        "Ready: the request below is what Approve will send.", "vc-ok");
    }
  });
  log.debug("Leaving onRequestOptionsChange().");
  return true;
}

// ---------------------------------------------------------------------------
// The proof JWT, taken back out of the request body's proofs.jwt and decoded
// into its header and payload — read from the body rather than from the
// variable it was built in, so what is shown is literally what is being sent.
// ---------------------------------------------------------------------------
function renderProofJwt(body) {
  log.debug("Entering renderProofJwt().");
  var jwt = body && body.proofs && body.proofs.jwt && body.proofs.jwt[0];
  if (!jwt) {
    setValue("jwt_header", "");
    setValue("jwt_payload", "");
    return;
  }
  var parts = String(jwt).split(".");
  try {
    setValue("jwt_header", JSON.stringify(metadataClient.b64uToJson(parts[0]), null, 2));
    setValue("jwt_payload", JSON.stringify(metadataClient.b64uToJson(parts[1]), null, 2));
  } catch (e) {
    log.error("could not decode the proof JWT: " + e.message);
    setValue("jwt_header", "Could not decode the proof JWT: " + e.message);
    setValue("jwt_payload", "");
  }
  log.debug("Leaving renderProofJwt().");
}

// ---------------------------------------------------------------------------
// The call Approve will make, spelled out: method, full URL, headers and body.
//
// The Authorization header is part of it — presenting the access token as a
// Bearer credential IS how the request is authorized — so leaving it out would
// not be the whole call.
// ---------------------------------------------------------------------------
function renderAssembledCall() {
  log.debug("Entering renderAssembledCall().");
  var endpoint = request.config ? request.config.credentialEndpoint : "";
  if (!endpoint || !request.body) {
    setValue("vc_approval_request", "");
    return "";
  }
  var accessToken = sdJwtVc.get("token_access_token") || "";
  // What is shown must be what is SENT. When the request is encrypted the body
  // on the wire is the compact JWE and the media type is application/jwt, so
  // showing the JSON here would describe a call this page does not make — and
  // the JSON is exactly what encryption is hiding. The plaintext is still worth
  // seeing, so it is named as such below the JWE rather than shown as the body.
  var encryptedBody = request.encryptedRequest || "";
  var text = vciWallet.describeCall({
    method: "POST",
    url: endpoint,
    contentType: encryptedBody ? "application/jwt" : "application/json",
    authorization: "Bearer " + (accessToken || "(no access token yet — authenticate in step 1)"),
    body: encryptedBody || JSON.stringify(request.body, null, 2)
  });
  if (encryptedBody) {
    text += "\n\n--- the plaintext inside that JWE (not sent in the clear) ---\n" +
            JSON.stringify(request.body, null, 2);
  }
  setValue("vc_approval_request", text);
  log.debug("Leaving renderAssembledCall().");
  return text;
}

// ---------------------------------------------------------------------------
// The Token Request, for an offer that carries a pre-authorized code
// (OID4VCI Appendix H.2 / H.3).
//
// There was no authorization request and nobody signed in: the End-User was
// identified by the issuer through some other channel days or minutes ago, and
// the code in the offer is what that produced. When the offer says a
// Transaction Code is required, it must be presented too — and it reached the
// End-User separately from the offer, which is what stops a photographed QR
// code from being enough on its own.
// ---------------------------------------------------------------------------
function preAuthorizedOffer() {
  var code = sdJwtVc.offerPreAuthorizedCode();
  if (!code) return null;
  return { code: code, txCode: sdJwtVc.offerTxCode() };
}

function tokenRequestBody() {
  log.debug("Entering tokenRequestBody().");
  var offer = preAuthorizedOffer();
  if (!offer) {
    log.debug("Leaving tokenRequestBody(). There is no pre-authorized offer.");
    return null;
  }
  var params = {
    grant_type: sdJwtVc.PRE_AUTHORIZED_GRANT,
    "pre-authorized_code": offer.code
  };
  var clientId = sdJwtVc.get("client_id") || "";
  if (clientId) params.client_id = clientId;
  var typed = (el("vc_tx_code") && el("vc_tx_code").value || "").trim();
  if (typed) params.tx_code = typed;
  log.debug("Leaving tokenRequestBody().");
  return params;
}

function renderTokenRequest() {
  log.debug("Entering renderTokenRequest().");
  var params = tokenRequestBody();
  var endpoint = sdJwtVc.get("token_endpoint") || "";
  if (!params) {
    setValue("vc_token_request", "");
    log.debug("Leaving renderTokenRequest(). Nothing to render.");
    return "";
  }
  var text = vciWallet.describeCall({
    method: "POST",
    url: endpoint || "(no token_endpoint is configured — retrieve the metadata in step 1)",
    contentType: "application/x-www-form-urlencoded",
    body: vciWallet.encodeForm(params)
  });
  setValue("vc_token_request", text);
  log.debug("Leaving renderTokenRequest().");
  return text;
}

function onTxCodeChange() {
  renderTokenRequest();
  return true;
}

// Show the pane, and say what the offer demands before anything is sent.
function showPreAuthorizedPane() {
  log.debug("Entering showPreAuthorizedPane().");
  var offer = preAuthorizedOffer();
  var pane = el("pane_pre_authorized");
  if (!pane) return false;
  if (!offer) {
    pane.style.display = "none";
    log.debug("Leaving showPreAuthorizedPane(). Not a pre-authorized issuance.");
    return false;
  }
  pane.style.display = "";
  setText("vc_pre_authorized_code", offer.code);
  var row = el("vc_tx_code_row");
  if (offer.txCode) {
    if (row) row.style.display = "";
    var hint = "The issuer requires a Transaction Code" +
      (offer.txCode.length ? " of " + offer.txCode.length + " " : " ") +
      (offer.txCode.input_mode === "numeric" ? "digits" : "characters") + ". " +
      (offer.txCode.description || "");
    setText("vc_tx_code_hint", hint.trim());
    if (el("vc_tx_code") && offer.txCode.length) el("vc_tx_code").maxLength = offer.txCode.length;
  } else if (row) {
    row.style.display = "none";
  }
  renderTokenRequest();
  status("vc_token_status", offer.txCode
    ? "Type the Transaction Code the issuer showed you, then send the Token Request."
    : "Send the Token Request to redeem the pre-authorized code.", "vc-pending");
  log.debug("Leaving showPreAuthorizedPane().");
  return true;
}

function sendTokenRequest() {
  log.debug("Entering sendTokenRequest().");
  var params = tokenRequestBody();
  var endpoint = sdJwtVc.get("token_endpoint") || "";
  if (!params) {
    status("vc_token_status", "There is no pre-authorized offer to redeem.", "vc-bad");
    return false;
  }
  if (!endpoint) {
    status("vc_token_status",
      "No token_endpoint is configured. Retrieve the authorization server metadata in step 1.", "vc-bad");
    return false;
  }
  var offer = preAuthorizedOffer();
  if (offer.txCode && !params.tx_code) {
    status("vc_token_status",
      "This offer requires the Transaction Code the issuer displayed. Type it in first.", "vc-bad");
    log.debug("Leaving sendTokenRequest(). No tx_code was typed.");
    return false;
  }

  el("vc_token_request_button").disabled = true;
  status("vc_token_status", "Redeeming the pre-authorized code …", "vc-pending");
  fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: vciWallet.encodeForm(params)
  })
    .then(function (r) {
      return r.text().then(function (text) {
        var parsed = null;
        try {
          parsed = JSON.parse(text);
        } catch (e) {
          // Not JSON: the raw text is what gets shown.
        }
        return { ok: r.ok, statusCode: r.status, body: parsed, raw: text };
      });
    })
    .then(function (response) {
      var box = el("vc_token_response");
      if (box) {
        box.style.display = "block";
        box.textContent = response.body ? JSON.stringify(response.body, null, 2) : response.raw;
      }
      if (!response.ok || !response.body || !response.body.access_token) {
        var err = (response.body && (response.body.error_description || response.body.error)) ||
                  ("HTTP " + response.statusCode);
        status("vc_token_status", "The token endpoint refused the request: " + err, "vc-bad");
        el("vc_token_request_button").disabled = false;
        log.debug("Leaving sendTokenRequest(). Refused: " + err);
        return;
      }
      // Stored under the same names the OIDC leg uses, so everything downstream
      // — this page, token_detail.html — reads it without knowing which flow
      // produced it.
      sdJwtVc.set("token_access_token", response.body.access_token);
      if (response.body.id_token) sdJwtVc.set("token_id_token", response.body.id_token);
      if (response.body.refresh_token) sdJwtVc.set("token_refresh_token", response.body.refresh_token);
      status("vc_token_status",
        "An access token was issued. The credential request below can now be authorized with it.", "vc-ok");
      showTokens();
      renderAssembledCall();
      status("vc_approval_status",
        "Ready: the proof of possession is signed and the request below is what Approve will send.", "vc-ok");
    })
    .catch(function (e) {
      log.error("the token request failed: " + e.message);
      status("vc_token_status", "The token request failed: " + e.message, "vc-bad");
      el("vc_token_request_button").disabled = false;
    });
  log.debug("Leaving sendTokenRequest().");
  return false;
}

// --- the credential request -------------------------------------------------
function approveIssuance() {
  log.debug("Entering approveIssuance().");
  var accessToken = sdJwtVc.get("token_access_token") || "";
  if (!accessToken) {
    status("vc_approval_status",
      "There is no access token to present. Run step 1 and authenticate first.", "vc-bad");
    return false;
  }
  if (!request.config.credentialEndpoint) {
    status("vc_approval_status",
      "No credential_endpoint is configured. Retrieve the credential issuer metadata in step 1.", "vc-bad");
    return false;
  }
  el("vc_approve_button").disabled = true;

  var send = function () {
    log.debug("Entering send().");
    status("vc_approval_status",
      request.encryptedRequest ? "Sending the encrypted Credential Request …"
                               : "Sending the Credential Request …", "vc-pending");
    // Section 10: an encrypted request IS a JWT and says so in its media type,
    // which is what tells the issuer to decrypt rather than parse. The JWE was
    // built in prepareRequest() over the finished body; it is reused here rather
    // than rebuilt so the bytes sent are the bytes the pane displayed.
    var encrypted = request.encryptedRequest || "";
    log.debug("Leaving send().");
    return fetch(request.config.credentialEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": encrypted ? "application/jwt" : "application/json",
        "Authorization": "Bearer " + accessToken
      },
      body: encrypted || JSON.stringify(request.body || buildRequestBody())
    }).then(function (r) {
      return r.text().then(function (text) {
        return readCredentialResponse(r, text);
      });
    });
  };

  // The proof shown above was built when the page loaded; if it is not there
  // (or the issuer rejects it as stale — a c_nonce is single use and expires)
  // build a fresh one and send once more.
  var ready = request.proof ? Promise.resolve(true) : prepareRequest();
  ready
    .then(send)
    .then(function (response) {
      if (response.ok || !response.body || response.body.error !== "invalid_proof") return response;
      log.debug("the issuer rejected the proof; rebuilding it with a fresh nonce and retrying once.");
      status("vc_approval_status",
        "The proof had gone stale (a c_nonce is single use) — rebuilding it and trying again …", "vc-pending");
      return prepareRequest().then(send);
    })
    .then(function (response) {
      var box = el("vc_response_body");
      box.style.display = "block";
      box.textContent = response.body ? JSON.stringify(response.body, null, 2) : response.raw;
      if (!response.ok) {
        var err = (response.body && (response.body.error_description || response.body.error)) ||
                  ("HTTP " + response.statusCode);
        status("vc_approval_status", "The issuer refused the request: " + err, "vc-bad");
        el("vc_approve_button").disabled = false;
        return;
      }
      // The issuer may not be able to issue immediately (OID4VCI section 8.3):
      // then the response is a transaction_id, and the credential is collected
      // from the Deferred Credential Endpoint instead.
      if (response.body && response.body.transaction_id && !extractCredential(response.body)) {
        beginDeferred(response.body, response.statusCode);
        return;
      }
      var credential = extractCredential(response.body);
      if (!credential) {
        status("vc_approval_status",
          "The issuer answered, but the response carries no credential.", "vc-bad");
        el("vc_approve_button").disabled = false;
        return;
      }
      keepCredential(credential, response.body, {});
      status("vc_approval_status", "Credential issued. Opening step 3 …", "vc-ok");
      window.location.href = sdJwtVc.STEP3_URL;
    })
    .catch(function (e) {
      log.error("credential request failed: " + e.message);
      status("vc_approval_status", "The credential request failed: " + e.message, "vc-bad");
      el("vc_approve_button").disabled = false;
    });
  log.debug("Leaving approveIssuance().");
  return false;
}

// Everything that has to be remembered about an issued credential, wherever it
// finally came from — the credential endpoint or the deferred one.
function keepCredential(credential, responseBody, extra) {
  log.debug("Entering keepCredential().");
  sdJwtVc.set(sdJwtVc.KEYS.CREDENTIAL, credential);
  // A batch request comes back with one credential per proof. Step 3 shows them
  // all rather than silently dropping the rest.
  var all = allCredentials(responseBody);
  sdJwtVc.setJson(sdJwtVc.KEYS.CREDENTIALS, all);
  var meta = {
    issuer: request.config.credentialIssuer,
    endpoint: request.config.credentialEndpoint,
    configurationId: request.config.credentialConfigurationId,
    format: request.config.format,
    vct: request.config.vct,
    requestedAt: new Date().toISOString(),
    notificationId: (responseBody && responseBody.notification_id) || "",
    request: request.body,
    holderJwk: request.holderPublicJwk,
    // One entry per credential, in the order the proofs were sent, so step 3 can
    // say which key each credential is bound to.
    holderJwks: (request.holderKeys || []).map(function (k) { return k.publicJwk; }),
    credentialCount: all.length,
    encrypted: !!request.encryption,
    notificationEndpoint: request.config.notificationEndpoint || ""
  };
  Object.keys(extra || {}).forEach(function (k) { meta[k] = extra[k]; });
  sdJwtVc.setJson(sdJwtVc.KEYS.CREDENTIAL_META, meta);
  // The first generation of this credential. Step 4 records every refresh that
  // replaces it, so the history it navigates starts here — with the holder key,
  // because going back to a generation whose key is gone would give the wallet a
  // credential it cannot present.
  sdJwtVc.recordCredentialGeneration({
    source: meta.deferred ? "issued (deferred)" : "issued",
    // The history pane says what happened for every row; the issuance is a row
    // too, so it needs its sentence as much as a refresh does.
    detail: "issued by " + (request.config.credentialIssuer || "the credential issuer") +
            (all.length > 1 ? " — " + all.length + " credentials in one response" : "") +
            (meta.deferred ? ", collected from the Deferred Credential Endpoint" : "") +
            (request.encryption ? ", in an encrypted Credential Response" : ""),
    credential: credential,
    credentials: all,
    meta: meta,
    holderJwk: request.holderPublicJwk,
    holderPrivateJwk: request.holderPrivateJwk
  });
  log.debug("Leaving keepCredential().");
}

// ---------------------------------------------------------------------------
// Deferred issuance (OID4VCI section 9, Appendix H.3).
//
// The Credential Response carried a transaction_id instead of a credential, so
// the wallet keeps coming back to the Deferred Credential Endpoint until it
// gets one. `interval` is the issuer saying how long to wait between attempts;
// every attempt is shown, because a wallet that silently spins is exactly what
// a debugger should not be.
// ---------------------------------------------------------------------------
var deferred = {
  transactionId: "",
  intervalSeconds: 0,
  attempts: [],
  timer: 0,
  polling: false
};

function deferredEndpoint() {
  return (request.config && request.config.deferredCredentialEndpoint) ||
         sdJwtVc.get("vci_deferred_credential_endpoint") || "";
}

function renderDeferredRequest() {
  log.debug("Entering renderDeferredRequest().");
  var endpoint = deferredEndpoint();
  var accessToken = sdJwtVc.get("token_access_token") || "";
  setValue("vc_deferred_request", vciWallet.describeCall({
    method: "POST",
    url: endpoint || "(this issuer publishes no deferred_credential_endpoint)",
    contentType: "application/json",
    authorization: "Bearer " + (accessToken || "(no access token)"),
    body: JSON.stringify({ transaction_id: deferred.transactionId }, null, 2)
  }));
  log.debug("Leaving renderDeferredRequest().");
}

function renderDeferredAttempts() {
  var e = el("vc_deferred_attempts");
  if (!e) return;
  e.textContent = deferred.attempts.length
    ? deferred.attempts.map(function (a, i) {
        return (i + 1) + ". " + a.at + "  HTTP " + a.status + "  " + a.summary;
      }).join("\n")
    : "—";
}

function beginDeferred(body, statusCode) {
  log.debug("Entering beginDeferred(). transaction_id=" + body.transaction_id);
  deferred.transactionId = String(body.transaction_id);
  deferred.intervalSeconds = Number(body.interval) || 5;
  deferred.attempts = [];
  var pane = el("pane_deferred");
  if (pane) pane.style.display = "";
  setText("vc_transaction_id", deferred.transactionId);
  setText("vc_deferred_endpoint", deferredEndpoint() || "— none published —");
  renderDeferredRequest();
  renderDeferredAttempts();
  status("vc_approval_status",
    "The issuer answered " + statusCode + ": it cannot issue this credential yet. Collecting it from the " +
    "Deferred Credential Endpoint …", "vc-pending");

  if (!deferredEndpoint()) {
    status("vc_deferred_status",
      "The issuer deferred the issuance but publishes no deferred_credential_endpoint, so there is nowhere " +
      "to collect the credential from. That is the issuer's bug, not the wallet's.", "vc-bad");
    log.debug("Leaving beginDeferred(). No endpoint to poll.");
    return;
  }
  status("vc_deferred_status",
    "Waiting for the issuer. It asked for " + deferred.intervalSeconds +
    "s between attempts; the wallet will keep checking.", "vc-pending");
  scheduleDeferredPoll(0);
  log.debug("Leaving beginDeferred().");
}

function scheduleDeferredPoll(delaySeconds) {
  if (deferred.timer) window.clearTimeout(deferred.timer);
  deferred.timer = window.setTimeout(function () {
    pollDeferred();
  }, Math.max(0, delaySeconds) * 1000);
}

function pollDeferred() {
  log.debug("Entering pollDeferred().");
  if (!deferred.transactionId) {
    status("vc_deferred_status", "There is no deferred issuance in progress.", "vc-bad");
    return false;
  }
  if (deferred.polling) {
    log.debug("Leaving pollDeferred(). A poll is already in flight.");
    return false;
  }
  var endpoint = deferredEndpoint();
  if (!endpoint) {
    status("vc_deferred_status", "This issuer publishes no deferred_credential_endpoint.", "vc-bad");
    return false;
  }
  deferred.polling = true;
  renderDeferredRequest();
  fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + (sdJwtVc.get("token_access_token") || "")
    },
    body: JSON.stringify({ transaction_id: deferred.transactionId })
  })
    .then(function (r) {
      return r.text().then(function (text) {
        return readCredentialResponse(r, text);
      });
    })
    .then(function (response) {
      deferred.polling = false;
      var credential = extractCredential(response.body);
      var summary;
      if (credential) {
        summary = "the credential was issued";
      } else if (response.body && response.body.transaction_id) {
        summary = "still pending (interval " + (response.body.interval || deferred.intervalSeconds) + "s)";
      } else {
        summary = (response.body && (response.body.error_description || response.body.error)) || response.raw;
      }
      deferred.attempts.push({
        at: new Date().toISOString(),
        status: response.statusCode,
        summary: String(summary).slice(0, 200)
      });
      renderDeferredAttempts();

      if (credential) {
        keepCredential(credential, response.body, {
          deferred: true,
          transactionId: deferred.transactionId,
          deferredEndpoint: endpoint,
          deferredAttempts: deferred.attempts.length
        });
        // Spent: the issuer invalidates it once the credential is collected.
        deferred.transactionId = "";
        status("vc_deferred_status",
          "The credential was issued after " + deferred.attempts.length +
          (deferred.attempts.length === 1 ? " attempt." : " attempts."), "vc-ok");
        status("vc_approval_status", "Credential issued. Opening step 3 …", "vc-ok");
        window.location.href = sdJwtVc.STEP3_URL;
        return;
      }

      if (response.statusCode === 202 && response.body && response.body.transaction_id) {
        var wait = Number(response.body.interval) || deferred.intervalSeconds;
        deferred.intervalSeconds = wait;
        status("vc_deferred_status",
          "Attempt " + deferred.attempts.length + ": the issuer is still working on it. Checking again in " +
          wait + "s.", "vc-pending");
        scheduleDeferredPoll(wait);
        return;
      }

      var err = (response.body && (response.body.error_description || response.body.error)) ||
                ("HTTP " + response.statusCode);
      status("vc_deferred_status", "The deferred request was refused: " + err, "vc-bad");
      log.debug("Leaving pollDeferred(). Refused: " + err);
    })
    .catch(function (e) {
      deferred.polling = false;
      log.error("the deferred credential request failed: " + e.message);
      deferred.attempts.push({ at: new Date().toISOString(), status: 0, summary: e.message });
      renderDeferredAttempts();
      status("vc_deferred_status", "The deferred request failed: " + e.message +
             " Use “Check again now” to retry.", "vc-bad");
    });
  log.debug("Leaving pollDeferred().");
  return false;
}

// ---------------------------------------------------------------------------
// Reading a Credential Response, encrypted or not (OID4VCI section 10), and
// finding the credential(s) in it. Both live in vci_wallet.js, because step 4
// reads exactly the same response when it refreshes the credential.
// ---------------------------------------------------------------------------
function readCredentialResponse(r, text) {
  return vciWallet.readCredentialResponse(r, text, request.encryption);
}

function allCredentials(body) { return vciWallet.allCredentials(body); }

function extractCredential(body) { return vciWallet.extractCredential(body); }

function denyIssuance() {
  sdJwtVc.endFlow();
  status("vc_approval_status",
    "Issuance denied. Nothing was sent to the issuer. Returning to step 1 …", "vc-pending");
  window.setTimeout(function () { window.location.href = "/vc-issuance-1.html"; }, 1200);
  return false;
}

// --- page state -------------------------------------------------------------
function showTokens() {
  log.debug("Entering showTokens().");
  var access = sdJwtVc.get("token_access_token") || "";
  var id = sdJwtVc.get("token_id_token") || "";
  var refresh = sdJwtVc.get("token_refresh_token") || "";
  setValue("vc_access_token", access);
  setValue("vc_id_token", id);
  setValue("vc_refresh_token", refresh);

  var claims = null;
  try {
    if (id && id.split(".").length === 3) claims = metadataClient.b64uToJson(id.split(".")[1]);
  } catch (e) {
    // not a JWT
  }
  setJson("vc_id_token_claims", claims);

  if (!access) {
    status("tokens_status",
      "No access token found. Step 2 runs on the tokens the OIDC flow leaves behind — " +
      "start from step 1 and authenticate.", "vc-bad");
  } else {
    status("tokens_status", "Access token present" + (id ? " with an ID token." : "."), "vc-ok");
  }
  log.debug("Leaving showTokens().");
  return claims;
}

function showRequestConfig(idTokenClaims) {
  log.debug("Entering showRequestConfig().");
  var cfg = sdJwtVc.storedRequestConfig();
  request.config = cfg;
  setText("vc_credential_endpoint", cfg.credentialEndpoint || "—");
  setText("vc_credential_issuer", cfg.credentialIssuer || "—");
  setText("vc_credential_config",
    (cfg.credentialConfigurationId || "—") + " (" + (cfg.format || "?") + ", vct " + (cfg.vct || "?") + ")");
  setText("vc_approval_issuer", cfg.credentialIssuer || "—");
  setText("vc_approval_credential", (cfg.credentialConfigurationId || "—") + " / " + (cfg.vct || "?"));
  var subject = (idTokenClaims && (idTokenClaims.preferred_username || idTokenClaims.email ||
                                   idTokenClaims.sub)) || "the authenticated user";
  setText("vc_approval_subject", subject);

  // What the issuer said this credential can carry, straight from the metadata
  // document step 1 retrieved.
  var claimNames = [];
  var doc = sdJwtVc.getJson("vci_info");
  var cfgs = (doc && doc.credential_configurations_supported) || {};
  var chosen = cfgs[cfg.credentialConfigurationId];
  if (chosen && Object.prototype.toString.call(chosen.claims) === "[object Array]") {
    claimNames = chosen.claims.map(function (c) {
      return Object.prototype.toString.call(c.path) === "[object Array]" ? c.path.join(".") : String(c.path);
    });
  }
  setText("vc_approval_claims", claimNames.length ? claimNames.join(", ") : "not stated in the metadata");
  log.debug("Leaving showRequestConfig().");
}

function togglePane(id) {
  var fs = el(id);
  if (fs) fs.style.display = (fs.style.display === "none") ? "block" : "none";
  return false;
}

function onload() {
  log.debug("Entering onload().");
  // The hand-off has done its job; from here the workflow is on its own pages.
  sdJwtVc.endFlow();
  sdJwtVc.renderUseCaseBadge();
  var step = document.getElementById("vc_step_2");
  if (step) step.className = "vc-step-current";
  var done = document.getElementById("vc_step_1");
  if (done) done.className = "vc-step-done";
  var zero = document.getElementById("vc_step_0");
  if (zero) zero.className = "vc-step-done";

  // Reflect the stored preference on the checkbox, and re-apply it: if saving
  // was turned off in an earlier session, anything written since (by an older
  // build, or by a page that ran before this one) has to go.
  var saveBox = document.getElementById("vc_save_holder_key");
  if (saveBox) saveBox.checked = sdJwtVc.holderPrivateKeyMayBeStored();
  if (!sdJwtVc.holderPrivateKeyMayBeStored()) sdJwtVc.forgetStoredHolderPrivateKeys();
  renderHolderKeyStorageNote();

  var claims = showTokens();
  showRequestConfig(claims);
  // A pre-authorized offer has no OIDC leg behind it: the token request is
  // this page's job, and it is shown before it is sent like everything else.
  showPreAuthorizedPane();
  loadOrGenerateHolderKey()
    .then(function (pub) {
      setJson("vc_holder_jwk", pub);
      // Build the request now, so the pane shows what approving will send.
      // Deliberately NOT conditional on having an access token: the proof of
      // possession is signed with the holder key and addressed to the issuer,
      // neither of which comes from the OIDC leg. Someone who opens this page
      // directly still gets to see the request the workflow would make.
      return prepareRequest();
    })
    .then(function (ready) {
      if (!ready) return;
      status("vc_approval_status", sdJwtVc.get("token_access_token")
        ? "Ready: the proof of possession is signed and the request below is what Approve will send."
        : "The request below is ready, but there is no access token to authorize it with — " +
          "start from step 1 and authenticate.",
        sdJwtVc.get("token_access_token") ? "vc-ok" : "vc-pending");
    })
    .catch(function (e) {
      status("vc_approval_status", "Could not prepare the credential request: " + e.message, "vc-bad");
    });
  log.debug("SD-JWT VC issuance step 2 ready.");
  log.debug("Leaving onload().");
}

if (typeof window !== "undefined") {
  window.addEventListener("load", onload);
}

module.exports = {
  approveIssuance: approveIssuance,
  sendTokenRequest: sendTokenRequest,
  onTxCodeChange: onTxCodeChange,
  showPreAuthorizedPane: showPreAuthorizedPane,
  pollDeferred: pollDeferred,
  renderProofJwt: renderProofJwt,
  renderAssembledCall: renderAssembledCall,
  denyIssuance: denyIssuance,
  regenerateHolderKey: regenerateHolderKey,
  downloadHolderKey: downloadHolderKey,
  onSaveHolderKeyChange: onSaveHolderKeyChange,
  togglePane: togglePane,
  extractCredential: extractCredential,
  allCredentials: allCredentials,
  onRequestOptionsChange: onRequestOptionsChange,
  renderRequestOptions: renderRequestOptions,
  onload: onload
};
