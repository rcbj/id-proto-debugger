var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var $ = require("jquery");
// THE TWO ENGINES THAT READ A PROTECTED USERINFO RESPONSE, and they are the
// same two every other page here uses — `jws.js` verifies the signature and
// `jose_jwe.js` decrypts, so a response this page accepts is one the JWT Tools
// and token detail pages accept, and a defect in either is a defect in one
// place. See OIDC Core section 5.3.2.
var jwsLib = require("./jws");
var jose = require("./jose_jwe");
var log = bunyan.createLogger({ name: 'userinfo',
                                level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());
var initialized = false
var userinfo_endpoint = "";
var userinfo_scope = "";
var userinfo_method = "";
var userinfo_claims = "";
var token_access_token = "";
var query_string = "";

var useFrontEnd = false;

// The last response exactly as it arrived, so the raw pane shows the OCTETS the
// signature is over rather than a re-rendering of them.
var lastRawResponse = "";

function getParameterByName(name, url)
{
  log.debug("Entering getParameterByName().");
  if (!url)
  {
    url = window.location.search;
  }
  var urlParams = new URLSearchParams(url);
  log.debug("Leaving getParameterByName().");
  return urlParams.get(name);
}

window.onload = function() 
{
  log.debug("Entering onload().");
  log.debug("Entering window.onload() function.");
  initLocalStorage();
  loadValuesFromLocalStorage();
  // Static build (appconfig.backendAvailable === false): no api backend, so
  // force the frontend and disable (gray out) the backend initiation option.
  if (appconfig.backendAvailable === false) {
    $("#userinfo_initiateFromFrontEnd").prop("checked", true);
    $("#userinfo_initiateFromBackEnd").prop("checked", false).prop("disabled",
      true);
  }
  resetErrorDisplays();
  var frontEndInitiated = $("#userinfo_initiateFromFrontEnd").is(":checked");
  if(frontEndInitiated) {
    useFrontEnd = true;
  } else {
    useFrontEnd = false;
  }
  log.debug("useFrontEnd=" + useFrontEnd + ", typeof(useFrontEnd)=" +
            typeof(useFrontEnd));
  recalculateUserInfoURL();
  log.debug("Leaving window.onload() function.");
  log.debug("Leaving onload().");
}

function recalculateUserInfoURL()
{
  log.debug("Entering recalculateUserInfoURL() function.");
  if(!!userinfo_scope) {
    query_string = 'scope=' + userinfo_scope;
  }
  if(!!userinfo_claims) {
    query_string += '&claims=' + userinfo_claims;
  }
  query_string = encodeURI(query_string);
  log.debug("Leaving recalculateUserInfoURL(): query_string=" + query_string);
}

function callUserInfoEndpoint()
{
  log.debug("Entering callUserInfoEndpoint().");
  var url_ = "";
  log.debug("Making Userinfo call. useFrontEnd=" + useFrontEnd);
  const headers = {
    "Authorization": 'Bearer ' + token_access_token,
  };
  if ( userinfo_method === "post" ) {
    headers["Content-Type"] = "application/json";
  }
  if(useFrontEnd) {
    url_ = userinfo_endpoint + "?" + query_string;
  } else {
    url_ = appconfig.apiUrl +
           "/userinfo?" +
           query_string +
           "&userinfo_endpoint=" +
           Buffer.from(userinfo_endpoint +
           "?" +
           query_string).toString('base64');
  }
  log.debug("url_: " + url_);
  $.ajax({
    type: userinfo_method,
    crossdomain: true,
    url: url_,
    headers: headers,
    success: ajaxSuccessFunction,
    error: ajaxErrorFunction
  });
  log.debug("Entering callUserInfoEndpoint().");
  log.debug("Leaving callUserInfoEndpoint().");
}

// ---------------------------------------------------------------------------
// READING A USERINFO RESPONSE — OIDC Core section 5.3.2.
//
// The response is a JSON object UNLESS the client registered a
// `userinfo_signed_response_alg` or a `userinfo_encrypted_response_alg`, in
// which case it is a JWT and the content type is `application/jwt`. There are
// four shapes and this page reads all four:
//
//   application/json          the claims, as they are
//   a three-part JWT          a JWS over the claims
//   a five-part JWT           a JWE over the claims
//   a five-part JWT with a    a JWS INSIDE a JWE — a Nested JWT, which is the
//   three-part JWS inside     order section 5.3.2 requires: signed, THEN
//                             encrypted
//
// The nesting is detected by COUNTING SEGMENTS rather than by trusting the
// outer `cty` header, because `cty: "JWT"` is the announcement a well-behaved
// issuer makes and this is a debugger — the response that is worth reading is
// the one from the issuer that forgot. `cty` is still reported, so its absence
// is visible as a finding rather than as nothing at all.
//
// EVERY STEP IS REPORTED BY NAME. A single "verified: true" over a response
// whose signature was never checked because it was only encrypted is the most
// dangerous thing this page could say — encryption is not authentication, and
// a JWE this page decrypted proves only that it was encrypted to this key.
// ---------------------------------------------------------------------------

function reportLine(report, ok, label, detail) {
  log.debug("Entering reportLine().");
  var mark = ok === null ? "  · " : (ok ? "  OK " : "  ** ");
  report.push(mark + label + (detail ? ": " + detail : ""));
  if (ok === false) {
    report.failed = true;
  }
  log.debug("Leaving reportLine().");
}

// The OP's verification key, from whichever source the page was told to use.
// An HMAC-signed response is verified with the CLIENT SECRET and not with
// anything in the JWKS — OIDC Core section 10.1's symmetric case — which is why
// the source is chosen by the header's `alg` and not by a setting.
async function verificationKeyFor(header) {
  log.debug("Entering verificationKeyFor(). alg=" + (header && header.alg));
  var alg = String((header && header.alg) || "");
  if (alg.indexOf("HS") === 0) {
    var secret = document.getElementById("userinfo_client_secret").value.trim();
    if (!secret) {
      log.debug("Leaving verificationKeyFor(). No client secret.");
      throw new Error("this response is signed " + alg + ", which is signed " +
          "with the client secret — fill in Client Secret to verify it");
    }
    // Read as UTF-8 TEXT, because a client_secret is a password an identity
    // provider issued and not a base64url-encoded JWK member. The JWT Tools
    // page reads its own secret field as base64url for the opposite reason.
    log.debug("Leaving verificationKeyFor(). Client secret.");
    return { secret: secret, encoding: "text" };
  }
  var source = document.getElementById("userinfo_jwks_source").value;
  var value = document.getElementById("userinfo_jwks").value.trim();
  if (!value) {
    log.debug("Leaving verificationKeyFor(). No JWKS.");
    throw new Error("no verification key: fill in the OP's JWKS URL or paste " +
        "the JWK Set");
  }
  if (source === "jwks_url") {
    var response = await fetch(value);
    if (!response.ok) {
      log.debug("Leaving verificationKeyFor(). The JWKS URL failed.");
      throw new Error("the JWKS URL answered HTTP " + response.status);
    }
    log.debug("Leaving verificationKeyFor(). Fetched.");
    return { jwks: await response.json() };
  }
  log.debug("Leaving verificationKeyFor(). Pasted.");
  return { jwks: JSON.parse(value) };
}

// Section 5.3.2's two checks on a SIGNED response, and the reason a signed
// UserInfo response is worth asking for at all: without `iss` and `aud` a
// signed profile of somebody issued for one client is one any other client
// would also believe.
function checkSignedClaims(claims, report) {
  log.debug("Entering checkSignedClaims().");
  var expectedIssuer =
      document.getElementById("userinfo_expected_issuer").value.trim();
  var expectedAudience =
      document.getElementById("userinfo_expected_audience").value.trim();

  if (!claims.iss) {
    reportLine(report, false, "iss", "absent — section 5.3.2 requires it on " +
        "a signed response");
  } else if (!expectedIssuer) {
    reportLine(report, null, "iss", claims.iss +
        " (not checked — no expected issuer given)");
  } else {
    reportLine(report, claims.iss === expectedIssuer, "iss",
      claims.iss === expectedIssuer ? claims.iss
        : claims.iss + " — expected " + expectedIssuer);
  }

  var audience = claims.aud;
  var audienceList = Array.isArray(audience) ? audience
    : (audience === undefined ? [] : [audience]);
  if (!audienceList.length) {
    reportLine(report, false, "aud", "absent — section 5.3.2 requires it on " +
        "a signed response");
  } else if (!expectedAudience) {
    reportLine(report, null, "aud", audienceList.join(", ") +
        " (not checked — no expected audience given)");
  } else {
    reportLine(report, audienceList.indexOf(expectedAudience) !== -1, "aud",
      audienceList.indexOf(expectedAudience) !== -1
        ? audienceList.join(", ")
        : audienceList.join(", ") + " — this client (" + expectedAudience +
          ") is not among them");
  }
  log.debug("Leaving checkSignedClaims().");
}

// Section 5.3.2 again: the `sub` here MUST match the `sub` of the ID Token the
// access token was issued with. A UserInfo response is a statement about a
// subject, and nothing in it says which subject you ASKED about — so a response
// whose sub differs is either a mixed-up token or a server conflating users,
// and neither is visible without this comparison.
function checkSubjectAgainstIdToken(claims, report) {
  log.debug("Entering checkSubjectAgainstIdToken().");
  var idToken = "";
  if (localStorage) {
    idToken = localStorage.getItem("token_id_token") || "";
  }
  if (!idToken || idToken.split(".").length !== 3) {
    reportLine(report, null, "sub", String(claims.sub) +
        " (no ID Token in storage to compare it with)");
    log.debug("Leaving checkSubjectAgainstIdToken(). No id_token.");
    return;
  }
  var payload;
  try {
    payload = JSON.parse(jose.b64uToStr(idToken.split(".")[1]));
  } catch (e) {
    reportLine(report, null, "sub", String(claims.sub) +
        " (the stored ID Token could not be read: " + e.message + ")");
    log.debug("Leaving checkSubjectAgainstIdToken(). Unreadable id_token.");
    return;
  }
  if (!payload.sub) {
    reportLine(report, null, "sub", String(claims.sub) +
        " (the stored ID Token carries no sub)");
    log.debug("Leaving checkSubjectAgainstIdToken(). No sub in the id_token.");
    return;
  }
  reportLine(report, payload.sub === claims.sub, "sub",
    payload.sub === claims.sub
      ? String(claims.sub) + " — matches the ID Token"
      : String(claims.sub) + " — the ID Token says " + payload.sub +
        ", which section 5.3.2 says a client MUST verify");
  log.debug("Leaving checkSubjectAgainstIdToken().");
}

async function decryptResponse(token, report) {
  log.debug("Entering decryptResponse().");
  var key = document.getElementById("userinfo_decryption_key").value.trim();
  var header = jose.parseCompact(token).header;
  reportLine(report, null, "JWE header", "alg=" + header.alg + ", enc=" +
      header.enc + (header.kid ? ", kid=" + header.kid : "") +
      (header.cty ? ", cty=" + header.cty : ""));
  if (!key) {
    log.debug("Leaving decryptResponse(). No key.");
    throw new Error("this response is encrypted (" + header.alg + " / " +
        header.enc + ") and no decryption key was given. Paste the client's " +
        "private key — the one whose public half is in the jwks the client " +
        "registered.");
  }
  var opened = await jose.decryptCompact({ jwe: token, key: key });
  reportLine(report, true, "decrypted", header.alg + " / " + header.enc);
  log.debug("Leaving decryptResponse().");
  // The header goes back with the plaintext so the caller can report a MISSING
  // `cty` — but only once it knows there is a JWS inside to announce. Reporting
  // it here would put "cty absent" on every encrypted-only response, where
  // there is nothing nested and nothing to declare.
  return { plaintext: opened.plaintext.trim(), header: header };
}

async function verifyResponse(token, report) {
  log.debug("Entering verifyResponse().");
  var header;
  try {
    header = JSON.parse(jose.b64uToStr(token.split(".")[0]));
  } catch (e) {
    log.debug("Leaving verifyResponse(). Unreadable header.");
    throw new Error("the JWS protected header is not readable JSON: " +
        e.message);
  }
  reportLine(report, null, "JWS header", "alg=" + header.alg +
      (header.kid ? ", kid=" + header.kid : "") +
      (header.typ ? ", typ=" + header.typ : ""));
  if (header.alg === "none") {
    // RFC 8725 section 3.2. An unsecured JWS here is not a signed response at
    // all, and calling it one would be the worst possible reading.
    reportLine(report, false, "signature", 'alg is "none" — this response is ' +
        "NOT signed, whatever its content type suggests");
    log.debug("Leaving verifyResponse(). Unsecured.");
    return JSON.parse(jose.b64uToStr(token.split(".")[1]));
  }
  var keyInput = await verificationKeyFor(header);
  // No algId: this page reads a token somebody else issued, so the header's
  // `alg` is the only thing to go on — but the KEY is chosen by this page,
  // which is what keeps RFC 8725 section 3.1 satisfied.
  var verdict = await jwsLib.verifyJwsAsync({ jws: token, publicKey: keyInput,
                                              backend: "webcrypto" });
  var first = verdict.signatures[0] || {};
  reportLine(report, verdict.valid, "signature",
    verdict.valid ? header.alg + " verified"
                  : (first.reason || "does not verify"));
  if (!verdict.valid) {
    log.debug("Leaving verifyResponse(). The signature did not verify.");
    throw new Error("the signature did not verify: " +
        (first.reason || "no reason given"));
  }
  log.debug("Leaving verifyResponse().");
  return JSON.parse(verdict.payload);
}

async function openUserinfoResponse(raw, contentType) {
  log.debug("Entering openUserinfoResponse(). contentType=" + contentType);
  var report = [];
  var claims;
  var type = String(contentType || "");
  reportLine(report, null, "content type", type || "(none returned)");

  try {
    if (type.indexOf("application/jwt") !== -1 ||
        (!type && String(raw).trim().split(".").length >= 3)) {
      var token = String(raw).trim();
      var wasEncrypted = false;
      var outerHeader = null;
      if (token.split(".").length === 5) {
        wasEncrypted = true;
        var opened = await decryptResponse(token, report);
        token = opened.plaintext;
        outerHeader = opened.header;
      }
      if (token.split(".").length === 3) {
        if (wasEncrypted && !outerHeader.cty) {
          // There IS a JWS in here and the outer header did not say so. Not
          // fatal — this page found it by counting segments — but a recipient
          // that trusted `cty` would have handed the claims parser a
          // dot-separated string and reported the issuer as broken.
          reportLine(report, false, "cty", 'absent — there is a JWS inside ' +
              'this JWE and RFC 7519 section 5.2 requires cty="JWT" to ' +
              'announce it');
        }
        claims = await verifyResponse(token, report);
      } else {
        claims = JSON.parse(token);
        if (wasEncrypted) {
          // Encrypted and not signed. Worth stating rather than leaving the
          // reader to infer it from the absence of a signature line: this
          // response is confidential and its ORIGIN is unproven.
          reportLine(report, null, "signature", "none — this response was " +
              "encrypted but not signed, so nothing here proves who issued it");
        }
      }
      if (claims && (claims.iss !== undefined || claims.aud !== undefined ||
                     !type.length || token.split(".").length === 3)) {
        checkSignedClaims(claims, report);
      }
    } else {
      reportLine(report, null, "protection", "none — a plain JSON response, " +
          "which is what section 5.3.2 gives a client that registered " +
          "neither userinfo_signed_response_alg nor " +
          "userinfo_encrypted_response_alg");
      claims = typeof raw === "string" ? JSON.parse(raw) : raw;
    }
    if (claims) {
      checkSubjectAgainstIdToken(claims, report);
    }
    $("#userinfo_output").val(JSON.stringify(claims, null, 2));
  } catch (e) {
    log.error("Could not read the UserInfo response: " + e.message);
    reportLine(report, false, "could not be read", e.message);
    $("#userinfo_output").val("");
  }
  $("#userinfo_protection_report").val(report.join("\n"));
  log.debug("Leaving openUserinfoResponse().");
}

function ajaxSuccessFunction(data, textStatus, jqXHR) {
  log.debug("Entering ajaxSuccessFunction().");
  log.debug('UserInfo textStatus: ' + JSON.stringify(textStatus));
  log.debug('UserInfo Response Content-Type: ' +
            jqXHR.getResponseHeader("Content-Type"));
  // `responseText` and NOT `data`: jQuery hands back a parsed object for JSON,
  // and for a JWT the response is a signature over EXACT OCTETS — anything that
  // has been through a parse and a re-serialize is no longer those octets. The
  // raw text is also what the Raw Response pane shows, for the same reason.
  var raw = (jqXHR && typeof jqXHR.responseText === "string")
    ? jqXHR.responseText
    : (typeof data === "string" ? data : JSON.stringify(data));
  lastRawResponse = raw;
  $("#userinfo_raw_response").val(raw);
  // A missing Content-Type is not an error here: a cross-origin response
  // exposes only the CORS-safelisted headers unless the OP says otherwise, so
  // the shape is worked out from the body when the header is withheld.
  var contentType = (jqXHR && jqXHR.getResponseHeader)
    ? (jqXHR.getResponseHeader("Content-Type") || "") : "";
  openUserinfoResponse(raw, contentType);
  log.debug("Leaving ajaxSuccessFunction().");
}

function ajaxErrorFunction(request, status, error) {
  log.debug("Entering ajaxErrorFunction().");
  log.debug("request: " + JSON.stringify(request));
  log.debug("status: " + JSON.stringify(status));
  log.debug("error: " + JSON.stringify(error));
  const errorStatus = {
    request: request,
    status: status,
    error: error
  };
  $("#userinfo_output").val(JSON.stringify(errorStatus,null,2));
  log.debug("Leaving ajaxErrorFunction().");
}

$(".userinfo_endpoint").keypress(function() {
  log.debug("Entering keypress().");
  localStorage.setItem("userinfo_endpoint", userinfo_endpoint);
});

$(".userinfo_method").keypress(function() {
  log.debug("Entering keypress()."); 
  localStorage.setItem("userinfo_method", userinfo_method);
});

$(".userinfo_scope").keypress(function() {
  log.debug("Entering keypress().");
  localStorage.setItem("userinfo_scope", userinfo_scope);
  recalculateUserInfoURL();
});

$(".userinfo_claims").keypress(function() {
  log.debug("Entering keypress().");
  localStorage.setItem("userinfo_claims", userinfo_claims);
  recalculateUserInfoURL(); 
});

$(".token_access_token").keypress(function() {
  log.debug("Entering keypress().");
  localStorage.setItem("token_access_token", token_access_token);
});

function resetUI(value)
{
  log.debug("Entering resetUI().");
  log.debug("Leaving resetUI().");
}

function resetErrorDisplays()
{
  log.debug("Entering resetErrorDisplays().");
  log.debug("Leaving resetErrorDisplays().");
}

function writeValuesToLocalStorage()
{
  log.debug("Entering writeValuesToLocalStorage().");
  if (localStorage) {
    localStorage.setItem("userinfo_endpoint", userinfo_endpoint);
    localStorage.setItem("userinfo_method", userinfo_method);
    localStorage.setItem("userinfo_scope", userinfo_scope);
    localStorage.setItem("userinfo_claims", userinfo_claims);
    localStorage.setItem("token_access_token", token_access_token);
    // The section 5.3.2 settings. NOTE WHAT IS NOT HERE and read the comment
    // in loadValuesFromLocalStorage() before adding to this list: neither the
    // decryption key nor the client secret is written anywhere, ever.
    storeField("userinfo_jwks_source");
    storeField("userinfo_jwks");
    storeField("userinfo_expected_issuer");
    storeField("userinfo_expected_audience");
  }
  log.debug("Leaving writeValuesToLocalStorage().");
}

function storeField(id)
{
  log.debug("Entering storeField(). id=" + id);
  var element = document.getElementById(id);
  if (element) {
    localStorage.setItem(id, element.value);
  }
  log.debug("Leaving storeField().");
}

// Fill a field from storage, preferring a value this page saved and falling
// back to whatever the OAuth2 / OIDC workflow already knows — the JWKS
// endpoint, the issuer and the client id are all sitting in storage from the
// metadata load, and asking somebody to retype them here would be asking them
// to retype something the tool has.
function fillField(id, ownKey, fallbackKey)
{
  log.debug("Entering fillField(). id=" + id);
  var element = document.getElementById(id);
  if (!element) {
    log.debug("Leaving fillField(). No such element.");
    return;
  }
  var value = localStorage.getItem(ownKey);
  if (!value && fallbackKey) {
    value = localStorage.getItem(fallbackKey);
  }
  if (value) {
    element.value = value;
  }
  log.debug("Leaving fillField().");
}

function initLocalStorage()
{
  log.debug("Entering initLocalStorage().");
  if(localStorage && !initialized) {
    localStorage.setItem("userinfo_method", "GET");
    localStorage.setItem("userinfo_scope", "profile email address phone");
    var default_claims = {
     "userinfo":
      {
       "given_name": {"essential": true},
       "nickname": null,
       "email": {"essential": true},
       "email_verified": {"essential": true},
       "picture": null,
       "http://example.info/claims/groups": null
      },
     "id_token":
      {
       "auth_time": {"essential": true},
       "acr": {"values": ["urn:mace:incommon:iap:silver"] }
      }
    };
    localStorage.setItem("userinfo_claims", JSON.stringify(default_claims, null,
                         2));
    initialized = true;
  }
  log.debug("Leaving initLocalStorage().");
}

function loadValuesFromLocalStorage()
{
  log.debug("Entering loadValuesFromLocalStorage().");
  if(localStorage) {
    userinfo_endpoint = localStorage.getItem("oidc_userinfo_endpoint");
    userinfo_method = localStorage.getItem("userinfo_method");
    userinfo_scope = localStorage.getItem("userinfo_scope");
    userinfo_claims = localStorage.getItem("userinfo_claims");
    var type = getParameterByName('type');
    if (type === 'history_access') {
      var generation = parseInt(getParameterByName('generation'), 10);
      var history = [];
      try {
        history = JSON.parse(localStorage.getItem('token_history') || '[]');
      } catch (e) {
        log.error('Failed to parse token_history: ' + e);
      }
      if (!isNaN(generation) && generation >= 0 &&
          generation < history.length) {
        token_access_token = history[generation].access_token || '';
      } else {
        log.error('Invalid generation index: ' + generation);
        token_access_token = '';
      }
    } else if (type === 'refresh_access_token') {
      token_access_token = localStorage.getItem('refresh_access_token');
    } else {
      token_access_token = localStorage.getItem("token_access_token");
    }
  }
  // Set configuration fields
  document.getElementById("userinfo_endpoint").value = userinfo_endpoint;
  document.getElementById("userinfo_method").value = userinfo_method;
  document.getElementById("userinfo_scope").value = userinfo_scope;
  document.getElementById("userinfo_claims").value = userinfo_claims;
  document.getElementById("token_access_token").value = token_access_token;

  // The section 5.3.2 settings, prefilled from what the OAuth2 / OIDC workflow
  // already loaded rather than asked for again.
  //
  // TWO OF THESE FIELDS ARE DELIBERATELY NOT PERSISTED AND MUST NOT BECOME SO.
  // `userinfo_decryption_key` is the CLIENT'S PRIVATE KEY and
  // `userinfo_client_secret` is a credential; this page generates neither and
  // has no next screen to carry either to, so there is nothing to be gained by
  // keeping them and a private key in localStorage to be lost. That is the same
  // decision the SAML request and response decoders made for the same reason —
  // a page that only READS may take a key and must not keep it. The key-pair
  // opt-out described in the repo-root CLAUDE.md is for pages that GENERATE a
  // pair and need it on a later screen; this is not one.
  fillField("userinfo_jwks_source", "userinfo_jwks_source", null);
  fillField("userinfo_jwks", "userinfo_jwks", "jwks_endpoint");
  fillField("userinfo_expected_issuer", "userinfo_expected_issuer", "issuer");
  fillField("userinfo_expected_audience", "userinfo_expected_audience",
            "client_id");
  log.debug("Leaving loadValuesFromLocalStorage().");
}

function regenerateState() {
  log.debug("Entering regenerateState().");
  document.getElementById("state").value = generateUUID();
  localStorage.setItem('state', document.getElementById("state").value);
  log.debug("Leaving regenerateState().");
}

function onClickToggleConfigurationParameters() {
  log.debug("Entering onClickToggleConfigurationParameters().");
  if(document.getElementById("config_fieldset").style.display == 'block') {
    document.getElementById('config_fieldset').style.display = 'none'
  } else {
    document.getElementById('config_fieldset').style.display = 'block'
  }
  log.debug("Leaving onClickToggleConfigurationParameters().");
}

function setInitiateFromEnd(which_end) {
  log.debug("Entering setInitiateFromEnd(). which_end=" + which_end);
  var frontEndInitiated = $("#userinfo_initiateFromFrontEnd").is(":checked");
  var backEndInitiated = $("#userinfo_initiateFromBackEnd").is(":checked");
  log.debug("typeof(frontEndInitiated): " + typeof(frontEndInitiated));
  if(frontEndInitiated) {
    useFrontEnd = true;
  } else {
    useFrontEnd = false;
  }
  log.debug("frontEndInitiated: " + frontEndInitiated);
  log.debug("backEndInitiated: " + backEndInitiated);
  log.debug("Leaving setInitiateFromEnd().");
}

function getLSBooleanItem(key)
{
  log.debug("Entering getLSBooleanItem().");
  log.debug("Leaving getLSBooleanItem().");
  return localStorage.getItem(key) === 'true';
}

function clickLink() {
  log.debug("Entering clickLink().");
  writeValuesToLocalStorage();
  log.debug("Leaving clickLink().");
  return true;
}

module.exports = {
  getParameterByName,
  callUserInfoEndpoint,
  openUserinfoResponse,
  onClickToggleConfigurationParameters,
  setInitiateFromEnd,
  clickLink
};
