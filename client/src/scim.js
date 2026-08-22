// File: scim.js
//
// ---------------------------------------------------------------------------
// THE SCIM 2.0 PAGE — a provisioning debugger and a test harness in one.
//
// SCIM (RFC 7642, 7643, 7644) is the sixteenth protocol family here and the
// first one whose whole purpose is to WRITE. Every other workflow in this
// debugger asks a question about somebody who is already there — issue this
// person a token, tell me who signed in, seal this ticket. These endpoints
// CREATE and DELETE accounts, which is why this page is shaped differently from
// the rest of the tree: a single call is rarely the interesting thing, and what
// somebody actually needs to know is what happens when a hundred of them run in
// order against a real directory.
//
// So the page has two halves and they share everything below them:
//
//   * **one endpoint at a time**, which is the ordinary debugger — pick an
//     operation, see the request that will be sent, send it, read what came
//     back;
//   * **scenarios**, which are named plans of many operations with an
//     expectation on every step. `scim_scenarios.js` builds them and this file
//     runs them.
//
// ---------------------------------------------------------------------------
// THIS FILE IS THE DOM AND THE TRANSPORT. IT BUILDS NO REQUESTS AND JUDGES NO
// ANSWERS.
//
// `scim_client.js` composes every request and reads every response;
// `scim_scenarios.js` plans and judges. Both have no DOM, which is what lets
// `tests/scim_engine.js` drive the whole of the interesting logic in node with
// no browser, no server and no page. What is left here — and it is genuinely
// all that is left — is reading fields, drawing results, and the two ways a
// request can be sent.
//
// The temptation when adding an endpoint is to build its body in the click
// handler. Do not: a PATCH whose path grammar is wrong and a PATCH the button
// never sent both present as "nothing changed", and only one of those is
// findable from a test.
//
// ---------------------------------------------------------------------------
// TWO CALL PATHS, AND UNLIKE LDAP AND KERBEROS THE BROWSER ONE IS REAL.
//
// SCIM is ordinary HTTPS with a JSON body, so this page can call a SCIM server
// directly — which is what makes it work on the static deployments, where there
// is no api at all. That is the difference between this workflow and the three
// that are greyed out there.
//
// The api path exists for the three things a browser cannot do, and the page
// says which is which rather than presenting one as a fallback for the other:
//
//   * **CORS.** Essentially no real SCIM endpoint sends
//     `Access-Control-Allow-Origin`, and a browser refuses the request before
//     it is made. The only error JavaScript can see is `TypeError: Failed to
//     fetch`, which is the SAME message a browser gives for a dead host, a DNS
//     failure and a rejected certificate — so `explainBrowserFailure()` below
//     spells out all four possibilities rather than guessing at one.
//   * **A self-signed certificate**, which a browser refuses and a staging
//     server always has.
//   * **The exchange itself.** A browser withholds the headers it adds and CORS
//     withholds most of those that come back, so a browser-direct call can only
//     ever be reported in part — and the Exchange pane says so, rather than
//     presenting a partial list as a whole one. That is the same rule the
//     OAuth2 token pane already follows.
//
// **Two schemes are browser-only and it is not a limitation of this page.** A
// session cookie is attached by the browser and the api has no cookie jar; a
// TLS client certificate is chosen during the handshake by whatever holds the
// key. Selecting either turns the backend radio off with a reason on screen.
//
// ---------------------------------------------------------------------------
// WHAT IS REMEMBERED AND WHAT IS NOT.
//
// Every field is written to `localStorage` except the credentials, which follow
// the project-wide rule in the repo-root CLAUDE.md. Two of them are treated
// differently from each other on purpose:
//
//   * **A password is NEVER stored.** Same as the LDAP page, no opt-in, no
//     checkbox. There is no case where keeping one here is worth it.
//   * **An access token is stored only if `scim_save_token` is ticked, and it
//     ships CLEAR.** It is an opt-IN rather than the key-pair panes' opt-OUT
//     because the trade is different: a SAML SP key is needed on a later page
//     to decrypt an assertion and re-pasting it is real friction, while a
//     bearer token is pasted once and expires anyway. Clearing the box PURGES
//     what was already written, on the spot and from `saveState()` rather than
//     only from the change handler — an opt-out that leaves yesterday's token
//     in storage is not an opt-out. That purge also runs on load, so arriving
//     with the box already clear cleans up.
//
// The HOBA private key is never stored at all, under any setting: it is
// generated per session and the page says so, because a signing key in
// `localStorage` is a signing key in every extension's reach.
// ---------------------------------------------------------------------------

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var scimClient = require("./scim_client");
var scenarios = require("./scim_scenarios");
var dpop = require("./dpop");
var history = require("./scim_history");

var log = bunyan.createLogger({ name: 'scim', level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());

var API_URL = appconfig.apiUrl || '';
var BACKEND_AVAILABLE = appconfig.backendAvailable !== false;

// Fields written to localStorage. The credentials are NOT here — see the
// header; `scim_auth_token` is added conditionally by saveState().
var REMEMBERED = [
  'scim_base_url', 'scim_ssl_validate',
  'scim_auth_scheme', 'scim_auth_username', 'scim_auth_realm',
  'scim_hoba_username',
  'scim_op', 'scim_op_id', 'scim_op_body',
  'scim_query_filter', 'scim_query_sort_by', 'scim_query_sort_order',
  'scim_query_start_index', 'scim_query_count', 'scim_query_attributes',
  'scim_query_excluded_attributes',
  'scim_gen_seed', 'scim_gen_prefix', 'scim_gen_count', 'scim_gen_domain',
  'scim_scenario', 'scim_scenario_seed', 'scim_scenario_prefix',
  'scim_scenario_count',
  'scim_last_user_id', 'scim_last_group_id'
];

// The credential fields, listed once so that the purge and the "never save"
// rule cannot disagree about which is which.
var TOKEN_FIELD = 'scim_auth_token';
var NEVER_STORED = ['scim_auth_password'];

// --- tiny DOM helpers ------------------------------------------------------
//
// One-liners called on every field read and every render, and they deliberately
// carry NO entering/leaving log lines. That is the hot-path exception the
// repo-root CLAUDE.md describes and the one saml_tools.js earned the hard way:
// a log pair in a one-line accessor is not a trace, it is the entire log, and
// at logLevel debug it took that page's in-browser sweep past the WebDriver
// script timeout. The functions that CALL these keep their logging.
function el(id) { return document.getElementById(id); }
function val(id) { var e = el(id); return e ? String(e.value || '') : ''; }
function setVal(id, v) { var e = el(id); if (e) e.value = v == null ? '' : v; }
function isOn(id) { var e = el(id); return !!(e && e.checked); }
function setText(id, v) {
  var e = el(id);
  if (e) e.textContent = v == null ? '' : String(v);
}
function show(id, on) {
  var e = el(id);
  if (!e) { return; }
  e.style.display = on ? '' : 'none';
  // The class as well as the inline style, for the reason pki.js records: an
  // element hidden by a class in the markup stays hidden however the inline
  // style is set, and for as long as that was true the banner was asked for and
  // never appeared.
  if (on) {
    e.classList.remove('scim-hidden');
  } else {
    e.classList.add('scim-hidden');
  }
}

function statusOk(id, message) {
  log.debug("Entering statusOk(). id=" + id);
  var e = el(id);
  if (e) {
    e.value = message;
    e.className = 'scim-status scim-grow scim-ok';
  }
  log.debug("Leaving statusOk().");
}

function statusBad(id, message) {
  log.debug("Entering statusBad(). id=" + id);
  var e = el(id);
  if (e) {
    e.value = message;
    e.className = 'scim-status scim-grow scim-bad';
  }
  log.debug("Leaving statusBad().");
}

function statusBusy(id, message) {
  log.debug("Entering statusBusy(). id=" + id);
  var e = el(id);
  if (e) {
    e.value = message;
    e.className = 'scim-status scim-grow scim-pending';
  }
  log.debug("Leaving statusBusy().");
}

// Pretty JSON into a <pre>, as TEXT.
//
// textContent and never innerHTML: a SCIM response body is somebody else's
// bytes, and concatenating those into markup is the js/xss-through-dom defect
// the OAuth2 token pane already carries a long comment about. There is nothing
// to sanitise here because nothing is ever parsed as HTML.
function setJson(id, value) {
  log.debug("Entering setJson(). id=" + id);
  var e = el(id);
  if (!e) {
    log.debug("Leaving setJson(). No such element.");
    return;
  }
  if (value === null || value === undefined) {
    e.textContent = '';
    log.debug("Leaving setJson(). Empty.");
    return;
  }
  if (typeof value === 'string') {
    e.textContent = value;
    log.debug("Leaving setJson(). A string.");
    return;
  }
  try {
    e.textContent = JSON.stringify(value, null, 2);
  } catch (err) {
    // A cycle, which a parsed JSON body cannot have — but a value built here
    // could, and a page that threw while rendering would lose the answer as
    // well as the render.
    e.textContent = '(this value could not be rendered: ' + err.message + ')';
  }
  log.debug("Leaving setJson().");
}

// --- state -----------------------------------------------------------------
function saveState() {
  log.debug("Entering saveState().");
  try {
    REMEMBERED.forEach(function (id) {
      var e = el(id);
      if (!e) {
        return;
      }
      var value = (e.type === 'checkbox') ? (e.checked ? '1' : '0')
        : String(e.value || '');
      localStorage.setItem(id, value);
    });
    // THE PURGE LIVES HERE and not only in the checkbox's change handler, so
    // that no code path can leave a token behind. See the header.
    if (isOn('scim_save_token')) {
      localStorage.setItem('scim_save_token', '1');
      localStorage.setItem(TOKEN_FIELD, val(TOKEN_FIELD));
    } else {
      localStorage.setItem('scim_save_token', '0');
      localStorage.removeItem(TOKEN_FIELD);
    }
    NEVER_STORED.forEach(function (id) {
      localStorage.removeItem(id);
    });
  } catch (e) {
    // No storage in this context (a private window, or storage disabled). The
    // page works without it; only the remembering is lost.
    log.warn('could not write to localStorage: ' + e.message);
  }
  log.debug("Leaving saveState().");
}

function loadState() {
  log.debug("Entering loadState().");
  var defaults = {
    scim_base_url: appconfig.scimBaseUrlDefault || '',
    scim_ssl_validate: 'true',
    scim_auth_scheme: 'none',
    scim_auth_username: 'alice',
    scim_auth_realm: 'SCIM',
    scim_hoba_username: 'alice',
    scim_op: 'serviceProviderConfig',
    scim_query_count: '25',
    scim_query_start_index: '1',
    scim_gen_seed: 'seed-1',
    scim_gen_prefix: 'scim',
    scim_gen_count: '5',
    scim_gen_domain: 'example.com',
    scim_scenario: 'discovery',
    scim_scenario_seed: 'seed-1',
    scim_scenario_prefix: 'scim',
    scim_scenario_count: '5'
  };
  try {
    REMEMBERED.forEach(function (id) {
      var stored = localStorage.getItem(id);
      var e = el(id);
      if (!e) {
        return;
      }
      var value = stored === null ? (defaults[id] === undefined ? ''
        : defaults[id]) : stored;
      if (e.type === 'checkbox') {
        e.checked = (value === '1' || value === 'true');
        return;
      }
      e.value = value;
    });
    var saveToken = localStorage.getItem('scim_save_token');
    var box = el('scim_save_token');
    if (box) {
      // Absent means NOT saving. This is the opposite default from the
      // key-pair panes and is deliberate — see the header.
      box.checked = saveToken === '1';
    }
    if (saveToken === '1') {
      setVal(TOKEN_FIELD, localStorage.getItem(TOKEN_FIELD) || '');
    } else {
      // The load-time half of the purge: arriving with the box already clear
      // cleans up whatever an earlier session wrote.
      localStorage.removeItem(TOKEN_FIELD);
    }
    NEVER_STORED.forEach(function (id) {
      localStorage.removeItem(id);
    });
  } catch (e) {
    log.warn('could not read localStorage: ' + e.message);
  }
  log.debug("Leaving loadState().");
}

// ---------------------------------------------------------------------------
// WHICH WAY THE CALL GOES.
//
// The radio, plus the two schemes that force the browser. A page that let
// somebody select "through the api" with a cookie scheme would send a request
// with no cookie and report a 401 as the server's fault.
// ---------------------------------------------------------------------------
function callVia() {
  log.debug("Entering callVia().");
  var scheme = scimClient.authScheme(val('scim_auth_scheme'));
  if (scheme && scheme.backend === false) {
    log.debug("Leaving callVia(). Forced to the browser by the scheme.");
    return 'browser';
  }
  if (!BACKEND_AVAILABLE) {
    log.debug("Leaving callVia(). No api on this deployment.");
    return 'browser';
  }
  var via = isOn('scim_call_backend') ? 'api' : 'browser';
  log.debug("Leaving callVia(). " + via);
  return via;
}

function refreshCallPathControls() {
  log.debug("Entering refreshCallPathControls().");
  var scheme = scimClient.authScheme(val('scim_auth_scheme'));
  var backendRadio = el('scim_call_backend');
  var browserRadio = el('scim_call_browser');
  var reason = '';
  if (!BACKEND_AVAILABLE) {
    reason = 'This build has no api behind it, so every call is made by this ' +
        'browser. That is what makes this page work on the hosted site — ' +
        'and it means a SCIM server that sends no CORS headers cannot be ' +
        'reached from here. Run the debugger locally for those.';
  } else if (scheme && scheme.backend === false) {
    reason = 'The ' + scheme.label + ' scheme is browser-only: ' +
        scheme.what.split('.')[0] + '. The call path is fixed to this ' +
        'browser while it is selected.';
  }
  if (backendRadio) {
    backendRadio.disabled = !!reason;
    if (reason) {
      backendRadio.checked = false;
      if (browserRadio) {
        browserRadio.checked = true;
      }
    }
  }
  setText('scim_call_path_note', reason);
  show('scim_call_path_note', !!reason);
  log.debug("Leaving refreshCallPathControls().");
}

// ---------------------------------------------------------------------------
// THE AUTHENTICATION STATE, assembled per request.
//
// Two of the seven schemes cannot be composed from the fields alone: DPoP needs
// a proof JWT signed over THIS method and URL, and HOBA needs a signature over
// a blob carrying a challenge the SERVER issued. Both are asynchronous, so this
// returns a promise and every send goes through it — including the ones using a
// scheme that needs nothing, so there is one path rather than two.
// ---------------------------------------------------------------------------
var dpopKey = null;      // { alg, publicJwk, privateJwk } for this session.
var hobaKey = null;      // { kid, publicPem, privateKey } for this session.
var lastChallenges = []; // The WWW-Authenticate challenges from the last 401.

function authStateFor(request) {
  log.debug("Entering authStateFor(). scheme=" + val('scim_auth_scheme'));
  var id = val('scim_auth_scheme') || 'none';
  var state = { scheme: id };
  if (id === 'bearer') {
    state.token = val(TOKEN_FIELD);
    log.debug("Leaving authStateFor(). Bearer.");
    return Promise.resolve(state);
  }
  if (id === 'basic') {
    state.username = val('scim_auth_username');
    state.password = val('scim_auth_password');
    log.debug("Leaving authStateFor(). Basic.");
    return Promise.resolve(state);
  }
  if (id === 'dpop') {
    state.token = val(TOKEN_FIELD);
    log.debug("Leaving authStateFor(). DPoP, minting a proof.");
    return mintDpopProof(request, state.token).then(function (proof) {
      state.proof = proof;
      return state;
    });
  }
  if (id === 'digest') {
    // The first leg carries nothing; the 401 it provokes carries the nonce.
    // `sendOnce()` retries with `state.digest` filled in, which is the whole of
    // the RFC 7616 handshake and is deliberately visible on the page rather
    // than hidden inside a library.
    log.debug("Leaving authStateFor(). Digest, first leg.");
    return Promise.resolve(state);
  }
  if (id === 'hoba') {
    log.debug("Leaving authStateFor(). HOBA, signing.");
    return signHoba(request).then(function (signed) {
      state.hoba = signed;
      return state;
    });
  }
  // cookie, clientcert and none all add nothing.
  log.debug("Leaving authStateFor(). Nothing to add.");
  return Promise.resolve(state);
}

function mintDpopProof(request, token) {
  log.debug("Entering mintDpopProof().");
  var ready = dpopKey ? Promise.resolve(dpopKey)
    : dpop.generateKeyPair().then(function (pair) {
        dpopKey = pair;
        setText('scim_dpop_thumbprint', 'a fresh ' + pair.alg +
            ' key was generated for this session');
        return pair;
      });
  log.debug("Leaving mintDpopProof().");
  return ready.then(function (key) {
    return dpop.proof({
      key: key,
      htm: request.method,
      htu: request.url,
      accessToken: token || null,
      nonce: lastDpopNonce
    });
  }).then(function (made) {
    setJson('scim_dpop_proof', { header: made.header, payload: made.payload });
    return made.proof;
  }).catch(function (error) {
    // A proof that could not be minted is reported and the request is sent
    // WITHOUT one, so that the server's own refusal is what appears rather
    // than a silence from this page. The note in applyAuth() says which
    // happened.
    log.warn('could not mint a DPoP proof: ' + error.message);
    setText('scim_dpop_thumbprint', 'the proof could not be minted: ' +
        error.message);
    return '';
  });
}

var lastDpopNonce = '';

// RFC 7486 needs an RSA key: algorithm "0" is RSA-SHA256 and there is no
// registered elliptic-curve one, so an ECDSA key would produce a signature the
// scheme has no identifier for. RSASSA-PKCS1-v1_5 with SHA-256 is what `0`
// names, which is `crypto.verify('sha256', ...)` on the other side.
function generateHobaKey() {
  log.debug("Entering generateHobaKey().");
  statusBusy('scim_hoba_status', 'Generating an RSA key…');
  return crypto.subtle.generateKey({
    name: 'RSASSA-PKCS1-v1_5',
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-256'
  }, true, ['sign', 'verify']).then(function (pair) {
    return crypto.subtle.exportKey('spki', pair.publicKey)
      .then(function (spki) {
        hobaKey = {
          // The key id is the client's to choose and the server stores the key
          // under it. A random one per session keeps two browsers from
          // overwriting each other's registration on a shared mock.
          kid: 'scimpage-' + Math.floor(Math.random() * 1e9).toString(36),
          privateKey: pair.privateKey,
          publicPem: pemFromSpki(spki)
        };
        setVal('scim_hoba_kid', hobaKey.kid);
        setJson('scim_hoba_public_key', hobaKey.publicPem);
        statusOk('scim_hoba_status', 'A 2048-bit RSA key was generated. It ' +
            'lives in this page only — it is never written to localStorage — ' +
            'so it is gone when this tab is closed. Register it below before ' +
            'using the HOBA scheme.');
        log.debug("Leaving generateHobaKey(). kid=" + hobaKey.kid);
        return hobaKey;
      });
  }).catch(function (error) {
    statusBad('scim_hoba_status', 'The key could not be generated: ' +
        error.message + '. Web Crypto needs a secure context — https, or ' +
        'localhost.');
    log.debug("Leaving generateHobaKey(). Failed.");
    throw error;
  });
}

function pemFromSpki(buffer) {
  log.debug("Entering pemFromSpki().");
  var bytes = new Uint8Array(buffer);
  var binary = '';
  var i;
  for (i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  var base64 = btoa(binary);
  var lines = [];
  for (i = 0; i < base64.length; i += 64) {
    lines.push(base64.slice(i, i + 64));
  }
  var pem = '-----BEGIN PUBLIC KEY-----\n' + lines.join('\n') +
      '\n-----END PUBLIC KEY-----\n';
  log.debug("Leaving pemFromSpki(). " + pem.length + " characters.");
  return pem;
}

function base64UrlFromBytes(buffer) {
  log.debug("Entering base64UrlFromBytes().");
  var bytes = new Uint8Array(buffer);
  var binary = '';
  var i;
  for (i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  var out = btoa(binary).split('+').join('-').split('/').join('_')
    .split('=').join('');
  log.debug("Leaving base64UrlFromBytes(). " + out.length + " characters.");
  return out;
}

// Register the generated public key with the server. RFC 7486 section 7 puts
// this at a well-known path on the SERVER'S ORIGIN — not under the SCIM base
// path — and this project's mock takes it form-encoded.
function registerHobaKey() {
  log.debug("Entering registerHobaKey().");
  var ready = hobaKey ? Promise.resolve(hobaKey) : generateHobaKey();
  ready.then(function (key) {
    var origin = scimClient.originOf(val('scim_base_url'));
    // originOf() always spells the port, which is right for the SIGNED blob and
    // wrong for a URL — a fetch of https://host:443/ is a different origin
    // string from https://host/ to some servers' virtual hosting. So the
    // registration URL is built from the base URL's own prefix instead.
    var match = String(val('scim_base_url')).match(/^(https?:\/\/[^/]+)/i);
    var registrationUrl = (match ? match[1] : origin) +
        scimClient.HOBA_REGISTRATION_PATH;
    statusBusy('scim_hoba_status', 'Registering the key at ' +
        registrationUrl + '…');
    var body = 'pub=' + encodeURIComponent(key.publicPem) +
        '&username=' + encodeURIComponent(val('scim_hoba_username')) +
        '&kid=' + encodeURIComponent(key.kid);
    return fetch(registrationUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body
    }).then(function (response) {
      return response.text().then(function (text) {
        if (response.status >= 200 && response.status < 300) {
          statusOk('scim_hoba_status', 'Registered under key id ' + key.kid +
              ' for ' + val('scim_hoba_username') + '. HOBA calls will now ' +
              'sign with it.');
        } else {
          statusBad('scim_hoba_status', 'The registration was refused: ' +
              response.status + ' ' + text.slice(0, 300));
        }
        setJson('scim_hoba_registration', text.slice(0, 2000));
        log.debug("Leaving registerHobaKey(). status=" + response.status);
      });
    });
  }).catch(function (error) {
    statusBad('scim_hoba_status', 'The registration call failed: ' +
        error.message + '. ' + explainBrowserFailure());
    log.debug("Leaving registerHobaKey(). The call failed.");
  });
}

// The signature itself. The challenge comes from the server's own
// WWW-Authenticate header, which means a HOBA call is a two-leg exchange like
// Digest: probe, read the challenge, sign, send.
function signHoba(request) {
  log.debug("Entering signHoba().");
  if (!hobaKey) {
    log.debug("Leaving signHoba(). No key has been generated.");
    return Promise.resolve(null);
  }
  var challenge = challengeParam('hoba', 'challenge');
  if (!challenge) {
    log.debug("Leaving signHoba(). No challenge has been collected.");
    return Promise.resolve(null);
  }
  var nonce = Math.floor(Math.random() * 1e12).toString(36) +
      Math.floor(Math.random() * 1e12).toString(36);
  var realm = challengeParam('hoba', 'realm') || val('scim_auth_realm') ||
      'SCIM';
  var tbs = scimClient.hobaToBeSigned({
    nonce: nonce,
    alg: scimClient.HOBA_ALG_RSA_SHA256,
    origin: scimClient.originOf(val('scim_base_url')),
    realm: realm,
    kid: hobaKey.kid,
    challenge: challenge
  });
  setText('scim_hoba_tbs', tbs);
  log.debug("Leaving signHoba(). Signing " + tbs.length + " characters.");
  return crypto.subtle.sign('RSASSA-PKCS1-v1_5', hobaKey.privateKey,
      new TextEncoder().encode(tbs))
    .then(function (signature) {
      return {
        kid: hobaKey.kid,
        challenge: challenge,
        nonce: nonce,
        signature: base64UrlFromBytes(signature)
      };
    })
    .catch(function (error) {
      log.warn('the HOBA signature failed: ' + error.message);
      return null;
    });
}

// ---------------------------------------------------------------------------
// The cookie scheme's one affordance.
//
// There is nothing to compose and nothing to send, so the only thing that can
// be wrong is whether a session exists at all — and a session is made by
// signing in at the SERVER, not here. This opens the server's own origin in a
// new tab so that can happen; it deliberately does not guess at a sign-in path,
// because a service's login screen is usually reached through a protocol flow
// (an authorization request, a WS-Federation wsignin1.0) rather than at a URL a
// client can name, and a button that opened a 404 would be worse than one that
// opened the front door.
//
// `scimSignInUrlDefault` overrides it for a deployment that does have a URL
// worth naming.
// ---------------------------------------------------------------------------
function openSignIn() {
  log.debug("Entering openSignIn().");
  var configured = appconfig.scimSignInUrlDefault || '';
  var match = String(val('scim_base_url')).match(/^(https?:\/\/[^/]+)/i);
  var target = configured || (match ? match[1] + '/' : '');
  if (target === '') {
    statusBad('scim_auth_status', 'The service root is not an absolute URL, ' +
        'so there is no origin to open.');
    log.debug("Leaving openSignIn(). No origin.");
    return;
  }
  // noopener, because the opened page would otherwise get a handle to this
  // one through window.opener and this page holds credentials in its fields.
  window.open(target, '_blank', 'noopener');
  statusOk('scim_auth_status', 'Opened ' + target + ' in a new tab. Sign in ' +
      'there through any workflow that uses that server\'s login screen, ' +
      'then come back and send something — the browser will attach the ' +
      'session cookie by itself.');
  log.debug("Leaving openSignIn(). " + target);
}

function challengeParam(scheme, name) {
  log.debug("Entering challengeParam(). " + scheme + "." + name);
  var found = '';
  lastChallenges.forEach(function (row) {
    if (String(row.scheme).toLowerCase() === String(scheme).toLowerCase() &&
        row.params[name] !== undefined) {
      found = row.params[name];
    }
  });
  log.debug("Leaving challengeParam(). " + (found ? 'found' : 'not found'));
  return found;
}

// ---------------------------------------------------------------------------
// DIGEST, which is a handshake and is shown as one.
//
// The arithmetic is in `scim_client.js` — all three RFC 7616 algorithms and
// their `-sess` variants, none of them Web Crypto — so what is left here is the
// two things that are genuinely the PAGE's: which nonce we are on, and the
// nonce count.
//
// **THE NONCE COUNT MUST INCREASE, AND GETTING THIS WRONG COSTS EXACTLY ONE
// REQUEST.** `nc` is what makes a Digest credential single-use: a server that
// tracks it — this project's mock does — refuses a repeat as a REPLAY, and
// refuses it *without* `stale=true`, because stale means "your credential was
// fine, try again" and a replay is the opposite claim. So a client that
// hardcodes `00000001` authenticates once per nonce and then fails, in a way
// that reads as expired credentials rather than as a counter. That matters far
// more here than on a page that makes one call: a scenario run makes a hundred
// and fifty.
//
// The counter is keyed BY NONCE rather than being a single number, because the
// server issues a fresh nonce whenever the old one goes stale and the count
// starts again at 1 for each.
// ---------------------------------------------------------------------------
var digestCounts = {};

function nextNonceCount(nonce) {
  log.debug("Entering nextNonceCount().");
  var key = String(nonce || '');
  digestCounts[key] = (digestCounts[key] || 0) + 1;
  // RFC 7616 section 3.4: eight hexadecimal digits, lower case, zero-padded.
  var text = ('00000000' + digestCounts[key].toString(16)).slice(-8);
  log.debug("Leaving nextNonceCount(). nc=" + text);
  return text;
}

function digestFieldsFor(request) {
  log.debug("Entering digestFieldsFor().");
  var chosen = scimClient.chooseDigestChallenge(lastChallenges);
  if (!chosen) {
    log.debug("Leaving digestFieldsFor(). No Digest challenge.");
    return { missing: true };
  }
  if (chosen.unsupported) {
    log.debug("Leaving digestFieldsFor(). Unsupported: " +
        chosen.unsupported.join(', '));
    return { unsupported: chosen.unsupported };
  }
  var params = chosen.challenge.params;
  var fields = scimClient.digestCredential({
    params: params,
    algorithm: chosen.algorithm,
    realm: params.realm || val('scim_auth_realm'),
    username: val('scim_auth_username'),
    password: val('scim_auth_password'),
    method: request.method,
    // The request-target — path and query, not the absolute URL. It is hashed
    // into A2 and compared by the server against what actually arrived.
    uri: requestTarget(request.url),
    nc: nextNonceCount(params.nonce),
    cnonce: Math.floor(Math.random() * 1e16).toString(36) +
        Math.floor(Math.random() * 1e16).toString(36)
  });
  setText('scim_digest_chosen', 'Answering the ' + fields.algorithm +
      ' challenge with nc=' + fields.nc + '. The server offered ' +
      scimClient.challengesFor(lastChallenges, 'digest').length +
      ' Digest challenge(s); this build can compute ' +
      scimClient.DIGEST_ALGORITHMS.map(function (row) {
        return row.token;
      }).join(', ') + ' and picks the strongest on offer.');
  log.debug("Leaving digestFieldsFor(). " + fields.algorithm);
  return fields;
}

function requestTarget(url) {
  log.debug("Entering requestTarget().");
  var match = String(url || '')
    .match(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^/]*(.*)$/);
  var target = match ? (match[1] || '/') : String(url || '/');
  log.debug("Leaving requestTarget(). " + target);
  return target;
}

// ---------------------------------------------------------------------------
// SENDING.
//
// `send()` is the whole transport and it is one function so that the endpoint
// pane and the scenario runner cannot come to disagree about what a call is. It
// handles the two challenge-response schemes by sending twice — which is what
// they are — and records the exchange either way.
// ---------------------------------------------------------------------------
function send(request) {
  log.debug("Entering send(). " + request.method + " " + request.url);
  return authStateFor(request).then(function (auth) {
    return sendOnce(request, auth).then(function (first) {
      var needsSecondLeg = first.status === 401 &&
          (auth.scheme === 'digest' || auth.scheme === 'hoba');
      if (!needsSecondLeg) {
        log.debug("Leaving send(). One leg, status=" + first.status);
        return first;
      }
      // The 401 carried the challenge. Collect it, build the credential and
      // send again — and keep BOTH legs, because the handshake is the
      // interesting part of these two schemes and a library normally hides it.
      lastChallenges = scimClient.parseChallenges(
        scenarios.headerValue(first.headers, 'www-authenticate'));
      renderChallenges();
      if (auth.scheme === 'digest') {
        var fields = digestFieldsFor(request);
        if (fields.missing) {
          first.pageNote = 'The server answered 401 but offered no Digest ' +
              'challenge, so there is no nonce to compute a credential over. ' +
              'The challenges it did offer are in the Authentication pane.';
          log.debug("Leaving send(). No Digest challenge offered.");
          return first;
        }
        if (fields.unsupported) {
          first.pageNote = 'The server offered Digest with ' +
              fields.unsupported.join(', ') + ' and this build can compute ' +
              scimClient.DIGEST_ALGORITHMS.map(function (row) {
                return row.token;
              }).join(', ') + ' — so none of its challenges can be ' +
              'answered. That is a gap between this client and that server ' +
              'rather than a problem with these credentials.';
          log.debug("Leaving send(). No computable Digest algorithm.");
          return first;
        }
        auth.digest = fields;
        return sendOnce(request, auth).then(function (second) {
          second.firstLeg = first;
          // RFC 7616 section 3.5, and the half most implementations leave
          // out: rspauth is how the CLIENT authenticates the SERVER. Checking
          // it is what turns Digest into mutual authentication, and a client
          // that never looks has the property available and unused.
          second.authenticationInfo = scimClient.verifyAuthenticationInfo({
            header: scenarios.headerValue(second.headers,
                'authentication-info'),
            fields: fields
          });
          log.debug("Leaving send(). Digest, two legs, status=" +
              second.status + ", rspauth " +
              (second.authenticationInfo.ok ? 'verified' : 'not verified'));
          return second;
        });
      }
      return signHoba(request).then(function (signed) {
        if (!signed) {
          first.pageNote = 'The server issued a HOBA challenge and this page ' +
              'has no registered key to answer it with. Generate one and ' +
              'register it in the Authentication pane.';
          log.debug("Leaving send(). No HOBA key.");
          return first;
        }
        auth.hoba = signed;
        return sendOnce(request, auth).then(function (second) {
          second.firstLeg = first;
          log.debug("Leaving send(). HOBA, two legs, status=" + second.status);
          return second;
        });
      });
    });
  });
}

function sendOnce(request, auth) {
  log.debug("Entering sendOnce(). scheme=" + auth.scheme);
  var applied = scimClient.applyAuth(request, auth);
  var headers = Object.assign({}, request.headers, applied.headers);
  var via = callVia();
  showRequest(request, headers, via, applied.note);
  if (via === 'api') {
    log.debug("Leaving sendOnce(). Through the api.");
    return sendThroughApi(request, headers);
  }
  log.debug("Leaving sendOnce(). From this browser.");
  return sendFromBrowser(request, headers, applied.credentials);
}

function sendFromBrowser(request, headers, credentials) {
  log.debug("Entering sendFromBrowser().");
  var started = Date.now();
  var options = {
    method: request.method,
    headers: headers,
    credentials: credentials
  };
  if (request.body !== null && request.body !== undefined &&
      request.method !== 'GET' && request.method !== 'DELETE') {
    options.body = JSON.stringify(request.body);
  }
  log.debug("Leaving sendFromBrowser().");
  return fetch(request.url, options).then(function (response) {
    return response.text().then(function (text) {
      var parsed = null;
      try {
        parsed = text === '' ? null : JSON.parse(text);
      } catch (e) {
        // Not JSON. Kept as text: an HTML error page from something in front
        // of the SCIM server is exactly the case where the body is the only
        // useful evidence.
        parsed = null;
      }
      var out = {
        status: response.status,
        headers: readableHeaders(response),
        body: parsed,
        rawBody: text,
        scimType: parsed && parsed.scimType ? String(parsed.scimType) : '',
        detail: parsed && parsed.detail ? String(parsed.detail) : '',
        elapsedMs: Date.now() - started,
        via: 'browser',
        partialHeaders: true
      };
      rememberDpopNonce(out.headers);
      log.debug("Leaving sendFromBrowser(). status=" + out.status);
      return out;
    });
  }).catch(function (error) {
    // THE ONE BRANCH WHERE NOTHING CAME BACK AT ALL. A browser gives the same
    // TypeError for four quite different causes, so the message names all four
    // rather than guessing.
    log.warn('the browser-direct SCIM call failed: ' + error.message);
    return {
      status: 0,
      headers: {},
      body: null,
      rawBody: '',
      scimType: '',
      detail: '',
      elapsedMs: Date.now() - started,
      via: 'browser',
      transportError: error.message + ' — ' + explainBrowserFailure()
    };
  });
}

// What a browser will let this page read of a response.
//
// CORS restricts it to the seven "simple" response headers unless the server
// names more in `Access-Control-Expose-Headers` — so `Location`, which every
// SCIM create sends and which the scenario runner would like, is usually NOT
// readable from here even though it was sent. The Exchange pane says so; a
// partial list presented as a whole one is the failure this note exists to
// prevent.
function readableHeaders(response) {
  log.debug("Entering readableHeaders().");
  var out = {};
  try {
    response.headers.forEach(function (value, name) {
      out[name] = value;
    });
  } catch (e) {
    log.warn('could not read the response headers: ' + e.message);
  }
  log.debug("Leaving readableHeaders(). " + Object.keys(out).length +
      " readable.");
  return out;
}

function rememberDpopNonce(headers) {
  log.debug("Entering rememberDpopNonce().");
  var nonce = scenarios.headerValue(headers, 'dpop-nonce');
  if (nonce) {
    lastDpopNonce = nonce;
    setText('scim_dpop_nonce', nonce);
  }
  log.debug("Leaving rememberDpopNonce(). " + (nonce ? 'stored' : 'none'));
}

function explainBrowserFailure() {
  log.debug("Entering explainBrowserFailure().");
  var text = 'A browser reports the same error for four different causes and ' +
      'will not say which: the server sent no CORS headers (which is true ' +
      'of essentially every real SCIM endpoint), the host could not be ' +
      'resolved or reached, the TLS certificate was rejected, or the page ' +
      'is https and the URL is http. ' +
      (BACKEND_AVAILABLE
        ? 'Switch the call path to "through the api" — it has no CORS to ' +
          'obey, can be told to skip certificate validation, and reports ' +
          'the whole exchange.'
        : 'This build has no api to fall back to, so a server with no CORS ' +
          'headers cannot be reached from here. Run the debugger locally ' +
          'for that.');
  log.debug("Leaving explainBrowserFailure().");
  return text;
}

function sendThroughApi(request, headers) {
  log.debug("Entering sendThroughApi().");
  var started = Date.now();
  log.debug("Leaving sendThroughApi().");
  return fetch(API_URL + '/scim', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      url: request.url,
      method: request.method,
      headers: headers,
      body: request.body,
      sslValidate: val('scim_ssl_validate') !== 'false',
      http_trace: true
    })
  }).then(function (response) {
    return response.text().then(function (text) {
      var payload;
      try {
        payload = JSON.parse(text);
      } catch (e) {
        payload = { error: text };
      }
      if (response.status === 400) {
        // The api refused to SEND it. That is this debugger's own rule
        // speaking, not the SCIM server, and conflating the two would send
        // somebody to look at a server that was never contacted.
        return {
          status: 0, headers: {}, body: null, rawBody: '', scimType: '',
          detail: '', elapsedMs: Date.now() - started, via: 'api',
          transportError: 'The api refused to send this request: ' +
              (payload.error || 'no reason given'),
          exchange: payload.http_exchange || null
        };
      }
      if (response.status === 502) {
        return {
          status: 0, headers: {}, body: null, rawBody: '', scimType: '',
          detail: '', elapsedMs: Date.now() - started, via: 'api',
          transportError: payload.error ||
              'The SCIM server could not be reached.',
          exchange: payload.http_exchange || null
        };
      }
      var out = {
        status: payload.status,
        headers: payload.headers || {},
        body: payload.body || null,
        rawBody: payload.rawBody || '',
        scimType: payload.scimType || '',
        detail: payload.detail || '',
        elapsedMs: Date.now() - started,
        via: 'api',
        partialHeaders: false,
        exchange: payload.http_exchange || null
      };
      rememberDpopNonce(out.headers);
      log.debug("Leaving sendThroughApi(). status=" + out.status);
      return out;
    });
  }).catch(function (error) {
    log.warn('the call to the api failed: ' + error.message);
    return {
      status: 0, headers: {}, body: null, rawBody: '', scimType: '',
      detail: '', elapsedMs: Date.now() - started, via: 'api',
      transportError: 'The call to the api at ' + API_URL + ' failed: ' +
          error.message
    };
  });
}

// ---------------------------------------------------------------------------
// THE EXCHANGE PANE.
//
// Text nodes throughout, for the reason setJson() gives. What is shown differs
// between the two call paths and the pane SAYS which — a browser-direct call
// cannot show the headers the browser added or most of those that came back,
// and presenting that as the whole exchange would be a debugger lying with a
// straight face.
// ---------------------------------------------------------------------------
function showRequest(request, headers, via, authNote) {
  log.debug("Entering showRequest().");
  setText('scim_exchange_request_line', request.method + ' ' + request.url);
  setJson('scim_exchange_request_headers', headers);
  setJson('scim_exchange_request_body', request.body);
  setText('scim_exchange_auth_note', authNote || '');
  setText('scim_exchange_via', via === 'api'
    ? 'Sent by the api. Everything below is what THIS request and response ' +
      'actually were, headers included.'
    : 'Sent by this browser. The browser adds headers of its own that this ' +
      'page cannot see (Host, Origin, User-Agent, Content-Length among ' +
      'them), and CORS hides most of the response headers unless the server ' +
      'names them in Access-Control-Expose-Headers — Location in particular ' +
      'is usually invisible here even though it was sent.');
  setText('scim_exchange_response_line', '(waiting)');
  setJson('scim_exchange_response_headers', null);
  setJson('scim_exchange_response_body', null);
  log.debug("Leaving showRequest().");
}

function showResponse(result) {
  log.debug("Entering showResponse(). status=" + result.status);
  if (result.transportError) {
    setText('scim_exchange_response_line', 'No response — ' +
        result.transportError);
    setJson('scim_exchange_response_headers', null);
    setJson('scim_exchange_response_body', null);
    log.debug("Leaving showResponse(). No response.");
    return;
  }
  var described = scimClient.describeResponse(result.status, result.body);
  setText('scim_exchange_response_line', result.status + ' — ' +
      described.summary + ' (' + result.elapsedMs + 'ms)');
  setJson('scim_exchange_response_headers', result.headers);
  setJson('scim_exchange_response_body',
      result.body === null ? (result.rawBody || '(no body)') : result.body);
  var notes = described.conformance.slice(0);
  if (described.scimType) {
    var explained = scimClient.explainScimType(described.scimType);
    if (explained) {
      notes.push(described.scimType + ': ' + explained);
    }
  }
  if (result.pageNote) {
    notes.push(result.pageNote);
  }
  if (result.authenticationInfo) {
    notes.push(result.authenticationInfo.note);
  }
  setText('scim_exchange_notes', notes.join('  '));
  show('scim_exchange_notes', notes.length > 0);
  if (result.firstLeg) {
    setText('scim_exchange_first_leg', 'This was a two-leg exchange. The ' +
        'first request was answered ' + result.firstLeg.status + ' with a ' +
        'challenge, and the credential above was computed over it. That ' +
        'handshake is what these schemes ARE, which is why both legs are ' +
        'shown rather than only the one that worked.');
    show('scim_exchange_first_leg', true);
  } else {
    show('scim_exchange_first_leg', false);
  }
  log.debug("Leaving showResponse().");
}

function renderChallenges() {
  log.debug("Entering renderChallenges().");
  if (!lastChallenges.length) {
    setText('scim_challenges', 'No challenge has been collected yet. Send ' +
        'anything with the scheme set to None: a server with authentication ' +
        'turned on answers 401 and RFC 7644 section 2 requires it to say in ' +
        'that response which schemes it accepts.');
    log.debug("Leaving renderChallenges(). None.");
    return;
  }
  var lines = lastChallenges.map(function (row) {
    var params = Object.keys(row.params).map(function (name) {
      return name + '=' + row.params[name];
    }).join(', ');
    return row.scheme + (params ? ' (' + params + ')' : '');
  });
  setText('scim_challenges', 'The server offered: ' + lines.join('  |  '));
  log.debug("Leaving renderChallenges(). " + lines.length + " challenge(s).");
}

// --- the history log -------------------------------------------------------
function renderHistory() {
  log.debug("Entering renderHistory().");
  var host = el('scim_history');
  if (host) {
    history.render(host);
  }
  log.debug("Leaving renderHistory().");
}

function recordAndSend(request, label) {
  log.debug("Entering recordAndSend(). " + label);
  var entryId = history.record({
    operation: request.label || label,
    target: request.method + ' ' + shortUrl(request.url),
    detailText: label || '',
    server: originLabel(request.url),
    result: history.SENT
  });
  renderHistory();
  log.debug("Leaving recordAndSend().");
  return send(request).then(function (result) {
    if (result.transportError) {
      // A row that stays Sent would mean nothing came back at all; this one
      // came back as a failure of the CALL rather than of the operation, and
      // the two are the states people most often confuse.
      history.update(entryId, history.FAILURE, 'no answer');
    } else if (result.status >= 200 && result.status < 300) {
      history.update(entryId, history.SUCCESS, String(result.status));
    } else {
      history.update(entryId, history.FAILURE, String(result.status) +
          (result.scimType ? ' ' + result.scimType : ''));
    }
    renderHistory();
    return result;
  });
}

function shortUrl(url) {
  log.debug("Entering shortUrl().");
  var target = requestTarget(url);
  var out = target.length > 70 ? target.slice(0, 67) + '…' : target;
  log.debug("Leaving shortUrl().");
  return out;
}

function originLabel(url) {
  log.debug("Entering originLabel().");
  var match = String(url || '').match(/^(https?:\/\/[^/]+)/i);
  var out = match ? match[1] : '';
  log.debug("Leaving originLabel().");
  return out;
}

// ---------------------------------------------------------------------------
// THE ENDPOINT PANE — one operation at a time.
// ---------------------------------------------------------------------------
function populateOperations() {
  log.debug("Entering populateOperations().");
  var select = el('scim_op');
  if (!select) {
    log.debug("Leaving populateOperations(). No such element.");
    return;
  }
  var groups = [
    { id: 'discovery', label: 'Discovery' },
    { id: 'user', label: 'Users' },
    { id: 'group', label: 'Groups' },
    { id: 'query', label: 'Across resources' }
  ];
  select.innerHTML = '';
  groups.forEach(function (group) {
    var optionGroup = document.createElement('optgroup');
    optionGroup.label = group.label;
    scimClient.operationsInGroup(group.id).forEach(function (row) {
      var option = document.createElement('option');
      option.value = row.id;
      option.textContent = row.method + ' — ' + row.label;
      optionGroup.appendChild(option);
    });
    select.appendChild(optionGroup);
  });
  log.debug("Leaving populateOperations(). " + scimClient.OPERATIONS.length +
      " operation(s).");
}

function refreshOperationControls() {
  log.debug("Entering refreshOperationControls().");
  var row = scimClient.operation(val('scim_op'));
  if (!row) {
    log.debug("Leaving refreshOperationControls(). Unknown operation.");
    return;
  }
  setText('scim_op_what', row.what);
  setText('scim_op_section', row.section);
  setText('scim_op_need', row.need === 'none'
    ? 'Needs no scope — discovery is readable before a client knows how to ' +
      'authenticate, which is the one bootstrapping problem RFC 7644 leaves ' +
      'to the reader.'
    : 'Needs the ' + row.need + ' scope on an OAuth credential. Other ' +
      'schemes carry no scope at all, so a server that accepts them usually ' +
      'lets the caller do everything.');
  show('scim_op_id_row', row.path.indexOf('{id}') >= 0);
  setText('scim_op_id_label', row.idLabel || 'Resource id');
  var idField = el('scim_op_id');
  if (idField) {
    idField.placeholder = row.idExample ||
        'uid=alice,ou=users,dc=example,dc=com';
  }
  var queryNames = row.query || [];
  ['filter', 'sort_by', 'sort_order', 'start_index', 'count', 'attributes',
   'excluded_attributes'].forEach(function (name) {
    var wanted = name.replace(/_([a-z])/g, function (whole, letter) {
      return letter.toUpperCase();
    });
    show('scim_query_' + name + '_row', queryNames.indexOf(wanted) >= 0);
  });
  show('scim_op_query_row', queryNames.length > 0);
  show('scim_op_body_row', !!row.body);
  setText('scim_op_body_kind', row.body
    ? 'This operation carries a ' + row.body + ' body. The button beside it ' +
      'fills in a generated one.'
    : '');
  refreshRequestPreview();
  log.debug("Leaving refreshOperationControls(). " + row.id);
}

function queryFromFields(row) {
  log.debug("Entering queryFromFields().");
  var query = {};
  var map = {
    filter: 'scim_query_filter',
    sortBy: 'scim_query_sort_by',
    sortOrder: 'scim_query_sort_order',
    startIndex: 'scim_query_start_index',
    count: 'scim_query_count',
    attributes: 'scim_query_attributes',
    excludedAttributes: 'scim_query_excluded_attributes'
  };
  (row.query || []).forEach(function (name) {
    var value = val(map[name]);
    if (value !== '') {
      query[name] = value;
    }
  });
  log.debug("Leaving queryFromFields(). " + Object.keys(query).length +
      " parameter(s).");
  return query;
}

function bodyFromField(row) {
  log.debug("Entering bodyFromField().");
  if (!row.body) {
    log.debug("Leaving bodyFromField(). This operation carries none.");
    return { ok: true, body: null };
  }
  var text = val('scim_op_body').trim();
  if (text === '') {
    log.debug("Leaving bodyFromField(). Empty.");
    return { ok: false, error: 'This operation needs a ' + row.body +
        ' body. Use the Generate button beside the field, or paste one.' };
  }
  try {
    var parsed = JSON.parse(text);
    log.debug("Leaving bodyFromField(). Parsed.");
    return { ok: true, body: parsed };
  } catch (e) {
    log.debug("Leaving bodyFromField(). Not JSON: " + e.message);
    return { ok: false, error: 'The body is not valid JSON: ' + e.message };
  }
}

function currentRequest() {
  log.debug("Entering currentRequest().");
  var row = scimClient.operation(val('scim_op'));
  if (!row) {
    log.debug("Leaving currentRequest(). Unknown operation.");
    return { ok: false, error: 'Choose an operation.' };
  }
  var body = bodyFromField(row);
  if (!body.ok) {
    log.debug("Leaving currentRequest(). " + body.error);
    return body;
  }
  try {
    var request = scimClient.buildRequest({
      operation: row.id,
      baseUrl: val('scim_base_url'),
      id: val('scim_op_id'),
      query: queryFromFields(row),
      body: body.body
    });
    log.debug("Leaving currentRequest(). Built.");
    return { ok: true, request: request };
  } catch (e) {
    log.debug("Leaving currentRequest(). " + e.message);
    return { ok: false, error: e.message };
  }
}

function refreshRequestPreview() {
  log.debug("Entering refreshRequestPreview().");
  var built = currentRequest();
  if (!built.ok) {
    setText('scim_op_preview', built.error);
    log.debug("Leaving refreshRequestPreview(). Not buildable yet.");
    return;
  }
  setText('scim_op_preview', built.request.method + ' ' + built.request.url);
  log.debug("Leaving refreshRequestPreview().");
}

function runOperation() {
  log.debug("Entering runOperation().");
  saveState();
  var built = currentRequest();
  if (!built.ok) {
    statusBad('scim_op_status', built.error);
    log.debug("Leaving runOperation(). " + built.error);
    return Promise.resolve(null);
  }
  statusBusy('scim_op_status', 'Sending ' + built.request.method + ' ' +
      shortUrl(built.request.url) + '…');
  log.debug("Leaving runOperation(). Sent.");
  return recordAndSend(built.request, built.request.label)
    .then(function (result) {
      showResponse(result);
      setJson('scim_op_result',
          result.body === null ? (result.rawBody || '(no body)') : result.body);
      if (result.transportError) {
        statusBad('scim_op_status', result.transportError);
        return result;
      }
      var described = scimClient.describeResponse(result.status, result.body);
      if (described.ok) {
        statusOk('scim_op_status', result.status + ' — ' + described.summary);
        rememberCreatedId(built.request, result);
      } else {
        // The server ANSWERED and the answer was no. That is a result and not
        // a failure of this page, and the status line says so — the same
        // distinction the LDAP page draws between a result code and a
        // transport failure.
        statusBad('scim_op_status', 'The server refused it: ' + result.status +
            (result.scimType ? ' ' + result.scimType : '') +
            (result.detail ? ' — ' + result.detail : '') +
            '. The exchange itself worked.');
      }
      return result;
    });
}

function rememberCreatedId(request, result) {
  log.debug("Entering rememberCreatedId().");
  if (!result.body || !result.body.id) {
    log.debug("Leaving rememberCreatedId(). Nothing to remember.");
    return;
  }
  if (request.resourceType === 'User') {
    setVal('scim_last_user_id', result.body.id);
  }
  if (request.resourceType === 'Group') {
    setVal('scim_last_group_id', result.body.id);
  }
  saveState();
  log.debug("Leaving rememberCreatedId(). " + result.body.id);
}

// Fill the id field from whichever of the two remembered ids fits the operation
// being run. A debugger where an id has to be copied by hand between two fields
// on the same page is one nobody uses twice.
function useLastId() {
  log.debug("Entering useLastId().");
  var row = scimClient.operation(val('scim_op'));
  if (!row) {
    log.debug("Leaving useLastId(). Unknown operation.");
    return;
  }
  var id = row.resourceType === 'Group' ? val('scim_last_group_id')
    : val('scim_last_user_id');
  if (id === '') {
    statusBad('scim_op_status', 'Nothing has been created from this page ' +
        'yet, so there is no id to reuse.');
    log.debug("Leaving useLastId(). Nothing remembered.");
    return;
  }
  setVal('scim_op_id', id);
  refreshRequestPreview();
  log.debug("Leaving useLastId(). " + id);
}

// ---------------------------------------------------------------------------
// THE GENERATOR PANE.
// ---------------------------------------------------------------------------
function generatorSettings() {
  log.debug("Entering generatorSettings().");
  var out = {
    seed: val('scim_gen_seed') || 'seed-1',
    prefix: val('scim_gen_prefix') || 'scim',
    count: Math.max(1, Math.min(50, Number(val('scim_gen_count')) || 1)),
    domain: val('scim_gen_domain') || 'example.com',
    minimal: isOn('scim_gen_minimal')
  };
  log.debug("Leaving generatorSettings(). count=" + out.count);
  return out;
}

function generateUsers() {
  log.debug("Entering generateUsers().");
  saveState();
  var settings = generatorSettings();
  var rng = scimClient.newRng(settings.seed);
  var users = [];
  var i;
  for (i = 0; i < settings.count; i++) {
    users.push(scimClient.randomUser({
      rng: rng, prefix: settings.prefix, index: i, domain: settings.domain,
      minimal: settings.minimal
    }));
  }
  setJson('scim_gen_output', settings.count === 1 ? users[0] : users);
  statusOk('scim_gen_status', settings.count + ' user(s) generated from the ' +
      'seed "' + settings.seed + '". The SAME seed always produces the SAME ' +
      'users, which is what makes a failure here reproducible rather than a ' +
      'story.');
  log.debug("Leaving generateUsers(). " + users.length + " user(s).");
  return users;
}

function generateGroup() {
  log.debug("Entering generateGroup().");
  saveState();
  var settings = generatorSettings();
  var rng = scimClient.newRng(settings.seed + ':group');
  var group = scimClient.randomGroup({ rng: rng, prefix: settings.prefix });
  setJson('scim_gen_output', group);
  statusOk('scim_gen_status', 'A group was generated. Members are added ' +
      'afterwards with a PATCH against the GROUP — membership is a fact ' +
      'about the group and is never changed through a User resource.');
  log.debug("Leaving generateGroup().");
  return group;
}

function useGeneratedBody() {
  log.debug("Entering useGeneratedBody().");
  var text = el('scim_gen_output') ? el('scim_gen_output').textContent : '';
  if (String(text).trim() === '') {
    statusBad('scim_gen_status', 'Generate something first.');
    log.debug("Leaving useGeneratedBody(). Nothing generated.");
    return;
  }
  setVal('scim_op_body', text);
  saveState();
  refreshRequestPreview();
  statusOk('scim_gen_status', 'Copied into the Endpoint pane\'s body.');
  log.debug("Leaving useGeneratedBody().");
}

// Fill the body field with a skeleton of whatever the selected operation takes.
function generateBodyForOperation() {
  log.debug("Entering generateBodyForOperation().");
  var row = scimClient.operation(val('scim_op'));
  if (!row || !row.body) {
    log.debug("Leaving generateBodyForOperation(). No body on this one.");
    return;
  }
  var settings = generatorSettings();
  var rng = scimClient.newRng(settings.seed + ':' + row.id);
  var body = null;
  if (row.body === 'User') {
    body = scimClient.randomUser({ rng: rng, prefix: settings.prefix,
        index: 0, domain: settings.domain, minimal: settings.minimal });
  } else if (row.body === 'Group') {
    body = scimClient.randomGroup({ rng: rng, prefix: settings.prefix });
  } else if (row.body === 'SearchRequest') {
    body = scimClient.searchRequest({
      filter: val('scim_query_filter') || 'userName pr',
      count: Number(val('scim_query_count')) || 10,
      startIndex: 1
    });
  } else if (row.body === 'PatchOp') {
    body = scimClient.patchOp([
      { op: 'replace', path: 'title', value: 'Changed from the SCIM page' },
      { op: 'add', path: 'emails',
        value: [{ value: 'added@' + settings.domain, type: 'other' }] },
      { op: 'remove', path: 'emails[type eq "other"]' }
    ]);
  } else if (row.body === 'BulkRequest') {
    var operations = [];
    var members = [];
    var i;
    for (i = 0; i < settings.count; i++) {
      operations.push({ method: 'POST', bulkId: 'user' + i, path: '/Users',
        data: scimClient.randomUser({ rng: rng, prefix: settings.prefix,
            index: i, domain: settings.domain, minimal: settings.minimal }) });
      members.push({ value: 'bulkId:user' + i, type: 'User' });
    }
    var group = scimClient.randomGroup({ rng: rng, prefix: settings.prefix });
    group.members = members;
    operations.push({ method: 'POST', bulkId: 'group0', path: '/Groups',
      data: group });
    body = scimClient.bulkRequest(operations, { failOnErrors: 1 });
  }
  setVal('scim_op_body', JSON.stringify(body, null, 2));
  saveState();
  refreshRequestPreview();
  statusOk('scim_op_status', 'A ' + row.body + ' body was generated. Edit it ' +
      'before sending if you want to see what a particular field does.');
  log.debug("Leaving generateBodyForOperation(). " + row.body);
}

// ---------------------------------------------------------------------------
// THE SCENARIO RUNNER.
//
// Sequential and never parallel, and that is a decision rather than laziness: a
// scenario is an ORDERED plan whose later steps reference what earlier ones
// created, and half of what a provisioning harness is for is finding out what
// happens in order. Running them concurrently would also make the progress
// table unreadable and would put a directory under a load this page has no
// business generating by accident.
// ---------------------------------------------------------------------------
var currentPlan = null;
var runState = { running: false, stopRequested: false, captured: {},
                 results: [] };

function planScenario() {
  log.debug("Entering planScenario().");
  saveState();
  var id = val('scim_scenario');
  try {
    currentPlan = scenarios.plan(id, {
      seed: val('scim_scenario_seed'),
      prefix: val('scim_scenario_prefix'),
      userCount: Number(val('scim_scenario_count')),
      domain: val('scim_gen_domain') || 'example.com'
    });
  } catch (e) {
    statusBad('scim_scenario_status', e.message);
    log.debug("Leaving planScenario(). " + e.message);
    return null;
  }
  runState = { running: false, stopRequested: false, captured: {},
               results: [] };
  renderPlan();
  statusOk('scim_scenario_status', currentPlan.label + ' — ' +
      currentPlan.steps.length + ' step(s), from the seed "' +
      currentPlan.seed + '". Nothing has been sent: this is the plan. Read ' +
      'it, then run it.');
  log.debug("Leaving planScenario(). " + currentPlan.steps.length +
      " step(s).");
  return currentPlan;
}

function renderPlan() {
  log.debug("Entering renderPlan().");
  var host = el('scim_runner_table');
  if (!host) {
    log.debug("Leaving renderPlan(). No table.");
    return;
  }
  // Built out of createElement and text nodes rather than an HTML string,
  // because every cell here can carry a userName, a filter or a server's own
  // error text — all of it somebody else's bytes.
  host.innerHTML = '';
  var head = document.createElement('thead');
  var headRow = document.createElement('tr');
  ['#', 'Step', 'Operation', 'Expected', 'Result', 'Verdict'].forEach(
    function (label) {
      var cell = document.createElement('th');
      cell.textContent = label;
      headRow.appendChild(cell);
    });
  head.appendChild(headRow);
  host.appendChild(head);
  var body = document.createElement('tbody');
  (currentPlan ? currentPlan.steps : []).forEach(function (row, index) {
    var tr = document.createElement('tr');
    tr.id = 'scim_step_row_' + index;
    appendCell(tr, String(index + 1));
    var titleCell = appendCell(tr, row.title);
    if (row.why) {
      var note = document.createElement('div');
      note.className = 'scim-step-why';
      note.textContent = row.why;
      titleCell.appendChild(note);
    }
    appendCell(tr, row.operation);
    appendCell(tr, row.expect.status.join(' or ') +
        (row.expect.scimType ? ' ' + row.expect.scimType : ''));
    appendCell(tr, '—').className = 'scim-step-result';
    var verdict = appendCell(tr, 'not run');
    verdict.className = 'scim-step-verdict scim-pending';
    body.appendChild(tr);
  });
  host.appendChild(body);
  setText('scim_runner_summary', currentPlan
    ? currentPlan.steps.length + ' step(s) planned.' : '');
  log.debug("Leaving renderPlan().");
}

// Hot: called six times per step, and a fifty-user scenario is over 150 steps
// — so nine hundred calls to draw one table. The functions that CALL it
// (renderPlan(), renderCapabilities()) keep their logging, which is where a
// trace of the render actually lives.
function appendCell(row, text) {
  var cell = document.createElement('td');
  cell.textContent = text === undefined || text === null ? '' : String(text);
  row.appendChild(cell);
  return cell;
}

function markStep(index, resultText, verdictText, verdictClass) {
  log.debug("Entering markStep(). index=" + index);
  var row = el('scim_step_row_' + index);
  if (!row) {
    log.debug("Leaving markStep(). No such row.");
    return;
  }
  var cells = row.getElementsByTagName('td');
  if (cells.length >= 6) {
    cells[4].textContent = resultText;
    cells[5].textContent = verdictText;
    cells[5].className = 'scim-step-verdict ' + verdictClass;
  }
  log.debug("Leaving markStep().");
}

function runScenario() {
  log.debug("Entering runScenario().");
  if (runState.running) {
    log.debug("Leaving runScenario(). Already running.");
    return Promise.resolve(null);
  }
  if (!currentPlan) {
    planScenario();
  }
  if (!currentPlan) {
    log.debug("Leaving runScenario(). Nothing planned.");
    return Promise.resolve(null);
  }
  runState = { running: true, stopRequested: false, captured: {},
               results: [] };
  renderPlan();
  show('scim_runner_stop', true);
  statusBusy('scim_scenario_status', 'Running ' + currentPlan.steps.length +
      ' step(s)…');
  log.debug("Leaving runScenario(). Started.");
  return runStepsFrom(0).then(function () {
    runState.running = false;
    show('scim_runner_stop', false);
    summarizeRun();
    return runState.results;
  });
}

function stopScenario() {
  log.debug("Entering stopScenario().");
  runState.stopRequested = true;
  statusBusy('scim_scenario_status', 'Stopping after the step in flight…');
  log.debug("Leaving stopScenario().");
}

// Recursive rather than a loop, because each step has to WAIT for the one
// before it: an id captured by step 3 is what step 7 addresses.
function runStepsFrom(index) {
  log.debug("Entering runStepsFrom(). index=" + index);
  if (index >= currentPlan.steps.length || runState.stopRequested) {
    log.debug("Leaving runStepsFrom(). Done at " + index);
    return Promise.resolve();
  }
  var oneStep = currentPlan.steps[index];
  var prepared = scenarios.prepare(oneStep, runState.captured);
  if (prepared.skipped) {
    markStep(index, 'not sent', 'skipped', 'scim-bad');
    runState.results.push({ step: oneStep, skipped: true,
                            why: prepared.reason });
    log.debug("Leaving runStepsFrom(). Step skipped.");
    return runStepsFrom(index + 1);
  }
  var built;
  try {
    built = scimClient.buildRequest({
      operation: oneStep.operation,
      baseUrl: val('scim_base_url'),
      id: prepared.resourceId,
      query: prepared.query || {},
      body: prepared.body
    });
  } catch (e) {
    markStep(index, e.message, 'not built', 'scim-bad');
    runState.results.push({ step: oneStep, skipped: true, why: e.message });
    log.debug("Leaving runStepsFrom(). Could not build: " + e.message);
    return runStepsFrom(index + 1);
  }
  markStep(index, 'sending…', 'running', 'scim-pending');
  return recordAndSend(built, oneStep.title).then(function (result) {
    showResponse(result);
    var verdict = scenarios.judge(oneStep, result);
    var captured = scenarios.capture(oneStep, result);
    if (captured) {
      runState.captured[oneStep.id] = captured;
    }
    var described = result.transportError ? null
      : scimClient.describeResponse(result.status, result.body);
    markStep(index,
        result.transportError ? 'no answer'
          : result.status + (result.scimType ? ' ' + result.scimType : ''),
        verdict.ok ? 'as planned' : verdict.why,
        verdict.ok ? 'scim-ok' : 'scim-bad');
    runState.results.push({ step: oneStep, result: result, verdict: verdict,
                            described: described });
    setText('scim_runner_summary', (index + 1) + ' of ' +
        currentPlan.steps.length + ' step(s) run.');
    log.debug("Leaving runStepsFrom(). Step " + index + " " +
        (verdict.ok ? 'passed' : 'failed'));
    return runStepsFrom(index + 1);
  });
}

function summarizeRun() {
  log.debug("Entering summarizeRun().");
  var passed = 0;
  var failed = 0;
  var skipped = 0;
  runState.results.forEach(function (row) {
    if (row.skipped) {
      skipped++;
      return;
    }
    if (row.verdict && row.verdict.ok) {
      passed++;
      return;
    }
    failed++;
  });
  var text = passed + ' as planned, ' + failed + ' not, ' + skipped +
      ' skipped, of ' + currentPlan.steps.length + ' planned' +
      (runState.stopRequested ? ' (stopped early)' : '') + '.';
  setText('scim_runner_summary', text);
  if (failed === 0 && skipped === 0 && !runState.stopRequested) {
    statusOk('scim_scenario_status', text + ' Every step did what the plan ' +
        'said it would — including the ones that expected a refusal.');
  } else {
    statusBad('scim_scenario_status', text + ' A step that did not go as ' +
        'planned is not necessarily a broken server: read the Verdict ' +
        'column, which says what was expected and what happened.');
  }
  log.debug("Leaving summarizeRun(). " + text);
}

function populateScenarios() {
  log.debug("Entering populateScenarios().");
  var select = el('scim_scenario');
  if (!select) {
    log.debug("Leaving populateScenarios(). No such element.");
    return;
  }
  select.innerHTML = '';
  scenarios.SCENARIOS.forEach(function (row) {
    var option = document.createElement('option');
    option.value = row.id;
    option.textContent = row.label;
    select.appendChild(option);
  });
  var random = document.createElement('option');
  random.value = 'random';
  random.textContent = 'Random — a scenario composed from the seed';
  select.appendChild(random);
  log.debug("Leaving populateScenarios(). " + scenarios.SCENARIOS.length +
      " scenario(s) plus random.");
}

function refreshScenarioControls() {
  log.debug("Entering refreshScenarioControls().");
  var id = val('scim_scenario');
  if (id === 'random') {
    setText('scim_scenario_what', 'Two to four of the scenarios above, ' +
        'chosen from the seed and run one after another, each with its own ' +
        'prefix so they cannot collide on a userName. The seed is shown ' +
        'with the plan: the same seed always composes the same scenario, ' +
        'which is what makes a failure here reproducible.');
    show('scim_scenario_count_row', true);
    show('scim_scenario_auth_note', false);
    log.debug("Leaving refreshScenarioControls(). Random.");
    return;
  }
  var row = scenarios.scenario(id);
  if (!row) {
    log.debug("Leaving refreshScenarioControls(). Unknown scenario.");
    return;
  }
  setText('scim_scenario_what', row.what);
  show('scim_scenario_count_row', (row.takes || []).indexOf('userCount') >= 0);
  show('scim_scenario_auth_note', row.needsAuth === true);
  log.debug("Leaving refreshScenarioControls(). " + row.id);
}

// ---------------------------------------------------------------------------
// DISCOVERY — the three documents a client should read before anything else,
// with the ServiceProviderConfig tabulated rather than dumped, because what a
// reader wants from it is six booleans and two numbers.
// ---------------------------------------------------------------------------
function readServiceProviderConfig() {
  log.debug("Entering readServiceProviderConfig().");
  saveState();
  var request;
  try {
    request = scimClient.buildRequest({
      operation: 'serviceProviderConfig',
      baseUrl: val('scim_base_url')
    });
  } catch (e) {
    statusBad('scim_discovery_status', e.message);
    log.debug("Leaving readServiceProviderConfig(). " + e.message);
    return Promise.resolve(null);
  }
  statusBusy('scim_discovery_status', 'Reading the ServiceProviderConfig…');
  log.debug("Leaving readServiceProviderConfig(). Sent.");
  return recordAndSend(request, 'ServiceProviderConfig').then(
    function (result) {
      showResponse(result);
      if (result.transportError) {
        statusBad('scim_discovery_status', result.transportError);
        return result;
      }
      setJson('scim_discovery_output', result.body);
      renderCapabilities(result.body);
      if (result.status === 200) {
        statusOk('scim_discovery_status', 'Read. Everything this page can do ' +
            'is a promise made in this document — the table below is it.');
      } else {
        statusBad('scim_discovery_status', 'The server answered ' +
            result.status + '. Note that discovery needs no scope anywhere ' +
            'in RFC 7644, so a 401 here means the server requires ' +
            'authentication even to be described.');
      }
      return result;
    });
}

function renderCapabilities(body) {
  log.debug("Entering renderCapabilities().");
  var host = el('scim_capabilities');
  if (!host) {
    log.debug("Leaving renderCapabilities(). No host.");
    return;
  }
  host.innerHTML = '';
  if (!body) {
    log.debug("Leaving renderCapabilities(). Nothing to draw.");
    return;
  }
  var rows = [
    ['patch', supportedText(body.patch), 'Whether PATCH works at all. ' +
        'Without it every change is a PUT, which replaces the resource.'],
    ['bulk', supportedText(body.bulk) +
        (body.bulk && body.bulk.maxOperations
          ? ' — at most ' + body.bulk.maxOperations + ' operations, ' +
            body.bulk.maxPayloadSize + ' bytes' : ''),
        'Many operations in one request.'],
    ['filter', supportedText(body.filter) +
        (body.filter && body.filter.maxResults
          ? ' — at most ' + body.filter.maxResults + ' results' : ''),
        'ONE boolean for fourteen operators, which is why the filter tour ' +
        'scenario exists: this says nothing about which of them work.'],
    ['sort', supportedText(body.sort), 'sortBy and sortOrder.'],
    ['etag', supportedText(body.etag), 'Optimistic concurrency. A server ' +
        'that says false here and sends an ETag anyway is worse than one ' +
        'with none, because a client would trust it.'],
    ['changePassword', supportedText(body.changePassword),
        'Whether a password can be set through SCIM.'],
    ['authenticationSchemes',
        (body.authenticationSchemes || []).map(function (row) {
          return row.type || row.name;
        }).join(', ') || '(none advertised)',
        'RFC 7643 section 5. An EMPTY list is an honest answer from a ' +
        'server that authenticates nobody — and a very different thing from ' +
        'the member being absent.']
  ];
  var table = document.createElement('table');
  table.className = 'scim-capability-table';
  rows.forEach(function (row) {
    var tr = document.createElement('tr');
    appendCell(tr, row[0]).className = 'scim-capability-name';
    appendCell(tr, row[1]).className = 'scim-capability-value';
    appendCell(tr, row[2]).className = 'scim-capability-note';
    table.appendChild(tr);
  });
  host.appendChild(table);
  log.debug("Leaving renderCapabilities(). " + rows.length + " row(s).");
}

function supportedText(value) {
  log.debug("Entering supportedText().");
  var out;
  if (value === undefined || value === null) {
    out = '(not stated)';
  } else if (typeof value === 'boolean') {
    out = value ? 'yes' : 'no';
  } else if (typeof value === 'object') {
    out = value.supported ? 'yes' : 'no';
  } else {
    out = String(value);
  }
  log.debug("Leaving supportedText(). " + out);
  return out;
}

function readSchemas() {
  log.debug("Entering readSchemas().");
  var pending = runDiscovery('schemas', 'Schemas');
  log.debug("Leaving readSchemas().");
  return pending;
}

function readResourceTypes() {
  log.debug("Entering readResourceTypes().");
  var pending = runDiscovery('resourceTypes', 'ResourceTypes');
  log.debug("Leaving readResourceTypes().");
  return pending;
}

function runDiscovery(operationId, label) {
  log.debug("Entering runDiscovery(). " + operationId);
  saveState();
  var request;
  try {
    request = scimClient.buildRequest({ operation: operationId,
                                        baseUrl: val('scim_base_url') });
  } catch (e) {
    statusBad('scim_discovery_status', e.message);
    log.debug("Leaving runDiscovery(). " + e.message);
    return Promise.resolve(null);
  }
  statusBusy('scim_discovery_status', 'Reading the ' + label + '…');
  log.debug("Leaving runDiscovery(). Sent.");
  return recordAndSend(request, label).then(function (result) {
    showResponse(result);
    if (result.transportError) {
      statusBad('scim_discovery_status', result.transportError);
      return result;
    }
    setJson('scim_discovery_output',
        result.body === null ? result.rawBody : result.body);
    var described = scimClient.describeResponse(result.status, result.body);
    if (described.ok) {
      statusOk('scim_discovery_status', label + ': ' + described.summary);
    } else {
      statusBad('scim_discovery_status', 'The server answered ' +
          result.status + ' — ' + described.summary);
    }
    return result;
  });
}

// A deliberate 401, to read the challenge. This is the fastest way to find out
// what a server will accept and it is a BUTTON rather than something the page
// does silently, because it is a request being sent.
function probeAuthentication() {
  log.debug("Entering probeAuthentication().");
  saveState();
  var request;
  try {
    request = scimClient.buildRequest({ operation: 'listUsers',
        baseUrl: val('scim_base_url'), query: { count: '1' } });
  } catch (e) {
    statusBad('scim_auth_status', e.message);
    log.debug("Leaving probeAuthentication(). " + e.message);
    return Promise.resolve(null);
  }
  statusBusy('scim_auth_status', 'Sending an unauthenticated request to see ' +
      'what the server asks for…');
  var applied = scimClient.applyAuth(request, { scheme: 'none' });
  showRequest(request, request.headers, callVia(), applied.note);
  log.debug("Leaving probeAuthentication(). Sent.");
  return sendOnce(request, { scheme: 'none' }).then(function (result) {
    showResponse(result);
    if (result.transportError) {
      statusBad('scim_auth_status', result.transportError);
      return result;
    }
    lastChallenges = scimClient.parseChallenges(
      scenarios.headerValue(result.headers, 'www-authenticate'));
    renderChallenges();
    if (result.status === 401) {
      statusOk('scim_auth_status', 'The server refused an anonymous request ' +
          'and said what it accepts — that WWW-Authenticate header is the ' +
          'only normative requirement RFC 7644 section 2 makes of a SCIM ' +
          'server\'s authentication. The challenge is below.');
    } else if (result.status >= 200 && result.status < 300) {
      statusBad('scim_auth_status', 'The server allowed an ANONYMOUS read ' +
          '(' + result.status + '). That is not a failure of this page: ' +
          'this server does not require authentication on that endpoint. ' +
          'Nothing was sent as a credential.');
    } else if (result.status === 403) {
      statusBad('scim_auth_status', 'The server answered 403 rather than ' +
          '401. That means it recognised the caller and refused the ' +
          'operation, which with no credential sent usually means an ' +
          'anonymous identity with no scope.');
    } else {
      statusBad('scim_auth_status', 'The server answered ' + result.status +
          '. No challenge was collected.');
    }
    return result;
  });
}

function refreshAuthControls() {
  log.debug("Entering refreshAuthControls().");
  var scheme = scimClient.authScheme(val('scim_auth_scheme'));
  if (!scheme) {
    log.debug("Leaving refreshAuthControls(). Unknown scheme.");
    return;
  }
  setText('scim_auth_what', scheme.what);
  setText('scim_auth_spec', scheme.spec);
  show('scim_auth_token_row', scheme.id === 'bearer' || scheme.id === 'dpop');
  show('scim_auth_password_row', scheme.id === 'basic' ||
      scheme.id === 'digest');
  show('scim_auth_realm_row', scheme.id === 'digest' || scheme.id === 'hoba');
  show('scim_digest_row', scheme.id === 'digest');
  show('scim_dpop_row', scheme.id === 'dpop');
  show('scim_hoba_row', scheme.id === 'hoba');
  show('scim_cookie_row', scheme.id === 'cookie');
  show('scim_clientcert_row', scheme.id === 'clientcert');
  setText('scim_auth_scope_note', scheme.scoped
    ? 'This scheme carries SCOPES, so what it may do is decided per ' +
      'operation: the read scope to read, the write scope to write. It is ' +
      'the only kind of credential here that can be refused with a 403 ' +
      'rather than a 401.'
    : 'This scheme carries NO scope. A server that accepts it has no ' +
      'per-operation policy to apply to it, which in practice means the ' +
      'caller may do everything — worth knowing before concluding that a ' +
      'scope restriction works.');
  refreshCallPathControls();
  log.debug("Leaving refreshAuthControls(). " + scheme.id);
}

// ---------------------------------------------------------------------------
// WHAT THE api WILL DO, read from the api itself.
//
// GET /scim/limits is also how this page finds out whether there IS an api:
// a static deployment gets nothing, which is a stronger signal than a
// configuration flag because it is the service itself answering.
// ---------------------------------------------------------------------------
function loadApiLimits() {
  log.debug("Entering loadApiLimits().");
  if (!BACKEND_AVAILABLE) {
    setText('scim_api_limits', 'This build has no api. Every call on this ' +
        'page is made by the browser.');
    log.debug("Leaving loadApiLimits(). No api in this build.");
    return Promise.resolve(null);
  }
  log.debug("Leaving loadApiLimits(). Asking.");
  return fetch(API_URL + '/scim/limits').then(function (response) {
    return response.json();
  }).then(function (limits) {
    setText('scim_api_limits', 'The api will send ' +
        limits.methods.join(', ') + '; it refuses the framing headers (' +
        limits.refusedHeaders.join(', ') + '); at most ' +
        limits.maxRequestBytes + ' bytes out and ' + limits.maxResponseBytes +
        ' back; ' + limits.callTimeoutMs + 'ms per call. ' +
        limits.statusRule);
    log.debug("Leaving loadApiLimits(). Read.");
    return limits;
  }).catch(function (error) {
    setText('scim_api_limits', 'The api at ' + API_URL + ' did not answer ' +
        '(' + error.message + '), so the backend call path will not work. ' +
        'Browser-direct calls are unaffected.');
    log.debug("Leaving loadApiLimits(). No answer.");
    return null;
  });
}

// ---------------------------------------------------------------------------
// Pane collapse, matching the .dbg-* chrome the rest of the tree uses.
// ---------------------------------------------------------------------------
function togglePane(id) {
  log.debug("Entering togglePane(). id=" + id);
  var body = el(id + '_body');
  if (!body) {
    log.debug("Leaving togglePane(). No such pane.");
    return;
  }
  var hidden = body.style.display === 'none';
  body.style.display = hidden ? '' : 'none';
  log.debug("Leaving togglePane(). " + (hidden ? 'opened' : 'closed'));
}

function onload() {
  log.debug("Entering onload().");
  populateOperations();
  populateScenarios();
  loadState();
  refreshAuthControls();
  refreshOperationControls();
  refreshScenarioControls();
  refreshCallPathControls();
  renderChallenges();
  renderHistory();
  loadApiLimits();
  // Every field writes through on change, so a reload keeps the page a person
  // had set up — the same rule every other workflow here follows.
  REMEMBERED.concat([TOKEN_FIELD, 'scim_save_token']).forEach(function (id) {
    var e = el(id);
    if (!e) {
      return;
    }
    e.addEventListener('change', function () {
      saveState();
    });
  });
  var opSelect = el('scim_op');
  if (opSelect) {
    opSelect.addEventListener('change', refreshOperationControls);
  }
  var schemeSelect = el('scim_auth_scheme');
  if (schemeSelect) {
    schemeSelect.addEventListener('change', refreshAuthControls);
  }
  var scenarioSelect = el('scim_scenario');
  if (scenarioSelect) {
    scenarioSelect.addEventListener('change', refreshScenarioControls);
  }
  ['scim_base_url', 'scim_op_id', 'scim_query_filter', 'scim_query_count',
   'scim_query_start_index', 'scim_query_sort_by', 'scim_query_sort_order',
   'scim_query_attributes', 'scim_query_excluded_attributes'].forEach(
    function (id) {
      var e = el(id);
      if (e) {
        e.addEventListener('input', refreshRequestPreview);
      }
    });
  log.debug("Leaving onload().");
}

window.onload = onload;

module.exports = {
  // The inline handlers on scim.html.
  onload: onload,
  togglePane: togglePane,
  runOperation: runOperation,
  useLastId: useLastId,
  generateBodyForOperation: generateBodyForOperation,
  generateUsers: generateUsers,
  generateGroup: generateGroup,
  useGeneratedBody: useGeneratedBody,
  planScenario: planScenario,
  runScenario: runScenario,
  stopScenario: stopScenario,
  readServiceProviderConfig: readServiceProviderConfig,
  readSchemas: readSchemas,
  readResourceTypes: readResourceTypes,
  probeAuthentication: probeAuthentication,
  generateHobaKey: generateHobaKey,
  registerHobaKey: registerHobaKey,
  openSignIn: openSignIn,
  saveState: saveState,
  // Reached by tests/scim_page.js, which asserts what the page composes rather
  // than only what came back — the difference between "the request was wrong"
  // and "the button did nothing".
  currentRequest: currentRequest,
  callVia: callVia,
  refreshRequestPreview: refreshRequestPreview
};
