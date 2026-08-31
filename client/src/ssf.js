// File: ssf.js
//
// ---------------------------------------------------------------------------
// THE SHARED SIGNALS (SSF) DEBUGGER PAGE, AND NOTHING ELSE.
//
// This file is the DOM. Everything that is a decision about the protocol is in
// `ssf_client.js` (the pipe: subjects, the SET envelope, streams, both
// deliveries), `ssf_events.js` (the vocabulary — the one file CAEP and RISC
// will change), `ssf_history.js` (the two histories) and `jws.js` (every
// signature). That split is the rule `scim.js`, `digital_signature.js` and
// `encryption_tools.js` follow, and it is what lets `tests/ssf_engine.js`
// assert the interesting half in node with no browser at all: the defects that
// matter in this protocol are never crashes — a subject with an extra member,
// an `exp` on a SET, `events_requested` read back as `events_delivered` — and
// none of them is visible from a page that agrees with itself.
//
// ---------------------------------------------------------------------------
// TWO CALL PATHS, AND THE ONE ASYMMETRY THAT CANNOT BE DESIGNED AWAY.
//
// Every call this page makes can go two ways, exactly as the SCIM page's can:
// FRONTEND is a `fetch` from this browser, BACKEND goes through the api's
// `POST /ssf/call`. The browser path is the default and works with no api at
// all, which is why this page ships to the hosted static sites; the api path
// exists for CORS, for a self-signed certificate, and because only the api can
// report the whole exchange. **On a build with no api the BackEnd option is
// disabled and says why**, which is the same trade `pki.html`'s TLS pane and
// `scim.html`'s `callPath` row make.
//
// **RECEIVING IS WHERE THE TWO STOP BEING INTERCHANGEABLE.** RFC 8936 poll
// delivery has the receiver come to the transmitter, which a page can do. RFC
// 8935 push delivery has the transmitter POST to the receiver, and **a browser
// cannot be an HTTP server**. That is a property of the specifications, not of
// this tool, and no amount of proxying changes it — so the api hosts an inbox
// on this page's behalf (`api/ssf_receiver.js`) and this page puts its URL on
// the stream. With no api there is no push, and the page says so rather than
// offering a stream that would silently deliver nothing.
//
// ---------------------------------------------------------------------------
// WHAT IS AND IS NOT WRITTEN TO STORAGE.
//
// The ordinary settings go to `localStorage` like every other page here. THE
// CREDENTIALS DO NOT: the access token, the ID Token, the Basic password, the
// transmitting private key and the `delivery.authorization_header` are all
// absent from `REMEMBERED` and are never written anywhere.
//
// The two histories are `ssf_history.js`'s and it argues the split at length:
// the TOKEN history is `sessionStorage`, because a token is a credential this
// workflow is using to drive somebody's control plane; the MESSAGE history is
// `localStorage`, because a Security Event Token is EVIDENCE rather than a
// credential — holding one grants nothing — and evidence is what a debugger
// most needs to survive a navigation.
// ---------------------------------------------------------------------------

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var ssfClient = require("./ssf_client");
var ssfEvents = require("./ssf_events");
var ssfHistory = require("./ssf_history");
var handoff = require("./token_handoff");
var opHistory = require("./op_history");
var jws = require("./jws");

var log = bunyan.createLogger({ name: 'ssf', level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());

var API_URL = appconfig.apiUrl || '';
var BACKEND_AVAILABLE = appconfig.backendAvailable !== false;

// Fields written to localStorage. THE CREDENTIALS ARE NOT HERE — see the
// header. `ssf_access_token`, `ssf_id_token`, `ssf_basic_password`,
// `ssf_tx_private_key` and `ssf_stream_auth_header` are deliberately absent.
var REMEMBERED = [
  'ssf_base_url', 'ssf_stream_aud', 'ssf_stream_delivery',
  'ssf_stream_format', 'ssf_stream_description', 'ssf_stream_endpoint',
  'ssf_stream_id', 'ssf_subject_format', 'ssf_subject_json',
  'ssf_status_value', 'ssf_status_reason', 'ssf_verify_state',
  'ssf_poll_max', 'ssf_tx_type', 'ssf_tx_alg', 'ssf_tx_iss', 'ssf_tx_aud',
  'ssf_tx_txn', 'ssf_tx_media', 'ssf_tx_payload', 'ssf_tx_subject',
  'ssf_tx_endpoint', 'ssf_auth_scheme', 'ssf_basic_user', 'ssf_verify_alg'
];

// The operations log. `classPrefix` is `ssf` because this page does not link
// css/saml_common.css — a `saml-*` class on a page that never loaded that
// sheet is exactly what checkStylesheetsLoaded() in tests/navigation.js fails
// on, which is the mistake the Kerberos pages made when they first reused this
// module.
var operations = opHistory.createHistory({
  storeKey: 'ssf_operation_history',
  classPrefix: 'ssf',
  resultClasses: { ok: 'ssf-ok', bad: 'ssf-bad', pending: 'ssf-pending' },
  emptyText: 'No calls recorded yet.',
  columns: [
    { key: 'operation', label: 'Operation' },
    { key: 'target', label: 'Endpoint', className: 'ssf-history-uri' },
    { key: 'stream', label: 'Stream', className: 'ssf-jti' }
  ]
});

// What the api said it would do, or null where there is no api. Read once on
// load: it is also how the page knows there IS an api, which is a stronger
// signal than a configuration flag because it is the api itself saying so.
var apiLimits = null;

// The metadata document, as fetched. Every endpoint below comes out of it.
var metadata = null;

// The push inbox the api is holding for this page, or null.
var inbox = null;

// How many events this page has already collected from that inbox — the
// cursor `GET /ssf/receiver/:id/events` takes. Kept here rather than in
// storage: an inbox does not survive a reload either.
var inboxSeen = 0;

// The id of the token set in use, so a call can be recorded against it.
var currentTokenId = '';

// ---------------------------------------------------------------------------
// Small DOM helpers. Every readout on this page is a `textarea` or a text
// node and NEVER `innerHTML` of something that arrived over the network — a
// transmitter's `description` is somebody else's bytes, and this page draws
// several of them.
// ---------------------------------------------------------------------------
function el(id) {
  return document.getElementById(id);
}

function val(id) {
  var node = el(id);
  return node ? String(node.value || '') : '';
}

function setVal(id, value) {
  var node = el(id);
  if (node) {
    node.value = value == null ? '' : String(value);
  }
}

function isOn(id) {
  var node = el(id);
  return !!(node && node.checked);
}

function show(id, visible) {
  var node = el(id);
  if (!node) {
    return;
  }
  if (visible) {
    node.classList.remove('ssf-hidden');
  } else {
    node.classList.add('ssf-hidden');
  }
}

function setText(id, text, cls) {
  var node = el(id);
  if (!node) {
    return;
  }
  node.textContent = text == null ? '' : String(text);
  if (cls) {
    node.className = cls;
  }
}

function setStatus(id, text, kind) {
  var node = el(id);
  if (!node) {
    return;
  }
  node.value = text == null ? '' : String(text);
  node.classList.remove('ssf-ok', 'ssf-bad', 'ssf-pending');
  if (kind) {
    node.classList.add('ssf-' + kind);
  }
}

// Build an element with text in it. Used everywhere a value that came off the
// network is drawn, which is the whole page.
function node(tag, cls, text) {
  var made = document.createElement(tag);
  if (cls) {
    made.className = cls;
  }
  if (text !== undefined && text !== null) {
    made.textContent = String(text);
  }
  return made;
}

function clear(id) {
  var host = el(id);
  if (host) {
    while (host.firstChild) {
      host.removeChild(host.firstChild);
    }
  }
  return host;
}

function pretty(value) {
  try {
    return JSON.stringify(value, null, 2);
  } catch (e) {
    // A cycle, which nothing here should produce — but a readout that threw
    // would take the whole render with it.
    return String(value);
  }
}

// ---------------------------------------------------------------------------
// STATE.
// ---------------------------------------------------------------------------
function saveState() {
  log.debug("Entering saveState().");
  try {
    REMEMBERED.forEach(function (id) {
      var v = val(id);
      if (v) {
        localStorage.setItem(id, v);
      } else {
        localStorage.removeItem(id);
      }
    });
    localStorage.setItem('ssf_ssl_validate', isOn('ssf_ssl_validate') ? '1'
      : '0');
    localStorage.setItem('ssf_call_path', callPath());
  } catch (e) {
    // No storage for this origin. Every field still works; nothing is kept.
    log.debug("saveState(): no storage — " + e.message);
  }
  log.debug("Leaving saveState().");
}

function loadState() {
  log.debug("Entering loadState().");
  try {
    REMEMBERED.forEach(function (id) {
      var stored = localStorage.getItem(id);
      if (stored !== null && el(id)) {
        setVal(id, stored);
      }
    });
    var ssl = localStorage.getItem('ssf_ssl_validate');
    if (ssl !== null && el('ssf_ssl_validate')) {
      el('ssf_ssl_validate').checked = ssl !== '0';
    }
  } catch (e) {
    log.debug("loadState(): no storage — " + e.message);
  }
  if (!val('ssf_base_url')) {
    setVal('ssf_base_url', appconfig.ssfTransmitterUrlDefault || '');
  }
  log.debug("Leaving loadState().");
}

function callPath() {
  log.debug("Entering callPath().");
  var chosen = isOn('ssf_cfg_callPath_api') && BACKEND_AVAILABLE
    ? 'api' : 'browser';
  log.debug("Leaving callPath(). " + chosen);
  return chosen;
}

// The `callPath` row is the ONE control this page disables on a static
// deployment, and it is disabled the way `pki.js` disables its TLS pane:
// switched off rather than merely marked. A radio that only LOOKS grey is
// still selectable with a keyboard, and the refusal would then come from a
// fetch to an api that is not there — which reads as a broken page rather than
// as a build without a backend.
function applyBackendAvailability() {
  log.debug("Entering applyBackendAvailability().");
  var radio = el('ssf_cfg_callPath_api');
  var row = el('ssf_config_callpath_row');
  if (BACKEND_AVAILABLE) {
    log.debug("Leaving applyBackendAvailability(). There is an api.");
    return;
  }
  if (radio) {
    radio.checked = false;
    radio.disabled = true;
  }
  if (el('ssf_cfg_callPath_browser')) {
    el('ssf_cfg_callPath_browser').checked = true;
  }
  if (row) {
    row.classList.add('ssf-path-disabled');
  }
  setText('ssf_callpath_note',
    'This build has no api behind it, so every call is made by this browser. ' +
    'What that costs: a transmitter that sends no CORS headers cannot be ' +
    'reached, a self-signed certificate is refused before this page sees ' +
    'anything, and the exchange below is only the half a browser can see. ' +
    'It also means PUSH delivery is unavailable — a page cannot be an HTTP ' +
    'server, and there is no api here to host an endpoint on its behalf. ' +
    'POLL delivery needs none of that and works exactly as it does ' +
    'anywhere.');
  show('ssf_callpath_note', true);
  show('ssf_inbox_row', false);
  log.debug("Leaving applyBackendAvailability(). No api.");
}

// The credential row follows the scheme, because a password box on a page
// where Bearer is selected is a control with no effect — and this page's
// Basic fields are the ONE pair on it that is never written to storage, so a
// reader who cannot see them cannot tell that from a field that is simply
// empty.
function authSchemeChanged() {
  log.debug("Entering authSchemeChanged().");
  show('ssf_basic_row', val('ssf_auth_scheme') === 'basic');
  saveState();
  log.debug("Leaving authSchemeChanged().");
  return false;
}

function setCallPath(which) {
  log.debug("Entering setCallPath(). " + which);
  if (which === 'api' && !BACKEND_AVAILABLE) {
    if (el('ssf_cfg_callPath_browser')) {
      el('ssf_cfg_callPath_browser').checked = true;
    }
    log.debug("Leaving setCallPath(). Refused: no api.");
    return false;
  }
  saveState();
  log.debug("Leaving setCallPath().");
  return false;
}

// ---------------------------------------------------------------------------
// THE ONE CALL FUNCTION.
//
// Both paths, one signature, one exchange record. Everything on this page goes
// through it, which is what makes "which path was that call on" answerable at
// all — and what keeps the operations log honest, since a call that never left
// the page is recorded as a Failure rather than as a Sent that never resolves.
//
// It returns `{ ok, status, body, text, err, description, exchange }` and
// NEVER rejects: a rejected promise here would have to be caught at twenty
// call sites and the twenty-first added later would not be.
// ---------------------------------------------------------------------------
function authHeaders() {
  log.debug("Entering authHeaders().");
  var headers = {};
  var scheme = val('ssf_auth_scheme');
  if (scheme === 'bearer') {
    var token = val('ssf_access_token').trim();
    if (token) {
      headers.Authorization = 'Bearer ' + token;
    }
  } else if (scheme === 'basic') {
    var user = val('ssf_basic_user');
    var password = val('ssf_basic_password');
    if (user) {
      headers.Authorization = 'Basic ' + btoa(user + ':' + password);
    }
  }
  log.debug("Leaving authHeaders(). " + Object.keys(headers).length);
  return headers;
}

function request(options) {
  log.debug("Entering request(). " + options.method + " " + options.url);
  var asked = options || {};
  var startedAt = Date.now();
  var headers = Object.assign({}, authHeaders(), asked.headers || {});
  var body = asked.body === undefined || asked.body === null ? null
    : (typeof asked.body === 'string' ? asked.body
      : JSON.stringify(asked.body));
  if (body !== null && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }
  if (!headers.Accept) {
    headers.Accept = 'application/json';
  }
  if (callPath() === 'api') {
    log.debug("Leaving request(). Through the api.");
    return requestThroughApi(asked, headers, body, startedAt);
  }
  log.debug("Leaving request(). From this browser.");
  return requestFromBrowser(asked, headers, body, startedAt);
}

function requestFromBrowser(asked, headers, body, startedAt) {
  log.debug("Entering requestFromBrowser().");
  var init = { method: asked.method, headers: headers };
  if (body !== null) {
    init.body = body;
  }
  return fetch(asked.url, init).then(function (response) {
    return response.text().then(function (text) {
      var parsed = null;
      if (text) {
        try {
          parsed = JSON.parse(text);
        } catch (e) {
          // Not JSON. On this protocol that is usually a 204 with a body a
          // proxy added, or an HTML error page from something in front of the
          // transmitter, and the TEXT is the diagnosis.
          parsed = null;
        }
      }
      var out = {
        ok: response.status >= 200 && response.status < 300,
        status: response.status,
        body: parsed,
        text: text,
        err: parsed && parsed.err ? String(parsed.err) : '',
        description: parsed && parsed.description
          ? String(parsed.description) : '',
        exchange: {
          method: asked.method,
          url: asked.url,
          status: response.status,
          elapsedMs: Date.now() - startedAt,
          requestHeaders: headers,
          // WHAT A BROWSER CAN SEE, which is not the whole. CORS hides every
          // response header but the handful on the safelist unless the server
          // names them in Access-Control-Expose-Headers, and the browser adds
          // several to the request that this page never gets to look at. Said
          // out loud rather than presented as a complete list.
          responseHeaders: browserResponseHeaders(response),
          requestBody: body === null ? '' : body,
          responseBody: text,
          path: 'browser'
        }
      };
      log.debug("Leaving requestFromBrowser(). " + out.status);
      return out;
    });
  }).catch(function (e) {
    // `TypeError: Failed to fetch` and nothing else — which is
    // indistinguishable from a DNS failure, a dead host, a bad certificate
    // and a CORS refusal. Saying WHICH is impossible from here and pretending
    // otherwise would be worse than naming the four.
    log.debug("Leaving requestFromBrowser(). It did not complete.");
    return {
      ok: false, status: 0, body: null, text: '', err: '',
      description: 'This browser could not complete the request: ' +
        e.message + '. From a page, that one message covers four different ' +
        'things — the transmitter sent no CORS headers, its certificate is ' +
        'not trusted, the host is unreachable, or DNS failed — and nothing ' +
        'here can tell them apart. ' + (BACKEND_AVAILABLE
          ? 'Switch callPath to BackEnd: the api has no CORS to satisfy, can ' +
            'be told to ignore a certificate, and reports what actually ' +
            'happened.'
          : 'This build has no api to fall back to.'),
      exchange: {
        method: asked.method, url: asked.url, status: 0,
        elapsedMs: Date.now() - startedAt, requestHeaders: headers,
        responseHeaders: {}, requestBody: body === null ? '' : body,
        responseBody: '', path: 'browser', error: e.message
      }
    };
  });
}

function browserResponseHeaders(response) {
  log.debug("Entering browserResponseHeaders().");
  var out = {};
  try {
    response.headers.forEach(function (value, name) {
      out[name] = value;
    });
  } catch (e) {
    // Some very old browsers have no iterable Headers. An empty set is
    // honest; a thrown render is not.
    log.debug("browserResponseHeaders(): not iterable.");
  }
  log.debug("Leaving browserResponseHeaders(). " + Object.keys(out).length);
  return out;
}

function requestThroughApi(asked, headers, body, startedAt) {
  log.debug("Entering requestThroughApi().");
  return fetch(API_URL + '/ssf/call', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      url: asked.url,
      method: asked.method,
      headers: headers,
      body: body === null ? undefined : body,
      sslValidate: isOn('ssf_ssl_validate'),
      http_trace: true
    })
  }).then(function (response) {
    return response.json().then(function (answer) {
      if (response.status === 400 || response.status === 502) {
        // The api refusing (400) or failing to reach the transmitter (502).
        // Neither is an SSF answer, and reporting either as one would make a
        // network failure look like a refusal by the far end.
        log.debug("Leaving requestThroughApi(). The api answered " +
            response.status + ".");
        return {
          ok: false, status: 0, body: null, text: '', err: '',
          description: String(answer.error || 'The api refused the call.'),
          exchange: apiExchange(asked, answer, headers, body, startedAt)
        };
      }
      log.debug("Leaving requestThroughApi(). " + answer.status);
      return {
        ok: answer.ok === true,
        status: Number(answer.status) || 0,
        body: answer.body || null,
        text: String(answer.rawBody || ''),
        err: String(answer.err || ''),
        description: String(answer.description || ''),
        exchange: apiExchange(asked, answer, headers, body, startedAt)
      };
    });
  }).catch(function (e) {
    log.debug("Leaving requestThroughApi(). The api could not be reached.");
    return {
      ok: false, status: 0, body: null, text: '', err: '',
      description: 'The api could not be reached: ' + e.message,
      exchange: { method: asked.method, url: asked.url, status: 0,
        elapsedMs: Date.now() - startedAt, requestHeaders: headers,
        responseHeaders: {}, requestBody: body === null ? '' : body,
        responseBody: '', path: 'api', error: e.message }
    };
  });
}

// The api returns the whole exchange under `http_exchange` when it is asked
// with `http_trace: true`. Where it did not — an older api, or a refusal
// before the call was made — the fallback is this page's own call TO the api,
// and it says which: a fallback that looked like the real thing would be a
// debugger showing the wrong URL with a straight face.
function apiExchange(asked, answer, headers, body, startedAt) {
  log.debug("Entering apiExchange().");
  if (answer && answer.http_exchange) {
    var trace = answer.http_exchange;
    trace.path = 'api';
    log.debug("Leaving apiExchange(). The api's own trace.");
    return trace;
  }
  log.debug("Leaving apiExchange(). This page's call to the api.");
  return {
    method: asked.method, url: asked.url,
    status: Number((answer || {}).status) || 0,
    elapsedMs: Date.now() - startedAt,
    requestHeaders: headers, responseHeaders: {},
    requestBody: body === null ? '' : body,
    responseBody: String((answer || {}).rawBody || ''),
    path: 'api',
    note: 'The api returned no trace of its own, so this is THIS PAGE\'s ' +
      'call to the api rather than the api\'s call to the transmitter. The ' +
      'URL above is the one that was asked for; the headers and the timing ' +
      'are this hop\'s.'
  };
}

function drawExchange(exchange) {
  log.debug("Entering drawExchange().");
  if (!exchange) {
    setVal('ssf_exchange', 'Nothing has been sent yet.');
    log.debug("Leaving drawExchange(). Nothing.");
    return;
  }
  var lines = [];
  lines.push('# ' + (exchange.path === 'api'
    ? 'Made by the api (BackEnd call path)'
    : 'Made by this browser (FrontEnd call path)'));
  if (exchange.note) {
    lines.push('# ' + exchange.note);
  }
  if (exchange.path === 'browser') {
    lines.push('# A browser withholds the headers it adds, and CORS hides ' +
      'every response header but the safelist unless the server names it in ' +
      'Access-Control-Expose-Headers. What follows is what this page could ' +
      'see.');
  }
  lines.push('');
  lines.push(exchange.method + ' ' + exchange.url);
  Object.keys(exchange.requestHeaders || {}).forEach(function (name) {
    var value = exchange.requestHeaders[name];
    lines.push(name + ': ' + (/^authorization$/i.test(name)
      ? '(sent — not shown)' : value));
  });
  if (exchange.requestBody) {
    lines.push('');
    lines.push(exchange.requestBody);
  }
  lines.push('');
  lines.push('--- ' + (exchange.status || 'no response') + ' in ' +
    (exchange.elapsedMs || 0) + 'ms ---');
  Object.keys(exchange.responseHeaders || {}).forEach(function (name) {
    lines.push(name + ': ' + exchange.responseHeaders[name]);
  });
  if (exchange.responseBody) {
    lines.push('');
    lines.push(exchange.responseBody);
  } else {
    lines.push('');
    lines.push('(no body — which on this protocol is usually a SUCCESS: Add ' +
      'Subject, Remove Subject and the verification endpoint all answer 204 ' +
      'with nothing in them.)');
  }
  if (exchange.error) {
    lines.push('');
    lines.push('The request did not complete: ' + exchange.error);
  }
  setVal('ssf_exchange', lines.join('\n'));
  log.debug("Leaving drawExchange().");
}

// One place records a call, so the operations log cannot disagree with the
// status line beside a button.
function recordCall(operation, url, streamId) {
  log.debug("Entering recordCall(). " + operation);
  var id = operations.record({ operation: operation, target: url,
    stream: streamId || '', result: operations.SENT });
  if (currentTokenId) {
    ssfHistory.noteTokenUse(currentTokenId, operation +
      (streamId ? ' on ' + streamId : ''));
  }
  log.debug("Leaving recordCall(). " + id);
  return id;
}

function settleCall(id, result, detail) {
  log.debug("Entering settleCall(). " + result);
  operations.update(id, result, detail || '');
  renderOperations();
  log.debug("Leaving settleCall().");
}

function renderOperations() {
  log.debug("Entering renderOperations().");
  operations.render(el('ssf_history'));
  log.debug("Leaving renderOperations().");
}

function clearOperations() {
  log.debug("Entering clearOperations().");
  operations.clear();
  renderOperations();
  log.debug("Leaving clearOperations().");
  return false;
}

// ---------------------------------------------------------------------------
// THE TOKEN HAND-OFF, AND WHO YOU ARE.
// ---------------------------------------------------------------------------
function startTokenHandoff() {
  log.debug("Entering startTokenHandoff().");
  saveState();
  var started = handoff.start({
    returnUrl: '/ssf.html',
    label: 'the Shared Signals workflow'
  });
  if (!started) {
    setText('ssf_token_handoff_note',
      'The handoff could not be started — this browser has no session ' +
      'storage for this origin, so a token cannot be carried back ' +
      'automatically. Run the OAuth2 / OIDC workflow and paste the tokens ' +
      'above.', 'ssf-bad');
    log.debug("Leaving startTokenHandoff(). Not recorded.");
    return false;
  }
  setText('ssf_token_handoff_note', 'Going to the OAuth2 / OIDC workflow…');
  window.location.href = '/oauth2_oidc_1.html';
  log.debug("Leaving startTokenHandoff().");
  return false;
}

// Collect whatever the OAuth2 / OIDC workflow left, on load. `take()` clears
// the slot whether or not there was anything in it.
function collectHandedTokens() {
  log.debug("Entering collectHandedTokens().");
  var taken = handoff.take();
  if (taken.expired) {
    setText('ssf_token_handoff_note',
      'A token was handed back by the OAuth2 / OIDC workflow more than half ' +
      'an hour ago and has not been used, so it was dropped rather than ' +
      'filled in here. Ask for another.', 'ssf-pending');
    log.debug("Leaving collectHandedTokens(). Expired.");
    return;
  }
  if (!taken.token) {
    log.debug("Leaving collectHandedTokens(). Nothing waiting.");
    return;
  }
  setVal('ssf_access_token', taken.token);
  var set = taken.set || {};
  if (set.idToken) {
    setVal('ssf_id_token', set.idToken);
  }
  setText('ssf_token_handoff_note',
    'These tokens came back from the OAuth2 / OIDC workflow — from ' +
    (taken.source || 'that workflow') + '. They are held for this tab only ' +
    'and are not written to localStorage.', 'ssf-ok');
  rememberTokenSet('the OAuth2 / OIDC workflow — ' +
    (taken.source || 'a hand-off'), set);
  log.debug("Leaving collectHandedTokens(). Filled in.");
}

// Read a JWT's claims WITHOUT verifying anything. This is an ID Token this
// page was handed by its own other half; verifying it here would be verifying
// a token this workflow does not consume, and the JWT Tools page is where that
// question is asked properly.
function claimsOf(token) {
  log.debug("Entering claimsOf().");
  var parsed = ssfClient.parseSet(token);
  log.debug("Leaving claimsOf(). " + (parsed.ok ? 'read' : parsed.problem));
  return parsed.ok ? parsed.claims : null;
}

function rememberTokenSet(source, set) {
  log.debug("Entering rememberTokenSet().");
  var idToken = (set && set.idToken) || val('ssf_id_token');
  var claims = idToken ? claimsOf(idToken) : null;
  currentTokenId = ssfHistory.recordTokens({
    source: source,
    accessToken: val('ssf_access_token'),
    idToken: idToken,
    refreshToken: (set && set.refreshToken) || '',
    tokenType: (set && set.tokenType) || '',
    scope: (set && set.scope) || '',
    expiresIn: (set && set.expiresIn) || 0,
    subject: claims ? String(claims.sub || '') : '',
    subjectName: claims
      ? String(claims.name || claims.preferred_username ||
          claims.email || '') : '',
    issuer: claims ? String(claims.iss || '') : '',
    audience: claims ? String(claims.aud || '') : ''
  });
  renderIdentity(claims);
  renderTokenHistory();
  log.debug("Leaving rememberTokenSet(). " + currentTokenId);
}

function readPastedTokens() {
  log.debug("Entering readPastedTokens().");
  rememberTokenSet('pasted into this page', {});
  saveState();
  log.debug("Leaving readPastedTokens().");
  return false;
}

// WHO THE AUTHENTICATED USER IS. It is read off the ID Token, and the page
// says WHERE it read it from — a bearer token this service issued is opaque to
// a client, so a page that named a user without saying how would be inviting
// somebody to believe the access token said it.
function renderIdentity(claims) {
  log.debug("Entering renderIdentity().");
  var host = clear('ssf_identity');
  if (!host) {
    log.debug("Leaving renderIdentity(). No host.");
    return;
  }
  if (!claims) {
    host.appendChild(node('p', 'ssf-note',
      val('ssf_access_token')
        ? 'An access token is held and there is no ID Token to read, so this ' +
          'page cannot say who you are. An access token this service issues ' +
          'is opaque to a client — the identity is in the ID Token, which an ' +
          '`openid` scope is what asks for.'
        : 'No token yet. The panes below will run without one against a ' +
          'transmitter that requires none.'));
    log.debug("Leaving renderIdentity(). Nobody.");
    return;
  }
  var name = String(claims.name || claims.preferred_username ||
      claims.email || claims.sub || '(no subject claim)');
  host.appendChild(node('div', 'ssf-identity-who',
    'Signed in as ' + name));
  var rows = [
    ['sub', claims.sub],
    ['iss', claims.iss],
    ['aud', claims.aud],
    ['email', claims.email],
    ['preferred_username', claims.preferred_username],
    ['auth_time', claims.auth_time],
    ['sid', claims.sid]
  ].filter(function (row) {
    return row[1] !== undefined && row[1] !== null && row[1] !== '';
  });
  var table = node('table', 'ssf-table');
  rows.forEach(function (row) {
    var tr = node('tr');
    tr.appendChild(node('td', null, row[0]));
    tr.appendChild(node('td', 'ssf-uri', String(row[1])));
    table.appendChild(tr);
  });
  host.appendChild(table);
  host.appendChild(node('p', 'ssf-note',
    'Read from the ID Token, and NOT verified here: this workflow does not ' +
    'consume an ID Token, so checking its signature would be answering a ' +
    'question nothing on this page asks. The JWT Tools page is where that ' +
    'is done properly.'));
  log.debug("Leaving renderIdentity(). " + name);
}

function renderTokenHistory() {
  log.debug("Entering renderTokenHistory().");
  var host = clear('ssf_token_history');
  if (!host) {
    log.debug("Leaving renderTokenHistory(). No host.");
    return;
  }
  var rows = ssfHistory.tokens();
  if (!rows.length) {
    host.appendChild(node('p', 'ssf-note', 'No tokens recorded yet.'));
    log.debug("Leaving renderTokenHistory(). Empty.");
    return;
  }
  var table = node('table', 'ssf-table');
  var head = node('tr');
  ['#', 'Time (UTC)', 'Source', 'Subject', 'Scope', 'Used for'].forEach(
    function (label) {
      head.appendChild(node('th', null, label));
    });
  table.appendChild(head);
  rows.slice().reverse().forEach(function (row, index) {
    var tr = node('tr');
    tr.appendChild(node('td', null, String(rows.length - index)));
    tr.appendChild(node('td', 'ssf-history-time',
      String(row.timestamp).substring(0, 19).replace('T', ' ') + 'Z'));
    tr.appendChild(node('td', null, row.source));
    tr.appendChild(node('td', 'ssf-uri',
      row.subjectName ? row.subjectName + ' (' + row.subject + ')'
        : (row.subject || '—')));
    tr.appendChild(node('td', null, row.scope || '—'));
    tr.appendChild(node('td', null, (row.used || []).length
      ? (row.used || []).map(function (one) {
          return one.what;
        }).join('; ')
      : 'nothing yet'));
    table.appendChild(tr);
  });
  host.appendChild(table);
  host.appendChild(node('p', 'ssf-note',
    'These are the tokens THIS WORKFLOW has used, which is a different set ' +
    'from the ones the OAuth2 / OIDC page has obtained: a hand-off delivers ' +
    'one of its many, and a token pasted in here was never on that page at ' +
    'all. They are in sessionStorage and go when this tab closes.'));
  log.debug("Leaving renderTokenHistory(). " + rows.length);
}

function clearTokenHistory() {
  log.debug("Entering clearTokenHistory().");
  ssfHistory.clearTokens();
  currentTokenId = '';
  renderTokenHistory();
  log.debug("Leaving clearTokenHistory().");
  return false;
}

// ---------------------------------------------------------------------------
// DISCOVERY.
// ---------------------------------------------------------------------------
function discover() {
  log.debug("Entering discover().");
  saveState();
  var candidates = ssfClient.metadataCandidates(val('ssf_base_url'));
  if (!candidates.length) {
    setStatus('ssf_discover_status',
      'Fill in the base URL first.', 'bad');
    log.debug("Leaving discover(). No base URL.");
    return false;
  }
  setStatus('ssf_discover_status', 'Fetching…', 'pending');
  var entry = recordCall('discover', candidates[0], '');
  tryMetadata(candidates, 0, entry);
  log.debug("Leaving discover().");
  return false;
}

// Both shapes, insertion first, exactly as `metadata_client.js` tries both for
// an issuer: RFC 8414 inserts the well-known segment before the path and
// OpenID Connect Discovery appends it, and a transmitter published under a
// path can be either.
function tryMetadata(candidates, index, entry) {
  log.debug("Entering tryMetadata(). " + index);
  if (index >= candidates.length) {
    settleCall(entry, operations.FAILURE, 'no metadata document');
    setStatus('ssf_discover_status',
      'No configuration metadata at any of: ' + candidates.join(', ') +
      '. SSF publishes every endpoint in that document, so without it this ' +
      'page has nowhere to send anything — it composes no paths of its own.',
      'bad');
    log.debug("Leaving tryMetadata(). Nothing found.");
    return;
  }
  request({ method: 'GET', url: candidates[index] }).then(function (answer) {
    drawExchange(answer.exchange);
    if (!answer.ok || !answer.body) {
      log.debug("tryMetadata(): " + candidates[index] + " answered " +
          answer.status + ".");
      tryMetadata(candidates, index + 1, entry);
      return;
    }
    metadata = answer.body;
    settleCall(entry, operations.SUCCESS, 'read from ' + candidates[index]);
    renderMetadata(candidates[index]);
    log.debug("Leaving tryMetadata(). Found at " + candidates[index] + ".");
  });
}

function renderMetadata(from) {
  log.debug("Entering renderMetadata().");
  var read = ssfClient.readMetadata(metadata);
  var host = clear('ssf_metadata_table');
  if (!host) {
    log.debug("Leaving renderMetadata(). No host.");
    return;
  }
  setStatus('ssf_discover_status',
    'Read from ' + from + (read.ok ? '' : ' — and it is missing ' +
      read.missing.join(', ')), read.ok ? 'ok' : 'bad');
  var table = node('table', 'ssf-table ssf-metadata');
  var head = node('tr');
  ['Member', 'Value', 'What it is'].forEach(function (label) {
    head.appendChild(node('th', null, label));
  });
  table.appendChild(head);
  read.rows.forEach(function (row) {
    var tr = node('tr');
    tr.appendChild(node('td', 'ssf-uri', row.name +
      (row.required ? ' (required)' : '')));
    var value = node('td', 'ssf-uri');
    if (row.present) {
      value.textContent = typeof row.value === 'object'
        ? pretty(row.value) : String(row.value);
    } else {
      value.className = row.required
        ? 'ssf-metadata-missing' : 'ssf-metadata-absent';
      value.textContent = row.required
        ? 'MISSING — SSF makes this required'
        : 'not published';
    }
    tr.appendChild(value);
    tr.appendChild(node('td', null, row.what));
    table.appendChild(tr);
  });
  host.appendChild(table);
  if (read.unknown.length) {
    host.appendChild(node('p', 'ssf-metadata-extra',
      'This document also carries ' + read.unknown.join(', ') + ', which ' +
      'this build does not know. That is REPORTED rather than refused: SSF ' +
      'metadata extends, and a member here that is not in the table above ' +
      'is a transmitter doing something extra rather than something wrong.'));
  }
  host.appendChild(node('p', 'ssf-note',
    'Delivery: ' + (read.canPush ? 'push offered' : 'no push') + ', ' +
    (read.canPoll ? 'poll offered' : 'no poll') + '. An empty subject list ' +
    'on a stream here means ' + (read.defaultSubjects === 'NONE'
      ? 'NOBODY until a subject is added'
      : (read.defaultSubjects === 'ALL'
        ? 'EVERYBODY, so adding a subject narrows nothing'
        : 'whatever this transmitter decides — it publishes no ' +
          'default_subjects, which is the one member worth asking about ' +
          'because guessing wrong gets you every event in the estate or ' +
          'none')) + '.'));
  renderEventChoices(read);
  renderDeliveryChoices(read);
  log.debug("Leaving renderMetadata().");
}

// The `events_requested` checkbox column. Built from what the TRANSMITTER
// supports where it published a list, and from this build's own catalogue
// otherwise — with the difference stated, because a box offering a type the
// transmitter never mentioned is a request that will be silently dropped from
// `events_delivered`.
function renderEventChoices(read) {
  log.debug("Entering renderEventChoices().");
  var host = clear('ssf_events_requested');
  if (!host) {
    log.debug("Leaving renderEventChoices(). No host.");
    return;
  }
  var supported = [];
  if (metadata && Object.prototype.toString.call(metadata.events_supported) ===
      '[object Array]') {
    supported = metadata.events_supported.map(String);
  }
  var list = supported.length ? supported : ssfEvents.EVENT_URIS;
  list.forEach(function (uri) {
    var row = ssfEvents.EVENT_BY_URI[uri];
    var label = node('label');
    var box = document.createElement('input');
    box.type = 'checkbox';
    box.className = 'ssf-event-choice';
    box.value = uri;
    label.appendChild(box);
    label.appendChild(document.createTextNode(' ' +
      (row ? row.name + ' — ' : '') + uri +
      (row ? '' : ' (this build does not implement it)')));
    host.appendChild(label);
  });
  host.appendChild(node('p', 'ssf-note', supported.length
    ? 'From this transmitter\'s own events_supported. Leaving every box ' +
      'clear asks for all of them.'
    : 'This transmitter publishes no events_supported in its metadata, so ' +
      'these are the types THIS BUILD knows. A box ticked here for a type ' +
      'the transmitter does not have is dropped from events_delivered and ' +
      'nothing says so — which is why the Stream pane compares the two ' +
      'lists for you.'));
  log.debug("Leaving renderEventChoices(). " + list.length);
}

function renderDeliveryChoices(read) {
  log.debug("Entering renderDeliveryChoices().");
  var select = el('ssf_stream_delivery');
  if (!select) {
    log.debug("Leaving renderDeliveryChoices(). No select.");
    return;
  }
  var wanted = select.value;
  while (select.firstChild) {
    select.removeChild(select.firstChild);
  }
  ssfClient.DELIVERY_METHODS.forEach(function (row) {
    var offered = !read.deliveryMethods.length ||
      read.deliveryMethods.indexOf(row.method) >= 0;
    var option = document.createElement('option');
    option.value = row.method;
    option.textContent = row.label + ' — ' + row.method +
      (offered ? '' : ' (this transmitter does not offer it)');
    select.appendChild(option);
  });
  select.value = wanted || ssfClient.DELIVERY_POLL;
  deliveryChanged();
  log.debug("Leaving renderDeliveryChoices().");
}

// ---------------------------------------------------------------------------
// STREAMS.
// ---------------------------------------------------------------------------
function deliveryChanged() {
  log.debug("Entering deliveryChanged().");
  var push = val('ssf_stream_delivery') === ssfClient.DELIVERY_PUSH;
  show('ssf_push_row', push);
  show('ssf_push_auth_row', push);
  if (push && !BACKEND_AVAILABLE) {
    setStatus('ssf_stream_status_text',
      'Push delivery needs an endpoint a TRANSMITTER can reach, and a ' +
      'browser is not an HTTP server. This build has no api to host one, so ' +
      'a push stream created here would be agreed and would silently ' +
      'deliver nothing. Poll delivery works exactly as it does anywhere.',
      'pending');
  }
  saveState();
  log.debug("Leaving deliveryChanged(). push=" + push);
  return false;
}

function requestedEvents() {
  log.debug("Entering requestedEvents().");
  var out = [];
  var boxes = document.querySelectorAll('.ssf-event-choice');
  var i;
  for (i = 0; i < boxes.length; i++) {
    if (boxes[i].checked) {
      out.push(boxes[i].value);
    }
  }
  log.debug("Leaving requestedEvents(). " + out.length);
  return out;
}

function streamBody(withId) {
  log.debug("Entering streamBody().");
  var body = ssfClient.buildStreamConfiguration({
    aud: val('ssf_stream_aud'),
    events_requested: requestedEvents(),
    deliveryMethod: val('ssf_stream_delivery'),
    endpointUrl: val('ssf_stream_endpoint'),
    authorizationHeader: val('ssf_stream_auth_header'),
    format: val('ssf_stream_format'),
    description: val('ssf_stream_description'),
    stream_id: withId ? val('ssf_stream_id') : ''
  });
  log.debug("Leaving streamBody().");
  return body;
}

function endpoint(member) {
  log.debug("Entering endpoint(). " + member);
  var found = ssfClient.endpointFor(metadata, member);
  if (!found.ok) {
    setStatus('ssf_stream_status_text', found.error, 'bad');
  }
  log.debug("Leaving endpoint(). " + (found.ok ? found.url : 'none'));
  return found;
}

function createStream() {
  log.debug("Entering createStream().");
  saveState();
  var where = endpoint('configuration_endpoint');
  if (!where.ok) {
    log.debug("Leaving createStream(). No endpoint.");
    return false;
  }
  var body = streamBody(false);
  var check = ssfClient.checkStreamConfiguration(body, metadata);
  if (!check.ok) {
    setStatus('ssf_stream_status_text', check.errors.join(' '), 'bad');
    log.debug("Leaving createStream(). Refused here.");
    return false;
  }
  if (check.warnings.length) {
    setStatus('ssf_stream_status_text', check.warnings.join(' '), 'pending');
  }
  var entry = recordCall('create stream', where.url, '');
  request({ method: 'POST', url: where.url, body: body })
    .then(function (answer) {
      drawExchange(answer.exchange);
      if (!answer.ok) {
        settleCall(entry, operations.FAILURE, refusal(answer));
        setStatus('ssf_stream_status_text', refusal(answer), 'bad');
        log.debug("Leaving createStream(). Refused.");
        return;
      }
      var read = ssfClient.readStreamConfiguration(answer.body, body);
      setVal('ssf_stream_id', read.streamId);
      saveState();
      settleCall(entry, operations.SUCCESS, read.streamId);
      setStatus('ssf_stream_status_text',
        'Created ' + read.streamId + '.', 'ok');
      notePollEndpoint(read);
      renderStream(read);
      log.debug("Leaving createStream(). " + read.streamId);
    });
  return false;
}

function readStream() {
  log.debug("Entering readStream().");
  var where = endpoint('configuration_endpoint');
  if (!where.ok) {
    log.debug("Leaving readStream(). No endpoint.");
    return false;
  }
  var id = val('ssf_stream_id');
  var url = id ? where.url + '?stream_id=' + encodeURIComponent(id)
    : where.url;
  var entry = recordCall('read stream', url, id);
  request({ method: 'GET', url: url }).then(function (answer) {
    drawExchange(answer.exchange);
    if (!answer.ok) {
      settleCall(entry, operations.FAILURE, refusal(answer));
      setStatus('ssf_stream_status_text', refusal(answer), 'bad');
      log.debug("Leaving readStream(). Refused.");
      return;
    }
    settleCall(entry, operations.SUCCESS, '');
    if (Object.prototype.toString.call(answer.body) === '[object Array]') {
      renderStreamList(answer.body);
      setStatus('ssf_stream_status_text',
        answer.body.length + ' stream(s).', 'ok');
      log.debug("Leaving readStream(). A list.");
      return;
    }
    var read = ssfClient.readStreamConfiguration(answer.body, {});
    setStatus('ssf_stream_status_text', 'Read ' + read.streamId + '.', 'ok');
    notePollEndpoint(read);
    renderStream(read);
    log.debug("Leaving readStream(). One stream.");
  });
  return false;
}

function updateStream(method, label) {
  log.debug("Entering updateStream(). " + method);
  saveState();
  var where = endpoint('configuration_endpoint');
  if (!where.ok) {
    log.debug("Leaving updateStream(). No endpoint.");
    return false;
  }
  var id = val('ssf_stream_id');
  if (!id) {
    setStatus('ssf_stream_status_text',
      'There is no stream_id to ' + label + '. Create one first, or paste ' +
      'the id of one this transmitter already holds.', 'bad');
    log.debug("Leaving updateStream(). No id.");
    return false;
  }
  var body = streamBody(true);
  var entry = recordCall(label + ' stream', where.url, id);
  request({ method: method, url: where.url, body: body })
    .then(function (answer) {
      drawExchange(answer.exchange);
      if (!answer.ok) {
        settleCall(entry, operations.FAILURE, refusal(answer));
        setStatus('ssf_stream_status_text', refusal(answer), 'bad');
        log.debug("Leaving updateStream(). Refused.");
        return;
      }
      settleCall(entry, operations.SUCCESS, '');
      var read = ssfClient.readStreamConfiguration(answer.body, body);
      notePollEndpoint(read);
      setStatus('ssf_stream_status_text',
        (method === 'PUT'
          ? 'Replaced. Every member this page left empty went back to its ' +
            'default, which is what makes a PUT different from a PATCH.'
          : 'Merged. Only what was filled in changed.'), 'ok');
      renderStream(read);
      log.debug("Leaving updateStream(). " + method);
    });
  return false;
}

function replaceStream() {
  log.debug("Entering replaceStream().");
  var out = updateStream('PUT', 'replace');
  log.debug("Leaving replaceStream().");
  return out;
}

function mergeStream() {
  log.debug("Entering mergeStream().");
  var out = updateStream('PATCH', 'merge');
  log.debug("Leaving mergeStream().");
  return out;
}

function deleteStream() {
  log.debug("Entering deleteStream().");
  var where = endpoint('configuration_endpoint');
  if (!where.ok) {
    log.debug("Leaving deleteStream(). No endpoint.");
    return false;
  }
  var id = val('ssf_stream_id');
  if (!id) {
    setStatus('ssf_stream_status_text', 'There is no stream_id to delete.',
      'bad');
    log.debug("Leaving deleteStream(). No id.");
    return false;
  }
  var entry = recordCall('delete stream', where.url, id);
  request({ method: 'DELETE', url: where.url, body: { stream_id: id } })
    .then(function (answer) {
      drawExchange(answer.exchange);
      if (!answer.ok) {
        settleCall(entry, operations.FAILURE, refusal(answer));
        setStatus('ssf_stream_status_text', refusal(answer), 'bad');
        log.debug("Leaving deleteStream(). Refused.");
        return;
      }
      settleCall(entry, operations.SUCCESS, '');
      setStatus('ssf_stream_status_text',
        'Deleted ' + id + '. The transmitter does NOT tell a receiver its ' +
        'stream is gone — SSF has no event for that — so anything still ' +
        'polling finds out with a 404.', 'ok');
      clear('ssf_stream_view');
      log.debug("Leaving deleteStream(). Deleted.");
    });
  return false;
}

function setStreamStatus() {
  log.debug("Entering setStreamStatus().");
  saveState();
  var where = endpoint('status_endpoint');
  if (!where.ok) {
    log.debug("Leaving setStreamStatus(). No endpoint.");
    return false;
  }
  var id = val('ssf_stream_id');
  var entry = recordCall('set status', where.url, id);
  request({ method: 'POST', url: where.url, body: {
    stream_id: id, status: val('ssf_status_value'),
    reason: val('ssf_status_reason') } }).then(function (answer) {
    drawExchange(answer.exchange);
    if (!answer.ok) {
      settleCall(entry, operations.FAILURE, refusal(answer));
      setStatus('ssf_stream_status_text', refusal(answer), 'bad');
      log.debug("Leaving setStreamStatus(). Refused.");
      return;
    }
    settleCall(entry, operations.SUCCESS, val('ssf_status_value'));
    setStatus('ssf_stream_status_text',
      'The stream is now ' + String((answer.body || {}).status ||
        val('ssf_status_value')) + '. A conforming transmitter also sends a ' +
      'stream-updated EVENT down the stream — poll or collect below to see ' +
      'whether this one did, which is a different assurance from this ' +
      'answer.', 'ok');
    log.debug("Leaving setStreamStatus(). Set.");
  });
  return false;
}

function getStreamStatus() {
  log.debug("Entering getStreamStatus().");
  var where = endpoint('status_endpoint');
  if (!where.ok) {
    log.debug("Leaving getStreamStatus(). No endpoint.");
    return false;
  }
  var id = val('ssf_stream_id');
  var url = where.url + '?stream_id=' + encodeURIComponent(id);
  var entry = recordCall('read status', url, id);
  request({ method: 'GET', url: url }).then(function (answer) {
    drawExchange(answer.exchange);
    if (!answer.ok) {
      settleCall(entry, operations.FAILURE, refusal(answer));
      setStatus('ssf_stream_status_text', refusal(answer), 'bad');
      log.debug("Leaving getStreamStatus(). Refused.");
      return;
    }
    settleCall(entry, operations.SUCCESS, '');
    var status = String((answer.body || {}).status || '');
    var row = ssfClient.STREAM_STATUSES.filter(function (one) {
      return one.status === status;
    })[0];
    setStatus('ssf_stream_status_text', status +
      (row ? ' — ' + row.what : ''), 'ok');
    log.debug("Leaving getStreamStatus(). " + status);
  });
  return false;
}

function verifyStream() {
  log.debug("Entering verifyStream().");
  saveState();
  var where = endpoint('verification_endpoint');
  if (!where.ok) {
    log.debug("Leaving verifyStream(). No endpoint.");
    return false;
  }
  var id = val('ssf_stream_id');
  var state = val('ssf_verify_state');
  var entry = recordCall('verify', where.url, id);
  request({ method: 'POST', url: where.url,
    body: { stream_id: id, state: state } }).then(function (answer) {
    drawExchange(answer.exchange);
    if (!answer.ok) {
      settleCall(entry, operations.FAILURE, refusal(answer));
      setStatus('ssf_stream_status_text', refusal(answer), 'bad');
      log.debug("Leaving verifyStream(). Refused.");
      return;
    }
    settleCall(entry, operations.SUCCESS, '');
    setStatus('ssf_stream_status_text',
      'The transmitter accepted the request (' + answer.status + '). THE ' +
      'EVENT IS A SEPARATE EXCHANGE and has not been seen yet — poll, or ' +
      'collect from the push inbox, to find out whether the pipe actually ' +
      'works. That is the whole point of a verification event.', 'ok');
    log.debug("Leaving verifyStream(). Asked.");
  });
  return false;
}

function refusal(answer) {
  log.debug("Entering refusal().");
  var text = answer.description ||
    (answer.err ? answer.err : '') ||
    (answer.text ? answer.text.slice(0, 300) : '');
  var out = (answer.status ? answer.status + ' ' : '') +
    (answer.err ? answer.err + ' — ' : '') +
    (text || 'the transmitter refused with no explanation');
  log.debug("Leaving refusal().");
  return out;
}

function renderStream(read) {
  log.debug("Entering renderStream().");
  var host = clear('ssf_stream_view');
  if (!host) {
    log.debug("Leaving renderStream(). No host.");
    return;
  }
  var table = node('table', 'ssf-table');
  ssfClient.STREAM_MEMBERS.forEach(function (member) {
    var value = read.raw ? read.raw[member.name] : undefined;
    var tr = node('tr');
    tr.appendChild(node('td', 'ssf-uri', member.name));
    tr.appendChild(node('td', null, member.owner));
    tr.appendChild(node('td', 'ssf-uri', value === undefined
      ? 'not set'
      : (typeof value === 'object' ? pretty(value) : String(value))));
    tr.appendChild(node('td', null, member.what));
    table.appendChild(tr);
  });
  var head = node('tr');
  ['Member', 'Whose', 'Value', 'What it is'].forEach(function (label) {
    head.appendChild(node('th', null, label));
  });
  table.insertBefore(head, table.firstChild);
  host.appendChild(table);
  read.surprises.forEach(function (text) {
    host.appendChild(node('p', 'ssf-finding ssf-finding-warn', '! ' + text));
  });
  log.debug("Leaving renderStream().");
}

function renderStreamList(rows) {
  log.debug("Entering renderStreamList().");
  var host = clear('ssf_stream_view');
  if (!host) {
    log.debug("Leaving renderStreamList(). No host.");
    return;
  }
  if (!rows.length) {
    host.appendChild(node('p', 'ssf-note',
      'This transmitter holds no streams for this credential.'));
    log.debug("Leaving renderStreamList(). Empty.");
    return;
  }
  var table = node('table', 'ssf-table');
  var head = node('tr');
  ['stream_id', 'Delivery', 'Delivers', 'Audience'].forEach(function (label) {
    head.appendChild(node('th', null, label));
  });
  table.appendChild(head);
  rows.forEach(function (row) {
    var tr = node('tr');
    tr.appendChild(node('td', 'ssf-jti', String(row.stream_id || '')));
    tr.appendChild(node('td', null,
      ssfClient.deliveryLabel((row.delivery || {}).method)));
    tr.appendChild(node('td', 'ssf-uri',
      (row.events_delivered || []).join('\n')));
    tr.appendChild(node('td', 'ssf-uri', String(row.aud || '')));
    table.appendChild(tr);
  });
  host.appendChild(table);
  log.debug("Leaving renderStreamList(). " + rows.length);
}

// ---------------------------------------------------------------------------
// SUBJECTS.
// ---------------------------------------------------------------------------
function fillSubjectFormats() {
  log.debug("Entering fillSubjectFormats().");
  var select = el('ssf_subject_format');
  var streamFormat = el('ssf_stream_format');
  if (select) {
    ssfClient.SUBJECT_FORMATS.forEach(function (row) {
      var option = document.createElement('option');
      option.value = row.format;
      option.textContent = row.label;
      select.appendChild(option);
    });
    var complex = document.createElement('option');
    complex.value = 'complex';
    complex.textContent = 'Complex subject (user, device, session, …)';
    select.appendChild(complex);
  }
  if (streamFormat) {
    ssfClient.SUBJECT_FORMATS.forEach(function (row) {
      var option = document.createElement('option');
      option.value = row.format;
      option.textContent = row.format;
      streamFormat.appendChild(option);
    });
  }
  log.debug("Leaving fillSubjectFormats().");
}

function subjectFormatChanged() {
  log.debug("Entering subjectFormatChanged().");
  var chosen = val('ssf_subject_format');
  if (chosen === 'complex') {
    setText('ssf_subject_what',
      'SSF 1.0 section 4. A complex subject has NO "format" member and ' +
      'carries any of ' + ssfClient.COMPLEX_SUBJECT_MEMBER_NAMES.join(', ') +
      ', each itself a Subject Identifier. That is what makes "this session ' +
      'was revoked" expressible at all: the person is not revoked, one ' +
      'session of theirs is — which is the distinction the whole of CAEP ' +
      'rests on.');
    log.debug("Leaving subjectFormatChanged(). Complex.");
    return false;
  }
  var row = ssfClient.SUBJECT_FORMATS.filter(function (one) {
    return one.format === chosen;
  })[0];
  setText('ssf_subject_what', row ? row.what : '');
  saveState();
  log.debug("Leaving subjectFormatChanged(). " + chosen);
  return false;
}

function fillSubjectExample() {
  log.debug("Entering fillSubjectExample().");
  var chosen = val('ssf_subject_format');
  if (chosen === 'complex') {
    setVal('ssf_subject_json', pretty({
      user: { format: 'email', email: 'alice@example.com' },
      session: { format: 'opaque', id: 'sess-0123456789' },
      device: { format: 'opaque', id: 'device-abcdef' }
    }));
    saveState();
    log.debug("Leaving fillSubjectExample(). Complex.");
    return false;
  }
  var row = ssfClient.SUBJECT_FORMATS.filter(function (one) {
    return one.format === chosen;
  })[0];
  if (row) {
    setVal('ssf_subject_json', pretty(row.example));
    saveState();
  }
  log.debug("Leaving fillSubjectExample(). " + chosen);
  return false;
}

function currentSubject() {
  log.debug("Entering currentSubject().");
  var text = val('ssf_subject_json').trim();
  if (!text) {
    log.debug("Leaving currentSubject(). Empty.");
    return { ok: false,
      error: 'There is no subject in the box. Pick a format and press ' +
        '"Fill with an example" to start from the specification\'s own ' +
        'specimen.' };
  }
  try {
    var parsed = JSON.parse(text);
    log.debug("Leaving currentSubject(). Parsed.");
    return { ok: true, subject: parsed };
  } catch (e) {
    log.debug("Leaving currentSubject(). Not JSON.");
    return { ok: false, error: 'That is not JSON: ' + e.message };
  }
}

function criticalMembers() {
  log.debug("Entering criticalMembers().");
  var read = ssfClient.readMetadata(metadata);
  log.debug("Leaving criticalMembers(). " +
      read.criticalSubjectMembers.length);
  return read.criticalSubjectMembers;
}

function checkSubject() {
  log.debug("Entering checkSubject().");
  saveState();
  var got = currentSubject();
  var host = clear('ssf_subject_findings');
  if (!got.ok) {
    setText('ssf_subject_status', got.error, 'ssf-status ssf-bad');
    log.debug("Leaving checkSubject(). Unreadable.");
    return false;
  }
  var verdict = ssfClient.validateSubjectId(got.subject, {
    criticalMembers: criticalMembers() });
  if (verdict.ok) {
    setText('ssf_subject_status',
      'Valid: ' + (verdict.complex ? 'a complex subject' :
        'the "' + verdict.format + '" format') + ' — ' +
      ssfClient.describeSubject(got.subject), 'ssf-status ssf-ok');
    log.debug("Leaving checkSubject(). Valid.");
    return false;
  }
  setText('ssf_subject_status',
    verdict.errors.length + ' problem(s). A conforming receiver refuses this.',
    'ssf-status ssf-bad');
  verdict.errors.forEach(function (text) {
    host.appendChild(node('p', 'ssf-finding ssf-finding-error', '× ' + text));
  });
  log.debug("Leaving checkSubject(). " + verdict.errors.length);
  return false;
}

function subjectCall(member, label) {
  log.debug("Entering subjectCall(). " + label);
  saveState();
  var got = currentSubject();
  if (!got.ok) {
    setText('ssf_subject_status', got.error, 'ssf-status ssf-bad');
    log.debug("Leaving subjectCall(). Unreadable.");
    return false;
  }
  var where = ssfClient.endpointFor(metadata, member);
  if (!where.ok) {
    setText('ssf_subject_status', where.error, 'ssf-status ssf-bad');
    log.debug("Leaving subjectCall(). No endpoint.");
    return false;
  }
  var id = val('ssf_stream_id');
  var body = { stream_id: id, subject: got.subject };
  if (member === 'add_subject_endpoint') {
    body.verified = isOn('ssf_subject_verified');
  }
  var entry = recordCall(label, where.url, id);
  request({ method: 'POST', url: where.url, body: body })
    .then(function (answer) {
      drawExchange(answer.exchange);
      if (!answer.ok) {
        settleCall(entry, operations.FAILURE, refusal(answer));
        setText('ssf_subject_status', refusal(answer), 'ssf-status ssf-bad');
        log.debug("Leaving subjectCall(). Refused.");
        return;
      }
      settleCall(entry, operations.SUCCESS, '');
      setText('ssf_subject_status',
        answer.status + ' — ' + label + ' succeeded for ' +
        ssfClient.describeSubject(got.subject) +
        (member === 'remove_subject_endpoint'
          ? '. A remove is IDEMPOTENT: this is the same answer whether the ' +
            'subject was on the stream or not, so a receiver tidying up ' +
            'after a crash need not know what it had already removed.'
          : ''), 'ssf-status ssf-ok');
      log.debug("Leaving subjectCall(). Done.");
    });
  return false;
}

function addSubject() {
  log.debug("Entering addSubject().");
  var out = subjectCall('add_subject_endpoint', 'add subject');
  log.debug("Leaving addSubject().");
  return out;
}

function removeSubject() {
  log.debug("Entering removeSubject().");
  var out = subjectCall('remove_subject_endpoint', 'remove subject');
  log.debug("Leaving removeSubject().");
  return out;
}

// ---------------------------------------------------------------------------
// RECEIVING — POLL.
// ---------------------------------------------------------------------------
function pollEndpoint() {
  log.debug("Entering pollEndpoint().");
  // RFC 8936's poll endpoint is the TRANSMITTER's and it publishes it in the
  // stream configuration it hands back — NOT in its metadata, because it is
  // per stream. So it is read off the stream, and the metadata's
  // configuration endpoint is not a substitute.
  var fromStream = pollEndpointFromLastStream;
  if (fromStream) {
    log.debug("Leaving pollEndpoint(). From the stream.");
    return { ok: true, url: fromStream, error: '' };
  }
  log.debug("Leaving pollEndpoint(). Not known.");
  return { ok: false, url: '',
    error: 'This page has not seen a poll endpoint. RFC 8936\'s is the ' +
      'TRANSMITTER\'s and is published in the stream configuration rather ' +
      'than in the metadata, because it is per stream — so read or create a ' +
      'POLL stream first and the endpoint comes back on it.' };
}

var pollEndpointFromLastStream = '';

function notePollEndpoint(read) {
  log.debug("Entering notePollEndpoint().");
  if (read && read.delivery && read.delivery.method ===
      ssfClient.DELIVERY_POLL && read.delivery.endpoint_url) {
    pollEndpointFromLastStream = String(read.delivery.endpoint_url);
  }
  log.debug("Leaving notePollEndpoint(). " +
      (pollEndpointFromLastStream || 'none'));
}

function pollOnce() {
  log.debug("Entering pollOnce().");
  saveState();
  var where = pollEndpoint();
  if (!where.ok) {
    setStatus('ssf_poll_status', where.error, 'bad');
    log.debug("Leaving pollOnce(). No endpoint.");
    return false;
  }
  var id = val('ssf_stream_id');
  var body = ssfClient.buildPollRequest({
    streamId: id,
    maxEvents: Number(val('ssf_poll_max')) || 10,
    returnImmediately: true,
    ack: pendingAcks
  });
  var entry = recordCall('poll', where.url, id);
  request({ method: 'POST', url: where.url, body: body })
    .then(function (answer) {
      drawExchange(answer.exchange);
      if (!answer.ok) {
        settleCall(entry, operations.FAILURE, refusal(answer));
        setStatus('ssf_poll_status', refusal(answer), 'bad');
        log.debug("Leaving pollOnce(). Refused.");
        return;
      }
      settleCall(entry, operations.SUCCESS, '');
      pendingAcks = [];
      var read = ssfClient.readPollResponse(answer.body);
      read.jtis.forEach(function (jti) {
        takeReceivedToken(read.sets[jti], 'poll', id);
        if (isOn('ssf_poll_ack')) {
          pendingAcks.push(jti);
        }
      });
      setStatus('ssf_poll_status',
        read.jtis.length + ' event(s)' +
        (read.moreAvailable
          ? ' — AND moreAvailable IS TRUE, so the queue is not drained. A ' +
            'client that ignores that member assumes one poll empties it.'
          : ' — the queue is drained (moreAvailable is false).') +
        (isOn('ssf_poll_ack') && read.jtis.length
          ? ' They will be acknowledged on the next poll.'
          : ''),
        read.jtis.length ? 'ok' : 'pending');
      renderMessages();
      log.debug("Leaving pollOnce(). " + read.jtis.length);
    });
  return false;
}

// What the next poll will acknowledge. Held here rather than sent with the
// poll that returned them because RFC 8936's `ack` is a member of the NEXT
// request: a receiver acknowledges what it has STORED, and it has not stored
// anything until this page has drawn it.
var pendingAcks = [];

// ---------------------------------------------------------------------------
// RECEIVING — THE api's PUSH INBOX.
// ---------------------------------------------------------------------------
function createReceiver() {
  log.debug("Entering createReceiver().");
  if (!BACKEND_AVAILABLE) {
    setText('ssf_inbox_status',
      'This build has no api, so there is nothing to host a push endpoint. ' +
      'A browser cannot be an HTTP server — that is RFC 8935 rather than a ' +
      'limitation of this tool — so use POLL delivery, which needs no ' +
      'endpoint of this receiver\'s at all.', 'ssf-status ssf-bad');
    log.debug("Leaving createReceiver(). No api.");
    return false;
  }
  fetch(API_URL + '/ssf/receiver', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ label: 'the Shared Signals debugger' })
  }).then(function (response) {
    return response.json();
  }).then(function (answer) {
    if (!answer.ok) {
      setText('ssf_inbox_status', String(answer.error || 'refused'),
        'ssf-status ssf-bad');
      log.debug("Leaving createReceiver(). Refused.");
      return;
    }
    inbox = answer.inbox;
    inboxSeen = 0;
    setVal('ssf_inbox_url', answer.deliveryEndpoint);
    setVal('ssf_stream_endpoint', answer.deliveryEndpoint);
    saveState();
    setText('ssf_inbox_status',
      'The api is holding an inbox at ' + answer.deliveryEndpoint + '. Put ' +
      'that in the stream\'s delivery.endpoint_url — it is already filled ' +
      'in above. THE TRANSMITTER has to be able to reach it, which is why ' +
      'it is the api\'s address as this page reached it rather than a ' +
      'configured one.', 'ssf-status ssf-ok');
    log.debug("Leaving createReceiver(). " + answer.inbox.id);
  }).catch(function (e) {
    setText('ssf_inbox_status', 'The api could not be reached: ' + e.message,
      'ssf-status ssf-bad');
    log.debug("Leaving createReceiver(). Unreachable.");
  });
  return false;
}

function drainReceiver() {
  log.debug("Entering drainReceiver().");
  if (!inbox) {
    setText('ssf_inbox_status',
      'There is no inbox. Ask the api for one first.', 'ssf-status ssf-bad');
    log.debug("Leaving drainReceiver(). No inbox.");
    return false;
  }
  fetch(API_URL + '/ssf/receiver/' + encodeURIComponent(inbox.id) +
      '/events?after=' + inboxSeen).then(function (response) {
    return response.json();
  }).then(function (answer) {
    if (!answer.ok) {
      setText('ssf_inbox_status', String(answer.error || 'gone'),
        'ssf-status ssf-bad');
      log.debug("Leaving drainReceiver(). Refused.");
      return;
    }
    inbox = answer.inbox;
    inboxSeen = answer.total;
    answer.events.forEach(function (one) {
      takeReceivedToken(one.token, 'push', val('ssf_stream_id'), one);
    });
    setText('ssf_inbox_status',
      answer.events.length + ' new event(s); ' + answer.inbox.pushes +
      ' pushed to this inbox in total' +
      (answer.inbox.dropped
        ? ', and ' + answer.inbox.dropped + ' dropped because the inbox ' +
          'filled up — the OLDEST go, because a receiver that has stopped ' +
          'reading most wants what has happened lately'
        : '') + '.',
      answer.events.length ? 'ssf-status ssf-ok' : 'ssf-status ssf-pending');
    renderMessages();
    log.debug("Leaving drainReceiver(). " + answer.events.length);
  }).catch(function (e) {
    setText('ssf_inbox_status', 'The api could not be reached: ' + e.message,
      'ssf-status ssf-bad');
    log.debug("Leaving drainReceiver(). Unreachable.");
  });
  return false;
}

function deleteReceiver() {
  log.debug("Entering deleteReceiver().");
  if (!inbox) {
    log.debug("Leaving deleteReceiver(). No inbox.");
    return false;
  }
  fetch(API_URL + '/ssf/receiver/' + encodeURIComponent(inbox.id), {
    method: 'DELETE'
  }).then(function () {
    inbox = null;
    inboxSeen = 0;
    setVal('ssf_inbox_url', '');
    setText('ssf_inbox_status',
      'The inbox is gone. A transmitter still pushing to it now gets a 404, ' +
      'which is what a receiver that went away looks like from the other ' +
      'end.', 'ssf-status ssf-pending');
    log.debug("Leaving deleteReceiver(). Deleted.");
  }).catch(function (e) {
    setText('ssf_inbox_status', 'The api could not be reached: ' + e.message,
      'ssf-status ssf-bad');
    log.debug("Leaving deleteReceiver(). Unreachable.");
  });
  return false;
}

// ---------------------------------------------------------------------------
// READING ONE ARRIVING EVENT, AND SAYING WHAT EVERY CHECK SAID.
//
// This is where the page earns its place. A receiver's own code answers "did
// it verify"; what a person needs is every check BY NAME — because a single
// "valid" over a token whose audience is somebody else is the most dangerous
// thing this page could say.
// ---------------------------------------------------------------------------
function takeReceivedToken(token, via, streamId, extra) {
  log.debug("Entering takeReceivedToken(). " + via);
  var parsed = ssfClient.parseSet(token);
  var verdicts = [];
  if (!parsed.ok) {
    verdicts.push({ level: 'error', text: parsed.problem });
    ssfHistory.recordMessage({ direction: 'received', via: via,
      streamId: streamId, token: token, verdicts: verdicts,
      outcome: 'unreadable', detail: parsed.problem });
    log.debug("Leaving takeReceivedToken(). Unreadable.");
    return;
  }
  var read = ssfClient.readMetadata(metadata);
  var headerVerdict = ssfClient.inspectSetHeader(parsed.header);
  var setVerdict = ssfClient.inspectSet(parsed.claims, {
    expectedIssuer: read.issuer,
    expectedAudience: val('ssf_stream_aud'),
    criticalMembers: read.criticalSubjectMembers
  });
  headerVerdict.errors.forEach(function (text) {
    verdicts.push({ level: 'error', text: text });
  });
  headerVerdict.warnings.forEach(function (text) {
    verdicts.push({ level: 'warn', text: text });
  });
  setVerdict.errors.forEach(function (text) {
    verdicts.push({ level: 'error', text: text });
  });
  setVerdict.warnings.forEach(function (text) {
    verdicts.push({ level: 'warn', text: text });
  });
  setVerdict.notes.forEach(function (text) {
    verdicts.push({ level: 'note', text: text });
  });
  if (extra && extra.contentType !== undefined) {
    verdicts.push({
      level: extra.correctMediaType ? 'note' : 'warn',
      text: extra.correctMediaType
        ? 'Delivered as ' + ssfClient.SET_MEDIA_TYPE + ', which is what RFC ' +
          '8417 section 2.3 specifies.'
        : 'Delivered as "' + String(extra.contentType || '(none)') + '" ' +
          'rather than ' + ssfClient.SET_MEDIA_TYPE + '. A receiver that ' +
          'dispatches on the media type — and several do — drops a token ' +
          'sent that way with no error anybody sees.'
    });
  }
  ssfEvents.describeEvents(parsed.claims.events).forEach(function (row) {
    verdicts.push({
      level: row.known ? 'note' : 'warn',
      text: row.known
        ? row.name + ' (' + row.uri + ')'
        : 'This build does not implement "' + row.uri + '"' +
          (row.family ? ' — it is a ' + row.family.toUpperCase() +
            ' event, which is a later part of this work' : '') +
          '. The payload is shown as it arrived.'
    });
    row.errors.forEach(function (text) {
      verdicts.push({ level: 'error', text: text });
    });
    row.warnings.forEach(function (text) {
      verdicts.push({ level: 'warn', text: text });
    });
  });

  var id = ssfHistory.recordMessage({
    direction: 'received', via: via, streamId: streamId,
    jti: setVerdict.jti, types: setVerdict.types,
    subject: setVerdict.subject
      ? ssfClient.describeSubject(setVerdict.subject) : '',
    issuer: setVerdict.issuer,
    audience: typeof setVerdict.audience === 'string'
      ? setVerdict.audience : pretty(setVerdict.audience),
    token: token, header: parsed.header, claims: parsed.claims,
    verdicts: verdicts,
    signature: 'not checked',
    outcome: verdicts.some(function (one) {
      return one.level === 'error';
    }) ? 'findings' : 'clean'
  });
  verifyReceived(id, token, parsed);
  log.debug("Leaving takeReceivedToken(). " + id);
}

// The signature, checked separately and asynchronously — several algorithms
// are. **AN UNCHECKED SIGNATURE IS REPORTED AS UNCHECKED AND NEVER AS VALID**,
// which is the whole of why this is its own step: a receiver has to act on the
// difference, and a page that quietly showed "no key" as a pass would be
// teaching the opposite of what this protocol needs.
function verifyReceived(id, token, parsed) {
  log.debug("Entering verifyReceived().");
  var keyText = val('ssf_verify_key').trim();
  if (!keyText) {
    log.debug("Leaving verifyReceived(). No key.");
    return;
  }
  var alg = val('ssf_verify_alg') || (parsed.header || {}).alg;
  var key;
  try {
    key = JSON.parse(keyText);
  } catch (e) {
    // A PEM, or something else jws.js can resolve. Handed over as text.
    key = keyText;
  }
  ssfClient.verifySet(token, key, alg).then(function (verdict) {
    // `reason` is per SIGNATURE rather than per token — a general
    // serialization can carry several — so the first one's is what a compact
    // SET's failure is.
    var first = (verdict.signatures || [])[0] || {};
    noteSignature(id, verdict.valid
      ? 'verified with ' + alg
      : 'DID NOT VERIFY with ' + alg + ': ' +
        String(first.reason || 'the signature does not match'));
    log.debug("Leaving verifyReceived(). " + verdict.valid);
  }).catch(function (e) {
    noteSignature(id, 'could not be checked: ' + e.message);
    log.debug("Leaving verifyReceived(). Threw.");
  });
}

function noteSignature(id, text) {
  log.debug("Entering noteSignature().");
  // The history is written whole, so the row is re-read, changed and written
  // back — which is what keeps ssf_history.js free of a "patch one field"
  // function that only this caller would use.
  var rows = ssfHistory.messages();
  var i;
  for (i = rows.length - 1; i >= 0; i--) {
    if (rows[i].id === id) {
      rows[i].signature = text;
      break;
    }
  }
  try {
    localStorage.setItem(ssfHistory.MESSAGE_KEY, JSON.stringify(rows));
  } catch (e) {
    log.debug("noteSignature(): the history could not be written back.");
  }
  renderMessages();
  log.debug("Leaving noteSignature().");
}

function decodePastedSet() {
  log.debug("Entering decodePastedSet().");
  var token = val('ssf_paste_set').trim();
  if (!token) {
    log.debug("Leaving decodePastedSet(). Nothing pasted.");
    return false;
  }
  takeReceivedToken(token, 'pasted', val('ssf_stream_id'));
  renderMessages();
  log.debug("Leaving decodePastedSet().");
  return false;
}

function fetchJwks() {
  log.debug("Entering fetchJwks().");
  var read = ssfClient.readMetadata(metadata);
  if (!read.jwksUri) {
    setText('ssf_inbox_status',
      'This transmitter publishes no jwks_uri, so there is nowhere to fetch ' +
      'a key from. Fetch its metadata first.', 'ssf-status ssf-bad');
    log.debug("Leaving fetchJwks(). No jwks_uri.");
    return false;
  }
  var entry = recordCall('fetch jwks', read.jwksUri, '');
  request({ method: 'GET', url: read.jwksUri }).then(function (answer) {
    drawExchange(answer.exchange);
    if (!answer.ok) {
      settleCall(entry, operations.FAILURE, refusal(answer));
      log.debug("Leaving fetchJwks(). Refused.");
      return;
    }
    settleCall(entry, operations.SUCCESS, '');
    setVal('ssf_verify_key', pretty(answer.body));
    log.debug("Leaving fetchJwks(). Fetched.");
  });
  return false;
}

// ---------------------------------------------------------------------------
// TRANSMITTING.
// ---------------------------------------------------------------------------
function fillEventTypes() {
  log.debug("Entering fillEventTypes().");
  var select = el('ssf_tx_type');
  if (select) {
    ssfEvents.EVENTS.forEach(function (row) {
      var option = document.createElement('option');
      option.value = row.uri;
      option.textContent = row.name + ' — ' + row.uri;
      select.appendChild(option);
    });
  }
  var algs = el('ssf_tx_alg');
  var verifyAlgs = el('ssf_verify_alg');
  jws.algIds().forEach(function (id) {
    var spec = jws.algSpec(id);
    if (spec.alg === 'none') {
      // `alg: none` is a legal JWS and it is not offered HERE. A Security
      // Event Token says somebody's session was revoked; an unsigned one says
      // anybody who can reach the endpoint can claim it. The Digital
      // Signature page is where an unsecured JWS is built on purpose, and
      // this page still REPORTS one that arrives.
      return;
    }
    [algs, verifyAlgs].forEach(function (host) {
      if (!host) {
        return;
      }
      var option = document.createElement('option');
      option.value = id;
      option.textContent = spec.label || id;
      host.appendChild(option);
    });
  });
  if (algs && !algs.value) {
    algs.value = 'ES256';
  }
  renderFamilies();
  log.debug("Leaving fillEventTypes().");
}

function renderFamilies() {
  log.debug("Entering renderFamilies().");
  var host = clear('ssf_families');
  if (!host) {
    log.debug("Leaving renderFamilies(). No host.");
    return;
  }
  host.appendChild(node('p', 'ssf-note',
    'Which vocabularies this build carries. A page offering two event types ' +
    'where a reader expected eighteen would read as broken rather than as ' +
    'staged, so the two that are not here say so.'));
  var wrap = node('div', 'ssf-families');
  ssfEvents.FAMILIES.forEach(function (row) {
    var box = node('div', 'ssf-family' +
      (row.implemented ? '' : ' ssf-family-absent'));
    box.appendChild(node('span', 'ssf-family-name', row.label));
    box.appendChild(document.createTextNode(' — ' + row.what));
    wrap.appendChild(box);
  });
  host.appendChild(wrap);
  log.debug("Leaving renderFamilies().");
}

function transmitTypeChanged() {
  log.debug("Entering transmitTypeChanged().");
  var row = ssfEvents.EVENT_BY_URI[val('ssf_tx_type')];
  if (!row) {
    log.debug("Leaving transmitTypeChanged(). Unknown.");
    return false;
  }
  setText('ssf_tx_what', row.what + ' ' + row.howItIsAsked);
  setVal('ssf_tx_payload', pretty(ssfEvents.generateEvent(row.uri, {
    state: 'a-value-the-receiver-chose', status: 'enabled',
    reason: 'because somebody asked' })));
  saveState();
  log.debug("Leaving transmitTypeChanged(). " + row.uri);
  return false;
}

function generateTxKey() {
  log.debug("Entering generateTxKey().");
  var alg = val('ssf_tx_alg');
  setStatus('ssf_tx_key_status', 'Generating a ' + alg + ' key pair…',
    'pending');
  try {
    // SYNCHRONOUS, and deliberately not wrapped in a promise: jws.js generates
    // in the JavaScript engine rather than through Web Crypto, which is what
    // lets this page work over plain http and outside a secure context. An
    // RSA key is the slow one and it is still under a second.
    var pair = jws.generateKey(alg);
    var spec = jws.algSpec(alg);
    setVal('ssf_tx_public_key', spec.family === 'rsa'
      ? String(pair.publicKey)
      : pretty(jws.publicJwk(alg, pair.publicKey)));
    setVal('ssf_tx_private_key', spec.family === 'rsa'
      // RSA has no raw private JWK here — jws.js says so by name — so the
      // PEM is what goes in the box, and signSet() takes it as readily.
      ? String(pair.privateKey)
      : pretty(jws.privateJwk(alg, pair.privateKey, pair.publicKey)));
    setStatus('ssf_tx_key_status',
      'A ' + alg + ' key pair. The private half is NEVER written to storage ' +
      '— hand the public half to whatever is going to verify what you send.',
      'ok');
    log.debug("Leaving generateTxKey(). Generated.");
  } catch (e) {
    setStatus('ssf_tx_key_status',
      'That key could not be generated: ' + e.message, 'bad');
    log.debug("Leaving generateTxKey(). Failed.");
  }
  return false;
}

function buildEvent() {
  log.debug("Entering buildEvent().");
  saveState();
  var uri = val('ssf_tx_type');
  var payload;
  try {
    payload = JSON.parse(val('ssf_tx_payload') || '{}');
  } catch (e) {
    setStatus('ssf_tx_status', 'The payload is not JSON: ' + e.message, 'bad');
    log.debug("Leaving buildEvent(). Payload unreadable.");
    return false;
  }
  var subject = null;
  var subjectText = val('ssf_tx_subject').trim();
  if (subjectText) {
    try {
      subject = JSON.parse(subjectText);
    } catch (e) {
      setStatus('ssf_tx_status', 'The subject is not JSON: ' + e.message,
        'bad');
      log.debug("Leaving buildEvent(). Subject unreadable.");
      return false;
    }
    var verdict = ssfClient.validateSubjectId(subject, {});
    if (!verdict.ok) {
      setStatus('ssf_tx_status', verdict.errors.join(' '), 'bad');
      log.debug("Leaving buildEvent(). Subject invalid.");
      return false;
    }
  }
  var eventVerdict = ssfEvents.validateEvent(uri, payload);
  if (!eventVerdict.ok) {
    setStatus('ssf_tx_status', eventVerdict.errors.join(' '), 'bad');
    log.debug("Leaving buildEvent(). Payload invalid.");
    return false;
  }
  var claims = ssfClient.buildSetClaims({
    issuer: val('ssf_tx_iss'),
    audience: val('ssf_tx_aud'),
    uri: uri,
    payload: payload,
    subject: subject,
    txn: val('ssf_tx_txn')
  });
  var alg = val('ssf_tx_alg');
  var keyText = val('ssf_tx_private_key').trim();
  if (!keyText) {
    setStatus('ssf_tx_status',
      'There is no private key. Press "Generate a signing key", or paste ' +
      'one as a JWK or a PEM.', 'bad');
    log.debug("Leaving buildEvent(). No key.");
    return false;
  }
  var key = keyText;
  try {
    key = JSON.parse(keyText);
  } catch (e) {
    // A PEM, or a raw secret. jws.js resolves every form a key arrives in,
    // so it is handed over as text rather than refused here — refusing would
    // make RSA unusable, since jws.js has no raw private JWK for it.
    key = keyText;
  }
  setStatus('ssf_tx_status', 'Signing with ' + alg + '…', 'pending');
  return ssfClient.signSet(claims, key, alg, {}).then(function (token) {
    setVal('ssf_tx_token', token);
    renderBuiltEvent(claims, token, eventVerdict);
    setStatus('ssf_tx_status',
      'Signed with ' + alg + '. Nothing has been sent.', 'ok');
    log.debug("Leaving buildEvent(). Signed.");
    return token;
  }).catch(function (e) {
    setStatus('ssf_tx_status', 'It could not be signed: ' + e.message, 'bad');
    log.debug("Leaving buildEvent(). Signing failed.");
    return '';
  });
}

function renderBuiltEvent(claims, token, eventVerdict) {
  log.debug("Entering renderBuiltEvent().");
  var host = clear('ssf_tx_decoded');
  if (!host) {
    log.debug("Leaving renderBuiltEvent(). No host.");
    return;
  }
  host.appendChild(node('p', 'ssf-note',
    'The claim set, before signing. Note what is NOT in it: there is no ' +
    '"exp", because RFC 8417 section 4.1.4 says a SET must not be ' +
    'considered to expire — it records that something HAPPENED, and a fact ' +
    'does not stop being true. And the subject is in "sub_id" rather than ' +
    '"sub", because the thing an event is about may be a person AND a ' +
    'device AND a session at once.'));
  var box = node('textarea', 'ssf-field ssf-mono');
  box.rows = 10;
  box.readOnly = true;
  box.value = pretty(claims);
  host.appendChild(box);
  (eventVerdict.warnings || []).forEach(function (text) {
    host.appendChild(node('p', 'ssf-finding ssf-finding-warn', '! ' + text));
  });
  log.debug("Leaving renderBuiltEvent().");
}

function pushEvent() {
  log.debug("Entering pushEvent().");
  var token = val('ssf_tx_token');
  var send = token ? Promise.resolve(token) : buildEvent();
  Promise.resolve(send).then(function (signed) {
    if (!signed) {
      log.debug("pushEvent(): nothing to send.");
      return;
    }
    var url = val('ssf_tx_endpoint');
    if (!url) {
      setStatus('ssf_tx_status',
        'There is no receiver endpoint to push to.', 'bad');
      log.debug("pushEvent(): no endpoint.");
      return;
    }
    var push = ssfClient.buildPushRequest(signed, {
      mediaType: val('ssf_tx_media'),
      authorizationHeader: val('ssf_tx_auth')
    });
    var entry = recordCall('push event', url, val('ssf_stream_id'));
    request({ method: 'POST', url: url, headers: push.headers,
      body: push.body }).then(function (answer) {
      drawExchange(answer.exchange);
      var verdict = ssfClient.readPushResponse(answer.status, answer.body);
      var parsed = ssfClient.parseSet(signed);
      ssfHistory.recordMessage({
        direction: 'sent', via: 'push', streamId: val('ssf_stream_id'),
        jti: parsed.ok ? String(parsed.claims.jti || '') : '',
        types: parsed.ok ? Object.keys(parsed.claims.events || {}) : [],
        issuer: val('ssf_tx_iss'), audience: val('ssf_tx_aud'),
        token: signed, header: parsed.header, claims: parsed.claims,
        signature: 'signed here with ' + val('ssf_tx_alg'),
        outcome: verdict.accepted ? 'accepted'
          : (verdict.refused ? 'refused by the receiver' : 'not delivered'),
        detail: verdict.note || verdict.description ||
          (answer.description || ''),
        verdicts: [{ level: verdict.accepted ? 'note' : 'error',
          text: verdict.accepted
            ? 'The receiver answered ' + verdict.status + '.' +
              (verdict.note ? ' ' + verdict.note : '')
            : (verdict.refused
              ? 'REFUSED: ' + verdict.err + ' — ' + verdict.description
              : 'Not delivered: ' + (answer.description ||
                ('the receiver answered ' + answer.status))) }],
        exchange: answer.exchange
      });
      settleCall(entry, verdict.accepted ? operations.SUCCESS
        : operations.FAILURE, verdict.err || String(answer.status));
      setStatus('ssf_tx_status', verdict.accepted
        ? 'Delivered (' + verdict.status + ').' +
          (verdict.note ? ' ' + verdict.note : '')
        : (verdict.refused
          ? 'The receiver REFUSED it: ' + verdict.err + ' — ' +
            verdict.description + '. That is a different thing from a ' +
            'network failure: it read the SET and would not take it.'
          : refusal(answer)),
        verdict.accepted ? 'ok' : 'bad');
      renderMessages();
      log.debug("Leaving pushEvent(). " + verdict.status);
    });
  });
  return false;
}

// ---------------------------------------------------------------------------
// THE MESSAGE HISTORY PANE.
// ---------------------------------------------------------------------------
function renderMessages() {
  log.debug("Entering renderMessages().");
  var host = clear('ssf_messages');
  if (!host) {
    log.debug("Leaving renderMessages(). No host.");
    return;
  }
  var rows = ssfHistory.messages();
  if (!rows.length) {
    host.appendChild(node('p', 'ssf-note', 'No events yet.'));
    log.debug("Leaving renderMessages(). Empty.");
    return;
  }
  rows.slice().reverse().forEach(function (row) {
    var box = node('div', 'ssf-message ssf-message-' + row.direction);
    var head = node('div', 'ssf-message-head',
      (row.direction === 'sent' ? '→ sent' : '← received') +
      (row.via ? ' (' + row.via + ')' : '') + ' — ' +
      (row.types.length ? row.types.join(', ') : 'no event type'));
    head.appendChild(node('span', 'ssf-message-when',
      '  ' + String(row.timestamp).substring(0, 19).replace('T', ' ') + 'Z'));
    box.appendChild(head);
    if (row.jti) {
      box.appendChild(node('div', 'ssf-jti', 'jti: ' + row.jti));
    }
    if (row.subject) {
      box.appendChild(node('div', 'ssf-uri', 'subject: ' + row.subject));
    }
    box.appendChild(node('div', 'ssf-note',
      'Signature: ' + row.signature +
      (row.outcome ? ' · outcome: ' + row.outcome : '')));
    (row.verdicts || []).forEach(function (one) {
      var mark = one.level === 'error' ? '× '
        : (one.level === 'warn' ? '! ' : '· ');
      box.appendChild(node('p', 'ssf-finding ssf-finding-' +
        (one.level === 'error' ? 'error'
          : (one.level === 'warn' ? 'warn' : 'note')), mark + one.text));
    });
    if (row.claims) {
      var claims = node('textarea', 'ssf-field ssf-mono');
      claims.rows = 8;
      claims.readOnly = true;
      claims.value = pretty({ header: row.header, claims: row.claims });
      box.appendChild(claims);
    }
    var token = node('textarea', 'ssf-field ssf-mono ssf-token');
    token.rows = 2;
    token.readOnly = true;
    token.value = row.token;
    box.appendChild(token);
    host.appendChild(box);
  });
  log.debug("Leaving renderMessages(). " + rows.length);
}

function clearMessages() {
  log.debug("Entering clearMessages().");
  ssfHistory.clearMessages();
  renderMessages();
  log.debug("Leaving clearMessages().");
  return false;
}

// ---------------------------------------------------------------------------
// WHAT THE api SAYS IT WILL DO.
//
// It is also how the page knows there IS an api: a static deployment gets no
// answer here, which is a stronger signal than a configuration flag because it
// is the api itself saying so.
// ---------------------------------------------------------------------------
function askApiLimits() {
  log.debug("Entering askApiLimits().");
  if (!BACKEND_AVAILABLE) {
    setText('ssf_limits',
      'This build has no api. Every call is made by this browser, and PUSH ' +
      'delivery is unavailable — a page cannot be an HTTP server, which is ' +
      'RFC 8935 rather than a limitation of this tool. POLL delivery works ' +
      'exactly as it does anywhere.');
    log.debug("Leaving askApiLimits(). No api.");
    return;
  }
  fetch(API_URL + '/ssf/limits').then(function (response) {
    return response.json();
  }).then(function (answer) {
    apiLimits = answer;
    var receiver = answer.receiver || {};
    setText('ssf_limits',
      'The api will forward ' + (answer.methods || []).join(', ') +
      ', up to ' + answer.maxRequestBytes + ' bytes of request body, and it ' +
      'refuses the framing headers (' +
      (answer.refusedHeaders || []).join(', ') + '). ' + answer.statusRule +
      ' ' + (receiver.enabled
        ? 'It will also host a push receiver: up to ' + receiver.maxInboxes +
          ' inbox(es), ' + receiver.maxEvents + ' event(s) each, ' +
          receiver.maxEventBytes + ' bytes per event, expiring after ' +
          Math.round((receiver.ttlMs || 0) / 60000) + ' minute(s). It does ' +
          'NOT check a signature — it holds no key of the transmitter\'s, ' +
          'so this page does that.'
        : 'It will NOT host a push receiver (ssfReceiverEnabled), so push ' +
          'delivery is unavailable here.'));
    log.debug("Leaving askApiLimits(). Answered.");
  }).catch(function (e) {
    setText('ssf_limits',
      'The api did not answer (' + e.message + '), so every call will be ' +
      'made by this browser.');
    log.debug("Leaving askApiLimits(). No answer.");
  });
}

// ---------------------------------------------------------------------------
// LOAD.
// ---------------------------------------------------------------------------
function onload() {
  log.debug("Entering onload().");
  fillSubjectFormats();
  fillEventTypes();
  loadState();
  applyBackendAvailability();
  collectHandedTokens();
  subjectFormatChanged();
  transmitTypeChanged();
  deliveryChanged();
  authSchemeChanged();
  renderIdentity(val('ssf_id_token') ? claimsOf(val('ssf_id_token')) : null);
  renderTokenHistory();
  renderMessages();
  renderOperations();
  drawExchange(null);
  askApiLimits();
  // Every field saves as it changes, which is what every other page here
  // does. It is one listener rather than an `onchange` per field: this page
  // has forty of them, and an attribute per field is forty chances to forget.
  document.addEventListener('change', function (event) {
    saveState();
    // The two rows whose VISIBILITY follows a control rather than a value.
    // They are handled here rather than by an `onchange` attribute apiece
    // because this page has forty fields and an attribute per field is forty
    // chances to forget one — the same reason saveState() is one listener.
    var id = event && event.target ? event.target.id : '';
    if (id === 'ssf_auth_scheme') {
      authSchemeChanged();
    }
    if (id === 'ssf_stream_delivery') {
      deliveryChanged();
    }
  });
  log.debug("Leaving onload().");
}

window.onload = onload;

module.exports = {
  // The inline handlers on ssf.html.
  onload: onload,
  setCallPath: setCallPath,
  authSchemeChanged: authSchemeChanged,
  startTokenHandoff: startTokenHandoff,
  readPastedTokens: readPastedTokens,
  clearTokenHistory: clearTokenHistory,
  discover: discover,
  deliveryChanged: deliveryChanged,
  createStream: createStream,
  readStream: readStream,
  replaceStream: replaceStream,
  mergeStream: mergeStream,
  deleteStream: deleteStream,
  setStatus: setStreamStatus,
  getStatus: getStreamStatus,
  verifyStream: verifyStream,
  subjectFormatChanged: subjectFormatChanged,
  fillSubjectExample: fillSubjectExample,
  checkSubject: checkSubject,
  addSubject: addSubject,
  removeSubject: removeSubject,
  pollOnce: pollOnce,
  createReceiver: createReceiver,
  drainReceiver: drainReceiver,
  deleteReceiver: deleteReceiver,
  decodePastedSet: decodePastedSet,
  fetchJwks: fetchJwks,
  transmitTypeChanged: transmitTypeChanged,
  generateTxKey: generateTxKey,
  buildEvent: buildEvent,
  pushEvent: pushEvent,
  clearMessages: clearMessages,
  clearOperations: clearOperations,
  // Reached by tests/ssf_page.js, which asserts what the page composes rather
  // than only what came back — the difference between "the request was wrong"
  // and "the button did nothing".
  streamBody: streamBody,
  saveState: saveState,
  takeReceivedToken: takeReceivedToken,
  notePollEndpoint: notePollEndpoint
};
