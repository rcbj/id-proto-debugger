// File: spiffe.js
//
// ---------------------------------------------------------------------------
// The SPIFFE Protocol Debugger.
//
// SPIFFE's server side is THREE surfaces, and the whole shape of this page
// follows from the fact that they have almost nothing in common:
//
//   the bundle endpoint    plain HTTPS. One GET returning a JWK Set. This is
//                          the whole of the federation protocol's server half,
//                          and it is the only surface a browser could reach on
//                          its own — which it still does not, because a bundle
//                          endpoint sends no CORS headers.
//   the Workload API       gRPC. What a WORKLOAD talks to, to be given an
//                          identity. Never authenticated, and that is the
//                          specification speaking.
//   the SPIRE Server API   gRPC over MUTUAL TLS. What an OPERATOR and an AGENT
//                          talk to: forty-two methods across six services.
//
// **A BROWSER CANNOT SPEAK gRPC AT ALL**, and that is not a limitation of this
// page. gRPC is HTTP/2 with a length-prefixed binary framing and a status in
// the TRAILERS: `fetch` will not open an HTTP/2 stream of its own, cannot send
// or read trailers, cannot see a `grpc-status`, and — the one that ends the
// argument — cannot present a client certificate, which the SPIRE Server API
// requires. So both gRPC surfaces are performed by the debugger's **api**, and
// the Exchange pane shows both halves of what was asked of it.
//
// The addresses on this page are resolved BY THE API and not by this browser:
// `localhost` there means the machine the api runs on, and a `unix://` socket
// path is a path on THAT machine. That catches everybody once.
//
// ---------------------------------------------------------------------------
// THE THREE THINGS THIS PAGE DOES WITH NO NETWORK AT ALL
//
// They are here because each of them is a question somebody asks while holding
// a value and nothing else, and sending it somewhere to be told the answer
// would be worse than useless:
//
//   * **the SPIFFE ID grammar**, which is stricter than a URL parser in four
//     ways that each produce an identifier looking perfectly fine in a log —
//     `common/spiffe/spiffe_id.js`, the same module the api refuses with;
//   * **a trust bundle document**, whose one consequential defect (a JWK with
//     no `use`) makes a bundle verify NOTHING while reporting no error
//     anywhere — `common/spiffe/spiffe_bundle.js`, again the api's own;
//   * **an SVID**, X.509 or JWT. An X509-SVID is an ordinary certificate whose
//     identity is in its URI subjectAltName and nowhere else, so `x509.js`
//     already reads one; a JWT-SVID is a JWS with `sub`, `aud` and `exp`.
//
// ---------------------------------------------------------------------------
// WHY THERE IS A CSR BUILDER ON THIS PAGE
//
// FIVE of the forty-nine methods take a PKCS#10 certification request —
// `AttestAgent`, `RenewAgent`, `MintX509SVID`, `BatchNewX509SVID` and
// `NewDownstreamX509CA` — because in SPIFFE the requester keeps its own private
// key and the authority never sees it. Without a way to build one, five methods
// on this page would be unreachable in practice, which would make "every method
// is here" a claim about a list rather than about what can be done. The builder
// is `x509.js`'s `certificationRequest()`, shared with the PKI page.
//
// The key pair it makes MATTERS AFTERWARDS: the SVID that comes back is only
// usable as an identity while its private key is still here, and that is what
// the Held Identity pane keeps. Which is also why this page has a key-material
// opt-out checkbox like the SAML, WS-Trust and WS-Federation workflows — see
// `spiffe_save_identity` below.
// ---------------------------------------------------------------------------

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var history = require("./spiffe_history");
var spiffeId = require("./spiffe_id.js");
var spiffeBundle = require("./spiffe_bundle.js");
var x509 = require("./x509");
var keys = require("./key_material");
var log = bunyan.createLogger({ name: 'spiffe', level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());

var API_URL = appconfig.apiUrl || '';
var BACKEND_AVAILABLE = appconfig.backendAvailable !== false;

// Every field on this page is remembered. The one thing that is NOT
// unconditionally remembered is the held identity's PRIVATE KEY — see
// `spiffe_save_identity`, and the long note in the repo-root CLAUDE.md about
// why every workflow that generates a key pair has an opt-out rather than a
// rule.
var REMEMBERED = [
  'spiffe_trust_domain', 'spiffe_bundle_url',
  'spiffe_workload_address', 'spiffe_workload_method',
  'spiffe_workload_request', 'spiffe_workload_messages',
  'spiffe_workload_metadata',
  'spiffe_server_address', 'spiffe_server_service', 'spiffe_server_method',
  'spiffe_server_request', 'spiffe_server_messages',
  'spiffe_server_id', 'spiffe_server_identity_mode', 'spiffe_server_metadata',
  'spiffe_csr_subject', 'spiffe_csr_key_alg', 'spiffe_csr_uri',
  'spiffe_id_input'
];

// The localStorage keys holding key MATERIAL. Listed separately because
// clearing the opt-out has to remove whatever is already there — an opt-out
// that leaves yesterday's private key in storage is not an opt-out.
var IDENTITY_KEYS = [
  'spiffe_identity_cert', 'spiffe_identity_key', 'spiffe_identity_id',
  'spiffe_identity_bundle'
];

var SAVE_IDENTITY_KEY = 'spiffe_save_identity';

// The catalogue, as `GET /spiffe/limits` published it. Null until it arrives,
// which is how the page tells "the api has not answered yet" from "there is no
// api" — the two produce very different advice and look identical in an empty
// dropdown.
var CATALOGUE = null;
var LIMITS = null;

// --- tiny DOM helpers ------------------------------------------------------
//
// One-liners called on every field read and every render, and they carry NO
// entering/leaving log lines. That is the hot-path exception the repo-root
// CLAUDE.md describes and the one saml_tools.js earned the hard way: a log pair
// in a one-line accessor is not a trace, it is the entire log. The functions
// that CALL these keep their logging, which is where a trace actually lives.
function el(id) { return document.getElementById(id); }
function val(id) { var e = el(id); return e ? String(e.value || '') : ''; }
function setVal(id, v) {
  var e = el(id);
  if (!e) return;
  e.value = v == null ? '' : v;
  fitTextarea(e);
}
function isOn(id) { var e = el(id); return !!(e && e.checked); }

// Size a textarea to what is actually in it, between the `data-min-rows` and
// `data-max-rows` the markup declares.
//
// THIS IS THE PAGE'S BIGGEST SOURCE OF WHITE SPACE and it is not a style
// preference: the two Exchange readouts, the SVID Inspector's output and the
// three certification-request boxes are EMPTY until something is done, and a
// ten-row empty box is ten rows of nothing between two panes. Every one of
// them now opens at two rows and grows to the answer it is given, which is
// what puts the panes below back on the screen. The maximum is what keeps a
// two-hundred-line gRPC answer scrolling inside its own box rather than
// pushing every pane under it out of sight.
//
// It carries no entering/leaving pair for the reason `el` and `val` above do
// not: `setVal()` calls it on every write, and a rendered history or a
// described SVID is hundreds of those.
function fitTextarea(e) {
  if (!e || e.tagName !== 'TEXTAREA') return;
  var max = parseInt(e.getAttribute('data-max-rows') || '0', 10);
  if (!max) return;
  var min = parseInt(e.getAttribute('data-min-rows') || '2', 10);
  var lines = String(e.value || '').split('\n').length;
  e.rows = Math.max(min, Math.min(max, lines));
}

// Every box that declares a ceiling, sized to what it holds — on load, and
// again on every keystroke in one somebody is typing into. The `input`
// listener is what makes a request editor grow as a JSON body is pasted into
// it; `setVal()` covers everything this page writes itself.
function mountAutoFit() {
  log.debug("Entering mountAutoFit().");
  var boxes = document.querySelectorAll('textarea[data-max-rows]');
  for (var i = 0; i < boxes.length; i++) {
    fitTextarea(boxes[i]);
    if (boxes[i].readOnly) continue;
    boxes[i].addEventListener('input', function (event) {
      fitTextarea(event.target);
    });
  }
  log.debug("Leaving mountAutoFit(). boxes=" + boxes.length);
}
function setText(id, v) {
  var e = el(id);
  if (e) e.textContent = v == null ? '' : String(v);
}
function clear(node) {
  while (node && node.firstChild) { node.removeChild(node.firstChild); }
}
function cell(row, text, className) {
  var td = document.createElement('td');
  td.textContent = text == null ? '' : String(text);
  if (className) td.className = className;
  row.appendChild(td);
  return td;
}

function statusOk(id, message) {
  log.debug("Entering statusOk(). id=" + id);
  var e = el(id);
  if (e) {
    e.value = message;
    e.className = 'spiffe-status spiffe-grow spiffe-ok';
  }
  log.debug("Leaving statusOk().");
}

function statusBad(id, message) {
  log.debug("Entering statusBad(). id=" + id);
  var e = el(id);
  if (e) {
    e.value = message;
    e.className = 'spiffe-status spiffe-grow spiffe-bad';
  }
  log.debug("Leaving statusBad().");
}

function statusBusy(id, message) {
  log.debug("Entering statusBusy(). id=" + id);
  var e = el(id);
  if (e) {
    e.value = message;
    e.className = 'spiffe-status spiffe-grow spiffe-pending';
  }
  log.debug("Leaving statusBusy().");
}

// --- state -----------------------------------------------------------------

function savingIdentity() {
  log.debug("Entering savingIdentity().");
  var box = el(SAVE_IDENTITY_KEY);
  // A MISSING checkbox keeps saving, rather than silently dropping an identity
  // the user expects to still be there. That is the rule the SAML, WS-Trust and
  // WS-Federation panes follow, and it exists for the older-cached-page case.
  var on = !box || !!box.checked;
  log.debug("Leaving savingIdentity(). " + on);
  return on;
}

function purgeIdentityStorage() {
  log.debug("Entering purgeIdentityStorage().");
  try {
    IDENTITY_KEYS.forEach(function (key) {
      localStorage.removeItem(key);
    });
  } catch (e) {
    log.warn('could not clear the held identity from localStorage: ' +
             e.message);
  }
  log.debug("Leaving purgeIdentityStorage().");
}

function saveState() {
  log.debug("Entering saveState().");
  try {
    REMEMBERED.forEach(function (id) {
      var e = el(id);
      if (e) localStorage.setItem(id, String(e.value || ''));
    });
    localStorage.setItem(SAVE_IDENTITY_KEY, savingIdentity() ? '1' : '0');
    // The purge lives HERE rather than only in the checkbox's change handler,
    // so that no code path can leave the pair behind.
    if (!savingIdentity()) {
      purgeIdentityStorage();
    }
  } catch (e) {
    log.warn('could not write to localStorage: ' + e.message);
  }
  log.debug("Leaving saveState().");
}

function loadState() {
  log.debug("Entering loadState().");
  var stored;
  try {
    stored = localStorage.getItem(SAVE_IDENTITY_KEY);
  } catch (e) {
    stored = null;
  }
  var box = el(SAVE_IDENTITY_KEY);
  // Only an explicit "0" turns it off, so an unreadable preference fails
  // TOWARDS the workflow rather than towards an empty pane.
  if (box) box.checked = stored !== '0';
  REMEMBERED.forEach(function (id) {
    var e = el(id);
    if (!e) return;
    var value = null;
    try {
      value = localStorage.getItem(id);
    } catch (err) {
      value = null;
    }
    if (value !== null && value !== '') e.value = value;
  });
  // Runs on LOAD as well as on change, so that upgrading to this build with the
  // box already cleared cleans up what an older one wrote.
  if (!savingIdentity()) {
    purgeIdentityStorage();
  }
  log.debug("Leaving loadState().");
}

// --- the held identity -----------------------------------------------------
//
// An X509-SVID and the private key that goes with it. This is what turns the
// SPIRE Server API from a surface you can only reach anonymously into one you
// can be somebody on, and there are exactly two ways to come by one here:
// FetchX509SVID on the Workload API (which needs no credential at all — that is
// the bootstrap), and AttestAgent (which makes you an agent).
//
// It is held in memory and mirrored to localStorage only while
// `spiffe_save_identity` is checked.
var IDENTITY = { certPem: '', keyPem: '', id: '', bundle: '' };

function rememberIdentity(certPem, keyPem, id, bundle) {
  log.debug("Entering rememberIdentity(). id=" + id);
  IDENTITY = { certPem: certPem || '', keyPem: keyPem || '',
               id: id || '', bundle: bundle || IDENTITY.bundle || '' };
  if (savingIdentity()) {
    try {
      localStorage.setItem('spiffe_identity_cert', IDENTITY.certPem);
      localStorage.setItem('spiffe_identity_key', IDENTITY.keyPem);
      localStorage.setItem('spiffe_identity_id', IDENTITY.id);
      localStorage.setItem('spiffe_identity_bundle', IDENTITY.bundle);
    } catch (e) {
      log.warn('could not store the held identity: ' + e.message);
    }
  }
  renderIdentity();
  log.debug("Leaving rememberIdentity().");
}

function restoreIdentity() {
  log.debug("Entering restoreIdentity().");
  if (!savingIdentity()) {
    log.debug("Leaving restoreIdentity(). Saving is off.");
    return;
  }
  try {
    IDENTITY = {
      certPem: localStorage.getItem('spiffe_identity_cert') || '',
      keyPem: localStorage.getItem('spiffe_identity_key') || '',
      id: localStorage.getItem('spiffe_identity_id') || '',
      bundle: localStorage.getItem('spiffe_identity_bundle') || ''
    };
  } catch (e) {
    log.warn('could not read the held identity: ' + e.message);
  }
  log.debug("Leaving restoreIdentity(). id=" + IDENTITY.id);
}

function forgetIdentity() {
  log.debug("Entering forgetIdentity().");
  IDENTITY = { certPem: '', keyPem: '', id: '', bundle: IDENTITY.bundle };
  purgeIdentityStorage();
  renderIdentity();
  statusOk('spiffe_identity_status', 'The held identity has been discarded. ' +
           'Calls on the SPIRE Server API will now be anonymous, which is ' +
           'enough for GetBundle and AttestAgent and for nothing else.');
  log.debug("Leaving forgetIdentity().");
  return false;
}

function renderIdentity() {
  log.debug("Entering renderIdentity().");
  setVal('spiffe_identity_id_view', IDENTITY.id ||
         '(none — the SPIRE Server API will be called anonymously)');
  setVal('spiffe_identity_cert_view', IDENTITY.certPem || '');
  setVal('spiffe_identity_bundle_view', IDENTITY.bundle || '');
  var holds = el('spiffe_identity_holds_key');
  if (holds) {
    holds.textContent = IDENTITY.keyPem
      ? 'A private key is held for this SVID, so it can be presented.'
      : 'No private key is held, so this SVID cannot be presented — an ' +
        'X509-SVID without its key proves nothing.';
    holds.className = IDENTITY.keyPem ? 'spiffe-note spiffe-ok-text'
                                      : 'spiffe-note spiffe-bad-text';
  }
  log.debug("Leaving renderIdentity().");
}

// --- the exchange pane -----------------------------------------------------

function showRequest(path, body) {
  log.debug("Entering showRequest(). path=" + path);
  var redacted = JSON.parse(JSON.stringify(body || {}));
  // The private key is the one thing that must not be echoed into a pane
  // somebody will screenshot. What is shown is that a key was sent, which is
  // the fact that matters when reading the exchange.
  if (redacted.identity && redacted.identity.keyPem) {
    redacted.identity.keyPem = '(a private key was sent, ' +
      String(redacted.identity.keyPem).length + ' characters)';
  }
  setVal('spiffe_exchange_request',
         'POST ' + path + '\n\n' + JSON.stringify(redacted, null, 2));
  log.debug("Leaving showRequest().");
}

function showResponse(status, payload) {
  log.debug("Entering showResponse(). status=" + status);
  setVal('spiffe_exchange_response',
         'HTTP ' + status + '\n\n' + JSON.stringify(payload, null, 2));
  log.debug("Leaving showResponse().");
}

// --- the api ---------------------------------------------------------------

// One call, for all forty-nine methods. Returns a promise of
// {status, payload}; it NEVER rejects because the far end said no — see the
// three-outcomes note in api/spiffe_client.js, which this function is the other
// half of.
function callApi(path, body, operation, surface, detailText, statusId) {
  log.debug("Entering callApi(). path=" + path);
  showRequest(path, body);
  statusBusy(statusId, 'Calling ' + operation + '…');
  var entryId = history.record({
    operation: operation,
    surface: surface || '',
    detailText: detailText || '',
    code: '',
    server: body.address || body.url || '',
    result: history.SENT
  });
  renderHistory();
  return fetch(API_URL + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  }).then(function (response) {
    return response.text().then(function (text) {
      var payload;
      try {
        payload = JSON.parse(text);
      } catch (e) {
        // Not JSON. The raw text is what gets shown — an HTML error page from
        // something in front of the api is exactly the case where the body is
        // the only useful evidence.
        payload = { error: text };
      }
      return { status: response.status, payload: payload };
    });
  }).then(function (answer) {
    showResponse(answer.status, answer.payload);
    var payload = answer.payload || {};
    if (answer.status === 200 && payload.ok) {
      history.update(entryId, history.SUCCESS,
                     (payload.status && payload.status.name) || 'OK');
      renderHistory();
      log.debug("Leaving callApi(). OK.");
      return answer;
    }
    if (answer.status === 200) {
      // The far end ANSWERED and the answer was no. On this surface that is
      // usually the interesting outcome rather than the disappointing one, so
      // the status line says what was refused and by whom.
      var name = (payload.status && payload.status.name) || 'unknown';
      history.update(entryId, history.FAILURE, name);
      statusBad(statusId, name + ': ' +
                ((payload.status && payload.status.details) ||
                 'no detail was given') + ' — the call reached the server ' +
                'and the server refused it.');
    } else if (payload.identityMismatch) {
      // A server answered, presented a certificate a trusted authority had
      // signed, and was somebody else. Its own outcome, because that is a
      // different fact from "nothing was there".
      history.update(entryId, history.FAILURE, 'server identity');
      statusBad(statusId, 'The server is not who this call required: ' +
                (payload.error || 'no message') + ' The chain verified — ' +
                'this is a real certificate — but it names a different ' +
                'identity.');
    } else {
      history.update(entryId, history.FAILURE,
                     (payload.code || ('HTTP ' + answer.status)));
      statusBad(statusId, 'HTTP ' + answer.status + ' from the api: ' +
                (payload.error || 'no message') + (answer.status === 400 ?
                ' (the api refused the request)' :
                ' (the server could not be reached)'));
    }
    renderHistory();
    log.debug("Leaving callApi(). status=" + answer.status);
    return answer;
  }).catch(function (error) {
    // The fetch itself failed: the api is not there, or CORS refused it. This
    // is the one branch where nothing came back at all, and it is why the
    // history has a `Sent` state.
    history.update(entryId, history.FAILURE, 'no answer: ' + error.message);
    renderHistory();
    showResponse('(no response)', { error: String(error && error.message) });
    statusBad(statusId, 'The call to the api failed: ' +
              (error && error.message) + '. The api is at ' + API_URL +
              '; this page cannot speak gRPC without it.');
    log.debug("Leaving callApi(). The fetch failed.");
    return { status: 0, payload: { error: String(error && error.message) } };
  });
}

// --- the catalogue ---------------------------------------------------------

function loadLimits() {
  log.debug("Entering loadLimits().");
  if (!BACKEND_AVAILABLE) {
    setText('spiffe_limits',
            'This build has no api behind it, so neither gRPC surface can be ' +
            'reached at all. The bundle reader, the SVID inspector and the ' +
            'SPIFFE ID checker below still work: none of them needs a ' +
            'network.');
    log.debug("Leaving loadLimits(). No backend.");
    return Promise.resolve(null);
  }
  return fetch(API_URL + '/spiffe/limits').then(function (response) {
    if (!response.ok) {
      throw new Error('HTTP ' + response.status);
    }
    return response.json();
  }).then(function (limits) {
    LIMITS = limits;
    CATALOGUE = limits.surfaces;
    populateMethodPickers();
    setText('spiffe_limits',
            'The api will dial ports ' +
            (limits.ports === 'any' ? 'ANY' : limits.ports.join(', ')) +
            ' and Unix sockets under ' +
            (limits.socketPaths === 'any' ? 'ANY path'
                                          : limits.socketPaths.join(', ')) +
            '. A stream is read for at most ' + limits.maxStreamMessages +
            ' message(s) or ' + Math.round(limits.streamTimeoutMs / 1000) +
            ' seconds. The address policy is ' +
            (limits.addressPolicy ? 'ON — private and loopback addresses are ' +
             'refused' : 'off') + '.');
    log.debug("Leaving loadLimits(). " + limits.ports);
    return limits;
  }).catch(function (error) {
    setText('spiffe_limits',
            'The api at ' + API_URL + ' did not answer GET /spiffe/limits (' +
            error.message + '). Either it is not running or it is an older ' +
            'build with no SPIFFE support — which is a different thing from ' +
            'a SPIRE server that will not answer, and worth telling apart ' +
            'before blaming the server. The three things this page does with ' +
            'no network still work: the trust bundle reader in this pane, ' +
            'and the two offline panes below.');
    log.debug("Leaving loadLimits(). Failed.");
    return null;
  });
}

function methodsOf(surface, service) {
  log.debug("Entering methodsOf().");
  var groups = (CATALOGUE && CATALOGUE[surface]) || [];
  for (var i = 0; i < groups.length; i++) {
    if (!service || groups[i].service === service) {
      log.debug("Leaving methodsOf(). " + groups[i].methods.length);
      return groups[i].methods;
    }
  }
  log.debug("Leaving methodsOf(). None.");
  return [];
}

function fillSelect(id, options, keep) {
  log.debug("Entering fillSelect(). id=" + id);
  var select = el(id);
  if (!select) {
    log.debug("Leaving fillSelect(). No such select.");
    return;
  }
  var wanted = keep || select.value;
  clear(select);
  options.forEach(function (option) {
    var node = document.createElement('option');
    node.value = option.value;
    node.textContent = option.label;
    select.appendChild(node);
  });
  if (wanted) {
    select.value = wanted;
    // A stored value naming a method that no longer exists would leave the
    // select on nothing at all, which reads as an empty catalogue.
    if (!select.value && options.length) select.value = options[0].value;
  }
  log.debug("Leaving fillSelect(). " + options.length + " option(s).");
}

function populateMethodPickers() {
  log.debug("Entering populateMethodPickers().");
  fillSelect('spiffe_workload_method', methodsOf('workload').map(function (m) {
    return { value: m.name,
             label: m.name + (m.responseStream ? '  (stream)' : '') };
  }));
  var services = ((CATALOGUE && CATALOGUE.server) || []).map(function (g) {
    return { value: g.service, label: g.label };
  });
  fillSelect('spiffe_server_service', services);
  populateServerMethods();
  describeWorkloadMethod();
  log.debug("Leaving populateMethodPickers().");
}

function populateServerMethods() {
  log.debug("Entering populateServerMethods().");
  var service = val('spiffe_server_service');
  fillSelect('spiffe_server_method',
    methodsOf('server', service).map(function (m) {
      return { value: m.name,
               label: m.name + ((m.requestStream || m.responseStream)
                                ? '  (stream)' : '') };
    }));
  describeServerMethod();
  log.debug("Leaving populateServerMethods().");
}

function methodNote(surface, service, name) {
  log.debug("Entering methodNote().");
  var rows = methodsOf(surface, service);
  for (var i = 0; i < rows.length; i++) {
    if (rows[i].name === name) {
      log.debug("Leaving methodNote(). Found.");
      return rows[i];
    }
  }
  log.debug("Leaving methodNote(). Not found.");
  return null;
}

// Show what a method is for and seed the request editor with its example. The
// editor is only overwritten when it is empty or still holds the PREVIOUS
// method's example — typing into it and then changing the picker must not
// silently discard what was typed.
function applyMethod(surface, service, methodId, requestId, aboutId, seed) {
  log.debug("Entering applyMethod(). method=" + methodId);
  var note = methodNote(surface, service, val(methodId));
  var about = el(aboutId);
  if (about) {
    about.textContent = note
      ? note.what
      : 'Waiting for the api to publish the catalogue.';
  }
  if (!note) {
    log.debug("Leaving applyMethod(). No note.");
    return;
  }
  var current = val(requestId).trim();
  var isExample = !current || SEEDED_EXAMPLES.indexOf(current) !== -1;
  if (seed || isExample) {
    var text = JSON.stringify(note.example || {}, null, 2);
    setVal(requestId, text);
    if (SEEDED_EXAMPLES.indexOf(text) === -1) SEEDED_EXAMPLES.push(text);
  }
  var streaming = el(surface === 'workload' ? 'spiffe_workload_streaming'
                                            : 'spiffe_server_streaming');
  if (streaming) {
    streaming.textContent = (note.requestStream || note.responseStream)
      ? 'This method is a STREAM. The api reads up to the message cap or the ' +
        'stream deadline and reports which stopped it; ask for two messages ' +
        'on FetchX509SVID to watch a ROTATION.'
      : '';
  }
  log.debug("Leaving applyMethod().");
}

// Every example this page has put in an editor. An editor still holding one of
// them is one the user has not touched, which is what makes seeding safe.
var SEEDED_EXAMPLES = [];

function describeWorkloadMethod() {
  log.debug("Entering describeWorkloadMethod().");
  applyMethod('workload', null, 'spiffe_workload_method',
              'spiffe_workload_request', 'spiffe_workload_about', false);
  saveState();
  log.debug("Leaving describeWorkloadMethod().");
  return false;
}

function describeServerMethod() {
  log.debug("Entering describeServerMethod().");
  applyMethod('server', val('spiffe_server_service'), 'spiffe_server_method',
              'spiffe_server_request', 'spiffe_server_about', false);
  saveState();
  log.debug("Leaving describeServerMethod().");
  return false;
}

function onChangeService() {
  log.debug("Entering onChangeService().");
  populateServerMethods();
  saveState();
  log.debug("Leaving onChangeService().");
  return false;
}

// Put the method's own example back, discarding whatever is in the editor. A
// button rather than a side effect, because the editor is where the user's work
// is and nothing should throw it away without being asked.
function resetWorkloadRequest() {
  log.debug("Entering resetWorkloadRequest().");
  applyMethod('workload', null, 'spiffe_workload_method',
              'spiffe_workload_request', 'spiffe_workload_about', true);
  log.debug("Leaving resetWorkloadRequest().");
  return false;
}

function resetServerRequest() {
  log.debug("Entering resetServerRequest().");
  applyMethod('server', val('spiffe_server_service'), 'spiffe_server_method',
              'spiffe_server_request', 'spiffe_server_about', true);
  log.debug("Leaving resetServerRequest().");
  return false;
}

// --- reading the request editors -------------------------------------------

function readJson(id, statusId, what) {
  log.debug("Entering readJson(). id=" + id);
  var text = val(id).trim();
  if (!text) {
    log.debug("Leaving readJson(). Empty.");
    return {};
  }
  try {
    var parsed = JSON.parse(text);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      statusBad(statusId, what + ' must be a JSON object — a protobuf ' +
                'message is a set of named fields, so an array or a bare ' +
                'value has nowhere to go.');
      log.debug("Leaving readJson(). Not an object.");
      return null;
    }
    log.debug("Leaving readJson(). Parsed.");
    return parsed;
  } catch (e) {
    statusBad(statusId, what + ' is not valid JSON: ' + e.message);
    log.debug("Leaving readJson(). Not JSON.");
    return null;
  }
}

// The extra gRPC metadata, one `name: value` per line. Refused by SHAPE at the
// api rather than by an allowlist, so anything a real server asks for can be
// sent — including the mock STS's `x-sts-mock-workload-selector`, which is how
// selector matching gets exercised at all.
function readMetadata(id) {
  log.debug("Entering readMetadata(). id=" + id);
  var out = {};
  val(id).split('\n').forEach(function (line) {
    var text = String(line).trim();
    if (!text) return;
    var at = text.indexOf(':');
    if (at < 1) return;
    out[text.slice(0, at).trim()] = text.slice(at + 1).trim();
  });
  log.debug("Leaving readMetadata(). " + Object.keys(out).length + " item(s).");
  return out;
}

function messageCap(id) {
  log.debug("Entering messageCap().");
  var wanted = parseInt(val(id), 10);
  if (!isFinite(wanted) || wanted < 1) wanted = 1;
  log.debug("Leaving messageCap(). " + wanted);
  return wanted;
}

// --- the Workload API ------------------------------------------------------

function callWorkload() {
  log.debug("Entering callWorkload().");
  saveState();
  var request = readJson('spiffe_workload_request',
                         'spiffe_workload_status', 'The request');
  if (request === null) {
    log.debug("Leaving callWorkload(). Bad JSON.");
    return false;
  }
  var method = val('spiffe_workload_method');
  var body = {
    address: val('spiffe_workload_address'),
    service: 'workload',
    method: method,
    request: request,
    metadata: readMetadata('spiffe_workload_metadata'),
    maxMessages: messageCap('spiffe_workload_messages'),
    // Unchecking this is the only way to see what a conforming server does to
    // a client that forgot the header, which is a bug nothing else reports.
    securityHeader: isOn('spiffe_workload_security_header')
  };
  callApi('/spiffe/call', body, method, 'Workload API',
          JSON.stringify(request).slice(0, 120), 'spiffe_workload_status')
    .then(function (answer) {
      renderMessages('spiffe_workload_result', answer.payload);
      if (answer.status === 200 && answer.payload.ok) {
        statusOk('spiffe_workload_status', describeOk(answer.payload));
        offerIdentityFrom(answer.payload);
      }
      log.debug("callWorkload(): rendered.");
    });
  log.debug("Leaving callWorkload().");
  return false;
}

function describeOk(payload) {
  log.debug("Entering describeOk().");
  var stream = payload.streaming || {};
  var text = 'OK — ' + payload.messages.length + ' message(s) in ' +
    ((payload.timing && payload.timing.totalMs) || 0) + 'ms.';
  if (stream.response || stream.request) {
    text += ' The stream stopped because ' + ({
      messages: 'the message cap was reached',
      timeout: 'the stream deadline expired',
      size: 'the size cap was reached',
      end: 'the server ended it'
    }[stream.stopped] || stream.stopped) + '.';
  }
  log.debug("Leaving describeOk().");
  return text;
}

// FetchX509SVID and AttestAgent both hand back an SVID with its key, and both
// are how somebody comes to have an identity here. Rather than making the user
// copy four base64 blobs between panes, the SVID is offered as the held
// identity — which is the only thing that makes the SPIRE Server API reachable
// as anybody at all.
function offerIdentityFrom(payload) {
  log.debug("Entering offerIdentityFrom().");
  var first = payload.messages && payload.messages[0];
  if (!first) {
    log.debug("Leaving offerIdentityFrom(). No messages.");
    return;
  }
  var svid = first.svids && first.svids[0];
  if (svid && svid.x509_svid && svid.x509_svid_key) {
    rememberIdentity(svid.x509_svid, svid.x509_svid_key, svid.spiffe_id,
                     svid.bundle || '');
    statusOk('spiffe_identity_status', 'Held: ' + svid.spiffe_id +
             '. This came from the Workload API, which needs no credential — ' +
             'that is the bootstrap the SPIFFE specification describes, and ' +
             'it is why the SPIRE Server API can now be called as somebody.');
    log.debug("Leaving offerIdentityFrom(). Workload SVID kept.");
    return;
  }
  log.debug("Leaving offerIdentityFrom(). Nothing to keep.");
}

// --- the SPIRE Server API --------------------------------------------------

function serverIdentityFor(body) {
  log.debug("Entering serverIdentityFor().");
  var which = val('spiffe_server_present');
  if (which === 'held' && IDENTITY.certPem && IDENTITY.keyPem) {
    body.identity = { certPem: IDENTITY.certPem, keyPem: IDENTITY.keyPem };
  } else if (which === 'pasted') {
    body.identity = { certPem: val('spiffe_server_cert'),
                      keyPem: val('spiffe_server_key') };
  }
  log.debug("Leaving serverIdentityFor(). " + which);
  return body;
}

function callServer() {
  log.debug("Entering callServer().");
  saveState();
  var request = readJson('spiffe_server_request', 'spiffe_server_status',
                         'The request');
  if (request === null) {
    log.debug("Leaving callServer(). Bad JSON.");
    return false;
  }
  var method = val('spiffe_server_method');
  var service = val('spiffe_server_service');
  var body = {
    address: val('spiffe_server_address'),
    service: service,
    method: method,
    request: request,
    metadata: readMetadata('spiffe_server_metadata'),
    maxMessages: messageCap('spiffe_server_messages'),
    trustDomain: val('spiffe_trust_domain'),
    serverIdentityMode: val('spiffe_server_identity_mode'),
    serverId: val('spiffe_server_id'),
    trustBundle: val('spiffe_server_bundle') || IDENTITY.bundle,
    // Only for a deployment with mutual TLS turned OFF on this port. It is a
    // deliberate choice rather than a fallback: a client that silently dropped
    // to plaintext when TLS failed would be the worst possible default here.
    plaintext: isOn('spiffe_server_plaintext')
  };
  serverIdentityFor(body);
  callApi('/spiffe/call', body, method,
          'SPIRE Server API / ' + service,
          JSON.stringify(request).slice(0, 120), 'spiffe_server_status')
    .then(function (answer) {
      renderMessages('spiffe_server_result', answer.payload);
      renderPeer(answer.payload);
      if (answer.status === 200 && answer.payload.ok) {
        statusOk('spiffe_server_status', describeOk(answer.payload));
        keepIssuedSvid(answer.payload);
      }
      log.debug("callServer(): rendered.");
    });
  log.debug("Leaving callServer().");
  return false;
}

// AttestAgent and RenewAgent hand back an SVID for the key in the CSR that was
// just sent — so the private key that goes with it is the one the CSR pane
// generated, and it is still here. Pairing the two is what makes "attest, then
// call an agent method" a thing somebody can actually do on this page.
function keepIssuedSvid(payload) {
  log.debug("Entering keepIssuedSvid().");
  var first = (payload.messages && payload.messages[0]) || {};
  var svid = (first.result && first.result.svid) || first.svid;
  var chain = svid && svid.cert_chain;
  if (!chain || !chain.length) {
    log.debug("Leaving keepIssuedSvid(). No SVID in the answer.");
    return;
  }
  if (!CSR_KEY) {
    statusBad('spiffe_identity_status', 'An SVID came back, and the private ' +
              'key it belongs to is not here — it was in a certification ' +
              'request this page did not build. An X509-SVID without its key ' +
              'proves nothing, so it has not been kept.');
    log.debug("Leaving keepIssuedSvid(). No key for it.");
    return;
  }
  var id = svid.id ? spiffeId.fromProto(svid.id) : '';
  rememberIdentity(chain[0], CSR_KEY, id, IDENTITY.bundle);
  statusOk('spiffe_identity_status', 'Held: ' + (id || 'an issued SVID') +
           ', paired with the private key from the certification request ' +
           'this page built. Calls on the SPIRE Server API will now present ' +
           'it.');
  log.debug("Leaving keepIssuedSvid(). Kept.");
}

function renderPeer(payload) {
  log.debug("Entering renderPeer().");
  var peer = payload && payload.peer;
  var node = el('spiffe_server_peer');
  if (!node) {
    log.debug("Leaving renderPeer(). No pane.");
    return;
  }
  if (!peer || !peer.uris) {
    node.textContent = payload && payload.transport === 'unix'
      ? 'A Unix socket, so there is no TLS and no certificate to report — ' +
        'this socket is the `local` entity and its access control is the ' +
        'filesystem.'
      : '';
    log.debug("Leaving renderPeer(). Nothing to show.");
    return;
  }
  node.textContent = 'The server presented ' +
    (peer.uris.length ? peer.uris.join(', ')
                      : 'a certificate with no URI subjectAltName') +
    (peer.validTo ? ', valid until ' + peer.validTo : '') +
    '. Note that this is the ONLY thing identifying it: a SPIRE server\'s ' +
    'certificate carries no DNS name, so hostname verification cannot apply.';
  log.debug("Leaving renderPeer().");
}

// --- rendering an answer ---------------------------------------------------

function renderMessages(id, payload) {
  log.debug("Entering renderMessages(). id=" + id);
  var node = el(id);
  if (!node) {
    log.debug("Leaving renderMessages(). No pane.");
    return;
  }
  clear(node);
  if (!payload) {
    log.debug("Leaving renderMessages(). No payload.");
    return;
  }
  if (!payload.messages || !payload.messages.length) {
    var empty = document.createElement('p');
    empty.className = 'spiffe-note';
    // Every <p> this page GENERATES carries an id, and the four result
    // containers are why: they sit outside the folds the shipped prose lives
    // in, so a note drawn into one is a paragraph of unfolded text as far as
    // anything reading the DOM can tell — including tests/spiffe_page.js,
    // whose "every explanation is inside a fold" check exempts prose with an
    // id precisely because an id marks a SLOT the page fills rather than
    // prose it ships.
    empty.id = id + '_note';
    empty.textContent = payload.status
      ? 'No messages. The server answered ' + payload.status.name +
        (payload.status.details ? ': ' + payload.status.details : '') + '.'
      : (payload.error || 'No messages.');
    node.appendChild(empty);
    log.debug("Leaving renderMessages(). Empty.");
    return;
  }
  payload.messages.forEach(function (message, index) {
    var heading = document.createElement('p');
    heading.className = 'spiffe-note';
    heading.id = id + '_message_' + (index + 1);
    heading.textContent = payload.messages.length > 1
      ? 'Message ' + (index + 1) + ' of ' + payload.messages.length
      : 'The answer';
    node.appendChild(heading);
    var box = document.createElement('textarea');
    box.className = 'spiffe-output';
    box.readOnly = true;
    box.rows = 12;
    // A tooltip here for the same reason every other control on this page has
    // one: with the prose folded, this is the only explanation on screen for
    // the box somebody is looking straight at.
    box.title = 'The message the server sent back, as JSON. This is what ' +
      'came off the wire, decoded from protobuf and nothing more — no ' +
      'field is added, renamed or interpreted here.';
    // textContent rather than innerHTML, everywhere on this page. What is being
    // rendered came off a wire this page does not control, and a readonly
    // textarea holding text is a sink with no interpretation at all — which is
    // a stronger position than sanitising markup that never needed to be
    // markup.
    box.textContent = JSON.stringify(message, null, 2);
    node.appendChild(box);
  });
  log.debug("Leaving renderMessages(). " + payload.messages.length);
}

// --- the trust bundle ------------------------------------------------------

function fetchBundle() {
  log.debug("Entering fetchBundle().");
  saveState();
  var url = val('spiffe_bundle_url');
  if (!url) {
    statusBad('spiffe_bundle_status', 'A bundle endpoint URL is needed.');
    log.debug("Leaving fetchBundle(). No URL.");
    return false;
  }
  callApi('/spiffe/bundle',
          { url: url, sslValidate: isOn('spiffe_bundle_ssl') },
          'GET the bundle', 'Bundle endpoint', url, 'spiffe_bundle_status')
    .then(function (answer) {
      var payload = answer.payload || {};
      if (payload.body) {
        setVal('spiffe_bundle_document', payload.body);
        // Kept as the trust anchor for the SPIRE Server API, because that is
        // what a bundle IS for and copying it by hand between two panes is
        // friction with no lesson in it.
        describeBundleText(payload.report);
      }
      if (answer.status === 200 && payload.report) {
        var report = payload.report;
        if (report.ok) {
          statusOk('spiffe_bundle_status', 'HTTP ' + payload.httpStatus +
                   '. ' + report.keys.length + ' usable key(s): ' +
                   report.counts['x509-svid'] + ' x509-svid, ' +
                   report.counts['jwt-svid'] + ' jwt-svid' +
                   (report.warnings.length ? '; ' + report.warnings.length +
                    ' warning(s) below' : '') + '.');
        } else {
          statusBad('spiffe_bundle_status', 'HTTP ' + payload.httpStatus +
                    ', and the document cannot be used as a trust bundle: ' +
                    report.errors[0]);
        }
      }
      log.debug("fetchBundle(): rendered.");
    });
  log.debug("Leaving fetchBundle().");
  return false;
}

// The offline half. Reads whatever is in the document box with no network at
// all, which is what makes this group useful on a static deployment and when
// somebody has a bundle in a file and a question about it.
function readBundle() {
  log.debug("Entering readBundle().");
  var report = spiffeBundle.describe(val('spiffe_bundle_document'));
  describeBundleText(report);
  if (report.ok) {
    statusOk('spiffe_bundle_status', report.keys.length +
             ' usable key(s), read here with no network: ' +
             report.counts['x509-svid'] + ' x509-svid, ' +
             report.counts['jwt-svid'] + ' jwt-svid.');
  } else {
    statusBad('spiffe_bundle_status', report.errors[0]);
  }
  log.debug("Leaving readBundle().");
  return false;
}

function describeBundleText(report) {
  log.debug("Entering describeBundleText().");
  var node = el('spiffe_bundle_report');
  if (!node || !report) {
    log.debug("Leaving describeBundleText(). Nothing to draw.");
    return;
  }
  clear(node);
  var summary = document.createElement('p');
  summary.className = 'spiffe-note';
  summary.id = 'spiffe_bundle_summary';
  summary.textContent = 'spiffe_sequence ' +
    (report.sequence === null ? '(absent)' : report.sequence) +
    ', spiffe_refresh_hint ' +
    (report.refreshHint === null ? '(absent)' : report.refreshHint + 's') +
    ', ' + report.keys.length + ' usable key(s), ' +
    report.ignored.length + ' a consumer must ignore.';
  node.appendChild(summary);

  [['spiffe-bad-text', 'Error', report.errors],
   ['spiffe-warn-text', 'Warning', report.warnings]].forEach(function (pair) {
    pair[2].forEach(function (line, index) {
      var p = document.createElement('p');
      p.className = 'spiffe-note ' + pair[0];
      p.id = 'spiffe_bundle_' + pair[1].toLowerCase() + '_' + (index + 1);
      p.textContent = pair[1] + ': ' + line;
      node.appendChild(p);
    });
  });

  if (report.keys.length || report.ignored.length) {
    var table = document.createElement('table');
    table.className = 'spiffe-table';
    var head = document.createElement('tr');
    ['#', 'use', 'kty / crv', 'kid', 'x5c', 'Status'].forEach(function (name) {
      var th = document.createElement('th');
      th.textContent = name;
      head.appendChild(th);
    });
    table.appendChild(head);
    report.keys.forEach(function (key) {
      var row = document.createElement('tr');
      cell(row, key.index);
      cell(row, key.use);
      cell(row, key.kty + (key.crv ? ' / ' + key.crv : ''));
      cell(row, key.kid, 'spiffe-wrap');
      cell(row, key.x5c.length ? key.x5c.length + ' certificate(s)' : '—');
      cell(row, key.problems.length ? key.problems.join(' ') : 'usable',
           key.problems.length ? 'spiffe-warn-text' : 'spiffe-ok-text');
      table.appendChild(row);
    });
    report.ignored.forEach(function (key) {
      var row = document.createElement('tr');
      cell(row, key.index);
      cell(row, key.use || '(none)');
      cell(row, '—');
      cell(row, key.kid || '', 'spiffe-wrap');
      cell(row, '—');
      cell(row, 'IGNORED — ' + key.reason, 'spiffe-bad-text');
      table.appendChild(row);
    });
    node.appendChild(table);
  }
  log.debug("Leaving describeBundleText().");
}

// The bundle in the document box, as the trust anchor for the SPIRE Server API.
// The x5c members are what an X.509 authority actually is; the JWT keys have no
// certificate and are not anchors for TLS.
function useBundleAsAnchor() {
  log.debug("Entering useBundleAsAnchor().");
  var report = spiffeBundle.describe(val('spiffe_bundle_document'));
  var anchors = [];
  spiffeBundle.keysFor(report, spiffeBundle.USE_X509).forEach(function (key) {
    key.x5c.forEach(function (one) {
      anchors.push(one);
    });
  });
  if (!anchors.length) {
    statusBad('spiffe_bundle_status', 'There is no x509-svid key with an x5c ' +
              'in this bundle, so there is no X.509 trust anchor in it. A ' +
              'jwt-svid key verifies JWT-SVIDs and cannot verify a TLS ' +
              'connection.');
    log.debug("Leaving useBundleAsAnchor(). No anchors.");
    return false;
  }
  // PEM rather than the raw base64 the JWK carries, because that is what the
  // field's label promises and what a reader can paste anywhere else — and
  // because SEPARATE BLOCKS are the visible form of the sentence below. A
  // single run of concatenated base64 would look like one authority, and node
  // reads concatenated DER as exactly that.
  var pem = anchors.map(function (one) {
    return '-----BEGIN CERTIFICATE-----\n' +
      String(one).replace(/\s+/g, '').replace(/(.{64})/g, '$1\n')
        .replace(/\n$/, '') +
      '\n-----END CERTIFICATE-----';
  }).join('\n');
  setVal('spiffe_server_bundle', pem);
  IDENTITY.bundle = pem;
  statusOk('spiffe_bundle_status', anchors.length + ' X.509 authority/ies ' +
           'are now the trust anchor in the SPIRE Server API group. Note ' +
           'that ALL of them go across: a trust domain that has rotated ' +
           'publishes the old authority too, and dropping it is the ' +
           'difference between a rotation and an outage.');
  log.debug("Leaving useBundleAsAnchor(). " + anchors.length);
  return false;
}

// --- the certification request builder -------------------------------------

// The private key of the last CSR built here. Held so that an SVID issued
// against that CSR can be paired with it — see keepIssuedSvid().
var CSR_KEY = '';

function buildCsr() {
  log.debug("Entering buildCsr().");
  saveState();
  statusBusy('spiffe_csr_status', 'Generating a key pair and signing the ' +
             'request…');
  var alg = val('spiffe_csr_key_alg') || 'ec-p256';
  var uri = val('spiffe_csr_uri').trim();
  var names = [];
  if (uri) {
    var parsed = spiffeId.parse(uri);
    if (!parsed.ok) {
      statusBad('spiffe_csr_status', 'That is not a SPIFFE ID: ' +
                parsed.reason);
      log.debug("Leaving buildCsr(). Bad SPIFFE ID.");
      return false;
    }
    names.push({ kind: 'uri', value: parsed.id });
  }
  keys.generateKeyPair(alg).then(function (pair) {
    return x509.certificationRequest({
      subject: val('spiffe_csr_subject') || 'C=US,O=SPIRE',
      publicKeyPem: pair.publicPem,
      privateKeyPem: pair.privatePem,
      subjectAltName: names
    }).then(function (csr) {
      CSR_KEY = pair.privatePem;
      setVal('spiffe_csr_base64', csr.base64);
      setVal('spiffe_csr_pem', csr.pem);
      setVal('spiffe_csr_key', pair.privatePem);
      statusOk('spiffe_csr_status', 'A ' + alg + ' key pair and a PKCS#10 ' +
               'request signed with it. The private key STAYS HERE — that is ' +
               'the point of a certification request, and it is why an SVID ' +
               'issued against this one can be presented afterwards.');
      log.debug("buildCsr(): built.");
    });
  }).catch(function (error) {
    statusBad('spiffe_csr_status', 'The request could not be built: ' +
              (error && error.message));
    log.debug("buildCsr(): failed.");
  });
  log.debug("Leaving buildCsr().");
  return false;
}

// Put the base64 CSR into whichever request editor wants one. Which field it
// belongs in differs per method, so the target path is named rather than
// guessed — `csr`, `params.params.csr`, `params.csr` and `params[0].csr` are
// four different places across the five methods that take one.
function insertCsr(target) {
  log.debug("Entering insertCsr(). target=" + target);
  var base64 = val('spiffe_csr_base64');
  if (!base64) {
    statusBad('spiffe_csr_status', 'Build a request first.');
    log.debug("Leaving insertCsr(). Nothing to insert.");
    return false;
  }
  var editor = target === 'workload' ? 'spiffe_workload_request'
                                     : 'spiffe_server_request';
  var statusId = target === 'workload' ? 'spiffe_workload_status'
                                       : 'spiffe_server_status';
  var request = readJson(editor, statusId, 'The request');
  if (request === null) {
    log.debug("Leaving insertCsr(). The editor does not parse.");
    return false;
  }
  var placed = placeCsr(request, base64);
  if (!placed) {
    statusBad('spiffe_csr_status', 'The request in that editor has no csr ' +
              'field to fill. The five methods that take one are ' +
              'AttestAgent, RenewAgent, MintX509SVID, BatchNewX509SVID and ' +
              'NewDownstreamX509CA — load one of their examples first.');
    log.debug("Leaving insertCsr(). Nowhere to put it.");
    return false;
  }
  setVal(editor, JSON.stringify(request, null, 2));
  statusOk('spiffe_csr_status', 'The request is in the ' + target +
           ' editor. The private key for it is held here, so an SVID issued ' +
           'against it will be paired with its key automatically.');
  log.debug("Leaving insertCsr(). Placed.");
  return false;
}

// Walk the object for a `csr` member at any depth and fill it. Written as a
// walk rather than as a table of the four paths, because the table would have
// to be right about four methods and this has to be right about one word.
function placeCsr(node, base64) {
  log.debug("Entering placeCsr().");
  if (!node || typeof node !== 'object') {
    log.debug("Leaving placeCsr(). Not an object.");
    return false;
  }
  if (Array.isArray(node)) {
    for (var i = 0; i < node.length; i++) {
      if (placeCsr(node[i], base64)) {
        log.debug("Leaving placeCsr(). Placed in an array.");
        return true;
      }
    }
    log.debug("Leaving placeCsr(). Not in this array.");
    return false;
  }
  if (Object.prototype.hasOwnProperty.call(node, 'csr')) {
    node.csr = base64;
    log.debug("Leaving placeCsr(). Placed.");
    return true;
  }
  var names = Object.keys(node);
  for (var j = 0; j < names.length; j++) {
    if (placeCsr(node[names[j]], base64)) {
      log.debug("Leaving placeCsr(). Placed below.");
      return true;
    }
  }
  log.debug("Leaving placeCsr(). Not here.");
  return false;
}

// --- the SVID inspector ----------------------------------------------------

function inspectSvid() {
  log.debug("Entering inspectSvid().");
  var text = val('spiffe_svid_input').trim();
  if (!text) {
    statusBad('spiffe_svid_status', 'Paste an X509-SVID (PEM or base64 DER) ' +
              'or a JWT-SVID.');
    log.debug("Leaving inspectSvid(). Empty.");
    return false;
  }
  if (text.split('.').length === 3 && text.indexOf('-----') === -1) {
    describeJwtSvid(text);
    log.debug("Leaving inspectSvid(). JWT.");
    return false;
  }
  describeX509Svid(text);
  log.debug("Leaving inspectSvid(). X.509.");
  return false;
}

function describeX509Svid(text) {
  log.debug("Entering describeX509Svid().");
  var pem = text.indexOf('-----BEGIN') !== -1 ? text
    : '-----BEGIN CERTIFICATE-----\n' +
      text.replace(/\s+/g, '').replace(/(.{64})/g, '$1\n') +
      '\n-----END CERTIFICATE-----';
  x509.describeCertificate(pem).then(function (described) {
    var uris = [];
    (described.extensions || []).forEach(function (ext) {
      if (ext.name === 'subjectAltName' || ext.oid === '2.5.29.17') {
        String(x509.extensionValueText(ext) || '').split(/[\n,]/)
          .forEach(function (part) {
            var one = String(part).trim();
            if (one.slice(0, 4).toUpperCase() === 'URI:') {
              uris.push(one.slice(4));
            }
            else if (one.indexOf('spiffe://') === 0) {
              uris.push(one);
            }
          });
      }
    });
    setVal('spiffe_svid_output', JSON.stringify(described, null, 2));
    // The one thing that makes a certificate an SVID, checked and said out
    // loud: the identity is the URI subjectAltName and NOTHING else. The
    // subject DN is decoration — SPIRE issues `C=US, O=SPIRE` to everything —
    // so a reader who looks at the subject for the identity is looking at the
    // one field that never carries it.
    if (!uris.length) {
      statusBad('spiffe_svid_status', 'This certificate has no URI ' +
                'subjectAltName, so it is not an X509-SVID: a SPIFFE ' +
                'identity lives there and nowhere else. Its subject is ' +
                (described.subject || '(none)') + ', which in SPIFFE carries ' +
                'no meaning at all.');
      log.debug("Leaving describeX509Svid(). No URI SAN.");
      return;
    }
    if (uris.length > 1) {
      statusBad('spiffe_svid_status', 'This certificate has ' + uris.length +
                ' URI subjectAltNames (' + uris.join(', ') + '). An SVID has ' +
                'exactly one — choosing between two would be deciding which ' +
                'identity its holder has.');
      log.debug("Leaving describeX509Svid(). Several URI SANs.");
      return;
    }
    var parsed = spiffeId.parse(uris[0]);
    statusOk('spiffe_svid_status', (parsed.ok
      ? 'X509-SVID for ' + parsed.id + ' (trust domain ' + parsed.trustDomain +
        (parsed.reserved ? ', a RESERVED /spire path — this is a server or ' +
         'an agent rather than a workload' : '') + ')'
      : 'The URI subjectAltName is ' + uris[0] + ', which is NOT a valid ' +
        'SPIFFE ID: ' + parsed.reason) +
      '. Valid ' + described.notBefore + ' to ' + described.notAfter + '.');
    log.debug("Leaving describeX509Svid(). Described.");
  }).catch(function (error) {
    statusBad('spiffe_svid_status', 'That is not a certificate this page can ' +
              'read: ' + (error && error.message));
    log.debug("Leaving describeX509Svid(). Failed.");
  });
}

function b64uToText(text) {
  log.debug("Entering b64uToText().");
  var padded = String(text).replace(/-/g, '+').replace(/_/g, '/');
  while (padded.length % 4) { padded += '='; }
  var binary = atob(padded);
  var bytes = new Uint8Array(binary.length);
  for (var i = 0; i < binary.length; i++) { bytes[i] = binary.charCodeAt(i); }
  log.debug("Leaving b64uToText().");
  return new TextDecoder().decode(bytes);
}

function describeJwtSvid(text) {
  log.debug("Entering describeJwtSvid().");
  var parts = text.split('.');
  var header;
  var claims;
  try {
    header = JSON.parse(b64uToText(parts[0]));
    claims = JSON.parse(b64uToText(parts[1]));
  } catch (e) {
    statusBad('spiffe_svid_status', 'That has three dot-separated parts and ' +
              'is not a JWT: ' + e.message);
    log.debug("Leaving describeJwtSvid(). Not a JWT.");
    return;
  }
  setVal('spiffe_svid_output',
         JSON.stringify({ header: header, claims: claims }, null, 2));
  var problems = [];
  var parsed = spiffeId.parse(claims.sub);
  if (!parsed.ok) {
    problems.push('the sub is not a SPIFFE ID (' + parsed.reason + ')');
  }
  // The audience is not decoration on a JWT-SVID. It is a BEARER credential,
  // and the audience is the only thing that stops one issued for service A
  // being replayed against service B — which is why every conforming
  // implementation refuses to issue one without it.
  if (!claims.aud || (Array.isArray(claims.aud) && !claims.aud.length)) {
    problems.push('there is no aud, so nothing stops this token being ' +
                  'replayed against a service it was not issued for');
  }
  if (!claims.exp) {
    problems.push('there is no exp, so this token never expires');
  } else if (claims.exp * 1000 < Date.now()) {
    problems.push('it expired at ' + new Date(claims.exp * 1000).toISOString());
  }
  if (!header.kid) {
    problems.push('the header has no kid, so a verifier has to try every ' +
                  'jwt-svid key in the bundle');
  }
  if (problems.length) {
    statusBad('spiffe_svid_status', 'JWT-SVID read, and ' + problems.length +
              ' thing(s) are wrong with it: ' + problems.join('; ') +
              '. Note that reading a token is not verifying one — send it to ' +
              'ValidateJWTSVID on the Workload API for that.');
  } else {
    statusOk('spiffe_svid_status', 'JWT-SVID for ' + parsed.id +
             ', audience ' + [].concat(claims.aud).join(', ') +
             ', expiring ' + new Date(claims.exp * 1000).toISOString() +
             '. READ, not verified — nothing here checked the signature. ' +
             'ValidateJWTSVID on the Workload API is what does that.');
  }
  log.debug("Leaving describeJwtSvid().");
}

// --- the SPIFFE ID checker -------------------------------------------------

function checkSpiffeId() {
  log.debug("Entering checkSpiffeId().");
  saveState();
  var text = val('spiffe_id_input');
  var parsed = spiffeId.parse(text);
  var node = el('spiffe_id_report');
  if (node) {
    clear(node);
    var line = document.createElement('p');
    line.id = 'spiffe_id_verdict';
    line.className = 'spiffe-note ' +
      (parsed.ok ? 'spiffe-ok-text' : 'spiffe-bad-text');
    line.textContent = parsed.ok
      ? 'Valid. Trust domain ' + parsed.trustDomain + '; path ' +
        (parsed.path || '(none — this names the trust domain itself, which ' +
         'is what keys a bundle map)') +
        (parsed.reserved ? '. This is under the RESERVED /spire path, which ' +
         'belongs to the SPIFFE implementation itself — a registration entry ' +
         'there is refused.' : '.')
      : 'Not a SPIFFE ID: ' + parsed.reason;
    node.appendChild(line);
    if (parsed.ok) {
      var member = document.createElement('p');
      member.id = 'spiffe_id_membership';
      member.className = 'spiffe-note';
      var against = val('spiffe_trust_domain');
      member.textContent = against
        ? (spiffeId.memberOf(parsed.id, against)
            ? 'It belongs to ' + against + '.'
            : 'It does NOT belong to ' + against + '. Membership is decided ' +
              'by comparing parsed trust domains and never by a prefix test, ' +
              'which is what stops spiffe://' + against +
              '.example.invalid/x passing for one.')
        : '';
      node.appendChild(member);
    }
  }
  log.debug("Leaving checkSpiffeId(). ok=" + parsed.ok);
  return false;
}

// --- history ---------------------------------------------------------------

function renderHistory() {
  log.debug("Entering renderHistory().");
  history.render(el('spiffe_operation_history'));
  log.debug("Leaving renderHistory().");
}

function clearOperationHistory() {
  log.debug("Entering clearOperationHistory().");
  history.clear();
  renderHistory();
  log.debug("Leaving clearOperationHistory().");
  return false;
}

function onToggleSaveIdentity() {
  log.debug("Entering onToggleSaveIdentity().");
  saveState();
  if (!savingIdentity()) {
    statusOk('spiffe_identity_status', 'The held identity will not be ' +
             'written to this browser\'s storage, and whatever was there has ' +
             'been removed. It stays in this page until you reload.');
  }
  log.debug("Leaving onToggleSaveIdentity().");
  return false;
}

function onChangeField() {
  log.debug("Entering onChangeField().");
  saveState();
  log.debug("Leaving onChangeField().");
  return false;
}

// Put a value in a field that has none. A field the user has typed in — or one
// loadState() has just filled from storage — is left exactly as it is, which is
// what makes this safe to call on every load.
//
// `configured` is what CONFIG_FILE says and `fallback` is what this page uses
// when the config says nothing. An EMPTY string in the config is a deliberate
// answer (see the note in init(), and prod.js), so only null/undefined falls
// through to the fallback.
function seed(id, configured, fallback) {
  log.debug("Entering seed(). id=" + id);
  if (val(id)) {
    log.debug("Leaving seed(). Already filled.");
    return;
  }
  var value = (configured === null || configured === undefined)
    ? fallback : configured;
  setVal(id, value);
  log.debug("Leaving seed(). value=" + value);
}

// ---------------------------------------------------------------------------
// PANE COLLAPSE, using the shared `.dbg-*` chrome rather than a fourth
// implementation of it.
//
// The markup contract is `scim.html`'s, which is the Kerberos pages':
//
//   <div class="spiffe-pane dbg-pane" id="pane_x">
//     <legend class="dbg-legend" id="spiffe_x_expand_button">Title</legend>
//     <fieldset name="spiffe_x_fieldset" id="spiffe_x_fieldset"
//               style="display: block;">…</fieldset>
//   </div>
//
// The legend and the fieldset are PAIRED BY CONVENTION — `x_expand_button`
// drives `x_fieldset` — rather than by an inline
// `onclick="spiffe.togglePane('x_fieldset')"`. The inline spelling writes the
// id twice and fails silently when the two drift: a pane title that does
// nothing at all, with nothing anywhere complaining. Here a drifted pair is a
// console warning, and this page's console is asserted clean by
// `tests/spiffe_page.js`, so it is a failure rather than a shrug.
//
// The `style="display: block"` in the markup is not decoration either:
// css/debugger.css turns the triangle with
// `.dbg-pane:has(fieldset[style*="display: none"])`, which reads the INLINE
// style, so a pane that started with no inline display at all would show an
// expanded triangle over a pane the switch had never touched.
// ---------------------------------------------------------------------------
function togglePane(bodyId) {
  log.debug("Entering togglePane(). id=" + bodyId);
  var body = el(bodyId);
  if (!body) {
    log.debug("Leaving togglePane(). No such pane.");
    return false;
  }
  body.style.display = (body.style.display === 'none') ? 'block' : 'none';
  log.debug("Leaving togglePane(). " + body.style.display);
  return false;
}

// Expand or collapse every pane on the page.
//
// The fieldsets are DISCOVERED rather than listed. Several workflows here keep
// an array of pane ids instead, and every one of those is a list a new pane
// has to be remembered into — an omission whose only symptom is the one pane
// the switch skips. Reading them off the DOM covers a pane added later by
// construction.
function setAllPanes(expand) {
  log.debug("Entering setAllPanes(). expand=" + !!expand);
  var panes = document.querySelectorAll('.dbg-pane > fieldset');
  for (var i = 0; i < panes.length; i++) {
    panes[i].style.display = expand ? 'block' : 'none';
  }
  var text = document.querySelector('.dbg-toggle-text');
  if (text) {
    text.textContent = expand ? 'Collapse all panes' : 'Expand all panes';
  }
  log.debug("Leaving setAllPanes(). " + panes.length + " pane(s).");
  return false;
}

// Bind every pane's title to its fieldset, and the one switch to all of them.
//
// A legend whose fieldset is missing is REPORTED rather than skipped: that is
// exactly the drift the id convention exists to prevent, and a silent
// `continue` would hide it again behind a title that does nothing.
function wirePanes() {
  log.debug("Entering wirePanes().");
  var legends = document.querySelectorAll('.dbg-legend');
  var wired = 0;
  for (var i = 0; i < legends.length; i++) {
    var legend = legends[i];
    var id = legend.id || '';
    if (id.indexOf('_expand_button') === -1) {
      log.warn('a .dbg-legend has id ' + JSON.stringify(id) + ', which does ' +
          'not end in _expand_button, so it cannot be paired with a fieldset');
      continue;
    }
    var bodyId = id.replace('_expand_button', '_fieldset');
    if (!el(bodyId)) {
      log.warn('legend ' + id + ' names no fieldset ' + bodyId + ' — the ' +
          "pane's ids have drifted and the title will do nothing");
      continue;
    }
    legend.addEventListener('click', (function (target) {
      return function () {
        togglePane(target);
        return false;
      };
    })(bodyId));
    wired += 1;
  }
  var toggleAll = el('dbg_toggle_all');
  if (toggleAll) {
    toggleAll.addEventListener('change', function () {
      setAllPanes(toggleAll.checked);
    });
  } else {
    log.warn('there is no dbg_toggle_all on this page, so nothing expands ' +
        'or collapses every pane at once');
  }
  log.debug("Leaving wirePanes(). " + wired + " pane(s) wired.");
  return wired;
}

function init() {
  log.debug("Entering init().");
  loadState();
  restoreIdentity();
  renderIdentity();
  renderHistory();
  // Seeded only where nothing was stored, so a reload keeps what was typed.
  //
  // THE FOUR ADDRESSES COME FROM `CONFIG_FILE`, and until this build they did
  // not: `spiffeTrustDomainDefault`, `spiffeWorkloadAddressDefault`,
  // `spiffeServerAddressDefault` and `spiffeBundleUrlDefault` were declared in
  // every `client/src/env/*.js`, documented in docs/spiffe.md as "the page's
  // defaults", and read by nothing at all — so a deployment that set them got
  // an empty box and no complaint from anywhere. They are read here now, which
  // is also why `prod.js` and `test-idptools-com.js` leave them EMPTY: those
  // targets have no api, so neither gRPC surface exists and an address would
  // be a suggestion to dial something unreachable.
  seed('spiffe_trust_domain', appconfig.spiffeTrustDomainDefault,
       'example.org');
  seed('spiffe_workload_address', appconfig.spiffeWorkloadAddressDefault, '');
  seed('spiffe_server_address', appconfig.spiffeServerAddressDefault, '');
  seed('spiffe_bundle_url', appconfig.spiffeBundleUrlDefault, '');
  seed('spiffe_csr_subject', null, 'C=US,O=SPIRE');
  wirePanes();
  mountAutoFit();
  loadLimits();
  log.debug("Leaving init().");
}

if (typeof document !== 'undefined' && document.addEventListener) {
  document.addEventListener('DOMContentLoaded', init);
}

module.exports = {
  callWorkload: callWorkload,
  callServer: callServer,
  fetchBundle: fetchBundle,
  readBundle: readBundle,
  useBundleAsAnchor: useBundleAsAnchor,
  buildCsr: buildCsr,
  insertCsr: insertCsr,
  inspectSvid: inspectSvid,
  checkSpiffeId: checkSpiffeId,
  describeWorkloadMethod: describeWorkloadMethod,
  describeServerMethod: describeServerMethod,
  onChangeService: onChangeService,
  resetWorkloadRequest: resetWorkloadRequest,
  resetServerRequest: resetServerRequest,
  forgetIdentity: forgetIdentity,
  onToggleSaveIdentity: onToggleSaveIdentity,
  onChangeField: onChangeField,
  clearOperationHistory: clearOperationHistory,
  togglePane: togglePane,
  setAllPanes: setAllPanes,
  renderHistory: renderHistory,
  init: init
};
