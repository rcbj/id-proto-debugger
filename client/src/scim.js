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
// key. Selecting either disables the `callPath` row with a reason on screen.
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
// A prose block that has been folded is hidden by hiding its `details`
// wrapper, which by convention is the block's own id with `_fold` on the end.
// Hiding only the paragraph would leave a summary the reader can open onto
// nothing at all — which is worse than the note being absent, because it reads
// as a note that failed to render.
function show(id, on) {
  var e = el(id + '_fold') || el(id);
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
// EVERY READOUT ON THIS PAGE IS A TEXTAREA, and that is a layout decision
// rather than a cosmetic one — see the header of css/scim.css. It matters here
// because a textarea's content is its VALUE and not its text: assigning
// textContent to one works exactly once, until something sets `value`, after
// which the browser's dirty-value flag makes every later textContent
// assignment invisible. A readout that stops updating after the first answer,
// silently, with the right text still in the DOM inspector, is not a defect
// anybody finds quickly. So write through `value` wherever there is one.
function setBoxText(e, text) {
  log.debug("Entering setBoxText(). " + e.tagName);
  if (e.tagName === 'TEXTAREA' || e.tagName === 'INPUT') {
    e.value = text;
    log.debug("Leaving setBoxText(). Through value.");
    return;
  }
  e.textContent = text;
  log.debug("Leaving setBoxText(). Through textContent.");
}

// And the way back out, for the one caller that reads a readout it wrote.
function readBox(id) {
  log.debug("Entering readBox(). id=" + id);
  var e = el(id);
  if (!e) {
    log.debug("Leaving readBox(). No such element.");
    return '';
  }
  var text = (e.tagName === 'TEXTAREA' || e.tagName === 'INPUT')
    ? String(e.value || '') : String(e.textContent || '');
  log.debug("Leaving readBox(). " + text.length + " character(s).");
  return text;
}

function setJson(id, value) {
  log.debug("Entering setJson(). id=" + id);
  var e = el(id);
  if (!e) {
    log.debug("Leaving setJson(). No such element.");
    return;
  }
  if (value === null || value === undefined) {
    setBoxText(e, '');
    log.debug("Leaving setJson(). Empty.");
    return;
  }
  if (typeof value === 'string') {
    setBoxText(e, value);
    log.debug("Leaving setJson(). A string.");
    return;
  }
  try {
    setBoxText(e, JSON.stringify(value, null, 2));
  } catch (err) {
    // A cycle, which a parsed JSON body cannot have — but a value built here
    // could, and a page that threw while rendering would lose the answer as
    // well as the render.
    setBoxText(e, '(this value could not be rendered: ' + err.message + ')');
  }
  log.debug("Leaving setJson().");
}

// ---------------------------------------------------------------------------
// HTTP HEADERS, SHOWN THE WAY THEY GO ON THE WIRE.
//
// `Name: value`, one per line, and not a JSON dump. What a reader compares
// these against is a header they read in an RFC, a `curl -v` transcript or
// another server's log, and none of those is quoted, braced or
// comma-separated — a JSON object of headers has to be translated in the head
// before it can be compared with any of them.
//
// A REPEATED HEADER BECOMES ONE LINE EACH. `Set-Cookie` is the one that
// matters and it is the one HTTP field that may not be joined with a comma
// (RFC 7230 section 3.2.2 says so in as many words, because a cookie's own
// `expires` attribute contains one). fetch's Headers object has already
// joined those before this page can see them, which is a limit of the browser
// path rather than of this function; the api hands them over as an array and
// they are unrolled here.
// ---------------------------------------------------------------------------
function setHeaders(id, headers) {
  log.debug("Entering setHeaders(). id=" + id);
  var e = el(id);
  if (!e) {
    log.debug("Leaving setHeaders(). No such element.");
    return;
  }
  if (!headers || typeof headers !== 'object') {
    setBoxText(e, '');
    log.debug("Leaving setHeaders(). None.");
    return;
  }
  var lines = [];
  Object.keys(headers).forEach(function (name) {
    var value = headers[name];
    if (Object.prototype.toString.call(value) === '[object Array]') {
      value.forEach(function (one) {
        lines.push(name + ': ' + String(one));
      });
      return;
    }
    lines.push(name + ': ' + (value === null || value === undefined
      ? '' : String(value)));
  });
  setBoxText(e, lines.length ? lines.join('\n')
    : '(no headers — see the note above this pane)');
  log.debug("Leaving setHeaders(). " + lines.length + " line(s).");
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
// TABS INSIDE A PANE.
//
// The same markup the Kerberos pages use, paired by a shared group name rather
// than by two ids that have to be kept in step:
//
//   <div class="scim-tabs" data-scim-tabs="discovery">
//     <button class="scim-tab scim-tab-on" data-scim-tab="described">…</button>
//     <button class="scim-tab" data-scim-tab="document">…</button>
//   </div>
//   <div class="scim-tabpanel" data-scim-tabs="discovery"
//        data-scim-tab="described">…</div>
//   <div class="scim-tabpanel scim-tabpanel-off" data-scim-tabs="discovery"
//        data-scim-tab="document">…</div>
//
// Panels are hidden by CLASS and not by an inline style, so that nothing which
// sets `display` on a container can leave two panels showing at once.
// ---------------------------------------------------------------------------
function selectTab(group, name) {
  log.debug("Entering selectTab(). group=" + group + " tab=" + name);
  var i;
  var strip = document.querySelector('.scim-tabs[data-scim-tabs="' + group +
      '"]');
  var buttons = strip ? strip.querySelectorAll('.scim-tab') : [];
  for (i = 0; i < buttons.length; i++) {
    var on = buttons[i].getAttribute('data-scim-tab') === name;
    buttons[i].className = 'scim-tab' + (on ? ' scim-tab-on' : '');
    buttons[i].setAttribute('aria-selected', on ? 'true' : 'false');
  }
  var panels = document.querySelectorAll(
      '.scim-tabpanel[data-scim-tabs="' + group + '"]');
  for (i = 0; i < panels.length; i++) {
    var showing = panels[i].getAttribute('data-scim-tab') === name;
    panels[i].className = 'scim-tabpanel' +
        (showing ? '' : ' scim-tabpanel-off');
  }
  log.debug("Leaving selectTab(). " + buttons.length + " button(s), " +
      panels.length + " panel(s).");
}

function wireTabs() {
  log.debug("Entering wireTabs().");
  var strips = document.querySelectorAll('.scim-tabs');
  var wired = 0;
  for (var i = 0; i < strips.length; i++) {
    var group = strips[i].getAttribute('data-scim-tabs');
    if (!group) {
      log.warn('a .scim-tabs strip has no data-scim-tabs group name, so its ' +
          'buttons cannot be paired with any panel');
      continue;
    }
    var buttons = strips[i].querySelectorAll('.scim-tab');
    for (var j = 0; j < buttons.length; j++) {
      buttons[j].addEventListener('click', (function (g, name) {
        return function () {
          selectTab(g, name);
          return false;
        };
      })(group, buttons[j].getAttribute('data-scim-tab')));
    }
    wired += buttons.length;
  }
  log.debug("Leaving wireTabs(). " + wired + " tab(s) wired.");
  return wired;
}

// ---------------------------------------------------------------------------
// EXPANDING A READOUT.
//
// Every readout on this page is a bounded, scrolling textarea — which is what
// keeps a 400-line ListResponse from making the page four thousand pixels
// tall. Bounded is right for reading a status and wrong for reading a body, so
// each box carries a button that opens it to a working height and closes it
// again, and `resize: vertical` in the stylesheet lets it be dragged to
// anything in between.
//
// The buttons are wired here rather than by an inline `onclick`, because the
// pairing is already in the markup (`data-scim-expand` names the box) and a
// second copy of it in an attribute is a second thing to get wrong.
// ---------------------------------------------------------------------------
function toggleExpand(id) {
  log.debug("Entering toggleExpand(). id=" + id);
  var box = el(id);
  if (!box) {
    log.debug("Leaving toggleExpand(). No such box.");
    return false;
  }
  var tall = box.classList.contains('scim-box-tall');
  if (tall) {
    box.classList.remove('scim-box-tall');
    // The inline height a drag on the resize handle may have left behind.
    // Without this the box stays at whatever it was dragged to and the button
    // reads as having done nothing.
    box.style.height = '';
  } else {
    box.classList.add('scim-box-tall');
  }
  var button = document.querySelector('[data-scim-expand="' + id + '"]');
  if (button) {
    button.value = tall ? 'Expand' : 'Collapse';
  }
  log.debug("Leaving toggleExpand(). " + (tall ? 'collapsed' : 'expanded'));
  return false;
}

function wireExpanders() {
  log.debug("Entering wireExpanders().");
  var buttons = document.querySelectorAll('[data-scim-expand]');
  for (var i = 0; i < buttons.length; i++) {
    buttons[i].addEventListener('click', (function (id) {
      return function () {
        toggleExpand(id);
        return false;
      };
    })(buttons[i].getAttribute('data-scim-expand')));
  }
  log.debug("Leaving wireExpanders(). " + buttons.length + " button(s).");
  return buttons.length;
}

// ---------------------------------------------------------------------------
// WHICH WAY THE CALL GOES.
//
// ONE CONTROL, and it is the `callPath` row of the configuration table. It was
// a pair of radio buttons in a Connection pane of its own and a row in the
// table that reflected them, which is two spellings of one setting: the row is
// now the setting itself.
//
// The preference and the path IN FORCE are deliberately different things.
// `configValues.callPath` is what the reader asked for and is remembered;
// `callVia()` is what will actually happen, because two schemes force the
// browser and a build with no api behind it has no choice at all. The select
// shows the second — a page that let somebody select "through the api" with a
// cookie scheme would send a request with no cookie and report the 401 as the
// server's fault.
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
  var via = configValues.callPath === 'api' ? 'api' : 'browser';
  log.debug("Leaving callVia(). " + via);
  return via;
}

function refreshCallPathControls() {
  log.debug("Entering refreshCallPathControls().");
  var scheme = scimClient.authScheme(val('scim_auth_scheme'));
  var pathSelect = el('scim_cfg_callPath');
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
  if (pathSelect) {
    // Disabled rather than removed, and the PREFERENCE underneath is left
    // alone: a scheme selected for one call must not silently throw away a
    // call path chosen for the next one. Changing the scheme back restores it.
    pathSelect.disabled = !!reason;
  }
  setText('scim_call_path_note', reason);
  show('scim_call_path_note', !!reason);
  // The callPath row shows what is IN FORCE rather than what was last asked
  // for, and a scheme that forces the browser has just changed the first
  // without touching the second.
  refreshConfigValues();
  log.debug("Leaving refreshCallPathControls(). " +
      (reason ? 'fixed to the browser' : 'the reader\'s choice'));
}

// ---------------------------------------------------------------------------
// THE CONFIGURATION PARAMETERS PANE.
//
// Every setting this workflow has, in one table, WITH THE SOURCE OF EACH. That
// last column is the reason the pane exists. The value of a parameter is
// already visible in the field it belongs to; what is not visible anywhere
// else is whether it is there because somebody typed it or because a server
// said so in a discovery document — and those two behave identically right up
// until the server changes its mind, after which exactly one of them is stale
// and nothing on screen says which.
//
// THREE KINDS OF ROW, and the difference between the first two is the whole
// design:
//
//   * an OWNED field (`field` with `owns`). The row IS the control:
//     `configInput()` gives it the field's own id, so `scim_base_url` and
//     `scim_auth_scheme` are elements of this table and of nothing else. That
//     is a change from the first cut of this page, where the row mirrored a
//     field in a Connection or an Authentication pane — one setting spelled
//     twice, in two panes that could disagree about it. There is now nothing
//     to mirror.
//   * a MIRROR of a field in a pane that is still here (`field` WITHOUT
//     `owns`) — the generator's four and the scenario planner's three, which
//     belong beside the buttons that use them. The field is the value; this
//     row reads and writes it, in both directions.
//
//     **`owns` IS NOT OPTIONAL ON THE FIRST KIND AND MUST NOT BE ADDED TO THE
//     SECOND.** `configControlId()` gives an owned row the field's own id, so
//     marking a row that still has a field of its own elsewhere puts TWO
//     elements with that id on the page — and `getElementById` returns the
//     first in document order, which is this table's, so the pane's own box
//     silently stops doing anything. tests/scim_page.js counts the elements
//     per id with `querySelectorAll` for exactly this reason.
//   * a DISCOVERED parameter (`discovered`), which lives here and nowhere
//     else. `discoveredValues` keeps what the document said and
//     `configValues` keeps what is in force, so an override is a visible
//     difference between the two rather than a lost original.
//   * a heading (`group`), which is a row of the table and not a parameter.
//
// NO CREDENTIAL IS IN THIS TABLE, and that is deliberate rather than an
// oversight to be tidied up later — the panes went away, this rule did not.
// The password is never written anywhere; the HOBA private key is generated
// per session and never stored, because a signing key in localStorage is a
// signing key in every extension's reach; and the access token is under its
// own opt-in. All three are in the Credential block BELOW the table, which is
// part of this pane and is not part of this table: a settings pane that
// quietly became the fourth place a bearer token is written would defeat that
// opt-in without changing a word of it. What decides whether a thing is a row
// here is whether it is a value that can be compared against a document —
// a minted proof and a generated key never can be.
//
// THE TABLE IS REBUILT WHOLE on every discovery, so `renderConfig()` carries
// the owned fields' values across the rebuild and puts the focus back. It
// would otherwise wipe the service root the moment the automatic probe that
// the service root triggered came back.
//
// WHAT THE PAGE ACTS ON, honestly marked. `userEndpoint` and `groupEndpoint`
// are real: they are handed to `scimClient.buildRequest`, so a server whose
// ResourceTypes say `/user` is addressed at `/user`. The rest are read out and
// shown, and each row's tooltip says which of the two it is — a settings pane
// implying that a value it cannot act on is being applied is worse than no
// pane, because it makes a server's refusal look like a bug in this page.
// ---------------------------------------------------------------------------
var CONFIG_STORAGE_KEY = 'scim_config';
var DISCOVERED_STORAGE_KEY = 'scim_discovered';

var SPC = 'ServiceProviderConfig';
var RT = 'ResourceTypes';

var CONFIG_PARAMS = [
  { group: 'Connection' },
  { name: 'baseUrl', label: 'baseUrl', field: 'scim_base_url', owns: true,
    source: 'you', placeholder: 'http://localhost:8081/scim/v2',
    wire: wireBaseUrl, applied: true,
    what: 'The SCIM service root every path is composed against — the host ' +
        'plus the SCIM base path, which is /scim/v2 on essentially every ' +
        'implementation. ACTED ON: every request on this page is composed ' +
        'onto it, and changing it makes this page ask the server what it ' +
        'accepts. Do NOT put a resource path here; /Users and the rest are ' +
        'built onto it.' },
  { name: 'sslValidate', label: 'sslValidate', field: 'scim_ssl_validate',
    owns: true, source: 'you', kind: 'select',
    options: [['true', 'validate'], ['false', 'do not validate']],
    what: 'Applies to the api call path only. A browser decides this for ' +
        'itself and cannot be told otherwise, so switching it off changes ' +
        'nothing about a browser-direct call.' },
  { name: 'callPath', label: 'callPath', source: 'you', kind: 'select',
    options: [['browser', 'from this browser'], ['api', 'through the api']],
    what: 'Which way a request goes. From this browser is a fetch() off ' +
        'this page and is the only path the hosted site has; through the api ' +
        'exists for the three things a browser cannot do — reach a server ' +
        'with no CORS headers, reach one with a self-signed certificate, and ' +
        'show every header each way. Two schemes — session cookie and TLS ' +
        'client certificate — force the browser, and this row then shows ' +
        'what is IN FORCE rather than what was last chosen.' },

  { group: 'Authentication' },
  { name: 'authScheme', label: 'authScheme', field: 'scim_auth_scheme',
    owns: true, source: 'you', kind: 'select', optionsFn: authSchemeOptions,
    what: 'Which of RFC 7644 section 2\'s six schemes to use, or anonymous. ' +
        'Only the two OAuth ones carry scopes. The list is ORDERED by what ' +
        'the server\'s own WWW-Authenticate challenge named, which this page ' +
        'collects by itself whenever the service root changes — every scheme ' +
        'stays selectable, because a server may accept one it does not ' +
        'advertise.' },
  { name: 'authUsername', label: 'authUsername',
    field: 'scim_auth_username', owns: true, source: 'you',
    what: 'The account a Basic or Digest credential authenticates as. The ' +
        'PASSWORD is not in this table and is never stored anywhere — it is ' +
        'in the Credential block below. Note that an accepted Basic name is ' +
        'an identity at the server and usually gains a directory entry of ' +
        'its own; it is not one of the users this page provisions.' },
  { name: 'authRealm', label: 'authRealm', field: 'scim_auth_realm',
    owns: true, source: 'you',
    what: 'The realm used when the server\'s own challenge does not supply ' +
        'one. It is hashed into a Digest credential and signed into a HOBA ' +
        'blob, so one character wrong produces a credential that verifies ' +
        'against nothing.' },
  { name: 'hobaUsername', label: 'hobaUsername',
    field: 'scim_hoba_username', owns: true, source: 'you',
    what: 'The account a generated HOBA key is registered against. The key ' +
        'itself is not in this table and is never written to storage.' },
  { name: 'challengeSchemes', label: 'challengeSchemes', discovered: true,
    source: 'WWW-Authenticate',
    what: 'What the server said it accepts, from the 401 the Ask-the-server ' +
        'button provokes. RFC 7644 section 2 makes this the ONE normative ' +
        'requirement of a SCIM server\'s authentication. Shown, not acted ' +
        'on: which scheme to send is the row above.' },
  { name: 'challengeRealm', label: 'challengeRealm', discovered: true,
    source: 'WWW-Authenticate',
    what: 'The realm out of that challenge. It is used in preference to the ' +
        'authRealm row above whenever a challenge has been collected — a ' +
        'credential is computed over the realm the SERVER named.' },
  { name: 'digestAlgorithms', label: 'digestAlgorithms', discovered: true,
    source: 'WWW-Authenticate',
    what: 'The Digest algorithms offered. The STRONGEST that this build can ' +
        'compute is answered; taking the last one parsed is the trap, ' +
        'because the conventional ordering puts the weakest last.' },

  { group: 'Endpoints (RFC 7644 section 4)' },
  { name: 'userEndpoint', label: 'userEndpoint', discovered: true,
    source: RT, applied: true,
    what: 'Where Users live, relative to the service root. ACTED ON: every ' +
        'User operation is composed onto this. /Users is a convention and ' +
        'not a requirement — RFC 7643 section 6 has each ResourceType ' +
        'publish its own endpoint, and a client that hard codes the ' +
        'convention meets a conformant server with a 404 on everything.' },
  { name: 'groupEndpoint', label: 'groupEndpoint', discovered: true,
    source: RT, applied: true,
    what: 'The same for Groups. ACTED ON: every Group operation is composed ' +
        'onto this.' },
  { name: 'userSchema', label: 'userSchema', discovered: true, source: RT,
    what: 'The URN of the schema the User resource type names. Shown, not ' +
        'acted on — the generator emits the RFC 7643 core schema.' },
  { name: 'groupSchema', label: 'groupSchema', discovered: true, source: RT,
    what: 'The URN of the Group resource type\'s schema.' },
  { name: 'schemaExtensions', label: 'schemaExtensions', discovered: true,
    source: RT,
    what: 'The extension URNs the User resource type carries, and whether ' +
        'each is required. The enterprise extension is the one this page\'s ' +
        'generator emits.' },
  { name: 'schemaIds', label: 'schemaIds', discovered: true,
    source: 'Schemas',
    what: 'Every schema this server publishes. This is the document that ' +
        'says whether a field you sent was ever going to be stored.' },

  { group: 'Capabilities (RFC 7644 section 5)' },
  { name: 'patchSupported', label: 'patch.supported', discovered: true,
    source: SPC,
    what: 'Whether PATCH works at all. Without it every change is a PUT, ' +
        'which REPLACES the resource — and a PUT that omits an attribute ' +
        'the server holds usually clears it.' },
  { name: 'bulkSupported', label: 'bulk.supported', discovered: true,
    source: SPC,
    what: 'Whether many operations may be sent in one request.' },
  { name: 'bulkMaxOperations', label: 'bulk.maxOperations', discovered: true,
    source: SPC,
    what: 'The most operations one BulkRequest may carry. A bulk scenario ' +
        'larger than this is refused as a whole, not truncated.' },
  { name: 'bulkMaxPayloadSize', label: 'bulk.maxPayloadSize',
    discovered: true, source: SPC,
    what: 'The byte ceiling on a BulkRequest.' },
  { name: 'filterSupported', label: 'filter.supported', discovered: true,
    source: SPC,
    what: 'ONE boolean for fourteen operators, which is why the filter-tour ' +
        'scenario exists: this says nothing about which of them work.' },
  { name: 'filterMaxResults', label: 'filter.maxResults', discovered: true,
    source: SPC,
    what: 'The most resources a filtered query will return, whatever count ' +
        'asked for.' },
  { name: 'sortSupported', label: 'sort.supported', discovered: true,
    source: SPC, what: 'Whether sortBy and sortOrder are honoured.' },
  { name: 'etagSupported', label: 'etag.supported', discovered: true,
    source: SPC,
    what: 'Optimistic concurrency. A server that says false here and sends ' +
        'an ETag anyway is worse than one with none, because a client would ' +
        'trust it.' },
  { name: 'changePasswordSupported', label: 'changePassword.supported',
    discovered: true, source: SPC,
    what: 'Whether a password can be set through SCIM at all.' },
  { name: 'authenticationSchemes', label: 'authenticationSchemes',
    discovered: true, source: SPC,
    what: 'What the ServiceProviderConfig advertises. An EMPTY list is an ' +
        'honest answer from a server that authenticates nobody, and a very ' +
        'different thing from the member being absent.' },
  { name: 'documentationUri', label: 'documentationUri', discovered: true,
    source: SPC, what: 'Where the server says its own documentation is.' },

  { group: 'Data generation' },
  { name: 'genSeed', label: 'genSeed', field: 'scim_gen_seed', source: 'you',
    what: 'The generator\'s seed. The same seed always produces the same ' +
        'users, which is what makes a failure on the seventh one runnable ' +
        'again rather than describable.' },
  { name: 'genPrefix', label: 'genPrefix', field: 'scim_gen_prefix',
    source: 'you',
    what: 'Every generated userName starts with this, which is what makes ' +
        'them findable with one filter and cleanable in one sweep.' },
  { name: 'genCount', label: 'genCount', field: 'scim_gen_count',
    source: 'you', what: 'How many to generate. Capped at 50.' },
  { name: 'genDomain', label: 'genDomain', field: 'scim_gen_domain',
    source: 'you', what: 'The email domain generated addresses are built on.' },
  { name: 'scenarioSeed', label: 'scenarioSeed', field: 'scim_scenario_seed',
    source: 'you',
    what: 'The scenario planner\'s seed. Changing it throws away a plan ' +
        'already on screen, because a plan belongs to the inputs it was ' +
        'built from.' },
  { name: 'scenarioPrefix', label: 'scenarioPrefix',
    field: 'scim_scenario_prefix', source: 'you',
    what: 'Namespaces everything a scenario run creates.' },
  { name: 'scenarioCount', label: 'scenarioCount',
    field: 'scim_scenario_count', source: 'you',
    what: 'How many users a scenario provisions. Capped at 50 — fifty users ' +
        'is around 150 requests.' }
];

var CONFIG_BY_NAME = (function () {
  var index = {};
  CONFIG_PARAMS.forEach(function (row) {
    if (row.name) {
      index[row.name] = row;
    }
  });
  return index;
})();

// Where a row's control lives. An owned row took the field's own id, so that
// `val('scim_base_url')` reads this table and there is no second element to
// disagree with it; everything else gets a generated one.
//
// NO ENTERING/LEAVING PAIR, for the reason `configValue()` below records: this
// is called once per row by renderConfig(), and once per row again by
// refreshConfigValues() on every change event anywhere on the page.
function configControlId(row) {
  return row.owns ? row.field : ('scim_cfg_' + row.name);
}

// What is in force, and what the last document said. Kept apart on purpose:
// an override is then a visible difference rather than a lost original, and
// "restore" has something to restore to.
var configValues = {};
var discoveredValues = {};

// The value of one parameter, wherever it lives.
//
// NO ENTERING/LEAVING PAIR, and it is the hot-path exception the repo-root
// CLAUDE.md describes rather than an oversight: renderConfig() calls this once
// per row and refreshConfigValues() calls it once per row again on EVERY change
// event anywhere on the page, which at logLevel debug is eighty records for a
// keystroke that left a field. The functions that call it keep their logging,
// which is where a trace of a configuration change actually lives.
function configValue(name) {
  var row = CONFIG_BY_NAME[name];
  if (!row) {
    return '';
  }
  if (row.field) {
    return val(row.field);
  }
  if (name === 'callPath') {
    return callVia();
  }
  return configValues[name] === undefined ? '' : String(configValues[name]);
}

// The endpoints handed to every buildRequest() on this page.
//
// An empty override means "the catalogue's own path", which is what
// buildRequest does with an absent member — so an unread ResourceTypes
// document changes nothing at all, rather than composing a URL onto ''.
function endpointsForRequests() {
  log.debug("Entering endpointsForRequests().");
  var out = {
    User: configValue('userEndpoint'),
    Group: configValue('groupEndpoint')
  };
  log.debug("Leaving endpointsForRequests(). User=" +
      (out.User || '(default)') + " Group=" + (out.Group || '(default)'));
  return out;
}

function loadConfig() {
  log.debug("Entering loadConfig().");
  try {
    var stored = localStorage.getItem(CONFIG_STORAGE_KEY);
    configValues = stored ? JSON.parse(stored) : {};
    var was = localStorage.getItem(DISCOVERED_STORAGE_KEY);
    discoveredValues = was ? JSON.parse(was) : {};
  } catch (e) {
    // Unreadable or not JSON — an older build's key, or no storage at all.
    // The pane works from an empty store, so this fails towards the page
    // rather than towards a thrown load.
    log.warn('could not read the saved configuration: ' + e.message);
    configValues = {};
    discoveredValues = {};
  }
  log.debug("Leaving loadConfig(). " + Object.keys(configValues).length +
      " value(s), " + Object.keys(discoveredValues).length + " discovered.");
}

function persistConfig() {
  log.debug("Entering persistConfig().");
  try {
    localStorage.setItem(CONFIG_STORAGE_KEY, JSON.stringify(configValues));
    localStorage.setItem(DISCOVERED_STORAGE_KEY,
        JSON.stringify(discoveredValues));
  } catch (e) {
    log.warn('could not write the configuration: ' + e.message);
  }
  log.debug("Leaving persistConfig().");
}

// What a discovery document said, recorded as `discovered` and adopted as the
// value in force UNLESS the reader has overridden that row.
//
// The test for "overridden" is against the PREVIOUS discovered value and not
// against emptiness: a row the reader has never touched follows the server
// forever, and a row they have edited keeps their edit even when a later read
// of the same document says something else. Adopting over an edit would
// silently undo it, and doing so on a button press that says "read the
// documents" is the kind of change nobody attributes to the right cause.
function recordDiscovered(values) {
  log.debug("Entering recordDiscovered(). " + Object.keys(values).length +
      " value(s).");
  var adopted = 0;
  Object.keys(values).forEach(function (name) {
    var text = values[name] === undefined || values[name] === null
      ? '' : String(values[name]);
    var overridden = configValues[name] !== undefined &&
        configValues[name] !== discoveredValues[name];
    discoveredValues[name] = text;
    if (!overridden) {
      configValues[name] = text;
      adopted += 1;
    }
  });
  persistConfig();
  renderConfig();
  log.debug("Leaving recordDiscovered(). " + adopted + " adopted.");
}

// ---------------------------------------------------------------------------
// The table itself. Built with createElement and textContent throughout — a
// discovered value is somebody else's bytes and concatenating those into
// markup is the js/xss-through-dom defect the token pane already carries a
// long comment about.
// ---------------------------------------------------------------------------
function renderConfig() {
  log.debug("Entering renderConfig().");
  var host = el('scim_config');
  if (!host) {
    log.debug("Leaving renderConfig(). No host.");
    return;
  }
  // THE VALUES OF THE OWNED FIELDS, READ BEFORE THE TABLE IS TORN DOWN.
  // `configValue()` reads an owned row out of its control, and after
  // `innerHTML = ''` there is no control to read — so without this a rebuild
  // (which every discovery causes) empties the service root, the scheme and
  // the generator's seed at once, from a button nobody pressed.
  var carried = {};
  CONFIG_PARAMS.forEach(function (row) {
    if (row.name && row.owns) {
      carried[row.name] = configValue(row.name);
    }
  });
  // And the focus, for the same reason: the automatic probe fires on a change
  // to the service root, and its answer rebuilds this table.
  var focused = document.activeElement ? document.activeElement.id : '';
  host.innerHTML = '';
  var table = document.createElement('table');
  table.className = 'scim-config-table';
  table.appendChild(configHeaderRow());
  var rows = 0;
  CONFIG_PARAMS.forEach(function (row) {
    if (row.group) {
      table.appendChild(configGroupRow(row.group));
      return;
    }
    table.appendChild(configRow(row, carried));
    rows += 1;
  });
  host.appendChild(table);
  if (focused && el(focused) && typeof el(focused).focus === 'function') {
    el(focused).focus();
  }
  log.debug("Leaving renderConfig(). " + rows + " parameter(s).");
}

function configHeaderRow() {
  log.debug("Entering configHeaderRow().");
  var tr = document.createElement('tr');
  ['Parameter', 'Value', 'Source'].forEach(function (text) {
    var th = document.createElement('th');
    th.textContent = text;
    tr.appendChild(th);
  });
  log.debug("Leaving configHeaderRow().");
  return tr;
}

function configGroupRow(title) {
  log.debug("Entering configGroupRow(). " + title);
  var tr = document.createElement('tr');
  tr.className = 'scim-config-group';
  var td = document.createElement('td');
  td.colSpan = 3;
  td.textContent = title;
  tr.appendChild(td);
  log.debug("Leaving configGroupRow().");
  return tr;
}

function configRow(row, carried) {
  log.debug("Entering configRow(). " + row.name);
  var tr = document.createElement('tr');
  tr.id = 'scim_cfg_row_' + row.name;

  var name = document.createElement('td');
  name.className = 'scim-config-name';
  // The tooltip wrapper, built the same way the markup builds one — see the
  // note in css/scim.css about why the hidden span must never be a pointer
  // target.
  var tip = document.createElement('div');
  tip.className = 'tooltip scim-tip';
  var caption = document.createElement('span');
  caption.textContent = row.label || row.name;
  tip.appendChild(caption);
  var text = document.createElement('span');
  text.className = 'tooltiptext';
  text.textContent = row.what + (row.applied
    ? '' : (row.discovered ? ' Shown here; this page does not change what it ' +
        'sends because of it.' : ''));
  tip.appendChild(text);
  name.appendChild(tip);
  tr.appendChild(name);

  var value = document.createElement('td');
  value.className = 'scim-config-value';
  value.appendChild(configInput(row, carried));
  if (row.discovered && discoveredValues[row.name] !== undefined &&
      configValue(row.name) !== discoveredValues[row.name]) {
    value.className = 'scim-config-value scim-config-overridden';
    var was = document.createElement('span');
    was.className = 'scim-config-was';
    was.textContent = 'the server said: ' +
        (discoveredValues[row.name] === '' ? '(nothing)'
          : discoveredValues[row.name]);
    value.appendChild(was);
  }
  tr.appendChild(value);

  var source = document.createElement('td');
  source.className = 'scim-config-source';
  source.textContent = row.source + (row.applied ? ' — applied' : '');
  tr.appendChild(source);

  log.debug("Leaving configRow().");
  return tr;
}

// The control for one row.
//
// AN OWNED ROW TAKES THE FIELD'S OWN ID. That is what makes this table the
// setting rather than a view of it: `val('scim_base_url')` reads the cell of
// this table, `REMEMBERED` writes it to localStorage under the same name it
// always had, and there is no second element anywhere that could hold a
// different value.
function configInput(row, carried) {
  log.debug("Entering configInput(). " + row.name);
  var current = (carried && carried[row.name] !== undefined)
    ? carried[row.name] : configValue(row.name);
  var control;
  if (row.kind === 'select') {
    control = document.createElement('select');
    optionsFor(row).forEach(function (pair) {
      var option = document.createElement('option');
      option.value = pair[0];
      option.textContent = pair[1];
      control.appendChild(option);
    });
    control.value = current;
  } else {
    control = document.createElement('input');
    control.type = 'text';
    control.value = current;
    if (row.placeholder) {
      control.placeholder = row.placeholder;
    }
  }
  control.className = 'scim-field';
  control.id = configControlId(row);
  control.addEventListener('change', (function (name) {
    return function (event) {
      applyOneParameter(name, event.target.value);
    };
  })(row.name));
  if (row.owns) {
    // An owned field is a REMEMBERED field, and the listener the onload loop
    // adds is on the element that this rebuild has just replaced. Adding it
    // here rather than there is what keeps a value written through on a
    // change made after the first discovery. A MIRROR row needs none of this:
    // the field it reflects is in a pane of its own and keeps its listeners.
    control.addEventListener('change', saveState);
    if (row.wire) {
      row.wire(control);
    }
  }
  log.debug("Leaving configInput().");
  return control;
}

// The options for a select row: a fixed list, or one computed at render time.
function optionsFor(row) {
  log.debug("Entering optionsFor(). " + row.name);
  if (row.optionsFn) {
    var computed = row.optionsFn();
    log.debug("Leaving optionsFor(). " + computed.length + " computed.");
    return computed;
  }
  log.debug("Leaving optionsFor(). Its own list.");
  return row.options || [];
}

// ---------------------------------------------------------------------------
// THE SCHEME LIST, ORDERED BY WHAT THE SERVER SAID.
//
// RFC 7644 section 2 defines no SCIM credential of its own. It names six ways
// of doing it and makes exactly ONE normative requirement: that a server say
// which it accepts in a WWW-Authenticate header. So the list of schemes is not
// this page's to decide, and it is not a pane's either — it is read off that
// header, which `autoProbe()` collects whenever the service root changes.
//
// EVERY SCHEME STAYS SELECTABLE and the offered ones are merely moved to the
// top and marked. Filtering the list to the challenge would be wrong twice
// over: a server that accepts Bearer without advertising it is common enough
// to be the reason somebody opened this page, and two of the eight — a session
// cookie and a TLS client certificate — can never appear in a challenge at
// all, because neither puts anything in an Authorization header.
// ---------------------------------------------------------------------------
var CHALLENGE_TO_SCHEME = {
  bearer: 'bearer',
  dpop: 'dpop',
  basic: 'basic',
  digest: 'digest',
  hoba: 'hoba'
};

// Read from the live challenges when there are some, and from the recorded
// `challengeSchemes` row otherwise — so the ordering survives a reload of a
// page whose probe has already run.
function offeredSchemeIds() {
  log.debug("Entering offeredSchemeIds().");
  var names = lastChallenges.length
    ? lastChallenges.map(function (one) {
        return one.scheme;
      })
    : String(configValue('challengeSchemes') || '').split(',');
  var ids = {};
  names.forEach(function (name) {
    var id = CHALLENGE_TO_SCHEME[String(name).trim().toLowerCase()];
    if (id) {
      ids[id] = true;
    }
  });
  log.debug("Leaving offeredSchemeIds(). " + Object.keys(ids).length +
      " scheme(s).");
  return ids;
}

function authSchemeOptions() {
  log.debug("Entering authSchemeOptions().");
  var offered = offeredSchemeIds();
  var any = Object.keys(offered).length > 0;
  var anonymous = [];
  var first = [];
  var rest = [];
  scimClient.AUTH_SCHEMES.forEach(function (scheme) {
    if (scheme.id === 'none') {
      // Anonymous stays at the top whatever the server said. It is not a
      // scheme a server offers — it is sending nothing, which is always
      // available, is this page's default, and is the probe itself.
      anonymous.push([scheme.id, scheme.label]);
      return;
    }
    if (offered[scheme.id]) {
      first.push([scheme.id, scheme.label + ' — offered']);
      return;
    }
    // Only a scheme that COULD have been named in a challenge is marked as
    // absent from one. Saying "not offered" of a session cookie would be a
    // claim about the server that the header never made.
    var couldHave = CHALLENGE_TO_SCHEME[scheme.id] !== undefined;
    rest.push([scheme.id, scheme.label +
        (any && couldHave ? ' — not offered' : '')]);
  });
  var pairs = anonymous.concat(first, rest);
  log.debug("Leaving authSchemeOptions(). " + first.length + " offered of " +
      pairs.length + ".");
  return pairs;
}

// The service root is the one setting that makes this page go and ask a
// question of its own: a change to it invalidates every discovered row and the
// scheme list with them.
function wireBaseUrl(control) {
  log.debug("Entering wireBaseUrl().");
  control.addEventListener('input', refreshRequestPreview);
  control.addEventListener('change', scheduleAutoProbe);
  log.debug("Leaving wireBaseUrl().");
}

// There is no wireAuthScheme(): `applyOneParameter()` calls
// refreshAuthControls() for that row, and a second listener on the same change
// event would run the whole scheme refresh twice per keystroke-free click.

// One parameter, applied the moment it is changed. A settings pane whose
// values only take effect on a button press is a settings pane somebody
// changes and then wonders why nothing happened; Save is for PERSISTING.
function applyOneParameter(name, value) {
  log.debug("Entering applyOneParameter(). " + name);
  var row = CONFIG_BY_NAME[name];
  if (!row) {
    log.debug("Leaving applyOneParameter(). Unknown parameter.");
    return;
  }
  if (row.owns) {
    // The row IS the control, so this is a write to the same element the event
    // came from — which matters when the caller is Save rather than the
    // control's own change handler. NO `change` IS DISPATCHED: that event is
    // what called this, and re-firing it on the same element is an infinite
    // loop rather than a refresh.
    setVal(row.field, value);
    saveState();
    if (name === 'authScheme') {
      refreshAuthControls();
    }
  } else if (row.field) {
    // A mirror: the value lives in another pane's field, and that field's own
    // listeners are what a change has to reach.
    setVal(row.field, value);
    var field = el(row.field);
    if (field) {
      field.dispatchEvent(new Event('change'));
    }
    saveState();
  } else if (name === 'callPath') {
    // The PREFERENCE, which is not always what happens: `callVia()` overrides
    // it for a scheme that forces the browser, and the row shows that.
    configValues.callPath = value === 'api' ? 'api' : 'browser';
    refreshCallPathControls();
  } else {
    configValues[name] = value;
  }
  persistConfig();
  // A DISCOVERED row is redrawn, because its "the server said…" line and its
  // overridden tint have just changed and neither is a value. Everything else
  // has its VALUES refreshed instead: rebuilding the table replaces the very
  // control that fired this event, which on a text field means the focus
  // leaves for the page body on every Tab.
  if (row.discovered) {
    renderConfig();
  } else {
    refreshConfigValues();
  }
  refreshRequestPreview();
  log.debug("Leaving applyOneParameter().");
}

function saveConfig() {
  log.debug("Entering saveConfig().");
  CONFIG_PARAMS.forEach(function (row) {
    if (!row.name) {
      return;
    }
    var control = el(configControlId(row));
    if (!control) {
      return;
    }
    if (row.field || row.name === 'callPath') {
      applyOneParameter(row.name, control.value);
      return;
    }
    configValues[row.name] = String(control.value || '');
  });
  saveState();
  persistConfig();
  renderConfig();
  refreshRequestPreview();
  statusOk('scim_config_status', 'Saved. Every value above is in this ' +
      'browser\'s localStorage — except the password and the HOBA private ' +
      'key, which are never written anywhere, and the access token, which is ' +
      'written only under its own opt-in below.');
  log.debug("Leaving saveConfig(). Saved.");
  return false;
}

function restoreDiscovered() {
  log.debug("Entering restoreDiscovered().");
  var restored = 0;
  CONFIG_PARAMS.forEach(function (row) {
    if (!row.name || !row.discovered) {
      return;
    }
    if (discoveredValues[row.name] === undefined) {
      return;
    }
    if (configValues[row.name] !== discoveredValues[row.name]) {
      restored += 1;
    }
    configValues[row.name] = discoveredValues[row.name];
  });
  persistConfig();
  renderConfig();
  refreshRequestPreview();
  if (restored === 0) {
    statusOk('scim_config_status', 'Nothing to restore: no discovered ' +
        'parameter differs from what the server said. Rows you typed ' +
        'yourself are never touched by this button.');
  } else {
    statusOk('scim_config_status', restored + ' parameter(s) put back to ' +
        'what the server\'s own documents said.');
  }
  log.debug("Leaving restoreDiscovered(). " + restored + " restored.");
  return false;
}

// Keep the table's controls in step with fields edited in the other panes.
// The values are re-read rather than the table rebuilt, so that a select the
// reader has open is not replaced under them.
function refreshConfigValues() {
  log.debug("Entering refreshConfigValues().");
  var changed = 0;
  CONFIG_PARAMS.forEach(function (row) {
    if (!row.name) {
      return;
    }
    var control = el(configControlId(row));
    if (!control) {
      return;
    }
    var current = configValue(row.name);
    if (String(control.value) !== current) {
      control.value = current;
      changed += 1;
    }
  });
  log.debug("Leaving refreshConfigValues(). " + changed + " updated.");
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
              'The challenges it did offer are in the Credential block ' +
              'under the configuration table.';
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
              'register it in the Credential block under the ' +
              'configuration table.';
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

// `options.via` overrides the call path for ONE call and `options.quiet`
// keeps it out of the Exchange pane. Both exist for the automatic
// authentication probe and for nothing else — see probeAuthentication().
function sendOnce(request, auth, options) {
  log.debug("Entering sendOnce(). scheme=" + auth.scheme);
  var applied = scimClient.applyAuth(request, auth);
  var headers = Object.assign({}, request.headers, applied.headers);
  var via = (options && options.via) || callVia();
  if (!(options && options.quiet)) {
    showRequest(request, headers, via, applied.note);
  }
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
  // Headers in wire form, and the request line above them — together they are
  // the head of the request as it goes out, which is the thing a reader is
  // comparing against an RFC or a curl transcript.
  setHeaders('scim_exchange_request_headers', headers);
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
  setHeaders('scim_exchange_response_headers', null);
  setJson('scim_exchange_response_body', null);
  log.debug("Leaving showRequest().");
}

function showResponse(result) {
  log.debug("Entering showResponse(). status=" + result.status);
  if (result.transportError) {
    setText('scim_exchange_response_line', 'No response — ' +
        result.transportError);
    setHeaders('scim_exchange_response_headers', null);
    setJson('scim_exchange_response_body', null);
    log.debug("Leaving showResponse(). No response.");
    return;
  }
  var described = scimClient.describeResponse(result.status, result.body);
  setText('scim_exchange_response_line', result.status + ' — ' +
      described.summary + ' (' + result.elapsedMs + 'ms)');
  setHeaders('scim_exchange_response_headers', result.headers);
  // THE HEADERS THE api ACTUALLY SENT, when it was the api that sent them.
  // What `showRequest()` drew a moment ago is what this PAGE composed, and the
  // two differ: axios adds a User-Agent, a Content-Length and an
  // Accept-Encoding of its own. On a browser-direct call there is nothing to
  // correct — the browser will not say what it added — and the note above the
  // pane says so rather than presenting the page's list as the whole one.
  if (result.exchange && result.exchange.request) {
    setHeaders('scim_exchange_request_headers',
        result.exchange.request.headers);
  }
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
    setText('scim_challenges', 'No challenge has been collected. This page ' +
        'asks for one by itself whenever the service root changes — an ' +
        'unauthenticated request, which a server with authentication turned ' +
        'on answers 401, and RFC 7644 section 2 requires that answer to say ' +
        'which schemes it accepts. Nothing here means one of three things: ' +
        'the server was not reachable, it authenticates nobody, or the ' +
        'probe went from this browser and CORS withheld the header — which ' +
        'it does unless the server names WWW-Authenticate in ' +
        'Access-Control-Expose-Headers. The api reads every header, so the ' +
        'callPath row above is what settles the third.');
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
  captureFromChallenges();
  log.debug("Leaving renderChallenges(). " + lines.length + " challenge(s).");
}

// The WWW-Authenticate header is the fourth discovery source on this page, and
// the only one RFC 7644 makes NORMATIVE — section 2 requires a server to say
// in a 401 which schemes it accepts, and requires nothing else of SCIM
// authentication at all. So it belongs in the Configuration Parameters table
// beside the three documents rather than only in a line of prose above the
// scheme selector.
function captureFromChallenges() {
  log.debug("Entering captureFromChallenges().");
  var schemes = lastChallenges.map(function (row) {
    return row.scheme;
  }).join(', ');
  var digest = lastChallenges.filter(function (row) {
    return String(row.scheme).toLowerCase() === 'digest';
  }).map(function (row) {
    // A challenge with no `algorithm` is MD5 by RFC 7616 section 3.3, and
    // saying so is better than an empty cell that reads as "none offered".
    return row.params.algorithm || 'MD5 (by default)';
  }).join(', ');
  recordDiscovered({
    challengeSchemes: schemes,
    challengeRealm: challengeParam('digest', 'realm') ||
        challengeParam('basic', 'realm') ||
        challengeParam('hoba', 'realm'),
    digestAlgorithms: digest
  });
  log.debug("Leaving captureFromChallenges(). " + lastChallenges.length +
      " challenge(s).");
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
      // The discovered `/Users` / `/Groups` override, from the Configuration
      // Parameters pane. Empty there means the catalogue's own path, so an
      // unread ResourceTypes document changes nothing.
      endpoints: endpointsForRequests(),
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
  var text = readBox('scim_gen_output');
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

// ---------------------------------------------------------------------------
// A PLAN BELONGS TO THE INPUTS IT WAS BUILT FROM, so changing any of them
// throws it away.
//
// The Run button plans for itself when there is no plan, and only then — so
// without this, choosing a different scenario (or a different seed, prefix or
// user count) after pressing Plan and then pressing Run RAN THE OLD ONE, while
// the description beside the selector, and the table, described the new one.
// Nothing about that looks like a failure: the run goes green, every step
// passes, and it was the wrong scenario. It cost a test exactly that way —
// tests/scim_page.js looked for a step of the negatives scenario in a table
// still showing the team-provisioning one and reported it as missing.
//
// The table is emptied with it, because a plan on screen that the Run button
// would not run is the misleading half. A run in flight keeps its plan: it is
// the thing currently executing, and the steps left to run are its own.
// ---------------------------------------------------------------------------
function forgetPlan() {
  log.debug("Entering forgetPlan().");
  if (runState.running) {
    log.debug("Leaving forgetPlan(). A run is in flight.");
    return;
  }
  if (!currentPlan) {
    log.debug("Leaving forgetPlan(). Nothing was planned.");
    return;
  }
  currentPlan = null;
  runState = { running: false, stopRequested: false, captured: {},
               results: [] };
  renderPlan();
  statusOk('scim_scenario_status', 'The scenario, the seed, the prefix or ' +
      'the user count changed, so the plan below no longer describes what ' +
      'would be sent and has been dropped. Press Plan to build one for what ' +
      'is on screen now — or Run, which plans first when there is nothing ' +
      'planned.');
  log.debug("Leaving forgetPlan(). Dropped.");
}

// A change to the scenario selector is both: the description beside it is
// rewritten, and whatever was planned before is no longer this scenario.
function onScenarioSelected() {
  log.debug("Entering onScenarioSelected().");
  refreshScenarioControls();
  forgetPlan();
  log.debug("Leaving onScenarioSelected().");
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
      endpoints: endpointsForRequests(),
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
      baseUrl: val('scim_base_url'),
      endpoints: endpointsForRequests()
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
      describedWhat('ServiceProviderConfig', 'RFC 7644 section 5. Everything ' +
          'this page can do is a promise made in this document.');
      captureFromServiceProviderConfig(result.body);
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

// ---------------------------------------------------------------------------
// THE DESCRIBED VIEW OF THE OTHER TWO DOCUMENTS.
//
// The ServiceProviderConfig has had a table since this page was written, for
// the reason renderCapabilities() gives — what a reader wants from it is six
// booleans and two numbers. ResourceTypes and Schemas were dumped as JSON and
// nothing else, which is the same mistake one document later: what a reader
// wants from a ResourceTypes is WHERE each type answers and which schema it
// carries, and finding those in a nested list response is a scroll and a
// squint.
//
// Both views are kept. The described table is a READING of the document and
// the document is the thing being read; a disagreement between the two is a
// defect in this page, and hiding the original would make that undiscoverable.
// ---------------------------------------------------------------------------
function describedWhat(title, note) {
  log.debug("Entering describedWhat(). " + title);
  setText('scim_described_what', title + ' — ' + note);
  log.debug("Leaving describedWhat().");
}

function renderDescribed(operationId, body) {
  log.debug("Entering renderDescribed(). " + operationId);
  if (operationId === 'resourceTypes') {
    renderResourceTypes(body);
    log.debug("Leaving renderDescribed(). ResourceTypes.");
    return;
  }
  if (operationId === 'schemas') {
    renderSchemas(body);
    log.debug("Leaving renderDescribed(). Schemas.");
    return;
  }
  log.debug("Leaving renderDescribed(). Nothing described for that one.");
}

function resourcesOf(body) {
  log.debug("Entering resourcesOf().");
  var list = [];
  if (body && Object.prototype.toString.call(body.Resources) ===
      '[object Array]') {
    list = body.Resources;
  } else if (Object.prototype.toString.call(body) === '[object Array]') {
    // A server answering with a bare array rather than a ListResponse. RFC
    // 7644 section 4 says ListResponse; enough implementations do this that
    // reading it is worth more than refusing it.
    list = body;
  }
  log.debug("Leaving resourcesOf(). " + list.length + " resource(s).");
  return list;
}

function renderResourceTypes(body) {
  log.debug("Entering renderResourceTypes().");
  var host = el('scim_capabilities');
  if (!host) {
    log.debug("Leaving renderResourceTypes(). No host.");
    return;
  }
  describedWhat('ResourceTypes', 'RFC 7644 section 4. Where each type ' +
      'answers and what it carries. THE ENDPOINT IS NOT DECORATION: /Users ' +
      'and /Groups are conventions, and this page composes its requests onto ' +
      'whatever is in the Configuration Parameters pane below.');
  host.innerHTML = '';
  var types = resourcesOf(body);
  if (!types.length) {
    var empty = document.createElement('p');
    empty.className = 'scim-config-empty';
    empty.textContent = 'The server returned no resource types. A SCIM ' +
        'server with none is answerable at no resource path at all, so this ' +
        'is either an empty document or a body that is not a ListResponse.';
    host.appendChild(empty);
    log.debug("Leaving renderResourceTypes(). None.");
    return;
  }
  var table = document.createElement('table');
  table.className = 'scim-table';
  var head = document.createElement('tr');
  ['Type', 'Endpoint', 'Schema', 'Extensions'].forEach(function (text) {
    var th = document.createElement('th');
    th.textContent = text;
    head.appendChild(th);
  });
  table.appendChild(head);
  types.forEach(function (row) {
    var tr = document.createElement('tr');
    appendCell(tr, row.name || row.id || '(unnamed)').className =
        'scim-described-name';
    appendCell(tr, row.endpoint || '(not stated)').className =
        'scim-described-value';
    appendCell(tr, row.schema || '(not stated)').className =
        'scim-described-value';
    appendCell(tr, extensionSummary(row)).className = 'scim-described-note';
    table.appendChild(tr);
  });
  host.appendChild(table);
  captureFromResourceTypes(types);
  log.debug("Leaving renderResourceTypes(). " + types.length + " type(s).");
}

function extensionSummary(row) {
  log.debug("Entering extensionSummary().");
  var list = row && Object.prototype.toString.call(row.schemaExtensions) ===
      '[object Array]' ? row.schemaExtensions : [];
  var text = list.map(function (one) {
    return String(one.schema) + (one.required ? ' (required)' : '');
  }).join(', ') || 'none';
  log.debug("Leaving extensionSummary(). " + list.length + " extension(s).");
  return text;
}

function renderSchemas(body) {
  log.debug("Entering renderSchemas().");
  var host = el('scim_capabilities');
  if (!host) {
    log.debug("Leaving renderSchemas(). No host.");
    return;
  }
  describedWhat('Schemas', 'RFC 7643 section 7. Every attribute this server ' +
      'knows and how many of them each schema has — this is the document ' +
      'that says whether a field you sent was ever going to be stored.');
  host.innerHTML = '';
  var schemas = resourcesOf(body);
  if (!schemas.length) {
    var empty = document.createElement('p');
    empty.className = 'scim-config-empty';
    empty.textContent = 'The server published no schemas.';
    host.appendChild(empty);
    log.debug("Leaving renderSchemas(). None.");
    return;
  }
  var table = document.createElement('table');
  table.className = 'scim-table';
  var head = document.createElement('tr');
  ['Name', 'URN', 'Attributes', 'Required'].forEach(function (text) {
    var th = document.createElement('th');
    th.textContent = text;
    head.appendChild(th);
  });
  table.appendChild(head);
  schemas.forEach(function (row) {
    var attributes = Object.prototype.toString.call(row.attributes) ===
        '[object Array]' ? row.attributes : [];
    var required = attributes.filter(function (one) {
      return one && one.required === true;
    }).map(function (one) {
      return one.name;
    });
    var tr = document.createElement('tr');
    appendCell(tr, row.name || '(unnamed)').className = 'scim-described-name';
    appendCell(tr, row.id || '(no id)').className = 'scim-described-value';
    appendCell(tr, String(attributes.length)).className =
        'scim-described-note';
    // The required ones by NAME rather than a count: a create refused for a
    // missing attribute names the attribute, and this is the list that says
    // which they were before the refusal rather than after it.
    appendCell(tr, required.length ? required.join(', ') : 'none')
        .className = 'scim-described-note';
    table.appendChild(tr);
  });
  host.appendChild(table);
  captureFromSchemas(schemas);
  log.debug("Leaving renderSchemas(). " + schemas.length + " schema(s).");
}

// ---------------------------------------------------------------------------
// WHAT EACH DOCUMENT CONTRIBUTES TO THE CONFIGURATION PARAMETERS PANE.
//
// Three small readers rather than one, because each is answering a different
// document and a combined one would have to guess which it had been given.
// ---------------------------------------------------------------------------
function captureFromServiceProviderConfig(body) {
  log.debug("Entering captureFromServiceProviderConfig().");
  if (!body) {
    log.debug("Leaving captureFromServiceProviderConfig(). Nothing to read.");
    return;
  }
  recordDiscovered({
    patchSupported: supportedText(body.patch),
    bulkSupported: supportedText(body.bulk),
    bulkMaxOperations: numberOrBlank(body.bulk, 'maxOperations'),
    bulkMaxPayloadSize: numberOrBlank(body.bulk, 'maxPayloadSize'),
    filterSupported: supportedText(body.filter),
    filterMaxResults: numberOrBlank(body.filter, 'maxResults'),
    sortSupported: supportedText(body.sort),
    etagSupported: supportedText(body.etag),
    changePasswordSupported: supportedText(body.changePassword),
    authenticationSchemes: (body.authenticationSchemes || [])
      .map(function (row) {
        return row.type || row.name;
      }).join(', '),
    documentationUri: body.documentationUri || ''
  });
  log.debug("Leaving captureFromServiceProviderConfig().");
}

function numberOrBlank(holder, member) {
  log.debug("Entering numberOrBlank(). " + member);
  var out = (holder && holder[member] !== undefined &&
      holder[member] !== null) ? String(holder[member]) : '';
  log.debug("Leaving numberOrBlank(). " + (out || '(blank)'));
  return out;
}

function captureFromResourceTypes(types) {
  log.debug("Entering captureFromResourceTypes().");
  var found = {};
  types.forEach(function (row) {
    var name = String(row.name || row.id || '');
    if (name === 'User') {
      found.userEndpoint = row.endpoint || '';
      found.userSchema = row.schema || '';
      found.schemaExtensions = extensionSummary(row);
    }
    if (name === 'Group') {
      found.groupEndpoint = row.endpoint || '';
      found.groupSchema = row.schema || '';
    }
  });
  if (!Object.keys(found).length) {
    // A server whose types are named something other than User and Group.
    // Nothing is invented for it: an endpoint guessed here would be composed
    // into every request, and a wrong one produces a 404 on everything.
    log.warn('the ResourceTypes document names no User or Group type, so ' +
        'no endpoint was taken from it');
    log.debug("Leaving captureFromResourceTypes(). Nothing recognised.");
    return;
  }
  recordDiscovered(found);
  log.debug("Leaving captureFromResourceTypes().");
}

function captureFromSchemas(schemas) {
  log.debug("Entering captureFromSchemas().");
  recordDiscovered({
    schemaIds: schemas.map(function (row) {
      return row.id;
    }).filter(Boolean).join(', ')
  });
  log.debug("Leaving captureFromSchemas().");
}

// The three documents in turn, from the Configuration Parameters pane. In
// SEQUENCE and not in parallel: three concurrent calls against a server that
// rate-limits gets one answer and two 429s, and the point of the button is to
// fill the table rather than to be quick.
function readAllDiscovery() {
  log.debug("Entering readAllDiscovery().");
  statusBusy('scim_config_status', 'Reading the three discovery ' +
      'documents…');
  log.debug("Leaving readAllDiscovery(). Started.");
  return readServiceProviderConfig().then(function () {
    return readResourceTypes();
  }).then(function () {
    return readSchemas();
  }).then(function () {
    statusOk('scim_config_status', 'Read. Every row marked discovered above ' +
        'now says what the server said — except any you had already ' +
        'overridden, which are left as you set them.');
    return null;
  }).catch(function (error) {
    statusBad('scim_config_status', 'The documents could not all be read: ' +
        error.message);
    return null;
  });
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
        baseUrl: val('scim_base_url'),
        endpoints: endpointsForRequests() });
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
    renderDescribed(operationId, result.body);
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

// ---------------------------------------------------------------------------
// A DELIBERATE 401, TO READ THE CHALLENGE — AND THE PAGE DOES IT BY ITSELF.
//
// RFC 7644 section 2 defines no credential of its own and makes one normative
// requirement of a SCIM server: that a 401 say in WWW-Authenticate which
// schemes it accepts. That header is therefore the whole of SCIM's
// authentication discovery, and asking for it is one unauthenticated request
// against the resource the page is already pointed at. There is nothing for a
// reader to decide and so nothing for a button to ask them, which is why the
// button is gone: the probe runs whenever the service root changes, and the
// scheme list in the configuration table is ordered by what came back.
//
// `quiet` is what makes that acceptable. An automatic probe must not overwrite
// the Exchange pane — the request somebody is looking at is the one THEY sent,
// and having it replaced by a probe they did not ask for makes the page look
// like it is sending things at random. So the automatic call records the
// challenges and the status and renders neither half of the exchange; a probe
// asked for through the module (which is how tests/scim_page.js drives it)
// shows both, because then it IS the thing being looked at.
// ---------------------------------------------------------------------------
function probeAuthentication(options) {
  var quiet = !!(options && options.quiet);
  log.debug("Entering probeAuthentication(). quiet=" + quiet);
  saveState();
  var request;
  try {
    request = scimClient.buildRequest({ operation: 'listUsers',
        baseUrl: val('scim_base_url'), endpoints: endpointsForRequests(),
        query: { count: '1' } });
  } catch (e) {
    statusBad('scim_auth_status', e.message);
    log.debug("Leaving probeAuthentication(). " + e.message);
    return Promise.resolve(null);
  }
  statusBusy('scim_auth_status', 'Sending an unauthenticated request to see ' +
      'what the server asks for…');
  var via = probeVia();
  log.debug("Leaving probeAuthentication(). Sent via " + via + ".");
  return sendOnce(request, { scheme: 'none' },
      { via: via, quiet: quiet }).then(function (result) {
    if (!quiet) {
      showResponse(result);
    }
    if (result.transportError) {
      statusBad('scim_auth_status', result.transportError);
      return result;
    }
    lastChallenges = scimClient.parseChallenges(
      scenarios.headerValue(result.headers, 'www-authenticate'));
    renderChallenges();
    if (result.status === 401 && lastChallenges.length) {
      statusOk('scim_auth_status', 'The server refused an anonymous request ' +
          'and said what it accepts — that WWW-Authenticate header is the ' +
          'only normative requirement RFC 7644 section 2 makes of a SCIM ' +
          'server\'s authentication. What it named is at the top of the ' +
          'authScheme list above, marked "offered"' +
          (val('scim_auth_scheme') === 'none'
            ? ', and nothing is selected but anonymous — pick one.' : '.'));
    } else if (result.status === 401) {
      // THE 401 CAME BACK AND THE CHALLENGE DID NOT, which on the browser path
      // says nothing at all about the server: CORS hands this page only the
      // seven simple response headers, and WWW-Authenticate is not one of
      // them. The header was almost certainly sent. Reporting "this server
      // named no scheme" here would be a claim about somebody else's server
      // made out of a limit of this one's call path.
      statusBad('scim_auth_status', 'The server refused an anonymous ' +
          'request, and no WWW-Authenticate challenge could be READ from ' +
          'here. ' + (result.via === 'browser'
            ? 'That is very likely this call path rather than that server: a ' +
              'browser-direct call sees only the seven simple response ' +
              'headers unless the server names WWW-Authenticate in ' +
              'Access-Control-Expose-Headers. Set callPath to "through the ' +
              'api", which reads every header each way.'
            : 'The api reads every header, so the server genuinely sent ' +
              'none — which RFC 7644 section 2 requires it to send.'));
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

// ---------------------------------------------------------------------------
// THE AUTOMATIC PROBE.
//
// Debounced, because `change` on the service root fires on every blur — a Tab
// through the table would otherwise send one request per field — and BY URL,
// so that leaving and re-entering the field without editing it sends nothing
// at all. A page that re-probes on every focus change is a page somebody's
// server log will notice.
//
// It fails towards the page in every direction: an empty or unparseable
// service root is not probed, a probe already in flight is not doubled, and a
// server that does not answer leaves the scheme list exactly as it was. None
// of that is reported as an error, because nobody asked for this request.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// A PROBE PREFERS THE api, WHATEVER `callPath` SAYS, AND THIS IS NOT AN
// OVERRIDE OF THE READER'S CHOICE.
//
// The whole content of this request is a RESPONSE HEADER, and CORS hands a
// browser-direct call only the seven simple ones — `WWW-Authenticate` is not
// among them, so from the browser a probe of a cross-origin SCIM server reads
// an empty challenge from a server that sent a perfectly good one. The api
// reads every header each way, which is the reason it exists. So the probe
// goes that way when there is an api that answered, and the reader's callPath
// still decides every request they actually asked for.
//
// On a static deployment there is no api and the probe goes from the browser,
// where it will usually collect nothing — and the status line says which of
// the two happened rather than blaming the server.
// ---------------------------------------------------------------------------
function probeVia() {
  log.debug("Entering probeVia().");
  var via = (BACKEND_AVAILABLE && apiAnswered) ? 'api' : callVia();
  log.debug("Leaving probeVia(). " + via);
  return via;
}

var AUTO_PROBE_DELAY_MS = 400;
var autoProbeTimer = null;
var autoProbedUrl = null;
var autoProbeInFlight = false;

function scheduleAutoProbe() {
  log.debug("Entering scheduleAutoProbe().");
  if (autoProbeTimer) {
    clearTimeout(autoProbeTimer);
  }
  autoProbeTimer = setTimeout(autoProbe, AUTO_PROBE_DELAY_MS);
  log.debug("Leaving scheduleAutoProbe(). In " + AUTO_PROBE_DELAY_MS + "ms.");
}

function autoProbe() {
  log.debug("Entering autoProbe().");
  autoProbeTimer = null;
  var url = val('scim_base_url').trim();
  if (!/^https?:\/\//i.test(url)) {
    log.debug("Leaving autoProbe(). Not an absolute service root.");
    return Promise.resolve(null);
  }
  if (autoProbeInFlight) {
    log.debug("Leaving autoProbe(). One is already in flight.");
    return Promise.resolve(null);
  }
  if (url === autoProbedUrl) {
    log.debug("Leaving autoProbe(). This service root has been probed.");
    return Promise.resolve(null);
  }
  autoProbedUrl = url;
  autoProbeInFlight = true;
  // A NEW SERVICE ROOT MEANS NEW CHALLENGES, so the old ones go before the
  // request rather than after it. Leaving them would order the scheme list by
  // what a DIFFERENT server said, which is the one wrong answer this list can
  // give and the one nothing on screen would contradict.
  lastChallenges = [];
  log.debug("Leaving autoProbe(). Probing " + url);
  // AFTER the api has said whether it is there, because probeVia() reads that
  // answer and the load-time probe races it otherwise — a probe that took the
  // browser path only because the limits call had not come back yet would
  // collect no challenge from a server that sends one.
  return Promise.resolve(apiLimitsPromise).then(function () {
    return probeAuthentication({ quiet: true });
  }).then(function (result) {
    autoProbeInFlight = false;
    // NO CHALLENGE MEANS NO CHALLENGE, and the three discovered rows have to
    // say so. A 200 (this server authenticates nobody), a 403, and a server
    // that did not answer at all each leave `lastChallenges` empty, and
    // leaving the previous service root's schemes in the table would order the
    // scheme list by what a DIFFERENT server said — the one wrong answer this
    // list can give, and the one nothing on screen would contradict.
    if (!lastChallenges.length) {
      recordDiscovered({ challengeSchemes: '', challengeRealm: '',
          digestAlgorithms: '' });
    }
    return result;
  }).catch(function (error) {
    autoProbeInFlight = false;
    // Nobody asked for this request, so its failure is a log line and not a
    // banner. `probeAuthentication()` has already put the transport error in
    // the credential block's own status.
    log.warn('the automatic authentication probe failed: ' + error.message);
    return null;
  });
}

// Whether the automatic probe has anything left to do.
//
// Reached by tests/scim_page.js and by nothing on the page. It is here because
// the probe is the one thing on this page that starts by ITSELF: a test that
// sets the service root and reads the scheme list is otherwise racing a
// debounce it cannot see, and the failure looks like a wrong list rather than
// an early read.
function autoProbeState() {
  log.debug("Entering autoProbeState().");
  var state = { pending: !!autoProbeTimer, inFlight: autoProbeInFlight,
      probedUrl: autoProbedUrl };
  log.debug("Leaving autoProbeState(). pending=" + state.pending +
      " inFlight=" + state.inFlight);
  return state;
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
  // There is no realm row to show: `authRealm` and `hobaUsername` are rows of
  // the configuration table and are always on screen. Only the things a table
  // cannot hold appear and disappear with the scheme.
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
// Set by loadApiLimits(). `BACKEND_AVAILABLE` is what the build was told and
// this is what the api itself said, which is the stronger of the two — see the
// note on GET /scim/limits in api/scim_proxy.js.
var apiAnswered = false;
var apiLimitsPromise = null;

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
    apiAnswered = true;
    log.debug("Leaving loadApiLimits(). Read.");
    return limits;
  }).catch(function (error) {
    apiAnswered = false;
    setText('scim_api_limits', 'The api at ' + API_URL + ' did not answer ' +
        '(' + error.message + '), so the backend call path will not work. ' +
        'Browser-direct calls are unaffected — but the automatic ' +
        'authentication probe is not, because CORS withholds ' +
        'WWW-Authenticate from a browser-direct call.');
    log.debug("Leaving loadApiLimits(). No answer.");
    return null;
  });
}

// ---------------------------------------------------------------------------
// PANE COLLAPSE, matching the .dbg-* chrome the rest of the tree uses.
//
// The markup contract, which is the Kerberos pages' rather than the VC ones':
//
//   <div class="scim-pane dbg-pane" id="pane_x">
//     <legend class="dbg-legend" id="x_expand_button">Title</legend>
//     <fieldset name="x_fieldset" id="x_fieldset"
//               style="display: block;">…</fieldset>
//   </div>
//
// The legend and the fieldset are PAIRED BY CONVENTION — `x_expand_button`
// drives `x_fieldset` — rather than by an inline
// `onclick="…togglePane('x_fieldset')"`. The inline spelling repeats the id in
// two places and fails silently when the two drift: a title that does nothing
// at all, with nothing in the page complaining. Here a drifted pair is a
// warning in the console, and the console on this page is asserted clean by
// tests/scim_page.js section 9 — so it is a failure rather than a shrug.
//
// The `style="display: block"` in the markup is not decoration either:
// css/debugger.css turns the triangle with
// `.dbg-pane:has(fieldset[style*="display: none"])`, which reads the INLINE
// style, so a pane that starts with no inline display at all would show an
// expanded triangle over a pane the toggle had never touched.
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
// an array of pane ids instead, and every one of those is a list a new pane has
// to be remembered into — the kind of omission whose only symptom is one pane
// that the toggle skips. Reading them off the DOM covers a pane added later by
// construction.
function setAllPanes(expand) {
  log.debug("Entering setAllPanes(). expand=" + !!expand);
  var panes = document.querySelectorAll('.dbg-pane fieldset');
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
// precisely the drift the id convention exists to prevent, and a silent
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
    log.warn('there is no dbg_toggle_all on this page, so nothing expands or ' +
        'collapses every pane at once');
  }
  log.debug("Leaving wirePanes(). " + wired + " pane(s) wired.");
  return wired;
}

// ---------------------------------------------------------------------------
// THE ORDER HERE IS LOAD-BEARING, and it changed when the Connection and
// Authentication panes were folded into the configuration table.
//
// `renderConfig()` now CREATES the service root, the scheme select and the
// generator's fields, because those rows own their controls rather than
// mirroring somebody else's. So it has to run before `loadState()`, which
// fills every remembered field and skips the ones that are not there yet — and
// after `loadConfig()`, which is where the discovered values it draws come
// from. Getting this backwards is not an exception: it is a page that comes up
// with an empty service root every time, from storage that has one.
// ---------------------------------------------------------------------------
function onload() {
  log.debug("Entering onload().");
  populateOperations();
  populateScenarios();
  loadConfig();
  renderConfig();
  loadState();
  wirePanes();
  wireTabs();
  wireExpanders();
  refreshAuthControls();
  refreshOperationControls();
  refreshScenarioControls();
  refreshCallPathControls();
  renderChallenges();
  renderHistory();
  refreshConfigValues();
  apiLimitsPromise = loadApiLimits();
  // Every field writes through on change, so a reload keeps the page a person
  // had set up — the same rule every other workflow here follows.
  REMEMBERED.concat([TOKEN_FIELD, 'scim_save_token']).forEach(function (id) {
    var e = el(id);
    if (!e) {
      return;
    }
    e.addEventListener('change', function () {
      saveState();
      // The Configuration Parameters table mirrors these fields rather than
      // copying them, so it has to follow an edit made in the pane the field
      // lives in. Values only — the table is not rebuilt, so a select the
      // reader has open is not replaced under them.
      refreshConfigValues();
    });
  });
  var opSelect = el('scim_op');
  if (opSelect) {
    opSelect.addEventListener('change', refreshOperationControls);
  }
  // The scheme select and the service root are wired by `configInput()` when
  // the table builds them — they belong to it now, and a listener added here
  // would be lost on the first rebuild.
  var scenarioSelect = el('scim_scenario');
  if (scenarioSelect) {
    scenarioSelect.addEventListener('change', onScenarioSelected);
  }
  // The other three inputs a plan is built from. `input` rather than `change`,
  // so a plan stops describing the screen the moment the screen changes rather
  // than when the field is left.
  ['scim_scenario_seed', 'scim_scenario_prefix',
   'scim_scenario_count'].forEach(function (id) {
    var e = el(id);
    if (e) {
      e.addEventListener('input', forgetPlan);
    }
  });
  ['scim_op_id', 'scim_query_filter', 'scim_query_count',
   'scim_query_start_index', 'scim_query_sort_by', 'scim_query_sort_order',
   'scim_query_attributes', 'scim_query_excluded_attributes'].forEach(
    function (id) {
      var e = el(id);
      if (e) {
        e.addEventListener('input', refreshRequestPreview);
      }
    });
  // And the first probe, for the service root that was just restored from
  // storage. Debounced like every other one, so a page opened and immediately
  // edited sends one request rather than two.
  scheduleAutoProbe();
  log.debug("Leaving onload().");
}

window.onload = onload;

module.exports = {
  // The inline handlers on scim.html.
  onload: onload,
  togglePane: togglePane,
  setAllPanes: setAllPanes,
  wirePanes: wirePanes,
  toggleExpand: toggleExpand,
  selectTab: selectTab,
  saveConfig: saveConfig,
  restoreDiscovered: restoreDiscovered,
  readAllDiscovery: readAllDiscovery,
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
  // No longer an inline handler — the page probes for itself when the
  // service root changes. Exported because tests/scim_page.js drives it
  // directly, which is the only way to assert what one probe did.
  probeAuthentication: probeAuthentication,
  autoProbe: autoProbe,
  autoProbeState: autoProbeState,
  generateHobaKey: generateHobaKey,
  registerHobaKey: registerHobaKey,
  openSignIn: openSignIn,
  saveState: saveState,
  // Reached by tests/scim_page.js, which asserts what the page composes rather
  // than only what came back — the difference between "the request was wrong"
  // and "the button did nothing".
  currentRequest: currentRequest,
  callVia: callVia,
  refreshRequestPreview: refreshRequestPreview,
  // The configuration store, so that a test can assert what the page WOULD
  // compose a request onto rather than only what a table happens to show.
  configValue: configValue,
  endpointsForRequests: endpointsForRequests
};
