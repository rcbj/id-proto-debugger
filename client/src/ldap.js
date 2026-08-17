// File: ldap.js
//
// The LDAP Protocol Debugger (ldap.html) — one page, ten operations, and every
// one of them performed by the api rather than by this bundle.
//
// ---------------------------------------------------------------------------
// WHY THERE IS NO PROTOCOL CODE IN THIS FILE, AND WHY THAT IS NOT A SHORTCUT.
//
// LDAP is BER over a TCP socket (RFC 4511). A browser cannot open one: there is
// no fetch, no XHR and no WebSocket that will produce an LDAPMessage, and no
// amount of code here changes that. So this page is the same shape as the
// Kerberos pages — it builds the operation, `POST /ldap/*` performs it, and
// what comes back is reported in full.
//
// That is the opposite of how the SAML, WS-Trust and WebAuthn pages work, where
// the protocol runs in the browser and the api is optional. It has one visible
// consequence: **this page cannot work at all without an api behind it**, which
// is why `client/static_site.js` leaves it out of the deployed static sites and
// why its landing card is greyed out there. A page whose every button reported
// "no back end" would be worse than no page.
//
// It has a second, less obvious consequence worth stating: the URL in the
// connection pane is resolved by the API, not by the browser. `localhost` in
// that field means the api container, not the reader's machine — the same trap
// `krb5KdcHostDefault` documents, and the same reason the default here is the
// compose service name.
//
// ---------------------------------------------------------------------------
// WHAT THE PAGE IS ARRANGED AROUND.
//
// The five panes are not five features; they are one protocol at three levels
// of abstraction, and the arrangement is the teaching:
//
//   Connection   the BIND, on its own. It is a distinct LDAP operation and the
//                only one whose failure is about credentials, so it gets a
//                button of its own rather than being a side effect of the first
//                search somebody happens to run.
//   Search       the read half, with four presets that are the four questions
//                people actually ask a directory. The presets FILL THE FIELDS
//                rather than running a hidden query, because the filter they
//                produce is the thing worth seeing — "which groups is this user
//                in" is a search of the GROUPS for a member attribute naming the
//                user, and almost nobody guesses that the first time.
//   Users /      the write half, in the vocabulary of the objects rather than
//   Groups       of the protocol. Every button here composes into the Entry
//                pane's operations and says which one it used.
//   Entry        the write half in the protocol's own vocabulary — add, modify,
//                delete, modifyDN, compare against any DN at all. This is what
//                the two panes above are shorthand for, and it is where a
//                reader ends up once they want to do something the shorthand
//                does not cover.
//   Exchange     what was sent to the api and what came back, both verbatim.
//
// ---------------------------------------------------------------------------
// GROUP MEMBERSHIP IS A MODIFY, AND THAT IS THE SINGLE MOST USEFUL THING HERE.
//
// There is no "add user to group" operation in LDAP. A groupOfNames holds its
// membership in a multi-valued `member` attribute whose values are DNs, so
// adding a member is `modify` with one `add` change, and removing one is
// `modify` with one `delete` change carrying the value. The buttons in the
// Groups pane do exactly that and the Exchange pane shows the change list they
// built, because a reader who has only ever used a directory through an admin
// console has no reason to know it.
//
// The other half of that story is what happens when the user is deleted: the
// group still lists them. Referential integrity is a directory feature, not a
// protocol rule — OpenLDAP needs an overlay for it and Active Directory does it
// in the DSA — so a dangling member is the correct thing to see, and the page
// says so rather than tidying it away.
// ---------------------------------------------------------------------------

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var history = require("./ldap_history");
var log = bunyan.createLogger({ name: 'ldap', level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());

var API_URL = appconfig.apiUrl || '';
var BACKEND_AVAILABLE = appconfig.backendAvailable !== false;

// Every field on this page is remembered EXCEPT the password, which follows the
// project-wide rule: user configuration goes to localStorage, credentials do
// not. There is no opt-out checkbox here because there is no key pair to keep —
// nothing on this page generates key material.
var REMEMBERED = [
  'ldap_url', 'ldap_bind_dn', 'ldap_base_dn',
  'ldap_search_base', 'ldap_search_scope', 'ldap_search_filter',
  'ldap_search_attributes', 'ldap_search_size_limit',
  'ldap_user_uid', 'ldap_user_cn', 'ldap_user_sn', 'ldap_user_given_name',
  'ldap_user_mail', 'ldap_user_title',
  'ldap_group_cn', 'ldap_group_description',
  'ldap_entry_dn', 'ldap_entry_attributes', 'ldap_entry_changes',
  'ldap_entry_attribute', 'ldap_entry_value', 'ldap_entry_new_rdn'
];

// --- tiny DOM helpers ------------------------------------------------------
//
// These are one-liners called on every field read and every render, and they
// deliberately carry NO entering/leaving log lines. That is the hot-path
// exception the repo-root CLAUDE.md describes, and it is the same one
// saml_tools.js earned the hard way: a log pair in a one-line accessor is not a
// trace, it is the entire log, and at logLevel debug it took that page's
// in-browser sweep from 1.9s to 34s and past the WebDriver script timeout in
// CI. The functions that CALL these keep their logging, which is where a trace
// of an operation actually lives.
function el(id) { return document.getElementById(id); }
function val(id) { var e = el(id); return e ? String(e.value || '') : ''; }
function setVal(id, v) { var e = el(id); if (e) e.value = v == null ? '' : v; }
function setText(id, v) {
  var e = el(id);
  if (e) e.textContent = v == null ? '' : String(v);
}

function statusOk(id, message) {
  log.debug("Entering statusOk(). id=" + id);
  var e = el(id);
  if (e) {
    e.value = message;
    e.className = 'ldap-status ldap-grow ldap-ok';
  }
  log.debug("Leaving statusOk().");
}

function statusBad(id, message) {
  log.debug("Entering statusBad(). id=" + id);
  var e = el(id);
  if (e) {
    e.value = message;
    e.className = 'ldap-status ldap-grow ldap-bad';
  }
  log.debug("Leaving statusBad().");
}

function statusBusy(id, message) {
  log.debug("Entering statusBusy(). id=" + id);
  var e = el(id);
  if (e) {
    e.value = message;
    e.className = 'ldap-status ldap-grow ldap-pending';
  }
  log.debug("Leaving statusBusy().");
}

// --- state -----------------------------------------------------------------
function saveState() {
  log.debug("Entering saveState().");
  try {
    REMEMBERED.forEach(function (id) {
      var e = el(id);
      if (e) localStorage.setItem(id, String(e.value || ''));
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
    ldap_url: appconfig.ldapUrlDefault || '',
    ldap_bind_dn: appconfig.ldapBindDnDefault || '',
    ldap_base_dn: appconfig.ldapBaseDnDefault || '',
    ldap_search_base: appconfig.ldapBaseDnDefault || '',
    ldap_search_scope: 'sub',
    ldap_search_filter: '(objectClass=*)',
    ldap_search_attributes: '',
    ldap_search_size_limit: '100',
    ldap_user_uid: 'dave',
    ldap_user_cn: 'Dave Davis',
    ldap_user_sn: 'Davis',
    ldap_user_given_name: 'Dave',
    ldap_user_mail: 'dave@sts-mock.example',
    ldap_user_title: 'Support Analyst',
    ldap_group_cn: 'testers',
    ldap_group_description: 'A group created by the LDAP debugger.',
    ldap_entry_dn: '',
    ldap_entry_attributes: '',
    ldap_entry_changes: '',
    ldap_entry_attribute: 'sn',
    ldap_entry_value: '',
    ldap_entry_new_rdn: ''
  };
  REMEMBERED.forEach(function (id) {
    var stored = null;
    try {
      stored = localStorage.getItem(id);
    } catch (e) {
      stored = null;
    }
    // An empty stored value is a value: somebody cleared the field on purpose,
    // and re-seeding the default over it would make the field impossible to
    // empty. Only a MISSING key falls back.
    setVal(id, stored === null ? (defaults[id] || '') : stored);
  });
  // The password is never stored, so it is seeded from the configuration on
  // every load. On the deployed builds that default is empty, which is correct
  // — those builds have no api and no directory to reach anyway.
  setVal('ldap_password', appconfig.ldapPasswordDefault || '');
  log.debug("Leaving loadState().");
}

// --- talking to the api ----------------------------------------------------

// Both halves of the exchange, verbatim, because this page's whole claim is to
// show what happened. The request is recorded BEFORE the call, so a call that
// never answers still leaves the reader something to look at.
function showRequest(path, body) {
  log.debug("Entering showRequest(). path=" + path);
  var shown = JSON.parse(JSON.stringify(body));
  // The password is redacted here and nowhere else. Its LENGTH is kept,
  // because "did the field reach the api at all" is a real question when a bind
  // fails, and a debugger that answers it with silence sends people hunting in
  // the wrong place.
  if (typeof shown.password === 'string') {
    shown.password = '(' + shown.password.length + ' characters, not shown)';
  }
  setVal('ldap_request_json',
         'POST ' + API_URL + path + '\n' +
         'Content-Type: application/json\n\n' +
         JSON.stringify(shown, null, 2));
  setVal('ldap_response_json', '');
  setText('ldap_result_summary', '');
  log.debug("Leaving showRequest().");
}

function showResponse(status, payload) {
  log.debug("Entering showResponse(). status=" + status);
  setVal('ldap_response_json',
         'HTTP ' + status + '\n\n' + JSON.stringify(payload, null, 2));
  log.debug("Leaving showResponse().");
}

// One sentence naming what the directory said, in the protocol's own
// vocabulary. It is a separate line from the status because the status says
// whether the BUTTON worked and this says what LDAP answered — and on this page
// those are genuinely different: a `noSuchObject` is a successful round trip.
function showResult(payload) {
  log.debug("Entering showResult().");
  if (!payload || !payload.result) {
    setText('ldap_result_summary', '');
    log.debug("Leaving showResult(). There was no result code.");
    return;
  }
  var text = 'LDAP result ' + payload.result.code + ' (' +
    payload.result.name + ')';
  if (payload.diagnosticMessage) {
    text += ' — ' + payload.diagnosticMessage;
  }
  if (payload.timing) {
    text += '. ' + payload.timing.totalMs + ' ms in total';
    if (payload.timing.connectMs !== null &&
        payload.timing.connectMs !== undefined) {
      text += ', ' + payload.timing.connectMs + ' ms of it connecting';
    }
    text += '.';
  }
  if (payload.truncated) {
    text += ' ' + payload.truncated;
  }
  setText('ldap_result_summary', text);
  log.debug("Leaving showResult().");
}

// The connection fields every operation carries. Read fresh each time rather
// than cached, because a reader who changes the URL and presses the same button
// again expects the new one to be used.
function connection() {
  log.debug("Entering connection().");
  var out = {
    url: val('ldap_url').trim(),
    bindDn: val('ldap_bind_dn').trim(),
    password: val('ldap_password')
  };
  log.debug("Leaving connection(). url=" + out.url);
  return out;
}

// Perform one operation. Returns a promise of {status, payload}; it NEVER
// rejects for a directory answering "no", and the callers depend on that — see
// the note in api/ldap_client.js about the three outcomes.
function callApi(path, body, operation, dn, detailText, statusId) {
  log.debug("Entering callApi(). path=" + path);
  showRequest(path, body);
  statusBusy(statusId, 'Sending ' + operation + '…');
  var entryId = history.record({
    operation: operation,
    dn: dn || '',
    detailText: detailText || '',
    code: '',
    server: body.url || '',
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
    showResult(answer.payload);
    var payload = answer.payload || {};
    var code = payload.result ? String(payload.result.code) : '';
    if (answer.status === 200 && payload.ok) {
      history.update(entryId, history.SUCCESS,
                     'result ' + code + ' (' + payload.result.name + ')');
      statusOk(statusId, operation + ' succeeded. ' +
               'LDAP result 0 (success).');
    } else if (answer.status === 200) {
      // A round trip that the directory answered with a refusal. Recorded as a
      // Failure of the OPERATION, which it is, while the status line says the
      // exchange itself worked — that distinction is most of what somebody
      // debugging a directory is trying to establish.
      history.update(entryId, history.FAILURE,
                     'result ' + code + ' (' +
                     (payload.result ? payload.result.name : 'unknown') + ')');
      statusBad(statusId, 'The directory refused it: result ' + code + ' (' +
                (payload.result ? payload.result.name : 'unknown') + ')' +
                (payload.diagnosticMessage ?
                 ' — ' + payload.diagnosticMessage : '') + '.');
    } else {
      history.update(entryId, history.FAILURE,
                     'HTTP ' + answer.status + ': ' +
                     (payload.error || 'no message'));
      statusBad(statusId, 'HTTP ' + answer.status + ' from the api: ' +
                (payload.error || 'no message') + (answer.status === 400 ?
                ' (this service refused the request)' :
                ' (the directory could not be reached)'));
    }
    // The history row is rewritten rather than patched in place, because the
    // renderer is the same one that drew it and a second implementation of the
    // row would be one more thing to keep in step.
    renderHistory();
    log.debug("Leaving callApi(). status=" + answer.status);
    return answer;
  }).catch(function (error) {
    // The fetch itself failed: the api is not there, or CORS refused it. This
    // is the one branch where nothing came back at all, and it is why the
    // history has a `Sent` state — a row that stays Sent means exactly this.
    history.update(entryId, history.FAILURE, 'no answer: ' + error.message);
    renderHistory();
    showResponse('(no response)', { error: String(error && error.message) });
    statusBad(statusId, 'The call to the api failed: ' +
              (error && error.message) + '. The api is at ' + API_URL +
              '; this page cannot speak LDAP without it.');
    log.debug("Leaving callApi(). The fetch failed.");
    return { status: 0, payload: { error: String(error && error.message) } };
  });
}

// --- the DNs the shorthand panes build -------------------------------------
//
// Derived from the base DN rather than typed, and each is shown on the page
// beside the button that uses it, so nothing here is a hidden convention. They
// are the ones the mock directory seeds; a real directory with a different
// layout is what the Entry pane is for.
function usersDn() {
  log.debug("Entering usersDn().");
  var base = val('ldap_base_dn').trim();
  log.debug("Leaving usersDn().");
  return base ? 'ou=users,' + base : '';
}

function groupsDn() {
  log.debug("Entering groupsDn().");
  var base = val('ldap_base_dn').trim();
  log.debug("Leaving groupsDn().");
  return base ? 'ou=groups,' + base : '';
}

function userDn() {
  log.debug("Entering userDn().");
  var uid = val('ldap_user_uid').trim();
  var parent = usersDn();
  log.debug("Leaving userDn().");
  return (uid && parent) ? 'uid=' + uid + ',' + parent : '';
}

function groupDn() {
  log.debug("Entering groupDn().");
  var cn = val('ldap_group_cn').trim();
  var parent = groupsDn();
  log.debug("Leaving groupDn().");
  return (cn && parent) ? 'cn=' + cn + ',' + parent : '';
}

function refreshDerivedDns() {
  log.debug("Entering refreshDerivedDns().");
  setText('ldap_user_dn_preview', userDn() || '(set a base DN and a uid)');
  setText('ldap_group_dn_preview', groupDn() || '(set a base DN and a cn)');
  log.debug("Leaving refreshDerivedDns().");
}

// --- Connection ------------------------------------------------------------
function testBind() {
  log.debug("Entering testBind().");
  saveState();
  var body = connection();
  callApi('/ldap/bind', body, 'bind', body.bindDn || '(anonymous)',
          body.bindDn ? 'simple bind' : 'anonymous simple bind',
          'ldap_bind_status');
  log.debug("Leaving testBind().");
  return false;
}

// What the api will and will not do, asked for before anything is attempted.
// A debugger that discovers its own limits by hitting them reports them as
// somebody else's fault — and a build of the api WITHOUT the LDAP endpoints
// answers 404 here, which is a different thing from a directory that will not
// answer and is worth saying so.
function loadLimits() {
  log.debug("Entering loadLimits().");
  if (!BACKEND_AVAILABLE) {
    setText('ldap_limits',
            'This build has no api behind it, so no LDAP operation on this ' +
            'page can run. LDAP is BER over a TCP socket and a browser ' +
            'cannot open one.');
    log.debug("Leaving loadLimits(). There is no back end.");
    return;
  }
  fetch(API_URL + '/ldap/limits').then(function (response) {
    if (response.status === 404) {
      setText('ldap_limits',
              'The api at ' + API_URL + ' answered 404 for /ldap/limits, ' +
              'so it is a build without the LDAP endpoints rather than a ' +
              'directory that is refusing to answer.');
      return null;
    }
    return response.json();
  }).then(function (limits) {
    if (!limits) {
      log.debug("Leaving the limits handler. Nothing to show.");
      return;
    }
    var ports = limits.allowedPorts === 'any'
      ? 'any port (the api is configured with ldapAllowedPorts: "any")'
      : [].concat(limits.allowedPorts).join(', ');
    setText('ldap_limits',
      'The api will connect to ' + ports + ' over ' +
      [].concat(limits.schemes).join(' or ') + '. It gives up on a ' +
      'connection after ' + limits.limits.connectTimeout + ' ms and on an ' +
      'operation after ' + limits.limits.callTimeout + ' ms, and it stops ' +
      'accumulating a search result at ' + limits.limits.maxEntries +
      ' entries or ' + limits.limits.maxResultBytes + ' bytes. It does not ' +
      'follow referrals, does not offer StartTLS, and supports no SASL ' +
      'mechanism — simple bind only. The address policy is ' +
      (limits.addressPolicyEnabled ? 'ON, so private and loopback addresses ' +
       'are refused' : 'off on this deployment, which is why a directory on ' +
       'a private address can be reached') + '.');
  }).catch(function (error) {
    setText('ldap_limits', 'Could not ask the api what it will do: ' +
            error.message + '. Every button on this page needs it.');
    log.warn('could not read /ldap/limits: ' + error.message);
  });
  log.debug("Leaving loadLimits().");
}

// --- Search ----------------------------------------------------------------
function runSearch() {
  log.debug("Entering runSearch().");
  saveState();
  var body = connection();
  body.baseDn = val('ldap_search_base').trim();
  body.scope = val('ldap_search_scope');
  body.filter = val('ldap_search_filter').trim() || '(objectClass=*)';
  var attributes = val('ldap_search_attributes').trim();
  body.attributes = attributes
    ? attributes.split(/[\s,]+/).filter(function (a) { return a !== ''; })
    : [];
  var limit = parseInt(val('ldap_search_size_limit'), 10);
  if (limit > 0) body.sizeLimit = limit;
  callApi('/ldap/search', body, 'search', body.baseDn,
          body.scope + ' ' + body.filter, 'ldap_search_status')
    .then(function (answer) {
      renderEntries(answer.payload);
    });
  log.debug("Leaving runSearch().");
  return false;
}

// The result table, built with DOM APIs and textContent rather than a string of
// HTML. Everything in it — DNs, attribute names, attribute values — came out of
// a directory this page does not control, which is precisely the content that
// must not be handed to innerHTML. The same rule the WebAuthn panes follow.
function renderEntries(payload) {
  log.debug("Entering renderEntries().");
  var box = el('ldap_search_results');
  if (!box) {
    log.debug("Leaving renderEntries(). There is no results box.");
    return;
  }
  while (box.firstChild) box.removeChild(box.firstChild);
  var entries = (payload && payload.entries) || [];
  setText('ldap_search_count', entries.length +
          (entries.length === 1 ? ' entry' : ' entries'));
  if (!entries.length) {
    var empty = document.createElement('p');
    empty.className = 'ldap-note';
    empty.textContent = payload && payload.ok
      ? 'The search succeeded and matched nothing. That is a different ' +
        'answer from an error: the base exists, the filter ran, and no entry ' +
        'satisfied it.'
      : 'No entries. See the result code above.';
    box.appendChild(empty);
    log.debug("Leaving renderEntries(). There were no entries.");
    return;
  }
  var table = document.createElement('table');
  table.className = 'ldap-table ldap-entries';
  var head = document.createElement('thead');
  var headRow = document.createElement('tr');
  ['#', 'DN', 'Attributes'].forEach(function (label) {
    var th = document.createElement('th');
    th.textContent = label;
    headRow.appendChild(th);
  });
  head.appendChild(headRow);
  table.appendChild(head);
  var body = document.createElement('tbody');
  entries.forEach(function (entry, index) {
    var row = document.createElement('tr');
    var number = document.createElement('td');
    number.textContent = String(index + 1);
    row.appendChild(number);
    var dn = document.createElement('td');
    dn.className = 'ldap-entry-dn';
    dn.textContent = entry.dn;
    row.appendChild(dn);
    var attrs = document.createElement('td');
    Object.keys(entry.attributes || {}).forEach(function (name) {
      var line = document.createElement('div');
      var key = document.createElement('span');
      key.className = 'ldap-attr-name';
      key.textContent = name + ': ';
      line.appendChild(key);
      var value = document.createElement('span');
      value.className = 'ldap-attr-value';
      value.textContent = entry.attributes[name].join(' | ');
      line.appendChild(value);
      attrs.appendChild(line);
    });
    row.appendChild(attrs);
    body.appendChild(row);
  });
  table.appendChild(body);
  box.appendChild(table);
  log.debug("Leaving renderEntries(). " + entries.length + " entry/entries.");
}

// The four presets FILL THE FIELDS and then run. Filling rather than running a
// hidden query is the point: the filter is the thing worth reading, and the
// third one below is the one nobody guesses.
function presetUsers() {
  log.debug("Entering presetUsers().");
  setVal('ldap_search_base', usersDn() || val('ldap_base_dn'));
  setVal('ldap_search_scope', 'sub');
  setVal('ldap_search_filter', '(objectClass=inetOrgPerson)');
  setVal('ldap_search_attributes', '');
  log.debug("Leaving presetUsers().");
  return runSearch();
}

function presetGroups() {
  log.debug("Entering presetGroups().");
  setVal('ldap_search_base', groupsDn() || val('ldap_base_dn'));
  setVal('ldap_search_scope', 'sub');
  setVal('ldap_search_filter', '(objectClass=groupOfNames)');
  setVal('ldap_search_attributes', '');
  log.debug("Leaving presetGroups().");
  return runSearch();
}

// The members of one group: a BASE-scoped read of the group itself, asking only
// for `member`. Not a search of the users — the membership lives on the group.
function presetGroupMembers() {
  log.debug("Entering presetGroupMembers().");
  var dn = groupDn();
  if (!dn) {
    statusBad('ldap_search_status', 'Set a base DN and a group cn first — ' +
              'the members of a group are read from the group entry itself.');
    log.debug("Leaving presetGroupMembers(). There is no group DN.");
    return false;
  }
  setVal('ldap_search_base', dn);
  setVal('ldap_search_scope', 'base');
  setVal('ldap_search_filter', '(objectClass=*)');
  setVal('ldap_search_attributes', 'member');
  log.debug("Leaving presetGroupMembers().");
  return runSearch();
}

// The groups one user is in — and this is the one that surprises people. There
// is no attribute on the user to read: `memberOf` is a Microsoft extension that
// OpenLDAP only has behind an overlay, and this directory does not have it. So
// the question is answered from the other end, by searching the GROUPS for a
// `member` value that is the user's DN.
function presetUserGroups() {
  log.debug("Entering presetUserGroups().");
  var dn = userDn();
  if (!dn) {
    statusBad('ldap_search_status', 'Set a base DN and a uid first — the ' +
              'groups a user is in are found by searching the groups for a ' +
              'member value naming that user.');
    log.debug("Leaving presetUserGroups(). There is no user DN.");
    return false;
  }
  setVal('ldap_search_base', groupsDn() || val('ldap_base_dn'));
  setVal('ldap_search_scope', 'sub');
  setVal('ldap_search_filter',
         '(&(objectClass=groupOfNames)(member=' + dn + '))');
  setVal('ldap_search_attributes', 'cn member');
  log.debug("Leaving presetUserGroups().");
  return runSearch();
}

// --- Users -----------------------------------------------------------------
function createUser() {
  log.debug("Entering createUser().");
  saveState();
  var dn = userDn();
  if (!dn) {
    statusBad('ldap_user_status', 'A uid and a base DN are needed to build ' +
              'the DN of the entry to create.');
    log.debug("Leaving createUser(). There is no DN.");
    return false;
  }
  var body = connection();
  body.dn = dn;
  body.attributes = {
    objectClass: ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
    uid: val('ldap_user_uid').trim(),
    cn: val('ldap_user_cn').trim() || val('ldap_user_uid').trim(),
    sn: val('ldap_user_sn').trim() || val('ldap_user_uid').trim()
  };
  // Optional attributes are omitted rather than sent empty. An LDAP attribute
  // always has at least one value (RFC 4511 section 4.1.7), so an empty one is
  // not a weaker claim — it is a malformed one, and a strict directory refuses
  // the whole add for it.
  var given = val('ldap_user_given_name').trim();
  if (given) body.attributes.givenName = [given];
  var mail = val('ldap_user_mail').trim();
  if (mail) body.attributes.mail = [mail];
  var title = val('ldap_user_title').trim();
  if (title) body.attributes.title = [title];
  callApi('/ldap/add', body, 'create user', dn,
          'add, ' + Object.keys(body.attributes).length + ' attributes',
          'ldap_user_status');
  log.debug("Leaving createUser().");
  return false;
}

function updateUser() {
  log.debug("Entering updateUser().");
  saveState();
  var dn = userDn();
  if (!dn) {
    statusBad('ldap_user_status', 'A uid and a base DN are needed to build ' +
              'the DN of the entry to change.');
    log.debug("Leaving updateUser(). There is no DN.");
    return false;
  }
  var body = connection();
  body.dn = dn;
  // `replace` with values is what "set this attribute to this" means, and it
  // is not the same as `add`: add would leave the old value beside the new one,
  // since these attributes are multi-valued in the schema even when a person
  // thinks of them as single-valued. That is one of the two mistakes this pane
  // exists to make visible; the Exchange pane shows the change list.
  body.changes = [];
  [['cn', 'ldap_user_cn'], ['sn', 'ldap_user_sn'],
   ['givenName', 'ldap_user_given_name'], ['mail', 'ldap_user_mail'],
   ['title', 'ldap_user_title']].forEach(function (pair) {
    var value = val(pair[1]).trim();
    if (value) {
      body.changes.push({ operation: 'replace', type: pair[0],
                          values: [value] });
    }
  });
  if (!body.changes.length) {
    statusBad('ldap_user_status', 'Nothing to change — fill in at least one ' +
              'of cn, sn, givenName, mail or title.');
    log.debug("Leaving updateUser(). There is nothing to change.");
    return false;
  }
  callApi('/ldap/modify', body, 'update user attributes', dn,
          body.changes.length + ' replace change(s)', 'ldap_user_status');
  log.debug("Leaving updateUser().");
  return false;
}

function deleteUser() {
  log.debug("Entering deleteUser().");
  saveState();
  var dn = userDn();
  if (!dn) {
    statusBad('ldap_user_status', 'A uid and a base DN are needed to build ' +
              'the DN of the entry to delete.');
    log.debug("Leaving deleteUser(). There is no DN.");
    return false;
  }
  var body = connection();
  body.dn = dn;
  callApi('/ldap/delete', body, 'delete user', dn, 'delete',
          'ldap_user_status');
  log.debug("Leaving deleteUser().");
  return false;
}

// --- Groups ----------------------------------------------------------------
function createGroup() {
  log.debug("Entering createGroup().");
  saveState();
  var dn = groupDn();
  if (!dn) {
    statusBad('ldap_group_status', 'A group cn and a base DN are needed to ' +
              'build the DN of the entry to create.');
    log.debug("Leaving createGroup(). There is no DN.");
    return false;
  }
  var body = connection();
  body.dn = dn;
  body.attributes = {
    objectClass: ['top', 'groupOfNames'],
    cn: val('ldap_group_cn').trim()
  };
  var description = val('ldap_group_description').trim();
  if (description) body.attributes.description = [description];
  // A groupOfNames MUST have at least one member: `member` is a MUST attribute
  // in RFC 4519's definition of the class, so an empty group is not
  // expressible. Seeding it with the user named in the pane above is what a
  // real client does; the alternative, and what Active Directory chose, is the
  // `groupOfUniqueNames`-free `group` class, which has no such rule. This
  // directory has no schema and would accept an empty one, and sending it
  // anyway would teach a habit every real directory refuses.
  var member = userDn();
  if (member) {
    body.attributes.member = [member];
  } else {
    statusBad('ldap_group_status', 'A groupOfNames must have at least one ' +
              'member (RFC 4519 makes `member` a MUST), so set a uid in the ' +
              'Users pane first — it is used as the first member.');
    log.debug("Leaving createGroup(). There is no member to seed it with.");
    return false;
  }
  callApi('/ldap/add', body, 'create group', dn,
          'add, seeded with one member', 'ldap_group_status');
  log.debug("Leaving createGroup().");
  return false;
}

function deleteGroup() {
  log.debug("Entering deleteGroup().");
  saveState();
  var dn = groupDn();
  if (!dn) {
    statusBad('ldap_group_status', 'A group cn and a base DN are needed to ' +
              'build the DN of the entry to delete.');
    log.debug("Leaving deleteGroup(). There is no DN.");
    return false;
  }
  var body = connection();
  body.dn = dn;
  callApi('/ldap/delete', body, 'delete group', dn, 'delete',
          'ldap_group_status');
  log.debug("Leaving deleteGroup().");
  return false;
}

// Membership, both ways. There is no "add member" operation in LDAP — see the
// note at the top of this file — so both of these are `modify` on the GROUP.
function changeMembership(operation, label) {
  log.debug("Entering changeMembership(). operation=" + operation);
  saveState();
  var group = groupDn();
  var member = userDn();
  if (!group || !member) {
    statusBad('ldap_group_status', 'Both a group cn and a user uid are ' +
              'needed: membership is an attribute on the GROUP whose value ' +
              'is the DN of the user.');
    log.debug("Leaving changeMembership(). A DN is missing.");
    return false;
  }
  var body = connection();
  body.dn = group;
  body.changes = [{ operation: operation, type: 'member', values: [member] }];
  callApi('/ldap/modify', body, label, group,
          'modify: ' + operation + ' member ' + member, 'ldap_group_status');
  log.debug("Leaving changeMembership().");
  return false;
}

function addMember() {
  log.debug("Entering addMember().");
  log.debug("Leaving addMember().");
  return changeMembership('add', 'add user to group');
}

function removeMember() {
  log.debug("Entering removeMember().");
  log.debug("Leaving removeMember().");
  return changeMembership('delete', 'remove user from group');
}

// --- Entry (the protocol's own vocabulary) ---------------------------------

// The two JSON fields are parsed here rather than at the api, so a typo is
// reported against the box it was typed in instead of coming back as a 400
// naming a field name.
function parseJsonField(id, what, statusId) {
  log.debug("Entering parseJsonField(). id=" + id);
  var text = val(id).trim();
  if (!text) {
    log.debug("Leaving parseJsonField(). It is empty.");
    return null;
  }
  try {
    var parsed = JSON.parse(text);
    log.debug("Leaving parseJsonField(). It parsed.");
    return parsed;
  } catch (e) {
    statusBad(statusId, what + ' is not valid JSON: ' + e.message);
    log.debug("Leaving parseJsonField(). It did not parse.");
    return undefined;
  }
}

function entryAdd() {
  log.debug("Entering entryAdd().");
  saveState();
  var attributes = parseJsonField('ldap_entry_attributes', 'Attributes',
                                  'ldap_entry_status');
  if (attributes === undefined) {
    log.debug("Leaving entryAdd(). The attributes did not parse.");
    return false;
  }
  if (!attributes) {
    statusBad('ldap_entry_status', 'Attributes are required for an add — a ' +
              'JSON object of attribute name to value or array of values.');
    log.debug("Leaving entryAdd(). There were no attributes.");
    return false;
  }
  var body = connection();
  body.dn = val('ldap_entry_dn').trim();
  body.attributes = attributes;
  callApi('/ldap/add', body, 'add', body.dn,
          Object.keys(attributes).length + ' attributes',
          'ldap_entry_status');
  log.debug("Leaving entryAdd().");
  return false;
}

function entryModify() {
  log.debug("Entering entryModify().");
  saveState();
  var changes = parseJsonField('ldap_entry_changes', 'Changes',
                               'ldap_entry_status');
  if (changes === undefined) {
    log.debug("Leaving entryModify(). The changes did not parse.");
    return false;
  }
  if (!changes) {
    statusBad('ldap_entry_status', 'Changes are required for a modify — a ' +
              'JSON array of {operation, type, values}, where operation is ' +
              'add, delete or replace.');
    log.debug("Leaving entryModify(). There were no changes.");
    return false;
  }
  var body = connection();
  body.dn = val('ldap_entry_dn').trim();
  body.changes = changes;
  callApi('/ldap/modify', body, 'modify', body.dn,
          [].concat(changes).length + ' change(s)', 'ldap_entry_status');
  log.debug("Leaving entryModify().");
  return false;
}

function entryDelete() {
  log.debug("Entering entryDelete().");
  saveState();
  var body = connection();
  body.dn = val('ldap_entry_dn').trim();
  callApi('/ldap/delete', body, 'delete', body.dn, 'delete',
          'ldap_entry_status');
  log.debug("Leaving entryDelete().");
  return false;
}

function entryCompare() {
  log.debug("Entering entryCompare().");
  saveState();
  var body = connection();
  body.dn = val('ldap_entry_dn').trim();
  body.attribute = val('ldap_entry_attribute').trim();
  body.value = val('ldap_entry_value');
  callApi('/ldap/compare', body, 'compare', body.dn,
          body.attribute + ' = ' + body.value, 'ldap_entry_status')
    .then(function (answer) {
      var payload = answer.payload || {};
      if (answer.status === 200 && payload.matched !== null &&
          payload.matched !== undefined) {
        // A compare answers compareTrue (6) or compareFalse (5). NEITHER is
        // success (0), which is why this operation gets its own line rather
        // than relying on the shared "it succeeded" status: a false compare is
        // a working operation with a negative answer.
        statusOk('ldap_entry_status', payload.matched
          ? 'compareTrue (6): the attribute has that value.'
          : 'compareFalse (5): the attribute exists and does not have that ' +
            'value. Note that neither of those codes is success (0).');
      }
    });
  log.debug("Leaving entryCompare().");
  return false;
}

function entryRename() {
  log.debug("Entering entryRename().");
  saveState();
  var body = connection();
  body.dn = val('ldap_entry_dn').trim();
  body.newRdn = val('ldap_entry_new_rdn').trim();
  callApi('/ldap/modifydn', body, 'modifyDN', body.dn,
          'new RDN ' + body.newRdn, 'ldap_entry_status');
  log.debug("Leaving entryRename().");
  return false;
}

// Fill the Entry pane from the shorthand panes, so the reader can see what the
// buttons above were actually sending and then change it. This is the bridge
// between the two levels of abstraction the page is arranged around.
function fillEntryFromUser() {
  log.debug("Entering fillEntryFromUser().");
  setVal('ldap_entry_dn', userDn());
  setVal('ldap_entry_attributes', JSON.stringify({
    objectClass: ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
    uid: [val('ldap_user_uid').trim()],
    cn: [val('ldap_user_cn').trim()],
    sn: [val('ldap_user_sn').trim()]
  }, null, 2));
  setVal('ldap_entry_changes', JSON.stringify([
    { operation: 'replace', type: 'title',
      values: [val('ldap_user_title').trim()] }
  ], null, 2));
  saveState();
  log.debug("Leaving fillEntryFromUser().");
  return false;
}

function fillEntryFromGroup() {
  log.debug("Entering fillEntryFromGroup().");
  setVal('ldap_entry_dn', groupDn());
  setVal('ldap_entry_attributes', JSON.stringify({
    objectClass: ['top', 'groupOfNames'],
    cn: [val('ldap_group_cn').trim()],
    member: [userDn()]
  }, null, 2));
  setVal('ldap_entry_changes', JSON.stringify([
    { operation: 'add', type: 'member', values: [userDn()] }
  ], null, 2));
  saveState();
  log.debug("Leaving fillEntryFromGroup().");
  return false;
}

// --- History ---------------------------------------------------------------
function renderHistory() {
  log.debug("Entering renderHistory().");
  history.render(el('ldap_operation_history'));
  log.debug("Leaving renderHistory().");
}

function clearOperationHistory() {
  log.debug("Entering clearOperationHistory().");
  history.clear();
  renderHistory();
  log.debug("Leaving clearOperationHistory().");
  return false;
}

// --- misc ------------------------------------------------------------------
function copyField(id) {
  log.debug("Entering copyField(). id=" + id);
  var e = el(id);
  if (!e) {
    log.debug("Leaving copyField(). There is no such field.");
    return false;
  }
  e.select();
  try {
    document.execCommand('copy');
  } catch (err) {
    // Not available in this context. The text is selected either way, which is
    // most of what the button was for.
    log.warn('copy failed: ' + err.message);
  }
  log.debug("Leaving copyField().");
  return false;
}

function init() {
  log.debug("Entering init().");
  loadState();
  refreshDerivedDns();
  renderHistory();
  loadLimits();
  REMEMBERED.forEach(function (id) {
    var e = el(id);
    if (!e) return;
    e.addEventListener('change', function () {
      saveState();
      refreshDerivedDns();
    });
    e.addEventListener('keyup', refreshDerivedDns);
  });
  if (!BACKEND_AVAILABLE) {
    // Every button needs the api. Saying so once, up front, is better than
    // eleven identical failures — and this branch is what the deployed static
    // builds would show if the page were deployed at all, which it is not.
    statusBad('ldap_bind_status', 'This build has no api behind it, so no ' +
              'operation on this page can run.');
  }
  log.debug("Leaving init().");
}

if (typeof window !== 'undefined') {
  window.addEventListener('DOMContentLoaded', init);
}

module.exports = {
  testBind: testBind,
  runSearch: runSearch,
  presetUsers: presetUsers,
  presetGroups: presetGroups,
  presetGroupMembers: presetGroupMembers,
  presetUserGroups: presetUserGroups,
  createUser: createUser,
  updateUser: updateUser,
  deleteUser: deleteUser,
  createGroup: createGroup,
  deleteGroup: deleteGroup,
  addMember: addMember,
  removeMember: removeMember,
  entryAdd: entryAdd,
  entryModify: entryModify,
  entryDelete: entryDelete,
  entryCompare: entryCompare,
  entryRename: entryRename,
  fillEntryFromUser: fillEntryFromUser,
  fillEntryFromGroup: fillEntryFromGroup,
  clearOperationHistory: clearOperationHistory,
  copyField: copyField,
  // Exported for the test suite, which drives the page through the same
  // functions a click does rather than through a second implementation of them.
  usersDn: usersDn,
  groupsDn: groupsDn,
  userDn: userDn,
  groupDn: groupDn
};
