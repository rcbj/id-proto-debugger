// File: pki.js
// Author: Robert C. Broeckelmann Jr.
//
// ---------------------------------------------------------------------------
// The PKI page (client/public/pki.html): a Root CA, an Intermediate, an Issuing
// CA, and the leaf certificates any of them can sign — then a real TLS
// connection made with what was issued.
//
// This file is the DOM half and only the DOM half. Everything it does that is
// worth testing lives somewhere else on purpose:
//
//   client/src/key_material.js  key pairs and keystore formats (shared with
//                               jwt_tools.js — the Key Pair block on this page
//                               is that pane, not a copy of it)
//   client/src/x509.js          certificates: profiles, every X.509v3
//                               extension, issuing, describing, chain checks
//   client/src/pki_store.js     the keys and certificates kept for reuse, and
//                               the private-key opt-out
//   api/tls_probe.js            the TLS / mutual-TLS connection
//
// so tests/pki_x509.js can drive the whole issuing matrix in node against
// OpenSSL, and tests/pki_page.js has only the page left to check.
//
// One thing about the markup this file drives, because nothing in here says it
// and it is the shape everything below assumes. The page is FIVE panes, and
// the first of them — `pane_config` — holds what were three: Key Pair, Issue a
// Certificate and X.509v3 Extensions. They are one act, and every field in all
// three is an input to the single "Generate Key Pair & Issue Certificate"
// button at the TOP of it. So a new block of fields belongs inside that pane
// under a `.pki-group` heading rather than in a sixth pane; tests/pki_page.js
// asserts the pane list by name, and docs/pki.md says what the merge bought
// and what it costs when the layout that made it possible collapses.
//
// ---------------------------------------------------------------------------
// WHY THERE IS NO "RUN THE TLS TEST IN THE BROWSER" OPTION
//
// Every other page here offers the choice: call from the browser, or proxy
// through the api. This one does not, and the omission is the design rather
// than an unfinished half.
//
// A browser cannot answer any of the questions this pane exists to ask. It
// cannot present a chosen client certificate — the browser picks from its own
// store through its own UI, so the certificate issued thirty seconds ago on
// this page is not offered and "present none" is not offerable. It cannot be
// given a truststore, so "does this chain verify against MY root, and only
// mine" is unaskable. It cannot read the negotiated version, the cipher, the
// ALPN protocol or the server's chain. And a failed handshake arrives as a
// generic network error with the TLS alert — the one genuinely informative
// thing — discarded. A browser-side option would therefore be a button that
// answers a different question, badly, and every answer it gave would be about
// the browser rather than about the server.
//
// ---------------------------------------------------------------------------
// THE LIST FIELDS ARE TEXT, ONE ENTRY PER LINE, AND THAT IS DELIBERATE
//
// subjectAltName, the CRL distribution points, the AIA entries, the policies,
// the name constraints and the custom extensions are all textareas with a
// small documented syntax rather than rows of widgets. Three reasons: an
// extension editor built from widgets can only express what its widgets
// anticipated, and the point of this page is issuing the certificate that is
// wrong in exactly one way; a line of text is something an operator can paste
// from a ticket, a config file or a colleague; and it is a form of input a test
// can drive exhaustively without a hundred `findElement` calls. The syntax is
// documented on the page beside each field and parsed by the parse*() functions
// below, which tests/pki_page.js checks directly.
// ---------------------------------------------------------------------------

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var keys = require("./key_material");
var x509 = require("./x509");
var store = require("./pki_store");
var history = require("./pki_history");

var log = bunyan.createLogger({ name: 'pki', level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());

var STORE_PREFIX = 'pkitools_';

// Added to #pane_tls on a deployment with no api behind it. The rules are in
// client/public/css/pki.css; disableTlsPane() below is what puts it on and
// what disables the controls underneath it.
var DISABLED_PANE_CLASS = 'pki-pane-disabled';

// ---------------------------------------------------------------------------
// Small DOM helpers.
//
// These are one-liners called on nearly every interaction, and they carry NO
// entry/exit logging for the reason the repo-root CLAUDE.md gives about
// saml_tools.js's accessors: rendering the store table and rebuilding the
// extension form passes through them hundreds of times, and a log record is a
// JSON serialization plus a console write. The functions that CALL them keep
// their logging, which is where a trace of an operation actually lives.
// ---------------------------------------------------------------------------
function el(id) {
  return document.getElementById(id);
}
function val(id) {
  var e = el(id);
  return e ? e.value : '';
}
function setVal(id, v) {
  var e = el(id);
  if (e) e.value = (v == null ? '' : v);
}
function checked(id) {
  var e = el(id);
  return !!(e && e.checked);
}
function setChecked(id, on) {
  var e = el(id);
  if (e) e.checked = !!on;
}
// Both halves, because this page hides things two different ways and neither
// alone covers it. #pki_issuer_row is hidden by an inline display and nothing
// else; #pki_backend_notice is hidden by `saml-hidden` in the markup, which is
// `display: none !important` in saml_common.css — so setting style.display
// back to '' does not put it on the page. That is what happened to the backend
// notice: the static build called this with `true`, the class kept the banner
// off the page, and the one thing that saw a difference was
// tests/pki_page.js, which reads the inline style rather than the rendered
// element and therefore agreed with the caller rather than with the user.
// saml_request.js and wstrust_tools.js toggle the class; this now does that
// too, as well as what it already did.
function show(id, on) {
  var e = el(id);
  if (!e) return;
  e.style.display = on ? '' : 'none';
  if (!e.classList) return;
  if (on) {
    e.classList.remove('saml-hidden');
  } else {
    e.classList.add('saml-hidden');
  }
}
function setText(id, text) {
  var e = el(id);
  if (e) e.textContent = text == null ? '' : String(text);
}
function setTitle(id, text) {
  var e = el(id);
  if (e) e.title = text == null ? '' : String(text);
}
function trimmed(id) {
  return String(val(id) || '').trim();
}
function lines(id) {
  return String(val(id) || '').split(/\r?\n/).map(function (line) {
    return line.trim();
  }).filter(Boolean);
}

function status(message) {
  log.debug("Entering status(). " + message);
  setText('pki_status', message);
  log.debug("Leaving status().");
}

// ---------------------------------------------------------------------------
// localStorage persistence — every .stored element by its id, exactly as the
// SAML/WS-Trust/WS-Federation pages do it.
//
// The KEY MATERIAL on this page is not here: the key pair fields and the
// objects the store holds are governed by pki_store.js's own preference, which
// is the checkbox `pki_save_keys`. Everything this function writes is
// configuration — subjects, algorithms, extension text, TLS settings.
// ---------------------------------------------------------------------------
var KEYPAIR_FIELDS = ['pki_private_key', 'pki_public_key'];

function persistedEls() {
  log.debug("Entering persistedEls().");
  log.debug("Leaving persistedEls().");
  return document.querySelectorAll('.stored');
}

function keyMaterialMayBeStored() {
  log.debug("Entering keyMaterialMayBeStored().");
  var e = el('pki_save_keys');
  // An absent checkbox (an older cached copy of the page) keeps saving rather
  // than silently dropping a CA key somebody expects to still be there.
  log.debug("Leaving keyMaterialMayBeStored().");
  return !e || e.checked;
}

function forgetStoredKeyPair() {
  log.debug("Entering forgetStoredKeyPair().");
  if (!window.localStorage) {
    log.debug("Leaving forgetStoredKeyPair().");
    return;
  }
  for (var i = 0; i < KEYPAIR_FIELDS.length; i++) {
    localStorage.removeItem(STORE_PREFIX + KEYPAIR_FIELDS[i]);
  }
  log.debug("Leaving forgetStoredKeyPair().");
}

function saveState() {
  log.debug("Entering saveState().");
  if (!window.localStorage) {
    log.debug("Leaving saveState().");
    return;
  }
  var storeKeys = keyMaterialMayBeStored();
  var els = persistedEls();
  for (var i = 0; i < els.length; i++) {
    if (!els[i].id) continue;
    if (!storeKeys && KEYPAIR_FIELDS.indexOf(els[i].id) >= 0) continue;
    var v = els[i].type === 'checkbox' ? (els[i].checked ? '1' : '0')
      : els[i].value;
    localStorage.setItem(STORE_PREFIX + els[i].id, v);
  }
  // Not merely "skip writing": remove what an earlier save already put there.
  // saveState() runs on most interactions, so no code path can leave the key
  // pair behind — the rule the SAML page learned and the reason its purge
  // lives here rather than in the change handler.
  if (!storeKeys) forgetStoredKeyPair();
  log.debug("Leaving saveState().");
}

// "YYYY-MM-DDTHH:MM" in local time — what a datetime-local input holds — from
// anything Date can parse, and '' from anything it cannot. Minute precision,
// because that is the input's own default step and a seconds field is a fifth
// spin box in a column that has room for four.
function asLocalDateTime(text) {
  log.debug("Entering asLocalDateTime().");
  var raw = String(text == null ? '' : text).trim();
  if (!raw) {
    log.debug("Leaving asLocalDateTime(). Empty.");
    return '';
  }
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(raw)) {
    log.debug("Leaving asLocalDateTime(). Already in shape.");
    return raw;
  }
  var d = new Date(raw);
  if (isNaN(d.getTime())) {
    log.debug("Leaving asLocalDateTime(). Unparseable: " + raw);
    return '';
  }
  function pad(n) {
    return (n < 10 ? '0' : '') + n;
  }
  var out = d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' +
      pad(d.getDate()) + 'T' + pad(d.getHours()) + ':' + pad(d.getMinutes());
  log.debug("Leaving asLocalDateTime(). " + out);
  return out;
}

function restoreState() {
  log.debug("Entering restoreState().");
  if (!window.localStorage) {
    log.debug("Leaving restoreState().");
    return;
  }
  var els = persistedEls();
  for (var i = 0; i < els.length; i++) {
    if (!els[i].id) continue;
    var v = localStorage.getItem(STORE_PREFIX + els[i].id);
    if (v === null) continue;
    if (els[i].type === 'checkbox') {
      els[i].checked = (v === '1' || v === 'true' || v === 'on');
    } else if (els[i].type === 'datetime-local') {
      // A datetime-local input takes "YYYY-MM-DDTHH:MM" in LOCAL time and
      // REJECTS anything else by silently setting itself to empty — so a
      // value stored by an older build of this page (these four fields were
      // ISO 8601 text inputs until 2026-08-18, and their placeholder said
      // "2026-01-01T00:00:00Z") would vanish on the reload that upgraded the
      // page, with nothing anywhere to say why. Converting it here keeps the
      // INSTANT and moves it into the shape the control accepts.
      els[i].value = asLocalDateTime(v);
    } else {
      els[i].value = v;
    }
  }
  log.debug("Leaving restoreState().");
}

function renderKeyStorageNote() {
  log.debug("Entering renderKeyStorageNote().");
  var note = el('pki_keys_storage_note');
  if (!note) {
    log.debug("Leaving renderKeyStorageNote().");
    return;
  }
  if (keyMaterialMayBeStored()) {
    note.textContent = '';
    log.debug("Leaving renderKeyStorageNote().");
    return;
  }
  // textContent, not innerHTML: this is a message, not markup.
  note.textContent = 'Private keys are not being saved. The certificates and ' +
    'public keys below are kept, so they can still be inspected, exported ' +
    'and put in a truststore — but nothing here can sign or be presented as ' +
    'a client certificate any more, and the private half already written has ' +
    'been removed. Use Download to carry a key pair yourself.';
  log.debug("Leaving renderKeyStorageNote().");
}

function onSaveKeysChange() {
  log.debug("Entering onSaveKeysChange().");
  store.setSaveKeys(keyMaterialMayBeStored());
  saveState();
  renderKeyStorageNote();
  renderStore();
  refreshIssuerOptions();
  refreshTlsSelectors();
  log.debug("Leaving onSaveKeysChange().");
  return false;
}

// ---------------------------------------------------------------------------
// The key pair pane — the same pane jwt_tools.html carries, over the same
// module. Nothing about generation, conversion or export is implemented here.
// ---------------------------------------------------------------------------
function currentKeyDescriptor() {
  log.debug("Entering currentKeyDescriptor().");
  var desc = keys.keyAlg(val('pki_key_alg')) || keys.keyAlg('rsa-2048');
  log.debug("Leaving currentKeyDescriptor(). " + desc.id);
  return desc;
}

function onKeyAlgChange() {
  log.debug("Entering onKeyAlgChange().");
  saveState();
  refreshSignatureOptions();
  log.debug("Leaving onKeyAlgChange().");
  return false;
}

async function generateKeys() {
  log.debug("Entering generateKeys().");
  var desc = currentKeyDescriptor();
  status('Generating a ' + desc.label + ' key pair…');
  var entry = history.record({ operation: history.OP_GENERATE_KEY,
                              subject: '(new key pair)',
                              algorithm: desc.label, issuer: '' });
  try {
    var pair = await keys.generateKeyPair(desc);
    setVal('pki_private_key', pair.privatePem);
    setVal('pki_public_key', pair.publicPem);
    await applyKeyFormat();
    saveState();
    status('Generated a ' + desc.label + ' key pair. It is not stored ' +
        'anywhere until a certificate is issued with it.');
    history.update(entry, history.SUCCESS, desc.label);
  } catch (e) {
    log.error('generateKeys: ' + e.message);
    status('Key generation failed: ' + e.message);
    history.update(entry, history.FAILURE, e.message);
  }
  renderHistory();
  log.debug("Leaving generateKeys().");
  return false;
}

// The ONE button the configuration pane is an input to, and the reason there
// is no longer a second one. "Generate Key Pair" and "Issue Certificate" were
// two halves of a single act: a pair that is never certified is kept nowhere
// (generateKeys() says so in its own status line), and issue() refuses
// outright without one — "Generate a key pair first" is an error message for
// a step that could only ever be forgotten.
//
// The pair is generated here unless the reuse checkbox says an existing one is
// to be certified: a CA re-issuing its own certificate, or the pair the
// store's "Use this key pair" button just loaded, which ticks that box itself.
// The fields are checked as well as the box, because a ticked box over two
// empty fields is a request to certify nothing.
async function generateAndIssue() {
  log.debug("Entering generateAndIssue().");
  var reuse = checked('pki_reuse_key') && !!trimmed('pki_private_key') &&
      !!trimmed('pki_public_key');
  if (!reuse) {
    // What the fields held BEFORE, because a failed generation leaves them
    // exactly as they were rather than empty — see below.
    var before = trimmed('pki_private_key');
    await generateKeys();
    // generateKeys() has already put its own failure in the status line. A
    // second attempt at issuing would replace that message with a vaguer one
    // about a missing key pair.
    //
    // Emptiness is not the test, and testing it that way misreported a whole
    // class of failure. generateKeys() catches its own error and leaves the
    // fields untouched, so after a failed generation they hold the PREVIOUS
    // pair — which on this page is the pair of a DIFFERENT algorithm, since
    // the only reason to generate again is that the dropdown changed. Issuing
    // then imported that pair under the newly chosen algorithm and reported
    // the mismatch, so a browser with no Ed25519 in Web Crypto (anything
    // before Chrome 137) answered "Generate Key Pair & Issue Certificate"
    // with
    //
    //   Could not issue the certificate: Failed to execute 'importKey' on
    //   'SubtleCrypto': Algorithm: Unrecognized name
    //
    // naming the wrong call, on a key the user had not asked to certify. An
    // unchanged private key means generation did not happen: two successful
    // generations never produce the same one.
    var after = trimmed('pki_private_key');
    if (!after || !trimmed('pki_public_key') || after === before) {
      log.debug("Leaving generateAndIssue(). No key pair to certify.");
      return false;
    }
  }
  await issue();
  log.debug("Leaving generateAndIssue().");
  return false;
}

// Make both key fields match the PEM/JWK toggle, which is key_material.js's
// conversion and not a second one.
async function applyKeyFormat() {
  log.debug("Entering applyKeyFormat().");
  var toJwk = checked('pki_key_jwk');
  var desc = currentKeyDescriptor();
  try {
    var priv = trimmed('pki_private_key');
    if (priv) {
      if (toJwk && !keys.isJwk(priv)) {
        setVal('pki_private_key',
            JSON.stringify(await keys.privToJwk(priv, desc), null, 2));
      } else if (!toJwk && keys.isJwk(priv)) {
        setVal('pki_private_key', await keys.privToPem(priv, desc));
      }
    }
    var pub = trimmed('pki_public_key');
    if (pub) {
      if (toJwk && !keys.isJwk(pub)) {
        setVal('pki_public_key',
            JSON.stringify(await keys.pubToJwk(pub, desc), null, 2));
      } else if (!toJwk && keys.isJwk(pub)) {
        setVal('pki_public_key', await keys.pubToPem(pub, desc));
      }
    }
    saveState();
  } catch (e) {
    log.error('applyKeyFormat: ' + e.message);
    status('Key format conversion error: ' + e.message);
  }
  log.debug("Leaving applyKeyFormat().");
  return false;
}

function toggleKeyFormat() {
  log.debug("Entering toggleKeyFormat().");
  log.debug("Leaving toggleKeyFormat().");
  return applyKeyFormat();
}

// Download the key pair in the chosen keystore format. When an object in the
// store is selected, its certificate chain goes in too — which is what makes a
// PKCS#12 importable as a client identity rather than as a bare key.
async function downloadKeys() {
  log.debug("Entering downloadKeys().");
  var desc = currentKeyDescriptor();
  var format = val('pki_ks_format') || 'pem';
  var selected = selectedObject();
  var certs = [];
  if (selected && checked('pki_ks_include_chain')) {
    certs = store.chainPems(selected.id);
  } else if (selected && selected.certificatePem) {
    certs = [selected.certificatePem];
  }
  var entry = history.record({ operation: history.OP_EXPORT,
      subject: selected ? selected.subject : '(key pair only)',
      algorithm: format.toUpperCase(),
      issuer: '' });
  try {
    var result = await keys.exportKeyPair({
      format: format,
      privatePem: selected && selected.privateKeyPem
        ? selected.privateKeyPem : trimmed('pki_private_key'),
      publicPem: selected && selected.publicKeyPem
        ? selected.publicKeyPem : trimmed('pki_public_key'),
      desc: selected ? (keys.keyAlg(selected.keyAlg) || desc) : desc,
      password: val('pki_ks_password'),
      baseName: fileBaseName(selected),
      friendlyName: selected ? selected.subject : 'idptools key pair',
      certs: certs
    });
    status(keys.downloadFiles(result));
    history.update(entry, history.SUCCESS, result.status);
  } catch (e) {
    log.error('downloadKeys: ' + e.message);
    status('Export failed: ' + e.message);
    history.update(entry, history.FAILURE, e.message);
  }
  renderHistory();
  log.debug("Leaving downloadKeys().");
  return false;
}

// A file name from the subject's CN, because "key-pair.p12" four times in a
// downloads folder is four files nobody can tell apart.
function fileBaseName(entry) {
  log.debug("Entering fileBaseName().");
  var name = 'idptools-key-pair';
  if (entry && entry.subject) {
    var cn = /CN=([^,]+)/.exec(entry.subject);
    if (cn) name = cn[1].trim();
  }
  log.debug("Leaving fileBaseName().");
  return String(name).replace(/[^A-Za-z0-9._-]+/g, '-').slice(0, 60) ||
      'idptools-key-pair';
}

// Show the selected object's certificate on the shared certificate-details
// page, which is the tool that already exists for it.
function viewCertificate() {
  log.debug("Entering viewCertificate().");
  var selected = selectedObject();
  if (!selected || !selected.certificatePem) {
    status('Select a certificate in the store first.');
    log.debug("Leaving viewCertificate(). Nothing selected.");
    return false;
  }
  if (window.localStorage) {
    localStorage.setItem('saml_cert_view', selected.certificatePem);
  }
  window.open('/saml_cert.html?from=pki.html', '_blank');
  log.debug("Leaving viewCertificate().");
  return false;
}

function copyField(id) {
  log.debug("Entering copyField().");
  var e = el(id);
  if (!e) {
    log.debug("Leaving copyField(). No such field.");
    return false;
  }
  var text = e.value || '';
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).catch(function (err) {
      log.error('copyField: ' + err);
    });
  } else {
    try {
      e.focus();
      e.select();
      document.execCommand('copy');
    } catch (err) {
      log.error('copyField fallback: ' + err.message);
    }
  }
  log.debug("Leaving copyField().");
  return false;
}

// ---------------------------------------------------------------------------
// The list fields' syntax. Each parser takes the textarea's text and returns
// what x509.js's extension builders take. They are exported so that
// tests/pki_page.js can check the syntax without driving the form.
// ---------------------------------------------------------------------------

// dns:host | ip:addr | email:a@b | uri:https://… | upn:user@REALM |
// krb5:host/x@REALM | rid:1.2.3.4 | dirname:CN=x,O=y |
// othername:<oid>:<base64 DER>
function parseAltNames(text) {
  log.debug("Entering parseAltNames().");
  var out = [];
  String(text || '').split(/\r?\n/).forEach(function (raw) {
    var line = raw.trim();
    if (!line || line.charAt(0) === '#') return;
    var colon = line.indexOf(':');
    if (colon < 0) {
      throw new Error('Alternative name "' + line + '" has no type. Write ' +
          'dns:example.com, ip:10.0.0.1, email:a@b, uri:https://…, ' +
          'upn:user@REALM, krb5:host/x@REALM, rid:1.2.3.4, dirname:CN=x, ' +
          'or othername:<oid>:<base64>.');
    }
    var kind = line.slice(0, colon).trim().toLowerCase();
    var value = line.slice(colon + 1).trim();
    if (kind === 'othername') {
      var second = value.indexOf(':');
      if (second < 0) {
        throw new Error('othername needs an OID and a base64 DER value: ' +
            'othername:1.2.3.4:BASE64');
      }
      out.push({ kind: 'otherName', oid: value.slice(0, second).trim(),
                value: value.slice(second + 1).trim() });
      return;
    }
    var known = { dns: 'dns', ip: 'ip', email: 'email', uri: 'uri',
                 upn: 'upn', krb5: 'krb5', rid: 'registeredID',
                 dirname: 'dirName' };
    if (!known[kind]) {
      throw new Error('Unknown alternative name type "' + kind + '".');
    }
    out.push({ kind: known[kind], value: value });
  });
  log.debug("Leaving parseAltNames(). " + out.length + " name(s).");
  return out;
}

// ocsp:http://… | caissuers:http://… | <oid>:http://…
function parseAiaEntries(text) {
  log.debug("Entering parseAiaEntries().");
  var out = [];
  String(text || '').split(/\r?\n/).forEach(function (raw) {
    var line = raw.trim();
    if (!line || line.charAt(0) === '#') return;
    var colon = line.indexOf(':');
    if (colon < 0) {
      throw new Error('Access description "' + line + '" has no method. ' +
          'Write ocsp:http://… or caissuers:http://…');
    }
    var method = line.slice(0, colon).trim();
    var url = line.slice(colon + 1).trim();
    var lower = method.toLowerCase();
    var known = { ocsp: 'ocsp', caissuers: 'caIssuers',
                 timestamping: 'timeStamping', carepository: 'caRepository' };
    out.push({ method: known[lower] || method, url: url });
  });
  log.debug("Leaving parseAiaEntries(). " + out.length + " entry(ies).");
  return out;
}

// <policy oid>[|cps=<uri>][|notice=<text>]
function parsePolicies(text) {
  log.debug("Entering parsePolicies().");
  var out = [];
  String(text || '').split(/\r?\n/).forEach(function (raw) {
    var line = raw.trim();
    if (!line || line.charAt(0) === '#') return;
    var parts = line.split('|');
    var policy = { oid: parts[0].trim() };
    for (var i = 1; i < parts.length; i++) {
      var piece = parts[i].trim();
      var eq = piece.indexOf('=');
      if (eq < 0) continue;
      var name = piece.slice(0, eq).trim().toLowerCase();
      var value = piece.slice(eq + 1).trim();
      if (name === 'cps') policy.cps = value;
      else if (name === 'notice') policy.notice = value;
    }
    out.push(policy);
  });
  log.debug("Leaving parsePolicies(). " + out.length + " policy(ies).");
  return out;
}

// <issuer policy oid>=<subject policy oid>
function parsePolicyMappings(text) {
  log.debug("Entering parsePolicyMappings().");
  var out = [];
  String(text || '').split(/\r?\n/).forEach(function (raw) {
    var line = raw.trim();
    if (!line || line.charAt(0) === '#') return;
    var eq = line.indexOf('=');
    if (eq < 0) {
      throw new Error('A policy mapping is <issuer oid>=<subject oid>; got "' +
          line + '".');
    }
    out.push({ issuer: line.slice(0, eq).trim(),
              subject: line.slice(eq + 1).trim() });
  });
  log.debug("Leaving parsePolicyMappings(). " + out.length + " mapping(s).");
  return out;
}

// permit dns:example.com | exclude ip:10.0.0.0/8
//
// Note the IP form takes a PREFIX. A name constraint's iPAddress is the address
// followed by its mask — eight bytes for v4, not four — which is the one place
// a general name is not just an address, and x509.js encodes it.
function parseNameConstraints(text) {
  log.debug("Entering parseNameConstraints().");
  var out = { permitted: [], excluded: [] };
  String(text || '').split(/\r?\n/).forEach(function (raw) {
    var line = raw.trim();
    if (!line || line.charAt(0) === '#') return;
    var space = line.indexOf(' ');
    if (space < 0) {
      throw new Error('A name constraint is "permit <name>" or "exclude ' +
          '<name>"; got "' + line + '".');
    }
    var verb = line.slice(0, space).trim().toLowerCase();
    var rest = line.slice(space + 1).trim();
    var names = parseAltNames(rest);
    if (verb === 'permit' || verb === 'permitted') {
      out.permitted = out.permitted.concat(names);
    } else if (verb === 'exclude' || verb === 'excluded') {
      out.excluded = out.excluded.concat(names);
    } else {
      throw new Error('A name constraint starts with "permit" or "exclude"; ' +
          'got "' + verb + '".');
    }
  });
  log.debug("Leaving parseNameConstraints(). " + out.permitted.length +
      " permitted, " + out.excluded.length + " excluded.");
  return out;
}

// <oid>|<critical|->|<base64 DER>
function parseCustomExtensions(text) {
  log.debug("Entering parseCustomExtensions().");
  var out = [];
  String(text || '').split(/\r?\n/).forEach(function (raw) {
    var line = raw.trim();
    if (!line || line.charAt(0) === '#') return;
    var parts = line.split('|');
    if (parts.length < 3) {
      throw new Error('A custom extension is <oid>|<critical or ->|<base64 ' +
          'DER>; got "' + line + '".');
    }
    out.push({ oid: parts[0].trim(),
              critical: /^crit/i.test(parts[1].trim()),
              value: parts.slice(2).join('|').trim() });
  });
  log.debug("Leaving parseCustomExtensions(). " + out.length + " of them.");
  return out;
}

// The subject DN: the named fields, then any extra lines of NAME=value or
// OID=value in the order they are written. Order matters — an RDNSequence is
// ordered, and a reordered DN is a different name.
function collectSubject() {
  log.debug("Entering collectSubject().");
  var out = [];
  var fields = [['CN', 'pki_dn_cn'], ['O', 'pki_dn_o'], ['OU', 'pki_dn_ou'],
                ['L', 'pki_dn_l'], ['ST', 'pki_dn_st'], ['C', 'pki_dn_c'],
                ['emailAddress', 'pki_dn_email'], ['DC', 'pki_dn_dc'],
                ['UID', 'pki_dn_uid'],
                ['serialNumber', 'pki_dn_serialnumber']];
  fields.forEach(function (field) {
    var value = trimmed(field[1]);
    if (value) out.push({ name: field[0], value: value });
  });
  lines('pki_dn_extra').forEach(function (line) {
    if (line.charAt(0) === '#') return;
    var eq = line.indexOf('=');
    if (eq < 0) {
      throw new Error('An extra subject attribute is NAME=value or ' +
          'OID=value; got "' + line + '".');
    }
    var name = line.slice(0, eq).trim();
    var value = line.slice(eq + 1).trim();
    if (x509.DN_ATTRS[name]) out.push({ name: name, value: value });
    else out.push({ oid: name, value: value });
  });
  log.debug("Leaving collectSubject(). " + out.length + " attribute(s).");
  return out;
}

// Read the whole extension form into the spec x509.js takes. One function, so
// the tests can check the form against the encoder in one call.
function collectExtensions() {
  log.debug("Entering collectExtensions().");
  var checkedUsages = function (prefix, names) {
    return names.filter(function (name) {
      return checked(prefix + name);
    });
  };
  var ext = {
    basicConstraints: {
      present: checked('pki_ext_bc'),
      ca: checked('pki_bc_ca'),
      pathLen: trimmed('pki_bc_pathlen'),
      critical: checked('pki_bc_critical')
    },
    keyUsage: {
      present: checked('pki_ext_ku'),
      usages: checkedUsages('pki_ku_', x509.KEY_USAGE_BITS.map(function (b) {
        return b.name;
      })),
      critical: checked('pki_ku_critical')
    },
    extKeyUsage: {
      present: checked('pki_ext_eku'),
      usages: checkedUsages('pki_eku_',
          Object.keys(x509.EKU_OIDS)).concat(lines('pki_eku_extra')),
      critical: checked('pki_eku_critical')
    },
    subjectKeyIdentifier: {
      present: checked('pki_ext_skid'), critical: false
    },
    authorityKeyIdentifier: {
      present: checked('pki_ext_akid'), critical: false,
      includeIssuerAndSerial: checked('pki_akid_issuer_serial')
    },
    subjectAltName: {
      present: checked('pki_ext_san'),
      names: parseAltNames(val('pki_san')),
      critical: checked('pki_san_critical')
    },
    issuerAltName: {
      present: checked('pki_ext_ian'),
      names: parseAltNames(val('pki_ian')),
      critical: checked('pki_ian_critical')
    },
    cRLDistributionPoints: {
      present: checked('pki_ext_cdp'),
      urls: lines('pki_cdp'),
      critical: checked('pki_cdp_critical')
    },
    freshestCRL: {
      present: checked('pki_ext_freshest'),
      urls: lines('pki_freshest'),
      critical: false
    },
    authorityInfoAccess: {
      present: checked('pki_ext_aia'),
      entries: parseAiaEntries(val('pki_aia')),
      critical: false
    },
    subjectInfoAccess: {
      present: checked('pki_ext_sia'),
      entries: parseAiaEntries(val('pki_sia')),
      critical: false
    },
    certificatePolicies: {
      present: checked('pki_ext_policies'),
      policies: parsePolicies(val('pki_policies')),
      critical: checked('pki_policies_critical')
    },
    policyMappings: {
      present: checked('pki_ext_policy_mappings'),
      mappings: parsePolicyMappings(val('pki_policy_mappings')),
      critical: true
    },
    policyConstraints: {
      present: checked('pki_ext_policy_constraints'),
      requireExplicitPolicy: trimmed('pki_require_explicit_policy'),
      inhibitPolicyMapping: trimmed('pki_inhibit_policy_mapping'),
      critical: true
    },
    nameConstraints: (function () {
      var parsed = parseNameConstraints(val('pki_name_constraints'));
      return { present: checked('pki_ext_name_constraints'),
               permitted: parsed.permitted, excluded: parsed.excluded,
               critical: checked('pki_nc_critical') };
    })(),
    inhibitAnyPolicy: {
      present: checked('pki_ext_inhibit_any'),
      skipCerts: trimmed('pki_inhibit_any_skip'),
      critical: true
    },
    privateKeyUsagePeriod: {
      present: checked('pki_ext_pkup'),
      notBefore: trimmed('pki_pkup_not_before'),
      notAfter: trimmed('pki_pkup_not_after'),
      critical: false
    },
    tlsFeature: {
      present: checked('pki_ext_tls_feature'),
      features: lines('pki_tls_feature'),
      critical: false
    },
    ocspNoCheck: {
      present: checked('pki_ext_ocsp_nocheck'), critical: false
    },
    netscapeCertType: {
      present: checked('pki_ext_ns_cert_type'),
      types: checkedUsages('pki_ns_', x509.NS_CERT_TYPE_BITS.map(
          function (b) { return b.name; })),
      critical: false
    },
    netscapeComment: {
      present: checked('pki_ext_ns_comment'),
      text: trimmed('pki_ns_comment'), critical: false
    },
    custom: parseCustomExtensions(val('pki_custom_extensions'))
  };
  log.debug("Leaving collectExtensions().");
  return ext;
}

// Put a profile's defaults into the form. Called when the profile changes, and
// on load — the form IS the extension set, so a profile that only changed what
// gets issued and not what is shown would be a page that lies about what it is
// about to do.
function applyProfileDefaults(profileId) {
  log.debug("Entering applyProfileDefaults(). profile=" + profileId);
  var ext = x509.defaultExtensions(profileId);
  setChecked('pki_ext_bc', ext.basicConstraints.present);
  setChecked('pki_bc_ca', ext.basicConstraints.ca);
  setChecked('pki_bc_critical', ext.basicConstraints.critical);
  setVal('pki_bc_pathlen', ext.basicConstraints.pathLen === null ||
      ext.basicConstraints.pathLen === undefined
      ? '' : String(ext.basicConstraints.pathLen));
  setChecked('pki_ext_ku', ext.keyUsage.present);
  setChecked('pki_ku_critical', ext.keyUsage.critical);
  x509.KEY_USAGE_BITS.forEach(function (bit) {
    setChecked('pki_ku_' + bit.name,
        ext.keyUsage.usages.indexOf(bit.name) >= 0);
  });
  setChecked('pki_ext_eku', ext.extKeyUsage.present);
  setChecked('pki_eku_critical', ext.extKeyUsage.critical);
  Object.keys(x509.EKU_OIDS).forEach(function (name) {
    setChecked('pki_eku_' + name, ext.extKeyUsage.usages.indexOf(name) >= 0);
  });
  setChecked('pki_ext_skid', ext.subjectKeyIdentifier.present);
  setChecked('pki_ext_akid', ext.authorityKeyIdentifier.present);
  setChecked('pki_ext_ocsp_nocheck', ext.ocspNoCheck.present);
  saveState();
  log.debug("Leaving applyProfileDefaults().");
}

// The subject CN follows the profile, until somebody types one of their own.
//
// A default CN is worth having because an empty subject is a legal DN and the
// store then holds four rows nobody can tell apart; and it has to MOVE with the
// profile, or picking Intermediate CA after Root CA issues an intermediate
// called "RootCA", which chains correctly and reads as a bug in the
// chain view for as long as it takes to notice.
//
// So: an empty field is filled, a field still holding ANY profile's default is
// replaced, and anything else is left exactly as it is. That third case is the
// one that matters — this runs on every profile change and once on load, after
// restoreState(), so a name typed yesterday would otherwise be overwritten by
// a page that had merely been reopened.
function applyDefaultSubjectCN(profileId) {
  log.debug("Entering applyDefaultSubjectCN(). profile=" + profileId);
  var current = trimmed('pki_dn_cn');
  if (current && !x509.isDefaultSubjectCN(current)) {
    log.debug("Leaving applyDefaultSubjectCN(). Kept " + current);
    return;
  }
  setVal('pki_dn_cn', x509.defaultSubjectCN(profileId));
  log.debug("Leaving applyDefaultSubjectCN().");
}

// The rest of the subject DN — O, OU, L, ST, C — which does not follow the
// profile and so is filled ONCE, on load, into whatever is empty.
//
// It is fill-only: anything already in a field stays, including a value this
// function put there yesterday. The case it cannot tell apart is a field
// somebody deliberately EMPTIED — clearing O and reloading gets O back — which
// is the same trade applyDefaultSubjectCN() has always made for the CN, and
// the alternative is remembering a negative in storage for every field on the
// page.
function applyDefaultSubjectDN() {
  log.debug("Entering applyDefaultSubjectDN().");
  var fields = [['O', 'pki_dn_o'], ['OU', 'pki_dn_ou'], ['L', 'pki_dn_l'],
                ['ST', 'pki_dn_st'], ['C', 'pki_dn_c']];
  fields.forEach(function (field) {
    if (trimmed(field[1])) return;
    setVal(field[1], x509.DEFAULT_DN[field[0]] || '');
  });
  log.debug("Leaving applyDefaultSubjectDN().");
}

// The last subjectAltName this page wrote by itself.
//
// It is what tells "the SAN is still ours" from "somebody has edited it" in
// the one case x509.isDefaultSubjectAltName() cannot answer: once the CN has
// been typed over, the SAN this page derived from it (`dns:www.example.test`)
// is not any profile's default and looks exactly like a name a person chose.
// A module variable rather than storage, deliberately — after a reload the
// page has no idea which of the two it is looking at, and the safe reading of
// an unknown is that it belongs to the reader.
var lastAutoSan = null;

function setSubjectAltName(value) {
  log.debug("Entering setSubjectAltName(). " + (value || '(none)'));
  setVal('pki_san', value);
  setChecked('pki_ext_san', !!value);
  lastAutoSan = value;
  log.debug("Leaving setSubjectAltName().");
}

// Whether the subjectAltName field is one this page may still overwrite:
// empty, any profile's default, the last one this page wrote, or one that
// already says exactly what the CN says — in which case rewriting it to match
// a new CN takes nothing away.
function subjectAltNameIsOurs() {
  log.debug("Entering subjectAltNameIsOurs().");
  var current = trimmed('pki_san');
  var cn = trimmed('pki_dn_cn');
  var ours = x509.isDefaultSubjectAltName(current) ||
      current === lastAutoSan ||
      (!!cn && current === 'dns:' + cn);
  log.debug("Leaving subjectAltNameIsOurs(). " + ours);
  return ours;
}

// The subjectAltName that goes with the profile, which only the two serverAuth
// profiles have: `dns:` + whatever the CN says.
//
// For a TLS server that is not a convenience, it is the difference between a
// certificate a client will accept and one it will not — every current browser
// ignores the Common Name — so the checkbox is ticked with it rather than left
// for the reader to find among twenty-two extension cards.
//
// The same three cases as the CN, and for the same reason: fill an empty
// field, REPLACE one this page put there (a Root CA chosen after a TLS Server
// keeps `dns:server`, which is a name that certificate has no business
// asserting), and never touch a name somebody typed.
//
// It follows the CN rather than the profile's own default, which is the whole
// point of it: picking TLS Server and then typing the name you actually want
// is the ordinary way to use this page, and a SAN left naming `server` while
// the CN says something else is the same unusable certificate as no SAN at
// all — the one this is here to stop.
function applyDefaultSubjectAltName(profileId) {
  log.debug("Entering applyDefaultSubjectAltName(). profile=" + profileId);
  if (!subjectAltNameIsOurs()) {
    log.debug("Leaving applyDefaultSubjectAltName(). Kept " +
        trimmed('pki_san'));
    return;
  }
  var wanted = x509.defaultSubjectAltName(profileId);
  var cn = trimmed('pki_dn_cn');
  if (wanted && cn) wanted = 'dns:' + cn;
  setSubjectAltName(wanted);
  log.debug("Leaving applyDefaultSubjectAltName(). " + (wanted || '(none)'));
}

// The CN changed under a profile whose subjectAltName is derived from it.
// Wired to the field itself rather than to the delegated change listener,
// which only saves state.
function onSubjectCnChange() {
  log.debug("Entering onSubjectCnChange().");
  applyDefaultSubjectAltName(val('pki_profile'));
  saveState();
  log.debug("Leaving onSubjectCnChange().");
  return false;
}

function onProfileChange() {
  log.debug("Entering onProfileChange().");
  var profileId = val('pki_profile');
  applyProfileDefaults(profileId);
  applyDefaultSubjectCN(profileId);
  var p = x509.profile(profileId) || {};
  // A root is self-signed by definition, so the issuer dropdown is pointless
  // for it and actively misleading: a "root" signed by something else is an
  // intermediate.
  show('pki_issuer_row', !p.selfSigned);
  // The note this profile used to print under the dropdown is the dropdown's
  // own tooltip now. It says something for seven of the fourteen profiles, so
  // there is a fallback: a control whose title is empty has no tooltip at all,
  // and "some of these have one" is worse than none.
  setTitle('pki_profile', profileNote(profileId) ||
      'Sets the default extensions, the default validity and whether this ' +
      'certificate is self-signed.');
  applyDefaultSubjectAltName(profileId);
  setVal('pki_validity_years', String(p.years || 1));
  refreshSignatureOptions();
  saveState();
  log.debug("Leaving onProfileChange().");
  return false;
}

function profileNote(profileId) {
  log.debug("Entering profileNote().");
  var notes = {
    'root-ca': 'Self-signed, and the only certificate here that is. Its ' +
        'private key signs the intermediate; nothing signs it.',
    'intermediate-ca': 'Signed by the root, and signs the issuing CA. ' +
        'pathLenConstraint 1 lets exactly one more CA follow it.',
    'issuing-ca': 'Signed by the intermediate, and signs leaf certificates ' +
        'only — pathLenConstraint 0 says so, and a validator enforces it.',
    'tls-server': 'The name a client checks is in subjectAltName, not the ' +
        'CN. A certificate with only a CN is refused by every current ' +
        'browser.',
    'tls-client': 'Presented by the client in a mutual-TLS handshake. The ' +
        'TLS test below can present this one.',
    'ocsp-responder': 'Carries id-pkix-ocsp-nocheck, so a validator does not ' +
        'try to check the revocation status of the responder that answers ' +
        'revocation questions.',
    'kdc': 'PKINIT. The KDC certificate needs the Kerberos principal in a ' +
        'subjectAltName otherName — write krb5:krbtgt/REALM@REALM.'
  };
  log.debug("Leaving profileNote().");
  return notes[profileId] || '';
}

// ---------------------------------------------------------------------------
// Issuing
// ---------------------------------------------------------------------------
function selectedIssuer() {
  log.debug("Entering selectedIssuer().");
  var id = val('pki_issuer');
  var entry = id ? store.get(id) : null;
  log.debug("Leaving selectedIssuer(). " + (entry ? entry.subject : 'none'));
  return entry;
}

function refreshIssuerOptions() {
  log.debug("Entering refreshIssuerOptions().");
  var select = el('pki_issuer');
  if (!select) {
    log.debug("Leaving refreshIssuerOptions(). No dropdown.");
    return;
  }
  var previous = select.value;
  while (select.firstChild) select.removeChild(select.firstChild);
  // Only CAs whose private key is still here: offering one that cannot sign
  // produces a Web Crypto error two clicks later naming neither the CA nor the
  // missing key.
  store.certificateAuthorities(true).forEach(function (entry) {
    var option = document.createElement('option');
    option.value = entry.id;
    option.textContent = store.labelFor(entry);
    select.appendChild(option);
  });
  if (!select.options.length) {
    var none = document.createElement('option');
    none.value = '';
    none.textContent = '(no certificate authority in the store yet)';
    select.appendChild(none);
  }
  if (previous) select.value = previous;
  refreshSignatureOptions();
  log.debug("Leaving refreshIssuerOptions(). " + select.options.length +
      " option(s).");
}

// The signature algorithms offered are the ones the SIGNING key can actually
// produce — the issuer's for a leaf, the subject's own for a self-signed root.
// Offering ECDSA against an RSA key fails inside Web Crypto with a message
// about key usage that names neither key nor algorithm.
function refreshSignatureOptions() {
  log.debug("Entering refreshSignatureOptions().");
  var select = el('pki_sig_alg');
  if (!select) {
    log.debug("Leaving refreshSignatureOptions(). No dropdown.");
    return;
  }
  var profileId = val('pki_profile');
  var p = x509.profile(profileId) || {};
  var signerDesc;
  if (p.selfSigned) {
    signerDesc = currentKeyDescriptor();
  } else {
    var issuer = selectedIssuer();
    signerDesc = issuer ? keys.keyAlg(issuer.keyAlg) : currentKeyDescriptor();
  }
  var allowed = x509.signatureAlgorithmsFor(signerDesc || {});
  var previous = select.value;
  while (select.firstChild) select.removeChild(select.firstChild);
  allowed.forEach(function (id) {
    var option = document.createElement('option');
    option.value = id;
    option.textContent = x509.SIG_ALGS[id].label;
    select.appendChild(option);
  });
  if (allowed.indexOf(previous) >= 0) {
    select.value = previous;
  } else if (signerDesc) {
    select.value = x509.defaultSignatureAlgorithm(signerDesc);
  }
  setTitle('pki_sig_alg', signerDesc
    ? 'The signing key is ' + (signerDesc.label || signerDesc.kind) +
      ', so these are the algorithms it can produce.'
    : 'No signing key chosen yet, so this is every algorithm the page has.');
  log.debug("Leaving refreshSignatureOptions(). " + allowed.length +
      " option(s).");
}

function onIssuerChange() {
  log.debug("Entering onIssuerChange().");
  refreshSignatureOptions();
  saveState();
  log.debug("Leaving onIssuerChange().");
  return false;
}

// A fresh random 128-bit serial in the Serial Number field.
//
// The field is filled rather than left empty so that the value about to be
// signed is visible — and editable — before the certificate exists, instead
// of appearing for the first time in the store's Serial Number row. It is
// refilled after every issue, because a serial that stayed put would be
// re-used by the next certificate the same CA signs, and two certificates
// from one issuer sharing a serial is exactly what a serial is for
// preventing: they are indistinguishable to anything that revokes, caches or
// pins by (issuer, serial).
function newSerial() {
  log.debug("Entering newSerial().");
  setVal('pki_serial', x509.randomSerialHex(16));
  // setVal() is not a user edit, so the delegated change listener never sees
  // it and the value would not survive a reload.
  saveState();
  log.debug("Leaving newSerial().");
}

function validityDates() {
  log.debug("Entering validityDates().");
  var notBefore = trimmed('pki_not_before');
  var notAfter = trimmed('pki_not_after');
  var out = {
    notBefore: notBefore ? new Date(notBefore) : new Date()
  };
  if (notAfter) {
    out.notAfter = new Date(notAfter);
  } else {
    var years = parseInt(val('pki_validity_years'), 10);
    if (!(years > 0)) years = 1;
    out.notAfter = new Date(out.notBefore.getTime());
    out.notAfter.setUTCFullYear(out.notAfter.getUTCFullYear() + years);
  }
  log.debug("Leaving validityDates().");
  return out;
}

async function issue() {
  log.debug("Entering issue().");
  var profileId = val('pki_profile');
  var p = x509.profile(profileId) || {};
  var entryId = history.record({ operation: history.OP_ISSUE,
      subject: trimmed('pki_dn_cn') || '(no CN)',
      algorithm: val('pki_sig_alg'),
      issuer: p.selfSigned ? '(self-signed)'
        : (selectedIssuer() ? selectedIssuer().subject : '(none)') });
  try {
    var subject = collectSubject();
    if (!subject.length) {
      throw new Error('A certificate needs a subject — at least a Common ' +
          'Name.');
    }
    var privatePem = trimmed('pki_private_key');
    var publicPem = trimmed('pki_public_key');
    if (!privatePem || !publicPem) {
      throw new Error('There is no key pair to certify. Clear "reuse the ' +
          'key pair below" and the button generates one: the certificate ' +
          'certifies the public key above, and a CA needs the private half ' +
          'to sign with later.');
    }
    var keyDesc = currentKeyDescriptor();
    // The fields may hold JWK (the format toggle); everything below is PEM.
    privatePem = await keys.asPrivatePem(privatePem, keyDesc);
    publicPem = await keys.asPublicPem(publicPem, keyDesc);

    var issuer = null;
    if (!p.selfSigned) {
      issuer = selectedIssuer();
      if (!issuer) {
        throw new Error('Choose the certificate authority that signs this ' +
            'certificate. A root CA has to exist before anything else can ' +
            'be issued.');
      }
      if (!store.canSign(issuer)) {
        throw new Error('"' + issuer.subject + '" has no private key in this ' +
            'browser, so it cannot sign. Its private key was either never ' +
            'saved or was purged when key saving was turned off.');
      }
    }

    var validity = validityDates();
    var serial = trimmed('pki_serial') || x509.randomSerialHex(16);
    var result = await x509.issueCertificate({
      profile: profileId,
      subject: subject,
      subjectPublicKey: publicPem,
      issuer: issuer
        ? { certificatePem: issuer.certificatePem,
            privateKeyPem: issuer.privateKeyPem, keyAlg: issuer.keyAlg }
        : null,
      issuerPrivateKey: issuer ? null : privatePem,
      signatureAlg: val('pki_sig_alg'),
      serial: serial,
      notBefore: validity.notBefore,
      notAfter: validity.notAfter,
      extensions: collectExtensions()
    });

    var stored = store.put({
      id: store.newId(p.ca ? 'ca' : 'leaf'),
      kind: p.ca ? store.KIND_CA : store.KIND_LEAF,
      profile: profileId,
      profileLabel: p.label,
      subject: result.subject,
      issuerId: issuer ? issuer.id : null,
      issuerSubject: result.issuer,
      serialHex: result.serialHex,
      keyAlg: keyDesc.id,
      keyAlgLabel: keyDesc.label,
      signatureAlg: result.signatureAlg,
      privateKeyPem: privatePem,
      publicKeyPem: publicPem,
      certificatePem: result.pem,
      notBefore: result.notBefore,
      notAfter: result.notAfter,
      created: new Date().toISOString()
    });

    newSerial();
    renderStore();
    refreshIssuerOptions();
    refreshTlsSelectors();
    await showDetails(stored.id);
    var note = store.canSign(stored) ? ''
      : ' Its private key was not saved (key saving is off), so it cannot ' +
        'sign or be presented as a client certificate.';
    status('Issued "' + result.subject + '", serial ' +
        result.serialHex.slice(0, 16) + '…, signed with ' +
        x509.SIG_ALGS[result.signatureAlg].label + '.' + note);
    history.update(entryId, history.SUCCESS, result.subject);
  } catch (e) {
    log.error('issue: ' + e.message);
    status('Could not issue the certificate: ' + e.message);
    history.update(entryId, history.FAILURE, e.message);
  }
  renderHistory();
  log.debug("Leaving issue().");
  return false;
}

// ---------------------------------------------------------------------------
// The store table
// ---------------------------------------------------------------------------
function selectedObject() {
  log.debug("Entering selectedObject().");
  var id = val('pki_selected');
  var entry = id ? store.get(id) : null;
  log.debug("Leaving selectedObject().");
  return entry;
}

function renderStore() {
  log.debug("Entering renderStore().");
  var box = el('pki_store_table');
  if (!box) {
    log.debug("Leaving renderStore(). No table.");
    return;
  }
  while (box.firstChild) box.removeChild(box.firstChild);
  var entries = store.list();
  if (!entries.length) {
    var empty = document.createElement('p');
    empty.className = 'saml-note';
    empty.textContent = 'Nothing issued yet. Choose the Root CA profile ' +
        'above and press "Generate Key Pair & Issue Certificate".';
    box.appendChild(empty);
    setText('pki_store_count', '0 objects');
    log.debug("Leaving renderStore(). Empty.");
    return;
  }
  // Built with DOM calls rather than innerHTML throughout: every value in this
  // table — subjects, labels, algorithms — came from a text field on this page,
  // and a subject is exactly the sort of thing somebody pastes an angle bracket
  // into.
  var table = document.createElement('table');
  table.className = 'saml-table pki-store';
  var head = document.createElement('thead');
  var headRow = document.createElement('tr');
  ['', 'Subject', 'Kind', 'Key', 'Signed with', 'Issued by', 'Expires',
   'Private key'].forEach(function (label) {
    var th = document.createElement('th');
    th.textContent = label;
    headRow.appendChild(th);
  });
  head.appendChild(headRow);
  table.appendChild(head);
  var body = document.createElement('tbody');
  var selectedId = val('pki_selected');
  entries.forEach(function (entry) {
    var row = document.createElement('tr');
    if (entry.id === selectedId) row.className = 'pki-row-selected';
    var pick = document.createElement('td');
    var radio = document.createElement('input');
    radio.type = 'radio';
    radio.name = 'pki_store_pick';
    radio.value = entry.id;
    radio.checked = entry.id === selectedId;
    radio.setAttribute('data-object-id', entry.id);
    radio.onclick = function () {
      setVal('pki_selected', entry.id);
      saveState();
      renderStore();
      showDetails(entry.id);
    };
    pick.appendChild(radio);
    row.appendChild(pick);
    [entry.subject,
     entry.profileLabel || entry.profile,
     entry.keyAlgLabel || entry.keyAlg,
     (x509.SIG_ALGS[entry.signatureAlg] || {}).label || entry.signatureAlg,
     entry.issuerSubject || '(self-signed)',
     String(entry.notAfter || '').slice(0, 10),
     store.canSign(entry) ? 'held' : 'not saved'].forEach(function (text) {
      var td = document.createElement('td');
      td.textContent = text == null ? '' : String(text);
      row.appendChild(td);
    });
    body.appendChild(row);
  });
  table.appendChild(body);
  box.appendChild(table);
  setText('pki_store_count', entries.length + ' object' +
      (entries.length === 1 ? '' : 's'));
  var stranded = store.orphans();
  setText('pki_store_orphans', stranded.length
    ? stranded.length + ' object(s) name an issuer that is no longer here, ' +
      'so their chain cannot be assembled. Their certificates are still ' +
      'valid documents; re-issue them, or import the missing CA.'
    : '');
  log.debug("Leaving renderStore(). " + entries.length + " row(s).");
}

async function showDetails(id) {
  log.debug("Entering showDetails(). id=" + id);
  var box = el('pki_details');
  if (!box) {
    log.debug("Leaving showDetails(). No pane.");
    return false;
  }
  var entry = id ? store.get(id) : selectedObject();
  while (box.firstChild) box.removeChild(box.firstChild);
  if (!entry) {
    setText('pki_details_status', 'Select an object in the store above.');
    log.debug("Leaving showDetails(). Nothing selected.");
    return false;
  }
  try {
    var described = await x509.describeCertificate(entry.certificatePem);
    box.appendChild(detailTable(described));
    var chain = store.chainPems(entry.id);
    var verdicts = await x509.verifyChain(chain);
    box.appendChild(chainTable(verdicts));
    var pem = document.createElement('textarea');
    pem.readOnly = true;
    pem.rows = 8;
    pem.id = 'pki_details_pem';
    pem.value = chain.join('');
    box.appendChild(pem);
    setText('pki_details_status', 'Showing "' + described.subject + '".');
  } catch (e) {
    log.error('showDetails: ' + e.message);
    setText('pki_details_status', 'Could not read the certificate: ' +
        e.message);
  }
  log.debug("Leaving showDetails().");
  return false;
}

function detailRow(key, value) {
  log.debug("Entering detailRow().");
  var row = document.createElement('tr');
  var k = document.createElement('td');
  k.className = 'saml-key';
  k.textContent = key;
  var v = document.createElement('td');
  v.textContent = value == null ? '' : String(value);
  row.appendChild(k);
  row.appendChild(v);
  log.debug("Leaving detailRow().");
  return row;
}

function detailTable(described) {
  log.debug("Entering detailTable().");
  var table = document.createElement('table');
  table.className = 'saml-table';
  table.id = 'pki_details_table';
  var body = document.createElement('tbody');
  body.appendChild(detailRow('Subject', described.subject));
  body.appendChild(detailRow('Issuer', described.issuer));
  body.appendChild(detailRow('Version', 'v' + described.version));
  body.appendChild(detailRow('Serial Number', described.serialHex));
  body.appendChild(detailRow('Not Before', described.notBefore));
  body.appendChild(detailRow('Not After', described.notAfter));
  body.appendChild(detailRow('Signature Algorithm',
      described.signatureAlgorithm + ' (' + described.signatureAlgorithmOid +
      ')'));
  body.appendChild(detailRow('Public Key', described.publicKey));
  body.appendChild(detailRow('Self-signed', described.selfSigned ? 'yes'
      : 'no'));
  body.appendChild(detailRow('SHA-1 Fingerprint',
      described.fingerprints.sha1));
  body.appendChild(detailRow('SHA-256 Fingerprint',
      described.fingerprints.sha256));
  described.extensions.forEach(function (ext) {
    body.appendChild(detailRow('Extension: ' + ext.name +
        (ext.critical ? ' (critical)' : ''), x509.extensionValueText(ext)));
  });
  table.appendChild(body);
  log.debug("Leaving detailTable(). " + described.extensions.length +
      " extension(s).");
  return table;
}

function chainTable(verdicts) {
  log.debug("Entering chainTable().");
  var table = document.createElement('table');
  table.className = 'saml-table';
  table.id = 'pki_chain_table';
  var head = document.createElement('thead');
  var headRow = document.createElement('tr');
  ['Certificate', 'Signed by', 'Names match', 'Signature', 'Validity']
    .forEach(function (label) {
      var th = document.createElement('th');
      th.textContent = label;
      headRow.appendChild(th);
    });
  head.appendChild(headRow);
  table.appendChild(head);
  var body = document.createElement('tbody');
  verdicts.forEach(function (link) {
    var row = document.createElement('tr');
    [link.subject,
     link.selfSigned ? link.signedBy + ' (self-signed)' : link.signedBy,
     link.namesMatch ? 'yes' : 'NO',
     link.signatureValid ? 'valid' : (link.error || 'INVALID'),
     link.expired ? 'EXPIRED' : (link.notYetValid ? 'NOT YET VALID' : 'in date')
    ].forEach(function (text, index) {
      var td = document.createElement('td');
      td.textContent = String(text);
      if (index === 3) {
        td.className = link.signatureValid ? 'saml-ok' : 'saml-bad';
      }
      if (index === 2 && !link.namesMatch) td.className = 'saml-bad';
      if (index === 4 && (link.expired || link.notYetValid)) {
        td.className = 'saml-bad';
      }
      row.appendChild(td);
    });
    body.appendChild(row);
  });
  table.appendChild(body);
  log.debug("Leaving chainTable(). " + verdicts.length + " link(s).");
  return table;
}

function removeObject() {
  log.debug("Entering removeObject().");
  var entry = selectedObject();
  if (!entry) {
    status('Select an object first.');
    log.debug("Leaving removeObject(). Nothing selected.");
    return false;
  }
  store.remove(entry.id);
  setVal('pki_selected', '');
  saveState();
  renderStore();
  refreshIssuerOptions();
  refreshTlsSelectors();
  showDetails(null);
  status('Removed "' + entry.subject + '". Anything it issued is still here ' +
      'and now names an issuer that is not.');
  log.debug("Leaving removeObject().");
  return false;
}

function clearStore() {
  log.debug("Entering clearStore().");
  store.clear();
  setVal('pki_selected', '');
  saveState();
  renderStore();
  refreshIssuerOptions();
  refreshTlsSelectors();
  showDetails(null);
  status('Cleared every key and certificate this page was holding.');
  log.debug("Leaving clearStore().");
  return false;
}

// Load the selected object's key pair back into the key pane, so the next
// certificate can be issued for the same key — a re-issue with a longer
// validity, or the same key under a different profile.
function useStoredKey() {
  log.debug("Entering useStoredKey().");
  var entry = selectedObject();
  if (!entry) {
    status('Select an object first.');
    log.debug("Leaving useStoredKey(). Nothing selected.");
    return false;
  }
  if (!store.canSign(entry)) {
    status('"' + entry.subject + '" has no private key here, so there is ' +
        'nothing to load. Its certificate and public key are still usable.');
    log.debug("Leaving useStoredKey(). No private key.");
    return false;
  }
  setVal('pki_private_key', entry.privateKeyPem);
  setVal('pki_public_key', entry.publicKeyPem);
  setVal('pki_key_alg', entry.keyAlg);
  setChecked('pki_key_jwk', false);
  // Tick the reuse box with it: the one button above generates a fresh pair
  // by default, which would throw this one away between loading it and
  // issuing for it.
  setChecked('pki_reuse_key', true);
  saveState();
  refreshSignatureOptions();
  status('Loaded the key pair of "' + entry.subject + '" into the key pane, ' +
      'and ticked "reuse the key pair below" so the next certificate is ' +
      'issued for it rather than for a new one.');
  log.debug("Leaving useStoredKey().");
  return false;
}

// ---------------------------------------------------------------------------
// The TLS / mutual-TLS test. Always through the api — see the header.
// ---------------------------------------------------------------------------
function apiBase() {
  log.debug("Entering apiBase().");
  log.debug("Leaving apiBase().");
  return appconfig.apiUrl || '';
}

function backendAvailable() {
  log.debug("Entering backendAvailable().");
  log.debug("Leaving backendAvailable().");
  return appconfig.backendAvailable !== false;
}

// The TLS pane on a build that declares it has no api (the static sites: see
// client/static_site.js). This workflow is NOT one of the three that are
// dropped from those sites altogether — the certificate authority, every
// X.509v3 extension and the whole keystore matrix are Web Crypto and pkijs in
// the browser and work there exactly as they do here. One pane cannot, so one
// pane is switched off rather than a card being greyed on the landing page.
//
// Both halves of "switched off" are needed and they do different jobs. The
// class is what says so at a glance, and `disabled` is what makes it true: a
// pane that only LOOKS dead still submits when somebody presses Return in a
// text field, and runTlsTest()'s own refusal is then the first thing that says
// anything — one status line at the bottom of a pane full of live-looking
// controls, which is the failure this exists to replace.
//
// The legend is deliberately left alone: the pane still collapses and expands,
// and a heading nobody can read is a pane nobody can find.
function disableTlsPane() {
  log.debug("Entering disableTlsPane().");
  var pane = el('pane_tls');
  if (pane && pane.classList) pane.classList.add(DISABLED_PANE_CLASS);
  var body = el('pane_tls_body');
  if (body) {
    var controls = body.querySelectorAll('input, select, textarea, button');
    for (var i = 0; i < controls.length; i++) {
      controls[i].disabled = true;
    }
  }
  show('pki_tls_unavailable', true);
  log.debug("Leaving disableTlsPane().");
}

function refreshTlsSelectors() {
  log.debug("Entering refreshTlsSelectors().");
  var clientSelect = el('pki_tls_client_cert');
  if (clientSelect) {
    var previousClient = clientSelect.value;
    while (clientSelect.firstChild) {
      clientSelect.removeChild(clientSelect.firstChild);
    }
    var none = document.createElement('option');
    none.value = '';
    none.textContent = '(present no client certificate)';
    clientSelect.appendChild(none);
    store.list().forEach(function (entry) {
      // Only something with a private key can be PRESENTED: the certificate is
      // what is sent, the key is what proves it is yours.
      if (!store.canSign(entry)) return;
      var option = document.createElement('option');
      option.value = entry.id;
      option.textContent = store.labelFor(entry);
      clientSelect.appendChild(option);
    });
    if (previousClient) clientSelect.value = previousClient;
  }
  var trustSelect = el('pki_tls_truststore');
  if (trustSelect) {
    var previousTrust = [];
    for (var i = 0; i < trustSelect.options.length; i++) {
      if (trustSelect.options[i].selected) {
        previousTrust.push(trustSelect.options[i].value);
      }
    }
    while (trustSelect.firstChild) {
      trustSelect.removeChild(trustSelect.firstChild);
    }
    // Any certificate can be a trust anchor — usually a CA, but pinning a leaf
    // is a legitimate thing to test, so the list is not filtered to CAs.
    store.list().forEach(function (entry) {
      var option = document.createElement('option');
      option.value = entry.id;
      option.textContent = store.labelFor(entry);
      option.selected = previousTrust.indexOf(entry.id) >= 0;
      trustSelect.appendChild(option);
    });
  }
  log.debug("Leaving refreshTlsSelectors().");
}

function selectAllTrust() {
  log.debug("Entering selectAllTrust().");
  var trustSelect = el('pki_tls_truststore');
  if (trustSelect) {
    for (var i = 0; i < trustSelect.options.length; i++) {
      trustSelect.options[i].selected = true;
    }
  }
  log.debug("Leaving selectAllTrust().");
  return false;
}

function collectTruststore() {
  log.debug("Entering collectTruststore().");
  var out = [];
  var trustSelect = el('pki_tls_truststore');
  if (trustSelect) {
    for (var i = 0; i < trustSelect.options.length; i++) {
      if (!trustSelect.options[i].selected) continue;
      var entry = store.get(trustSelect.options[i].value);
      if (entry && entry.certificatePem) out.push(entry.certificatePem);
    }
  }
  var pasted = String(val('pki_tls_trust_pem') || '').trim();
  if (pasted) out.push(pasted);
  log.debug("Leaving collectTruststore(). " + out.length + " anchor(s).");
  return out;
}

async function runTlsTest() {
  log.debug("Entering runTlsTest().");
  if (!backendAvailable()) {
    setText('pki_tls_status', 'This deployment has no api, and this test can ' +
        'only be made by one — a browser cannot choose a client certificate, ' +
        'choose a truststore, or read the handshake.');
    log.debug("Leaving runTlsTest(). No backend.");
    return false;
  }
  var host = trimmed('pki_tls_host');
  var port = trimmed('pki_tls_port');
  if (!host || !port) {
    setText('pki_tls_status', 'A host and a port are required.');
    log.debug("Leaving runTlsTest(). No host or port.");
    return false;
  }
  var clientEntry = val('pki_tls_client_cert')
    ? store.get(val('pki_tls_client_cert')) : null;
  var entryId = history.record({ operation: history.OP_TLS,
      subject: host + ':' + port,
      algorithm: val('pki_tls_min_version') || 'any version',
      issuer: clientEntry ? clientEntry.subject : '(no client certificate)' });
  setText('pki_tls_status', 'Connecting to ' + host + ':' + port + '…');
  try {
    var body = {
      host: host,
      port: parseInt(port, 10),
      servername: trimmed('pki_tls_servername') || undefined,
      minVersion: val('pki_tls_min_version') || undefined,
      maxVersion: val('pki_tls_max_version') || undefined,
      ciphers: trimmed('pki_tls_ciphers') || undefined,
      alpnProtocols: lines('pki_tls_alpn'),
      trustCertificates: collectTruststore(),
      includeSystemRoots: checked('pki_tls_system_roots'),
      mutualAuthProbe: checked('pki_tls_probe_mutual')
    };
    if (checked('pki_tls_http_probe')) {
      // One GET over the connection just made, so the far end's account of it
      // comes back beside this one's. It is the same connection deliberately: a
      // second one is a different connection and says nothing about this
      // certificate on this handshake. The api refuses anything but a path.
      body.httpRequest = { path: trimmed('pki_tls_http_path') || '/' };
    }
    if (clientEntry) {
      if (!store.canSign(clientEntry)) {
        throw new Error('"' + clientEntry.subject + '" has no private key ' +
            'here, so it cannot be presented.');
      }
      // The CHAIN, leaf first — not just the leaf. A server verifying a client
      // certificate has to build a path from what was sent to an anchor it
      // holds, so a leaf issued by an intermediate and presented alone is
      // unverifiable to a server holding only the root. Node's server answers
      // that by resetting the connection with no alert, which reads as "the
      // server refused my certificate" when what it could not do was find the
      // issuer. The root itself is dropped: a server that does not already
      // hold it will not trust it because we sent it.
      var chain = store.chainPems(clientEntry.id);
      body.clientCertificatePem = (chain.length > 1
        ? chain.slice(0, chain.length - 1)
        : chain).join('');
      body.clientKeyPem = clientEntry.privateKeyPem;
    }
    var response = await fetch(apiBase() + '/tls/connect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    var json = await response.json();
    if (!response.ok) {
      throw new Error((json && json.error) || ('HTTP ' + response.status));
    }
    renderTlsReport(json);
    // `usable`, not `connected`: the api decides whether the connection
    // actually worked, because under TLS 1.3 a handshake completes before the
    // server has said anything about the client certificate and the refusal
    // arrives afterwards — as an alert or as a bare hang-up. Re-deriving that
    // here is how this line came to report success for a server that had
    // already hung up. An older api sends no `usable`, so fall back.
    var connected = json.result && (json.result.usable !== undefined
      ? json.result.usable
      : (json.result.connected && !json.result.postHandshakeError));
    setText('pki_tls_status', connected
      ? 'Handshake completed with ' + host + ':' + port + '.'
      : 'The handshake did not complete — the report below says why.');
    history.update(entryId, connected ? history.SUCCESS : history.FAILURE,
        connected
          ? (json.result.protocol + ' / ' + json.result.cipher.name)
          : tlsFailureDetail(json.result));
  } catch (e) {
    log.error('runTlsTest: ' + e.message);
    setText('pki_tls_status', 'The test could not be run: ' + e.message);
    history.update(entryId, history.FAILURE, e.message);
  }
  renderHistory();
  log.debug("Leaving runTlsTest().");
  return false;
}

function tlsFailureDetail(result) {
  log.debug("Entering tlsFailureDetail().");
  var detail = 'no handshake';
  if (result && result.postHandshakeError) {
    detail = result.postHandshakeError.code ||
        result.postHandshakeError.message;
  } else if (result && result.error) {
    detail = result.error.code || result.error.message;
  }
  log.debug("Leaving tlsFailureDetail().");
  return detail;
}

function renderTlsReport(json) {
  log.debug("Entering renderTlsReport().");
  var box = el('pki_tls_report');
  if (!box) {
    log.debug("Leaving renderTlsReport(). No pane.");
    return;
  }
  while (box.firstChild) box.removeChild(box.firstChild);
  var result = json.result || {};
  var table = document.createElement('table');
  table.className = 'saml-table';
  table.id = 'pki_tls_table';
  var body = document.createElement('tbody');
  body.appendChild(detailRow('Connected', result.connected ? 'yes' : 'no'));
  if (result.usable !== undefined && result.connected && !result.usable) {
    body.appendChild(detailRow('Usable', 'no — the handshake completed and ' +
        'the connection did not survive it. Under TLS 1.3 that is how a ' +
        'server refuses a client certificate.'));
  }
  body.appendChild(detailRow('Address', (result.address || '') + ':' +
      (result.port || '')));
  body.appendChild(detailRow('SNI / verified name', result.servername ||
      '(none sent)'));
  body.appendChild(detailRow('Protocol', result.protocol || '(none)'));
  body.appendChild(detailRow('Cipher', result.cipher
    ? (result.cipher.standardName || result.cipher.name || '(none)')
    : '(none)'));
  body.appendChild(detailRow('ALPN', result.alpnProtocol || '(none)'));
  body.appendChild(detailRow('Certificate verified',
      result.authorized ? 'yes' : 'no'));
  if (result.authorizationError) {
    body.appendChild(detailRow('Verification error',
        result.authorizationError));
  }
  if (result.trustStore) {
    body.appendChild(detailRow('Truststore',
        result.trustStore.pastedAnchors + ' anchor(s) supplied; platform ' +
        'roots ' + (result.trustStore.systemRoots ? 'included' : 'excluded')));
  }
  body.appendChild(detailRow('Client certificate offered',
      result.clientCertificateOffered ? 'yes' : 'no'));
  if (result.error) {
    body.appendChild(detailRow('Handshake error',
        (result.error.code || '') + ' ' + result.error.message));
  }
  // The TLS 1.3 case, and the one most likely to be misread: the handshake
  // completed and the server then rejected the client certificate.
  if (result.postHandshakeError) {
    body.appendChild(detailRow('After the handshake',
        (result.postHandshakeError.code || '') + ' ' +
        result.postHandshakeError.message +
        ' — the handshake completed and the server then sent this alert, ' +
        'which under TLS 1.3 is how a client certificate is refused.'));
  }
  body.appendChild(detailRow('Elapsed', (result.elapsedMs || 0) + ' ms'));
  table.appendChild(body);
  box.appendChild(table);

  if (json.mutualAuth) {
    var verdict = document.createElement('p');
    verdict.className = 'saml-note';
    verdict.id = 'pki_tls_mutual_verdict';
    verdict.textContent = 'Client authentication: ' + json.mutualAuth.verdict +
        ' — ' + json.mutualAuth.detail;
    box.appendChild(verdict);
  }

  if ((result.peerChain || []).length) {
    var chain = document.createElement('table');
    chain.className = 'saml-table';
    chain.id = 'pki_tls_chain_table';
    var chainHead = document.createElement('thead');
    var chainRow = document.createElement('tr');
    ['Depth', 'Subject', 'Issuer', 'Not after', 'SHA-256']
      .forEach(function (label) {
        var th = document.createElement('th');
        th.textContent = label;
        chainRow.appendChild(th);
      });
    chainHead.appendChild(chainRow);
    chain.appendChild(chainHead);
    var chainBody = document.createElement('tbody');
    result.peerChain.forEach(function (cert) {
      var row = document.createElement('tr');
      [String(cert.depth),
       dnObjectToString(cert.subject),
       dnObjectToString(cert.issuer),
       cert.validTo || '',
       cert.fingerprint256 || ''].forEach(function (text) {
        var td = document.createElement('td');
        td.textContent = text;
        row.appendChild(td);
      });
      chainBody.appendChild(row);
    });
    chain.appendChild(chainBody);
    box.appendChild(chain);
  }

  if (result.httpResponse) renderServerView(box, result);
  log.debug("Leaving renderTlsReport().");
}

// The other side of the same connection: what the SERVER says it saw.
//
// Everything above this is what the api observed from its end. This is the far
// end's own account, fetched over that very connection, and it is the only
// place three things can appear at all — which chain the server built out of
// what was sent, which anchor it verified against, and whether it considers the
// certificate accepted. Under TLS 1.3 the client has not been told any of that
// by the time its handshake completes.
//
// A body that parses as JSON and carries the sections the mock STS publishes is
// rendered as a table; anything else is shown as text. That order matters: this
// pane must not be useless against a server that is not the mock, so an
// unrecognised body is displayed rather than discarded.
function renderServerView(box, result) {
  log.debug("Entering renderServerView().");
  var http = result.httpResponse;
  var heading = document.createElement('p');
  heading.className = 'saml-note';
  heading.id = 'pki_tls_server_view_note';
  heading.textContent = 'What the server saw — its own account of this ' +
      'connection, asked for over the connection itself (' +
      (result.httpRequest ? result.httpRequest.method + ' ' +
        result.httpRequest.path : 'GET') + ').';
  box.appendChild(heading);

  var table = document.createElement('table');
  table.className = 'saml-table';
  table.id = 'pki_tls_server_view';
  var body = document.createElement('tbody');
  body.appendChild(detailRow('Answered', http.statusLine ||
      (http.parsed ? http.statusCode : '(not an HTTP response)')));
  if (http.headers && http.headers['content-type']) {
    body.appendChild(detailRow('Content type', http.headers['content-type']));
  }
  body.appendChild(detailRow('Read', http.bytes + ' bytes; the read ended on ' +
      humanEndedBy(http.endedBy) +
      (http.truncated ? ' — and was TRUNCATED at the api’s size cap' : '') +
      (http.bodyComplete === false
        ? ' — the body did not reach its terminating chunk' : '')));

  var seen = parseJsonBody(http.body);
  if (seen && (seen.tls || seen.clientCertificate)) {
    if (seen.verdict) body.appendChild(detailRow('The server says',
        seen.verdict));
    if (seen.tls) {
      body.appendChild(detailRow('It negotiated',
          (seen.tls.protocol || '(unknown)') + ' / ' +
          ((seen.tls.cipher || {}).standardName ||
           (seen.tls.cipher || {}).name || '(unknown cipher)')));
      body.appendChild(detailRow('It was reached as',
          'SNI ' + (seen.tls.sniServername || '(none sent)') +
          (seen.tls.listenerPort ? ', on port ' + seen.tls.listenerPort : '') +
          (seen.tls.listener ? ' (' + seen.tls.listener +
            ' client certificate)' : '')));
    }
    if (seen.https) {
      body.appendChild(detailRow('It received',
          seen.https.method + ' ' + seen.https.url + ' from ' +
          (seen.https.remoteAddress || '(unknown)') +
          ', Host: ' + (seen.https.host || '(none)')));
    }
    var cert = seen.clientCertificate || {};
    body.appendChild(detailRow('Client certificate, as the server read it',
        !cert.presented ? 'none was presented'
          : (cert.subject + ' — ' + (cert.authorized
              ? 'VERIFIED against ' +
                ((seen.truststore || {}).anchors || 0) + ' anchor(s) it holds'
              : 'NOT verified: ' +
                (cert.authorizationError || 'no reason given')))));
    if (cert.presented) {
      // NOT a count of what was sent. It is the path the server assembled, and
      // when verification succeeded its last entry is an anchor that server
      // holds — which this end did not send, and for a root must not.
      body.appendChild(detailRow('The path it built',
          cert.chainLength + ' certificate(s), leaf first. A leaf presented ' +
          'without its intermediates is the commonest mutual-TLS mistake ' +
          'there is and is invisible from here; it shows there as a chain of ' +
          'one that did not verify.'));
    }
    if (seen.authentication && seen.authentication.authenticated === false) {
      body.appendChild(detailRow('And what it means to that server',
          seen.authentication.note || 'nothing — a verified certificate is ' +
          'not a login there.'));
    }
    table.appendChild(body);
    box.appendChild(table);
    if ((cert.chain || []).length) {
      box.appendChild(serverChainTable(cert.chain));
    }
    log.debug("Leaving renderServerView(). Rendered a structured report.");
    return;
  }

  table.appendChild(body);
  box.appendChild(table);
  // Not the mock, or not JSON. Show what came back rather than nothing: the
  // point of this pane is the far end's own words.
  var raw = document.createElement('pre');
  raw.id = 'pki_tls_server_view_body';
  raw.className = 'pki-server-body';
  raw.textContent = http.body || '(the server sent no body)';
  box.appendChild(raw);
  log.debug("Leaving renderServerView(). Rendered the body as text.");
}

function serverChainTable(chain) {
  log.debug("Entering serverChainTable().");
  var table = document.createElement('table');
  table.className = 'saml-table';
  table.id = 'pki_tls_server_chain_table';
  var head = document.createElement('thead');
  var headRow = document.createElement('tr');
  ['Depth', 'Subject (as the server read it)', 'Issuer', 'Not after']
    .forEach(function (label) {
      var th = document.createElement('th');
      th.textContent = label;
      headRow.appendChild(th);
    });
  head.appendChild(headRow);
  table.appendChild(head);
  var body = document.createElement('tbody');
  chain.forEach(function (cert) {
    var row = document.createElement('tr');
    [String(cert.depth), cert.subject || '', cert.issuer || '',
     cert.validTo || ''].forEach(function (text) {
      var td = document.createElement('td');
      td.textContent = text;
      row.appendChild(td);
    });
    body.appendChild(row);
  });
  table.appendChild(body);
  log.debug("Leaving serverChainTable().");
  return table;
}

function humanEndedBy(reason) {
  log.debug("Entering humanEndedBy(). reason=" + reason);
  var text;
  if (reason === 'close' || reason === 'end') {
    text = 'the server closing the connection, which is what ' +
        '"Connection: close" asked it to do';
  } else if (reason === 'silence') {
    text = 'the server going quiet without closing';
  } else if (reason === 'cap') {
    text = 'the api’s size cap';
  } else if (reason === 'write-failed') {
    text = 'the connection being gone before the request could be written — ' +
        'which is a refusal arriving in its third form';
  } else {
    text = String(reason || 'an unrecorded reason');
  }
  log.debug("Leaving humanEndedBy().");
  return text;
}

// A body that is not JSON is not an error here: the pane shows it as text.
function parseJsonBody(text) {
  log.debug("Entering parseJsonBody().");
  if (!text || !String(text).trim()) {
    log.debug("Leaving parseJsonBody(). Empty.");
    return null;
  }
  try {
    var parsed = JSON.parse(text);
    log.debug("Leaving parseJsonBody(). Parsed.");
    return parsed;
  } catch (e) {
    log.debug("Leaving parseJsonBody(). Not JSON: " + e.message);
    return null;
  }
}

// node hands a certificate's subject back as an object of arrays; render it as
// the one-line DN everybody recognises.
function dnObjectToString(dn) {
  log.debug("Entering dnObjectToString().");
  if (!dn || typeof dn !== 'object') {
    log.debug("Leaving dnObjectToString(). Not a DN.");
    return String(dn || '');
  }
  var out = Object.keys(dn).map(function (key) {
    var value = dn[key];
    return key + '=' + (Object.prototype.toString.call(value) ===
        '[object Array]' ? value.join('+') : value);
  }).join(', ');
  log.debug("Leaving dnObjectToString().");
  return out;
}

async function loadTlsLimits() {
  log.debug("Entering loadTlsLimits().");
  if (!backendAvailable()) {
    setText('pki_tls_limits', 'No api on this deployment, so no TLS test.');
    log.debug("Leaving loadTlsLimits(). No backend.");
    return;
  }
  try {
    var response = await fetch(apiBase() + '/tls/limits');
    var limits = await response.json();
    var ports = limits.allowedPorts === 'any' ? 'any port'
      : (limits.allowedPorts || []).join(', ');
    setText('pki_tls_limits', 'The api will connect to ' + ports +
        '; connect budget ' + limits.connectionTimeoutMs + ' ms, handshake ' +
        'budget ' + limits.callTimeoutMs + ' ms; ' + limits.systemRootCount +
        ' platform root certificates are available; address policy ' +
        (limits.addressPolicyEnabled ? 'enabled' : 'disabled') + '.');
    // An api that predates "ask the server what it saw" would accept the call
    // and ignore the request, which reads as a server that answered nothing —
    // exactly the wrong conclusion. So the control is turned off and says why,
    // rather than being left to produce a silent, wrong result.
    var ask = el('pki_tls_http_probe');
    if (ask && limits.httpRequestAvailable !== true) {
      ask.checked = false;
      ask.disabled = true;
      setText('pki_tls_http_note', 'This api is older than this page and ' +
          'cannot make a request over the connection, so that option is off. ' +
          'It would otherwise look like a server that said nothing.');
    }
  } catch (e) {
    log.error('loadTlsLimits: ' + e.message);
    setText('pki_tls_limits', 'Could not read the api’s TLS limits: ' +
        e.message + '. The api may be older than this page, or not running.');
  }
  log.debug("Leaving loadTlsLimits().");
}

// ---------------------------------------------------------------------------
// History and panes
// ---------------------------------------------------------------------------
function renderHistory() {
  log.debug("Entering renderHistory().");
  history.render(el('pki_operation_history'));
  log.debug("Leaving renderHistory().");
}

function clearOperationHistory() {
  log.debug("Entering clearOperationHistory().");
  history.clear();
  renderHistory();
  log.debug("Leaving clearOperationHistory().");
  return false;
}

function togglePane(id) {
  log.debug("Entering togglePane(). id=" + id);
  var pane = el(id);
  if (pane) pane.style.display = (pane.style.display === 'none') ? '' : 'none';
  log.debug("Leaving togglePane().");
  return false;
}

function setAllPanes(collapsed) {
  log.debug("Entering setAllPanes().");
  var bodies = document.querySelectorAll('.saml-pane-body');
  for (var i = 0; i < bodies.length; i++) {
    bodies[i].style.display = collapsed ? 'none' : '';
  }
  log.debug("Leaving setAllPanes().");
  return false;
}

// Fill the two dropdowns that are driven by the modules rather than by markup,
// so adding an algorithm or a profile is one table edit rather than two.
function populateStaticOptions() {
  log.debug("Entering populateStaticOptions().");
  var keySelect = el('pki_key_alg');
  if (keySelect && !keySelect.options.length) {
    keys.keyAlgIds().forEach(function (id) {
      var option = document.createElement('option');
      option.value = id;
      option.textContent = keys.KEY_ALGS[id].label;
      keySelect.appendChild(option);
    });
  }
  var profileSelect = el('pki_profile');
  if (profileSelect && !profileSelect.options.length) {
    x509.profileIds().forEach(function (id) {
      var option = document.createElement('option');
      option.value = id;
      option.textContent = x509.PROFILES[id].label;
      profileSelect.appendChild(option);
    });
  }
  log.debug("Leaving populateStaticOptions().");
}

function onAnyChange() {
  log.debug("Entering onAnyChange().");
  saveState();
  log.debug("Leaving onAnyChange().");
  return false;
}

window.onload = function () {
  log.debug("Entering onload().");
  populateStaticOptions();
  restoreState();
  // One delegated listener rather than an onchange attribute on each of the
  // hundred-odd fields this page has. Every one of them is `.stored`, so the
  // handler is the same for all of them, and a field added to the markup
  // without an attribute would otherwise be the one that silently does not
  // survive a reload.
  document.addEventListener('change', function () { saveState(); });
  // The store's own preference and this page's checkbox are the same setting,
  // and the checkbox is what restoreState() has just set — so push it into the
  // store rather than reading it back, or a cleared box would be forgotten by
  // the module that enforces it.
  store.setSaveKeys(keyMaterialMayBeStored());
  renderKeyStorageNote();
  if (!trimmed('pki_serial')) newSerial();
  // Before onProfileChange(), which fills the CN: these five do not follow the
  // profile and the DN reads as one block whichever order they are written in.
  applyDefaultSubjectDN();
  if (!val('pki_profile')) setVal('pki_profile', 'root-ca');
  if (!val('pki_key_alg')) setVal('pki_key_alg', 'rsa-2048');
  onProfileChange();
  refreshIssuerOptions();
  refreshTlsSelectors();
  renderStore();
  renderHistory();
  showDetails(null);
  show('pki_backend_notice', !backendAvailable());
  // After refreshTlsSelectors(), which fills the two selects this then
  // disables — a select disabled first is a select the fill would leave
  // looking usable.
  if (!backendAvailable()) {
    disableTlsPane();
  }
  loadTlsLimits();
  log.debug("Leaving onload().");
};

module.exports = {
  // the Key Pair block of the configuration pane
  generateAndIssue: generateAndIssue,
  generateKeys: generateKeys,
  downloadKeys: downloadKeys,
  toggleKeyFormat: toggleKeyFormat,
  onKeyAlgChange: onKeyAlgChange,
  onSaveKeysChange: onSaveKeysChange,
  copyField: copyField,
  viewCertificate: viewCertificate,
  // issuing
  onProfileChange: onProfileChange,
  applyDefaultSubjectCN: applyDefaultSubjectCN,
  onSubjectCnChange: onSubjectCnChange,
  onIssuerChange: onIssuerChange,
  issue: issue,
  // the store
  showDetails: showDetails,
  removeObject: removeObject,
  clearStore: clearStore,
  useStoredKey: useStoredKey,
  // TLS
  runTlsTest: runTlsTest,
  selectAllTrust: selectAllTrust,
  // panes and history
  togglePane: togglePane,
  setAllPanes: setAllPanes,
  clearOperationHistory: clearOperationHistory,
  onAnyChange: onAnyChange,
  // exported for tests/pki_page.js, which checks the list-field syntax
  // directly rather than only through the form
  parseAltNames: parseAltNames,
  parseAiaEntries: parseAiaEntries,
  parsePolicies: parsePolicies,
  parsePolicyMappings: parsePolicyMappings,
  parseNameConstraints: parseNameConstraints,
  parseCustomExtensions: parseCustomExtensions,
  collectExtensions: collectExtensions,
  collectSubject: collectSubject
};
