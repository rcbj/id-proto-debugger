// File: kerberos.js
//
// ---------------------------------------------------------------------------
// The Kerberos AS exchange (kerberos.html): get a TGT from a KDC.
//
// Everything protocol-shaped happens HERE, in the browser. The api's
// `POST /krb5/kdc` is a guarded byte relay and nothing more — it frames, checks
// its address and port policy, times the call and hands the reply back. The
// password never leaves this page, no key is derived anywhere but here, and every
// pane can honestly say "these are the bytes that went on the wire" because this
// file produced them. See docs/kerberos-plan.md for why that shape was chosen over
// protocol-aware endpoints.
//
// **This page cannot work on the static deployments**, and says so on arrival
// rather than by failing. Kerberos needs a TCP socket to port 88; a browser has
// none; `appconfig.backendAvailable === false` is how a build declares it has no
// api behind it. The Kerberos DECODER page is the part of this workflow that does
// ship statically, because parsing pasted bytes needs no network at all.
//
// ---------------------------------------------------------------------------
// The two-message dance is the page's structure, not an implementation detail.
//
// A first AS-REQ carrying no pre-authentication is answered by
// KDC_ERR_PREAUTH_REQUIRED **with PA-ETYPE-INFO2**, which is where the SALT comes
// from — and the salt is not guessable (Active Directory uses realm +
// sAMAccountName for a user but a host-shaped string for a computer account). So
// the page has two buttons in that order, the second one enabled by what the first
// one learned, and the salt is displayed rather than hidden: somebody debugging a
// service account needs to SEE that the salt is not what they assumed.
//
// **No `innerHTML` anywhere.** Every value here came from a KDC somebody else
// operates — a realm, a principal name, an e-text — so the DOM is built with
// createElement and textContent, the same rule webauthn_panes.js and
// kerberos_decoder.js carry. The rendering is shared with the decoder page through
// common/krb5/krb5_describe.js, which means a message renders identically wherever
// it is shown and the protocol knowledge lives in one place.
//
// **Key material.** The password is never persisted — that is the repo-wide rule.
// The TGT's SESSION KEY is a credential too, and a less obvious one: it is standing
// access to whatever that ticket can reach. So the credential cache lives in
// sessionStorage and is gone when the tab closes, unless `krb_save_ccache` is
// ticked; clearing that box purges what was already stored, on the spot, because an
// opt-out that leaves yesterday's session key behind is not an opt-out.
// ---------------------------------------------------------------------------

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "kerberos", level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());

var prim = require("./krb5_primitives.js");
var asn1 = require("./krb5_asn1.js");
var msgs = require("./krb5_messages.js");
var kcrypto = require("./krb5_crypto.js");
var describer = require("./krb5_describe.js");
// The shared DOM half, the credential cache and the relay calls. These were
// copied into this file and into kerberos_decoder.js before the TGS and AP
// pages made it four copies; the cache in particular has three writers now
// (this page produces a TGT, the TGS page spends it, the AP page presents the
// result), and shared state with three writers needs one implementation — three
// would drift on the question that matters most, which is WHERE a session key
// is kept.
var panes = require("./kerberos_panes.js");
// The hex view is required here for ONE pane. The request and reply panes get
// theirs from renderMessage(), which pairs `krb_x_pane` with `krb_x_hex` by
// convention — but the held ticket is not a message this page sent or received,
// it is a field lifted out of one, so renderCache() renders it itself. That is
// also why its decoded pane is `krb_cache_pane` while its hex is
// `krb_ticket_hex`: the two halves are of different things, and the convention
// correctly does not fire.
var hexview = require("./kerberos_hex.js");
var ophistory = require("./kerberos_history.js");
// The Ticket Cache & History pane, which lived in this file until it went on
// all five pages. It renders the list and owns Make active and Clear; this page
// supplies the slot it holds (a TGT) and re-renders the pane above when a row
// is put back into it.
var tickets = require("./kerberos_tickets.js");

// ---------------------------------------------------------------------------
// Storage. Six keys, all prefixed krb_, and the cache is deliberately separate
// from the configuration because they have different lifetimes.
// ---------------------------------------------------------------------------
var KEYS = panes.KEYS;

// Aliases rather than re-implementations. See the note on the require above.
var el = panes.el;
var val = panes.val;
var setVal = panes.setVal;
var checked = panes.checked;
var make = panes.make;
var clear = panes.clear;
var status = panes.status;
var saveCache = panes.saveTgt;
var readCache = panes.readTgt;
var purgeCache = panes.forgetTgt;

function saveConfiguration() {
  log.debug("Entering saveConfiguration().");
  if (!window.localStorage) {
    log.debug("Leaving saveConfiguration().");
    return;
  }
  try {
    localStorage.setItem(KEYS.REALM, val("krb_realm"));
    localStorage.setItem(KEYS.KDC_HOST, val("krb_kdc_host"));
    localStorage.setItem(KEYS.KDC_PORT, val("krb_kdc_port"));
    localStorage.setItem(KEYS.TRANSPORT, val("krb_transport"));
    localStorage.setItem(KEYS.PRINCIPAL, val("krb_principal"));
    localStorage.setItem(KEYS.ETYPES, val("krb_etypes"));
    localStorage.setItem(KEYS.SAVE_CCACHE, checked("krb_save_ccache") ? "1" :
        "0");
    // The PASSWORD is deliberately absent from this list, as it is on every
    // other page in this repository.
    if (!checked("krb_save_ccache")) panes.enforceStoragePreference();
  } catch (e) {
    log.error("could not store the configuration: " + e.message);
  }
  log.debug("Leaving saveConfiguration().");
}

// The build's own defaults, applied BEFORE anything stored so a value the user
// has typed still wins. They come from the config rather than from the markup
// because the right answer differs per build: the relay reaches the KDC from
// inside the API container, so the working host is the compose service name
// `sts` — `localhost` there is the api itself — while a deployed build has no
// api at all and defaults to nothing. Writing the working value into the HTML
// would be right in one environment and wrong in the two others, with the
// failure reading as a connection refused to an address the user can reach from
// their own shell.
function applyBuildDefaults() {
  log.debug("Entering applyBuildDefaults().");
  var defaults = [
    ["krb_realm", appconfig.krb5RealmDefault],
    ["krb_kdc_host", appconfig.krb5KdcHostDefault],
    ["krb_kdc_port", appconfig.krb5KdcPortDefault],
    ["krb_principal", appconfig.krb5PrincipalDefault],
    ["krb_password", appconfig.krb5PasswordDefault]
  ];
  var applied = 0;
  defaults.forEach(function (pair) {
    if (!pair[1]) {
      return;
    }                       // absent or "" on a build with no api
    setVal(pair[0], pair[1]);
    applied++;
  });
  log.debug("Leaving applyBuildDefaults(). applied=" + applied);
  return applied;
}

function loadConfiguration() {
  log.debug("Entering loadConfiguration().");
  applyBuildDefaults();
  if (!window.localStorage) {
    return;
  }
  var stored = {
    krb_realm: localStorage.getItem(KEYS.REALM),
    krb_kdc_host: localStorage.getItem(KEYS.KDC_HOST),
    krb_kdc_port: localStorage.getItem(KEYS.KDC_PORT),
    krb_transport: localStorage.getItem(KEYS.TRANSPORT),
    krb_principal: localStorage.getItem(KEYS.PRINCIPAL),
    krb_etypes: localStorage.getItem(KEYS.ETYPES)
  };
  Object.keys(stored).forEach(function (id) {
    if (stored[id] !== null && stored[id] !== undefined &&
        stored[id] !== "") setVal(id, stored[id]);
  });
  var save = localStorage.getItem(KEYS.SAVE_CCACHE);
  var box = el("krb_save_ccache");
  // Absent means the default, which is OFF: unlike the SAML and WS-Federation
  // key panes (where saving is the default because the workflow spans pages),
  // nothing here needs the cache to survive a page load, so the safer default
  // is available.
  if (box) box.checked = save === "1";
  if (!box || !box.checked) panes.enforceStoragePreference();
  log.debug("Leaving loadConfiguration().");
}

// ---------------------------------------------------------------------------
// Rendering, shared with the decoder page.
// ---------------------------------------------------------------------------
var renderRow = panes.renderRow;
var renderSection = panes.renderSection;
var renderMessage = panes.renderMessage;
var bytesToB64 = panes.bytesToB64;
var b64ToBytes = panes.b64ToBytes;

// The AS page's own relay call: it reads the KDC coordinates out of ITS fields,
// which the shared helper deliberately does not do — the TGS page has the same
// fields and the AP page has different ones, so the field names belong to the
// page.
async function sendToKdc(message) {
  return panes.sendToKdc({
    host: val("krb_kdc_host").trim(),
    port: parseInt(val("krb_kdc_port"), 10) || 88,
    transport: val("krb_transport") || "tcp",
    message: message
  });
}

// ---------------------------------------------------------------------------
// Building the request.
// ---------------------------------------------------------------------------
function requestedEtypes() {
  log.debug("Entering requestedEtypes().");
  var text = val("krb_etypes").trim();
  if (!text) {
    log.debug("Leaving requestedEtypes().");
    return kcrypto.DEFAULT_ETYPE_PREFERENCE.slice();
  }
  var ids = [];
  text.split(/[\s,]+/).forEach(function (part) {
    if (!part) {
      return;
    }
    var id = parseInt(part, 10);
    if (Number.isInteger(id)) ids.push(id);
  });
  log.debug("Leaving requestedEtypes().");
  return ids.length ? ids : kcrypto.DEFAULT_ETYPE_PREFERENCE.slice();
}

function requestedOptions() {
  var options = [];
  if (checked("krb_opt_forwardable")) options.push(msgs.KDC_OPTION.FORWARDABLE);
  if (checked("krb_opt_renewable")) options.push(msgs.KDC_OPTION.RENEWABLE);
  if (checked("krb_opt_canonicalize")) options.push(msgs.KDC_OPTION.CANONICALIZE);
  return options;
}

var lastNonce = 0;
function freshNonce() {
  // A UInt32 from the browser's own CSPRNG. The nonce is the client's only
  // defence against a replayed reply, so it must be unpredictable rather than a
  // counter.
  var b = kcrypto.randomBytes(4);
  lastNonce = ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
  return lastNonce;
}

function buildAsReq(padata) {
  log.debug("Entering buildAsReq().");
  var realm = val("krb_realm").trim();
  var principal = msgs.parsePrincipal(val("krb_principal").trim(),
      msgs.NAME_TYPE.PRINCIPAL);
  var lifetime = parseInt(val("krb_lifetime"), 10) || 10;
  log.debug("Leaving buildAsReq().");
  return msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.AS_REQ,
    // PA-PAC-REQUEST has THREE states and only two of them are a checkbox, so
    // the mapping matters. Ticked sends include-pac=TRUE and unticked sends
    // include-pac=FALSE — an explicit decline, which is what actually gets a
    // ticket with no PAC in it. Omitting the padata altogether is the third
    // state and means "the KDC decides", and Active Directory decides to
    // include one; a control that omitted it while offering to show you a
    // ticket without a PAC would hand you a ticket with one. That difference is
    // visible in the reply: an implicitly-granted PAC says
    // PAC_WAS_GIVEN_IMPLICITLY in PAC_ATTRIBUTES_INFO rather than
    // PAC_WAS_REQUESTED.
    padata: (padata || []).concat([
      {
        type: msgs.PA_TYPE.PAC_REQUEST,
        value: msgs.encPaPacRequest(checked("krb_opt_pac"))
      }
    ]),
    reqBody: {
      kdcOptions: requestedOptions(),
      cname: { type: principal.type, name: principal.name },
      realm: realm,
      sname: { type: msgs.NAME_TYPE.SRV_INST, name: ["krbtgt", realm] },
      till: new Date(Date.now() + lifetime * 3600 * 1000),
      rtime: checked("krb_opt_renewable") ? new Date(Date.now() +
          7 * 24 * 3600 * 1000) : null,
      nonce: freshNonce(),
      etypes: requestedEtypes()
    }
  });
}

// ---------------------------------------------------------------------------
// Open an Operations History row for one of this page's two AS exchanges.
//
// The principal and the KDC are read from the FIELDS rather than from the
// parsed request, because this is called before the request is built and the
// row has to exist even when it never will be. What the user typed is also
// what they will scan this list for.
// ---------------------------------------------------------------------------
function beginAsOperation(operation) {
  log.debug("Entering beginAsOperation(). " + operation);
  var user = val("krb_principal").trim();
  var realm = val("krb_realm").trim();
  ophistory.begin({
    operation: operation,
    principal: user + (realm ? "@" + realm : ""),
    target: val("krb_kdc_host").trim() + ":" + (val("krb_kdc_port") || "88") +
        "/" + (val("krb_transport") || "tcp"),
    statusId: "krb_as_status"
  });
  log.debug("Leaving beginAsOperation().");
}

// What the KDC told us in the last PREAUTH_REQUIRED: the etypes, salts and
// iteration counts. Held in memory only — it is derived from a message the page
// still has on screen, so persisting it would add nothing but a stale copy.
var discovered = null;

// ---------------------------------------------------------------------------
// Step 1: ask without pre-authentication.
// ---------------------------------------------------------------------------
async function onRequestWithoutPreAuth() {
  log.debug("Entering onRequestWithoutPreAuth().");
  // Opened before this handler's own guards run, so a request that cannot even
  // be built is recorded as the Failure it is. Every exit below sets a status
  // on krb_as_status, and that is what closes this row — see the note at the
  // top of kerberos_history.js.
  beginAsOperation(ophistory.OPS.AS_NO_PREAUTH);
  status("krb_as_status", "Sending an AS-REQ with no pre-authentication…",
      "krb-pending");
  var request;
  try {
    request = buildAsReq([]);
  } catch (e) {
    status("krb_as_status", "The request could not be built: " + e.message,
        "krb-bad");
    return false;
  }
  saveConfiguration();
  await renderMessage("krb_request_pane", "Sent", request);

  var result;
  try {
    result = await sendToKdc(request);
  } catch (e) {
    // A failure is rendered where the action happened, and the request pane
    // keeps what it was showing: the bytes that were sent are still the most
    // useful thing on the screen when the send failed.
    status("krb_as_status", e.message, "krb-bad");
    log.debug("Leaving onRequestWithoutPreAuth(). send failed.");
    return false;
  }

  var doc = await renderMessage("krb_reply_pane", "Received",
      result.reply);
  var response;
  try {
    response = msgs.readKdcResponse(result.reply);
  } catch (e) {
    status("krb_as_status", "The KDC answered something this page cannot " +
        "read: " + e.message, "krb-bad");
    return false;
  }

  if (response.kind === "KRB-ERROR" && response.error.errorCode === 25) {
    // The expected answer, and not a failure. Read the salt out for step 2.
    var info = null;
    (response.error.eDataPaData || []).forEach(function (pa) {
      if (pa.type === msgs.PA_TYPE.ETYPE_INFO2) {
        try {
          info = msgs.readEtypeInfo2(pa.value);
        } catch (e) {
          log.warn("ETYPE-INFO2 did not decode: " + e.message);
        }
      }
    });
    if (!info || !info.length) {
      status("krb_as_status",
        "The KDC asked for pre-authentication but sent no PA-ETYPE-INFO2, so " +
            "it has not said which " +
        "salt to use. Supply one by hand below — Active Directory's default " +
            "is the realm followed " +
        "by the sAMAccountName for a user account.", "krb-bad");
      discovered = null;
      renderDiscovered(null);
      return false;
    }
    discovered = info;
    renderDiscovered(info);
    status("krb_as_status",
      "KDC_ERR_PREAUTH_REQUIRED — which is the expected answer, not a " +
          "failure. The KDC has told us " +
      "the salt and iteration count for " + info.length + " encryption " +
          "type(s); step 2 can now " +
      "derive the right key.", "krb-ok");
    var second = el("krb_preauth_button");
    if (second) second.disabled = false;
    log.debug("Leaving onRequestWithoutPreAuth(). salt discovered.");
    return false;
  }

  if (response.kind === "AS-REP") {
    // An account with pre-authentication disabled. Unusual against AD, and
    // worth saying so rather than quietly succeeding.
    status("krb_as_status",
      "The KDC issued a ticket WITHOUT pre-authentication, which means this " +
          "account does not " +
      "require it. On Active Directory that is the DONT_REQUIRE_PREAUTH " +
          "flag, and it is the " +
      "condition that makes an account's password attackable offline from a " +
          "single AS-REP.",
      "krb-ok");
    await completeWithReply(result.reply, null);
    return false;
  }

  status("krb_as_status", "The KDC refused: " + response.error.error.name +
      " — " +
    response.error.error.meaning, "krb-bad");
  log.debug("Leaving onRequestWithoutPreAuth(). refused with " +
      response.error.error.name);
  return false;
}

function renderDiscovered(info) {
  log.debug("Entering renderDiscovered().");
  var host = el("krb_discovered_pane");
  if (!host) {
    log.debug("Leaving renderDiscovered().");
    return;
  }
  clear(host);
  if (!info) {
    log.debug("Leaving renderDiscovered().");
    return;
  }
  var pane = make("div", "krb-section");
  pane.appendChild(make("h4", "krb-section-title", "What the KDC told us"));
  pane.appendChild(make("p", "krb-section-note",
    "The salt is not guessable and this is the only place it comes from. " +
        "Active Directory uses the " +
    "realm followed by the sAMAccountName for a user, but a host-shaped " +
        "string for a computer " +
    "account — so if you are debugging a service, expect the second shape."));
  var table = make("table", "krb-table");
  info.forEach(function (entry) {
    var iterations = null;
    if (entry.s2kparams && prim.toBytes(entry.s2kparams).length === 4) {
      var p = prim.toBytes(entry.s2kparams);
      iterations = ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
    }
    renderRow(table, {
      name: "etype " + entry.etype + " " + entry.etypeName,
      value: "salt: " + (entry.salt === null ? "(none — arcfour is unsalted)" :
          entry.salt) +
             (iterations !== null ? "\niterations: " + iterations : ""),
      note: entry.salt === null
        ? "arcfour-hmac-md5's string-to-key is the NT hash and ignores the " +
            "salt entirely."
        : null
    });
  });
  pane.appendChild(table);
  el("krb_discovered_pane").appendChild(pane);

  // Offer the etype the KDC listed first, which is the one it prefers.
  var select = el("krb_preauth_etype");
  if (select) {
    clear(select);
    info.forEach(function (entry) {
      var option = make("option", null, entry.etype + " — " + entry.etypeName +
        (entry.salt === null ? " (unsalted)" : ""));
      option.value = String(entry.etype);
      select.appendChild(option);
    });
  }
  setVal("krb_salt", (info[0] && info[0].salt) || "");
  log.debug("Leaving renderDiscovered().");
}

// ---------------------------------------------------------------------------
// Step 2: ask again, with PA-ENC-TIMESTAMP.
// ---------------------------------------------------------------------------
async function onRequestWithPreAuth() {
  log.debug("Entering onRequestWithPreAuth().");
  beginAsOperation(ophistory.OPS.AS_PREAUTH);
  var password = val("krb_password");
  if (!password) {
    status("krb_as_status", "A password is needed to build PA-ENC-TIMESTAMP. " +
        "It is used here in the " +
      "browser and is never sent to the api.", "krb-bad");
    return false;
  }
  var etype = parseInt(val("krb_preauth_etype"), 10);
  if (!Number.isInteger(etype)) {
    status("krb_as_status", "Choose an encryption type first — step 1 fills " +
        "this list from what the " +
      "KDC offered.", "krb-bad");
    return false;
  }
  var salt = val("krb_salt");
  var entry = (discovered ||
      []).filter(function (e) { return e.etype === etype; })[0] || null;

  status("krb_as_status", "Deriving the key and sending an AS-REQ with " +
      "PA-ENC-TIMESTAMP…", "krb-pending");
  var profile;
  var key;
  try {
    profile = kcrypto.etypeById(etype);
    key = await profile.stringToKey(password, prim.utf8(salt), entry &&
        entry.s2kparams);
  } catch (e) {
    status("krb_as_status", "The key could not be derived: " + e.message,
        "krb-bad");
    return false;
  }

  var request;
  try {
    var stamp = msgs.encPaEncTsEnc(new Date(), 0);
    request = buildAsReq([{
      type: msgs.PA_TYPE.ENC_TIMESTAMP,
      value: msgs.encEncryptedData({
        etype: etype,
        // Key usage 1, and only 1. Any other number produces a well-formed
        // message the KDC reports as a wrong password.
        cipher: await profile.encrypt(key,
            kcrypto.KEY_USAGE.AS_REQ_PA_ENC_TIMESTAMP, stamp)
      })
    }]);
  } catch (e) {
    status("krb_as_status", "The request could not be built: " + e.message,
        "krb-bad");
    return false;
  }
  saveConfiguration();
  // The client's key goes to the REQUEST pane as well as to the reply's, and it
  // is not decoration: PA-ENC-TIMESTAMP is encrypted under exactly this key at
  // key usage 1, so with it the pane shows the timestamp the KDC is about to
  // compare against its own clock. Without it the padata was a byte count, and
  // a page that had just derived the key and did not use it was hiding the one
  // field a pre-authentication failure is about.
  await renderMessage("krb_request_pane", "Sent", request,
      clientKeyList({ etype: etype, key: key, salt: salt }));

  var result;
  try {
    result = await sendToKdc(request);
  } catch (e) {
    status("krb_as_status", e.message, "krb-bad");
    return false;
  }
  await completeWithReply(result.reply, {
    etype: etype,
    key: key,
    profile: profile,
    salt: salt
  });
  log.debug("Leaving onRequestWithPreAuth().");
  return false;
}

// The one key this page derives, in the shape the describer wants it.
//
// It opens two things and NOT a third, and that distinction is why this page
// asks for no other key: PA-ENC-TIMESTAMP on the way out and the AS-REP's
// enc-part on the way back are both under the client's long-term key, while the
// TICKET inside that reply is under krbtgt's and no password typed anywhere
// will ever open it. The ticket's contents are shown from the KDC's own report
// of them instead — see reportedTicketContents() below.
function clientKeyList(clientKey) {
  log.debug("Entering clientKeyList().");
  if (!clientKey) {
    log.debug("Leaving clientKeyList(). No key derived yet.");
    return [];
  }
  log.debug("Leaving clientKeyList().");
  return [{
    etype: clientKey.etype,
    key: clientKey.key,
    label: "the password with salt " + JSON.stringify(clientKey.salt)
  }];
}

// Read a reply, and if it is a ticket, open it with the client key and store
// it.
async function completeWithReply(replyBytes, clientKey) {
  log.debug("Entering completeWithReply().");
  await renderMessage("krb_reply_pane", "Received", replyBytes,
      clientKeyList(clientKey));

  var response;
  try {
    response = msgs.readKdcResponse(replyBytes);
  } catch (e) {
    status("krb_as_status", "The reply could not be read: " + e.message,
        "krb-bad");
    return;
  }
  if (response.kind === "KRB-ERROR") {
    var e = response.error;
    status("krb_as_status", e.error.name + " — " + e.error.meaning, "krb-bad");
    log.debug("Leaving completeWithReply(). refused.");
    return;
  }

  var rep = response.rep;
  if (rep.encPart.nonce !== undefined) { /* nothing: the nonce is inside the enc-part */ }
  if (!clientKey) {
    status("krb_as_status", "A ticket arrived, but without a key this page " +
        "cannot open its " +
      "enc-part — so the session key inside is not available and the ticket " +
          "cannot be used yet.",
      "krb-pending");
    renderCache(null);
    return;
  }

  var part;
  try {
    part = msgs.readEncKdcRepPart(
      await clientKey.profile.decrypt(clientKey.key,
          kcrypto.KEY_USAGE.AS_REP_ENCPART,
        rep.encPart.cipher));
  } catch (err) {
    status("krb_as_status",
      "The KDC issued a ticket, but its enc-part will not decrypt with the " +
          "key derived from this " +
      "password and salt (" + err.message + "). The commonest cause is the " +
          "SALT rather than the " +
      "password — check it against what step 1 reported.", "krb-bad");
    return;
  }

  // The nonce check. It is the client's only defence against a replayed reply,
  // and a page that did not check it would be a page that cannot detect one.
  if (part.nonce !== lastNonce) {
    status("krb_as_status",
      "THE NONCE DOES NOT MATCH. This reply carries " + part.nonce +
          " and the request sent " +
      lastNonce + ", so this is not an answer to the request just made — it " +
          "may be a replay. The " +
      "ticket has NOT been stored.", "krb-bad");
    log.error("nonce mismatch: sent " + lastNonce + ", received " + part.nonce);
    return;
  }

  // What is kept about the ticket, and it is deliberately EVERYTHING the KDC
  // reported about it rather than only what this page's summary table shows.
  // Those values are the ticket's own contents — the KDC repeats them in the
  // enc-part because the client cannot read the ticket — so keeping them is
  // what lets the Ticket pane show the inside of a TGT with no service key
  // anywhere. See renderTicketDetail(). `starttime` and the etype's NAME are
  // here for that reason and for no other; a reader who has to translate "18"
  // is a reader the page has failed.
  var entry = {
    realm: rep.crealm,
    client: msgs.principalToString(rep.cname, rep.crealm),
    service: msgs.principalToString(part.sname, part.srealm),
    ticket: bytesToB64(rep.ticket.raw),
    sessionKey: prim.toHex(part.key.key),
    sessionKeyEtype: part.key.etype,
    sessionKeyEtypeName: kcrypto.etypeName(part.key.etype),
    flags: msgs.ticketFlagNames(part.flags),
    authtime: part.authtime.toISOString(),
    starttime: part.starttime ? part.starttime.toISOString() : null,
    endtime: part.endtime.toISOString(),
    renewTill: part.renewTill ? part.renewTill.toISOString() : null,
    storedAt: new Date().toISOString()
  };
  saveCache(entry);
  // Into the history as well as into the live slot. Both, not one then the
  // other: the history is what makes an earlier ticket reachable, and a ticket
  // that was issued and never recorded is one the pane at the bottom will deny
  // ever existed.
  panes.recordTicket(entry);
  renderCache(entry);
  tickets.refresh();
  status("krb_as_status",
    "A TGT for " + entry.client + " was issued and stored, valid until " +
        entry.endtime + ". " +
    (checked("krb_save_ccache")
      ? "It is in localStorage because you asked for that; the session key " +
          "inside it is a credential."
      : "It is in sessionStorage only, so it goes when this tab closes."),
          "krb-ok");
  log.debug("Leaving completeWithReply(). ticket stored.");
}


function renderCache(entry) {
  log.debug("Entering renderCache().");
  // FIRST, not last. This function has three early returns — no pane, no
  // ticket, an unreadable one — and a banner painted at the bottom is a banner
  // that never appears in the case that matters most: somebody who arrived
  // from another workflow BECAUSE they have no ticket. That is the shape the
  // repo-root CLAUDE.md warns about for `Leaving` lines, and it bites the same
  // way for anything else placed after a return.
  showReturnBanner();
  var host = el("krb_cache_pane");
  if (!host) {
    log.debug("Leaving renderCache().");
    return;
  }
  clear(host);
  var current = entry || readCache();
  if (!current) {
    host.appendChild(make("p", "krb-note", "No ticket held. Complete the " +
        "exchange above to get one."));
    var button = el("krb_forget_button");
    if (button) button.disabled = true;
    // Clear the hex tab too. Left alone it would go on showing the bytes of a
    // ticket that has just been forgotten, which is the one thing a page about
    // credential storage must not do.
    hexview.render("krb_ticket_hex", null, "Ticket");
    log.debug("Leaving renderCache().");
    return;
  }
  // The ticket as it arrived. b64ToBytes rather than the decoded structure,
  // because the hex view's whole point is the bytes that were on the wire.
  try {
    hexview.render("krb_ticket_hex", panes.b64ToBytes(current.ticket),
        "Ticket");
  } catch (e) {
    log.warn("the cached ticket did not decode to bytes for the hex view: " +
        e.message);
  }
  var pane = make("div", "krb-section");
  pane.appendChild(make("h4", "krb-section-title", "Credential cache"));
  var table = make("table", "krb-table");
  [
    ["client", current.client, null],
    // "phase 3" was this project's build order and means nothing to a reader of
    // the page.
    ["service", current.service,
      "a TGT is a ticket for krbtgt, and useful only for buying others — the " +
          "TGS page spends it"],
    ["flags", (current.flags || []).join(", "), null],
    ["session key", current.sessionKeyEtype + ": " + current.sessionKey,
      "A CREDENTIAL. Anything holding this can use the ticket, which is why " +
          "it is not persisted " +
      "unless you ask."],
    ["valid from", current.authtime, null],
    ["valid until", current.endtime, null],
    ["renewable until", current.renewTill || "(not renewable)", null],
    ["ticket", (current.ticket || "").slice(0, 96) + "…",
      "The bytes exactly as the KDC sent them. Decoded field by field below, " +
          "and byte by byte on the Hex tab."]
  ].forEach(function (row) {
    renderRow(table, { name: row[0], value: row[1], note: row[2] });
  });
  pane.appendChild(table);
  host.appendChild(pane);
  var forget = el("krb_forget_button");
  if (forget) forget.disabled = false;
  // The decode goes on below, asynchronously, and its failures are its own: a
  // credential cache that renders and a decode that does not is far better than
  // a pane that shows neither because one of them threw.
  renderTicketDetail(current).catch(function (e) {
    log.error("the held ticket could not be decoded: " +
        (e.stack || e.message));
  });
  log.debug("Leaving renderCache().");
}

// ---------------------------------------------------------------------------
// THE TICKET, DECODED, WITH ITS CONTENTS FILLED IN — and with nothing to click.
//
// The key that opens a TGT is `krbtgt`'s, and no client has ever held it: that
// is what a ticket IS. What every client does hold is the KDC's own copy of the
// ticket's contents, which arrives in the reply's enc-part under the client's
// own key — the part this page decrypts with the password on the way in. So the
// flags, the session key, both realms, both principals and all four times are
// available with no key, no keytab and no second step, and they are stored on
// the cache entry for exactly this. The one field genuinely missing is the
// ticket's
// **authorization-data** (the PAC), which the KDC does not repeat to the
// client;
// the section says so rather than leaving a gap the reader has to notice.
//
// `krb5_describe.js` renders it and labels where the values came from, which is
// not decoration — see describeReportedTicketContents() there. The provenance
// is the difference between "here is the plaintext of that ciphertext" and
// "here is what the KDC says the plaintext is", and only the second is true
// here.
//
// Fed from the STORED entry rather than from the live exchange, so it is
// identical after a reload and after *Make active* on a row from the history —
// two paths that have no reply in hand at all.
// ---------------------------------------------------------------------------
function reportedTicketContents(entry) {
  log.debug("Entering reportedTicketContents().");
  function when(text) {
    return text ? new Date(text) : null;
  }
  // "alice@EXAMPLE.COM" / "krbtgt/EXAMPLE.COM@EXAMPLE.COM": the realm is behind
  // the LAST @, and a service principal has slashes but never a second @.
  var serviceRealm = String(entry.service || "").split("@").slice(1).join("@");
  log.debug("Leaving reportedTicketContents().");
  return {
    source: "From the AS-REP's own enc-part (EncASRepPart), decrypted here " +
      "with the key this page derived from the password.",
    flagNames: entry.flags || [],
    sessionKey: {
      etypeName: entry.sessionKeyEtypeName ||
          kcrypto.etypeName(entry.sessionKeyEtype),
      hex: entry.sessionKey
    },
    crealm: entry.realm,
    cname: entry.client,
    authtime: when(entry.authtime),
    starttime: when(entry.starttime),
    endtime: when(entry.endtime),
    renewTill: when(entry.renewTill),
    srealm: serviceRealm || entry.realm,
    sname: entry.service
  };
}

async function renderTicketDetail(entry) {
  log.debug("Entering renderTicketDetail().");
  var host = el("krb_cache_pane");
  if (!host || !entry || !entry.ticket) {
    log.debug("Leaving renderTicketDetail(). Nothing to decode.");
    return false;
  }
  var doc;
  try {
    doc = await describer.describe(panes.b64ToBytes(entry.ticket),
        { reported: reportedTicketContents(entry) });
  } catch (e) {
    // Said out loud in the pane. A ticket this page issued and stored that will
    // not decode is a finding about the codec, and the quietest way to lose it
    // would be an empty space under the table.
    host.appendChild(make("p", "krb-note krb-bad",
      "The stored ticket did not decode: " + e.message));
    log.debug("Leaving renderTicketDetail(). Did not decode.");
    return false;
  }
  // Appended rather than replacing: the table above is what this page HOLDS and
  // this is what is INSIDE it, and the pane answers both questions at once.
  (doc.sections || []).forEach(function (section) {
    renderSection(host, section, 0);
  });
  if (doc.problems && doc.problems.length) {
    var problems = make("div", "krb-problems");
    problems.appendChild(make("h4", "krb-section-title", "Worth knowing"));
    var list = make("ul");
    doc.problems.forEach(function (text) {
      list.appendChild(make("li", null, text));
    });
    problems.appendChild(list);
    host.appendChild(problems);
  }
  log.debug("Leaving renderTicketDetail(). sections=" +
      (doc.sections || []).length);
  return true;
}

// ---------------------------------------------------------------------------
// The way back, when somebody arrived from another workflow.
//
// The SPNEGO page cannot obtain a ticket — that is this page and then the TGS
// page — so it sends people here with ?return=spnego. This offers the link
// back, and says which of the two states they are in. It never navigates on
// its own: an automatic hop the moment a TGT arrived would take the two
// decoded messages off the screen at the moment somebody wanted to read them,
// which is what this page is FOR.
// ---------------------------------------------------------------------------
function showReturnBanner() {
  log.debug("Entering showReturnBanner().");
  var held = panes.readTgt();
  panes.renderReturnBanner("krb_return_banner", {
    ready: !!held,
    readyText: "You have a ticket-granting ticket. SPNEGO needs a SERVICE " +
      "ticket though, so step 2 — the TGS exchange — comes next; going back " +
      "now will offer you that link.",
    needText: "It needs a service ticket, and a service ticket is bought " +
      "with a TGT. Get one here, then buy the ticket on the TGS page."
  });
  log.debug("Leaving showReturnBanner().");
}

function onForget() {
  log.debug("Entering onForget().");
  // Recorded before the purge, while the ticket it is about can still be
  // named: afterwards there is nothing left to say whose it was.
  var held = readCache();
  purgeCache();
  renderCache(null);
  ophistory.note({
    operation: ophistory.OPS.FORGET_TGT,
    principal: (held && held.client) || "",
    detail: "Cleared from both sessionStorage and localStorage."
  });
  status("krb_as_status", "The credential cache was cleared from both " +
      "sessionStorage and " +
    "localStorage.", null);
  log.debug("Leaving onForget().");
  return false;
}

function onSaveCacheChanged() {
  // Unticking must purge what was already written. An opt-out that leaves
  // yesterday's session key in localStorage is not an opt-out.
  log.debug("Entering onSaveCacheChanged().");
  if (!checked("krb_save_ccache")) {
    try {
      panes.enforceStoragePreference();
    } catch (e) {
      log.warn("could not purge the stored cache: " + e.message);
    }
    // The purge empties localStorage, so both panes are now showing rows and
    // fields that no longer exist. Re-read them from the store rather than
    // leaving the screen asserting a credential is held when it has just been
    // deleted — which on a page about credential storage is the worst possible
    // thing to be wrong about.
    renderCache(null);
    tickets.refresh();
  }
  saveConfiguration();
  log.debug("Leaving onSaveCacheChanged().");
  return true;
}

// ---------------------------------------------------------------------------
// Arrival.
// ---------------------------------------------------------------------------
function reportEnvironment() {
  log.debug("Entering reportEnvironment().");
  var note = el("krb_environment_note");
  if (!note) {
    return;
  }
  clear(note);

  // No api means no socket means no Kerberos. Said on arrival rather than by
  // failing, and the controls are disabled so the page cannot pretend.
  if (appconfig.backendAvailable === false) {
    var pane = make("p", "krb-note krb-bad");
    pane.textContent = "This build has no api behind it, and Kerberos needs " +
        "one: the protocol " +
      "speaks DER over a TCP socket to port 88, which a browser cannot open. " +
          "Every other workflow " +
      "here can run entirely in the browser; this one cannot. The Kerberos " +
          "Decoder page does work " +
      "on this build — it parses bytes you already have.";
    note.appendChild(pane);
    ["krb_noreauth_button", "krb_preauth_button"].forEach(function (id) {
      var b = el(id);
      if (b) b.disabled = true;
    });
    return;
  }

  if (!(window.crypto && window.crypto.subtle)) {
    note.appendChild(make("p", "krb-note krb-bad",
      "This page is not in a secure context, so Web Crypto is unavailable " +
          "and no key can be " +
      "derived. Load it over https, or from localhost."));
  }

  // What the relay will and will not do, fetched so the page can say so before
  // a call fails rather than reporting its own limits as the KDC's fault.
  fetch(appconfig.apiUrl +
      "/krb5/limits").then(function (r) { return r.json(); }).then(function (limits) {
    var text = "The api will relay to ports " + (limits.allowedPorts ||
        []).join(", ") +
      "; its address policy is " + (limits.addressPolicyEnabled ? "ON" :
          "off") +
      (limits.addressPolicyEnabled
        ? " (so a KDC on a private or loopback address will be refused — the " +
            "local and " +
          "containerized stacks turn it off for exactly that reason)"
        : "") + ".";
    note.appendChild(make("p", "krb-note", text));
  }).catch(function (e) {
    note.appendChild(make("p", "krb-note krb-bad",
      "The api at " + appconfig.apiUrl + " did not answer GET /krb5/limits (" +
          e.message +
      "), so it may not be running or may be an older build without the " +
          "Kerberos relay."));
  });
  log.debug("Leaving reportEnvironment().");
}

window.onload = function () {
  log.debug("Entering onload().");
  // The shared chrome every workflow here has: the step trail marks where we
  // are, and the toggle collapses or expands every pane at once. wirePanes()
  // pairs each legend with its fieldset by id, so a pane added later is
  // clickable without anything being registered for it.
  panes.markCurrentStep("krb_step_as");
  panes.wirePanes();
  panes.wireTabs();
  var toggleAll = el("dbg_toggle_all");
  if (toggleAll) {
    toggleAll.addEventListener("change", function () {
      panes.setAllPanes(toggleAll.checked);
    });
  }
  loadConfiguration();
  reportEnvironment();
  // Read before the first render, so the banner is painted by renderCache()
  // below rather than needing a second pass.
  panes.noteReturnTarget();
  renderCache(null);
  // The Ticket Cache & History pane, from partials/krb_tickets.html. The slot
  // this page holds is a TGT slot — the TGS exchange spends whatever is in it —
  // so a TGT is the only kind it may take back; a service ticket accepted here
  // would fail a page later, naming something else. The callback re-renders the
  // pane above, so the cache, its hex tab and the list all move together.
  tickets.mount({
    slots: ["TGT"],
    onActivate: function (entry) {
      renderCache(entry);
    }
  });
  // The Operations History pane, from partials/krb_history.html. The same two
  // ids on all five pages, because they all include the same partial.
  ophistory.mount("krb_operation_history", "krb_clear_operations_button");
  var without = el("krb_noreauth_button");
  if (without) without.addEventListener("click",
      function () { onRequestWithoutPreAuth(); });
  var withPre = el("krb_preauth_button");
  if (withPre) withPre.addEventListener("click",
      function () { onRequestWithPreAuth(); });
  var forget = el("krb_forget_button");
  if (forget) forget.addEventListener("click", onForget);
  var box = el("krb_save_ccache");
  if (box) box.addEventListener("change", onSaveCacheChanged);
  status("krb_as_status", "Step 1 asks the KDC for a ticket with no " +
      "pre-authentication, which is " +
    "how the salt is discovered.", null);
  log.debug("Leaving onload().");
};

module.exports = {
  onRequestWithoutPreAuth: onRequestWithoutPreAuth,
  onRequestWithPreAuth: onRequestWithPreAuth,
  onForget: onForget
};
