// File: kerberos_keys.js
//
// ---------------------------------------------------------------------------
// The Decryption keys pane, shared by every Kerberos page that shows a message.
//
// ---------------------------------------------------------------------------
// WHY THIS EXISTS, which is a protocol fact rather than a UI preference.
//
// A ticket's EncTicketPart is encrypted at key usage 2 under the SERVICE
// principal's own long-term key — `krbtgt/REALM`'s for a ticket-granting
// ticket, the service account's for a service ticket. A client never holds that
// key: it carries the ticket and cannot read it, which is the whole reason a
// ticket is safe to hand over. So on every page here the most interesting
// section of the most interesting message said "not opened", and the only thing
// on screen was an instruction to go and use the decoder page.
//
// That instruction was the defect. The key can only come from the reader, but
// the place to put it belongs beside the message it opens: leaving the page you
// are debugging, pasting a ticket into another one and pasting a key beside it
// is three steps to see a field that is already on screen — and it loses the
// context the page was showing. The decoder page keeps its own pane and its own
// job (bytes from anywhere, no exchange, no credential), which is why it is
// still there and still linked; what changed is that it is no longer the only
// way to open what THIS page just received.
//
// ---------------------------------------------------------------------------
// HOW IT REACHES THE PANES, without touching a single call site.
//
// `mount()` registers `collect` with kerberos_panes.js, which adds whatever
// this pane yields to the keys each caller passes `renderMessage()`. So every
// message pane on every one of these pages — ten across five bundles, plus the
// AP-REQ nested inside a TGS-REQ's padata — opens on the same terms, and a page
// that never mounts this pane behaves exactly as it did before. The button then
// replays the panes already on screen (`panes.rerenderMessages()`), because the
// common case is pasting a key AFTER an exchange has run and re-running an
// exchange to read a ticket you already hold is not an answer.
//
// ---------------------------------------------------------------------------
// THREE ROUTES, because a reader is in one of three situations.
//
//   * a **raw key** in hex, from a keytab read elsewhere or derived by hand;
//   * a **password and its salt** — and the salt is NOT guessable, which is why
//     it is a field and not something computed here. Active Directory salts a
//     user as realm + sAMAccountName and a COMPUTER account as realm + "host" +
//     short name + DNS domain, so a page that guessed would be right until the
//     first machine account and then wrong in a way that looks like a wrong
//     password;
//   * a **keytab**, which is what a service account's keys actually arrive in.
//     Every usable key in it is offered, so a ticket whose etype you do not
//     know still opens.
//
// ---------------------------------------------------------------------------
// NOTHING HERE IS STORED. Every other field on these pages is remembered in
// localStorage; this pane's are not, in any store, and that is deliberate
// rather than unfinished: what goes in here is a long-term key — the credential
// the whole realm rests on, in the krbtgt case — and a debugger that remembered
// it would be a worse place to leave it than the keytab it came from. The
// consequence is honest and stated in the pane: the keys last as long as the
// page is open. `collect()` reads the fields on every render for the same
// reason, so there is no copy of them anywhere but the DOM.
// ---------------------------------------------------------------------------

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "kerberos_keys",
  level: appconfig.logLevel
});

var prim = require("./krb5_primitives.js");
var kcrypto = require("./krb5_crypto.js");
var describer = require("./krb5_describe.js");
var keytabReader = require("./krb5_keytab.js");
var panes = require("./kerberos_panes.js");

var el = panes.el;
var val = panes.val;
var make = panes.make;
var status = panes.status;

// The ids in partials/krb_keys.html. Deliberately NOT `krb_password` /
// `krb_salt`: those are taken on kerberos.html, where they are the CLIENT's
// credentials for pre-authentication, and reusing them would mean typing a
// service key into the field that authenticates you.
var FIELDS = {
  hex: "krb_deckey_hex",
  etype: "krb_deckey_etype",
  password: "krb_deckey_password",
  salt: "krb_deckey_salt",
  keytab: "krb_deckey_keytab",
  button: "krb_deckey_button",
  notes: "krb_deckey_notes",
  status: "krb_deckey_status"
};

// What mount() was given. Held because collect() runs later, from
// renderMessage(), with no caller to pass it anything.
var mounted = null;

// ---------------------------------------------------------------------------
// Assembling the keys, from a field map so the decoder page can use the same
// implementation against its own ids.
//
// A route that fails NEVER stops the others: three keys are offered here and a
// mistyped one must not cost a reader the two that were right. Each failure
// becomes a note instead, and the notes are shown.
// ---------------------------------------------------------------------------
async function collectFrom(fields, options) {
  log.debug("Entering collectFrom().");
  var opts = options || {};
  var keys = [];
  var notes = [];

  var rawHex = val(fields.hex).trim();
  if (rawHex) {
    var etype = parseInt(val(fields.etype), 10);
    try {
      var bytes = prim.fromHex(rawHex.replace(/[\s:]/g, ""));
      var profile = kcrypto.etypeById(etype);
      if (bytes.length !== profile.keyBytes) {
        notes.push("The key given is " + bytes.length + " bytes and " +
          profile.name + " keys are " + profile.keyBytes + ". It was offered " +
          "anyway, and will fail integrity rather than being rejected here.");
      }
      keys.push({
        etype: etype,
        key: bytes,
        label: "the key you pasted (" + profile.name + ")"
      });
    } catch (e) {
      notes.push("The pasted key could not be read: " + e.message);
    }
  }

  var password = val(fields.password);
  if (password) {
    var salt = val(fields.salt).trim();
    if (!salt && opts.defaultSalt) {
      // A page that can WORK OUT the conventional salt says what it assumed
      // rather than either failing or hiding it, because the assumption is the
      // thing most likely to be wrong.
      try {
        salt = opts.defaultSalt() || "";
      } catch (e) {
        log.warn("the default salt could not be computed: " + e.message);
        salt = "";
      }
      if (salt) {
        notes.push("No salt was given, so " + JSON.stringify(salt) + " was " +
          "assumed — the realm followed by the principal name. Active " +
          "Directory salts a COMPUTER account differently (realm + \"host\" " +
          "+ short name + DNS domain), and a wrong salt looks exactly like a " +
          "wrong password.");
      }
    }
    if (!salt) {
      notes.push("A password was given with no salt. The salt is NOT " +
        "guessable — take it from the KDC's own PA-ETYPE-INFO2, which " +
        "arrives inside the KDC_ERR_PREAUTH_REQUIRED error. Keys were " +
        "derived with an empty salt, which will almost certainly be wrong.");
    }
    try {
      keys = keys.concat(await describer.keysFromPassword(password, salt,
          null));
    } catch (e) {
      notes.push("Could not derive keys from the password: " + e.message);
    }
  }

  var keytabText = val(fields.keytab).trim();
  if (keytabText) {
    try {
      var parsedInput = describer.parseInput(keytabText);
      var kt = keytabReader.parseKeytab(parsedInput.bytes);
      var fromKeytab = keytabReader.keysFromKeytab(kt);
      keys = keys.concat(fromKeytab);
      notes.push("Keytab: version 0x" + kt.version.toString(16) + ", " +
        kt.entries.length + " entr" +
        (kt.entries.length === 1 ? "y" : "ies") +
        (kt.deletedSlots ? " and " + kt.deletedSlots + " deleted slot(s)" :
            "") +
        ", " + fromKeytab.length + " usable key(s): " +
        kt.entries.map(function (e) {
          return e.principal + " kvno " + e.kvno + " " + e.etypeName +
            (e.supported ? "" : " (not performed here)");
        }).join("; "));
    } catch (e) {
      notes.push("Keytab could not be read: " + e.message);
    }
  }

  log.debug("Leaving collectFrom(). keys=" + keys.length + ", notes=" +
      notes.length);
  return { keys: keys, notes: notes };
}

// The pane's own fields. This is what is registered with kerberos_panes.js, so
// it runs on EVERY message render — which is why it derives keys from the
// password each time rather than caching: a cache here would be a copy of a
// long-term key living outside the field the reader can see and clear.
async function collect() {
  log.debug("Entering collect().");
  if (!el(FIELDS.hex) && !el(FIELDS.password) && !el(FIELDS.keytab)) {
    // This page does not carry the pane. Not an error: the decoder page has its
    // own, and a page could legitimately have none.
    log.debug("Leaving collect(). No pane on this page.");
    return [];
  }
  var gathered = await collectFrom(FIELDS, mounted || {});
  log.debug("Leaving collect(). " + gathered.keys.length + " key(s).");
  return gathered.keys;
}

// ---------------------------------------------------------------------------
// The button: read the fields, repaint every message pane, say what happened.
//
// The status line is written in all three cases, including the one where
// nothing was supplied. A button that appears to do nothing is
// indistinguishable from a button that is broken, and this one legitimately has
// nothing to do when the fields are empty.
// ---------------------------------------------------------------------------
async function apply() {
  log.debug("Entering apply().");
  var gathered;
  try {
    gathered = await collectFrom(FIELDS, mounted || {});
  } catch (e) {
    log.error("collectFrom failed: " + (e.stack || e.message));
    status(FIELDS.status, "The keys could not be assembled: " + e.message,
        "krb-bad");
    log.debug("Leaving apply(). Failed.");
    return false;
  }

  var host = el(FIELDS.notes);
  if (host) {
    panes.clear(host);
    gathered.notes.forEach(function (text) {
      host.appendChild(make("p", "krb-note", text));
    });
  }

  var panesRedrawn = await panes.rerenderMessages();
  if (!gathered.keys.length) {
    status(FIELDS.status, "No key was supplied, so the encrypted parts are " +
      "described but not opened. A ticket needs the key of the principal in " +
      "its sname — that is the KDC's own krbtgt key for a ticket-granting " +
      "ticket, and the service account's for a service ticket.", "krb-pending");
    log.debug("Leaving apply(). Nothing supplied.");
    return false;
  }
  status(FIELDS.status, gathered.keys.length + " key(s) offered, and " +
    panesRedrawn + " pane(s) re-read with them. Each encrypted part now says " +
    "either which key opened it or what was tried and failed. Nothing typed " +
    "here is stored or sent anywhere.", "krb-ok");
  log.debug("Leaving apply(). keys=" + gathered.keys.length + ", panes=" +
      panesRedrawn);
  return false;
}

// ---------------------------------------------------------------------------
// Mounting. Called from each page's load handler, after wirePanes().
//
// options.defaultSalt  a function returning the salt to assume when a password
//                      is given without one. Only the SPNEGO page has enough
//                      context to compute one (it knows the SPN it just used),
//                      and where there is none the pane says the salt is
//                      required rather than inventing one.
// options.onApply      called after a successful application, for panes that
//                      are NOT message panes and so are not replayed by
//                      rerenderMessages() — the delegation page's trail note is
//                      the only one today.
// ---------------------------------------------------------------------------
function mount(options) {
  log.debug("Entering mount().");
  mounted = options || {};
  if (!el(FIELDS.hex) && !el(FIELDS.password) && !el(FIELDS.keytab)) {
    // A page that includes the partial gets the pane; one that does not is not
    // broken, so this is a debug line rather than a warning.
    log.debug("Leaving mount(). This page has no Decryption keys pane.");
    return false;
  }
  panes.setExtraKeys(collect);
  var button = el(FIELDS.button);
  if (button) {
    button.addEventListener("click", function () {
      Promise.resolve()
        .then(apply)
        .then(function () {
          if (mounted && typeof mounted.onApply === "function") {
            mounted.onApply();
          }
        })
        .catch(function (e) {
          // Without this the handler's rejection is unhandled and the page
          // simply stops with the status line still saying nothing.
          log.error("applying the supplied keys failed: " +
              (e.stack || e.message));
          status(FIELDS.status, "The keys could not be applied: " + e.message,
              "krb-bad");
        });
    });
  }
  log.debug("Leaving mount().");
  return true;
}

module.exports = {
  FIELDS: FIELDS,
  mount: mount,
  collect: collect,
  collectFrom: collectFrom,
  apply: apply
};
