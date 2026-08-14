// File: webauthn_panes.js
//
// ---------------------------------------------------------------------------
// The DOM half of the WebAuthn workflow: the panes that render a decoded
// ceremony. Shared by the Analyzer (artifacts somebody pasted) and the Lab (a
// ceremony this origin just performed), because those two differ in where the
// bytes came from and in nothing else — a flags table that disagreed between
// them would be a bug that only appears when you compare the two pages.
//
// Kept OUT of webauthn.js deliberately. That module has no DOM in it, which is
// what lets tests/webauthn_decode.js drive the decoding and the verification in
// node against real ceremonies, with no browser and no chance of flaking. Put
// one document.createElement in there and that test needs a browser.
//
// **Nothing here uses innerHTML.** Everything these panes render arrived from
// an authenticator, from a third-party relying party, or from a paste box. The
// whole file builds nodes with createElement and sets text with textContent, so
// there is no path from those bytes to markup at all — a stronger guarantee
// than sanitising, and free, because none of these panes need rich content.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
var cose = require("./cose");
var cbor = require("./cbor");
var webauthn = require("./webauthn");

// The log level comes from the same configuration the pages use. A consumer
// outside the browser bundles may not have one, so fall back to info rather
// than failing to load.
var log = bunyan.createLogger({
  name: "webauthn_panes",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      // No CONFIG_FILE resolvable here — a node caller rather than a bundle.
      return "info";
    }
  })()
});

function byId(id) {
  log.debug("Entering byId().");
  log.debug("Leaving byId().");
  return document.getElementById(id);
}

function clear(node) {
  log.debug("Entering clear().");
  while (node && node.firstChild) {
    node.removeChild(node.firstChild);
  }
  log.debug("Leaving clear().");
}

function el(tag, className, text) {
  log.debug("Entering el().");
  var node = document.createElement(tag);
  if (className) {
    node.className = className;
  }
  if (text !== undefined && text !== null) {
    node.textContent = String(text);
  }
  log.debug("Leaving el().");
  return node;
}

function table(parent) {
  log.debug("Entering table().");
  var t = el("table", "wa-table");
  var tbody = el("tbody");
  t.appendChild(tbody);
  parent.appendChild(t);
  log.debug("Leaving table().");
  return tbody;
}

function row(parent, name, value, extraClass) {
  log.debug("Entering row().");
  var tr = el("tr", extraClass || null);
  tr.appendChild(el("td", "wa-name", name));
  tr.appendChild(el("td", "wa-value", value));
  parent.appendChild(tr);
  log.debug("Leaving row().");
  return tr;
}

function status(id, text, kind) {
  log.debug("Entering status().");
  var node = byId(id);
  if (!node) {
    log.debug("Leaving status().");
    return;
  }
  node.textContent = text;
  node.className = "wa-status" + (kind ? " wa-" + kind : "");
  log.debug("Leaving status().");
}

function setValue(id, text) {
  log.debug("Entering setValue().");
  var node = byId(id);
  if (node) {
    node.value = text === undefined || text === null ? "" : String(text);
  }
  log.debug("Leaving setValue().");
}

// --- the panes ---------------------------------------------------------------

function renderClientData(paneId, rawId, cd) {
  log.debug("Entering renderClientData().");
  var pane = byId(paneId);
  if (!pane) {
    log.debug("Leaving renderClientData().");
    return;
  }
  clear(pane);
  var t = table(pane);
  row(t, "type", cd.type);
  row(t, "challenge", cd.challenge);
  row(t, "origin", cd.origin);
  row(t, "crossOrigin", String(cd.crossOrigin));
  if (cd.topOrigin !== undefined) {
    row(t, "topOrigin", cd.topOrigin);
  }
  if (cd.extraMembers.length) {
    // Chrome inserts `other_keys_can_be_added_here` into some ceremonies and
    // not others, at random, precisely so that implementations cannot compare
    // this against a template. Somebody staring at an unexplained member
    // deserves to be told what it is rather than left to wonder.
    row(t, "additional members", cd.extraMembers.join(", "), "wa-note-row");
    pane.appendChild(el("p", "wa-note",
      "Additional members are legal and expected. Chrome inserts " +
      "\"other_keys_can_be_added_here\" into some ceremonies and not others, " +
          "deliberately, so that " +
      "implementations cannot compare clientDataJSON against a fixed " +
          "template. Parse it; never " +
      "compare its bytes."));
  }
  setValue(rawId, cd.text);
  log.debug("Leaving renderClientData().");
}

function renderAuthenticatorData(paneId, ad) {
  log.debug("Entering renderAuthenticatorData().");
  var pane = byId(paneId);
  if (!pane) {
    log.debug("Leaving renderAuthenticatorData().");
    return;
  }
  clear(pane);
  var t = table(pane);
  row(t, "RP ID hash", ad.rpIdHashHex);
  row(t, "sign count", String(ad.signCount));

  var flags = el("div", "wa-flags");
  [["UP", "user present", ad.flags.UP],
   ["UV", "user verified", ad.flags.UV],
   ["BE", "backup eligible", ad.flags.BE],
   ["BS", "backed up", ad.flags.BS],
   ["AT", "attested credential data", ad.flags.AT],
   ["ED", "extension data", ad.flags.ED]].forEach(function (f) {
    var chip = el("span", "wa-flag " + (f[2] ? "wa-flag-set" : "wa-flag-clear"),
                  f[0] + " " + (f[2] ? "✓" : "✗"));
    chip.title = f[1];
    flags.appendChild(chip);
  });
  var flagRow = el("tr");
  flagRow.appendChild(el("td", "wa-name", "flags"));
  var flagCell = el("td", "wa-value");
  flagCell.appendChild(flags);
  flagCell.appendChild(el("div", "wa-subtle", "0x" +
                       ad.flagsByte.toString(16)));
  flagRow.appendChild(flagCell);
  t.appendChild(flagRow);

  if (ad.flags.AT) {
    row(t, "AAGUID", ad.aaguidHex);
    row(t, "credential ID", webauthn.bytesToBase64url(ad.credentialId) +
        "  (" + ad.credentialId.length + " bytes)");
  }
  if (ad.trailingBytes) {
    row(t, "trailing bytes", ad.trailingBytes +
        " byte(s) follow the fields the flags describe — the buffer is not " +
            "what it claims",
        "wa-bad-row");
  }
  log.debug("Leaving renderAuthenticatorData(). AT=" + ad.flags.AT);
}

// Returns the JWK when there was one, so the caller can remember it.
function renderCoseKey(paneId, pemId, ad) {
  log.debug("Entering renderCoseKey().");
  var pane = byId(paneId);
  if (!pane) {
    log.debug("Leaving renderCoseKey().");
    return null;
  }
  clear(pane);
  if (!ad.flags.AT || !ad.credentialPublicKey) {
    pane.appendChild(el("p", "wa-note",
      "No credential public key here. Only a REGISTRATION carries one; an " +
          "assertion is signed by " +
      "a key the relying party is expected to already hold."));
    setValue(pemId, "");
    log.debug("Leaving renderCoseKey(). none present");
    return null;
  }
  var described;
  try {
    described = cose.describe(ad.credentialPublicKey);
  } catch (e) {
    pane.appendChild(el("p", "wa-bad",
                     "The credential public key did not decode: " + e.message));
    log.debug("Leaving renderCoseKey(). decode failed");
    return null;
  }
  var t = table(pane);
  row(t, "COSE alg", described.coseAlg + "  (" + described.algorithm + ")");
  Object.keys(described.jwk).forEach(function (k) {
    row(t, "jwk." + k, described.jwk[k]);
  });
  setValue(pemId, described.pem || ("No PEM: " + described.pemUnavailable));
  log.debug("Leaving renderCoseKey(). alg=" + described.algorithm);
  return described.jwk;
}

function renderAttestation(paneId, rawId, att) {
  log.debug("Entering renderAttestation().");
  var pane = byId(paneId);
  if (!pane) {
    log.debug("Leaving renderAttestation().");
    return;
  }
  clear(pane);
  var t = table(pane);
  var s = att.attStmtSummary;
  row(t, "fmt", att.fmt);
  if (s.algName) {
    row(t, "alg", s.alg + "  (" + s.algName + ")");
  }
  if (s.sigBytes !== null && s.sigBytes !== undefined) {
    row(t, "sig", s.sigBytes + " bytes");
  }
  if (s.x5c) {
    row(t, "x5c", s.x5c.length + " certificate(s): " +
        s.x5c.map(function (c) { return c.bytes + "B"; }).join(", "));
    pane.appendChild(el("p", "wa-note",
      "The certificate chain is reported, not validated. Identifying an " +
          "authenticator from a chain " +
      "this tool has not checked against a metadata service would be a " +
          "confident guess, and a " +
      "confident guess is the one thing a debugger must not offer."));
  }
  if (s.note) {
    pane.appendChild(el("p", s.recognised ? "wa-note" : "wa-bad", s.note));
  }
  setValue(rawId, JSON.stringify(cbor.toPlain(att.attStmt), null, 2));
  log.debug("Leaving renderAttestation(). fmt=" + att.fmt);
}

// Every check, named, in order — not one boolean. The point of the pane is to
// say WHICH step failed; "invalid" would be useless for that, and is what makes
// people blame the authenticator.
function renderChecks(paneId, statusId, result) {
  log.debug("Entering renderChecks(). valid=" + result.valid);
  var pane = byId(paneId);
  if (!pane) {
    log.debug("Leaving renderChecks().");
    return;
  }
  clear(pane);
  var t = table(pane);
  result.checks.forEach(function (c) {
    var tr = el("tr", c.ok ? "wa-ok-row" : "wa-bad-row");
    tr.appendChild(el("td", "wa-name", (c.ok ? "✓ " : "✗ ") + c.name));
    tr.appendChild(el("td", "wa-value", c.detail));
    t.appendChild(tr);
  });
  var failed = result.checks.filter(function (c) {
    return !c.ok;
  }).length;
  status(statusId,
    result.valid
      ? "VALID — all " + result.checks.length + " checks passed."
      : "NOT VALID — " + failed + " of " + result.checks.length +
          " checks failed.",
    result.valid ? "good" : "bad");
  log.debug("Leaving renderChecks().");
}

module.exports = {
  byId: byId,
  clear: clear,
  el: el,
  table: table,
  row: row,
  status: status,
  setValue: setValue,
  renderClientData: renderClientData,
  renderAuthenticatorData: renderAuthenticatorData,
  renderCoseKey: renderCoseKey,
  renderAttestation: renderAttestation,
  renderChecks: renderChecks,
};
