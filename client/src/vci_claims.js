// File: vci_claims.js
//
// ---------------------------------------------------------------------------
// WHICH CLAIMS THE WALLET ASKS THE ISSUER TO PUT IN THE CREDENTIAL, with no DOM
// in it.
//
// OID4VCI 1.0 lets a Wallet name the claims it wants, and the place it does so
// is not the one most people look for first: the optional `claims` member
// belongs to the **authorization_details** entry of type `openid_credential`
// (section 5.1.1), NOT to the Credential Request. Section 8.2 defines only
// credential_identifier / credential_configuration_id, proofs and
// credential_response_encryption, and the 1.1 editor's draft still does. So the
// selection is made when the issuance is AUTHORIZED — in the Authorization
// Request, or, for the pre-authorized code flow that has no authorization
// request at all, in the Token Request (section 6.1.1 allows both) — and by the
// time the Credential Request is made it has already been granted.
//
// Two pages therefore need this: step 1, which owns the pane and builds the
// authorization request, and step 2, which builds the pre-authorized Token
// Request and says what was asked for. It lives here so the two cannot disagree
// about what "everything is selected" sends.
//
// The rows come from the issuer's own metadata —
// credential_configurations_supported[<id>].claims, an array of claims
// description objects (Appendix A.2) each carrying a claims path pointer
// (Appendix B) — so this asks in the vocabulary the issuer published rather
// than in one invented here.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
// The log level comes from the same configuration the pages use. A consumer
// outside the browser bundles (a node-based test loading this module directly)
// may not have one, so fall back to info rather than failing to load.
var log = bunyan.createLogger({
  name: "vci_claims",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// Where the selection is remembered. One entry per credential configuration,
// because the claims a configuration offers are its own and switching between
// two of them must not carry one's choices onto the other.
//
// What is stored is which claims are **excluded**, not which are included, and
// that is the whole reason the default works: a configuration nobody has
// touched has no entry and every row comes out checked, and a claim the issuer
// starts advertising later is checked too, for somebody who unchecked something
// else a month ago. Storing the included set would silently drop it.
var KEY = "sdjwtvc_requested_claims";

// A claims path pointer as one comparable string. JSON rather than a join,
// because a pointer may hold nulls and integers as well as strings (Appendix B)
// and "a.0.b" cannot tell those from the strings "0" and "b".
function pathKey(path) {
  log.debug("Entering pathKey().");
  log.debug("Leaving pathKey().");
  return JSON.stringify(path);
}

// The same pointer, for a person to read: dotted, with `null` (every element of
// an array) shown as [] and an integer as its index.
function pathLabel(path) {
  log.debug("Entering pathLabel().");
  var out = "";
  (path || []).forEach(function (part) {
    if (part === null) {
      out += "[]";
    } else if (typeof part === "number") {
      out += "[" + part + "]";
    } else {
      out += (out ? "." : "") + String(part);
    }
  });
  log.debug("Leaving pathLabel().");
  return out;
}

// The display name the issuer gives a claim, for whichever locale is at hand.
// English first when there is one, because the rest of this workflow's chrome
// is English and a name in a language the page is not in reads as a bug;
// otherwise the first the issuer listed, because that is its own order of
// preference.
function displayName(claim) {
  log.debug("Entering displayName().");
  var display = (claim && claim.display) || [];
  if (Object.prototype.toString.call(display) !== "[object Array]") {
    log.debug("Leaving displayName(). display is not an array.");
    return "";
  }
  var chosen = null;
  display.forEach(function (d) {
    if (!d || typeof d !== "object") return;
    if (!chosen) chosen = d;
    if (!chosen.locale || String(chosen.locale).indexOf("en") !== 0) {
      if (d.locale && String(d.locale).indexOf("en") === 0) chosen = d;
    }
  });
  log.debug("Leaving displayName().");
  return (chosen && chosen.name) ? String(chosen.name) : "";
}

// ---------------------------------------------------------------------------
// The rows: what one credential configuration says it can carry.
//
// An issuer need not publish `claims` at all — it is OPTIONAL — and several do
// not. That is not an error and must not read as one: it means this wallet has
// nothing to build a request out of, so it asks for no subset and takes what it
// is given. The caller distinguishes "no rows" from "no claims selected".
// ---------------------------------------------------------------------------
function claimsFor(vciInfo, configId) {
  log.debug("Entering claimsFor(). configId=" + configId);
  var configs = (vciInfo && vciInfo.credential_configurations_supported) || {};
  var config = configId ? configs[configId] : null;
  var claims = config && config.claims;
  if (Object.prototype.toString.call(claims) !== "[object Array]") {
    log.debug("Leaving claimsFor(). This configuration advertises no claims.");
    return [];
  }
  var rows = [];
  claims.forEach(function (claim) {
    if (!claim || typeof claim !== "object") return;
    var path = claim.path;
    if (Object.prototype.toString.call(path) !== "[object Array]" ||
        !path.length) {
      // Not a claims path pointer, so there is nothing this wallet could ask
      // for. Skipped rather than rendered, and said once by the caller.
      log.debug("claimsFor(): a claims description has no usable path.");
      return;
    }
    rows.push({
      path: path.slice(),
      key: pathKey(path),
      label: pathLabel(path),
      name: displayName(claim),
      // The ISSUER's mandatory (Appendix A.2), which is a different statement
      // from the wallet's (A.1): here it means the issuer always includes the
      // claim, so leaving it out of the request changes nothing.
      mandatory: claim.mandatory === true
    });
  });
  log.debug("Leaving claimsFor(). " + rows.length + " claim(s) advertised.");
  return rows;
}

// ---------------------------------------------------------------------------
// The selection, over those rows.
// ---------------------------------------------------------------------------
function excludedFor(stored, configId) {
  log.debug("Entering excludedFor(). configId=" + configId);
  var map = (stored && typeof stored === "object" &&
             Object.prototype.toString.call(stored) !== "[object Array]")
    ? stored : {};
  var list = map[configId];
  if (Object.prototype.toString.call(list) !== "[object Array]") {
    log.debug("Leaving excludedFor(). Nothing excluded.");
    return [];
  }
  log.debug("Leaving excludedFor(). " + list.length + " excluded.");
  return list.map(String);
}

// Which rows are checked. Everything the stored value does not exclude — see
// the note on KEY for why it is kept that way round.
function selectedRows(rows, stored, configId) {
  log.debug("Entering selectedRows(). configId=" + configId);
  var excluded = excludedFor(stored, configId);
  var out = (rows || []).filter(function (row) {
    return excluded.indexOf(row.key) === -1;
  });
  log.debug("Leaving selectedRows(). " + out.length + " of " +
            (rows || []).length + " selected.");
  return out;
}

// The stored value with this configuration's selection replaced. `keys` is what
// is CHECKED; what gets written is the complement, taken over the rows on
// screen, so a claim this issuer no longer advertises stops being excluded
// rather than staying excluded for ever.
function withSelection(stored, configId, rows, keys) {
  log.debug("Entering withSelection(). configId=" + configId);
  var map = {};
  if (stored && typeof stored === "object" &&
      Object.prototype.toString.call(stored) !== "[object Array]") {
    Object.keys(stored).forEach(function (k) { map[k] = stored[k]; });
  }
  map[configId] = (rows || []).filter(function (row) {
    return (keys || []).indexOf(row.key) === -1;
  }).map(function (row) { return row.key; });
  log.debug("Leaving withSelection(). " + map[configId].length + " excluded.");
  return map;
}

// ---------------------------------------------------------------------------
// What goes on the wire: the `claims` member of an authorization detail, or
// null when there is nothing to say.
//
// Null in two cases, and they mean different things to the issuer only in that
// neither restricts it: the configuration advertises no claims (there is no
// vocabulary to ask in), or every advertised claim is selected (asking for all
// of them is what omitting the member already means). Null also when NOTHING is
// selected, because Appendix A.1 requires a non-empty array — a wallet that
// wants no claims at all cannot say so, and the pane says that rather than
// sending `[]` for an issuer to refuse.
//
// `mandatory` is deliberately not sent. Here it would mean "this wallet will
// only accept a credential containing this claim" (A.1), which is a refusal the
// wallet then has to be prepared to make, and this one is a debugger that shows
// what came back rather than rejecting it.
// ---------------------------------------------------------------------------
function claimsMember(rows, stored, configId) {
  log.debug("Entering claimsMember(). configId=" + configId);
  if (!rows || !rows.length) {
    log.debug("Leaving claimsMember(). No claims are advertised.");
    return null;
  }
  var selected = selectedRows(rows, stored, configId);
  if (!selected.length) {
    log.debug("Leaving claimsMember(). Nothing is selected.");
    return null;
  }
  if (selected.length === rows.length) {
    log.debug("Leaving claimsMember(). Everything is selected.");
    return null;
  }
  log.debug("Leaving claimsMember(). " + selected.length + " claim(s).");
  return selected.map(function (row) { return { path: row.path.slice() }; });
}

// Whether the selection is one the issuer would notice — i.e. whether anything
// would be sent. The pre-authorized Token Request asks this before adding an
// authorization_details parameter it would otherwise not send at all.
function restrictsClaims(rows, stored, configId) {
  log.debug("Entering restrictsClaims().");
  var member = claimsMember(rows, stored, configId);
  log.debug("Leaving restrictsClaims(). " + (member ? "yes" : "no"));
  return !!member;
}

// Why a selection may go nowhere, in the one state where that happens: the
// authorization request is being made with a `scope`, and the claims member
// belongs to an authorization_details entry (section 5.1.1) — there is no room
// for it on a scope request, and no other call in the Authorization Code Flow
// carries it. The pre-authorized flow is the exception and needs no mechanism
// at all, because its Token Request carries authorization_details of its own
// (section 6.1.1).
var WHY_NOT_DELIVERABLE =
  "this authorization asks for the credential with a scope, and the claims " +
  "member belongs to authorization_details (OID4VCI section 5.1.1), which a " +
  "scope request has nowhere to put. Switch the pane below to " +
  "authorization_details — or take a Credential Offer with a pre-authorized " +
  "code, whose Token Request on step 2 carries them instead.";

// One sentence about the state of the pane, for whichever page is showing it.
//
// `canSend` is the caller's answer to "will the call this selection belongs to
// actually carry it" — see WHY_NOT_DELIVERABLE. It is a parameter rather than
// something worked out here because the answer lives in another pane (how the
// authorization is being asked for) and, on step 2, in the token response. A
// summary that ignored it is what this pane shipped with for a day: it said "9
// of 10 advertised claims will be asked for" on the scope route, where the
// request carries no claims member at all and the credential comes back with
// everything in it. The pane was right about the selection and wrong about the
// only thing anybody reads it for.
function summarize(rows, stored, configId, canSend) {
  log.debug("Entering summarize(). configId=" + configId);
  var text;
  if (!rows || !rows.length) {
    text = "This credential configuration's metadata does not say which " +
      "claims it can carry, so there is nothing to choose from and the " +
      "request will not restrict them.";
  } else {
    var selected = selectedRows(rows, stored, configId);
    if (!selected.length) {
      text = "Nothing is selected. A claims member has to be a non-empty " +
        "array (OID4VCI Appendix A.1), so none will be sent and this issuer " +
        "will decide what the credential carries.";
    } else if (selected.length === rows.length) {
      text = "All " + rows.length + " advertised claims are selected, which " +
        "is what sending no claims member means — so none will be sent.";
    } else if (canSend === false) {
      text = selected.length + " of " + rows.length + " advertised claims " +
        "are selected, but nothing will ask for them: " + WHY_NOT_DELIVERABLE;
    } else {
      text = selected.length + " of " + rows.length + " advertised claims " +
        "will be asked for: " +
        selected.map(function (row) { return row.label; }).join(", ") + ".";
    }
  }
  log.debug("Leaving summarize().");
  return text;
}

module.exports = {
  KEY: KEY,
  WHY_NOT_DELIVERABLE: WHY_NOT_DELIVERABLE,
  pathKey: pathKey,
  pathLabel: pathLabel,
  displayName: displayName,
  claimsFor: claimsFor,
  excludedFor: excludedFor,
  selectedRows: selectedRows,
  withSelection: withSelection,
  claimsMember: claimsMember,
  restrictsClaims: restrictsClaims,
  summarize: summarize
};
