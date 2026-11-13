// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: rfc9068.js
//
// ---------------------------------------------------------------------------
// RFC 9068 (JWT Profile for OAuth 2.0 Access Tokens), the checks a
// debugger can make. No DOM and no storage: the token-detail page and
// JWT Tools read their checkboxes and hand the facts in.
//
// Section 4 accepts a typ of "at+jwt" or "application/at+jwt". Media
// types compare case-insensitively, so the example's "at+JWT" is the
// same value. Section 2.2.3.1's groups, roles and entitlements follow
// the multi-valued User attributes in RFC 7643 section 4.1.2: an array
// of strings, or of objects whose "value" is a string. Section 2.2.1
// keeps auth_time, acr and amr the same on a refresh and on a token
// exchange. Section 3's aud follows the resource parameter that was
// sent, the token request's when that request included one.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "rfc9068",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var AUTHORIZATION_CLAIMS = ["groups", "roles", "entitlements"];

function finding(level, claim, message) {
  log.debug("Entering finding().");
  var row = { level: level, claim: claim, message: message };
  log.debug("Leaving finding().");
  return row;
}

function formatFinding(row) {
  log.debug("Entering formatFinding().");
  var tag = row.level === "pass" ? "PASS  " :
      row.level === "fail" ? "FAIL  " : "SKIP  ";
  log.debug("Leaving formatFinding().");
  return tag + row.claim + ": " + row.message;
}

// True when typ is the profile's media type, with or without the
// "application/" prefix, in any case.
function typAccepted(typ) {
  log.debug("Entering typAccepted().");
  if (typeof typ !== "string") {
    log.debug("Leaving typAccepted().");
    return false;
  }
  var value = typ.toLowerCase();
  var accepted = value === "at+jwt" ||
      value === "application/at+jwt";
  log.debug("Leaving typAccepted().");
  return accepted;
}

function typFinding(typ) {
  log.debug("Entering typFinding().");
  var row;
  if (typ === undefined || typ === null || typ === "") {
    row = finding("fail", "typ",
        'Missing — must be "at+jwt" or "application/at+jwt" ' +
        "(RFC 9068 §2.1, §4)");
  } else if (typeof typ !== "string") {
    row = finding("fail", "typ", '"typ" must be a string');
  } else if (typAccepted(typ)) {
    row = finding("pass", "typ", '"' + typ + '"');
  } else {
    row = finding("fail", "typ",
        '"' + typ + '" — must be "at+jwt" or ' +
        '"application/at+jwt" (RFC 9068 §4)');
  }
  log.debug("Leaving typFinding().");
  return row;
}

// Section 4 makes the signature a resource server's first check. A
// report that left it out says so in a row of its own, so "All checks
// passed" is never read as an accepted token.
function signatureNotVerifiedFinding() {
  log.debug("Entering signatureNotVerifiedFinding().");
  var row = finding("skip", "signature",
      "Not verified by this report. RFC 9068 §4 requires a resource " +
      "server to verify it before trusting any claim below");
  log.debug("Leaving signatureNotVerifiedFinding().");
  return row;
}

// A claim that is present but had nothing to be compared with. Section
// 4 requires iss to match the issuer and aud to name this resource, so
// "present" alone is not a pass. `what` is "issuer" or "audience".
function notComparedFinding(claim, value, what) {
  log.debug("Entering notComparedFinding().");
  var row = finding("skip", claim, JSON.stringify(value) +
      " — not compared: no expected " + what);
  log.debug("Leaving notComparedFinding().");
  return row;
}

// The closing line of a report. `notChecked` names the steps the
// report left out (the signature, an iss or aud with nothing to compare
// against), so a clean run is never read as an accepted token.
function summaryLine(failCount, notChecked) {
  log.debug("Entering summaryLine().");
  var missing = Array.isArray(notChecked) ? notChecked : [];
  var line;
  if (failCount > 0) {
    line = failCount + " check(s) failed.";
  } else if (missing.length === 0) {
    line = "All checks passed.";
  } else {
    line = "No check failed, but these were not checked: " +
        missing.join(", ") + ". RFC 9068 §4 does not accept a token " +
        "until they are.";
  }
  log.debug("Leaving summaryLine().");
  return line;
}

// Whether a report already compared `claim`: a PASS or FAIL row for it
// or for one of the workflow rows that compare it.
function compared(results, claims) {
  log.debug("Entering compared().");
  var found = results.some(function (line) {
    return claims.some(function (claim) {
      return line.indexOf("PASS  " + claim + ":") === 0 ||
          line.indexOf("FAIL  " + claim + ":") === 0;
    });
  });
  log.debug("Leaving compared().");
  return found;
}

function segmentCount(token) {
  log.debug("Entering segmentCount().");
  var count = 0;
  if (typeof token === "string" && token.length > 0) {
    count = token.split(".").length;
  }
  log.debug("Leaving segmentCount().");
  return count;
}

function b64uToUtf8(segment) {
  log.debug("Entering b64uToUtf8().");
  var b64 = segment.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) {
    b64 = b64 + "=";
  }
  var raw = atob(b64);
  var text;
  try {
    text = decodeURIComponent(raw.split("").map(function (c) {
      return "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(""));
  } catch (e) {
    text = raw;
  }
  log.debug("Leaving b64uToUtf8().");
  return text;
}

// Read a compact JWS into header and payload objects. A JWE, an
// opaque token and a non-JSON payload come back null. This does not
// verify anything.
function decodeCompact(token) {
  log.debug("Entering decodeCompact().");
  if (segmentCount(token) !== 3) {
    log.debug("Leaving decodeCompact().");
    return null;
  }
  var parts = token.split(".");
  var header;
  var payload;
  try {
    header = JSON.parse(b64uToUtf8(parts[0]));
    payload = JSON.parse(b64uToUtf8(parts[1]));
  } catch (e) {
    log.debug("Leaving decodeCompact().");
    return null;
  }
  if (header === null || typeof header !== "object" ||
      Array.isArray(header) || payload === null ||
      typeof payload !== "object" || Array.isArray(payload)) {
    log.debug("Leaving decodeCompact().");
    return null;
  }
  log.debug("Leaving decodeCompact().");
  return { header: header, payload: payload };
}

function authorizationItemOk(item) {
  log.debug("Entering authorizationItemOk().");
  var ok = false;
  if (typeof item === "string") {
    ok = true;
  } else if (item !== null && typeof item === "object" &&
      !Array.isArray(item) && typeof item.value === "string") {
    ok = true;
  }
  log.debug("Leaving authorizationItemOk().");
  return ok;
}

// One of groups, roles, entitlements. Absent is a skip: the claims
// are optional. Present must be the multi-valued shape from RFC 7643.
function checkAuthorizationClaim(name, value) {
  log.debug("Entering checkAuthorizationClaim().");
  var row;
  if (value === undefined) {
    row = finding("skip", name, "Not present (RFC 9068 §2.2.3.1)");
  } else if (!Array.isArray(value)) {
    row = finding("fail", name,
        "Must be an array (RFC 7643 §4.1.2, RFC 9068 §2.2.3.1)");
  } else if (!value.every(authorizationItemOk)) {
    row = finding("fail", name,
        "Each value must be a string, or an object with a string " +
        '"value" (RFC 7643 §4.1.2)');
  } else {
    row = finding("pass", name, value.length + " value(s)");
  }
  log.debug("Leaving checkAuthorizationClaim().");
  return row;
}

function checkAuthorizationClaims(payload) {
  log.debug("Entering checkAuthorizationClaims().");
  var body = payload && typeof payload === "object" ? payload : {};
  var rows = AUTHORIZATION_CLAIMS.map(function (name) {
    return checkAuthorizationClaim(name, body[name]);
  });
  log.debug("Leaving checkAuthorizationClaims().");
  return rows;
}

function bothAbsent(current, original) {
  log.debug("Entering bothAbsent().");
  var absent = current === undefined && original === undefined;
  log.debug("Leaving bothAbsent().");
  return absent;
}

function compareAuthTime(current, original) {
  log.debug("Entering compareAuthTime().");
  var row;
  if (bothAbsent(current, original)) {
    row = finding("pass", "auth_time", "Absent on both tokens");
  } else if (current === undefined || original === undefined) {
    row = finding("fail", "auth_time",
        "Present on only one token (RFC 9068 §2.2.1)");
  } else if (typeof current !== "number" ||
      typeof original !== "number" ||
      !Number.isInteger(current) || !Number.isInteger(original)) {
    row = finding("fail", "auth_time",
        "Must be an integer NumericDate on both tokens");
  } else if (current !== original) {
    row = finding("fail", "auth_time",
        "Changed from " + original + " to " + current +
        " (RFC 9068 §2.2.1)");
  } else {
    row = finding("pass", "auth_time",
        "Unchanged (" + current + ")");
  }
  log.debug("Leaving compareAuthTime().");
  return row;
}

function compareAcr(current, original) {
  log.debug("Entering compareAcr().");
  var row;
  if (bothAbsent(current, original)) {
    row = finding("pass", "acr", "Absent on both tokens");
  } else if (typeof current !== "string" ||
      typeof original !== "string") {
    row = finding("fail", "acr",
        "Must be a string on both tokens, or absent on both " +
        "(RFC 9068 §2.2.1)");
  } else if (current !== original) {
    row = finding("fail", "acr",
        'Changed from "' + original + '" to "' + current +
        '" (RFC 9068 §2.2.1)');
  } else {
    row = finding("pass", "acr", 'Unchanged ("' + current + '")');
  }
  log.debug("Leaving compareAcr().");
  return row;
}

function amrEqual(current, original) {
  log.debug("Entering amrEqual().");
  var equal = false;
  if (Array.isArray(current) && Array.isArray(original) &&
      current.length === original.length &&
      current.every(function (item, i) {
        return typeof item === "string" && item === original[i];
      })) {
    equal = true;
  }
  log.debug("Leaving amrEqual().");
  return equal;
}

function compareAmr(current, original) {
  log.debug("Entering compareAmr().");
  var row;
  if (bothAbsent(current, original)) {
    row = finding("pass", "amr", "Absent on both tokens");
  } else if (!amrEqual(current, original)) {
    row = finding("fail", "amr",
        "Must be the same array of strings on both tokens " +
        "(RFC 9068 §2.2.1)");
  } else {
    row = finding("pass", "amr",
        "Unchanged (" + current.length + " value(s))");
  }
  log.debug("Leaving compareAmr().");
  return row;
}

// current and original are payload objects. Section 2.2.1: the three
// authentication claims stay fixed across a refresh and a token
// exchange. Absence on both sides is the same value.
function compareAuthenticationContext(current, original) {
  log.debug("Entering compareAuthenticationContext().");
  var left = current && typeof current === "object" ? current : {};
  var right = original && typeof original === "object" ? original : {};
  var rows = [
    compareAuthTime(left.auth_time, right.auth_time),
    compareAcr(left.acr, right.acr),
    compareAmr(left.amr, right.amr)
  ];
  log.debug("Leaving compareAuthenticationContext().");
  return rows;
}

function blank(value) {
  log.debug("Entering blank().");
  var empty = value === undefined || value === null ||
      String(value).trim() === "";
  log.debug("Leaving blank().");
  return empty;
}

// The token request's resource is the one that mints the access
// token. The authorization request's resource is used when the token
// request did not include one. A request that did not include the
// parameter contributes nothing, even if its field still holds text.
function requestedResource(authz, token) {
  log.debug("Entering requestedResource().");
  var chosen = null;
  if (token && token.sent && !blank(token.value)) {
    chosen = String(token.value).trim();
  } else if (authz && authz.sent && !blank(authz.value)) {
    chosen = String(authz.value).trim();
  }
  log.debug("Leaving requestedResource().");
  return chosen;
}

function audienceContains(aud, resource) {
  log.debug("Entering audienceContains().");
  var values = Array.isArray(aud) ? aud : [aud];
  var found = values.indexOf(resource) >= 0;
  log.debug("Leaving audienceContains().");
  return found;
}

function compareIssuer(payload, issuer) {
  log.debug("Entering compareIssuer().");
  var row;
  if (blank(issuer)) {
    row = finding("skip", "iss/workflow",
        "No issuer stored from discovery");
  } else if (payload.iss === issuer) {
    row = finding("pass", "iss/workflow",
        '"' + payload.iss + '" matches the discovered issuer');
  } else {
    row = finding("fail", "iss/workflow",
        'Discovered issuer "' + issuer + '", token iss "' +
        (payload.iss === undefined ? "" : payload.iss) +
        '" (RFC 9068 §4)');
  }
  log.debug("Leaving compareIssuer().");
  return row;
}

function compareClient(payload, clientId) {
  log.debug("Entering compareClient().");
  var row;
  if (blank(clientId)) {
    row = finding("skip", "client_id/workflow",
        "No client id stored from the workflow");
  } else if (payload.client_id === clientId) {
    row = finding("pass", "client_id/workflow",
        '"' + payload.client_id + '" matches the workflow client id');
  } else {
    row = finding("fail", "client_id/workflow",
        'Workflow client id "' + clientId + '", token client_id "' +
        (payload.client_id === undefined ? "" : payload.client_id) +
        '" (RFC 9068 §2.2)');
  }
  log.debug("Leaving compareClient().");
  return row;
}

function compareResource(payload, resource) {
  log.debug("Entering compareResource().");
  var row;
  if (blank(resource)) {
    row = finding("skip", "aud/resource",
        "No resource parameter was sent");
  } else if (audienceContains(payload.aud, resource)) {
    row = finding("pass", "aud/resource",
        '"' + resource + '" is in aud (RFC 9068 §3)');
  } else {
    row = finding("fail", "aud/resource",
        'Requested resource "' + resource + '" is not in aud ' +
        JSON.stringify(payload.aud) + " (RFC 9068 §3)");
  }
  log.debug("Leaving compareResource().");
  return row;
}

// expected: { issuer, clientId, resource }. resource is null when
// neither request included the parameter.
function checkWorkflow(payload, expected) {
  log.debug("Entering checkWorkflow().");
  var body = payload && typeof payload === "object" ? payload : {};
  var facts = expected && typeof expected === "object" ? expected : {};
  var rows = [
    compareIssuer(body, facts.issuer),
    compareClient(body, facts.clientId),
    compareResource(body, facts.resource)
  ];
  log.debug("Leaving checkWorkflow().");
  return rows;
}

module.exports = {
  AUTHORIZATION_CLAIMS: AUTHORIZATION_CLAIMS,
  finding: finding,
  formatFinding: formatFinding,
  typAccepted: typAccepted,
  typFinding: typFinding,
  signatureNotVerifiedFinding: signatureNotVerifiedFinding,
  notComparedFinding: notComparedFinding,
  summaryLine: summaryLine,
  compared: compared,
  segmentCount: segmentCount,
  decodeCompact: decodeCompact,
  checkAuthorizationClaim: checkAuthorizationClaim,
  checkAuthorizationClaims: checkAuthorizationClaims,
  compareAuthenticationContext: compareAuthenticationContext,
  requestedResource: requestedResource,
  checkWorkflow: checkWorkflow
};
