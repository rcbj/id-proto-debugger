// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: acdc_page.js
//
// ---------------------------------------------------------------------------
// acdc.html (#480): verify an ACDC presentation stream — the KELs, the
// registry, the credential, the credentials it chains to — or an IPEX grant;
// issue one (either CESR version, weighted thresholds, witnesses, a
// delegated issuer, a backer registry, an aggregate, a chain), revoke it,
// grant it, and disclose its aggregate selectively. The work is acdc.js;
// this file is the DOM.
//
// NOTHING ON THIS PAGE IS STORED, the issuer's keys included: an issuance
// here is a demonstration whose keys live for the page load. Every value
// shown came from pasted text, so it is written with textContent.
// ---------------------------------------------------------------------------

var acdc = require("./acdc");

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "acdc_page",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var lastIssued = null;
var lastStream = "";

function el(id) {
  log.debug("Entering el(). " + id);
  log.debug("Leaving el().");
  return document.getElementById(id);
}

function val(id) {
  log.debug("Entering val(). " + id);
  var e = el(id);
  log.debug("Leaving val().");
  return e ? e.value : "";
}

function setVal(id, v) {
  log.debug("Entering setVal(). " + id);
  var e = el(id);
  if (e) {
    e.value = v;
  }
  log.debug("Leaving setVal().");
}

function setStatus(id, text, cls) {
  log.debug("Entering setStatus(). " + id);
  var e = el(id);
  if (e) {
    e.textContent = text;
    e.className = "vc-status " + (cls || "");
  }
  log.debug("Leaving setStatus().");
}

function togglePane(id) {
  log.debug("Entering togglePane(). " + id);
  var fs = el(id);
  if (fs) {
    fs.style.display = fs.style.display === "none" ? "block" : "none";
  }
  log.debug("Leaving togglePane().");
  return false;
}

function renderChecks(result) {
  log.debug("Entering renderChecks().");
  var host = el("acdc_checks");
  host.textContent = "";
  var table = document.createElement("table");
  table.className = "acdc-checks";
  result.checks.forEach(function (c) {
    var tr = document.createElement("tr");
    var mark = document.createElement("td");
    mark.textContent = c.ok ? "✔" : "✘";
    mark.className = c.ok ? "vc-ok" : "vc-error";
    var name = document.createElement("td");
    name.textContent = c.name;
    var detail = document.createElement("td");
    detail.textContent = c.detail;
    tr.appendChild(mark);
    tr.appendChild(name);
    tr.appendChild(detail);
    table.appendChild(tr);
  });
  host.appendChild(table);
  log.debug("Leaving renderChecks().");
}

// The schemas field: one schema, or a JSON list of them. Answers the list,
// or throws.
function readSchemas(id) {
  log.debug("Entering readSchemas().");
  var t = val(id).trim();
  if (!t) {
    log.debug("Leaving readSchemas(). None.");
    return [];
  }
  var parsed = JSON.parse(t);
  log.debug("Leaving readSchemas().");
  return Array.isArray(parsed) ? parsed : [t];
}

function showResult(r, what) {
  log.debug("Entering showResult().");
  setStatus("acdc_verify_status", r.valid ? "VALID — " + what :
            (r.revoked ? "REVOKED — " : "INVALID — ") + r.reason,
            r.valid ? "vc-ok" : "vc-error");
  renderChecks(r);
  var shown = r.acdc || (r.credential && r.credential.acdc) || r.exn;
  el("acdc_credential").textContent = shown ?
    JSON.stringify(shown, null, 2) : "";
  log.debug("Leaving showResult().");
}

function verifyStream() {
  log.debug("Entering verifyStream().");
  var schemas;
  try {
    schemas = readSchemas("acdc_schema");
  } catch (e) {
    setStatus("acdc_verify_status", "The schemas are not JSON: " + e.message,
              "vc-error");
    log.debug("Leaving verifyStream(). Bad schema.");
    return false;
  }
  var r = acdc.verifyPresentation(val("acdc_stream").trim(),
                                  { schemas: schemas });
  showResult(r, "issued by " + r.issuer + ", anchored in its KEL, not " +
             "revoked in this stream.");
  log.debug("Leaving verifyStream(). " + r.valid);
  return false;
}

function verifyGrant() {
  log.debug("Entering verifyGrant().");
  var schemas;
  try {
    schemas = readSchemas("acdc_schema");
  } catch (e) {
    setStatus("acdc_verify_status", "The schemas are not JSON: " + e.message,
              "vc-error");
    log.debug("Leaving verifyGrant(). Bad schema.");
    return false;
  }
  var r = acdc.verifyExchange(val("acdc_stream").trim(),
                              { schemas: schemas });
  showResult(r, "an IPEX grant from " + (r.exn ? r.exn.i : "") + ", signed " +
             "against its KEL, carrying a credential that verifies.");
  log.debug("Leaving verifyGrant(). " + r.valid);
  return false;
}

function intField(id, fallback) {
  log.debug("Entering intField(). " + id);
  var n = parseInt(val(id), 10);
  log.debug("Leaving intField().");
  return isNaN(n) ? fallback : n;
}

// The issue pane's options for acdc.issue().
function issueOptions(attributes) {
  log.debug("Entering issueOptions().");
  var o = { version: val("acdc_version") === "2" ? 2 : 1,
            signers: intField("acdc_signers", 1),
            witnesses: intField("acdc_witnesses", 0),
            backers: intField("acdc_backers", 0),
            delegated: el("acdc_delegated").checked };
  var toad = intField("acdc_toad", null);
  if (toad !== null) {
    o.toad = toad;
  }
  var kt = val("acdc_kt").trim();
  if (kt) {
    o.kt = kt.charAt(0) === "[" ? JSON.parse(kt) : kt;
    o.nt = o.kt;
  }
  if (o.backers && o.version === 2) {
    throw new Error("backer registries are version 1 (bis/brv); a version " +
                    "2 registry is rip/upd.");
  }
  if (el("acdc_aggregate").checked) {
    o.aggregate = Object.keys(attributes).map(function (k) {
      var b = {};
      b[k] = attributes[k];
      return b;
    });
  } else {
    o.attributes = attributes;
  }
  var recipient = val("acdc_recipient").trim();
  if (recipient) {
    o.recipient = recipient;
  }
  log.debug("Leaving issueOptions().");
  return o;
}

function issueCredential() {
  log.debug("Entering issueCredential().");
  var attributes;
  var o;
  try {
    attributes = JSON.parse(val("acdc_attributes") || "{}");
    if (!attributes || typeof attributes !== "object" ||
        Array.isArray(attributes)) {
      throw new Error("the attributes are a JSON object.");
    }
    o = issueOptions(attributes);
  } catch (e) {
    setStatus("acdc_issue_status", "Not issued: " + e.message, "vc-error");
    log.debug("Leaving issueCredential(). Bad input.");
    return false;
  }
  var parent = null;
  try {
    if (el("acdc_chain").checked) {
      var delegator = o.delegated ? acdc.makeController({ gen: o.version }) :
          null;
      var ctl = acdc.makeController({ gen: o.version, signers: o.signers,
        kt: o.kt, nt: o.nt, witnesses: o.witnesses, toad: o.toad,
        delegator: delegator });
      parent = acdc.issue({ version: o.version, recipient: ctl.prefix,
                            attributes: { role: "parent" } });
      o.issuer = ctl;
      o.edges = { parent: parent };
    }
    lastIssued = acdc.issue(o);
  } catch (e) {
    setStatus("acdc_issue_status", "Not issued: " + e.message, "vc-error");
    log.debug("Leaving issueCredential(). Refused.");
    return false;
  }
  lastIssued.parent = parent;
  lastStream = (parent ? parent.stream : "") + lastIssued.stream;
  setVal("acdc_issue_output", lastStream);
  setVal("acdc_issue_schema", parent ? JSON.stringify([parent.schema,
    lastIssued.schema]) : JSON.stringify(lastIssued.schema));
  setStatus("acdc_issue_status", "Issued by " + lastIssued.ctl.prefix +
            " (CESR version " + lastIssued.gen + "): its KEL, the registry, " +
            "the issuance and the ACDC " + lastIssued.acdc.d +
            (parent ? ", after the parent credential it chains to" : "") +
            ". The keys are not kept.", "vc-ok");
  log.debug("Leaving issueCredential().");
  return false;
}

function revokeCredential() {
  log.debug("Entering revokeCredential().");
  if (!lastIssued) {
    setStatus("acdc_issue_status", "Issue a credential first: only this " +
              "page's issuer can revoke what it issued.", "vc-error");
    log.debug("Leaving revokeCredential(). Nothing issued.");
    return false;
  }
  if (lastIssued.revoked) {
    setStatus("acdc_issue_status", "Already revoked.", "vc-error");
    log.debug("Leaving revokeCredential(). Again.");
    return false;
  }
  var stream = acdc.revoke(lastIssued);
  lastIssued.revoked = true;
  lastStream = (lastIssued.parent ? lastIssued.parent.stream : "") + stream;
  setVal("acdc_issue_output", lastStream);
  setStatus("acdc_issue_status", "Revoked: " + (lastIssued.gen === 2 ?
            "an upd with ts revoked" : "a rev") + " in the registry, " +
            "anchored by a further ixn, appended to the stream.", "vc-ok");
  log.debug("Leaving revokeCredential().");
  return false;
}

function grantCredential() {
  log.debug("Entering grantCredential().");
  if (!lastIssued) {
    setStatus("acdc_issue_status", "Issue a credential first.", "vc-error");
    log.debug("Leaving grantCredential(). Nothing issued.");
    return false;
  }
  var g;
  try {
    if (!lastIssued.acdc.a || !lastIssued.acdc.a.i) {
      throw new Error("a grant goes to the credential's issuee: issue it " +
                      "with an Issuee AID.");
    }
    g = acdc.grant(lastIssued);
  } catch (e) {
    setStatus("acdc_issue_status", "No grant: " + e.message, "vc-error");
    log.debug("Leaving grantCredential(). Refused.");
    return false;
  }
  lastStream += g.text;
  setVal("acdc_issue_output", lastStream);
  setStatus("acdc_issue_status", "Granted: an IPEX grant " + g.exn.d +
            " to " + g.exn.a.i + " appended. Verify it with \"Verify IPEX " +
            "Grant\".", "vc-ok");
  log.debug("Leaving grantCredential().");
  return false;
}

function verifyIssued() {
  log.debug("Entering verifyIssued().");
  setVal("acdc_stream", val("acdc_issue_output"));
  setVal("acdc_schema", val("acdc_issue_schema"));
  log.debug("Leaving verifyIssued().");
  return verifyStream();
}

function discloseBlocks() {
  log.debug("Entering discloseBlocks().");
  if (!lastIssued || !Array.isArray(lastIssued.acdc.A)) {
    setStatus("acdc_disclose_status", "Issue a credential with " +
              "\"Aggregate\" first.", "vc-error");
    log.debug("Leaving discloseBlocks(). No aggregate.");
    return false;
  }
  var indices = val("acdc_disclose_indices").split(",").map(function (x) {
    return parseInt(x.trim(), 10);
  }).filter(function (n) {
    return n >= 1 && n < lastIssued.acdc.A.length;
  });
  var body = acdc.discloseAggregate(lastIssued.acdc, indices);
  setVal("acdc_disclose_output", lastStream.replace(
    JSON.stringify(lastIssued.acdc), body));
  setStatus("acdc_disclose_status", "Disclosed block(s) " +
            (indices.join(", ") || "none") + " of " +
            (lastIssued.acdc.A.length - 1) + "; the others are their SAIDs." +
            (lastIssued.gen === 2 ? "" : " (Version 1 SAIDs are over the " +
             "full form, so this variant will not verify.)"), "vc-ok");
  log.debug("Leaving discloseBlocks().");
  return false;
}

function verifyDisclosed() {
  log.debug("Entering verifyDisclosed().");
  setVal("acdc_stream", val("acdc_disclose_output"));
  setVal("acdc_schema", val("acdc_issue_schema"));
  log.debug("Leaving verifyDisclosed().");
  return verifyStream();
}

module.exports = {
  togglePane: togglePane,
  verifyStream: verifyStream,
  verifyGrant: verifyGrant,
  issueCredential: issueCredential,
  revokeCredential: revokeCredential,
  grantCredential: grantCredential,
  verifyIssued: verifyIssued,
  discloseBlocks: discloseBlocks,
  verifyDisclosed: verifyDisclosed
};
