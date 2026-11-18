// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: acdc_page.js
//
// ---------------------------------------------------------------------------
// acdc.html (#480): verify an ACDC presentation stream — the issuer's KEL,
// its registry, the credential's issuance (and revocation) events and the
// credential — and issue one. The work is acdc.js; this file is the DOM.
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
  if (e) e.value = v;
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
  if (fs) fs.style.display = fs.style.display === "none" ? "block" : "none";
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

function verifyStream() {
  log.debug("Entering verifyStream().");
  var schema;
  if (val("acdc_schema").trim()) {
    try {
      schema = JSON.parse(val("acdc_schema"));
    } catch (e) {
      setStatus("acdc_verify_status", "The schema is not JSON: " + e.message,
                "vc-error");
      log.debug("Leaving verifyStream(). Bad schema.");
      return false;
    }
  }
  var r = acdc.verifyPresentation(val("acdc_stream").trim(),
                                  { schema: schema });
  setStatus("acdc_verify_status", r.valid ? "VALID — issued by " + r.issuer +
            ", anchored in its KEL, not revoked in this stream." :
            (r.revoked ? "REVOKED — " : "INVALID — ") + r.reason,
            r.valid ? "vc-ok" : "vc-error");
  renderChecks(r);
  el("acdc_credential").textContent = r.acdc ?
    JSON.stringify(r.acdc, null, 2) : "";
  log.debug("Leaving verifyStream(). " + r.valid);
  return false;
}

function issueCredential() {
  log.debug("Entering issueCredential().");
  var attributes;
  try {
    attributes = JSON.parse(val("acdc_attributes") || "{}");
    if (!attributes || typeof attributes !== "object" ||
        Array.isArray(attributes)) {
      throw new Error("the attributes are a JSON object.");
    }
  } catch (e) {
    setStatus("acdc_issue_status", "Not issued: " + e.message, "vc-error");
    log.debug("Leaving issueCredential(). Bad attributes.");
    return false;
  }
  var recipient = val("acdc_recipient").trim();
  lastIssued = acdc.issue({ attributes: attributes,
                            recipient: recipient || undefined });
  setVal("acdc_issue_output", lastIssued.stream);
  setVal("acdc_issue_schema", JSON.stringify(lastIssued.schema));
  setStatus("acdc_issue_status", "Issued by " + lastIssued.icp.i + ": its " +
            "KEL (icp and two ixn), the registry (vcp), the iss and the " +
            "ACDC " + lastIssued.acdc.d + ". The keys are not kept.",
            "vc-ok");
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
  setVal("acdc_issue_output", acdc.revoke(lastIssued));
  setStatus("acdc_issue_status", "Revoked: a rev in the registry, anchored " +
            "by a further ixn, appended to the stream.", "vc-ok");
  log.debug("Leaving revokeCredential().");
  return false;
}

function verifyIssued() {
  log.debug("Entering verifyIssued().");
  setVal("acdc_stream", val("acdc_issue_output"));
  setVal("acdc_schema", val("acdc_issue_schema"));
  log.debug("Leaving verifyIssued().");
  return verifyStream();
}

module.exports = {
  togglePane: togglePane,
  verifyStream: verifyStream,
  issueCredential: issueCredential,
  revokeCredential: revokeCredential,
  verifyIssued: verifyIssued
};
