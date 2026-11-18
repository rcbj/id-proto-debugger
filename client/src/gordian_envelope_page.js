// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: gordian_envelope_page.js
//
// ---------------------------------------------------------------------------
// gordian-envelope.html (#480): read a Gordian Envelope credential, verify
// its issuer's signature, present it with chosen claims elided, and issue
// one. The work is gordian_envelope.js; this file is the DOM.
//
// NOTHING ON THIS PAGE IS STORED, the issuer's seed included. Every value
// shown came from pasted text, so it is written with textContent.
// ---------------------------------------------------------------------------

var ge = require("./gordian_envelope");
var cbytes = require("./crypto_bytes");

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "gordian_envelope_page",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// bc-envelope's test credential, as its tests build it (the issuer key is
// derived from the tests' "Alice" seed, which is public).
var EXAMPLE_SEED = "82f32c855d3d542256180810797e0073";
var EXAMPLE_CLAIMS = [
  "'isA': Certificate of Completion",
  "'issuer': Example Electrical Engineering Board",
  "'controller': Example Electrical Engineering Board",
  "firstName: James", "lastName: Maxwell", "issueDate: date 2020-01-01",
  "expirationDate: date 2028-01-01",
  "photo: This is James Maxwell's photo.",
  "certificateNumber: 123-456-789",
  "subject: RF and Microwave Engineering",
  "continuingEducationUnits: 1", "professionalDevelopmentHours: 15"
].join("\n");

var current = null;

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

function setPre(id, text) {
  log.debug("Entering setPre(). " + id);
  var e = el(id);
  if (e) e.textContent = text;
  log.debug("Leaving setPre().");
}

function togglePane(id) {
  log.debug("Entering togglePane(). " + id);
  var fs = el(id);
  if (fs) fs.style.display = fs.style.display === "none" ? "block" : "none";
  log.debug("Leaving togglePane().");
  return false;
}

// ---------------------------------------------------------------------------
// Reading, verifying and presenting.
// ---------------------------------------------------------------------------

function renderClaims(env) {
  log.debug("Entering renderClaims().");
  var host = el("ge_claims");
  host.textContent = "";
  var c = ge.claims(env);
  if (!c.subject) {
    host.textContent = "Not a signed credential (a wrapped subject under a " +
      "'signed' assertion), so there are no claims to choose from.";
    log.debug("Leaving renderClaims(). Not a credential.");
    return;
  }
  c.claims.forEach(function (claim, i) {
    var row = document.createElement("label");
    row.className = "ge-claim";
    var box = document.createElement("input");
    box.type = "checkbox";
    box.id = "ge_claim_" + i;
    box.value = claim.digest;
    box.checked = !claim.elided;
    box.disabled = claim.elided;
    row.appendChild(box);
    row.appendChild(document.createTextNode(" " + claim.label +
      (claim.salted ? "  (salted)" : "") + "  " +
      claim.digest.slice(0, 8)));
    host.appendChild(row);
  });
  log.debug("Leaving renderClaims().");
}

function readEnvelope() {
  log.debug("Entering readEnvelope().");
  try {
    current = ge.read(val("ge_input"));
  } catch (e) {
    current = null;
    setStatus("ge_read_status", "Not read: " + e.message, "vc-error");
    setPre("ge_notation", "");
    setPre("ge_tree", "");
    el("ge_claims").textContent = "";
    log.debug("Leaving readEnvelope(). Unreadable.");
    return false;
  }
  setStatus("ge_read_status", "Read. Root digest " +
            cbytes.bytesToHex(current.digest) + ".", "vc-ok");
  setPre("ge_notation", ge.notation(current));
  setPre("ge_tree", ge.tree(current));
  renderClaims(current);
  log.debug("Leaving readEnvelope().");
  return false;
}

function verifyEnvelope() {
  log.debug("Entering verifyEnvelope().");
  if (!current) readEnvelope();
  if (!current) {
    log.debug("Leaving verifyEnvelope(). Nothing read.");
    return false;
  }
  var pub;
  try {
    pub = ge.readPublicKey(val("ge_public_key"));
  } catch (e) {
    setStatus("ge_verify_status", "The issuer key: " + e.message, "vc-error");
    log.debug("Leaving verifyEnvelope(). Bad key.");
    return false;
  }
  var r = ge.verifySignatures(current, pub);
  setStatus("ge_verify_status", r.valid ? "VALID — a " + pub.scheme +
            " signature by this key over the subject's digest " +
            cbytes.bytesToHex(r.signedDigest).slice(0, 8) + "… (every claim " +
            "under it, elided or not, is covered)." : "INVALID — " + r.reason,
            r.valid ? "vc-ok" : "vc-error");
  log.debug("Leaving verifyEnvelope(). " + r.valid);
  return false;
}

function presentEnvelope() {
  log.debug("Entering presentEnvelope().");
  if (!current) {
    log.debug("Leaving presentEnvelope(). Nothing read.");
    return false;
  }
  var keep = Array.prototype.slice.call(document.querySelectorAll(
    "#ge_claims input[type=checkbox]")).filter(function (b) {
    return b.checked && !b.disabled;
  }).map(function (b) {
    return b.value;
  });
  var shown = ge.present(current, keep);
  setVal("ge_presentation", ge.toUr(shown));
  setPre("ge_presentation_notation", ge.notation(shown));
  var same = cbytes.bytesEqual(shown.digest, current.digest);
  setStatus("ge_present_status", (same ? "The root digest is unchanged, so " +
            "the issuer's signature still verifies. " : "The root digest " +
            "CHANGED — this should not happen. ") + keep.length + " claim(s) " +
            "disclosed.", same ? "vc-ok" : "vc-error");
  log.debug("Leaving presentEnvelope(). " + keep.length);
  return false;
}

// Hand the presentation back to the read pane.
function readPresentation() {
  log.debug("Entering readPresentation().");
  setVal("ge_input", val("ge_presentation"));
  readEnvelope();
  log.debug("Leaving readPresentation().");
  return verifyEnvelope();
}

// ---------------------------------------------------------------------------
// Issuing.
// ---------------------------------------------------------------------------

// "predicate: value" per line. A predicate in single quotes is a known
// value ('isA'); a value "date YYYY-MM-DD" is a Date, an integer is a
// number, anything else text.
function parseClaims(text) {
  log.debug("Entering parseClaims().");
  var out = String(text || "").split(/\r?\n/).filter(function (l) {
    return l.trim();
  }).map(function (line, i) {
    var at = line.indexOf(":");
    if (at < 1) {
      throw new Error("line " + (i + 1) + " is not \"predicate: value\".");
    }
    var p = line.slice(0, at).trim();
    var v = line.slice(at + 1).trim();
    var predicate = /^'.*'$/.test(p) ? ge.knownValue(p.slice(1, -1)) :
        ge.leaf(p);
    var m = /^date (\d{4}-\d{2}-\d{2})$/.exec(v);
    var object = m ? ge.leaf(new ge.Tagged(ge.TAG.DATE,
                                           Date.parse(m[1]) / 1000)) :
        /^-?\d+$/.test(v) ? ge.leaf(parseInt(v, 10)) : ge.leaf(v);
    return [predicate, object];
  });
  log.debug("Leaving parseClaims(). " + out.length);
  return out;
}

function keyFromPage() {
  log.debug("Entering keyFromPage().");
  var seed = cbytes.hexToBytes(val("ge_seed").replace(/\s+/g, ""));
  if (seed.length < 16) {
    log.debug("Leaving keyFromPage(). Short seed.");
    throw new Error("the seed is at least 16 bytes of hex (press Generate).");
  }
  log.debug("Leaving keyFromPage().");
  return { scheme: val("ge_scheme") || "schnorr",
           privateKey: ge.signingKeyFromSeed(seed) };
}

function generateSeed() {
  log.debug("Entering generateSeed().");
  setVal("ge_seed", cbytes.bytesToHex(cbytes.randomBytes(16)));
  showIssuerKey();
  log.debug("Leaving generateSeed().");
  return false;
}

function showIssuerKey() {
  log.debug("Entering showIssuerKey().");
  try {
    setVal("ge_issuer_public_key", ge.publicKeyUr(ge.publicKeyOf(
      keyFromPage())));
  } catch (e) {
    setVal("ge_issuer_public_key", "");
  }
  log.debug("Leaving showIssuerKey().");
  return false;
}

function loadExample() {
  log.debug("Entering loadExample().");
  setVal("ge_seed", EXAMPLE_SEED);
  setVal("ge_scheme", "schnorr");
  setVal("ge_subject_arid", "4676635a6e6068c2ef3ffd8ff726dd401fd341036e9" +
         "20f136a1d8af5e829496d");
  setVal("ge_issue_claims", EXAMPLE_CLAIMS);
  setVal("ge_note", "Signed by Example Electrical Engineering Board");
  showIssuerKey();
  log.debug("Leaving loadExample().");
  return false;
}

function issueEnvelope() {
  log.debug("Entering issueEnvelope().");
  var out;
  try {
    var key = keyFromPage();
    var arid = val("ge_subject_arid").replace(/\s+/g, "");
    var subject = ge.leaf(new ge.Tagged(ge.TAG.ARID, arid ?
      cbytes.hexToBytes(arid) : cbytes.randomBytes(32)));
    var salt = el("ge_salt") && el("ge_salt").checked;
    var cred = subject;
    parseClaims(val("ge_issue_claims")).forEach(function (pair) {
      cred = ge.addAssertion(cred, salt ? ge.saltedAssertion(pair[0],
        pair[1], cbytes.randomBytes(8)) : ge.assertion(pair[0], pair[1]));
    });
    out = ge.sign(cred, key);
    if (val("ge_note").trim()) {
      out = ge.addAssertion(out, ge.knownValue("note"), val("ge_note"));
    }
    showIssuerKey();
  } catch (e) {
    setStatus("ge_issue_status", "Not issued: " + e.message, "vc-error");
    log.debug("Leaving issueEnvelope(). Failed.");
    return false;
  }
  setVal("ge_issue_output", ge.toUr(out));
  setStatus("ge_issue_status", "Issued: wrapped, then signed (" +
            val("ge_scheme") + "), so every claim is under the signature; " +
            "the note is not.", "vc-ok");
  log.debug("Leaving issueEnvelope().");
  return false;
}

// Hand the issued credential and its key to the read pane.
function readIssued() {
  log.debug("Entering readIssued().");
  setVal("ge_input", val("ge_issue_output"));
  setVal("ge_public_key", val("ge_issuer_public_key"));
  readEnvelope();
  log.debug("Leaving readIssued().");
  return verifyEnvelope();
}

module.exports = {
  togglePane: togglePane,
  readEnvelope: readEnvelope,
  verifyEnvelope: verifyEnvelope,
  presentEnvelope: presentEnvelope,
  readPresentation: readPresentation,
  generateSeed: generateSeed,
  showIssuerKey: showIssuerKey,
  loadExample: loadExample,
  issueEnvelope: issueEnvelope,
  readIssued: readIssued
};
