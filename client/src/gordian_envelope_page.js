// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: gordian_envelope_page.js
//
// ---------------------------------------------------------------------------
// gordian-envelope.html (#480): read a Gordian Envelope credential, verify
// its issuer's signature, present it with chosen claims elided, and issue
// one; encrypt, compress, split into SSKR shares and send as multi-part
// URs. The work is gordian_envelope.js, gordian_envelope_crypto.js, sskr.js
// and bc_ur.js; this file is the DOM.
//
// NOTHING ON THIS PAGE IS STORED: the issuer's seed, content keys, private
// keys and passwords live in their fields for this page load only. Every
// value shown came from pasted text, so it is written with textContent.
// ---------------------------------------------------------------------------

var ge = require("./gordian_envelope");
var gc = require("./gordian_envelope_crypto");
var bcur = require("./bc_ur");
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
  var parts = String(val("ge_input")).trim().split(/\s+/).length;
  setStatus("ge_read_status", "Read" + (parts > 1 ? " from " + parts +
            " parts of a multi-part UR" : "") + ". Root digest " +
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
  var scheme = val("ge_scheme") || "schnorr";
  if (ge.isMldsa(scheme)) {
    log.debug("Leaving keyFromPage(). ML-DSA.");
    return ge.mldsaKeyPair(scheme, ge.signingKeyFromSeed(seed));
  }
  if (scheme === "ssh-ed25519") {
    log.debug("Leaving keyFromPage(). SSH.");
    return ge.sshEd25519FromSeed(seed);
  }
  log.debug("Leaving keyFromPage().");
  return { scheme: scheme, privateKey: ge.signingKeyFromSeed(seed) };
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

// ---------------------------------------------------------------------------
// The obscuring panes. Each reads its own Envelope field and writes a
// Result that "Read It" hands to the first pane.
// ---------------------------------------------------------------------------

function readField(id) {
  log.debug("Entering readField(). " + id);
  var text = String(val(id)).trim();
  if (!text) {
    log.debug("Leaving readField(). Empty.");
    throw new Error("paste an envelope first.");
  }
  log.debug("Leaving readField().");
  return ge.read(text);
}

function showResult(outId, notationId, e) {
  log.debug("Entering showResult(). " + outId);
  setVal(outId, ge.toUr(e));
  if (notationId) setPre(notationId, ge.notation(e));
  log.debug("Leaving showResult().");
}

function readResult(id) {
  log.debug("Entering readResult(). " + id);
  setVal("ge_input", val(id));
  readEnvelope();
  var pane = el("ge_read_fieldset");
  if (pane) pane.style.display = "block";
  log.debug("Leaving readResult().");
  return false;
}

function digestNote(a, b) {
  log.debug("Entering digestNote().");
  var same = cbytes.bytesEqual(a.digest, b.digest);
  log.debug("Leaving digestNote(). " + same);
  return same ? " The digest is unchanged (" +
    cbytes.bytesToHex(b.digest).slice(0, 8) + "…)." :
    " The digest CHANGED — this should not happen.";
}

// Let a status line paint before a slow step (Argon2id, scrypt).
function later(statusId, fn) {
  log.debug("Entering later(). " + statusId);
  setStatus(statusId, "Working…", "");
  setTimeout(fn, 10);
  log.debug("Leaving later().");
  return false;
}

function generateContentKey() {
  log.debug("Entering generateContentKey().");
  setVal("ge_enc_key", gc.keyUr(gc.generateKey()));
  log.debug("Leaving generateContentKey().");
  return false;
}

function lines(id) {
  log.debug("Entering lines(). " + id);
  var out = String(val(id)).split(/\s+/).filter(Boolean);
  log.debug("Leaving lines(). " + out.length);
  return out;
}

function doEncrypt() {
  log.debug("Entering doEncrypt().");
  var out;
  var said = [];
  try {
    var env = readField("ge_enc_input");
    var wrapFirst = el("ge_enc_wrap") && el("ge_enc_wrap").checked;
    var target = wrapFirst ? ge.wrap(env) : env;
    if (!String(val("ge_enc_key")).trim()) generateContentKey();
    var key = gc.readKey(val("ge_enc_key"));
    out = gc.encryptSubject(target, key);
    lines("ge_enc_recipients").forEach(function (r) {
      out = gc.addRecipient(out, gc.readPublicKeys(r), key);
    });
    if (gc.recipients(out).length) {
      said.push(gc.recipients(out).length + " recipient(s)");
    }
    if (val("ge_enc_password")) {
      out = gc.addSecret(out, val("ge_enc_kdf") || "argon2id",
                         cbytes.strBytes(val("ge_enc_password")), key);
      said.push("a " + (val("ge_enc_kdf") || "argon2id") + " password lock");
    }
    showResult("ge_enc_output", "ge_enc_notation", out);
    setStatus("ge_enc_status", "Encrypted " + (wrapFirst ? "(wrapped " +
              "first, so the assertions are hidden too)" : "(the subject " +
              "only)") + (said.length ? ", with " + said.join(" and ") :
              "") + "." + digestNote(ge.subjectOf(target),
                                     ge.subjectOf(out)), "vc-ok");
  } catch (e) {
    setStatus("ge_enc_status", "Not encrypted: " + e.message, "vc-error");
    log.debug("Leaving doEncrypt(). Failed.");
    return;
  }
  log.debug("Leaving doEncrypt().");
}

function encryptEnvelope() {
  log.debug("Entering encryptEnvelope().");
  log.debug("Leaving encryptEnvelope().");
  return later("ge_enc_status", doEncrypt);
}

function doDecrypt() {
  log.debug("Entering doDecrypt().");
  var out;
  var how;
  try {
    var env = readField("ge_enc_input");
    if (val("ge_enc_password")) {
      out = gc.unlockSubject(env, cbytes.strBytes(val("ge_enc_password")));
      how = "with the password";
    } else if (String(val("ge_enc_private_keys")).trim()) {
      out = gc.decryptSubjectToRecipient(env,
        gc.readPrivateKeys(val("ge_enc_private_keys")));
      how = "as a recipient";
    } else if (String(val("ge_enc_key")).trim()) {
      out = gc.decryptSubject(env, gc.readKey(val("ge_enc_key")));
      how = "with the content key";
    } else {
      throw new Error("give the content key, the private keys of a " +
                      "recipient, or the password.");
    }
    var unwrapped = false;
    if (out.kind === "wrapped" && el("ge_enc_wrap") &&
        el("ge_enc_wrap").checked) {
      out = out.envelope;
      unwrapped = true;
    }
    showResult("ge_enc_output", "ge_enc_notation", out);
    setStatus("ge_enc_status", "Decrypted " + how + (unwrapped ? ", and " +
              "unwrapped" : "") + "." + (unwrapped ? "" :
              digestNote(env, out)), "vc-ok");
  } catch (e) {
    setStatus("ge_enc_status", "Not decrypted: " + e.message, "vc-error");
    log.debug("Leaving doDecrypt(). Failed.");
    return;
  }
  log.debug("Leaving doDecrypt().");
}

function decryptEnvelope() {
  log.debug("Entering decryptEnvelope().");
  log.debug("Leaving decryptEnvelope().");
  return later("ge_enc_status", doDecrypt);
}

function makeRecipientKeys() {
  log.debug("Entering makeRecipientKeys().");
  try {
    var scheme = val("ge_kp_scheme") || "x25519";
    var seedHex = String(val("ge_kp_seed")).replace(/\s+/g, "");
    var seed = seedHex ? cbytes.hexToBytes(seedHex) : cbytes.randomBytes(16);
    if (seed.length < 16) throw new Error("the seed is at least 16 bytes.");
    var keys = gc.privateKeysFromSeed(seed);
    if (scheme !== "x25519") keys.encapsulation = gc.mlkemKeyPair(scheme);
    var pub = gc.publicKeysUr(gc.publicKeysOf(keys));
    setVal("ge_kp_seed", cbytes.bytesToHex(seed));
    setVal("ge_kp_public", pub);
    setVal("ge_enc_private_keys", gc.privateKeysUr(keys));
    setVal("ge_enc_recipients", (String(val("ge_enc_recipients")).trim() ?
      String(val("ge_enc_recipients")).trim() + "\n" : "") + pub);
    setStatus("ge_enc_status", "Made a " + scheme + " recipient: its public " +
              "keys are in Recipients, its private keys in Private keys " +
              "(neither is stored).", "vc-ok");
  } catch (e) {
    setStatus("ge_enc_status", "No keys: " + e.message, "vc-error");
  }
  log.debug("Leaving makeRecipientKeys().");
  return false;
}

function compressEnvelope() {
  log.debug("Entering compressEnvelope().");
  try {
    var env = readField("ge_comp_input");
    var subj = el("ge_comp_subject") && el("ge_comp_subject").checked;
    var out = subj ? gc.compressSubject(env) : gc.compress(env);
    var c = gc.readCompressed(ge.subjectOf(out).cbor);
    showResult("ge_comp_output", null, out);
    setStatus("ge_comp_status", "Compressed " + (subj ? "the subject" :
              "the envelope") + ": " + c.size + " bytes of CBOR in " +
              c.data.length + (c.data.length === c.size ? " (DEFLATE would " +
              "not shrink them, so they are stored as they are)" : "") + "." +
              digestNote(env, out), "vc-ok");
  } catch (e) {
    setStatus("ge_comp_status", "Not compressed: " + e.message, "vc-error");
  }
  log.debug("Leaving compressEnvelope().");
  return false;
}

function decompressEnvelope() {
  log.debug("Entering decompressEnvelope().");
  try {
    var env = readField("ge_comp_input");
    var out = env.kind === "compressed" ? gc.decompress(env) :
        gc.decompressSubject(env);
    if (out === env) throw new Error("nothing in it is compressed.");
    showResult("ge_comp_output", null, out);
    setStatus("ge_comp_status", "Decompressed; the CRC-32 and the digest " +
              "check." + digestNote(env, out), "vc-ok");
  } catch (e) {
    setStatus("ge_comp_status", "Not decompressed: " + e.message,
              "vc-error");
  }
  log.debug("Leaving decompressEnvelope().");
  return false;
}

function splitEnvelope() {
  log.debug("Entering splitEnvelope().");
  try {
    var env = readField("ge_sskr_input");
    var groups = String(val("ge_sskr_groups")).split(/[,;]/)
      .map(function (g) {
        return g.trim();
      }).filter(Boolean);
    var r = gc.splitEnvelope(env, parseInt(val("ge_sskr_threshold"), 10) ||
                             1, groups);
    setVal("ge_sskr_shares", r.shares.map(ge.toUr).join("\n"));
    setStatus("ge_sskr_status", "Split into " + r.shares.length +
              " share envelope(s) in " + r.groups.length + " group(s) (" +
              groups.join(", ") + "; " + (parseInt(val("ge_sskr_threshold"),
              10) || 1) + " group(s) needed). The content key is not kept.",
              "vc-ok");
  } catch (e) {
    setStatus("ge_sskr_status", "Not split: " + e.message, "vc-error");
  }
  log.debug("Leaving splitEnvelope().");
  return false;
}

function joinShares() {
  log.debug("Entering joinShares().");
  try {
    var shares = lines("ge_sskr_shares").map(function (t) {
      return ge.read(t);
    });
    var out = gc.joinEnvelope(shares);
    setVal("ge_sskr_output", ge.toUr(out));
    setStatus("ge_sskr_status", "Joined from " + shares.length +
              " share(s). Root digest " +
              cbytes.bytesToHex(out.digest).slice(0, 8) + "….", "vc-ok");
  } catch (e) {
    setStatus("ge_sskr_status", "Not joined: " + e.message, "vc-error");
  }
  log.debug("Leaving joinShares().");
  return false;
}

function encodeParts() {
  log.debug("Entering encodeParts().");
  try {
    var env = readField("ge_parts_input");
    var max = parseInt(val("ge_parts_max"), 10) || 100;
    var extra = Math.max(0, parseInt(val("ge_parts_extra"), 10) || 0);
    var enc = new bcur.MultipartEncoder("envelope",
                                        ge.encode(ge.toCbor(env)), max);
    var n = enc.fragmentCount();
    var parts = [];
    for (var i = 0; i < n + extra; i++) parts.push(enc.nextPart());
    setVal("ge_parts_list", parts.join("\n"));
    setStatus("ge_parts_status", n + " fragment(s) of at most " + max +
              " bytes, and " + extra + " fountain part(s) after them.",
              "vc-ok");
  } catch (e) {
    setStatus("ge_parts_status", "No parts: " + e.message, "vc-error");
  }
  log.debug("Leaving encodeParts().");
  return false;
}

function decodeParts() {
  log.debug("Entering decodeParts().");
  try {
    var text = lines("ge_parts_list").join("\n");
    var d = bcur.decodeAny(text);
    if (d.type !== "envelope") {
      throw new Error("ur:" + d.type + " is not an envelope.");
    }
    var env = ge.fromCbor(ge.decode(d.body));
    setVal("ge_parts_output", ge.toUr(env));
    setStatus("ge_parts_status", "Rebuilt from " + d.parts + " part(s) (" +
              d.fragments + " fragment(s)). Root digest " +
              cbytes.bytesToHex(env.digest).slice(0, 8) + "….", "vc-ok");
  } catch (e) {
    setStatus("ge_parts_status", "Not rebuilt: " + e.message, "vc-error");
  }
  log.debug("Leaving decodeParts().");
  return false;
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
  readIssued: readIssued,
  readResult: readResult,
  generateContentKey: generateContentKey,
  encryptEnvelope: encryptEnvelope,
  decryptEnvelope: decryptEnvelope,
  makeRecipientKeys: makeRecipientKeys,
  compressEnvelope: compressEnvelope,
  decompressEnvelope: decompressEnvelope,
  splitEnvelope: splitEnvelope,
  joinShares: joinShares,
  encodeParts: encodeParts,
  decodeParts: decodeParts
};
