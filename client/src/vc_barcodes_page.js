// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: vc_barcodes_page.js
//
// ---------------------------------------------------------------------------
// vc-barcodes.html (#480): read and verify a VC barcode — the QR code beside
// an MRZ, the credential inside an AAMVA PDF417, or (Appendix B) an ISO
// licence's DG11 — check the status list its terse entry expands to, and
// issue one. The work is vc_barcodes.js and cborld.js, pdf417.js for the
// PDF417 symbols and vp_verifier.js's Bitstring Status List reader (the
// Verifier role's, so the two pages cannot disagree about a list); this
// file is the DOM.
//
// NOTHING ON THIS PAGE IS STORED. The issuer's private key in particular
// lives in the text box for the length of the page load: a barcode is
// issued once and printed, and a key kept in a browser for that is a key
// kept for no reason. Download it if you need it again.
//
// Every value shown came from a pasted or scanned barcode, so it is written
// with textContent and never as markup.
// ---------------------------------------------------------------------------

var vcb = require("./vc_barcodes");
var cborld = require("./cborld");
require("./data_integrity_rdfc");
var provider = require("./crypto_provider");
var cbytes = require("./crypto_bytes");
var didLib = require("./did");
var qrcode = require("qrcode-generator");
var jsQR = require("jsqr");
var pdf417 = require("./pdf417");
var vpVerifier = require("./vp_verifier");

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "vc_barcodes_page",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// The specification's two Utopia examples (VC Barcodes Appendix C), so the
// page can be tried with nothing in hand.
var EXAMPLES = {
  ead: {
    barcode: "VC1-R0OR*W3Y33V%K PG88G3A3B60A8G1534KG$-ENXKWQN053653Y53I53 " +
      "539*K0XJ.TDYOQJ63P63L6337BPMFPCP7EH2R12YH%%EXU4$08E-D8D86F8E2HX:" +
      "T8Z8/ 1TZEH.QBA03Q5W.I0N6FBF4E3:SOQU8. A3MSELNHFU0GCVVBP6LU9T%ES-3",
    mrz: "IAUTO0000007010SRC0000000701<<\n8804192M2601058NOT<<<<<<<<<<<5\n" +
      "SMITH<<JOHN<<<<<<<<<<<<<<<<<<<",
    aamva: ""
  },
  dl: {
    barcode: "@\n\x1e\rANSI 000000090002DL00410234ZZ02750202DLDAQF987654321" +
      "\nDCSSMITH\nDDEN\nDACJOHN\nDDFN\nDADNONE\nDDGN\nDCAC\nDCBNONE\n" +
      "DCDNONE\nDBD01012024\nDBB04191988\nDBA04192030\nDBC1\nDAU069 IN\n" +
      "DAYBRO\nDAG123 MAIN ST\nDAIANYVILLE\nDAJUTO\nDAKF87P20000  \n" +
      "DCFUTODOCDISCRIM\nDCGUTO\nDAW158\nDCK1234567890\nDDAN\rZZZZA2csdghh" +
      "kpgGDGYAAGYABGYACGJ2CGHYYpBi4oxicGKYYzhiyGNAa5ZIggRi6ohicGKAYqER1g" +
      "gAgGL4YqhjApRicGGwY1gQY4BjmGOJYQXq3wuVrSeLM5iGEziaBjhWosXMWRAG107u" +
      "T/9bSteuPasCXFQKuPdSdF+xmUoFkA0yRJoW4ERvATNyewT263ZHMGOQYrA==\r",
    mrz: "",
    aamva: ""
  },
  // Appendix B has no example, so this one was made for tests/
  // vc_barcodes_engine.js (ISO_EXAMPLE_DG11 there) by Digital Bazaar's
  // ecdsa-xi-2023-cryptosuite and cborld, on a key since discarded.
  iso: {
    barcode: "DG1: UTO\\x1dSMITH\\x1dJOHN\\x1d19880419\\x1d20240101" +
      "\\x1d20300419\\x1dUTOPIA DMV\\x1dF987654321\n" +
      "DG2: hex:fbff3ec0fe7f00ff\nDG3: BRO\\x1d069\n" +
      "DG10: ENDORSEMENTS:NONE\nDG11: " +
      "2csdghhkpQGDGYAAGYABoXgrSXNvRHJpdmluZ0xpY2VuY2VNYWNoaW5lUmVhZGFi" +
      "bGVJbmZvcm1hdGlvbnhIaHR0cHM6Ly93M2lkLm9yZy92Yy1iYXJjb2RlcyNJc29E" +
      "cml2aW5nTGljZW5jZU1hY2hpbmVSZWFkYWJsZUluZm9ybWF0aW9uGJ2CGHYYpBiy" +
      "ohicGKoYqEN1wEAYtoIZBAFYI4AkA7PTi9n4hQNhmVLLNdlG_QSgSyjM9MHACH_9" +
      "_bkzc0w3GLilGJwYbBjKBBjUGNoY1lhBeoKm-_CqGFQs0Qvw5p1jsrq1tCQEPcoo" +
      "f9GH3QtlwwSJaP19j3O0d3_psG2eHyuR5fUO4eyQ3_G8joaJ9FYfotMY2IMZBAFY" +
      "I4AkA7PTi9n4hQNhmVLLNdlG_QSgSyjM9MHACH_9_bkzc0w3WCOAJAOz04vZ-IUD" +
      "YZlSyzXZRv0EoEsozPTBwAh__f25M3NMNw",
    mrz: "",
    aamva: ""
  }
};

// What the ISO example's licence prints (everything but DG11), as the
// issue pane's default.
var SAMPLE_ISO = EXAMPLES.iso.barcode.slice(0,
  EXAMPLES.iso.barcode.indexOf("\nDG11: "));

// The last verified barcode's result, for the status pane.
var lastResult = null;

// What the AAMVA example's licence prints, as the issue pane's default.
var SAMPLE_AAMVA = EXAMPLES.dl.barcode.slice(0,
  EXAMPLES.dl.barcode.indexOf("ZZZZA"));

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

// The PDF417 text carries control characters (RS, CR) that a textarea
// would silently mangle, so it is shown and read with them escaped.
function escapeControls(text) {
  log.debug("Entering escapeControls().");
  log.debug("Leaving escapeControls().");
  return String(text).replace(/\x1e/g, "\\x1e").replace(/\r/g, "\\r\n");
}

function unescapeControls(text) {
  log.debug("Entering unescapeControls().");
  var s = String(text);
  if (s.indexOf("\\r") === -1 && s.indexOf("\\x1e") === -1) {
    log.debug("Leaving unescapeControls(). Nothing escaped.");
    return s;
  }
  log.debug("Leaving unescapeControls().");
  return s.replace(/\\r\r?\n/g, "\r").replace(/\\r/g, "\r")
    .replace(/\\x1e/g, "\x1e").replace(/\\n/g, "\n");
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

// A two-column table of [label, value] rows, written as text.
function renderRows(id, rows) {
  log.debug("Entering renderRows(). " + id);
  var host = el(id);
  if (!host) {
    log.debug("Leaving renderRows(). No host.");
    return;
  }
  host.textContent = "";
  var table = document.createElement("table");
  table.className = "vcb-result";
  rows.forEach(function (r) {
    var tr = document.createElement("tr");
    var th = document.createElement("th");
    th.textContent = r[0];
    var td = document.createElement("td");
    if (r[2] === "pre") {
      var pre = document.createElement("pre");
      pre.textContent = r[1];
      td.appendChild(pre);
    } else {
      td.textContent = r[1];
    }
    if (r[3]) td.className = r[3];
    tr.appendChild(th);
    tr.appendChild(td);
    table.appendChild(tr);
  });
  host.appendChild(table);
  log.debug("Leaving renderRows().");
}

function togglePane(id) {
  log.debug("Entering togglePane(). " + id);
  var fs = el(id);
  if (fs) fs.style.display = fs.style.display === "none" ? "block" : "none";
  log.debug("Leaving togglePane().");
  return false;
}

function loadExample(name) {
  log.debug("Entering loadExample(). " + name);
  var ex = EXAMPLES[name];
  setVal("vcb_barcode", escapeControls(ex.barcode));
  setVal("vcb_mrz", ex.mrz);
  setVal("vcb_aamva", ex.aamva);
  setVal("vcb_iso", "");
  setStatus("vcb_read_status", name === "iso" ? "Loaded an ISO licence " +
            "example (Appendix B has none of its own; this one was made " +
            "with Digital Bazaar's libraries). Press Verify." :
            "Loaded the specification's " +
            (name === "ead" ? "employment authorization document (QR " +
             "code + MRZ)" : "driver's licence (PDF417)") +
            " example. Press Verify.", "vc-pending");
  log.debug("Leaving loadExample().");
  return false;
}

// ---------------------------------------------------------------------------
// Reading.
// ---------------------------------------------------------------------------

function imagePixels(image) {
  log.debug("Entering imagePixels().");
  var w = image.naturalWidth || image.width || 800;
  var h = image.naturalHeight || image.height || 800;
  var scale = Math.max(1, Math.floor(800 / Math.max(w, h)));
  var canvas = document.createElement("canvas");
  canvas.width = w * scale;
  canvas.height = h * scale;
  var ctx = canvas.getContext("2d");
  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.imageSmoothingEnabled = false;
  ctx.drawImage(image, 0, 0, canvas.width, canvas.height);
  log.debug("Leaving imagePixels().");
  return ctx.getImageData(0, 0, canvas.width, canvas.height);
}

// A picture of a QR code or a PDF417 symbol -> its text in the barcode
// box. QR first (jsQR), then PDF417 (pdf417.js, @zxing/library).
function onImage(event) {
  log.debug("Entering onImage().");
  var file = event && event.target && event.target.files &&
      event.target.files[0];
  if (!file) {
    log.debug("Leaving onImage(). No file.");
    return false;
  }
  var url = URL.createObjectURL(file);
  var image = new Image();
  image.onload = function () {
    try {
      var px = imagePixels(image);
      var found = jsQR(px.data, px.width, px.height,
                       { inversionAttempts: "attemptBoth" });
      var text = found && found.data ? null : pdf417.readSymbol(
        pdf417.luminanceOf(px.data, px.width, px.height), px.width,
        px.height);
      if (found && found.data) {
        setVal("vcb_barcode", found.data);
        setStatus("vcb_read_status", "Read a QR code of " +
                  found.data.length + " characters from the image.",
                  "vc-ok");
      } else if (text) {
        setVal("vcb_barcode", escapeControls(text));
        setStatus("vcb_read_status", "Read a PDF417 symbol of " +
                  text.length + " characters from the image (" +
                  pdf417.DECODER + ").", "vc-ok");
      } else {
        setStatus("vcb_read_status", "No QR code or PDF417 symbol could " +
                  "be read in that image. Crop it to the symbol, or paste " +
                  "its text.", "vc-error");
      }
    } finally {
      URL.revokeObjectURL(url);
    }
  };
  image.onerror = function () {
    URL.revokeObjectURL(url);
    setStatus("vcb_read_status", "That file is not an image this browser " +
              "can draw.", "vc-error");
  };
  image.src = url;
  log.debug("Leaving onImage().");
  return false;
}

function printedFromPage() {
  log.debug("Entering printedFromPage().");
  var printed = {};
  if (val("vcb_mrz").trim()) printed.mrz = val("vcb_mrz");
  if (val("vcb_aamva").trim()) {
    printed.aamva = unescapeControls(val("vcb_aamva"));
  }
  if (val("vcb_iso").trim()) {
    printed.iso = val("vcb_iso");
  }
  log.debug("Leaving printedFromPage().");
  return printed;
}

function statusRows(result) {
  log.debug("Entering statusRows().");
  if (!result.status) {
    log.debug("Leaving statusRows(). None.");
    return [];
  }
  var listLength = parseInt(val("vcb_list_length"), 10) || Math.pow(2, 26);
  var purpose = val("vcb_status_purpose") || "revocation";
  try {
    var expanded = vcb.expandStatus(result.status, {
      listLength: listLength, statusPurpose: purpose });
    setVal("vcb_status_entry", JSON.stringify(expanded, null, 2));
    setStatus("vcb_status_status", "The entry the barcode's terse status " +
              "expands to is below. Fetch and Check, or paste the list.",
              "vc-pending");
    log.debug("Leaving statusRows().");
    return [["Status (expanded)", JSON.stringify(expanded, null, 2), "pre"]];
  } catch (e) {
    log.debug("Leaving statusRows(). Bad entry.");
    return [["Status", e.message, "", "vc-error"]];
  }
}

async function verifyBarcode() {
  log.debug("Entering verifyBarcode().");
  setStatus("vcb_read_status", "Reading…", "vc-pending");
  // ISO data groups carry their own escapes, read by vc_barcodes.js; the
  // PDF417 ones must not be applied to them first.
  var raw = val("vcb_barcode");
  var input = /^\s*DG\d+\s*[:=]/.test(raw) ? raw : unescapeControls(raw);
  var result;
  lastResult = null;
  try {
    result = await vcb.verify(input, { printed: printedFromPage() });
  } catch (e) {
    setStatus("vcb_read_status", "Could not read the barcode: " + e.message,
              "vc-error");
    renderRows("vcb_read_result", []);
    log.debug("Leaving verifyBarcode(). Unreadable.");
    return false;
  }
  setStatus("vcb_read_status", result.valid ? "VALID — " +
            (result.cryptosuite || "the proof") + " verifies" +
            (result.opticalDataBytes ? ", over the credential AND the " +
             "optical data printed on the document." : ".") :
            "INVALID — " + result.reason,
            result.valid ? "vc-ok" : "vc-error");
  var rows = [
    ["Carried as", { qr: "QR text (\"VC1-\" + multibase base45)",
                     pdf417: "PDF417 field (base64 / base64url)",
                     dg11: "ISO data group 11 (base64url; Appendix B, " +
                       "informative)",
                     hex: "hex", bytes: "bytes" }[result.carrier] ||
     result.carrier],
    ["CBOR-LD", result.format + ", registry entry " +
     result.registryEntryId + (result.registryEntryId === 100 ?
                               " (VC Barcodes)" : "") + ", " +
     result.cborld.length + " bytes"],
    ["CBOR-LD (hex)", cbytes.bytesToHex(result.cborld), "pre"],
    ["Proof", (result.proofType || "none") + (result.cryptosuite ?
     " / " + result.cryptosuite : "") + (result.proof &&
     result.proof.verificationMethod ? " by " +
     result.proof.verificationMethod : "")]
  ];
  if (result.protected) {
    var iso = (result.subjectTypes || []).indexOf(vcb.ISO_IDL) !== -1;
    rows.push([iso ? "Protected data groups" : "Protected AAMVA fields",
               result.protected.join(", ")]);
  }
  if (result.canonical !== undefined) {
    rows.push(["Optical data signed", result.canonical, "pre"]);
    rows.push(["opticalDataBytes", cbytes.bytesToHex(
      result.opticalDataBytes)]);
  }
  rows = rows.concat(statusRows(result));
  rows.push(["Credential", JSON.stringify(result.credential, null, 2),
             "pre"]);
  renderRows("vcb_read_result", rows);
  lastResult = result;
  log.debug("Leaving verifyBarcode(). " + result.valid);
  return false;
}

// The barcode box's text drawn as a PDF417 symbol, e.g. the specification's
// licence text, to print or to read back with Barcode image.
function drawReadPdf417() {
  log.debug("Entering drawReadPdf417().");
  var ok = showPdf417("vcb_read_symbol",
                      unescapeControls(val("vcb_barcode")));
  setStatus("vcb_read_status", ok ? "Drew the barcode text as a PDF417 " +
            "symbol (" + pdf417.ENCODER + ", error correction level " +
            pdf417.EC_LEVEL + ")." : "Not drawn: " +
            el("vcb_read_symbol").textContent, ok ? "vc-ok" : "vc-error");
  log.debug("Leaving drawReadPdf417().");
  return false;
}

// The text as a PDF417 symbol in the element `id`. The SVG is the
// encoder's: rectangles from the modules, none of the text.
function showPdf417(id, text) {
  log.debug("Entering showPdf417(). " + id);
  var host = el(id);
  host.textContent = "";
  if (!text) {
    log.debug("Leaving showPdf417(). Nothing.");
    return false;
  }
  try {
    host.innerHTML = pdf417.symbolSvg(text);
  } catch (e) {
    host.textContent = e.message;
    log.debug("Leaving showPdf417(). Failed.");
    return false;
  }
  log.debug("Leaving showPdf417().");
  return true;
}

// ---------------------------------------------------------------------------
// Status: the Bitstring Status List a terse entry expands to.
// ---------------------------------------------------------------------------

// fetch() from this page. A server without CORS headers fails here as a
// TypeError the browser will not explain; the message says what to do.
async function fetchStatusText(url, opts) {
  log.debug("Entering fetchStatusText(). " + url);
  var res;
  try {
    res = await fetch(url, { headers: { Accept: (opts && opts.accept) ||
                                         "application/vc" } });
  } catch (e) {
    log.debug("Leaving fetchStatusText(). Network.");
    throw new Error(e.message + " — most often a server that sends no " +
                    "CORS headers, which a page cannot read; paste the " +
                    "status list credential and press Check Pasted");
  }
  if (!res.ok) {
    log.debug("Leaving fetchStatusText(). HTTP " + res.status);
    throw new Error("HTTP " + res.status);
  }
  var body = await res.text();
  log.debug("Leaving fetchStatusText().");
  return { body: body, contentType: res.headers.get("content-type") || "" };
}

async function checkStatus(pasted) {
  log.debug("Entering checkStatus(). " + pasted);
  var entry;
  try {
    entry = JSON.parse(val("vcb_status_entry"));
  } catch (e) {
    setStatus("vcb_status_status", "There is no status entry: verify a " +
              "barcode that carries a terse status, or type one.",
              "vc-error");
    log.debug("Leaving checkStatus(). No entry.");
    return false;
  }
  var list = val("vcb_status_list").trim();
  if (pasted && !list) {
    setStatus("vcb_status_status", "Paste the status list credential " +
              "first.", "vc-error");
    log.debug("Leaving checkStatus(). Nothing pasted.");
    return false;
  }
  setStatus("vcb_status_status", pasted ? "Checking the pasted list…" :
            "Fetching " + entry.statusListCredential + "…", "vc-pending");
  var issuer = lastResult && lastResult.credential &&
      lastResult.credential.issuer;
  var r;
  try {
    r = await vpVerifier.checkBitstringStatus(entry, {
      issuer: typeof issuer === "string" ? issuer : (issuer || {}).id,
      fetchText: pasted ? function pastedList() {
        log.debug("Entering pastedList().");
        log.debug("Leaving pastedList().");
        return Promise.resolve(list);
      } : fetchStatusText });
  } catch (e) {
    setStatus("vcb_status_status", "Not checked: " + e.message,
              "vc-error");
    log.debug("Leaving checkStatus(). Failed.");
    return false;
  }
  var purpose = String(entry.statusPurpose || "");
  var word = { revocation: "REVOKED", suspension: "SUSPENDED" }[purpose] ||
      "SET";
  var verdict;
  var cls;
  if (r.value === undefined) {
    verdict = "NOT CHECKED — the status list could not be read; see below.";
    cls = "vc-error";
  } else if (!r.trusted) {
    verdict = "UNVERIFIED — the bit is " + r.value + ", but the status list " +
      "credential did not verify, so it is not relied on.";
    cls = "vc-error";
  } else if (r.value === 0) {
    verdict = "NOT " + word + " — entry " + entry.statusListIndex + " of " +
      r.entries + " is 0, in a status list credential that verifies.";
    cls = "vc-ok";
  } else {
    verdict = word + " — entry " + entry.statusListIndex + " of " +
      r.entries + " is " + r.value + ", in a status list credential that " +
      "verifies.";
    cls = "vc-error";
  }
  setStatus("vcb_status_status", verdict, cls);
  renderRows("vcb_status_result", r.checks.map(function (c) {
    return [c.label, c.status.toUpperCase() + ": " + c.detail, "",
            c.status === "pass" ? "vc-ok" : c.status === "fail" ?
              "vc-error" : ""];
  }).concat(r.credential ? [["Status list credential", JSON.stringify(
    r.credential, null, 2), "pre"]] : []));
  log.debug("Leaving checkStatus(). " + r.value);
  return false;
}

// ---------------------------------------------------------------------------
// Issuing.
// ---------------------------------------------------------------------------

function didKeyOf(jwk) {
  log.debug("Entering didKeyOf().");
  // The compressed point: 02 or 03 by the parity of y, then x.
  var y = cbytes.b64uToBytes(jwk.y);
  var raw = cbytes.concatBytes(new Uint8Array([2 + (y[y.length - 1] & 1)]),
                               cbytes.b64uToBytes(jwk.x));
  var codec = jwk.crv === "P-256" ? [0x80, 0x24] : [0x81, 0x24];
  var mb = "z" + didLib.base58Encode(cbytes.concatBytes(
    new Uint8Array(codec), raw));
  log.debug("Leaving didKeyOf().");
  return { did: "did:key:" + mb, vm: "did:key:" + mb + "#" + mb };
}

function generateKey() {
  log.debug("Entering generateKey().");
  var crv = val("vcb_curve") || "P-256";
  var pair = provider.generateKeyPair(crv === "P-384" ? "ec-p384" :
                                      "ec-p256");
  var jwk = provider.exportKey(pair, "jwk");
  setVal("vcb_private_jwk", JSON.stringify(jwk, null, 2));
  var k = didKeyOf(jwk);
  setVal("vcb_issuer", k.did);
  setStatus("vcb_issue_status", "A new " + crv + " key; the issuer is its " +
            "did:key. It is not stored — download it to keep it.",
            "vc-pending");
  log.debug("Leaving generateKey().");
  return false;
}

function downloadKey() {
  log.debug("Entering downloadKey().");
  var text = val("vcb_private_jwk");
  if (!text.trim()) {
    log.debug("Leaving downloadKey(). Nothing.");
    return false;
  }
  var a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: "application/json" }));
  a.download = "vc-barcode-issuer-key.json";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  log.debug("Leaving downloadKey().");
  return false;
}

function onSubjectType() {
  log.debug("Entering onSubjectType().");
  var type = val("vcb_subject_type");
  var aamva = type === vcb.AAMVA;
  var iso = type === vcb.ISO_IDL;
  el("vcb_issue_mrz_row").style.display = aamva || iso ? "none" : "";
  el("vcb_issue_aamva_row").style.display = aamva ? "" : "none";
  el("vcb_protect_row").style.display = aamva ? "" : "none";
  el("vcb_issue_iso_row").style.display = iso ? "" : "none";
  el("vcb_iso_protect_row").style.display = iso ? "" : "none";
  log.debug("Leaving onSubjectType().");
  return false;
}

function protectedChoice() {
  log.debug("Entering protectedChoice().");
  var iso = val("vcb_subject_type") === vcb.ISO_IDL;
  var ids = (iso ? vcb.ISO_DATA_GROUPS : vcb.AAMVA_MANDATORY).filter(
    function (id) {
      var box = el((iso ? "vcb_iso_protect_" : "vcb_protect_") + id);
      return box && box.checked;
    });
  log.debug("Leaving protectedChoice(). " + ids.join(","));
  return ids;
}

function showQr(text) {
  log.debug("Entering showQr().");
  var host = el("vcb_qr");
  host.textContent = "";
  if (!text) {
    log.debug("Leaving showQr(). Nothing.");
    return;
  }
  try {
    var code = qrcode(0, "L");
    code.addData(text, "Alphanumeric");
    code.make();
    // createSvgTag() draws rectangles from the bits alone; nothing of the
    // text reaches the markup.
    host.innerHTML = code.createSvgTag({ cellSize: 3, margin: 4,
                                         scalable: true });
  } catch (e) {
    host.textContent = "Too long for a QR code: " + e.message;
  }
  log.debug("Leaving showQr().");
}

// The licence's PDF417 text with the credential added as subfile ZZ,
// element ZZA, as the specification's example carries it.
function withZzSubfile(aamvaText, field) {
  log.debug("Entering withZzSubfile().");
  var parsed = vcb.parseAamva(aamvaText);
  var dl = parsed.subfiles[0];
  var at = aamvaText.indexOf("ANSI ") + 5;
  var body = aamvaText.slice(dl.offset);
  var dlEnd = body.indexOf("\r") + 1;
  var dlText = body.slice(0, dlEnd);
  var zz = "ZZZZA" + field + "\r";
  var headerLen = at + 12 + 2 * 10;
  var pad = function (n) {
    return ("0000" + n).slice(-4);
  };
  var head = aamvaText.slice(0, at + 10) + "02" +
    dl.type + pad(headerLen) + pad(dlText.length) +
    "ZZ" + pad(headerLen + dlText.length) + pad(zz.length);
  log.debug("Leaving withZzSubfile().");
  return head + dlText + zz;
}

async function issueBarcode() {
  log.debug("Entering issueBarcode().");
  setStatus("vcb_issue_status", "Signing…", "vc-pending");
  var jwk;
  try {
    jwk = JSON.parse(val("vcb_private_jwk"));
  } catch (e) {
    setStatus("vcb_issue_status", "The issuer key is not a JSON JWK " +
              "(press Generate).", "vc-error");
    log.debug("Leaving issueBarcode(). No key.");
    return false;
  }
  var type = val("vcb_subject_type");
  var aamvaText = unescapeControls(val("vcb_issue_aamva"));
  var groups = null;
  if (type === vcb.ISO_IDL) {
    try {
      groups = vcb.parseIsoDataGroups(val("vcb_issue_iso"));
    } catch (e) {
      setStatus("vcb_issue_status", "Not issued: the data groups: " +
                e.message, "vc-error");
      log.debug("Leaving issueBarcode(). Bad data groups.");
      return false;
    }
  }
  var printed = type === vcb.AAMVA ? { aamva: aamvaText } :
      type === vcb.ISO_IDL ? { iso: groups } : { mrz: val("vcb_issue_mrz") };
  var issuer = val("vcb_issuer").trim() || didKeyOf(jwk).did;
  var vm = val("vcb_issuer_vm").trim() ||
      (issuer.indexOf("did:key:") === 0 ? issuer + "#" + issuer.slice(8) :
       issuer + "#key-1");
  var status = null;
  if (val("vcb_status_base").trim()) {
    status = { terseStatusListBaseUrl: val("vcb_status_base").trim(),
               terseStatusListIndex: parseInt(val("vcb_status_index"), 10) ||
                 0 };
  }
  var out;
  try {
    var unsigned = vcb.credentialTemplate({ issuer: issuer,
      subjectType: type, protect: protectedChoice(), status: status });
    out = await vcb.issue(unsigned, { privateJwk: jwk,
      verificationMethod: vm, printed: printed });
  } catch (e) {
    setStatus("vcb_issue_status", "Not issued: " + e.message, "vc-error");
    log.debug("Leaving issueBarcode(). Failed.");
    return false;
  }
  var carried = out.carrier === "qr" ? out.text :
      out.carrier === "dg11" ? vcb.formatIsoDataGroups(vcb.withVcbInDg11(
        groups, out.text)) : withZzSubfile(aamvaText, out.text);
  setVal("vcb_issue_output", out.carrier === "pdf417" ?
         escapeControls(carried) : carried);
  showQr(out.carrier === "qr" ? out.text : "");
  var drawn = out.carrier === "pdf417" && showPdf417("vcb_pdf417", carried);
  if (out.carrier !== "pdf417") {
    el("vcb_pdf417").textContent = "";
  }
  setStatus("vcb_issue_status", "Issued: " + out.cborld.length + " bytes " +
            "of CBOR-LD, " + (out.carrier === "qr" ? "a QR code of " +
            out.text.length + " characters (alphanumeric mode)." :
            out.carrier === "dg11" ? "base64url in DG11 of the data groups " +
            "below. No symbol is drawn: how an ISO licence's data groups " +
            "are compact-encoded into its PDF417 is ISO/IEC 18013-2's." :
            "in subfile ZZ, element ZZA of the PDF417 text below" +
            (drawn ? ", drawn as the PDF417 symbol below (" +
             pdf417.ENCODER + ")." : "; the symbol could not be drawn: " +
             el("vcb_pdf417").textContent)), "vc-ok");
  renderRows("vcb_issue_result", [
    ["Optical data signed", out.canonical, "pre"],
    ["opticalDataBytes", cbytes.bytesToHex(out.opticalDataBytes)],
    ["CBOR-LD (hex)", cbytes.bytesToHex(out.cborld), "pre"],
    ["Credential", JSON.stringify(out.credential, null, 2), "pre"]
  ]);
  log.debug("Leaving issueBarcode().");
  return false;
}

// Hand the issued barcode to the read pane, with what the document prints.
function readIssued() {
  log.debug("Entering readIssued().");
  setVal("vcb_barcode", val("vcb_issue_output"));
  var type = val("vcb_subject_type");
  setVal("vcb_mrz", type === vcb.MRZ ? val("vcb_issue_mrz") : "");
  setVal("vcb_aamva", "");
  setVal("vcb_iso", "");
  log.debug("Leaving readIssued().");
  return verifyBarcode();
}

function init() {
  log.debug("Entering init().");
  var host = el("vcb_protect_boxes");
  if (host) {
    vcb.AAMVA_MANDATORY.forEach(function (id) {
      var label = document.createElement("label");
      label.className = "vcb-protect";
      var box = document.createElement("input");
      box.type = "checkbox";
      box.id = "vcb_protect_" + id;
      box.checked = ["DAC", "DAQ", "DCS"].indexOf(id) !== -1;
      label.appendChild(box);
      label.appendChild(document.createTextNode(" " + id));
      host.appendChild(label);
    });
  }
  var isoHost = el("vcb_iso_protect_boxes");
  if (isoHost) {
    vcb.ISO_DATA_GROUPS.forEach(function (name) {
      var label = document.createElement("label");
      label.className = "vcb-protect";
      var box = document.createElement("input");
      box.type = "checkbox";
      box.id = "vcb_iso_protect_" + name;
      box.checked = ["DG1", "DG2", "DG10"].indexOf(name) !== -1;
      if (name === vcb.ISO_VCB_GROUP) {
        box.disabled = true;
        label.title = "DG11 carries the credential, so it is not protected " +
          "(Appendix B.1).";
      }
      label.appendChild(box);
      label.appendChild(document.createTextNode(" " + name));
      isoHost.appendChild(label);
    });
  }
  if (!val("vcb_issue_mrz")) setVal("vcb_issue_mrz", EXAMPLES.ead.mrz);
  if (!val("vcb_issue_iso")) {
    setVal("vcb_issue_iso", SAMPLE_ISO);
  }
  if (!val("vcb_issue_aamva")) {
    setVal("vcb_issue_aamva", escapeControls(SAMPLE_AAMVA));
  }
  onSubjectType();
  log.debug("Leaving init().");
}

if (typeof document !== "undefined") {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
}

module.exports = {
  togglePane: togglePane,
  loadExample: loadExample,
  onImage: onImage,
  verifyBarcode: verifyBarcode,
  drawReadPdf417: drawReadPdf417,
  checkStatus: checkStatus,
  generateKey: generateKey,
  downloadKey: downloadKey,
  onSubjectType: onSubjectType,
  issueBarcode: issueBarcode,
  readIssued: readIssued,
  REGISTRY: cborld.REGISTRY
};
