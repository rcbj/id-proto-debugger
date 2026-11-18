// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: vc_barcodes_page.js
//
// ---------------------------------------------------------------------------
// vc-barcodes.html (#480): read and verify a VC barcode — the QR code beside
// an MRZ, or the credential inside an AAMVA PDF417 — and issue one. The
// work is vc_barcodes.js and cborld.js; this file is the DOM.
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
  }
};

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
  setStatus("vcb_read_status", "Loaded the specification's " +
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

// A picture of the QR code -> its text in the barcode box. PDF417 is not
// decoded from images here (no PDF417 reader is bundled): paste what a
// scanner reads instead.
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
      if (found && found.data) {
        setVal("vcb_barcode", found.data);
        setStatus("vcb_read_status", "Read a QR code of " +
                  found.data.length + " characters from the image.",
                  "vc-ok");
      } else {
        setStatus("vcb_read_status", "No QR code could be read in that " +
                  "image. Crop it to the code, or paste its text.",
                  "vc-error");
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
  var input = unescapeControls(val("vcb_barcode"));
  var result;
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
    rows.push(["Protected AAMVA fields", result.protected.join(", ")]);
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
  log.debug("Leaving verifyBarcode(). " + result.valid);
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
  var aamva = val("vcb_subject_type") === vcb.AAMVA;
  el("vcb_issue_mrz_row").style.display = aamva ? "none" : "";
  el("vcb_issue_aamva_row").style.display = aamva ? "" : "none";
  el("vcb_protect_row").style.display = aamva ? "" : "none";
  log.debug("Leaving onSubjectType().");
  return false;
}

function protectedChoice() {
  log.debug("Entering protectedChoice().");
  var ids = vcb.AAMVA_MANDATORY.filter(function (id) {
    var box = el("vcb_protect_" + id);
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
  var printed = type === vcb.AAMVA ? { aamva: aamvaText } :
      { mrz: val("vcb_issue_mrz") };
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
      withZzSubfile(aamvaText, out.text);
  setVal("vcb_issue_output", out.carrier === "qr" ? carried :
         escapeControls(carried));
  showQr(out.carrier === "qr" ? out.text : "");
  setStatus("vcb_issue_status", "Issued: " + out.cborld.length + " bytes " +
            "of CBOR-LD, " + (out.carrier === "qr" ? "a QR code of " +
            out.text.length + " characters (alphanumeric mode)." :
            "in subfile ZZ, element ZZA of the PDF417 text below (this " +
            "page draws no PDF417 symbol)."), "vc-ok");
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
  var aamva = val("vcb_subject_type") === vcb.AAMVA;
  setVal("vcb_mrz", aamva ? "" : val("vcb_issue_mrz"));
  setVal("vcb_aamva", "");
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
  if (!val("vcb_issue_mrz")) setVal("vcb_issue_mrz", EXAMPLES.ead.mrz);
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
  generateKey: generateKey,
  downloadKey: downloadKey,
  onSubjectType: onSubjectType,
  issueBarcode: issueBarcode,
  readIssued: readIssued,
  REGISTRY: cborld.REGISTRY
};
