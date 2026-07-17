// File: encoding_tools.js
// Author: Robert C. Broeckelmann Jr.
// Notes:
//
// Client-side encoding / hashing utilities:
//   * Base64 encode / decode
//   * URI (percent) encode / decode
//   * CRC-32 checksum (one-way)
//   * SHA hashing (SHA-1 / SHA-256 / SHA-384 / SHA-512) via the Web Crypto API
//
// Everything runs entirely in the browser. No values are written to
// localStorage or sent to a server.
//
var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'encoding_tools',
                                level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());

// ---------------------------------------------------------------------------
// Small DOM helpers
// ---------------------------------------------------------------------------
function val(id) {
  var el = document.getElementById(id);
  return el ? el.value : '';
}

function setVal(id, v) {
  var el = document.getElementById(id);
  if (el) el.value = v;
}

function setStatus(id, msg) {
  setVal(id, msg || '');
}

// ---------------------------------------------------------------------------
// Byte helpers (UTF-8 aware)
// ---------------------------------------------------------------------------
function strToBytes(str) {
  return new TextEncoder().encode(str);
}

function bytesToStr(bytes) {
  return new TextDecoder().decode(bytes);
}

function bytesToHex(bytes) {
  var hex = '';
  for (var i = 0; i < bytes.length; i++) {
    hex += ('0' + bytes[i].toString(16)).slice(-2);
  }
  return hex;
}

// ---------------------------------------------------------------------------
// 1. Base64
// ---------------------------------------------------------------------------
function base64Encode() {
  try {
    var bytes = strToBytes(val('b64_unencoded'));
    var bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    setVal('b64_encoded', btoa(bin));
    setStatus('b64_status', 'Encoded ' + bytes.length + ' byte(s).');
  } catch (e) {
    log.error('base64Encode: ' + e.message);
    setStatus('b64_status', 'Encode error: ' + e.message);
  }
  return false;
}

function base64Decode() {
  try {
    var bin = atob(val('b64_encoded').replace(/\s+/g, ''));
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    setVal('b64_unencoded', bytesToStr(bytes));
    setStatus('b64_status', 'Decoded ' + bytes.length + ' byte(s).');
  } catch (e) {
    log.error('base64Decode: ' + e.message);
    setStatus('b64_status', 'Decode error: not valid Base64.');
  }
  return false;
}

// ---------------------------------------------------------------------------
// 2. URI (percent) encoding
// ---------------------------------------------------------------------------
function uriEncode() {
  try {
    setVal('uri_encoded', encodeURIComponent(val('uri_unencoded')));
    setStatus('uri_status', 'Encoded.');
  } catch (e) {
    log.error('uriEncode: ' + e.message);
    setStatus('uri_status', 'Encode error: ' + e.message);
  }
  return false;
}

function uriDecode() {
  try {
    setVal('uri_unencoded', decodeURIComponent(val('uri_encoded')));
    setStatus('uri_status', 'Decoded.');
  } catch (e) {
    log.error('uriDecode: ' + e.message);
    setStatus('uri_status', 'Decode error: malformed percent-encoding.');
  }
  return false;
}

// ---------------------------------------------------------------------------
// 3. CRC-32 checksum (one-way — no decode)
// ---------------------------------------------------------------------------
var CRC32_TABLE = (function () {
  var table = new Array(256);
  for (var n = 0; n < 256; n++) {
    var c = n;
    for (var k = 0; k < 8; k++) {
      c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    }
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(bytes) {
  var crc = 0xFFFFFFFF;
  for (var i = 0; i < bytes.length; i++) {
    crc = (crc >>> 8) ^ CRC32_TABLE[(crc ^ bytes[i]) & 0xFF];
  }
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

function checksum() {
  try {
    var bytes = strToBytes(val('checksum_unencoded'));
    var value = crc32(bytes);
    setVal('checksum_encoded', ('0000000' + value.toString(16)).slice(-8));
    setStatus('checksum_status', 'CRC-32 of ' + bytes.length + ' byte(s).');
  } catch (e) {
    log.error('checksum: ' + e.message);
    setStatus('checksum_status', 'Checksum error: ' + e.message);
  }
  return false;
}

// ---------------------------------------------------------------------------
// 4. SHA hashing (Web Crypto API)
// ---------------------------------------------------------------------------
function shaHash() {
  var alg = val('sha_size') || 'SHA-256';
  try {
    if (!(typeof crypto !== 'undefined' && crypto.subtle)) {
      throw new Error('Web Crypto API not available in this browser.');
    }
    var bytes = strToBytes(val('sha_unencoded'));
    setStatus('sha_status', 'Hashing with ' + alg + '…');
    crypto.subtle.digest(alg, bytes).then(function (digest) {
      var hex = bytesToHex(new Uint8Array(digest));
      setVal('sha_encoded', hex);
      setStatus('sha_status', alg + ' — ' + (hex.length * 4) + ' bit(s).');
    }).catch(function (err) {
      log.error('shaHash: ' + err);
      setStatus('sha_status', 'Hash error: ' + err.message);
    });
  } catch (e) {
    log.error('shaHash: ' + e.message);
    setStatus('sha_status', 'Hash error: ' + e.message);
  }
  return false;
}

// ---------------------------------------------------------------------------
// Copy a field's contents to the clipboard.
// ---------------------------------------------------------------------------
function copyField(elementId) {
  var el = document.getElementById(elementId);
  if (!el) { log.error('copyField: element not found: ' + elementId); return false; }
  var text = el.value || '';
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).catch(function (err) { log.error('copyField: ' + err); });
  } else {
    try { el.focus(); el.select(); document.execCommand('copy'); } catch (e) { log.error('copyField fallback: ' + e.message); }
  }
  return false;
}

// ---------------------------------------------------------------------------
// "Return to debugger" link — point back at whichever page sent us here.
// Only known debugger pages are honoured to avoid an open redirect.
// ---------------------------------------------------------------------------
function setReturnLink() {
  var allowed = { 'debugger.html': '/debugger.html', 'debugger2.html': '/debugger2.html' };
  var from = new URLSearchParams(window.location.search).get('from');
  var target = allowed[from] || '/debugger.html';
  var link = document.getElementById('return_link');
  if (link) link.setAttribute('href', target);
}

window.onload = function () {
  log.debug('Entering onload function.');
  setReturnLink();

  // Seed each Unencoded field with a sample value, then run the corresponding
  // Encode / hash so the Encoded fields are populated on first load.
  setVal('b64_unencoded', 'Hello, OAuth2!');
  setVal('uri_unencoded', 'https://idptools.com/callback?state=a b&scope=openid profile');
  setVal('checksum_unencoded', 'The quick brown fox jumps over the lazy dog');
  setVal('sha_unencoded', 'Hello, OAuth2!');

  base64Encode();
  uriEncode();
  checksum();
  shaHash();
};

module.exports = {
  base64Encode,
  base64Decode,
  uriEncode,
  uriDecode,
  checksum,
  shaHash,
  copyField
};
