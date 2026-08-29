// File: encoding_tools.js
// Author: Robert C. Broeckelmann Jr.
// Notes:
//
// Client-side encoding / hashing utilities:
//   * Base64 encode / decode
//   * URI (percent) encode / decode
//   * CRC-32 checksum (one-way)
//   * SHA-1 / SHA-2 hashing (FIPS 180-4)
//   * SHA-3 and SHAKE hashing (FIPS 202) — the sponge family the three
//     post-quantum standards are built from
//   * cSHAKE, KMAC, TupleHash and ParallelHash (NIST SP 800-185)
//
// Everything runs entirely in the browser. No values are written to
// localStorage or sent to a server.
//
// THE HASHING IS NOT WEB CRYPTO ANY MORE, and that is deliberate twice over.
// `crypto.subtle` has no SHA-3 in any browser — not one of FIPS 202's six
// functions, and none of SP 800-185's four — so the post-quantum half could
// never have been built on it; and it does not exist outside a secure
// context, which the containerized test origin (http://client:3000) is not,
// so the SHA-2 pane silently had no cryptography there. Both panes now go
// through client/src/hash_tools.js, which is pure JavaScript, synchronous,
// and DOM-free — see the header of that file for what the panes are FOR, and
// tests/hash_engine.js for the vectors that hold it to the specifications.
//
var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var hashes = require("./hash_tools");
var log = bunyan.createLogger({ name: 'encoding_tools',
                                level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());

// ---------------------------------------------------------------------------
// Small DOM helpers
// ---------------------------------------------------------------------------
function val(id) {
  log.debug("Entering val().");
  var el = document.getElementById(id);
  log.debug("Leaving val().");
  return el ? el.value : '';
}

function setVal(id, v) {
  log.debug("Entering setVal().");
  var el = document.getElementById(id);
  if (el) el.value = v;
  log.debug("Leaving setVal().");
}

function setStatus(id, msg) {
  log.debug("Entering setStatus().");
  setVal(id, msg || '');
  log.debug("Leaving setStatus().");
}

// Enable or disable a control and mark it, so a field that does not apply to
// the selected function reads as inapplicable rather than as empty.
function setEnabled(id, on) {
  log.debug("Entering setEnabled(). id=" + id);
  var el = document.getElementById(id);
  if (!el) {
    log.debug("Leaving setEnabled(). No element.");
    return;
  }
  el.disabled = !on;
  if (on) {
    el.classList.remove('et-inactive');
  } else {
    el.classList.add('et-inactive');
  }
  log.debug("Leaving setEnabled().");
}

// ---------------------------------------------------------------------------
// Byte helpers (UTF-8 aware)
// ---------------------------------------------------------------------------
function strToBytes(str) {
  log.debug("Entering strToBytes().");
  log.debug("Leaving strToBytes().");
  return new TextEncoder().encode(str);
}

function bytesToStr(bytes) {
  log.debug("Entering bytesToStr().");
  log.debug("Leaving bytesToStr().");
  return new TextDecoder().decode(bytes);
}

// ---------------------------------------------------------------------------
// 1. Base64
// ---------------------------------------------------------------------------
function base64Encode() {
  log.debug("Entering base64Encode().");
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
  log.debug("Leaving base64Encode().");
  return false;
}

function base64Decode() {
  log.debug("Entering base64Decode().");
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
  log.debug("Leaving base64Decode().");
  return false;
}

// ---------------------------------------------------------------------------
// 2. URI (percent) encoding
// ---------------------------------------------------------------------------
function uriEncode() {
  log.debug("Entering uriEncode().");
  try {
    setVal('uri_encoded', encodeURIComponent(val('uri_unencoded')));
    setStatus('uri_status', 'Encoded.');
  } catch (e) {
    log.error('uriEncode: ' + e.message);
    setStatus('uri_status', 'Encode error: ' + e.message);
  }
  log.debug("Leaving uriEncode().");
  return false;
}

function uriDecode() {
  log.debug("Entering uriDecode().");
  try {
    setVal('uri_unencoded', decodeURIComponent(val('uri_encoded')));
    setStatus('uri_status', 'Decoded.');
  } catch (e) {
    log.error('uriDecode: ' + e.message);
    setStatus('uri_status', 'Decode error: malformed percent-encoding.');
  }
  log.debug("Leaving uriDecode().");
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
  log.debug("Entering crc32().");
  var crc = 0xFFFFFFFF;
  for (var i = 0; i < bytes.length; i++) {
    crc = (crc >>> 8) ^ CRC32_TABLE[(crc ^ bytes[i]) & 0xFF];
  }
  log.debug("Leaving crc32().");
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

function checksum() {
  log.debug("Entering checksum().");
  try {
    var bytes = strToBytes(val('checksum_unencoded'));
    var value = crc32(bytes);
    setVal('checksum_encoded', ('0000000' + value.toString(16)).slice(-8));
    setStatus('checksum_status', 'CRC-32 of ' + bytes.length + ' byte(s).');
  } catch (e) {
    log.error('checksum: ' + e.message);
    setStatus('checksum_status', 'Checksum error: ' + e.message);
  }
  log.debug("Leaving checksum().");
  return false;
}

// ---------------------------------------------------------------------------
// 4 & 5. Hashing — SHA-1/SHA-2 (FIPS 180-4) and SHA-3/SHAKE (FIPS 202).
//
// Both panes are the same three lines of work against hash_tools.js and
// differ only in which element ids they read, so they share runHash() rather
// than being written twice: the SHA-3 pane has the extra output-length field
// an extendable-output function needs, and a pane that only sometimes has one
// is the whole difference.
// ---------------------------------------------------------------------------
function runHash(ids) {
  log.debug("Entering runHash(). alg=" + val(ids.alg));
  var alg = val(ids.alg);
  try {
    var message = hashes.decodeInput(val(ids.input),
                                     val(ids.inputEncoding) || 'text');
    var opts = {};
    if (ids.outputBits) {
      opts.outputBits = val(ids.outputBits);
    }
    var out = hashes.digest(alg, message, opts);
    setVal(ids.output, hashes.encodeOutput(out, val(ids.format) || 'hex'));
    setVal(ids.notes, hashes.describe(alg, opts.outputBits));
    setStatus(ids.status, alg + ' — ' + message.length + ' byte(s) in, ' +
              (out.length * 8) + ' bit(s) out.');
  } catch (e) {
    log.error('runHash: ' + e.message);
    setVal(ids.output, '');
    setStatus(ids.status, 'Hash error: ' + e.message);
  }
  log.debug("Leaving runHash().");
  return false;
}

var SHA_IDS = { alg: 'sha_size', input: 'sha_unencoded',
                inputEncoding: 'sha_input_encoding', output: 'sha_encoded',
                format: 'sha_output_format', notes: 'sha_notes',
                status: 'sha_status' };

var SHA3_IDS = { alg: 'sha3_alg', input: 'sha3_unencoded',
                 inputEncoding: 'sha3_input_encoding',
                 output: 'sha3_encoded', format: 'sha3_output_format',
                 outputBits: 'sha3_output_bits', notes: 'sha3_notes',
                 status: 'sha3_status' };

function shaHash() {
  log.debug("Entering shaHash().");
  var result = runHash(SHA_IDS);
  log.debug("Leaving shaHash().");
  return result;
}

function sha3Hash() {
  log.debug("Entering sha3Hash().");
  var result = runHash(SHA3_IDS);
  log.debug("Leaving sha3Hash().");
  return result;
}

// The output-length field applies to SHAKE and to nothing else: a fixed
// digest has its length in its name, and a box that accepts one anyway is a
// box whose value is silently ignored.
function sha3AlgChanged() {
  log.debug("Entering sha3AlgChanged().");
  var alg = hashes.algorithm(val('sha3_alg'));
  setEnabled('sha3_output_bits', !!(alg && alg.xof));
  sha3Hash();
  log.debug("Leaving sha3AlgChanged().");
  return false;
}

// ---------------------------------------------------------------------------
// 6. SP 800-185 — cSHAKE, KMAC, TupleHash, ParallelHash.
//
// One pane for four functions because they are one construction with four
// sets of arguments, and seeing which argument each of them drops is most of
// the point: TupleHash is the only one that takes a LIST, KMAC the only one
// that takes a key, ParallelHash the only one whose block size changes the
// answer, and cSHAKE the only one whose function name N is yours to set.
// ---------------------------------------------------------------------------
function sp185Kind() {
  log.debug("Entering sp185Kind().");
  var fn = hashes.derived(val('sp185_fn'));
  log.debug("Leaving sp185Kind().");
  return fn ? fn.kind : '';
}

function sp185FnChanged() {
  log.debug("Entering sp185FnChanged().");
  var kind = sp185Kind();
  setEnabled('sp185_key', kind === 'kmac');
  setEnabled('sp185_key_encoding', kind === 'kmac');
  setEnabled('sp185_function_name', kind === 'cshake');
  setEnabled('sp185_block_bytes', kind === 'parallel');
  sp185Compute();
  log.debug("Leaving sp185FnChanged().");
  return false;
}

function sp185Compute() {
  log.debug("Entering sp185Compute().");
  var id = val('sp185_fn');
  try {
    var encoding = val('sp185_message_encoding') || 'text';
    var opts = { customization: val('sp185_customization'),
                 functionName: val('sp185_function_name'),
                 blockBytes: val('sp185_block_bytes'),
                 outputBits: val('sp185_output_bits') };
    var kind = sp185Kind();
    if (kind === 'tuple') {
      // One element per line. Blank lines are dropped rather than hashed as
      // empty strings: an editor's trailing newline would otherwise change
      // the digest, which is exactly the ambiguity TupleHash exists to end.
      var lines = val('sp185_message').split(/\r?\n/).filter(
          function (line) { return line.length > 0; });
      opts.messages = lines.map(function (line) {
        return hashes.decodeInput(line, encoding);
      });
    } else {
      opts.message = hashes.decodeInput(val('sp185_message'), encoding);
    }
    if (kind === 'kmac') {
      opts.key = hashes.decodeInput(val('sp185_key'),
                                    val('sp185_key_encoding') || 'text');
    }
    var out = hashes.derive(id, opts);
    setVal('sp185_encoded',
           hashes.encodeOutput(out, val('sp185_output_format') || 'hex'));
    setVal('sp185_notes', hashes.describeDerived(id, opts));
    setStatus('sp185_status', id + ' — ' + (out.length * 8) +
              ' bit(s) out' + (kind === 'tuple' ?
              ', ' + opts.messages.length + ' tuple element(s).' : '.'));
  } catch (e) {
    log.error('sp185Compute: ' + e.message);
    setVal('sp185_encoded', '');
    setStatus('sp185_status', 'Error: ' + e.message);
  }
  log.debug("Leaving sp185Compute().");
  return false;
}

// ---------------------------------------------------------------------------
// Copy a field's contents to the clipboard.
// ---------------------------------------------------------------------------
function copyField(elementId) {
  log.debug("Entering copyField().");
  var el = document.getElementById(elementId);
  if (!el) {
    log.error('copyField: element not found: ' + elementId);
    log.debug("Leaving copyField().");
    return false;
  }
  var text = el.value || '';
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).catch(function (err) { log.error(
                                  'copyField: ' + err); });
  } else {
    try {
      el.focus();
      el.select();
      document.execCommand('copy');
    } catch (e) {
      log.error('copyField fallback: ' + e.message);
    }
  }
  log.debug("Leaving copyField().");
  return false;
}

// ---------------------------------------------------------------------------
// "Return to debugger" link — point back at whichever page sent us here.
// Only known debugger pages are honoured to avoid an open redirect.
// ---------------------------------------------------------------------------
function setReturnLink() {
  log.debug("Entering setReturnLink().");
  var allowed = { 'oauth2_oidc_1.html': '/oauth2_oidc_1.html',
      'oauth2_oidc_2.html': '/oauth2_oidc_2.html' };
  var from = new URLSearchParams(window.location.search).get('from');
  var target = allowed[from] || '/oauth2_oidc_1.html';
  var link = document.getElementById('return_link');
  if (link) link.setAttribute('href', target);
  log.debug("Leaving setReturnLink().");
}

window.onload = function () {
  log.debug("Entering onload().");
  log.debug('Entering onload function.');
  setReturnLink();

  // Seed each Unencoded field with a sample value, then run the corresponding
  // Encode / hash so the Encoded fields are populated on first load.
  //
  // The two new panes are seeded with the SPECIFICATIONS' OWN sample inputs
  // rather than with a greeting: "abc" is the input every FIPS 202 example
  // uses, and the SP 800-185 pane loads holding KMAC Sample #1 — key
  // 40..5F, data 00010203, no customization, L = 256 — whose expected output
  // is printed in section A.1 of that document. So the page can be checked
  // against NIST by reading it, and tests/hash_engine.js asserts both.
  setVal('b64_unencoded', 'Hello, OAuth2!');
  setVal('uri_unencoded',
         'https://idptools.com/callback?state=a b&scope=openid profile');
  setVal('checksum_unencoded', 'The quick brown fox jumps over the lazy dog');
  setVal('sha_unencoded', 'Hello, OAuth2!');
  setVal('sha3_unencoded', 'abc');
  setVal('sp185_message', '00010203');
  setVal('sp185_key',
         '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f');

  base64Encode();
  uriEncode();
  checksum();
  shaHash();
  sha3AlgChanged();
  sp185FnChanged();
  log.debug("Leaving onload().");
};

module.exports = {
  base64Encode,
  base64Decode,
  uriEncode,
  uriDecode,
  checksum,
  shaHash,
  sha3Hash,
  sha3AlgChanged,
  sp185Compute,
  sp185FnChanged,
  copyField
};
