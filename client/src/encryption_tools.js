// File: encryption_tools.js
// Author: Robert C. Broeckelmann Jr.
//
// ---------------------------------------------------------------------------
// The Encryption / Decryption page — nine panes, one per mechanism.
//
//   Symmetric   #1 AES              every mode, every key size
//               #2 ChaCha20-Poly1305 RFC 8439
//               #3 3DES / DES        the legacy block ciphers
//               #9 Password-based    PBKDF2 / scrypt / PBES2
//   Asymmetric  #4 RSA               OAEP and PKCS#1 v1.5, direct and hybrid
//               #5 ECC (ECIES)       ephemeral ECDH -> HKDF -> AEAD
//               #6 ML-KEM            FIPS 203, alone or hybridised with X25519
//               #7 DSA-family (FFC)  ElGamal and DHIES over an RFC 3526 group
//   Protocol    #8 JWE               RFC 7516 compact serialization
//
// THIS FILE IS THE DOM AND NOTHING ELSE. Every byte of cryptography on this
// page is in a module that has no DOM and is therefore driven directly by
// tests/crypto_engines.js in node: symmetric_crypto.js, pk_encryption.js,
// jose_jwe.js, key_material.js and crypto_bytes.js. That split is what lets
// the RFCs' own test vectors be asserted on every run without a browser, and
// it is the same split the Digital Signature page now uses — the two pages
// share the modules, the pane grid (tool_panes.js) and the stylesheet
// (css/tool_panes.css).
//
// NO KEY MATERIAL IS STORED. Nothing here touches localStorage or
// sessionStorage: a key exists in the fields on this page and nowhere else,
// which is the same rule the Digital Signature page follows and the reason
// neither page appears in the key-pair storage opt-out that governs the
// multi-screen workflows.
// ---------------------------------------------------------------------------

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var nobleHkdf = require("@noble/hashes/hkdf").hkdf;
var noblePbkdf2 = require("@noble/hashes/pbkdf2").pbkdf2;
var nobleScrypt = require("@noble/hashes/scrypt").scrypt;
var nobleSha256 = require("@noble/hashes/sha256").sha256;
var nobleSha512 = require("@noble/hashes/sha512");
var bytes = require("./crypto_bytes");
var symmetric = require("./symmetric_crypto");
var pk = require("./pk_encryption");
var jose = require("./jose_jwe");
var keyMaterial = require("./key_material");
var x509 = require("./x509");
var panes = require("./tool_panes");

var log = bunyan.createLogger({ name: 'encryption_tools',
                                level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());

var val = panes.val;
var setVal = panes.setVal;
var defer = panes.defer;

// ---------------------------------------------------------------------------
// Field conventions, and why they are what they are.
//
// KEYS AND IVs ARE HEX; CIPHERTEXTS AND TAGS ARE BASE64. That split is the
// Digital Signature page's (keys hex, signatures base64) and it is kept here
// so the two pages can be used together without a mental conversion. It also
// matches what the tools on the other side of most of these do: `openssl enc`
// takes -K and -iv in hex, and every protocol that carries a ciphertext in
// text carries it in base64.
// ---------------------------------------------------------------------------
function fieldId(prefix, name) {
  log.debug("Entering fieldId().");
  log.debug("Leaving fieldId().");
  return 'enc_' + prefix + '_' + name;
}

function field(prefix, name) {
  log.debug("Entering field().");
  log.debug("Leaving field().");
  return val(fieldId(prefix, name));
}

function setField(prefix, name, value) {
  log.debug("Entering setField().");
  setVal(fieldId(prefix, name), value);
  log.debug("Leaving setField().");
}

// EVERY IN-PROGRESS MESSAGE ENDS WITH AN ELLIPSIS, AND NOTHING ELSE DOES.
//
// That is a contract with tests/encryption_tools.js rather than a matter of
// taste: the only way a test can tell "still working" from "finished" on a
// page whose operations are deferred is the shape of the line, and the check
// is a TRAILING ellipsis rather than one anywhere, because finished messages
// quote ranges and counts that contain dots. So a parenthetical explanation
// goes BEFORE the ellipsis — "Generating a key pair — pure JS, so larger sizes
// take longer…", never "Generating a key pair… (pure JS)". Two messages here
// were written the second way and the test waited out its whole budget on the
// first of them.
function status(prefix, message) {
  log.debug("Entering status(). " + prefix + ": " + message);
  setVal(fieldId(prefix, 'status'), message);
  log.debug("Leaving status().");
}

// Every button handler ends here. Reporting the message rather than a generic
// failure is the whole point of the page: "the tag did not verify" and "that
// key is 16 bytes and this cipher wants 32" are different problems, and a
// pane that says "error" for both is a pane you cannot debug with.
//
// WHICH IS WHY describeError() EXISTS, and it was written after the page had
// already failed at exactly the thing it is for. Web Crypto rejects with an
// `OperationError` whose `message` is the EMPTY STRING — no reason, no
// detail — so the JWE pane, handed a token with one bit flipped, put an empty
// string in its status line and said nothing at all. The single most important
// refusal on the page was the one it reported worst. Anything that reaches
// crypto.subtle can do this: the JWE pane, and every password-protected
// keystore download.
function describeError(error) {
  log.debug("Entering describeError().");
  var message = (error && error.message) ? String(error.message).trim() : '';
  if (message) {
    log.debug("Leaving describeError(). Has a message.");
    return message;
  }
  var name = (error && error.name) ? String(error.name) : 'Error';
  if (name === 'OperationError') {
    log.debug("Leaving describeError(). Bare OperationError.");
    return 'The operation failed and Web Crypto did not say why — it ' +
           'reports OperationError with an empty message. On a decryption ' +
           'that means the authentication did not check out: the key, the ' +
           'IV, the additional authenticated data or the ciphertext is not ' +
           'what it was encrypted with, and an authenticated cipher cannot ' +
           'tell you which.';
  }
  log.debug("Leaving describeError(). Name only.");
  return name + ' — the underlying error carried no message.';
}

function fail(prefix, where, error) {
  var described = describeError(error);
  log.error(where + ': ' + described);
  status(prefix, described);
  return false;
}

// Hex in a key field, with the field named when it is not hex. bytes.hexToBytes
// already refuses a non-hex character; this turns its message into one that
// says WHICH box.
function hexField(prefix, name, label) {
  log.debug("Entering hexField().");
  try {
    log.debug("Leaving hexField().");
    return bytes.hexToBytes(field(prefix, name));
  } catch (e) {
    log.debug("Leaving hexField(). Not hex.");
    throw new Error(label + ': ' + e.message);
  }
}

function b64Field(prefix, name, label) {
  log.debug("Entering b64Field().");
  try {
    log.debug("Leaving b64Field().");
    return bytes.b64ToBytes(field(prefix, name));
  } catch (e) {
    log.debug("Leaving b64Field(). Not base64.");
    throw new Error(label + ' is not valid Base64.');
  }
}

// What the plaintext box holds: text, or hex when the pane's Hex box is
// ticked. Binary is why the toggle exists — a ciphertext decrypted to bytes
// that are not UTF-8 has to be shown as something, and the same switch lets
// those bytes be encrypted again unchanged.
function plaintextIn(prefix) {
  log.debug("Entering plaintextIn().");
  var text = field(prefix, 'plaintext');
  if (panes.isChecked(fieldId(prefix, 'hex'))) {
    log.debug("Leaving plaintextIn(). Hex.");
    return bytes.hexToBytes(text);
  }
  log.debug("Leaving plaintextIn(). Text.");
  return bytes.strBytes(text);
}

// And back. A decrypted value that is not valid UTF-8 is shown as hex with the
// box ticked, rather than as the replacement characters TextDecoder would
// otherwise produce — those are lossy, so copying the box back out would not
// give you your bytes.
function plaintextOut(prefix, plain) {
  log.debug("Entering plaintextOut().");
  var text = null;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(plain);
  } catch (e) {
    log.debug("plaintextOut(): not UTF-8, showing hex.");
    text = null;
  }
  var box = document.getElementById(fieldId(prefix, 'hex'));
  if (text === null) {
    if (box) box.checked = true;
    setField(prefix, 'plaintext', bytes.bytesToHex(plain));
    log.debug("Leaving plaintextOut(). Hex.");
    return ' (not UTF-8 — shown as hex)';
  }
  if (box) box.checked = false;
  setField(prefix, 'plaintext', text);
  log.debug("Leaving plaintextOut(). Text.");
  return '';
}

// ===========================================================================
// Panes #1, #2, #3 — the symmetric ciphers
//
// One implementation for three panes, because they differ ONLY in which
// ciphers their dropdown offers. Splitting them into three panes is a UI
// decision (a reader looking for DES should not have to find it inside an AES
// pane); making them three implementations would have been a mistake.
// ===========================================================================
// The three prefixes, and NOT the algorithm lists.
//
// Which ciphers each pane offers is in the markup's <select>, and symmetric_
// crypto.js's catalogue is what validates a chosen one — a third list here
// would be a copy nothing reads, and a copy nothing reads is a copy that
// drifts. What this is for is the two places that genuinely need to do
// something once per symmetric pane: seeding them at load, and nothing else.
var SYM_PANES = ['aes', 'cc', 'des'];

function symCipherId(prefix) {
  log.debug("Entering symCipherId().");
  log.debug("Leaving symCipherId().");
  return field(prefix, 'alg');
}

// Fresh key AND IV. They are generated together because generating one without
// the other is how a nonce gets reused: with GCM selected, a user who presses
// "Generate Key" and then encrypts twice has two messages under one key, and
// the second one is only safe because the IV moved too.
function symGenerateKey(prefix) {
  log.debug("Entering symGenerateKey(). prefix=" + prefix);
  try {
    var id = symCipherId(prefix);
    var spec = symmetric.describe(id);
    setField(prefix, 'key', bytes.bytesToHex(symmetric.generateKey(id)));
    setField(prefix, 'iv', bytes.bytesToHex(symmetric.generateIv(id)));
    status(prefix, 'Generated a ' + (spec.keyBytes * 8) + '-bit key' +
           (spec.ivBytes ? ' and a fresh ' + spec.ivBytes + '-byte ' +
            (spec.aead ? 'nonce' : 'IV') + '.'
                         : '. ' + spec.label + ' has no IV.'));
  } catch (e) {
    log.debug("Leaving symGenerateKey(). Failed.");
    return fail(prefix, 'symGenerateKey', e);
  }
  log.debug("Leaving symGenerateKey().");
  return false;
}

function symGenerateIv(prefix) {
  log.debug("Entering symGenerateIv(). prefix=" + prefix);
  try {
    var id = symCipherId(prefix);
    var spec = symmetric.describe(id);
    if (!spec.ivBytes) {
      status(prefix, spec.label + ' has no IV — every block is encrypted ' +
             'independently under the key alone, which is what makes ECB ' +
             'leak the plaintext’s structure.');
      log.debug("Leaving symGenerateIv(). No IV for this mode.");
      return false;
    }
    setField(prefix, 'iv', bytes.bytesToHex(symmetric.generateIv(id)));
    status(prefix, 'Generated a fresh ' + spec.ivBytes + '-byte ' +
           (spec.aead ? 'nonce. Never reuse one under the same key.' : 'IV.'));
  } catch (e) {
    log.debug("Leaving symGenerateIv(). Failed.");
    return fail(prefix, 'symGenerateIv', e);
  }
  log.debug("Leaving symGenerateIv().");
  return false;
}

// The dropdown changed: the key and IV that are in the boxes are almost
// certainly the wrong length for the newly selected cipher, so say what is
// needed now rather than waiting for the button to fail.
function symAlgChanged(prefix) {
  log.debug("Entering symAlgChanged(). prefix=" + prefix);
  try {
    var spec = symmetric.describe(symCipherId(prefix));
    status(prefix, spec.label + ' — ' + spec.keyBytes + '-byte key' +
           (spec.ivBytes ? ', ' + spec.ivBytes + '-byte ' +
            (spec.aead ? 'nonce' : 'IV') : ', no IV') +
           (spec.aead ? ', authenticated (produces a tag).'
                      : ', NOT authenticated (no tag; a modified ciphertext ' +
                        'is not detected).'));
  } catch (e) {
    log.debug("Leaving symAlgChanged(). Failed.");
    return fail(prefix, 'symAlgChanged', e);
  }
  log.debug("Leaving symAlgChanged().");
  return false;
}

function symEncrypt(prefix) {
  log.debug("Entering symEncrypt(). prefix=" + prefix);
  try {
    var id = symCipherId(prefix);
    var spec = symmetric.describe(id);
    var out = symmetric.encrypt({
      id: id,
      key: hexField(prefix, 'key', 'Secret Key'),
      iv: hexField(prefix, 'iv', spec.aead ? 'Nonce' : 'IV'),
      aad: spec.aead ? bytes.strBytes(field(prefix, 'aad'))
                     : new Uint8Array(0),
      plaintext: plaintextIn(prefix)
    });
    setField(prefix, 'ciphertext', bytes.bytesToB64(out.ciphertext));
    setField(prefix, 'tag', spec.aead ? bytes.bytesToB64(out.tag) : '');
    status(prefix, 'Encrypted ' + out.ciphertext.length + ' bytes with ' +
           spec.label + (spec.aead ? ', plus a 16-byte tag.'
                                   : '. No tag: this mode authenticates ' +
                                     'nothing.'));
  } catch (e) {
    log.debug("Leaving symEncrypt(). Failed.");
    return fail(prefix, 'symEncrypt', e);
  }
  log.debug("Leaving symEncrypt().");
  return false;
}

function symDecrypt(prefix) {
  log.debug("Entering symDecrypt(). prefix=" + prefix);
  try {
    var id = symCipherId(prefix);
    var spec = symmetric.describe(id);
    var plain = symmetric.decrypt({
      id: id,
      key: hexField(prefix, 'key', 'Secret Key'),
      iv: hexField(prefix, 'iv', spec.aead ? 'Nonce' : 'IV'),
      aad: spec.aead ? bytes.strBytes(field(prefix, 'aad'))
                     : new Uint8Array(0),
      ciphertext: b64Field(prefix, 'ciphertext', 'Ciphertext'),
      tag: spec.aead ? b64Field(prefix, 'tag', 'Tag') : new Uint8Array(0)
    });
    var note = plaintextOut(prefix, plain);
    status(prefix, 'Decrypted ' + plain.length + ' bytes with ' + spec.label +
           (spec.aead ? '; the tag verified.' : '.') + note);
  } catch (e) {
    log.debug("Leaving symDecrypt(). Failed.");
    return fail(prefix, 'symDecrypt', e);
  }
  log.debug("Leaving symDecrypt().");
  return false;
}

// ===========================================================================
// Pane #4 — RSA
// ===========================================================================
function rsaGenerateKeys() {
  log.debug("Entering rsaGenerateKeys().");
  var bits = parseInt(val('enc_rsa_bits'), 10) || 2048;
  status('rsa', 'Generating an RSA ' + bits + '-bit key pair — pure JS, ' +
         'so larger sizes take longer…');
  defer(function () {
    try {
      var pair = pk.rsaGenerateKeyPair(bits);
      setField('rsa', 'private_key', pair.privatePem);
      setField('rsa', 'public_key', pair.publicPem);
      status('rsa', 'Generated an RSA ' + bits + '-bit key pair. ' +
             rsaLimitNote());
    } catch (e) {
      fail('rsa', 'rsaGenerateKeys', e);
    }
  });
  log.debug("Leaving rsaGenerateKeys().");
  return false;
}

// How much this key and padding can carry directly. Shown when the key, the
// padding or the hash changes, because the limit depends on all three and
// "data too large for key size" arriving after the fact explains none of it.
function rsaLimitNote() {
  log.debug("Entering rsaLimitNote().");
  try {
    var max = pk.rsaMaxDirectBytes({ publicPem: field('rsa', 'public_key'),
                                     padding: val('enc_rsa_padding'),
                                     hash: val('enc_rsa_hash') });
    log.debug("Leaving rsaLimitNote().");
    return 'Direct mode carries at most ' + max + ' bytes with this key, ' +
           'padding and hash; Hybrid carries any length.';
  } catch (e) {
    log.debug("Leaving rsaLimitNote(). No usable public key yet.");
    return '';
  }
}

function rsaOptionsChanged() {
  log.debug("Entering rsaOptionsChanged().");
  var note = rsaLimitNote();
  if (note) {
    status('rsa', note);
  }
  log.debug("Leaving rsaOptionsChanged().");
  return false;
}

function rsaIsHybrid() {
  log.debug("Entering rsaIsHybrid().");
  log.debug("Leaving rsaIsHybrid().");
  return val('enc_rsa_mode') === 'hybrid';
}

function rsaEncrypt() {
  log.debug("Entering rsaEncrypt().");
  try {
    var common = { publicPem: field('rsa', 'public_key'),
                   padding: val('enc_rsa_padding'),
                   hash: val('enc_rsa_hash'),
                   plaintext: plaintextIn('rsa') };
    if (!rsaIsHybrid()) {
      var direct = pk.rsaEncrypt(common);
      setField('rsa', 'encapsulation', '');
      setField('rsa', 'iv', '');
      setField('rsa', 'tag', '');
      setField('rsa', 'ciphertext', bytes.bytesToB64(direct.ciphertext));
      status('rsa', 'Encrypted directly with ' +
             pk.RSA_PADDINGS[val('enc_rsa_padding')].label +
             '. The ciphertext is exactly one RSA block (' +
             direct.ciphertext.length + ' bytes) whatever the message length.');
      log.debug("Leaving rsaEncrypt(). Direct.");
      return false;
    }
    common.cipherId = val('enc_rsa_cipher');
    common.aad = bytes.strBytes(field('rsa', 'aad'));
    var out = pk.rsaHybridEncrypt(common);
    setField('rsa', 'encapsulation', bytes.bytesToB64(out.encapsulation));
    setField('rsa', 'iv', bytes.bytesToHex(out.iv));
    setField('rsa', 'ciphertext', bytes.bytesToB64(out.ciphertext));
    setField('rsa', 'tag', bytes.bytesToB64(out.tag));
    status('rsa', 'Hybrid: RSA wrapped a fresh ' + out.cipherId +
           ' key (that is the Wrapped Key box) and the message is encrypted ' +
           'under it. This is what CMS, S/MIME and JWE all do.');
  } catch (e) {
    log.debug("Leaving rsaEncrypt(). Failed.");
    return fail('rsa', 'rsaEncrypt', e);
  }
  log.debug("Leaving rsaEncrypt().");
  return false;
}

function rsaDecrypt() {
  log.debug("Entering rsaDecrypt().");
  try {
    var common = { privatePem: field('rsa', 'private_key'),
                   padding: val('enc_rsa_padding'),
                   hash: val('enc_rsa_hash') };
    var plain;
    if (!rsaIsHybrid()) {
      common.ciphertext = b64Field('rsa', 'ciphertext', 'Ciphertext');
      plain = pk.rsaDecrypt(common);
    } else {
      common.cipherId = val('enc_rsa_cipher');
      common.aad = bytes.strBytes(field('rsa', 'aad'));
      common.encapsulation = b64Field('rsa', 'encapsulation', 'Wrapped Key');
      common.iv = hexField('rsa', 'iv', 'IV');
      common.ciphertext = b64Field('rsa', 'ciphertext', 'Ciphertext');
      common.tag = b64Field('rsa', 'tag', 'Tag');
      plain = pk.rsaHybridDecrypt(common);
    }
    var note = plaintextOut('rsa', plain);
    status('rsa', 'Decrypted ' + plain.length + ' bytes.' + note);
  } catch (e) {
    log.debug("Leaving rsaDecrypt(). Failed.");
    return fail('rsa', 'rsaDecrypt', e);
  }
  log.debug("Leaving rsaDecrypt().");
  return false;
}

// ===========================================================================
// Pane #5 — ECC (ECIES)
// ===========================================================================
function eccGenerateKeys() {
  log.debug("Entering eccGenerateKeys().");
  try {
    var curve = val('enc_ecc_curve');
    var pair = pk.eciesGenerateKeyPair(curve);
    setField('ecc', 'private_key', pair.privateKeyHex);
    setField('ecc', 'public_key', pair.publicKeyHex);
    status('ecc', 'Generated a ' + pk.eciesCurve(curve).label +
           ' key pair (private ' + (pair.privateKeyHex.length / 2) +
           ' B, public ' + (pair.publicKeyHex.length / 2) + ' B).');
  } catch (e) {
    log.debug("Leaving eccGenerateKeys(). Failed.");
    return fail('ecc', 'eccGenerateKeys', e);
  }
  log.debug("Leaving eccGenerateKeys().");
  return false;
}

function eccEncrypt() {
  log.debug("Entering eccEncrypt().");
  try {
    var out = pk.eciesEncrypt({
      curve: val('enc_ecc_curve'),
      publicKeyHex: field('ecc', 'public_key'),
      info: field('ecc', 'info'),
      aad: bytes.strBytes(field('ecc', 'aad')),
      cipherId: val('enc_ecc_cipher'),
      plaintext: plaintextIn('ecc')
    });
    setField('ecc', 'encapsulation', bytes.bytesToHex(out.encapsulation));
    setField('ecc', 'iv', bytes.bytesToHex(out.iv));
    setField('ecc', 'ciphertext', bytes.bytesToB64(out.ciphertext));
    setField('ecc', 'tag', bytes.bytesToB64(out.tag));
    status('ecc', 'ECIES: a fresh ephemeral key pair agreed a secret with ' +
           'the recipient’s public key, HKDF-SHA256 turned it into a ' +
           out.cipherId + ' key, and the message is encrypted under that. ' +
           'The Ephemeral Public Key box is what the recipient needs.');
  } catch (e) {
    log.debug("Leaving eccEncrypt(). Failed.");
    return fail('ecc', 'eccEncrypt', e);
  }
  log.debug("Leaving eccEncrypt().");
  return false;
}

function eccDecrypt() {
  log.debug("Entering eccDecrypt().");
  try {
    var plain = pk.eciesDecrypt({
      curve: val('enc_ecc_curve'),
      privateKeyHex: field('ecc', 'private_key'),
      info: field('ecc', 'info'),
      aad: bytes.strBytes(field('ecc', 'aad')),
      cipherId: val('enc_ecc_cipher'),
      encapsulation: hexField('ecc', 'encapsulation', 'Ephemeral Public Key'),
      iv: hexField('ecc', 'iv', 'IV'),
      ciphertext: b64Field('ecc', 'ciphertext', 'Ciphertext'),
      tag: b64Field('ecc', 'tag', 'Tag')
    });
    var note = plaintextOut('ecc', plain);
    status('ecc', 'Decrypted ' + plain.length + ' bytes; the tag verified.' +
           note);
  } catch (e) {
    log.debug("Leaving eccDecrypt(). Failed.");
    return fail('ecc', 'eccDecrypt', e);
  }
  log.debug("Leaving eccDecrypt().");
  return false;
}

// ===========================================================================
// Pane #6 — ML-KEM (post-quantum)
// ===========================================================================
function kemIsHybrid() {
  log.debug("Entering kemIsHybrid().");
  log.debug("Leaving kemIsHybrid().");
  return val('enc_kem_mode') === 'hybrid';
}

function kemGenerateKeys() {
  log.debug("Entering kemGenerateKeys().");
  var set = val('enc_kem_set');
  status('kem', 'Generating an ' + set + ' key pair…');
  defer(function () {
    try {
      var pair = pk.mlkemGenerateKeyPair(set, kemIsHybrid());
      setField('kem', 'private_key', pair.privateKeyHex);
      setField('kem', 'public_key', pair.publicKeyHex);
      status('kem', 'Generated ' + set +
             (kemIsHybrid() ? ' + X25519 (two keys, colon-separated)' : '') +
             ' — public ' + Math.floor(pair.publicKeyHex
               .replace(':', '').length / 2) + ' B, private ' +
             Math.floor(pair.privateKeyHex.replace(':', '').length / 2) +
             ' B. Post-quantum keys are large; that is the trade.');
    } catch (e) {
      fail('kem', 'kemGenerateKeys', e);
    }
  });
  log.debug("Leaving kemGenerateKeys().");
  return false;
}

function kemEncrypt() {
  log.debug("Entering kemEncrypt().");
  try {
    var out = pk.mlkemEncrypt({
      paramSet: val('enc_kem_set'),
      hybrid: kemIsHybrid(),
      publicKeyHex: field('kem', 'public_key'),
      info: field('kem', 'info'),
      aad: bytes.strBytes(field('kem', 'aad')),
      cipherId: val('enc_kem_cipher'),
      plaintext: plaintextIn('kem')
    });
    setField('kem', 'encapsulation', out.encapsulationHex);
    setField('kem', 'iv', bytes.bytesToHex(out.iv));
    setField('kem', 'ciphertext', bytes.bytesToB64(out.ciphertext));
    setField('kem', 'tag', bytes.bytesToB64(out.tag));
    status('kem', 'Encapsulated a fresh shared secret to the recipient’s ' +
           val('enc_kem_set') + ' public key' +
           (kemIsHybrid() ? ', concatenated an X25519 one with it,' : '') +
           ' derived a ' + out.cipherId + ' key from it with HKDF-SHA256, ' +
           'and encrypted the message under that.');
  } catch (e) {
    log.debug("Leaving kemEncrypt(). Failed.");
    return fail('kem', 'kemEncrypt', e);
  }
  log.debug("Leaving kemEncrypt().");
  return false;
}

function kemDecrypt() {
  log.debug("Entering kemDecrypt().");
  try {
    var plain = pk.mlkemDecrypt({
      paramSet: val('enc_kem_set'),
      hybrid: kemIsHybrid(),
      privateKeyHex: field('kem', 'private_key'),
      info: field('kem', 'info'),
      aad: bytes.strBytes(field('kem', 'aad')),
      cipherId: val('enc_kem_cipher'),
      encapsulationHex: field('kem', 'encapsulation'),
      iv: hexField('kem', 'iv', 'IV'),
      ciphertext: b64Field('kem', 'ciphertext', 'Ciphertext'),
      tag: b64Field('kem', 'tag', 'Tag')
    });
    var note = plaintextOut('kem', plain);
    status('kem', 'Decapsulated and decrypted ' + plain.length +
           ' bytes; the tag verified.' + note);
  } catch (e) {
    log.debug("Leaving kemDecrypt(). Failed.");
    return fail('kem', 'kemDecrypt', e);
  }
  log.debug("Leaving kemDecrypt().");
  return false;
}

// ===========================================================================
// Pane #7 — the DSA family (finite-field cryptography)
// ===========================================================================
function ffcIsHybrid() {
  log.debug("Entering ffcIsHybrid().");
  log.debug("Leaving ffcIsHybrid().");
  return val('enc_ffc_mode') === 'hybrid';
}

function ffcGenerateKeys() {
  log.debug("Entering ffcGenerateKeys().");
  var group = val('enc_ffc_group');
  status('ffc', 'Generating a key pair in ' + pk.ffcGroup(group).label +
         '…');
  defer(function () {
    try {
      var pair = pk.ffcGenerateKeyPair(group);
      setField('ffc', 'private_key', pair.privateKeyHex);
      setField('ffc', 'public_key', pair.publicKeyHex);
      status('ffc', 'Generated x (private) and y = g^x mod p (public) in ' +
             pk.ffcGroup(group).label + '. The group itself is public and ' +
             'fixed — that is what a named MODP group is.');
    } catch (e) {
      fail('ffc', 'ffcGenerateKeys', e);
    }
  });
  log.debug("Leaving ffcGenerateKeys().");
  return false;
}

function ffcEncrypt() {
  log.debug("Entering ffcEncrypt().");
  try {
    var group = val('enc_ffc_group');
    if (!ffcIsHybrid()) {
      var eg = pk.elgamalEncrypt({ group: group,
                                   publicKeyHex: field('ffc', 'public_key'),
                                   plaintext: plaintextIn('ffc') });
      setField('ffc', 'encapsulation', eg.c1Hex);
      setField('ffc', 'ciphertext', eg.c2Hex);
      setField('ffc', 'iv', '');
      setField('ffc', 'tag', '');
      status('ffc', 'Textbook ElGamal: c1 = g^k and c2 = m·y^k mod p, ' +
             'shown as hex in the two boxes. It is UNAUTHENTICATED and ' +
             'malleable — multiply c2 by t and the plaintext becomes m·t, ' +
             'and the scheme itself does not object. (This page marks the ' +
             'message with a length byte, so an arbitrary mauling is ' +
             'usually caught on the way back; that is an encoding check, ' +
             'not integrity protection.) Use Hybrid for anything real.');
      log.debug("Leaving ffcEncrypt(). ElGamal.");
      return false;
    }
    var out = pk.ffcHybridEncrypt({
      group: group,
      publicKeyHex: field('ffc', 'public_key'),
      info: field('ffc', 'info'),
      aad: bytes.strBytes(field('ffc', 'aad')),
      cipherId: val('enc_ffc_cipher'),
      plaintext: plaintextIn('ffc')
    });
    setField('ffc', 'encapsulation', out.encapsulationHex);
    setField('ffc', 'iv', bytes.bytesToHex(out.iv));
    setField('ffc', 'ciphertext', bytes.bytesToB64(out.ciphertext));
    setField('ffc', 'tag', bytes.bytesToB64(out.tag));
    status('ffc', 'DHIES: an ephemeral Diffie-Hellman key pair in the same ' +
           'group agreed a secret, HKDF-SHA256 made a ' + out.cipherId +
           ' key of it, and the message is encrypted under that.');
  } catch (e) {
    log.debug("Leaving ffcEncrypt(). Failed.");
    return fail('ffc', 'ffcEncrypt', e);
  }
  log.debug("Leaving ffcEncrypt().");
  return false;
}

function ffcDecrypt() {
  log.debug("Entering ffcDecrypt().");
  try {
    var group = val('enc_ffc_group');
    var plain;
    if (!ffcIsHybrid()) {
      plain = pk.elgamalDecrypt({ group: group,
                                  privateKeyHex: field('ffc', 'private_key'),
                                  c1Hex: field('ffc', 'encapsulation'),
                                  c2Hex: field('ffc', 'ciphertext') });
    } else {
      plain = pk.ffcHybridDecrypt({
        group: group,
        privateKeyHex: field('ffc', 'private_key'),
        info: field('ffc', 'info'),
        aad: bytes.strBytes(field('ffc', 'aad')),
        cipherId: val('enc_ffc_cipher'),
        encapsulationHex: field('ffc', 'encapsulation'),
        iv: hexField('ffc', 'iv', 'IV'),
        ciphertext: b64Field('ffc', 'ciphertext', 'Ciphertext'),
        tag: b64Field('ffc', 'tag', 'Tag')
      });
    }
    var note = plaintextOut('ffc', plain);
    status('ffc', 'Decrypted ' + plain.length + ' bytes.' + note);
  } catch (e) {
    log.debug("Leaving ffcDecrypt(). Failed.");
    return fail('ffc', 'ffcDecrypt', e);
  }
  log.debug("Leaving ffcDecrypt().");
  return false;
}

// The mode dropdown drives which boxes mean anything, and the two modes here
// are genuinely different schemes rather than two settings of one.
function ffcModeChanged() {
  log.debug("Entering ffcModeChanged().");
  if (ffcIsHybrid()) {
    status('ffc', 'DHIES — any message length, authenticated, and the ' +
           'Ephemeral Public Key / IV / Tag boxes are all used.');
  } else {
    status('ffc', 'Textbook ElGamal — at most ' +
           pk.elgamalMaxBytes(val('enc_ffc_group')) + ' bytes, ' +
           'unauthenticated, and only the c1 and c2 boxes are used.');
  }
  log.debug("Leaving ffcModeChanged().");
  return false;
}

// ===========================================================================
// Pane #8 — JWE
//
// The only pane whose output is a PROTOCOL artifact rather than raw bytes,
// and the reason it belongs on this page in this project: a JWE compact
// serialization is what an OID4VCI credential response, an encrypted ID Token
// and a JAR request object all are. It is jose_jwe.js — the same module the
// issuance panes and jwt_tools use — so what this pane produces is what the
// rest of the debugger consumes.
// ===========================================================================
// NOTE THE RETURN SHAPES. jose_jwe.js's two entry points return OBJECTS —
// `{ jwe, header }` and `{ plaintext, header }` — not strings, because both
// hand back the protected header they built or read. Assigning the object to a
// field puts "[object Object]" in the box, which is what the first draft of
// this pane did; the header is used below rather than re-parsed, which is the
// reason the module returns it.
async function jweEncrypt() {
  log.debug("Entering jweEncrypt().");
  try {
    var encrypted = await jose.encryptCompact({
      alg: val('enc_jwe_alg'),
      enc: val('enc_jwe_enc'),
      key: field('jwe', 'public_key'),
      plaintext: field('jwe', 'plaintext')
    });
    setField('jwe', 'ciphertext', encrypted.jwe);
    status('jwe', 'Encrypted as a compact JWE with alg=' +
           encrypted.header.alg + ', enc=' + encrypted.header.enc +
           ' — five dot-separated segments: header, encrypted key, IV, ' +
           'ciphertext, tag.');
  } catch (e) {
    log.debug("Leaving jweEncrypt(). Failed.");
    return fail('jwe', 'jweEncrypt', e);
  }
  log.debug("Leaving jweEncrypt().");
  return false;
}

async function jweDecrypt() {
  log.debug("Entering jweDecrypt().");
  try {
    var opened = await jose.decryptCompact({ jwe: field('jwe', 'ciphertext'),
                                             key: field('jwe',
                                                        'private_key') });
    setField('jwe', 'plaintext', opened.plaintext);
    status('jwe', 'Decrypted. The JWE’s own header said alg=' +
           opened.header.alg + ', enc=' + opened.header.enc +
           ' — read from the token, not from the dropdowns.');
  } catch (e) {
    log.debug("Leaving jweDecrypt(). Failed.");
    return fail('jwe', 'jweDecrypt', e);
  }
  log.debug("Leaving jweDecrypt().");
  return false;
}

// A key pair for the JWE pane, of a kind the selected alg can actually use.
// RSA algs need an RSA key and the ECDH-ES ones need an EC key, and handing
// Web Crypto the wrong one produces a DataError from inside importKey that
// names neither.
function jweGenerateKeys() {
  log.debug("Entering jweGenerateKeys().");
  var alg = val('enc_jwe_alg');
  var spec = alg.indexOf('ECDH-ES') === 0
    ? { name: 'ECDH', namedCurve: 'P-256' }
    : { name: 'RSA-OAEP', modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' };
  status('jwe', 'Generating a key pair for ' + alg + '…');
  crypto.subtle.generateKey(spec, true,
      spec.name === 'ECDH' ? ['deriveBits'] : ['encrypt', 'decrypt'])
    .then(async function (pair) {
      var priv = bytes.derToPem(
        await crypto.subtle.exportKey('pkcs8', pair.privateKey),
        'PRIVATE KEY');
      var pub = bytes.derToPem(
        await crypto.subtle.exportKey('spki', pair.publicKey), 'PUBLIC KEY');
      setField('jwe', 'private_key', priv);
      setField('jwe', 'public_key', pub);
      status('jwe', 'Generated a ' +
             (spec.name === 'ECDH' ? 'P-256 ECDH' : '2048-bit RSA') +
             ' key pair for ' + alg + '.');
    })
    .catch(function (e) { fail('jwe', 'jweGenerateKeys', e); });
  log.debug("Leaving jweGenerateKeys().");
  return false;
}

// Web Crypto's own answer to what it will do, rather than this page's guess.
// Chrome refuses every AES-192 operation, so A192GCM is offered by the RFC and
// unusable in the browser the suite runs in — jose_jwe.js probes for it and
// this is where the answer is shown.
async function jweAlgChanged() {
  log.debug("Entering jweAlgChanged().");
  try {
    var why = await jose.encUnsupportedReason(val('enc_jwe_enc'));
    if (why) {
      status('jwe', val('enc_jwe_enc') + ' cannot be used here: ' + why + '.');
      log.debug("Leaving jweAlgChanged(). Unsupported enc.");
      return false;
    }
    status('jwe', 'alg=' + val('enc_jwe_alg') + ', enc=' +
           val('enc_jwe_enc') + '. Generate a key pair, or paste the ' +
           'recipient’s public key (PEM or JWK) to encrypt to it.');
  } catch (e) {
    log.debug("Leaving jweAlgChanged(). Failed.");
    return fail('jwe', 'jweAlgChanged', e);
  }
  log.debug("Leaving jweAlgChanged().");
  return false;
}

// ===========================================================================
// Pane #9 — password-based encryption
// ===========================================================================
var PBE_KDFS = {
  'PBKDF2-SHA256': { kind: 'pbkdf2', hash: nobleSha256,
                     label: 'PBKDF2-HMAC-SHA256' },
  'PBKDF2-SHA512': { kind: 'pbkdf2', hash: nobleSha512.sha512,
                     label: 'PBKDF2-HMAC-SHA512' },
  'scrypt': { kind: 'scrypt', label: 'scrypt' },
  'HKDF-SHA256': { kind: 'hkdf', hash: nobleSha256, label: 'HKDF-SHA256' }
};

// The derived key, and the parameters that produced it. A KDF's parameters are
// not decoration: the same password and salt with a different iteration count
// give a different key, so they are fields rather than constants and they are
// what has to travel with the ciphertext.
function pbeDeriveKey(saltBytes, keyBytes) {
  log.debug("Entering pbeDeriveKey().");
  var kdf = PBE_KDFS[val('enc_pbe_kdf')];
  if (!kdf) {
    log.debug("Leaving pbeDeriveKey(). Unknown KDF.");
    throw new Error('Unknown KDF: ' + val('enc_pbe_kdf'));
  }
  var password = bytes.strBytes(field('pbe', 'password'));
  if (!password.length) {
    log.debug("Leaving pbeDeriveKey(). No password.");
    throw new Error('Enter a password. An empty one derives a key that ' +
                    'anybody else can derive too.');
  }
  var iterations = parseInt(field('pbe', 'iterations'), 10) || 0;
  var derived;
  if (kdf.kind === 'pbkdf2') {
    if (iterations < 1) {
      log.debug("Leaving pbeDeriveKey(). Bad iteration count.");
      throw new Error('PBKDF2 needs an iteration count of at least 1 (OWASP ' +
                      'currently suggests 600,000 for HMAC-SHA256).');
    }
    derived = noblePbkdf2(kdf.hash, password, saltBytes,
                          { c: iterations, dkLen: keyBytes });
  } else if (kdf.kind === 'scrypt') {
    // N must be a power of two, which is a property of the algorithm rather
    // than of this field, so it is checked here where the message can say so.
    var n = iterations || 16384;
    if ((n & (n - 1)) !== 0) {
      log.debug("Leaving pbeDeriveKey(). N is not a power of two.");
      throw new Error('scrypt’s N (the "iterations" field here) must be ' +
                      'a power of two; ' + n + ' is not. Try 16384, 32768 ' +
                      'or 65536.');
    }
    derived = nobleScrypt(password, saltBytes,
                          { N: n, r: 8, p: 1, dkLen: keyBytes });
  } else {
    derived = nobleHkdf(kdf.hash, password, saltBytes,
                        bytes.strBytes('encryption-tools-pbe'), keyBytes);
  }
  log.debug("Leaving pbeDeriveKey().");
  return bytes.asBytes(derived);
}

function pbeGenerateSalt() {
  log.debug("Entering pbeGenerateSalt().");
  setField('pbe', 'salt', bytes.bytesToHex(bytes.randomBytes(16)));
  status('pbe', 'Generated a fresh 16-byte salt. A salt is public and goes ' +
         'with the ciphertext — what it stops is one precomputed table ' +
         'attacking every password at once.');
  log.debug("Leaving pbeGenerateSalt().");
  return false;
}

function pbeDeriveOnly() {
  log.debug("Entering pbeDeriveOnly().");
  status('pbe', 'Deriving — a deliberately slow function, which is what ' +
         'makes it a password KDF…');
  defer(function () {
    try {
      var spec = symmetric.describe(val('enc_pbe_cipher'));
      var salt = hexField('pbe', 'salt', 'Salt');
      var started = Date.now();
      var key = pbeDeriveKey(salt, spec.keyBytes);
      setField('pbe', 'key', bytes.bytesToHex(key));
      status('pbe', 'Derived a ' + (spec.keyBytes * 8) + '-bit key with ' +
             PBE_KDFS[val('enc_pbe_kdf')].label + ' in ' +
             (Date.now() - started) + ' ms. That time is the point: it is ' +
             'paid once by you and once per guess by an attacker.');
    } catch (e) {
      fail('pbe', 'pbeDeriveOnly', e);
    }
  });
  log.debug("Leaving pbeDeriveOnly().");
  return false;
}

function pbeEncrypt() {
  log.debug("Entering pbeEncrypt().");
  status('pbe', 'Deriving the key and encrypting…');
  defer(function () {
    try {
      var id = val('enc_pbe_cipher');
      var spec = symmetric.describe(id);
      var salt = hexField('pbe', 'salt', 'Salt');
      var key = pbeDeriveKey(salt, spec.keyBytes);
      setField('pbe', 'key', bytes.bytesToHex(key));
      var iv = symmetric.generateIv(id);
      var out = symmetric.encrypt({ id: id, key: key, iv: iv,
                                    plaintext: plaintextIn('pbe') });
      setField('pbe', 'iv', bytes.bytesToHex(iv));
      setField('pbe', 'ciphertext', bytes.bytesToB64(out.ciphertext));
      setField('pbe', 'tag', bytes.bytesToB64(out.tag));
      status('pbe', 'Encrypted with ' + spec.label + ' under a key derived ' +
             'from the password. Keep the salt, the IV and the KDF ' +
             'parameters — without them the password alone will not ' +
             'open this.');
    } catch (e) {
      fail('pbe', 'pbeEncrypt', e);
    }
  });
  log.debug("Leaving pbeEncrypt().");
  return false;
}

function pbeDecrypt() {
  log.debug("Entering pbeDecrypt().");
  status('pbe', 'Deriving the key and decrypting…');
  defer(function () {
    try {
      var id = val('enc_pbe_cipher');
      var spec = symmetric.describe(id);
      var salt = hexField('pbe', 'salt', 'Salt');
      var key = pbeDeriveKey(salt, spec.keyBytes);
      setField('pbe', 'key', bytes.bytesToHex(key));
      var plain = symmetric.decrypt({
        id: id, key: key, iv: hexField('pbe', 'iv', 'IV'),
        ciphertext: b64Field('pbe', 'ciphertext', 'Ciphertext'),
        tag: b64Field('pbe', 'tag', 'Tag')
      });
      var note = plaintextOut('pbe', plain);
      status('pbe', 'Decrypted ' + plain.length + ' bytes; the tag ' +
             'verified, which also says the password was right.' + note);
    } catch (e) {
      fail('pbe', 'pbeDecrypt', e);
    }
  });
  log.debug("Leaving pbeDecrypt().");
  return false;
}

// The JOSE form of the same idea, and the one that is a wire format: a compact
// PBES2 JWE, which is exactly what the Download Keys button writes when a
// password is given on either of these two pages.
async function pbeToJwe() {
  log.debug("Entering pbeToJwe().");
  try {
    var password = field('pbe', 'password');
    if (!password) {
      status('pbe', 'Enter a password first.');
      log.debug("Leaving pbeToJwe(). No password.");
      return false;
    }
    var compact = await jose.pbes2JweEncrypt(field('pbe', 'plaintext'),
                                             password);
    setField('pbe', 'ciphertext', compact);
    setField('pbe', 'tag', '');
    setField('pbe', 'iv', '');
    status('pbe', 'Wrapped as a compact PBES2 JWE ' +
           '(PBES2-HS256+A128KW over A256GCM, 100,000 iterations). The salt ' +
           'and the iteration count are inside its header, which is why this ' +
           'one needs nothing kept beside it but the password.');
  } catch (e) {
    log.debug("Leaving pbeToJwe(). Failed.");
    return fail('pbe', 'pbeToJwe', e);
  }
  log.debug("Leaving pbeToJwe().");
  return false;
}

// ===========================================================================
// Key pair downloads — the same keystore matrix the Digital Signature page
// offers, from the same module (key_material.js), because a key pair is a key
// pair whatever it was generated for.
// ===========================================================================
function downloadRsaKeys() {
  log.debug("Entering downloadRsaKeys().");
  var format = val('enc_rsa_ks_format') || 'pem';
  var password = val('enc_rsa_ks_password');
  status('rsa', 'Preparing ' + format.toUpperCase() + '…');
  defer(async function () {
    try {
      var descriptor = { kind: 'rsa', hash: 'SHA-256' };
      var privatePem = field('rsa', 'private_key');
      var publicPem = field('rsa', 'public_key');
      // PKCS#12 has nowhere to put a bare key: the format is a key bag beside
      // a CERTIFICATE bag. key_material.js deliberately does not mint one (it
      // would have to depend on x509.js, which depends on it), so the page
      // supplies the throwaway — the same call jwt_tools makes, from the same
      // module, differing only in the subject that says which page made it.
      var certs = [];
      if (format === 'pkcs12' && privatePem.trim() && publicPem.trim()) {
        certs = [await x509.selfSignedCertPem({
          subject: 'CN=encryption-tools generated key',
          privatePem: privatePem,
          publicPem: publicPem,
          desc: descriptor
        })];
      }
      var result = await keyMaterial.exportKeyPair({
        privatePem: privatePem,
        publicPem: publicPem,
        desc: descriptor,
        format: format,
        password: password,
        friendlyName: 'encryption-tools',
        use: 'enc',
        certs: certs,
        baseName: 'rsa-encryption-keys'
      });
      keyMaterial.downloadFiles(result.files);
      status('rsa', result.status);
    } catch (e) {
      fail('rsa', 'downloadRsaKeys', e);
    }
  });
  log.debug("Leaving downloadRsaKeys().");
  return false;
}

// The three raw-byte panes. Their keys are not ASN.1 structures — an ML-KEM
// key is a byte string and an ECIES private key is a scalar — so PEM here is
// framing rather than an encoding anything else will parse, and JWK is offered
// only where a registered `kty` exists for it. Saying so beats emitting a file
// that looks like a keystore and opens in nothing.
function downloadRawKeys(prefix, baseName, jwkBuilder) {
  log.debug("Entering downloadRawKeys(). prefix=" + prefix);
  var format = val('enc_' + prefix + '_ks_format') || 'pem';
  var password = val('enc_' + prefix + '_ks_password');
  var priv = field(prefix, 'private_key'), pub = field(prefix, 'public_key');
  if (!priv && !pub) {
    status(prefix, 'Nothing to download — generate a key pair first.');
    log.debug("Leaving downloadRawKeys(). Nothing to export.");
    return false;
  }
  defer(async function () {
    try {
      if (format === 'pem') {
        if (password) {
          status(prefix, 'These keys are raw bytes rather than a PKCS#8 ' +
                 'structure, so there is no standard encrypted PEM for ' +
                 'them. Choose JWK to password-protect the download.');
          return;
        }
        panes.triggerDownload(baseName + '.pem',
          bytes.rawToPem(bytes.hexToBytes(pub),
                         baseName.toUpperCase() + ' PUBLIC KEY') +
          bytes.rawToPem(bytes.hexToBytes(priv),
                         baseName.toUpperCase() + ' PRIVATE KEY'),
          'application/x-pem-file');
        status(prefix, 'Downloaded ' + baseName + '.pem (raw keys in PEM ' +
               'framing).');
        return;
      }
      if (format === 'jwk') {
        var jwks = jwkBuilder(priv, pub);
        if (!jwks) {
          status(prefix, 'There is no registered JWK key type for these ' +
                 'keys, so a JWK export would be inventing one. Use PEM, or ' +
                 'copy the hex out of the key fields.');
          return;
        }
        await panes.downloadJwkSet(jwks, password, baseName,
                                   fieldId(prefix, 'status'));
        return;
      }
      status(prefix, format.toUpperCase() + ' export is not defined for ' +
             'these raw keys. Use PEM or JWK.');
    } catch (e) {
      fail(prefix, 'downloadRawKeys', e);
    }
  });
  log.debug("Leaving downloadRawKeys().");
  return false;
}

// ECIES keys DO have a JWK form on the Weierstrass curves (kty EC) and on
// X25519 (kty OKP, RFC 8037) — and `use: "enc"` rather than `"sig"`, which is
// the one member that differs from the Digital Signature page's ECC pane and
// the whole reason these are separate keys.
function eccJwkSet(privHex, pubHex) {
  log.debug("Entering eccJwkSet().");
  var curveId = val('enc_ecc_curve');
  var descriptor = pk.eciesCurve(curveId);
  var priv = bytes.hexToBytes(privHex);
  if (descriptor.montgomery) {
    var pub = bytes.hexToBytes(pubHex);
    log.debug("Leaving eccJwkSet(). OKP.");
    return [
      { kty: 'OKP', crv: 'X25519', x: bytes.bytesToB64u(pub), use: 'enc' },
      { kty: 'OKP', crv: 'X25519', x: bytes.bytesToB64u(pub),
        d: bytes.bytesToB64u(priv), use: 'enc' }
    ];
  }
  var point = descriptor.curve.ProjectivePoint.fromHex(pubHex).toAffine();
  var size = Math.ceil(descriptor.curve.CURVE.Fp.BITS / 8);
  var x = bytes.bytesToB64u(bytes.bigToBytes(point.x, size));
  var y = bytes.bytesToB64u(bytes.bigToBytes(point.y, size));
  var crv = curveId === 'secp256k1' ? 'secp256k1' : curveId;
  log.debug("Leaving eccJwkSet(). EC.");
  return [
    { kty: 'EC', crv: crv, x: x, y: y, use: 'enc' },
    { kty: 'EC', crv: crv, x: x, y: y, d: bytes.bytesToB64u(priv),
      use: 'enc' }
  ];
}

function downloadEccKeys() {
  log.debug("Entering downloadEccKeys().");
  log.debug("Leaving downloadEccKeys().");
  return downloadRawKeys('ecc', 'ecies-keys', eccJwkSet);
}

function downloadKemKeys() {
  log.debug("Entering downloadKemKeys().");
  log.debug("Leaving downloadKemKeys().");
  // No registered JWK kty for ML-KEM: the AKP type covers the post-quantum
  // SIGNATURE schemes, and inventing a member for a KEM would produce a file
  // that no other implementation reads. PEM framing only, and the pane says
  // so rather than pretending.
  return downloadRawKeys('kem', 'ml-kem-keys', function () {
    log.debug("Entering kemJwkSet().");
    log.debug("Leaving kemJwkSet(). None defined.");
    return null;
  });
}

function downloadFfcKeys() {
  log.debug("Entering downloadFfcKeys().");
  log.debug("Leaving downloadFfcKeys().");
  return downloadRawKeys('ffc', 'ffc-keys', function () {
    log.debug("Entering ffcJwkSet().");
    log.debug("Leaving ffcJwkSet(). None defined.");
    return null;
  });
}

// ===========================================================================
// Page plumbing
// ===========================================================================
var RETURN_TARGETS = {
  'oauth2_oidc_1.html': { href: '/oauth2_oidc_1.html', label: 'debugger' },
  'oauth2_oidc_2.html': { href: '/oauth2_oidc_2.html', label: 'debugger' },
  'digital_signature.html': { href: '/digital_signature.html',
                              label: 'Digital Signature' },
  'jwt_tools.html': { href: '/jwt_tools.html', label: 'JWT Tools' },
  'encoding_tools.html': { href: '/encoding_tools.html',
                           label: 'Encoding / Hashing Tools' },
  'pki.html': { href: '/pki.html',
                label: 'Certificate Authority & X.509 Tools' }
};

function expandAll() {
  log.debug("Entering expandAll().");
  log.debug("Leaving expandAll().");
  return panes.expandAll();
}

function collapseAll() {
  log.debug("Entering collapseAll().");
  log.debug("Leaving collapseAll().");
  return panes.collapseAll();
}

function copyField(elementId) {
  log.debug("Entering copyField().");
  log.debug("Leaving copyField().");
  return panes.copyField(elementId);
}

// Seed every pane with something that works, so the first press of a button on
// any of them does something rather than reporting an empty field. The
// asymmetric panes are seeded with a MESSAGE only: generating four key pairs
// at load would cost seconds of pure JS on a page most visitors open to use
// one pane.
function seedPanes() {
  log.debug("Entering seedPanes().");
  SYM_PANES.forEach(function (prefix) {
    setField(prefix, 'plaintext', 'Encrypt me.');
    symGenerateKey(prefix);
  });
  setField('aes', 'aad', 'bound, not hidden');
  setField('cc', 'aad', 'bound, not hidden');
  setField('rsa', 'plaintext', 'Encrypt me with RSA.');
  setField('ecc', 'plaintext', 'Encrypt me with ECIES.');
  setField('ecc', 'info', 'encryption-tools/ecies');
  setField('kem', 'plaintext', 'Encrypt me with ML-KEM.');
  setField('kem', 'info', 'encryption-tools/ml-kem');
  setField('ffc', 'plaintext', 'Encrypt me with ElGamal.');
  setField('ffc', 'info', 'encryption-tools/dhies');
  setField('jwe', 'plaintext', '{"sub":"alice","iss":"https://idp.example"}');
  setField('pbe', 'plaintext', 'Encrypt me with a password.');
  setField('pbe', 'password', 'correct horse battery staple');
  setField('pbe', 'iterations', '600000');
  pbeGenerateSalt();
  log.debug("Leaving seedPanes().");
}

window.onload = function () {
  log.debug("Entering onload().");
  panes.setReturnLink(RETURN_TARGETS, '/oauth2_oidc_1.html');
  seedPanes();
  panes.wireCollapsibleLegends();
  // Every pane starts collapsed: nine of them expanded is a page you scroll
  // past to reach the one you came for, and the titles are the index.
  panes.collapseAll();
  log.debug("Leaving onload().");
};

module.exports = {
  // symmetric panes (one implementation, three panes)
  symGenerateKey,
  symGenerateIv,
  symAlgChanged,
  symEncrypt,
  symDecrypt,
  // RSA
  rsaGenerateKeys,
  rsaOptionsChanged,
  rsaEncrypt,
  rsaDecrypt,
  downloadRsaKeys,
  // ECIES
  eccGenerateKeys,
  eccEncrypt,
  eccDecrypt,
  downloadEccKeys,
  // ML-KEM
  kemGenerateKeys,
  kemEncrypt,
  kemDecrypt,
  downloadKemKeys,
  // finite field / DSA family
  ffcGenerateKeys,
  ffcEncrypt,
  ffcDecrypt,
  ffcModeChanged,
  downloadFfcKeys,
  // JWE
  jweGenerateKeys,
  jweEncrypt,
  jweDecrypt,
  jweAlgChanged,
  // password-based
  pbeGenerateSalt,
  pbeDeriveOnly,
  pbeEncrypt,
  pbeDecrypt,
  pbeToJwe,
  // page chrome
  expandAll,
  collapseAll,
  copyField
};
