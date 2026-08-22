// File: symmetric_crypto.js
//
// ---------------------------------------------------------------------------
// The symmetric primitives: block ciphers, their modes, one stream cipher, and
// the MAC constructions built on top of them.
//
// It exists because two pages need the same engines. The Digital Signature
// page's three symmetric-MAC panes had AES-CMAC, AES-CBC-MAC, AES-GMAC,
// Poly1305 and SipHash-2-4 written inside the page bundle; the Encryption /
// Decryption page needs AES, 3DES, DES and ChaCha20-Poly1305, and
// ChaCha20-Poly1305 needs that same Poly1305. A second Poly1305 would have
// been a second reading of RFC 8439 section 2.5, and the failure mode of
// getting one of those subtly wrong is a tag that verifies against your own
// implementation and nobody else's — which is precisely the class of defect
// this tree keeps its wire formats in one place to avoid.
//
// NO DOM. Everything takes and returns bytes, so tests/crypto_engines.js drives
// all of it in node against the RFCs' own vectors.
//
// WHY node-forge RATHER THAN THE WEB CRYPTO API, deliberately and for all of
// it. crypto.subtle offers AES in GCM, CBC and CTR and nothing else — no CFB,
// no OFB, no ECB, no DES, no 3DES — and Chrome refuses every AES-192 operation
// outright (jose_jwe.js carries a capability probe for exactly that, and
// docs/encryption.md records it). A page whose point is to show what a mode
// does cannot offer three of the six and refuse a key size, so the block
// ciphers here are forge's pure-JS implementations throughout, which behave
// identically in every browser and in node. ChaCha20 is written out below
// because forge does not have it.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
var forge = require("node-forge");
var bytes = require("./crypto_bytes");

// A node consumer (the tests load this module directly) may have no
// CONFIG_FILE, so fall back to info rather than failing to load.
var log = bunyan.createLogger({
  name: "symmetric_crypto",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var asBytes = bytes.asBytes;
var concatBytes = bytes.concatBytes;
var bytesEqual = bytes.bytesEqual;
var randomBytes = bytes.randomBytes;

// BigInt LITERALS ARE FORBIDDEN in client/src — envify's esprima predates them
// and rejects the file, in whichever bundle happens to require it. See
// client/CLAUDE.md. Hoisted here for Poly1305 and SipHash below.
var _B0 = BigInt(0), _B1 = BigInt(1), _B5 = BigInt(5), _B8 = BigInt(8);
var _B64 = BigInt(64), _B128 = BigInt(128), _B130 = BigInt(130);
var _BFF = BigInt(0xff);

// ---------------------------------------------------------------------------
// forge speaks BINARY STRINGS; everything else here speaks Uint8Array. These
// two are the only place that boundary is crossed.
// ---------------------------------------------------------------------------
function toForge(input) {
  log.debug("Entering toForge().");
  log.debug("Leaving toForge().");
  return forge.util.binary.raw.encode(asBytes(input));
}

function fromForge(binary) {
  log.debug("Entering fromForge().");
  log.debug("Leaving fromForge().");
  return forge.util.binary.raw.decode(binary);
}

// ---------------------------------------------------------------------------
// THE CIPHER CATALOGUE.
//
// `forgeAlg` is what forge is asked for. `keyBytes` and `ivBytes` are what the
// page generates and what a pasted value is measured against — a key of the
// wrong length is the single most common thing to get wrong here, and forge
// answers it with a range error from inside its own buffer code.
//
// `aead` marks the two that authenticate: only those produce and require a
// tag, and only those accept additional authenticated data. Everything else is
// confidentiality alone, which the page says out loud beside each of them,
// because "it decrypted to the wrong thing silently" is the property that
// separates these two groups and it is not visible from the ciphertext.
//
// `padded` marks the modes that need whole blocks (forge applies and strips
// PKCS#7 itself); the stream-shaped modes take any length.
//
// `security` is what the UI badges. It is not advice about whether to press
// the button — this is a debugger, and reproducing what a legacy system did is
// most of why DES is here at all.
// ---------------------------------------------------------------------------
var CIPHERS = {
  'AES-128-GCM': { family: 'aes', forgeAlg: 'AES-GCM', keyBytes: 16,
                   ivBytes: 12, aead: true, padded: false,
                   label: 'AES-128-GCM' },
  'AES-192-GCM': { family: 'aes', forgeAlg: 'AES-GCM', keyBytes: 24,
                   ivBytes: 12, aead: true, padded: false,
                   label: 'AES-192-GCM' },
  'AES-256-GCM': { family: 'aes', forgeAlg: 'AES-GCM', keyBytes: 32,
                   ivBytes: 12, aead: true, padded: false,
                   label: 'AES-256-GCM' },
  'AES-128-CBC': { family: 'aes', forgeAlg: 'AES-CBC', keyBytes: 16,
                   ivBytes: 16, aead: false, padded: true,
                   label: 'AES-128-CBC' },
  'AES-192-CBC': { family: 'aes', forgeAlg: 'AES-CBC', keyBytes: 24,
                   ivBytes: 16, aead: false, padded: true,
                   label: 'AES-192-CBC' },
  'AES-256-CBC': { family: 'aes', forgeAlg: 'AES-CBC', keyBytes: 32,
                   ivBytes: 16, aead: false, padded: true,
                   label: 'AES-256-CBC' },
  'AES-256-CTR': { family: 'aes', forgeAlg: 'AES-CTR', keyBytes: 32,
                   ivBytes: 16, aead: false, padded: false,
                   label: 'AES-256-CTR' },
  'AES-256-CFB': { family: 'aes', forgeAlg: 'AES-CFB', keyBytes: 32,
                   ivBytes: 16, aead: false, padded: false,
                   label: 'AES-256-CFB' },
  'AES-256-OFB': { family: 'aes', forgeAlg: 'AES-OFB', keyBytes: 32,
                   ivBytes: 16, aead: false, padded: false,
                   label: 'AES-256-OFB' },
  // ECB has no IV, which is the whole of what is wrong with it: the same
  // plaintext block encrypts to the same ciphertext block every time, so the
  // ciphertext carries the plaintext's structure. The page demonstrates that
  // rather than describing it.
  'AES-256-ECB': { family: 'aes', forgeAlg: 'AES-ECB', keyBytes: 32,
                   ivBytes: 0, aead: false, padded: true,
                   security: 'insecure', label: 'AES-256-ECB' },

  // 3DES. 24 bytes is keying option 1, three independent keys (K1 K2 K3) run
  // encrypt-decrypt-encrypt. A 16-byte key is keying option 2, where K3 = K1 —
  // and `twoKey` is what says so, because forge implements only the 24-byte
  // form and answers a 16-byte key with `Invalid Triple-DES key size: 128`,
  // from inside its own DES code. Two-key 3DES is not a different algorithm,
  // it is the same one with a key that repeats, so expandDesKey() below builds
  // K1 K2 K1 and hands forge that. Both are offered because a legacy system
  // that has one of them rarely has the other.
  '3DES-192-CBC': { family: 'des', forgeAlg: '3DES-CBC', keyBytes: 24,
                    ivBytes: 8, aead: false, padded: true,
                    security: 'legacy', label: '3DES (three-key) CBC' },
  '3DES-128-CBC': { family: 'des', forgeAlg: '3DES-CBC', keyBytes: 16,
                    ivBytes: 8, aead: false, padded: true, twoKey: true,
                    security: 'legacy', label: '3DES (two-key) CBC' },
  '3DES-192-ECB': { family: 'des', forgeAlg: '3DES-ECB', keyBytes: 24,
                    ivBytes: 0, aead: false, padded: true,
                    security: 'insecure', label: '3DES (three-key) ECB' },

  // Single DES: a 56-bit effective key, brute-forced in public in 1998. It is
  // here to read something old, and it says so.
  'DES-CBC': { family: 'des', forgeAlg: 'DES-CBC', keyBytes: 8, ivBytes: 8,
               aead: false, padded: true, security: 'broken',
               label: 'DES-CBC' },
  'DES-ECB': { family: 'des', forgeAlg: 'DES-ECB', keyBytes: 8, ivBytes: 0,
               aead: false, padded: true, security: 'broken',
               label: 'DES-ECB' },

  // RFC 8439. The nonce is 12 bytes and MUST NOT repeat under one key — the
  // page generates a fresh one per encryption for that reason.
  'CHACHA20-POLY1305': { family: 'chacha', keyBytes: 32, ivBytes: 12,
                         aead: true, padded: false,
                         label: 'ChaCha20-Poly1305' },
  'CHACHA20': { family: 'chacha', keyBytes: 32, ivBytes: 12, aead: false,
                padded: false, label: 'ChaCha20 (raw keystream)' }
};

// The order the dropdowns show them in. An object's key order is not a
// contract, and two pages listing the same ciphers differently is a difference
// only a screenshot would find.
var CIPHER_ORDER = ['AES-256-GCM', 'AES-192-GCM', 'AES-128-GCM',
                    'AES-256-CBC', 'AES-192-CBC', 'AES-128-CBC',
                    'AES-256-CTR', 'AES-256-CFB', 'AES-256-OFB',
                    'AES-256-ECB',
                    'CHACHA20-POLY1305', 'CHACHA20',
                    '3DES-192-CBC', '3DES-128-CBC', '3DES-192-ECB',
                    'DES-CBC', 'DES-ECB'];

function cipherIds() {
  log.debug("Entering cipherIds().");
  log.debug("Leaving cipherIds().");
  return CIPHER_ORDER.slice();
}

// The descriptor for a cipher id. Returns null for an unknown id rather than
// throwing, so a page can say "this build does not know that cipher" against a
// value a newer one wrote.
function cipher(id) {
  log.debug("Entering cipher(). id=" + id);
  var found = CIPHERS[String(id || '').toUpperCase()] || null;
  log.debug("Leaving cipher().");
  return found ? Object.assign({ id: String(id).toUpperCase() }, found) : null;
}

function describe(id) {
  log.debug("Entering describe().");
  var spec = cipher(id);
  if (!spec) {
    log.debug("Leaving describe(). Unknown.");
    throw new Error('Unknown cipher: ' + id);
  }
  log.debug("Leaving describe().");
  return spec;
}

function generateKey(id) {
  log.debug("Entering generateKey(). id=" + id);
  var spec = describe(id);
  log.debug("Leaving generateKey().");
  return randomBytes(spec.keyBytes);
}

// An IV / nonce for one message. Zero-length for the modes that have none, so
// a caller never has to special-case ECB.
function generateIv(id) {
  log.debug("Entering generateIv(). id=" + id);
  var spec = describe(id);
  log.debug("Leaving generateIv().");
  return spec.ivBytes ? randomBytes(spec.ivBytes) : new Uint8Array(0);
}

// Check a key and IV the user supplied before forge does, so the message names
// the field and the length rather than arriving from inside a buffer.
function checkMaterial(spec, key, iv) {
  log.debug("Entering checkMaterial().");
  if (key.length !== spec.keyBytes) {
    log.debug("Leaving checkMaterial(). Wrong key length.");
    throw new Error(spec.label + ' needs a ' + spec.keyBytes + '-byte key (' +
                    (spec.keyBytes * 8) + '-bit); this one is ' + key.length +
                    ' bytes.');
  }
  if (spec.ivBytes && iv.length !== spec.ivBytes) {
    log.debug("Leaving checkMaterial(). Wrong IV length.");
    throw new Error(spec.label + ' needs a ' + spec.ivBytes + '-byte ' +
                    (spec.aead ? 'nonce' : 'IV') + '; this one is ' +
                    iv.length + ' bytes.');
  }
  if (!spec.ivBytes && iv.length) {
    log.debug("Leaving checkMaterial(). IV supplied for a mode with none.");
    throw new Error(spec.label + ' takes no IV — ECB encrypts every block ' +
                    'independently, which is exactly why it leaks structure.');
  }
  log.debug("Leaving checkMaterial().");
}

// ---------------------------------------------------------------------------
// encrypt / decrypt
//
// One shape for every cipher: bytes in, bytes out, and an authentication tag
// alongside rather than glued on. Keeping the tag OUT of the ciphertext is
// deliberate — the page shows it in its own field, because "where does the tag
// go" is a real interoperability question (JWE puts it in its own segment,
// OpenSSL appends it, TLS records carry it at the end) and a tool that silently
// picks one has answered it for you.
// ---------------------------------------------------------------------------
function encrypt(options) {
  log.debug("Entering encrypt(). id=" + (options || {}).id);
  var opts = options || {};
  var spec = describe(opts.id);
  var key = asBytes(opts.key), iv = asBytes(opts.iv || new Uint8Array(0));
  var plaintext = asBytes(opts.plaintext);
  var aad = asBytes(opts.aad || new Uint8Array(0));
  checkMaterial(spec, key, iv);
  if (aad.length && !spec.aead) {
    log.debug("Leaving encrypt(). AAD given to a cipher that has none.");
    throw new Error(spec.label + ' is not authenticated, so it has nowhere ' +
                    'to put additional authenticated data. Use a GCM or ' +
                    'ChaCha20-Poly1305 option for that.');
  }
  if (spec.family === 'chacha') {
    var chacha = spec.aead
      ? chacha20Poly1305Encrypt(key, iv, plaintext, aad)
      : { ciphertext: chacha20(key, iv, plaintext, 1),
          tag: new Uint8Array(0) };
    log.debug("Leaving encrypt(). ChaCha20.");
    return { ciphertext: chacha.ciphertext, tag: chacha.tag, iv: iv };
  }
  var engine = forge.cipher.createCipher(spec.forgeAlg,
      forge.util.createBuffer(toForge(expandDesKey(spec, key))));
  var start = {};
  if (spec.ivBytes) start.iv = toForge(iv);
  if (spec.aead) {
    start.additionalData = toForge(aad);
    start.tagLength = 128;
  }
  engine.start(start);
  engine.update(forge.util.createBuffer(toForge(plaintext)));
  if (!engine.finish()) {
    log.debug("Leaving encrypt(). forge refused.");
    throw new Error('Encryption failed in ' + spec.label + '.');
  }
  var tag = spec.aead ? fromForge(engine.mode.tag.getBytes())
                      : new Uint8Array(0);
  log.debug("Leaving encrypt().");
  return { ciphertext: fromForge(engine.output.getBytes()), tag: tag, iv: iv };
}

function decrypt(options) {
  log.debug("Entering decrypt(). id=" + (options || {}).id);
  var opts = options || {};
  var spec = describe(opts.id);
  var key = asBytes(opts.key), iv = asBytes(opts.iv || new Uint8Array(0));
  var ciphertext = asBytes(opts.ciphertext);
  var aad = asBytes(opts.aad || new Uint8Array(0));
  var tag = asBytes(opts.tag || new Uint8Array(0));
  checkMaterial(spec, key, iv);
  if (spec.aead && tag.length !== 16) {
    log.debug("Leaving decrypt(). No tag.");
    throw new Error(spec.label + ' is authenticated and needs its 16-byte ' +
                    'tag to verify; this one is ' + tag.length + ' bytes. ' +
                    'Without it there is nothing to detect a modified ' +
                    'ciphertext with.');
  }
  if (spec.padded && (ciphertext.length === 0 ||
      ciphertext.length % blockBytes(spec) !== 0)) {
    log.debug("Leaving decrypt(). Not a whole number of blocks.");
    throw new Error(spec.label + ' is a block mode, so the ciphertext must ' +
                    'be a whole number of ' + blockBytes(spec) +
                    '-byte blocks; this one is ' + ciphertext.length +
                    ' bytes.');
  }
  if (spec.family === 'chacha') {
    var plain = spec.aead
      ? chacha20Poly1305Decrypt(key, iv, ciphertext, aad, tag)
      : chacha20(key, iv, ciphertext, 1);
    log.debug("Leaving decrypt(). ChaCha20.");
    return plain;
  }
  var engine = forge.cipher.createDecipher(spec.forgeAlg,
      forge.util.createBuffer(toForge(expandDesKey(spec, key))));
  var start = {};
  if (spec.ivBytes) start.iv = toForge(iv);
  if (spec.aead) {
    start.additionalData = toForge(aad);
    start.tagLength = 128;
    start.tag = forge.util.createBuffer(toForge(tag));
  }
  engine.start(start);
  engine.update(forge.util.createBuffer(toForge(ciphertext)));
  if (!engine.finish()) {
    // forge returns false for two different facts and the difference matters
    // to whoever is reading the screen, so they are separated here.
    log.debug("Leaving decrypt(). forge refused.");
    throw new Error(spec.aead
      ? 'The authentication tag did not verify. The key, the nonce, the ' +
        'additional authenticated data or the ciphertext is not what it was ' +
        'encrypted with — an authenticated cipher cannot tell you which.'
      : 'Decryption failed: the PKCS#7 padding is not valid. With an ' +
        'unauthenticated mode that usually means the wrong key or IV, but ' +
        'note that padding is all this mode checks — a modified ciphertext ' +
        'can decrypt "successfully" to something else.');
  }
  log.debug("Leaving decrypt().");
  return fromForge(engine.output.getBytes());
}

function blockBytes(spec) {
  log.debug("Entering blockBytes().");
  log.debug("Leaving blockBytes().");
  return spec.family === 'des' ? 8 : 16;
}

// Two-key 3DES (NIST SP 800-67 keying option 2) is K1 K2 K1. forge implements
// only the 24-byte form, so the third subkey is materialised here rather than
// the option being dropped — a legacy system's 16-byte key is exactly the one
// somebody comes to this page holding. Every other cipher passes through.
function expandDesKey(spec, key) {
  log.debug("Entering expandDesKey().");
  if (!spec.twoKey) {
    log.debug("Leaving expandDesKey(). Not two-key.");
    return key;
  }
  log.debug("Leaving expandDesKey(). K1 K2 K1.");
  return concatBytes(key, key.slice(0, 8));
}

// ---------------------------------------------------------------------------
// ChaCha20 and Poly1305 — RFC 8439.
//
// Written out because forge has no ChaCha, and checked against the RFC's own
// vectors in tests/crypto_engines.js. The quarter-round and the block function
// are the one HOT PATH in this file: chacha20Block() runs once per 64 bytes of
// message and quarterRound() eighty times inside each of those, so neither
// carries the Entering/Leaving pair the house style asks for. That omission is
// deliberate and is noted here rather than left to be read as an oversight —
// see the hot-path exception in the repo-root CLAUDE.md.
// ---------------------------------------------------------------------------
function rotl32(value, count) {
  return ((value << count) | (value >>> (32 - count))) >>> 0;
}

function quarterRound(state, a, b, c, d) {
  state[a] = (state[a] + state[b]) >>> 0;
  state[d] = rotl32(state[d] ^ state[a], 16);
  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = rotl32(state[b] ^ state[c], 12);
  state[a] = (state[a] + state[b]) >>> 0;
  state[d] = rotl32(state[d] ^ state[a], 8);
  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = rotl32(state[b] ^ state[c], 7);
}

function le32(buffer, offset) {
  return (buffer[offset] | (buffer[offset + 1] << 8) |
          (buffer[offset + 2] << 16) | (buffer[offset + 3] << 24)) >>> 0;
}

// One 64-byte keystream block for the given counter.
function chacha20Block(key, nonce, counter) {
  var state = new Uint32Array(16);
  // "expand 32-byte k"
  state[0] = 0x61707865; state[1] = 0x3320646e;
  state[2] = 0x79622d32; state[3] = 0x6b206574;
  var i;
  for (i = 0; i < 8; i++) state[4 + i] = le32(key, i * 4);
  state[12] = counter >>> 0;
  for (i = 0; i < 3; i++) state[13 + i] = le32(nonce, i * 4);
  var working = state.slice();
  for (i = 0; i < 10; i++) {
    quarterRound(working, 0, 4, 8, 12);
    quarterRound(working, 1, 5, 9, 13);
    quarterRound(working, 2, 6, 10, 14);
    quarterRound(working, 3, 7, 11, 15);
    quarterRound(working, 0, 5, 10, 15);
    quarterRound(working, 1, 6, 11, 12);
    quarterRound(working, 2, 7, 8, 13);
    quarterRound(working, 3, 4, 9, 14);
  }
  var out = new Uint8Array(64);
  for (i = 0; i < 16; i++) {
    var word = (working[i] + state[i]) >>> 0;
    out[i * 4] = word & 0xff;
    out[i * 4 + 1] = (word >>> 8) & 0xff;
    out[i * 4 + 2] = (word >>> 16) & 0xff;
    out[i * 4 + 3] = (word >>> 24) & 0xff;
  }
  return out;
}

// The stream cipher itself. `counter` is 1 for the AEAD's payload, because
// block 0 is spent generating the Poly1305 one-time key; RFC 8439 section 2.4
// starts a bare ChaCha20 at 1 as well.
function chacha20(key, nonce, input, counter) {
  log.debug("Entering chacha20().");
  var keyBytes = asBytes(key), nonceBytes = asBytes(nonce);
  var data = asBytes(input);
  if (keyBytes.length !== 32) {
    log.debug("Leaving chacha20(). Bad key length.");
    throw new Error('ChaCha20 needs a 32-byte key; this one is ' +
                    keyBytes.length + ' bytes.');
  }
  if (nonceBytes.length !== 12) {
    log.debug("Leaving chacha20(). Bad nonce length.");
    throw new Error('ChaCha20 needs a 12-byte nonce; this one is ' +
                    nonceBytes.length + ' bytes.');
  }
  var out = new Uint8Array(data.length);
  var block = null;
  for (var i = 0; i < data.length; i++) {
    if (i % 64 === 0) {
      block = chacha20Block(keyBytes, nonceBytes,
                            (counter === undefined ? 1 : counter) + (i >> 6));
    }
    out[i] = data[i] ^ block[i % 64];
  }
  log.debug("Leaving chacha20().");
  return out;
}

// Poly1305 (RFC 8439 section 2.5). A ONE-TIME authenticator: the 32-byte key
// must never be reused across messages, which in the AEAD is guaranteed by
// deriving it from the nonce.
function poly1305(key, message) {
  log.debug("Entering poly1305().");
  var keyBytes = asBytes(key), data = asBytes(message);
  if (keyBytes.length !== 32) {
    log.debug("Leaving poly1305(). Bad key length.");
    throw new Error('Poly1305 needs a 32-byte key; this one is ' +
                    keyBytes.length + ' bytes.');
  }
  var P = (_B1 << _B130) - _B5, M128 = (_B1 << _B128) - _B1;
  var r = _B0, i;
  for (i = 15; i >= 0; i--) r = (r << _B8) | BigInt(keyBytes[i]);
  r &= BigInt('0x0ffffffc0ffffffc0ffffffc0fffffff');
  var s = _B0;
  for (i = 15; i >= 0; i--) s = (s << _B8) | BigInt(keyBytes[16 + i]);
  var acc = _B0;
  for (i = 0; i < data.length; i += 16) {
    var chunk = data.slice(i, i + 16), n = _B0, j;
    for (j = chunk.length - 1; j >= 0; j--) n = (n << _B8) | BigInt(chunk[j]);
    n += (_B1 << BigInt(8 * chunk.length));
    acc = ((acc + n) * r) % P;
  }
  acc = (acc + s) & M128;
  var out = new Uint8Array(16);
  for (i = 0; i < 16; i++) {
    out[i] = Number(acc & _BFF);
    acc >>= _B8;
  }
  log.debug("Leaving poly1305().");
  return out;
}

// RFC 8439 section 2.8's AEAD construction: the MAC covers the AAD and the
// ciphertext, each zero-padded to a 16-byte boundary, then their two lengths
// as little-endian 64-bit counts. The padding and the lengths are what stop an
// attacker moving bytes between the two halves, and leaving them out produces
// a tag that verifies against itself and against nothing else.
function poly1305Pad(length) {
  log.debug("Entering poly1305Pad().");
  log.debug("Leaving poly1305Pad().");
  return new Uint8Array((16 - (length % 16)) % 16);
}

function le64(value) {
  log.debug("Entering le64().");
  var out = new Uint8Array(8), n = value;
  for (var i = 0; i < 8; i++) {
    out[i] = n & 0xff;
    n = Math.floor(n / 256);
  }
  log.debug("Leaving le64().");
  return out;
}

function chacha20Poly1305Tag(key, nonce, ciphertext, aad) {
  log.debug("Entering chacha20Poly1305Tag().");
  var otk = chacha20Block(asBytes(key), asBytes(nonce), 0).slice(0, 32);
  var mac = poly1305(otk, concatBytes(aad, poly1305Pad(aad.length),
                                      ciphertext,
                                      poly1305Pad(ciphertext.length),
                                      le64(aad.length),
                                      le64(ciphertext.length)));
  log.debug("Leaving chacha20Poly1305Tag().");
  return mac;
}

function chacha20Poly1305Encrypt(key, nonce, plaintext, aad) {
  log.debug("Entering chacha20Poly1305Encrypt().");
  var ciphertext = chacha20(key, nonce, plaintext, 1);
  log.debug("Leaving chacha20Poly1305Encrypt().");
  return { ciphertext: ciphertext,
           tag: chacha20Poly1305Tag(key, nonce, ciphertext, asBytes(aad)) };
}

function chacha20Poly1305Decrypt(key, nonce, ciphertext, aad, tag) {
  log.debug("Entering chacha20Poly1305Decrypt().");
  var expected = chacha20Poly1305Tag(key, nonce, asBytes(ciphertext),
                                     asBytes(aad));
  if (!bytesEqual(expected, tag)) {
    log.debug("Leaving chacha20Poly1305Decrypt(). Tag mismatch.");
    throw new Error('The Poly1305 tag did not verify. The key, the nonce, ' +
                    'the additional authenticated data or the ciphertext is ' +
                    'not what it was encrypted with — an authenticated ' +
                    'cipher cannot tell you which.');
  }
  log.debug("Leaving chacha20Poly1305Decrypt().");
  return chacha20(key, nonce, ciphertext, 1);
}

// ---------------------------------------------------------------------------
// MAC constructions over a block cipher.
//
// Moved here from digital_signature.js unchanged in behaviour, so that page
// and this one share them. aesBlock() is a single raw ECB block and is the
// primitive CMAC and CBC-MAC are defined in terms of.
// ---------------------------------------------------------------------------
function aesBlock(key, block16) {
  log.debug("Entering aesBlock().");
  var engine = forge.cipher.createCipher('AES-ECB',
      forge.util.createBuffer(toForge(key)));
  engine.start();
  engine.update(forge.util.createBuffer(toForge(block16)));
  engine.finish();
  log.debug("Leaving aesBlock().");
  return fromForge(engine.output.getBytes()).slice(0, 16);
}

function shl1(block) {
  log.debug("Entering shl1().");
  var out = new Uint8Array(16), carry = 0;
  for (var i = 15; i >= 0; i--) {
    out[i] = ((block[i] << 1) | carry) & 0xff;
    carry = (block[i] & 0x80) ? 1 : 0;
  }
  log.debug("Leaving shl1().");
  return out;
}

// AES-CMAC (RFC 4493), checked against the RFC's vectors.
function aesCmac(key, message) {
  log.debug("Entering aesCmac().");
  var keyBytes = asBytes(key), msg = asBytes(message);
  var Rb = new Uint8Array(16);
  Rb[15] = 0x87;
  var L = aesBlock(keyBytes, new Uint8Array(16));
  var K1 = shl1(L);
  if (L[0] & 0x80) K1 = bytes.xorBytes(K1, Rb);
  var K2 = shl1(K1);
  if (K1[0] & 0x80) K2 = bytes.xorBytes(K2, Rb);
  var n = Math.ceil(msg.length / 16) || 1;
  var complete = msg.length > 0 && msg.length % 16 === 0;
  var last;
  if (complete) {
    last = bytes.xorBytes(msg.slice((n - 1) * 16), K1);
  } else {
    var pad = new Uint8Array(16), rem = msg.slice((n - 1) * 16);
    pad.set(rem);
    pad[rem.length] = 0x80;
    last = bytes.xorBytes(pad, K2);
  }
  var x = new Uint8Array(16);
  for (var i = 0; i < n - 1; i++) {
    x = aesBlock(keyBytes, bytes.xorBytes(x, msg.slice(i * 16, i * 16 + 16)));
  }
  log.debug("Leaving aesCmac().");
  return aesBlock(keyBytes, bytes.xorBytes(x, last));
}

// AES-CBC-MAC (legacy; zero IV, last block). Insecure for variable-length
// messages, which is what CMAC's two subkeys exist to fix.
function aesCbcMac(key, message) {
  log.debug("Entering aesCbcMac().");
  var keyBytes = asBytes(key), msg = asBytes(message);
  var n = Math.ceil(msg.length / 16) || 1;
  var x = new Uint8Array(16);
  for (var i = 0; i < n; i++) {
    var block = new Uint8Array(16);
    block.set(msg.slice(i * 16, i * 16 + 16));
    x = aesBlock(keyBytes, bytes.xorBytes(x, block));
  }
  log.debug("Leaving aesCbcMac().");
  return x;
}

// AES-GMAC via GCM with an empty plaintext and the message as AAD. DEMO NOTE:
// a fixed all-zero nonce, for a deterministic key+value -> tag; real GMAC needs
// a unique nonce per message per key.
function aesGmac(key, message) {
  log.debug("Entering aesGmac().");
  var engine = forge.cipher.createCipher('AES-GCM',
      forge.util.createBuffer(toForge(key)));
  engine.start({ iv: toForge(new Uint8Array(12)),
                 additionalData: toForge(message), tagLength: 128 });
  engine.finish();
  log.debug("Leaving aesGmac().");
  return fromForge(engine.mode.tag.getBytes()).slice(0, 16);
}

// SipHash-2-4 (reference), checked against the reference vector.
function siphash24(key, message) {
  log.debug("Entering siphash24().");
  var keyBytes = asBytes(key), msg = asBytes(message);
  var M = (_B1 << _B64) - _B1;
  function rotl(x, b) {
    log.debug("Entering rotl().");
    log.debug("Leaving rotl().");
    return ((x << BigInt(b)) | (x >> BigInt(64 - b))) & M;
  }
  function rd(buffer, offset) {
    log.debug("Entering rd().");
    var v = _B0;
    for (var i = 7; i >= 0; i--) v = (v << _B8) | BigInt(buffer[offset + i]);
    log.debug("Leaving rd().");
    return v;
  }
  var k0 = rd(keyBytes, 0), k1 = rd(keyBytes, 8);
  var v0 = BigInt('0x736f6d6570736575') ^ k0;
  var v1 = BigInt('0x646f72616e646f6d') ^ k1;
  var v2 = BigInt('0x6c7967656e657261') ^ k0;
  var v3 = BigInt('0x7465646279746573') ^ k1;
  function round() {
    log.debug("Entering round().");
    v0 = (v0 + v1) & M; v1 = rotl(v1, 13); v1 ^= v0; v0 = rotl(v0, 32);
    v2 = (v2 + v3) & M; v3 = rotl(v3, 16); v3 ^= v2;
    v0 = (v0 + v3) & M; v3 = rotl(v3, 21); v3 ^= v0;
    v2 = (v2 + v1) & M; v1 = rotl(v1, 17); v1 ^= v2; v2 = rotl(v2, 32);
    log.debug("Leaving round().");
  }
  var blocks = Math.floor(msg.length / 8), i;
  for (i = 0; i < blocks; i++) {
    var m = rd(msg, i * 8);
    v3 ^= m;
    round(); round();
    v0 ^= m;
  }
  var tail = new Uint8Array(8);
  tail.set(msg.slice(blocks * 8));
  tail[7] = msg.length & 0xff;
  var last = rd(tail, 0);
  v3 ^= last;
  round(); round();
  v0 ^= last;
  v2 ^= BigInt(0xff);
  round(); round(); round(); round();
  var out = new Uint8Array(8), acc = (v0 ^ v1 ^ v2 ^ v3) & M;
  for (i = 0; i < 8; i++) {
    out[i] = Number(acc & _BFF);
    acc >>= _B8;
  }
  log.debug("Leaving siphash24().");
  return out;
}

module.exports = {
  // the catalogue
  CIPHERS: CIPHERS,
  cipherIds: cipherIds,
  cipher: cipher,
  describe: describe,
  blockBytes: blockBytes,
  expandDesKey: expandDesKey,
  // key material
  generateKey: generateKey,
  generateIv: generateIv,
  checkMaterial: checkMaterial,
  // the ciphers
  encrypt: encrypt,
  decrypt: decrypt,
  // ChaCha20 / Poly1305, exported for the AEAD's own vectors
  chacha20: chacha20,
  chacha20Block: chacha20Block,
  poly1305: poly1305,
  chacha20Poly1305Encrypt: chacha20Poly1305Encrypt,
  chacha20Poly1305Decrypt: chacha20Poly1305Decrypt,
  // MACs over a block cipher
  aesBlock: aesBlock,
  aesCmac: aesCmac,
  aesCbcMac: aesCbcMac,
  aesGmac: aesGmac,
  siphash24: siphash24
};
