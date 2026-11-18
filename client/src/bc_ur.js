// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: bc_ur.js
//
// ---------------------------------------------------------------------------
// Uniform Resources (#480): Blockchain Commons' text form for CBOR, single-
// part (BCR-2020-005, with the bytewords of BCR-2020-012) and MULTI-PART,
// the fountain-coded sequence BCR-2020-005 section "Multi-part URs" and
// BCR-2024-001 describe and the released `ur` 0.4.1 crate (which bc-ur
// 0.19.2 delegates to) implements:
//
//   ur:<type>/<bytewords>                    one part
//   ur:<type>/<seq>-<count>/<bytewords>      part <seq> of a <count>-fragment
//                                            message
//
// A multi-part UR's body is the CBOR array [seq, count, messageLength,
// checksum, data] — checksum the CRC-32 of the WHOLE message, data one
// fragment's worth — written in minimal bytewords with the CRC-32 of that
// CBOR appended. Parts 1..count are the fragments themselves. Every part
// after `count` is a FOUNTAIN part: the XOR of a pseudo-random subset of
// the fragments, chosen by Xoshiro256** seeded with SHA-256 of
// (seq || checksum), its size drawn from a 1/k ("robust soliton"-like)
// distribution by the alias method. A decoder accepts parts in any order,
// any mixture of simple and mixed, until every fragment is known. Every
// floating-point step (the double drawn from a 64-bit output, the alias
// table's weights) is written in the crate's order of operations, because
// a different rounding chooses different fragments and the parts are then
// a different stream; tests/gordian_envelope_engine.js holds this to the
// crate's own twenty-part vector.
//
// NO DOM.
// ---------------------------------------------------------------------------

var nobleSha256 = require("@noble/hashes/sha256").sha256;
var cbytes = require("./crypto_bytes");

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "bc_ur",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var BYTEWORDS = (
  "able acid also apex aqua arch atom aunt away axis back bald barn belt " +
  "beta bias blue body brag brew bulb buzz calm cash cats chef city claw " +
  "code cola cook cost crux curl cusp cyan dark data days deli dice diet " +
  "door down draw drop drum dull duty each easy echo edge epic even exam " +
  "exit eyes fact fair fern figs film fish fizz flap flew flux foxy free " +
  "frog fuel fund gala game gear gems gift girl glow good gray grim guru " +
  "gush gyro half hang hard hawk heat help high hill holy hope horn huts " +
  "iced idea idle inch inky into iris iron item jade jazz join jolt jowl " +
  "judo jugs jump junk jury keep keno kept keys kick kiln king kite kiwi " +
  "knob lamb lava lazy leaf legs liar limp lion list logo loud love luau " +
  "luck lung main many math maze memo menu meow mild mint miss monk nail " +
  "navy need news next noon note numb obey oboe omit onyx open oval owls " +
  "paid part peck play plus poem pool pose puff puma purr quad quiz race " +
  "ramp real redo rich road rock roof ruby ruin runs rust safe saga scar " +
  "sets silk skew slot soap solo song stub surf swan taco task taxi tent " +
  "tied time tiny toil tomb toys trip tuna twin ugly undo unit urge user " +
  "vast very veto vial vibe view visa void vows wall wand warm wasp wave " +
  "waxy webs what when whiz wolf work yank yawn yell yoga yurt zaps zero " +
  "zest zinc zone zoom").split(" ");
var MINIMAL = BYTEWORDS.map(function (w) {
  return w.charAt(0) + w.charAt(3);
});
var MINIMAL_INDEX = {};
MINIMAL.forEach(function (w, i) {
  MINIMAL_INDEX[w] = i;
});

var CRC_TABLE = (function () {
  var t = [];
  for (var n = 0; n < 256; n++) {
    var c = n;
    for (var k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t.push(c >>> 0);
  }
  return t;
})();

function crc32(bytes) {
  log.debug("Entering crc32().");
  var c = 0xffffffff;
  for (var i = 0; i < bytes.length; i++) {
    c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  }
  log.debug("Leaving crc32().");
  return (c ^ 0xffffffff) >>> 0;
}

function u32be(n) {
  log.debug("Entering u32be().");
  log.debug("Leaving u32be().");
  return new Uint8Array([n >>> 24, (n >>> 16) & 0xff, (n >>> 8) & 0xff,
                         n & 0xff]);
}

// Minimal bytewords of bytes || CRC-32(bytes).
function bytewordsEncode(bytes) {
  log.debug("Entering bytewordsEncode().");
  var all = cbytes.concatBytes(bytes, u32be(crc32(bytes)));
  var words = "";
  for (var i = 0; i < all.length; i++) words += MINIMAL[all[i]];
  log.debug("Leaving bytewordsEncode().");
  return words;
}

// The bytes of minimal bytewords, their CRC-32 checked and removed.
function bytewordsDecode(words) {
  log.debug("Entering bytewordsDecode().");
  if (!/^[a-z]*$/.test(words) || words.length % 2) {
    log.debug("Leaving bytewordsDecode(). Not minimal bytewords.");
    throw new Error("UR bytewords are pairs of lower-case letters.");
  }
  var out = new Uint8Array(words.length / 2);
  for (var i = 0; i < words.length; i += 2) {
    var b = MINIMAL_INDEX[words.slice(i, i + 2)];
    if (b === undefined) {
      log.debug("Leaving bytewordsDecode(). Not a byteword.");
      throw new Error(JSON.stringify(words.slice(i, i + 2)) + " is not a " +
                      "minimal byteword.");
    }
    out[i / 2] = b;
  }
  if (out.length < 5) {
    log.debug("Leaving bytewordsDecode(). Too short.");
    throw new Error("a UR too short to carry its checksum.");
  }
  var body = out.slice(0, -4);
  var n = out.length;
  var crc = ((out[n - 4] << 24) | (out[n - 3] << 16) | (out[n - 2] << 8) |
             out[n - 1]) >>> 0;
  if (crc !== crc32(body)) {
    log.debug("Leaving bytewordsDecode(). Bad CRC.");
    throw new Error("the UR's CRC-32 does not match its body.");
  }
  log.debug("Leaving bytewordsDecode().");
  return body;
}

function urEncode(type, body) {
  log.debug("Entering urEncode(). " + type);
  log.debug("Leaving urEncode().");
  return "ur:" + type + "/" + bytewordsEncode(body);
}

// "ur:type/[seq-count/]words" -> { type, seq, count, words } (seq and count
// null for a single part).
function parseUr(text) {
  log.debug("Entering parseUr().");
  var s = String(text || "").trim().toLowerCase();
  var m = /^ur:([a-z0-9-]+)\/(?:([0-9]+)-([0-9]+)\/)?([a-z]+)$/.exec(s);
  if (!m) {
    log.debug("Leaving parseUr(). Not a UR.");
    throw new Error("not a UR (ur:<type>/<bytewords>, or " +
                    "ur:<type>/<seq>-<count>/<bytewords> for one part of " +
                    "several).");
  }
  log.debug("Leaving parseUr().");
  return { type: m[1], seq: m[2] ? Number(m[2]) : null,
           count: m[3] ? Number(m[3]) : null, words: m[4] };
}

function urDecode(text) {
  log.debug("Entering urDecode().");
  var p = parseUr(text);
  if (p.seq !== null) {
    log.debug("Leaving urDecode(). One part of several.");
    throw new Error("ur:" + p.type + "/" + p.seq + "-" + p.count + "/… is " +
                    "one part of a multi-part UR; give every part " +
                    "(decodeParts).");
  }
  log.debug("Leaving urDecode().");
  return { type: p.type, body: bytewordsDecode(p.words) };
}

// ---------------------------------------------------------------------------
// The fountain code.
// ---------------------------------------------------------------------------

var M64 = (BigInt(1) << BigInt(64)) - BigInt(1);
var TWO64 = 18446744073709551616;

// rotl() runs twice per 64-bit output, hundreds of times per part, so it
// carries no Entering/Leaving pair (the hot-path exception the code style
// allows); chooseFragments() logs.
function rotl(x, k) {
  return ((x << BigInt(k)) | (x >> BigInt(64 - k))) & M64;
}

// Xoshiro256**, its state the four big-endian 64-bit words of SHA-256 of
// the seed bytes (the ur crate's From<&[u8]>).
function Xoshiro(seedBytes) {
  log.debug("Entering Xoshiro().");
  var h = nobleSha256(cbytes.asBytes(seedBytes));
  this.s = [];
  for (var i = 0; i < 4; i++) {
    var v = BigInt(0);
    for (var n = 0; n < 8; n++) v = (v << BigInt(8)) | BigInt(h[8 * i + n]);
    this.s.push(v);
  }
  log.debug("Leaving Xoshiro().");
}

// The generator is called hundreds of times per part; next(), nextDouble()
// and nextInt() carry no Entering/Leaving pair (the hot-path exception the
// code style allows). The functions that call them log.
Xoshiro.prototype.next = function () {
  var s = this.s;
  var r = (rotl((s[1] * BigInt(5)) & M64, 7) * BigInt(9)) & M64;
  var t = (s[1] << BigInt(17)) & M64;
  s[2] ^= s[0];
  s[3] ^= s[1];
  s[1] ^= s[2];
  s[0] ^= s[3];
  s[2] ^= t;
  s[3] = rotl(s[3], 45);
  return r;
};

Xoshiro.prototype.nextDouble = function () {
  return Number(this.next()) / TWO64;
};

Xoshiro.prototype.nextInt = function (low, high) {
  return Math.floor(this.nextDouble() * (high - low + 1)) + low;
};

Xoshiro.prototype.shuffled = function (items) {
  log.debug("Entering Xoshiro.shuffled().");
  var rest = items.slice();
  var out = [];
  while (rest.length) {
    out.push(rest.splice(this.nextInt(0, rest.length - 1), 1)[0]);
  }
  log.debug("Leaving Xoshiro.shuffled().");
  return out;
};

// Vose's alias method over `weights`, in the ur crate's order.
function aliasTable(weights) {
  log.debug("Entering aliasTable().");
  var w = weights.slice();
  var count = w.length;
  var summed = 0;
  w.forEach(function (x) {
    summed += x;
  });
  for (var i = 0; i < count; i++) w[i] *= count / summed;
  var small = [];
  var large = [];
  for (var j = count - 1; j >= 0; j--) {
    if (w[j] < 1) {
      small.push(j);
    } else {
      large.push(j);
    }
  }
  var probs = new Array(count).fill(0);
  var aliases = new Array(count).fill(0);
  while (small.length && large.length) {
    var a = small.pop();
    var g = large.pop();
    probs[a] = w[a];
    aliases[a] = g;
    w[g] += w[a] - 1;
    if (w[g] < 1) {
      small.push(g);
    } else {
      large.push(g);
    }
  }
  while (large.length) probs[large.pop()] = 1;
  while (small.length) probs[small.pop()] = 1;
  log.debug("Leaving aliasTable().");
  return { probs: probs, aliases: aliases };
}

function chooseDegree(rng, length) {
  log.debug("Entering chooseDegree(). " + length);
  var weights = [];
  for (var x = 1; x <= length; x++) weights.push(1 / x);
  var t = aliasTable(weights);
  var r1 = rng.nextDouble();
  var r2 = rng.nextDouble();
  var i = Math.floor(t.probs.length * r1);
  var out = (r2 < t.probs[i] ? i : t.aliases[i]) + 1;
  log.debug("Leaving chooseDegree(). " + out);
  return out;
}

// The fragment indexes part `seq` carries: just seq-1 for the first
// `count`, then a shuffled subset.
function chooseFragments(seq, count, checksum) {
  log.debug("Entering chooseFragments(). " + seq + "/" + count);
  if (seq <= count) {
    log.debug("Leaving chooseFragments(). Simple.");
    return [seq - 1];
  }
  var rng = new Xoshiro(cbytes.concatBytes(u32be(seq >>> 0),
                                           u32be(checksum >>> 0)));
  var degree = chooseDegree(rng, count);
  var all = [];
  for (var i = 0; i < count; i++) all.push(i);
  var out = rng.shuffled(all).slice(0, degree);
  log.debug("Leaving chooseFragments(). Degree " + degree + ".");
  return out;
}

function fragmentLength(dataLength, maxFragmentLength) {
  log.debug("Entering fragmentLength().");
  var fragmentCount = Math.ceil(dataLength / maxFragmentLength);
  log.debug("Leaving fragmentLength().");
  return Math.ceil(dataLength / fragmentCount);
}

function xorInto(a, b) {
  log.debug("Entering xorInto().");
  for (var i = 0; i < a.length; i++) a[i] ^= b[i];
  log.debug("Leaving xorInto().");
}

// A CBOR head (major type, argument), shortest form.
function cborHead(major, n) {
  log.debug("Entering cborHead().");
  var out;
  if (n < 24) {
    out = [(major << 5) | n];
  } else if (n < 0x100) {
    out = [(major << 5) | 24, n];
  } else if (n < 0x10000) {
    out = [(major << 5) | 25, n >>> 8, n & 0xff];
  } else {
    out = [(major << 5) | 26].concat(Array.from(u32be(n)));
  }
  log.debug("Leaving cborHead().");
  return out;
}

// [seq, count, messageLength, checksum, data].
function partCbor(p) {
  log.debug("Entering partCbor().");
  var out = cborHead(4, 5).concat(cborHead(0, p.seq), cborHead(0, p.count),
    cborHead(0, p.messageLength), cborHead(0, p.checksum),
    cborHead(2, p.data.length), Array.from(p.data));
  log.debug("Leaving partCbor().");
  return new Uint8Array(out);
}

function readPartCbor(bytes) {
  log.debug("Entering readPartCbor().");
  var i = 0;
  function arg(expectMajor) {
    log.debug("Entering arg(). " + expectMajor);
    var ib = bytes[i++];
    if (ib === undefined || ib >> 5 !== expectMajor) {
      log.debug("Leaving arg(). Wrong type.");
      throw new Error("a multi-part UR's body is [seq, count, length, " +
                      "checksum, data].");
    }
    var ai = ib & 0x1f;
    if (ai < 24) {
      log.debug("Leaving arg(). Immediate.");
      return ai;
    }
    var n = { 24: 1, 25: 2, 26: 4 }[ai];
    if (!n || i + n > bytes.length) {
      log.debug("Leaving arg(). Not a 32-bit number.");
      throw new Error("a multi-part UR's numbers are 32-bit unsigned.");
    }
    var v = 0;
    for (var k = 0; k < n; k++) v = v * 256 + bytes[i++];
    log.debug("Leaving arg().");
    return v;
  }
  var head = bytes[i++];
  if (head !== 0x85) {
    log.debug("Leaving readPartCbor(). Not a five-element array.");
    throw new Error("a multi-part UR's body is a five-element array.");
  }
  var seq = arg(0);
  var count = arg(0);
  var messageLength = arg(0);
  var checksum = arg(0);
  var len = arg(2);
  if (i + len !== bytes.length) {
    log.debug("Leaving readPartCbor(). Length.");
    throw new Error("a multi-part UR's fragment is not the rest of its " +
                    "body.");
  }
  log.debug("Leaving readPartCbor().");
  return { seq: seq, count: count, messageLength: messageLength,
           checksum: checksum >>> 0, data: bytes.slice(i) };
}

// The encoder: the fragments of `body`, then fountain parts for ever.
// encoder.nextPart() is the ur crate's Encoder::next_part().
function MultipartEncoder(type, body, maxFragmentLength) {
  log.debug("Entering MultipartEncoder(). " + type);
  var msg = cbytes.asBytes(body);
  if (!msg.length) {
    log.debug("Leaving MultipartEncoder(). Empty.");
    throw new Error("a multi-part UR needs a non-empty message.");
  }
  if (!(maxFragmentLength > 0)) {
    log.debug("Leaving MultipartEncoder(). Bad fragment length.");
    throw new Error("the maximum fragment length is a positive number.");
  }
  var len = fragmentLength(msg.length, maxFragmentLength);
  var padded = new Uint8Array(Math.ceil(msg.length / len) * len);
  padded.set(msg);
  this.type = type;
  this.fragments = [];
  for (var i = 0; i < padded.length; i += len) {
    this.fragments.push(padded.slice(i, i + len));
  }
  this.messageLength = msg.length;
  this.checksum = crc32(msg);
  this.seq = 0;
  log.debug("Leaving MultipartEncoder(). " + this.fragments.length +
            " fragments of " + len + ".");
}

MultipartEncoder.prototype.fragmentCount = function () {
  log.debug("Entering MultipartEncoder.fragmentCount().");
  log.debug("Leaving MultipartEncoder.fragmentCount().");
  return this.fragments.length;
};

MultipartEncoder.prototype.nextPart = function () {
  log.debug("Entering MultipartEncoder.nextPart().");
  this.seq += 1;
  var count = this.fragments.length;
  var mixed = new Uint8Array(this.fragments[0].length);
  var self = this;
  chooseFragments(this.seq, count, this.checksum).forEach(function (k) {
    xorInto(mixed, self.fragments[k]);
  });
  var text = "ur:" + this.type + "/" + this.seq + "-" + count + "/" +
    bytewordsEncode(partCbor({ seq: this.seq, count: count,
                               messageLength: this.messageLength,
                               checksum: this.checksum, data: mixed }));
  log.debug("Leaving MultipartEncoder.nextPart(). " + this.seq);
  return text;
};

// `n` parts (default: one per fragment, the minimum a decoder needs).
function encodeParts(type, body, maxFragmentLength, n) {
  log.debug("Entering encodeParts().");
  var enc = new MultipartEncoder(type, body, maxFragmentLength);
  var out = [];
  var total = n || enc.fragmentCount();
  for (var i = 0; i < total; i++) out.push(enc.nextPart());
  log.debug("Leaving encodeParts(). " + out.length);
  return out;
}

// The decoder: the ur crate's Decoder, with bc-ur's check that every part
// names the same type.
function MultipartDecoder() {
  log.debug("Entering MultipartDecoder().");
  this.type = null;
  this.decoded = new Map();
  this.received = new Set();
  this.buffer = new Map();
  this.queue = [];
  this.count = 0;
  this.messageLength = 0;
  this.checksum = 0;
  this.fragmentLength = 0;
  this.partsSeen = 0;
  log.debug("Leaving MultipartDecoder().");
}

MultipartDecoder.prototype.isComplete = function () {
  log.debug("Entering MultipartDecoder.isComplete().");
  log.debug("Leaving MultipartDecoder.isComplete().");
  return this.messageLength !== 0 && this.decoded.size === this.count;
};

// One part's text. True when it told the decoder something new.
MultipartDecoder.prototype.receive = function (text) {
  log.debug("Entering MultipartDecoder.receive().");
  var p = parseUr(text);
  if (p.seq === null) {
    log.debug("Leaving MultipartDecoder.receive(). Single part.");
    throw new Error("ur:" + p.type + "/… is a single-part UR, not one part " +
                    "of several.");
  }
  if (this.type !== null && this.type !== p.type) {
    log.debug("Leaving MultipartDecoder.receive(). Type changed.");
    throw new Error("a part of ur:" + p.type + " among parts of ur:" +
                    this.type + ".");
  }
  var part = readPartCbor(bytewordsDecode(p.words));
  if (part.seq !== p.seq || part.count !== p.count) {
    log.debug("Leaving MultipartDecoder.receive(). Label disagrees.");
    throw new Error("the part labelled " + p.seq + "-" + p.count + " says " +
                    "it is " + part.seq + "-" + part.count + ".");
  }
  if (this.isComplete()) {
    log.debug("Leaving MultipartDecoder.receive(). Already complete.");
    return false;
  }
  if (!part.count || !part.data.length || !part.messageLength) {
    log.debug("Leaving MultipartDecoder.receive(). Empty part.");
    throw new Error("an empty part.");
  }
  if (!this.received.size) {
    this.type = p.type;
    this.count = part.count;
    this.messageLength = part.messageLength;
    this.checksum = part.checksum;
    this.fragmentLength = part.data.length;
  } else if (part.count !== this.count ||
             part.messageLength !== this.messageLength ||
             part.checksum !== this.checksum ||
             part.data.length !== this.fragmentLength) {
    log.debug("Leaving MultipartDecoder.receive(). Inconsistent.");
    throw new Error("part " + part.seq + " is not part of the same message " +
                    "as the parts before it.");
  }
  var indexes = chooseFragments(part.seq, part.count, part.checksum);
  var key = indexes.join(",");
  if (this.received.has(key)) {
    log.debug("Leaving MultipartDecoder.receive(). Seen.");
    return false;
  }
  this.received.add(key);
  this.partsSeen += 1;
  if (indexes.length === 1) {
    this.decoded.set(indexes[0], part.data);
    this.queue.push([indexes[0], part.data]);
    this.processQueue();
  } else {
    this.processMixed(indexes, part.data);
  }
  log.debug("Leaving MultipartDecoder.receive(). " + this.decoded.size + "/" +
            this.count);
  return true;
};

MultipartDecoder.prototype.processQueue = function () {
  log.debug("Entering MultipartDecoder.processQueue().");
  while (this.queue.length) {
    var item = this.queue.pop();
    var index = item[0];
    var simple = item[1];
    var self = this;
    Array.from(this.buffer.keys()).filter(function (k) {
      return self.buffer.get(k).indexes.indexOf(index) !== -1;
    }).forEach(function (k) {
      var mixed = self.buffer.get(k);
      self.buffer.delete(k);
      var rest = mixed.indexes.filter(function (x) {
        return x !== index;
      });
      xorInto(mixed.data, simple);
      if (rest.length === 1) {
        self.decoded.set(rest[0], mixed.data);
        self.queue.push([rest[0], mixed.data]);
      } else {
        self.buffer.set(rest.join(","), { indexes: rest, data: mixed.data });
      }
    });
  }
  log.debug("Leaving MultipartDecoder.processQueue().");
};

MultipartDecoder.prototype.processMixed = function (indexes, data) {
  log.debug("Entering MultipartDecoder.processMixed().");
  var self = this;
  var known = indexes.filter(function (k) {
    return self.decoded.has(k);
  });
  if (known.length === indexes.length) {
    log.debug("Leaving MultipartDecoder.processMixed(). Nothing new.");
    return;
  }
  var mixed = data.slice();
  known.forEach(function (k) {
    xorInto(mixed, self.decoded.get(k));
  });
  var rest = indexes.filter(function (k) {
    return known.indexOf(k) === -1;
  });
  if (rest.length === 1) {
    this.decoded.set(rest[0], mixed);
    this.queue.push([rest[0], mixed]);
    this.processQueue();
  } else {
    this.buffer.set(rest.join(","), { indexes: rest, data: mixed });
  }
  log.debug("Leaving MultipartDecoder.processMixed().");
};

// { type, body } once complete; null before.
MultipartDecoder.prototype.message = function () {
  log.debug("Entering MultipartDecoder.message().");
  if (!this.isComplete()) {
    log.debug("Leaving MultipartDecoder.message(). Incomplete.");
    return null;
  }
  var all = new Uint8Array(this.count * this.fragmentLength);
  for (var i = 0; i < this.count; i++) {
    all.set(this.decoded.get(i), i * this.fragmentLength);
  }
  for (var j = this.messageLength; j < all.length; j++) {
    if (all[j] !== 0) {
      log.debug("Leaving MultipartDecoder.message(). Padding.");
      throw new Error("the reassembled message's padding is not zero.");
    }
  }
  var body = all.slice(0, this.messageLength);
  if (crc32(body) !== this.checksum) {
    log.debug("Leaving MultipartDecoder.message(). Checksum.");
    throw new Error("the reassembled message's CRC-32 does not match the " +
                    "parts' checksum.");
  }
  log.debug("Leaving MultipartDecoder.message().");
  return { type: this.type, body: body };
};

// One UR or several parts of one, in any order, separated by whitespace.
// -> { type, body, parts, fragments } (parts and fragments 1 for a
// single-part UR).
function decodeAny(text) {
  log.debug("Entering decodeAny().");
  var items = String(text || "").trim().split(/\s+/).filter(Boolean);
  if (items.length === 1 && parseUr(items[0]).seq === null) {
    var single = urDecode(items[0]);
    log.debug("Leaving decodeAny(). Single part.");
    return { type: single.type, body: single.body, parts: 1, fragments: 1 };
  }
  var dec = new MultipartDecoder();
  items.forEach(function (t) {
    dec.receive(t);
  });
  var m = dec.message();
  if (!m) {
    log.debug("Leaving decodeAny(). Incomplete.");
    throw new Error("these " + items.length + " part(s) recover " +
                    dec.decoded.size + " of the message's " + dec.count +
                    " fragments; more parts are needed.");
  }
  log.debug("Leaving decodeAny(). " + items.length + " parts.");
  return { type: m.type, body: m.body, parts: items.length,
           fragments: dec.count };
}

function isUrText(text) {
  log.debug("Entering isUrText().");
  log.debug("Leaving isUrText().");
  return /^\s*ur:/i.test(String(text || ""));
}

module.exports = {
  BYTEWORDS: BYTEWORDS,
  MINIMAL: MINIMAL,
  crc32: crc32,
  bytewordsEncode: bytewordsEncode,
  bytewordsDecode: bytewordsDecode,
  urEncode: urEncode,
  urDecode: urDecode,
  parseUr: parseUr,
  Xoshiro: Xoshiro,
  chooseFragments: chooseFragments,
  fragmentLength: fragmentLength,
  MultipartEncoder: MultipartEncoder,
  MultipartDecoder: MultipartDecoder,
  encodeParts: encodeParts,
  decodeAny: decodeAny,
  isUrText: isUrText
};
