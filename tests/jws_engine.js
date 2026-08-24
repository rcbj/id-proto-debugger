// File: jws_engine.js
//
// ---------------------------------------------------------------------------
// The Digital Signature page's JWS pane, driven in NODE with no browser —
// because the module it is built on (client/src/jws.js) has no DOM.
//
// tests/digital_signature.js drives the PANE: it presses the buttons, reads
// the status lines, and proves the wiring. What it cannot do is tell you the
// bytes are right, because everything it checks it checks against this same
// code, and sign-then-verify agrees with itself whatever the implementation
// does. A JWS is a wire format somebody else's library has to read, so the
// defects that matter here are exactly the self-consistent ones:
//
//   * An ECDSA signature left as the DER SEQUENCE every crypto API hands back,
//     where RFC 7518 §3.4 requires the R || S concatenation, each half padded
//     to the coordinate size. It round-trips perfectly and verifies nowhere.
//   * A PSS salt of some length other than the hash's own, which §3.5 fixes.
//   * A payload re-serialized between validating it and signing it, so that
//     the octets signed are not the octets sent.
//   * base64 where base64url was meant — two characters and a padding rule.
//
// So this job asserts against things that are NOT this code: node's own
// crypto (which is OpenSSL) in BOTH directions for every asymmetric
// algorithm, and `jsonwebtoken` as a third opinion on the four families it
// covers. Then, separately, the rules no vector can express — RFC 7515's
// `crit` MUST, RFC 7797's period rule, RFC 8725's "the verifier decides the
// algorithm", and what an Unsecured JWS is allowed to be.
// ---------------------------------------------------------------------------

// NOTE ON OPTIONS: run-report.js spawns every job as
// `node <script>.js --url <BASE_URL>`, and commander exits on an option it has
// not been told about. This job parses no arguments at all — it drives a
// module in process and has no base url to visit — so node ignores the pair
// and there is nothing to declare. Do not add commander here without also
// declaring `--url`; see tests/CLAUDE.md.
const assert = require("assert");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'jws_engine',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());

// The module under test lives next to this script in the tests image and in
// client/src in a checkout — see the note in tests/module_paths.js, and the
// tests/Dockerfile COPY that puts it here.
const paths = require("./module_paths.js");
const SRC = path.resolve(__dirname, "..", "client", "src");
const jws = paths.requireSharedModule(
  [path.join(__dirname, "jws.js"), path.join(SRC, "jws.js")],
  "client/src/jws.js");
const jsonwebtoken = require("jsonwebtoken");

// A payload with indentation ON PURPOSE. A JWS signs the base64url of the
// payload's own octets, so this whitespace is inside the signature — which is
// the property one of the checks below is about.
const PAYLOAD = JSON.stringify({
  iss: "https://as.example.com",
  sub: "alice",
  aud: "https://api.example.com",
  scope: "read write"
}, null, 2);

// The curve each ES* algorithm signs over, spelled the way node spells it.
const NODE_CURVES = { ES256: "prime256v1", ES384: "secp384r1",
                      ES512: "secp521r1", ES256K: "secp256k1" };
const NODE_HASH = { "SHA-256": "sha256", "SHA-384": "sha384",
                    "SHA-512": "sha512" };

// ---------------------------------------------------------------------------
// DER <-> R||S. This conversion lives in the TEST rather than in the module
// because the module must never produce DER — having it here is what lets the
// test hand OpenSSL a signature the module made and take one back.
// ---------------------------------------------------------------------------
function rsToDer(sig) {
  log.debug("Entering rsToDer().");
  const n = sig.length / 2;
  function trim(b) {
    log.debug("Entering trim().");
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    b = b.slice(i);
    if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
    log.debug("Leaving trim().");
    return b;
  }
  const r = trim(sig.slice(0, n)), s = trim(sig.slice(n));
  const body = Buffer.concat([Buffer.from([0x02, r.length]), r,
                              Buffer.from([0x02, s.length]), s]);
  const header = body.length < 128 ? Buffer.from([0x30, body.length])
    : Buffer.from([0x30, 0x81, body.length]);
  log.debug("Leaving rsToDer().");
  return Buffer.concat([header, body]);
}

function derToRs(der, n) {
  log.debug("Entering derToRs().");
  let i = 2;
  if (der[1] & 0x80) i += der[1] & 0x7f;
  function read() {
    log.debug("Entering read().");
    const len = der[i + 1];
    let b = der.slice(i + 2, i + 2 + len);
    i += 2 + len;
    while (b.length > n) b = b.slice(1);
    log.debug("Leaving read().");
    return Buffer.concat([Buffer.alloc(n - b.length), b]);
  }
  const r = read(), s = read();
  log.debug("Leaving derToRs().");
  return Buffer.concat([r, s]);
}

// A node KeyObject for the public half of whatever this module generated. The
// route is through the module's OWN JWK export, which makes that export part
// of what is under test: a wrong `crv`, a mis-padded coordinate or base64
// instead of base64url all stop node from importing the key at all.
function nodePublicKey(algId, publicKey) {
  log.debug("Entering nodePublicKey(). alg=" + algId);
  const spec = jws.algSpec(algId);
  if (spec.family === "rsa") {
    log.debug("Leaving nodePublicKey(). RSA PEM.");
    return crypto.createPublicKey(publicKey);
  }
  const jwk = jws.publicJwk(algId, publicKey);
  const key = crypto.createPublicKey({ key: {
    kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, format: "jwk" });
  log.debug("Leaving nodePublicKey().");
  return key;
}

function nodeSignParams(spec) {
  log.debug("Entering nodeSignParams().");
  if (spec.pad !== "pss") {
    log.debug("Leaving nodeSignParams(). Not PSS.");
    return {};
  }
  log.debug("Leaving nodeSignParams(). PSS.");
  return { padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
           saltLength: jws.HASHES[spec.hash].bytes };
}

// ---------------------------------------------------------------------------
// 1. The division itself: this job can only exist because the JWS engine was
//    kept out of the page bundle, and that is a property a later edit can
//    quietly take away.
// ---------------------------------------------------------------------------
function checkNoDom() {
  log.debug("Entering checkNoDom().");
  const file = fs.existsSync(path.join(__dirname, "jws.js"))
    ? path.join(__dirname, "jws.js") : path.join(SRC, "jws.js");
  const forbidden = /\b(document|window|localStorage|navigator|alert)\b/;
  fs.readFileSync(file, "utf8").split("\n").forEach(function (line, index) {
    // Comments are where the reasoning lives, and a MESSAGE is prose too:
    // "it must be a JSON document." is not a DOM access, and a check that
    // cannot tell the difference gets edited into uselessness the first time
    // it fires on one. So strip both before looking.
    const code = line
      .replace(/^\s*(\/\/|\*).*$/, '')
      .replace(/\/\/.*$/, '')
      .replace(/'(\\.|[^'\\])*'/g, "''")
      .replace(/"(\\.|[^"\\])*"/g, '""');
    assert.ok(!forbidden.test(code),
      "jws.js line " + (index + 1) + " touches the DOM: " + line.trim() +
      "\nThe DOM half of this pane belongs in digital_signature.js; this " +
      "module is what lets tests/jws_engine.js run without a browser.");
  });
  log.info("[no-dom] OK — jws.js reaches no DOM.");
  log.debug("Leaving checkNoDom().");
}

// ---------------------------------------------------------------------------
// 2. Every algorithm, every serialization, round trip.
// ---------------------------------------------------------------------------
function checkRoundTrips() {
  log.debug("Entering checkRoundTrips().");
  let count = 0;
  jws.algIds().forEach(function (algId) {
    const key = jws.generateKey(algId, { bits: 2048 });
    ["compact", "flattened", "general"].forEach(function (serialization) {
      const signed = jws.signJws({ algId: algId, payload: PAYLOAD,
        privateKey: key.privateKey, publicKey: key.publicKey,
        serialization: serialization, kid: "k1" });
      const verified = jws.verifyJws({ jws: signed.serialized,
        publicKey: key.publicKey, algId: algId });
      assert.ok(verified.valid, algId + " / " + serialization +
        " did not verify: " + JSON.stringify(verified.signatures));
      // The payload comes back BYTE FOR BYTE, indentation included. A module
      // that re-serialized it would return something that parses the same and
      // is not the same, and every signature it made would be over octets the
      // caller never saw.
      assert.strictEqual(verified.payload, PAYLOAD,
        algId + " / " + serialization + " did not return the payload as it " +
        "was given.");
      assert.strictEqual(verified.serialization, serialization);
      count++;
    });
  });
  log.info("[round-trip] OK — " + count + " algorithm/serialization pairs.");
  log.debug("Leaving checkRoundTrips().");
}

// ---------------------------------------------------------------------------
// 3. OpenSSL, in both directions. This is the check that catches DER-instead-
//    of-R||S and a wrong PSS salt, and neither is visible from a round trip.
// ---------------------------------------------------------------------------
function checkAgainstOpenssl() {
  log.debug("Entering checkAgainstOpenssl().");
  const rsa = jws.generateKey("RS256", { bits: 2048 });
  let count = 0;
  jws.algIds().forEach(function (algId) {
    const spec = jws.algSpec(algId);
    if (spec.family === "none") return;
    const key = spec.family === "rsa" ? rsa : jws.generateKey(algId);

    const signed = jws.signJws({ algId: algId, payload: PAYLOAD,
      privateKey: key.privateKey, publicKey: key.publicKey });
    const parts = signed.serialized.split(".");
    const input = Buffer.from(parts[0] + "." + parts[1]);
    const signature = Buffer.from(parts[2], "base64url");

    if (spec.family === "hmac") {
      const tag = crypto.createHmac(NODE_HASH[spec.hash],
        Buffer.from(key.privateKey)).update(input).digest();
      assert.ok(tag.equals(signature),
        algId + " does not match node's HMAC over the same input.");
      count++;
      return;
    }
    const pub = nodePublicKey(algId, key.publicKey);
    if (spec.family === "okp") {
      assert.ok(crypto.verify(null, input, pub, signature),
        algId + " signature was refused by OpenSSL.");
      const back = crypto.sign(null, input, key.privateKey && pub && (function
          () {
        return crypto.createPrivateKey({ key: {
          kty: "OKP", crv: spec.crv,
          x: jws.publicJwk(algId, key.publicKey).x,
          d: Buffer.from(key.privateKey).toString("base64url") },
          format: "jwk" });
      })());
      assert.ok(jws.verifyJws({ jws: parts[0] + "." + parts[1] + "." +
        back.toString("base64url"), publicKey: key.publicKey,
        algId: algId }).valid,
        algId + ": a signature OpenSSL made was refused by this module.");
      count++;
      return;
    }
    if (spec.family === "ec") {
      // RFC 7518 §3.4: R || S, each padded to the coordinate size. This is
      // the assertion that fails the moment somebody returns what a crypto
      // library's sign() hands back, which is DER.
      assert.strictEqual(signature.length, spec.fieldBytes * 2,
        algId + " signature is " + signature.length + " bytes; RFC 7518 §3.4 " +
        "requires " + (spec.fieldBytes * 2) + " (R || S). A DER SEQUENCE is " +
        "the usual reason this is wrong, and it round-trips perfectly.");
      const verifier = crypto.createVerify(NODE_HASH[spec.hash]);
      verifier.update(input);
      assert.ok(verifier.verify(pub, rsToDer(signature)),
        algId + " signature was refused by OpenSSL.");
      const ecPriv = crypto.createPrivateKey({ key: {
        kty: "EC", crv: jws.publicJwk(algId, key.publicKey).crv,
        x: jws.publicJwk(algId, key.publicKey).x,
        y: jws.publicJwk(algId, key.publicKey).y,
        d: Buffer.from(key.privateKey).toString("base64url") },
        format: "jwk" });
      const signer = crypto.createSign(NODE_HASH[spec.hash]);
      signer.update(input);
      const raw = derToRs(signer.sign(ecPriv), spec.fieldBytes);
      assert.ok(jws.verifyJws({ jws: parts[0] + "." + parts[1] + "." +
        raw.toString("base64url"), publicKey: key.publicKey,
        algId: algId }).valid,
        algId + ": a signature OpenSSL made was refused by this module. For " +
        "secp256k1 the usual cause is @noble's low-S rule, which JOSE does " +
        "not have.");
      count++;
      return;
    }
    // RSA, both paddings, both directions.
    const params = nodeSignParams(spec);
    const v = crypto.createVerify(NODE_HASH[spec.hash]);
    v.update(input);
    assert.ok(v.verify(Object.assign({ key: key.publicKey }, params),
      signature), algId + " signature was refused by OpenSSL.");
    const s = crypto.createSign(NODE_HASH[spec.hash]);
    s.update(input);
    const opensslSig = s.sign(Object.assign({ key: key.privateKey }, params));
    assert.ok(jws.verifyJws({ jws: parts[0] + "." + parts[1] + "." +
      opensslSig.toString("base64url"), publicKey: key.publicKey,
      algId: algId }).valid,
      algId + ": a signature OpenSSL made was refused by this module.");
    count++;
  });
  log.info("[openssl] OK — " + count + " algorithms cross-checked against " +
           "node's own crypto, in both directions.");
  log.debug("Leaving checkAgainstOpenssl().");
}

// The PSS salt length is fixed by RFC 7518 §3.5 at the hash's own size, and a
// wrong one is invisible from a round trip. OpenSSL will verify a PSS
// signature with `saltLength: RSA_PSS_SALTLEN_AUTO` whatever the salt was, so
// this asserts the length EXPLICITLY in both directions instead.
function checkPssSaltLength() {
  log.debug("Entering checkPssSaltLength().");
  const rsa = jws.generateKey("RS256", { bits: 2048 });
  ["PS256", "PS384", "PS512"].forEach(function (algId) {
    const spec = jws.algSpec(algId);
    const expected = jws.HASHES[spec.hash].bytes;
    const signed = jws.signJws({ algId: algId, payload: PAYLOAD,
      privateKey: rsa.privateKey });
    const parts = signed.serialized.split(".");
    const input = Buffer.from(parts[0] + "." + parts[1]);
    const signature = Buffer.from(parts[2], "base64url");
    const v = crypto.createVerify(NODE_HASH[spec.hash]);
    v.update(input);
    assert.ok(v.verify({ key: rsa.publicKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: expected }, signature),
      algId + " was not made with a " + expected + "-byte salt. RFC 7518 " +
      "§3.5 fixes it at the hash length; any other value verifies against " +
      "nothing else.");
    const wrong = expected === 32 ? 48 : 32;
    const v2 = crypto.createVerify(NODE_HASH[spec.hash]);
    v2.update(input);
    assert.ok(!v2.verify({ key: rsa.publicKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: wrong },
      signature), algId + ": the salt-length assertion above is vacuous — " +
      "OpenSSL accepted a " + wrong + "-byte salt too.");
  });
  log.info("[pss] OK — every PS* salt is exactly the hash length.");
  log.debug("Leaving checkPssSaltLength().");
}

// ---------------------------------------------------------------------------
// 4. jsonwebtoken — a third opinion, and the one that reads a JWS the way an
//    application does rather than the way a crypto library does.
// ---------------------------------------------------------------------------
function checkAgainstJsonwebtoken() {
  log.debug("Entering checkAgainstJsonwebtoken().");
  const rsa = jws.generateKey("RS256", { bits: 2048 });
  const claims = { sub: "alice", iss: "https://as.example.com" };
  let count = 0;
  ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384",
   "PS512", "ES256", "ES384", "ES512"].forEach(function (algId) {
    const spec = jws.algSpec(algId);
    const key = spec.family === "rsa" ? rsa : jws.generateKey(algId);
    const signed = jws.signJws({ algId: algId,
      payload: JSON.stringify(claims), privateKey: key.privateKey,
      publicKey: key.publicKey, typ: "JWT" });
    const verifyKey = spec.family === "hmac" ? Buffer.from(key.privateKey)
      : nodePublicKey(algId, key.publicKey);
    const decoded = jsonwebtoken.verify(signed.serialized, verifyKey,
      { algorithms: [algId] });
    assert.strictEqual(decoded.sub, "alice",
      algId + ": jsonwebtoken read a different payload.");
    count++;
  });
  log.info("[jsonwebtoken] OK — " + count + " algorithms accepted by a " +
           "library that is not this one.");
  log.debug("Leaving checkAgainstJsonwebtoken().");
}

// ---------------------------------------------------------------------------
// 5. The serializations, and what each of them may and may not carry.
// ---------------------------------------------------------------------------
function checkSerializations() {
  log.debug("Entering checkSerializations().");
  const key = jws.generateKey("ES256");
  const compact = jws.signJws({ algId: "ES256", payload: PAYLOAD,
    privateKey: key.privateKey });
  assert.strictEqual(compact.serialized.split(".").length, 3);

  const flattened = JSON.parse(jws.signJws({ algId: "ES256",
    payload: PAYLOAD, privateKey: key.privateKey,
    serialization: "flattened", unprotected: { note: "not signed" }
  }).serialized);
  assert.ok(flattened.payload && flattened.protected && flattened.signature,
    "a flattened JWS carries payload, protected and signature.");
  assert.strictEqual(flattened.header.note, "not signed");

  const general = JSON.parse(jws.signJws({ algId: "ES256", payload: PAYLOAD,
    privateKey: key.privateKey, serialization: "general" }).serialized);
  assert.ok(Array.isArray(general.signatures),
    "a general JWS carries a signatures ARRAY (RFC 7515 §7.2.1).");

  // RFC 7515 §7.1: the compact serialization has nowhere to put an
  // unprotected header, so asking for one is an error rather than a silent
  // drop — a dropped one would be a member the caller believes is present.
  assert.throws(function () {
    jws.signJws({ algId: "ES256", payload: PAYLOAD,
      privateKey: key.privateKey, unprotected: { note: "x" } });
  }, /unprotected header/i);

  // An unprotected member is NOT covered: changing it leaves the signature
  // valid, which is the whole difference between the two headers and the
  // reason nothing security-relevant belongs in one.
  const doc = JSON.parse(jws.signJws({ algId: "ES256", payload: PAYLOAD,
    privateKey: key.privateKey, serialization: "flattened",
    unprotected: { note: "not signed" } }).serialized);
  doc.header.note = "changed";
  assert.ok(jws.verifyJws({ jws: JSON.stringify(doc),
    publicKey: key.publicKey, algId: "ES256" }).valid,
    "an unprotected header member is not covered by the signature.");
  log.info("[serializations] OK — compact, flattened and general.");
  log.debug("Leaving checkSerializations().");
}

// ---------------------------------------------------------------------------
// 6. Detached payloads (RFC 7515 App. F) and unencoded ones (RFC 7797).
// ---------------------------------------------------------------------------
function checkDetachedAndUnencoded() {
  log.debug("Entering checkDetachedAndUnencoded().");
  const key = jws.generateKey("ES256");
  const detached = jws.signJws({ algId: "ES256", payload: PAYLOAD,
    privateKey: key.privateKey, detached: true });
  assert.strictEqual(detached.serialized.split(".")[1], "",
    "a detached compact JWS has an EMPTY middle part.");
  assert.ok(jws.verifyJws({ jws: detached.serialized,
    publicKey: key.publicKey, algId: "ES256",
    detachedPayload: PAYLOAD }).valid);
  assert.throws(function () {
    jws.verifyJws({ jws: detached.serialized, publicKey: key.publicKey,
      algId: "ES256" });
  }, /detached/i, "verifying a detached JWS with no payload must say so.");
  assert.ok(!jws.verifyJws({ jws: detached.serialized,
    publicKey: key.publicKey, algId: "ES256",
    detachedPayload: PAYLOAD + " " }).valid,
    "a detached JWS must not verify against a different payload.");

  // RFC 7797 §3: b64 goes in the PROTECTED header and MUST be listed in crit,
  // so a recipient that does not implement 7797 rejects the JWS rather than
  // verifying it against the base64url of a payload that was never encoded.
  const unencoded = jws.signJws({ algId: "ES256", payload: '{"a":1}',
    privateKey: key.privateKey, b64: false, serialization: "flattened" });
  assert.strictEqual(unencoded.header.b64, false);
  assert.ok(unencoded.header.crit.indexOf("b64") >= 0,
    'RFC 7797 §3: "b64" MUST appear in the crit header.');
  assert.ok(jws.verifyJws({ jws: unencoded.serialized,
    publicKey: key.publicKey, algId: "ES256" }).valid);

  // §5.2: the period is the compact serialization's delimiter, so an
  // unencoded payload containing one cannot go in it. A JSON payload hits
  // this on any decimal number.
  assert.throws(function () {
    jws.signJws({ algId: "ES256", payload: '{"pi":3.14}',
      privateKey: key.privateKey, b64: false });
  }, /RFC 7797/, "an unencoded compact payload containing a period must be " +
     "refused, not serialized into four parts.");
  log.info("[detached/unencoded] OK — RFC 7515 App. F and RFC 7797.");
  log.debug("Leaving checkDetachedAndUnencoded().");
}

// ---------------------------------------------------------------------------
// 7. The header rules a verifier is most often missing.
// ---------------------------------------------------------------------------
function checkHeaderRules() {
  log.debug("Entering checkHeaderRules().");
  const key = jws.generateKey("ES256");
  const b64u = function (o) {
    log.debug("Entering b64u().");
    log.debug("Leaving b64u().");
    return Buffer.from(JSON.stringify(o)).toString("base64url");
  };

  // RFC 7515 §4.1.11: an extension the producer marked critical and the
  // verifier does not implement means the JWS is REJECTED. Verifying it with
  // the member ignored is the defect this asserts against.
  const header = { alg: "ES256", crit: ["exp-ext"], "exp-ext": 1 };
  const payload = Buffer.from(PAYLOAD).toString("base64url");
  const input = b64u(header) + "." + payload;
  const signature = jws.signOctets(jws.algSpec("ES256"), key.privateKey,
    Buffer.from(input));
  const forged = input + "." +
    Buffer.from(signature).toString("base64url");
  const critResult = jws.verifyJws({ jws: forged, publicKey: key.publicKey,
    algId: "ES256" });
  assert.ok(!critResult.valid,
    "a crit header naming an unimplemented extension MUST be rejected " +
    "(RFC 7515 §4.1.11), even though the signature itself is good.");
  assert.ok(/critical/i.test(critResult.signatures[0].reason),
    "the refusal must name what it is about: " +
    critResult.signatures[0].reason);

  // RFC 8725 §3.1: the verifier decides the algorithm. Selecting one and
  // being handed a token that names another is reported, not accommodated —
  // that accommodation is the algorithm-confusion attack.
  const signed = jws.signJws({ algId: "ES256", payload: PAYLOAD,
    privateKey: key.privateKey });
  const mismatch = jws.verifyJws({ jws: signed.serialized,
    publicKey: key.publicKey, algId: "ES384" });
  assert.ok(!mismatch.valid && /RFC 8725/.test(mismatch.signatures[0].reason),
    "an alg the verifier did not choose must be refused by name.");

  // The header is covered by the signature. Changing one byte of it — a kid,
  // say — invalidates the JWS even though nothing about the payload moved.
  const withKid = jws.signJws({ algId: "ES256", payload: PAYLOAD,
    privateKey: key.privateKey, kid: "k1", typ: "JWT",
    cty: "application/json", header: { custom: true } });
  assert.strictEqual(withKid.header.kid, "k1");
  assert.strictEqual(withKid.header.typ, "JWT");
  assert.strictEqual(withKid.header.cty, "application/json");
  assert.strictEqual(withKid.header.custom, true);
  const parts = withKid.serialized.split(".");
  const swapped = b64u(Object.assign({}, withKid.header, { kid: "k2" })) +
    "." + parts[1] + "." + parts[2];
  assert.ok(!jws.verifyJws({ jws: swapped, publicKey: key.publicKey,
    algId: "ES256" }).valid,
    "the protected header is covered by the signature.");

  // An embedded jwk is the public half and nothing else — a `d` member there
  // would be the private key published in the token.
  const embedded = jws.signJws({ algId: "ES256", payload: PAYLOAD,
    privateKey: key.privateKey, publicKey: key.publicKey, embedJwk: true });
  assert.strictEqual(embedded.header.jwk.crv, "P-256");
  assert.strictEqual(embedded.header.jwk.d, undefined,
    "an embedded jwk must never carry the private key.");
  log.info("[headers] OK — crit, algorithm confusion, coverage, jwk.");
  log.debug("Leaving checkHeaderRules().");
}

// ---------------------------------------------------------------------------
// 8. EdDSA: one `alg`, two curves, and the key is the only thing that says
//    which (RFC 8037 §3.1). Getting this wrong reads as a bad signature.
// ---------------------------------------------------------------------------
function checkEddsaCurves() {
  log.debug("Entering checkEddsaCurves().");
  const ed25519 = jws.generateKey("EdDSA-Ed25519");
  const ed448 = jws.generateKey("EdDSA-Ed448");
  assert.strictEqual(ed25519.publicKey.length, 32);
  assert.strictEqual(ed448.publicKey.length, 57);

  const a = jws.signJws({ algId: "EdDSA-Ed25519", payload: PAYLOAD,
    privateKey: ed25519.privateKey });
  const b = jws.signJws({ algId: "EdDSA-Ed448", payload: PAYLOAD,
    privateKey: ed448.privateKey });
  assert.strictEqual(a.header.alg, "EdDSA");
  assert.strictEqual(b.header.alg, "EdDSA");
  assert.notStrictEqual(a.signature.length, b.signature.length,
    "the two curves produce different signature sizes; the header does not " +
    "distinguish them.");

  // Verification with no algId picks the row by KEY LENGTH, which is the only
  // information there is.
  assert.ok(jws.verifyJws({ jws: a.serialized,
    publicKey: ed25519.publicKey }).valid);
  assert.ok(jws.verifyJws({ jws: b.serialized,
    publicKey: ed448.publicKey }).valid);
  assert.ok(!jws.verifyJws({ jws: a.serialized,
    publicKey: ed448.publicKey }).valid,
    "an Ed25519 signature must not verify under an Ed448 key.");
  log.info("[eddsa] OK — one alg, two curves, told apart by the key.");
  log.debug("Leaving checkEddsaCurves().");
}

// ---------------------------------------------------------------------------
// 9. The Unsecured JWS. It is in the registry, it authenticates nothing, and
//    the reason to implement it is that a relying party which accepts one has
//    a critical defect you have to be able to demonstrate.
// ---------------------------------------------------------------------------
function checkUnsecured() {
  log.debug("Entering checkUnsecured().");
  const signed = jws.signJws({ algId: "none", payload: PAYLOAD });
  assert.ok(/\.$/.test(signed.serialized),
    "an Unsecured JWS ends with an EMPTY signature (RFC 7515 §6).");
  const verified = jws.verifyJws({ jws: signed.serialized, algId: "none" });
  assert.ok(verified.valid && verified.unsecured,
    "an Unsecured JWS is well-formed and is reported AS unsecured.");

  // A non-empty signature is not an Unsecured JWS. Saying "valid" about one
  // would be a claim about a token nothing authenticates either way.
  const parts = signed.serialized.split(".");
  const bogus = parts[0] + "." + parts[1] + "." +
    Buffer.from("anything").toString("base64url");
  assert.ok(!jws.verifyJws({ jws: bogus, algId: "none" }).valid,
    "alg=none with a non-empty signature must be refused.");
  log.info("[none] OK — Unsecured JWS is produced, and is reported as one.");
  log.debug("Leaving checkUnsecured().");
}

// ---------------------------------------------------------------------------
// 10. Tampering, and the JSON rule the pane exists to enforce.
// ---------------------------------------------------------------------------
function checkTamperingAndJson() {
  log.debug("Entering checkTamperingAndJson().");
  jws.algIds().forEach(function (algId) {
    if (jws.algSpec(algId).family === "none") return;
    const key = jws.generateKey(algId, { bits: 2048 });
    const signed = jws.signJws({ algId: algId, payload: PAYLOAD,
      privateKey: key.privateKey });
    const parts = signed.serialized.split(".");
    const swapped = parts[0] + "." +
      Buffer.from(PAYLOAD.replace("alice", "mallory")).toString("base64url") +
      "." + parts[2];
    assert.ok(!jws.verifyJws({ jws: swapped, publicKey: key.publicKey,
      algId: algId }).valid, algId + ": a changed payload must not verify.");
  });

  assert.ok(jws.validateJson('{"a":1}').valid);
  assert.strictEqual(jws.validateJson('{"a":1}').kind, "object");
  assert.strictEqual(jws.validateJson('[1,2]').kind, "array");
  assert.ok(!jws.validateJson("{not json").valid);
  assert.ok(!jws.validateJson("").valid);
  assert.ok(/not well-formed JSON/.test(jws.validateJson("{").error));

  // compactJson() is the ONLY thing here that rewrites a payload, and it is
  // separate from signing on purpose: reformatting changes the octets under
  // the signature, so it is a decision rather than a side effect.
  assert.strictEqual(jws.compactJson(PAYLOAD).indexOf("\n"), -1);
  assert.throws(function () { jws.compactJson("{"); }, /not well-formed/);
  log.info("[tamper/json] OK — every algorithm refuses a changed payload, " +
           "and the JSON check reports rather than repairs.");
  log.debug("Leaving checkTamperingAndJson().");
}

// ---------------------------------------------------------------------------
// 11. THE KEY FORMS, which are what let five pages stop each carrying their
//     own reading of "the user pasted something".
//
//     Every conversion is checked by making node produce the key and this
//     module consume it (or the reverse), so a wrong `crv`, a mis-padded
//     coordinate, a DER OCTET STRING read as a scalar, or base64 where
//     base64url was meant all fail here rather than in a browser.
// ---------------------------------------------------------------------------
function nodeKeyPair(algId) {
  log.debug("Entering nodeKeyPair().");
  const spec = jws.algSpec(algId);
  let pair;
  if (spec.family === "rsa") {
    pair = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  } else if (spec.family === "ec") {
    pair = crypto.generateKeyPairSync("ec",
      { namedCurve: NODE_CURVES[algId] });
  } else {
    pair = crypto.generateKeyPairSync(spec.crv.toLowerCase());
  }
  log.debug("Leaving nodeKeyPair().");
  return {
    privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }),
    publicPem: pair.publicKey.export({ format: "pem", type: "spki" }),
    privateJwk: pair.privateKey.export({ format: "jwk" }),
    publicJwk: pair.publicKey.export({ format: "jwk" }),
    nodePrivate: pair.privateKey,
    nodePublic: pair.publicKey
  };
}

// A real X.509 certificate over a given key, minted with node's own OpenSSL
// through node-forge for RSA and by hand-assembling the DER for the rest —
// except node cannot issue certificates, so this uses the module under test's
// sibling: forge for RSA, and for the curves a certificate produced by
// wrapping the SPKI, which is all spkiFromCertificatePem() has to find.
function certificateOver(publicPem, privatePem) {
  log.debug("Entering certificateOver().");
  const forge = require("node-forge");
  const cert = forge.pki.createCertificate();
  cert.publicKey = forge.pki.publicKeyFromPem(publicPem);
  cert.serialNumber = "01";
  cert.validity.notBefore = new Date(Date.UTC(2020, 0, 1));
  cert.validity.notAfter = new Date(Date.UTC(2035, 0, 1));
  const attrs = [{ name: "commonName", value: "jws-engine-test" }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(forge.pki.privateKeyFromPem(privatePem), forge.md.sha256.create());
  log.debug("Leaving certificateOver().");
  return forge.pki.certificateToPem(cert);
}

function checkKeyForms() {
  log.debug("Entering checkKeyForms().");
  let count = 0;

  // --- PEM in, both directions, for every asymmetric family. The PRIVATE
  //     side is the one that catches a bad PKCS#8 walk: an EC private key is
  //     an OCTET STRING inside an OCTET STRING, and reading the outer one
  //     gives DER where a scalar belongs — which signs, and verifies nowhere.
  ["RS256", "PS384", "ES256", "ES384", "ES512", "EdDSA-Ed25519",
   "EdDSA-Ed448"].forEach(function (algId) {
    const keys = nodeKeyPair(algId);
    const signed = jws.signJws({ algId: algId, payload: PAYLOAD,
      privateKey: keys.privatePem });
    assert.ok(jws.verifyJws({ jws: signed.serialized,
      publicKey: keys.publicPem, algId: algId }).valid,
      algId + ": a PKCS#8 PEM in and an SPKI PEM out did not round-trip.");
    // ...and node agrees the signature is over the right octets.
    const parts = signed.serialized.split(".");
    const input = Buffer.from(parts[0] + "." + parts[1]);
    const sig = Buffer.from(parts[2], "base64url");
    const spec = jws.algSpec(algId);
    let ok;
    if (spec.family === "okp") {
      ok = crypto.verify(null, input, keys.nodePublic, sig);
    } else if (spec.family === "ec") {
      const v = crypto.createVerify(NODE_HASH[spec.hash]);
      v.update(input);
      ok = v.verify(keys.nodePublic, rsToDer(sig));
    } else {
      const v = crypto.createVerify(NODE_HASH[spec.hash]);
      v.update(input);
      ok = v.verify(Object.assign({ key: keys.nodePublic },
                                  nodeSignParams(spec)), sig);
    }
    assert.ok(ok, algId + ": OpenSSL refused a signature made from its own " +
      "PEM key, so the PEM was parsed as something other than that key.");
    count++;
  });

  // --- JWK in, both directions. node exports the JWK; this module reads it.
  ["RS256", "ES256", "ES512", "EdDSA-Ed25519", "EdDSA-Ed448"].forEach(
      function (algId) {
    const keys = nodeKeyPair(algId);
    const signed = jws.signJws({ algId: algId, payload: PAYLOAD,
      privateKey: { jwk: keys.privateJwk } });
    assert.ok(jws.verifyJws({ jws: signed.serialized,
      publicKey: { jwk: keys.publicJwk }, algId: algId }).valid,
      algId + ": a private JWK in and a public JWK out did not round-trip.");
    // A PUBLIC JWK must be refused for signing, by name — handing one to a
    // signer is a mistake that otherwise produces a key of zeros.
    assert.throws(function () {
      jws.signJws({ algId: algId, payload: PAYLOAD,
        privateKey: { jwk: keys.publicJwk } });
    }, /PUBLIC key|no "d"|d.*member/i,
       algId + ": signing with a public JWK must be refused by name.");
    count++;
  });

  // --- An EC JWK whose coordinate lost a leading zero. A conforming
  //     publisher may trim it; the point must still be the same point.
  const ec = nodeKeyPair("ES256");
  const trimmed = Object.assign({}, ec.publicJwk);
  const xBytes = Buffer.from(trimmed.x, "base64url");
  if (xBytes[0] === 0) {
    trimmed.x = xBytes.slice(1).toString("base64url");
    const signed = jws.signJws({ algId: "ES256", payload: PAYLOAD,
      privateKey: { jwk: ec.privateJwk } });
    assert.ok(jws.verifyJws({ jws: signed.serialized,
      publicKey: { jwk: trimmed }, algId: "ES256" }).valid,
      "a trimmed EC coordinate must be re-padded to the original point.");
  }

  // --- Certificates. The two verification panes in this tree both offered
  //     "X.509 Certificate (PEM)" and both fed the PEM to importKey('spki'),
  //     which cannot read a Certificate at all — so the only thing that ever
  //     worked in those fields was a public KEY. This asserts the label is
  //     true now: a real certificate verifies.
  const rsa = nodeKeyPair("RS256");
  const certPem = certificateOver(rsa.publicPem, rsa.privatePem);
  const rsaSigned = jws.signJws({ algId: "RS256", payload: PAYLOAD,
    privateKey: rsa.privatePem });
  assert.ok(jws.verifyJws({ jws: rsaSigned.serialized, publicKey: certPem,
    algId: "RS256" }).valid,
    "an X.509 CERTIFICATE must verify a JWS, not only a public key PEM.");
  // ...and the SPKI it pulled out is byte-identical to the key's own.
  assert.strictEqual(
    jws.spkiFromCertificatePem(certPem).replace(/\s+/g, ""),
    rsa.publicPem.replace(/\s+/g, ""),
    "the SPKI walked out of the certificate is not the key's own SPKI.");
  count++;

  // --- A JWK Set: by kid, by being the only candidate, and the two ways it
  //     can be unanswerable.
  const a = nodeKeyPair("RS256"), b = nodeKeyPair("ES256");
  const set = { keys: [
    Object.assign({ kid: "a", use: "sig" }, a.publicJwk),
    Object.assign({ kid: "b", use: "sig" }, b.publicJwk)
  ] };
  const byKid = jws.signJws({ algId: "ES256", payload: PAYLOAD,
    privateKey: { jwk: b.privateJwk }, kid: "b" });
  assert.ok(jws.verifyJws({ jws: byKid.serialized, publicKey: { jwks: set },
    algId: "ES256" }).valid, "a JWK Set must resolve the key by kid.");
  const wrongKid = jws.signJws({ algId: "ES256", payload: PAYLOAD,
    privateKey: { jwk: b.privateJwk }, kid: "nope" });
  const missing = jws.verifyJws({ jws: wrongKid.serialized,
    publicKey: { jwks: set }, algId: "ES256" });
  assert.ok(!missing.valid && /kid/.test(missing.signatures[0].reason),
    "a kid that is not in the set must be reported as that, not as a bad " +
    "signature. Got: " + missing.signatures[0].reason);
  // No kid, one usable key for that algorithm: the common small-issuer case.
  const noKid = jws.signJws({ algId: "ES256", payload: PAYLOAD,
    privateKey: { jwk: b.privateJwk } });
  assert.ok(jws.verifyJws({ jws: noKid.serialized,
    publicKey: { jwks: { keys: [b.publicJwk] } }, algId: "ES256" }).valid,
    "a set with one usable key and no kid must verify.");
  // No kid, two usable keys: genuinely unanswerable, and it says so rather
  // than picking the first and being right half the time.
  const c = nodeKeyPair("ES256");
  const ambiguous = jws.verifyJws({ jws: noKid.serialized,
    publicKey: { jwks: { keys: [b.publicJwk, c.publicJwk] } },
    algId: "ES256" });
  assert.ok(!ambiguous.valid &&
    /not knowable|no "kid"/.test(ambiguous.signatures[0].reason),
    "an ambiguous set must be refused, not guessed. Got: " +
    ambiguous.signatures[0].reason);
  count++;

  // --- The three ways a shared secret is written down. The SAME bytes must
  //     come out, and two of this tree's pages disagreed about this for the
  //     same field.
  const raw = Buffer.from("0123456789abcdef0123456789abcdef", "utf8");
  assert.ok(Buffer.from(jws.secretBytes(raw.toString("utf8"), "text"))
    .equals(raw));
  assert.ok(Buffer.from(jws.secretBytes(raw.toString("hex"), "hex"))
    .equals(raw));
  assert.ok(Buffer.from(jws.secretBytes(raw.toString("base64url"), "b64u"))
    .equals(raw));
  const hs = jws.signJws({ algId: "HS256", payload: PAYLOAD,
    privateKey: { secret: raw.toString("hex"), encoding: "hex" } });
  assert.ok(jws.verifyJws({ jws: hs.serialized,
    publicKey: raw.toString("base64url"), secretEncoding: "b64u",
    algId: "HS256" }).valid,
    "the same secret written two ways must verify its own signature.");
  assert.ok(!jws.verifyJws({ jws: hs.serialized,
    publicKey: raw.toString("hex"), secretEncoding: "text",
    algId: "HS256" }).valid,
    "reading a hex secret as TEXT must NOT verify — that is the difference " +
    "two pages in this tree had between them, and it is a different key.");
  count++;

  log.info("[key forms] OK — " + count + " form group(s): PEM (PKCS#8/SPKI), " +
           "X.509 certificates, JWK, JWK Sets, and secrets in three " +
           "encodings.");
  log.debug("Leaving checkKeyForms().");
}

// ---------------------------------------------------------------------------
// 12. THE TWO BACKENDS MUST BE INTERCHANGEABLE.
//
//     This is the assertion the whole consolidation rests on. Four workflows
//     (DPoP proofs, OID4VCI credential proofs, SD-JWT VC Key Binding JWTs and
//     the JWT Tools Sign pane) signed with crypto.subtle before this module
//     absorbed them, and none of their tests could have noticed if the bytes
//     had changed. So: sign the same input with each backend and require the
//     other one to verify it — and, for the deterministic algorithms, require
//     the bytes themselves to be identical.
// ---------------------------------------------------------------------------
async function checkBackendsAgree() {
  log.debug("Entering checkBackendsAgree().");
  if (!globalThis.crypto || !globalThis.crypto.subtle) {
    // Not a skip that hides: a node old enough to lack Web Crypto cannot run
    // this half, and the run has to say so rather than report a pass.
    throw new Error("This node has no global Web Crypto, so the webcrypto " +
      "backend cannot be checked. That is the backend four workflows use.");
  }
  let count = 0;
  const ALGS = ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512",
                "PS256", "ES256", "ES384", "ES512", "EdDSA-Ed25519"];
  for (const algId of ALGS) {
    const spec = jws.algSpec(algId);
    let priv, pub;
    if (spec.family === "hmac") {
      const secret = crypto.randomBytes(jws.HASHES[spec.hash].bytes);
      priv = pub = { secret: secret.toString("base64url"), encoding: "b64u" };
    } else {
      const keys = nodeKeyPair(algId);
      priv = { jwk: keys.privateJwk };
      pub = { jwk: keys.publicJwk };
    }
    const viaJs = jws.signJws({ algId: algId, payload: PAYLOAD,
      privateKey: priv, backend: "js" });
    const viaWeb = await jws.signJwsAsync({ algId: algId, payload: PAYLOAD,
      privateKey: priv, backend: "webcrypto" });

    // The protected header and the signing input are the JOSE half, and they
    // must be identical whatever signed them.
    assert.strictEqual(viaJs.protected, viaWeb.protected,
      algId + ": the two backends produced different protected headers.");
    assert.strictEqual(viaJs.signingInput, viaWeb.signingInput,
      algId + ": the two backends produced different signing inputs.");

    // Each backend's signature must satisfy the other's verifier.
    assert.ok((await jws.verifyJwsAsync({ jws: viaJs.serialized,
      publicKey: pub, algId: algId, backend: "webcrypto" })).valid,
      algId + ": Web Crypto refused a signature the JS backend made.");
    assert.ok(jws.verifyJws({ jws: viaWeb.serialized, publicKey: pub,
      algId: algId, backend: "js" }).valid,
      algId + ": the JS backend refused a signature Web Crypto made.");

    // For the deterministic algorithms the BYTES must match too. ECDSA and
    // PSS are randomised, so equality there would be a bug in the test.
    if (spec.family === "hmac" || (spec.family === "rsa" &&
        spec.pad !== "pss") || spec.family === "okp") {
      assert.strictEqual(viaJs.serialized, viaWeb.serialized,
        algId + " is deterministic, so the two backends must produce the " +
        "SAME token byte for byte. They did not, which means routing a " +
        "workflow through this module would change what it emits.");
    }
    count++;
  }

  // A CryptoKey picks the Web Crypto backend on its own, which is what the
  // pages holding non-extractable keys rely on.
  const wcPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  const fromCryptoKey = await jws.signJwsAsync({ algId: "ES256",
    payload: PAYLOAD, privateKey: wcPair.privateKey });
  assert.strictEqual(fromCryptoKey.backend, "webcrypto",
    "a CryptoKey must select the Web Crypto backend without being told.");
  assert.ok((await jws.verifyJwsAsync({ jws: fromCryptoKey.serialized,
    publicKey: wcPair.publicKey, algId: "ES256" })).valid,
    "a JWS signed with a non-extractable CryptoKey must verify with its " +
    "public half.");

  // And the synchronous entry point REFUSES a key it cannot use, rather than
  // returning a promise where a value was expected.
  assert.throws(function () {
    jws.signJws({ algId: "ES256", payload: PAYLOAD,
      privateKey: wcPair.privateKey });
  }, /synchronous/,
     "signJws() must refuse a CryptoKey by name rather than misbehave.");

  log.info("[backends] OK — " + count + " algorithms produce interchangeable " +
           "signatures on both backends, and identical bytes wherever the " +
           "algorithm is deterministic.");
  log.debug("Leaving checkBackendsAgree().");
}

// ---------------------------------------------------------------------------
// 13. The header a caller supplies VERBATIM.
//
//     Four workflows hand this module a header object they built themselves.
//     A JWS is the base64url of those exact bytes, so member order is part of
//     the token — re-ordering it would change every DPoP proof and every
//     credential proof this application produces, and no test in this
//     repository could have caught that.
// ---------------------------------------------------------------------------
function checkVerbatimHeader() {
  log.debug("Entering checkVerbatimHeader().");
  const keys = nodeKeyPair("ES256");
  const supplied = { typ: "dpop+jwt", alg: "ES256", jwk: keys.publicJwk };
  const signed = jws.signJws({ algId: "ES256",
    protectedHeader: supplied, payload: { htm: "POST" },
    privateKey: { jwk: keys.privateJwk } });
  const decoded = Buffer.from(signed.serialized.split(".")[0], "base64url")
    .toString("utf8");
  assert.strictEqual(decoded, JSON.stringify(supplied),
    "the supplied header must be serialized verbatim, member order included.");
  assert.ok(/^\{"typ"/.test(decoded),
    "`typ` was first in the supplied header and must still be first.");

  // A supplied header that disagrees with the chosen algorithm is refused,
  // rather than one of the two silently winning.
  assert.throws(function () {
    jws.signJws({ algId: "ES384",
      protectedHeader: { alg: "ES256" }, payload: {},
      privateKey: { jwk: keys.privateJwk } });
  }, /alg=ES256 but ES384/,
     "a header/algorithm disagreement must be named.");

  // An object payload is serialized compactly; a string payload is untouched.
  const obj = jws.signJws({ algId: "ES256", payload: { b: 1, a: 2 },
    privateKey: { jwk: keys.privateJwk } });
  assert.strictEqual(obj.payload, '{"b":1,"a":2}',
    "an object payload is serialized in its own member order, compactly.");
  const str = jws.signJws({ algId: "ES256", payload: "  {\n  }  ",
    privateKey: { jwk: keys.privateJwk } });
  assert.strictEqual(str.payload, "  {\n  }  ",
    "a string payload must be signed exactly as given, whitespace included.");
  log.info("[verbatim header] OK — supplied headers and payloads are not " +
           "rewritten.");
  log.debug("Leaving checkVerbatimHeader().");
}

// ---------------------------------------------------------------------------
async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. The Digital Signature page's JWS engine, in " +
           "node.");
  checkNoDom();
  checkRoundTrips();
  checkAgainstOpenssl();
  checkPssSaltLength();
  checkAgainstJsonwebtoken();
  checkSerializations();
  checkDetachedAndUnencoded();
  checkHeaderRules();
  checkEddsaCurves();
  checkUnsecured();
  checkTamperingAndJson();
  checkKeyForms();
  await checkBackendsAgree();
  checkVerbatimHeader();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

test().catch(function (error) {
  log.error(error.stack || error.message);
  process.exit(1);
});
