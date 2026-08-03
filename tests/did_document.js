// File: did_document.js
//
// client/src/did.js — Decentralized Identifiers for the VC workflows, and the
// Well Known DID Configuration check that links a DID to an origin.
//
// Everything in this file is testable without a browser or a service, and it is
// all the kind of thing that fails SILENTLY when it is wrong, which is why it is
// tested here rather than only through the pages:
//
//   * multicodec is an unsigned VARINT. The did:key table lists P-256 as 0x1200
//     and writing that as the two bytes 0x12 0x00 produces identifiers that
//     decode perfectly in our own code and in nobody else's. The visible
//     consequence is the prefix — every P-256 did:key begins "zDn" — so the
//     prefixes are pinned here.
//   * did:key carries a COMPRESSED EC point, so a round trip needs a modular
//     square root to get y back. A wrong root gives the OTHER valid point on the
//     curve: still a well-formed key, still decodes, verifies nothing. The oracle
//     is node's own EC implementation, which shares no code with this module.
//   * base58btc drops leading zero bytes unless they are counted and re-emitted,
//     and a key that loses one is a different key.
//   * a Domain Linkage Credential is a JWT with a header that MUST NOT carry typ
//     and a payload that permits no member beyond iss/sub/nbf/exp/vc. Both are
//     things a JWT library adds for you by default, so a correct-looking document
//     is the expected failure — and the whole point of the document is to be
//     checkable by somebody else's verifier.
//
// The negatives all assert WHICH check failed, not merely that verification
// failed overall. A verifier that rejects everything would pass a test that only
// looked at the verdict.
//
// No browser and no services: node only, so it never skips.
const assert = require("assert");
const crypto = require("crypto");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "did_document",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

// In a checkout the module is at client/src/did.js; the tests image copies it
// flat next to the test scripts (see tests/Dockerfile).
var did = paths.requireSharedModule(
  [__dirname + "/../client/src/did.js", __dirname + "/did.js"], "did.js");

// The signature checks go through Web Crypto, as they do in the browser. Assert
// it rather than discover a TypeError six functions deep.
assert.strictEqual(typeof crypto.webcrypto.subtle, "object", "this node has no Web Crypto");

function b64u(input) {
  return Buffer.from(input).toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// --- base58btc --------------------------------------------------------------
function base58RoundTrips() {
  log.info("=== base58btc ===");
  for (var length = 1; length <= 40; length++) {
    var bytes = crypto.randomBytes(length);
    var encoded = did.base58Encode(new Uint8Array(bytes));
    var back = Buffer.from(did.base58Decode(encoded));
    assert.strictEqual(back.toString("hex"), bytes.toString("hex"),
      length + " random bytes did not survive a base58btc round trip.");
  }
  log.info("[base58] OK — 40 lengths round-tripped.");

  // Base 58 arithmetic cannot express a leading zero byte, so the encoder has to
  // count them and re-emit one "1" each. A key that silently loses one is a
  // DIFFERENT key, and it decodes cleanly.
  var withZeros = new Uint8Array([0, 0, 0, 9, 9]);
  var enc = did.base58Encode(withZeros);
  assert.strictEqual(enc.slice(0, 3), "111",
    'three leading zero bytes must encode as three "1"s; got "' + enc + '".');
  assert.deepStrictEqual(Array.from(did.base58Decode(enc)), [0, 0, 0, 9, 9],
    "the leading zero bytes did not come back.");
  log.info("[base58] OK — leading zero bytes are preserved as \"1\"s.");

  // The alphabet omits the four characters that look alike, which is the whole
  // reason base58btc exists rather than base62.
  var alphabetSample = did.base58Encode(new Uint8Array(crypto.randomBytes(200)));
  ["0", "O", "I", "l"].forEach(function (c) {
    assert.strictEqual(alphabetSample.indexOf(c), -1,
      'base58btc must not emit "' + c + '"; it is excluded so a DID can be read aloud.');
  });
  log.info("[base58] OK — 0, O, I and l are never emitted.");
}

// --- multicodec -------------------------------------------------------------
function multicodecIsAVarint() {
  log.info("=== multicodec is a varint ===");
  assert.deepStrictEqual(Array.from(did.varintEncode(0x1200)), [0x80, 0x24],
    "0x1200 as an unsigned varint is 0x80 0x24. Written as the literal bytes 0x12 0x00 it " +
    "produces did:keys that decode here and nowhere else.");
  assert.deepStrictEqual(Array.from(did.varintEncode(0xed)), [0xed, 0x01],
    "0xed is ABOVE the 0x7f single-byte limit, so ed25519-pub is two bytes — which is why the " +
    "multicodec table writes it 0xed01 and why an Ed25519 did:key begins z6Mk.");
  assert.deepStrictEqual(Array.from(did.varintEncode(0x7f)), [0x7f],
    "0x7f is the largest value that fits in one varint byte.");
  [0, 1, 0x7f, 0x80, 0xed, 0xec, 0xe7, 0x1200, 0x1201, 0x1202, 0xffff].forEach(function (code) {
    var decoded = did.varintDecode(new Uint8Array(did.varintEncode(code)));
    assert.strictEqual(decoded.value, code, "varint round trip failed for 0x" + code.toString(16));
    assert.strictEqual(decoded.length, did.varintEncode(code).length,
      "varintDecode must report how many bytes it consumed, or the key that follows is misread.");
  });
  log.info("[multicodec] OK — 0x1200 encodes as 0x80 0x24 and eleven codes round-trip.");
}

// The prefix is the OBSERVABLE consequence of the varint being right, and it is
// what an interoperability failure would look like: a wallet comparing DIDs by
// string sees the wrong prefix long before anything is verified. These are the
// prefixes the did:key specification's own vectors show.
function didKeyPrefixes() {
  log.info("=== did:key prefixes ===");
  var expected = [
    { crv: "P-256", prefix: "zDn" },
    { crv: "P-384", prefix: "z82" },
    { crv: "P-521", prefix: "z2J" },
    { crv: "Ed25519", prefix: "z6Mk" }
  ];
  expected.forEach(function (spec) {
    var jwk;
    if (spec.crv === "Ed25519") {
      var ed = crypto.generateKeyPairSync("ed25519");
      jwk = ed.publicKey.export({ format: "jwk" });
    } else {
      var ec = crypto.generateKeyPairSync("ec", { namedCurve: spec.crv });
      jwk = ec.publicKey.export({ format: "jwk" });
    }
    var identifier = did.jwkToDidKey(jwk);
    assert.ok(identifier.indexOf("did:key:" + spec.prefix) === 0,
      "a " + spec.crv + " did:key must begin did:key:" + spec.prefix + "; got " +
      identifier.slice(0, 20) + "…");
  });
  log.info("[did:key] OK — P-256 zDn, P-384 z82, P-521 z2J, Ed25519 z6Mk.");
}

// The curve constants, checked against their published values before any point
// arithmetic uses them.
//
// This check exists because it found a real bug: P-384's and P-521's p and b were
// decimal strings split across two literals with a `+`, and each was NINE DIGITS
// SHORT. A truncated 116-digit decimal is invisible on the page, and the failure
// it produced was a refusal rather than a wrong answer — with the wrong field, no
// x has a square root, so every P-384 did:key was rejected as "not on the curve".
// P-256 was correct, and P-256 is the only curve anything in this project uses in
// anger, which is exactly why nothing noticed.
//
// The oracles are the definitions themselves: each NIST prime has a closed form,
// and p = 3 (mod 4) is the property decompressPoint() relies on to take a square
// root with a single modular exponentiation.
function curveConstantsArePublishedValues() {
  log.info("=== curve constants ===");
  var expected = {
    "P-256": { p: (BigInt(2) ** BigInt(256)) - (BigInt(2) ** BigInt(224)) +
                  (BigInt(2) ** BigInt(192)) + (BigInt(2) ** BigInt(96)) - BigInt(1), size: 32 },
    "P-384": { p: (BigInt(2) ** BigInt(384)) - (BigInt(2) ** BigInt(128)) -
                  (BigInt(2) ** BigInt(96)) + (BigInt(2) ** BigInt(32)) - BigInt(1), size: 48 },
    "P-521": { p: (BigInt(2) ** BigInt(521)) - BigInt(1), size: 66 }
  };
  Object.keys(expected).forEach(function (crv) {
    var curve = did.CURVES_FOR_TESTS[crv];
    assert.ok(curve, "did.js has no parameters for " + crv);
    assert.strictEqual(curve.p.toString(), expected[crv].p.toString(),
      crv + ": p is not the published prime. A truncated or mistyped field modulus makes every " +
      "point look as though it were off the curve.");
    assert.strictEqual((curve.p % BigInt(4)).toString(), "3",
      crv + ": p must be 3 (mod 4), which is what lets the square root be a single modPow.");
    // b must be a field element of the right magnitude — a truncated one is
    // orders of magnitude too small, which is precisely how the bug read.
    var pHexDigits = curve.p.toString(16).length;
    var bHexDigits = curve.b.toString(16).length;
    assert.ok(bHexDigits >= pHexDigits - 2 && bHexDigits <= pHexDigits,
      crv + ": b has " + bHexDigits + " hex digits against a field of " + pHexDigits +
      ". A curve coefficient that short has been truncated.");
    assert.ok(curve.b > BigInt(0) && curve.b < curve.p, crv + ": b must be a field element.");
    assert.strictEqual(curve.size, expected[crv].size, crv + ": the coordinate byte length is wrong.");
  });
  log.info("[curves] OK — three primes match their closed forms, all are 3 (mod 4), b is full length.");
}

// --- did:key against node's own EC implementation ---------------------------
function didKeyRoundTripsAgainstNode() {
  log.info("=== did:key round trip (oracle: node) ===");
  ["P-256", "P-384", "P-521"].forEach(function (crv) {
    // Several keys per curve: y's parity decides which square root is the right
    // one, so a decompressor that always picks the same root passes half the time.
    for (var i = 0; i < 8; i++) {
      var pair = crypto.generateKeyPairSync("ec", { namedCurve: crv });
      var jwk = pair.publicKey.export({ format: "jwk" });
      var identifier = did.jwkToDidKey(jwk);
      var recovered = did.didKeyToJwk(identifier);
      assert.strictEqual(recovered.kty, "EC", crv + ": kty was lost.");
      assert.strictEqual(recovered.crv, crv, crv + ": the curve was lost.");
      assert.strictEqual(recovered.x, jwk.x, crv + ": x did not survive the round trip.");
      assert.strictEqual(recovered.y, jwk.y,
        crv + ": y did not survive the round trip. A compressed point stores only x and the " +
        "parity of y, so this is the modular square root — the wrong root gives the other, " +
        "equally well-formed point on the curve, which verifies nothing.");
      // And the recovered key must be a key node itself will accept, which the
      // JWK comparison above does not prove on its own.
      crypto.createPublicKey({ key: recovered, format: "jwk" });
    }
  });
  log.info("[did:key] OK — 24 keys over three curves, y recovered by modular square root.");

  var ed = crypto.generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" });
  var edDid = did.jwkToDidKey(ed);
  var edBack = did.didKeyToJwk(edDid);
  assert.strictEqual(edBack.x, ed.x, "an Ed25519 key is not compressed and must round-trip exactly.");
  assert.strictEqual(edBack.crv, "Ed25519", "the Ed25519 curve was lost.");
  log.info("[did:key] OK — Ed25519 (uncompressed, 32 bytes).");

  assert.throws(function () { did.didKeyToJwk("did:key:QmFkZ2Vy"); }, /base58btc/,
    'a did:key that does not begin "z" is not multibase base58btc and must be refused.');
  assert.throws(function () { did.didKeyToJwk("did:key:z" + did.base58Encode(new Uint8Array([0x99, 0x01, 1, 2]))); },
    /multicodec/, "an unknown multicodec must be refused by name rather than guessed at.");
  log.info("[did:key] OK — a wrong multibase prefix and an unknown multicodec are refused.");
}

// --- did:jwk ----------------------------------------------------------------
function didJwkRoundTrips() {
  log.info("=== did:jwk ===");
  var pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var jwk = pair.publicKey.export({ format: "jwk" });
  var identifier = did.jwkToDidJwk(jwk);
  assert.ok(identifier.indexOf("did:jwk:") === 0, "a did:jwk must carry the method prefix.");
  var back = did.didJwkToJwk(identifier);
  assert.strictEqual(back.x, jwk.x, "x was lost.");
  assert.strictEqual(back.y, jwk.y, "y was lost.");

  // walt.id names its keys with a DID URL fragment, so a fragment must not stop
  // the identifier decoding — this is the form that arrives in a real iss.
  assert.strictEqual(did.didJwkToJwk(identifier + "#0").x, jwk.x,
    "a fragment on a did:jwk must be ignored when decoding the key.");

  // A private member must never reach the identifier: a did:jwk is published.
  var withPrivate = Object.assign({}, jwk, { d: "c2hvdWxkLW5vdC1iZS1oZXJl" });
  assert.strictEqual(did.didJwkToJwk(did.jwkToDidJwk(withPrivate)).d, undefined,
    "jwkToDidJwk must publish the public half only; a d member would put a private key in a DID.");
  assert.strictEqual(did.didJwkToJwk("did:jwk:notbase64url{"), null,
    "an undecodable did:jwk resolves to nothing rather than throwing: callers have other routes.");
  log.info("[did:jwk] OK — round trip, fragment tolerated, private members stripped.");
}

// --- did:web URL rules ------------------------------------------------------
function didWebUrlRules() {
  log.info("=== did:web URL rules ===");
  assert.strictEqual(did.didWebToUrl("did:web:example.com"),
    "https://example.com/.well-known/did.json",
    "a did:web with no path takes the well-known location.");
  assert.strictEqual(did.didWebToUrl("did:web:example.com:issuer:1"),
    "https://example.com/issuer/1/did.json",
    "a did:web WITH a path appends did.json to it and does NOT use the well-known location.");
  assert.strictEqual(did.didWebToUrl("did:web:localhost%3A8081"),
    "https://localhost:8081/.well-known/did.json",
    "a port is percent-encoded in the identifier and must be decoded back to a colon.");
  assert.strictEqual(did.didWebToUrl("did:web:sts%3A8081:oid4vci"),
    "https://sts:8081/oid4vci/did.json",
    "a port and a path together.");
  assert.strictEqual(did.didWebToUrlInsecure("did:web:localhost%3A8081"),
    "http://localhost:8081/.well-known/did.json",
    "the insecure variant differs only in the scheme; these stacks have no TLS.");
  assert.strictEqual(did.didWebToUrl("did:key:z6Mkabc"), "",
    "only did:web has a URL, and asking for another method's must not invent one.");
  log.info("[did:web] OK — well-known vs path, %3A ports, and the http variant.");
}

// --- resolution -------------------------------------------------------------
function fakeFetch(routes) {
  var calls = [];
  var impl = function (url) {
    calls.push(url);
    var route = routes[url];
    if (!route) return Promise.resolve({ ok: false, status: 404, text: function () { return Promise.resolve("not found"); } });
    return Promise.resolve({
      ok: route.status === undefined || (route.status >= 200 && route.status < 300),
      status: route.status === undefined ? 200 : route.status,
      text: function () { return Promise.resolve(typeof route.body === "string" ? route.body : JSON.stringify(route.body)); }
    });
  };
  impl.calls = calls;
  return impl;
}

async function resolutionIsLocalWherePossible() {
  log.info("=== resolve() ===");
  var pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var jwk = pair.publicKey.export({ format: "jwk" });

  // The provenance matters as much as the document: a pane that said "retrieved"
  // for a did:jwk would be teaching the opposite of how the method works.
  for (const identifier of [did.jwkToDidJwk(jwk), did.jwkToDidKey(jwk)]) {
    var noFetch = fakeFetch({});
    var resolved = await did.resolve(identifier, { fetch: noFetch });
    assert.strictEqual(resolved.url, "", identifier.slice(0, 12) + " must resolve with no URL.");
    assert.ok(/no network call/.test(resolved.from),
      "the provenance must say there was no network call; got: " + resolved.from);
    assert.strictEqual(noFetch.calls.length, 0,
      identifier.slice(0, 12) + " resolved locally but something was fetched anyway.");
    assert.strictEqual(resolved.document.id, identifier, "the document must identify the DID resolved.");
    assert.strictEqual(did.assertionKeys(resolved.document)[0].jwk.x, jwk.x,
      "the locally-derived document must carry the key the identifier encodes.");
  }
  log.info("[resolve] OK — did:jwk and did:key resolve locally, and fetch is never called.");

  var webDid = "did:web:issuer.example%3A8081";
  var url = did.didWebToUrl(webDid);
  var document = { "@context": ["https://www.w3.org/ns/did/v1"], id: webDid, verificationMethod: [] };
  var routes = {};
  routes[url] = { body: document };
  var fetched = await did.resolve(webDid, { fetch: fakeFetch(routes) });
  assert.strictEqual(fetched.url, url, "a did:web must report the URL it came from.");
  assert.ok(/retrieved from/.test(fetched.from), "and say that it was retrieved: " + fetched.from);
  log.info("[resolve] OK — did:web is fetched from the URL the method's rules give.");

  // DID Core: a resolved document's id MUST be the DID resolved. A document
  // claiming to be somebody else is the interesting failure and must not be
  // displayed as though it belonged here.
  var wrong = {};
  wrong[url] = { body: { id: "did:web:somebody.else", verificationMethod: [] } };
  await assert.rejects(did.resolve(webDid, { fetch: fakeFetch(wrong) }),
    /identifies itself as/,
    "a document whose id is a different DID must be refused, not rendered.");

  var notJson = {};
  notJson[url] = { body: "<html>nope</html>" };
  await assert.rejects(did.resolve(webDid, { fetch: fakeFetch(notJson) }), /is not JSON/,
    "a non-JSON document must say so.");
  await assert.rejects(did.resolve(webDid, { fetch: fakeFetch({}) }), /HTTP 404/,
    "an HTTP error must be reported with its status.");
  await assert.rejects(did.resolve("did:example:123", { fetch: fakeFetch({}) }),
    /not a method this debugger resolves/,
    "an unsupported method must name itself rather than failing obscurely.");
  await assert.rejects(did.resolve("not-a-did", { fetch: fakeFetch({}) }), /is not a DID/,
    "and something that is not a DID at all must say that.");
  log.info("[resolve] OK — id mismatch, non-JSON, HTTP status, unknown method and non-DIDs refused.");
}

// --- reading a document -----------------------------------------------------
function documentReading() {
  log.info("=== assertionKeys / keyForKid / assertionJwks ===");
  var rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var rsaJwk = rsa.publicKey.export({ format: "jwk" });
  var webDid = "did:web:issuer.example";
  var document = {
    id: webDid,
    verificationMethod: [
      { id: webDid + "#sig-1", type: "JsonWebKey2020", controller: webDid,
        publicKeyJwk: Object.assign({ kid: "sig-1", alg: "RS256" }, rsaJwk) },
      { id: webDid + "#bbs-1", type: "Multikey", controller: webDid,
        publicKeyMultibase: "uSGVsbG8gQkJT" }
    ],
    authentication: [webDid + "#sig-1"],
    assertionMethod: [webDid + "#sig-1", webDid + "#bbs-1"]
  };

  var methods = did.verificationMethods(document);
  assert.strictEqual(methods.length, 2, "both verification methods must be listed.");
  assert.strictEqual(methods[1].jwk, null,
    "a Multikey this cannot decode is still LISTED, with no JWK — dropping it would hide a " +
    "published key from the pane.");

  // assertionMethod holds references here, and they must be resolved against
  // verificationMethod rather than read where they stand.
  var asserting = did.assertionKeys(document);
  assert.strictEqual(asserting.length, 2, "both references must resolve.");
  assert.strictEqual(asserting[0].id, webDid + "#sig-1", "a reference must resolve to its method.");

  // The conversion issuance step 3 and the linkage check share.
  var converted = did.assertionJwks(document);
  assert.strictEqual(converted.jwks.keys.length, 1,
    "only the key with a JOSE representation can verify a JWS.");
  assert.strictEqual(converted.jwks.keys[0].kid, "sig-1",
    "a key that carries its own kid must KEEP it: that is the value a JWS header will name, and " +
    "overwriting it with the verification method's id would leave a kid lookup nothing to match.");
  assert.deepStrictEqual(converted.unusable, [webDid + "#bbs-1 (Multikey)"],
    "the keys that were passed over must be named, so \"no usable key\" can say why.");

  // A key with no kid of its own takes the method's id, which is what a DID-URL
  // kid names.
  var noKid = { id: webDid, verificationMethod: [
    { id: webDid + "#0", type: "JsonWebKey2020", publicKeyJwk: rsaJwk }] };
  assert.strictEqual(did.assertionJwks(noKid).jwks.keys[0].kid, webDid + "#0",
    "a key with no kid must be named by its verification method id.");

  // No assertionMethod at all: fall back to every method. A document that lists
  // keys but no relationships is common in the wild, and refusing to verify
  // against it would report a working credential as unverifiable.
  var noRelationships = { id: webDid, verificationMethod: document.verificationMethod };
  assert.strictEqual(did.assertionKeys(noRelationships).length, 2,
    "with no assertionMethod, every verification method is a candidate.");

  // An embedded method inside assertionMethod, rather than a reference.
  var embedded = { id: webDid, verificationMethod: [], assertionMethod: [
    { id: webDid + "#inline", type: "JsonWebKey2020", publicKeyJwk: rsaJwk }] };
  assert.strictEqual(did.assertionJwks(embedded).jwks.keys.length, 1,
    "an assertionMethod may embed a method instead of referencing one.");

  assert.strictEqual(did.keyForKid(document, "sig-1").id, webDid + "#sig-1",
    "a bare fragment must find the method whose id ends with it.");
  assert.strictEqual(did.keyForKid(document, webDid + "#bbs-1").id, webDid + "#bbs-1",
    "a full DID URL must find its method exactly.");
  assert.strictEqual(did.keyForKid(document, "").id, webDid + "#sig-1",
    "with no kid, the first assertion key is the unambiguous choice.");
  log.info("[document] OK — references, embedded methods, Multikey, kid preservation, fallbacks.");
}

// --- a proof's verificationMethod, both forms -------------------------------
//
// This is what an ldp_vc presentation needs before it can do anything: the
// issuer's BBS key, named by the credential's own proof. The two forms are not
// interchangeable and the wallet used to handle only one — it called fetch() on
// whatever the proof said, which works for the https URL this project's ldp_vc
// credentials used to carry and cannot work for a DID URL. The symptom was the
// issuer's key reported as unreachable, i.e. a broken issuer rather than a wallet
// that cannot follow a DID.
async function verificationMethodsResolveBothWays() {
  log.info("=== resolveVerificationMethod() ===");
  var subject = "did:web:issuer.example%3A8081";
  var multibase = "uSGVsbG8gQkJT";
  var document = {
    id: subject,
    verificationMethod: [
      { id: subject + "#sig-1", type: "JsonWebKey2020", publicKeyJwk: { kty: "RSA", n: "x", e: "AQAB" } },
      { id: subject + "#bbs-1", type: "Multikey", publicKeyMultibase: multibase }
    ],
    assertionMethod: [subject + "#sig-1", subject + "#bbs-1"]
  };
  var routes = {};
  routes[did.didWebToUrlInsecure(subject)] = { body: document };
  routes["http://issuer.example:8081/bbs/keys/1"] = { body: { publicKeyMultibase: multibase } };
  var fetchImpl = fakeFetch(routes);

  // The DID URL form: resolve the DID, then pick out the method the FRAGMENT
  // names — not the first key in the document, which for this issuer is the RSA
  // signing key and would silently produce a wrong BBS key.
  var byDid = await did.resolveVerificationMethod(subject + "#bbs-1",
    { fetch: fetchImpl, allowHttp: true });
  assert.strictEqual(byDid.method.publicKeyMultibase, multibase,
    "the DID URL must resolve to the method its fragment names.");
  assert.strictEqual(byDid.method.id, subject + "#bbs-1",
    "and it must be the BBS method, not the first one in the document.");

  // The https form, which is what an issuer not named by DID publishes.
  var byUrl = await did.resolveVerificationMethod("http://issuer.example:8081/bbs/keys/1",
    { fetch: fetchImpl });
  assert.strictEqual(byUrl.method.publicKeyMultibase, multibase,
    "a plain https verificationMethod must still be fetched, as it always was.");

  // A fragment the document does not publish must FAIL, naming what it does
  // publish. There is no falling back to another key: the proof named one.
  await assert.rejects(
    did.resolveVerificationMethod(subject + "#bbs-9", { fetch: fetchImpl, allowHttp: true }),
    function (e) {
      assert.ok(/no verification method/.test(e.message),
        "the refusal should say the method is absent: " + e.message);
      assert.ok(e.message.indexOf(subject + "#bbs-1") !== -1,
        "and should list what the document does publish: " + e.message);
      return true;
    },
    "an unknown fragment must be refused rather than resolved to a different key.");
  await assert.rejects(did.resolveVerificationMethod("", { fetch: fetchImpl }),
    /names no verificationMethod/, "an empty verificationMethod must say so.");
  log.info("[verificationMethod] OK — DID URL by fragment, https by fetch, no silent fallback.");
}

// --- Well Known DID Configuration -------------------------------------------
//
// One builder for every case, so a negative differs from the positive in exactly
// the one way it is named after. `mutate` is handed the header, the payload and
// the credential before signing.
function linkageJwt(options) {
  var subject = options.did;
  var now = Math.floor(Date.now() / 1000);
  var vc = {
    "@context": ["https://www.w3.org/2018/credentials/v1",
                 "https://identity.foundation/.well-known/did-configuration/v1"],
    issuer: subject,
    issuanceDate: new Date((now - 60) * 1000).toISOString(),
    expirationDate: new Date((now + 3600) * 1000).toISOString(),
    type: ["VerifiableCredential", "DomainLinkageCredential"],
    credentialSubject: { id: subject, origin: options.origin }
  };
  var header = { alg: "RS256", kid: subject + "#sig-1" };
  var payload = { iss: subject, sub: subject, nbf: now - 60, exp: now + 3600, vc: vc };
  if (options.mutate) options.mutate(header, payload, vc);
  var signing = b64u(JSON.stringify(header)) + "." + b64u(JSON.stringify(payload));
  var key = options.signWith || options.key;
  return signing + "." + b64u(crypto.sign("sha256", Buffer.from(signing), key));
}

function linkageFixture() {
  var rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var origin = "http://issuer.example:8081";
  var subject = "did:web:issuer.example%3A8081";
  var document = {
    "@context": ["https://www.w3.org/ns/did/v1"],
    id: subject,
    verificationMethod: [{ id: subject + "#sig-1", type: "JsonWebKey2020", controller: subject,
                           publicKeyJwk: rsa.publicKey.export({ format: "jwk" }) }],
    assertionMethod: [subject + "#sig-1"]
  };
  var routes = {};
  routes[did.didWebToUrlInsecure(subject)] = { body: document };
  return { key: rsa.privateKey, origin: origin, did: subject, document: document, routes: routes,
           fetch: fakeFetch(routes) };
}

function checkNamed(verdict, name) {
  var found = verdict.checks.filter(function (c) { return c.name === name; });
  assert.strictEqual(found.length, 1,
    'expected exactly one check named "' + name + '"; got ' +
    verdict.checks.map(function (c) { return c.name; }).join(", "));
  return found[0];
}

// Assert that the ONE named check failed and every other check passed. This is
// what makes each negative meaningful: a verifier that failed everything, or that
// failed for a different reason than the mutation introduced, does not pass.
function assertOnlyFailure(verdict, name, label) {
  assert.strictEqual(verdict.valid, false, label + ": the verdict should be invalid.");
  assert.strictEqual(checkNamed(verdict, name).ok, false,
    label + ': the "' + name + '" check should have failed. Details: ' +
    JSON.stringify(verdict.checks));
  verdict.checks.forEach(function (c) {
    if (c.name === name) return;
    assert.strictEqual(c.ok, true,
      label + ': only "' + name + '" should have failed, but "' + c.name + '" did too: ' + c.detail);
  });
}

async function domainLinkageVerifies() {
  log.info("=== Well Known DID Configuration: the positive ===");
  var f = linkageFixture();
  var verdict = await did.verifyDomainLinkage(
    linkageJwt(f), f.origin, { fetch: f.fetch, allowHttp: true });
  assert.strictEqual(verdict.valid, true,
    "a correctly formed Domain Linkage Credential should verify. Checks: " +
    JSON.stringify(verdict.checks, null, 1));
  assert.strictEqual(verdict.did, f.did, "the verdict must name the DID that was linked.");
  assert.strictEqual(verdict.origin, f.origin, "and the origin it was linked to.");
  assert.ok(checkNamed(verdict, "Issuer signature").ok,
    "the signature must be verified against the DID's own assertionMethod key.");
  log.info("[linkage] OK — the positive verifies, all " + verdict.checks.length + " checks pass.");
}

async function domainLinkageNegatives() {
  log.info("=== Well Known DID Configuration: the negatives ===");
  var f = linkageFixture();
  var opts = { fetch: f.fetch, allowHttp: true };

  // The two a JWT library does for you, which is why they are first.
  assertOnlyFailure(await did.verifyDomainLinkage(linkageJwt({
    did: f.did, origin: f.origin, key: f.key,
    mutate: function (header) { header.typ = "JWT"; }
  }), f.origin, opts), "JWT header",
    'typ: "JWT" in the header — forbidden here, and added by default by most libraries');

  assertOnlyFailure(await did.verifyDomainLinkage(linkageJwt({
    did: f.did, origin: f.origin, key: f.key,
    mutate: function (header, payload) { payload.iat = Math.floor(Date.now() / 1000); }
  }), f.origin, opts), "JWT claims",
    "an iat claim — no member beyond iss/sub/nbf/exp/vc is permitted");

  // The linkage itself: this is the check the document exists to make.
  assertOnlyFailure(await did.verifyDomainLinkage(
    linkageJwt(f), "http://somewhere.else:8081", opts), "Origin",
    "a credential read from an origin it does not name");

  assertOnlyFailure(await did.verifyDomainLinkage(linkageJwt({
    did: f.did, origin: f.origin, key: f.key,
    mutate: function (header, payload) { payload.sub = "did:web:somebody.else"; }
  }), f.origin, opts), "Self-issued to one DID",
    "sub naming a different DID than iss");

  assertOnlyFailure(await did.verifyDomainLinkage(linkageJwt({
    did: f.did, origin: f.origin, key: f.key,
    mutate: function (header, payload, vc) { vc.id = "urn:uuid:not-allowed"; }
  }), f.origin, opts), "No credential id",
    "an id at the credential root, which the specification forbids");

  assertOnlyFailure(await did.verifyDomainLinkage(linkageJwt({
    did: f.did, origin: f.origin, key: f.key,
    mutate: function (header, payload, vc) { vc["@context"] = ["https://www.w3.org/2018/credentials/v1"]; }
  }), f.origin, opts), "Credential @context",
    "the did-configuration context missing");

  assertOnlyFailure(await did.verifyDomainLinkage(linkageJwt({
    did: f.did, origin: f.origin, key: f.key,
    mutate: function (header, payload, vc) { vc.type = ["VerifiableCredential"]; }
  }), f.origin, opts), "Credential type",
    "DomainLinkageCredential missing from type");

  assertOnlyFailure(await did.verifyDomainLinkage(linkageJwt({
    did: f.did, origin: f.origin, key: f.key,
    mutate: function (header, payload) { payload.exp = Math.floor(Date.now() / 1000) - 10; }
  }), f.origin, opts), "Validity window", "an expired credential");

  // And the one that cannot be faked: signed by a key the DID does not publish.
  var impostor = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
  assertOnlyFailure(await did.verifyDomainLinkage(linkageJwt({
    did: f.did, origin: f.origin, key: f.key, signWith: impostor
  }), f.origin, opts), "Issuer signature",
    "a signature by a key that is not in the DID's assertionMethod");
  log.info("[linkage] OK — nine negatives, each failing exactly the check it should.");

  // A document whose only assertion key cannot verify a JWS must say WHICH key it
  // passed over. The BBS key on the mock issuer's real document is exactly this.
  var multikeyOnly = linkageFixture();
  multikeyOnly.document.verificationMethod = [{
    id: multikeyOnly.did + "#bbs-1", type: "Multikey", controller: multikeyOnly.did,
    publicKeyMultibase: "uSGVsbG8gQkJT"
  }];
  multikeyOnly.document.assertionMethod = [multikeyOnly.did + "#bbs-1"];
  var routes = {};
  routes[did.didWebToUrlInsecure(multikeyOnly.did)] = { body: multikeyOnly.document };
  var verdict = await did.verifyDomainLinkage(linkageJwt(multikeyOnly), multikeyOnly.origin,
    { fetch: fakeFetch(routes), allowHttp: true });
  assert.strictEqual(verdict.valid, false, "no usable key means no verification.");
  assert.ok(/Multikey/.test(checkNamed(verdict, "Issuer signature").detail),
    "the unusable key must be named: " + checkNamed(verdict, "Issuer signature").detail);
  log.info("[linkage] OK — a document with only a Multikey names it rather than reporting nothing.");

  // The Linked Data Proof form is VALID per the specification and simply not
  // checkable here. Reporting it as invalid would be a lie about somebody else's
  // conforming document.
  var ldForm = await did.verifyDomainLinkage({ "@context": [], proof: { type: "JsonWebSignature2020" } },
    f.origin, opts);
  assert.strictEqual(ldForm.valid, false, "an unverified credential is not a verified one.");
  assert.ok(/valid per the specification/.test(checkNamed(ldForm, "Credential form").detail),
    "an LD-proof entry must be reported as unverifiable-here, not as malformed: " +
    checkNamed(ldForm, "Credential form").detail);
  log.info("[linkage] OK — the LD-proof form is reported as unverifiable here, not as invalid.");
}

async function originLinkageAsksAboutOneDid() {
  log.info("=== verifyOriginLinkage() ===");
  var f = linkageFixture();
  var configuration = {
    "@context": "https://identity.foundation/.well-known/did-configuration/v1",
    linked_dids: [linkageJwt(f)]
  };
  var routes = Object.assign({}, f.routes);
  routes[did.didConfigurationUrl(f.origin)] = { body: configuration };

  var verdict = await did.verifyOriginLinkage(f.origin, f.did,
    { fetch: fakeFetch(routes), allowHttp: true });
  assert.strictEqual(verdict.linked, true,
    "the origin links this DID and the credential verifies. Results: " + JSON.stringify(verdict.results));
  assert.strictEqual(verdict.matched.length, 1, "one entry should be for the DID asked about.");

  // The substance: an origin that links SOME DID has not vouched for the one the
  // wallet is asking about. Without this, a site linking its own DID would appear
  // to vouch for anybody's.
  var other = await did.verifyOriginLinkage(f.origin, "did:web:somebody.else",
    { fetch: fakeFetch(routes), allowHttp: true });
  assert.strictEqual(other.linked, false,
    "an origin that links a DIFFERENT DID must not read as linking this one.");
  assert.strictEqual(other.matched.length, 0, "and nothing should match the DID asked about.");
  log.info("[linkage] OK — linkage is answered for the DID asked about, not for any DID.");

  var wrongContext = Object.assign({}, routes);
  wrongContext[did.didConfigurationUrl(f.origin)] = { body: { "@context": "https://example.com/v1", linked_dids: [] } };
  await assert.rejects(
    did.verifyOriginLinkage(f.origin, f.did, { fetch: fakeFetch(wrongContext), allowHttp: true }),
    /@context/, "the resource's @context is fixed by the specification and must be checked.");

  var empty = Object.assign({}, routes);
  empty[did.didConfigurationUrl(f.origin)] = { body: { "@context": did.DID_CONFIGURATION_CONTEXT } };
  await assert.rejects(
    did.verifyOriginLinkage(f.origin, f.did, { fetch: fakeFetch(empty), allowHttp: true }),
    /no linked_dids/, "a resource with no linked_dids must say so.");

  assert.strictEqual(did.didConfigurationUrl("http://host:1/"),
    "http://host:1/.well-known/did-configuration.json",
    "the resource sits at a fixed path at the origin root, trailing slash or not.");
  log.info("[linkage] OK — the resource's own rules are checked.");
}

async function test() {
  base58RoundTrips();
  multicodecIsAVarint();
  didKeyPrefixes();
  curveConstantsArePublishedValues();
  didKeyRoundTripsAgainstNode();
  didJwkRoundTrips();
  didWebUrlRules();
  await resolutionIsLocalWherePossible();
  documentReading();
  await verificationMethodsResolveBothWays();
  await domainLinkageVerifies();
  await domainLinkageNegatives();
  await originLinkageAsksAboutOneDid();
  log.info("Test completed successfully.");
}

const program = new Command();
program
  .name("did_document")
  .description("Verify client/src/did.js: DID methods, document reading, and DIF domain linkage.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>", "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
