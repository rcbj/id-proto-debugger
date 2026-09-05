// File: sd_jwt_vc_engine.js
//
// ---------------------------------------------------------------------------
// THE SD-JWT VC WALLET'S MEMORY, DRIVEN IN NODE WITH NO SERVER AND NO BROWSER.
//
// `client/src/sd_jwt_vc.js` is what the issuance and presentation pages
// REMEMBER: the storage keys, the key-saving opt-out and the gate that
// enforces it, which private key a credential is actually bound to, whether a
// proof can be made right now, whether a credential can be presented at all,
// and the Credential History. 1,970 lines, seven DOM references, and the
// interesting half of it is arithmetic over storage.
//
// **WHY THIS FILE EXISTS, AND THE ANSWER IS A MEASUREMENT.** It was the
// largest block of untested code in this tree that a node test can reach —
// 538 uncovered lines at 72.7% on the merged report (tests/coverage_merge.js)
// — and the four SD-JWT VC page jobs that drive it are Selenium jobs against a
// live issuer, so every one of the decisions below was exercised only in the
// one combination that a passing end-to-end run happens to take.
//
// **WHAT A DEFECT HERE LOOKS LIKE.** Every failure this module can have is a
// user stranded or a key quietly kept, and neither raises:
//
//   * ABSENT BY CHOICE vs ABSENT AND LOST. With key saving off there is
//     nothing in storage and a field on the next page to paste into, so the
//     workflow must NOT block; with saving on and the key gone it was never
//     generated here, there is nothing to paste, and it must. Get that
//     backwards and the user is stranded two pages before the only field that
//     would fix it — or walked forward into a step that cannot complete.
//   * THE OPT-OUT THAT DOES NOT OPT OUT. `set()` refuses the four private-key
//     names when saving is off AND removes what an earlier session wrote. A
//     gate that only refuses new writes leaves yesterday's private key in
//     storage, which is not an opt-out and looks exactly like one.
//   * THE WRONG KEY, CONFIDENTLY. A credential names the key it is bound to in
//     `cnf.jwk`; signing a Key Binding JWT with any other produces a
//     presentation a Verifier refuses with a complaint about the signature.
//     Under Holder of Key the bound key is the DPoP key rather than the holder
//     key, and the two are both in storage.
//
// It needs no server, no browser and no network, so it never skips. What it
// DOES need is `window.localStorage` and a `document`, which are stubbed here
// — that stub is the whole reason this file can exist, and it is written to be
// the browser's semantics rather than a convenience: values are strings, a
// missing key is null, and `setItem` can be made to throw.
//
// EIGHT SECTIONS:
//
//   1. the store — strings, absence, and unreadable JSON
//   2. the key-saving gate — the refusal, the purge, and failing toward the
//      workflow
//   3. public-key comparison, which is what "bound to" is decided by
//   4. reading a holder key — from storage, from a paste, from a downloaded
//      pair, and the two ways it can be wrong
//   5. which key a credential is BOUND to, including Holder of Key
//   6. whether a proof can be made right now
//   7. whether a credential can be PRESENTED — the distinction above
//   8. the Credential History and the flow hand-off
// ---------------------------------------------------------------------------

const assert = require("assert");
const path = require("path");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sd_jwt_vc_engine",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

// ---------------------------------------------------------------------------
// THE BROWSER, AS MUCH OF IT AS THIS MODULE TOUCHES.
//
// `ls()` reads `window.localStorage` inside a try/catch — the module's own
// answer to private mode — and `readHolderPrivateJwk()` reads one input by id.
// Nothing else here is a DOM.
//
// The stub keeps the browser's semantics rather than a convenience: every
// value is a STRING (a store that returned the object you put in would make
// `getJson()` untestable, since it would never parse anything), a missing key
// is `null` rather than `undefined`, and `setItem` can be made to throw so the
// over-quota path is reachable.
// ---------------------------------------------------------------------------
function makeStore() {
  log.debug("Entering makeStore().");
  const held = {};
  const store = {
    failWrites: false,
    getItem: function (key) {
      return Object.prototype.hasOwnProperty.call(held, key) ? held[key] : null;
    },
    setItem: function (key, value) {
      if (store.failWrites) {
        throw new Error("QuotaExceededError (stub)");
      }
      held[key] = String(value);
    },
    removeItem: function (key) {
      delete held[key];
    },
    keys: function () {
      return Object.keys(held);
    },
    reset: function () {
      Object.keys(held).forEach(function (k) {
        delete held[k];
      });
      store.failWrites = false;
    }
  };
  log.debug("Leaving makeStore().");
  return store;
}

const store = makeStore();
const fields = {};

global.window = { localStorage: store };
global.localStorage = store;
global.document = {
  getElementById: function (id) {
    return Object.prototype.hasOwnProperty.call(fields, id)
      ? { value: fields[id] } : null;
  },
  createElement: function () {
    return { classList: { add: function () {} }, appendChild: function () {},
             setAttribute: function () {}, style: {} };
  },
  querySelector: function () {
    return null;
  }
};

// The module under test. requireSharedModule() is what makes a module borrowed
// from client/src resolve its own dependencies — node resolves those relative
// to where the MODULE lives. In a checkout it is under client/src; the tests
// image copies it flat beside the test scripts, which is also why this file
// cannot be called sd_jwt_vc.js.
const vc = paths.requireSharedModule(
  [path.join(__dirname, "sd_jwt_vc.js"),
   path.join(__dirname, "..", "client", "src", "sd_jwt_vc.js")],
  "client/src/sd_jwt_vc.js");

let checks = 0;

function check(what, fn) {
  log.debug("Entering check(). " + what);
  store.reset();
  Object.keys(fields).forEach(function (id) {
    delete fields[id];
  });
  fn();
  checks++;
  log.info("  ok — " + what);
  log.debug("Leaving check().");
}

// ---------------------------------------------------------------------------
// FIXTURES.
//
// Two EC key pairs whose public halves differ, and an RSA one. The values are
// not real key material and do not need to be: nothing here signs, and every
// decision in this module is made by COMPARING JWK members. Using real keys
// would make the fixtures long and would test node's crypto rather than this
// module's arithmetic.
// ---------------------------------------------------------------------------
const HOLDER_KEY = { kty: "EC", crv: "P-256", x: "holder-x", y: "holder-y",
                     d: "holder-d" };
const HOLDER_PUB = { kty: "EC", crv: "P-256", x: "holder-x", y: "holder-y" };
const DPOP_KEY = { kty: "EC", crv: "P-256", x: "dpop-x", y: "dpop-y",
                   d: "dpop-d" };
const DPOP_PUB = { kty: "EC", crv: "P-256", x: "dpop-x", y: "dpop-y" };
const OTHER_KEY = { kty: "EC", crv: "P-256", x: "other-x", y: "other-y",
                    d: "other-d" };

function b64u(obj) {
  log.debug("Entering b64u().");
  const out = Buffer.from(JSON.stringify(obj), "utf8").toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  log.debug("Leaving b64u().");
  return out;
}

// An SD-JWT VC: a JWS with `~`-separated Disclosures after it. Nothing here
// verifies the signature, so the third segment is a placeholder — what is
// being tested is what the wallet decides about a credential, not whether the
// issuer signed it.
function sdJwt(payload, disclosures) {
  log.debug("Entering sdJwt().");
  const jwt = b64u({ alg: "ES256", typ: "dc+sd-jwt" }) + "." + b64u(payload) +
      ".c2ln";
  const out = [jwt].concat(disclosures || []).join("~") + "~";
  log.debug("Leaving sdJwt().");
  return out;
}

function disclosure(name, value) {
  log.debug("Entering disclosure().");
  const out = Buffer.from(JSON.stringify(["saltsaltsalt", name, value]),
      "utf8").toString("base64").replace(/\+/g, "-").replace(/\//g, "_")
    .replace(/=+$/, "");
  log.debug("Leaving disclosure().");
  return out;
}

const BOUND_CREDENTIAL = sdJwt(
  { vct: "https://example.com/IdentityCredential", sub: "did:example:bob",
    iss: "https://issuer.example.com", cnf: { jwk: HOLDER_PUB },
    _sd: ["ZGlnZXN0MQ"] },
  [disclosure("given_name", "Bob")]);

const UNBOUND_CREDENTIAL = sdJwt(
  { vct: "https://example.com/IdentityCredential",
    iss: "https://issuer.example.com" },
  [disclosure("given_name", "Bob")]);

// ---------------------------------------------------------------------------
// 1. THE STORE.
// ---------------------------------------------------------------------------
function theStoreDegradesRatherThanThrowing() {
  log.debug("Entering theStoreDegradesRatherThanThrowing().");

  check('an absent key reads as null and not as the string "undefined"',
      function () {
    assert.strictEqual(vc.get("sdjwtvc_nothing_here"), null);
    assert.strictEqual(vc.getJson("sdjwtvc_nothing_here"), null);
  });

  check('a value written by an older build, or hand-edited, is ABSENT ' +
      'rather than an exception', function () {
    // This is the whole reason getJson() exists rather than a JSON.parse at
    // thirty call sites: a wallet that threw on one unreadable key would take
    // the page down over a value it does not need.
    store.setItem("sdjwtvc_credential_meta", "{not json");
    assert.strictEqual(vc.getJson("sdjwtvc_credential_meta"), null);
  });

  check('a write that cannot be made loses the value and not the page',
      function () {
    // Over quota, or storage disabled. There is nothing to fall back to, so
    // the requirement is only that it does not throw.
    store.failWrites = true;
    vc.set("sdjwtvc_use_case", "batch");
    store.failWrites = false;
    assert.strictEqual(vc.get("sdjwtvc_use_case"), null);
  });

  check('setJson round-trips through a string, as a browser store does',
      function () {
    vc.setJson("sdjwtvc_credential_meta", { issuer: "https://i", count: 2 });
    assert.strictEqual(typeof store.getItem("sdjwtvc_credential_meta"),
        "string", "A store that kept the object would make every getJson() " +
        "test here vacuous.");
    assert.deepStrictEqual(vc.getJson("sdjwtvc_credential_meta"),
        { issuer: "https://i", count: 2 });
  });

  log.debug("Leaving theStoreDegradesRatherThanThrowing().");
}

// ---------------------------------------------------------------------------
// 2. THE KEY-SAVING GATE.
//
// The repo-root CLAUDE.md states the contract: enforcement is CENTRAL, in
// `set()`, because writers live in three bundles and a guard per call site is
// a guard somebody forgets.
// ---------------------------------------------------------------------------
function theKeySavingOptOutIsEnforcedCentrally() {
  log.debug("Entering theKeySavingOptOutIsEnforcedCentrally().");

  check('saving is ON by default, and only an explicit "0" turns it off',
      function () {
    // An unreadable preference fails TOWARD the workflow: a wallet that
    // treated a missing value as "off" would silently stop keeping the key
    // every existing user expects to still be there.
    assert.strictEqual(vc.holderPrivateKeyMayBeStored(), true);
    store.setItem("sdjwtvc_save_holder_key", "");
    assert.strictEqual(vc.holderPrivateKeyMayBeStored(), true);
    store.setItem("sdjwtvc_save_holder_key", "nonsense");
    assert.strictEqual(vc.holderPrivateKeyMayBeStored(), true);
    store.setItem("sdjwtvc_save_holder_key", "0");
    assert.strictEqual(vc.holderPrivateKeyMayBeStored(), false);
  });

  check('with saving off, every private-key name is REFUSED', function () {
    vc.setHolderKeySaving(false);
    vc.HOLDER_PRIVATE_KEYS.forEach(function (key) {
      vc.set(key, JSON.stringify(HOLDER_KEY));
      assert.strictEqual(store.getItem(key), null,
          key + " was written with holder key saving turned off. The gate is " +
          "in set() precisely so that no call site can miss it.");
    });
  });

  check('the DPoP private key is on that list, and the consequence is the ' +
      'point', function () {
    // Under Holder of Key the DPoP key IS the holder key, so it belongs there
    // for the same reason. The consequence — an access token bound to a key
    // that does not survive a page load — is a sender-constrained token
    // behaving exactly as it should.
    assert.ok(vc.HOLDER_PRIVATE_KEYS.indexOf("sdjwtvc_dpop_private_jwk") >= 0,
        "The DPoP private key is not on HOLDER_PRIVATE_KEYS, so the opt-out " +
        "does not cover it — and under Holder of Key that IS the holder key.");
  });

  check('turning the opt-out ON purges what an earlier session wrote',
      function () {
    // An opt-out that only refuses new writes leaves yesterday's private key
    // in storage, which is not an opt-out and looks exactly like one.
    vc.HOLDER_PRIVATE_KEYS.forEach(function (key) {
      store.setItem(key, JSON.stringify(HOLDER_KEY));
    });
    vc.setHolderKeySaving(false);
    vc.HOLDER_PRIVATE_KEYS.forEach(function (key) {
      assert.strictEqual(store.getItem(key), null,
          key + " survived the opt-out being turned on.");
    });
  });

  check('and it strips the key out of EVERY Credential History row, ' +
      'counting them', function () {
    // The deliberate part, and the count is what the pane tells the user. A
    // generation whose key has been stripped cannot be presented — which is
    // the point here rather than a bug, and is why the number is reported
    // instead of the purge happening silently.
    vc.setJson("sdjwtvc_credential_history", [
      { id: "gen-1", holderPrivateJwk: HOLDER_KEY },
      { id: "gen-2", holderPrivateJwk: null },
      { id: "gen-3", holderPrivateJwk: DPOP_KEY }
    ]);
    const stripped = vc.setHolderKeySaving(false);
    assert.strictEqual(stripped, 2,
        "setHolderKeySaving(false) reported " + stripped + " stripped rows " +
        "and two of the three carried a key. The count is what the pane " +
        "tells the user, and a wrong one understates what was just given up.");
    const after = vc.getJson("sdjwtvc_credential_history");
    after.forEach(function (row) {
      assert.strictEqual(row.holderPrivateJwk, null,
          "Generation " + row.id + " kept its private key through the " +
          "opt-out. The rows are exactly where a key survives a purge that " +
          "only looked at the four top-level names.");
    });
    assert.strictEqual(after.length, 3,
        "The rows themselves must survive — it is the KEY that is dropped, " +
        "not the record that the generation happened.");
  });

  check('with no history there is nothing to strip and it says zero',
      function () {
    vc.setJson("sdjwtvc_holder_private_jwk", HOLDER_KEY);
    assert.strictEqual(vc.setHolderKeySaving(false), 0);
  });

  check('a REFUSED write also removes what was already there', function () {
    // The purge inside set() itself, which is a different path from
    // setHolderKeySaving()'s sweep and is the one that runs on an ORDINARY
    // page load: a page that stores a key it just generated, with saving off,
    // must not leave an older value of that same key sitting in storage. The
    // comment in set() calls remove() directly rather than going through
    // forgetStoredHolderPrivateKeys() to avoid recursing, so this is the only
    // check that covers it.
    store.setItem("sdjwtvc_holder_private_jwk", JSON.stringify(OTHER_KEY));
    store.setItem("sdjwtvc_save_holder_key", "0");
    vc.set("sdjwtvc_holder_private_jwk", JSON.stringify(HOLDER_KEY));
    assert.strictEqual(store.getItem("sdjwtvc_holder_private_jwk"), null,
        "The write was refused and yesterday's key was left behind. An " +
        "opt-out that only declines NEW writes is not an opt-out, and it " +
        "looks exactly like one.");
  });

  check('a PUBLIC half is not a private key and is kept', function () {
    // The opt-out is about private material. Purging the public half too
    // would lose the wallet's own record of which key a credential is bound
    // to, for no privacy gain at all.
    vc.setHolderKeySaving(false);
    vc.set("sdjwtvc_holder_jwk", JSON.stringify(HOLDER_PUB));
    assert.notStrictEqual(store.getItem("sdjwtvc_holder_jwk"), null);
  });

  check('turning saving back ON does not un-purge, and stores again',
      function () {
    vc.setHolderKeySaving(false);
    vc.set("sdjwtvc_holder_private_jwk", JSON.stringify(HOLDER_KEY));
    assert.strictEqual(store.getItem("sdjwtvc_holder_private_jwk"), null);
    vc.setHolderKeySaving(true);
    assert.strictEqual(store.getItem("sdjwtvc_holder_private_jwk"), null,
        "Turning it back on must not resurrect a key that was never kept.");
    vc.set("sdjwtvc_holder_private_jwk", JSON.stringify(HOLDER_KEY));
    assert.deepStrictEqual(vc.getJson("sdjwtvc_holder_private_jwk"),
        HOLDER_KEY);
  });

  log.debug("Leaving theKeySavingOptOutIsEnforcedCentrally().");
}

// ---------------------------------------------------------------------------
// 3. PUBLIC-KEY COMPARISON.
// ---------------------------------------------------------------------------
function twoKeysAreComparedByTheirPublicHalf() {
  log.debug("Entering twoKeysAreComparedByTheirPublicHalf().");

  check('the public half of a private JWK needs no cryptography', function () {
    // A private EC JWK carries x and y beside d, and a private RSA JWK carries
    // n and e — which is why this works with no Web Crypto and can be used
    // from a synchronous render.
    assert.deepStrictEqual(vc.publicHalfOf(HOLDER_KEY), HOLDER_PUB);
    assert.deepStrictEqual(
        vc.publicHalfOf({ kty: "RSA", n: "nn", e: "AQAB", d: "dd", p: "pp" }),
        { kty: "RSA", n: "nn", e: "AQAB" });
    assert.deepStrictEqual(
        vc.publicHalfOf({ kty: "OKP", crv: "Ed25519", x: "xx", d: "dd" }),
        { kty: "OKP", crv: "Ed25519", x: "xx" });
    assert.ok(!vc.publicHalfOf({ kty: "oct", k: "secret" }),
        "A symmetric key has no public half, and returning the key itself " +
        "would compare a secret against a credential's cnf.");
    assert.strictEqual(vc.publicHalfOf(null), null);
  });

  check('two keys match on their public members and nothing else',
      function () {
    assert.ok(vc.samePublicKey(HOLDER_PUB, vc.publicHalfOf(HOLDER_KEY)));
    assert.ok(!vc.samePublicKey(HOLDER_PUB, DPOP_PUB));
    assert.ok(!vc.samePublicKey(HOLDER_PUB,
        { kty: "EC", crv: "P-384", x: "holder-x", y: "holder-y" }),
        "A different curve is a different key, and the coordinates alone " +
        "would say otherwise.");
    assert.ok(!vc.samePublicKey(HOLDER_PUB,
        { kty: "RSA", n: "holder-x", e: "holder-y" }),
        "Different key types are never the same key.");
    assert.ok(!vc.samePublicKey(null, HOLDER_PUB));
    assert.ok(!vc.samePublicKey({ kty: "oct", k: "a" }, { kty: "oct", k: "a" }),
        "An unrecognised kty answers NO rather than yes: this decides which " +
        "key a Key Binding JWT is signed with, so a hopeful match is worse " +
        "than none.");
  });

  log.debug("Leaving twoKeysAreComparedByTheirPublicHalf().");
}

// ---------------------------------------------------------------------------
// 4. READING A HOLDER KEY.
// ---------------------------------------------------------------------------
function aHolderKeyIsReadFromStorageOrFromAPaste() {
  log.debug("Entering aHolderKeyIsReadFromStorageOrFromAPaste().");

  check('storage wins, and says so', function () {
    vc.setJson("sdjwtvc_holder_private_jwk", HOLDER_KEY);
    const got = vc.readHolderPrivateJwk("vc_holder_private_jwk");
    assert.deepStrictEqual(got.jwk, HOLDER_KEY);
    assert.strictEqual(got.source, "storage");
    assert.strictEqual(got.problem, null);
  });

  check('nothing anywhere is "none" and NOT a problem', function () {
    // The three outcomes are returned rather than collapsed because they need
    // different things said: absent is a prompt, unparseable is a correction.
    const got = vc.readHolderPrivateJwk("vc_holder_private_jwk");
    assert.strictEqual(got.jwk, null);
    assert.strictEqual(got.source, "none");
    assert.strictEqual(got.problem, null,
        "An empty field is not an error — with saving off it is the ordinary " +
        "state on arrival, and reporting it as a problem would make every " +
        "such page open on a complaint.");
  });

  check('a pasted bare private JWK is accepted', function () {
    vc.setHolderKeySaving(false);
    fields.vc_holder_private_jwk = "  " + JSON.stringify(HOLDER_KEY) + "  ";
    const got = vc.readHolderPrivateJwk("vc_holder_private_jwk");
    assert.deepStrictEqual(got.jwk, HOLDER_KEY);
    assert.strictEqual(got.source, "pasted");
  });

  check('the DOWNLOADED FILE is accepted as it stands', function () {
    // The file the Download button produces is { publicJwk, privateJwk }, and
    // pasting back what you were given is the obvious thing to try. A reader
    // that took only a bare JWK would refuse the wallet's own file.
    vc.setHolderKeySaving(false);
    fields.vc_holder_private_jwk = JSON.stringify(
        { publicJwk: HOLDER_PUB, privateJwk: HOLDER_KEY });
    const got = vc.readHolderPrivateJwk("vc_holder_private_jwk");
    assert.deepStrictEqual(got.jwk, HOLDER_KEY);
  });

  check('the two ways a paste can be wrong are told apart', function () {
    vc.setHolderKeySaving(false);
    fields.vc_holder_private_jwk = "not json at all";
    const bad = vc.readHolderPrivateJwk("vc_holder_private_jwk");
    assert.strictEqual(bad.jwk, null);
    assert.ok(/is not JSON/.test(bad.problem));

    fields.vc_holder_private_jwk = JSON.stringify(HOLDER_PUB);
    const pub = vc.readHolderPrivateJwk("vc_holder_private_jwk");
    assert.strictEqual(pub.jwk, null);
    assert.ok(/needs at least kty and d/.test(pub.problem),
        "A PUBLIC key pasted where a private one was asked for is the " +
        "commonest mistake here, and 'not JSON' would be the wrong thing to " +
        "say about it.");
  });

  check('a field that is not on the page is not a paste', function () {
    const got = vc.readHolderPrivateJwk("no_such_field");
    assert.strictEqual(got.source, "none");
  });

  log.debug("Leaving aHolderKeyIsReadFromStorageOrFromAPaste().");
}

// ---------------------------------------------------------------------------
// 5. WHICH KEY A CREDENTIAL IS BOUND TO.
// ---------------------------------------------------------------------------
function theBoundKeyIsChosenByTheCredentialsOwnCnf() {
  log.debug("Entering theBoundKeyIsChosenByTheCredentialsOwnCnf().");

  check('with no cnf to match, the holder key is used as it always was',
      function () {
    // Guessing the DPoP key here would change behaviour for every credential
    // that has no key binding — which is legal: OID4VCI section 8 makes the
    // proof optional when the issuer does not require binding.
    vc.setJson("sdjwtvc_holder_private_jwk", HOLDER_KEY);
    vc.setJson("sdjwtvc_dpop_private_jwk", DPOP_KEY);
    const got = vc.boundPrivateJwk(null, "vc_holder_private_jwk");
    assert.deepStrictEqual(got.jwk, HOLDER_KEY);
    assert.ok(/holder key/.test(got.boundTo));
  });

  check('a cnf naming the holder key selects the holder key', function () {
    vc.setJson("sdjwtvc_holder_private_jwk", HOLDER_KEY);
    vc.setJson("sdjwtvc_dpop_private_jwk", DPOP_KEY);
    const got = vc.boundPrivateJwk(HOLDER_PUB, "vc_holder_private_jwk");
    assert.deepStrictEqual(got.jwk, HOLDER_KEY);
    assert.strictEqual(got.problem, null);
  });

  check('a cnf naming the DPoP key selects THAT — Holder of Key', function () {
    // The case this function exists for. Both keys are in storage and the
    // wallet must pick the one the credential names, or the Key Binding JWT is
    // signed with the wrong key and the Verifier complains about a signature.
    vc.setJson("sdjwtvc_holder_private_jwk", HOLDER_KEY);
    vc.setJson("sdjwtvc_dpop_private_jwk", DPOP_KEY);
    const got = vc.boundPrivateJwk(DPOP_PUB, "vc_holder_private_jwk");
    assert.deepStrictEqual(got.jwk, DPOP_KEY);
    assert.ok(/DPoP key/.test(got.boundTo),
        "The pane says WHICH key it chose, and 'a key' is not an answer when " +
        "there were two.");
  });

  check('a pasted key is checked against the cnf too', function () {
    vc.setHolderKeySaving(false);
    fields.vc_holder_private_jwk = JSON.stringify(HOLDER_KEY);
    const got = vc.boundPrivateJwk(HOLDER_PUB, "vc_holder_private_jwk");
    assert.deepStrictEqual(got.jwk, HOLDER_KEY);
    assert.strictEqual(got.source, "pasted");
  });

  check('a pasted key that is NOT the bound one is refused BY NAME',
      function () {
    // Accepting it produces exactly the same unhelpful verifier complaint as
    // signing with the wrong key, one step later and with nothing to point at.
    vc.setHolderKeySaving(false);
    fields.vc_holder_private_jwk = JSON.stringify(OTHER_KEY);
    const got = vc.boundPrivateJwk(HOLDER_PUB, "vc_holder_private_jwk");
    assert.strictEqual(got.jwk, null);
    assert.ok(/not the key this credential is bound to/.test(got.problem));
  });

  // -------------------------------------------------------------------------
  // THE FOUR OUTCOMES WHEN NOTHING IN STORAGE MATCHES THE cnf, and they were
  // one outcome until 2026-09-01.
  //
  // `boundPrivateJwk()` used to finish by calling `readHolderPrivateJwk()`,
  // which PREFERS storage — so after the loop above had already tested every
  // stored key against the cnf and rejected it, that call handed the same
  // stored key straight back. Two consequences, and the first is the serious
  // one:
  //
  //   * a user who pasted the RIGHT key had it ignored, because the field was
  //     never read, and was told "the pasted key is not the key this
  //     credential is bound to" — about a key they had not pasted, and which
  //     was in fact the correct one;
  //   * and the "this browser holds N key(s)" branch was unreachable whenever
  //     a holder key was stored, which is the ordinary case.
  //
  // It reads the FIELD now (`pastedHolderPrivateJwk()`), and these four
  // checks are one per branch so that a regression names which.
  // -------------------------------------------------------------------------
  check('a pasted key is accepted even when a DIFFERENT key is in storage',
      function () {
    // The case that was broken. A credential issued to one key, a browser
    // holding another, and the holder pasting the right one is exactly the
    // situation the paste field exists for.
    vc.setJson("sdjwtvc_holder_private_jwk", OTHER_KEY);
    fields.vc_holder_private_jwk = JSON.stringify(HOLDER_KEY);
    const got = vc.boundPrivateJwk(HOLDER_PUB, "vc_holder_private_jwk");
    assert.deepStrictEqual(got.jwk, HOLDER_KEY,
        "The pasted key was ignored in favour of a stored key that does not " +
        "match the cnf. The field is the only way out of this state, so " +
        "not reading it strands the holder with a credential they cannot " +
        "present.");
    assert.strictEqual(got.source, "pasted");
    assert.strictEqual(got.boundTo, "the pasted key");
  });

  check('a pasted key that is NOT the bound one says so, about the PASTE',
      function () {
    vc.setJson("sdjwtvc_holder_private_jwk", OTHER_KEY);
    fields.vc_holder_private_jwk = JSON.stringify(DPOP_KEY);
    const got = vc.boundPrivateJwk(HOLDER_PUB, "vc_holder_private_jwk");
    assert.strictEqual(got.jwk, null);
    assert.strictEqual(got.source, "pasted");
    assert.ok(/the pasted key is not the key/.test(got.problem));
  });

  check('with NOTHING pasted, the message is about what STORAGE holds',
      function () {
    // The branch that was unreachable. Saying "the pasted key" over an empty
    // field sends somebody to check a control they never touched.
    vc.setJson("sdjwtvc_holder_private_jwk", OTHER_KEY);
    const got = vc.boundPrivateJwk(HOLDER_PUB, "vc_holder_private_jwk");
    assert.strictEqual(got.jwk, null);
    assert.strictEqual(got.source, "storage",
        "With an empty field this must be reported as a STORAGE problem. It " +
        "read 'pasted' until the paste and the storage reads were separated.");
    assert.ok(/holds 1 key\(s\)/.test(got.problem),
        "Got: " + JSON.stringify(got.problem));
    assert.ok(/Holder of Key/.test(got.problem),
        "The likeliest cause is a credential issued under Holder of Key " +
        "whose DPoP key was discarded when DPoP was switched off, and this " +
        "message is where somebody finds that out.");
  });

  check('an unreadable paste is reported as a PASTE problem, not as storage',
      function () {
    // "that JSON is not a private JWK" is something a reader can act on;
    // "this browser holds 1 key(s)" said over a typo in the field is not.
    vc.setJson("sdjwtvc_holder_private_jwk", OTHER_KEY);
    fields.vc_holder_private_jwk = "{ not json";
    const got = vc.boundPrivateJwk(HOLDER_PUB, "vc_holder_private_jwk");
    assert.strictEqual(got.jwk, null);
    assert.strictEqual(got.source, "pasted");
    assert.ok(/is not JSON/.test(got.problem),
        "The parse error was swallowed and replaced by the storage message. " +
        "Got: " + JSON.stringify(got.problem));
  });

  check('readHolderPrivateJwk still prefers STORAGE, which its other ' +
      'callers depend on', function () {
    // The split must not change this function: vc_issuance_4.js asks it for
    // "the holder key, from wherever", and a paste-first read there would
    // ignore the key the wallet actually holds.
    vc.setJson("sdjwtvc_holder_private_jwk", HOLDER_KEY);
    fields.vc_holder_private_jwk = JSON.stringify(OTHER_KEY);
    const got = vc.readHolderPrivateJwk("vc_holder_private_jwk");
    assert.deepStrictEqual(got.jwk, HOLDER_KEY);
    assert.strictEqual(got.source, "storage");
  });

  check('with the DPoP key stored and the holder key absent, a cnf naming ' +
      'the DPoP key still resolves', function () {
    // The Holder of Key case with only one key in the browser, which is what
    // is left after the holder key has been purged by the opt-out.
    vc.setJson("sdjwtvc_dpop_private_jwk", DPOP_KEY);
    const got = vc.boundPrivateJwk(DPOP_PUB, "vc_holder_private_jwk");
    assert.deepStrictEqual(got.jwk, DPOP_KEY);
  });

  check('no key at all keeps readHolderPrivateJwk\'s shape', function () {
    const got = vc.boundPrivateJwk(HOLDER_PUB, "vc_holder_private_jwk");
    assert.strictEqual(got.jwk, null);
    assert.strictEqual(got.source, "none");
    assert.strictEqual(got.boundTo, "");
  });

  log.debug("Leaving theBoundKeyIsChosenByTheCredentialsOwnCnf().");
}

// ---------------------------------------------------------------------------
// 6. WHETHER A PROOF CAN BE MADE RIGHT NOW.
// ---------------------------------------------------------------------------
function dpopReadinessTellsConfigurationFromBreakage() {
  log.debug("Entering dpopReadinessTellsConfigurationFromBreakage().");

  check('DPoP off is not a problem', function () {
    const r = vc.dpopReadiness();
    assert.strictEqual(r.on, false);
    assert.strictEqual(r.ready, false);
    assert.strictEqual(r.problem, null);
  });

  check('DPoP on with a key pair is ready, and reports the thumbprint',
      function () {
    vc.setDpopEnabled(true);
    vc.storeDpopKeyPair({ publicJwk: DPOP_PUB, privateJwk: DPOP_KEY,
                          alg: "ES256" }, "the-jkt");
    const r = vc.dpopReadiness();
    assert.strictEqual(r.on, true);
    assert.strictEqual(r.ready, true);
    assert.strictEqual(r.jkt, "the-jkt");
  });

  check('DPoP on with NO key is a wallet that will fail its next call, and ' +
      'the two reasons are different sentences', function () {
    // Saving off: the key does not survive a page load, which is a
    // sender-constrained token behaving exactly as it should.
    vc.setDpopEnabled(true);
    vc.setHolderKeySaving(false);
    const off = vc.dpopReadiness();
    assert.strictEqual(off.ready, false);
    assert.ok(/saving private keys is turned off/.test(off.problem));

    // Saving on: nothing has been generated yet, which is a step not taken.
    store.reset();
    vc.setDpopEnabled(true);
    const on = vc.dpopReadiness();
    assert.strictEqual(on.ready, false);
    assert.ok(/no key pair has been generated yet/.test(on.problem));
    assert.notStrictEqual(on.problem, off.problem,
        "Both are 'DPoP is on and there is no key', and they need different " +
        "things done about them.");
  });

  check('storeDpopKeyPair honours the opt-out like every other writer',
      function () {
    vc.setDpopEnabled(true);
    vc.setHolderKeySaving(false);
    vc.storeDpopKeyPair({ publicJwk: DPOP_PUB, privateJwk: DPOP_KEY }, "jkt");
    assert.strictEqual(store.getItem("sdjwtvc_dpop_private_jwk"), null,
        "The DPoP writer went round the gate, which is what a guard per call " +
        "site always eventually does.");
  });

  check('the context handed to the wire module is null when there is no key',
      function () {
    // null means "send a Bearer request", which is the answer both when DPoP
    // is off and when the key is gone: the caller does not have to tell those
    // apart to make a call, only to explain itself.
    assert.strictEqual(vc.dpopContext(), null);
    vc.setDpopEnabled(true);
    vc.setHolderKeySaving(false);
    assert.strictEqual(vc.dpopContext(), null);
  });

  check('a nonce is remembered, and an ABSENT one does not erase it',
      function () {
    // The second half is the deliberate part. RFC 9449 has the server send a
    // `DPoP-Nonce` header when it wants one and say nothing when it does not,
    // so most responses carry none — and a wallet that treated "no header" as
    // "forget the nonce" would drop it on the first ordinary reply and pay an
    // extra round trip on every request after that. `rememberDpopNonce()`
    // ignores an empty value rather than storing or clearing one.
    vc.rememberDpopNonce("nonce-1");
    assert.strictEqual(vc.dpopNonce(), "nonce-1");
    vc.rememberDpopNonce("");
    assert.strictEqual(vc.dpopNonce(), "nonce-1",
        "An empty nonce erased the stored one. Most responses carry no " +
        "DPoP-Nonce header at all, so that is the difference between nonce " +
        "mode being invisible and it costing a round trip every time.");
    vc.rememberDpopNonce(undefined);
    assert.strictEqual(vc.dpopNonce(), "nonce-1");
    vc.rememberDpopNonce("nonce-2");
    assert.strictEqual(vc.dpopNonce(), "nonce-2",
        "A new nonce must replace the old one — the server has moved on.");
  });

  check('no nonce at all reads as the empty string', function () {
    assert.strictEqual(vc.dpopNonce(), "",
        "null here would be concatenated into a proof as the text 'null'.");
  });

  log.debug("Leaving dpopReadinessTellsConfigurationFromBreakage().");
}

// ---------------------------------------------------------------------------
// 7. WHETHER A CREDENTIAL CAN BE PRESENTED.
//
// THE SECTION THIS FILE WAS WRITTEN FOR. `presentationReadiness()` decides
// whether step 1 of the presentation workflow lets somebody continue, and the
// distinction it has to draw is between a key that is absent BY CHOICE and one
// that is absent and LOST. Getting it backwards strands the user two pages
// before the only field that would fix it.
// ---------------------------------------------------------------------------
function presentationReadinessTellsChoiceFromLoss() {
  log.debug("Entering presentationReadinessTellsChoiceFromLoss().");

  check('nothing held is a refusal that says what the workflow is for',
      function () {
    const r = vc.presentationReadiness();
    assert.strictEqual(r.ready, false);
    assert.strictEqual(r.level, "vc-bad");
    assert.ok(/Nothing is held yet/.test(r.message));
  });

  check('a credential that cannot be parsed is refused, naming the parse',
      function () {
    vc.set("sdjwtvc_credential", "this is not a credential");
    const r = vc.presentationReadiness();
    assert.strictEqual(r.ready, false);
    assert.strictEqual(r.level, "vc-bad");
    assert.ok(/cannot be parsed/.test(r.message));
  });

  check('a credential and its key is READY, and counts what would be offered',
      function () {
    vc.set("sdjwtvc_credential", BOUND_CREDENTIAL);
    vc.setJson("sdjwtvc_holder_private_jwk", HOLDER_KEY);
    const r = vc.presentationReadiness();
    assert.strictEqual(r.ready, true);
    assert.strictEqual(r.level, "vc-ok");
    assert.ok(/selectively-disclosable claim/.test(r.message),
        "An SD-JWT offers a CHOICE of claims and the message says how many; " +
        "that is the difference from jwt_vc_json, which offers all or none.");
  });

  check('SAVING ON and the key gone BLOCKS — it was never generated here',
      function () {
    // There is nothing to paste, and presentation step 1 refuses to continue
    // past exactly this. Blocking here says so one page earlier.
    vc.set("sdjwtvc_credential", BOUND_CREDENTIAL);
    assert.strictEqual(vc.holderPrivateKeyMayBeStored(), true);
    const r = vc.presentationReadiness();
    assert.strictEqual(r.ready, false);
    assert.strictEqual(r.level, "vc-bad");
    assert.ok(/would stop at step 1/.test(r.message));
  });

  check('SAVING OFF and the key gone is an ADVISORY and must not block',
      function () {
    // The one that strands a user if it is got backwards: presentation step 2
    // has a field to paste the key into, so refusing here would stop them two
    // pages before it.
    vc.set("sdjwtvc_credential", BOUND_CREDENTIAL);
    vc.setHolderKeySaving(false);
    const r = vc.presentationReadiness();
    assert.strictEqual(r.ready, true,
        "This blocks the user two pages before the field that would fix it. " +
        "Absent BY CHOICE is not absent and lost.");
    assert.strictEqual(r.level, "vc-pending");
    assert.ok(/asked to paste it/.test(r.message));
  });

  check('the two absences produce different levels as well as different ' +
      'words', function () {
    // The level is what the pane colours by, so two states that read
    // differently and colour identically are two states a reader will not
    // notice are different.
    vc.set("sdjwtvc_credential", BOUND_CREDENTIAL);
    const lost = vc.presentationReadiness();
    store.reset();
    vc.set("sdjwtvc_credential", BOUND_CREDENTIAL);
    vc.setHolderKeySaving(false);
    const byChoice = vc.presentationReadiness();
    assert.notStrictEqual(lost.level, byChoice.level);
    assert.notStrictEqual(lost.ready, byChoice.ready);
  });

  check('a credential with no cnf still needs its key to be presented',
      function () {
    vc.set("sdjwtvc_credential", UNBOUND_CREDENTIAL);
    vc.setJson("sdjwtvc_holder_private_jwk", HOLDER_KEY);
    const r = vc.presentationReadiness();
    assert.strictEqual(r.ready, true);
  });

  log.debug("Leaving presentationReadinessTellsChoiceFromLoss().");
}

// ---------------------------------------------------------------------------
// 8. THE CREDENTIAL HISTORY AND THE FLOW HAND-OFF.
// ---------------------------------------------------------------------------
function theHistoryAndTheFlowHandoff() {
  log.debug("Entering theHistoryAndTheFlowHandoff().");

  check('an empty history is an empty list rather than null', function () {
    assert.deepStrictEqual(vc.credentialHistory(), []);
    assert.strictEqual(vc.hasCredentialHistory(), false);
  });

  check('an unreadable history reads as empty', function () {
    store.setItem("sdjwtvc_credential_history", "{{{");
    assert.deepStrictEqual(vc.credentialHistory(), []);
  });

  check('the cap is enforced ON WRITE, not on read', function () {
    // Writing the rows straight into storage does NOT trim them, and that is
    // the right division: `credentialHistory()` is a reader and a reader that
    // silently rewrote what it read would make the pane and the store
    // disagree. The trim belongs to `trimHistory()`, on the write path.
    for (var i = 0; i < vc.HISTORY_LIMIT + 12; i++) {
      vc.recordHistoryEntry({ kind: vc.HISTORY_KIND.CREDENTIAL_REQUEST,
                              outcome: vc.HISTORY_OUTCOME.FAILED,
                              detail: "attempt " + i });
    }
    const kept = vc.credentialHistory();
    assert.ok(kept.length <= vc.HISTORY_LIMIT,
        "The history grew to " + kept.length + " rows past a limit of " +
        vc.HISTORY_LIMIT + ". Unbounded, it is the thing that fills a " +
        "browser's storage and makes every later write on this page fail.");
    assert.strictEqual(kept[kept.length - 1].detail,
        "attempt " + (vc.HISTORY_LIMIT + 11),
        "The NEWEST row was dropped. A history that discards the most recent " +
        "entry is a history of the wrong thing.");
  });

  check('a HELD generation is kept in preference to an ordinary row',
      function () {
    // The interesting half of trimHistory(). A row that records a failed
    // attempt is a log line; a row that holds a credential is the credential.
    // Evicting by age alone would throw away the wallet's contents to make
    // room for its logs.
    vc.recordCredentialGeneration({ credential: BOUND_CREDENTIAL,
                                    source: "issued" });
    for (var i = 0; i < vc.HISTORY_LIMIT + 5; i++) {
      vc.recordHistoryEntry({ kind: vc.HISTORY_KIND.CREDENTIAL_REQUEST,
                              outcome: vc.HISTORY_OUTCOME.FAILED,
                              detail: "noise " + i });
    }
    const held = vc.heldGenerations();
    assert.strictEqual(held.length, 1,
        "The held generation was evicted while " + vc.HISTORY_LIMIT +
        " ordinary rows survived. trimHistory() takes the oldest row that is " +
        "NOT a held generation first, and only drops a held one when every " +
        "row is one.");
    assert.strictEqual(held[0].entry.credential, BOUND_CREDENTIAL);
  });

  check('when every row is a held generation the oldest goes and is COUNTED',
      function () {
    // The pane says how many generations have been dropped, so the count has
    // to be kept rather than the loss being silent.
    assert.strictEqual(vc.droppedGenerations(), 0);
    for (var i = 0; i < vc.HISTORY_LIMIT + 3; i++) {
      vc.recordCredentialGeneration({
        credential: sdJwt({ vct: "https://example.com/C", iss: "https://i",
                            jti: "gen-" + i }, []),
        source: "issued" });
    }
    assert.ok(vc.credentialHistory().length <= vc.HISTORY_LIMIT);
    assert.ok(vc.droppedGenerations() >= 3,
        "Held generations were dropped past the limit and the count says " +
        vc.droppedGenerations() + ". A wallet that quietly forgets a " +
        "credential it was issued is worse than one that says it had to.");
  });

  check('the SAME credential twice in a row is ONE generation', function () {
    // A reload or a retried click re-stores what was already stored, and a
    // history that counted that twice would tell the holder they were issued
    // two credentials.
    const first = vc.recordCredentialGeneration({
        credential: BOUND_CREDENTIAL, source: "issued" });
    const again = vc.recordCredentialGeneration({
        credential: BOUND_CREDENTIAL, source: "issued" });
    assert.strictEqual(again, first);
    assert.strictEqual(vc.heldGenerations().length, 1);
  });

  check('a generation with no credential in it is not a generation',
      function () {
    assert.strictEqual(vc.recordCredentialGeneration({ source: "issued" }), -1);
    assert.strictEqual(vc.heldGenerations().length, 0);
  });

  check('the flow hand-off is one-shot and names where to come back to',
      function () {
    assert.strictEqual(vc.isFlowActive(), false);
    vc.startFlow("/vc-issuance-2.html");
    assert.strictEqual(vc.isFlowActive(), true);
    assert.strictEqual(vc.returnUrl(), "/vc-issuance-2.html");
    vc.endFlow();
    assert.strictEqual(vc.isFlowActive(), false,
        "A flow that stays active sends the NEXT visit to oauth2_oidc_2.html " +
        "back into a workflow nobody started.");
  });

  check('the use case falls back to the default rather than to nothing',
      function () {
    // It answers with the use case OBJECT rather than its id — the pages read
    // its steps and its wording off it — so the fallback has to resolve to a
    // real entry rather than to an id that is not in the table.
    assert.ok(vc.useCaseById(vc.DEFAULT_USE_CASE),
        "The default use case is not in USE_CASES, so every fallback below " +
        "falls back to nothing.");
    assert.strictEqual(vc.currentUseCase().id, vc.DEFAULT_USE_CASE);
    vc.set("sdjwtvc_use_case", "no-such-use-case");
    assert.strictEqual(vc.currentUseCase().id, vc.DEFAULT_USE_CASE,
        "An unknown use case must fall back, or a value written by an older " +
        "build leaves the workflow with no steps at all.");
    assert.strictEqual(vc.useCaseById("no-such-use-case"), null,
        "An unknown id must not resolve to something: a use case invented " +
        "from an unknown name is a workflow with steps nobody wrote.");
  });

  check('every use case in the table is complete enough to drive a page',
      function () {
    const seen = {};
    vc.useCases().forEach(function (uc) {
      assert.ok(uc.id && uc.label,
          "A use case with no id or no label cannot be chosen on step 0.");
      assert.ok(!seen[uc.id],
          "Two use cases share the id " + uc.id + ", so useCaseById() " +
          "answers with whichever came first and the other is unreachable.");
      seen[uc.id] = true;
    });
    assert.ok(vc.useCases().length >= 2);
  });

  check('an offer is stored, read and forgotten', function () {
    vc.storeOffer({ credential_issuer: "https://issuer.example.com",
                    grants: { authorization_code: { issuer_state: "st-1" } } },
                  "qr");
    assert.strictEqual(vc.offerIssuerState(), "st-1");
    assert.ok(vc.storedOffer());
    vc.forgetOffer();
    assert.strictEqual(vc.storedOffer(), null);
    assert.strictEqual(vc.offerIssuerState(), "",
        "A stale issuer_state is sent on the next authorization request and " +
        "refused, which reads as a broken issuer.");
  });

  check('a pre-authorized offer is recognised and its code read', function () {
    // The grant name is built rather than written as a key: an object key
    // cannot be a concatenation (`"a" + "b":` is a syntax error), which is one
    // of the three things the repo-root CLAUDE.md says not to break to reach
    // 80 columns.
    const grants = {};
    grants[vc.PRE_AUTHORIZED_GRANT] = {
      "pre-authorized_code": "pac-1",
      tx_code: { length: 4, input_mode: "numeric" }
    };
    vc.storeOffer({ credential_issuer: "https://issuer.example.com",
                    grants: grants },
                  "qr");
    assert.ok(vc.preAuthorizedGrant());
    assert.strictEqual(vc.offerPreAuthorizedCode(), "pac-1");
    assert.ok(vc.offerTxCode());
  });

  log.debug("Leaving theHistoryAndTheFlowHandoff().");
}

function test() {
  log.debug("Entering test().");
  theStoreDegradesRatherThanThrowing();
  theKeySavingOptOutIsEnforcedCentrally();
  twoKeysAreComparedByTheirPublicHalf();
  aHolderKeyIsReadFromStorageOrFromAPaste();
  theBoundKeyIsChosenByTheCredentialsOwnCnf();
  dpopReadinessTellsConfigurationFromBreakage();
  presentationReadinessTellsChoiceFromLoss();
  theHistoryAndTheFlowHandoff();
  // A count, and it is asserted rather than only printed: this file needs no
  // server and no browser, so there is no legitimate reason for it to run
  // fewer checks than it has. A sudden drop means a section stopped being
  // called, which is the way a suite quietly stops testing something.
  log.info(checks + " checks passed.");
  assert.ok(checks >= 35,
      'Only ' + checks + ' checks ran and this file defines well over ' +
      'thirty-five. A section has stopped being called.');
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sd_jwt_vc_engine")
  .description("Drive client/src/sd_jwt_vc.js in node with no server and no " +
      "browser: the store, the key-saving opt-out and the gate that " +
      "enforces it, which private key a credential is bound to, whether a " +
      "DPoP proof can be made, whether a credential can be presented, and " +
      "the Credential History.")
  // Accepted and ignored: run-report.js passes --url to every job, and
  // commander exits 1 on an option it has not been told about.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

try {
  test();
} catch (e) {
  log.error(e.stack || e.message);
  process.exit(1);
}
