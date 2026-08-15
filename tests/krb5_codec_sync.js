// File: krb5_codec_sync.js
//
// The Kerberos codec exists TWICE, and this is the test that makes that safe.
//
// ---------------------------------------------------------------------------
// Why there are two copies.
//
// The KDC needs the same codec the browser uses — it is the other end of the same
// wire. But the KDC lives in the rcbj/mock-sts SUBMODULE, and compose builds that
// service with `context: ./sts`. A Docker build cannot COPY from outside its
// context, so `../common/krb5` is simply unreachable from there. The options were
// to publish a package (too much ceremony for four files), to move the KDC into
// this repository as a side-car like keycloak-wsfed/ (rejected: the mock STS is
// where every other mock protocol lives), or to vendor a copy and test it. This is
// the test.
//
// ---------------------------------------------------------------------------
// Why a file comparison is not enough on its own.
//
// The failure mode of a vendored wire codec is not "one copy is broken". It is
// that BOTH copies are self-consistent and disagree only with each other — the
// KDC encrypts with one key usage number and the wallet decrypts with another,
// and each one's own tests pass. The symptom is an integrity failure, which is
// indistinguishable from a wrong password, discovered against a real domain
// controller weeks later.
//
// So this test does two different things:
//
//   1. **A behavioural cross-check.** Messages are built with copy A and read with
//      copy B and vice versa, and — the strongest assertion here — copy A ENCRYPTS
//      and copy B DECRYPTS. A divergence in key usage numbers, in what the MAC
//      covers, in string-to-key, or in a context tag fails this and nothing else
//      would.
//   2. **A file comparison**, which catches drift before it has consequences and
//      names the one command that fixes it.
//
// If the submodule is not initialised there is nothing to compare, and this test
// says so and passes rather than pretending: an uninitialised submodule is an
// EMPTY DIRECTORY, and reporting that as a codec failure would send somebody
// looking in the wrong place entirely.
//
// No browser and no services: node only.
// ---------------------------------------------------------------------------
const assert = require("assert");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "krb5_codec_sync",
    level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

// krb5_gss.js is vendored too, because the protected service parses the same
// GSS tokens the client builds. krb5_ndr.js and krb5_pac.js are vendored
// because the KDC MINTS the PAC that the browser then reads — the two ends of
// the least forgiving structure in the whole protocol, where a one-byte
// disagreement about NDR alignment makes each copy self-consistent and mutually
// unintelligible. krb5_client.js and krb5_describe.js are NOT vendored: the
// client half and the presentation layer have no counterpart in the KDC, so
// vendoring them would create a copy nothing reads — and an unread copy is one
// that drifts silently.
const MODULES = ["krb5_primitives.js", "krb5_asn1.js", "krb5_crypto.js",
    "krb5_messages.js",
                 "krb5_gss.js", "krb5_ndr.js", "krb5_pac.js"];

// The canonical copy.
//
// In a checkout that is common/krb5. In the tests image there is no common/
// tree at all — those modules are copied FLAT beside the test scripts — so the
// flat copies are the canonical ones there, and the comparison is still the one
// that matters: the flat files came from common/krb5 and the sts/ ones came
// from the submodule.
//
// Without this the test failed in the containerized suite with "common/krb5/...
// is missing", which reads as a broken checkout rather than as a layout
// difference.
const CANONICAL_DIR = (function () {
  const inCheckout = path.join(__dirname, "..", "common", "krb5");
  if (fs.existsSync(path.join(inCheckout, "krb5_primitives.js"))) {
    return inCheckout;
  }
  return __dirname;
})();

// The vendored copy, wherever it is in this layout. The tests image copies the
// submodule's files in under sts/, a checkout has them in the submodule, and a
// developer mid-loop has them in a sibling checkout.
function findVendoredDir() {
  log.debug("Entering findVendoredDir().");
  const candidates = [
    { dir: path.join(__dirname, "..", "sts"), what: "the sts/ submodule" },
    { dir: path.join(__dirname, "sts"), what: "sts/ inside the tests image" },
    {
      dir: path.join(__dirname, "..", "..", "mock-sts"),
      what: "a sibling mock-sts checkout"
    }
  ].filter(function (candidate) {
    // Never compare the canonical directory with itself. In the flat container
    // layout CANONICAL_DIR is __dirname, and a candidate resolving to the same
    // place would make this test compare a thing with itself and pass
    // vacuously.
    return path.resolve(candidate.dir) !== path.resolve(CANONICAL_DIR);
  });
  for (const candidate of candidates) {
    if (MODULES.every(function (m) { return fs.existsSync(path.join(candidate.dir,
        m)); })) {
      log.debug("Leaving findVendoredDir().");
      return candidate;
    }
  }
  // Partial is worse than absent and must be reported as a failure: it means a
  // sync half happened, and half a codec is a codec that does not load.
  for (const candidate of candidates) {
    const present = MODULES.filter(function (m) { return fs.existsSync(path.join(candidate.dir,
        m)); });
    if (present.length) {
      log.debug("Leaving findVendoredDir().");
      throw new Error("the vendored codec in " + candidate.what +
          " is INCOMPLETE: it has " +
        present.join(", ") + " but not " +
            MODULES.filter(function (m) { return present.indexOf(m) === -1; }).join(", ") +
        ". Run common/krb5/sync-to-mock-sts.sh — a partial copy will fail to " +
            "load rather than " +
        "merely disagree.");
    }
  }
  log.debug("Leaving findVendoredDir().");
  return null;
}

function sha256(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

// ---------------------------------------------------------------------------
// The behavioural cross-check.
// ---------------------------------------------------------------------------
async function theTwoCopiesAgreeOnTheWire(vendoredDir) {
  log.debug("Entering theTwoCopiesAgreeOnTheWire().");

  // Both copies are require()d by absolute path, which bypasses the resolution
  // fallback the other tests get for free from requireSharedModule — so it is
  // applied explicitly here. Without it the codec loads until it reaches its
  // own `require("bunyan")`, which resolves relative to where the MODULE lives
  // (common/krb5, or the submodule) rather than to this test's node_modules.
  paths.addTestsModulesToResolutionPath();

  // Two independent module instances. require() caches by resolved path, so
  // loading from two directories gives two separate copies of the code — which
  // is exactly the situation being tested.
  function load(dir) {
    return {
      prim: require(path.join(dir, "krb5_primitives.js")),
      asn1: require(path.join(dir, "krb5_asn1.js")),
      msgs: require(path.join(dir, "krb5_messages.js")),
      kcrypto: require(path.join(dir, "krb5_crypto.js")),
      ndr: require(path.join(dir, "krb5_ndr.js")),
      kpac: require(path.join(dir, "krb5_pac.js"))
    };
  }
  const A = load(CANONICAL_DIR);
  const B = load(vendoredDir);
  assert.notStrictEqual(A.msgs, B.msgs,
    "the two copies resolved to the SAME module instance, so this test is " +
        "comparing a thing with " +
    "itself and proves nothing. Are common/krb5 and the vendored directory " +
        "the same path, or is " +
    "one a symlink to the other?");

  // --- 1. Constants. A protocol constant that differs between the two ends is
  // a wire incompatibility, and the cheapest possible thing to check.
  ["PVNO"].forEach(function (name) {
    assert.strictEqual(A.msgs[name], B.msgs[name], "msgs." + name +
        " differs between the copies");
  });
  ["MSG_TYPE", "APPLICATION", "NAME_TYPE", "PA_TYPE", "KDC_OPTION",
      "TICKET_FLAG", "AP_OPTION"]
    .forEach(function (table) {
      assert.deepStrictEqual(A.msgs[table], B.msgs[table],
        "msgs." + table + " differs between the two copies of the codec. A " +
            "constant that differs " +
        "between the KDC and the wallet is a wire incompatibility that each " +
            "end's own tests pass.");
    });
  assert.deepStrictEqual(A.kcrypto.KEY_USAGE, B.kcrypto.KEY_USAGE,
    "THE KEY USAGE TABLE DIFFERS. This is the worst possible divergence: " +
        "every message would be " +
    "well formed and every decryption would fail an integrity check, which a " +
        "KDC reports as a " +
    "wrong password.");
  assert.deepStrictEqual(A.kcrypto.DEFAULT_ETYPE_PREFERENCE,
      B.kcrypto.DEFAULT_ETYPE_PREFERENCE,
    "the default etype preference differs");
  assert.deepStrictEqual(Object.keys(A.kcrypto.ETYPES).sort(),
      Object.keys(B.kcrypto.ETYPES).sort(),
    "the two copies implement different sets of encryption types");

  // --- 2. Crypto, cross-wise. A encrypts, B decrypts, and back. This is the
  // assertion that catches a divergence in key usage folding, in what the MAC
  // covers, or in string-to-key — none of which a same-copy round trip can see.
  for (const id of Object.keys(A.kcrypto.ETYPES).map(Number)) {
    const profileA = A.kcrypto.etypeById(id);
    const profileB = B.kcrypto.etypeById(id);
    assert.strictEqual(profileA.name, profileB.name, "etype " + id +
        " has a different name");

    const keyA = await profileA.stringToKey("shared secret",
        A.prim.utf8("EXAMPLE.COMalice"), null);
    const keyB = await profileB.stringToKey("shared secret",
        B.prim.utf8("EXAMPLE.COMalice"), null);
    assert.strictEqual(A.prim.toHex(keyA), B.prim.toHex(keyB),
      profileA.name + ": string-to-key differs between the copies, so the " +
          "KDC and the wallet would " +
      "derive different keys from the same password and salt");

    const plaintext = A.prim.utf8("the session key goes here");
    const usage = A.kcrypto.KEY_USAGE.AS_REP_ENCPART;
    const fromA = await profileA.encrypt(keyA, usage, plaintext);
    const readByB = await profileB.decrypt(keyB, usage, fromA);
    assert.strictEqual(B.prim.toHex(readByB), A.prim.toHex(plaintext),
      profileA.name + ": what copy A encrypted, copy B could not read back. " +
          "This is the divergence " +
      "that no single-copy test can find.");
    const fromB = await profileB.encrypt(keyB, usage, plaintext);
    const readByA = await profileA.decrypt(keyA, usage, fromB);
    assert.strictEqual(A.prim.toHex(readByA), A.prim.toHex(plaintext),
      profileA.name + ": what copy B encrypted, copy A could not read back");

    // Checksums too, since a service verifies a checksum the client computed.
    const message = A.prim.utf8("the authenticator's checksum covers this");
    const cksumA = await profileA.checksum(keyA,
        A.kcrypto.KEY_USAGE.AP_REQ_AUTH_CKSUM, message);
    assert.strictEqual(
      await profileB.verifyChecksum(keyB,
          B.kcrypto.KEY_USAGE.AP_REQ_AUTH_CKSUM, message, cksumA),
      true, profileA.name + ": copy B rejected a checksum copy A computed");
    log.debug("etype " + id + " (" + profileA.name + ") agrees across the " +
        "copies");
  }

  // --- 3. Messages, cross-wise. Built by one copy, read by the other, and the
  // re-encoding compared byte for byte.
  const till = new Date(Date.UTC(2026, 7, 14, 0, 0, 0));
  const corpus = [
    ["AS-REQ", function (m) {
      return m.encKdcReq({
        msgType: m.MSG_TYPE.AS_REQ,
        padata: [{
          type: m.PA_TYPE.PAC_REQUEST,
          value: m.encPaPacRequest(true)
        }],
        reqBody: {
          kdcOptions: [m.KDC_OPTION.FORWARDABLE, m.KDC_OPTION.RENEWABLE,
              m.KDC_OPTION.CANONICALIZE],
          cname: { type: m.NAME_TYPE.PRINCIPAL, name: ["alice"] },
          realm: "EXAMPLE.COM",
          sname: {
            type: m.NAME_TYPE.SRV_INST,
            name: ["krbtgt", "EXAMPLE.COM"]
          },
          from: till,
          till: till,
          rtime: till,
          nonce: 3735928559,
          etypes: [18, 17, 23],
          addresses: [{ type: 2, address: Uint8Array.from([10, 0, 0, 1]) }]
        }
      });
    }, function (m, bytes) { return m.readKdcReq(bytes); }],
    ["KRB-ERROR with ETYPE-INFO2", function (m) {
      return m.encKrbError({
        stime: till,
        susec: 1,
        errorCode: 25,
        realm: "EXAMPLE.COM",
        sname: {
          type: 2,
          name: ["krbtgt", "EXAMPLE.COM"]
        },
        eText: "NEEDED_PREAUTH",
        eData: A.asn1.encSequenceOf([m.encPaData({
          type: m.PA_TYPE.ETYPE_INFO2,
          value: m.encEtypeInfo2([
            {
              etype: 18,
              salt: "EXAMPLE.COMalice",
              s2kparams: Uint8Array.from([0, 0, 0x10, 0])
            },
            { etype: 23, salt: null, s2kparams: null }])
        })])
      });
    }, function (m, bytes) { return m.readKrbError(bytes); }],
    ["EncTicketPart", function (m) {
      return m.encEncTicketPart({
        flags: [m.TICKET_FLAG.FORWARDABLE, m.TICKET_FLAG.INITIAL,
            m.TICKET_FLAG.PRE_AUTHENT],
        key: { etype: 18, key: Uint8Array.from(new Array(32).fill(7)) },
        crealm: "EXAMPLE.COM",
        cname: { type: 1, name: ["alice"] },
        authtime: till,
        endtime: till
      });
    }, function (m, bytes) { return m.readEncTicketPart(bytes); }],
    ["Authenticator with a negative cksumtype", function (m) {
      return m.encAuthenticator({
        crealm: "EXAMPLE.COM",
        cname: { type: 1, name: ["alice"] },
        cksum: {
          type: -138,
          checksum: Uint8Array.from(new Array(16).fill(0xab))
        },
        cusec: 12345,
        ctime: till,
        seqNumber: 1234567890
      });
    }, function (m, bytes) { return m.readAuthenticator(bytes); }],
    ["KRB-CRED (a forwarded ticket and its key)", function (m) {
      return m.encKrbCred({
        tickets: [{
          realm: "EXAMPLE.COM",
          sname: {
            type: m.NAME_TYPE.SRV_INST,
            name: ["krbtgt", "EXAMPLE.COM"]
          },
          encPart: {
            etype: 18,
            kvno: 3,
            cipher: Uint8Array.from(new Array(48).fill(9))
          }
        }],
        encPart: { etype: 18, cipher: Uint8Array.from(new Array(64).fill(5)) }
      });
    }, function (m, bytes) { return m.readKrbCred(bytes); }],
    ["EncKrbCredPart", function (m) {
      return m.encEncKrbCredPart({
        ticketInfo: [{
          key: { etype: 18, key: Uint8Array.from(new Array(32).fill(4)) },
          prealm: "EXAMPLE.COM",
          pname: { type: 1, name: ["alice"] },
          flags: [m.TICKET_FLAG.FORWARDABLE, m.TICKET_FLAG.FORWARDED],
          authtime: till,
          endtime: till,
          renewTill: till,
          srealm: "EXAMPLE.COM",
          sname: { type: 2, name: ["krbtgt", "EXAMPLE.COM"] },
          caddr: [{ type: 2, address: Uint8Array.from([10, 0, 0, 5]) }]
        }],
        nonce: 3735928559,
        timestamp: till,
        usec: 999999,
        // A SINGLE HostAddress, not the SEQUENCE OF — encoding these with the
        // plural form wraps them in an extra SEQUENCE that decodes as an
        // address whose type field is a whole structure.
        sAddress: { type: 2, address: Uint8Array.from([10, 0, 0, 1]) },
        rAddress: { type: 2, address: Uint8Array.from([10, 0, 0, 2]) }
      });
    }, function (m, bytes) { return m.readEncKrbCredPart(bytes); }],
    ["PA-PAC-OPTIONS with the RBCD bit", function (m) {
      return m.encPaPacOptions([m.PAC_OPTION.RESOURCE_BASED_CONSTRAINED_DELEGATION]);
    }, function (m, bytes) { return m.readPaPacOptions(bytes); }],
    ["PA-FOR-USER", function (m) {
      return m.encPaForUser({
        userName: { type: 1, name: ["bob"] },
        userRealm: "EXAMPLE.COM",
        cksum: { type: -138, checksum: Uint8Array.from(new Array(16).fill(3)) },
        authPackage: "Kerberos"
      });
    }, function (m, bytes) { return m.readPaForUser(bytes); }]
  ];

  for (const [label, build, read] of corpus) {
    const bytesA = build(A.msgs);
    const bytesB = build(B.msgs);
    assert.strictEqual(A.prim.toHex(bytesA), B.prim.toHex(bytesB),
      label + ": the two copies ENCODE it differently, so the KDC and the " +
          "wallet would put " +
      "different bytes on the wire for the same message");

    // And each reads the other's bytes. A reader that silently drops a field
    // the other writes is the case a byte comparison of the two ENCODERS
    // misses.
    const byB = read(B.msgs, bytesA);
    const byA = read(A.msgs, bytesB);
    assert.ok(byB && byA, label + ": one copy could not read the other's " +
        "bytes");
    // Compare the parsed shapes through JSON, with bytes rendered as hex so
    // Uint8Array and Buffer do not compare unequal for uninteresting reasons.
    const normalise = function (value) {
      return JSON.stringify(value, function (key, v) {
        if (v && (v instanceof Uint8Array || (v.type === "Buffer" &&
            Array.isArray(v.data)))) {
          return "bytes:" + Buffer.from(v.data || v).toString("hex");
        }
        return v;
      });
    };
    assert.strictEqual(normalise(byA), normalise(byB),
      label + ": the two copies PARSE the same bytes into different shapes");
    log.debug(label + " agrees across the copies (" + bytesA.length +
        " bytes)");
  }

  // --- 4. The PAC, cross-wise. This is the sharpest check in the file, because
  // the PAC is the one structure where the two copies play genuinely different
  // roles: the KDC MINTS it and the browser READS it, so a divergence is not
  // symmetrical and a byte comparison of two encoders would not find it. NDR
  // makes it worse — get the alignment or a referent-id ordering wrong in both
  // copies and each is perfectly self-consistent, so the KDC would issue PACs
  // its own tests parse and no Windows service accepts.
  //
  // The check is deliberately asymmetric in both directions: A signs, B
  // verifies with the same keys; then B signs and A verifies. A shared
  // misunderstanding of what the signatures cover survives one direction and
  // not both.
  const pacKeys = {
    serverKey: { etype: 18, key: Uint8Array.from(new Array(32).fill(0x5a)) },
    kdcKey: { etype: 18, key: Uint8Array.from(new Array(32).fill(0xa5)) }
  };
  const pacSpec = {
    includeExtendedKdcSignature: true,
    logonInfo: {
      logonTime: till,
      effectiveName: "alice",
      fullName: "Alice Example",
      logonServer: "DC01",
      logonDomainName: "EXAMPLE",
      logonDomainId: "S-1-5-21-1004336348-1177238915-682003330",
      userId: 1104,
      primaryGroupId: 513,
      // More than one of each: a single-element array hides an ordering error.
      groups: [{ relativeId: 513 }, { relativeId: 512 }],
      extraSids: [{ sid: "S-1-18-1" }, { sid: "S-1-5-32-544" }],
      resourceGroupDomainSid: "S-1-5-21-99-98-97",
      resourceGroups: [{ relativeId: 1200 }, { relativeId: 1201 }],
      userAccountControl: 0x00000010 | 0x00002000
    },
    clientInfo: { name: "alice", clientId: till },
    upnDns: {
      upn: "alice@example.com",
      dnsDomainName: "EXAMPLE.COM",
      samName: "alice",
      sid: "S-1-5-21-1004336348-1177238915-682003330-1104"
    },
    attributes: 0x00000001,
    requestorSid: "S-1-5-21-1004336348-1177238915-682003330-1104"
  };

  assert.strictEqual(A.kpac.KERB_NON_KERB_CKSUM_SALT,
      B.kpac.KERB_NON_KERB_CKSUM_SALT,
    "the two copies disagree about the PAC signatures' key usage number. " +
        "Every PAC the KDC signs " +
    "would fail verification in the browser, and the message would be about " +
        "a bad signature " +
    "rather than about a constant.");
  assert.deepStrictEqual(A.kpac.TYPE, B.kpac.TYPE, "the PAC buffer type " +
      "numbers differ");
  assert.deepStrictEqual(A.kpac.USER_ACCOUNT_CONTROL,
      B.kpac.USER_ACCOUNT_CONTROL,
    "the UserAccountControl tables differ, so the two ends would name " +
        "different account flags");
  assert.deepStrictEqual(A.kpac.GROUP_ATTRIBUTES, B.kpac.GROUP_ATTRIBUTES,
    "the SE_GROUP_* tables differ");
  assert.strictEqual(A.kpac.USER_FLAG_EXTRA_SIDS, B.kpac.USER_FLAG_EXTRA_SIDS,
    "the D (EXTRA_SIDS) bit differs, so one copy would emit extra SIDs the " +
        "other ignores");

  for (const [signer, verifier, label] of [[A, B, "A signs, B verifies"],
      [B, A, "B signs, A verifies"]]) {
    const pacBytes = await signer.kpac.buildPac(Object.assign({}, pacSpec,
        pacKeys));
    const parsed = verifier.kpac.parsePac(pacBytes);
    assert.deepStrictEqual(parsed.problems, [],
      label + ": the verifying copy finds this PAC malformed: " +
          parsed.problems.join(" | "));

    const info = verifier.kpac.bufferOfType(parsed,
        verifier.kpac.TYPE.LOGON_INFO).parsed;
    assert.strictEqual(info.effectiveName, "alice", label + ": the account " +
        "name did not survive");
    assert.strictEqual(info.userSid,
        "S-1-5-21-1004336348-1177238915-682003330-1104",
      label + ": the account SID did not survive");
    assert.deepStrictEqual(info.groups.map(function (g) { return g.relativeId; }),
        [513, 512],
      label + ": the group list did not survive in order");
    assert.deepStrictEqual(info.extraSids.map(function (e) { return e.text; }),
      ["S-1-18-1", "S-1-5-32-544"],
      label + ": the extra SIDs did not survive — this is the " +
          "deferred-pointer ordering, which is " +
      "where an NDR divergence shows up first");
    assert.deepStrictEqual(info.resourceGroups.map(function (g) { return g.relativeId; }),
      [1200, 1201], label + ": the resource groups did not survive");
    assert.ok(info.userAccountControlNames.indexOf("TRUSTED_FOR_DELEGATION") !== -1,
      label + ": the account flags did not survive: " +
          info.userAccountControlNames.join(", "));
    assert.deepStrictEqual(info.notes, [],
      label + ": the verifying copy raises consistency notes on a PAC the " +
          "other just built: " +
      info.notes.join(" | "));

    const sigs = await verifier.kpac.verifySignatures(parsed, pacKeys);
    sigs.forEach(function (s) {
      assert.strictEqual(s.verified, true,
        label + ": the " + s.name + " signed by one copy does not verify in " +
            "the other (" + s.note +
        "). The two disagree about WHAT that signature covers, which is " +
            "invisible to either " +
        "copy's own tests.");
    });
    log.debug(label + ": " + pacBytes.length + " bytes, " + sigs.length +
        " signatures verified");
  }

  log.info("the two copies of the codec agree on " + corpus.length +
      " message shapes, " +
    Object.keys(A.kcrypto.ETYPES).length + " encryption types and the PAC, " +
        "cross-wise.");
  log.debug("Leaving theTwoCopiesAgreeOnTheWire().");
}

// ---------------------------------------------------------------------------
// The file comparison.
// ---------------------------------------------------------------------------
function theFilesAreIdentical(vendoredDir, what) {
  log.debug("Entering theFilesAreIdentical().");
  const differences = [];
  MODULES.forEach(function (module) {
    const canonical = path.join(CANONICAL_DIR, module);
    const vendored = path.join(vendoredDir, module);
    const a = sha256(canonical);
    const b = sha256(vendored);
    if (a !== b) {
      differences.push(module + " (common/krb5 " + a.slice(0, 12) + ", " +
          what + " " + b.slice(0, 12) + ")");
    }
  });
  assert.deepStrictEqual(differences, [],
    "the vendored codec has drifted from common/krb5:\n  " +
        differences.join("\n  ") +
    "\n\nRun common/krb5/sync-to-mock-sts.sh, then commit and push in " +
        "mock-sts and bump this " +
    "repository's sts/ gitlink. Note that the behavioural cross-check above " +
        "may still have PASSED " +
    "— two copies can differ in comments or formatting and agree on the wire " +
        "— but a divergence " +
    "left in place is one that eventually stops being cosmetic.");
  log.info("all " + MODULES.length + " vendored files are byte-identical to " +
      "common/krb5.");
  log.debug("Leaving theFilesAreIdentical().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. Comparing the two copies of the Kerberos " +
      "codec.");
  MODULES.forEach(function (module) {
    assert.ok(fs.existsSync(path.join(CANONICAL_DIR, module)),
      "common/krb5/" + module + " is missing — this is the canonical copy");
  });

  const vendored = findVendoredDir();
  if (!vendored) {
    // Said plainly, and passing. An uninitialised submodule is an empty
    // directory, and reporting that as a codec failure sends somebody looking
    // in the wrong place. What is NOT acceptable is being silent about it,
    // because then a green run looks like the comparison happened.
    log.warn("NO VENDORED COPY FOUND, so the two copies were NOT compared. " +
        "The mock STS is the " +
      "sts/ SUBMODULE: run `git submodule update --init sts`. An " +
          "uninitialised submodule is an " +
      "EMPTY DIRECTORY rather than a missing one, which is why this is a " +
          "warning about the " +
      "checkout and not a failure of the codec.");
    log.info("Test completed successfully.");
    return;
  }
  log.info("comparing common/krb5 against " + vendored.what + " (" +
      vendored.dir + ")");
  await theTwoCopiesAgreeOnTheWire(vendored.dir);
  theFilesAreIdentical(vendored.dir, vendored.what);
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("krb5_codec_sync")
  .description("Verify that the vendored Kerberos codec in the mock STS " +
      "still agrees with common/krb5.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
      "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
