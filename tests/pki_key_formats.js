// File: pki_key_formats.js
//
// client/src/key_material.js — key generation and every keystore format, read
// back by OpenSSL.
//
// ---------------------------------------------------------------------------
// WHY THIS IS ITS OWN TEST, AND WHY IT ASKS OPENSSL
//
// This module used to be the bottom third of client/src/jwt_tools.js, exercised
// only through that page's Download button by a browser test that could see the
// status line and not the file. What a keystore export produces is a WIRE
// FORMAT that somebody else's tool has to read — `openssl pkcs12 -in`, keytool,
// the Windows certificate store — so "the button said Downloaded" is not a
// check on anything. A PKCS#12 with the wrong bag attributes, an
// EncryptedPrivateKeyInfo with the wrong KDF parameters and a JWK missing its
// curve all produce a file, a status line, and a support ticket a week later.
//
// Extracting it for the PKI page made it testable: exportKeyPair() RETURNS the
// files rather than downloading them, so every cell of the matrix — 7 key
// algorithms x 4 formats x with and without a password — can be produced here
// and handed to OpenSSL.
//
// Two of those cells are refusals, and they are asserted as refusals with the
// right message rather than skipped: PKCS#12 without a password, and an HMAC
// secret in anything but JWK.
//
// Node only — no browser, no services — so it never skips.
// ---------------------------------------------------------------------------
const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");
const { Command, Option } = require("commander");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "pki_key_formats",
    level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

const paths = require("./module_paths.js");
function clientModule(name) {
  log.debug("Entering clientModule(). name=" + name);
  const found = paths.requireSharedModule(
    [path.join(__dirname, "..", "client", "src", name),
     path.join(__dirname, name)],
    "client/src/" + name);
  log.debug("Leaving clientModule().");
  return found;
}

const keys = clientModule("key_material.js");
const x509 = clientModule("x509.js");

const PASSWORD = "correct horse battery staple";

var workDir = null;

function tempDir() {
  log.debug("Entering tempDir().");
  if (!workDir) {
    workDir = fs.mkdtempSync(path.join(os.tmpdir(), "pki-formats-"));
  }
  log.debug("Leaving tempDir().");
  return workDir;
}

// Write what exportKeyPair() returned and give back the paths. The data may be
// a string or bytes depending on the format, which is exactly the sort of thing
// a page gets wrong when it assumes one of them.
function writeFiles(result) {
  log.debug("Entering writeFiles().");
  const written = {};
  result.files.forEach(function (file) {
    const target = path.join(tempDir(), file.name);
    const data = typeof file.data === "string"
      ? Buffer.from(file.data, "utf8")
      : Buffer.from(file.data);
    fs.writeFileSync(target, data);
    written[file.name] = target;
  });
  log.debug("Leaving writeFiles(). " + result.files.length + " file(s).");
  return written;
}

function openssl(args, options) {
  log.debug("Entering openssl(). " + args.join(" "));
  const out = execFileSync("openssl", args,
      Object.assign({ encoding: "utf8" }, options || {}));
  log.debug("Leaving openssl().");
  return out;
}

var keyCache = {};

async function keyFor(algId) {
  log.debug("Entering keyFor(). alg=" + algId);
  if (!keyCache[algId]) {
    keyCache[algId] = await keys.generateKeyPair(algId);
  }
  log.debug("Leaving keyFor().");
  return keyCache[algId];
}

var certCache = {};

// A self-signed certificate for the key, which PKCS#12 has to wrap the private
// key in. It comes from client/src/x509.js — the same call the pages make.
async function certFor(algId) {
  log.debug("Entering certFor(). alg=" + algId);
  if (!certCache[algId]) {
    const pair = await keyFor(algId);
    const desc = keys.keyAlg(algId);
    certCache[algId] = await x509.issueCertificate({
      profile: "tls-client",
      subject: "CN=format test " + algId + ",O=idptools",
      subjectPublicKey: pair.publicPem,
      issuerPrivateKey: pair.privatePem,
      signatureAlg: x509.defaultSignatureAlgorithm(desc),
      extensions: x509.defaultExtensions("tls-client")
    });
  }
  log.debug("Leaving certFor().");
  return certCache[algId];
}

// ---------------------------------------------------------------------------
// 1. Generation: every algorithm produces a usable pair, and OpenSSL agrees
//    about what it is.
// ---------------------------------------------------------------------------
async function everyAlgorithmGeneratesAKeyOpensslRecognises() {
  log.debug("Entering everyAlgorithmGeneratesAKeyOpensslRecognises().");
  const expected = {
    "rsa-2048": /Private-Key: \(2048 bit/,
    "rsa-3072": /Private-Key: \(3072 bit/,
    "rsa-4096": /Private-Key: \(4096 bit/,
    "ec-p256": /prime256v1|P-256/,
    "ec-p384": /secp384r1|P-384/,
    "ec-p521": /secp521r1|P-521/,
    "ed25519": /ED25519/i
  };
  const algIds = keys.keyAlgIds();
  assert.deepStrictEqual(algIds.sort(), Object.keys(expected).sort(),
    "the key algorithm list and this test's expectations have diverged — a " +
    "new algorithm with no expectation here is one nothing checks");
  for (const algId of keys.keyAlgIds()) {
    const pair = await keyFor(algId);
    assert.ok(/^-----BEGIN PRIVATE KEY-----/.test(pair.privatePem),
      algId + ": the private key is not a PKCS#8 PEM");
    assert.ok(/^-----BEGIN PUBLIC KEY-----/.test(pair.publicPem),
      algId + ": the public key is not a SubjectPublicKeyInfo PEM");
    const file = path.join(tempDir(), "gen.pem");
    fs.writeFileSync(file, pair.privatePem);
    const text = openssl(["pkey", "-in", file, "-noout", "-text"]);
    assert.ok(expected[algId].test(text),
      algId + ": openssl read the generated key as something else:\n" + text);
    // And the public half must belong to the private one, which is the check
    // that catches a pane showing two unrelated keys.
    fs.writeFileSync(path.join(tempDir(), "gen.pub"), pair.publicPem);
    const derived = openssl(["pkey", "-in", file, "-pubout"]);
    assert.strictEqual(derived.trim(), pair.publicPem.trim(),
      algId + ": the public key is not the private key's own public half");
  }
  log.info("Generated and checked " + keys.keyAlgIds().length +
      " key algorithms.");
  log.debug("Leaving everyAlgorithmGeneratesAKeyOpensslRecognises().");
}

// ---------------------------------------------------------------------------
// 2. The export matrix: every algorithm, every format, with and without a
//    password.
// ---------------------------------------------------------------------------
async function everyFormatIsReadableByOpenssl() {
  log.debug("Entering everyFormatIsReadableByOpenssl().");
  let cells = 0;
  for (const algId of keys.keyAlgIds()) {
    const pair = await keyFor(algId);
    const desc = keys.keyAlg(algId);
    const cert = await certFor(algId);
    for (const format of keys.keystoreFormats()) {
      for (const password of ["", PASSWORD]) {
        const label = algId + "/" + format + (password ? " (encrypted)" : "");
        // PKCS#12 without a password is a refusal, checked by name below
        // rather than skipped silently here.
        if (format === "pkcs12" && !password) continue;
        const result = await keys.exportKeyPair({
          format: format,
          privatePem: pair.privatePem,
          publicPem: pair.publicPem,
          desc: desc,
          password: password,
          baseName: "export",
          friendlyName: "idptools test",
          certs: [cert.pem],
          alg: "RS256",
          use: "sig"
        });
        assert.ok(result.files.length >= 1, label + ": no file was produced");
        assert.ok(result.status && result.status.length > 0,
          label + ": no status line was produced, so the pane would say " +
          "nothing after a download");
        const written = writeFiles(result);
        cells += 1;

        if (format === "pem") {
          const file = written["export.pem"];
          const args = ["pkey", "-in", file, "-noout", "-text"];
          if (password) args.push("-passin", "pass:" + PASSWORD);
          const text = openssl(args);
          assert.ok(text.length > 0, label + ": openssl read nothing back");
          const pem = fs.readFileSync(file, "utf8");
          if (password) {
            assert.ok(/-----BEGIN ENCRYPTED PRIVATE KEY-----/.test(pem),
              label + ": a password was supplied and the private key was " +
              "written in the clear anyway");
            // And the password must actually be required, or "encrypted" is
            // a label rather than a fact.
            assert.throws(function () {
              openssl(["pkey", "-in", file, "-noout", "-passin",
                       "pass:wrong-password"], { stdio: "pipe" });
            }, label + ": the wrong password opened the private key");
          } else {
            assert.ok(/-----BEGIN PRIVATE KEY-----/.test(pem),
              label + ": expected an unencrypted PKCS#8");
          }
          assert.ok(/-----BEGIN PUBLIC KEY-----/.test(pem),
            label + ": the public key is missing from the PEM bundle");
          assert.ok(/-----BEGIN CERTIFICATE-----/.test(pem),
            label + ": the certificate passed in was not appended");
        } else if (format === "der") {
          assert.strictEqual(result.files.length, 2,
            label + ": DER export is two files, a private and a public one");
          const priv = written["export-private.der"];
          const args = ["pkey", "-inform", "der", "-in", priv, "-noout"];
          if (password) args.push("-passin", "pass:" + PASSWORD);
          openssl(args);
          openssl(["pkey", "-pubin", "-inform", "der", "-in",
                   written["export-public.der"], "-noout"]);
        } else if (format === "jwk") {
          if (password) {
            const jwe = fs.readFileSync(written["export.jwe"], "utf8");
            assert.strictEqual(jwe.split(".").length, 5,
              label + ": a compact JWE has five parts, got " +
              jwe.split(".").length);
            const header = JSON.parse(Buffer.from(jwe.split(".")[0],
                "base64url").toString("utf8"));
            assert.strictEqual(header.alg, "PBES2-HS256+A128KW",
              label + ": unexpected JWE alg " + header.alg);
            assert.ok(header.p2c >= 100000,
              label + ": the PBKDF2 iteration count is only " + header.p2c);
            assert.ok(header.p2s && header.p2s.length > 0,
              label + ": the PBES2 salt is missing");
          } else {
            const set = JSON.parse(fs.readFileSync(written["export.jwk.json"],
                "utf8"));
            assert.strictEqual(set.keys.length, 2,
              label + ": a JWK set export is the public and private key");
            const priv = set.keys.filter(function (k) { return k.d; })[0];
            const pub = set.keys.filter(function (k) { return !k.d; })[0];
            assert.ok(priv && pub,
              label + ": the JWK set has no public/private pair");
            if (desc.kind === "ec") {
              assert.strictEqual(priv.crv, desc.curve,
                label + ": the JWK lost its curve");
              assert.strictEqual(pub.x, priv.x,
                label + ": the two JWKs are not the same key");
            }
            if (desc.kind === "rsa") {
              assert.strictEqual(pub.n, priv.n,
                label + ": the two JWKs are not the same key");
            }
            // A JWK that has to be re-imported is the whole point of the
            // format, so it is round-tripped rather than only inspected.
            const back = await keys.privToPem(JSON.stringify(priv), desc);
            assert.strictEqual(back.trim(), pair.privatePem.trim(),
              label + ": the private JWK does not convert back to the key it " +
              "came from");
          }
        } else if (format === "pkcs12") {
          const file = written["export.p12"];
          // OpenSSL 3 refuses the older PKCS#12 ciphers without -legacy on
          // some builds, so both invocations are accepted; what matters is
          // that ONE of them reads the file.
          let certOut = "";
          try {
            certOut = openssl(["pkcs12", "-in", file, "-passin",
                               "pass:" + PASSWORD, "-nokeys", "-noout"],
                              { stdio: "pipe" });
          } catch (e) {
            certOut = openssl(["pkcs12", "-in", file, "-passin",
                               "pass:" + PASSWORD, "-nokeys", "-noout",
                               "-legacy"], { stdio: "pipe" });
          }
          // The private key has to come out too, and with the certificate —
          // a .p12 holding one without the other imports as the wrong thing.
          const dump = openssl(["pkcs12", "-in", file, "-passin",
                                "pass:" + PASSWORD, "-nodes"],
                               { stdio: "pipe" });
          assert.ok(/-----BEGIN (ENCRYPTED )?PRIVATE KEY-----/.test(dump),
            label + ": the PKCS#12 has no private key in it");
          assert.ok(/-----BEGIN CERTIFICATE-----/.test(dump),
            label + ": the PKCS#12 has no certificate in it, so it imports " +
            "as a bare key rather than as an identity");
          assert.ok(dump.indexOf("format test " + algId) >= 0,
            label + ": the PKCS#12 carries a different certificate than the " +
            "one it was given");
          assert.throws(function () {
            openssl(["pkcs12", "-in", file, "-passin", "pass:wrong",
                     "-nokeys", "-noout"], { stdio: "pipe" });
          }, label + ": the wrong password opened the PKCS#12");
        }
        log.debug(label + ": ok");
      }
    }
  }
  log.info("Produced and read back " + cells + " keystore files.");
  assert.ok(cells >= 45,
    "only " + cells + " cells of the export matrix were exercised");
  log.debug("Leaving everyFormatIsReadableByOpenssl().");
}

// ---------------------------------------------------------------------------
// 3. A PKCS#12 carrying a whole CHAIN, which is what makes it importable as a
//    client identity rather than as a key with a stranger attached.
// ---------------------------------------------------------------------------
async function pkcs12CarriesTheWholeChain() {
  log.debug("Entering pkcs12CarriesTheWholeChain().");
  const rootKey = await keyFor("rsa-2048");
  const root = await x509.issueCertificate({
    profile: "root-ca", subject: "CN=P12 Root,O=idptools",
    subjectPublicKey: rootKey.publicPem,
    issuerPrivateKey: rootKey.privatePem, signatureAlg: "sha256-rsa",
    extensions: x509.defaultExtensions("root-ca")
  });
  const clientKey = await keyFor("ec-p256");
  const client = await x509.issueCertificate({
    profile: "tls-client", subject: "CN=P12 Client,O=idptools",
    subjectPublicKey: clientKey.publicPem,
    issuer: { certificatePem: root.pem, privateKeyPem: rootKey.privatePem,
             keyAlg: "rsa-2048" },
    signatureAlg: "sha256-rsa",
    extensions: x509.defaultExtensions("tls-client")
  });
  const result = await keys.exportKeyPair({
    format: "pkcs12", privatePem: clientKey.privatePem,
    publicPem: clientKey.publicPem, desc: keys.keyAlg("ec-p256"),
    password: PASSWORD, baseName: "identity",
    certs: [client.pem, root.pem]
  });
  const written = writeFiles(result);
  const dump = openssl(["pkcs12", "-in", written["identity.p12"], "-passin",
                        "pass:" + PASSWORD, "-nodes"], { stdio: "pipe" });
  const certCount = (dump.match(/-----BEGIN CERTIFICATE-----/g) || []).length;
  assert.strictEqual(certCount, 2,
    "expected the leaf and its root in the keystore, found " + certCount);
  assert.ok(dump.indexOf("P12 Client") >= 0 && dump.indexOf("P12 Root") >= 0,
    "the chain in the keystore is not the chain that was passed in");
  assert.ok(result.status.indexOf("2 certificate") >= 0,
    "the status line should say how many certificates went in: " +
    result.status);
  log.debug("Leaving pkcs12CarriesTheWholeChain().");
}

// ---------------------------------------------------------------------------
// 4. The refusals, by name.
// ---------------------------------------------------------------------------
async function refusalsSayWhichMistakeItWas() {
  log.debug("Entering refusalsSayWhichMistakeItWas().");
  const pair = await keyFor("ec-p256");
  const desc = keys.keyAlg("ec-p256");
  const cert = await certFor("ec-p256");

  async function refuses(options, pattern, what) {
    log.debug("Entering refuses(). what=" + what);
    let threw = null;
    try {
      await keys.exportKeyPair(options);
    } catch (e) {
      threw = e;
    }
    assert.ok(threw, what + " was accepted and should not have been");
    assert.ok(pattern.test(threw.message),
      what + " was refused with the wrong message: " + threw.message);
    log.debug("Leaving refuses().");
  }

  await refuses({ format: "pkcs12", privatePem: pair.privatePem,
                 publicPem: pair.publicPem, desc: desc, certs: [cert.pem] },
    /password/i, "a PKCS#12 with no password");
  await refuses({ format: "pkcs12", privatePem: pair.privatePem,
                 publicPem: pair.publicPem, desc: desc, password: PASSWORD,
                 certs: [] },
    /certificate/i, "a PKCS#12 with no certificate to wrap the key in");
  await refuses({ format: "nonsense", privatePem: pair.privatePem,
                 publicPem: pair.publicPem, desc: desc },
    /unknown keystore format/i, "an unknown keystore format");
  await refuses({ format: "pem", privatePem: "", publicPem: "", desc: desc },
    /no key pair/i, "an export with no key pair at all");
  await refuses({ format: "pem", privatePem: "abc", publicPem: "def",
                 desc: { kind: "hmac" } },
    /only jwk/i, "an HMAC secret exported as PEM");

  // And the one that is NOT a refusal any more, which is worth an assertion of
  // its own: PKCS#12 for Ed25519. It used to be refused, and the refusal was
  // misattributed — PKCS#12 carries the key perfectly well; what failed was
  // building the certificate to wrap it in, because pkijs cannot import an
  // Ed25519 public key. client/src/x509.js does that by hand now.
  const edPair = await keyFor("ed25519");
  const edCert = await certFor("ed25519");
  const edResult = await keys.exportKeyPair({
    format: "pkcs12", privatePem: edPair.privatePem,
    publicPem: edPair.publicPem, desc: keys.keyAlg("ed25519"),
    password: PASSWORD, baseName: "ed25519", certs: [edCert.pem]
  });
  const written = writeFiles(edResult);
  const dump = openssl(["pkcs12", "-in", written["ed25519.p12"], "-passin",
                        "pass:" + PASSWORD, "-nodes"], { stdio: "pipe" });
  assert.ok(/-----BEGIN PRIVATE KEY-----/.test(dump) &&
      /-----BEGIN CERTIFICATE-----/.test(dump),
    "openssl could not read an Ed25519 PKCS#12 back, so the refusal that " +
    "was removed should not have been");
  log.debug("Leaving refusalsSayWhichMistakeItWas().");
}

// ---------------------------------------------------------------------------
// 5. The PEM/JWK conversion the panes' format toggle runs on.
// ---------------------------------------------------------------------------
async function pemAndJwkConvertBothWays() {
  log.debug("Entering pemAndJwkConvertBothWays().");
  for (const algId of keys.keyAlgIds()) {
    const pair = await keyFor(algId);
    const desc = keys.keyAlg(algId);
    const privJwk = await keys.privToJwk(pair.privatePem, desc, "RS256",
        "sig");
    const pubJwk = await keys.pubToJwk(pair.publicPem, desc, "RS256", "sig");
    assert.ok(privJwk.d, algId + ": the private JWK has no private component");
    assert.ok(!pubJwk.d, algId + ": the public JWK carries private material");
    assert.strictEqual(privJwk.alg, "RS256",
      algId + ": the JOSE alg was not stamped on the JWK");
    assert.ok(!("key_ops" in privJwk) && !("ext" in privJwk),
      algId + ": Web Crypto's key_ops/ext leaked into the exported JWK, and " +
      "they are what makes a re-import fail when the usages disagree");
    const backPriv = await keys.privToPem(JSON.stringify(privJwk), desc);
    const backPub = await keys.pubToPem(JSON.stringify(pubJwk), desc);
    assert.strictEqual(backPriv.trim(), pair.privatePem.trim(),
      algId + ": the private key did not survive PEM -> JWK -> PEM");
    assert.strictEqual(backPub.trim(), pair.publicPem.trim(),
      algId + ": the public key did not survive PEM -> JWK -> PEM");
    // asPrivatePem/asPublicPem take either form, which is what the panes call
    // when they do not know which the field holds.
    assert.strictEqual(
      (await keys.asPrivatePem(JSON.stringify(privJwk), desc)).trim(),
      pair.privatePem.trim(), algId + ": asPrivatePem() did not accept a JWK");
    assert.strictEqual((await keys.asPublicPem(pair.publicPem, desc)).trim(),
      pair.publicPem.trim(), algId + ": asPublicPem() mangled a PEM");
  }
  log.debug("Leaving pemAndJwkConvertBothWays().");
}

// ---------------------------------------------------------------------------
// 6. describePublicPem() reads a PASTED key's algorithm off the key itself.
//    A stored key remembers what it is; a pasted one does not, and importing
//    an EC key as RSA fails with "Unsupported key", which names neither.
// ---------------------------------------------------------------------------
async function apastedPublicKeyIsIdentifiedFromItsBytes() {
  log.debug("Entering apastedPublicKeyIsIdentifiedFromItsBytes().");
  const expected = {
    "rsa-2048": { kind: "rsa", bits: 2048 },
    "rsa-3072": { kind: "rsa", bits: 3072 },
    "rsa-4096": { kind: "rsa", bits: 4096 },
    "ec-p256": { kind: "ec", curve: "P-256" },
    "ec-p384": { kind: "ec", curve: "P-384" },
    "ec-p521": { kind: "ec", curve: "P-521" },
    "ed25519": { kind: "okp" }
  };
  for (const algId of keys.keyAlgIds()) {
    const pair = await keyFor(algId);
    const described = await keys.describePublicPem(pair.publicPem);
    assert.ok(described, algId + ": the key was not recognised at all");
    assert.strictEqual(described.kind, expected[algId].kind,
      algId + ": read as " + described.kind);
    if (expected[algId].curve) {
      assert.strictEqual(described.curve, expected[algId].curve,
        algId + ": read as curve " + described.curve);
    }
    if (expected[algId].bits) {
      assert.strictEqual(described.bits, expected[algId].bits,
        algId + ": read as " + described.bits + " bits");
    }
  }
  const nonsense = await keys.describePublicPem(
    "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n");
  assert.strictEqual(nonsense, null,
    "an unreadable key must come back as null rather than as a guess");
  log.debug("Leaving apastedPublicKeyIsIdentifiedFromItsBytes().");
}

// ---------------------------------------------------------------------------
// 7. The HMAC secret, the one thing here that is not a key pair.
// ---------------------------------------------------------------------------
async function hmacSecretsExportAsOctJwkOnly() {
  log.debug("Entering hmacSecretsExportAsOctJwkOnly().");
  const secret = keys.generateSecret(32);
  assert.ok(/^[A-Za-z0-9_-]+$/.test(secret),
    "a generated secret must be base64url: " + secret);
  assert.strictEqual(Buffer.from(secret, "base64url").length, 32,
    "a 32-byte secret was asked for");
  const result = await keys.exportKeyPair({ format: "jwk",
    privatePem: secret, desc: { kind: "hmac" }, baseName: "secret",
    alg: "HS256", use: "sig" });
  const written = writeFiles(result);
  const jwk = JSON.parse(fs.readFileSync(written["secret.jwk.json"], "utf8"));
  assert.strictEqual(jwk.kty, "oct", "an HMAC secret is an oct JWK");
  assert.strictEqual(jwk.k, secret, "the secret did not survive the export");
  assert.strictEqual(jwk.alg, "HS256", "the JOSE alg was not carried over");
  let threw = null;
  try {
    await keys.generateKeyPair({ kind: "hmac" });
  } catch (e) {
    threw = e;
  }
  assert.ok(threw && /symmetric/i.test(threw.message),
    "generateKeyPair() must refuse HMAC by name rather than return " +
    "something shaped like a key pair");
  log.debug("Leaving hmacSecretsExportAsOctJwkOnly().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. Verifying client/src/key_material.js against " +
      "OpenSSL.");
  try {
    execFileSync("openssl", ["version"], { encoding: "utf8" });
  } catch (e) {
    throw new Error("openssl is not on the PATH. A keystore is a format " +
      "somebody else's tool has to read, so this test asks one; it cannot be " +
      "run without it. (tests/Dockerfile installs it.)");
  }
  await everyAlgorithmGeneratesAKeyOpensslRecognises();
  await pemAndJwkConvertBothWays();
  await apastedPublicKeyIsIdentifiedFromItsBytes();
  await hmacSecretsExportAsOctJwkOnly();
  await everyFormatIsReadableByOpenssl();
  await pkcs12CarriesTheWholeChain();
  await refusalsSayWhichMistakeItWas();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("pki_key_formats")
  .description("Verify key generation and every keystore format (PEM, DER, " +
      "JWK, PKCS#12, encrypted and not) against OpenSSL.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
      "needs no browser)"))
  .parse(process.argv);

test().then(function () {
  if (workDir) fs.rmSync(workDir, { recursive: true, force: true });
}).catch(function (e) {
  log.error(e.stack || e.message);
  if (workDir) fs.rmSync(workDir, { recursive: true, force: true });
  process.exit(1);
});
