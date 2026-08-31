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
// ---------------------------------------------------------------------------
// THE POST-QUANTUM ROWS ASK A DIFFERENT OPENSSL, AND ONE CELL IS A KNOWN GAP
//
// The `openssl` binary's version is whatever the base image or the developer's
// machine ships, and 3.0 — Ubuntu 22.04's — has no ML-DSA, SLH-DSA or ML-KEM.
// Node's OpenSSL moves with the node version, which every image here pins at
// 24.16 (OpenSSL 3.5.6), so the generation and PEM/DER rows for those keys are
// checked through tests/openssl35.js — the same library, a different door, and
// the same answer on every machine. See its header.
//
// PKCS#12 is where that runs out. The container is read by the 3.0 binary
// perfectly — it verifies the MAC with the password and prints the certificate
// bag — and then cannot decode the KEY inside it, because that is an ML-DSA
// PKCS#8. Node exposes no PKCS#12 reader at all. So a post-quantum .p12 is
// asserted here as far as another implementation can go (structure, MAC,
// certificate) and no further, and this comment is the record of why rather
// than a missing assertion nobody can explain later.
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
const oracle = require("./openssl35.js");

// The post-quantum algorithms this file's MATRIX uses, rather than all
// thirty-four. The matrix is (algorithms x 4 formats x 2 passwords) and each
// extra row costs a key pair and up to eight files, while what these rows
// exercise — how an opaque key is wrapped in PEM, DER, JWK and PKCS#12 — does
// not vary between parameter sets of one family. One per family, plus a
// composite, whose JWK export is a deliberate refusal. Every algorithm's own
// ENCODING is covered certificate by certificate in tests/pki_pqc_x509.js, and
// generation below still covers all of them.
const POST_QUANTUM_SAMPLE = ["ml-dsa-44", "slh-dsa-sha2-128f", "ml-kem-768",
                             "mldsa44-ecdsa-p256-sha256"];

function isPqc(algId) {
  log.debug("Entering isPqc(). alg=" + algId);
  const yes = keys.keyAlg(algId).kind === "pqc";
  log.debug("Leaving isPqc(). " + yes);
  return yes;
}

function classicalAlgIds() {
  log.debug("Entering classicalAlgIds().");
  const out = keys.keyAlgIds().filter(function (id) {
    return !isPqc(id);
  });
  log.debug("Leaving classicalAlgIds(). " + out.length + " of them.");
  return out;
}

function matrixAlgIds() {
  log.debug("Entering matrixAlgIds().");
  const out = classicalAlgIds().concat(POST_QUANTUM_SAMPLE);
  log.debug("Leaving matrixAlgIds(). " + out.length + " of them.");
  return out;
}

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
    const spec = {
      profile: "tls-client",
      subject: "CN=format test " + algId + ",O=idptools",
      subjectPublicKey: pair.publicPem,
      extensions: x509.defaultExtensions("tls-client")
    };
    if (x509.signatureAlgorithmsFor(desc).length) {
      spec.issuerPrivateKey = pair.privatePem;
      spec.signatureAlg = x509.defaultSignatureAlgorithm(desc);
    } else {
      // A key-encapsulation key: it has no signature algorithm at all, so the
      // certificate over it is issued by a CA rather than self-signed. This
      // is not a workaround — it is the only shape RFC 9935 allows.
      const caKey = await keyFor("ml-dsa-65");
      const ca = await x509.issueCertificate({
        profile: "root-ca", subject: "CN=format test issuer,O=idptools",
        subjectPublicKey: caKey.publicPem,
        issuerPrivateKey: caKey.privatePem, signatureAlg: "ml-dsa-65",
        extensions: x509.defaultExtensions("root-ca")
      });
      spec.issuer = { certificatePem: ca.pem, privateKeyPem: caKey.privatePem,
                     keyAlg: "ml-dsa-65" };
      spec.signatureAlg = "ml-dsa-65";
    }
    certCache[algId] = await x509.issueCertificate(spec);
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
  assert.deepStrictEqual(classicalAlgIds().slice().sort(),
    Object.keys(expected).sort(),
    "the classical key algorithm list and this test's expectations have " +
    "diverged — a new algorithm with no expectation here is one nothing " +
    "checks");
  for (const algId of keys.keyAlgIds()) {
    const pair = await keyFor(algId);
    assert.ok(/^-----BEGIN PRIVATE KEY-----/.test(pair.privatePem),
      algId + ": the private key is not a PKCS#8 PEM");
    assert.ok(/^-----BEGIN PUBLIC KEY-----/.test(pair.publicPem),
      algId + ": the public key is not a SubjectPublicKeyInfo PEM");
    if (isPqc(algId)) {
      await aPostQuantumKeyIsWhatOpensslReadsBack(algId, pair);
      continue;
    }
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

// The same two questions asked of a post-quantum key: does another
// implementation read it as the algorithm it claims to be, and does the public
// half belong to the private one. The oracle is node's OpenSSL 3.5 rather than
// the 3.0 binary, and for the composites — which no released OpenSSL knows —
// it is this build's own decoder plus the requirement that OpenSSL REFUSE the
// key rather than read it as something else.
async function aPostQuantumKeyIsWhatOpensslReadsBack(algId, pair) {
  log.debug("Entering aPostQuantumKeyIsWhatOpensslReadsBack(). alg=" + algId);
  const desc = keys.keyAlg(algId);
  const described = await keys.describePublicPem(pair.publicPem);
  assert.strictEqual(described.kind, "pqc",
    algId + ": its own public key was not recognised as post-quantum");
  assert.strictEqual(described.id, algId,
    algId + ": its own public key reads back as " + described.id);
  const privateDesc = keys.describePrivatePem(pair.privatePem);
  assert.strictEqual(privateDesc.id, algId,
    algId + ": its own private key reads back as " +
    (privateDesc && privateDesc.id));
  if (!oracle.available()) {
    log.warn(algId + ": " + oracle.unavailableReason());
    log.debug("Leaving aPostQuantumKeyIsWhatOpensslReadsBack(). Skipped.");
    return;
  }
  if (desc.family === "Composite ML-DSA") {
    assert.strictEqual(oracle.keyTypeOf(pair.publicPem), null,
      algId + ": OpenSSL read a composite key as something — if a release " +
      "has implemented draft-ietf-lamps-pq-composite-sigs, this test should " +
      "start asking it rather than asserting ignorance");
    log.debug("Leaving aPostQuantumKeyIsWhatOpensslReadsBack(). Composite.");
    return;
  }
  assert.strictEqual(oracle.keyTypeOf(pair.publicPem), algId,
    algId + ": OpenSSL 3.5 reads this public key as something else");
  assert.strictEqual(oracle.privateKey(pair.privatePem).asymmetricKeyType,
    algId, algId + ": OpenSSL 3.5 reads this private key as something else");
  // The public half, derived by OPENSSL from the private key, must be the one
  // this build wrote out — the same check `openssl pkey -pubout` makes above.
  const derived = oracle.publicFromPrivate(pair.privatePem);
  assert.strictEqual(derived.trim(), pair.publicPem.trim(),
    algId + ": OpenSSL derives a different public key from this private key");
  log.debug("Leaving aPostQuantumKeyIsWhatOpensslReadsBack().");
}

// An export that must be refused, with a message that says which mistake it
// was. Module-level rather than nested inside case 6, because the export
// matrix has a refusal cell of its own now — the composite JWK — and two
// copies of this would be two chances to check it differently.
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

// The PEM bundle of a post-quantum export, read by node's OpenSSL 3.5. The
// bundle is a private key, a public key and a certificate concatenated, and
// createPrivateKey/createPublicKey each read the first block of their own
// kind — which is exactly what a consumer of this file does.
function postQuantumPemIsReadable(algId, label, file, password) {
  log.debug("Entering postQuantumPemIsReadable(). alg=" + algId);
  if (!oracle.available()) {
    log.warn(label + ": " + oracle.unavailableReason());
    log.debug("Leaving postQuantumPemIsReadable(). Skipped.");
    return;
  }
  const text = fs.readFileSync(file, "utf8");
  if (keys.keyAlg(algId).family === "Composite ML-DSA") {
    // No released OpenSSL implements the composite draft, so the check is
    // that the bundle is otherwise well formed: the three PEM blocks are
    // there and the certificate — whose own encoding is ordinary DER — is
    // readable by the 3.0 binary.
    assert.ok(/-----BEGIN CERTIFICATE-----/.test(text),
      label + ": the certificate is missing from the bundle");
    log.debug("Leaving postQuantumPemIsReadable(). Composite.");
    return;
  }
  const key = password
    ? oracle.privateKey({ key: text, passphrase: PASSWORD })
    : oracle.privateKey(text);
  assert.ok(key.asymmetricKeyType,
    label + ": OpenSSL 3.5 could not read the private key out of the bundle");
  log.debug("Leaving postQuantumPemIsReadable().");
}

function postQuantumDerIsReadable(algId, label, privFile, pubFile, password) {
  log.debug("Entering postQuantumDerIsReadable(). alg=" + algId);
  if (!oracle.available()) {
    log.warn(label + ": " + oracle.unavailableReason());
    log.debug("Leaving postQuantumDerIsReadable(). Skipped.");
    return;
  }
  if (keys.keyAlg(algId).family === "Composite ML-DSA") {
    log.debug("Leaving postQuantumDerIsReadable(). Composite.");
    return;
  }
  const privDer = fs.readFileSync(privFile);
  // An encrypted PKCS#8 is an EncryptedPrivateKeyInfo and node reads it with
  // the same type name plus a passphrase, which is the one thing about this
  // API that is not obvious.
  const opts = { key: privDer, format: "der", type: "pkcs8" };
  if (password) opts.passphrase = PASSWORD;
  assert.ok(oracle.privateKey(opts).asymmetricKeyType,
    label + ": OpenSSL 3.5 could not read the DER private key");
  assert.ok(oracle.publicKey({ key: fs.readFileSync(pubFile), format: "der",
                              type: "spki" }).asymmetricKeyType,
    label + ": OpenSSL 3.5 could not read the DER public key");
  log.debug("Leaving postQuantumDerIsReadable().");
}

// ---------------------------------------------------------------------------
// 2. The export matrix: every algorithm, every format, with and without a
//    password.
// ---------------------------------------------------------------------------
async function everyFormatIsReadableByOpenssl() {
  log.debug("Entering everyFormatIsReadableByOpenssl().");
  let cells = 0;
  for (const algId of matrixAlgIds()) {
    const pair = await keyFor(algId);
    const desc = keys.keyAlg(algId);
    // An ML-KEM key cannot sign, so it cannot self-sign the certificate a
    // PKCS#12 wraps it in — a real one is issued by somebody else. The
    // certificate for it therefore comes from an ML-DSA CA, which is also
    // what an encryption certificate looks like in practice.
    const cert = await certFor(algId);
    for (const format of keys.keystoreFormats()) {
      for (const password of ["", PASSWORD]) {
        const label = algId + "/" + format + (password ? " (encrypted)" : "");
        // PKCS#12 without a password is a refusal, checked by name below
        // rather than skipped silently here.
        if (format === "pkcs12" && !password) continue;
        // And so is a JWK of a COMPOSITE key, for a reason that is not a
        // limitation: the LAMPS serialization this build writes and the JOSE
        // one a JWK would be read as are different bytes for the same key.
        if (format === "jwk" &&
            keys.keyAlg(algId).family === "Composite ML-DSA") {
          await refuses({ format: "jwk", privatePem: pair.privatePem,
                         publicPem: pair.publicPem, desc: desc,
                         password: password },
              /JOSE/,
              algId + ": a composite key exported as a JWK");
          cells += 1;
          continue;
        }
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
          if (isPqc(algId)) {
            postQuantumPemIsReadable(algId, label, file, password);
          } else {
            const args = ["pkey", "-in", file, "-noout", "-text"];
            if (password) args.push("-passin", "pass:" + PASSWORD);
            const text = openssl(args);
            assert.ok(text.length > 0, label + ": openssl read nothing back");
          }
          const pem = fs.readFileSync(file, "utf8");
          if (password) {
            assert.ok(/-----BEGIN ENCRYPTED PRIVATE KEY-----/.test(pem),
              label + ": a password was supplied and the private key was " +
              "written in the clear anyway");
            // And the password must actually be required, or "encrypted" is
            // a label rather than a fact. For a post-quantum key the refusal
            // has to come from the KDF rather than from OpenSSL 3.0 not
            // knowing the algorithm, so it is asked of node's 3.5.
            if (isPqc(algId)) {
              assert.throws(function () {
                oracle.privateKey({ key: fs.readFileSync(file, "utf8"),
                                   passphrase: "wrong-password" });
              }, label + ": the wrong password opened the private key");
            } else {
              assert.throws(function () {
                openssl(["pkey", "-in", file, "-noout", "-passin",
                         "pass:wrong-password"], { stdio: "pipe" });
              }, label + ": the wrong password opened the private key");
            }
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
          if (isPqc(algId)) {
            postQuantumDerIsReadable(algId, label, priv,
                written["export-public.der"], password);
          } else {
            const args = ["pkey", "-inform", "der", "-in", priv, "-noout"];
            if (password) args.push("-passin", "pass:" + PASSWORD);
            openssl(args);
            openssl(["pkey", "-pubin", "-inform", "der", "-in",
                     written["export-public.der"], "-noout"]);
          }
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
          } else if (isPqc(algId)) {
            const set = JSON.parse(fs.readFileSync(written["export.jwk.json"],
                "utf8"));
            // RFC 9964: an AKP key has exactly `pub` and `priv`, and `alg` is
            // REQUIRED because the parameters are opaque octets that identify
            // nothing on their own.
            assert.strictEqual(set.keys.length, 2,
              label + ": a JWK set export is the public and private key");
            const priv = set.keys.filter(function (k) { return k.priv; })[0];
            const pub = set.keys.filter(function (k) { return !k.priv; })[0];
            assert.ok(priv && pub,
              label + ": the AKP JWK set has no public/private pair");
            [priv, pub].forEach(function (jwk) {
              assert.strictEqual(jwk.kty, "AKP",
                label + ": a post-quantum key exported as kty " + jwk.kty);
              assert.ok(jwk.alg,
                label + ": an AKP JWK without alg identifies no algorithm");
              assert.ok(!("x" in jwk) && !("d" in jwk),
                label + ": the pre-RFC 9964 x/d parameter names are back, " +
                "and no conforming implementation reads them");
            });
            assert.strictEqual(pub.pub, priv.pub,
              label + ": the two JWKs are not the same key");
            const back = await keys.privToPem(JSON.stringify(priv), desc);
            assert.strictEqual(back.trim(), pair.privatePem.trim(),
              label + ": the AKP JWK does not convert back to the key it " +
              "came from");
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
          if (isPqc(algId)) {
            // As far as OpenSSL 3.0 can go: it opened the file, verified the
            // MAC with the password (that is what -nokeys -info does) and
            // read the certificate bag. Decoding the KEY needs 3.5, and node
            // — which has 3.5 — has no PKCS#12 reader at all. See the header.
            const info = openssl(["pkcs12", "-in", file, "-passin",
                                  "pass:" + PASSWORD, "-nokeys", "-info"],
                                 { stdio: "pipe" });
            assert.ok(info.indexOf("format test " + algId) >= 0,
              label + ": the PKCS#12 carries a different certificate than " +
              "the one it was given");
            assert.throws(function () {
              openssl(["pkcs12", "-in", file, "-passin", "pass:wrong",
                       "-nokeys", "-noout"], { stdio: "pipe" });
            }, label + ": the wrong password opened the PKCS#12");
            log.debug(label + ": ok (certificate bag and MAC only)");
            continue;
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
    if (isPqc(algId)) {
      await akpJwksConvertBothWays(algId, pair, desc);
      continue;
    }
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

// The post-quantum half of case 5. RFC 9964's AKP has two parameters and an
// `alg` that is not decoration: `pub` and `priv` are opaque octets and nothing
// but `alg` says what algorithm they belong to. The composites have no JWK
// form here at all, and that refusal is part of the round trip rather than a
// gap in it — see the note in key_material.js.
async function akpJwksConvertBothWays(algId, pair, desc) {
  log.debug("Entering akpJwksConvertBothWays(). alg=" + algId);
  if (desc.family === "Composite ML-DSA") {
    let threw = null;
    try {
      await keys.pubToJwk(pair.publicPem, desc);
    } catch (e) {
      threw = e;
    }
    assert.ok(threw && /JOSE/.test(threw.message),
      algId + ": a composite key produced a JWK, and the JOSE and X.509 " +
      "serializations of one are different bytes");
    log.debug("Leaving akpJwksConvertBothWays(). Composite refused.");
    return;
  }
  const privJwk = await keys.privToJwk(pair.privatePem, desc, null, "sig");
  const pubJwk = await keys.pubToJwk(pair.publicPem, desc, null, "sig");
  assert.strictEqual(privJwk.kty, "AKP",
    algId + ": exported as kty " + privJwk.kty);
  assert.ok(privJwk.priv, algId + ": the private JWK has no private half");
  assert.ok(!pubJwk.priv, algId + ": the public JWK carries private material");
  // The `alg` is the algorithm's own name as its standard spells it —
  // ML-DSA-44, SLH-DSA-SHAKE-128f — which is what the registry holds and what
  // an AKP JWK has to carry to be readable at all.
  assert.strictEqual(privJwk.alg, desc.pqc,
    algId + ": the AKP alg is " + privJwk.alg);
  const backPriv = await keys.privToPem(JSON.stringify(privJwk), desc);
  const backPub = await keys.pubToPem(JSON.stringify(pubJwk), desc);
  assert.strictEqual(backPriv.trim(), pair.privatePem.trim(),
    algId + ": the private key did not survive PEM -> JWK -> PEM");
  assert.strictEqual(backPub.trim(), pair.publicPem.trim(),
    algId + ": the public key did not survive PEM -> JWK -> PEM");
  log.debug("Leaving akpJwksConvertBothWays().");
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
    if (isPqc(algId)) {
      // A post-quantum SPKI names its algorithm in an OID, so this is a
      // lookup rather than the trial-import the classical families need —
      // and it has to happen FIRST, since every one of those imports would
      // fail on it slowly and blame the wrong thing.
      assert.strictEqual(described.kind, "pqc",
        algId + ": read as " + described.kind);
      assert.strictEqual(described.id, algId,
        algId + ": read as " + described.id);
      assert.strictEqual(described.family, keys.keyAlg(algId).family,
        algId + ": read as family " + described.family);
      continue;
    }
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
