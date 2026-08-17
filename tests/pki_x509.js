// File: pki_x509.js
//
// client/src/x509.js — certificate authoring, checked against OpenSSL.
//
// ---------------------------------------------------------------------------
// WHY THIS TEST IS THE IMPORTANT ONE FOR THE PKI PAGE
//
// A certificate that is wrong is not a certificate that looks wrong. Every
// defect this test exists to catch produces bytes that parse perfectly, display
// plausibly in `openssl x509 -text`, and are then refused by something else
// entirely — usually with a message about a signature, which sends you looking
// at the key. Four of them were real, and all four were found here:
//
//   * pkijs builds a Name as ONE RDN holding every attribute (a multi-valued
//     RDN, rendered by OpenSSL with `+` between the attributes) rather than as
//     the RDNSequence a Name is. It parses; it is simply a different name, so
//     nothing chains to it.
//   * pkijs's GeneralName wraps an otherName in a SECOND [0] tag. `openssl
//     x509 -text` prints the name; `openssl verify` refuses the certificate
//     with `ossl_x509v3_cache_extensions:reason(158)`, naming no extension, no
//     name and no field.
//   * the hash a signing key is IMPORTED with is the hash pkijs writes into
//     signatureAlgorithm, so importing at SHA-256 and signing at SHA-512 gives
//     a certificate whose declared algorithm and actual signature disagree.
//   * a notAfter at or after 2050 must be a GeneralizedTime; encoded as a
//     UTCTime it reads as 1950, i.e. a certificate that expired seventy years
//     ago, reported by every validator as expired and by none as misencoded.
//
// So the assertions here are made by OPENSSL wherever they can be — `openssl
// verify` on a real chain, and `openssl x509 -text` on the extensions — rather
// than by reading back what this codebase just wrote with the same codebase.
// A round trip through one implementation cannot catch any of the four above.
//
// The matrix is the whole cross product the page offers: every signature
// algorithm a key family can produce, against every subject key algorithm. It
// is ~240 certificates and takes a few seconds, because "we support every
// combination" is a claim that is only worth making if every combination has
// been made at least once.
//
// Node only — no browser, no services, no network — so it never skips.
// ---------------------------------------------------------------------------
const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");
const { Command, Option } = require("commander");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "pki_x509",
    level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

// In a checkout these are under client/src; the tests image copies them flat
// beside the test scripts (see tests/Dockerfile). Resolved through
// module_paths.js so both layouts work and a missing COPY fails with a pointed
// message rather than a bare MODULE_NOT_FOUND.
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

var workDir = null;

function tempDir() {
  log.debug("Entering tempDir().");
  if (!workDir) {
    workDir = fs.mkdtempSync(path.join(os.tmpdir(), "pki-x509-"));
  }
  log.debug("Leaving tempDir().");
  return workDir;
}

function writePem(name, pem) {
  log.debug("Entering writePem().");
  const file = path.join(tempDir(), name);
  fs.writeFileSync(file, pem);
  log.debug("Leaving writePem().");
  return file;
}

// `openssl x509 -text` for a certificate, so the assertions below are about
// what ANOTHER implementation reads rather than about what this one wrote.
function opensslText(pem) {
  log.debug("Entering opensslText().");
  const file = writePem("subject.pem", pem);
  const out = execFileSync("openssl",
      ["x509", "-in", file, "-noout", "-text"], { encoding: "utf8" });
  log.debug("Leaving opensslText().");
  return out;
}

// `openssl verify`, returning {ok, output}. A FAILURE is a result here as often
// as a success is — the name-constraint and pathLen cases below are asserting
// that OpenSSL refuses something.
function opensslVerify(leafPem, rootPem, untrustedPems) {
  log.debug("Entering opensslVerify().");
  const leaf = writePem("verify-leaf.pem", leafPem);
  const root = writePem("verify-root.pem", rootPem);
  const args = ["verify", "-CAfile", root];
  if (untrustedPems && untrustedPems.length) {
    const chain = writePem("verify-chain.pem", untrustedPems.join(""));
    args.push("-untrusted", chain);
  }
  args.push(leaf);
  let output = "";
  let ok = false;
  try {
    output = execFileSync("openssl", args, { encoding: "utf8",
        stdio: ["pipe", "pipe", "pipe"] });
    ok = /: OK\s*$/.test(output.trim() + "\n") || /\bOK\b/.test(output);
  } catch (e) {
    output = String((e.stdout || "") + (e.stderr || "")) || e.message;
    ok = false;
  }
  log.debug("Leaving opensslVerify(). ok=" + ok);
  return { ok: ok, output: output.trim() };
}

// One key pair per algorithm, generated once. RSA-4096 generation is the
// slowest thing in this file by an order of magnitude, and the matrix below
// would otherwise pay for it 30-odd times.
var keyCache = {};

async function keyFor(algId) {
  log.debug("Entering keyFor(). alg=" + algId);
  if (!keyCache[algId]) {
    keyCache[algId] = await keys.generateKeyPair(algId);
  }
  log.debug("Leaving keyFor().");
  return keyCache[algId];
}

// ---------------------------------------------------------------------------
// 1. Every signature algorithm against every subject key algorithm.
// ---------------------------------------------------------------------------
async function everyAlgorithmCombinationIssuesAndVerifies() {
  log.debug("Entering everyAlgorithmCombinationIssuesAndVerifies().");
  const keyAlgs = keys.keyAlgIds();
  assert.ok(keyAlgs.length >= 7,
    "the key algorithm list has shrunk — this matrix is only meaningful if " +
    "it covers what the page offers");
  let issued = 0;
  let combinations = 0;
  for (const issuerAlg of keyAlgs) {
    const issuerKey = await keyFor(issuerAlg);
    const issuerDesc = keys.keyAlg(issuerAlg);
    const sigAlgs = x509.signatureAlgorithmsFor(issuerDesc);
    assert.ok(sigAlgs.length >= 1,
      issuerAlg + " can produce no signature algorithm at all, so no " +
      "certificate could ever be signed with it");
    for (const sigAlgId of sigAlgs) {
      // A self-signed CA per (issuer key, signature algorithm), so the leaves
      // below are verified against a root signed the same way.
      const ca = await x509.issueCertificate({
        profile: "root-ca",
        subject: "CN=Matrix CA " + issuerAlg + " " + sigAlgId + ",O=idptools",
        subjectPublicKey: issuerKey.publicPem,
        issuerPrivateKey: issuerKey.privatePem,
        signatureAlg: sigAlgId,
        extensions: x509.defaultExtensions("root-ca")
      });
      assert.strictEqual(ca.signatureAlg, sigAlgId,
        "the issued CA reports a different signature algorithm than the one " +
        "asked for");
      // The DECLARED algorithm has to be the one that was used, and only
      // OpenSSL can say so — it is what verifies the signature.
      const caText = opensslText(ca.pem);
      const wantedOid = x509.sigAlg(sigAlgId);
      assert.ok(/Signature Algorithm:/.test(caText),
        "openssl could not read the CA issued with " + sigAlgId);
      combinations += 1;

      for (const subjectAlg of keyAlgs) {
        const subjectKey = await keyFor(subjectAlg);
        const leaf = await x509.issueCertificate({
          profile: "tls-server",
          subject: "CN=matrix-leaf." + subjectAlg + ".example,O=idptools",
          subjectPublicKey: subjectKey.publicPem,
          issuer: { certificatePem: ca.pem,
                   privateKeyPem: issuerKey.privatePem, keyAlg: issuerAlg },
          signatureAlg: sigAlgId,
          extensions: (function () {
            const ext = x509.defaultExtensions("tls-server");
            ext.subjectAltName = { present: true, critical: false,
                names: [{ kind: "dns", value: "matrix-leaf.example" }] };
            return ext;
          })()
        });
        const verdict = opensslVerify(leaf.pem, ca.pem);
        assert.ok(verdict.ok,
          "openssl refused a " + subjectAlg + " leaf signed by an " +
          issuerAlg + " CA using " + sigAlgId + ": " + verdict.output);
        issued += 1;
      }
      // And this codebase's own chain check has to agree with OpenSSL, or one
      // of the two is lying about the same bytes.
      const ownVerdict = await x509.verifyChain([ca.pem]);
      assert.strictEqual(ownVerdict[0].signatureValid, true,
        "verifyChain() says the " + sigAlgId + " self-signature is invalid " +
        "while openssl accepts it");
    }
  }
  log.info("Issued and verified " + issued + " leaf certificates over " +
    combinations + " (issuer key, signature algorithm) combinations.");
  assert.ok(issued >= 200,
    "the matrix issued only " + issued + " certificates — the algorithm " +
    "tables have shrunk and the claim that every combination works is no " +
    "longer being tested");
  log.debug("Leaving everyAlgorithmCombinationIssuesAndVerifies().");
}

// ---------------------------------------------------------------------------
// 2. The DN is an RDNSequence, not one multi-valued RDN.
//
// This is the pkijs default, and the give-away is the `+` OpenSSL prints
// between the attributes. A certificate whose issuer field is a multi-valued
// RDN chains to nothing, because the CA's own subject is the ordinary kind.
// ---------------------------------------------------------------------------
async function theSubjectIsAnRdnSequence() {
  log.debug("Entering theSubjectIsAnRdnSequence().");
  const key = await keyFor("ec-p256");
  const cert = await x509.issueCertificate({
    profile: "root-ca",
    subject: "CN=Sequence Test,O=Example,OU=Unit,C=US",
    subjectPublicKey: key.publicPem,
    issuerPrivateKey: key.privatePem,
    signatureAlg: "sha256-ecdsa",
    extensions: x509.defaultExtensions("root-ca")
  });
  const file = writePem("rdn.pem", cert.pem);
  const subject = execFileSync("openssl",
      ["x509", "-in", file, "-noout", "-subject"], { encoding: "utf8" });
  assert.ok(subject.indexOf("+") === -1,
    "the subject is a MULTI-VALUED RDN (openssl prints '+' between the " +
    "attributes): " + subject.trim() + ". A Name is a SEQUENCE of SETs, one " +
    "per attribute; this is a different name and nothing will chain to it.");
  assert.ok(/CN\s*=\s*Sequence Test/.test(subject) &&
      /O\s*=\s*Example/.test(subject) && /C\s*=\s*US/.test(subject),
    "the subject lost an attribute: " + subject.trim());
  // The order is the name. A reordered DN is a different DN.
  const order = ["CN", "O", "OU", "C"].map(function (name) {
    return subject.indexOf(name + " =");
  });
  for (let i = 1; i < order.length; i++) {
    assert.ok(order[i] > order[i - 1],
      "the DN attributes came out in a different order than they were " +
      "written (" + subject.trim() + "); an RDNSequence is ordered and a " +
      "reordered one is a different name");
  }
  log.debug("Leaving theSubjectIsAnRdnSequence().");
}

// ---------------------------------------------------------------------------
// 3. Every extension, one at a time, read back by OpenSSL.
// ---------------------------------------------------------------------------
async function everyExtensionIsWrittenAndReadBack() {
  log.debug("Entering everyExtensionIsWrittenAndReadBack().");
  const caKey = await keyFor("rsa-2048");
  const ca = await x509.issueCertificate({
    profile: "root-ca",
    subject: "CN=Extension Test CA,O=idptools",
    subjectPublicKey: caKey.publicPem,
    issuerPrivateKey: caKey.privatePem,
    signatureAlg: "sha256-rsa",
    extensions: x509.defaultExtensions("root-ca")
  });
  const leafKey = await keyFor("ec-p256");

  // Each case: what to switch on, and what OpenSSL must then print. The
  // expectations are OpenSSL's own words rather than this codebase's, which is
  // the point — a round trip through x509.js alone would pass with the
  // otherName bug in place.
  const cases = [
    { name: "keyUsage",
      apply: function (ext) {
        ext.keyUsage = { present: true, critical: true,
          usages: ["digitalSignature", "keyEncipherment", "keyAgreement",
                   "nonRepudiation", "dataEncipherment", "encipherOnly",
                   "decipherOnly"] };
      },
      expect: [/X509v3 Key Usage: critical/, /Digital Signature/,
               /Key Encipherment/, /Key Agreement/, /Non Repudiation/,
               /Encipher Only/, /Decipher Only/] },
    { name: "extendedKeyUsage",
      apply: function (ext) {
        ext.extKeyUsage = { present: true, critical: true,
          usages: ["serverAuth", "clientAuth", "codeSigning",
                   "emailProtection", "timeStamping", "ocspSigning",
                   "msSmartcardLogon", "kdcAuthentication",
                   "1.3.6.1.4.1.99999.5.5"] };
      },
      expect: [/X509v3 Extended Key Usage: critical/,
               /TLS Web Server Authentication/,
               /TLS Web Client Authentication/, /Code Signing/,
               /E-mail Protection/, /Time Stamping/, /OCSP Signing/,
               /1\.3\.6\.1\.4\.1\.311\.20\.2\.2|Microsoft Smartcard Login/,
               /1\.3\.6\.1\.4\.1\.99999\.5\.5/] },
    { name: "subjectAltName (every general name type)",
      apply: function (ext) {
        ext.subjectAltName = { present: true, critical: false, names: [
          { kind: "dns", value: "alt.example.com" },
          { kind: "ip", value: "192.0.2.10" },
          { kind: "ip", value: "2001:db8::1" },
          { kind: "email", value: "person@example.com" },
          { kind: "uri", value: "https://example.com/resource" },
          { kind: "upn", value: "person@EXAMPLE.COM" },
          { kind: "krb5", value: "host/server@EXAMPLE.COM" },
          { kind: "registeredID", value: "1.3.6.1.4.1.99999.9" },
          { kind: "dirName", value: "CN=alt name,O=Example" }
        ] };
      },
      expect: [/DNS:alt\.example\.com/, /IP Address:192\.0\.2\.10/,
               /IP Address:2001:DB8:0:0:0:0:0:1|IP Address:2001:db8/i,
               /email:person@example\.com/,
               /URI:https:\/\/example\.com\/resource/,
               /othername:.*person@EXAMPLE\.COM/,
               /othername:.*host\/server@EXAMPLE\.COM/,
               /Registered ID:1\.3\.6\.1\.4\.1\.99999\.9/,
               /DirName:.*alt name/] },
    { name: "issuerAltName",
      apply: function (ext) {
        ext.issuerAltName = { present: true, critical: false,
          names: [{ kind: "uri", value: "https://ca.example.com/" }] };
      },
      expect: [/X509v3 Issuer Alternative Name/,
               /URI:https:\/\/ca\.example\.com\//] },
    { name: "cRLDistributionPoints",
      apply: function (ext) {
        ext.cRLDistributionPoints = { present: true, critical: false,
          urls: ["http://crl.example.com/a.crl",
                 "http://crl2.example.com/a.crl"] };
      },
      expect: [/X509v3 CRL Distribution Points/,
               /URI:http:\/\/crl\.example\.com\/a\.crl/,
               /URI:http:\/\/crl2\.example\.com\/a\.crl/] },
    { name: "freshestCRL",
      apply: function (ext) {
        ext.freshestCRL = { present: true, critical: false,
          urls: ["http://crl.example.com/delta.crl"] };
      },
      expect: [/Freshest CRL/, /URI:http:\/\/crl\.example\.com\/delta\.crl/] },
    { name: "authorityInfoAccess",
      apply: function (ext) {
        ext.authorityInfoAccess = { present: true, critical: false, entries: [
          { method: "ocsp", url: "http://ocsp.example.com" },
          { method: "caIssuers", url: "http://example.com/ca.cer" }
        ] };
      },
      expect: [/Authority Information Access/,
               /OCSP - URI:http:\/\/ocsp\.example\.com/,
               /CA Issuers - URI:http:\/\/example\.com\/ca\.cer/] },
    { name: "subjectInfoAccess",
      apply: function (ext) {
        ext.subjectInfoAccess = { present: true, critical: false, entries: [
          { method: "caRepository", url: "http://example.com/certs/" }
        ] };
      },
      expect: [/Subject Information Access/,
               /URI:http:\/\/example\.com\/certs\//] },
    { name: "certificatePolicies with both qualifiers",
      apply: function (ext) {
        ext.certificatePolicies = { present: true, critical: false,
          policies: [{ oid: "1.3.6.1.4.1.99999.1.1",
                      cps: "https://example.com/cps",
                      notice: "Test certificates only" }] };
      },
      expect: [/X509v3 Certificate Policies/, /1\.3\.6\.1\.4\.1\.99999\.1\.1/,
               /CPS: https:\/\/example\.com\/cps/,
               /Test certificates only/] },
    { name: "privateKeyUsagePeriod",
      apply: function (ext) {
        ext.privateKeyUsagePeriod = { present: true, critical: false,
          notBefore: "2026-01-01T00:00:00Z",
          notAfter: "2027-06-30T12:00:00Z" };
      },
      expect: [/Private Key Usage Period/, /2026/, /2027/] },
    { name: "TLS Feature (must-staple)",
      apply: function (ext) {
        ext.tlsFeature = { present: true, critical: false, features: [5] };
      },
      expect: [/TLS Feature/, /status_request/] },
    { name: "id-pkix-ocsp-nocheck",
      apply: function (ext) {
        ext.ocspNoCheck = { present: true, critical: false };
      },
      expect: [/OCSP No Check|1\.3\.6\.1\.5\.5\.7\.48\.1\.5/] },
    { name: "Netscape certificate type and comment",
      apply: function (ext) {
        ext.netscapeCertType = { present: true, critical: false,
          types: ["sslClient", "sslServer"] };
        ext.netscapeComment = { present: true, critical: false,
          text: "issued by the debugger" };
      },
      expect: [/Netscape Cert Type/, /SSL Client/, /SSL Server/,
               /Netscape Comment/, /issued by the debugger/] },
    { name: "an arbitrary extension by OID",
      apply: function (ext) {
        // UTF8String "abc"
        ext.custom = [{ oid: "1.3.6.1.4.1.99999.7.7", critical: false,
                       value: Buffer.from([0x0c, 0x03, 0x61, 0x62, 0x63])
                         .toString("base64") }];
      },
      expect: [/1\.3\.6\.1\.4\.1\.99999\.7\.7/] }
  ];

  for (const testCase of cases) {
    const ext = x509.defaultExtensions("tls-server");
    testCase.apply(ext);
    const leaf = await x509.issueCertificate({
      profile: "tls-server",
      subject: "CN=extension-case.example,O=idptools",
      subjectPublicKey: leafKey.publicPem,
      issuer: { certificatePem: ca.pem, privateKeyPem: caKey.privatePem,
               keyAlg: "rsa-2048" },
      signatureAlg: "sha256-rsa",
      extensions: ext
    });
    const text = opensslText(leaf.pem);
    testCase.expect.forEach(function (pattern) {
      assert.ok(pattern.test(text),
        testCase.name + ": openssl did not report " + pattern + " in:\n" +
        text);
    });
    // And it must still verify — an extension that breaks verification is the
    // otherName failure mode, and reading the text does not catch it.
    const verdict = opensslVerify(leaf.pem, ca.pem);
    assert.ok(verdict.ok,
      testCase.name + ": openssl parsed the extension and then refused the " +
      "certificate: " + verdict.output);
    // The describer has to agree with OpenSSL about what is in there.
    const described = await x509.describeCertificate(leaf.pem);
    assert.ok(described.extensions.length > 0,
      testCase.name + ": describeCertificate() found no extensions at all");
    log.debug(testCase.name + ": ok");
  }
  log.info("Checked " + cases.length + " extension cases against openssl.");
  log.debug("Leaving everyExtensionIsWrittenAndReadBack().");
}

// ---------------------------------------------------------------------------
// 4. All of them at once — an extension set is not the sum of its parts, and a
//    certificate carrying twenty extensions is what an operator actually ends
//    up issuing.
// ---------------------------------------------------------------------------
async function theWholeExtensionSetAtOnce() {
  log.debug("Entering theWholeExtensionSetAtOnce().");
  const caKey = await keyFor("ec-p384");
  const ca = await x509.issueCertificate({
    profile: "root-ca",
    subject: "CN=Everything CA,O=idptools",
    subjectPublicKey: caKey.publicPem,
    issuerPrivateKey: caKey.privatePem,
    signatureAlg: "sha384-ecdsa",
    extensions: x509.defaultExtensions("root-ca")
  });
  const leafKey = await keyFor("rsa-3072");
  const ext = x509.defaultExtensions("tls-server-client");
  ext.subjectAltName = { present: true, critical: false, names: [
    { kind: "dns", value: "everything.example.com" },
    { kind: "ip", value: "203.0.113.5" },
    { kind: "upn", value: "user@EXAMPLE.COM" }
  ] };
  ext.issuerAltName = { present: true, critical: false,
    names: [{ kind: "uri", value: "https://ca.example.com/" }] };
  ext.cRLDistributionPoints = { present: true, critical: false,
    urls: ["http://crl.example.com/issuing.crl"] };
  ext.freshestCRL = { present: true, critical: false,
    urls: ["http://crl.example.com/delta.crl"] };
  ext.authorityInfoAccess = { present: true, critical: false, entries: [
    { method: "ocsp", url: "http://ocsp.example.com" },
    { method: "caIssuers", url: "http://example.com/issuing.cer" } ] };
  ext.subjectInfoAccess = { present: true, critical: false,
    entries: [{ method: "caRepository", url: "http://example.com/certs/" }] };
  ext.certificatePolicies = { present: true, critical: false,
    policies: [{ oid: "1.3.6.1.4.1.99999.1.1",
                cps: "https://example.com/cps", notice: "Everything" }] };
  ext.privateKeyUsagePeriod = { present: true, critical: false,
    notBefore: "2026-01-01T00:00:00Z", notAfter: "2027-01-01T00:00:00Z" };
  ext.tlsFeature = { present: true, critical: false, features: [5] };
  ext.netscapeCertType = { present: true, critical: false,
    types: ["sslClient", "sslServer"] };
  ext.netscapeComment = { present: true, critical: false, text: "all of it" };
  ext.custom = [{ oid: "1.3.6.1.4.1.99999.7.7", critical: false,
                 value: Buffer.from([0x05, 0x00]).toString("base64") }];
  const leaf = await x509.issueCertificate({
    profile: "tls-server-client",
    subject: "CN=everything.example.com,O=idptools,C=US",
    subjectPublicKey: leafKey.publicPem,
    issuer: { certificatePem: ca.pem, privateKeyPem: caKey.privatePem,
             keyAlg: "ec-p384" },
    signatureAlg: "sha384-ecdsa",
    extensions: ext
  });
  const verdict = opensslVerify(leaf.pem, ca.pem);
  assert.ok(verdict.ok,
    "a certificate carrying the full extension set was refused: " +
    verdict.output);
  const described = await x509.describeCertificate(leaf.pem);
  assert.ok(described.extensions.length >= 15,
    "expected at least 15 extensions, got " + described.extensions.length);
  described.extensions.forEach(function (e) {
    assert.ok(!e.parseError,
      "describeCertificate() could not read back the " + e.name +
      " extension it had just written: " + e.parseError);
  });
  log.debug("Leaving theWholeExtensionSetAtOnce().");
}

// ---------------------------------------------------------------------------
// 5. The four-deep hierarchy the page exists to build.
// ---------------------------------------------------------------------------
async function aRootIntermediateIssuingChainVerifies() {
  log.debug("Entering aRootIntermediateIssuingChainVerifies().");
  // Deliberately a different key algorithm at every level, and a different
  // signature algorithm at every hop: a hierarchy where every link is the same
  // shape is one where a mix-up cannot show.
  const rootKey = await keyFor("rsa-4096");
  const root = await x509.issueCertificate({
    profile: "root-ca", subject: "CN=Chain Root CA,O=idptools,C=US",
    subjectPublicKey: rootKey.publicPem,
    issuerPrivateKey: rootKey.privatePem,
    signatureAlg: "sha512-rsapss",
    extensions: x509.defaultExtensions("root-ca")
  });
  const interKey = await keyFor("ec-p384");
  const inter = await x509.issueCertificate({
    profile: "intermediate-ca",
    subject: "CN=Chain Intermediate CA,O=idptools,C=US",
    subjectPublicKey: interKey.publicPem,
    issuer: { certificatePem: root.pem, privateKeyPem: rootKey.privatePem,
             keyAlg: "rsa-4096" },
    signatureAlg: "sha512-rsapss",
    extensions: x509.defaultExtensions("intermediate-ca")
  });
  const issuingKey = await keyFor("ed25519");
  const issuing = await x509.issueCertificate({
    profile: "issuing-ca", subject: "CN=Chain Issuing CA,O=idptools,C=US",
    subjectPublicKey: issuingKey.publicPem,
    issuer: { certificatePem: inter.pem, privateKeyPem: interKey.privatePem,
             keyAlg: "ec-p384" },
    signatureAlg: "sha384-ecdsa",
    extensions: x509.defaultExtensions("issuing-ca")
  });
  const leafKey = await keyFor("ec-p256");
  const leafExt = x509.defaultExtensions("tls-server");
  leafExt.subjectAltName = { present: true, critical: false,
    names: [{ kind: "dns", value: "chain-leaf.example.com" }] };
  const leaf = await x509.issueCertificate({
    profile: "tls-server", subject: "CN=chain-leaf.example.com,O=idptools",
    subjectPublicKey: leafKey.publicPem,
    issuer: { certificatePem: issuing.pem,
             privateKeyPem: issuingKey.privatePem, keyAlg: "ed25519" },
    signatureAlg: "ed25519",
    extensions: leafExt
  });

  const verdict = opensslVerify(leaf.pem, root.pem, [inter.pem, issuing.pem]);
  assert.ok(verdict.ok,
    "openssl refused the four-deep chain: " + verdict.output);

  // The module's own chain check must agree, link by link.
  const links = await x509.verifyChain([leaf.pem, issuing.pem, inter.pem,
                                        root.pem]);
  assert.strictEqual(links.length, 4, "expected four links");
  links.forEach(function (link, index) {
    assert.strictEqual(link.signatureValid, true,
      "link " + index + " (" + link.subject + ") has an invalid signature");
    assert.strictEqual(link.namesMatch, true,
      "link " + index + " (" + link.subject + ") names an issuer that is not " +
      "the certificate above it");
    assert.strictEqual(link.expired, false,
      "link " + index + " is already expired");
  });
  assert.strictEqual(links[3].selfSigned, true,
    "the root must be the self-signed one");
  assert.strictEqual(links[0].selfSigned, false,
    "the leaf must not be self-signed");

  // AND the negative: the leaf must NOT verify without the intermediates. A
  // chain test that only ever passes is a chain test that would pass against a
  // validator that checks nothing.
  const withoutChain = opensslVerify(leaf.pem, root.pem);
  assert.ok(!withoutChain.ok,
    "openssl accepted the leaf without the intermediate certificates, which " +
    "means this test is not proving what it claims to");
  log.debug("Leaving aRootIntermediateIssuingChainVerifies().");
}

// ---------------------------------------------------------------------------
// 6. nameConstraints are ENFORCED, not merely encoded.
//
// This is the assertion that proves the extension is real: an encoding that
// parses but constrains nothing looks identical in `openssl x509 -text`.
// ---------------------------------------------------------------------------
async function nameConstraintsAreEnforcedByOpenssl() {
  log.debug("Entering nameConstraintsAreEnforcedByOpenssl().");
  const rootKey = await keyFor("rsa-2048");
  const root = await x509.issueCertificate({
    profile: "root-ca", subject: "CN=Constrained Root,O=idptools",
    subjectPublicKey: rootKey.publicPem,
    issuerPrivateKey: rootKey.privatePem, signatureAlg: "sha256-rsa",
    extensions: x509.defaultExtensions("root-ca")
  });
  const caKey = await keyFor("ec-p256");
  const caExt = x509.defaultExtensions("intermediate-ca");
  caExt.nameConstraints = { present: true, critical: true,
    permitted: [{ kind: "dns", value: "permitted.example" },
                { kind: "ip", value: "10.0.0.0/8" }],
    excluded: [{ kind: "dns", value: "bad.permitted.example" }] };
  const constrained = await x509.issueCertificate({
    profile: "intermediate-ca", subject: "CN=Constrained CA,O=idptools",
    subjectPublicKey: caKey.publicPem,
    issuer: { certificatePem: root.pem, privateKeyPem: rootKey.privatePem,
             keyAlg: "rsa-2048" },
    signatureAlg: "sha256-rsa",
    extensions: caExt
  });
  const constrainedText = opensslText(constrained.pem);
  assert.ok(/X509v3 Name Constraints: critical/.test(constrainedText),
    "nameConstraints must be critical (RFC 5280 says MUST): " +
    constrainedText);
  assert.ok(/Permitted:/.test(constrainedText) &&
      /DNS:permitted\.example/.test(constrainedText),
    "openssl did not read the permitted subtree back: " + constrainedText);
  assert.ok(/Excluded:/.test(constrainedText),
    "openssl did not read the excluded subtree back: " + constrainedText);
  assert.ok(/IP:10\.0\.0\.0\/255\.0\.0\.0/.test(constrainedText),
    "the IP name constraint must carry its MASK — an iPAddress constraint " +
    "is eight bytes for IPv4, address then mask, and encoding it as a bare " +
    "address constrains nothing while looking correct: " + constrainedText);

  const leafKey = await keyFor("ec-p384");
  async function leafFor(dnsName) {
    log.debug("Entering leafFor(). name=" + dnsName);
    const ext = x509.defaultExtensions("tls-server");
    ext.subjectAltName = { present: true, critical: false,
      names: [{ kind: "dns", value: dnsName }] };
    const issued = await x509.issueCertificate({
      profile: "tls-server", subject: "CN=" + dnsName + ",O=idptools",
      subjectPublicKey: leafKey.publicPem,
      issuer: { certificatePem: constrained.pem,
               privateKeyPem: caKey.privatePem, keyAlg: "ec-p256" },
      signatureAlg: "sha256-ecdsa",
      extensions: ext
    });
    log.debug("Leaving leafFor().");
    return issued;
  }

  const inside = await leafFor("host.permitted.example");
  const okVerdict = opensslVerify(inside.pem, root.pem, [constrained.pem]);
  assert.ok(okVerdict.ok,
    "a name INSIDE the permitted subtree was refused: " + okVerdict.output);

  const outside = await leafFor("host.forbidden.example");
  const badVerdict = opensslVerify(outside.pem, root.pem, [constrained.pem]);
  assert.ok(!badVerdict.ok,
    "openssl accepted a name OUTSIDE the permitted subtree, so the name " +
    "constraint was encoded in a way that constrains nothing");
  assert.ok(/permitted subtree violation/i.test(badVerdict.output),
    "expected a permitted-subtree violation, got: " + badVerdict.output);

  const excluded = await leafFor("bad.permitted.example");
  const excludedVerdict = opensslVerify(excluded.pem, root.pem,
      [constrained.pem]);
  assert.ok(!excludedVerdict.ok,
    "openssl accepted a name in the EXCLUDED subtree");
  log.debug("Leaving nameConstraintsAreEnforcedByOpenssl().");
}

// ---------------------------------------------------------------------------
// 7. basicConstraints: cA and pathLenConstraint are enforced.
// ---------------------------------------------------------------------------
async function basicConstraintsAreEnforcedByOpenssl() {
  log.debug("Entering basicConstraintsAreEnforcedByOpenssl().");
  const rootKey = await keyFor("rsa-2048");
  const root = await x509.issueCertificate({
    profile: "root-ca", subject: "CN=PathLen Root,O=idptools",
    subjectPublicKey: rootKey.publicPem,
    issuerPrivateKey: rootKey.privatePem, signatureAlg: "sha256-rsa",
    extensions: x509.defaultExtensions("root-ca")
  });
  // An issuing CA with pathLenConstraint 0: it may sign leaves and no further
  // CA.
  const issuingKey = await keyFor("ec-p256");
  const issuing = await x509.issueCertificate({
    profile: "issuing-ca", subject: "CN=PathLen Zero CA,O=idptools",
    subjectPublicKey: issuingKey.publicPem,
    issuer: { certificatePem: root.pem, privateKeyPem: rootKey.privatePem,
             keyAlg: "rsa-2048" },
    signatureAlg: "sha256-rsa",
    extensions: x509.defaultExtensions("issuing-ca")
  });
  assert.ok(/pathlen:0/i.test(opensslText(issuing.pem)),
    "the issuing CA profile must set pathLenConstraint 0");

  const belowKey = await keyFor("ec-p384");
  const belowExt = x509.defaultExtensions("issuing-ca");
  const below = await x509.issueCertificate({
    profile: "issuing-ca", subject: "CN=One CA Too Many,O=idptools",
    subjectPublicKey: belowKey.publicPem,
    issuer: { certificatePem: issuing.pem,
             privateKeyPem: issuingKey.privatePem, keyAlg: "ec-p256" },
    signatureAlg: "sha256-ecdsa",
    extensions: belowExt
  });
  const leafKey = await keyFor("rsa-3072");
  const leafExt = x509.defaultExtensions("tls-server");
  const leaf = await x509.issueCertificate({
    profile: "tls-server", subject: "CN=too-deep.example,O=idptools",
    subjectPublicKey: leafKey.publicPem,
    issuer: { certificatePem: below.pem, privateKeyPem: belowKey.privatePem,
             keyAlg: "ec-p384" },
    signatureAlg: "sha384-ecdsa",
    extensions: leafExt
  });
  const verdict = opensslVerify(leaf.pem, root.pem, [issuing.pem, below.pem]);
  assert.ok(!verdict.ok,
    "openssl accepted a chain one CA deeper than pathLenConstraint allows, " +
    "so the constraint was encoded in a way that constrains nothing");
  assert.ok(/path length constraint/i.test(verdict.output),
    "expected a path-length failure, got: " + verdict.output);

  // A leaf must not be usable as a CA. cA=false is the default for every leaf
  // profile, and this is what proves it is written rather than assumed.
  assert.ok(/CA:FALSE/.test(opensslText(leaf.pem)),
    "a leaf certificate must carry basicConstraints cA=FALSE");
  log.debug("Leaving basicConstraintsAreEnforcedByOpenssl().");
}

// ---------------------------------------------------------------------------
// 8. A critical extension nobody understands makes a validator refuse the
//    certificate, which is what the critical flag is FOR — and the reason this
//    page lets you set it on anything.
// ---------------------------------------------------------------------------
async function anUnknownCriticalExtensionIsRefused() {
  log.debug("Entering anUnknownCriticalExtensionIsRefused().");
  const caKey = await keyFor("rsa-2048");
  const ca = await x509.issueCertificate({
    profile: "root-ca", subject: "CN=Critical Test CA,O=idptools",
    subjectPublicKey: caKey.publicPem,
    issuerPrivateKey: caKey.privatePem, signatureAlg: "sha256-rsa",
    extensions: x509.defaultExtensions("root-ca")
  });
  const leafKey = await keyFor("ec-p256");
  async function leafWithCustom(critical) {
    log.debug("Entering leafWithCustom(). critical=" + critical);
    const ext = x509.defaultExtensions("tls-server");
    ext.custom = [{ oid: "1.3.6.1.4.1.99999.42.42", critical: critical,
                   value: Buffer.from([0x05, 0x00]).toString("base64") }];
    const issued = await x509.issueCertificate({
      profile: "tls-server", subject: "CN=critical.example,O=idptools",
      subjectPublicKey: leafKey.publicPem,
      issuer: { certificatePem: ca.pem, privateKeyPem: caKey.privatePem,
               keyAlg: "rsa-2048" },
      signatureAlg: "sha256-rsa", extensions: ext
    });
    log.debug("Leaving leafWithCustom().");
    return issued;
  }
  const harmless = await leafWithCustom(false);
  assert.ok(opensslVerify(harmless.pem, ca.pem).ok,
    "a NON-critical unknown extension must not stop verification");
  const critical = await leafWithCustom(true);
  const verdict = opensslVerify(critical.pem, ca.pem);
  assert.ok(!verdict.ok,
    "openssl accepted a certificate carrying a CRITICAL extension it cannot " +
    "possibly understand — either the critical flag was not written, or this " +
    "assertion is no longer testing it");
  assert.ok(/critical extension/i.test(verdict.output),
    "expected an unhandled-critical-extension failure, got: " +
    verdict.output);
  log.debug("Leaving anUnknownCriticalExtensionIsRefused().");
}

// ---------------------------------------------------------------------------
// 9. Serial numbers, and the two ways they go wrong.
// ---------------------------------------------------------------------------
async function serialNumbersArePositiveAndLongEnough() {
  log.debug("Entering serialNumbersArePositiveAndLongEnough().");
  const key = await keyFor("ec-p256");
  const seen = {};
  for (let i = 0; i < 25; i++) {
    const cert = await x509.issueCertificate({
      profile: "root-ca", subject: "CN=Serial Test,O=idptools",
      subjectPublicKey: key.publicPem, issuerPrivateKey: key.privatePem,
      signatureAlg: "sha256-ecdsa",
      extensions: x509.defaultExtensions("root-ca")
    });
    assert.ok(!seen[cert.serialHex],
      "two certificates were issued with the same serial number (" +
      cert.serialHex + ") — a random serial is what makes a collision on the " +
      "signed bytes impractical to arrange");
    seen[cert.serialHex] = true;
    assert.strictEqual(cert.serialHex.length, 32,
      "expected a 128-bit serial, got " + (cert.serialHex.length * 4) +
      " bits: " + cert.serialHex);
    const first = parseInt(cert.serialHex.slice(0, 2), 16);
    assert.ok(first < 0x80 && first > 0,
      "the leading byte of a serial must be 1..0x7f: 0x80 or above is read " +
      "as a NEGATIVE integer, and 0x00 gives a leading zero some parsers " +
      "report as a 17-byte serial. Got 0x" + first.toString(16));
    const text = opensslText(cert.pem);
    assert.ok(!/Serial Number: -/.test(text),
      "openssl read the serial as negative: " + text.split("\n")
        .filter(function (l) { return /Serial/.test(l); }).join(" "));
  }
  // An explicitly supplied serial has to survive, including one whose leading
  // byte would otherwise be read as negative.
  const explicit = await x509.issueCertificate({
    profile: "root-ca", subject: "CN=Explicit Serial,O=idptools",
    subjectPublicKey: key.publicPem, issuerPrivateKey: key.privatePem,
    signatureAlg: "sha256-ecdsa", serial: "ff00ff00",
    extensions: x509.defaultExtensions("root-ca")
  });
  const described = await x509.describeCertificate(explicit.pem);
  assert.ok(/ff00ff00$/.test(described.serialHex),
    "an explicit serial of ff00ff00 came back as " + described.serialHex);
  assert.ok(!/Serial Number: -/.test(opensslText(explicit.pem)),
    "a serial whose leading byte is 0xff must be padded so it stays positive");
  log.debug("Leaving serialNumbersArePositiveAndLongEnough().");
}

// ---------------------------------------------------------------------------
// 10. A date at or after 2050 is a GeneralizedTime.
//
// RFC 5280 section 4.1.2.5. A UTCTime there is read as 1950 — a certificate
// that expired seventy years ago, reported by every validator as expired and
// by none as misencoded.
// ---------------------------------------------------------------------------
async function datesAfter2049UseGeneralizedTime() {
  log.debug("Entering datesAfter2049UseGeneralizedTime().");
  const key = await keyFor("ec-p256");
  const cert = await x509.issueCertificate({
    profile: "root-ca", subject: "CN=Long Lived Root,O=idptools",
    subjectPublicKey: key.publicPem, issuerPrivateKey: key.privatePem,
    signatureAlg: "sha256-ecdsa",
    notBefore: "2026-01-01T00:00:00Z",
    notAfter: "2071-01-01T00:00:00Z",
    extensions: x509.defaultExtensions("root-ca")
  });
  const text = opensslText(cert.pem);
  assert.ok(/Not After\s*:\s*Jan\s+1\s+00:00:00 2071/.test(text),
    "a notAfter in 2071 came back as something else — the UTCTime/" +
    "GeneralizedTime boundary is at 2050 and the wrong choice reads as " +
    "1971: " + text.split("\n").filter(function (l) {
      return /Not After/.test(l);
    }).join(" "));
  const described = await x509.describeCertificate(cert.pem);
  assert.ok(described.notAfter.indexOf("2071") === 0,
    "describeCertificate() read the far date as " + described.notAfter);
  log.debug("Leaving datesAfter2049UseGeneralizedTime().");
}

// ---------------------------------------------------------------------------
// 11. The key identifiers match what every other implementation computes.
// ---------------------------------------------------------------------------
async function keyIdentifiersMatchOpenssl() {
  log.debug("Entering keyIdentifiersMatchOpenssl().");
  const caKey = await keyFor("rsa-2048");
  const ca = await x509.issueCertificate({
    profile: "root-ca", subject: "CN=KeyId CA,O=idptools",
    subjectPublicKey: caKey.publicPem, issuerPrivateKey: caKey.privatePem,
    signatureAlg: "sha256-rsa",
    extensions: x509.defaultExtensions("root-ca")
  });
  const leafKey = await keyFor("ec-p256");
  const leaf = await x509.issueCertificate({
    profile: "tls-client", subject: "CN=keyid-leaf,O=idptools",
    subjectPublicKey: leafKey.publicPem,
    issuer: { certificatePem: ca.pem, privateKeyPem: caKey.privatePem,
             keyAlg: "rsa-2048" },
    signatureAlg: "sha256-rsa",
    extensions: x509.defaultExtensions("tls-client")
  });
  const caText = opensslText(ca.pem);
  const leafText = opensslText(leaf.pem);
  // Built rather than written out: the AKI pattern is over 80 columns as a
  // literal, and a regex is one of the few things that cannot be wrapped.
  const SKID = /X509v3 Subject Key Identifier:\s*\n\s*([0-9A-F:]+)/;
  const AKID = new RegExp("X509v3 Authority Key Identifier:\\s*\\n" +
      "\\s*(?:keyid:)?\\s*([0-9A-F:]+)");
  const caSkid = SKID.exec(caText);
  const leafAkid = AKID.exec(leafText);
  assert.ok(caSkid, "the CA has no subjectKeyIdentifier");
  assert.ok(leafAkid, "the leaf has no authorityKeyIdentifier");
  assert.strictEqual(leafAkid[1].trim(), caSkid[1].trim(),
    "the leaf's authorityKeyIdentifier does not match the CA's " +
    "subjectKeyIdentifier, so a validator holding several certificates for " +
    "this CA cannot tell which one signed this leaf");
  // And the self-signed case, where the AKI has to be the subject's own key
  // because there is no issuer certificate to read it from.
  const caAkid = AKID.exec(caText);
  assert.ok(caAkid && caAkid[1].trim() === caSkid[1].trim(),
    "a self-signed certificate's authorityKeyIdentifier must be its own " +
    "subjectKeyIdentifier");
  log.debug("Leaving keyIdentifiersMatchOpenssl().");
}

// ---------------------------------------------------------------------------
// 12. Every profile issues something OpenSSL accepts and that carries what the
//     profile is named after.
// ---------------------------------------------------------------------------
async function everyProfileIssuesWhatItPromises() {
  log.debug("Entering everyProfileIssuesWhatItPromises().");
  const rootKey = await keyFor("rsa-2048");
  const root = await x509.issueCertificate({
    profile: "root-ca", subject: "CN=Profile Root,O=idptools",
    subjectPublicKey: rootKey.publicPem,
    issuerPrivateKey: rootKey.privatePem, signatureAlg: "sha256-rsa",
    extensions: x509.defaultExtensions("root-ca")
  });
  const subjectKey = await keyFor("ec-p256");
  const profiles = x509.profileIds();
  assert.ok(profiles.length >= 14,
    "the profile list has shrunk to " + profiles.length);
  for (const profileId of profiles) {
    const profile = x509.profile(profileId);
    const ext = x509.defaultExtensions(profileId);
    const selfSigned = !!profile.selfSigned;
    const issued = await x509.issueCertificate({
      profile: profileId,
      subject: "CN=" + profileId + ".example,O=idptools",
      subjectPublicKey: selfSigned ? rootKey.publicPem : subjectKey.publicPem,
      issuer: selfSigned ? null
        : { certificatePem: root.pem, privateKeyPem: rootKey.privatePem,
            keyAlg: "rsa-2048" },
      issuerPrivateKey: selfSigned ? rootKey.privatePem : null,
      signatureAlg: "sha256-rsa",
      extensions: ext
    });
    const text = opensslText(issued.pem);
    assert.ok(new RegExp("CA:" + (profile.ca ? "TRUE" : "FALSE")).test(text),
      profileId + ": basicConstraints cA should be " + !!profile.ca + "\n" +
      text);
    (profile.keyUsage || []).forEach(function (usage) {
      const described = ext.keyUsage.usages;
      assert.ok(described.indexOf(usage) >= 0,
        profileId + ": the default extensions dropped the " + usage +
        " key usage the profile names");
    });
    if (!selfSigned) {
      const verdict = opensslVerify(issued.pem, root.pem);
      assert.ok(verdict.ok,
        profileId + ": openssl refused a certificate issued from its own " +
        "profile defaults: " + verdict.output);
    }
    log.debug(profileId + ": ok");
  }
  log.info("Issued and checked " + profiles.length + " profiles.");
  log.debug("Leaving everyProfileIssuesWhatItPromises().");
}

// ---------------------------------------------------------------------------
// 13. The refusals: things that must NOT be issued.
// ---------------------------------------------------------------------------
async function badInputIsRefusedByName() {
  log.debug("Entering badInputIsRefusedByName().");
  const key = await keyFor("ec-p256");
  const base = {
    profile: "root-ca", subject: "CN=Refusals,O=idptools",
    subjectPublicKey: key.publicPem, issuerPrivateKey: key.privatePem,
    signatureAlg: "sha256-ecdsa",
    extensions: x509.defaultExtensions("root-ca")
  };
  async function refuses(mutate, pattern, what) {
    log.debug("Entering refuses(). what=" + what);
    const spec = Object.assign({}, base);
    mutate(spec);
    let threw = null;
    try {
      await x509.issueCertificate(spec);
    } catch (e) {
      threw = e;
    }
    assert.ok(threw, what + " was accepted and should not have been");
    assert.ok(pattern.test(threw.message),
      what + " was refused with the wrong message (" + threw.message +
      "), which is worse than not refusing it: it sends the reader at the " +
      "wrong thing");
    log.debug("Leaving refuses().");
  }
  await refuses(function (spec) { spec.subject = ""; }, /subject/i,
    "an empty subject");
  await refuses(function (spec) { spec.signatureAlg = "sha256-nonsense"; },
    /signature algorithm/i, "an unknown signature algorithm");
  await refuses(function (spec) { spec.issuerPrivateKey = null; },
    /private key|sign/i, "no signing key at all");
  await refuses(function (spec) {
    spec.extensions = x509.defaultExtensions("tls-server");
    spec.extensions.subjectAltName = { present: true,
      names: [{ kind: "ip", value: "not-an-address" }] };
  }, /not an ip address/i, "a subjectAltName IP that is not an address");
  await refuses(function (spec) {
    spec.extensions = x509.defaultExtensions("tls-server");
    spec.extensions.custom = [{ oid: "1.2.3", critical: false,
                               value: "!!!!not base64 or der!!!!" }];
  }, /not base64/i, "a custom extension whose value is not base64");
  await refuses(function (spec) {
    spec.extensions = x509.defaultExtensions("tls-server");
    spec.extensions.custom = [{ oid: "1.2.3", critical: false,
                               value: "aGVsbG8gd29ybGQ=" }];
  }, /not der/i, "a custom extension that is base64 but not DER");
  await refuses(function (spec) {
    spec.extensions = x509.defaultExtensions("tls-server");
    spec.extensions.subjectAltName = { present: true,
      names: [{ kind: "nonsense", value: "x" }] };
  }, /unknown general name/i, "an unknown general name type");
  log.debug("Leaving badInputIsRefusedByName().");
}

// ---------------------------------------------------------------------------
// 14. The describer reads back what the builder wrote, field for field. This
//     is the check the PAGE depends on — its detail table is this function's
//     output.
// ---------------------------------------------------------------------------
async function theDescriberRoundTripsEveryField() {
  log.debug("Entering theDescriberRoundTripsEveryField().");
  const caKey = await keyFor("rsa-2048");
  const ca = await x509.issueCertificate({
    profile: "root-ca", subject: "CN=Describe CA,O=idptools,C=US",
    subjectPublicKey: caKey.publicPem, issuerPrivateKey: caKey.privatePem,
    signatureAlg: "sha384-rsapss",
    extensions: x509.defaultExtensions("root-ca")
  });
  const described = await x509.describeCertificate(ca.pem);
  assert.strictEqual(described.version, 3, "certificates here are v3");
  assert.strictEqual(described.subject, "CN=Describe CA, O=idptools, C=US",
    "the subject came back as " + described.subject);
  assert.strictEqual(described.selfSigned, true, "a root is self-signed");
  assert.strictEqual(described.signatureAlgorithm, "rsassaPss",
    "expected an RSASSA-PSS signature algorithm, got " +
    described.signatureAlgorithm);
  assert.strictEqual(described.publicKey, "RSA 2048-bit",
    "expected an RSA 2048-bit key, got " + described.publicKey);
  assert.ok(/^[0-9A-F:]{95}$/.test(described.fingerprints.sha256),
    "the SHA-256 fingerprint is not 32 colon-separated bytes: " +
    described.fingerprints.sha256);

  // The fingerprint has to be the one openssl computes, or it is useless for
  // the thing a fingerprint is for: comparing with somebody else's copy.
  const file = writePem("fingerprint.pem", ca.pem);
  const openssl = execFileSync("openssl",
      ["x509", "-in", file, "-noout", "-fingerprint", "-sha256"],
      { encoding: "utf8" });
  const expected = openssl.split("=").slice(1).join("=").trim();
  assert.strictEqual(described.fingerprints.sha256, expected,
    "the SHA-256 fingerprint disagrees with openssl: " +
    described.fingerprints.sha256 + " vs " + expected);

  const basic = described.extensions.filter(function (e) {
    return e.name === "basicConstraints";
  })[0];
  assert.ok(basic, "the CA has no basicConstraints");
  assert.strictEqual(basic.critical, true,
    "basicConstraints must be critical in a CA certificate");
  assert.strictEqual(basic.value.ca, true, "cA must be true");
  const usage = described.extensions.filter(function (e) {
    return e.name === "keyUsage";
  })[0];
  assert.ok(usage.value.indexOf("keyCertSign") >= 0,
    "a CA must have keyCertSign; got " + JSON.stringify(usage.value));
  assert.ok(usage.value.indexOf("cRLSign") >= 0,
    "a CA should have cRLSign; got " + JSON.stringify(usage.value));
  log.debug("Leaving theDescriberRoundTripsEveryField().");
}

// ---------------------------------------------------------------------------
// 15. The general-name and IP encoders, at the byte level.
// ---------------------------------------------------------------------------
function addressEncodingIsExact() {
  log.debug("Entering addressEncodingIsExact().");
  assert.deepStrictEqual(Array.from(x509.ipBytes("192.0.2.1")),
    [192, 0, 2, 1], "an IPv4 SAN is four bytes");
  assert.strictEqual(x509.ipBytes("2001:db8::1").length, 16,
    "an IPv6 SAN is sixteen bytes");
  assert.deepStrictEqual(Array.from(x509.ipBytes("::1")).slice(14), [0, 1],
    "'::1' must expand to fifteen zero bytes and a one");
  // The constraint form is the address FOLLOWED BY ITS MASK.
  assert.deepStrictEqual(Array.from(x509.ipConstraintBytes("10.0.0.0/8")),
    [10, 0, 0, 0, 255, 0, 0, 0],
    "an IPv4 name constraint is eight bytes: address then mask");
  assert.deepStrictEqual(
    Array.from(x509.ipConstraintBytes("192.168.1.0/24")),
    [192, 168, 1, 0, 255, 255, 255, 0], "a /24 mask is 255.255.255.0");
  assert.strictEqual(x509.ipConstraintBytes("2001:db8::/32").length, 32,
    "an IPv6 name constraint is thirty-two bytes");
  assert.throws(function () { x509.ipBytes("999.0.0.1"); }, /not an ip/i,
    "an octet above 255 is not an address");
  assert.throws(function () { x509.ipConstraintBytes("10.0.0.0/33"); },
    /prefix/i, "a /33 is out of range for IPv4");
  log.debug("Leaving addressEncodingIsExact().");
}

// ---------------------------------------------------------------------------
// 16. Distinguished-name parsing and rendering round-trip.
// ---------------------------------------------------------------------------
function distinguishedNamesRoundTrip() {
  log.debug("Entering distinguishedNamesRoundTrip().");
  const parsed = x509.parseDnString("CN=Some Name, O=Example Ltd, C=GB");
  assert.strictEqual(parsed.length, 3, "three attributes were written");
  assert.deepStrictEqual(parsed[0], { name: "CN", value: "Some Name" });
  assert.deepStrictEqual(parsed[2], { name: "C", value: "GB" });
  const withOid = x509.parseDnString("CN=x, 1.3.6.1.4.1.99999.2=y");
  assert.strictEqual(withOid[1].oid, "1.3.6.1.4.1.99999.2",
    "an attribute given by OID must be kept as an OID");
  const rendered = x509.dnToString(x509.buildDn(parsed));
  assert.strictEqual(rendered, "CN=Some Name, O=Example Ltd, C=GB",
    "the DN did not survive a build/render round trip: " + rendered);
  log.debug("Leaving distinguishedNamesRoundTrip().");
}

// ---------------------------------------------------------------------------
// 17. A signature algorithm the signing key cannot produce is not offered.
// ---------------------------------------------------------------------------
function signatureAlgorithmsAreFilteredByKey() {
  log.debug("Entering signatureAlgorithmsAreFilteredByKey().");
  const rsa = x509.signatureAlgorithmsFor({ kind: "rsa" });
  const ec = x509.signatureAlgorithmsFor({ kind: "ec" });
  const okp = x509.signatureAlgorithmsFor({ kind: "okp" });
  assert.ok(rsa.indexOf("sha256-rsa") >= 0 && rsa.indexOf("sha512-rsapss") >= 0,
    "an RSA key must be offered both PKCS#1 v1.5 and PSS");
  assert.ok(rsa.indexOf("sha256-ecdsa") === -1,
    "an RSA key was offered ECDSA, which it cannot produce — the Web Crypto " +
    "failure names key usage rather than the algorithm");
  assert.ok(ec.indexOf("sha384-ecdsa") >= 0 && ec.indexOf("ed25519") === -1,
    "an EC key must be offered ECDSA and not Ed25519");
  assert.deepStrictEqual(okp, ["ed25519"],
    "an Ed25519 key can produce exactly one signature algorithm");
  assert.strictEqual(
    x509.defaultSignatureAlgorithm({ kind: "ec", curve: "P-521" }),
    "sha512-ecdsa",
    "a P-521 key should default to its natural digest size");
  // The two SHA-1 entries are present and marked, because "does my stack " +
  // "still accept SHA-1" is a question this tool should be able to ask.
  assert.strictEqual(x509.sigAlg("sha1-rsa").weak, true,
    "the SHA-1 algorithms must be marked weak so nothing defaults to them");
  assert.ok(x509.defaultSignatureAlgorithm({ kind: "rsa" }).indexOf("sha1") <
      0, "nothing may default to SHA-1");
  log.debug("Leaving signatureAlgorithmsAreFilteredByKey().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. Verifying client/src/x509.js against OpenSSL.");
  try {
    execFileSync("openssl", ["version"], { encoding: "utf8" });
  } catch (e) {
    throw new Error("openssl is not on the PATH. This test asserts by asking " +
      "ANOTHER implementation what it reads, which is the only way to catch " +
      "an encoding that is wrong and self-consistent; it cannot be run " +
      "without it. (tests/Dockerfile installs it.)");
  }
  addressEncodingIsExact();
  distinguishedNamesRoundTrip();
  signatureAlgorithmsAreFilteredByKey();
  await theSubjectIsAnRdnSequence();
  await serialNumbersArePositiveAndLongEnough();
  await datesAfter2049UseGeneralizedTime();
  await keyIdentifiersMatchOpenssl();
  await theDescriberRoundTripsEveryField();
  await everyExtensionIsWrittenAndReadBack();
  await theWholeExtensionSetAtOnce();
  await everyProfileIssuesWhatItPromises();
  await aRootIntermediateIssuingChainVerifies();
  await nameConstraintsAreEnforcedByOpenssl();
  await basicConstraintsAreEnforcedByOpenssl();
  await anUnknownCriticalExtensionIsRefused();
  await badInputIsRefusedByName();
  // Last, because it is by far the longest.
  await everyAlgorithmCombinationIssuesAndVerifies();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("pki_x509")
  .description("Verify certificate authoring — every algorithm combination, " +
      "every X.509v3 extension, and a four-deep chain — against OpenSSL.")
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
