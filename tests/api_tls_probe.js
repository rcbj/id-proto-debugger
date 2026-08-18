// File: api_tls_probe.js
//
// api/tls_probe.js — the TLS / mutual-TLS test connection behind
// POST /tls/connect.
//
// ---------------------------------------------------------------------------
// WHY THIS TEST EXISTS
//
// This endpoint is in the same position as the Kerberos relay and needs the
// same accounting. `tls.connect` is a raw socket, so api/ssrf_guard.js — an
// axios interceptor plus hooks on the axios agents — never sees it, and a
// second enforcement of an address policy is exactly the kind of thing that is
// subtly weaker than the first unless something holds it to account. It is also
// broader than the Kerberos relay in one specific way: there is no payload
// shape to bound it with, because a ClientHello sent to port 22 is a perfectly
// well-formed ClientHello. The port allowlist is therefore doing all of that
// work, and it is tested here.
//
// The other half of the file is about what the endpoint REPORTS, and one
// assertion earns its keep more than all the rest:
//
//   **a completed handshake is not an accepted client certificate.**
//
// Under TLS 1.2 a server that refuses a client certificate refuses it during
// the handshake. Under TLS 1.3 the client sends its Certificate and Finished
// LAST — the handshake is complete from the client's point of view the instant
// it has written them — and the server's verdict arrives afterwards as a
// post-handshake alert. An implementation that resolves on `secureConnect`
// therefore reports a happy mutual-authentication connection to a server that
// rejected the certificate a millisecond later, and its mutual-auth probe
// answers "not required" for every TLS 1.3 server on earth. That is what this
// implementation did before the grace-period read, and `mutualAuthIsMeasured`
// below fails against it.
//
// Every listener here is a throwaway on 127.0.0.1 with the address policy
// DISABLED, which is what the local and containerized stacks do anyway. The
// policy itself is tested separately, enabled.
//
// No browser and no services: node only, so it never skips.
// ---------------------------------------------------------------------------
const assert = require("assert");
const net = require("net");
const tls = require("tls");
const path = require("path");
const { Command, Option } = require("commander");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "api_tls_probe",
    level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

const paths = require("./module_paths.js");
function sharedModule(dir, name) {
  log.debug("Entering sharedModule(). name=" + name);
  const found = paths.requireSharedModule(
    [path.join(__dirname, "..", dir, name), path.join(__dirname, name)],
    dir + "/" + name);
  log.debug("Leaving sharedModule().");
  return found;
}

const tlsProbe = sharedModule("api", "tls_probe.js");
const keys = sharedModule(path.join("client", "src"), "key_material.js");
const x509 = sharedModule(path.join("client", "src"), "x509.js");

// A guard that is off, which is what local.js and docker-tests.js configure and
// what every listener below needs (they are all on loopback).
const OPEN_GUARD = { enabled: false, blockedRangeFor: function () {
  return null;
} };

function probeFor(config, deps) {
  log.debug("Entering probeFor().");
  const probe = tlsProbe.createProbe(
    Object.assign({ tlsAllowedPorts: "any", connectionTimeout: 3000,
                   callTimeout: 6000 }, config || {}),
    (config && config.guard) || OPEN_GUARD, log, deps);
  log.debug("Leaving probeFor().");
  return probe;
}

// ---------------------------------------------------------------------------
// A small private PKI to test against, built with the same modules the page
// uses. Two roots, deliberately: "does this chain verify against MY root and
// only mine" is the question a truststore answers, and it cannot be asked with
// one root.
// ---------------------------------------------------------------------------
var pki = null;

async function buildPki() {
  log.debug("Entering buildPki().");
  if (pki) {
    log.debug("Leaving buildPki(). Cached.");
    return pki;
  }
  async function root(name) {
    log.debug("Entering root(). name=" + name);
    const key = await keys.generateKeyPair("ec-p256");
    const cert = await x509.issueCertificate({
      profile: "root-ca", subject: "CN=" + name + ",O=idptools",
      subjectPublicKey: key.publicPem, issuerPrivateKey: key.privatePem,
      signatureAlg: "sha256-ecdsa",
      extensions: x509.defaultExtensions("root-ca")
    });
    log.debug("Leaving root().");
    return { key: key, cert: cert };
  }
  async function leaf(ca, profile, cn, sanNames) {
    log.debug("Entering leaf(). cn=" + cn);
    const key = await keys.generateKeyPair("ec-p256");
    const ext = x509.defaultExtensions(profile);
    if (sanNames) {
      ext.subjectAltName = { present: true, critical: false,
                            names: sanNames };
    }
    const cert = await x509.issueCertificate({
      profile: profile, subject: "CN=" + cn + ",O=idptools",
      subjectPublicKey: key.publicPem,
      issuer: { certificatePem: ca.cert.pem, privateKeyPem: ca.key.privatePem,
               keyAlg: "ec-p256" },
      signatureAlg: "sha256-ecdsa", extensions: ext
    });
    log.debug("Leaving leaf().");
    return { key: key, cert: cert };
  }
  async function subCa(ca, name) {
    log.debug("Entering subCa(). name=" + name);
    const key = await keys.generateKeyPair("ec-p256");
    const cert = await x509.issueCertificate({
      profile: "issuing-ca", subject: "CN=" + name + ",O=idptools",
      subjectPublicKey: key.publicPem,
      issuer: { certificatePem: ca.cert.pem, privateKeyPem: ca.key.privatePem,
               keyAlg: "ec-p256" },
      signatureAlg: "sha256-ecdsa",
      extensions: x509.defaultExtensions("issuing-ca")
    });
    log.debug("Leaving subCa().");
    return { key: key, cert: cert };
  }
  const ourRoot = await root("Probe Root CA");
  const otherRoot = await root("Somebody Else's Root CA");
  const issuing = await subCa(ourRoot, "Probe Issuing CA");
  pki = {
    ourRoot: ourRoot,
    otherRoot: otherRoot,
    issuing: issuing,
    // A client certificate one level DOWN, which is the ordinary shape of a
    // real PKI and the one that needs its chain sent with it.
    deepClient: await leaf(issuing, "tls-client", "deep-client"),
    server: await leaf(ourRoot, "tls-server", "probe.example.test",
      [{ kind: "dns", value: "probe.example.test" },
       { kind: "dns", value: "localhost" },
       { kind: "ip", value: "127.0.0.1" }]),
    client: await leaf(ourRoot, "tls-client", "probe-client"),
    stranger: await leaf(otherRoot, "tls-client", "stranger-client")
  };
  log.debug("Leaving buildPki().");
  return pki;
}

// A throwaway TLS server on an ephemeral loopback port. `requestCert` and
// `rejectUnauthorized` are what make it a mutual-auth server or not.
function startServer(options) {
  log.debug("Entering startServer().");
  log.debug("Leaving startServer().");
  return new Promise(function (resolve) {
    const server = tls.createServer(options, function (socket) {
      socket.end("hello\n");
    });
    server.on("tlsClientError", function (error) {
      log.debug("startServer(): tlsClientError " + error.message);
    });
    server.listen(0, "127.0.0.1", function () {
      resolve({ server: server, port: server.address().port,
               close: function () { server.close(); } });
    });
  });
}

async function serverOptions(extra) {
  log.debug("Entering serverOptions().");
  const built = await buildPki();
  const options = Object.assign({
    key: built.server.key.privatePem,
    cert: built.server.cert.pem,
    ca: [built.ourRoot.cert.pem],
    ALPNProtocols: ["h2", "http/1.1"]
  }, extra || {});
  log.debug("Leaving serverOptions().");
  return options;
}

// ---------------------------------------------------------------------------
// 1. The ordinary case, and everything the report has to carry.
// ---------------------------------------------------------------------------
async function aHandshakeIsReportedInFull() {
  log.debug("Entering aHandshakeIsReportedInFull().");
  const built = await buildPki();
  const listener = await startServer(await serverOptions());
  try {
    const probe = probeFor();
    const report = (await probe.connect({
      host: "127.0.0.1", port: listener.port,
      servername: "probe.example.test",
      trustCertificates: [built.ourRoot.cert.pem],
      alpnProtocols: ["http/1.1"]
    })).result;
    assert.strictEqual(report.connected, true,
      "the handshake did not complete: " + JSON.stringify(report.error));
    assert.strictEqual(report.authorized, true,
      "the server's certificate did not verify against the root that " +
      "issued it: " + report.authorizationError);
    assert.strictEqual(report.authorizationError, null,
      "an authorized connection must carry no verification error");
    assert.ok(/^TLSv1\.[23]$/.test(report.protocol),
      "expected a modern TLS version, got " + report.protocol);
    assert.ok(report.cipher && report.cipher.name,
      "the negotiated cipher is missing — it is one of the things a browser " +
      "cannot see and this endpoint exists to report");
    assert.strictEqual(report.alpnProtocol, "http/1.1",
      "ALPN was offered and the chosen protocol was not reported back: " +
      report.alpnProtocol);
    assert.strictEqual(report.servername, "probe.example.test",
      "the SNI name sent was not reported");
    assert.strictEqual(report.peerChain.length, 2,
      "expected the leaf and its issuer, got " + report.peerChain.length);
    assert.ok(/probe\.example\.test/.test(
        JSON.stringify(report.peerChain[0].subject)),
      "the leaf certificate is not the one the server was given");
    assert.ok(report.peerChain[0].pem &&
        /-----BEGIN CERTIFICATE-----/.test(report.peerChain[0].pem),
      "the chain must come back as PEM as well as as fields — inspecting it " +
      "elsewhere is the point");
    assert.ok(report.peerChain[0].fingerprint256,
      "a certificate without a fingerprint cannot be compared with anybody " +
      "else's copy of it");
    assert.strictEqual(report.trustStore.pastedAnchors, 1,
      "the report must say how many anchors were used");
    assert.strictEqual(report.trustStore.systemRoots, false,
      "supplying anchors must NOT quietly add the platform roots — a chain " +
      "that verifies for a reason the caller did not ask about is not an " +
      "answer");
    assert.strictEqual(report.postHandshakeError, null,
      "no alert was expected after the handshake");
    assert.ok(typeof report.elapsedMs === "number",
      "the report must carry how long it took");
  } finally {
    listener.close();
  }
  log.debug("Leaving aHandshakeIsReportedInFull().");
}

// ---------------------------------------------------------------------------
// 2. The truststore is the caller's choice, and the verdict follows it.
// ---------------------------------------------------------------------------
async function theTruststoreDecidesTheVerdict() {
  log.debug("Entering theTruststoreDecidesTheVerdict().");
  const built = await buildPki();
  const listener = await startServer(await serverOptions());
  try {
    const probe = probeFor();
    const base = { host: "127.0.0.1", port: listener.port,
                  servername: "probe.example.test" };

    const ours = (await probe.connect(Object.assign({}, base,
        { trustCertificates: [built.ourRoot.cert.pem] }))).result;
    assert.strictEqual(ours.authorized, true,
      "our own root should verify our own server");

    const theirs = (await probe.connect(Object.assign({}, base,
        { trustCertificates: [built.otherRoot.cert.pem] }))).result;
    assert.strictEqual(theirs.connected, true,
      "a verification failure must not abort the handshake — the chain that " +
      "would explain it is exactly what gets thrown away when it does");
    assert.strictEqual(theirs.authorized, false,
      "a chain verified against the WRONG root came back authorized");
    assert.ok(theirs.authorizationError,
      "a failed verification must say why");
    assert.strictEqual(theirs.peerChain.length, 2,
      "the chain must still be reported when verification fails — that is " +
      "when it is most wanted");

    const none = (await probe.connect(Object.assign({}, base,
        { trustCertificates: [], includeSystemRoots: false }))).result;
    assert.strictEqual(none.authorized, false,
      "with no anchors at all nothing can verify; if this passes, the " +
      "verification is not happening");
    assert.strictEqual(none.trustStore.pastedAnchors, 0,
      "no anchors were supplied");

    const system = (await probe.connect(Object.assign({}, base,
        { trustCertificates: [], includeSystemRoots: true }))).result;
    assert.strictEqual(system.trustStore.systemRoots, true,
      "the platform roots were asked for and the report says otherwise");
    assert.strictEqual(system.authorized, false,
      "a private CA must not verify against the public roots");

    const both = (await probe.connect(Object.assign({}, base,
        { trustCertificates: [built.ourRoot.cert.pem],
         includeSystemRoots: true }))).result;
    assert.strictEqual(both.authorized, true,
      "our root plus the platform roots must still verify our server");
    assert.strictEqual(both.trustStore.systemRoots, true,
      "the report must say the platform roots were included");
  } finally {
    listener.close();
  }
  log.debug("Leaving theTruststoreDecidesTheVerdict().");
}

// ---------------------------------------------------------------------------
// 3. The name verified is the caller's choice, separately from the address
//    dialled. Testing a certificate for one name against a host at another is
//    the thing a debugger is for.
// ---------------------------------------------------------------------------
async function theVerifiedNameIsSeparateFromTheAddress() {
  log.debug("Entering theVerifiedNameIsSeparateFromTheAddress().");
  const built = await buildPki();
  const listener = await startServer(await serverOptions());
  try {
    const probe = probeFor();
    const right = (await probe.connect({ host: "127.0.0.1",
      port: listener.port, servername: "probe.example.test",
      trustCertificates: [built.ourRoot.cert.pem] })).result;
    assert.strictEqual(right.authorized, true,
      "the name in the certificate's subjectAltName should verify");

    const wrong = (await probe.connect({ host: "127.0.0.1",
      port: listener.port, servername: "not-in-the-certificate.example",
      trustCertificates: [built.ourRoot.cert.pem] })).result;
    assert.strictEqual(wrong.authorized, false,
      "a name that is not in the certificate came back verified");
    assert.ok(/ALTNAME|hostname|Host:/i.test(wrong.authorizationError || ""),
      "expected a hostname-mismatch error, got " + wrong.authorizationError);
    assert.strictEqual(wrong.servername, "not-in-the-certificate.example",
      "the report must say which name was checked");
  } finally {
    listener.close();
  }
  log.debug("Leaving theVerifiedNameIsSeparateFromTheAddress().");
}

// ---------------------------------------------------------------------------
// 4. THE IMPORTANT ONE. Whether a server requires client authentication is
//    MEASURED by connecting both ways, because it cannot be read off a socket
//    — and a completed TLS 1.3 handshake says nothing about it.
// ---------------------------------------------------------------------------
async function mutualAuthIsMeasuredRatherThanAssumed() {
  log.debug("Entering mutualAuthIsMeasuredRatherThanAssumed().");
  const built = await buildPki();
  const probe = probeFor();
  const base = { host: "127.0.0.1", servername: "probe.example.test",
                trustCertificates: [built.ourRoot.cert.pem],
                mutualAuthProbe: true };

  // (a) A server that REQUIRES a client certificate.
  let listener = await startServer(await serverOptions({
    requestCert: true, rejectUnauthorized: true }));
  try {
    const report = await probe.connect(Object.assign({}, base,
      { port: listener.port,
        clientCertificatePem: built.client.cert.pem,
        clientKeyPem: built.client.key.privatePem }));
    assert.ok(report.mutualAuth, "no mutual-auth verdict was produced");
    assert.strictEqual(report.mutualAuth.verdict, "required",
      "a server configured with requestCert + rejectUnauthorized was " +
      "reported as '" + report.mutualAuth.verdict + "'. Under TLS 1.3 the " +
      "handshake completes before the server's verdict arrives, so reading " +
      "`connected` alone answers this question wrongly for every TLS 1.3 " +
      "server: " + report.mutualAuth.detail);
    assert.strictEqual(report.result.connected, true,
      "the connection WITH the certificate should have completed");
    assert.strictEqual(report.result.postHandshakeError, null,
      "an accepted client certificate must draw no alert");
    assert.ok(report.withoutClientCertificate,
      "the probe must report the second handshake as well, not only its " +
      "conclusion");
    const anonymous = report.withoutClientCertificate;
    assert.ok(!anonymous.connected || anonymous.postHandshakeError,
      "the connection WITHOUT a certificate should have been refused, " +
      "either during the handshake or by a post-handshake alert");
  } finally {
    listener.close();
  }

  // (b) A server that does NOT ask for one.
  listener = await startServer(await serverOptions({ requestCert: false }));
  try {
    const report = await probe.connect(Object.assign({}, base,
      { port: listener.port,
        clientCertificatePem: built.client.cert.pem,
        clientKeyPem: built.client.key.privatePem }));
    assert.strictEqual(report.mutualAuth.verdict, "not-required",
      "a server that does not request a client certificate was reported as " +
      "'" + report.mutualAuth.verdict + "'");
  } finally {
    listener.close();
  }

  // (c) A server that requires one and REJECTS the one offered, because it was
  //     issued by a CA it does not trust. This is the case an operator hits
  //     most and the one a single connection cannot distinguish from (a).
  listener = await startServer(await serverOptions({
    requestCert: true, rejectUnauthorized: true }));
  try {
    const report = await probe.connect(Object.assign({}, base,
      { port: listener.port,
        clientCertificatePem: built.stranger.cert.pem,
        clientKeyPem: built.stranger.key.privatePem }));
    assert.ok(report.result.postHandshakeError ||
        !report.result.connected ||
        (report.result.closedByPeer && !report.result.peerData),
      "a client certificate from an untrusted CA was accepted, or its " +
      "rejection was not noticed: under TLS 1.3 that rejection arrives " +
      "AFTER the handshake, either as an alert or as a bare hang-up, and " +
      "both are missed entirely by an implementation that resolves on " +
      "secureConnect");
    assert.strictEqual(report.mutualAuth.verdict, "required-and-rejected",
      "a server that requires client authentication AND refuses the " +
      "certificate offered is the case an operator hits most, and it is the " +
      "one a single connection cannot tell from 'required'. Got: " +
      report.mutualAuth.verdict + " — " + report.mutualAuth.detail);
    assert.ok(/CA the server does not trust/.test(report.mutualAuth.detail),
      "the verdict must name the likely cause: " + report.mutualAuth.detail);
  } finally {
    listener.close();
  }

  // (d) No probe asked for: no second connection, no verdict.
  listener = await startServer(await serverOptions({ requestCert: false }));
  try {
    const report = await probe.connect({ host: "127.0.0.1",
      port: listener.port, servername: "probe.example.test",
      trustCertificates: [built.ourRoot.cert.pem],
      clientCertificatePem: built.client.cert.pem,
      clientKeyPem: built.client.key.privatePem });
    assert.ok(!report.mutualAuth,
      "a verdict was produced without the probe being asked for, which " +
      "means a second connection was made that the caller did not request");
    assert.strictEqual(report.result.clientCertificateOffered, true,
      "the report must say whether a client certificate was offered");
  } finally {
    listener.close();
  }
  log.debug("Leaving mutualAuthIsMeasuredRatherThanAssumed().");
}

// ---------------------------------------------------------------------------
// 4b. A CLIENT CERTIFICATE MUST BE SENT WITH ITS CHAIN, and the failure when it
//     is not looks exactly like a rejected certificate.
//
// A server verifying a client certificate has to build a path from what the
// client SENT to an anchor it holds. Given only the leaf, a server holding just
// the root cannot bridge the intermediate — and node's TLS server answers that
// by RESETTING the connection with no alert at all, so the far end reads as
// "your certificate was refused" when what it could not do was find the issuer.
//
// This is a real defect that an end-to-end run through the page found: the page
// was sending `certificatePem` where it had to send `chainPems()`. Both halves
// are asserted here — the leaf alone must fail, the chain must work — because
// asserting only the second would pass against a server that verifies nothing.
// ---------------------------------------------------------------------------
async function aClientCertificateIsSentWithItsChain() {
  log.debug("Entering aClientCertificateIsSentWithItsChain().");
  const built = await buildPki();
  const probe = probeFor();
  const listener = await startServer(await serverOptions({
    requestCert: true, rejectUnauthorized: true }));
  try {
    const base = { host: "127.0.0.1", port: listener.port,
                  servername: "probe.example.test",
                  trustCertificates: [built.ourRoot.cert.pem],
                  clientKeyPem: built.deepClient.key.privatePem };

    // The leaf alone: the server cannot reach the anchor it holds.
    const alone = (await probe.connect(Object.assign({}, base,
      { clientCertificatePem: built.deepClient.cert.pem }))).result;
    assert.ok(!alone.usable,
      "a client certificate issued by an INTERMEDIATE was accepted when sent " +
      "without that intermediate. Either the server is not verifying it, or " +
      "this assertion has stopped meaning anything — a server holding only " +
      "the root cannot build the path from the leaf alone.");

    // The leaf and its intermediate, leaf first, concatenated — which is what
    // the `cert` option takes and what the page now sends.
    const chained = (await probe.connect(Object.assign({}, base,
      { clientCertificatePem: built.deepClient.cert.pem +
          built.issuing.cert.pem }))).result;
    assert.strictEqual(chained.usable, true,
      "a client certificate sent WITH its intermediate was still refused: " +
      JSON.stringify(chained.error || chained.postHandshakeError));
    assert.strictEqual(chained.connected, true,
      "the chained handshake did not complete");
    assert.strictEqual(chained.postHandshakeError, null,
      "the chained handshake drew a post-handshake alert");
  } finally {
    listener.close();
  }
  log.debug("Leaving aClientCertificateIsSentWithItsChain().");
}

// ---------------------------------------------------------------------------
// 4c. `usable` is computed by the api, not by its callers.
//
// "Did this connection work" has ONE answer and it is not `connected`: under
// TLS 1.3 a handshake completes before the server has said anything about the
// client certificate. A caller left to re-derive it gets it wrong, which is
// what the page did until an end-to-end run showed it reporting a completed
// handshake for a server that had already hung up.
// ---------------------------------------------------------------------------
async function usableIsDecidedInOnePlace() {
  log.debug("Entering usableIsDecidedInOnePlace().");
  const built = await buildPki();
  const probe = probeFor();

  const good = await startServer(await serverOptions());
  try {
    const report = (await probe.connect({ host: "127.0.0.1",
      port: good.port, servername: "probe.example.test",
      trustCertificates: [built.ourRoot.cert.pem] })).result;
    assert.strictEqual(report.usable, true,
      "an ordinary successful connection must report usable: true");
  } finally {
    good.close();
  }

  const strict = await startServer(await serverOptions({
    requestCert: true, rejectUnauthorized: true }));
  try {
    const report = (await probe.connect({ host: "127.0.0.1",
      port: strict.port, servername: "probe.example.test",
      trustCertificates: [built.ourRoot.cert.pem],
      clientCertificatePem: built.stranger.cert.pem,
      clientKeyPem: built.stranger.key.privatePem })).result;
    assert.strictEqual(report.connected, true,
      "under TLS 1.3 this handshake DOES complete — that is the whole point");
    assert.strictEqual(report.usable, false,
      "the server refused the certificate (by alert or by hanging up) and " +
      "the report still says the connection was usable. Every caller reads " +
      "this field precisely so none of them knows about TLS 1.3's " +
      "ordering.");
  } finally {
    strict.close();
  }
  log.debug("Leaving usableIsDecidedInOnePlace().");
}

// ---------------------------------------------------------------------------
// 5. Versions and ciphers are the caller's, and an impossible combination is
//    refused by name rather than producing a confusing handshake failure.
// ---------------------------------------------------------------------------
async function versionsAndCiphersAreHonoured() {
  log.debug("Entering versionsAndCiphersAreHonoured().");
  const built = await buildPki();
  const probe = probeFor();

  let listener = await startServer(await serverOptions({
    maxVersion: "TLSv1.2" }));
  try {
    const twelve = (await probe.connect({ host: "127.0.0.1",
      port: listener.port, servername: "probe.example.test",
      trustCertificates: [built.ourRoot.cert.pem] })).result;
    assert.strictEqual(twelve.protocol, "TLSv1.2",
      "a server capped at 1.2 negotiated " + twelve.protocol);

    // The client asking for 1.3 against a 1.2-only server must FAIL, and the
    // failure must be reported rather than thrown away.
    const impossible = (await probe.connect({ host: "127.0.0.1",
      port: listener.port, servername: "probe.example.test",
      minVersion: "TLSv1.3",
      trustCertificates: [built.ourRoot.cert.pem] })).result;
    assert.strictEqual(impossible.connected, false,
      "TLSv1.3 was demanded of a 1.2-only server and the handshake " +
      "apparently succeeded");
    assert.ok(impossible.error && impossible.error.message,
      "a failed handshake must carry its error — the alert is the most " +
      "informative thing this endpoint produces");
  } finally {
    listener.close();
  }

  listener = await startServer(await serverOptions());
  try {
    const thirteen = (await probe.connect({ host: "127.0.0.1",
      port: listener.port, servername: "probe.example.test",
      minVersion: "TLSv1.3",
      trustCertificates: [built.ourRoot.cert.pem] })).result;
    assert.strictEqual(thirteen.protocol, "TLSv1.3",
      "TLSv1.3 was demanded and " + thirteen.protocol + " was negotiated");

    // A cipher list the server cannot satisfy fails, and says so.
    const noCipher = (await probe.connect({ host: "127.0.0.1",
      port: listener.port, servername: "probe.example.test",
      maxVersion: "TLSv1.2", ciphers: "ECDHE-RSA-AES128-GCM-SHA256",
      trustCertificates: [built.ourRoot.cert.pem] })).result;
    assert.strictEqual(noCipher.connected, false,
      "an RSA-only cipher list was accepted by an ECDSA server");
  } finally {
    listener.close();
  }

  async function refuses(options, code, what) {
    log.debug("Entering refuses(). what=" + what);
    let threw = null;
    try {
      await probe.connect(options);
    } catch (e) {
      threw = e;
    }
    assert.ok(threw, what + " was accepted");
    assert.strictEqual(threw.code, code,
      what + " was refused as " + threw.code + " rather than " + code + ": " +
      threw.message);
    log.debug("Leaving refuses().");
  }
  await refuses({ host: "127.0.0.1", port: 443, minVersion: "TLSv1.9" },
    "ETLSBADVERSION", "an unknown TLS version");
  await refuses({ host: "127.0.0.1", port: 443, minVersion: "TLSv1.3",
                 maxVersion: "TLSv1.2" },
    "ETLSBADVERSION", "a version range that allows nothing");
  await refuses({ host: "127.0.0.1", port: 0 }, "ETLSBADPORT", "port 0");
  await refuses({ host: "", port: 443 }, "ETLSNOHOST", "no host");
  await refuses({ host: "127.0.0.1", port: 443,
                 clientCertificatePem: "-----BEGIN CERTIFICATE-----" },
    "ETLSNOCLIENTKEY", "a client certificate with no private key");
  log.debug("Leaving versionsAndCiphersAreHonoured().");
}

// ---------------------------------------------------------------------------
// 6. The port allowlist. It is the ONLY thing bounding which ports this
//    endpoint can reach — there is no payload shape to check, because a
//    ClientHello sent anywhere is a well-formed ClientHello.
// ---------------------------------------------------------------------------
async function onlyAllowedPortsAreReachable() {
  log.debug("Entering onlyAllowedPortsAreReachable().");
  const restricted = tlsProbe.createProbe({ tlsAllowedPorts: [443, 8443] },
      OPEN_GUARD, log);
  let threw = null;
  try {
    await restricted.connect({ host: "127.0.0.1", port: 22 });
  } catch (e) {
    threw = e;
  }
  assert.ok(threw, "port 22 was reachable under an allowlist of 443 and 8443");
  assert.strictEqual(threw.code, "ETLSPORTNOTALLOWED",
    "expected a port refusal, got " + threw.code);
  assert.ok(/8443/.test(threw.message),
    "the refusal must say what IS allowed, or the caller cannot act on it");

  // A malformed allowlist falls back to the default rather than to "anything".
  const malformed = tlsProbe.createProbe({ tlsAllowedPorts: "not a list" },
      OPEN_GUARD, log);
  assert.deepStrictEqual(malformed.limits().allowedPorts,
    tlsProbe.DEFAULT_ALLOWED_PORTS,
    "a malformed tlsAllowedPorts must fall back to the default list, not to " +
    "an empty one (which refuses everything, confusingly) and certainly not " +
    "to no restriction at all");

  // An allowlist with no usable entries refuses everything: the safe
  // direction, and logged as the mistake it almost certainly is.
  const empty = tlsProbe.createProbe({ tlsAllowedPorts: [0, 99999] },
      OPEN_GUARD, log);
  threw = null;
  try {
    await empty.connect({ host: "127.0.0.1", port: 443 });
  } catch (e) {
    threw = e;
  }
  assert.strictEqual(threw && threw.code, "ETLSPORTNOTALLOWED",
    "an allowlist whose every entry was invalid must refuse, not allow");

  // "any" is spelled as a word so that enabling it cannot be a typo.
  const anyPort = tlsProbe.createProbe({ tlsAllowedPorts: "any" },
      OPEN_GUARD, log);
  assert.strictEqual(anyPort.limits().allowedPorts, "any",
    "the limits endpoint must publish that any port is reachable");
  log.debug("Leaving onlyAllowedPortsAreReachable().");
}

// ---------------------------------------------------------------------------
// 7. The address policy applies to this raw socket, and a NAME is judged by
//    what it resolves to.
// ---------------------------------------------------------------------------
async function theAddressPolicyAppliesToRawSockets() {
  log.debug("Entering theAddressPolicyAppliesToRawSockets().");
  const calls = [];
  const guard = {
    enabled: true,
    blockedRangeFor: function (address) {
      calls.push(address);
      return /^127\./.test(address) ? "127.0.0.0/8" : null;
    }
  };
  const probe = tlsProbe.createProbe({ tlsAllowedPorts: "any" }, guard, log);

  let threw = null;
  try {
    await probe.connect({ host: "127.0.0.1", port: 8443 });
  } catch (e) {
    threw = e;
  }
  assert.strictEqual(threw && threw.code, "EBLOCKEDADDRESS",
    "a loopback LITERAL was not refused. Node never calls a resolver for a " +
    "literal, which is the gap that made the HTTP guard need two hooks " +
    "rather than one — and a redirect's Location usually IS a literal.");
  assert.ok(/127\.0\.0\.0\/8/.test(threw.message),
    "the refusal must name the range, or the operator cannot tell which " +
    "rule fired");

  // A NAME that resolves into a blocked range must be refused too, and the
  // decision must be made on the ADDRESS.
  const named = tlsProbe.createProbe({ tlsAllowedPorts: "any" }, guard, log,
    { lookup: function (host, cb) { cb(null, "127.0.0.1", 4); } });
  threw = null;
  try {
    await named.connect({ host: "sneaky.example", port: 8443 });
  } catch (e) {
    threw = e;
  }
  assert.strictEqual(threw && threw.code, "EBLOCKEDADDRESS",
    "a hostname resolving to loopback was not refused — a name has to be " +
    "judged by what it resolves to, or localtest.me walks straight past the " +
    "policy");
  assert.ok(/resolves to 127\.0\.0\.1/.test(threw.message),
    "the refusal must say what the name resolved to: " + threw.message);
  assert.ok(calls.indexOf("127.0.0.1") >= 0,
    "the guard's own decision must be what is consulted, rather than a " +
    "second copy of the ranges living in this module");

  // And with the policy off, the same call proceeds to the network.
  const off = tlsProbe.createProbe({ tlsAllowedPorts: "any" }, OPEN_GUARD,
      log);
  assert.strictEqual(off.limits().addressPolicyEnabled, false,
    "the limits endpoint must publish whether the policy is on");
  log.debug("Leaving theAddressPolicyAppliesToRawSockets().");
}

// ---------------------------------------------------------------------------
// 8. The three deadlines, and the one that was missing from the Kerberos relay
//    until a flaky run found it.
// ---------------------------------------------------------------------------
async function everyDeadlineIsSeparateAndArmed() {
  log.debug("Entering everyDeadlineIsSeparateAndArmed().");
  // (a) THE NAME LOOKUP. Until a name is an address, neither of the other
  //     budgets has started, so an unbounded lookup is an unbounded request.
  //     A resolver that works cannot test this, which is why the lookup is
  //     injectable: this one never calls back.
  const stuck = tlsProbe.createProbe(
    { tlsAllowedPorts: "any", connectionTimeout: 300, callTimeout: 5000 },
    OPEN_GUARD, log, { lookup: function () { /* never calls back */ } });
  const started = Date.now();
  let threw = null;
  try {
    await stuck.connect({ host: "never-answers.invalid", port: 443 });
  } catch (e) {
    threw = e;
  }
  const elapsed = Date.now() - started;
  assert.strictEqual(threw && threw.code, "ETLSDNSTIMEOUT",
    "a name lookup that never answers must fail as a DNS timeout, not hang: " +
    "got " + (threw && threw.code));
  assert.ok(elapsed < 3000,
    "the lookup deadline did not fire (waited " + elapsed + " ms against a " +
    "300 ms budget)");
  assert.ok(/DNS/i.test(threw.message) && /resolver/i.test(threw.message),
    "the message must say this is a fact about this machine's resolver " +
    "rather than about the server: " + threw.message);

  // (b) THE CONNECT BUDGET against an address nothing is listening on.
  const probe = probeFor({ connectionTimeout: 400, callTimeout: 4000 });
  // A port in the blackhole range: connecting to a closed loopback port is
  // REFUSED rather than timing out, which is a different path, so both are
  // accepted here — what must not happen is a hang.
  const closedStart = Date.now();
  const closed = (await probe.connect({ host: "127.0.0.1", port: 9,
    servername: "nothing.example" })).result;
  assert.strictEqual(closed.connected, false,
    "a closed port cannot produce a handshake");
  assert.ok(Date.now() - closedStart < 3000,
    "a closed port took longer than the connect budget to report");

  // (c) THE HANDSHAKE BUDGET, and the assertion that separates it from (b): a
  //     server that ACCEPTS the connection and then says nothing is alive and
  //     thinking — which is what a loaded server looks like — so it must get
  //     the whole call budget rather than dying at the connect budget.
  //     Expressing both with one timer makes whichever is smaller the only one
  //     that ever fires, and this fails against that.
  const silent = net.createServer(function (socket) {
    // Accept and say nothing at all: no ServerHello, no close.
    socket.on("error", function () { /* the probe hangs up; fine */ });
  });
  await new Promise(function (resolve) {
    silent.listen(0, "127.0.0.1", resolve);
  });
  const silentPort = silent.address().port;
  try {
    const slow = probeFor({ connectionTimeout: 300, callTimeout: 1500 });
    const handshakeStart = Date.now();
    let handshakeError = null;
    try {
      await slow.connect({ host: "127.0.0.1", port: silentPort,
                          servername: "silent.example" });
    } catch (e) {
      handshakeError = e;
    }
    const took = Date.now() - handshakeStart;
    assert.strictEqual(handshakeError && handshakeError.code,
      "ETLSHANDSHAKETIMEOUT",
      "a server that connects and then says nothing must fail on the " +
      "HANDSHAKE budget, not the connect one: got " +
      (handshakeError && handshakeError.code));
    assert.ok(took >= 1000,
      "the handshake failed after " + took + " ms against a 300 ms connect " +
      "budget and a 1500 ms call budget — the two deadlines have collapsed " +
      "into one, and a slow-but-alive server now dies as readily as a dead " +
      "address");
    assert.ok(took < 4000,
      "the handshake budget did not fire (waited " + took + " ms)");
  } finally {
    silent.close();
  }
  log.debug("Leaving everyDeadlineIsSeparateAndArmed().");
}

// ---------------------------------------------------------------------------
// 9. Every path settles. Aiming this endpoint at a host that may not be there
//    is the point of it, so a hang is the one outcome it may never produce.
// ---------------------------------------------------------------------------
async function everyPathSettles() {
  log.debug("Entering everyPathSettles().");
  const probe = probeFor({ connectionTimeout: 800, callTimeout: 1500 });
  const attempts = [
    { what: "a closed port", options: { host: "127.0.0.1", port: 9 } },
    { what: "a host that does not resolve",
      options: { host: "no-such-host-here.invalid", port: 443 } },
    { what: "a plain HTTP server (no TLS at all)", options: null },
    { what: "a refused port under a policy",
      options: { host: "127.0.0.1", port: 22 } }
  ];
  // A plain HTTP listener, which is what somebody pointing this at the wrong
  // port actually hits — and what tests/pki_page.js drives from the browser.
  const plain = net.createServer(function (socket) {
    socket.on("data", function () {
      socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
    });
    socket.on("error", function () { /* expected */ });
  });
  await new Promise(function (resolve) {
    plain.listen(0, "127.0.0.1", resolve);
  });
  attempts[2].options = { host: "127.0.0.1", port: plain.address().port };
  try {
    for (const attempt of attempts) {
      const started = Date.now();
      let settled = false;
      try {
        const report = await probe.connect(attempt.options);
        settled = true;
        // A failed handshake is a RESULT, so these resolve rather than throw.
        assert.strictEqual(report.result.connected, false,
          attempt.what + " somehow completed a handshake");
        assert.ok(report.result.error,
          attempt.what + " produced no error to show the user");
      } catch (e) {
        settled = true;
        assert.ok(e.code, attempt.what + " threw without a code: " +
            e.message);
      }
      const took = Date.now() - started;
      assert.ok(settled, attempt.what + " never settled");
      assert.ok(took < 6000,
        attempt.what + " took " + took + " ms — every path here must settle " +
        "inside the budgets, because the alternative is a browser waiting on " +
        "an api that never replies");
      log.debug(attempt.what + ": settled in " + took + " ms");
    }
  } finally {
    plain.close();
  }
  log.debug("Leaving everyPathSettles().");
}

// ---------------------------------------------------------------------------
// 10. The truststore parser, and its cap.
// ---------------------------------------------------------------------------
async function truststoreInputIsSplitAndBounded() {
  log.debug("Entering truststoreInputIsSplitAndBounded().");
  const built = await buildPki();
  const bundle = built.ourRoot.cert.pem + built.otherRoot.cert.pem;
  const split = tlsProbe.splitPemCertificates(bundle);
  assert.strictEqual(split.length, 2,
    "a pasted BUNDLE must be split into individual certificates — node's " +
    "`ca` option takes an array, and handing it the bundle as one string " +
    "uses only the first certificate on some node versions, which reads as " +
    "'the root I added is not trusted'");
  assert.ok(/-----END CERTIFICATE-----$/.test(split[0].trim()),
    "each split certificate must be complete");
  assert.strictEqual(tlsProbe.splitPemCertificates("not a certificate").length,
    0, "text with no certificate in it yields none");

  const probe = probeFor();
  const many = [];
  for (let i = 0; i < tlsProbe.MAX_TRUST_ANCHORS + 1; i++) {
    many.push(built.ourRoot.cert.pem);
  }
  let threw = null;
  try {
    await probe.connect({ host: "127.0.0.1", port: 443,
                         trustCertificates: many });
  } catch (e) {
    threw = e;
  }
  assert.strictEqual(threw && threw.code, "ETLSTRUSTTOOLARGE",
    "an oversized truststore must be refused before a socket is opened");
  log.debug("Leaving truststoreInputIsSplitAndBounded().");
}

// ---------------------------------------------------------------------------
// 11. Asking the server what IT saw, over the connection just made.
//
// Everything above is this end's account of the handshake, and this end is the
// party that already knows what it sent. `httpRequest` is how the far end's
// account comes back, and there are four things about it worth asserting:
//
//   * the response is reported verbatim — status line, headers, body;
//   * a CHUNKED body is de-framed, in BYTES. That is not fussiness: a chunk
//     size counts bytes and a JavaScript string is indexed in code units, so a
//     decoder that works on text walks into the framing of the next chunk the
//     moment the body contains a multi-byte character. It produced valid JSON
//     followed by a fragment of hexadecimal, against a server whose only crime
//     was writing prose with em dashes in it, and this case is that server;
//   * a server that HANGS UP instead of answering must not read as success. It
//     is the TLS 1.3 client-certificate rejection, arriving as a FIN with no
//     bytes behind it — and 'end' fires before 'close', so a `usable` computed
//     only from the 'close' handler reports a happy connection to a server that
//     refused the certificate;
//   * the path is the only part of the request a caller contributes, so a path
//     carrying CR or LF is refused BY NAME rather than escaped. Escaping means
//     deciding what the caller meant, and what a newline in a request line
//     means is somebody else's header.
// ---------------------------------------------------------------------------
async function theServerIsAskedWhatItSaw() {
  log.debug("Entering theServerIsAskedWhatItSaw().");
  const built = await buildPki();
  const https = require("https");

  // An https server rather than the bare tls one above, because what is being
  // tested is a real HTTP response — including the chunked framing node applies
  // whenever it does not know the body's length in advance, which is here.
  const options = await serverOptions({ requestCert: true,
                                       rejectUnauthorized: false });
  const seen = [];
  const server = https.createServer(options, function (req, res) {
    seen.push({ method: req.method, url: req.url, headers: req.headers });
    if (req.url === "/plain") {
      const body = "just text";
      res.writeHead(200, { "Content-Type": "text/plain",
                          "Content-Length": Buffer.byteLength(body) });
      res.end(body);
      return;
    }
    // No Content-Length, so node chunks it — and the body carries em dashes and
    // an accented name on purpose, so a byte/character confusion in the decoder
    // shows up as corruption rather than passing by luck.
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      sawClientCertificate: !!(req.socket.getPeerCertificate() || {}).subject,
      authorized: req.socket.authorized === true,
      protocol: req.socket.getProtocol(),
      servername: req.socket.servername || null,
      note: "a report — written by the server — about the connection it is " +
        "travelling on, with a name like Ø and an em dash — twice"
    }));
  });
  await new Promise(function (resolve) {
    server.listen(0, "127.0.0.1", resolve);
  });
  const port = server.address().port;

  try {
    const probe = probeFor();
    const report = (await probe.connect({
      host: "127.0.0.1", port: port, servername: "probe.example.test",
      trustCertificates: [built.ourRoot.cert.pem],
      clientCertificatePem: built.client.cert.pem,
      clientKeyPem: built.client.key.privatePem,
      httpRequest: { path: "/whoami?asked=1" }
    })).result;

    assert.strictEqual(report.connected, true,
      "the handshake did not complete: " + JSON.stringify(report.error));
    assert.ok(report.httpResponse,
      "httpRequest was asked for and no response was reported at all");
    assert.strictEqual(report.httpResponse.statusCode, 200,
      "the status line was not read: " +
      JSON.stringify(report.httpResponse.statusLine));
    assert.strictEqual(report.httpResponse.headers["content-type"],
      "application/json",
      "the response headers must come back — they are half of what the far " +
      "end said: " + JSON.stringify(report.httpResponse.headers));
    assert.strictEqual(report.httpResponse.transferEncoding, "chunked",
      "this server answers chunked (node does whenever it does not know the " +
      "length), and the report must say so rather than silently hiding that " +
      "the body was de-framed");
    assert.strictEqual(report.httpResponse.bodyComplete, true,
      "the chunked body did not reach its terminating zero-length chunk");

    let parsed = null;
    try {
      parsed = JSON.parse(report.httpResponse.body);
    } catch (e) {
      throw new Error("the body did not survive the read: " + e.message +
        ". The usual cause is de-framing a chunked body as a STRING — the " +
        "chunk sizes are BYTES, so every multi-byte character shifts the end " +
        "of the chunk and the decoder walks into the next size line. The " +
        "body was: " + JSON.stringify(report.httpResponse.body.slice(0, 400)));
    }
    assert.strictEqual(parsed.authorized, true,
      "the SERVER's own account says it did not verify the client " +
      "certificate, which is the thing this whole feature exists to report");
    assert.strictEqual(parsed.sawClientCertificate, true,
      "the server saw no client certificate on a connection that presented " +
      "one");
    assert.ok(/em dash — twice/.test(parsed.note),
      "the multi-byte characters were corrupted in transit: " + parsed.note);

    // The request that went out is reported too, and it is built here rather
    // than by the caller: a caller that could set a header could set any
    // header.
    assert.strictEqual(report.httpRequest.method, "GET",
      "the method is GET and nothing else");
    assert.strictEqual(report.httpRequest.path, "/whoami?asked=1",
      "the path asked for was not the path sent");
    assert.strictEqual(seen.length, 1,
      "expected exactly one request to reach the server, got " + seen.length);
    assert.strictEqual(seen[0].url, "/whoami?asked=1",
      "the server received a different path: " + seen[0].url);
    assert.strictEqual(seen[0].headers.host, "probe.example.test:" + port,
      "the Host header must be the name asked to be VERIFIED, so a virtual " +
      "host routes this request the way it routed the handshake: " +
      seen[0].headers.host);
    assert.strictEqual(seen[0].headers.connection, "close",
      "Connection: close is what makes the end of the response an event " +
      "rather than a guess");

    // And a response WITH a Content-Length must come back just as whole. The
    // two paths through the reader are different, so one working proves
    // nothing about the other.
    const plain = (await probe.connect({
      host: "127.0.0.1", port: port, servername: "probe.example.test",
      trustCertificates: [built.ourRoot.cert.pem],
      httpRequest: "/plain"
    })).result;
    assert.strictEqual(plain.httpResponse.body, "just text",
      "a Content-Length body was not read verbatim: " +
      JSON.stringify(plain.httpResponse.body));
    assert.strictEqual(plain.httpResponse.transferEncoding, null,
      "an unchunked response must not claim to have been de-framed");
    assert.strictEqual(plain.usable, true,
      "a server that answered is a server this connection worked with");
  } finally {
    server.close();
  }

  // A server that hangs up rather than answering — which is exactly what a TLS
  // 1.3 server does when it rejects the client certificate, and what node's own
  // server does with rejectUnauthorized. The request goes out, nothing comes
  // back, and the connection must NOT read as usable.
  const strict = await startServer(await serverOptions({
    requestCert: true, rejectUnauthorized: true }));
  try {
    const probe = probeFor();
    const refused = (await probe.connect({
      host: "127.0.0.1", port: strict.port, servername: "probe.example.test",
      trustCertificates: [built.ourRoot.cert.pem],
      clientCertificatePem: built.stranger.cert.pem,
      clientKeyPem: built.stranger.key.privatePem,
      httpRequest: { path: "/whoami" }
    })).result;
    assert.strictEqual(refused.usable, false,
      "a server that took the request and then hung up without answering is " +
      "refusing the client certificate, and `usable` must say so. 'end' " +
      "fires before 'close', so recording the hang-up only in the 'close' " +
      "handler leaves this true — which is a happy mutual-TLS report about a " +
      "connection the server rejected.");
    assert.ok(!refused.httpResponse || !refused.httpResponse.statusCode,
      "nothing was answered, so there is no status to report");
  } finally {
    strict.close();
  }

  // The path is the only thing a caller contributes to the bytes that go out.
  const probe = probeFor();
  const badPaths = ["whoami", "/x HTTP/1.0", "/x\r\nX-Injected: 1",
                    "/x\nX-Injected: 1", "/" + "a".repeat(4096)];
  for (const bad of badPaths) {
    let threw = null;
    try {
      await probe.connect({ host: "127.0.0.1", port: 443,
                           httpRequest: { path: bad } });
    } catch (e) {
      threw = e;
    }
    assert.strictEqual(threw && threw.code, "ETLSBADHTTPPATH",
      "the path " + JSON.stringify(bad) + " must be refused by name before a " +
      "socket is opened, not escaped: escaping means deciding which of two " +
      "things the caller meant, and a newline in a request line is somebody " +
      "else's header. Got " + (threw ? threw.code : "no refusal at all"));
  }

  // And the parser itself, on a response that is not one. A far end that hangs
  // up mid-header is a fact about the far end, not an error here.
  const nonsense = tlsProbe.parseHttpResponse("HTTP/1.1 200 OK\r\nX-Half:");
  assert.strictEqual(nonsense.parsed, false,
    "a response with no blank line in it cannot have been parsed");
  assert.ok(/X-Half/.test(nonsense.raw),
    "what did arrive must still be reported: " + JSON.stringify(nonsense.raw));
  log.debug("Leaving theServerIsAskedWhatItSaw().");
}

// ---------------------------------------------------------------------------
// 12. What GET /tls/limits publishes. A page that discovers the api's limits
//     by hitting them reports them as somebody else's fault.
// ---------------------------------------------------------------------------
function limitsArePublished() {
  log.debug("Entering limitsArePublished().");
  const probe = tlsProbe.createProbe({ tlsAllowedPorts: [443],
    connectionTimeout: 1234, callTimeout: 4321, maxContentLength: 65536 },
    OPEN_GUARD, log);
  const limits = probe.limits();
  assert.deepStrictEqual(limits.allowedPorts, [443],
    "the allowed ports must be published");
  assert.strictEqual(limits.connectionTimeoutMs, 1234,
    "the connect budget must be published");
  assert.strictEqual(limits.callTimeoutMs, 4321,
    "the handshake budget must be published");
  assert.strictEqual(limits.maxChainBytes, 65536,
    "the chain cap must be published");
  assert.deepStrictEqual(limits.tlsVersions,
    ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"],
    "the version list the page's dropdowns offer must come from here");
  assert.ok(limits.systemRootCount > 0,
    "the platform root count must be published — 'also trust the platform " +
    "roots' is meaningless without knowing there are any");
  assert.strictEqual(limits.mutualAuthProbeAvailable, true,
    "the page checks this before offering the mutual-auth checkbox, so an " +
    "older api can be told from a broken one");
  assert.strictEqual(limits.httpRequestAvailable, true,
    "the page checks this before offering to ask the server what it saw, for " +
    "the same reason: a request an older api silently ignores must read as " +
    "an older api rather than as a server that said nothing");
  assert.strictEqual(limits.httpRequestMethod, "GET",
    "the method is not negotiable and the page says so on the pane");
  assert.ok(limits.httpResponseGraceMs > 0,
    "the response grace must be published — it is what bounds a server that " +
    "answers and then keeps the socket open");
  log.debug("Leaving limitsArePublished().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. Verifying api/tls_probe.js.");
  limitsArePublished();
  await onlyAllowedPortsAreReachable();
  await theAddressPolicyAppliesToRawSockets();
  await truststoreInputIsSplitAndBounded();
  await aHandshakeIsReportedInFull();
  await theTruststoreDecidesTheVerdict();
  await theVerifiedNameIsSeparateFromTheAddress();
  await versionsAndCiphersAreHonoured();
  await mutualAuthIsMeasuredRatherThanAssumed();
  await aClientCertificateIsSentWithItsChain();
  await usableIsDecidedInOnePlace();
  await theServerIsAskedWhatItSaw();
  await everyDeadlineIsSeparateAndArmed();
  await everyPathSettles();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("api_tls_probe")
  .description("Verify the TLS probe's address policy, port allowlist, " +
      "truststore handling, mutual-auth measurement and deadlines.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
      "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
