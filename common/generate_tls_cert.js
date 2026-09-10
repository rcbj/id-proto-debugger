// File: generate_tls_cert.js
//
// ---------------------------------------------------------------------------
// THE ONE PLACE A TLS SERVER CERTIFICATE FOR THIS STACK IS MADE, AND IT IS A
// CALLER OF THIS PROJECT'S OWN X.509 MODULE RATHER THAN A NEW ENCODER.
//
// `client/src/x509.js` already authors certificates: fourteen profiles, every
// X.509v3 extension, and a `tls-server` profile that exists for exactly this.
// `client/src/key_material.js` already makes the key pair. Between them,
// `tests/pki_x509.js` drives about 240 certificates through that encoder in
// node and hands every one of them to **OpenSSL** — which makes it the one
// certificate encoder in this repository that has been shown to agree with
// somebody else's parser.
//
// So this file contains no cryptography and no DER. Writing a dozen lines of
// node-forge here instead would have produced a second encoder with nothing
// behind it, which is the mistake `common/xmldsig.js`'s header records having
// been made three times over in XML Signature — a canonicalizer is a READING
// of a specification, and so is a certificate profile.
//
// ---------------------------------------------------------------------------
// WHY IT IS A SCRIPT AND NOT PART OF THE SERVICES.
//
// The certificate has to exist BEFORE anything starts, because the mock STS
// pushes to the api (RFC 8935 Shared Signals delivery) and therefore has to be
// given the anchor in its environment. A certificate a service generates for
// itself at startup cannot be trusted by a container that was configured a
// moment earlier. One pair, on disk, before compose — see the header of
// common/tls_listener.js.
//
// It also cannot live in the api: `client/src/x509.js` needs pkijs, asn1js and
// the @noble family, which are the CLIENT's dependencies. This script runs on
// the host, out of the checkout, where `client/node_modules` is what those
// requires resolve against — the same place common/common.sh's
// generateSpKeyPair() already runs openssl from.
//
// ---------------------------------------------------------------------------
// THE SANs ARE THE WHOLE CERTIFICATE.
//
// A TLS server certificate is judged by its subjectAltName and by nothing else
// — a matching Common Name has not been accepted by Chrome since 58 nor by
// node since 0.12 — and the names this stack is reached by differ per
// launcher: `localhost` on the host launchers, `client` and `api` on the
// containerized bridge, and the loopback literals from anything that dials an
// address instead of a name. Every one of them goes in every certificate,
// because a certificate that is right on one stack and wrong on another fails
// as ERR_TLS_CERT_ALTNAME_INVALID — which names the certificate rather than
// the stack that asked for the wrong name.
//
// ---------------------------------------------------------------------------
// USAGE
//
//   node common/generate_tls_cert.js --out-dir <dir> [--ca-dir <dir>]
//                                    [--rotate-ca] [--name <extra-san>]...
//
// Writes <out-dir>/stack-tls-key.pem and <out-dir>/stack-tls-cert.pem — the
// latter being the leaf, the issuing CA and the root as one PEM bundle — and
// prints the two paths and the base64 SHA-256 of the LEAF's
// SubjectPublicKeyInfo (the SPKI pin Chrome's
// --ignore-certificate-errors-spki-list takes), one `KEY=value` per line.
//
// The certificate authority lives in --ca-dir, which defaults to <out-dir>/ca
// and is REUSED whenever it is already there: that is what lets a person
// trust the root once instead of once per run. --rotate-ca throws it away and
// starts a new one, which invalidates that trust deliberately. The three
// printed lines are unchanged by any of this, because common/common.sh reads
// them by name.
// ---------------------------------------------------------------------------
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

// The Entering/Leaving convention wants a `log` here and bunyan is not
// reachable from common/ — the same situation common/sp_keypair.js is in and
// documents at length. This is that file's console-backed shim; DEBUG off, so
// an ordinary run prints only what it is asked for. The methods below are the
// one place the convention cannot apply: a log line inside log.debug() is
// infinite recursion.
var DEBUG = process.env.TLS_CERT_DEBUG === 'true';
var LOG_TAG = '[generate_tls_cert]';
var log = {
  debug: function () {
    if (!DEBUG) {
      return;
    }
    console.error.apply(console,
      [LOG_TAG].concat(Array.prototype.slice.call(arguments)));
  },
  info: function () {
    console.error.apply(console,
      [LOG_TAG].concat(Array.prototype.slice.call(arguments)));
  },
  warn: function () {
    console.warn.apply(console,
      [LOG_TAG].concat(Array.prototype.slice.call(arguments)));
  },
  error: function () {
    console.error.apply(console,
      [LOG_TAG].concat(Array.prototype.slice.call(arguments)));
  }
};

// The names every certificate this stack uses has to answer to. THE ONE COPY:
// common/tls_listener.js reads a certificate rather than making one, so it has
// no business holding a second list that could drift from this.
//
// THE LAST THREE ARE THE MOCK STS's, and they are here so that ONE leaf serves
// all three processes rather than two of them plus a stranger. That service
// used to issue its own self-signed certificate at every start and publish it
// from `GET /tls/server-certificate` for a caller to trust — which works, and
// costs a SECOND trust decision, on a THIRD origin, renewed every restart.
// Since the leaf now chains to a root that outlives it, handing the mock the
// same file makes one trusted root cover the UI, the api and the mock at once.
// They are the mock's own `tls.hostnames` default (localhost, sts, sts-mock,
// sts.example.com), so its certificate answers to exactly the names its
// callers already use; `sts` is the compose service name and the other two are
// what a host run and its documentation reach it by.
const DNS_NAMES = ['localhost', 'client', 'api',
                   'sts', 'sts-mock', 'sts.example.com'];
const IP_NAMES = ['127.0.0.1', '::1'];

// ---------------------------------------------------------------------------
// THE STDOUT CONTRACT IS ENFORCED HERE, NOT MERELY DOCUMENTED.
//
// The two modules below are ordinary client modules, and every module under
// client/src carries a bunyan logger whose stream is process.stdout and whose
// level is read from CONFIG_FILE — which the launchers export, which resolves
// from client/src/ because require() is relative to the module that calls it,
// and which in both ./env/local.js and ./env/docker-tests.js says "debug". So
// merely REQUIRING x509.js under a launcher put a few hundred
// Entering/Leaving records on the one channel common/common.sh reads back:
// bash applied quote removal and brace expansion to the JSON and reported
// `name:pqc: command not found` fourteen times, naming a module that had done
// nothing wrong.
//
// Lowering the level here would only narrow that — an info line from any of
// the thirty modules underneath would do it again — so stdout is taken away
// for the whole run instead and handed back only to the three lines main()
// prints, through the reference captured here. Only under `require.main`: a
// consumer that requires this file for altNames() or spkiPin() keeps its own
// stdout.
// ---------------------------------------------------------------------------
const RUNNING_AS_SCRIPT = require.main === module;
const writeStdout = process.stdout.write.bind(process.stdout);
if (RUNNING_AS_SCRIPT) {
  process.stdout.write = function () {
    return process.stderr.write.apply(process.stderr, arguments);
  };
}

// The project's own authoring modules. Required by path rather than through
// tests/module_paths.js, which is the TEST suite's resolver and is not
// reachable from a launcher.
const keys = require('../client/src/key_material.js');
const x509 = require('../client/src/x509.js');

function parseArgs(argv) {
  log.debug('Entering parseArgs().');
  const out = { outDir: '', caDir: '', rotateCa: false, extraNames: [] };
  for (var at = 0; at < argv.length; at++) {
    if (argv[at] === '--out-dir' && argv[at + 1]) {
      out.outDir = argv[at + 1];
      at++;
    } else if (argv[at] === '--ca-dir' && argv[at + 1]) {
      out.caDir = argv[at + 1];
      at++;
    } else if (argv[at] === '--rotate-ca') {
      out.rotateCa = true;
    } else if (argv[at] === '--name' && argv[at + 1]) {
      out.extraNames.push(argv[at + 1]);
      at++;
    }
  }
  log.debug('Leaving parseArgs(). outDir=' + out.outDir);
  return out;
}

// Every subjectAltName entry, in the shape x509.js takes: {kind, value}, where
// kind is 'dns' or 'ip'. The machine's own hostname is added because on the
// containerized bridge a container is reachable by it and it cannot be written
// down ahead of time; duplicates are dropped rather than repeated, since a
// repeated SAN is legal and still reads as though somebody built it twice.
function altNames(extraNames) {
  log.debug('Entering altNames().');
  const dns = DNS_NAMES.slice();
  [].concat(extraNames || [], [os.hostname()]).forEach(function (one) {
    const name = String(one || '').trim();
    if (name && dns.indexOf(name) === -1) {
      dns.push(name);
    }
  });
  const names = dns.map(function (one) {
    return { kind: 'dns', value: one };
  }).concat(IP_NAMES.map(function (one) {
    return { kind: 'ip', value: one };
  }));
  log.debug('Leaving altNames(). ' + names.length + ' name(s).');
  return names;
}

// The SPKI pin Chrome's --ignore-certificate-errors-spki-list takes: the
// base64 SHA-256 of the DER-encoded SubjectPublicKeyInfo. Not of the
// certificate and not of the PEM text — getting that wrong produces a pin that
// is simply never matched, which looks exactly like no pin at all.
// common/common.sh computes the same value from the same input with three
// openssl invocations; this is that arithmetic where the key already is.
function spkiPin(certPem) {
  log.debug('Entering spkiPin().');
  const der = new crypto.X509Certificate(certPem).publicKey
    .export({ type: 'spki', format: 'der' });
  const pin = crypto.createHash('sha256').update(der).digest('base64');
  log.debug('Leaving spkiPin().');
  return pin;
}

// ---------------------------------------------------------------------------
// THE HIERARCHY: A ROOT CA, AN ISSUING CA UNDER IT, AND THE LEAF THE STACK
// SERVES — ALL THREE FROM client/src/x509.js's OWN PROFILES.
//
// This was ONE self-signed leaf until 2026-09-01, and what ended that is what
// a browser actually trusts. A trust decision names a KEY: clicking through an
// interstitial, importing an anchor, pinning an SPKI — every one of them is
// about the exact certificate in front of you, so every one of them is VOID
// the next time this script runs.
//
// That is not a theoretical cost. The api is a SECOND ORIGIN
// (https://localhost:4000) which no tab ever navigates to, so its exception is
// the one nobody re-grants by hand — and its absence reaches the browser as a
// CORS error naming a header nobody changed. See the note under "Running the
// App" in the repo-root CLAUDE.md.
//
// A root that OUTLIVES the leaf turns that into a single act: trust the root
// once, and every certificate issued here afterwards is trusted with no
// further clicks. That matters most for the browsers a pin cannot reach —
// Firefox carries its OWN NSS store on every platform, and Chrome's
// --ignore-certificate-errors-spki-list has no Firefox equivalent.
//
// THE PROFILES ARE THE PKI PAGE'S, UNWRAPPED. `root-ca`, `issuing-ca` and
// `tls-server` are three of the fourteen in x509.js, used exactly as the page
// uses them. This file gains no certificate profile of its own, for the same
// reason it has never had an encoder of its own.
//
// WHY AN ISSUING CA RATHER THAN A ROOT THAT SIGNS LEAVES. A root that signs
// directly cannot be kept back, cannot be rotated without re-trusting, and
// models nothing anybody deploys — on a stack whose entire subject is what
// real PKI does. `issuing-ca` carries pathLen 0, so this chain is exactly
// three certificates deep and provably cannot grow.
//
// ec-p256 throughout, matching what tests/api_tls_probe.js's own listeners
// use: every TLS implementation in reach negotiates it, and it generates in a
// millisecond where RSA-2048 is about a hundred.
// ---------------------------------------------------------------------------
const KEY_ALG = 'ec-p256';
const SIG_ALG = 'sha256-ecdsa';

// The four files that ARE the certificate authority. They are deliberately
// not in the output directory: compose bind-mounts that into the api and the
// client (see docker-compose.yml), and the root private key is the one piece
// of material here that a person has told their browser to trust. It has no
// business inside a container that never signs anything.
const CA_FILES = {
  rootKey: 'stack-tls-root-key.pem',
  rootCert: 'stack-tls-root.pem',
  issuingKey: 'stack-tls-issuing-key.pem',
  issuingCert: 'stack-tls-issuing.pem'
};

function caPaths(caDir) {
  log.debug('Entering caPaths().');
  const out = {};
  Object.keys(CA_FILES).forEach(function (name) {
    out[name] = path.join(caDir, CA_FILES[name]);
  });
  log.debug('Leaving caPaths().');
  return out;
}

// The CA already on disk, or null. NULL RATHER THAN A THROW for a missing
// file, because "there is no CA yet" is the ordinary first run; a file that
// exists and cannot be read or parsed is a different thing and says so.
function readCa(caDir) {
  log.debug('Entering readCa().');
  const at = caPaths(caDir);
  const missing = Object.keys(at).filter(function (name) {
    return !fs.existsSync(at[name]);
  });
  if (missing.length) {
    log.debug('Leaving readCa(). ' + missing.length + ' file(s) absent.');
    return null;
  }
  const read = {};
  Object.keys(at).forEach(function (name) {
    read[name] = fs.readFileSync(at[name], 'utf8');
  });
  // An EXPIRED anchor is worth catching here rather than at a handshake: the
  // browser reports it against the leaf, which is freshly issued and looks
  // perfectly good, and says nothing about the root twenty years above it.
  const rootEnd = new crypto.X509Certificate(read.rootCert).validTo;
  if (new Date(rootEnd).getTime() <= Date.now()) {
    log.warn('The root CA in ' + caDir + ' expired on ' + rootEnd + '. ' +
             'Issuing a new one — it has to be trusted again.');
    log.debug('Leaving readCa(). Root expired.');
    return null;
  }
  const issuingEnd =
    new crypto.X509Certificate(read.issuingCert).validTo;
  if (new Date(issuingEnd).getTime() <= Date.now()) {
    log.warn('The issuing CA in ' + caDir + ' expired on ' + issuingEnd +
             '. Issuing a new one under the SAME root, so nothing has to ' +
             'be trusted again.');
    log.debug('Leaving readCa(). Issuing CA expired.');
    return { root: { pem: read.rootCert, privatePem: read.rootKey },
             issuing: null };
  }
  log.debug('Leaving readCa(). Reused.');
  return {
    root: { pem: read.rootCert, privatePem: read.rootKey },
    issuing: { pem: read.issuingCert, privatePem: read.issuingKey }
  };
}

async function makeRootCa() {
  log.debug('Entering makeRootCa().');
  const key = await keys.generateKeyPair(KEY_ALG);
  const cert = await x509.issueCertificate({
    profile: 'root-ca',
    subject: 'CN=id-proto-debugger Local Root CA,O=idptools',
    subjectPublicKey: key.publicPem,
    issuerPrivateKey: key.privatePem,
    signatureAlg: SIG_ALG,
    extensions: x509.defaultExtensions('root-ca')
  });
  log.debug('Leaving makeRootCa().');
  return { pem: cert.pem, privatePem: key.privatePem };
}

async function makeIssuingCa(root) {
  log.debug('Entering makeIssuingCa().');
  const key = await keys.generateKeyPair(KEY_ALG);
  const cert = await x509.issueCertificate({
    profile: 'issuing-ca',
    subject: 'CN=id-proto-debugger Issuing CA,O=idptools',
    subjectPublicKey: key.publicPem,
    issuer: { certificatePem: root.pem, privateKeyPem: root.privatePem,
              keyAlg: KEY_ALG },
    signatureAlg: SIG_ALG,
    extensions: x509.defaultExtensions('issuing-ca')
  });
  log.debug('Leaving makeIssuingCa().');
  return { pem: cert.pem, privatePem: key.privatePem };
}

// The CA to issue this run's leaf from: whatever is on disk, or a new one.
// REUSE IS THE ENTIRE POINT — a root regenerated per run would be exactly the
// self-signed leaf this replaced, with two more files to carry.
async function loadOrMakeCa(caDir, rotate) {
  log.debug('Entering loadOrMakeCa(). rotate=' + !!rotate);
  const existing = rotate ? null : readCa(caDir);
  const root = (existing && existing.root) || await makeRootCa();
  const issuing = (existing && existing.issuing) || await makeIssuingCa(root);
  const fresh = !existing || !existing.issuing;
  if (fresh) {
    const at = caPaths(caDir);
    fs.mkdirSync(caDir, { recursive: true });
    // 0600 on both private keys, and this one is NOT the trade
    // common/common.sh makes for the leaf. That key is throwaway and has to
    // be read by a container running as another uid; these never leave the
    // host, and the root's is the key a browser has been told to trust — it
    // can mint a certificate for any name at all.
    fs.writeFileSync(at.rootKey, root.privatePem, { mode: 0o600 });
    fs.writeFileSync(at.rootCert, root.pem, { mode: 0o644 });
    fs.writeFileSync(at.issuingKey, issuing.privatePem, { mode: 0o600 });
    fs.writeFileSync(at.issuingCert, issuing.pem, { mode: 0o644 });
  }
  log.debug('Leaving loadOrMakeCa(). ' +
            (fresh ? 'Wrote a new CA.' : 'Reused the CA on disk.'));
  return { root: root, issuing: issuing, fresh: fresh,
           rootFile: caPaths(caDir).rootCert };
}

// The leaf, plus the chain a client needs to build a path to the root.
//
// WHAT stack-tls-cert.pem HOLDS, AND WHY THE ROOT IS IN IT. Node takes a PEM
// BUNDLE for `cert` and sends every certificate in it, so leaf-then-issuing is
// what a handshake requires. The root is appended for a reason that is not
// about TLS at all: common/common.sh points STACK_TLS_CA_FILE at this same
// file and the compose files hand it to node as NODE_EXTRA_CA_CERTS, so with
// the root inside it every existing consumer keeps working with no path
// changed anywhere. A client that already trusts the root ignores the extra
// copy. Anything reading this file for the SERVER's certificate — the SPKI
// pin here, `openssl x509 -in`, node's X509Certificate — takes the FIRST one,
// which is the leaf.
async function generate(outDir, extraNames, opts) {
  log.debug('Entering generate().');
  const options = opts || {};
  const caDir = options.caDir || path.join(outDir, 'ca');
  const ca = await loadOrMakeCa(caDir, options.rotateCa);

  const key = await keys.generateKeyPair(KEY_ALG);
  const extensions = x509.defaultExtensions('tls-server');
  extensions.subjectAltName = { present: true, critical: false,
                                names: altNames(extraNames) };
  const cert = await x509.issueCertificate({
    profile: 'tls-server',
    subject: 'CN=id-proto-debugger,O=idptools',
    subjectPublicKey: key.publicPem,
    issuer: { certificatePem: ca.issuing.pem,
              privateKeyPem: ca.issuing.privatePem,
              keyAlg: KEY_ALG },
    signatureAlg: SIG_ALG,
    extensions: extensions
  });

  fs.mkdirSync(outDir, { recursive: true });
  const keyFile = path.join(outDir, 'stack-tls-key.pem');
  const certFile = path.join(outDir, 'stack-tls-cert.pem');
  const chain = [cert.pem, ca.issuing.pem, ca.root.pem].join('');
  fs.writeFileSync(keyFile, key.privatePem, { mode: 0o600 });
  fs.writeFileSync(certFile, chain, { mode: 0o644 });
  const out = { keyFile: keyFile, certFile: certFile,
                rootFile: ca.rootFile, caDir: caDir, freshCa: ca.fresh,
                pin: spkiPin(chain) };
  log.debug('Leaving generate().');
  return out;
}

async function main() {
  log.debug('Entering main().');
  const args = parseArgs(process.argv.slice(2));
  if (!args.outDir) {
    log.error('generate_tls_cert.js needs --out-dir <dir>.');
    log.debug('Leaving main(). No --out-dir.');
    process.exitCode = 1;
    return;
  }
  const made = await generate(args.outDir, args.extraNames,
    { caDir: args.caDir, rotateCa: args.rotateCa });
  // One KEY=value per line, through the saved reference rather than through
  // process.stdout.write — which by now goes to stderr, so that these three
  // lines are the ONLY thing on the channel common/common.sh parses. See the
  // stdout note above the requires.
  writeStdout('STACK_TLS_KEY_FILE=' + made.keyFile + '\n');
  writeStdout('STACK_TLS_CERT_FILE=' + made.certFile + '\n');
  writeStdout('STACK_TLS_SPKI_PIN=' + made.pin + '\n');
  log.debug('Leaving main().');
}

if (require.main === module) {
  main().catch(function (e) {
    log.error(e.stack || e.message);
    process.exitCode = 1;
  });
}

module.exports = {
  generate: generate,
  altNames: altNames,
  spkiPin: spkiPin,
  DNS_NAMES: DNS_NAMES,
  IP_NAMES: IP_NAMES
};
