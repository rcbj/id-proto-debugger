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
//   node common/generate_tls_cert.js --out-dir <dir> [--name <extra-san>]...
//
// Writes <dir>/stack-tls-key.pem and <dir>/stack-tls-cert.pem, and prints the
// two paths and the base64 SHA-256 of the SubjectPublicKeyInfo — the SPKI pin
// Chrome's --ignore-certificate-errors-spki-list takes — one `KEY=value` per
// line, so a shell can eval it.
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
const DNS_NAMES = ['localhost', 'client', 'api'];
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
  const out = { outDir: '', extraNames: [] };
  for (var at = 0; at < argv.length; at++) {
    if (argv[at] === '--out-dir' && argv[at + 1]) {
      out.outDir = argv[at + 1];
      at++;
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

// A self-signed `tls-server` certificate. SELF-SIGNED rather than issued from
// a throwaway root, and that is a deliberate simplification: the consumers
// trust it as an exact key (Chrome's SPKI pin) or as an anchor
// (NODE_EXTRA_CA_CERTS), and both of those take the leaf directly. A root
// would add a second file for every consumer to carry and would verify
// nothing that the pin does not already verify.
//
// ec-p256, matching what tests/api_tls_probe.js's own listeners use: every TLS
// implementation in reach negotiates it, and it generates in a millisecond
// where RSA-2048 is about a hundred.
async function generate(outDir, extraNames) {
  log.debug('Entering generate().');
  const key = await keys.generateKeyPair('ec-p256');
  const extensions = x509.defaultExtensions('tls-server');
  extensions.subjectAltName = { present: true, critical: false,
                                names: altNames(extraNames) };
  const cert = await x509.issueCertificate({
    profile: 'tls-server',
    subject: 'CN=id-proto-debugger,O=idptools',
    subjectPublicKey: key.publicPem,
    issuerPrivateKey: key.privatePem,
    signatureAlg: 'sha256-ecdsa',
    extensions: extensions
  });

  fs.mkdirSync(outDir, { recursive: true });
  const keyFile = path.join(outDir, 'stack-tls-key.pem');
  const certFile = path.join(outDir, 'stack-tls-cert.pem');
  fs.writeFileSync(keyFile, key.privatePem, { mode: 0o600 });
  fs.writeFileSync(certFile, cert.pem, { mode: 0o644 });
  const out = { keyFile: keyFile, certFile: certFile,
                pin: spkiPin(cert.pem) };
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
  const made = await generate(args.outDir, args.extraNames);
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
