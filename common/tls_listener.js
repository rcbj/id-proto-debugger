// File: tls_listener.js
//
// ---------------------------------------------------------------------------
// THE ONE PLACE THAT DECIDES WHETHER A SERVICE HERE BINDS TLS, AND WHAT
// CERTIFICATE IT BINDS WITH.
//
// It is in `common/` for the reason `xmldsig.js` is: BOTH services listen, the
// decision is the same one twice, and two copies of it are two chances for the
// api and the client to end up on different schemes — which is not a cosmetic
// disagreement here. A page on https that posts a form to http is not a page
// with a mixed-content warning; it is a page whose form Chrome DOES NOT SUBMIT,
// behind a full-screen "Form is not secure" interstitial. That failure already
// cost this project a containerized run on 2026-08-27, when the mock STS was
// https and the api's SAML landing was not — 53 of 77 jobs, none of whose
// messages named a browser. See tests/browser_flags.js.
//
// ---------------------------------------------------------------------------
// THIS MODULE DOES NO CRYPTOGRAPHY. IT READS A FILE.
//
// The certificate is made by `common/generate_tls_cert.js`, which is a caller
// of THIS PROJECT'S OWN X.509 authoring module — `client/src/x509.js`'s
// `tls-server` profile over a `client/src/key_material.js` key pair. That is
// deliberate and it is the second time the argument has had to be made in this
// tree: `common/xmldsig.js` exists because three private canonicalizers
// disagreed with each other, and a fourth certificate encoder here would be
// the same mistake in PKIX. x509.js is the module ~240 certificates in
// tests/pki_x509.js are driven through and handed to OpenSSL, so it is the one
// encoder in this repository that has been shown to agree with somebody else's
// parser. A dozen lines of node-forge boilerplate in this file would have had
// none of that behind it.
//
// So the arrangement is: ONE generator, outside the services, writing a key
// and a certificate to disk; and both services reading that file.
//
// ONE PAIR FOR THE WHOLE STACK, and the reason is not tidiness. The mock STS
// PUSHES to the api — RFC 8935 Shared Signals delivery, `POST
// /ssf/receiver/:id` — so that container has to TRUST the api's certificate,
// and a certificate generated inside the api at startup does not exist when
// the mock's environment is being built. One file on disk before anything
// starts is what makes the trust arrangement expressible at all. It is also
// one anchor for node (NODE_EXTRA_CA_CERTS names ONE file) and one SPKI pin
// for Chrome instead of two of each.
//
// THE NAMES THE CERTIFICATE ANSWERS TO are the generator's business, not
// this file's — see the SANs note in common/generate_tls_cert.js, which is
// where the one list lives.
//
// ---------------------------------------------------------------------------
// OFF IS STILL A SETTING, AND IT IS THE DEFAULT.
//
// `https` absent or false binds a plain listener, exactly as before. Only the
// stack configurations turn it on (client/src/env/*.js, api/env/*.js), which
// is the arrangement the mock STS already uses for `global.https` — the switch
// lives in configuration, the code supports both, and a deployment that has a
// reverse proxy terminating TLS in front of it is not forced to terminate it
// twice.
// ---------------------------------------------------------------------------
'use strict';

const fs = require('fs');
const http = require('http');
const https = require('https');

// The same bunyan-or-console logger `common/spiffe/spiffe_bundle.js` carries,
// and for the same reason: this module lives in `common/`, so node resolves
// its own requires by walking up from `common/` — which reaches neither
// `api/node_modules` nor `client/node_modules` in a checkout, and in an image
// reaches nothing at all. See the long note in common/sp_keypair.js.
var log = (function () {
  try {
    var bunyan = require("bunyan");
    return bunyan.createLogger({
      name: "tls_listener",
      level: (function () {
        try {
          return require(process.env.CONFIG_FILE).logLevel || "info";
        } catch (e) {
          // No CONFIG_FILE resolvable from here.
          return "info";
        }
      })()
    });
  } catch (e) {
    var DEBUG = false;
    var TAG = "[tls_listener]";
    return {
      debug: function () {
        if (!DEBUG) {
          return;
        }
        console.log.apply(console,
          [TAG].concat(Array.prototype.slice.call(arguments)));
      },
      info: function () {
        console.log.apply(console,
          [TAG].concat(Array.prototype.slice.call(arguments)));
      },
      warn: function () {
        console.warn.apply(console,
          [TAG].concat(Array.prototype.slice.call(arguments)));
      },
      error: function () {
        console.error.apply(console,
          [TAG].concat(Array.prototype.slice.call(arguments)));
      }
    };
  }
})();

// What the running process is serving, so that GET /tls/server-certificate can
// publish it. Set by listen(); null until then, and null for ever on a plain
// listener.
var servingCertificatePem = null;

// Whether a value that is meant to be a switch is on. An explicit string is
// accepted because this is reachable from an environment variable, where
// everything is a string and `"false"` is truthy.
function isOn(value) {
  log.debug("Entering isOn().");
  if (value === true) {
    log.debug("Leaving isOn(). true (boolean)");
    return true;
  }
  if (typeof value === 'string' && /^(true|1|yes|on)$/i.test(value.trim())) {
    log.debug("Leaving isOn(). true (string)");
    return true;
  }
  log.debug("Leaving isOn(). false");
  return false;
}

// The key and certificate to bind with, or null when this service is not
// serving TLS at all.
//
// The environment OUTRANKS the configuration file, which is the rule the rest
// of this tree already follows for a value compose has to set (see the
// CONFIG_FILE note in local-run-tests.sh): a compose file cannot edit a
// checked-in `env/*.js`, so the variables are how a stack says what it wants.
function materialFor(appconfig, serviceName) {
  log.debug("Entering materialFor(). service=" + serviceName);
  const config = appconfig || {};
  const wantsHttps = process.env.TLS_ENABLED !== undefined
    ? isOn(process.env.TLS_ENABLED)
    : isOn(config.https);
  if (!wantsHttps) {
    log.debug("Leaving materialFor(). Plain HTTP.");
    return null;
  }

  const certFile = process.env.TLS_CERT_FILE || config.tlsCertFile || '';
  const keyFile = process.env.TLS_KEY_FILE || config.tlsKeyFile || '';
  if (certFile && keyFile) {
    // A NAMED FILE THAT IS NOT THERE IS FATAL, and deliberately so. Falling
    // back to a generated certificate would leave the service up, serving a
    // key nothing in the run trusts, and every caller would report a
    // handshake failure against a certificate the launcher believes it
    // distributed. That is a worse fifteen minutes than a startup that says
    // which path was missing.
    const cert = fs.readFileSync(certFile, 'utf8');
    const key = fs.readFileSync(keyFile, 'utf8');
    log.info('tls_listener: ' + serviceName + ' is serving TLS with the ' +
             'certificate at ' + certFile + '.');
    log.debug("Leaving materialFor(). From files.");
    return { cert: cert, key: key, source: certFile };
  }

  // TLS ASKED FOR AND NO CERTIFICATE NAMED IS FATAL, and there is deliberately
  // no in-process fallback to generate one. A service that quietly invented a
  // key pair would be up, serving a certificate nothing in the run trusts,
  // and every caller would report a handshake failure against a certificate
  // the launcher believes it distributed — while the mock STS, which has to
  // trust the api to push a Security Event Token to it, could never have been
  // given the anchor at all. Fifteen minutes of that is worse than a startup
  // that names the generator.
  log.debug("Leaving materialFor(). No certificate named.");
  throw new Error('tls_listener: ' + serviceName + ' is configured for TLS ' +
    '(https: true, or TLS_ENABLED) but no certificate was named. Set ' +
    'tlsCertFile and tlsKeyFile, or TLS_CERT_FILE and TLS_KEY_FILE. The ' +
    'launchers do this for you — common/common.sh\'s ' +
    'generateStackTlsCertificate() writes the pair with ' +
    'common/generate_tls_cert.js before compose starts. To make one by ' +
    'hand: node common/generate_tls_cert.js --out-dir <dir>');
}

// Bind, and say what was bound. Returns the server so a caller can hold it.
//
// The announcement is built from what was actually decided rather than from
// the configuration that asked for it, because those are the two things worth
// telling apart when a caller cannot reach the port.
function listen(app, appconfig, options) {
  log.debug("Entering listen().");
  const opts = options || {};
  const serviceName = opts.name || 'service';
  const port = opts.port;
  const host = opts.host;
  const material = materialFor(appconfig, serviceName);

  if (!material) {
    servingCertificatePem = null;
    const plain = http.createServer(app);
    plain.listen(port, host, function () {
      log.info(serviceName + ' running on http://' + host + ':' + port);
    });
    log.debug("Leaving listen(). Plain.");
    return plain;
  }

  servingCertificatePem = material.cert;
  const secure = https.createServer({ cert: material.cert, key: material.key },
                                    app);
  secure.listen(port, host, function () {
    log.info(serviceName + ' running on https://' + host + ':' + port +
             ' (certificate: ' + material.source + ')');
  });
  log.debug("Leaving listen(). TLS.");
  return secure;
}

// The certificate this process is serving, as PEM, or null on a plain
// listener. This is what `GET /tls/server-certificate` publishes; it is the
// PUBLIC half and there is nothing confidential in it.
function serverCertificate() {
  log.debug("Entering serverCertificate().");
  log.debug("Leaving serverCertificate(). " +
            (servingCertificatePem ? 'present' : 'none'));
  return servingCertificatePem;
}

// Whether this process bound TLS. Read by the two services to decide what
// their own limits endpoints report.
function isSecure() {
  log.debug("Entering isSecure().");
  log.debug("Leaving isSecure(). " + (servingCertificatePem !== null));
  return servingCertificatePem !== null;
}

module.exports = {
  listen: listen,
  serverCertificate: serverCertificate,
  isSecure: isSecure
};
