'use strict';
//
// File: helpers.js
//
// ---------------------------------------------------------------------------
// The things every other module of this mock needs, and nothing that belongs to
// one protocol.
//
// Three kinds of thing live here, and the reason each is shared rather than
// owned is worth knowing before moving anything out:
//
//   * the LOG and the artifact log. This mock exists to show what it did, so
//     every module writes to one logger at one level.
//   * the KEYS. One RSA key pair signs everything (SAML assertions, every JWT,
//     the RFC 8414 and OID4VCI metadata, the DID documents) and one BBS key pair
//     signs every ldp_vc credential. They are generated once per start, so they
//     cannot be per-module: two modules generating their own would publish two
//     keys under one issuer and the symptom is "the signature does not verify".
//   * the small helpers that more than one protocol needs — base64url, the
//     request's own base URL, a body parser that copes with form or JSON, the two
//     error-response shapes, and the mock's one user.
//
// The last group is why this file exists at all rather than each protocol
// keeping its own: `userFor`, `parseBody`, `oauthError`, `signJwt` and `vciError`
// were used across the OAuth2, OID4VCI and OID4VP sections, and leaving them in
// any one of those made the modules require each other in a CYCLE (the offer
// pages need the mock user; the authorization server needs the offer state).
// A cycle in node does not fail loudly — it hands back a half-initialised module
// whose exports are undefined, and the failure surfaces later as a function that
// is not a function. Keeping the shared leaves here is what makes the dependency
// graph a tree.
// ---------------------------------------------------------------------------

const appconfig = require(process.env.CONFIG_FILE);
const crypto = require('crypto');
const forge = require('node-forge');
const jwt = require('jsonwebtoken');
const bunyan = require("bunyan");
const bbs2023 = require('./bbs2023.js');
const log = bunyan.createLogger({ name: 'sts', 
                                level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());

// ---------------------------------------------------------------------------
// Logging helpers.
//
// This is a mock whose whole purpose is to show what it did, so everything it
// produces is written down at debug level: the artifact BEFORE it was signed or
// encrypted, the artifact AFTER, and — for every endpoint — the request that
// came in, the response that went back, the status code and how long it took.
// ---------------------------------------------------------------------------

// A security artifact, recorded before and after it was protected.
//
//   what   'SAML assertion' / 'JWT' / 'SD-JWT VC' ...
//   stage  'before signing' / 'after signing' / 'before encryption' / ...
//   value  the object or string itself, recorded in full
function logArtifact(what, stage, value) {
  log.debug({ artifact: what,
              stage: stage,
              value: (typeof value === 'string') ? value : JSON.stringify(value) },
            what + ' ' + stage + '.');
}

// Headers with nothing removed: this mock issues test credentials only, and the
// point of the log is to be able to see exactly what was exchanged.
function headersOf(source) {
  const out = {};
  Object.keys(source || {}).forEach(function (k) { out[k] = source[k]; });
  return out;
}

// Bodies arrive (and leave) as strings or objects; either way they go in whole.
function bodyOf(value) {
  if (value === undefined || value === null) return '';
  return (typeof value === 'string') ? value : JSON.stringify(value);
}

const PORT = parseInt(process.env.STS_PORT, 10) || 8081;

const ISSUER = process.env.STS_ISSUER || 'urn:wstrust:mock:sts';

// --- STS signing key/cert (generated once at startup) ----------------------
function makeStsKeys() {
  const kp = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const cert = forge.pki.createCertificate();
  cert.publicKey = kp.publicKey;
  cert.serialNumber = '02';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 5);
  const attrs = [{ name: 'commonName', value: 'ws-trust-mock-sts' }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(kp.privateKey, forge.md.sha256.create());
  const certB64 = forge.pki.certificateToPem(cert)
    .replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  return {
    privateKeyPem: forge.pki.privateKeyToPem(kp.privateKey),
    certPem: forge.pki.certificateToPem(cert),
    certB64: certB64,
    // A `kid` names a KEY, so it is derived from the key material rather than
    // hard-coded. This key is regenerated on every start, and the kid was
    // previously a constant — so two instances of this mock (a stale container
    // beside a fresh one, or two ports during development) published the SAME kid
    // over DIFFERENT keys. A verifier matches the kid exactly, tries that one key,
    // fails, and reports "the signature does not verify", which reads like a
    // corrupt document instead of what it is: keys fetched from the wrong
    // instance. A per-key kid cannot collide, so the mismatch names itself.
    kid: 'sts-mock-' + forge.md.sha256.create().update(certB64).digest().toHex().slice(0, 12)
  };
}

const STS = makeStsKeys();

// Every document that carries or describes this key is served `Cache-Control:
// no-store` (the RFC 8414 metadata, the OID4VCI credential issuer metadata, the
// jwt-vc-issuer document and the JWKS). The key is regenerated on every start, so
// a cached copy of any of them outlives the key it describes — and the resulting
// failure is a signature that does not verify, which looks like a broken document
// rather than a stale one. Nothing about a mock is worth caching.

// --- helpers ---------------------------------------------------------------
function xmlEscape(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

function genId() {
  return '_' + forge.util.bytesToHex(forge.random.getBytesSync(16));
}

function iso(offsetMin) {
  return new Date(Date.now() + (offsetMin || 0) * 60000).toISOString();
}

// base64url, in both directions. Deliberately without entering/leaving logs:
// these are called several times per token and would drown the log.
function b64u(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64uDecode(s) {
  return Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function jsonFromB64u(s) { return JSON.parse(b64uDecode(s).toString('utf8')); }

// Small and called constantly: no entering/leaving logs, they would drown the log.
function nowSec() { return Math.floor(Date.now() / 1000); }

function randomId(bytes) { return b64u(crypto.randomBytes(bytes || 24)); }

// One BBS key pair per start, like the RSA one. Generated lazily because key
// generation is async and the module loads synchronously.
let bbsKeys = null;

async function bbsKeyPair() {
  if (!bbsKeys) bbsKeys = await bbs2023.generateKeyPair();
  return bbsKeys;
}

// Request bodies arrive as raw text (the SOAP parser takes every content type),
// so form-encoded and JSON are both decoded here.
function parseBody(req) {
  log.debug("Entering parseBody(). content-type=" + (req.headers['content-type'] || '(none)'));
  const raw = typeof req.body === 'string' ? req.body : '';
  const type = String(req.headers['content-type'] || '');
  if (/json/i.test(type)) {
    try {
      const parsed = JSON.parse(raw || '{}');
      log.debug("Leaving parseBody(). Parsed a JSON body.");
      return parsed;
    } catch (e) {
      log.error('the request body is not JSON: ' + e.message);
      log.debug("Leaving parseBody(). Nothing could be parsed.");
      return {};
    }
  }
  const out = {};
  new URLSearchParams(raw).forEach(function (v, k) { out[k] = v; });
  log.debug("Leaving parseBody(). Parsed a form-encoded body with " +
            Object.keys(out).length + " parameter(s).");
  return out;
}

function oauthError(res, status, error, description) {
  log.debug("Entering oauthError(). status=" + status + ", error=" + error);
  res.status(status).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify({ error: error, error_description: description }));
  log.debug("Leaving oauthError().");
}

// --- token minting ----------------------------------------------------------
// Every OAuth token this server issues goes through here, so this is where each
// one is recorded: the claim set before it is signed, and the JWT after.
function signJwt(payload) {
  log.debug("Entering signJwt(). typ=" + (payload.typ || '(none)'));
  logArtifact('OAuth token (' + (payload.typ || 'unknown') + ')', 'before signing',
              { header: { alg: 'RS256', kid: STS.kid }, payload: payload });
  const signed = jwt.sign(payload, STS.privateKeyPem, { algorithm: 'RS256', keyid: STS.kid });
  logArtifact('OAuth token (' + (payload.typ || 'unknown') + ')', 'after signing', signed);
  log.debug("Leaving signJwt().");
  return signed;
}

function vciError(res, status, error, description) {
  log.debug("Entering vciError(). status=" + status + ", error=" + error);
  res.status(status).type('application/json').send(JSON.stringify({
    error: error, error_description: description
  }));
  log.debug("Leaving vciError().");
}

function baseUrlOf(req) {
  log.debug("Entering baseUrlOf().");
  const base = (req.protocol || 'http') + '://' + (req.get('host') || ('localhost:' + PORT));
  log.debug("Leaving baseUrlOf(). base=" + base);
  return base;
}


// Where the wallet lives, as a URL the BROWSER can use. Shared because the
// Credential Offer pages and the OID4VP request pages both hand the End-User back
// to it (OID4VP_WALLET_URL falls back to this one).
const WALLET_BASE_URL = process.env.OID4VCI_WALLET_URL || 'http://localhost:3000';

// Whoever signs in at the login screen. No password is ever checked; the
// username they type is the identity every token then describes.
function userFor(username) {
  log.debug("Entering userFor(). username=" + username);
  const name = String(username || 'mock-user');
  const user = {
    sub: 'urn:sts-mock:user:' + name,
    username: name,
    preferred_username: name,
    name: name + ' (mock)',
    given_name: name,
    family_name: 'Mock',
    email: name + '@sts-mock.example',
    email_verified: true
  };
  log.debug("Leaving userFor(). sub=" + user.sub);
  return user;
}

module.exports = {
  log: log,
  logArtifact: logArtifact,
  headersOf: headersOf,
  bodyOf: bodyOf,
  PORT: PORT,
  ISSUER: ISSUER,
  STS: STS,
  xmlEscape: xmlEscape,
  genId: genId,
  iso: iso,
  baseUrlOf: baseUrlOf,
  b64u: b64u,
  b64uDecode: b64uDecode,
  jsonFromB64u: jsonFromB64u,
  nowSec: nowSec,
  randomId: randomId,
  bbsKeyPair: bbsKeyPair,
  WALLET_BASE_URL: WALLET_BASE_URL,
  parseBody: parseBody,
  oauthError: oauthError,
  vciError: vciError,
  signJwt: signJwt,
  userFor: userFor
};
