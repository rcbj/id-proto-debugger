'use strict';
//
// ---------------------------------------------------------------------------
// The issuer and verifier half of the `bbs-2023` cryptosuite, for the mock STS.
//
// This deliberately does NOT reuse client/src/bbs2023.js. The BBS protocol code
// here is @digitalbazaar/bbs-signatures — a different implementation from the
// one the browser runs — so a credential this service issues is signed by one
// codebase and its derived proof is produced by another, and each side verifies
// the other's work. That cross-check is the point: BBS has several places where
// a signer and verifier can share a mistake, agree perfectly, and agree with
// nobody else (see tests/bbs_crypto.js).
//
// What IS shared, and must be, is the canonical form. bbs-2023 signs canonical
// N-Quad statements, so both sides run the same `jsonld` canonicalization over
// the same vendored contexts. A one-byte difference there fails every signature
// while looking exactly like a crypto bug.
//
// The library is ESM-only and this service is CommonJS, so it is loaded with a
// dynamic import() the first time it is needed and then kept.
// ---------------------------------------------------------------------------

const jsonld = require('jsonld');
const path = require('path');
const fs = require('fs');

const CRYPTOSUITE = 'bbs-2023';
const PROOF_TYPE = 'DataIntegrityProof';
const IDENTITY_CONTEXT_URL = 'https://idptools.com/contexts/identity/v1';

// The contexts, read from the client's copies so that the two sides cannot
// drift: if the browser signs against a different context than this service
// verifies against, every signature fails for a reason that looks like BBS.
// Two layouts: this service in a checkout (contexts live in the client tree) and
// the tests image, where everything is copied flat beside the scripts. Resolved
// rather than assumed, because a missing context is not a missing file error at
// signing time — it is every signature failing later, looking like a crypto bug.
const CONTEXT_DIRS = [
  path.join(__dirname, '..', 'client', 'src', 'contexts'),
  path.join(__dirname, 'contexts')
];
function loadContext(file) {
  for (const dir of CONTEXT_DIRS) {
    const candidate = path.join(dir, file);
    if (fs.existsSync(candidate)) return JSON.parse(fs.readFileSync(candidate, 'utf8'));
  }
  throw new Error('bbs-2023 needs the vendored JSON-LD context ' + file +
    '; looked in ' + CONTEXT_DIRS.join(' and '));
}
const CONTEXTS = {
  'https://www.w3.org/ns/credentials/v2': loadContext('credentials_v2.json'),
  'https://www.w3.org/2018/credentials/v1': loadContext('credentials_v1.json'),
  [IDENTITY_CONTEXT_URL]: loadContext('idptools_identity_v1.json')
};

function documentLoader(url) {
  if (CONTEXTS[url]) {
    return Promise.resolve({ contextUrl: null, documentUrl: url, document: CONTEXTS[url] });
  }
  return Promise.reject(new Error(
    'this issuer will only handle documents using a context it ships: ' +
    Object.keys(CONTEXTS).join(', ') + '. Asked for: ' + url));
}

let bbsLib = null;
async function bbs() {
  if (!bbsLib) bbsLib = await import('@digitalbazaar/bbs-signatures');
  return bbsLib;
}
async function ciphersuite() {
  return (await bbs()).CIPHERSUITES.BLS12381_SHA256;
}

const te = (s) => new TextEncoder().encode(s);

async function canonicalizedStatements(doc) {
  const nquads = await jsonld.canonize(doc, {
    algorithm: 'URDNA2015',
    format: 'application/n-quads',
    documentLoader,
    safe: true
  });
  return String(nquads).split('\n').filter((l) => l.trim() !== '').map((l) => l + '\n');
}

function proofConfig(proof) {
  const config = {};
  Object.keys(proof).forEach((k) => { if (k !== 'proofValue') config[k] = proof[k]; });
  return config;
}

async function headerFor(proof) {
  const statements = await canonicalizedStatements(proofConfig(proof));
  return te(statements.join(''));
}

function bytesToB64u(bytes) { return Buffer.from(bytes).toString('base64url'); }
function b64uToBytes(s) { return new Uint8Array(Buffer.from(String(s).replace(/^u/, ''), 'base64url')); }

async function generateKeyPair() {
  const lib = await bbs();
  const suite = await ciphersuite();
  const { secretKey, publicKey } = await lib.generateKeyPair({ ciphersuite: suite });
  return { secretKey, publicKey };
}

// --- issue ------------------------------------------------------------------
async function issue(unsecured, proofOptions, secretKey, publicKey) {
  const lib = await bbs();
  const suite = await ciphersuite();
  const proof = Object.assign({
    '@context': unsecured['@context'],
    type: PROOF_TYPE,
    cryptosuite: CRYPTOSUITE,
    proofPurpose: 'assertionMethod'
  }, proofOptions);

  const document = Object.assign({}, unsecured);
  delete document.proof;
  const statements = await canonicalizedStatements(document);
  const header = await headerFor(proof);
  const signature = await lib.sign({
    secretKey, publicKey, header, messages: statements.map(te), ciphersuite: suite
  });

  const attached = Object.assign({}, proof);
  delete attached['@context'];
  attached.proofValue = 'u' + bytesToB64u(signature);
  const secured = Object.assign({}, document, { proof: attached });
  return { credential: secured, statements, header, signature };
}

// --- verify -----------------------------------------------------------------
// Every crypto operation this service is handed goes through one of these two,
// and both report WHICH check failed rather than a bare boolean: "the
// presentation was refused" is not a useful answer to a wallet developer.
async function verifyBase(secured, publicKey) {
  const lib = await bbs();
  const suite = await ciphersuite();
  const proof = secured.proof || {};
  const document = Object.assign({}, secured);
  delete document.proof;
  const reproof = Object.assign({ '@context': secured['@context'] }, proof);
  delete reproof.proofValue;
  const statements = await canonicalizedStatements(document);
  const header = await headerFor(reproof);
  const signature = b64uToBytes(proof.proofValue);
  const ok = await lib.verifySignature({
    publicKey, signature, header, messages: statements.map(te), ciphersuite: suite
  }).catch(() => false);
  return { ok, statements, header };
}

async function verifyDerived(publicKey, derivedProof, header, presentationHeader,
                             disclosedStatements, disclosedIndexes) {
  const lib = await bbs();
  const suite = await ciphersuite();
  return lib.verifyProof({
    publicKey,
    proof: derivedProof,
    header,
    presentationHeader,
    disclosedMessages: disclosedStatements.map(te),
    disclosedMessageIndexes: disclosedIndexes.slice().sort((a, b) => a - b),
    ciphersuite: suite
  }).catch(() => false);
}

module.exports = {
  CRYPTOSUITE,
  PROOF_TYPE,
  IDENTITY_CONTEXT_URL,
  canonicalizedStatements,
  headerFor,
  generateKeyPair,
  issue,
  verifyBase,
  verifyDerived,
  bytesToB64u,
  b64uToBytes,
  documentLoader
};
