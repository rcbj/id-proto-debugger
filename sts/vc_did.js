'use strict';
//
// File: vc_did.js
//
// ---------------------------------------------------------------------------
// This issuer's DECENTRALIZED IDENTIFIER (W3C DID Core 1.0) and the two documents
// that make it discoverable and believable: the did:web document, and the DIF
// Well Known DID Configuration that links the DID to this origin.
//
// Kept apart from vc_issuer.js because it is asked about from both directions —
// the metadata advertises the DID, the credential builders name it, and the two
// documents here are served whether or not any credential uses one. It reads
// vc_configs.js to decide per configuration and is read by vc_issuer.js in turn,
// which is why the configuration registry is its own module: with the registry
// inside vc_issuer.js these two would require each other.
// ---------------------------------------------------------------------------

const crypto = require('crypto');
const forge = require('node-forge');
const jwt = require('jsonwebtoken');
const app = require('./app');
const bbs2023 = require('./bbs2023.js');
const { log, logArtifact, PORT, STS, baseUrlOf, bbsKeyPair } = require('./helpers');
const { VCI_CONFIGS } = require('./vc_configs');
// ---------------------------------------------------------------------------
// This issuer's DECENTRALIZED IDENTIFIER (W3C DID Core 1.0).
//
// did:web, because it is the only method with a document to serve: did:jwk and
// did:key resolve from the identifier itself and would make this endpoint
// pointless. The method-specific id is the host with its port percent-encoded,
// which is why a DID for localhost:8081 reads did:web:localhost%3A8081 — and why
// the document lives at /.well-known/did.json.
//
// The DID is always SERVED — the document and the domain linkage below cost
// nothing and are what make the DID discoverable. What is opt-in is naming
// CREDENTIALS by it, and there are two ways to ask, for two different reasons:
//
//   * the IdentityCredentialDid / IdentityCredentialLdpVcDid configurations,
//     which always do. A wallet asks for one by name, so both routes are live in
//     the same issuer at the same time and can be compared.
//   * the two startup flags below, which switch the PLAIN configurations over —
//     what a deployment that had gone to DIDs throughout would look like.
//
// The flags default OFF, and the reason is per format:
//
//   ldp_vc      VC Data Model 2.0 and Data Integrity are DID-native; naming the
//               issuer by DID is ordinary there. Off only because ldp_vc's
//               verificationMethod is an https URL that existing tests
//               dereference, and switching it to a DID URL silently breaks that.
//   dc+sd-jwt   draft-ietf-oauth-sd-jwt-vc defines NO DID-based issuer signature
//               mechanism — "A DID-based mechanism is not explicitly provided
//               herein but still possible via profile/extension" (-10 changelog).
//               So this is an extension, and the spec's own route
//               (/.well-known/jwt-vc-issuer) is what the plain configuration must
//               go on exercising.
// ---------------------------------------------------------------------------
function didFlag(name) {
  return String(process.env[name] || '').toLowerCase() === 'true';
}

const SD_JWT_ISSUER_DID = didFlag('OID4VCI_SD_JWT_ISSUER_DID');

const LDP_VC_ISSUER_DID = didFlag('OID4VCI_LDP_VC_ISSUER_DID');

// did:web for whatever host this request arrived on, so the same container
// works at localhost:8081, sts:8081 and behind a published port without being
// told which it is.
function stsDid(req) {
  const host = String((req && req.get && req.get('host')) || ('localhost:' + PORT));
  return 'did:web:' + host.replace(/:/g, '%3A');
}

// The DID Document. Two verification methods, because this issuer signs two
// quite different things: RS256 JWTs (the SD-JWT VCs and every token) and
// bbs-2023 Data Integrity proofs (the ldp_vc credentials). A BBS key has no
// registered JOSE kty, so it appears as a Multikey exactly as it does at
// /bbs/keys/1 rather than being forced into a publicKeyJwk it does not fit.
async function stsDidDocument(req) {
  log.debug("Entering stsDidDocument().");
  const did = stsDid(req);
  // The same RSA public key the JWKS publishes, read out of the certificate the
  // same way — one source of truth for what this issuer signs with, so a DID
  // document and a JWKS can never describe different keys.
  const pub = forge.pki.certificateFromPem(STS.certPem).publicKey;
  const b64uHex = function (hex) {
    return Buffer.from(hex.length % 2 ? '0' + hex : hex, 'hex').toString('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  const methods = [{
    id: did + '#' + STS.kid,
    type: 'JsonWebKey2020',
    controller: did,
    publicKeyJwk: {
      kty: 'RSA', use: 'sig', alg: 'RS256', kid: STS.kid,
      n: b64uHex(pub.n.toString(16)), e: b64uHex(pub.e.toString(16))
    }
  }];
  try {
    const keys = await bbsKeyPair();
    methods.push({
      id: did + '#bbs-1',
      type: 'Multikey',
      controller: did,
      // Same encoding as /bbs/keys/1: multibase base64url, which is "u" and then
      // the raw compressed bytes. A BBS key has no registered JOSE kty, so it
      // cannot be a publicKeyJwk however convenient that would be.
      publicKeyMultibase: 'u' + bbs2023.bytesToB64u(keys.publicKey)
    });
  } catch (e) {
    // The BBS half is optional here: an ldp_vc issued while it is unavailable
    // would fail earlier and louder than a missing verification method.
    log.error('the BBS key could not be published in the DID document: ' + e.message);
  }
  log.debug("Leaving stsDidDocument().");
  return {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
    id: did,
    verificationMethod: methods,
    authentication: [methods[0].id],
    assertionMethod: methods.map(function (m) { return m.id; })
  };
}

// did:web resolution is a plain GET of this document. no-store for the same
// reason the JWKS is: the keys it describes are regenerated on every start, so a
// cached copy outlives them.
app.get('/.well-known/did.json', async function (req, res) {
  log.debug("Entering the did:web document endpoint.");
  const doc = await stsDidDocument(req);
  logArtifact('DID Document', 'as served', doc);
  res.set('Cache-Control', 'no-store');
  res.status(200).type('application/did+json').send(JSON.stringify(doc, null, 2));
  log.debug("Leaving the did:web document endpoint. " + doc.verificationMethod.length + " method(s).");
});

// ---------------------------------------------------------------------------
// Well Known DID Configuration (DIF) — /.well-known/did-configuration.json
//
// This is the document that answers the question the other two cannot. The DID
// document says "this DID has these keys". The credential says "I was issued by
// did:web:sts%3A8081". Neither says why anyone should believe that DID is the
// same entity as the https issuer the wallet discovered, and for did:web the
// circularity is the trap: the DID resolves by fetching the very origin whose
// claim is in question, so "the DID document says so" establishes nothing extra.
//
// A Domain Linkage Credential is the assertion in the other direction — the DID,
// signing with its own key, naming the origin — and it is checkable: resolve the
// issuer DID independently, verify the signature against its assertionMethod,
// and require that credentialSubject.origin is the origin the document came from.
// On success the origin's controller and the DID's controller are one entity.
//
// The JWT form rather than the Linked Data Proof form, for two reasons: this
// issuer signs RS256 JWTs everywhere else, so the same key and the same JWKS
// verify it; and the LD form would need a JsonWebSignature2020 over URDNA2015
// canonicalization, which is real work for no additional teaching.
//
// Two details of the JWT form are easy to get wrong and are asserted by
// tests/did_document.js, because both produce a document that looks right:
//
//   * the header MUST NOT carry typ, and jsonwebtoken adds typ: "JWT" unless the
//     header override explicitly sets it undefined;
//   * the payload permits no members beyond iss/sub/nbf/exp/vc, and jsonwebtoken
//     adds iat unless told noTimestamp.
//
// Note the origin here is whatever this container is reached at, http included.
// The spec assumes https; the local and containerized stacks have no TLS, and the
// same deviation is already taken by did:web resolution over http.
// ---------------------------------------------------------------------------
const DID_CONFIGURATION_CONTEXT = 'https://identity.foundation/.well-known/did-configuration/v1';

async function domainLinkageCredential(req) {
  log.debug("Entering domainLinkageCredential().");
  const did = stsDid(req);
  const origin = baseUrlOf(req);
  const now = Math.floor(Date.now() / 1000);
  const exp = now + 365 * 24 * 3600;
  // issuer and credentialSubject.id are both the DID: a domain linkage credential
  // is self-issued by definition — nobody else is in a position to say which
  // origin a DID controls. `id` is deliberately absent at the credential root,
  // which the specification requires.
  const vc = {
    '@context': ['https://www.w3.org/2018/credentials/v1', DID_CONFIGURATION_CONTEXT],
    issuer: did,
    issuanceDate: new Date(now * 1000).toISOString(),
    expirationDate: new Date(exp * 1000).toISOString(),
    type: ['VerifiableCredential', 'DomainLinkageCredential'],
    credentialSubject: { id: did, origin: origin }
  };
  logArtifact('Domain Linkage Credential', 'before signing', vc);
  const token = jwt.sign({ iss: did, sub: did, nbf: now, exp: exp, vc: vc }, STS.privateKeyPem, {
    algorithm: 'RS256',
    noTimestamp: true,
    header: { alg: 'RS256', kid: did + '#' + STS.kid, typ: undefined }
  });
  logArtifact('Domain Linkage Credential', 'after signing (JWT form)', token);
  log.debug("Leaving domainLinkageCredential(). did=" + did + ", origin=" + origin);
  return token;
}

app.get('/.well-known/did-configuration.json', async function (req, res) {
  log.debug("Entering the DID Configuration endpoint.");
  const doc = {
    '@context': DID_CONFIGURATION_CONTEXT,
    linked_dids: [await domainLinkageCredential(req)]
  };
  logArtifact('DID Configuration', 'as served', doc);
  // no-store for the same reason as the DID document: the key that signed this
  // is regenerated on every start, so a cached copy verifies against nothing.
  res.set('Cache-Control', 'no-store');
  res.status(200).type('application/json').send(JSON.stringify(doc, null, 2));
  log.debug("Leaving the DID Configuration endpoint.");
});

// ---------------------------------------------------------------------------
// NON-SPEC, for tests and for trying the DID Tools page: generate a DID that can
// actually be VERIFIED.
//
// No specification defines this. It exists because a DID on its own proves nothing
// — the interesting checks are "does a key in this document verify something it
// signed" and "does an origin vouch for this DID" — and both need an artifact to
// check. Handing back a DID with no credential signed by it would make a test that
// could only assert the document parsed.
//
// Two methods, because they exercise genuinely different code in the wallet:
//
//   jwk  the identifier IS the key, so it resolves with NO network call. Generated
//        fresh per request from a new P-256 key, and the credential is signed with
//        that key (ES256) — so verifying it exercises the local-decode path end to
//        end and cannot pass by accident against this service's RSA key.
//   web  this service's own did:web, whose document is served at
//        /.well-known/did.json and whose domain linkage is at
//        /.well-known/did-configuration.json. The credential is signed with the
//        RS256 key that document publishes.
//
// did:key is deliberately absent: encoding one needs multicodec varints and
// base58btc, which live in the wallet (client/src/did.js) and would be a second
// implementation here — exactly the kind of duplication that lets two encoders
// agree with each other and with nobody else.
// ---------------------------------------------------------------------------
function generatedDidJwk() {
  log.debug("Entering generatedDidJwk().");
  const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const publicJwk = pair.publicKey.export({ format: 'jwk' });
  // The member order is the one a did:jwk is conventionally built from, and it is
  // not cosmetic: the identifier is the base64url of these exact bytes, so a
  // different order is a different DID for the same key.
  const ordered = { crv: publicJwk.crv, kty: publicJwk.kty, x: publicJwk.x, y: publicJwk.y };
  const did = 'did:jwk:' + Buffer.from(JSON.stringify(ordered), 'utf8').toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const document = {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
    id: did,
    verificationMethod: [{ id: did + '#0', type: 'JsonWebKey2020', controller: did,
                           publicKeyJwk: ordered }],
    authentication: [did + '#0'],
    assertionMethod: [did + '#0']
  };
  log.debug("Leaving generatedDidJwk(). did=" + did.slice(0, 40) + "…");
  return { did: did, document: document, publicJwk: ordered,
           privateKeyPem: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }) };
}

// An SD-JWT VC naming `issuerDid` as its iss and signed with the key that DID
// publishes. Minimal on purpose — one Disclosure and a cnf — because what is being
// tested is the SIGNATURE against a resolved document, not the credential's shape.
function credentialSignedBy(issuerDid, privateKeyPem, alg, kid) {
  log.debug("Entering credentialSignedBy(). alg=" + alg);
  const now = Math.floor(Date.now() / 1000);
  const salt = crypto.randomBytes(16).toString('base64url');
  const disclosure = Buffer.from(JSON.stringify([salt, 'given_name', 'Ada']), 'utf8')
    .toString('base64url');
  const digest = crypto.createHash('sha256').update(disclosure, 'ascii').digest('base64url');
  const holder = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const holderJwk = holder.publicKey.export({ format: 'jwk' });
  const payload = {
    iss: issuerDid, nbf: now, exp: now + 3600, vct: 'urn:idptools:did-tools:generated',
    sub: 'urn:uuid:' + crypto.randomUUID(),
    cnf: { jwk: { kty: holderJwk.kty, crv: holderJwk.crv, x: holderJwk.x, y: holderJwk.y } },
    _sd_alg: 'sha-256', _sd: [digest]
  };
  const header = { alg: alg, typ: 'dc+sd-jwt' };
  if (kid) header.kid = kid;
  logArtifact('generated SD-JWT VC', 'before signing', { header: header, payload: payload });
  const signed = jwt.sign(payload, privateKeyPem, { algorithm: alg, header: header });
  logArtifact('generated SD-JWT VC', 'after signing', signed);
  log.debug("Leaving credentialSignedBy().");
  return signed + '~' + disclosure + '~';
}

app.get('/did/generate', async function (req, res) {
  log.debug("Entering the DID generator endpoint.");
  const method = String(req.query.method || 'jwk').toLowerCase();
  if (method !== 'jwk' && method !== 'web') {
    res.status(400).type('application/json').send(JSON.stringify({
      error: 'invalid_request',
      error_description: 'method must be jwk or web. did:key is not generated here: encoding one ' +
        'needs multicodec and base58btc, which live in the wallet, and a second implementation ' +
        'would be free to agree only with itself.'
    }, null, 2));
    log.debug("Leaving the DID generator endpoint. Refused method " + method + ".");
    return;
  }

  let body;
  if (method === 'jwk') {
    const generated = generatedDidJwk();
    body = {
      method: 'jwk',
      did: generated.did,
      document: generated.document,
      // The document resolves from the identifier itself, so there is nothing to
      // fetch and nothing for a caller to point a URL at.
      documentUrl: '',
      verificationMethod: generated.did + '#0',
      credential: credentialSignedBy(generated.did, generated.privateKeyPem, 'ES256',
                                     generated.did + '#0')
    };
  } else {
    const did = stsDid(req);
    body = {
      method: 'web',
      did: did,
      document: await stsDidDocument(req),
      documentUrl: baseUrlOf(req) + '/.well-known/did.json',
      didConfigurationUrl: baseUrlOf(req) + '/.well-known/did-configuration.json',
      origin: baseUrlOf(req),
      verificationMethod: did + '#' + STS.kid,
      credential: credentialSignedBy(did, STS.privateKeyPem, 'RS256', STS.kid)
    };
  }
  logArtifact('generated DID', 'as returned', { method: body.method, did: body.did });
  // no-store for the same reason as every other document describing these keys: a
  // jwk DID is new on every call, and the web one describes a key regenerated at
  // each start.
  res.set('Cache-Control', 'no-store');
  res.status(200).type('application/json').send(JSON.stringify(body, null, 2));
  log.debug("Leaving the DID generator endpoint. method=" + body.method + ".");
});

// The DID this issuer should be named by for a given CONFIGURATION, or "" when it
// should keep the https identifier it has always used — in which case every
// builder behaves exactly as it did before any of this existed.
//
// Two ways to arrive at a DID, and they answer different questions. A
// configuration declared with issuerDid (IdentityCredentialDid,
// IdentityCredentialLdpVcDid) always uses one: that is the point of it, it is
// advertised in the metadata, and a wallet asks for it by name. The startup flags
// are the other way, and they apply to the PLAIN configurations: they are how a
// whole deployment says "name me by DID throughout", which is what a real issuer
// that had gone over to DIDs would look like. Off by default, because for
// dc+sd-jwt this is an extension and for ldp_vc it changes a verificationMethod
// that existing tests dereference as an https URL.
function issuerDidFor(configId, req) {
  const config = VCI_CONFIGS[configId] || {};
  if (config.issuerDid) return stsDid(req);
  if (config.format === 'ldp_vc') return LDP_VC_ISSUER_DID ? stsDid(req) : '';
  return SD_JWT_ISSUER_DID ? stsDid(req) : '';
}

module.exports = {
  stsDid: stsDid,
  stsDidDocument: stsDidDocument,
  domainLinkageCredential: domainLinkageCredential,
  issuerDidFor: issuerDidFor,
  DID_CONFIGURATION_CONTEXT: DID_CONFIGURATION_CONTEXT,
  SD_JWT_ISSUER_DID: SD_JWT_ISSUER_DID,
  LDP_VC_ISSUER_DID: LDP_VC_ISSUER_DID
};
