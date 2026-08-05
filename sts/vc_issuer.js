'use strict';
//
// File: vc_issuer.js
//
// ===========================================================================
// OpenID for Verifiable Credential Issuance (OID4VCI) — mock Credential Issuer
//
// The bare minimum needed to drive the debugger's SD-JWT VC issuance workflow
// end to end:
//
//   GET  /.well-known/openid-credential-issuer   Credential Issuer Metadata
//   GET  /.well-known/jwt-vc-issuer              JWT VC Issuer Metadata (the
//                                                SD-JWT VC key-resolution
//                                                document: issuer + jwks_uri)
//   POST /oid4vci/nonce                          a fresh c_nonce
//   POST /oid4vci/credential                     the Credential Request; returns
//                                                an SD-JWT VC built per RFC 9901
//
// This is a TEST issuer. It checks that a request carries SOME bearer token but
// cannot validate one issued by the separate authorization server (Keycloak in
// the test suite), so it does not try; what it DOES check properly is the
// wallet's proof of possession, because that is the part the debugger produces
// and therefore the part worth verifying.
//
// The authorization server the metadata advertises is configurable
// (OID4VCI_AUTHORIZATION_SERVER), so the document can point the wallet at the
// real IdP while the credential endpoint stays here.
// ===========================================================================
//
// What lives NEXT DOOR rather than here, and why: the credential configurations
// (vc_configs.js, read by the authorization server too), the Credential Offer and
// its pre-authorized codes (vc_offers.js, redeemed at the token endpoint), and the
// issuer's DID documents (vc_did.js). This module is the part that MINTS: the
// metadata, the nonce, the proof check, the three credential builders, the
// Credential Request in both its plain and encrypted forms, deferred issuance and
// the notification endpoint.
// ---------------------------------------------------------------------------

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const app = require('./app');
const bbs2023 = require('./bbs2023.js');
const { log, logArtifact, STS, baseUrlOf, b64u, b64uDecode, jsonFromB64u, randomId,
        bbsKeyPair, vciError } = require('./helpers');
const dpop = require('./dpop');
const { VCI_AS, VCI_BATCH_SIZE, VCI_CONFIGS, VCI_CONFIG_ID, VCI_JWT_CONFIG_ID,
        VCI_JWT_SCOPE, VCI_JWT_TYPES, VCI_LDP_CONFIG_ID, VCI_LDP_SCOPE, VCI_SCOPE,
        VCI_VCT, VC_CONTEXT, configIdOfIdentifier, vciConfigIds, vciFormatOf,
        vciUsesIssuerDid } = require('./vc_configs');
const { issuerDidFor, stsDid } = require('./vc_did');
const { DEFERRED_INTERVAL_S, DEFERRED_READY_MS, OFFER_TTL_MS, deferredAccessTokens,
        deferredTransactions } = require('./vc_offers');
// c_nonce values this issuer has handed out and not yet seen used. A nonce is
// single-use (RFC-conformant behaviour, and it makes replay visible in a test).
const vciNonces = new Map();

const VCI_NONCE_TTL_MS = 5 * 60 * 1000;

function vciMetadata(req) {
  log.debug("Entering vciMetadata().");
  const base = baseUrlOf(req);
  const authServer = VCI_AS || base;
  const meta = {
    // --- REQUIRED ---
    credential_issuer: base,
    credential_endpoint: base + '/oid4vci/credential',
    credential_configurations_supported: {},
    // --- OPTIONAL ---
    authorization_servers: [authServer],
    nonce_endpoint: base + '/oid4vci/nonce',
    // OPTIONAL, and a wallet must not assume it: an issuer that cannot defer
    // omits it entirely (walt.id's does). Ours can, so it says so.
    deferred_credential_endpoint: base + '/oid4vci/deferred_credential',
    notification_endpoint: base + '/oid4vci/notification',
    batch_credential_issuance: { batch_size: VCI_BATCH_SIZE },
    // Only what this issuer actually performs. It used to advertise ECDH-ES as
    // well, which nothing implemented — metadata that overstates is worse than
    // metadata that says little.
    credential_response_encryption: {
      alg_values_supported: [VCI_ENC_ALG],
      enc_values_supported: VCI_ENC_VALUES,
      encryption_required: false
    },
    // The other direction (section 10). Note the shape differs from the one
    // above and the difference is normative, not an oversight: requests carry
    // no alg_values_supported, because the JWE alg must equal the alg of the
    // JWK the wallet picked out of jwks.
    credential_request_encryption: credentialRequestEncryptionMetadata(),
    display: [{
      name: 'IdP Tools Mock Credential Issuer',
      locale: 'en-US',
      logo: { uri: base + '/images/logo.png', alt_text: 'IdP Tools' }
    }]
  };
  meta.credential_configurations_supported[VCI_CONFIG_ID] = {
    format: 'dc+sd-jwt',
    scope: VCI_SCOPE,
    vct: VCI_VCT,
    cryptographic_binding_methods_supported: ['jwk'],
    credential_signing_alg_values_supported: ['RS256'],
    proof_types_supported: {
      jwt: { proof_signing_alg_values_supported: ['ES256', 'RS256'] }
    },
    display: [{
      name: 'Identity Credential',
      locale: 'en-US',
      background_color: '#12107c',
      text_color: '#FFFFFF'
    }],
    claims: [
      { path: ['given_name'], display: [{ locale: 'en-US', name: 'Given name' }] },
      { path: ['family_name'], display: [{ locale: 'en-US', name: 'Family name' }] },
      { path: ['email'], display: [{ locale: 'en-US', name: 'Email address' }] },
      { path: ['birthdate'], display: [{ locale: 'en-US', name: 'Date of birth' }] },
      { path: ['address', 'country'], display: [{ locale: 'en-US', name: 'Country' }] }
    ]
  };
  // The same facts as a W3C VC secured as a JWT. `credential_definition.type`
  // is what identifies the credential in this format — jwt_vc_json has no vct —
  // and the claim paths are rooted at credentialSubject because that is where a
  // W3C VC keeps them.
  meta.credential_configurations_supported[VCI_JWT_CONFIG_ID] = {
    format: 'jwt_vc_json',
    scope: VCI_JWT_SCOPE,
    credential_definition: { type: VCI_JWT_TYPES },
    cryptographic_binding_methods_supported: ['jwk'],
    credential_signing_alg_values_supported: ['RS256'],
    proof_types_supported: {
      jwt: { proof_signing_alg_values_supported: ['ES256', 'RS256'] }
    },
    display: [{
      name: 'Identity Credential (JWT VC, no selective disclosure)',
      locale: 'en-US',
      background_color: '#0b6b4f',
      text_color: '#FFFFFF'
    }],
    claims: [
      { path: ['credentialSubject', 'given_name'], display: [{ locale: 'en-US', name: 'Given name' }] },
      { path: ['credentialSubject', 'family_name'], display: [{ locale: 'en-US', name: 'Family name' }] },
      { path: ['credentialSubject', 'email'], display: [{ locale: 'en-US', name: 'Email address' }] },
      { path: ['credentialSubject', 'birthdate'], display: [{ locale: 'en-US', name: 'Date of birth' }] },
      { path: ['credentialSubject', 'address', 'country'], display: [{ locale: 'en-US', name: 'Country' }] }
    ]
  };
  // ldp_vc: the signing "alg" slot holds a CRYPTOSUITE name, not a JOSE alg —
  // which is the visible sign that this format is secured differently.
  meta.credential_configurations_supported[VCI_LDP_CONFIG_ID] = {
    format: 'ldp_vc',
    scope: VCI_LDP_SCOPE,
    credential_definition: {
      '@context': ['https://www.w3.org/ns/credentials/v2', bbs2023.IDENTITY_CONTEXT_URL],
      type: VCI_JWT_TYPES
    },
    cryptographic_binding_methods_supported: ['did:key'],
    credential_signing_alg_values_supported: ['bbs-2023'],
    proof_types_supported: {
      jwt: { proof_signing_alg_values_supported: ['ES256'] }
    },
    display: [{
      name: 'Identity Credential (ldp_vc, BBS selective disclosure)',
      locale: 'en-US', background_color: '#4a148c', text_color: '#FFFFFF'
    }],
    claims: [
      { path: ['credentialSubject', 'given_name'], display: [{ locale: 'en-US', name: 'Given name' }] },
      { path: ['credentialSubject', 'family_name'], display: [{ locale: 'en-US', name: 'Family name' }] },
      { path: ['credentialSubject', 'email'], display: [{ locale: 'en-US', name: 'Email address' }] },
      { path: ['credentialSubject', 'birthDate'], display: [{ locale: 'en-US', name: 'Date of birth' }] }
    ]
  };
  // The DID variants, CLONED from the sibling each is based on rather than
  // written out a fourth and fifth time. Everything about the credential is
  // meant to be identical — the point of the pair is that only the issuer's own
  // name differs — so a claim or proof type added above must not be able to go
  // missing from the DID version.
  vciConfigIds().forEach(function (id) {
    const config = VCI_CONFIGS[id];
    if (!config.basedOn) return;
    const sibling = meta.credential_configurations_supported[config.basedOn];
    if (!sibling) {
      // Loud, because the symptom otherwise is a configuration this issuer
      // advertises nowhere while still minting credentials for it.
      log.error('the ' + id + ' configuration names a sibling ' + config.basedOn +
                ' that the metadata does not offer; it will not be advertised.');
      return;
    }
    const entry = JSON.parse(JSON.stringify(sibling));
    entry.scope = config.scope;
    if (Array.isArray(entry.display) && entry.display.length) {
      entry.display[0].name = entry.display[0].name + ' — issuer named by DID';
    }
    meta.credential_configurations_supported[id] = entry;
  });

  // --- who this issuer says it is (both extensions; see the DID section) -----
  //
  // OID4VCI registers neither of these members. They are here because without
  // them a wallet that receives a credential whose iss is a did:web has been
  // told about that DID by nothing it fetched: it has to take the credential's
  // word for who issued it, which is the one thing a credential's own contents
  // cannot establish.
  //
  //   issuer_did          the DID this issuer also answers to. Always present,
  //                       because the DID document is always served — a wallet
  //                       can resolve it, and can check the domain linkage at
  //                       /.well-known/did-configuration.json, before any
  //                       credential exists.
  //   issuer_identifier   per configuration: the value credentials from THIS
  //                       configuration will carry in iss (dc+sd-jwt) or issuer
  //                       (jwt_vc_json, ldp_vc). Stated per configuration
  //                       because that is the granularity at which it varies,
  //                       and computed from issuerDidFor() — the same function
  //                       the builders use — so the advertisement and the
  //                       credential cannot disagree.
  meta.issuer_did = stsDid(req);
  vciConfigIds().forEach(function (id) {
    const entry = meta.credential_configurations_supported[id];
    if (entry) entry.issuer_identifier = issuerDidFor(id, req) || base;
  });

  log.debug("Leaving vciMetadata(). " + Object.keys(meta.credential_configurations_supported).length +
            " credential configuration(s), " +
            vciConfigIds().filter(vciUsesIssuerDid).length + " of them naming the issuer by DID.");
  return meta;
}

// OID4VCI adopts RFC 8414's signed_metadata: a JWT of the metadata signed by
// the issuer. Signed with the same STS key, so the debugger can verify it
// against /oauth2/jwks exactly as it verifies an RFC 8414 document.
function sendVciMetadata(req, res) {
  log.debug("Entering sendVciMetadata().");
  const meta = vciMetadata(req);
  const claims = Object.assign({}, meta, { sub: meta.credential_issuer });
  logArtifact('OID4VCI signed_metadata', 'before signing', claims);
  try {
    meta.signed_metadata = jwt.sign(claims, STS.privateKeyPem,
      { algorithm: 'RS256', issuer: meta.credential_issuer, expiresIn: 3600, keyid: STS.kid });
    logArtifact('OID4VCI signed_metadata', 'after signing', meta.signed_metadata);
  } catch (e) {
    log.error('OID4VCI signed_metadata: ' + e.message);
  }
  res.status(200).type('application/json').set('Cache-Control', 'no-store').send(JSON.stringify(meta, null, 2));
  log.debug("Leaving sendVciMetadata().");
}

app.get('/.well-known/openid-credential-issuer', sendVciMetadata);

app.get('/.well-known/openid-credential-issuer/*', sendVciMetadata);

// SD-JWT VC key resolution: how a verifier finds the issuer's public keys.
//
// `issuer` is the https identifier and stays that way, because this document is
// found BY that identifier: draft-ietf-oauth-sd-jwt-vc has a verifier take the
// credential's iss, insert /.well-known/jwt-vc-issuer into it and require that
// the document's issuer equals the iss it started from. A DID cannot be the
// subject of that rule — there is no URL to insert anything into — which is
// exactly why the DID route is an extension and not this.
//
// `issuer_did` is that extension, and it is one line rather than a mechanism: it
// says the same issuer also answers to this DID, whose document publishes the
// same keys this jwks_uri does. A wallet holding a DID-named credential can start
// from the origin, find the DID named here, and confirm the two are one entity
// at /.well-known/did-configuration.json. Without it, the DID and the URL are
// two identifiers with nothing connecting them.
function sendJwtVcIssuerMetadata(req, res) {
  log.debug("Entering sendJwtVcIssuerMetadata().");
  const base = baseUrlOf(req);
  res.status(200).type('application/json').set('Cache-Control', 'no-store').send(JSON.stringify({
    issuer: base,
    jwks_uri: base + '/oauth2/jwks',
    issuer_did: stsDid(req)
  }, null, 2));
  log.debug("Leaving sendJwtVcIssuerMetadata().");
}

app.get('/.well-known/jwt-vc-issuer', sendJwtVcIssuerMetadata);

app.get('/.well-known/jwt-vc-issuer/*', sendJwtVcIssuerMetadata);

// --- Nonce Endpoint ---------------------------------------------------------
app.post('/oid4vci/nonce', function (req, res) {
  log.debug("Entering the OID4VCI nonce endpoint.");
  const nonce = b64u(crypto.randomBytes(24));
  const now = Date.now();
  vciNonces.set(nonce, now + VCI_NONCE_TTL_MS);
  // Opportunistic sweep, so a long-running mock does not grow without bound.
  vciNonces.forEach(function (expires, key) { if (expires < now) vciNonces.delete(key); });
  res.set('Cache-Control', 'no-store');
  // The one thing OID4VCI says about DPoP by name: "The Credential Issuer MAY
  // provide a DPoP nonce in an HTTP header as defined in Section 8.2 of RFC
  // 9449. In this case, the Wallet uses the new nonce value in the DPoP proof
  // when presenting an access token at the Credential Endpoint."
  //
  // Which is a genuinely useful pairing rather than a curiosity: the wallet is
  // already making this call to get a c_nonce for its proof of possession, so
  // handing it a DPoP nonce at the same time costs no extra round trip. The
  // alternative is the 401/retry handshake, and this endpoint is the one place
  // in the flow where that can be skipped.
  //
  // Only when nonces are actually being required — a DPoP-Nonce header on a
  // server that will accept a proof without one teaches the wallet to send a
  // claim nothing checks.
  if (dpop.nonceModeOn()) {
    const dpopNonce = dpop.issueNonce();
    res.set('DPoP-Nonce', dpopNonce);
    log.debug("...and a DPoP nonce alongside it (OID4VCI's Nonce Response, RFC 9449 8.2).");
  }
  res.status(200).type('application/json').send(JSON.stringify({
    c_nonce: nonce,
    c_nonce_expires_in: VCI_NONCE_TTL_MS / 1000
  }));
  log.debug("Leaving the OID4VCI nonce endpoint. Handed out one c_nonce; " +
            vciNonces.size + " now outstanding.");
});

// --- the wallet's proof of possession --------------------------------------
// A JWT proof (OID4VCI): typ openid4vci-proof+jwt, the holder's public key in
// the header as a JWK, and claims binding it to this issuer and to a c_nonce
// this issuer handed out. Returns the holder JWK on success.
function verifyProofJwt(proofJwt, credentialIssuer) {
  log.debug("Entering verifyProofJwt().");
  logArtifact('OID4VCI proof of possession', 'as received', proofJwt);
  const parts = String(proofJwt || '').split('.');
  if (parts.length !== 3) throw new Error('the proof is not a three-part JWS.');
  let header, claims;
  try {
    header = jsonFromB64u(parts[0]);
    claims = jsonFromB64u(parts[1]);
  } catch (e) {
    throw new Error('the proof is not a readable JWT: ' + e.message);
  }

  if (header.typ !== 'openid4vci-proof+jwt') {
    throw new Error('the proof typ must be openid4vci-proof+jwt, got "' + header.typ + '".');
  }
  if (!header.jwk) throw new Error('the proof header carries no jwk (this issuer binds to a JWK).');
  if (['ES256', 'RS256'].indexOf(header.alg) < 0) {
    throw new Error('unsupported proof alg "' + header.alg + '".');
  }
  if (claims.aud !== credentialIssuer) {
    throw new Error('the proof aud ("' + claims.aud + '") is not this credential issuer ("' +
                    credentialIssuer + '").');
  }
  if (!claims.iat || Math.abs(Date.now() / 1000 - claims.iat) > 600) {
    throw new Error('the proof iat is missing or too far from now.');
  }
  const expires = vciNonces.get(claims.nonce);
  if (!expires) throw new Error('the proof nonce is not one this issuer handed out (or was already used).');
  // The c_nonce belongs to the REQUEST, not to a single proof: a batch request
  // carries several proofs and they all quote the same one (section 8.2). So it
  // is not spent here — the caller spends it once, after every proof in the
  // request has been verified. Consuming it per proof made the second proof of
  // any batch fail, which is exactly the bug batch issuance uncovered.
  if (expires < Date.now()) {
    vciNonces.delete(claims.nonce);
    throw new Error('the proof nonce has expired.');
  }

  let key;
  try {
    key = crypto.createPublicKey({ key: header.jwk, format: 'jwk' });
  } catch (e) {
    throw new Error('the proof header jwk is not a usable public key: ' + e.message);
  }
  const data = Buffer.from(parts[0] + '.' + parts[1], 'ascii');
  const sig = b64uDecode(parts[2]);
  const opts = (header.alg === 'ES256')
    ? { key: key, dsaEncoding: 'ieee-p1363' }
    : { key: key };
  if (!crypto.verify('sha256', data, opts, sig)) {
    throw new Error('the proof signature does not verify with the key in its own header.');
  }
  logArtifact('OID4VCI proof of possession', 'verified', { header: header, payload: claims });
  log.debug("Leaving verifyProofJwt(). The proof is good.");
  return header.jwk;
}

// --- SD-JWT VC construction (RFC 9901) --------------------------------------
// A Disclosure is base64url(JSON [salt, claim name, claim value]); the digest
// that goes in _sd is base64url(SHA-256(the ASCII of that base64url string)).
function makeDisclosure(name, value) {
  log.debug("Entering makeDisclosure(). name=" + name);
  const salt = b64u(crypto.randomBytes(16));
  const encoded = b64u(Buffer.from(JSON.stringify([salt, name, value]), 'utf8'));
  const digest = b64u(crypto.createHash('sha256').update(encoded, 'ascii').digest());
  log.debug("Leaving makeDisclosure(). digest=" + digest);
  return { salt: salt, name: name, value: value, encoded: encoded, digest: digest };
}

function buildSdJwtVc(subjectClaims, holderJwk, credentialIssuer, issuerDid) {
  // An extension, not the spec: draft-ietf-oauth-sd-jwt-vc defines no DID-based
  // issuer signature mechanism. When one is configured the iss becomes the DID
  // and a wallet resolves it for the verification key instead of fetching
  // /.well-known/jwt-vc-issuer. cnf.jwk is untouched — holder binding is
  // RFC 7800 either way, and a DID there would be nobody's convention.
  log.debug("Entering buildSdJwtVc().");
  const issuerId = issuerDid || credentialIssuer;
  logArtifact('SD-JWT VC', 'the claims it will assert, before any of them are hidden',
              { subjectClaims: subjectClaims, holderJwk: holderJwk, credentialIssuer: credentialIssuer });
  const now = Math.floor(Date.now() / 1000);
  // Everything the holder can choose to disclose, one Disclosure each. sub is
  // not among them: it stays a plain claim, so the credential always says who
  // it is about.
  const disclosures = Object.keys(subjectClaims)
    .filter(function (name) { return name !== 'sub'; })
    .map(function (name) { return makeDisclosure(name, subjectClaims[name]); });
  // A decoy digest: RFC 9901 section 4.2.5 — hash a random value so the count
  // of _sd entries does not reveal how many claims there really are.
  const decoy = b64u(crypto.createHash('sha256').update(b64u(crypto.randomBytes(16)), 'ascii').digest());
  const digests = disclosures.map(function (d) { return d.digest; }).concat([decoy]).sort();

  const payload = {
    iss: issuerId,
    nbf: now,
    exp: now + 30 * 24 * 3600,
    vct: VCI_VCT,
    sub: subjectClaims.sub || 'urn:uuid:' + crypto.randomUUID(),
    cnf: { jwk: holderJwk },
    _sd_alg: 'sha-256',
    _sd: digests
  };
  logArtifact('SD-JWT VC', 'before signing',
              { header: { alg: 'RS256', typ: 'dc+sd-jwt', kid: STS.kid },
                payload: payload,
                disclosures: disclosures.map(function (d) {
                  return { name: d.name, value: d.value, salt: d.salt, digest: d.digest, encoded: d.encoded };
                }),
                decoyDigest: decoy });

  // iat is added by the signer (jsonwebtoken drops a payload iat when it is
  // told not to timestamp, so it is left to do it).
  const issuerJwt = jwt.sign(payload, STS.privateKeyPem, {
    algorithm: 'RS256',
    header: { alg: 'RS256', typ: 'dc+sd-jwt', kid: STS.kid }
  });
  logArtifact('SD-JWT VC issuer-signed JWT', 'after signing', issuerJwt);

  // Combined Serialization: <JWT>~<D1>~...~<Dn>~ (the trailing ~ is required
  // when no Key Binding JWT is present).
  const serialized = [issuerJwt].concat(disclosures.map(function (d) { return d.encoded; })).join('~') + '~';
  logArtifact('SD-JWT VC', 'after signing, as it will be sent (Combined Serialization)', serialized);
  log.debug("Leaving buildSdJwtVc(). " + disclosures.length + " disclosure(s) plus 1 decoy digest.");
  return { credential: serialized, disclosures: disclosures, payload: payload, decoy: decoy };
}

// A W3C Verifiable Credential secured as a JWT (OID4VCI format jwt_vc_json).
//
// The VC-JWT encoding of VCDM 1.1: the credential object goes in the `vc`
// claim, and the JWT's own registered claims carry the parts that would
// otherwise be duplicated inside it — iss is the issuer, sub the credential
// subject, nbf/exp the validity window, jti the credential id.
//
// Two things to notice, because they are what the workflow is meant to show:
// there are NO Disclosures and no _sd digests — every claim is in the clear in
// the payload, so a holder presenting this discloses all of it; and holder
// binding is the same cnf.jwk this issuer puts in an SD-JWT VC, but what proves
// possession at presentation time is a Verifiable Presentation JWT signed with
// that key rather than a Key Binding JWT.
function buildJwtVcJson(subjectClaims, holderJwk, credentialIssuer, issuerDid) {
  // As for ldp_vc, naming the issuer by DID is ordinary in a W3C credential
  // rather than an extension — this is VCDM, and the DID goes in both the JWT's
  // iss and the credential's own issuer, which must agree. It is wired here for
  // the same reason it is wired there: issuerDidFor() can return a DID for this
  // format (the startup flag covers every JOSE-secured configuration), and a
  // builder that took the argument and ignored it would issue https-named
  // credentials from an issuer whose metadata said otherwise.
  log.debug("Entering buildJwtVcJson().");
  const issuerId = issuerDid || credentialIssuer;
  logArtifact('jwt_vc_json credential', 'the claims it will assert',
              { subjectClaims: subjectClaims, holderJwk: holderJwk, credentialIssuer: credentialIssuer });
  const now = Math.floor(Date.now() / 1000);
  const exp = now + 30 * 24 * 3600;
  const subjectId = subjectClaims.sub || ('urn:uuid:' + crypto.randomUUID());

  // credentialSubject.id is the subject identifier; the rest of the claims sit
  // beside it. `sub` is not repeated inside as a claim of its own — it IS the id.
  const credentialSubject = { id: subjectId };
  Object.keys(subjectClaims).forEach(function (name) {
    if (name !== 'sub') credentialSubject[name] = subjectClaims[name];
  });

  const vc = {
    '@context': [VC_CONTEXT],
    type: VCI_JWT_TYPES,
    issuer: issuerId,
    issuanceDate: new Date(now * 1000).toISOString(),
    expirationDate: new Date(exp * 1000).toISOString(),
    credentialSubject: credentialSubject
  };
  const payload = {
    iss: issuerId,
    sub: subjectId,
    nbf: now,
    exp: exp,
    jti: 'urn:uuid:' + crypto.randomUUID(),
    cnf: { jwk: holderJwk },
    vc: vc
  };
  logArtifact('jwt_vc_json credential', 'before signing',
              { header: { alg: 'RS256', typ: 'JWT', kid: STS.kid }, payload: payload });

  const token = jwt.sign(payload, STS.privateKeyPem, {
    algorithm: 'RS256',
    header: { alg: 'RS256', typ: 'JWT', kid: STS.kid }
  });
  logArtifact('jwt_vc_json credential', 'after signing, as it will be sent', token);
  log.debug("Leaving buildJwtVcJson(). " + (Object.keys(credentialSubject).length - 1) +
            " claim(s), none of them selectively disclosable.");
  // `disclosures` is deliberately an empty array rather than absent: the callers
  // count them for logging, and "this format has none" is the honest answer.
  return { credential: token, disclosures: [], payload: payload, vc: vc };
}

// A W3C credential with an EMBEDDED bbs-2023 proof (OID4VCI format ldp_vc).
//
// Async, unlike the other two, because canonicalization is — which is why
// buildCredentialFor and the credential endpoint are async as well.
//
// Holder binding differs from the other formats by necessity: there is no
// cnf.jwk here. The holder is named by credentialSubject.id, a did:key built
// from the key it proved possession of, and what proves possession at
// presentation time is the BBS derived proof itself rather than a separate
// signature by the holder.
async function buildLdpVc(subjectClaims, holderJwk, credentialIssuer, issuerDid) {
  // VC Data Model 2.0 is DID-native, so naming the issuer by DID here is
  // ordinary rather than an extension. The verification method moves with it:
  // a DID URL fragment into this issuer's DID document instead of a
  // dereferenceable https URL.
  log.debug("Entering buildLdpVc().");
  const issuerId = issuerDid || credentialIssuer;
  const bbsVerificationMethod = issuerDid ? issuerDid + '#bbs-1'
                                          : credentialIssuer + '/bbs/keys/1';
  const keys = await bbsKeyPair();
  const now = Math.floor(Date.now() / 1000);
  const subjectId = 'did:jwk:' + b64u(Buffer.from(JSON.stringify({
    crv: holderJwk.crv, kty: holderJwk.kty, x: holderJwk.x, y: holderJwk.y
  })));
  const unsecured = {
    '@context': ['https://www.w3.org/ns/credentials/v2', bbs2023.IDENTITY_CONTEXT_URL],
    type: VCI_JWT_TYPES,
    issuer: issuerId,
    validFrom: new Date(now * 1000).toISOString(),
    validUntil: new Date((now + 30 * 24 * 3600) * 1000).toISOString(),
    credentialSubject: {
      id: subjectId,
      given_name: subjectClaims.given_name,
      family_name: subjectClaims.family_name,
      email: subjectClaims.email,
      birthDate: subjectClaims.birthdate
    }
  };
  logArtifact('ldp_vc credential', 'before signing', unsecured);
  const issued = await bbs2023.issue(unsecured, {
    verificationMethod: bbsVerificationMethod,
    created: new Date(now * 1000).toISOString()
  }, keys.secretKey, keys.publicKey);

  // Verified immediately, by this service, before it is handed out: the
  // requirement is that the STS validate every crypto operation, and an issuer
  // that cannot verify its own output has no business emitting it.
  const check = await bbs2023.verifyBase(issued.credential, keys.publicKey);
  if (!check.ok) throw new Error('the ldp_vc credential this issuer just built does not verify');

  logArtifact('ldp_vc credential', 'after signing (' + issued.statements.length + ' statements)',
              issued.credential);
  log.debug("Leaving buildLdpVc(). " + issued.statements.length + " canonical statement(s).");
  return { credential: issued.credential, disclosures: [], payload: issued.credential,
           statements: issued.statements };
}

// Mint whichever format the requested configuration names.
async function buildCredentialFor(configId, subjectClaims, holderJwk, credentialIssuer, issuerDid) {
  const format = vciFormatOf(configId);
  if (format === 'ldp_vc') return buildLdpVc(subjectClaims, holderJwk, credentialIssuer, issuerDid);
  if (format === 'jwt_vc_json') return buildJwtVcJson(subjectClaims, holderJwk, credentialIssuer, issuerDid);
  return buildSdJwtVc(subjectClaims, holderJwk, credentialIssuer, issuerDid);
}

// The claims the credential asserts. Lifted from the access token when it is a
// JWT (so the credential describes whoever actually authenticated), with
// mock-issuer defaults for anything the token does not carry.
function subjectClaimsFrom(accessToken) {
  log.debug("Entering subjectClaimsFrom().");
  let t = {};
  try {
    const parts = String(accessToken || '').split('.');
    if (parts.length === 3) t = jsonFromB64u(parts[1]) || {};
  } catch (e) {
    // An opaque token — the mock defaults it is.
    log.debug("The access token is not a readable JWT; using the default claims.");
  }
  const user = t.preferred_username || t.sub || 'mock-holder';
  log.debug("Leaving subjectClaimsFrom(). The credential will describe " + user + ".");
  return {
    sub: t.sub || ('urn:uuid:' + crypto.randomUUID()),
    given_name: t.given_name || user,
    family_name: t.family_name || 'Holder',
    email: t.email || (user + '@example.com'),
    birthdate: '1979-04-01',
    nationality: 'US',
    address: { street_address: '100 Main St', locality: 'Springfield', region: 'IL', country: 'US' }
  };
}

// ---------------------------------------------------------------------------
// Which Credential Dataset identifiers an access token was granted.
//
// They were put into the token when it was issued, and the token is signed by
// this service, so reading them back is a verification — a wallet cannot award
// itself an identifier by editing anything.
// ---------------------------------------------------------------------------
// The nonces a set of proofs quoted, spent together: one Credential Request, one
// c_nonce, however many proofs.
function spendProofNonces(proofJwts) {
  log.debug("Entering spendProofNonces(). " + proofJwts.length + " proof(s).");
  const spent = [];
  proofJwts.forEach(function (proof) {
    let nonce;
    try {
      nonce = (jsonFromB64u(String(proof).split('.')[1]) || {}).nonce;
    } catch (e) {
      // Unreadable proofs never got this far; ignore it rather than throwing
      // after the credential has already been decided on.
      log.debug("spendProofNonces(): a proof payload could not be read: " + e.message);
      return;
    }
    if (nonce && vciNonces.delete(nonce) && spent.indexOf(nonce) === -1) spent.push(nonce);
  });
  log.debug("Leaving spendProofNonces(). Spent " + spent.length + " distinct nonce(s).");
}

function grantedIdentifiers(accessToken) {
  log.debug("Entering grantedIdentifiers().");
  let claims;
  try {
    claims = jwt.verify(accessToken, STS.certPem, { algorithms: ['RS256'] });
  } catch (e) {
    // Not our token (or not valid): nothing was granted by us. The caller still
    // checks the token elsewhere; this only answers "what did we grant".
    log.debug("Leaving grantedIdentifiers(). The token is not one of ours: " + e.message);
    return [];
  }
  const details = claims.authorization_details || [];
  const out = [];
  details.forEach(function (d) {
    (d.credential_identifiers || []).forEach(function (id) { out.push(id); });
  });
  log.debug("Leaving grantedIdentifiers(). " + out.length + " identifier(s).");
  return out;
}

// ---------------------------------------------------------------------------
// Notification ids (OID4VCI section 11).
//
// The issuer returns one per Credential Response so the wallet can report what
// it did with the credential. Remembering them is what lets the notification
// endpoint tell a real id from an invented one — and section 11.3 defines
// invalid_notification_id precisely so that distinction is made.
// ---------------------------------------------------------------------------
const notificationIds = new Map();   // id -> { accessToken, expires, event }

function newNotificationId(accessToken) {
  log.debug("Entering newNotificationId().");
  const id = b64u(crypto.randomBytes(12));
  notificationIds.set(id, { accessToken: accessToken, expires: Date.now() + OFFER_TTL_MS, event: null });
  const now = Date.now();
  notificationIds.forEach(function (v, k) { if (v.expires < now) notificationIds.delete(k); });
  log.debug("Leaving newNotificationId(). " + id);
  return id;
}

// ---------------------------------------------------------------------------
// Credential Response encryption (OID4VCI section 10).
//
// The wallet supplies the key and the content encryption algorithm, and gets a
// JWE back instead of JSON. Only what the metadata advertises is accepted —
// advertising an algorithm this then refuses would make the metadata a lie.
// ---------------------------------------------------------------------------
const VCI_ENC_ALG = 'RSA-OAEP-256';

const VCI_ENC_VALUES = ['A128GCM', 'A256GCM'];

// ---------------------------------------------------------------------------
// Credential REQUEST encryption (OID4VCI section 10), the other direction.
//
// The response side is the wallet's key travelling in the request. This side is
// the reverse and the asymmetry is the whole reason it needs its own code: the
// ISSUER publishes the key, in credential_request_encryption.jwks, and the
// wallet encrypts to it. Two consequences fall out of section 10 that the
// response side does not have:
//
//   * there is no alg_values_supported for requests. "The `alg` parameter MUST
//     be present [in the JWK]. The JWE `alg` algorithm used MUST be equal to
//     the `alg` value of the chosen JWK" — so the algorithm is a property of
//     the key, not a separate list, and this key therefore carries alg itself;
//   * "Each JWK in the set MUST have a kid (Key ID) parameter that uniquely
//     identifies the key", and a JWE encrypted to a key with a kid MUST repeat
//     it in the JWE header. That is what lets an issuer rotate keys, so the kid
//     is checked on the way in rather than ignored.
//
// The key is regenerated per start, like the signing key, and its kid is
// derived from the key material for the same reason: two instances must not
// claim the same kid over different keys, or "decryption failed" looks like a
// corrupt request instead of the wrong issuer.
// ---------------------------------------------------------------------------
const VCI_REQUEST_ENC_VALUES = ['A128GCM', 'A256GCM'];

// Only an explicit "true" turns the requirement on: a mock that demanded
// encryption because of a typo in an environment variable would fail every
// existing test with an error about something the test never mentioned.
const VCI_REQUEST_ENCRYPTION_REQUIRED =
  String(process.env.OID4VCI_REQUEST_ENCRYPTION_REQUIRED || '').toLowerCase() === 'true';

const VCI_REQUEST_ENC_KEY = (function () {
  const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const publicJwk = pair.publicKey.export({ format: 'jwk' });
  // RFC 7638 thumbprint: the canonical members, in lexicographic order, no
  // whitespace. Deriving the kid from the key means it cannot outlive it.
  const thumbprint = crypto.createHash('sha256')
    .update(JSON.stringify({ e: publicJwk.e, kty: publicJwk.kty, n: publicJwk.n }))
    .digest('base64url').slice(0, 16);
  return {
    privateKey: pair.privateKey,
    publicJwk: Object.assign({}, publicJwk, {
      kid: 'sts-mock-req-enc-' + thumbprint,
      alg: VCI_ENC_ALG,
      use: 'enc',
      key_ops: ['encrypt']
    })
  };
})();

function credentialRequestEncryptionMetadata() {
  log.debug("Entering credentialRequestEncryptionMetadata().");
  log.debug("Leaving credentialRequestEncryptionMetadata().");
  return {
    jwks: { keys: [VCI_REQUEST_ENC_KEY.publicJwk] },
    enc_values_supported: VCI_REQUEST_ENC_VALUES,
    // zip_values_supported is deliberately absent: "If absent then no
    // compression algorithms are supported", and this issuer does not
    // decompress. Advertising a zip it then refused would make the metadata a
    // lie, which is the same rule the response side follows.
    encryption_required: VCI_REQUEST_ENCRYPTION_REQUIRED
  };
}

// The mirror of encryptToJwe(): RSA-OAEP-256 unwrap of the content key, then
// AES-GCM with the protected header as additional authenticated data. Written
// out by hand for the same reason — having the steps visible is the point.
//
// Throws with a reason a caller can hand back to the wallet; every failure here
// is the wallet's request being unusable, not an issuer fault.
function decryptJweRequest(compact) {
  log.debug("Entering decryptJweRequest().");
  const parts = String(compact || '').trim().split('.');
  if (parts.length !== 5) {
    throw new Error('an encrypted Credential Request must be a JWE in compact serialization ' +
      '(five dot-separated parts); this has ' + parts.length + '.');
  }
  let header;
  try {
    header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
  } catch (e) {
    throw new Error('the JWE protected header is not valid base64url JSON: ' + e.message);
  }
  logArtifact('OID4VCI Credential Request', 'JWE protected header as received', header);
  if (header.alg !== VCI_ENC_ALG) {
    throw new Error('this issuer decrypts with alg ' + VCI_ENC_ALG + '; the request used "' +
      header.alg + '".');
  }
  if (VCI_REQUEST_ENC_VALUES.indexOf(header.enc) === -1) {
    throw new Error('this issuer supports enc ' + VCI_REQUEST_ENC_VALUES.join(' or ') +
      '; the request used "' + header.enc + '".');
  }
  if (header.zip) {
    throw new Error('this issuer advertises no zip_values_supported, so a compressed request ' +
      'cannot be read.');
  }
  // Section 10 requires the kid to be echoed when the chosen key has one, and
  // this issuer's key always does. Checking it is what makes key rotation
  // detectable: a wallet holding a stale key is told so, instead of getting an
  // opaque decryption failure.
  if (header.kid !== VCI_REQUEST_ENC_KEY.publicJwk.kid) {
    throw new Error('the JWE kid "' + (header.kid || '(absent)') + '" is not this issuer\'s current ' +
      'request encryption key "' + VCI_REQUEST_ENC_KEY.publicJwk.kid + '". Re-read the credential ' +
      'issuer metadata: this key is regenerated when the issuer restarts.');
  }

  let cek;
  try {
    cek = crypto.privateDecrypt({
      key: VCI_REQUEST_ENC_KEY.privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    }, Buffer.from(parts[1], 'base64url'));
  } catch (e) {
    throw new Error('the content encryption key could not be unwrapped with this issuer\'s private ' +
      'key: ' + e.message);
  }
  const bits = header.enc === 'A128GCM' ? 128 : 256;
  if (cek.length !== bits / 8) {
    throw new Error('the unwrapped content encryption key is ' + cek.length + ' bytes; ' +
      header.enc + ' needs ' + (bits / 8) + '.');
  }

  let plaintext;
  try {
    const decipher = crypto.createDecipheriv('aes-' + bits + '-gcm', cek,
      Buffer.from(parts[2], 'base64url'));
    decipher.setAAD(Buffer.from(parts[0], 'ascii'));
    decipher.setAuthTag(Buffer.from(parts[4], 'base64url'));
    plaintext = Buffer.concat([
      decipher.update(Buffer.from(parts[3], 'base64url')), decipher.final()
    ]).toString('utf8');
  } catch (e) {
    // An authentication tag failure lands here, and it is the interesting case:
    // the ciphertext or the header was altered in flight.
    throw new Error('the ciphertext did not decrypt or its authentication tag did not verify: ' +
      e.message);
  }
  let body;
  try {
    body = JSON.parse(plaintext);
  } catch (e) {
    throw new Error('the decrypted request is not JSON: ' + e.message);
  }
  logArtifact('OID4VCI Credential Request', 'after decryption', body);
  log.debug("Leaving decryptJweRequest(). Decrypted " + plaintext.length + " characters.");
  return body;
}

// What either encrypted-capable endpoint does with its request body.
//
// Returns {body} or {error}. The caller answers; this decides. Both endpoints
// go through it so the credential and deferred paths cannot drift — section 10
// applies identically to each, and the deferred one is the easy one to forget.
// How the most recent Credential Request actually arrived, readable at the
// non-spec GET /oid4vci/last_request.
//
// This exists because a wallet's claim to have encrypted something is not
// observable from the wallet. A pane that assembles a perfect JWE, displays it,
// and then posts the plaintext anyway satisfies every client-side assertion —
// and while encryption_required is false the issuer accepts that JSON and
// issues, so even the end-to-end result looks right. Only the issuer knows what
// it received. A mutation test proved the point: dropping the ciphertext at the
// point of sending went completely undetected until this existed.
let lastCredentialRequest = { seen: false };

function readPossiblyEncryptedRequest(req) {
  log.debug("Entering readPossiblyEncryptedRequest().");
  const contentType = String(req.get('content-type') || '').toLowerCase();
  const encrypted = contentType.indexOf('application/jwt') === 0;
  if (!encrypted) {
    if (VCI_REQUEST_ENCRYPTION_REQUIRED) {
      // Section 10: "When encryption of a message was required but the received
      // message is unencrypted, it SHOULD be rejected."
      log.debug("Leaving readPossiblyEncryptedRequest(). Refused: encryption is required.");
      return {
        error: 'invalid_encryption_parameters',
        description: 'This issuer advertises credential_request_encryption.encryption_required = ' +
          'true, so the Credential Request must be a JWE sent as application/jwt.'
      };
    }
    // Every content type arrives as raw text here (the body parser above takes
    // all of them), so the plain path still has to parse its own JSON.
    try {
      const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
      lastCredentialRequest = {
        seen: true, encrypted: false, path: req.path,
        contentType: contentType || null, at: new Date().toISOString()
      };
      log.debug("Leaving readPossiblyEncryptedRequest(). Plain JSON.");
      return { body: body, encrypted: false };
    } catch (e) {
      log.error('the credential request body is not JSON: ' + e.message);
      return { error: 'invalid_request', description: 'The request body is not JSON: ' + e.message };
    }
  }
  try {
    const compact = typeof req.body === 'string' ? req.body : '';
    const body = decryptJweRequest(compact);
    // Recorded only once it has actually decrypted, so "encrypted" means the
    // issuer really read ciphertext rather than merely being sent a media type.
    let header = {};
    try { header = JSON.parse(Buffer.from(compact.split('.')[0], 'base64url').toString('utf8')); }
    catch (e2) { /* it decrypted, so this cannot fail; ignore defensively */ }
    lastCredentialRequest = {
      seen: true, encrypted: true, path: req.path,
      kid: header.kid || null, alg: header.alg || null, enc: header.enc || null,
      at: new Date().toISOString()
    };
    log.debug("Leaving readPossiblyEncryptedRequest(). Decrypted.");
    return { body: body, encrypted: true };
  } catch (e) {
    log.error('the encrypted Credential Request could not be read: ' + e.message);
    return { error: 'invalid_encryption_parameters', description: e.message };
  }
}

function encryptionProblem(encryption) {
  log.debug("Entering encryptionProblem().");
  const jwk = encryption.jwk;
  if (!jwk || jwk.kty !== 'RSA' || !jwk.n || !jwk.e) {
    log.debug("Leaving encryptionProblem(). The key is unusable.");
    return 'credential_response_encryption.jwk must be an RSA public key; this issuer encrypts with ' +
           VCI_ENC_ALG + '.';
  }
  const alg = jwk.alg || encryption.alg || VCI_ENC_ALG;
  if (alg !== VCI_ENC_ALG) {
    log.debug("Leaving encryptionProblem(). Unsupported alg " + alg);
    return 'This issuer supports alg ' + VCI_ENC_ALG + ' only; "' + alg + '" was requested.';
  }
  if (!encryption.enc) {
    log.debug("Leaving encryptionProblem(). No enc.");
    return 'credential_response_encryption.enc is required (' + VCI_ENC_VALUES.join(' or ') + ').';
  }
  if (VCI_ENC_VALUES.indexOf(encryption.enc) === -1) {
    log.debug("Leaving encryptionProblem(). Unsupported enc " + encryption.enc);
    return 'This issuer supports enc ' + VCI_ENC_VALUES.join(' or ') + '; "' + encryption.enc +
           '" was requested.';
  }
  if (encryption.zip) {
    log.debug("Leaving encryptionProblem(). zip requested.");
    return 'This issuer does not compress responses, so zip cannot be used.';
  }
  log.debug("Leaving encryptionProblem(). The parameters are usable.");
  return "";
}

// A JWE in compact serialization: RSA-OAEP-256 for the content key, AES-GCM for
// the content. Written out by hand rather than with a JOSE library, because
// having the steps visible is the point of a mock.
function encryptToJwe(plaintext, encryption) {
  log.debug("Entering encryptToJwe(). enc=" + encryption.enc);
  const bits = encryption.enc === 'A128GCM' ? 128 : 256;
  const cek = crypto.randomBytes(bits / 8);
  const iv = crypto.randomBytes(12);
  const header = { alg: VCI_ENC_ALG, enc: encryption.enc, typ: 'JWT' };
  if (encryption.jwk.kid) header.kid = encryption.jwk.kid;
  const headerB64 = b64u(Buffer.from(JSON.stringify(header), 'utf8'));

  const publicKey = crypto.createPublicKey({ key: encryption.jwk, format: 'jwk' });
  const encryptedKey = crypto.publicEncrypt({
    key: publicKey,
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: 'sha256'
  }, cek);

  const cipher = crypto.createCipheriv('aes-' + bits + '-gcm', cek, iv);
  // The protected header is the additional authenticated data, per RFC 7516.
  cipher.setAAD(Buffer.from(headerB64, 'ascii'));
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()]);
  const tag = cipher.getAuthTag();

  const compact = [headerB64, b64u(encryptedKey), b64u(iv), b64u(ciphertext), b64u(tag)].join('.');
  log.debug("Leaving encryptToJwe(). " + compact.length + " characters.");
  return compact;
}

// Every Credential Response goes out through here, so the encrypted and plain
// paths cannot drift apart.
function sendCredentialResponse(res, status, payload, encryption) {
  log.debug("Entering sendCredentialResponse(). status=" + status + ", encrypted=" + !!encryption);
  res.set('Cache-Control', 'no-store');
  if (!encryption) {
    res.status(status).type('application/json').send(JSON.stringify(payload));
    log.debug("Leaving sendCredentialResponse(). Sent as JSON.");
    return;
  }
  logArtifact('OID4VCI Credential Response', 'before encryption', payload);
  const jwe = encryptToJwe(JSON.stringify(payload), encryption);
  logArtifact('OID4VCI Credential Response', 'after encryption (JWE compact serialization)', jwe);
  // Section 10: an encrypted response is a JWT, and says so.
  res.status(status).type('application/jwt').send(jwe);
  log.debug("Leaving sendCredentialResponse(). Sent as a JWE.");
}

// The BBS public key the ldp_vc proofs are made with. A BBS key is not a JWK —
// there is no registered kty for BLS12-381 G2 in the JOSE registry — so it is
// published as its raw compressed bytes in multibase base64url, which is what
// the Data Integrity multikey encoding uses and what verificationMethod above
// points at. Served no-store because the key is regenerated on every start.
app.get('/bbs/keys/1', async function (req, res) {
  log.debug("Entering the BBS key endpoint.");
  const keys = await bbsKeyPair();
  res.set('Cache-Control', 'no-store');
  res.set('Access-Control-Allow-Origin', '*');
  res.status(200).type('application/json').send(JSON.stringify({
    id: baseUrlOf(req) + '/bbs/keys/1',
    type: 'Multikey',
    controller: baseUrlOf(req),
    cryptosuite: bbs2023.CRYPTOSUITE,
    publicKeyMultibase: 'u' + bbs2023.bytesToB64u(keys.publicKey)
  }));
  log.debug("Leaving the BBS key endpoint.");
});

app.post('/oid4vci/credential', async function (req, res) {
  log.debug("Entering the OID4VCI credential endpoint.");
  const presented = dpop.presentedAccessToken(req, res, 'the credential endpoint');
  if (!presented) return;
  const accessToken = presented.accessToken;

  // Section 10: the request may arrive encrypted, as application/jwt. Reading
  // it is the same job on both endpoints, so both call this.
  const read = readPossiblyEncryptedRequest(req);
  if (read.error) {
    return vciError(res, 400, read.error, read.description);
  }
  const body = read.body;

  // Which credential (OID4VCI section 8.2). Exactly one of the two identifies
  // it, and which one is not the wallet's choice: it depends on whether the
  // token response granted credential_identifiers.
  const granted = grantedIdentifiers(accessToken);
  const identifier = body.credential_identifier;
  const configId = body.credential_configuration_id;
  if (identifier && configId) {
    return vciError(res, 400, 'invalid_credential_request',
      'credential_identifier and credential_configuration_id are mutually exclusive; send one.');
  }
  if (identifier) {
    if (!granted.length) {
      return vciError(res, 400, 'invalid_credential_request',
        'credential_identifier may only be used when the token response granted credential_identifiers ' +
        '(this authorization used a scope, so send credential_configuration_id instead).');
    }
    if (granted.indexOf(identifier) === -1) {
      return vciError(res, 400, 'invalid_credential_request',
        'credential_identifier "' + identifier + '" was not granted by the token response. Granted: ' +
        granted.join(', '));
    }
  } else if (configId) {
    if (granted.length) {
      return vciError(res, 400, 'invalid_credential_request',
        'the token response granted credential_identifiers, so credential_configuration_id MUST NOT be used ' +
        '(OID4VCI section 8.2).');
    }
    if (!VCI_CONFIGS[configId]) {
      return vciError(res, 400, 'unsupported_credential_type',
        'This issuer offers credential_configuration_id ' +
        vciConfigIds().map(function (id) { return '"' + id + '"'; }).join(' and ') + '.');
    }
  } else {
    return vciError(res, 400, 'invalid_credential_request',
      'Name the credential: credential_identifier (when one was granted) or credential_configuration_id.');
  }

  // Which format, decided once. An identifier names its configuration in its own
  // prefix; a configuration id names it directly. Anything else falls back to
  // the SD-JWT configuration, which is what this issuer has always offered.
  const requestedConfigId = identifier
    ? (configIdOfIdentifier(identifier) || VCI_CONFIG_ID)
    : (configId || VCI_CONFIG_ID);
  log.debug("The credential endpoint will issue " + vciFormatOf(requestedConfigId) +
            " (configuration " + requestedConfigId + ").");

  // Encryption of the response is the wallet's call (section 8.2). Checked before
  // any signature work: a request this issuer is going to refuse should not cost
  // the wallet its single-use c_nonce, and "your enc is unsupported" is a more
  // useful answer than "your proof is stale".
  const encryption = body.credential_response_encryption;
  if (encryption) {
    const problem = encryptionProblem(encryption);
    if (problem) {
      log.debug("Leaving the OID4VCI credential endpoint. The encryption parameters were refused.");
      return vciError(res, 400, 'invalid_encryption_parameters', problem);
    }
  }

  // OID4VCI 1.0 sends proofs.jwt[], one entry per key the credential should be
  // bound to; the earlier single-proof form is accepted too, since wallets in
  // the wild still send it. One credential comes back per proof (section 8.3).
  let proofJwts = [];
  if (body.proofs && Array.isArray(body.proofs.jwt) && body.proofs.jwt.length) proofJwts = body.proofs.jwt;
  else if (body.proof && body.proof.jwt) proofJwts = [body.proof.jwt];
  if (!proofJwts.length) {
    return vciError(res, 400, 'invalid_proof', 'A JWT proof of possession is required (proofs.jwt).');
  }
  if (proofJwts.length > VCI_BATCH_SIZE) {
    return vciError(res, 400, 'invalid_credential_request',
      'This issuer accepts at most ' + VCI_BATCH_SIZE + ' proofs in one request ' +
      '(batch_credential_issuance.batch_size); ' + proofJwts.length + ' were sent.');
  }

  let holderJwks = [];
  try {
    holderJwks = proofJwts.map(function (jwt) {
      return verifyProofJwt(jwt, vciMetadata(req).credential_issuer);
    });
  } catch (e) {
    log.error('the proof of possession was refused: ' + e.message);
    return vciError(res, 400, 'invalid_proof', e.message);
  }
  // Every proof in this request quoted the same c_nonce, and it is single use:
  // spend it now that they have all been accepted, so replaying the request is
  // refused while a batch inside one request is not.
  spendProofNonces(proofJwts);
  const holderJwk = holderJwks[0];


  // A deferred issuance (OID4VCI section 8.3 / Appendix H.3): the issuer cannot
  // produce the credential yet, so it answers 202 with a transaction_id and the
  // wallet comes back to the Deferred Credential Endpoint for it. Everything
  // needed to mint the credential is kept here; only the answer is postponed.
  if (deferredAccessTokens.has(accessToken)) {
    deferredAccessTokens.delete(accessToken);
    const transactionId = randomId(16);
    deferredTransactions.set(transactionId, {
      claims: subjectClaimsFrom(accessToken),
      holderJwk: holderJwk,
      holderJwks: holderJwks,
      // The format was chosen in the request that was deferred, not in the one
      // that collects it — the wallet asked for a credential, and postponing
      // the answer must not change which credential it gets.
      configId: requestedConfigId,
      // A deferred response is encrypted with the parameters given in the
      // DEFERRED request, not these — but keeping them means an issuer that
      // decides otherwise still has them. Section 9.2 is explicit that the newly
      // provided ones win.
      encryption: encryption,
      accessToken: accessToken,
      readyAt: Date.now() + DEFERRED_READY_MS,
      expires: Date.now() + OFFER_TTL_MS
    });
    const deferredResponse = { transaction_id: transactionId, interval: DEFERRED_INTERVAL_S };
    logArtifact('OID4VCI Credential Response', 'deferred', deferredResponse);
    res.set('Cache-Control', 'no-store');
    res.status(202).type('application/json').send(JSON.stringify(deferredResponse));
    log.debug("Leaving the OID4VCI credential endpoint. Deferred as " + transactionId +
              ", ready in " + DEFERRED_READY_MS + "ms.");
    return;
  }

  // One credential per key the wallet proved possession of.
  const claims = subjectClaimsFrom(accessToken);
  const issuerId = vciMetadata(req).credential_issuer;
  const issued = await Promise.all(holderJwks.map(function (jwk) {
    return buildCredentialFor(requestedConfigId, claims, jwk, issuerId,
      issuerDidFor(requestedConfigId, req));
  }));
  const response = {
    credentials: issued.map(function (b) { return { credential: b.credential }; }),
    notification_id: newNotificationId(accessToken)
  };
  logArtifact('OID4VCI Credential Response', 'as returned', response);
  sendCredentialResponse(res, 200, response, encryption);
  log.debug("Leaving the OID4VCI credential endpoint. Issued " + issued.length + " " +
            vciFormatOf(requestedConfigId) + " credential(s), " + issued[0].disclosures.length +
            " disclosure(s) each" + (encryption ? ", encrypted to the wallet's key" : "") + ".");
});

// The Deferred Credential Endpoint (OID4VCI section 9). 202 with the same
// transaction_id while the issuance is still "in progress", 200 with the
// credential once it is ready, and invalid_transaction_id for a transaction
// this issuer never made or has already handed over.
app.post('/oid4vci/deferred_credential', async function (req, res) {
  log.debug("Entering the OID4VCI deferred credential endpoint.");
  if (!dpop.presentedAccessToken(req, res, 'the deferred credential endpoint')) return;

  // Section 10 covers the Deferred Credential Request too, in the same words as
  // the Credential Request — so it goes through the same reader rather than
  // getting a second, subtly different implementation.
  const read = readPossiblyEncryptedRequest(req);
  if (read.error) {
    log.debug("Leaving the OID4VCI deferred credential endpoint. Unreadable body.");
    return vciError(res, 400, read.error, read.description);
  }
  const body = read.body;

  const transactionId = String(body.transaction_id || '');
  const record = deferredTransactions.get(transactionId);
  if (!record || record.expires < Date.now()) {
    deferredTransactions.delete(transactionId);
    log.debug("Leaving the OID4VCI deferred credential endpoint. No such transaction.");
    return vciError(res, 400, 'invalid_transaction_id',
      'That transaction_id was not issued by this Credential Issuer, or it has already been used.');
  }

  if (Date.now() < record.readyAt) {
    const pending = { transaction_id: transactionId, interval: DEFERRED_INTERVAL_S };
    logArtifact('OID4VCI Deferred Credential Response', 'still pending', pending);
    res.set('Cache-Control', 'no-store');
    res.status(202).type('application/json').send(JSON.stringify(pending));
    log.debug("Leaving the OID4VCI deferred credential endpoint. Still " +
              (record.readyAt - Date.now()) + "ms to go.");
    return;
  }

  // Ready. The transaction_id MUST be invalidated once the credential has been
  // obtained, so a second poll with it is an error rather than a second copy.
  deferredTransactions.delete(transactionId);
  const holderKeys = record.holderJwks || [record.holderJwk];
  const issuerId = vciMetadata(req).credential_issuer;
  // The format the DEFERRED request asked for, not a fresh choice: see the note
  // where it was recorded.
  const deferredConfigId = record.configId || VCI_CONFIG_ID;
  const issued = await Promise.all(holderKeys.map(function (jwk) {
    return buildCredentialFor(deferredConfigId, record.claims, jwk, issuerId,
      issuerDidFor(deferredConfigId, req));
  }));
  const response = {
    credentials: issued.map(function (b) { return { credential: b.credential }; }),
    notification_id: newNotificationId(record.accessToken)
  };
  logArtifact('OID4VCI Deferred Credential Response', 'as returned', response);
  sendCredentialResponse(res, 200, response, record.encryption);
  log.debug("Leaving the OID4VCI deferred credential endpoint. Issued " + issued.length + " " +
            vciFormatOf(deferredConfigId) + " credential(s).");
});

// The Notification Endpoint (OID4VCI section 11): the wallet reports what it did
// with a credential this issuer issued.
//
// It used to answer 204 to anything at all, which made it useless — a wallet
// could not tell a notification that was understood from one that was ignored,
// and the suite could not tell whether it had sent a valid one. Now the id has
// to be one this issuer handed out and the event one of the three the spec
// defines.
const NOTIFICATION_EVENTS = ['credential_accepted', 'credential_failure', 'credential_deleted'];

app.post('/oid4vci/notification', function (req, res) {
  log.debug("Entering the OID4VCI notification endpoint.");
  if (!dpop.presentedAccessToken(req, res, 'the notification endpoint')) return;

  let body = {};
  try {
    body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
  } catch (e) {
    log.error('the notification body is not JSON: ' + e.message);
    log.debug("Leaving the OID4VCI notification endpoint. Unreadable body.");
    return vciError(res, 400, 'invalid_notification_request',
      'The request body is not JSON: ' + e.message);
  }

  const id = String(body.notification_id || '');
  const event = String(body.event || '');
  const record = notificationIds.get(id);
  if (!record || record.expires < Date.now()) {
    notificationIds.delete(id);
    log.debug("Leaving the OID4VCI notification endpoint. No such notification_id.");
    return vciError(res, 400, 'invalid_notification_id',
      'That notification_id was not issued by this Credential Issuer, or it has expired.');
  }
  if (NOTIFICATION_EVENTS.indexOf(event) === -1) {
    log.debug("Leaving the OID4VCI notification endpoint. Unknown event: " + event);
    return vciError(res, 400, 'invalid_notification_request',
      'event must be one of ' + NOTIFICATION_EVENTS.join(', ') + '; got "' + event + '".');
  }

  record.event = event;
  record.description = body.event_description || '';
  record.notifiedAt = new Date().toISOString();
  logArtifact('OID4VCI Notification', 'as received', {
    notification_id: id, event: event, event_description: record.description
  });
  // Section 11.2: 204, no body.
  res.status(204).end();
  log.debug("Leaving the OID4VCI notification endpoint. Recorded " + event + " for " + id + ".");
});

// Non-spec, like GET /oid4vci/notification/:id and GET /oid4vp/result/:state:
// how the last Credential Request actually arrived on the wire.
//
// A wallet cannot prove its own encryption. Everything observable in the page —
// the media type it displays, the ciphertext in its pane, even a credential
// coming back — is equally consistent with a wallet that built a JWE and then
// posted the plaintext, because with encryption_required false the issuer
// accepts that JSON and issues from it. This is the only place the truth lives.
app.get('/oid4vci/last_request', function (req, res) {
  log.debug("Entering the (non-spec) last credential request endpoint.");
  res.set('Cache-Control', 'no-store');
  res.status(200).type('application/json').send(JSON.stringify(lastCredentialRequest, null, 2));
  log.debug("Leaving the (non-spec) last credential request endpoint. encrypted=" +
            lastCredentialRequest.encrypted);
});

// What this issuer was told about a credential. Not part of OID4VCI — it exists
// so a test can check that a notification actually arrived and was understood,
// rather than trusting a 204.
app.get('/oid4vci/notification/:id', function (req, res) {
  log.debug("Entering the notification inspection endpoint. id=" + req.params.id);
  const record = notificationIds.get(String(req.params.id));
  if (!record) {
    log.debug("Leaving the notification inspection endpoint. Unknown id.");
    return vciError(res, 404, 'invalid_notification_id', 'No such notification_id.');
  }
  res.status(200).type('application/json').send(JSON.stringify({
    notification_id: req.params.id,
    event: record.event,
    event_description: record.description || '',
    notified_at: record.notifiedAt || null
  }));
  log.debug("Leaving the notification inspection endpoint.");
});

module.exports = {
  vciMetadata: vciMetadata,
  buildCredentialFor: buildCredentialFor,
  subjectClaimsFrom: subjectClaimsFrom,
  vciNonces: vciNonces,
  VCI_NONCE_TTL_MS: VCI_NONCE_TTL_MS
};
