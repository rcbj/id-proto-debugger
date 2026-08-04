'use strict';
//
// File: vc_configs.js
//
// ---------------------------------------------------------------------------
// Every credential this issuer offers, by credential_configuration_id.
//
// One module, because "is this a configuration I offer" is asked from five places
// — the credential endpoint, authorization_details, the offer builder, the DID
// decision and the metadata — and a list that disagrees with itself between them
// is an issuer that advertises what it will then refuse.
//
// It is also the bottom of the dependency graph: it names the credentials without
// knowing how any of them is built, which is what lets both the OID4VCI module
// and the authorization server read it without requiring each other.
// ---------------------------------------------------------------------------

const { log } = require('./helpers');
const VCI_AS = process.env.OID4VCI_AUTHORIZATION_SERVER || '';

const VCI_CONFIG_ID = 'IdentityCredential';

// The most proofs this issuer will take in one Credential Request, and so the
// most credentials it will return (OID4VCI section 14.6).
const VCI_BATCH_SIZE = Number(process.env.OID4VCI_BATCH_SIZE || 4);

const VCI_VCT = 'urn:idptools:sd-jwt-vc:identity';

const VCI_SCOPE = 'identity_credential';

// ---------------------------------------------------------------------------
// A second credential format: jwt_vc_json (OID4VCI Appendix A.1.1).
//
// The same End-User facts, issued as a W3C Verifiable Credential secured as a
// JWT instead of as an SD-JWT VC. It is here because the two formats differ in
// the one way this workflow is about: jwt_vc_json has NO selective disclosure.
// The whole credentialSubject is in the JWT, so a holder presenting it hands
// over everything in it — there are no Disclosures to choose between, and the
// holder binding that an SD-JWT does with a Key Binding JWT is done instead by
// signing a Verifiable Presentation JWT around the credential.
//
// Everything else is deliberately identical: the same proof of possession, the
// same batch and deferred paths, the same response encryption, the same
// notification ids. Only the artefact at the end is a different shape.
// ---------------------------------------------------------------------------
const VCI_JWT_CONFIG_ID = 'IdentityCredentialJwtVcJson';

const VCI_JWT_SCOPE = 'identity_credential_jwt';

const VCI_JWT_TYPES = ['VerifiableCredential', 'IdentityCredential'];

const VCI_LDP_CONFIG_ID = 'IdentityCredentialLdpVc';

const VCI_LDP_SCOPE = 'identity_credential_ldp';

const VC_CONTEXT = 'https://www.w3.org/2018/credentials/v1';

// Every credential this issuer offers, by credential_configuration_id. One
// place, because "is this a configuration I offer" is asked from four of them
// (the credential endpoint, authorization_details, the offer builder and the
// metadata) and a list that disagrees with itself between those is an issuer
// that advertises what it will then refuse.
const VCI_CONFIGS = {};
VCI_CONFIGS[VCI_CONFIG_ID] = { format: 'dc+sd-jwt', scope: VCI_SCOPE };
VCI_CONFIGS[VCI_JWT_CONFIG_ID] = { format: 'jwt_vc_json', scope: VCI_JWT_SCOPE };
// The third format: a W3C credential secured by an EMBEDDED Data Integrity
// proof (bbs-2023) rather than by a JWS. This is the only one of the three that
// can carry BBS at all — the other two are JOSE-secured and BBS is not a JOSE
// alg — and it is the only one offering unlinkable selective disclosure: the
// holder derives a fresh proof per presentation instead of replaying the
// issuer's signature.
VCI_CONFIGS[VCI_LDP_CONFIG_ID] = { format: 'ldp_vc', scope: VCI_LDP_SCOPE };

// ---------------------------------------------------------------------------
// Two more configurations, identical to their siblings above except that the
// issuer names ITSELF by a did:web instead of by its https identifier. See the
// DID section further down for what that DID is and what serves its document.
//
// Two configurations rather than one server-wide switch, and the reason is
// coverage: with a switch, a run exercises the DID route or the URL route but
// never both, and for dc+sd-jwt the URL route is the one the specification
// actually defines (/.well-known/jwt-vc-issuer). Offering both side by side lets
// one run cover both, lets a wallet SEE the difference in the metadata rather
// than being told out of band, and makes "which mechanism am I looking at" a
// choice the person driving the debugger makes deliberately.
//
// `issuerDid: true` is the whole of the difference. Everything else about these
// configurations — claims, proof types, batch, deferral, encryption — is
// inherited from the sibling, so there is no second definition to drift.
// ---------------------------------------------------------------------------
const VCI_DID_CONFIG_ID = 'IdentityCredentialDid';

const VCI_DID_SCOPE = 'identity_credential_did';

const VCI_LDP_DID_CONFIG_ID = 'IdentityCredentialLdpVcDid';

const VCI_LDP_DID_SCOPE = 'identity_credential_ldp_did';
VCI_CONFIGS[VCI_DID_CONFIG_ID] =
  { format: 'dc+sd-jwt', scope: VCI_DID_SCOPE, issuerDid: true, basedOn: VCI_CONFIG_ID };
VCI_CONFIGS[VCI_LDP_DID_CONFIG_ID] =
  { format: 'ldp_vc', scope: VCI_LDP_DID_SCOPE, issuerDid: true, basedOn: VCI_LDP_CONFIG_ID };

function vciConfigIds() { return Object.keys(VCI_CONFIGS); }

function vciFormatOf(configId) {
  const c = VCI_CONFIGS[configId];
  return c ? c.format : '';
}

// Whether credentials from this configuration name the issuer by DID. Asked by
// the credential builders and by the metadata, which must advertise the same
// answer the credential will carry — an issuer whose metadata and credentials
// disagree about who issued them is the bug this keeps in one place.
function vciUsesIssuerDid(configId) {
  const c = VCI_CONFIGS[configId];
  return !!(c && c.issuerDid);
}

// A credential_identifier is minted as "<configId>:<hash>", so the
// configuration it belongs to is the part before the colon. Used to route a
// section 8.2 identifier request to the right format.
function configIdOfIdentifier(identifier) {
  const prefix = String(identifier || '').split(':')[0];
  return VCI_CONFIGS[prefix] ? prefix : '';
}

module.exports = {
  VCI_AS: VCI_AS,
  VCI_CONFIG_ID: VCI_CONFIG_ID,
  VCI_BATCH_SIZE: VCI_BATCH_SIZE,
  VCI_VCT: VCI_VCT,
  VCI_SCOPE: VCI_SCOPE,
  VCI_JWT_CONFIG_ID: VCI_JWT_CONFIG_ID,
  VCI_JWT_SCOPE: VCI_JWT_SCOPE,
  VCI_JWT_TYPES: VCI_JWT_TYPES,
  VCI_LDP_CONFIG_ID: VCI_LDP_CONFIG_ID,
  VCI_LDP_SCOPE: VCI_LDP_SCOPE,
  VCI_DID_CONFIG_ID: VCI_DID_CONFIG_ID,
  VCI_DID_SCOPE: VCI_DID_SCOPE,
  VCI_LDP_DID_CONFIG_ID: VCI_LDP_DID_CONFIG_ID,
  VCI_LDP_DID_SCOPE: VCI_LDP_DID_SCOPE,
  VC_CONTEXT: VC_CONTEXT,
  VCI_CONFIGS: VCI_CONFIGS,
  vciConfigIds: vciConfigIds,
  vciFormatOf: vciFormatOf,
  vciUsesIssuerDid: vciUsesIssuerDid,
  configIdOfIdentifier: configIdOfIdentifier
};
