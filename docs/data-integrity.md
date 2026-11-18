# Data Integrity and Linked Data proofs (`ldp_vc`)

Issue #475 (phase 1 of #474). This note covers how an `ldp_vc` credential is
secured, verified and presented in the VC workflows, apart from the
selective-disclosure suites. `bbs-2023` lives in `bbs2023.js`, and
`ecdsa-sd-2023` is #476.

## Modules

| Module | What it is |
|---|---|
| `client/src/data_integrity.js` | Creates and verifies a proof in every suite below. It has no DOM, uses `common/crypto/crypto_provider.js` for the cryptography, and takes the caller's `resolveKey`. |
| `client/src/data_integrity_rdfc.js` | Registers RDFC-1.0 (`jsonld`) with the module above and returns it. |
| `client/src/jsonld_contexts.js` | The shipped JSON-LD contexts and the offline document loader. It was the top of `bbs2023.js` until #475. |
| `client/src/vc_formats.js` | What each credential format allows. Every page reads its defaults and menus from it. |

## Suites

| Proof | Canonicalization | Keys | Written as |
|---|---|---|---|
| `eddsa-rdfc-2022` | RDFC-1.0 | Ed25519 | `proofValue`, base58btc |
| `eddsa-jcs-2022` | JCS | Ed25519 | `proofValue` |
| `ecdsa-rdfc-2019` | RDFC-1.0 | P-256 (SHA-256), P-384 (SHA-384) | `proofValue` |
| `ecdsa-jcs-2019` | JCS | P-256, P-384 | `proofValue` |
| `Ed25519Signature2020` | RDFC-1.0 | Ed25519 | `proofValue` |
| `Ed25519Signature2018` | RDFC-1.0 | Ed25519 | detached JWS, `EdDSA` |
| `JsonWebSignature2020` | RDFC-1.0 | Ed25519, secp256k1, P-256/384/521, RSA | detached JWS, `alg` from the key (RSA: RS*/PS*) |
| `EcdsaSecp256k1Signature2019` | RDFC-1.0 | secp256k1 | detached JWS, `ES256K` |

`BbsBlsSignature2020` is recognised but not yet verified; it is still open
under #475.

## The @context rules

These rules differ by suite, and each one has broken at least one
implementation.

- **RDFC `DataIntegrityProof`.** The proof options are canonicalized under
  the document's `@context`. If a proof carries an `@context` of its own, it
  must equal the document's.
- **JCS suites.** The signer puts the document's `@context` into the proof,
  and the proof is sent with it. The verifier hashes the options exactly as
  received and checks that the document's `@context` *begins with* the
  proof's. Until #475 the wallet's `ecdsa-jcs-2019` holder proof hashed the
  `@context` but left it out of the proof it sent. Digital Bazaar's verifier
  rejects such a proof.
- **Legacy types.** These follow jsonld-signatures: the proof's own
  `@context` is used, otherwise the document's, otherwise
  `https://w3id.org/security/v2`.

**Spec only.** A proof that verifies only under a reading the specification
does not allow is **invalid**. Two readings are recognised: a JCS proof that
dropped its `@context`, and options canonicalized under `security/v2` by a
pre-2020 signer. For either one, `diagnosis` names the defect.

## Presenting

The holder's choice depends on whether the credential's suite is selective.

- **A selective suite** (`bbs-2023`): the holder derives a presentation.
- **Any other suite**: the credential goes whole, inside a
  `VerifiablePresentation` the holder signs (`vc_presentation_2.js`,
  `ldpWhole()`).

The holder proof's suite comes from `vc_formats.holderSuiteFor()`. It is the
first suite the holder key signs that the Verifier's
`vp_formats_supported.ldp_vc` accepts, with the JCS suites first:

- a P-256 key signs `ecdsa-jcs-2019`;
- an Ed25519 key signs `eddsa-jcs-2022`.

Issuance step 3 and presentation step 3 verify both proofs with
`data_integrity.js`.

## Tests

| Test | What it checks |
|---|---|
| `tests/data_integrity_engine.js` | Both directions against released Digital Bazaar and Blockcerts implementations, and JsonWebSignature2020 against `jose` (and node's crypto for ES256K) over `jsonld`'s RDFC-1.0. Includes two byte-for-byte vectors: Digital Bazaar's `eddsa-rdfc-2022` README example and Blockcerts' `EcdsaSecp256k1Signature2019` test. |
| `tests/data_integrity_iyasts.js` | Both directions against iya-sts's own `vc_data_integrity.js`, loaded from its image, plus the wallet's holder VP through iya-sts's Verifier. |
