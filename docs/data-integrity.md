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

## Selective disclosure (`ecdsa-sd-2023`, `bbs-2023`)

`client/src/di_selective.js` holds VC Data Integrity 1.1's
selective-disclosure functions, which both selective cryptosuites are
specified over: RDFC-1.0, blank-node relabelling, skolemization, JSON-pointer
selection, `canonicalizeAndGroup` and the proof hash. They moved there from
`bbs2023.js` in #476, unchanged.

`client/src/ecdsa_sd_2023.js` is `ecdsa-sd-2023` (vc-di-ecdsa sections
3.4–3.6) and registers with `data_integrity.js`.

- **How it signs:** the issuer signs each non-mandatory statement with a
  one-time P-256 key. Its own key signs `proofHash`, the one-time key and
  `mandatoryHash`.
- **What the holder sends:** a holder discloses a statement by handing over
  its signature. Two presentations of one credential can therefore be
  linked, and nothing inside the derived proof names the request; only the
  holder's VP binds it to one.
- **P-256 only:** the issuer key must be P-256, because section 3.5.8
  requires a 64-byte base signature. That section also gives the public
  key's length as 36 bytes, which every implementation reads as the 35 a
  P-256 Multikey is.
- **In the wallet:** it uses the same JSON-pointer rows as `bbs-2023`
  (`ldpEcdsaSd()` in `vc_presentation_2.js`).

`tests/ecdsa_sd_2023_engine.js` checks it against the W3C test vectors. For
both examples, the derived `proofValue` matches byte for byte. It is also
checked in every direction against Digital Bazaar's released
`ecdsa-sd-2023-cryptosuite`.

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

`BbsBlsSignature2020` and the `BbsBlsSignatureProof2020` a holder derives
from it are in `client/src/bbs_bls_2020.js` (the JSON-LD suite) over
`client/src/bbs_plus_2020.js` (the 2020 BBS+ scheme). Both are pure JS and
register themselves with `data_integrity.js` when `data_integrity_rdfc.js`
loads. They follow MATTR's released implementation, which defines the
suite in practice:

- **The signature scheme** is the Rust `bbs` crate 0.4.1, which is **not**
  the IETF BBS that `bbs-2023` uses.
- **Its generators** come from an older draft of hash-to-curve whose `sgn0`
  is not RFC 9380's. RFC 9380's map gets the generator right only about half
  the time, so `bbs_plus_2020.js` keeps RFC 9380's SWU and isogeny but uses
  the draft's sign rule.
- **The messages** are the canonical statements of the proof options and of
  the document.
- **A presentation** is derived by framing the credential to the chosen
  claims. The wallet uses the request's nonce as the derived proof's nonce.

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
| `tests/bbs_bls_2020_engine.js` | The scheme (1, 3, 9 and 17 messages) and the suite, in both directions against MATTR's released `bbs-signatures` and `jsonld-signatures-bbs` 1.2.0. |
| `tests/data_integrity_iyasts.js` | Both directions against iya-sts's own `vc_data_integrity.js`, loaded from its image, plus the wallet's holder VP through iya-sts's Verifier. |
