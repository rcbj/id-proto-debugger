# W3C VC with a Data Integrity proof (`ldp_vc`)

A W3C Verifiable Credential that is a JSON-LD document with the proof
**embedded** in it (`proof`), as opposed to enveloped in a JWT or COSE
structure. OpenID4VCI 1.0 Appendix A.1.3 and OpenID4VP 1.0 Appendix B.1.3
define the format identifier. What secures it is either a **Data Integrity**
`DataIntegrityProof` with a named `cryptosuite`, or one of the older **Linked
Data proof** types that predate Data Integrity.

## The proofs the debugger knows (`LDP_SUITES` in `client/src/vc_formats.js`)

| Proof | Kind | Keys | Selective |
|---|---|---|---|
| `eddsa-rdfc-2022` | Data Integrity | Ed25519 | no |
| `eddsa-jcs-2022` | Data Integrity | Ed25519 | no |
| `ecdsa-rdfc-2019` | Data Integrity | P-256, P-384 | no |
| `ecdsa-jcs-2019` | Data Integrity | P-256, P-384 | no |
| `ecdsa-sd-2023` | Data Integrity | P-256 only | yes, the holder derives |
| `bbs-2023` | Data Integrity (W3C Data Integrity BBS Cryptosuites v1.0) | BLS12-381 | yes, the holder derives |
| `Ed25519Signature2020` | Linked Data | Ed25519 | no |
| `Ed25519Signature2018` | Linked Data | Ed25519 | no |
| `JsonWebSignature2020` | Linked Data | Ed25519, secp256k1, P-256/384/521, RSA | no |
| `EcdsaSecp256k1Signature2019` | Linked Data | secp256k1 | no |
| `BbsBlsSignature2020` | Linked Data (MATTR's suite) | BLS12-381 | yes; a holder derives a `BbsBlsSignatureProof2020` |

RDFC suites canonicalize with RDFC-1.0, JCS suites with RFC 8785. Which
`@context` each one hashes differs by suite, and a proof that verifies only
under a reading the specification does not allow is reported **invalid**,
with a `diagnosis` naming the defect. The full rules are in
[data-integrity.md](../data-integrity.md#the-context-rules).

`ecdsa-xi-2023`, the barcode suite, is also implemented, but it means nothing
without a printed document and is used only on the VC Barcodes page
([format-vc-barcodes.md](format-vc-barcodes.md)).

## What the debugger allows

| | |
|---|---|
| Format identifier | `ldp_vc` |
| Credential signing "algorithms" | the cryptosuite or proof type names above. **Default `eddsa-rdfc-2022, ecdsa-rdfc-2019`** |
| Binding methods | `did:jwk`, `did:key`. **Default `did:jwk`**: the holder is named by `credentialSubject.id` |
| Key proof types | `jwt`, `di_vp` and `attestation` are listed; the wallet's Credential Request sends `proofs.jwt` |
| Holder binding when presenting | a Verifiable Presentation carrying the holder's own Data Integrity proof |
| Selective | by cryptosuite |
| Type member | `credential_definition.type` |

The holder's VP proof is chosen by `holderSuiteFor()`: the first suite the
holder key signs that the Verifier accepts (`cryptosuite_values` and
`proof_type_values`, from its `vp_formats_supported` or the DCQL query's
`meta`), JCS first because it needs no context at either end:

| Holder key | Suites tried, in order |
|---|---|
| Ed25519 | `eddsa-jcs-2022`, `eddsa-rdfc-2022`, `Ed25519Signature2020`, `JsonWebSignature2020`, `Ed25519Signature2018` |
| P-256, P-384 | `ecdsa-jcs-2019`, `ecdsa-rdfc-2019`, `JsonWebSignature2020` |
| P-521, RSA | `JsonWebSignature2020` |
| secp256k1 | `EcdsaSecp256k1Signature2019`, `JsonWebSignature2020` |

If none fits, the page says which suites the Verifier accepts and which the key
can sign.

## Where it appears

**Getting one.** Through the issuance workflow, from a Credential Issuer that
offers `"format": "ldp_vc"`. Which proof arrives is the issuer's choice; the
suite's own peers issue `bbs-2023` (iya-sts) and Ed25519 / P-256 suites
(walt.id). Any compliant issuer works.

### Issuance step 3

| Check | What passes |
|---|---|
| Proof | a recognised proof is present; the detail names the suite, `proofPurpose` and `verificationMethod` |
| Holder binding (credentialSubject.id) | the subject is a `did:jwk` or `did:key`; the detail says whether it is the key generated on step 2 |
| Validity window | `validFrom` / `validUntil` (or the 1.1 names) bracket now |
| Issuer proof | the proof verifies against the key its `verificationMethod` names. A `bbs-2023` base proof is reported, not verified, here: it is checked when the holder derives from it |

### Presentation: as a wallet

* **Step 2** has a **JSON-LD Contexts** pane. The wallet never fetches a
  context. It ships the standard W3C ones; an issuer's own vocabulary must be
  added there (the URL exactly as in `@context`, and the document). Added
  contexts are kept in this browser, and adding one reloads the page so the
  credential is canonicalized with it.
* **A non-selective suite**: the credential goes whole, inside a
  `VerifiablePresentation` signed by the holder's DID, with `challenge` set to
  the nonce and `domain` to the Client Identifier (Appendix B.1.3.2). When the
  query does not require holder binding, the credential may go bare.
* **`bbs-2023` and `ecdsa-sd-2023`**: step 2 offers every leaf of the
  credential as a JSON pointer, preselects the ones the DCQL claim paths name,
  and always reveals the issuer's mandatory pointers. Present derives a reveal
  document. For `bbs-2023` the derived proof's presentation header is the
  request's nonce. When binding is required (DCQL's default),
  `/credentialSubject/id` is selected by default and the derived credential
  travels inside a VP with an `ecdsa-jcs-2019` holder proof. A `bbs-2023`
  derived proof proves the issuer signed the values; only the VP proves who
  presents them.
* **`BbsBlsSignature2020`**: the wallet frames the credential to the chosen
  claims and derives a `BbsBlsSignatureProof2020`, with the request's nonce.

Step 3 re-checks what went. For `bbs-2023`: *Derived proof verifies*,
*Presentation header*, *Statements revealed*, *Holder proof*,
*Unlinkability*. For a whole credential: *Challenge and domain*, *Holder is
the subject*, *Holder proof* (or a note that none was asked for), *Proof
nonce* where a derived proof has one, and *Disclosure*.

### The Verifier page

`vc-verifier.html` can ask for `ldp_vc`; a query needs `type_values`. Its
`vp_formats_supported` is `proof_type_values: ["DataIntegrityProof"]` and
`cryptosuite_values` `bbs-2023`, `ecdsa-rdfc-2019`, `ecdsa-jcs-2019`,
`eddsa-rdfc-2022`, `eddsa-jcs-2022`. A derived `ecdsa-sd-2023` proof and the
Linked Data proof types are verified if they arrive, although the request
does not list them. Rows:

| Row | Check |
|---|---|
| `format` | the presentation is an `ldp_vc` |
| `vp.proof` | the VP's holder proof verifies |
| `vp.challenge`, `vp.domain` | the request's nonce, and this Verifier's Client Identifier |
| `vp.binding` | the holder is the credential's subject |
| `vc.proof` | the credential's issuer proof verifies, and is by a verification method the issuer controls (under the issuer's DID, or at or under an `https` issuer) |
| `vc.validity`, `vc.status` | validity, and the Bitstring Status List entry ([status-lists.md](status-lists.md)) |
| `types` | the credential's types match `type_values`, compared as fully expanded IRIs |

A bare `bbs-2023` reveal document is accepted when its presentation header is
the request's nonce. Of `bbs-2023`'s feature options only `baseline` is
implemented; anonymous holder binding and pseudonyms are refused by name.

## Related

* [Data Integrity developer notes](../data-integrity.md)
* [Presentation developer notes, ldp_vc section](../sd-jwt-vc-presentation.md#ldp_vc-and-holder-binding)
* [Verifier developer notes](../vc-verifier.md#what-is-checked)
