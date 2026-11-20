# W3C VC as a JWT (`jwt_vc_json`)

A W3C Verifiable Credential (Data Model 1.1 shape) secured as a JWT, with the
credential inside the JWT's `vc` claim. OpenID4VCI 1.0 Appendix A.1.1 and
OpenID4VP 1.0 Appendix B.1 define the format identifier. It has **no selective
disclosure**: everything in the credential goes to every Verifier.

Not to be confused with the W3C VC-JOSE-COSE `vc+jwt`, where the JWT payload
*is* a Data Model 2.0 credential and a `vc` claim is refused. See
[format-vc-jose-cose.md](format-vc-jose-cose.md).

`jwt_vc_json-ld` (Appendix A.1.2) has a row of its own in `vc_formats.js` with
the same rules, but the pages parse, present and verify `jwt_vc_json`.

## What the debugger allows (`client/src/vc_formats.js`)

| | |
|---|---|
| Format identifier | `jwt_vc_json` |
| Credential signing algorithms | the JOSE list (ES256 … ML-DSA-87). **Default `ES256`** |
| Binding methods | `jwk`, `did:jwk`, `did:key`. **Default `jwk`** |
| Key proof types | `jwt`, `attestation` listed; the wallet sends `proofs.jwt` |
| Holder binding when presenting | a Verifiable Presentation JWT signed by the holder |
| Selective | no |
| Type member | `credential_definition.type` |

On issuance step 1, `credential_definition` is REQUIRED for this format: its
`type` array identifies the credential in place of a `vct`.

## Where it appears

**Getting one.** Through the issuance workflow, from a Credential Issuer that
offers a configuration with `"format": "jwt_vc_json"`. The suite runs it
against iya-sts and walt.id; any compliant issuer works.

### Issuance step 3

There is no `jwt_vc_json`-specific check list on step 3. The credential is
shown through the SD-JWT VC list, so read its *Issuer signature* (keys from
`iss`, as for SD-JWT VC), *Signing algorithm* and *Validity window* rows; the
*Media type* and *vct* rows state SD-JWT VC rules this format does not have.
The format's own checks are made on presentation step 3 and on the Verifier
page.

### Presentation: as a wallet

* **Step 0** says the held credential is `jwt_vc_json` and that nothing in it
  can be withheld.
* **Step 1** lists the claims the query names against the credential's
  `credentialSubject`.
* **Step 2** sends the whole credential inside the `vp` claim of a
  Verifiable Presentation JWT signed by the holder key, with the request's
  `nonce` and the Verifier's Client Identifier as `aud`. There is no KB-JWT.
* **Step 3** re-checks: *Verifiable Presentation JWT* (a credential is
  embedded), *Presentation nonce*, *Presentation audience*, and *Selective
  disclosure*, which reports how many claims went whether or not they were
  asked for.

### The Verifier page

`vc-verifier.html` can ask for `jwt_vc_json`. A query needs `type_values`
(Appendix B.1.1). `vp_formats_supported` lists `alg_values` ES256, ES384,
EdDSA and Ed25519. Rows per answer:

| Row | Check |
|---|---|
| `vp.signature` | the VP JWT verifies with the holder's key |
| `vp.binding` | the VP is signed by the key the credential is bound to |
| `vp.nonce`, `vp.aud` | the request's nonce, this Verifier's Client Identifier |
| `vp.iat`, `vp.validity` | fresh, and within its `exp` and `nbf` |
| `vc.signature` | each embedded credential's issuer signature, found from `iss` (an `https` issuer's own metadata, or the DID `iss` is; a DID in `kid` does not choose the issuer) |
| `vc.validity` | each credential is within its validity window |
| `vc.status` | the W3C Bitstring Status List entry, see [status-lists.md](status-lists.md) |
| `types` | the credential's `type` matches the query's `type_values` |

With more than one embedded credential the rows are `vc[0].`, `vc[1].` and so
on. Under HAIP 1.0 the answer is sent with the HAIP transport, and a `format`
row warns that HAIP profiles only SD-JWT VC and mdoc.

## Related

* [Presentation developer notes](../sd-jwt-vc-presentation.md)
* [Verifier developer notes](../vc-verifier.md#what-is-checked)
