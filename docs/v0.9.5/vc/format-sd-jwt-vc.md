# SD-JWT VC (`dc+sd-jwt`)

The format most of the VC workflows were built around, and the one an
OpenID4VCI Credential Issuer is most likely to offer. For the tutorials that
issue and present one end to end, see the tutorials in [index.md](index.md#tutorials).

## What the specifications say

* **SD-JWT** ([RFC 9901](https://www.rfc-editor.org/rfc/rfc9901)) is a JWT
  whose claims can be withheld. Each selectively disclosable claim is replaced
  in the signed payload by a digest in an `_sd` array. The claim itself travels
  beside the JWT as a **Disclosure** (a base64url JSON array of salt, name and
  value). The serialization is `<issuer-signed JWT>~<Disclosure>~...~`, and a
  holder presents by dropping the Disclosures it does not want to show.
* **Key binding** (RFC 9901 section 4.3): the issuer puts the holder's public
  key in `cnf.jwk`. When presenting, the holder appends a **Key Binding JWT**
  (`typ: kb+jwt`) signed by that key, carrying the Verifier's `nonce`, its
  `aud`, an `iat`, and `sd_hash`: the digest of everything before it, trailing
  `~` included.
* **SD-JWT VC** (draft-ietf-oauth-sd-jwt-vc, **a draft**; the Verifier's checks
  cite revision -27) makes that a credential: header `typ: dc+sd-jwt` (it was
  `vc+sd-jwt` in earlier revisions), a `vct` claim naming the credential type,
  and an issuer whose keys are found from `iss`, through its JWT VC Issuer
  Metadata at `/.well-known/jwt-vc-issuer`, or through an `x5c` chain in the
  header.
* **OpenID4VCI 1.0 Appendix A.3** and **OpenID4VP 1.0 Appendix B.3** give the
  format identifier `dc+sd-jwt`, the `vct` in the credential configuration, and
  the DCQL `meta.vct_values`.

## What the debugger allows (`client/src/vc_formats.js`)

| | |
|---|---|
| Format identifier | `dc+sd-jwt` |
| Credential signing algorithms | any JOSE `alg` in the table: ES256, ES384, ES512, EdDSA, Ed25519, ES256K, PS256/384/512, RS256/384/512, ML-DSA-44/65/87. **Default before an issuer says otherwise: `ES256`** |
| Binding method | `jwk` only (the key goes in `cnf.jwk`). Default `jwk` |
| Key proof types | `jwt` and `attestation` are listed. The wallet's Credential Request sends `proofs.jwt` |
| Holder binding when presenting | a Key Binding JWT |
| Selective | yes, claim by claim |
| Type member | `vct` |

Issuance step 1 shows those defaults in the Configuration Parameters pane
until the issuer's metadata replaces them. The holder key the wallet generates
on step 2 is the first of ES256, EdDSA, Ed25519, ES384, ES256K, ES512, PS256,
RS256 that the issuer lists in `proof_signing_alg_values_supported` (ES256 when
it lists none).

## Where it appears

**Getting one.** Through the issuance workflow only: the Credential Issuer must
offer a credential configuration with `"format": "dc+sd-jwt"`. Any compliant
issuer works; the suite's peers include walt.id and iya-sts.

### Issuance step 3: the credential as issued

`vc-issuance-3.html` parses the credential and lists every Disclosure with its
digest. Its checks, by the names the page shows:

| Check | What passes |
|---|---|
| Media type (typ) | `typ` is `dc+sd-jwt`, `vc+sd-jwt`, or either with `application/` in front |
| Signing algorithm | an `alg` is present and is not `none` |
| Credential type (vct) | a `vct` claim is present |
| Key binding (cnf) | `cnf.jwk` is present. The detail says whether it is the holder key generated on step 2 |
| Hash algorithm (_sd_alg) | absent (so sha-256) or `sha-256`. Another value is a warning |
| Validity window | `exp` is in the future and `nbf` in the past, when present |
| Key Binding JWT | always passes. A credential as issued has none; that is shown as a note, because a KB-JWT is added when presenting |
| Disclosure digests | every Disclosure's digest is in an `_sd` array |
| Issuer signature | the issuer JWT verifies against the issuer's keys |

The issuer's keys are found from `iss`: a DID is resolved (did:jwk, did:key,
did:web; a DID-signed SD-JWT VC is an extension, which the code says), and an
`https` identifier is read through `/.well-known/jwt-vc-issuer` (both the
"well-known in front of the path" and "after" forms are tried). The Credential
Issuer metadata from step 1 is the fallback. The detail names where the keys
came from.

### Issuance step 4: refresh

The refreshed credential is compared field by field with the one held (`vct`,
`iss`, `sub`, the dates, the bound key, the status-list entry), because the
issuer may re-sign only or change claims too. See
[issuance](reference-issuance.md).

### Presentation steps 1 to 3: as a wallet

* **Step 1** reads the DCQL query and shows, per credential query, the
  `vct_values` wanted against the held `vct`, whether holder binding is
  required (DCQL's default is required), and each claim path, marked when the
  held credential does not contain it.
* **Step 2** has a checkbox per Disclosure, preset to exactly what was asked
  for. Present builds the SD-JWT with the chosen Disclosures and the KB-JWT:
  `nonce` is the request's, `aud` is the Verifier's Client Identifier, and
  `sd_hash` covers the bytes being sent. The KB-JWT is signed by the key named
  in `cnf.jwk`. The wallet looks for it in storage, then in the paste field.
  A pasted key that does not match `cnf.jwk` is reported as such. The
  `vp_token` is a JSON object keyed by the DCQL credential query id, each value
  an array.
* **Step 3** re-checks the bytes that went: *Key Binding JWT present*, *KB-JWT
  nonce*, *KB-JWT audience*, *KB-JWT sd_hash*, *Disclosure digests*. It also
  compares what the query asked for with what was disclosed, by name, in both
  directions.

### The Verifier page: as a Verifier

`vc-verifier.html` can ask for `dc+sd-jwt`. A query needs a vct
(`meta.vct_values` is required by OpenID4VP Appendix B.3.5, and an empty one is
refused rather than sent). The page's `vp_formats_supported` for this format
is `sd-jwt_alg_values` and `kb-jwt_alg_values` of ES256, ES384 and Ed25519.
Each answer is checked row by row:

| Row | Check |
|---|---|
| `format` | the presentation is an SD-JWT |
| `issuer.typ` | `typ` is `dc+sd-jwt`. The legacy `vc+sd-jwt` FAILS, with a note that the name changed |
| `issuer.signature` | the issuer's signature verifies: an `x5c` in the header, else the DID that `iss` is, else the JWT VC Issuer Metadata of an `https` `iss`. A DID in `kid` is never used to choose the issuer |
| `issuer.trust` | an `x5c` chain is linked and in date, and anchored by a configured trust anchor. With no anchor this is an essential SKIP and the verdict is *incomplete* |
| `issuer.self-signed`, `issuer.anchor-included`, `issuer.iss` | reported, never failed: a self-signed signer, an anchor inside `x5c`, and whether `iss` is bound to the certificate |
| `vct` | the vct is one the query asks for, directly, through `aka_vcts`, or by `extends` in Type Metadata fetched from an `https` vct |
| `disclosures` | every Disclosure's digest is in an `_sd` array |
| `validity` | the credential is within its validity window |
| `claims` | every requested claim is disclosed |
| `status` | the Token Status List entry, see [status-lists.md](status-lists.md) |
| `kb.present` | a KB-JWT is present when the query requires binding |
| `kb.header` | its `typ` is `kb+jwt` and it is signed |
| `kb.signature` | it verifies with the credential's `cnf` key |
| `kb.nonce`, `kb.aud`, `kb.iat` | the request's nonce, this Verifier's Client Identifier, and fresh |
| `kb.sd_hash` | `sd_hash` covers exactly what was presented |

Under HAIP 1.0 extra rows apply (the issuer's certificate must be in `x5c`,
among others). See [vc-verifier.md](../vc-verifier.md#what-is-checked) for
every rule.

## Related

* [SD-JWT VC issuance, developer notes](../sd-jwt-vc-issuance.md)
* [Presentation, developer notes](../sd-jwt-vc-presentation.md)
* [W3C `vc+sd-jwt`](format-vc-jose-cose.md): also an SD-JWT, told apart by its
  v2 `@context` and the absence of `vct`
* [Status lists](status-lists.md)
