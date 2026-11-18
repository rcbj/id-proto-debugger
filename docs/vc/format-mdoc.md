# ISO mdoc (`mso_mdoc`)

The ISO/IEC 18013-5 mobile document (a mobile driving licence is the familiar
example), as OpenID4VCI 1.0 Appendix A.2 issues it and OpenID4VP 1.0 Appendix
B.2 presents it. The debugger reads, presents and verifies mdocs. **It does not
mint them, and no issuer in the suite's own stack mints one**, so an mdoc
reaches the wallet only from a Credential Issuer that offers
`"format": "mso_mdoc"`. The suite's own tests use a separate test issuer
(`tests/mdoc_test_issuer.js`) and write its output into the wallet's storage;
there is no field on the pages for pasting a credential in.

ISO/IEC 18013-5 itself is not free to read. Everything below is what the code
does, from what OpenID4VCI and OpenID4VP say about the format and from the
structures the code decodes.

## What the format is

* The issuer signs a **Mobile Security Object** (MSO) inside `issuerAuth`, a
  COSE_Sign1 whose `x5chain` header carries the document signer certificate.
  The MSO holds a digest of every data element, per namespace, the
  `docType`, the validity, and the **device key** the mdoc is bound to.
* Each data element is an `IssuerSignedItem` wrapped in CBOR tag 24. The
  holder discloses by leaving items out. The items that go are sent **byte for
  byte as issued**, because the MSO's digests cover those exact bytes.
* The holder proves possession with a **device signature**: a detached
  COSE_Sign1 by the device key over `DeviceAuthenticationBytes`, which include
  OpenID4VP 1.0's session transcript (Appendix B.2.6.1):
  `["OpenID4VPHandover", SHA-256(cbor([client_id, nonce, jwkThumbprint,
  response_uri]))]`. `jwkThumbprint` is the RFC 7638 thumbprint of the key a
  `direct_post.jwt` answer is encrypted to, and null otherwise.
* A DCQL claim path for an mdoc is `[namespace, element]`, and the query names
  the type with `meta.doctype_value`.

## What the debugger allows (`client/src/vc_formats.js`)

| | |
|---|---|
| Format identifier | `mso_mdoc` |
| Credential signing algorithms | COSE algorithm numbers: -7 (ES256), -35 (ES384), -36 (ES512), -8 (EdDSA), -9 (ESP256), -51 (ESP384), -19 (Ed25519). **Default `-7`** |
| Binding method | `cose_key`. Default `cose_key` |
| Key proof types | `jwt` and `attestation` listed; the wallet sends `proofs.jwt` |
| Holder key | **always P-256 / ES256**, whatever else the issuer accepts, because the wallet's DeviceAuth signature is ES256 only. Step 2 says so when the issuer's `proof_signing_alg_values_supported` has no ES256 |
| Holder binding | the DeviceAuth signature |
| Selective | yes, element by element |
| Type member | `doctype` |

The MSO digest algorithms read are SHA-256, SHA-384 and SHA-512. The COSE
signature algorithms the code verifies are -7, -9, -35, -51, -36, -52, -8 and
-19.

## Where it appears

### Issuance

The issuance pages parse an mdoc Credential Response (base64url
`IssuerSigned`) like any other format, and each element becomes a row keyed
`namespace/element`. The device key is treated as the credential's `cnf.jwk`.
**Issuance step 3 has no mdoc-specific check list**: it shows the credential
through the SD-JWT VC list, whose rows do not describe an mdoc. The mdoc
checks are made when it is presented, below. Nothing in the suite drives mdoc
issuance end to end.

### Presentation steps 1 to 3: as a wallet

* **Step 1** shows the query's `doctype_value` beside the held `docType`, and
  each `[namespace, element]` path, marked when the mdoc does not hold it. The
  element is the last segment of the path; a namespace such as
  `org.iso.18013.5.1` has dots of its own.
* **Step 2** offers one row per element and builds a `DeviceResponse` with the
  chosen items exactly as issued, `issuerAuth` unchanged, and the device
  signature over the transcript. When the answer is `direct_post.jwt`, the
  encryption key is chosen once and used for both the transcript and the JWE.
* **Step 3** re-checks what went:

| Check | What passes |
|---|---|
| Element digests | every element hashes, with the MSO's `digestAlgorithm`, to the digest the MSO holds for it |
| Issuer signature | `issuerAuth` verifies with the document signer certificate in its own `x5chain`. The detail says the certificate is **unanchored** here: this check does not chain it to an IACA or a trust list |
| Device signature | verifies with the MSO's device key over the transcript for this `client_id`, nonce and response URI (and encryption key, if any) |
| Selective disclosure | how many elements went; the rest are present only as digests |

Under HAIP 1.0, `mso_mdoc` is one of the two formats the profile covers, so no
format warning appears.

### The Verifier page: as a Verifier

`vc-verifier.html` can ask for `mso_mdoc`. A query needs a doctype (Appendix
B.2.3 makes `doctype_value` required), and the page offers
`intent_to_retain` (*not said*, *true*, *false*) on mdoc claims only. Its
`vp_formats_supported` lists every COSE algorithm above as both
`issuerauth_alg_values` and `deviceauth_alg_values`. Rows per answer:

| Row | Check |
|---|---|
| `format` | the presentation is an mdoc `DeviceResponse` |
| `mdoc.issuer-signed` | the element digests and `issuerAuth` verify |
| `mdoc.issuer-trust` | the document signer certificate chains to a configured trust anchor (an essential SKIP without one, so the verdict is *incomplete*) |
| `mdoc.trusted-authorities` | when the query carried `trusted_authorities`, whether a certificate's AKI matches |
| `mdoc.device-signature` | the device signature covers this request's transcript |
| `mdoc.doctype` | `docType` is the one the query asks for |
| `validity` | the MSO's validity window |
| `status` | the MSO's `status`: an IETF Token Status List entry, see [status-lists.md](status-lists.md). Another mechanism, such as `identifier_list`, is a SKIP by name |

## Related

* [Presentation developer notes, ISO mdoc section](../sd-jwt-vc-presentation.md#iso-mdoc-mso_mdoc)
* [Verifier developer notes](../vc-verifier.md#what-is-checked)
