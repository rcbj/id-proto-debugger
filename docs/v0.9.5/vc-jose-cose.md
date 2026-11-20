# W3C VC-JOSE-COSE (`vc+jwt`, `vc+sd-jwt`, `vc+cose`)

Issue #477 (phase 3 of #474). This note covers the three ways the W3C
Recommendation *Securing Verifiable Credentials using JOSE and COSE* secures
a VCDM 2.0 credential: by **enveloping** it, so that the credential is the
JWS, SD-JWT or COSE_Sign1 payload itself. A Data Integrity proof is
**embedded** instead; that is `docs/v0.9.5/data-integrity.md`.

## Not the formats they look like

| Here | Not to be confused with | How they are told apart |
|---|---|---|
| `vc+jwt` | `jwt_vc_json` | `jwt_vc_json` is VCDM 1.1 inside a `vc` claim. A `vc+jwt` payload IS the credential, and a `vc` or `vp` claim in it is refused (section 3.1.1). |
| `vc+sd-jwt` | `dc+sd-jwt` (SD-JWT VC) | Both are SD-JWTs. A W3C one has the v2 `@context` first and no `vct`, and `credentialFormat()` asks `vc_jose_cose.detect()` **before** the tilde test that would otherwise call it `dc+sd-jwt`. |
| `vc+cose` | `mso_mdoc` | Both are COSE_Sign1. A `vc+cose` payload is the credential's JSON, and an mdoc's is a Mobile Security Object. |

**OpenID4VCI 1.0 and OpenID4VP 1.0 name no format identifier for any of the
three.** `vc_formats.js` lists them under the media types' own names, and
`vpFormatsSupported()` advertises them that way. A Verifier that asks for
them by another name won't match.

## Modules

| Module | What it is |
|---|---|
| `client/src/vc_jose_cose.js` | The engine, with no DOM. It covers detection, a complete RFC 9901 disclosure processor, COSE_Sign1 and its `Sig_structure`, the `EnvelopedVerifiableCredential` `data:` URL, key discovery by `kid` or `iss`, securing as issuer or holder, SD-JWT presentation with a Key Binding JWT, and verifying. All signing goes through `common/crypto/crypto_provider.js`, in pure JS. |
| `client/src/sd_jwt_vc.js` | `credentialFormat()` and `parseCredential()` recognise the three forms and give them the same parsed shape as every other format (`vcJoseCose.parse()`). |
| `client/src/sd_jwt_vp.js` | `buildPresentationFor()` and `presentedClaims()` handle the new formats. |

## What the specification fixes, and where it is enforced

- **@context, type and issuer are never selectively disclosable** (section
  3.2.1). `secureSdJwt()` refuses to make them so, and `verify()` refuses a
  credential that did.
- **`typ` is a SHOULD.** A missing or different `typ` is a warning, not a
  failure. A wrong `cty` is reported the same way.
- **The issuer key** comes from `kid` when the header has one: a DID URL
  resolves through `did.js`, and an absolute URL is fetched as a controlled
  identifier document. Otherwise it is looked up from `iss`, and failing that
  from the credential's `issuer`.
- **Holder binding** is `cnf.jwk` when present. Otherwise it is the DID that
  `credentialSubject.id` names (`boundHolderJwk()`).

## Presenting

| Credential | What goes to the Verifier |
|---|---|
| `vc+jwt`, `vc+cose` | The whole credential, as an `EnvelopedVerifiableCredential` (`data:application/vc+jwt,<jws>`, or `data:application/vc+cose;base64,<bytes>`) inside a `VerifiablePresentation` the holder secures as a `vp+jwt`. The request's `nonce` and the Client Identifier go in as the JWT's `nonce` and `aud` claims. The holder's `alg` is chosen from the Verifier's list (`sd_jwt_vp.holderJws()`). |
| `vc+sd-jwt` | An SD-JWT, exactly as for `dc+sd-jwt`: the selected Disclosures and a Key Binding JWT. |

Presentation step 3 re-checks what went with `vc_jose_cose.verify()`. For a
`vp+jwt` it checks the holder's signature, the nonce and audience, and then
the enveloped credential. For a `vc+sd-jwt` it checks the issuer's signature
and the Key Binding JWT.

## Tests

| Test | What it checks |
|---|---|
| `tests/vc_jose_cose_engine.js` | Both directions against iya-sts's own `vc_jose_cose.js` (loaded from its image) for P-256, P-384 and Ed25519 (iya-sts signs JOSE EdDSA only with `keys.eddsaSigning` on). Also both directions against `jose`, `@sd-jwt/core` 0.25.0 (including a one-claim presentation) and `@auth0/cose` 1.0.2. Then the specification's rules: a `vc` claim is refused, `issuer` is never disclosable, a `vct` makes it `dc+sd-jwt`, both envelopes round-trip, and a Key Binding JWT is checked against its nonce. |
| `tests/vc_jose_cose_presentation.js` | The presentation pages in Chrome. A `vc+jwt` (`jose`) and a `vc+cose` (`@auth0/cose`) are enveloped in the holder's `vp+jwt`, and a `vc+sd-jwt` (`@sd-jwt/core`) is presented with one Disclosure of two and a Key Binding JWT, each verified by the library that made it. It needs only the client. |
