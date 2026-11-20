# W3C VC-JOSE-COSE (`vc+jwt`, `vc+sd-jwt`, `vc+cose`)

The W3C Recommendation *Securing Verifiable Credentials using JOSE and COSE*
secures a Verifiable Credentials Data Model 2.0 credential by **enveloping**
it: the credential is itself the JWS, SD-JWT or COSE_Sign1 payload, with no
`vc` claim around it. (A Data Integrity proof embeds instead; see
[format-ldp-vc.md](format-ldp-vc.md).)

**OpenID4VCI 1.0 and OpenID4VP 1.0 define no format identifier for any of
the three.** The debugger uses the media types' own names, `vc+jwt`,
`vc+sd-jwt` and `vc+cose`, and a Verifier or issuer that names them otherwise
will not match.

## Not the formats they look like

| Here | Not | How the debugger tells them apart |
|---|---|---|
| `vc+jwt` (section 3.1) | `jwt_vc_json` | `jwt_vc_json` is Data Model 1.1 inside a `vc` claim. A `vc+jwt` payload is the credential, and a `vc` or `vp` claim in it is refused |
| `vc+sd-jwt` (section 3.2) | `dc+sd-jwt` | both are SD-JWTs. The W3C one has the v2 `@context` first and no `vct`, and the wallet checks for it before the `~` that would make it a `dc+sd-jwt` |
| `vc+cose` (section 3.3) | `mso_mdoc` | both are COSE_Sign1. A `vc+cose` payload is the credential's JSON; an mdoc's is a Mobile Security Object |

## What the debugger allows (`client/src/vc_formats.js`)

| | `vc+jwt` | `vc+sd-jwt` | `vc+cose` |
|---|---|---|---|
| Signing algorithms | JOSE list, **default ES256** | JOSE list, **default ES256** | COSE numbers -7, -35, -36, -8, -9, -51, -19, **default -7** |
| Binding methods | `jwk`, `did:jwk`, `did:key` (default `jwk`) | `jwk` | `jwk`, `did:jwk`, `did:key` (default `jwk`) |
| Key proof type | `jwt` | `jwt` | `jwt` |
| Holder binding | the credential enveloped in a `vp+jwt` the holder signs | a Key Binding JWT | as `vc+jwt` |
| Selective | no | yes | no |

Rules the specification fixes, and the debugger enforces:

* `@context`, `type` and `issuer` are never selectively disclosable in a
  `vc+sd-jwt` (section 3.2.1); a credential that made them so is refused.
* `typ` is a SHOULD, so a missing or different `typ`, or a wrong `cty`, is a
  warning, not a failure.
* The issuer's key comes from `kid` when there is one (a DID URL is resolved;
  an absolute URL is fetched as a controlled identifier document), otherwise
  from `iss`, otherwise from the credential's `issuer`.
* The holder is `cnf.jwk` when present, otherwise the DID that
  `credentialSubject.id` names.

## Where it appears

**Getting one.** The wallet recognises all three in a Credential Response,
so an OpenID4VCI issuer that returns one under a configuration it names this
way can issue it through the ordinary issuance flow. No issuer in the suite's
own stack does; the suite's browser test (`tests/vc_jose_cose_presentation.js`)
makes them with the `jose`, `@sd-jwt/core` and `@auth0/cose` libraries and puts
them in the wallet's storage. There is no paste-a-credential field.

### Issuance step 3

| Check | What passes |
|---|---|
| Format | names the format and says the credential is the payload, with no `vc` claim. For `vc+sd-jwt` it counts the Disclosures |
| Holder binding | `cnf.jwk`, or a `did:jwk` / `did:key` subject, names a key; the detail says whether it is the one generated on step 2 |
| Issuer signature | verifies with the key found as above; warnings (such as `typ`) are appended |

### Presentation: as a wallet

| Credential | What goes |
|---|---|
| `vc+jwt`, `vc+cose` | the whole credential as an `EnvelopedVerifiableCredential` (`data:application/vc+jwt,<jws>` or `data:application/vc+cose;base64,<bytes>`) inside a `VerifiablePresentation` the holder signs as a `vp+jwt`, with the request's `nonce` and the Client Identifier as `aud`. The holder's `alg` is picked from the Verifier's list |
| `vc+sd-jwt` | the selected Disclosures and a Key Binding JWT, as for `dc+sd-jwt` |

Step 3 re-checks: *Holder's vp+jwt*, *Nonce and audience* and *Enveloped
credential* for the first two; *Issuer's vc+sd-jwt* and *Key Binding JWT*
(nonce, audience and `sd_hash`) for the third.

### The Verifier page

`vc-verifier.html` does **not** request or verify these formats; its format
menu is `dc+sd-jwt`, `jwt_vc_json`, `mso_mdoc` and `ldp_vc`. Present them to a
Verifier that asks for them by these names.

## Related

* [VC-JOSE-COSE developer notes](../vc-jose-cose.md)
