# client/ — the Express frontend (port 3000) and everything in the browser

Scope: `client/src/`, `client/public/`, the bundles, the pages and their layout. Cross-cutting matters — versioning and the `{{VERSION}}` stamp, `CONFIG_FILE`, the key-material opt-out rule, how the suite is run — stay in the repo-root `CLAUDE.md`. The tests that drive these pages are in `tests/CLAUDE.md`, the edge landings they hand off to in `infra/CLAUDE.md`, and the mock issuer/verifier they talk to in `docs/mock-sts.md`.

**`/client/`** — Express frontend (port 3000). Serves static HTML/JS pages and handles the OAuth2 redirect callback at `/callback`, forwarding query params to `debugger2.html`.

This file holds what applies across the whole frontend: the shared modules, the landing page, and the build. Each workflow's own hard-won detail is one file away, and **each of these is worth opening before you edit the pages it names** — every one records a defect that looked like something else:

| Read | Before | Because |
|---|---|---|
| `docs/oidc-flows.md` | `debugger.html`, `debugger2.js`, the grant dropdown | five of the six OIDC flows sent `response_type=code` for months; a test that only checks "a token came back" is worthless here |
| `docs/sd-jwt-vc-issuance.md` | any `vc-issuance-*` page or `css/sd_jwt_vc.css` | the layout is measured and mutation-tested (a narrow pane *multiplies* height once populated), and Credential History logs every attempt, not just the kept ones |
| `docs/sd-jwt-vc-presentation.md` | any `vc-presentation-*` page, `sd_jwt_vp.js` | `sd_hash` covers the trailing `~`, the KB-JWT must verify against the credential's own `cnf.jwk`, and `vp_token` is keyed by DCQL query id |
| `docs/dpop.md` | `dpop.js`, `oauth_dpop.js`, `vci_wallet.js`, any protected call | the two workflows share the mechanism and **not** the state; DPoP is off by default on both, and OID4VP has none by design |
| `docs/dids.md` | `did.js`, `did-tools.html`, the DID panes on issuance step 1 | a `did:web` document read off its own origin is a circular check; the element id and the storage key are different strings, and confusing them fails silently |
| `docs/webauthn.md` | any `webauthn*` page, `cbor.js`, `cose.js`, `webauthn.js`, or the browser extension | the RP ID is the calling origin and that refusal *is* the phishing resistance; the decoder is checked against the browser's own `getPublicKey()`; and an ECDSA signature arrives DER-encoded while Web Crypto wants raw `r‖s`, which fails by returning `false` rather than throwing |

## Shared client modules

Several page bundles share modules rather than duplicating behaviour:

| Module | Shared by | What it holds |
|---|---|---|
| `metadata_client.js` | `debugger.js`, `sd_jwt_vc_issuance_*.js` | fetching/tabulating a metadata document, its provenance note, base64url + Web Crypto JWS verification, the `signed_metadata` verdict, and **where an issuer's metadata lives** (`wellKnownCandidates`/`fetchWellKnown`: RFC 8414 inserts the well-known before the issuer's path, OIDC Discovery appends it — both are tried, insertion first) |
| `op_metadata.js` | `debugger.js`, `debugger2.js`, `vc_issuance_1.js` | the OpenID Provider metadata members (and, separately, the RFC 8414-only ones) with their defaults and `-->not defined<--` notes |
| `vci_metadata.js` | `sd_jwt_vc_issuance_*.js` | the OID4VCI credential issuer metadata members (element ids and storage keys prefixed `vci_`) |
| `sd_jwt_vc.js` | `sd_jwt_vc_issuance_*.js`, `debugger.js`, `debugger2.js` | the issuance workflow's storage keys and hand-off flag, plus SD-JWT parsing and digest computation |
| `sd_jwt_vp.js` | `sd_jwt_vc_presentation_*.js` | the PRESENTATION workflow's storage keys and flows, the OID4VP request parameters and DCQL helpers (`requestedClaims`, `requiresKeyBinding`), and the artifact itself: `presentedPrefix`, `sdHash`, `signKbJwt` and `buildPresentation`, which assemble the SD-JWT+KB. It reuses `sd_jwt_vc.js` for parsing and digests, because a presentation is the same credential with a different last element |
| `vci_wallet.js` | `vc_issuance_2.js`, `vc_issuance_4.js` | the wallet's half of a **Credential Request**, with no DOM in it: holder key pairs, the `c_nonce`, the `openid4vci-proof+jwt` proof of possession, the request body, the text of an assembled HTTP call, and reading a Credential Response (JSON or the section 10 JWE). Extracted because step 4 refreshes a credential by making *the same call* step 2 makes — on the wire a refresh is not a different request, so it must not be a second implementation |
| `dpop.js` | `vci_wallet.js`, `vc_issuance_2.js`, `vc_issuance_4.js`, `debugger2.js` | **DPoP** (RFC 9449): the key pair, the RFC 7638 JWK Thumbprint that becomes `cnf.jkt`, `htu`/`ath`/`jti`, the `dpop+jwt` proof, and recognising the server's nonce request in either of its two shapes. No DOM and no storage, which is what lets `tests/dpop.js` check it against the RFCs' own vectors; the wallet's memory of it is in `sd_jwt_vc.js` and the wire is `vci_wallet.js`'s `fetchProtected()` |
| `edge_landing.js` | `saml_response.js`, `wsfed_response.js` | the **client half** of the static deployments' edge-landing hand-off: the sessionStorage key names, the `?posted=` marker and `takeHandoff()` (read once, then delete). Its counterpart is `infra/edge/edge_common.js`'s `CONTRACTS`, which ships to AWS by Terraform while this ships in the bundle — they cannot import each other, so `tests/edge_landing_contract.js` loads both and fails on drift |
| `op_history.js` | `saml_history.js`, `wstrust_history.js` | the Operations History log |
| `xmldsig.js` | the SAML and WS-Trust pages | in-browser XML Signature / XML Encryption |
| `css/saml_common.css` | the SAML, WS-Trust **and WS-Federation** pages | the shared `saml-*` look: panes, fields, tabs, buttons, notices, the collapse toggle. Every page in that family links it, and only the extras go in a page-specific sheet beside it (`saml_tools.css`, `wstrust_tools.css`). It was itself called `saml_tools.css` before the 2026-07-26 rename, which is how the WS-Federation pages ended up linking the small page-specific sheet after a merge and rendering completely unstyled — the link resolved, so nothing 404'd. `checkStylesheetsLoaded()` in `tests/navigation.js` now catches that: any class prefixed `saml-` / `wst-` / `wsfed-` / `vc-` / `vp-` that a page uses must be defined in one of the stylesheets that page actually loaded |
| `jwk_pem.js` | `jwks.js` | a JWK public key as a SubjectPublicKeyInfo **PEM** (RSA, and EC on P-256/384/521), which is the "PEM Format" box on the JWKS page. It is sixty lines of DER rather than the `jwk-to-pem` package because that package builds its EC point through **`elliptic`**, and browserify then ships `elliptic` to the browser — see *Keeping `elliptic` out of the bundles* below. A `d` member is ignored (these are published keys), and an unsupported `kty` throws so the page can mark **one** key unrenderable without losing the table |
| `jose_jwe.js` | `jwt_tools.js`, the OID4VCI issuance panes | in-browser **JWE** (RFC 7516/7518): RSA-OAEP(-256), ECDH-ES direct and +A*KW, A*GCM, the Concat KDF, flexible key input (CryptoKey / JWK object / JWK text / PEM), and a **Web Crypto capability probe** — Chrome rejects AES-192, so options needing it are marked unusable rather than failing with an OperationError. Extracted from `jwt_tools.js` because OID4VCI section 10 has both sides encrypting, and the KDF must exist once. Tested directly by `tests/jose_jwe.js` against an independent reading of RFC 7518 section 4.6 |
| `did.js` | `did_tools.js`, `vc_issuance_1.js` (the pane), `vc_issuance_3.js` (issuer verification), `vc_presentation_2.js` (the ldp_vc key) | **DIDs** (W3C DID Core 1.0): `did:jwk`, `did:key` and `did:web`, all resolving to the same document shape so one table renders any of them; reading a document (`assertionKeys`, `keyForKid`, `assertionJwks`); `resolveVerificationMethod`, which handles a proof naming its key by DID URL *or* by https URL; and **DIF Well Known DID Configuration** (`verifyDomainLinkage` / `verifyOriginLinkage`). Tested by `tests/did_document.js` |
| `cbor.js` | `cose.js`, `webauthn.js` | a decode-only, bounded CBOR reader (RFC 8949). Maps decode to a **`Map`**, because COSE is keyed by integers including negative ones and collapsing those to object keys makes `1` and `"1"` the same thing. Indefinite lengths are refused: CTAP2's canonical CBOR forbids them, so one in an attestation object is a finding rather than something to accept quietly. `decodeFirst()` exists because the credential public key sits mid-buffer inside the authenticator data with the extension data behind it |
| `cose.js` | `webauthn.js`, `webauthn_panes.js` | COSE_Key → JWK → SPKI PEM, **reusing `jwk_pem.js`** rather than re-encoding DER. A key carrying private material is refused rather than stripped. The negative labels are read per key type, because `-1` is the curve for an EC2 key and the modulus for an RSA one |
| `webauthn.js` | the two WebAuthn pages, `webauthn_panes.js`, `tests/webauthn_decode.js` | clientData, authenticator data, attestation statements, and assertion verification reporting every check **by name** rather than one boolean. No DOM in it, which is what lets the node test drive it against real ceremonies with no browser |
| `webauthn_panes.js` | `webauthn_analyzer.js`, `webauthn_lab.js` | the DOM half: the decode panes both pages render. They differ in where the bytes came from and nothing else, so a flags table that disagreed between them would be a bug visible only by comparing the pages. **No `innerHTML` anywhere** — everything here arrived from an authenticator or a paste box |

## The landing page

`client/public/index.html` is the protocol chooser — one card per protocol, styled by `css/landing.css`. **Every card has to be visible without scrolling**, which is the constraint that fixes the numbers in that file: a `grid-template-columns: repeat(auto-fit, minmax(205px, 1fr))` grid in a 940px box (**four** across on a desktop container, three at Bootstrap's 724px, one on a phone), a 48px icon, and descriptions kept short and roughly **equal in length** — a grid row is as tall as its tallest card, so one long description raises the whole row. The column count has had to grow twice for the same reason: two columns while there were four protocols put the last two of six below the fold, and three columns would have done the same to the seventh. Eight cards now sit in a 4 + 4 grid ending 571px down — the eighth filled the empty slot the seventh left, so it cost no height at all.

**Three cards point into the OAuth2 / OIDC pages**, because two of those protocols are panes rather than pages: Dynamic Client Registration links to `/debugger.html#dcr_fieldset` (the fragment opens the page at its pane), and Token Exchange links to plain `/debugger.html` — its pane is on `debugger2.html`, since an exchange needs a subject token first, so there is nothing on `debugger.html` to scroll to. Two cards therefore share one href, which is why `tests/navigation.js` locates those cards **by title** (`cardByTitle()`) rather than by href; the CSS href locator matches both.

`tests/navigation.js` clicks **every** card and checks the page it lands on — its footer build number and its stylesheets. That matters beyond navigation: a protocol's own suite may be gated (the WS-Federation one needs its Keycloak side-car and is skipped without it), so for those pages this is the only place they are loaded on every run.

Adding a protocol therefore means three things, and `landingFitsOnOneScreen()` in `tests/navigation.js` fails if any is missed: the cards must still fit (checked against the viewport *and* against a 640px budget, because headless Chrome has no toolbar and so its viewport is more generous than a real browser's), the new card needs its own `:nth-child(N) .landing-icon` accent rule or its icon silently falls back to the text colour, and no card may end up nested inside another — an unclosed `</a>` is invisible in a screenshot, since the browser recovers from it.

## Frontend Build

Client-side JavaScript lives in `/client/src/` and is compiled into `/client/public/js/` using **browserify** with the **envify** transform (substitutes `process.env.*` at build time). Each feature page has its own standalone bundle:

| Source | Bundle | Page |
|---|---|---|
| `debugger.js` | `debugger.js` | Authorization/Implicit initiation |
| `debugger2.js` | `debugger2.js` | Token exchange + results |
| `token_detail.js` | `token_detail.js` | JWT inspection/validation |
| `introspection.js` | `introspection.js` | Token introspection |
| `userinfo.js` | `userinfo.js` | Userinfo endpoint |
| `jwks.js` | `jwks.js` | JWKS endpoint |
| `logout.js` | `logout.js` | OIDC logout |
| `vc_issuance_0.js` | `vc_issuance_0.js` | SD-JWT VC issuance step 0, the use-case chooser (`vc-issuance-0.html`) |
| `vc_issuance_1.js` | `vc_issuance_1.js` | SD-JWT VC issuance step 1 (`vc-issuance-1.html`) |
| `vc_issuance_2.js` | `vc_issuance_2.js` | SD-JWT VC issuance step 2 (`vc-issuance-2.html`) |
| `vc_issuance_3.js` | `vc_issuance_3.js` | SD-JWT VC issuance step 3 (`vc-issuance-3.html`) |
| `vc_issuance_4.js` | `vc_issuance_4.js` | SD-JWT VC issuance step 4, the credential refresh (`vc-issuance-4.html`) |
| `vc_presentation_0.js` | `vc_presentation_0.js` | SD-JWT VC presentation step 0, the flow chooser (`vc-presentation-0.html`) |
| `vc_presentation_1.js` | `vc_presentation_1.js` | SD-JWT VC presentation step 1, the verifier's request (`vc-presentation-1.html`) |
| `vc_presentation_2.js` | `vc_presentation_2.js` | SD-JWT VC presentation step 2, choose and present (`vc-presentation-2.html`) |
| `vc_presentation_3.js` | `vc_presentation_3.js` | SD-JWT VC presentation step 3, the verdict (`vc-presentation-3.html`) |
| `did_tools.js` | `did_tools.js` | DID Tools, a general-purpose DID verifier (`did-tools.html`) |
| `webauthn_lab.js` | `webauthn_lab.js` | WebAuthn Lab — this origin as the relying party (`webauthn.html`) |
| `webauthn_analyzer.js` | `webauthn_analyzer.js` | WebAuthn Analyzer — decode artifacts from anywhere (`webauthn_analyzer.html`) |

The browserify build runs inside Docker. There is no local build script — to rebuild bundles you must use Docker.

**A new page has to be registered in TWO places**, and they are not near each other: the `BUNDLES` array in `client/build.js` (which the static deployments use) and a `RUN browserify` line in `client/Dockerfile` (which the container image uses). Miss the second and the deployed static site is perfectly fine while the containerized page's `<script>` 404s — so the failure appears only in the suite, and only as a page that does nothing.

### Keeping `elliptic` out of the bundles

`elliptic` carries GHSA-848j-6mx2-7j84 — ECDSA signing computes `k`'s byte length wrongly when `k` has leading zeros, truncating it, which produces a faulty signature and can expose the private key to anyone holding both the faulty and a correct signature for the same input. **There is no patched version and there is not going to be one**: the advisory's range is `<=6.6.1` and 6.6.1 is the latest release, so `npm audit fix` cannot resolve it and an override has nothing to point at. The only remedy is to stop requiring it.

It was reaching **five** bundles — `debugger.js`, `debugger2.js`, `jwks.js`, `token_detail.js`, `userinfo.js` — never because a page wanted ECDSA, but because browserify substitutes a bare `require('crypto')` with the whole **crypto-browserify** shim, and that shim contains browserify-sign and create-ecdh, and those contain `elliptic`. Four requires were pulling it, and three of the four were **dead code**:

| Require | Where | Replaced by |
|---|---|---|
| `jsonwebtoken` | `jwks.js`, `userinfo.js` — imported, never called | deleted |
| `jsonwebtoken` | `token_detail.js`, for one `jwt.decode(t, {complete:true})` | a local `decodeJWT()`, since decoding a JWT is base64url and no cryptography. Signature *verification* on that page was already Web Crypto's |
| `@fidm/x509` (plus `pem-file`, `@peculiar/asn1-pkcs8`) | `jwks.js` — the only references were two commented-out lines | deleted |
| `jwk-to-pem` | `jwks.js`, genuinely used | `./jwk_pem` |
| `require('crypto')` | `debugger.js`, for the PKCE `code_challenge` SHA-256 | **`create-hash`** — the very module crypto-browserify uses for `createHash`, so it is the same implementation and the same digest without the ECDSA half. Web Crypto is *not* the answer here: `crypto.subtle.digest` is async while `setPKCEValues()` calls this synchronously, and `crypto.subtle` does not exist at all on the containerized suite's `http://client:3000` origin |

Three rules follow, and `tests/jwk_pem_encoding.js` enforces all three:

* **No file in `client/src` may require `jwk-to-pem`, `jsonwebtoken`, `@fidm/x509`, or a bare `crypto`.** Any one of them silently re-adds `elliptic` to whatever bundle it lands in. This is the only check that would catch a *new* page doing it. (Comments discussing these requires are fine — that is where the reasoning lives — so only real code lines count.)
* Those packages are **removed from `client/package.json`**, so a future `npm install` cannot quietly restore the option.
* `browserify` and the minifiers are **devDependencies**, not dependencies. They are build tools that ship to nobody, and moving them is what makes `npm audit --omit=dev` report **0 vulnerabilities** — the full `npm audit` still shows the four `elliptic` lows, correctly, because the *build tool* still contains it. Both images install with plain `npm ci`, which includes devDependencies, so the build is unaffected. Note `client/Dockerfile` uses `npm ci`, so **`client/package-lock.json` must stay in sync with `package.json`** or the image build fails outright — unlike `api/`, which uses `npm install` and whose lock is knowingly stale.

What remains is `browserify`'s own copy, on disk in the built image. It is not reachable from any page, and removing it needs the runtime image to prune devDependencies (a multi-stage build, or `npm prune --omit=dev` after the bundling steps plus dropping the global `npm install -g browserify`) — not done.

