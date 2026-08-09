# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

It deliberately holds only what is **cross-cutting**: the overview, the component map, how to run and configure things, versioning, and the rules that apply wherever you are working. Everything specific to one part of the tree lives in that part of the tree and is loaded when you open it.

| Working on | Read |
|---|---|
| the Express backend, its outbound calls, the SSRF guard, the timeouts and size/redirect caps | `api/CLAUDE.md` |
| any page, bundle, layout or in-browser protocol implementation | `client/CLAUDE.md`, which indexes five topic docs under `docs/` |
| the Selenium suite, the launchers, the per-test map, the environment hazards | `tests/CLAUDE.md` |
| the deployed static sites, Terraform, the Lambda@Edge landings | `infra/CLAUDE.md` |
| the walt.id issuer/verifier containers and their configuration | `waltid/CLAUDE.md` |
| the WS-Federation Keycloak 8.0.1 side-car | `keycloak-wsfed/CLAUDE.md` |
| the WebAuthn workflow, its decoder, or the read-only browser extension | `docs/webauthn.md` |
| the mock STS — **a submodule**, so its notes cannot live under `sts/` | `docs/mock-sts.md` |

## Overview

OAuth2/OIDC Debugger — a two-service web application for testing and debugging OAuth2, OIDC, SAML, WS-Trust and SD-JWT VC (issuance and presentation) flows against real identity providers, issuers and verifiers. Supports Authorization Code, Implicit, Client Credentials, Resource Owner Password, and Refresh grants, plus all three OIDC authentication flows (Authorization Code, Implicit, Hybrid).

## Architecture

The project is split into two independent Node.js services:

- **`/api/`** — Express backend (port 4000). Proxies token endpoint calls server-side and provides a `/claimdescription` endpoint with cached IANA JWT claim metadata. It fetches URLs its **caller** chooses, so its outbound calls are governed by an address policy and six settings in `api/env/*.js` — none of which may be dropped from a new call site. See `api/CLAUDE.md` before touching `api/server.js`.
- **`/client/`** — Express frontend (port 3000). Serves static HTML/JS pages and handles the OAuth2 redirect callback at `/callback`, forwarding query params to `debugger2.html`. Every protocol implementation that runs in the browser is here; see `client/CLAUDE.md`.
- **`/common/data.js`** — Shared `convertToOAuth2Format()` function used by both services to normalize grant parameters (including PKCE and custom params).
- **`/sts/`** — A mock Security Token Service used by the test suite (OAuth2 AS, OIDC OP, WS-Trust, OID4VCI issuer, OID4VP verifier, DID publisher). **Its code is no longer in this repository** — it is the [`rcbj/mock-sts`](https://github.com/rcbj/mock-sts) submodule, so `git submodule update --init sts` is required once per checkout and an edit under `sts/` is an edit to somebody else's checkout. See `docs/mock-sts.md`.
- **`/waltid/`** — walt.id's own `issuer-api2` and `verifier-api2` containers, behind CORS proxies, for interoperability testing. See `waltid/CLAUDE.md`.
- **`/keycloak-wsfed/`** — A dedicated Keycloak 8.0.1 side-car carrying the cloudtrust `keycloak-wsfed` extension, because the main stack's Keycloak 26.x has no WS-Federation support at all. See `keycloak-wsfed/CLAUDE.md`.
- **`/extension/`** — a **read-only** browser extension that observes `navigator.credentials` on one origin you arm it for and hands the artifacts to the WebAuthn pages. It never alters a ceremony and never starts one, and it will not name an RP ID it does not own — an extension that could would be a working defeat of WebAuthn's phishing resistance. The builds are generated (`extension/build.js`, called by the launchers), not committed. See `docs/webauthn.md`.
- **`/infra/`** — Terraform and the Lambda@Edge handlers for the static deployments, which is how two protocols get an IdP's **POST** back to a site with no backend. See `infra/CLAUDE.md`.

## Running the App

```bash
# Once per checkout: the mock STS is a submodule, not code in this repository.
# The test launchers do this themselves; a bare docker-compose build does not.
git submodule update --init sts

# Start all services (api + client + sts)
CONFIG_FILE=./env/local.js docker-compose up

# Rebuild images first
CONFIG_FILE=./env/local.js docker-compose build
```

Access the app at `http://localhost:3000`.

## Running Tests

Tests use Selenium WebDriver with Chrome. A Keycloak test IdP is spun up automatically.

```bash
# Full battery of tests entirely in containers
./docker-run-tests.sh

# Tests from local shell, dependencies still in containers
./local-run-tests.sh

# Against a site that is ALREADY DEPLOYED, with everything on the other side
# of each protocol started locally
./remote-run-tests.sh [base-url]

# The containerized stack again, under Istanbul/c8 instrumentation
./run-coverage.sh

# Just the WS-Federation test, with only api + client + the side-car
./local-run-tests.sh --wsfed-only
```

`tests/CLAUDE.md` describes what each test file covers, what gates or skips it, and the environment hazards every browser test has to handle — Web Crypto's secure-context requirement, `--headless=new`, waiting on content rather than elements, and the rest. **Read it before writing or changing a test**; each of those hazards has already cost a run, and each fails in a way that names something other than itself.

There is no linting toolchain configured in this project.

## Configuration

Environment-specific config files live at:
- `/api/env/{local.js,test.js,docker-tests.js}`
- `/client/src/env/{local.js,test.js,docker-tests.js}`

The active config is selected via the `CONFIG_FILE` environment variable. For local development, this is `./env/local.js`.

## Versioning

The app version is **M.N.O**: `M.N` comes from the repo-root `VERSION` file (currently `0.9`), and `O` is a per-build number generated by `client/version.js` (the UTC build instant, `YYYYMMDDHHMMSS`, or `BUILD_NUMBER` if set). It is stamped at build time — `client/Dockerfile` runs `node version.js --stamp public`, and `client/build.js` writes `dist/version.json` — then substituted into the `{{VERSION}}` / `{{BUILD_INFO}}` placeholders in the footer partial and the error pages (by `build.js` at build time, by `server.js` at request time). The four `package.json` files (`api`, `client`, `tests`, `sts`) carry the same M.N as `M.N.0` (semver requires three parts). Bump a release by editing `VERSION`, then `node client/version.js --sync-manifests`; `--check-manifests` reports drift and `build.js` warns about it.

## Key Implementation Notes

- **State persistence**: All user configuration (endpoints, client IDs, scopes, etc.) is stored in browser `localStorage` — passwords are intentionally excluded.

  **Key material is the exception to that rule, and on every protocol that generates a key pair it is now an opt-out.** The multi-screen workflows do persist key pairs, because they have to: the SAML Response page needs the SP private key to decrypt an `EncryptedAssertion`, and re-pasting a PEM at every hop is the kind of friction that gets worked around by keeping the key somewhere worse. Each key-pair pane therefore carries a checkbox — **`saml_save_keypair`** (SP signing pair), **`wst_save_keypair`** (`wst_sp_private_key`/`wst_sp_cert`), **`wsfed_save_keypair`** (`wsfed_rp_private_key`/`wsfed_rp_cert`) — checked by default (so nothing about the existing flow changes), and clearing it means `saml_sp_private_key` / `saml_sp_public_key` are never written — *and* whatever was written before is **removed on the spot**, because an opt-out that leaves yesterday's private key in storage is not an opt-out. That purge lives in `saveState()` rather than only in the change handler, so no code path can leave the pair behind; it also runs on load, so upgrading to this build with the box already cleared cleans up. With saving off the user carries the pair themselves (the **Download** button beside the fields) and pastes it back here and into the response page's **Decryption Key** field — `saml_response.js` already prefills that field only opportunistically and is written to cope with an empty one. A missing checkbox (an older cached page) keeps saving, rather than silently dropping a key pair the user expects to still be there. Each list covers only *this* side's pair: `wst_enc_cert` (the STS's certificate) and `wsfed_signer_cert` (the IdP's) are somebody else's public credentials and are deliberately left alone. The WS-Federation page **does** have a signing toggle as of 2026-08-09 (`wsfed_sign_request`, **on by default**), but its key-pair pane is still always visible and does not depend on it — the pair is needed to decrypt an encrypted token on the response page whether or not the request is signed, which is why `keypair_storage_optout.js` treats the opener as optional. Note what the signature does and does not cover: the Passive Requestor Profile does not require a signed sign-in request at all, so this is a debugging affordance rather than a protocol obligation — see `docs/wsfed.md`.

  **The SD-JWT VC holder key pair works the same way but costs more, so read this before changing it.** The checkbox is on issuance step 2 (`vc_save_holder_key`) and the enforcement is central — `sd_jwt_vc.js`'s `set()` refuses the three `*_HOLDER_PRIVATE_JWK` keys when the preference is `"0"` — because writers live in three bundles and a guard per call site is a guard somebody forgets. Clearing it also strips `holderPrivateJwk` from **every Credential History row**, which is the deliberate part: the Credential History notes in `docs/sd-jwt-vc-issuance.md` warn that a generation without its key cannot be presented, and here that is the point rather than a bug. Only an explicit `"0"` disables it, so an unreadable preference fails toward the workflow. Because the key cannot then cross a page load, **paste-in fields exist on step 4 and presentation step 2** (`vc_holder_private_jwk` / `vp_holder_private_jwk`, fed by `readHolderPrivateJwk()`, which accepts either the *Download Key Pair* file or a bare private JWK and never stores what it reads), and step 4's *Reuse the bound key* option is re-enabled when a pasted key's own `x`/`y` match the credential's `cnf.jwk` — it compares against the pasted key rather than the stored public half, because with saving off step 2 regenerates a pair on every visit and that stored half goes stale.

  **The PRESENTATION workflow owns no key pair of its own** — worth knowing before looking for a checkbox there. Its six storage keys (`sdjwtvp_use_case`, `_request`, `_selected_disclosures`, `_presentation`, `_result`, `_verifier_jwks_url`) hold no key material, it never *writes* a holder key, and it has no raw `localStorage` access at all, so `sd_jwt_vc.js`'s gate already covers it. What it does need is to tell **absent-by-choice from absent-and-lost**: step 1 disables *Continue* for every entry in its `problems` list, so treating "no key in storage" as a problem strands the user one page before `vp_holder_private_jwk`, the only field that can supply it. With saving off it is an advisory and Continue stays enabled; with saving **on** and the key still missing it was never generated here, there is nothing to paste, and it blocks as before. Step 0's held-credential line makes the same distinction.
- **Token endpoint calls**: Can be made from the browser (client-side) or proxied through the API service (server-side). The UI lets users choose.
- **XSS prevention**: DOMPurify is used on the client when rendering token/claim data to the DOM.
- **SSL**: Server-side SSL certificate validation can be disabled for testing against self-signed certs.
