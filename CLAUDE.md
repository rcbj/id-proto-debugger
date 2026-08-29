# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

It deliberately holds only what is **cross-cutting**: the overview, the component map, how to run and configure things, versioning, and the rules that apply wherever you are working. Everything specific to one part of the tree lives in that part of the tree and is loaded when you open it.

| Working on | Read |
|---|---|
| the Express backend, its outbound calls, the SSRF guard, the timeouts and size/redirect caps | `api/CLAUDE.md` |
| any page, bundle, layout or in-browser protocol implementation | `client/CLAUDE.md`, which indexes ten topic docs under `docs/` |
| the Selenium suite, the launchers, the per-test map, the environment hazards | `tests/CLAUDE.md` |
| the deployed static sites, Terraform, the Lambda@Edge landings | `infra/CLAUDE.md` |
| the walt.id issuer/verifier containers and their configuration | `waltid/CLAUDE.md` |
| the WS-Federation Keycloak 8.0.1 side-car | `keycloak-wsfed/CLAUDE.md` |
| **SAML 1.1** — the second protocol version the SAML workflow speaks, which is a different protocol rather than an older spelling: no request message, no Single Logout, a QName status code, and five settings switched off | `docs/saml11.md` |
| **RFC 9700** — the OAuth 2.0 Security BCP compliance checkbox on the OAuth2/OIDC workflow, what it enforces, and why it is off by default | `docs/rfc9700.md` |
| the WebAuthn workflow, its decoder, or the read-only browser extension | `docs/webauthn.md` |
| the Kerberos workflow, its six pages, `common/krb5/`, the PAC, delegation, or the mock KDC | `docs/kerberos.md` |
| **SPNEGO** — Kerberos over HTTP: `spnego.html`, `krb5_spnego.js`, `POST /krb5/spnego`, the mock's protected page | `docs/spnego.md` |
| **LDAP** — `ldap.html`, `api/ldap_client.js`, the eight `POST /ldap/*` endpoints, the mock's embedded directory, the `node-ldapjs` submodules | `docs/ldap.md` |
| **SCIM** — the SCIM 2.0 provisioning page, its scenario harness, `client/src/scim*.js`, `api/scim_proxy.js` and `POST /scim` | `docs/scim.md` |
| **SPIFFE** — the SPIFFE / SPIRE page, `api/spiffe_client.js`, the vendored `api/protos/`, `common/spiffe/`, and all forty-nine methods | `docs/spiffe.md` |
| **PKI** — the certificate authority page, `x509.js`, `key_material.js`, the keystore formats, and the api's TLS / mutual-TLS test | `docs/pki.md` |
| **encryption** — the Encryption / Decryption page, its nine panes, and the DOM-free engines behind them (`symmetric_crypto.js`, `pk_encryption.js`, `crypto_bytes.js`) | `docs/encryption.md` |
| **hashing** — the Hashing / Encoding Tools page's three hash panes and the DOM-free engine behind them (`hash_tools.js`): FIPS 180-4, **FIPS 202** (SHA-3 and the SHAKEs) and **SP 800-185** (cSHAKE, KMAC, TupleHash, ParallelHash) — the functions ML-KEM, ML-DSA and SLH-DSA are built from | `docs/hashing.md` |
| **stateful hash-based signatures** — the LMS/HSS and XMSS/XMSS^MT pane on the Digital Signature page, `hbs.js`, and the state that makes them different from every other signature here | `docs/hbs.md` |
| the mock STS — **a submodule**, so its notes cannot live under `sts/` | `docs/mock-sts.md` |

## Overview

**The project was renamed on 2026-08-28.** It was `oauth2-oidc-debugger`,
and it is `id-proto-debugger` now — the old name described the first two of
the fifteen-odd protocols below, and stopped being accurate a long way back.
The rename reached the git remote
(`git@github.com:rcbj/id-proto-debugger.git`), this file, `README.md` and the
three `package.json`/`package-lock.json` name pairs, which are now
`id-proto-debugger-api`, `-client` and `-tests` (they were `idptools-api`,
`docker_web_server` and `idptools-tests`; nothing reads those names, and
`client/version.js` only ever touches the version field). It has NOT reached
everything else, and there a stale `oauth2-oidc-debugger` is expected rather
than a bug: the deployed sites, which keep their own names (idptools.com and
test.idptools.com), the logo file under `docs/images/` (its filename
still spells the old name), the one Medium article URL in `README.md`
— an external link, so changing it would break it — and every mention
inside `sts/`, which is somebody else's checkout. The working copy
itself is still nested under a directory of the old name. Nothing about
the code, the layout or the commands changed with the name.

id-proto-debugger — a two-service web application for testing and debugging OAuth2, OIDC, SAML, WS-Trust, WS-Federation, SD-JWT VC (issuance and presentation), WebAuthn and **Kerberos v5** flows against real identity providers, issuers, verifiers, key distribution centers and security keys. It **provisions** the identities those protocols then authenticate, over **SCIM 2.0** — one endpoint at a time, or as scenario batches that create, modify and deprovision populations of users and groups and check every step against what the plan said would happen. It hands those workloads the identities they authenticate WITH, over **SPIFFE** — an X509-SVID or a JWT-SVID from a Workload API that authenticates nobody, then all forty-two SPIRE Server API methods as whoever that credential makes you. It also builds the **X.509** certificate authorities those protocols run on — a Root, an Intermediate and an Issuing CA, with full X.509v3 extension control — and makes real **TLS and mutual-TLS** connections with what it issues. Supports Authorization Code, Implicit, Client Credentials, Resource Owner Password, and Refresh grants, plus all three OIDC authentication flows (Authorization Code, Implicit, Hybrid).

**Kerberos is the exception to "two-service web application", and to almost everything else here.** It is not an HTTP protocol: it speaks DER over TCP and UDP port 88, so a browser cannot reach a KDC and the api acts as a guarded byte relay rather than a proxy of anything HTTP-shaped. That makes it the one workflow absent from the deployed static sites — **all six of its pages**, the decoder included: it needs no network, but it has no landing card of its own and the only route to it is a link on `kerberos.html`, which is not there either. **SPNEGO goes with them and looks like it should not**: its own exchange is ordinary HTTP, but the ticket it carries comes from a KDC on port 88 and the two pages that obtain one are not deployed, so it would be a page whose only button says "no service ticket held" for ever. `client/static_site.js` holds the list, `client/build.js` acts on it, and the landing page's two cards for this workflow — Kerberos and SPNEGO — are greyed out and unclickable on those sites. See `docs/kerberos.md` and `docs/spnego.md`.

**LDAP is the second exception, and it is the cleaner one.** RFC 4511 is BER over a TCP socket on port 389, so a browser cannot speak it either — and unlike Kerberos, where the protocol runs in the browser and the api merely carries the bytes, here the whole protocol lives in the **api**: `api/ldap_client.js` encodes and performs the operation and `client/src/ldap.js` never touches a socket. So `ldap.html` has no offline half at all — not even a decoder — and it is the **third page** `client/static_site.js` drops and the **third landing card** greyed out on the deployed sites. One consequence catches everybody once: the URL in its connection pane is resolved by the API, not by the browser, so `localhost` there means the machine the api runs on. See `docs/ldap.md`.

**SPIFFE is the third exception, and the one that gives up the most to be
one.** Its server side is three surfaces and only the bundle endpoint is
ordinary HTTPS; the other two are **gRPC**, which is HTTP/2 with a binary
framing and its status in the trailers — `fetch` will not open an HTTP/2 stream
of its own, cannot send or read trailers, cannot see a `grpc-status`, and
cannot present the client certificate the SPIRE Server API requires. So both
live in `api/spiffe_client.js`, which vendors the SPIFFE project's and the
`spire-api-sdk`'s own protos **verbatim** into `api/protos/` because the whole
point of the dependency is that the wire matches what a real client expects.
What SPIFFE gives up that Kerberos and LDAP do not: three of its readers —
the trust bundle one (a group in the settings pane since 2026-08-26), the SVID
inspector and the SPIFFE ID checker — need **no
network at all**, and they go with the page anyway, because a page whose two
biggest panes are permanently dead is worse than a card that says why. It is
the **fourth page** `client/static_site.js` drops and the **fourth landing
card** greyed on the deployed sites. Two things about it surprise everybody
once, and both are the specifications rather than this code: the Workload API
**must not** authenticate anybody (a workload has no root of trust until that
call gives it one) while the SPIRE Server API's TCP port is mutual TLS; and a
SPIRE server's certificate carries **no DNS name**, so hostname verification
cannot apply and is REPLACED by a check on the SPIFFE ID in its URI
subjectAltName. See `docs/spiffe.md`.

## Architecture

The project is split into two independent Node.js services:

- **`/api/`** — Express backend (port 4000). Proxies token endpoint calls server-side and provides a `/claimdescription` endpoint with cached IANA JWT claim metadata. It fetches URLs its **caller** chooses, so its outbound calls are governed by an address policy and **sixteen** settings in `api/env/*.js` — none of which may be dropped from a new call site. Four of its capabilities are worth knowing before adding a rule for a fifth. `POST /scim` is an ordinary fetch and needs none of its own — the SCIM page calls a SCIM server straight from the browser and works with no api at all, which is what separates it from LDAP and Kerberos. The other three are not HTTP fetches and reuse that policy's *decision* over a raw socket: the Kerberos relay; `POST /tls/connect`, which opens a TLS or mutual-TLS connection for the PKI page because a browser cannot choose a client certificate, cannot be given a truststore, and cannot read the handshake it made; and `POST /spiffe/call`, which carries BOTH of SPIFFE's gRPC surfaces and is the only endpoint here that connects to a **filesystem path its caller chose** — an address policy cannot judge one, so `spiffeAllowedSocketPaths` stands in its place. See `api/CLAUDE.md` before touching `api/server.js`.
- **`/api/node-ldapjs/`** — a fork of [`ldapjs`](https://github.com/ldapjs/node-ldapjs), linked here as a **submodule** on branch `master` ([`rcbj/node-ldapjs`](https://github.com/rcbj/node-ldapjs)), for the LDAP support of issue #257. It is a submodule rather than a line in `api/package.json` because **upstream is decommissioned** — its maintainer stopped the project on 2024-05-14 and said so in its README — so the fork is pinned at that final commit and there is nobody upstream to publish a fix to npm. **Nothing in this tree requires it yet**: no `require`, no `COPY`, no compose service, so an uninitialised checkout currently breaks nothing and no launcher initialises it the way `requireMockStsCheckout()` does `sts/`. That stops being true at the first call site, and whatever adds one adds the initialisation with it. Until then, treat an edit under `api/node-ldapjs/` the way you treat one under `sts/` — it is somebody else's checkout, and `git status` reports it as a modified submodule rather than as a modified file.
- **`/client/`** — Express frontend (port 3000). Serves static HTML/JS pages and handles the OAuth2 redirect callback at `/callback`, forwarding query params to `oauth2_oidc_2.html`. Every protocol implementation that runs in the browser is here; see `client/CLAUDE.md`.
- **`/common/data.js`** — Shared `convertToOAuth2Format()` function used by both services to normalize grant parameters (including PKCE and custom params).
- **`/api/node-ldapjs/` and `/sts/node-ldapjs/`** — [`rcbj/node-ldapjs`](https://github.com/rcbj/node-ldapjs) (ldapjs 3.0.7), pinned as a submodule and used **UNMODIFIED**, twice: once for the api's LDAP client and once, inside the mock STS submodule, for its embedded directory. **Two copies rather than one shared, and the reason is npm rather than taste** — npm installs a `file:` dependency as a symlink and node resolves that package's own requires by walking up from where the REAL directory lives, so a copy outside the package root never reaches the `node_modules` the install just wrote (`Cannot find module 'abstract-logging'`, from inside ldapjs). Two further consequences: `sts/node-ldapjs` is a submodule of a submodule, so `git submodule update --init` stops one level short of it and **`--recursive` is required**; and `npm install` on a `file:` dependency installs that package's devDependencies too — ldapjs's are tap and eslint, about 200 packages and a dozen advisories — which is why both repositories carry an `.npmrc` with `omit=dev` and both Dockerfiles pass `--omit=dev` as well. An uninitialised submodule is an EMPTY DIRECTORY, so the build succeeds and the service dies at startup with `Cannot find module 'ldapjs'`. See `docs/ldap.md`.
- **`/common/xmldsig.js`** — **the** XML Signature and XML Encryption
  implementation, in `common/` because both services sign with it: ten
  browser bundles require it (staged into `client/src/` at build time the way
  `common/data.js` is) and `api/server.js` signs the SAML redirect and POST
  bindings with it. It was `client/src/xmldsig.js` until 2026-08-24, when the
  other two implementations were deleted — a private copy of the canonicalizer
  inside `saml_request.js`, and the `xml-crypto` package in the api. A
  canonicalizer is a READING of a specification, and three readings is three
  chances to disagree with the verifier at the far end, which for SAML is an
  identity provider that says only *invalid signature*. Both of the deleted
  copies had in fact already drifted: `saml_request.js`'s dropped processing
  instructions (C14N 1.0 retains them in both variants), and the api's redirect
  binding signed with SHA-256 whatever `SigAlg` it advertised. See
  `docs/wsfed.md` and `tests/xmlsec_interop.js`.
- **`/client/src/jws.js`** — **the** JWS implementation (RFC 7515/7518/7797/
  8037/8812), for the same reason and with the same history: six call sites had
  their own before 2026-08-24, two of them defining the same four verification
  functions under the same four names. It is not in `common/` because no
  service outside the browser signs a JWS. It has **two crypto backends** — the
  pure-JS one, which is what lets the Digital Signature page work over plain
  HTTP and offer secp256k1 and Ed448, and a Web Crypto one that exists so the
  four workflows it absorbed emit exactly the bytes they emitted before.
  `tests/jws_engine.js` holds the two backends to producing identical output.
- **`/common/krb5/`** — the **Kerberos v5** codec and crypto, shared by the browser bundles, the api's frame checks and the test suite, because one wire codec must not exist twice. It is the only protocol implementation here that is not under `client/src/`, and eight of its modules are additionally **vendored** into the `sts/` submodule (a Docker build cannot COPY from outside its context) with `tests/krb5_codec_sync.js` keeping the copies honest. `krb5_spnego.js` (RFC 4178) is the newest of them and the one with most to lose from drift — the browser encodes what the mock decodes and the mock encodes what the browser decodes, so every field crosses between the two copies in both directions. See `docs/kerberos.md` and `docs/spnego.md`.
- **`/client/src/crypto_bytes.js`, `/client/src/symmetric_crypto.js` and `/client/src/pk_encryption.js`** — the **encryption** engines, and the second place in this tree where cryptography was pulled *out* of a page rather than written for one. `crypto_bytes.js` is the bytes/base64/base64url/hex/PEM set that `jose_jwe.js`, `digital_signature.js` and `key_material.js` each had a copy of; `symmetric_crypto.js` is the block and stream ciphers plus the MAC constructions the Digital Signature page's three MAC panes were built on — Poly1305 forced that move, because ChaCha20-Poly1305 needs the same RFC 8439 section 2.5 implementation and two readings of it can agree with each other and be wrong together; `pk_encryption.js` is RSA, ECIES, ML-KEM and the finite-field family. **None of the three has a DOM**, which is what lets `tests/crypto_engines.js` drive every one of them in node against the RFCs' own vectors and against OpenSSL — the only kind of check that catches an AEAD tag which is self-consistent and interoperates with nothing. The DOM half is `client/src/tool_panes.js`, shared with the Digital Signature page. See `docs/encryption.md`.
- **`/client/src/hash_tools.js`** — **the** hash registry, the third engine pulled out of a page rather than written for one, and the one that is here because of what a browser CANNOT do: `crypto.subtle` has no SHA-3 in any browser — not one of FIPS 202's six functions, and none of SP 800-185's four — so the Hashing / Encoding Tools page could compute the SHA-2 family and nothing that any of the three post-quantum standards is actually built from. It now holds all of them (FIPS 180-4, FIPS 202, SP 800-185, plus the pre-FIPS Keccak padding that is not SHA-3 and is constantly mistaken for it) together with the security and post-quantum ROLE of each, which is the half a `sha3sum` alias does not give you: SHA3-256 is ML-KEM's H, SHAKE256 is the whole of SLH-DSA-SHAKE, and only one of those two names appears in FIPS 203. Moving off Web Crypto also ended a silent defect rather than only enabling a feature — `crypto.subtle` does not exist outside a secure context, so on the containerized test origin that pane had no cryptography at all and the suite passed a flag to conceal it. **No DOM**, so `tests/hash_engine.js` drives every function in node against OpenSSL, against `openssl mac`'s KMAC and against SP 800-185's own sample values. See `docs/hashing.md`.
- **`/client/src/hbs.js`** — **LMS/HSS (RFC 8554, RFC 9858) and XMSS/XMSS^MT (RFC 8391, SP 800-208)**, the two STATEFUL hash-based signature schemes NIST approves, and the only signature implementation in this tree written FROM THE SPECIFICATIONS rather than taken from a library — there is no LMS or XMSS in `@noble`, in Web Crypto or in node. That is a different class of risk from every other algorithm here, because a hash-based signature is simple to implement and unforgiving to get wrong: a dropped domain separator, a chain address written into the word the LEAF index lives in (which happened here, and only the reference vectors caught it), or SP 800-208's four-byte padding for the 192-bit parameter sets each produce a scheme that signs and verifies against ITSELF perfectly and interoperates with nothing. So `tests/hbs_signatures.js` asserts against RFC 8554's and RFC 9858's own test cases, one verification vector for each of the 21 XMSS parameter sets, the XMSS reference implementation's key generation vectors and eight signatures that must not verify. **The private key changes every time it is used**, which nothing else on that page does: spending one one-time key twice hands an attacker the material to forge a third message, so the pane keeps the index in the private key box, rewrites it on every Sign, and has a button that does the forbidden thing on purpose. **No DOM.** See `docs/hbs.md`.
- **`/client/src/scim_client.js` and `/client/src/scim_scenarios.js`** — the **SCIM 2.0** engines, and the third place in this tree where the interesting half of a workflow was kept OUT of the page on purpose. `scim_client.js` composes every request RFC 7644 defines, applies the seven authentication schemes, and generates a User carrying every optional attribute RFC 7643 section 4.1 has; `scim_scenarios.js` turns "create ten users, put them in a group, change five and delete the lot" into a list of steps each carrying its own EXPECTATION, which is what makes a 409 on a duplicate `userName` a **pass**. **Neither has a DOM**, which is what lets `tests/scim_engine.js` drive the whole of it in node against the RFCs' own text — the only kind of check that catches a double-encoded id (a 404 that reads exactly like a deleted user) or a wrong Digest hash (a 401 that reads exactly like a wrong password). Digest is implemented here for all three registered algorithms and NONE of them is Web Crypto, which has neither MD5 nor SHA-512/256. See `docs/scim.md`.
- **`/common/spiffe/` and `/api/protos/`** — the **SPIFFE** halves that are not
  a page. `spiffe_id.js` is the ID grammar and `spiffe_bundle.js` reads a trust
  bundle document; both are DOM-free and both live in `common/` because the
  api, the browser bundle and `tests/` all need them, and a grammar implemented
  three times is a grammar that disagrees with itself. The grammar is
  **stricter than a URL parser** in four ways that each produce an identifier
  looking perfectly fine in a log — a trust domain is lower-case and
  `new URL()` lower-cases a host for you, hiding it — and the bundle reader's
  one consequential rule is that a JWK with no `use` is one a consumer MUST
  IGNORE, so a bundle of them **verifies nothing** and reports no error
  anywhere. `api/protos/` is 21 `.proto` files vendored VERBATIM, byte-identical
  to the mock STS's copies, which `tests/spiffe_engine.js` compares file by
  file: an edit to one would make this debugger agree with that mock and
  interoperate with nothing. See `docs/spiffe.md`.
- **`/client/src/x509.js` and `/client/src/key_material.js`** — the **X.509 / PKI** pair, and the one place in the tree where a client module was extracted *out* of a page rather than written for one. `key_material.js` is the bottom third of `jwt_tools.js` — key pairs, PEM↔JWK, and the PEM/DER/JWK/PKCS#12 export matrix — moved so that the PKI page has the same pane rather than a second implementation of it; `jwt_tools.js` is now a caller and is 340 lines shorter. `x509.js` is certificate authoring: the profiles, every X.509v3 extension, issuing, describing and chain checks. Neither has a DOM, which is what lets `tests/pki_x509.js` drive ~240 certificates through the real encoder in node and hand every one of them to **OpenSSL** — the only kind of check that catches an encoding that is wrong and self-consistent, of which `docs/pki.md` records five that were real. See `docs/pki.md`.
- **`/sts/`** — A mock Security Token Service used by the test suite (OAuth2 AS, OIDC OP, WS-Trust, **WS-Federation IdP**, OID4VCI issuer, OID4VP verifier, DID publisher, and — on two HTTPS listeners of its own — a **TLS / mutual-TLS endpoint** whose whole content is what the server saw of the connection, which is what the PKI page presents a client certificate to). **Its code is no longer in this repository** — it is the [`rcbj/mock-sts`](https://github.com/rcbj/mock-sts) submodule, so `git submodule update --init --recursive sts` is required once per checkout — **`--recursive`, because the mock STS has a submodule of its own** (`node-ldapjs`, which its package.json takes as `"ldapjs": "file:node-ldapjs"`), and an uninitialised submodule is an empty DIRECTORY, so plain `--init` builds an image whose container dies at startup with `Cannot find module 'ldapjs'`, a message naming a package rather than a submodule. An edit under `sts/` is an edit to somebody else's checkout. Since 2026-08-19 its **`/admin` console has a management API beside it at `/admin-api`** — the same pages and the same forms over JSON, with a generated OpenAPI 3.1 document at `/admin-api/openapi.json` and an explorer that calls it at `/admin-api/docs` — which is how a test pins what that service issues without driving a form. It is unprotected, like everything else there, and the mock's own `admin_api.js` asserts the rule it is written under: a control added to the console gets an operation in the same commit. **That test, and the three beside it that drove the `/admin` console, left this repository's suite on 2026-08-28** — they assert things about the mock rather than about this debugger, so they are the submodule's now. See `docs/mock-sts.md`.
- **`/waltid/`** — walt.id's own `issuer-api2` and `verifier-api2` containers, behind CORS proxies, for interoperability testing. See `waltid/CLAUDE.md`.
- **`/keycloak-wsfed/`** — A dedicated Keycloak 8.0.1 side-car carrying the cloudtrust `keycloak-wsfed` extension, because the main stack's Keycloak 26.x has no WS-Federation support at all. Since 2026-08 the mock STS answers that profile too and **every WS-Federation case runs against both**; they are complementary, not redundant — the side-car is somebody else's implementation, and the mock is the one that reads what the debugger sends. See `keycloak-wsfed/CLAUDE.md` and `docs/wsfed.md`.
- **`/extension/`** — a **read-only** browser extension that observes `navigator.credentials` on one origin you arm it for and hands the artifacts to the WebAuthn pages. It never alters a ceremony and never starts one, and it will not name an RP ID it does not own — an extension that could would be a working defeat of WebAuthn's phishing resistance. The builds are generated (`extension/build.js`, called by the launchers), not committed. See `docs/webauthn.md`.
- **`/infra/`** — Terraform and the Lambda@Edge handlers for the static deployments, which is how two protocols get an IdP's **POST** back to a site with no backend. See `infra/CLAUDE.md`.
## Running the App

```bash
# Once per checkout. THREE submodules and one of them is nested, so --recursive
# is not optional: sts/ is the mock STS, api/node-ldapjs is the LDAP library the
# api's client uses, and sts/node-ldapjs is the same library inside the mock,
# which its embedded directory is built on. `--init sts` alone leaves that last
# one empty — and an uninitialised submodule is an EMPTY DIRECTORY, so the image
# builds and the container dies at startup with `Cannot find module 'ldapjs'`.
# The test launchers do this themselves; a bare docker-compose build does not.
# --recursive because the mock STS has a submodule of ITS own (node-ldapjs,
# which its package.json takes as "ldapjs": "file:node-ldapjs"). An
# uninitialised submodule is an EMPTY DIRECTORY, so plain --init builds an
# image whose container dies at startup with `Cannot find module 'ldapjs'` —
# a message naming a package rather than a submodule.
git submodule update --init --recursive

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

# The jobs run in a POOL — TEST_CONCURRENCY at a time, defaulting to one less
# than the machine's cores and held between 2 and 4. It reaches every launcher,
# the two CONTAINERIZED ones included, and there it crosses TWO boundaries:
# docker-compose-run-tests.yml substitutes it into the tests service, and
# common/common.sh forwards it past `sudo`, which empties the environment and
# passes only what COMPOSE_FORWARDED_VARS names. Both halves are needed — until
# 2026-08-27 only the first existed, so this line reached compose as EMPTY and
# the pool sized itself from the container's cores with no warning anywhere.
# tests/compose_env_forwarding.js now fails when a variable a compose file
# reads is not forwarded. TEST_CONCURRENCY=1 restores the old one-at-a-time run
# with live streamed output, which is the first thing to try when a job fails
# in the pool and passes on its own. What must not overlap is declared in
# JOB_LOCKS at the top of tests/run-report.js — read tests/CLAUDE.md before
# adding a test that configures a shared service.
TEST_CONCURRENCY=6 ./docker-run-tests.sh
TEST_CONCURRENCY=6 ./run-coverage.sh

# Each job is spawned in a PROCESS GROUP of its own and the whole group is
# killed when the job ends — passing or failing. A browser job is node ->
# chromedriver -> chrome and one headless Chrome is ~15 OS processes, of which
# only the first is the runner's child; before 2026-08-26 a test that died
# without reaching driver.quit() left the whole browser resident, and a run of
# this suite left 559 Chrome processes behind and cost a reboot. A watchdog
# (TEST_JOB_TIMEOUT_MS, default 900000 — 15 minutes; 0 disables) additionally
# kills a job's tree if it never exits. See tests/CLAUDE.md — and note that
# `process.exit()` in a catch SKIPS the finally that quits the driver, which
# is the bug that made the backstop necessary.
# It is forwarded to the containerized launchers the same way TEST_CONCURRENCY
# is, so it works on all three.
TEST_JOB_TIMEOUT_MS=300000 ./local-run-tests.sh

# Tests from local shell, dependencies still in containers
./local-run-tests.sh

# Against a site that is ALREADY DEPLOYED, with everything on the other side
# of each protocol started locally
./remote-run-tests.sh [base-url]

# Just the FEDERATED sign-ins. `=single` is ONE hop — an OIDC application in
# the trust realm `federation-realm-1`, authenticated over SAML 2.0 in
# `federation-realm-2`. `=chain` is TWO hops and THREE protocols: an
# application in `federation-realm-3`, SAML 2.0 on to `federation-realm-4`,
# which has no password box of its own and federates AGAIN over
# WS-Federation to `federation-realm-5`, where the only password field in
# the chain is drawn. That makes realm 4 a pure IDENTITY BRIDGE, and the
# attribute that makes it one — `fedAuthnMechanism` on its
# identity-provider-side relationship — is what that case exercises.
# `=both` is the default; the realms are disjoint so either runs alone.
# `=matrix` is the GRID: every combination of the two protocol layers and of
# how the far realm authenticates — five application protocols (oidc, oauth2,
# saml2, saml11, wsfed) by five federation protocols (the same five) by two
# mechanisms (password, webauthn), less the one `=single` already drives, so
# FORTY-NINE points. It has its own pair of realms (federation-matrix-1 and
# -2) and shares nothing with the two above. `=matrix:<app>/<fed>/<mech>` runs
# ONE point, which is how a failing combination is reproduced — add -b to
# watch it. The ordinary suite runs those forty-nine as pooled jobs;
# this loop runs them in order, for a live stack to look at afterwards.
# SPNEGO is deliberately not a third mechanism yet, and since the 2026-08-27
# sts/ bump the reason has NARROWED to one: the acceptor IS wired to a
# session now (/authn/spnego calls startSession(), and a relationship can
# carry fedAuthnMechanism: spnego), so what is left is where a HEADLESS
# browser gets a ticket and an allow-listed host to send it to. Twenty-five
# further points are deferred rather than faked. See tests/CLAUDE.md.
# Every realm is a logical copy of the ONE mock STS told apart by a path
# prefix, so this is client + api + the mock and nothing else. It leaves the
# realms configured on a running stack, which is where the sign-ins it just
# performed are visible: /admin on any of them. The single-hop case replaced
# the mock's own three-container `federation-e2e/` on 2026-08-26 — trust
# realms made the extra containers unnecessary.
./local-run-tests.sh --federation-only[=single|chain|both|matrix]
./local-run-tests.sh --federation-only=matrix:wsfed/oauth2/webauthn

# The containerized stack again, under Istanbul/c8 instrumentation
./run-coverage.sh

# Just the WS-Federation test, against BOTH its identity providers, with only
# api + client + the mock STS + the Keycloak side-car. `=sts` or `=keycloak`
# narrows it to one; `=sts` skips the twenty-second WildFly boot entirely.
./local-run-tests.sh --wsfed-only[=keycloak|sts|both]

# The three-tier delegation chains — a sign-in, then two hops through a middle
# tier — with only api + client + the mock STS. THE SAME SCENARIO IN TWO
# PROTOCOL FAMILIES, because the delegation register and the map drawn from it
# are ONE model for both. `=oauth` is an OIDC sign-in as webapp1 then two RFC
# 8693 exchanges as apigw1 and esb1, where the audience travels in an `aud`
# claim. `=wstrust` is a SAML 2.0 HTTP-POST sign-in as portal1, then two
# WS-Trust hops to https://esb.example.com and https://soap1.example.com, where
# the audience travels in the assertion's <saml:AudienceRestriction> — which
# says exactly what `aud` says — and it runs TWICE, once carrying
# <wst:OnBehalfOf> (impersonation) and once <wst14:ActAs> (composite
# delegation). `=both` is the default; the two use different people and
# different applications, so the pictures stay separate. It all LEAVES THE
# DELEGATION MAPS BEHIND as SVG under tests/report/delegation/, which is the
# only way to see those pictures at all: the mock's delegation register is in
# memory and dies with the container.
./local-run-tests.sh --delegation-only[=oauth|wstrust|both]

# Kerberos against a REAL Windows Server 2025 domain controller, spun up on AWS
# and destroyed afterwards. Needs AWS credentials and NOTHING else — no docker,
# no local stack, because the test loads the api's relay modules in-process and
# opens the socket itself. `=capture` refreshes the recorded exchange that
# tests/krb5_windows_vectors.js asserts offline on every ordinary run; `=both`
# does the test then the capture. THIS IS THE ONE COMMAND HERE THAT COSTS
# MONEY — it is not free tier, because a forest promotion needs more than the
# 1 GiB a t3.micro has. Teardown is on an EXIT trap and runs even when the test
# fails. See infra/terraform-krb5/README.md.
./local-run-tests.sh --krb5-real-dc[=test|capture|both]
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

## Style Notes

There is no linter here (see *Running Tests*), so nothing enforces any of the
following. That is exactly why it is written down: these three rules have had to
be re-applied across the tree more than once, and each pass is only necessary
because a new call site did not follow them in the first place. Apply them to
code you write **as you write it**, not as a later sweep.

- **Every function is entered and left out loud.** A function begins with
  `log.debug("Entering NAME().")` and ends with `log.debug("Leaving NAME().")`,
  where `NAME` is the function's own name — so a grep for `Leaving foo()` finds
  the one function it names. A function with early returns logs `Leaving` before
  **each** of them, not only at the bottom; a `Leaving` that a `return` can jump
  over is worse than none, because the absence in a log then reads as a hang.
  `log` is the module's own `bunyan` logger, created at the top of the file with
  the level read from `CONFIG_FILE` inside a `try`/`catch` that falls back to
  `"info"` — every module already has one; copy the block from a neighbour.
  **Five places cannot reach bunyan** and carry a console-backed `log` of the
  same shape instead, each saying why in a comment above it: `extension/src/*`
  (loaded raw by the browser, no module system), `infra/edge/*` (Lambda@Edge
  bundles a handler with no dependencies), `common/sp_keypair.js` (`common/` is
  outside the reach of `tests/node_modules` — see the note in `common/tests.js`),
  the build scripts `client/version.js`, `client/build.js`,
  `client/static_site.js`, `extension/build.js` plus `waltid/cors-proxy.js`,
  which run before or outside an install (`static_site.js` is additionally read
  by `tests/static_site_exclusions.js`, which must not need
  `client/node_modules` either), and **`client/src/coverage_beacon.js`**, which looks like an
  ordinary client module and is not one: `client/Dockerfile`'s coverage step
  *appends* it to each finished bundle (`cat src/coverage_beacon.js >>
  public/js/${src_name}.js`), so browserify and envify never see it and neither
  `require` nor `process` exists where it runs. Its shim is the only one written
  **inside** the file's IIFE rather than at the top, because appending it puts
  anything at top level into the *page's* global scope. Those shims' own
  `debug`/`info`/`warn`/`error` are the one place the convention *cannot* apply:
  a log line inside `log.debug()` is infinite recursion.
  This covers **declared functions and named function values** (`function foo()`,
  `var foo = function () {…}`, `const foo = () => {…}`, object and class
  methods). It does not extend to anonymous inline callbacks — a `.map(x => …)`,
  an `addEventListener` handler, a config IIFE — which have no name to log and
  are left alone.

  **Four places a log line is not a log line but a crash, and all four cost a
  run on 2026-08-14 (26 of 127 tests on the plain suite, from a baseline of 127
  green, and 12 more plus an empty coverage report on `./run-coverage.sh`).**
  Check each before adding one:

  * **`log` must actually be in scope.** `tests/edge_landing_contract.js` keeps
    its module logger as `fallbackLog` and takes the caller's as the *parameter*
    `assertEdgeLandingContract(log)`, so at module scope there is no `log` at
    all: a line added to its `locate()` helper was a `ReferenceError`, and it
    took out every WS-Federation case and the SAML EncryptedAssertion one —
    `log is not defined`, before the browser had been pointed at a page. Read
    the top of the file, not the file next to it.
  * **Never inside code that runs in the BROWSER.** Selenium serialises the
    function given to `driver.executeScript` / `executeAsyncScript` (and
    anything `.toString()`d into a script) and evaluates it in the page, where
    there is no bunyan. A log line there is `javascript error: log is not
    defined` from executeScript, which reads as a page fault. Log what the
    function *returns*, out in node. Those functions and everything they declare
    are exempt from this rule, and say so in a comment.
  * **The name `log` may already be taken — check before adding a shim.**
    `waltid/cors-proxy.js`, `client/build.js` and `extension/src/background.js`
    each already had a `function log(message)` of their own writing one line per
    request/step, and each was given a console-backed `var log = {…}` above it.
    A function declaration and a `var` of the same name are **one binding**, so
    the object assignment wins and every existing call becomes `log is not a
    function` — in the proxy, thrown from `server.listen()`'s callback, so it
    died before it listened and the only symptom was a connection refused on
    7005/7003 that failed all four walt.id interoperability tests naming
    walt.id. (`const`/`let` instead of `var` would at least be a `SyntaxError`
    at load; `var` defers it to the first call, which is why two of the three
    were invisible to the suite.) Fold the old function into the shim
    (`log.info(...)`, as `build.js` and `background.js` now do) or rename it
    (`logLine()`, as the proxy does) — never leave two.
  * **A file under `client/src` is not necessarily browserified.**
    `client/src/coverage_beacon.js` sits beside sixty modules that all take
    `require("bunyan")`, and it is the one that cannot: the coverage build
    **appends** it to already-built bundles, so it reaches the browser as raw
    script with no `require` and no `process`. The `require("bunyan")` this sweep
    gave it threw at top level, before `setInterval()` — so `./run-coverage.sh`
    shipped **no frontend coverage at all** (an empty
    `coverage/frontend/.nyc_output`, a 0-byte `lcov.info`) *and* failed the 12
    tests that assert the browser console is clean. None of the 12 named the
    beacon, coverage, or a require; each named a page and a line deep inside a
    bundle. The plain launchers never append the file, so **nothing but
    `./run-coverage.sh` can see this** — which is why
    `appendedBeaconNeedsNoModuleSystem()` in `tests/jwk_pem_encoding.js` now
    reads that file for `require`/`process`/`module.exports` on every ordinary
    run. Before adding a logger to a file here, check how it gets into a bundle,
    not just where it lives.

  The standing exception is a **hot path**, and it must say so: `cbor.js` runs
  its item decoder hundreds of times for a single credential, so it logs at the
  entry points and carries a comment explaining the omission below them. An
  exception without that comment is indistinguishable from an oversight and will
  be "fixed" by the next sweep.

  **A hot path is not only a loop inside one function — a whole rebuild path
  counts, and that is how this rule cost a CI run on 2026-08-14.** The second
  standing exception is the one-line helpers in `client/src/saml_tools.js`
  (`el`/`val`/`setVal`/`isOn`/`show`/`esc`/`version`/`isV2`, the attribute and
  compliance helpers, and `checkCompliance`'s own `pass`/`fail`/`warn`): every
  edit to any field on that page rebuilds the assertion and re-runs the
  compliance check, and one rebuild passes through those accessors on the order
  of a thousand times. At `logLevel: "debug"` — which `client/src/env/local.js`
  **and** `client/src/env/docker-tests.js` both set, so both test stacks emit
  every line — a record is a JSON serialization plus a console write, ~15µs
  measured in headless Chrome 121. Adding the pairs took `tests/saml_tools.js`'s
  in-page power-set sweep (2^10 rebuilds per version, one `executeScript` call)
  from 1.9s to 34s locally and past the WebDriver **script timeout** on a
  GitHub Actions runner, where the whole test died with `script timeout
  (Session info: chrome=121.0.6167.85)` — a message that names no page, no
  function and no log line, three steps after the last thing it printed. So
  before logging a getter, ask what calls it and how often: a pair of log lines
  in a one-line accessor is not a trace, it is the entire log. The functions
  that *call* those helpers keep their logging, which is where a trace of the
  rebuild actually lives.

- **No single-line `try`/`catch`.** There is a newline after every `try {` and
  after every `} catch (e) {` (and after `} finally {`), so the first statement
  of a block never shares a line with the brace that opens it:

  ```js
  try {
    return JSON.parse(text);
  } catch (e) {
    log.debug("Leaving parse(). Not JSON.");
    return null;
  }
  ```

  not `try { return JSON.parse(text); } catch (e) { return null; }`. The point is
  the diff and the breakpoint: a one-line block gives a stack frame and a change
  nowhere to land, and the `catch` is precisely where you go when something has
  already gone wrong.

  The same goes for any block a log line has to go into: an `if (x) { f();
  return; }` or a `case X: return y;` written on one line leaves the `Leaving`
  above wedged between two statements, so those open out too. What is left on one
  line, deliberately, is **JavaScript inside a string** — the probes the Selenium
  tests hand to `driver.executeScript(...)`, and the page template in
  `infra/edge/edge_common.js`. That is data this file happens to contain, not
  this file's control flow, and a grep for `try {` will find about fifteen of
  them.

- **80 columns.** No line exceeds 80 characters — code, comments, or string
  literals. Break at the boundaries the language already gives you, keeping the
  operator on the **first** line as the rest of the tree does — after a comma,
  after a `+` in a concatenation, after an `&&`/`||`, after an `=` — with one
  exception: a long chain breaks **before** each `.method()`, one per line. A
  long string becomes a concatenation across lines rather than a line that
  scrolls. Prose comments reflow like prose. The reason is review: these
  files are read side by side in diffs and in a terminal, and a wrapped line is
  where a stray argument or a swapped operand becomes visible.

  Three things must not be broken to reach it, and a line built out of them stays
  long: a `require("./x")` string (browserify resolves those by static analysis,
  and a concatenation makes the module invisible to it), an object key or `case`
  label (`"a" + "b":` is a syntax error), and a template literal. Neither is a
  base64 test vector, a JWK member or a URL worth mangling — about 430 lines in
  the tree are over the limit for one of those reasons, none by more than a
  little. Comments holding a table, an aligned two-column layout or a rule are
  left alone as well: reflowing those destroys the alignment that carries their
  meaning.

  **A source-inspection test is where this rule bites back.** Several tests
  assert a property by regex over `client/src` or `api/server.js` — the literal
  XML MIME type in `tests/xml_parse_inert.js`, the cached outbound agent in
  `tests/api_connect_timeout.js` — and a regex written against one line stops
  seeing a call the moment it wraps. Both of those broke on this sweep and both
  now read a *statement* rather than a line. Write them that way from the start:
  a check that a reformat can silence is a check that will be silenced, and it
  fails by naming the property rather than the formatting.

## Key Implementation Notes

- **State persistence**: All user configuration (endpoints, client IDs, scopes, etc.) is stored in browser `localStorage` — passwords are intentionally excluded.

  **Key material is the exception to that rule, and on every protocol that generates a key pair it is now an opt-out.** The multi-screen workflows do persist key pairs, because they have to: the SAML Response page needs the SP private key to decrypt an `EncryptedAssertion`, and re-pasting a PEM at every hop is the kind of friction that gets worked around by keeping the key somewhere worse. Each key-pair pane therefore carries a checkbox — **`saml_save_keypair`** (SP signing pair), **`wst_save_keypair`** (`wst_sp_private_key`/`wst_sp_cert`), **`wsfed_save_keypair`** (`wsfed_rp_private_key`/`wsfed_rp_cert`) — checked by default (so nothing about the existing flow changes), and clearing it means `saml_sp_private_key` / `saml_sp_public_key` are never written — *and* whatever was written before is **removed on the spot**, because an opt-out that leaves yesterday's private key in storage is not an opt-out. That purge lives in `saveState()` rather than only in the change handler, so no code path can leave the pair behind; it also runs on load, so upgrading to this build with the box already cleared cleans up. With saving off the user carries the pair themselves (the **Download** button beside the fields) and pastes it back here and into the response page's **Decryption Key** field — `saml_response.js` already prefills that field only opportunistically and is written to cope with an empty one. A missing checkbox (an older cached page) keeps saving, rather than silently dropping a key pair the user expects to still be there. Each list covers only *this* side's pair: `wst_enc_cert` (the STS's certificate) and `wsfed_signer_cert` (the IdP's) are somebody else's public credentials and are deliberately left alone. The WS-Federation page **does** have a signing toggle as of 2026-08-09 (`wsfed_sign_request`, **on by default**), but its key-pair pane is still always visible and does not depend on it — the pair is needed to decrypt an encrypted token on the response page whether or not the request is signed, which is why `keypair_storage_optout.js` treats the opener as optional. Note what the signature does and does not cover: the Passive Requestor Profile does not require a signed sign-in request at all, so this is a debugging affordance rather than a protocol obligation — see `docs/wsfed.md`.

  **The SD-JWT VC holder key pair works the same way but costs more, so read this before changing it.** The checkbox is on issuance step 2 (`vc_save_holder_key`) and the enforcement is central — `sd_jwt_vc.js`'s `set()` refuses the three `*_HOLDER_PRIVATE_JWK` keys when the preference is `"0"` — because writers live in three bundles and a guard per call site is a guard somebody forgets. Clearing it also strips `holderPrivateJwk` from **every Credential History row**, which is the deliberate part: the Credential History notes in `docs/sd-jwt-vc-issuance.md` warn that a generation without its key cannot be presented, and here that is the point rather than a bug. Only an explicit `"0"` disables it, so an unreadable preference fails toward the workflow. Because the key cannot then cross a page load, **paste-in fields exist on step 4 and presentation step 2** (`vc_holder_private_jwk` / `vp_holder_private_jwk`, fed by `readHolderPrivateJwk()`, which accepts either the *Download Key Pair* file or a bare private JWK and never stores what it reads), and step 4's *Reuse the bound key* option is re-enabled when a pasted key's own `x`/`y` match the credential's `cnf.jwk` — it compares against the pasted key rather than the stored public half, because with saving off step 2 regenerates a pair on every visit and that stored half goes stale.

  **The PRESENTATION workflow owns no key pair of its own** — worth knowing before looking for a checkbox there. Its six storage keys (`sdjwtvp_use_case`, `_request`, `_selected_disclosures`, `_presentation`, `_result`, `_verifier_jwks_url`) hold no key material, it never *writes* a holder key, and it has no raw `localStorage` access at all, so `sd_jwt_vc.js`'s gate already covers it. What it does need is to tell **absent-by-choice from absent-and-lost**: step 1 disables *Continue* for every entry in its `problems` list, so treating "no key in storage" as a problem strands the user one page before `vp_holder_private_jwk`, the only field that can supply it. With saving off it is an advisory and Continue stays enabled; with saving **on** and the key still missing it was never generated here, there is nothing to paste, and it blocks as before. Step 0's held-credential line makes the same distinction.
- **Token endpoint calls**: Can be made from the browser (client-side) or proxied through the API service (server-side). The UI lets users choose.
- **XSS prevention**: DOMPurify is used on the client when rendering token/claim data to the DOM.
- **SSL**: Server-side SSL certificate validation can be disabled for testing against self-signed certs.
