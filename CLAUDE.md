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
| the Kerberos workflow, its five pages, `common/krb5/`, the PAC, delegation, or the mock KDC | `docs/kerberos.md` |
| the mock STS — **a submodule**, so its notes cannot live under `sts/` | `docs/mock-sts.md` |

## Overview

OAuth2/OIDC Debugger — a two-service web application for testing and debugging OAuth2, OIDC, SAML, WS-Trust, WS-Federation, SD-JWT VC (issuance and presentation), WebAuthn and **Kerberos v5** flows against real identity providers, issuers, verifiers, key distribution centers and security keys. Supports Authorization Code, Implicit, Client Credentials, Resource Owner Password, and Refresh grants, plus all three OIDC authentication flows (Authorization Code, Implicit, Hybrid).

**Kerberos is the exception to "two-service web application", and to almost everything else here.** It is not an HTTP protocol: it speaks DER over TCP and UDP port 88, so a browser cannot reach a KDC and the api acts as a guarded byte relay rather than a proxy of anything HTTP-shaped. That makes it the one workflow absent from the deployed static sites — except its decoder, which needs no network. See `docs/kerberos.md`.

## Architecture

The project is split into two independent Node.js services:

- **`/api/`** — Express backend (port 4000). Proxies token endpoint calls server-side and provides a `/claimdescription` endpoint with cached IANA JWT claim metadata. It fetches URLs its **caller** chooses, so its outbound calls are governed by an address policy and six settings in `api/env/*.js` — none of which may be dropped from a new call site. See `api/CLAUDE.md` before touching `api/server.js`.
- **`/client/`** — Express frontend (port 3000). Serves static HTML/JS pages and handles the OAuth2 redirect callback at `/callback`, forwarding query params to `debugger2.html`. Every protocol implementation that runs in the browser is here; see `client/CLAUDE.md`.
- **`/common/data.js`** — Shared `convertToOAuth2Format()` function used by both services to normalize grant parameters (including PKCE and custom params).
- **`/common/krb5/`** — the **Kerberos v5** codec and crypto, shared by the browser bundles, the api's frame checks and the test suite, because one wire codec must not exist twice. It is the only protocol implementation here that is not under `client/src/`, and five of its modules are additionally **vendored** into the `sts/` submodule (a Docker build cannot COPY from outside its context) with `tests/krb5_codec_sync.js` keeping the copies honest. See `docs/kerberos.md`.
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
  `extension/build.js` plus `waltid/cors-proxy.js`, which run before or outside
  an install, and **`client/src/coverage_beacon.js`**, which looks like an
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
