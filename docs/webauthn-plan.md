# WebAuthn Debugger — design and implementation plan

**Status: phases 0–5 are implemented; phase 6 is partial. The workflow's own notes are now `docs/webauthn.md` — read that first. What remains here is the record of how each phase was decided and what it measured.** It is written in the same voice as the rest of `docs/` — the reasoning attached to each decision, so that the decision can be argued with later — but every "does" below should be read as "will do". Dated 2026-08-08. When a phase lands, the parts of this file describing it should move into `docs/webauthn.md` (the workflow's own notes) and this file should shrink to the phases still outstanding.

## What this adds

A ninth protocol workflow: a **WebAuthn debugger** that decodes and verifies the artifacts of a WebAuthn ceremony, plus a **read-only browser extension** that lets the debugger observe ceremonies performed by *other* sites. The motivating case is a YubiKey used as MFA on a third-party relying party, with the OIDC leg of that sign-in already covered by the existing OAuth2 / OIDC workflow — so the end state is one chain visible from the authorization request through the WebAuthn assertion to the tokens, with `amr` naming the hardware key.

## The boundary, stated first because it decides everything else

The browser is a mediator, not a pipe. JavaScript gets the ceremony's *artifacts* and never the authenticator: no private key, no PIN, no biometric, no authenticator state, and **no CTAP** — not the commands, not the USB frames, not the PIN protocol. This debugger is therefore a WebAuthn debugger and not a CTAP debugger, and the UI says so in the Ceremony Trace rather than leaving the user to discover it by looking for a pane that does not exist. A real CTAP debugger needs a native application with direct HID access; that is a different project.

Three corrections to the received wisdom, each of which would cost a day if discovered during implementation:

* **`getPublicKey()`, `getAuthenticatorData()` and `getTransports()` exist only on `AuthenticatorAttestationResponse`** — registration. An assertion hands back `authenticatorData`, `signature` and `userHandle` as raw buffers, so a COSE decoder is required regardless of how convenient the registration-side conveniences look.
* **WebAuthn Level 3's `PublicKeyCredential.toJSON()` and `parseCreationOptionsFromJSON()` / `parseRequestOptionsFromJSON()`** give a *specified* JSON shape for these artifacts. Every interchange in this feature — extension to page, paste-in, test fixture — uses it rather than inventing a serialization. **Phase 0 measured both as absent from the tests image's Chrome 121 and present on a current Chrome 151**, so the shim is required, not merely expected; it lives in `client/src/webauthn.js` so the page and the extension share one implementation, and it must be used unconditionally rather than behind a feature test, or CI would exercise a different code path from the one users get.
* **The request options are the interesting half.** Pasting a response shows the RP's answer; capturing the call shows what the RP *asked for* — challenge, `userVerification`, `allowCredentials`, `attestation`, extensions, timeout — which no site exposes to its user. That, not decoding, is what the extension is for.

## Non-goals, and why they are non-goals

**The extension will not perform a ceremony for an RP ID it does not own.** An extension with host permissions can, in some browsers, name another site's RP ID; doing so would make this repository ship a working defeat of WebAuthn's phishing resistance — a tool that mints assertions for `login.acme.com` from something that is not acme.com. Observation costs nothing for the intended use (the user is driving the third-party site in their own browser) and the capability is declined deliberately, in the README as well as here, because "the debugger can do it" is a sentence that gets quoted.

**The extension will not initiate, mutate, store or suppress anything.** See the read-only invariant below, which is the technical statement of the same commitment.

## The three modes

```
   ┌──── any site: login.acme.com, Keycloak, Entra, the mock RP ────────────────┐
   │  navigator.credentials.create/get                                          │
   │        │                                                                   │
   │  [ extension MAIN-world shim ] ── request options ──┐                      │
   │        │  (synchronous pass-through)  ── response ──┤                      │
   │        ▼                                            │                      │
   │   real WebAuthn ──► browser ──► authenticator       │                      │
   └─────────────────────────────────────────────────────┼──────────────────────┘
                                                         │
                              ┌──────────────────────────▼───────────────────┐
   MODE 3  Live capture       │ extension background — storage.local buffer   │
                              └──────────────────────────┬───────────────────┘
                                                         │ bridge, debugger origins only
   MODE 1  Lab       ┌──────────────────────────────────▼────────────────────┐
   debugger is RP ──►│ webauthn.html          builder · trace · capture inbox │
   MODE 2  Analyzer ►│ webauthn_analyzer.html import · decode · verify · raw  │
   paste artifacts   │ client/src/webauthn.js one decoder for all three       │
                     └────────────────────────────────────────────────────────┘
```

**Modes 1 and 2 must work with no extension installed at all.** The deployed static sites have visitors who will not install anything, and the analyzer needs neither a secure context nor an authenticator — it is arithmetic over pasted bytes. Mode 3 is the only part that needs the extension, which is what makes the install prompt appear at exactly one place in the workflow rather than on arrival.

## The read-only invariant

The extension wraps `navigator.credentials.create` and `.get` in the page's own world and copies what passes through. Four rules make "read-only" mean something, and three of them are the ways a well-intentioned wrapper stops being read-only:

* **No mutation.** Capture operates on a `structuredClone` of the options and of the result. A site holding a reference to its own options object cannot observe the debugger touching it.
* **No origination, and no other patches.** The shim never calls `create`/`get` itself, and leaves the rest of `CredentialsContainer` alone — `store()` and `preventSilentAccess()` stay unpatched, because hooking those is write-shaped behaviour with no debugging value.
* **Exception transparency.** Every failure inside capture — a clone that throws on an exotic option, a full buffer, a dead background worker — is caught and dropped. A site's ceremony must never fail *because the debugger was watching*, and that is precisely the failure mode of a naive wrapper.
* **No `await` before calling through.** `navigator.credentials.get()` consumes transient user activation, which is time-bounded. A shim that awaits a config read or a message round-trip before invoking the real API can let the activation lapse, and the site then sees a `NotAllowedError` indistinguishable from the user declining. The shim calls through **synchronously in the same task**, captures from the already-cloned options, and does all asynchronous work after the real promise has been returned. Any per-origin decision must therefore be made by *not injecting the shim*, never by a check inside it. This rule reads like a micro-optimisation and will be refactored away by somebody unless the comment above it says this.

**Proved rather than asserted.** Phase 5 carries a transparency test: the mock RP's ceremony runs twice against the virtual authenticator, once with the extension loaded and once without, and the two must agree on everything the ceremony is supposed to determine — the authenticator data flags, the sign-count progression, the algorithm, the transports, and the *parsed* `clientDataJSON` fields (`type`, `challenge`, `origin`, `crossOrigin`) — with timings within noise. **It must not compare `clientDataJSON` bytes.** Phase 0 caught Chrome emitting `"other_keys_can_be_added_here": "do not compare clientDataJSON against a template…"` in some ceremonies and not others, at random, precisely to break byte comparison; a test written the obvious way would have failed intermittently and been blamed on the extension. Nobody at a store will review this hook on our behalf (see *Distribution*), so this test and the rules above are the whole of the guarantee.

## Install, arm, disarm

**A web page cannot install an extension.** Chrome removed inline installation in 2018 and Firefox's `InstallTrigger` is gone. Installation is always a deliberate user act, and the workflow's step 0 detects presence via a handshake on the debugger's own origin and shows per-browser instructions when it is absent. There is no nagging: Lab and Analyzer never raise the subject.

Installation was never the risk, though — a live hook following the user around the web is. So the boundary is **arming**, which is entirely under our control:

| State | What the extension can do |
|---|---|
| Installed, never armed | Nothing. `optional_host_permissions` only, zero hosts granted, no content script anywhere. It is a toolbar icon. |
| Armed for one origin | Shim injected on that origin alone. Badge reads `ARM`, popup names the origin and shows a countdown. |
| Disarmed | Host permission revoked via `permissions.remove()`, shim gone, capture buffer cleared. |

Disarm happens on a ladder, ordered by how much it depends on anyone doing anything: **TTL expiry** (30 minutes, extended by activity, never firing mid-ceremony) and **browser restart** need nobody; **workflow completion** signals the extension and needs nobody; and the completion pane additionally offers `management.uninstallSelf({ showConfirmDialog: true })`, which removes the extension behind the browser's own native dialog. Only that last step can be declined, and declining it leaves an extension with no permissions and no hooks.

One browser rule shapes the UI: `permissions.request()` needs a user gesture **in the extension's own surface**, so the debugger page cannot grant on the user's behalf. Step 0 says "click the extension icon and confirm"; the popup does the asking; the browser names the single host.

**The two browsers differ in a way that favours the concern that prompted all this.** A Firefox temporary add-on (`about:debugging`) is removed on browser restart, so on Firefox the hook genuinely cannot survive into the next session whether or not anyone clicks anything. Chrome's unpacked extensions persist, which is why the self-uninstall button matters more there. The documentation states the two lifecycles separately rather than describing one.

## The capture contract

Three components depend on this shape and none of them can import the others — the same problem `tests/edge_landing_contract.js` exists to police, and the same remedy: a test that loads both sides and fails on drift.

```jsonc
{
  "v": 1,
  "ceremony": "create" | "get",
  "capturedAt": "2026-08-08T…Z",
  "origin":  "https://login.acme.com",   // top-level origin of the calling frame
  "rpId":    "acme.com",                 // as resolved, or as requested
  "request":  { /* options as passed in; buffers → base64url */ },
  "response": { /* PublicKeyCredential.toJSON(), or null */ },
  "error":    { "name": "NotAllowedError", "message": "…" } | null,
  "timing":   { "startedMs": 0, "endedMs": 8431 },
  "redacted": ["userHandle"]
}
```

**A failed ceremony is a first-class capture.** A `NotAllowedError` after a thirty-second timeout is one of the things users most need to see, and a format that recorded only successes would throw it away. `userHandle` and credential IDs are redacted on export by default, with the redaction listed rather than silent.

**Version drift is a real failure mode here** because unpacked extensions do not auto-update: a stale copy speaking `v: 1` to a page expecting `v: 2` would present as a mysteriously empty inbox. The presence handshake therefore carries the extension's build stamp, the page compares it with its own, and a mismatch is a banner naming both versions.

## Pages, panes and modules

| Page | Panes |
|---|---|
| `webauthn.html` (Lab) | Capability probe (`isUserVerifyingPlatformAuthenticatorAvailable`, `isConditionalMediationAvailable`) · registration options builder · authentication options builder · **Ceremony Trace** · live-capture inbox |
| `webauthn_analyzer.html` | Import (paste JSON, or pick a capture) · Client Data · Authenticator Data · Attestation Object · COSE Key · Extensions · **Verify** · Raw |

Every artifact pane carries the Simple / Protocol / Raw toggle, and Raw offers Hex / Base64URL / JSON / CBOR / DER / PEM — which is in character for this debugger and is most of the educational value. The **Ceremony Trace** draws the timeline from request through user interaction to response, with the authenticator boundary and the unobservable CTAP layer marked explicitly.

Three new modules, factored the way `dpop.js` and `jwk_pem.js` are — no DOM, so `tests/` can drive them in Node against the specifications' own vectors:

* **`client/src/cbor.js`** — a decode-only, length-bounded CBOR reader. Nothing in this repository does CBOR today.
* **`client/src/cose.js`** — COSE_Key → JWK → SPKI → PEM, **reusing `jwk_pem.js`** rather than re-implementing the DER encoder.
* **`client/src/webauthn.js`** — `clientDataJSON`; `authenticatorData` (RP ID hash, flags UP/UV/BE/BS/AT/ED, sign count, AAGUID, attested credential data, extensions); attestation statements (`packed`, `tpm`, `android-key`, `apple`, `fido-u2f`, `none`); assertion verification; and the `toJSON` shim if Phase 0 says one is needed.

**Two traps that this repository has already paid for once.** No bare `require('crypto')`, no `jsonwebtoken`, no `jwk-to-pem` — browserify substitutes crypto-browserify and silently re-adds vulnerable `elliptic` to the bundle; `tests/jwk_pem_encoding.js` enforces this and will fail. And **ECDSA signatures arrive DER-encoded while Web Crypto wants raw `r‖s`**: getting that conversion wrong reports "signature invalid" for a perfectly valid signature, which is the single most common WebAuthn implementation bug and would be read here as a bug in the authenticator.

**AAGUID identification** ships as a curated `webauthn_aaguids.json` — offline, so it works on the static sites and in the test suite — labelled throughout as *metadata says*, never as *this is a YubiKey*. A bundled list goes stale silently, so it carries a generation date and a test fails when it is more than a year old.

## The mock STS side

`sts/` is the [`rcbj/mock-sts`](https://github.com/rcbj/mock-sts) **submodule**, so this is a separate pull request there plus a gitlink bump here, and it cannot ride in the same commit as the client work.

* **`GET /demo-rp`** — a small relying party running OIDC Authorization Code against the STS itself. This is the "third-party website" the extension observes, and it is what makes Mode 3 testable in CI.
* **A WebAuthn MFA step in the STS login** — after the existing password screen, `/oauth2/webauthn` registers on first use and asserts thereafter, verifies server-side, and reflects the result as `amr: ["pwd","hwk"]` with a stepped-up `acr`. That is the whole of the wiring to the OIDC workflow: the debugger's existing pages already decode `amr`/`acr`, so the chain becomes visible end to end with no new OIDC code.
* **A verifier written independently of `client/src/webauthn.js`.** The precedent is bbs-2023, where `tests/bbs2023_cryptosuite.js` checks the wallet's implementation against the STS's; two independent readings of one specification that agree is a far stronger result than one implementation agreeing with itself, and a shared library would destroy it. No new dependency in the submodule.

## Mocking the authenticator

Already available and verified in this checkout: **`tests/node_modules/selenium-webdriver@4.38.0` ships `lib/virtual_authenticator.js`**, and `WebDriver.prototype` carries `addVirtualAuthenticator`, `removeVirtualAuthenticator`, `addCredential`, `getCredentials`, `removeCredential` and `removeAllCredentials`. `Transport` is `{BLE, USB, NFC, INTERNAL}`; `Protocol` is `{CTAP2, 'ctap1/u2f'}`.

```js
const opts = new VirtualAuthenticatorOptions()
  .setProtocol(Protocol.CTAP2).setTransport(Transport.USB)
  .setHasResidentKey(true).setHasUserVerification(true).setIsUserVerified(true);
await driver.addVirtualAuthenticator(opts);
```

A WebDriver-standard command backed by Chrome's CDP WebAuthn domain: headless, deterministic, no hardware. **The knobs are what make negatives possible** — `setIsUserVerified(false)` yields a real assertion with UV clear, `removeAllCredentials()` yields the no-credential path, and `addCredential()` plants a known key so our verifier's verdict can be checked against a signature verified independently in Node. Geckodriver implements the same commands, so the Firefox extension becomes testable the same way later.

Physical YubiKeys cover what the virtual authenticator cannot: real attestation certificates, a real AAGUID, real transports, and an actual touch. Those are a documented manual checklist, not CI.

## Tests

**Positive.** (1) Lab registration decodes to exactly what the authenticator was configured to produce. (2) Lab assertion verifies, and the sign counter advances across two ceremonies. (3) A captured blob pasted into the analyzer decodes identically to the live pane. (4) COSE → JWK → PEM agrees with Node's `crypto.createPublicKey`, an implementation we do not control. (5) The STS accepts exactly the assertions the client calls valid. (6) End to end: extension loaded, mock RP driven through OIDC → STS login → WebAuthn MFA, and the debugger shows the request options *and* the response, with `hwk` in the ID token's `amr`.

**Negative**, each failing exactly one check, in the style of the SD-JWT VP negatives: (7) tampered `authenticatorData`; (8) tampered `clientDataJSON` — which proves the SHA-256 binding is really computed; (9) challenge mismatch; (10) origin mismatch; (11) RP ID hash mismatch; (12) an assertion whose **UV flag is clear** checked against a policy requiring user verification, which must be rejected **on the flag and not on the signature**; (13) sign-count regression flagged as possible cloning; (14) unknown attestation `fmt` reported as unverifiable rather than crashing; (15) an assertion for a credential the authenticator does not hold.

**Twelve and fifteen are analyzer tests, not browser tests, and Phase 0 is why.** With `userVerification: "required"` and an authenticator that cannot verify, the *browser* refuses the ceremony outright — the RP never receives a UV-clear assertion to reject, so the check cannot be exercised from the Lab page. The material has to be manufactured instead: `userVerification: "discouraged"` against `setHasUserVerification(false)` produces a genuine, correctly-signed assertion with UV clear (measured: `{"UP":true,"UV":false,…}`), which is then fed to a verifier configured to require it. Fifteen is the same shape — the browser answers a missing credential with the generic `NotAllowedError`, so there is nothing to decode.

**And that generic error is itself a UI requirement.** WebAuthn deliberately collapses "no such credential", "user declined" and "timed out" into one indistinguishable `NotAllowedError: The operation either timed out or was not allowed`, for privacy reasons. The debugger must **say** that rather than guess at a cause; a pane confidently reporting "user declined" when the credential simply was not present would be inventing information the browser refused to give.

**Structural.** The transparency test (extension changes nothing), the capture-contract test (both sides of the JSON agree), and a manifest test asserting the CI manifest is identical to the shipped one outside the permissions block.

Every negative is paired with the positive that differs in exactly one byte — a negative that would also pass against a verifier hard-coded to say "invalid" is worth nothing, which is the recurring failure `tests/CLAUDE.md` warns about.

## Constraints this repository imposes

**The landing page will not fit a ninth card as it stands.** Eight cards sit 4+4 and end at 571px; `tests/navigation.js` enforces a **640px budget** (a real browser's toolbar, which headless does not have) and asserts every card has its own `:nth-child(N) .landing-icon` accent. A ninth makes three rows at roughly 700px and fails. The fix is five across — `minmax(180px, 1fr)` in the 940px box gives 5+4 — and it must be measured rather than assumed.

**WebAuthn needs a secure context and the containerized origin is not one — but the flag the suite already sets is enough.** Measured on Chrome 121: at `http://client:3199` with no flag, `window.PublicKeyCredential` is **undefined** and `isSecureContext` is false; adding `--unsafely-treat-insecure-origin-as-secure` (with the `--user-data-dir` Chrome demands alongside it, both of which `browser_flags.js` already supplies) makes the origin secure and a full registration ceremony **succeeds**. So the WebAuthn pages need `addBrowserAccessFlags()` for the same reason every crypto page does, and nothing more.

**The single-label RP ID worry was unfounded.** `rpId: "client"` against origin `http://client:3199` completed normally on both Chrome 121 and 151, as did the dotted `client.test`. **No compose network alias is needed**, and the three compose files and the env config stay untouched — the contingency in the decisions table is retired rather than exercised. If a future browser tightens this, the alias remains the fallback.

**`tests/webauthn_*.js` matches none of the tests image's `COPY` wildcards** (`tests/oauth2_*`, `tests/oidc_*`, …). Without an explicit line the new tests *vanish from the image* rather than failing — the silent outcome that Dockerfile's own comments warn about.

**`extension/` becomes the third thing that must carry `VERSION`.** The client and api images already do; omit it and the build silently stamps `0.0.x`, which here would also poison the drift banner described above.

## Distribution

Unpacked and self-hosted, at least initially: the directory ships in-repo and users load it through Chrome's developer mode or Firefox's `about:debugging`. No signing keys, no review latency, and free iteration while the capture format settles. The costs are accepted knowingly — a rougher install, no auto-update (hence the version handshake), and **no third-party review of a `navigator.credentials` hook**, which is why the read-only invariant carries its own test rather than a promise. `extension/build.js` emits `dist/chrome/`, `dist/firefox/` and the CI variant from one shared `src/` and three manifest templates. Publishing to the Chrome Web Store and AMO stays possible and is deliberately deferred.

## Phase 0 results — measured 2026-08-08, Chrome 121.0.6167.85 and 151.0.7922.108

Run against a throwaway page on loopback, with the container's origin emulated by Chrome's `--host-resolver-rules=MAP client 127.0.0.1` — a faithful single-label, plain-HTTP, non-localhost origin without touching `/etc/hosts`, and reproducible on any machine with the pinned browser.

| Question | Answer on Chrome 121 (CI) | Answer on Chrome 151 |
|---|---|---|
| Does the secure-context flag unlock `navigator.credentials`, not just `crypto.subtle`? | **Yes** — ceremony OK at `http://client:3199` | Yes |
| Is a single-label `rpId` (`client`) usable? | **Yes**; `client.test` also works | Yes |
| Does `addVirtualAuthenticator` drive a ceremony under `--headless=new`? | **Yes** — ES256, `transports:["usb"]`, 764-byte attestation object, sign count increments | Yes |
| Does `PublicKeyCredential.toJSON()` exist? | **No**, nor `parseCreationOptionsFromJSON()` | Yes, both |

Negative-case knobs, also measured on 121: UV required with a verifying authenticator gives `{"UP":true,"UV":true,…}`; UV required with `setHasUserVerification(false)` is refused by the browser before the RP sees anything; UV discouraged with the same authenticator yields a valid assertion with `UV` clear; and `get()` for an absent credential fails with the generic `NotAllowedError` rather than hanging.

**Three hazards worth carrying into the implementation.** The JS bindings' `VirtualAuthenticatorOptions` setters **return `undefined`** — unlike the Java ones — so the idiomatic chained form silently yields `undefined` and the authenticator is never registered; the resulting failure is not "no authenticator" but `NotAllowedError: WebAuthn is not supported on sites with TLS certificate errors`, which sends you looking at certificates and origins instead of at the line above. Chrome inserts `other_keys_can_be_added_here` into `clientDataJSON` at random, so nothing may compare those bytes to a fixture. And the browser's privacy-preserving error collapsing means a failed ceremony carries no diagnosable cause.

**Cost of the phase:** four questions answered, one planning decision retired, one test (12) relocated from the browser to the analyzer where it can actually be produced, and one test (the transparency check) rewritten before it could flake. The rig is at `/tmp/wa-spike` with Chrome 121 already unpacked, and is disposable.

## Phase 1 results — 2026-08-08

`client/src/cbor.js`, `cose.js` and `webauthn.js` are written and `tests/webauthn_decode.js` covers them with 15 checks, all green. The vectors are real: ES256 and RS256, registration and assertion, produced by the virtual authenticator and committed as `tests/webauthn_vectors.json` so the test needs no browser, no network and no hardware.

**Two oracles, neither of them ours.** The browser's own `getPublicKey()` gives the SPKI DER for the key we independently derive from the attestation object's COSE, and the two are compared byte for byte; node's `crypto.verify` then checks the same signatures from the JWK our decoder produced. A decoder tested only against material its own author invented agrees with itself and with nobody.

**Mutation-tested where it counts.** Removing the DER→raw ECDSA conversion breaks every ES256 check while RS256 stays green — the exact signature of that bug — and it fails by returning `false` rather than throwing, which is why the module's header warns about it in those terms.

**A pre-existing hole found while wiring this in.** The tests image copies `tests/jwk_pem.js` and `client/src/jwk_pem.js` flat into the same directory, and the module's `COPY` runs second, so it silently **replaced the test**. Running it in that layout produces no output and exit 0, so the runner recorded the job as passed while executing nothing — meaning the elliptic scan, the only check that would catch a new page requiring `jwk-to-pem`, had not run in a containerized build. Fixed by renaming the test to `tests/jwk_pem_encoding.js`, the same remedy `metadata_schema_validation.js` already documents. The module keeps its name, because `cose.js` requires `./jwk_pem`.

## Phase 2 results — 2026-08-08

`client/public/webauthn_analyzer.html`, `client/src/webauthn_analyzer.js` and `css/webauthn.css`, driven by `tests/webauthn_analyzer_page.js`: seven sections, all green, against the same real ceremonies the decoder test uses.

**No `innerHTML` anywhere on the page.** Everything on it arrived by paste from a third party, so it is built entirely with `createElement` and `textContent` — a stronger guarantee than sanitising, and free, because none of these panes need rich content.

**The page keeps a registration's public key so a later assertion can be verified**, which is the only way an assertion pasted on its own can be checked at all. That storage needs no opt-out checkbox and is outside the root `CLAUDE.md` key-material rule: a WebAuthn private key never leaves the authenticator, so what is kept is a public key, the same class of thing as an IdP certificate.

**Three things this phase taught, all recorded in code comments where they matter.** A bug of exactly the kind this workflow is meant to expose: the stored-key lookup read the credential id off the *inner* `response` member, which does not carry one, so the page reported "cannot verify" for a credential whose key it was holding — fixed, and the comment names the confusion. The layout bound from the SD-JWT VC pages applies here verbatim and is asserted (`table-layout: fixed`, `overflow-wrap: anywhere`, and no `code { white-space: nowrap }`), measured with an **RSA modulus** loaded, since that is the longest unbreakable string the page will ever hold — worst overhang 0px. And adding a page means editing **two** bundle lists: `client/build.js` for the static build and a `RUN browserify` line in `client/Dockerfile` for the image. Miss the second and the containerized page's script 404s while the static site is perfectly fine.

**Named `webauthn_analyzer_page.js`, not `webauthn_analyzer.js`** — the same flat-copy collision that had silently disabled the `jwk_pem` job.

## Phase 3 results — 2026-08-08

`client/public/webauthn.html` + `client/src/webauthn_lab.js`, the ninth landing card, and the grid rework. Eight sections in `tests/webauthn_lab_page.js`, all green: capabilities, a real registration decoded, the ceremony trace, an assertion verified against the key from that registration, **the sign counter advancing across two assertions**, the no-credential path reported rather than hung, the layout bound, and no console errors.

**The decode panes moved to `client/src/webauthn_panes.js`**, shared by the Lab and the Analyzer. Those two differ only in where the bytes came from, so a flags table that disagreed between them would be a bug visible solely by comparing the pages. The panes stay out of `webauthn.js`, which has no DOM in it — that is what lets the node test drive the decoding and verification with no browser at all.

**The landing page needed real measurement, three times.** Nine cards at the old `minmax(205px, 1fr)` is 4+4+1 across three rows ending at **762px** against a 625px viewport. Five columns need `min <= 175.2` (5×175 + 4×16 = 939 in the 940px box), and 175px is the widest that works — 180px silently stayed at four, with height as the only symptom. Widening the container is not available: the grid sits inside bootstrap's 940px `.container`. That got it to 633px, still 8px over; trimming the icon from 48px to 40px bought back 16px, because an icon costs its height **once per row**. 44px landed on exactly 625px, which passes and is still wrong — this suite has already lost a run to an 8px difference that appeared only in the container, where `fonts-liberation` gives different metrics from a host's Arial. Final: **617px of 625px**, rows [5, 4]. No card's copy was touched; shortening someone else's product text to fit a layout is the tail wagging the dog.

**`STYLED_PREFIXES` in `tests/navigation.js` now includes `wa-` and `wl-`.** It did not, so the stylesheet check would have inspected these two pages and silently found nothing to inspect — the shape of failure that file exists to prevent.

## Phase 4 progress — 2026-08-08

**Done: the verifier, and the cross-check that justifies it.** `mock-sts/webauthn.js` implements sections 7.1 and 7.2 server-side — its own CBOR reader, its own COSE mapping, node's `crypto.verify` — sharing no code with the client's decoder. `tests/webauthn_cross_impl.js` runs both over the same real ceremonies and requires the same verdict: **5 checks, all green**. They agree on the registration member for member (format, AAGUID, credential ID, sign count, and the public key JWK), accept the same valid ES256 and RS256 assertions, reject the same tampered one **naming the same failing check and nothing else**, treat the UV-clear assertion identically (both refuse it when UV is required, both still report the signature as valid, both accept it when UV is not), and reject challenge, origin and RP ID mismatches by the same names.

The independence is real rather than nominal: node takes an ECDSA signature in its native **DER** form, while the browser side must convert to raw `r‖s` because Web Crypto refuses DER. Those are different code paths, so an error in one is not mirrored in the other — which is the entire point, and the same arrangement `tests/bbs2023_cryptosuite.js` established for bbs-2023.

**A sequencing constraint, because getting it wrong breaks the image build.** `sts/` is a submodule and the new module currently exists only in the sibling development clone. `COPY sts/webauthn.js` in `tests/Dockerfile` would fail with `COPY sts/webauthn.js: not found` — the same opaque failure an uninitialised submodule gives. So **three things must land together with the gitlink bump, and not before**: that COPY (renamed to `sts_webauthn.js`, since the basename collides with the client's), the `tests/webauthn_cross_impl.js` COPY, and the run-report job. Until then the test runs in a checkout, where it finds the module in the sibling clone — and it **logs which of the three locations it loaded from**, because running against a stale submodule while editing the clone would otherwise look exactly like a pass.

**Also done: the MFA step, and the whole OIDC chain proved end to end.** The second factor lives in `oauth2.js` rather than a module of its own, because it is a step *in the login flow* and needs `pendingLogins` and `sessions` — reaching for those from elsewhere is the import cycle this service's split exists to avoid. `acr_values` naming `mfa`/`hwk`/`phr` forces the step and **disables the opt-out**, so a relying party's demand for step-up cannot be answered with a password. Driven against the virtual authenticator, five things hold: the checkbox is forced and locked; a first sign-in enrols and completes; the ID token carries `amr: ["pwd","hwk"]` with `acr: "mfa"`; a second sign-in asserts with the enrolled key rather than enrolling again; and a password-only sign-in reports `amr: ["pwd"]` with `acr: "1"` — the negative that makes the positive mean something, since a service that always claimed `hwk` would pass every other check here.

The session is deliberately **not** created after the password step. A session made there and upgraded later is a valid single-factor session in the window between, and an authorization request arriving in that window would be answered with tokens claiming one factor's assurance and carrying none of the second's.

**Two bugs worth recording, because both failed silently.** The ceremony script was inline at first, and this service sets `script-src 'none'` on every response by design — so the button did nothing, with no error anywhere. It is now a separate resource (`/oauth2/webauthn.js`) and exactly one response relaxes the policy, to `'self'` rather than `'unsafe-inline'`, so the exception is a named file rather than a hole. And the inline version's base64url helpers passed through a JavaScript string literal on the way out, where `\+` collapses to `+` and `\/` to `/` — the delivered script contained `/+/g` and `///g`. The replacement uses `split`/`join`, which has nothing to escape.

**Also done: `tests/webauthn_oidc_mfa.js`,** six sections, green — and green **twice in a row against the same running STS**, which is the part worth stating. The first version was not: the STS remembers enrolled keys per username for the life of its process while a virtual authenticator lives only as long as the browser session, so a re-run was told to assert with a key that browser had never held and failed with the browser's deliberately ambiguous `NotAllowedError`. CI starts the service fresh and would never have shown it. A username unique per run fixes it, and the comment says why — a test that passes only against a pristine service is one nobody can re-run while debugging it.

The console-error assertion filters exactly two 404s **by name**: the browser's unbidden `/favicon.ico`, and the redirect sink, which is a path nothing serves on purpose because this test is the relying party and reads the code off the URL. A filter broad enough to swallow a real error would make the assertion decorative.

**Deferred to Phase 5:** the `/demo-rp` relying party. It is the extension's target rather than this phase's — the MFA chain is already exercised end to end without it — so it belongs with the work that needs it.

## Phase 5 results — 2026-08-08

`extension/` — the MAIN-world shim, an isolated-world relay, a background worker owning the arm/disarm ladder, a bridge on the debugger's origins, and a popup that does the arming (the browser requires that gesture to be in the extension's own UI). `build.js` emits `dist/chrome`, `dist/firefox` and `dist/ci`. `tests/webauthn_extension.js` covers it in eight sections, all green, including the Analyzer's capture inbox.

**Read-only is now a measurement.** The same ceremony runs with the extension loaded and without, and the two must agree on flags, `clientData.type`/`origin`/`crossOrigin` and algorithm — deliberately *not* on clientDataJSON bytes, since Chrome randomises a filler member there precisely to defeat that comparison. And the CI build is compared to the shipped one file by file: the only permitted difference is a bundled `autoarm.json` plus its host permission, because a test-only bypass inside the arm path would mean CI exercising code users never run.

**The finding that cost most of the phase: this test cannot run against branded Google Chrome.** That build refuses to side-load an unpacked extension — `--disable-extensions-except is not allowed in Google Chrome, ignoring`, on stderr only — so the extension is simply absent and every capture assertion times out with nothing naming the cause. Chrome for Testing (what the image pins) and Chromium both allow it. A second, independent cause compounds it: **chromedriver passes `--disable-extensions` among its default switches**, which cancels `--load-extension` on its own, so `excludeSwitches("disable-extensions")` is required too. The test now asserts the extension is *loaded* before asserting anything about captures, so that failure names itself.

**Three bugs the inbox found, all of which had been silently sitting there.** A refused ceremony's envelope has `response: null`, and `analyze()` read through it — a TypeError that emptied every pane, which is the worst possible rendering of "the ceremony failed", and precisely the case this format calls first-class. The shared-panes refactor took `table()` and `row()` with it while `renderRequest` kept calling them, so "What the relying party asked for" threw `ReferenceError` — unnoticed because that pane fills *only* for an extension capture, and nothing exercised one until the inbox existed. **A pane no test opens is a pane that is broken.** And the drift warning compared two independently-stamped build numbers, so it fired on every matched build; it now checks the **capture format version**, which is the thing that would actually break, and merely *displays* the build.

**Wiring.** `buildBrowserExtension()` in `common/common.sh`, called by all three launchers beside `renderWaltidConfig` — same reason: generated per run, and the CI build has to bake in the origin the browser will see the STS on, which differs between the containerized stack and a host run. `tests/Dockerfile` COPYs `extension/dist/ci`; `.gitignore` ignores `extension/dist`; `.dockerignore` deliberately does **not**, with a comment saying so, because excluding it by analogy with `client/dist` would break that COPY.

## Phases

| Phase | Work | Exit criterion |
|---|---|---|
| **0** | Spikes, throwaway code | **DONE 2026-08-08** — see *Phase 0 results* above |
| **1** | `cbor.js`, `cose.js`, `webauthn.js`; `tests/webauthn_decode.js` in Node | **DONE 2026-08-08** — 15 checks green against real ES256/RS256 ceremonies, verified against both the browser's `getPublicKey()` and node's crypto; `tests/jwk_pem_encoding.js` still passes |
| **2** | Analyzer page | **DONE 2026-08-08** — 7 sections green driving the real page against real ceremonies, including the layout bound; the YubiKey pass stays on the Phase 6 hardware checklist |
| **3** | Lab page, ninth card, grid rework | **DONE 2026-08-08** — 8 sections green driving real ceremonies; `navigation.js` reports 9 cards in rows of [5, 4] ending at 617px of 625px |
| **4** | Mock STS (separate PR + gitlink bump) | **DONE 2026-08-08** — verifier cross-checked (5/5) and `tests/webauthn_oidc_mfa.js` green (6/6), twice in a row against a live service; the `/demo-rp` page is deferred to Phase 5, where the extension needs it |
| **5** | Chrome extension | **DONE 2026-08-08** — 8 sections green: capture, request half, inbox, disarm-from-page, build-difference and transparency |
| **6** | Firefox extension, hardware checklist | **PARTIAL 2026-08-08** — the checklist is written (`docs/webauthn.md`); Firefox installs but its content scripts do not run under automation, cause not isolated, so Firefox support is **unverified** |

Phase 0 was deliberately first and deliberately disposable: three of its four questions could each have invalidated a later phase, the worst case being a Chrome 121 that could not drive a virtual authenticator headlessly — where the choices would have narrowed to bumping the image's Chrome, which `tests/CLAUDE.md` records as load-bearing for old-versus-new headless behaviour, or dropping WebAuthn from the containerized job. None of that came to pass; the only casualty is `toJSON()`, which costs a shim.

## Decisions already taken

| Decision | Choice | Why |
|---|---|---|
| Extension capability | **Observe only** | Initiating for an arbitrary RP ID ships a phishing-resistance bypass; observation loses nothing for the intended use |
| STS verification | **Hand-rolled, independent** | Two independent readings that agree is the strong result; matches the bbs-2023 precedent; no new submodule dependency |
| AAGUID | **Bundled curated list** | Works offline and on the static sites; labelled as metadata, not fact |
| Container origin | **No change needed** — retired by the Phase 0 measurement | `rpId: "client"` works on Chrome 121 under the flag `browser_flags.js` already sets; the alias stays documented as a fallback |
| Distribution | **Unpacked / self-hosted first** | No review latency while the format settles; manifest kept store-ready |
