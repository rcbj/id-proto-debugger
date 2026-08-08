# WebAuthn — the Lab, the Analyzer, and the read-only observer

Three ways into one protocol, and the difference between them is only ever *where the bytes came from*:

| | Page | Needs |
|---|---|---|
| **Lab** | `webauthn.html` | a secure context and an authenticator. This origin is the relying party, so the ceremony is real and so are the artifacts. |
| **Analyzer** | `webauthn_analyzer.html` | nothing. It decodes and verifies bytes you already have, from any relying party, with no ceremony, no authenticator and no secure context. |
| **Observer** | the browser extension | itself, armed for one origin. Watches a ceremony belonging to somebody else's site and hands the artifacts to the Analyzer. |

Because they differ only in provenance, the decode panes are one implementation (`client/src/webauthn_panes.js`); a flags table that disagreed between the pages would be a bug visible only by comparing them.

## The boundary, which decides the shape of everything else

The browser is a mediator, not a pipe. JavaScript receives a ceremony's *artifacts* and never the authenticator: no private key, no PIN, no biometric, no authenticator state, and **no CTAP** — not the commands, not the USB frames, not the PIN protocol. This is a WebAuthn debugger and not a CTAP debugger, and the Ceremony Trace says so rather than leaving somebody hunting for a pane that cannot exist. A real CTAP debugger needs a native application with HID access; that is a different project.

Two consequences the pages state out loud:

* **The RP ID is not a free field.** WebAuthn binds a ceremony to the calling origin: the RP ID must be this page's host or a registrable parent of it. The Lab cannot run a ceremony for a domain it does not own, and that refusal *is* the phishing resistance. Debugging somebody else's relying party is the Analyzer's job, or the observer's.
* **A failed ceremony carries no diagnosable cause.** WebAuthn deliberately collapses "no matching credential", "the user declined" and "it timed out" into one `NotAllowedError`, for privacy. The pages say that instead of guessing which happened.

## The modules

`cbor.js` is a decode-only, bounded CBOR reader (RFC 8949). Maps decode to a **`Map`**, because COSE is keyed by integers including negative ones and collapsing those to object keys makes `1` and `"1"` the same thing. Indefinite lengths are refused: CTAP2's canonical CBOR forbids them, so one in an attestation object is a finding rather than something to absorb. `decodeFirst()` exists because the credential public key sits mid-buffer inside the authenticator data, with the extension data behind it.

`cose.js` maps COSE_Key → JWK → SPKI PEM, **reusing `jwk_pem.js`** rather than re-encoding DER — which is also why nothing here pulls in `elliptic`. It reads the negative labels per key type, because `-1` is the curve for an EC2 key and the modulus for an RSA one; read it without knowing `kty` first and a modulus decodes as a curve identifier.

`webauthn.js` has no DOM in it, which is what lets `tests/webauthn_decode.js` drive the decoding and verification in node against real ceremonies, with no browser and no chance of flaking. Three things in it have bitten every implementation ever written:

* **ECDSA signatures arrive DER-encoded and Web Crypto wants raw `r‖s`.** Hand it the DER and `verify` returns **false** — not an error — so a valid signature reads as a faulty authenticator. (Node's `crypto.verify` takes DER natively, which is why the STS's independent verifier needs no conversion and the browser's does.)
* **The signed message is `authenticatorData ‖ SHA-256(clientDataJSON)`** — the hash of the client data, and the *raw* authenticator data, not a re-encoding of the parsed fields.
* **clientDataJSON must be parsed, never compared.** Chrome inserts `other_keys_can_be_added_here` into some ceremonies and not others, at random, specifically to break implementations that compare it against a template.

## The observer, and what read-only means

The extension wraps `navigator.credentials.create`/`.get` in the page's own world, lets the call through untouched, and copies what passed. It **will not** name an RP ID it does not own: an extension that could would be a working defeat of WebAuthn's phishing resistance, and declining that is deliberate.

Four rules make read-only true rather than intended, and they are in `extension/src/shim.js` at the points they matter:

1. **No mutation** — capture works on a `structuredClone`.
2. **No origination, and no other patches** — `store()` and `preventSilentAccess()` stay alone.
3. **Exception transparency** — every failure inside capture is caught and dropped. A site's ceremony must never fail *because the debugger was watching*.
4. **No `await` before calling through.** `get()` consumes transient user activation, which is time-bounded; a shim that awaited anything first could let it lapse, and the site would see a `NotAllowedError` indistinguishable from a decline. Whether an origin is observed is decided by **not injecting the shim**, never by a check inside it.

`tests/webauthn_extension.js` proves the fourth claim rather than asserting it: the same ceremony runs with and without the extension, and the two must agree on flags, `clientData.type`/`origin`/`crossOrigin` and algorithm — deliberately *not* on clientDataJSON bytes.

**Arming, not installing, is the boundary.** A fresh install holds host permissions for the debugger's own origins and nothing else, and injects nothing anywhere. Observation is per-origin, visible (badge and popup), and on a clock: 30 minutes, cleared on browser restart, cleared when the Analyzer's *Done — stop observing* is pressed, and removable entirely through `management.uninstallSelf()` behind the browser's own dialog. Arming can only happen in the extension's popup, because `permissions.request()` requires a gesture there — a web page must not be able to talk a browser into watching another origin.

## Hazards, all of them measured

**Branded Google Chrome will not side-load an unpacked extension.** It refuses the flags and says so only on stderr (`--disable-extensions-except is not allowed in Google Chrome, ignoring`), after which the extension is simply absent and every assertion times out naming nothing. Chrome for Testing (what the tests image pins) and Chromium allow it. Independently, **chromedriver passes `--disable-extensions` among its default switches**, which cancels `--load-extension` on its own — `excludeSwitches("disable-extensions")` is required too.

**Selenium's `VirtualAuthenticatorOptions` setters return `undefined`** in the JS bindings, unlike the Java ones, so they cannot be chained. The resulting failure is not "no authenticator" but `NotAllowedError: WebAuthn is not supported on sites with TLS certificate errors`, which sends you hunting through origins and certificates.

**The containerized origin is not a secure context**, and WebAuthn does not degrade there — `PublicKeyCredential` is undefined. `browser_flags.js` already relaxes it, and that is enough: a full ceremony succeeds afterwards, single-label RP ID (`client`) included.

**`PublicKeyCredential.toJSON()` is absent from Chrome 121** (present on 151), so the Level 3 JSON form is produced by our own code, unconditionally, rather than depended on — a browser-dependent path would mean CI exercising something users do not.

## Manual verification — the part CI cannot do

Two things need a human, and neither is a substitute for the automated suite.

**A real authenticator.** The virtual authenticator is deterministic and headless, which is exactly why it cannot cover attestation from a real device. With a YubiKey:

1. Lab → Registration with **attestation: direct**. Confirm the attestation object carries `fmt: packed` with an `x5c` chain and a **real AAGUID** (not the virtual authenticator's `01020304-…`), and that the AAGUID lookup names a plausible device — as *metadata says*, never as fact.
2. Confirm **transports** report what the key actually is (`usb`, `nfc`), and that touching the key is genuinely required.
3. Authentication → Get Assertion & Verify, and confirm the verdict is VALID with the sign counter advancing between two assertions.
4. Set **user verification: required** and confirm the key asks for its PIN, and that UV comes back set.
5. Open the same artifacts in the Analyzer and confirm they decode identically.

**A real third-party relying party.** Install the extension, arm it for a site you have an account with (Keycloak, Entra ID, Okta, GitHub), and sign in with the key. Confirm the Analyzer's inbox shows the **request options that site sent** — the half it never displays — and that the sign-in behaves exactly as it does with the extension disarmed.

**Firefox is manual for now.** The `dist/firefox` build installs as a temporary add-on (`installAddon` returns its id) but its content scripts did not run under automation, and the cause is not yet isolated — the likeliest candidate is that Firefox MV3 treats `host_permissions` as opt-in rather than granting them at install, which would mean the extension is inert until the user allows the site. Setting `extensions.originControls.grantByDefault` did not change it, so that is a hypothesis and not a finding. Until somebody loads it through `about:debugging` and grants permissions by hand, **Firefox support is unverified** and should be described that way. One property is already in our favour there: a Firefox temporary add-on is removed when the browser restarts, so the hook cannot survive into the next session at all.
