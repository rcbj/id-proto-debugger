# Kerberos v5 Debugger — design and implementation plan

**Status: phases 0–5 are implemented. The workflow's own notes are now [`docs/kerberos.md`](kerberos.md) — read that first.** What remains here is the record of how each decision was reached and what is still outstanding. Dated 2026-08-12 and revised as each phase landed; it is written in the same voice as the rest of `docs/` — the reasoning attached to each decision, so the decision can be argued with later — so every "does" below should be read as "will do".

**What is left**: SPNEGO (phase 6, deliberately out of scope for this plan), kpasswd, SID filtering across a trust, and — the largest risk in the feature — **interoperability evidence against a real domain controller**. Everything built so far has been verified against this project's own mock KDC, which is not the same thing as being correct. See the last section of `docs/kerberos.md`.

## What this adds

A tenth protocol workflow: a **Kerberos v5 debugger** that performs the AS exchange, the TGS exchange and the AP exchange against a real Key Distribution Center — an Active Directory domain controller, an MIT or Heimdal KDC, or the mock KDC added to `mock-sts` by this plan — and shows every field of every message on the way past. Plus a **Kerberos decoder** page that parses tickets, KDC messages, GSS-API tokens, keytabs and the Windows PAC out of pasted bytes.

The motivating case is the one that is hardest to debug from anything else: *get a TGT from a domain controller, get a service ticket for a named SPN, present it to a Windows service, and see why the service said no.* Everything the tool does is arranged around making the failure legible, because in Kerberos the failure is almost never legible — a one-byte DER mistake, a wrong key-usage number and a genuinely wrong password all surface as the same integrity-check error.

## Scope, stated first because it decides everything else

**This is not an HTTP protocol.** Every other workflow in this repository runs in the browser and talks to the network through the browser, which is why the deployed static sites work at all. Kerberos speaks DER-encoded messages over TCP and UDP port 88 to a KDC that is usually not on the public internet, and a browser cannot open a TCP socket. So:

* **The feature exists only where `api/` exists.** It is absent from `idptools.com` and every other static deployment, and the landing page must say so on the card rather than letting a visitor discover it by clicking through to a page whose buttons all fail. This is the first workflow with that property; `infra/CLAUDE.md`'s Lambda@Edge trick rescued WS-Federation and SAML from the same problem, and it cannot rescue this one — there is no HTTP request to catch.
* **The one exception is the decoder.** Parsing a pasted ticket is arithmetic over bytes and needs no network at all, so `kerberos_decoder.html` ships to the static sites like the analyzer and the encoding tools do. Building it first also means the rest of the feature has a working microscope from day one.

**SPNEGO is out of scope for this plan** and is deliberately the next thing after it. It is easier, because the transport is HTTP and the browser can do most of it; it is a wrapper (RFC 4178 negotiation token) around the AP-REQ that phase 3 already produces. The only obligation this plan carries is to keep that seam clean: the GSS layer must be a separate module from the HTTP-facing code on both the client and the acceptor sides, so SPNEGO is a wrapper rather than a rewrite.

## Non-goals, and why

**No NTLM, no CredSSP, no PKINIT, no FAST, no kadmin, no DES.** Each is a defensible future phase and none belongs in the first one. DES is the exception that will never come back — Windows Server 2025 removed it — so it is decode-only, present so that a capture from an old estate still renders.

**The API's Kerberos endpoint is not a general TCP proxy.** See *The relay, and the security work it forces*. This is the single most consequential design constraint in the feature and the easiest one to lose during implementation, because "just send these bytes to that host" is the shortest thing to write.

**The tool does not crack anything.** The mock KDC includes a principal configured without pre-authentication, because the pre-auth round trip cannot be explained without showing both halves of it, and a client must handle a KDC that skips it. That is protocol behaviour and it is documented as such. The tool has no password list, no batching and no wordlist input, and the rate limiting described below exists partly so that a hosted instance cannot be turned into one.

---

## The finding that shapes the architecture

**There is no Node module that implements Kerberos without depending on the operating system.** This was checked rather than assumed, on 2026-08-12:

| Package | What it actually is | Verdict |
|---|---|---|
| [`kerberos`](https://www.npmjs.com/package/kerberos) (MongoDB, v7) | native addon over MIT GSSAPI / Windows SSPI | needs `krb5.conf`, a keytab and a credential cache — OS-dependent |
| [`krb5`](https://github.com/adaltas/node-krb5) / `node-krb5` (adaltas, ibmruntimes) | native binding to `libkrb5`, essentially `kinit` | same |
| `node-rs-krb5` | prebuilt *Rust binding* — still wraps MIT krb5 | same |
| [`auth0/node-kerberos-server`](https://deepwiki.com/auth0/node-kerberos-server) | Windows-only, shells out to a .NET process | worse |
| [`Kerberos-JS-Module`](https://github.com/YJDoc2/Kerberos-JS-Module) | a teaching model of the concepts; not RFC 4120 DER on the wire | not interoperable with any real KDC |
| `@kneel/krb5` | a real TypeScript AS/TGS/SPNEGO implementation ([write-up](https://thepotato.tech/posts/kerberos-in-typescript/)) | published to a private registry, not npm — proof the job is tractable, not a dependency that can be taken |

The only mature OS-independent implementation in any language with a browser-capable target is **[Devolutions `sspi-rs`](https://github.com/Devolutions/sspi-rs)** — pure Rust Kerberos, NTLM, SPNEGO and CredSSP, compiled to WASM for the IronRDP web client and driven through a KDC proxy. It is rejected anyway, for a reason that is about this product rather than about the library: its interface is SSPI-shaped, `InitializeSecurityContext` in and an opaque token out. **A debugger's entire product is the fields.** Wrapping an implementation that hides them would leave the tool able to say "authentication succeeded" and nothing else, which is the one answer nobody needs. It would also put a Rust toolchain and `wasm-pack` into a build that has never needed one.

So Kerberos v5 gets written in JavaScript, here. That is the same call already made for `client/src/xmldsig.js` (XML-DSig signing, verification and encryption in the browser) and for `client/src/jose_jwe.js`, and for the same reason.

---

## Architecture: the protocol runs in the browser

```
  browser                                    api/                     network
  ┌───────────────────────────────┐        ┌──────────────┐
  │ common/krb5/*                 │        │ POST /krb5/  │
  │  DER · messages · RFC 3961    │ b64    │   kdc        │  TCP:88   ┌───────────┐
  │  crypto · PAC · ccache        ├───────►│              ├──────────►│ mock KDC  │
  │                               │  DER   │ address+port │  UDP:88   │ (mock-sts)│
  │ WebCrypto: AES-CBC, PBKDF2,   │◄───────┤ policy       │◄──────────┤           │
  │   HMAC-SHA1/256/384           │        │ TCP framing  │  KKDCP    │ or a real │
  │ JS: CTS, n-fold, RC4, MD4     │        │ size cap     │  (https)  │  AD DC /  │
  └───────────────────────────────┘        │ timings      │           │  MIT krb5 │
         password never leaves here        └──────────────┘           └───────────┘
```

Everything protocol-shaped happens in the browser. The API frames, guards, times and relays; it holds no state, derives no keys and never sees a password. Three things follow, and they are the argument for this shape over the obvious alternative:

* **One codec, not two.** The decoder page, the live workflow and the test suite all load `common/krb5/`, the way `tests/module_paths.js` already loads shared client modules. Protocol-aware API endpoints (`POST /krb5/as`, `/krb5/tgs`) would need a second implementation in `api/`, and two codecs drift.
* **The credential stays put.** The API already proxies token calls with client secrets in them, so shipping a password would not be unprecedented — but it would be avoidable, and an unavoidable-looking design decision is worth the paragraph that explains it was a choice.
* **The panes can be honest.** A pane that says "this is what went on the wire" is telling the truth only if the page produced those bytes.

The cost is that the relay is a broader primitive than an HTTP fetcher, which is the next section.

---

## The relay, and the security work it forces

`api/ssrf_guard.js` is installed **on the shared axios instance** — a request interceptor plus `lookup` and `createConnection` hooks on the outbound agents. A `net.connect(port, host)` to a caller-named KDC walks past every layer of it. This is not a small addition to an existing guard; it is a second, parallel guard for a transport the existing one has never seen.

* **Reuse the decision, not the plumbing.** `toAddress()` and `blockedRangeFor()` become exported, and the socket path resolves the hostname itself and then **connects to the resolved literal**, so the DNS-rebinding window is as narrow on this path as on the HTTP one. `blockPrivateNetworkCalls` and `blockedAddressRanges` govern both, with the same rule that only an explicit `false` disables the first — and the same consequence that `local.js` and `docker-tests.js` must keep it off, since the mock KDC is a private address by definition.
* **A port allowlist is new, and necessary.** An HTTP fetcher aimed at port 22 gets nothing; a byte relay aimed at port 22 is a port scanner with a payload. A new setting — default `[88, 464, 749]`, Kerberos, kpasswd and kadmin — bounds it. Written as a list of ports, resolved by the same kind of validator as the other six settings, and logged at startup with its units like they are.
* **The payload must parse as Kerberos before a socket opens.** The relay decodes far enough to assert an `AS-REQ`, `TGS-REQ` or `AP-REQ` application tag and a plausible length. This is what keeps the endpoint from being a general-purpose tunnel: an arbitrary byte string is refused with a 400 that names why.
* **The TCP length prefix is attacker-controlled in both directions.** Outbound, the four-byte big-endian prefix is computed here, not taken from the caller; RFC 4120 reserves the high bit, so a reply claiming it is refused. Inbound, a KDC can announce four gigabytes; `maxContentLength`'s intent applies and the read is capped and abandoned incrementally, not measured after the fact.
* **`connectionTimeout` and `callTimeout` apply, and `connect_timeout.js` already has the socket-level pattern** — arm on connect initiation, disarm on `connect`. There is no TLS here except on the KKDCP path, which rides the existing guarded axios agents and therefore gets the `secureConnect` handling for free.
* **The handler must answer on the no-response branch.** `api/CLAUDE.md` records that this was wrong in three handlers and made every network-level failure a hang. For this endpoint, network-level failure is not the rare case — it is the *common* case, because the whole point is pointing it at a host that may not be there.
* **Rate limiting, which nothing else here has needed.** An endpoint that will send an AS-REQ to any KDC named by its caller is, if it is ever hosted publicly, a pre-authentication guessing relay running from somebody else's IP address. Today that is hypothetical — the static deployments have no API — and the mitigation is cheap: a per-source and per-target-realm rate limit, off by default in `local.js`, on wherever `blockPrivateNetworkCalls` is on. Whoever first deploys an API to the internet must read this paragraph, which is why it is here rather than in a ticket.

**MS-KKDCP (the KDC Proxy) is nearly free** once the codec exists: an HTTPS POST of the same framed message to `/KdcProxy`, wrapped in a small DER envelope. It goes through the existing guarded axios path with no new socket policy at all, and it is how a domain controller behind a firewall gets reached in practice. Worth doing in phase 2 rather than treating as an extra.

---

## `common/krb5/` — the codec and the crypto

| Module | Contents | Rough size |
|---|---|---|
| `asn1.js` | DER for Kerberos's grammar: `[APPLICATION n] SEQUENCE` wrappers, context tags on every field, `GeneralString`, `KerberosTime`, `KerberosFlags` as a `BIT STRING`. `asn1js` is already a client dependency; whether it earns its place here against a purpose-built coder is a **phase 0 decision**, not a guess made now. | 400–700 |
| `messages.js` | `AS-REQ`/`AS-REP`, `TGS-REQ`/`TGS-REP`, `AP-REQ`/`AP-REP`, `KRB-ERROR`, `Ticket`, `EncTicketPart`, `Authenticator`, `PA-DATA`, `PA-ENC-TIMESTAMP`, `ETYPE-INFO2`, `KRB-CRED`, `PrincipalName` | 800–1200 |
| `crypto.js` | The RFC 3961 framework: **n-fold**, DR/DK derivation, the encrypt/decrypt/checksum profile, and the key-usage table | 500–800 |
| `etypes/` | 17 and 18 (RFC 3962, AES-CTS-HMAC-SHA1-96), 19 and 20 (RFC 8009, AES-CTS-HMAC-SHA2), 23 (RFC 4757, arcfour-hmac-md5) | 400–600 |
| `gss.js` | RFC 4121: the InitialContextToken framing, the 0x8003 checksum, `Wrap` and `GetMIC` | 300–500 |
| `pac.js` | MS-PAC: the buffer table, an NDR reader, `KERB_VALIDATION_INFO`, UPN/DNS info, client info, the signature set | 600–1000 |
| `ccache.js` | The in-memory cache, a `klist`-shaped projection for the UI, and MIT ccache / keytab import and export | 300 |

### What the runtime does not give you

Measured on this checkout's Node 22.13:

```
cts ciphers: []            ← no CTS mode anywhere
rc4:         []            ← OpenSSL 3 moved it to the legacy provider
md4:         unsupported   ← needed for the NT hash behind etype 23
md5:         OK
```

So three primitives are written by hand, and the browser is in the same position:

* **Ciphertext stealing over `aes-256-cbc`.** RFC 3962 uses CBC with ciphertext stealing for the last two blocks, equivalent to CBC-CS3. Two cases are where implementations go wrong and both need a test of their own: when the plaintext length is an exact multiple of the block size the transformation degenerates to **plain CBC with the last two ciphertext blocks swapped**, and when the plaintext is one block or shorter nothing is swapped at all.
* **RC4 (~30 lines) and MD4 (~80 lines)**, if etype 23 is in scope. RC4-HMAC's string-to-key is `MD4(UTF-16LE(password))` — the NT hash, **unsalted**, which is why salt discovery matters only for AES and why this etype behaves so differently under offline attack.
* Everything else is available: PBKDF2-HMAC-SHA1/256/384, HMAC, AES-CBC, MD5, in both `node:crypto` and WebCrypto, behind the same thin adapter `bbs.js` and `jose_jwe.js` already use.

### Four traps to write down before they cost a day each

* **Key usage numbers.** Every encryption in Kerberos is keyed by a usage number (RFC 4120 §7.5.1) folded into the derivation: 1 for the PA-ENC-TIMESTAMP, 2 for the ticket's enc-part, 3 for the AS-REP enc-part under the client key, 7 and 11 for the TGS and AP authenticators, and so on. The right key, the right cipher and the wrong usage produce an integrity failure that names nothing. The table lives in `crypto.js` with the section reference beside it, and no call site passes a literal.
* **The AS-REP enc-part tag.** RFC 4120 records that implementations exist which tag the AS-REP's encrypted part as `EncTGSRepPart` rather than `EncASRepPart`. A client must accept either, and one that does not fails against real deployments while passing every test against its own mock.
* **The salt is not guessable and must come from `ETYPE-INFO2`.** Active Directory's default salt for a user is the realm concatenated with the sAMAccountName, but for a *computer* account it is realm + `host` + short name + lowercase DNS domain. Guessing it works until the first machine account. This is why the pre-authentication round trip below is load-bearing rather than a nicety.
* **A confounder precedes the plaintext in every etype.** Forgetting it produces plaintext that decrypts to garbage of exactly the right length.

---

## Windows compatibility: what is actually different

The protocol core is the same protocol. "Get a TGT from a domain controller and present a ticket to a Windows service" *is* AS + TGS + AP, and there is no Windows-only exchange. The delta is perhaps a quarter to a third more work, concentrated in five places:

1. **The PAC**, and it is the largest single item. The AS-REP's ticket carries `AD-IF-RELEVANT → AD-WIN2K-PAC`, and that structure — not anything in the Kerberos ticket proper — is what a Windows service reads to learn the user's group SIDs. It is NDR-encoded, so decoding `KERB_VALIDATION_INFO` means writing a small NDR reader; nothing in vanilla Kerberos prepares an implementer for that. Its signature set is worth rendering in full: the server checksum under the service key, the KDC checksum under the krbtgt key, and the ticket and extended-KDC signatures added by the 2022 hardening, because "which signature failed" is the whole answer when a service rejects a ticket. `PA-PAC-REQUEST` toggles inclusion, and being able to ask for a ticket *without* a PAC and watch the service's behaviour change is a genuinely useful thing this tool can do.
2. **GSS-API framing.** A Windows service does not accept a bare AP-REQ. It expects the RFC 4121 InitialContextToken: the `0x60` wrapper, the krb5 mech OID `1.2.840.113554.1.2.2`, the `01 00` token id, and an authenticator whose checksum is **type 0x8003** — sixteen zero bytes of channel bindings followed by the flags word. That checksum is the most commonly botched field in the protocol, and it fails as a generic "checksum type not supported" or a silent rejection.
3. **Pre-authentication, as a two-message round trip.** AD requires `PA-ENC-TIMESTAMP`. The canonical dance is AS-REQ without padata → `KDC_ERR_PREAUTH_REQUIRED` carrying `PA-ETYPE-INFO2` with the salt and the AES iteration count → derive → AS-REQ again. Both halves get their own pane, because the first message is where the salt and the KDC's supported etypes come from and users need to see it.
4. **Encryption-type negotiation, which is moving under everyone's feet right now and should therefore be a first-class display in the UI.** DES is gone in Server 2025. The Server 2025 security baseline [disables RC4](https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication/). The RFC 8009 AES-SHA2 types are defined in Server 2025's bitmask but [reported as not yet active in negotiation](https://strongwind.dev/Kerberos/protocol/encryption.html) as of April 2026. And Microsoft is changing the domain controller's default *assumed* supported types for service accounts with no explicit configuration by mid-2026. A pane that shows what the client offered, what the KDC advertised in `ETYPE-INFO2`, what it chose for the ticket and what it chose for the enc-part answers most of the questions people will bring to this tool in the next two years.
5. **The small stuff that fails loudly.** Uppercase realms; `NT-PRINCIPAL` versus `NT-SRV-INST` for `krbtgt/REALM` versus `NT-SRV-HST` for `host/fqdn`; the `canonicalize` option for UPN-style logon; and the five-minute default skew that produces `KRB_AP_ERR_SKEW` — cheap to detect and worth a banner, since the KDC's own timestamp comes back in the error.

**Delegation** — S4U2Self and S4U2Proxy, with `PA-FOR-USER` and its own HMAC-MD5 checksum, plus `PA-PAC-OPTIONS` for resource-based constrained delegation — is a further increment and gets its own phase rather than being folded into the TGS work.

---

## The mock KDC, in `mock-sts`

`sts/` is [the `rcbj/mock-sts` submodule](https://github.com/rcbj/mock-sts), so all of this is written there and the gitlink is bumped here afterwards, per `docs/mock-sts.md`.

* **`krb5_kdc.js`** — the AS exchange with the full `KDC_ERR_PREAUTH_REQUIRED` round trip (switchable per principal so the skip-it case can be shown too), the TGS exchange, renewals, and cross-realm referrals. Listeners on TCP and UDP 88, plus MS-KKDCP mounted on the existing Express app.
* **`krb5_principals.js`** — the principal database in config: users with a password, a salt and per-etype keys; service principals with keytab-equivalent long-term keys; `krbtgt/REALM`. It deliberately contains **misconfigured principals**, because a debugger is judged on how it renders failure: one with an etype set that forces `KDC_ERR_ETYPE_NOSUPP`, one that does not exist (`KDC_ERR_C_PRINCIPAL_UNKNOWN`), one whose password has expired, and a mode that answers with a deliberately skewed timestamp.
* **`krb5_service.js`** — the thing this feature is ultimately for: a service that will not talk to you without a ticket. A raw TCP AP-REQ/AP-REP acceptor, which is the shape of a non-HTTP Windows service; it validates the authenticator, keeps a replay cache, negotiates a subkey and does mutual authentication. Written as an acceptor module with the transport on top, so the SPNEGO phase adds an HTTP front and no protocol code.
* **A synthetic PAC** in issued tickets, with correct server and KDC checksums, so that `pac.js` has something real to decode and so that a PAC signature failure can be *induced* on demand.

Two frictions specific to this repository's layout, both of which need deciding before phase 2:

**The codec cannot be shared across the submodule boundary.** Compose builds the STS with `context: ./sts`, so it cannot `COPY ../common/krb5`. The realistic answer is a vendored copy in `mock-sts` plus a `sync-krb5.sh`, and — more importantly — **a conformance test in `tests/` that round-trips a fixture corpus through both copies and fails on divergence.** Without that test, a drifted codec talks happily to itself and the divergence is discovered against a real DC, weeks later. The alternative is to put the KDC in a side-car in this repository, the way `keycloak-wsfed/` is, which costs the submodule's tidiness and buys back a single implementation; this plan follows the stated preference for the mock STS, with the sync test as the price.

**`GET /sts-metadata` walks the Express router, so a raw TCP listener on port 88 is invisible to it.** The page's whole design is that it cannot go stale, and a protocol family it cannot see is the one way it can. The listener needs an explicit entry — and the drift test needs to tolerate an entry that has no route behind it, which today is the failure it is specifically written to catch.

---

## Client pages

Following the `wstrust_tools` / `saml_*` multi-page shape, with panes that update in place, show a pending state and log failures rather than navigating away:

* **`kerberos_decoder.html`** — paste base64 or hex of a KRB message, a ticket, a GSS token, a keytab or a PAC and get the field tree, with the encrypted parts decrypted if a key is supplied. **Built first**, ships to the static sites, and is the microscope for everything else.
* **`kerberos.html`** — realm, KDC address, transport (TCP / UDP / KKDCP), principal, credentials, etype preference; the AS exchange with the pre-auth refusal and the accepted request as two panes side by side.
* **`kerberos_tgs.html`** — the `klist`-shaped credential cache, an SPN entry field, the TGS exchange, referral chasing.
* **`kerberos_ap.html`** — the AP-REQ against the mock service or a real one, the authenticator, the mutual-authentication AP-REP, and `Wrap`/`GetMIC` over the established context.

`index.html` gains a card, on a grid that currently must fit one screen — a layout decision, not a paste.

**Key material.** The repo-root rule applies with teeth. The password is never persisted, as with every other password here. But **a ticket's session key is a credential in its own right** — a stored TGT session key is standing access to a service, and it is far less obvious than a private key in a PEM field. The credential cache therefore lives in memory or `sessionStorage` by default, with the established opt-in checkbox (`krb_save_ccache`) if persistence across the page hops is wanted, and the same purge-on-the-spot in `saveState()` that the SAML and WS-Federation key panes use — because an opt-out that leaves yesterday's session key in storage is not an opt-out.

---

## Testing

The standing hazard applies here more sharply than anywhere else in this repository: **testing our client against our own mock proves nothing if both share a bug.** Two implementations written from the same misreading agree perfectly. Four oracles, in increasing cost:

1. **Published test vectors, non-negotiable, before any message is written.** RFC 3961 publishes n-fold vectors; RFC 3962 publishes string-to-key and DK vectors; RFC 8009 publishes a full set. Pinning the crypto to them is the difference between "self-consistently wrong" and "interoperable", and it is the only cheap defence against a class of bug whose sole symptom is one opaque integrity error.
2. **Captured bytes as golden fixtures.** The Wireshark captures behind the [Kerberos and Windows Security series](https://medium.com/@robert.broeckelmann/kerberos-and-windows-security-series-59282e0f9465) are real AD traffic; the decoder must parse them exactly. Free, and they encode behaviour no RFC states.
3. **A real KDC in CI.** MIT krb5 in a container gives standards conformance. **Samba AD DC gives an AD-compatible KDC with a genuine PAC**, which is as close to "Windows compatible" as CI can get without a Windows licence, and it is what makes the PAC work testable at all. Run it in **both directions**: our client gets a TGT from it, and its `kinit`/`kvno` get a ticket from our mock KDC. The second direction is what makes the mock trustworthy, and it is the test most likely to be skipped and most costly to skip.
4. **Manual verification against a real Windows Server domain controller**, out of CI, with Wireshark beside it.

Browser tests follow `tests/CLAUDE.md`'s hazards unchanged — wait on content rather than elements, `--headless=new`, and the secure-context requirement, which bites here because the AES work uses WebCrypto. `tests/sts_metadata.js` will need the new endpoints described, and the codec conformance test above is new and specific to this feature.

---

## Phases

Each row's **Deliverable** is what was planned. Where a phase has landed, what it actually produced is in `docs/kerberos.md` rather than repeated here — the point of keeping this table is the *sizing*, which is what the next estimate will be argued against.

| Phase | Deliverable | Rough effort |
|---|---|---|
| **0 — Spike** | ~600 throwaway lines: n-fold, AES-CTS and string-to-key passing the RFC vectors, and a TGT out of an MIT krb5 container. Settles the `asn1js`-versus-hand-rolled question. Confirms or kills the whole approach for the price of two days. | 1–2 days |
| **1 — Codec** | `common/krb5/` — DER, messages, RFC 3961 framework, etypes 17/18 (and 23 if in scope); `kerberos_decoder.html`, which ships static | 1–2 weeks |
| **2 — Walking skeleton** | The relay endpoint and all of its security work; the mock KDC's AS exchange; `kerberos.html`; the pre-auth round trip end to end; KKDCP | 1–2 weeks |
| **3 — TGS and AP** | Service tickets, GSS framing and the 0x8003 checksum, the mock protected TCP service, mutual auth, the ccache pages | 1–2 weeks |
| **4 — Windows realism** | PAC decode, referrals, skew detection, the error catalogue, the etype-negotiation display, RFC 8009 etypes, the Samba AD oracle | 1.5–2.5 weeks |
| | **Cross-realm referrals are built** — see `docs/kerberos.md`. | |
| | **The PAC is built** — see `docs/kerberos.md`. | |
| **5 — Delegation** | S4U2Self, S4U2Proxy, RBCD, forwarded TGTs and `KRB-CRED`, renewals, possibly kpasswd | 1–1.5 weeks |
| | **S4U and renewals are built** — see `docs/kerberos.md`. | |
| **6 — out of scope here** | SPNEGO: a wrapper over phase 3's acceptor, if phases 1–3 keep the seam clean | — |

Six to ten weeks of focused work. **The unit is a human engineer's week**, which is how the sizes above should be compared against each other — it is a statement about the size of the problem, not about elapsed calendar time for any particular way of building it. **This would be the largest feature in the repository** — larger than the SD-JWT VC workflow, with more specification surface and considerably less forgiving failure modes.

What actually paces the work is the verification loop rather than the writing: the stack, the test battery and any real domain controller are run by hand, phase 0's vectors either pass or send the crypto back for another pass, and phases 4 and 5 cannot be checked at all without a Samba AD or Windows KDC in front of them. Phase 1 and the decoder are the cheapest part per line, because they are testable offline against fixtures; phase 4's PAC work is the most expensive, because every failure is a checksum that does not match and the next move is a guess.

**If it needs to be smaller:** phases 0–3 plus PAC decode is already a genuinely useful Kerberos debugger. The candidates for cutting are etype 23 (Microsoft is retiring RC4 anyway — at the cost of losing the ability to debug the older estates that need debugging most), cross-realm referrals, and all of phase 5.

## Open decisions

1. **Hand-written JS versus `sspi-rs` via WASM.** Recommended: hand-written, for the reason in *The finding that shapes the architecture*.
2. **Browser-side crypto with a thin guarded relay versus protocol endpoints in `api/`.** Recommended: browser-side.
3. **The mock KDC in the `mock-sts` submodule** — accepting a vendored codec copy plus the conformance test — **versus a side-car in this repository** like `keycloak-wsfed/`.
4. **Is etype 23 (RC4-HMAC) in scope?** It costs hand-rolled MD4 and RC4 and Microsoft is retiring it, but it is what the estates with problems are still running.
