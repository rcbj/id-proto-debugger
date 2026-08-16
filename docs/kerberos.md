# Kerberos v5 — five pages, one codec, and a KDC that is wrong on purpose

Read this before changing anything under `common/krb5/`, `client/src/kerberos*`, `api/krb5_*` or the mock KDC. The plan that produced it is `docs/kerberos-plan.md`, which now holds only the reasoning and what is still outstanding.

**This is the only workflow here that cannot run on the deployed static sites**, and the reason is not a policy: Kerberos speaks DER over TCP and UDP port 88, and a browser cannot open a socket. Everything except the decoder needs `api/`. The Lambda@Edge trick that rescued WS-Federation and SAML (`infra/CLAUDE.md`) cannot rescue this one — there is no HTTP request to catch.

**So none of these five pages is IN a static build**, decoder included, and the landing page's Kerberos card is greyed out and unclickable there. The list is `client/static_site.js`; `client/build.js` deletes those pages (and `css/kerberos.css`) from `dist/`, skips their bundles, strips the card's `href` and fails the build if a page that still ships links to one that does not. `tests/static_site_exclusions.js` checks the whole arrangement with no browser, including that `client/Dockerfile` still builds all five — the exclusion is static-only, and the container is where the workflow runs. The decoder goes with them although it needs no network: it has no card of its own, and the only route to it is the link on `kerberos.html`. Give it a landing card and it can ship on its own; until then, shipping it would be shipping an unreachable page.

Against a deployed static target `remote-run-tests.sh` sets `KERBEROS_AVAILABLE=false` and `run-report.js` skips **every** Kerberos job naming that, rather than failing on a 404. That is all fourteen, not just the five pages: the codec, the crypto vectors, the PAC layout, the decoder output, the codec sync, the relay and the mock-KDC exchanges are node-only and would otherwise run happily against a site that has no Kerberos — exercising local code, reporting nothing about the deployment, and (because `remote-run-tests.sh` sets a `CONFIG_FILE` that does not resolve inside the `sts/` submodule) failing for a reason that names a config file. The gate was called `KERBEROS_PAGES_AVAILABLE` while it applied only to the pages; the old name is still read so an existing environment keeps working.

| Page | Does | Needs |
|---|---|---|
| `kerberos_decoder.html` | Decodes pasted bytes — messages, tickets, GSS tokens, keytabs, the PAC, a KRB-CRED — and opens the encrypted parts when you supply a key. | nothing at runtime, but see above: it is not on the static sites either. |
| `kerberos.html` | The AS exchange: turn a password into a TGT, watching both messages of the two-message dance. | api + a KDC |
| `kerberos_tgs.html` | The TGS exchange: spend the TGT on a service ticket. | api + a KDC |
| `kerberos_ap.html` | The AP exchange: present the ticket to a service, with mutual authentication and per-message tokens. | api + a service |
| `kerberos_delegation.html` | S4U2Self, S4U2Proxy (classic **and** resource-based), forwarding, renewal. | api + a KDC |

The DOM helpers, the credential cache and the relay calls are **one module** (`client/src/kerberos_panes.js`) shared by all five, for the same reason `webauthn_panes.js` exists: a pane that disagreed between two pages would be a bug visible only by comparing them.

---

## The one architectural decision everything follows from

**The protocol runs in the browser. The api is a guarded byte relay that holds no state, derives no keys and never sees a password.**

```
  browser                                api/                    network
  common/krb5/*  ──── base64 ────►  POST /krb5/kdc  ──── TCP/UDP 88 ────►  KDC
  DER · messages · RFC 3961         address policy
  crypto · PAC · NDR · GSS          size + time caps
                 ◄─── base64 ────   TCP framing     ◄──────────────────
```

Two consequences worth knowing before proposing a change:

* **One codec, not two.** The decoder page, the four live pages, the api's frame checks and the test suite all load `common/krb5/`. Protocol-aware endpoints (`POST /krb5/as`) would need a second implementation in `api/`, and two codecs drift.
* **The api's endpoints are not a TCP proxy**, and the distinction is the whole of the security work — see `api/CLAUDE.md`. `POST /krb5/kdc` will only reach a port on its allowlist and only with bytes that parse as a KDC request; `POST /krb5/service` is **off unless configured** and checks the payload is a GSS-wrapped AP-REQ, because a service is not on port 88 and a port list cannot bound it.

---

## `common/krb5/` — nine modules, and what each is for

| Module | Holds |
|---|---|
| `krb5_primitives.js` | MD4, MD5, HMAC-MD5, RC4, n-fold, UTF-16LE — the things neither Web Crypto nor Node's OpenSSL 3 will do |
| `krb5_crypto.js` | RFC 3961's framework and etypes 17, 18, 19, 20, 23: unpadded CBC and CTS over Web Crypto, string-to-key, the key-usage table |
| `krb5_asn1.js` | DER for Kerberos's ASN.1, plus the generic TLV tree the decoder needs for bytes it cannot identify |
| `krb5_messages.js` | Every message, the error catalogue with diagnostic meanings, and `KRB-CRED` |
| `krb5_gss.js` | RFC 4121: the InitialContextToken, the 0x8003 checksum, MIC and Wrap |
| `krb5_ndr.js` | Just enough NDR ([MS-RPCE]) to read and write the PAC's logon information |
| `krb5_pac.js` | [MS-PAC]: the buffer table, `KERB_VALIDATION_INFO`, the four signatures, `S4U_DELEGATION_INFO` |
| `krb5_client.js` | The client half: TGS requests, AP requests, S4U, renewals, forwarding |
| `krb5_describe.js` | "Here are these bytes, explained" — the decoder page's whole content, with no DOM in it |
| `krb5_keytab.js` | Keytabs, in both byte orders |

`krb5_describe.js` returning a plain document rather than markup is what lets `tests/krb5_describe_output.js` check every fact the page shows with no browser. Every value it returns is **already a string**: the renderer never formats and never interprets, which is what keeps hostile bytes out of anything but `textContent`.

**Five of these are vendored into the mock STS** and the copies are byte-identical — see *The mock KDC* below.

---

## The traps. Each of these has cost a debugging round, and each fails by naming something else

**The salt is not the principal name, and it is not guessable.** Active Directory salts a user as the realm followed by the sAMAccountName (`EXAMPLE.COMalice`) and a **computer account** as the realm, the literal `host`, the short name in lower case and the DNS domain (`EXAMPLE.COMhostws01.example.com`). An implementation that derives the salt from the principal name works until the first machine account. The KDC tells the client in **PA-ETYPE-INFO2**, which arrives inside the `KDC_ERR_PREAUTH_REQUIRED` error — so a client that treats that error as a failure cannot authenticate to AD at all.

**Key usage numbers are invisible when wrong.** A wrong one produces a well-formed message that fails integrity at the far end, and the error a KDC returns for it is the same one it returns for a wrong password. They are named constants in `krb5_crypto.js` for that reason. The ones that bite: 1 for `PA-ENC-TIMESTAMP`, 6 and 7 for a TGS request's checksum and authenticator, **8 or 9** for a TGS reply depending on whether a subkey was sent (a client that always tries one fails half the time), 14 for `KRB-CRED`, and **17** for both `PA-FOR-USER` and all four PAC signatures.

**The 0x8003 checksum is not a checksum.** It carries channel bindings and the GSS flags, its integers are **little-endian** in a protocol where everything else is big-endian, and `Bnd` is sixteen **zero** bytes rather than absent when there are no bindings.

**KerberosTime carries no fractional seconds.** Sub-second precision lives in `cusec`. Comparing an AP-REP's echoed `ctime` against a millisecond-precision `Date` accuses a correct service of not being itself — which it did, on the first run of `krb5_tgs_ap.js`.

**NDR is not DER.** Inside the PAC everything is little-endian C structs, and the logon information is NDR: referent-id pointers that are **not offsets**, alignment measured from the start of the stream, and `FILETIME` that is two `ULONG`s and therefore aligns to **4, not 8**. `krb5_ndr.js`'s header lists all five rules; every one of them is a silent misread rather than an error.

**The PAC's four signatures cover four different things with two keys, and the order they are generated in is load-bearing.** The server signature uses the key the **ticket** is encrypted under, which is what lets a service verify it alone — and on a TGT that is the krbtgt key, so a mix-up only shows up on a *service* ticket. The KDC signature covers the server signature's **bytes only**, so altering the PAC's contents leaves it verifying: that is CVE-2022-37967's shape, and the extended KDC signature exists to close it.

**Two flag tables share their names and not their values.** [MS-SAMR]'s `USER_ACCOUNT` codes are what a PAC carries; LDAP's `userAccountControl` bits are not (`NORMAL_ACCOUNT` is 0x10 in one and 0x200 in the other). And [MS-PAC]'s bit diagrams number the **leftmost** cell bit 0 with the **rightmost** as least significant, so `UserFlags` D is 0x20 and `SE_GROUP_RESOURCE` is 0x20000000.

**Web Crypto cannot do most of this.** No MD5, no unpadded CBC, no CTS; Node's OpenSSL 3 has no MD4 or RC4. Hence `krb5_primitives.js`. And `globalThis.crypto` is used rather than `require("crypto")`, because browserify substitutes the latter with a shim that drags in `elliptic` — see `client/CLAUDE.md`.

---

## Delegation: four mechanisms, and which attribute decides

`kerberos_delegation.html` puts them on one page because the interesting part is the comparison.

| | What it does | What authorizes it |
|---|---|---|
| **S4U2Self** | A service gets a ticket to **itself**, naming a user who takes no part — no password, no ticket of theirs, no consent. | nothing. It is not a privilege: the ticket is to yourself. |
| **S4U2Proxy, classic** | That service reaches **another** service as the user. | `msDS-AllowedToDelegateTo` on the **front end**. Only a domain admin can set it. |
| **S4U2Proxy, resource-based** | Same thing. | `msDS-AllowedToActOnBehalfOfOtherIdentity` on the **back end**. Whoever controls that object can set it. |
| **Forwarding** | The client hands over its whole TGT in a `KRB-CRED`; the holder can reach **anything** as it. | nothing, ever again. The KDC is not consulted after issue. |

That inversion in the middle two rows is the entire security story of RBCD: it turns "I can write to this computer account" into "I can reach this service as anybody". The asymmetries that make it the easier path are real and reproduced: classic needs **forwardable** evidence (and so needs `TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION` on the front end), resource-based needs neither — but does need `PA-PAC-OPTIONS`, without which [MS-SFU] requires `KDC_ERR_BADOPTION`.

**Every refusal on that page is `KDC_ERR_BADOPTION`, whatever the cause.** The error names none of them, so the page's job is to narrow it: it lists both attributes on both accounts, the missing padata, and the evidence ticket's forwardability. That text is the product, and `tests/kerberos_delegation_page.js` asserts it rather than merely asserting the request failed.

**Forwardability is reported when the evidence ARRIVES**, not two steps later. A missing `TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION` lets S4U2Self *succeed* and returns a ticket that merely is not forwardable — so classic S4U2Proxy then complains about the *evidence ticket*, which is not where the problem is.

For forwarding, the one enforceable control is `NOT_DELEGATED` ("account is sensitive and cannot be delegated"), and it sits on the account being protected rather than on any service. The KDC withholds the forwardable flag at the **AS** exchange — not as an error, so the user still logs on — and re-checks at the TGS exchange, because a forwardable ticket issued before the flag was set would otherwise keep working. A service's `ok-as-delegate` flag is only **advice** to the client; nothing enforces it.

---

## The mock KDC, and the two things about it that are deliberate

It lives in the `sts/` **submodule** (`docs/mock-sts.md` has the detail, including why five codec modules are vendored there and how `tests/krb5_codec_sync.js` keeps the copies honest). Two design points matter when reading its tests:

**Its principals are misconfigured on purpose.** `locked`, `expired`, `aesonly` (a hardened account offering no RC4), `rc4only` (the legacy account a 2025 baseline breaks), `noreauth` (answered in **one** message rather than two), a computer account for the host-shaped salt, `sensitive` (flagged `NOT_DELEGATED`), and four service accounts differing by one delegation attribute each. The whole point is producing failures deliberately, and each account's PAC records the same misconfiguration its behaviour shows.

**It serves TWO realms with a trust between them**, which a real KDC never does. The simplification hides finding the other realm's KDC — DNS and SRV records — and none of the protocol, and it buys the whole cross-realm referral without a second container. A trust is not a setting: it is **one principal** whose key both KDCs consult.

---

## Testing

Ten of the twelve Kerberos test files need **no browser and no services** — the KDC and the protected service are started in-process on ephemeral ports — so they never skip. `docs/test-suite-map.md` has the per-file notes; two things about the approach are worth stating here.

**A round trip proves almost nothing for a wire codec.** A reader and a writer sharing one misunderstanding agree perfectly with each other and with nothing else in the world. So the assertions are byte offsets hand-derived from the specifications, structures with **more than one element** (an `ExtraSids` array defers all its pointers past the end of the array, so a reader that follows each as it goes is right for one element and wrong for two), and cross-checks where one copy of the codec encrypts and the other decrypts.

**Mutation testing is the standard of evidence.** Every section of the Kerberos tests was developed by breaking the thing it tests and confirming the test fails — around eighty mutations across the six phases. That is also how four real coverage gaps were found, each needing new fixture data rather than a new assertion: a realm-aware lookup that needed a client *native* to the second realm, a PAC domain SID nothing asserted, a delegation flag invisible where it is set, and an authtime comparison that compared a value with itself. When a mutation is **not** caught, confirm the mutation actually reached the source and changed behaviour before concluding the test is weak — twice it was the mutation that was inert.

---

## What is not here

**No SPNEGO** — deliberately the next thing, and cheap because the transport is HTTP and the AP-REQ already exists. The seam is kept clean for it: `krb5_gss.js` is a separate module from anything HTTP-facing.

**No PKINIT, FAST, NTLM, CredSSP, kadmin or kpasswd.** **No DES** and there never will be: Windows Server 2025 removed it, so it is decode-only, present so a capture from an old estate still renders.

**No SID filtering across a trust**, which is the control that stops a trusted realm asserting membership of groups in yours. Its absence is stated in the code, in `docs/mock-sts.md` and here rather than left as a silence.

**Interoperability against a real domain controller is now testable, but is not tested on every run.** Every other claim in this file rests on this project's own KDC, and the mock was written from the same reading of RFC 4120 and [MS-PAC] as the client it checks — so the two agree by construction and a shared misreading is invisible to all of them. `tests/krb5_real_dc.js` is the answer: it drives a **real Windows Server 2025 domain controller**, standing up a single-DC forest with `infra/terraform-krb5` and checking the chain end to end — a bare AS-REQ refused with `PREAUTH_REQUIRED` (asserting the salt is AD's `<REALM><samAccountName>`, no separator, which is the first place a client and a real DC part company), an AS-REQ with `PA-ENC-TIMESTAMP` yielding a TGT, a TGS-REQ for a mapped SPN, the service ticket **decrypted with the key Microsoft's own `ktpass` wrote into a keytab** (so `krb5_keytab.js` is parsing a real Microsoft file rather than one this project generated), the PAC inside it parsed with its server signature verified, and finally an AP-REQ built here and opened with the same key.

**It has been run, and it passed.** On 2026-08-16, against Windows Server 2025 Datacenter (`Windows_Server-2025-English-Full-Base-2026.08.12`): the salt came back as `KRB5TEST.LOCALkuser`, a TGT and a service ticket were issued at etype 18, the `ktpass` keytab opened the ticket, and the PAC parsed with **no problems reported** and its server signature verified with the service key. That is the strongest evidence in this file, because the PAC is the structure a mock is least likely to have got right — the NDR layout, the signature coverage and the zeroing all agree with Microsoft.

**Three things the real DC taught us that the mock had not, and one is a trap.**

* **Windows sends NO `s2kparams`.** Its `PA-ETYPE-INFO2` for aes256 omits the field entirely and relies on the RFC 3962 section 4 default of 4096 iterations. The mock KDC used to send it always, and `tests/krb5_as_exchange.js` asserted that it did — true of the mock, false of Active Directory. A client that *required* the field would pass every test here and then fail against every real domain, reporting a wrong password. **Three things changed as a result**: the mock now defaults to AD's behaviour and takes `KRB5_S2KPARAMS=send` for the old one (`docs/mock-sts.md`), that test covers both modes, and the **decoder page now says where the iteration count came from** — it printed nothing at all when the field was absent, which left "the KDC asked for the default" indistinguishable from "the decoder did not look". `tests/krb5_windows_vectors.js` proves the whole chain by deriving a key with a null `s2kparams` and opening Microsoft's own AS-REP with it.
* **A service ticket's PAC carries seven buffers, and not the ones you would guess.** Windows Server 2025 sent Logon Information, Client Info, UPN/DNS Info, and **all four signatures including the post-CVE-2020-17049 ticket checksum (16) and extended KDC checksum (19)** — but *not* `PAC_ATTRIBUTES_INFO` (17) or `PAC_REQUESTOR` (18), which the mock does put in a service ticket. Every type it did send is one this codec recognises and parses.
* **An unregistered SPN is answered with silence.** A TGS-REQ for an SPN mapped to no account gets a zero-length TCP frame and a closed connection, not `KDC_ERR_S_PRINCIPAL_UNKNOWN`. `api/krb5_frame.js` refuses that — an empty frame cannot be a Kerberos message — and now says why, because "0 bytes" on its own reads as a broken relay rather than as a KDC declining to answer.

**The evidence outlives the domain controller.** `tests/krb5_capture_real_dc.js` recorded every message of that exchange into `tests/captures/windows-server-2025.json`, and `tests/krb5_windows_vectors.js` asserts it on every ordinary run with no AWS and no network. So the expensive test's result is a permanent regression check rather than an afternoon that happened once. What the capture does **not** cover: cross-realm referrals, S4U2Self/S4U2Proxy, renewals, RC4, and the KDC signature — that one needs the krbtgt key, which a service never has and this capture deliberately does not carry.

It does **not** run in the ordinary suite, and that is deliberate rather than an omission. The domain controller costs money — free tier caps at 1 GiB and a forest promotion needs more, so the smallest size that works is `t3.medium` — and nothing should start one by accident. `run-report.js` skips the job unless `KRB5_DC_HOST` names a KDC that already exists, and `./infra/krb5-test.sh` is the only thing that brings one up — or `./local-run-tests.sh --krb5-real-dc`, which is a thin wrapper on it and needs no docker at all, since this test loads the api's relay modules in-process rather than talking to a running service. Either way it applies the stack, waits for the forest, runs the work and destroys everything again, with the teardown on an `EXIT` trap so a failed test still removes the instance. `--krb5-real-dc=capture` re-records the fixture instead of running the test, and `=both` does the test first — a capture taken from a broken run would be worse than none, because `krb5_windows_vectors.js` would then assert the breakage. Until that script has been run against a change, "correct" here still means "self-consistent and matching the specification as read here".
