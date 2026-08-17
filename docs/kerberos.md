# Kerberos v5 — six pages, one codec, and a KDC that is wrong on purpose

Read this before changing anything under `common/krb5/`, `client/src/kerberos*`, `api/krb5_*` or the mock KDC. The plan that produced it is `docs/kerberos-plan.md`, which now holds only the reasoning and what is still outstanding.

**This is the only workflow here that cannot run on the deployed static sites**, and the reason is not a policy: Kerberos speaks DER over TCP and UDP port 88, and a browser cannot open a socket. Everything except the decoder needs `api/`. The Lambda@Edge trick that rescued WS-Federation and SAML (`infra/CLAUDE.md`) cannot rescue this one — there is no HTTP request to catch.

**So none of these six pages is IN a static build**, decoder included, and the landing page's **two** cards for it — Kerberos and SPNEGO — are greyed out and unclickable there. SPNEGO looks like the exception and is not: its own exchange is HTTP, but the ticket it carries comes from a KDC on port 88 and the pages that obtain one are not there either, so a SPNEGO page on a static site would be a page whose only button says "no service ticket held" for ever. The list is `client/static_site.js`; `client/build.js` deletes those pages (and `css/kerberos.css`) from `dist/`, skips their bundles, strips the card's `href` and fails the build if a page that still ships links to one that does not. `tests/static_site_exclusions.js` checks the whole arrangement with no browser, including that `client/Dockerfile` still builds all six — the exclusion is static-only, and the container is where the workflow runs. The decoder goes with them although it needs no network: it has no card of its own, and the only route to it is the link on `kerberos.html`. Give it a landing card and it can ship on its own; until then, shipping it would be shipping an unreachable page.

Against a deployed static target `remote-run-tests.sh` sets `KERBEROS_AVAILABLE=false` and `run-report.js` skips **every** Kerberos job naming that, rather than failing on a 404. That is every one of them, not just the five pages: the codec, the crypto vectors, the PAC layout, the decoder output, the codec sync, the relay and the mock-KDC exchanges are node-only and would otherwise run happily against a site that has no Kerberos — exercising local code, reporting nothing about the deployment, and (because `remote-run-tests.sh` sets a `CONFIG_FILE` that does not resolve inside the `sts/` submodule) failing for a reason that names a config file. The gate was called `KERBEROS_PAGES_AVAILABLE` while it applied only to the pages; the old name is still read so an existing environment keeps working.

| Page | Does | Needs |
|---|---|---|
| `kerberos_decoder.html` | Decodes pasted bytes — messages, tickets, GSS tokens, keytabs, the PAC, a KRB-CRED — and opens the encrypted parts when you supply a key. | nothing at runtime, but see above: it is not on the static sites either. |
| `kerberos.html` | The AS exchange: turn a password into a TGT, watching both messages of the two-message dance. | api + a KDC |
| `kerberos_tgs.html` | The TGS exchange: spend the TGT on a service ticket. | api + a KDC |
| `kerberos_ap.html` | The AP exchange: present the ticket to a service, with mutual authentication and per-message tokens. | api + a service |
| `kerberos_delegation.html` | S4U2Self, S4U2Proxy (classic **and** resource-based), forwarding, renewal. | api + a KDC |
| `spnego.html` | The same service ticket, presented over **HTTP** rather than a socket: RFC 4559's `Negotiate` header, RFC 4178's negotiation around the AP-REQ, and the ticket inside it. See **`docs/spnego.md`**. | api + an HTTP service |

The DOM helpers, the credential cache and the relay calls are **one module** (`client/src/kerberos_panes.js`) shared by all six, for the same reason `webauthn_panes.js` exists: a pane that disagreed between two pages would be a bug visible only by comparing them.

**SPNEGO is a SIBLING of the AP exchange rather than a successor**, which is why it is step 5 in the trail while belonging beside step 3 in the protocol: both present a service ticket and the only difference is the transport. It is numbered last rather than inserted because renumbering the three exchanges would move ids every Kerberos test locates by. It is also the only page that ROUTES you elsewhere — it spends a ticket and cannot obtain one, so it links to the AS and TGS pages with `?return=spnego` and each of those offers a link back (`panes.noteReturnTarget()` / `renderReturnBanner()`, both in the shared module). `docs/spnego.md` says why that is a link and never a redirect, and why the banner has to render *before* a ticket exists.

---

## The furniture every page carries, and the two panes that span all six

The chrome is the other workflows' chrome, deliberately: a **step trail** at the top (`partials/krb_steps.html`, each page marking its own entry through `panes.markCurrentStep()`), a **collapse-all / expand-all** toggle, and a tooltip on every field. The trail's class is **`krb-trail`, not `krb-steps`** — `.krb-steps` was already taken on `kerberos.html`, where it lays step 1 and step 2 out side by side, and the unscoped rule for that was reaching the trail on all six pages. Tests locate the trail by its **id** (`krb_steps`), which is why the rename cost nothing. `panes.wirePanes()` pairs each `<legend id="x_expand_button">` with its `<fieldset id="x_fieldset">` **by convention** rather than by a registration list, which is what lets a pane added later be clickable with nothing registered for it — and which avoids the failure the older workflows have, where the same id appears in two `onclick` attributes and one of them silently does nothing.

**A page's inputs live in ONE pane, and it is called *Configuration Parameters*.** `kerberos.html` set that shape and `kerberos_ap.html` was brought to it on 2026-08-17: what were *Where the service is* and *What to ask for — the GSS flags* are now two columns of one `pane_config`, in a `krb-grid`, with the prose folded into the `krb-more` `<details>` beside them and the *Present the ticket* button at the foot of the pane it belongs to. Splitting parameters across panes costs a title bar, two borders and the vertical space between them for each extra pane — 213px here, which is the button moving from 1049px to 836px — and it makes the reader collapse two things to see the exchange rather than one. What the old legends said is not lost: it becomes a `krb-group` heading on its column, because the six checkboxes read as unexplained capitals if nothing on screen says they are the GSS flags of the 0x8003 checksum. Two traps live in that layout, and both are invisible until a column is narrow. `.tooltip` is bootstrap's `inline-block`, so a stack of checkboxes **flows** and any two labels that happen to fit share a line — `.krb-checks` exists to stop that, and `.krb-opts` is the same mechanism where the flowing is wanted. And `.krb-grid`'s `auto-fit` minimum decides the column count, so a pane that looks deliberate at 1366px is the minimum biting at 1024.

**Both of those strips are spent from a fixed budget, and adding them overspent it.** `theConfigurationAndBothControlsFitOnOneScreen()` in `tests/kerberos_as_page.js` requires the configuration pane and *both* exchange buttons inside 640px at 1366x768 — the house figure, see the note in `docs/`'s layout entries. The trail (41px), the collapse-all row (25px) and a `<div class="tooltip">` around each of fourteen field labels (~4px each) took step 1's button from 494px to 642px and step 2's further still. It is back inside with headroom, and the space came from margins and padding rather than from content: tighter trail/pane/legend spacing, no dotted underline under a form label, and the deletion of one `krb-note` on step 2 that repeated its own Password tooltip word for word. Every number here was measured in headless Chrome at that viewport, not estimated. If you add anything above those buttons, measure.

**The message panes have a *Decoded* tab and a *Hex* tab, and the hex one answers a different question.** Decoded says what the message says; hex says *which bytes say it* — the question you actually have when a KDC rejects a message you believe is correct, or when a capture disagrees with a decoder. It is on `kerberos.html` (request, reply, and the held ticket), `kerberos_tgs.html` and `kerberos_ap.html` (request and reply), and on the AP page the bytes shown are the **whole GSS InitialContextToken**, wrapper included, because that is what went to the service.

Three things about it are worth knowing before touching it:

* **The strip above the dump leads with the field's NAME**, from `common/krb5/krb5_field_names.js` — `AS-REQ → req-body → cname`, not `[APPLICATION 10] → SEQUENCE → [4] → SEQUENCE → [1]`. The encoding's own path is still there, on the second line, because that is what you need when comparing against a spec; it is no longer what you have to read first. Both lines are clipped to ONE line each with the full text on their `title`, and that is load-bearing rather than tidy: the strip sits above the bytes, so a line it gains pushes every row down and the pointer then rests on a different byte — measured at 32px of movement mid-hover before the clip.
* **Hovering a byte lights it in BOTH halves** — the hex pair and the character in the readable gutter — because the gutter is one cell per byte carrying the same range, rather than one string per row. That column is where a realm, a principal name and the `krbtgt` of a TGT are legible, and until it was per-byte cells you could see which bytes a field occupied and, one column over, not see which characters they were. Hovering the text works as well as hovering the hex; clicking either pins it.
* **A page gets all of this from MARKUP**, not from code: `renderMessage()` pairs `krb_x_pane` with `krb_x_hex` by convention, the same way `wirePanes()` pairs a legend with its fieldset. Add the tab strip and a `_hex` div and the view appears. The one exception is the AP page's request, which is assembled by hand rather than by `renderMessage()` and so calls `panes.renderCompanionHex()` itself. Note the delegation page's eight message panes do **not** have hex tabs yet; they are one markup block each away.

`tests/krb5_field_naming.js` holds the naming, and the assertion that carries it is name-to-bytes: slice the buffer at the range called `AS-REQ → req-body → cname → name-string[0]` and those bytes must decode to the principal that was encoded. A table with two fields transposed passes every other check and fails that one — which matters because a wrong name here does not crash, it says `till` while highlighting `rtime`, plausibly, and somebody reads a value off the screen that belongs to something else. Beside it: every context tag our own encoders emit must be named (the drift check between that table and `krb5_messages.js`, which carry the same tag numbers in different shapes), and a static half that fails when a page grows a `_hex` div nothing fills or a tab strip nothing wires — a hex tab that renders empty is indistinguishable from an exchange nobody has run. The page list is **discovered** from the pages that link `css/kerberos.css` rather than written out, which is how it already covers a sixth page added while it was being written.

Two things are worth knowing before touching either of the panes at the bottom of these pages, because they sit one above the other, look alike, and are governed by opposite rules.

**Ticket Cache & History** (all six pages, `partials/krb_tickets.html`, rendered by `client/src/kerberos_tickets.js`) is a **credential store**. Every ticket the workflow obtains lands in it — from every page: the AS exchange's TGTs, the TGS exchange's service tickets, and the delegation page's S4U2Self evidence, delegated tickets and renewals — and *Make active* puts one back in the live slot unchanged, so two tickets can be compared or one from before a configuration change returned to. Each row therefore **holds a session key**, so it obeys the same `krb_save_ccache` checkbox the live ticket does: `sessionStorage` unless ticked, and unticking purges the whole list on the spot (`enforceStoragePreference()`). Capped at 100, oldest dropped. It was the AS page's pane, called *Ticket History*, until 2026-08-17; what forced it onto all of them is that every page both fills the list and has something to do with a row in it, so a pane on one page was a pane you had to navigate away from to use.

**Which rows a page can activate is the per-page part, and the only part.** The pane is one module mounted with the slots that page holds: `["TGT"]` on the AS and TGS pages, `["service", "delegated"]` on the AP page (a ticket from S4U2Proxy *is* a service ticket, and that page presents it like any other), `["TGT", "evidence"]` on the delegation page, and **read-only on the decoder**, which holds nothing and must write nothing — there the Clear button is removed and each row instead offers its bytes to the decoder's own input, which is a read of storage and a write to a textarea. Where an activated ticket is written comes from `TICKET_SLOTS` in `kerberos_panes.js` and from the ticket's own kind, never from a caller: the kind is *derived* from the service name (`krbtgt/…` is a TGT) rather than taken from a label, because a service ticket accepted into the TGT slot is accepted silently and fails one page later, naming an encryption type. A row a page cannot take is **named**, with the page that can use it in its title — a control that is simply absent reads as a pane that failed to render. `activateTicket(index, kind)`'s second argument is a *check*, not an instruction.

The row for a ticket the workflow is holding right now says which slot has it (`heldTickets()`), and that is the *Cache* half of the title: the pane answers "what do I hold, and what did I hold" in one table.

**Operations History** (all six pages, `partials/krb_history.html`) is a **log**, holds no key material, and is therefore *not* touched by that checkbox: purging the record of what was attempted because somebody stopped storing session keys removes it exactly when it is most wanted. It is the fourth workflow over `client/src/op_history.js`, after SAML, WS-Trust and WS-Federation, and the log is **one list shown identically on every page** — a Kerberos exchange is a chain across the pages, so the useful question is never "what did this page do" but "what happened, in order, and against which KDC".

**How a row is closed is the one design decision in it.** The obvious shape — record on the way in, update on the way out — does not survive these handlers: `onS4u2Self()` alone has five `return false` paths before its request is built, and a row nobody closes stays `Sent` for ever. In this pane `Sent` *means* "no answer reached this debugger", so a forgotten update does not read as a missing log line, it reads as a broken KDC. So the close is driven from `panes.status()` — the one place every one of those exits already goes through, because a handler that returns without setting a status leaves the page saying "Sending…". `begin()` names the status line that will report the operation, and only a status on **that** line closes it; the delegation page has four lines and can have four operations outstanding, so the open rows are a map. The status class is the verdict: `krb-bad` → Failure, `krb-ok`/`krb-good`/**`krb-warn`** → Success (a `krb-warn` on the delegation page is an exchange that *worked* and produced a ticket with an unwelcome property — recording it as a failure would say the KDC refused a request it granted), anything else leaves the row open.

`tests/krb5_operation_history.js` is where that is checked, and the half that matters is static: per bundle, every status line an operation is opened against must have both a success and a failure path, and every page must both include the partial and `mount()` it against the partial's own ids. `tests/krb5_ticket_history.js` does the same for the pane above it, and one thing more: that each page mounts **only the slots it holds**, and that the decoder mounts read-only. Neither is checkable at runtime and neither would fail a browser test — the pane renders, the row is there, and it says `Sent`, which is a legitimate value; a page that includes the pane and never mounts it shows an empty div, which looks exactly like a workflow that has done nothing.

One more thing about the pane's classes. `op_history.js` renders `saml-*` by default and these five pages do not link `css/saml_common.css`, so it is configured with `classPrefix: "krb-op"` — **not** `"krb"`, because it emits `<prefix>-history` and `<prefix>-table` and both of those names are already the Ticket Cache & History table's on the same page. The three result colours are the pages' own `krb-ok` / `krb-bad` / `krb-pending`, so the row cannot say something different from the status line above it.

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

## `common/krb5/` — the modules, and what each is for

| Module | Holds |
|---|---|
| `krb5_primitives.js` | MD4, MD5, HMAC-MD5, RC4, n-fold, UTF-16LE — the things neither Web Crypto nor Node's OpenSSL 3 will do |
| `krb5_crypto.js` | RFC 3961's framework and etypes 17, 18, 19, 20, 23: unpadded CBC and CTS over Web Crypto, string-to-key, the key-usage table |
| `krb5_asn1.js` | DER for Kerberos's ASN.1, plus the generic TLV tree the decoder needs for bytes it cannot identify |
| `krb5_messages.js` | Every message, the error catalogue with diagnostic meanings, and `KRB-CRED` |
| `krb5_gss.js` | RFC 4121: the InitialContextToken, the 0x8003 checksum, MIC and Wrap |
| `krb5_spnego.js` | RFC 4178: the negotiation around that token — NegTokenInit, NegTokenResp, the OID coder Kerberos's own grammar never needed, and the mechListMIC. See `docs/spnego.md` |
| `krb5_ndr.js` | Just enough NDR ([MS-RPCE]) to read and write the PAC's logon information |
| `krb5_pac.js` | [MS-PAC]: the buffer table, `KERB_VALIDATION_INFO`, the four signatures, `S4U_DELEGATION_INFO` |
| `krb5_client.js` | The client half: TGS requests, AP requests, S4U, renewals, forwarding |
| `krb5_describe.js` | "Here are these bytes, explained" — the decoder page's whole content, with no DOM in it |
| `krb5_keytab.js` | Keytabs, in both byte orders |
| `krb5_ranges.js` | Which BYTES each ASN.1 element occupies — one absolute range per element, and the innermost owner of every byte. What the hex tab colours with |
| `krb5_field_names.js` | What those elements are CALLED: RFC 4120's field names per structure, and the four-state walk that turns `[APPLICATION 10] → SEQUENCE → [4] → SEQUENCE → [1]` into `AS-REQ → req-body → cname` |

`krb5_describe.js` returning a plain document rather than markup is what lets `tests/krb5_describe_output.js` check every fact the page shows with no browser. Every value it returns is **already a string**: the renderer never formats and never interprets, which is what keeps hostile bytes out of anything but `textContent`.

**Eight of these are vendored into the mock STS** and the copies are byte-identical — see *The mock KDC* below.

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

Most of the twenty-three Kerberos test files — all but the five page tests — need **no browser and no services** — the KDC and the protected service are started in-process on ephemeral ports — so they never skip. `docs/test-suite-map.md` has the per-file notes; two things about the approach are worth stating here.

**A round trip proves almost nothing for a wire codec.** A reader and a writer sharing one misunderstanding agree perfectly with each other and with nothing else in the world. So the assertions are byte offsets hand-derived from the specifications, structures with **more than one element** (an `ExtraSids` array defers all its pointers past the end of the array, so a reader that follows each as it goes is right for one element and wrong for two), and cross-checks where one copy of the codec encrypts and the other decrypts.

**Mutation testing is the standard of evidence.** Every section of the Kerberos tests was developed by breaking the thing it tests and confirming the test fails — around eighty mutations across the six phases. That is also how four real coverage gaps were found, each needing new fixture data rather than a new assertion: a realm-aware lookup that needed a client *native* to the second realm, a PAC domain SID nothing asserted, a delegation flag invisible where it is set, and an authtime comparison that compared a value with itself. When a mutation is **not** caught, confirm the mutation actually reached the source and changed behaviour before concluding the test is weak — twice it was the mutation that was inert.

---

## What is not here

**SPNEGO is now here** and has its own file: `docs/spnego.md`. It cost what that seam promised — `common/krb5/krb5_spnego.js` holds RFC 4178 and nothing else, `krb5_gss.js` was not touched beyond a comment, and the mock's acceptor performs every Kerberos check it already performed. What was added is two wrappers, a transport, and a sixth page.

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
