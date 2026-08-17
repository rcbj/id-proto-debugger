# SPNEGO — a Kerberos ticket in an HTTP header

Read this before changing `client/src/spnego.js`, `client/public/spnego.html`,
`common/krb5/krb5_spnego.js`, the mock's `spnego.js`, or `POST /krb5/spnego` in
`api/server.js`. It is the sixth page of the Kerberos workflow and shares
everything with the other five; `docs/kerberos.md` is the file to read first,
and this one holds only what is different.

**Nothing here is new protocol.** The AP-REQ is `krb5_client.js`'s — the same
one `kerberos_ap.html` presents over a raw socket. The acceptor is the mock's
`krb5_service.js`, unchanged, performing every check it performs on port 8888.
What this workflow adds is two wrappers and a transport:

```
  Authorization: Negotiate <base64>                      RFC 4559
    └── NegTokenInit / NegTokenResp                      RFC 4178
          └── InitialContextToken (0x60, krb5 OID)       RFC 4121 / 2743
                └── AP-REQ                               RFC 4120
                      └── Ticket, Authenticator, 0x8003 checksum
```

Four layers, of which HTTP shows you one. That is the whole reason the page
exists.

---

## The exchange, and the request that carries no information at all

```
  GET /spnego/protected                          (no Authorization header)
  401 WWW-Authenticate: Negotiate                (the bare challenge)

  GET /spnego/protected
  Authorization: Negotiate YIIF…                 NegTokenInit + AP-REQ
  200 WWW-Authenticate: Negotiate oRQw…          NegTokenResp + AP-REP
```

**The first 401 carries no token, and that is the fact this page exists to
make visible.** RFC 4559 section 4: the server says only that it will
negotiate. It does not say which realm, which KDC, or which service principal
name — the client derives `HTTP/<host>` from the URL it was already fetching and
finds the KDC from its own configuration. So a SPNEGO failure is very often a
DNS or SPN problem that leaves **no evidence on the wire at all**, and the
useful thing a debugger can do is show the guess it made. `spnego.html` puts the
derived SPN in an editable field with a note saying it is derived, because an
SPN's host component and the host in a URL are not required to agree and on a
load-balanced or CNAMEd service they routinely do not.

A token on that first challenge is not a harmless extra: a client that reads it
as the acceptor's first negotiation token has nothing to answer with. The page
reports one as a warning and carries on, and `krb5_spnego_http.js` asserts the
header is the bare word.

---

## Where the pieces live

| Piece | File | What it knows |
|---|---|---|
| RFC 4178 codec | `common/krb5/krb5_spnego.js` | NegTokenInit, NegTokenResp, the OID coder, mechListMIC, the section 5 rule. No DOM, no HTTP, no Kerberos beyond one OID |
| The page | `client/public/spnego.html`, `client/src/spnego.js` | assembly and panes. No protocol |
| The relay | `POST /krb5/spnego` (`api/server.js`) | one HTTP GET, and the `Authorization` header built from a validated token |
| The acceptor | the mock STS's `spnego.js` | the negotiation and the HTTP; every Kerberos check is `krb5_service.js`'s |
| The advert | the mock STS's `GET /spnego` | what a real intranet site never tells you: the SPN, the realm, the mechanisms |

`krb5_spnego.js` is **vendored into the mock STS** like the other seven codec
modules (`common/krb5/sync-to-mock-sts.sh`), and it is the module with the most
to lose from drift: the browser encodes a NegTokenInit the mock decodes and the
mock encodes a NegTokenResp the browser decodes, so every field crosses between
the two copies in both directions. `tests/krb5_codec_sync.js` checks byte
identity *and* cross-encodes both messages.

The dependency runs **one way**: `krb5_spnego.js` requires `krb5_gss.js` (for
the mechanism OID and for GSS_GetMIC) and `krb5_gss.js` knows nothing about
SPNEGO. That is the seam `krb5_gss.js`'s header promised, and it is what makes
the AP exchange identical whether or not a negotiation happened around it.

---

## The traps. Each one decodes as something else rather than failing

**Only the initiator's FIRST token is wrapped.** The NegTokenInit rides inside
an RFC 2743 InitialContextToken — `0x60`, SPNEGO's own OID `1.3.6.1.5.5.2`,
then `[0]`. Every token after it, **in both directions**, is a bare
NegTokenResp beginning `0xa1`, with no wrapper and no OID (RFC 4178 section
4.2). An acceptor that wraps its reply produces something no client will read;
a client that expects a wrapper reports "not a GSS token" for a perfectly good
answer. That OID appears exactly once in the whole exchange.

**The mechListMIC covers `MechTypeList`, not `[0] MechTypeList`.** Two bytes.
RFC 4178 section 5 spells the distinction out because implementations kept
getting it wrong, and a MIC over the tagged form verifies against nothing while
being perfectly well formed. `mechTypeListDer()` exists as its own exported
function, the encoder hands the bytes back, and the decoder reports the bytes it
**sliced** rather than re-encoding them — a legal but different re-encoding
would verify against nothing in exactly the same silent way.

**The two MICs use different keys, and the asymmetry is forced rather than
chosen.** The initiator's travels in the NegTokenInit, which is built before any
answer exists, so the only context key in existence is the subkey in its own
Authenticator — key usage 25. The acceptor's travels beside the AP-REP, by which
point it has offered a subkey of its own, and RFC 4121 makes *that* the context
key — key usage 23. Both are over the same bytes with sequence number 0. Using
one key for both is a MIC the other end cannot verify, and the error names a
checksum.

**`[3]` means two different things.** RFC 4178 puts `mechListMIC` there;
[MS-SPNG]'s NegTokenInit2 — what a Windows *acceptor* sends when it speaks
first — puts `negHints` there and displaces the MIC to `[4]`. The decoder tells
them apart by what is **inside** (a SEQUENCE is negHints, an OCTET STRING is a
MIC) and never by the direction of travel, because the interesting captures are
exactly the ones where the direction is not what you assumed. Windows's
`hintName` is the literal string `not_defined_in_RFC4178@please_ignore` on every
server ever shipped; it looks like a defect and is not.

**`negState` is ENUMERATED (0x0a), not INTEGER (0x02).** They encode identically
apart from the tag, so a coder that used INTEGER round-trips against itself
perfectly and is refused by a strict peer.

**Microsoft's Kerberos OID differs from the real one in a single arc**:
`1.2.840.48018.1.2.2` against `1.2.840.113554.1.2.2`. It is a long-standing typo
kept for compatibility, every Windows client offers both, and an acceptor that
treats it as an unknown mechanism refuses every Windows client while reporting a
mechanism mismatch. `isKerberosMech()` accepts both spellings and the acceptor
echoes back **the spelling the client offered**.

**A rejection carries no reason.** `negState` has no field for one. When a
server can say more it says it in the mechanism's own error token — a
`KRB-ERROR` inside `responseToken` — so an acceptor that swallows that leaves a
rejection indistinguishable from a wrong password. The page decodes it when it
is there and says plainly when it is not.

---

## The routing, and why it is a link rather than a redirect

SPNEGO **obtains nothing**. It spends a service ticket for `HTTP/<host>`, and
obtaining one is the AS exchange followed by the TGS exchange — two other pages
in this workflow. Re-implementing either here would be a second implementation
of the thing the workflow exists to show, so the page sends you to them instead:

* the credentials pane links to `/kerberos.html?return=spnego` and
  `/kerberos_tgs.html?return=spnego&spn=<the SPN>`;
* `panes.noteReturnTarget()` reads that parameter and keeps it in
  `sessionStorage`, so it survives the AS page sending you on to the TGS page —
  the common route, where a query parameter would be lost at the first hop;
* `panes.renderReturnBanner()` puts a banner above the step trail on both pages,
  carrying **two different sentences** depending on whether the caller now has
  what it came for. "You still need X" and "you have it" are different
  instructions, and a banner that says neither is just a link.

**It never navigates for you**, and that is deliberate: an automatic hop back
the moment a TGT arrives takes the AS exchange's two decoded messages off the
screen at exactly the moment somebody wanted to read them, which is what that
page is *for*. The same reasoning as the "panes update in place" rule the VC
workflow follows.

Two details in that banner are load-bearing and both have a test:

* It must render **before** a ticket exists. That is the case it is for —
  somebody arrives precisely because they have none — and it is the one an
  implementation puts after an early return and never renders. It happened here
  once: `renderCache()` has three early returns and the call was at the bottom.
* "Ready" on the TGS page is not "a ticket exists" but "**a ticket for that SPN**
  exists". A held ticket for another service proves nothing to this one, and a
  banner that said otherwise would send somebody back to a page that refuses
  them.

The `?spn=` parameter **wins over the SPN the TGS page used last**, because it
came from the URL somebody is actually trying to reach; buying a ticket for the
last-used service instead is refused a page later with `KRB_AP_ERR_NOT_US`,
which reads as a broken ticket.

---

## Why the request goes through the api

`POST /krb5/spnego` is a third relay endpoint, and it is the only one that is
not a socket. It exists because **a browser cannot show you either side of this
exchange**:

* a cross-origin `fetch` can read a response header only if the server chose to
  expose it with `Access-Control-Expose-Headers`, and `WWW-Authenticate` is
  exactly the header this workflow is about; and
* the browser owns its own request headers, so a page cannot report what it
  sent.

The endpoint reports both sides verbatim. What bounds it: the method is `GET`
and nothing else, and the only header a caller can influence is `Authorization`,
whose value the api builds itself as `Negotiate <base64>` from a token whose
alphabet it has validated. A caller cannot inject a header, a method or a body.
Everything else is the shared axios instance every other outbound call uses, so
the SSRF guard, the four limits and the `User-Agent` apply unchanged — see
`api/CLAUDE.md`.

It needs **no switch in the configuration**, unlike `POST /krb5/service`. That
one is off by default because it carries caller-supplied bytes to a
caller-supplied port; this one is an HTTP GET, the same capability as
`/userinfo` or `/samlmetadata`. `GET /krb5/limits` publishes `spnegoEnabled` so
the page can tell an older api from a broken one.

A `401` is **the protocol**, not a failure: `validateStatus` returns true for
everything, because the first request is supposed to be refused and the refusal
carries the challenge.

---

## The mock's protected page

`GET /spnego` advertises it, in HTML and (with `?format=json`) as JSON: the SPN,
the realm, the mechanisms accepted, and the knobs. That is deliberate — a real
intranet site tells you none of it, and the point of the mock is to make the
invisible half visible.

`GET /spnego/protected` is the resource. Three query parameters make the
negotiation fail in one specific way each, in the spirit of the mock's
misconfigured principals:

| Knob | What happens |
|---|---|
| `?mic=require` | answer the first token with `request-mic`, forcing the mechListMIC exchange and a second round trip |
| `?mech=none` | support no mechanism the client offers, so the negotiation ends in `reject` with no explanation |
| `?mutual=off` | accept the ticket and send no AP-REP, so the client is authenticated and has proved nothing about the server |

**A mechListMIC that does not verify is a REJECT, not a warning.** An acceptor
that logs a bad MIC and continues has implemented RFC 4178 section 5's syntax
and none of its protection: the MIC is the only thing standing between the
negotiation and an attacker who edited the mechanism list on the wire.

**A bare Kerberos token — no SPNEGO at all — is accepted**, because real clients
send one and a debugger that refused it would teach something false. The
difference is stated in the response body rather than smoothed over, since none
of SPNEGO's downgrade protection applies to it.

One structural difference from a real acceptor is stated rather than hidden: a
half-finished negotiation (between `request-mic` and the client's answer) is
held against the **client address**, not the connection. RFC 4559 section 5's
authentication is connection-based, and Express offers no stable connection
identity — which is also why real SPNEGO breaks behind connection-pooling
proxies and on HTTP/2 in ways nothing reports.

---

## What the page shows, and the one thing it cannot

Eight panes, and the tabs follow `kerberos.html`'s: **Decoded** and **Hex**,
paired by a `data-krb-tabs` group name. The hex view is `kerberos_hex.js`'s, so
hovering a byte names the ASN.1 element that owns it and its absolute offset —
the same binary field breakdown the AS exchange page carries, over the SPNEGO
token and over the ticket.

**The ticket is opaque, and the page says so.** It travels inside the AP-REQ
encrypted under the *service's* long-term key, which this browser does not hold
— that is the honest state of a client, and it never holds the key its own
ticket is sealed with. Supply the service key (hex), its password and salt, or
its **keytab** and the pane opens the `EncTicketPart`: the client name, the
flags, the session key and the **PAC**, which is what a Windows service
authorizes on. Nothing typed there is stored or sent anywhere; the derivation
happens in the browser through `krb5_describe.js`'s `keysFromPassword()`.

**Those fields are no longer this page's own, and that is the point.** They were
— `krb_service_key_hex`, `krb_service_password`, `krb_service_salt` and an *Open
the ticket* button, in the ticket pane — which made this the only page in the
workflow where a ticket could be opened, and it is the one page that cannot
*obtain* one. Since 2026-08-17 they are `partials/krb_keys.html` plus
`client/src/kerberos_keys.js`, included at the foot of all five exchange pages;
the ids are `krb_deckey_*` and the button is *Open the encrypted parts with these
keys*. Three things came with the move: the pane registers itself with
`kerberos_panes.js` (`setExtraKeys`), so every message pane here — the
negotiation tokens, the AP-REQ, the ticket inside it — is re-read with the keys
supplied rather than the ticket pane alone; the keytab route this page never had
came for free; and the *default salt* stayed page-specific, passed to `mount()`
as `assumedServiceSalt()`, because this is the only page that knows the SPN it
just used and so the only one that can offer realm + principal as an assumption.
It says which salt it assumed rather than assuming quietly. See `docs/kerberos.md`.

The salt field matters more than it looks: a salt is **not derivable from a
principal name** (Active Directory salts a computer account as realm + `host` +
short name + DNS domain), which is the whole reason `PA-ETYPE-INFO2` exists, and
a wrong salt looks exactly like a wrong password.

**The decoder page understands a `Negotiate` header too.** `krb5_describe.js`
now recognises a GSS token before it asks `identify()` — a SPNEGO token begins
`0x60`, which is `[APPLICATION 0]`, so identify() called it a Kerberos message
this build does not decode: true of the grammar, and the wrong layer. Paste an
`Authorization` value in and it explains the negotiation, the mechanism token
inside it, and the AP-REQ inside that, with the decryption attempts the page
already offers.

---

## Why your browser will not do this for you

Chrome and Firefox perform Negotiate only for hosts on an explicit allow-list
(`AuthServerAllowlist`, `network.negotiate-auth.trusted-uris`) and send a
Kerberos ticket to nobody else. That is a defence rather than an inconvenience —
a ticket handed to the wrong host is a credential handed to the wrong host — and
it is why this page performs the handshake by hand: it is the only way to see
what a browser *would* have sent. It also means the mock's protected page will
simply show you its 401 if you visit it directly, which is correct.

---

## Testing

Three jobs, and the split is the usual one here.

`tests/krb5_spnego_codec.js` — node only, never skips. Byte-level, with every
value derived by hand from RFC 4178 section 4 and the OIDs' own registrations
rather than from what the encoder produces. Two of its expectations were wrong
on the first run and the encoder was right, which is the point of writing them
that way.

`tests/krb5_spnego_http.js` — node only, never skips: the mock KDC and the
mock's Express app are started in-process on ephemeral ports. Eight positive
cases and **ten negatives**, and the negatives are the substantial half
deliberately, because an acceptor that authenticates a good client looks
finished and is worth very little. The two nothing else could catch:

* a mechListMIC computed over `[0] MechTypeList` — the ticket is perfect, the
  AP-REQ decrypts, the client is who it says it is, and the request is refused;
* an **edited mechanism list** — everything else about the request is valid,
  which is exactly why the MIC is the only thing that can notice. That is the
  downgrade RFC 4178 section 5 exists to stop.

Each negative asserts *which* check fired, and the ones carrying a `KRB-ERROR`
assert the code inside the `responseToken`, because a rejection with an empty
one is what an acceptor that swallowed the error looks like.

`tests/kerberos_spnego_page.js` — needs the client, the api and the mock STS.
It covers only what a browser is needed for: the routing loop out to the AS page
and on to the TGS page and back through the banner's own link, the banner
rendering *before* a ticket exists, the credential handoff under a third reader
of the shared cache, the SPN the page guesses, the panes and the hex view naming
a field under the pointer, and the ticket opening with a service key. Three
negatives through the UI, each a knob above.

**Three mutations were used to confirm the HTTP test is not vacuous**, and all
three were caught: making a bad mechListMIC a warning rather than a reject,
wrapping the acceptor's reply in an InitialContextToken, and putting a token on
the first challenge.

---

## What is not here

**No NTLM.** It is recognised in a client's `mechTypes` list and named, and it
is never selected — offering a mechanism this build cannot perform would be a
lie a client would act on. The page can offer it to watch a negotiation fail.

**No NEGOEX**, which negotiates again inside SPNEGO.

**No channel bindings over TLS.** The 0x8003 checksum's `Bnd` field is decoded
and shown, and the page sends sixteen zero bytes. Tying a context to the TLS
connection underneath it (RFC 5929, and what Windows's Extended Protection for
Authentication turns on) is not implemented.

**No credential delegation.** The `DELEG` flag and the KRB-CRED that rides in
the 0x8003 checksum are the delegation page's, and nothing here asks for
forwarded credentials over HTTP.

**Not tested against a real Windows server.** Everything above rests on this
project's own acceptor, which was written from the same reading of RFC 4178 as
the client it checks — so the two agree by construction and a shared misreading
is invisible to both. The Kerberos half of the stack *has* been proved against
Windows Server 2025 (`docs/kerberos.md`), and the same trick would work here:
`infra/terraform-krb5` stands up a domain controller, and IIS with Windows
Authentication is a role away.
