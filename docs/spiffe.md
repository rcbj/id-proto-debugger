# SPIFFE — the seventeenth workflow

**`client/public/spiffe.html`** · **`client/src/spiffe.js`** ·
**`api/spiffe_client.js`** · **`api/protos/`** · **`common/spiffe/`** ·
`tests/spiffe_engine.js`, `tests/spiffe_protocol.js`, `tests/api_spiffe.js`,
`tests/spiffe_page.js`

SPIFFE gives a *workload* — a process, a container, a pod — a cryptographic
identity that it did nothing to earn and holds no secret to obtain. Its server
side is **three surfaces**, and the single most useful thing to know before
reading anything else is that they have almost nothing in common:

| Surface | Transport | Who talks to it |
|---|---|---|
| **the bundle endpoint** | plain HTTPS, one GET returning a JWK Set | anybody who federates with this trust domain. This is the whole of the federation protocol's server half |
| **the Workload API** | gRPC, on a Unix socket and on TCP | a **workload**, to be given an identity. Seven methods |
| **the SPIRE Server API** | gRPC over **mutual TLS**, on a Unix socket and on TCP | an **operator** and an **agent**: registration entries, attestation, bundles, minting. Forty-two methods across six services |

All **forty-nine** methods are on the page.

---

## Why this workflow is not on the deployed static sites

**A browser cannot speak gRPC at all**, and that is not a limitation of the
page. gRPC is HTTP/2 with a length-prefixed binary framing and its status in
the **trailers**: `fetch` will not open an HTTP/2 stream of its own, cannot
send or read trailers, cannot see a `grpc-status`, and — the one that ends the
argument — cannot present a client certificate, which the SPIRE Server API
requires. So both gRPC surfaces live entirely in the **api**
(`api/spiffe_client.js`), and `client/static_site.js` drops `spiffe.html`, its
bundle and `css/spiffe.css` from `dist/` while `client/build.js` greys the
landing card.

**Note what that costs, because it is more than Kerberos and LDAP give up.**
The bundle endpoint *is* plain HTTPS, and three of the page's readers — the
bundle reader (a group in the settings pane since 2026-08-26), the SVID
inspector and the SPIFFE ID checker — need **no network
at all**. A page whose two biggest panes are permanently dead is still worse
than a card that says why, which is the same judgement made about SPNEGO and
the opposite of the one made about PKI and SCIM, whose api-less halves are the
majority of those pages rather than a corner of them.

---

## The two gRPC surfaces are authenticated in OPPOSITE ways

This looks like an inconsistency and is not. It is two documents making two
different demands, and getting either of them the other way round breaks a real
client.

**The Workload API must not authenticate anybody, and that is the
specification speaking.** The SPIFFE Workload Endpoint specification says the
endpoint "MUST NOT require any direct authentication of its clients" and that
"Transport Layer Security MUST NOT be required". The reason is bootstrapping: a
workload has no secret and no root of trust until this very call gives it one,
so there is nothing it could present.

**The SPIRE Server API is mutual TLS with an X509-SVID.** A real
`spire-server` binds a TCP port whose callers present an SVID from the trust
domain, takes the caller's SPIFFE ID off the certificate, and authorizes every
method against *what that caller is*. Its private Unix socket is trusted
outright — that is how the `spire-server` CLI works.

So the whole shape of the page is: **fetch an SVID from a surface that
authenticates nobody, then present it to one that requires mutual TLS, and find
out who that makes you.** The *Held Identity* pane is that hand-off, and it
keeps the private key beside the certificate because an X509-SVID without its
key proves nothing.

The bootstrapping case is handled the way SPIRE handles it: the TCP port **asks
for** a client certificate and does not **require** one, because `AttestAgent`
must be reachable by a caller that has no SVID yet.

---

## SPIFFE authentication is not hostname authentication

**The single most important twenty lines in `api/spiffe_client.js`**, and the
place a reasonable implementation goes wrong.

A SPIRE server's TLS certificate carries **no DNS subjectAltName and no CN
naming a host**. Its only subjectAltName is
`URI:spiffe://<trust domain>/spire/server`. So node's ordinary
`checkServerIdentity` — which compares a hostname against DNS names and the CN
— **cannot pass**, and the failure it produces reads as a certificate problem
rather than as a check that was never applicable:

```
Error [ERR_TLS_CERT_ALTNAME_INVALID]: Hostname/IP does not match certificate's altnames
```

The two obvious ways out are both worse than the problem. Turning
`rejectUnauthorized` off discards the **chain** check as well, which is the one
that matters. Passing `grpc.ssl_target_name_override` makes the hostname check
pass by lying about the hostname, which verifies nothing and looks like it
does.

So the check is **replaced**. TLS still verifies the chain against the trust
bundle; what this service adds is the SPIFFE half — the far end's URI SAN,
matched in one of three modes the caller chooses explicitly:

| Mode | What it means |
|---|---|
| `spiffe-id` | it must be exactly this SPIFFE ID. The default, and what a real client does; derived as `spiffe://<trust domain>/spire/server` when not given |
| `trust-domain` | any SPIFFE ID in this trust domain. Looser, and honest about being so |
| `none` | check nothing and **report what was presented**. Explicit, never a fallback — a debugger whose only answer to a mismatch is "it failed" cannot show which identity actually turned up. It turns off the SPIFFE-ID check and **nothing else**: the chain is still verified |

An SVID has **exactly one** URI SAN. Several is refused rather than searched:
choosing between two would be deciding which identity the far end has.

**A server that answers, presents a certificate a trusted authority signed, and
turns out to be somebody else is its own outcome** — `identityMismatch` on a
502, not an ordinary network failure. Those are different facts and only one of
them is about the network. Without the distinction, grpc-js reports it as
`UNAVAILABLE: No connection established`, which reads as a server that is not
there.

---

## The four identities, and why the order is the whole shape of SPIFFE

The SPIRE Server API authorizes every method against **what the caller is**, so
reaching all forty-two means being four different things. The page and
`tests/spiffe_protocol.js` both walk this in order:

| Entity | How you become it | What it opens |
|---|---|---|
| nothing | — | `Bundle.GetBundle` and `Agent.AttestAgent`, and no more. Both are open in a real SPIRE server too |
| a **workload** | `FetchX509SVID` on the Workload API, with no credential at all | nothing new on the SPIRE Server API by itself — but it is the credential everything below is built on |
| an **admin** | that same SVID, once `spiffe.adminIds` names it (SPIRE's own `admin_ids`, which needs no registration entry) — or a registration entry marked `admin` | thirty-odd methods: the whole registry, the agents, the bundles, minting |
| an **agent** | `AttestAgent` with a join token and a real CSR | the seven agent-only methods: `GetAuthorizedEntries`, `SyncAuthorizedEntries`, `RenewAgent`, `PostStatus`, `BatchNewX509SVID`, `NewJWTSVID`, `Bundle.GetFederatedBundle` |

And a fifth that is not an identity at all: the **local Unix socket**, trusted
outright the way a real `spire-server` trusts its private one. It is the only
route to `Debug.GetInfo`, which is **local-only** in SPIRE's own table — so an
administrator's SVID over TCP is refused it. **That row looks like an omission
and is not**: it is a health check for whoever is standing on the host, and the
surprise is the point.

**`UNAUTHENTICATED` and `PERMISSION_DENIED` are different instructions to a
client** — "authenticate" and "you may not" — and SPIRE distinguishes them.
Collapsing them sends a client that needs a credential looking for a permission
it will never get, so the api reports both as a **200** with the code and the
page shows the code.

---

## The api: `POST /spiffe/call`, `POST /spiffe/bundle`, `GET /spiffe/limits`

**One endpoint for forty-nine methods rather than forty-nine endpoints**, which
is the opposite of the choice `POST /ldap/*` made and is deliberate. There,
eight operations have eight different shapes and each route documents its own.
Here every method is `(service, method, request)` over one wire format, **the
method list is derived from the protos** rather than typed, and a route per
method would be forty-nine places for that list to drift from the protos it is
supposed to mirror.

`GET /spiffe/limits` publishes the catalogue, so the page's picker is built
from what the api can actually call. It is also how the page tells an older api
from a broken one: a build with no SPIFFE answers 404 there, which is a
different thing from a SPIRE server that will not answer.

### The three outcomes

The rule `POST /ldap/*` and `POST /scim` already follow, and it matters more
here than on either:

* a refusal by **this service** — an address it will not dial, a socket path
  outside the allowlist, a method that is not on the surface — is a **400**;
* a **network failure**, and a server whose SPIFFE ID was not the one required,
  are **502**s (the second flagged `identityMismatch`);
* **a gRPC status from the far end is a 200**, with `ok: false` and the code.

The third is the point. `PERMISSION_DENIED`, `UNAUTHENTICATED`,
`UNIMPLEMENTED` with the reason a server gives for declining,
`INVALID_ARGUMENT` on a JWT-SVID request with no audience — every one of those
is SPIFFE **answering**, and they are the most interesting thing this workflow
shows.

### What bounds it

`api/ssrf_guard.js` does not cover this, for the reason it does not cover the
Kerberos relay, the LDAP client or the TLS probe: the guard is installed on the
shared **axios** instance, and grpc-js opens its own socket with no axios in
the path and no agent to hook. So this is the **fourth** enforcement of the
same policy, and like the other three it reuses the guard's **decision**
(`blockedRangeFor`) rather than its own copy of the ranges.

| Bound | Setting | Default |
|---|---|---|
| the address must parse as `tcp://host:port`, `host:port` or `unix://path` | — | an unrecognised scheme is refused rather than defaulted, because grpc-js's own resolver treats an unknown one as a DNS name |
| the address policy | `blockPrivateNetworkCalls`, `blockedAddressRanges` | shared with the other three call sites |
| resolve, then dial the **literal** that was checked | — | closes the DNS-rebinding window |
| a port allowlist | **`spiffeAllowedPorts`** | `[8081, 8092, 8181]`, or the word `"any"` |
| a socket-path prefix allowlist | **`spiffeAllowedSocketPaths`** | `["/tmp/spire-agent/", "/tmp/spire-server/"]`, or `"any"` |
| how many messages a stream yields | **`spiffeMaxStreamMessages`** | 4 |
| how long a stream is held | **`spiffeStreamTimeout`** | 45000 ms |

**Resolving then dialling the literal costs nothing here, and that is worth
stating because it costs `ldap_client.js` something real**: for `ldaps:` that
file must hand TLS the *original name* as `servername` or certificate
verification compares a certificate against an IP address and fails every time.
SPIFFE has no such problem, because the far end is identified by its SPIFFE ID
and not by a hostname. (The `:authority` header is still set back to the name
the caller gave, so SNI is a name rather than an address — RFC 6066 does not
permit an IP there and node warns about it. That string decides nothing about
who the far end is proved to be.)

### The socket-path allowlist is the one bound nothing else here has needed

`SPIFFE_ENDPOINT_SOCKET` means a `unix://` path to `go-spiffe`,
`spiffe-helper` and the SPIRE agent, so a SPIFFE client that could not reach a
Unix socket would be unable to talk to what every real deployment runs. That
makes this the only endpoint in the api that opens a connection to a **path its
caller chose**, and the address policy cannot see it: there is no address to
judge.

What it protects against is not exotic: an api reachable from anywhere, pointed
at a path on the machine it runs on, is a way to make that machine connect to
one of its own local services and report what came back.

Two smaller checks come with it, and both exist because the alternative is a
confusing failure. A Unix socket path is bounded by `sun_path` at **108 bytes**
on Linux (104 on macOS; the api refuses at 103 so a path it accepts works on
both), and past that `bind`/`connect` fails with a message about the address
being **in use** — naming something that is not the problem. And a path that
exists and is **not a socket** is refused by name rather than dialled, because
"connection refused" on a regular file reads as a service that is down.

### The streams are bounded, and saying so is part of the answer

Six of the forty-nine methods are streams, and a real client holds
`FetchX509SVID` open for the life of its process. An HTTP endpoint cannot hold
a stream open on a browser's behalf, so the api reads up to
`spiffeMaxStreamMessages` or until `spiffeStreamTimeout`, cancels, and reports
**how it stopped** — `messages`, `timeout`, `size` or `end`. A client that
reported only the first message would make a rotation invisible; one that
reported nothing about why it stopped would make a timeout look like a server
that sent one message and went quiet.

**A stream gets its own deadline, longer than `callTimeout`**, and the reason
is arithmetic rather than taste: the mock STS re-sends at half the SVID
lifetime with a **floor of thirty seconds**, so a stream bounded by the
ten-second call budget could never observe a rotation however short the SVID
lifetime were set.

### One write, and the bidirectional stream is deliberately left open

`AttestAgent` and `SyncAuthorizedEntries` are bidirectional, and they are
request/response conversations that may take more than one turn — `AttestAgent`
may answer the params with a **challenge**, and the agent has to still be there
to answer it. A client that half-closes as soon as it has written has told the
server the conversation is over before hearing whether it was.

That is not theoretical. A server that ends its own side when it sees the
client's `end` does so while the reply is still being produced, and the write
that follows lands on a stream nobody is reading: **the call completes with
status OK and no messages**, which reads as a server that accepted an
attestation and issued nothing. That is exactly what this endpoint did until
the stream was left open, and `tests/spiffe_protocol.js` asserts a non-empty
`AttestAgent` response for that reason rather than asserting the status alone.

---

## The protos are vendored, verbatim, and that is the point

`api/protos/` holds the SPIFFE project's own `workloadapi.proto` and the
`spire-api-sdk`'s — 21 files, **byte-identical** to the copies the mock STS
carries. The wire matching what a *real* client and a *real* SPIRE server
expect is the entire reason `@grpc/grpc-js` is a dependency, so an edit to one
of these would give that up silently: the debugger would go on agreeing with
the mock and interoperate with nothing.

`tests/spiffe_engine.js` compares the two copies file by file, and finds the
mock's directory through its own `spiffe_grpc.js` rather than by naming
`spiffe/protos` — that service moved every module into folders on 2026-08-23,
and a path written down in this repository would have broken.

A missing proto is **not** a degraded feature: `api/spiffe_client.js` throws at
require time, because a client that starts and then answers `Unimplemented` to
everything is worse than one that does not start.

### Two load options do most of the work

`bytes: String` makes protobufjs hand every `bytes` field back as **base64**,
so a response is already JSON-serialisable and nothing walks a message
converting buffers — and it works in reverse, so a caller sends a CSR as base64
and it arrives as bytes with no conversion at either end. `longs: String` is
there for the same reason: a `uint64` expiry as a JavaScript number is wrong
above 2^53 and silently so.

`keepCase: true` keeps the field names the `.proto` writes. **It does not reach
protobufjs's built-in well-known types**, which is the trap that costs
everybody one afternoon:

* a **`google.protobuf.Struct`** decodes to
  `{ fields: { k: { stringValue: v, kind: 'stringValue' } } }` — camelCase
  members in a family that is otherwise entirely snake_case. The mock's
  `ValidateJWTSVID` answered 200 with empty claims for exactly this until a
  real client asked for them. The api flattens it to plain JSON.
* a **wrapper** (`google.protobuf.StringValue` and friends) is a MESSAGE, so
  the wire form is `{ value: x }` and a bare `x` **serialises to nothing at
  all**, with no throw and no warning. A `ListEntries` filter sent that way
  returns *every* entry and looks like a filter that works until somebody
  counts. The api accepts either form and wraps the bare one.

Both are handled from **typed-out tables** (`WRAPPED_FIELDS`, `STRUCT_FIELDS`)
rather than by walking the descriptors, because a field descriptor's `typeName`
is a *relative* protobuf name (`Filter`, `types.EntryMask`,
`Federated_bundles`) and resolving one means implementing protobuf's own
name-resolution algorithm — more code, with more to be wrong in it, than naming
six fields. What keeps a typed-out table honest is a test rather than a
convention: `tests/spiffe_engine.js` reads every `.proto` and fails if a
wrapper-typed or Struct-typed field is not in one of them.

---

## `common/spiffe/` — two modules, three callers

Both are DOM-free and both live in `common/` because the api, the browser
bundle and the tests all need them, and a grammar implemented three times is a
grammar that disagrees with itself.

**`spiffe_id.js` — the grammar, which is stricter than a URL parser** in four
ways that each produce an identifier looking perfectly fine in a log:

* **a trust domain name is lower-case.** `spiffe://Example.org/x` is not valid,
  and it is not another spelling of `spiffe://example.org/x` either — they are
  different identifiers. `new URL()` lower-cases a host for you, which *hides*
  the defect: the client that sent the wrong form gets an SVID naming the right
  one and never learns.
* **the path is not a URL path.** No percent-encoding, no empty segment (so no
  trailing slash and no `//`), no `.` and no `..`. A URL parser accepts all of
  those and normalises three of them away.
* **no port, no userinfo, no query, no fragment.** Each is a way of writing an
  identifier that a naive `startsWith()` treats as belonging to a trust domain
  it does not — an authorization bug in anything that federates. `memberOf()`
  compares **parsed** trust domains and never prefixes, which is what stops
  `spiffe://example.org.attacker.test/x` passing for a member of
  `example.org`.
* **`/spire` is reserved** for the implementation's own account — the server's
  identity and every agent it attests — so a registration entry there names
  something the server also mints for itself. The check is on **segments**:
  `/spireman` is not under `/spire`, and a `startsWith` gets that wrong.

`tests/spiffe_engine.js` drives 22 cases from the specification's own rules,
written out independently of the module — a table derived from what the module
does would agree with it by construction.

**`spiffe_bundle.js` — the trust bundle document**, and one rule in it matters
more than everything else put together. **A JWK in a SPIFFE bundle MUST carry
`use`, and a consumer MUST IGNORE one whose `use` is missing or unrecognised.**
So a bundle full of keys with no `use` is not a slightly imperfect bundle: it
**verifies nothing**, and it fails with no error anywhere pointing back at it —
the X509-SVID that will not validate names a signature, the JWT-SVID names a
key id, neither names the bundle that silently had no usable keys in it. The
module reports it as an **error** and counts survivors per `use`, because
"0 usable x509-svid keys" is the only form of that report anybody can act on.

It reads a document and deliberately does **no cryptography**: it has to run
unchanged in a browser bundle and in node, and the two have completely
different certificate machinery. `x5c` is checked for shape — present, an
array, one entry, base64 (**not** base64url, which is the opposite of every
other JWK member and the mistake to look for first) — and handed on.

---

## The page

`spiffe.html`, **nine panes** — it was ten until 2026-08-26, when the *Trust
Bundle* pane was folded into *Configuration Parameters* whole. Every readout is a `<textarea>` and never a `<pre>`,
and the pane carries `min-inline-size: 0` — a `<fieldset>` computes its
min-content width from its contents and `overflow` on it does **not** clamp
that, so one base64 DER certificate makes the pane itself thousands of pixels
wide rather than scrolling inside it.

| Pane | What it is for |
|---|---|
| **Configuration Parameters** | **every editable setting on the page**, grouped under the name of the pane it acts on — and, in its **Trust Bundle** group, the one operation that is here whole: fetch through the api (a bundle endpoint sends no CORS headers), or **read what is in the box with no network at all**; make the `x509-svid` authorities the trust anchor for the SPIRE Server API group two below it. See below |
| **Workload API** | all seven methods, the request, and what came back |
| **Held Identity** | the SVID **and its private key**, and what the page holds of each |
| **SPIRE Server API** | all forty-two, the request, and what came back |
| **Certification Request** | a key pair and a PKCS#10 request, in the browser |
| **SVID Inspector** | an X509-SVID or a JWT-SVID, read offline |
| **SPIFFE ID** | the grammar, offline |
| **Exchange** / **Operations History** | both halves of what the api was asked for, and a log of every call |

Every one of them collapses, and one switch at the top does all of them — see
*Every pane collapses* below.

### One pane owns the settings

There was a **Trust Domain** pane at the top of this page and there is not any
more: every editable setting moved into a single **Configuration Parameters**
pane, which is the arrangement `scim.html` arrived at and is documented in
`docs/scim.md` for the same reason — a setting a screen away from the button
that reads it is what people actually complain about. The groups inside it are
named after the panes the fields came from.

**The Trust Bundle group is the exception, and it is a whole pane rather than
a group of settings.** It was the *Trust Bundle* pane, second on the page, and
on 2026-08-26 it moved in here entire — the TLS-verification switch, the three
buttons, the status line, the document box and the report. Nothing about it
was split: a fold that moved the document and left the buttons where they were
would be a reader with nothing to read, and `spiffe_page.js` section 10 now
names all seven of its ids and fails if any of them is outside `#pane_config`.
The reason it belongs here rather than below is what the group *produces*: the
`x509-svid` authorities in that document become the **trust anchor** the SPIRE
Server API presents to, and that anchor is a field two groups further down
this same pane. Its one setting used to be a group of its own called
*Discovery*, and that name is gone with it.

**What stayed below is what *is* the operation** — the method pickers, the two
request editors, and the SVID inspector's and SPIFFE ID checker's inputs. A
"Call" button a screen away from the JSON it sends would be the same defect in
the other direction.

**Nothing is mirrored.** Each of those boxes is the one element with its id;
there is no second field anywhere that holds the same setting. That is the
rule `scim.js`'s `owns` flag exists to keep, and it matters for a reason that
is invisible until it bites: `getElementById` answers with the **first**
element in document order, so a duplicated id makes the other box silently
stop doing anything. `spiffe_page.js` section 10 counts ids for exactly this,
and asserts the list of controls that are editable outside the pane.

### The prose folds, and every control has a tooltip

Every explanation on the page is inside a `<details class="spiffe-more">` and
**ships closed**, the way `scim.html` and the Kerberos pages fold theirs. The
explanations are why this page is worth using — why a bundle of keys with no
`use` verifies nothing while reporting no error, why `UNAUTHENTICATED` and
`PERMISSION_DENIED` are different instructions — so they are folded rather
than cut.

What is **not** folded is the page's own answers: `spiffe_workload_about`,
`spiffe_server_about`, the two streaming lines, `spiffe_identity_holds_key`,
`spiffe_server_peer` and `spiffe_limits` are written by the bundle and stay on
the page. A result behind a click nobody knows to make is a result nobody
sees.

Those answers are told apart from the shipped prose **by their id**, and that
is the rule a new one has to follow: every `<p class="spiffe-note">` the
bundle GENERATES — `renderMessages()`'s per-message headings and its
no-messages line, `describeBundleText()`'s summary and its error and warning
lines, `checkSpiffeId()`'s verdict and membership lines — is given one, because
all four result containers (`spiffe_bundle_report`, `spiffe_workload_result`,
`spiffe_server_result`, `spiffe_id_report`) sit OUTSIDE the folds. Without an
id a generated note is indistinguishable from a paragraph of prose that
escaped its `<details>`, both to a reader and to `spiffe_page.js`, whose
"every explanation is inside a fold" check skips prose that has one. The
generated readouts carry a `title` for the same reason the static ones do.

With the prose folded, the **tooltip is the only explanation on screen for a
control somebody is looking straight at**, so every field and every button
carries one — the readouts included, since a box whose contents arrived from
somewhere else is exactly where "where did this come from" gets asked.

**The field NAMES carry it too**, and that is the other half rather than a
duplicate. A reader scanning a pane reads the labels, and on this page a label
is a `<label>` with its own hit area *beside* the box rather than on it — so a
tooltip living only on the control is one that is not there when the pointer is
over the word that raised the question. Each label carries the same string its
control carries, and `spiffe_page.js` asserts both that every label has one and
that the two texts are **identical**: a tooltip improved on the control and
left alone on the label is a page explaining one field two different ways
depending on where the pointer is.

### Every pane collapses, and one switch does all of them

The page is nine panes long, so the answer somebody wants is routinely four
panes below the one they are working in. Every pane therefore shuts, using the
**shared `.dbg-*` chrome in `css/debugger.css`** that twenty-odd pages here
already link — the same clickable title, the same triangle and the same
top-of-page switch as the OAuth2 / OIDC workflow — rather than a fourth
implementation of it. With every pane collapsed the page is **1,657px**
against 3,416px open, which is a table of contents. Both numbers were measured
with ten panes, before the trust bundle was folded into the settings pane; the
open height is the same content either way and the collapsed one is a legend
shorter.

The markup contract is `scim.html`'s, which is the Kerberos pages':

```html
<div class="spiffe-pane dbg-pane" id="pane_x">
  <legend class="dbg-legend" id="spiffe_x_expand_button">Title</legend>
  <fieldset name="spiffe_x_fieldset" id="spiffe_x_fieldset"
            style="display: block;">…</fieldset>
</div>
```

Four things about it are load-bearing.

**The pane is a `<div>` and the collapse target is the `<fieldset>` inside
it**, because the title has to stay visible when the pane is shut and so cannot
live inside the element that is hidden. That moves the `min-inline-size: 0` the
stylesheet header describes onto the **inner** fieldset — it is that element
which still computes a min-content width from a base64 certificate, and putting
the rule on the wrapping `div` would do nothing.

**The legend and the fieldset are paired by ID** — `x_expand_button` drives
`x_fieldset`, wired in `wirePanes()` — rather than by an inline
`onclick="spiffe.togglePane('x_fieldset')"`. The inline spelling writes the id
twice and fails silently when the two drift: a pane title that does nothing at
all. Here a drifted pair is a console warning, and this page's console is
asserted clean, so it is a failure rather than a shrug.

**`setAllPanes()` discovers the fieldsets off the DOM** instead of holding a
list of ids. Several workflows here keep the list, and every one of those is
something a new pane has to be remembered into — an omission whose only symptom
is the single pane the switch skips.

**`style="display: block"` in the markup is not decoration.**
`css/debugger.css` turns the triangle with
`.dbg-pane:has(fieldset[style*="display: none"])`, which reads the **inline**
style, so a pane that started with no inline display at all would show an
expanded triangle over a pane the switch had never touched. For the same
reason `spiffe_page.js` asserts the pane's **height** rather than its triangle:
the marker is a CSS rule and can perfectly well turn over a pane that is still
on the screen.

Two smaller notes. `css/debugger.css` is linked **before** `css/spiffe.css`, so
where the two disagree this page's own sheet wins and the tight borders,
padding and margins of the density pass survive; only the behaviour is
borrowed. And `dbg_toggle_all` is on `EDITABLE_OUTSIDE_CONFIG` in
`spiffe_page.js` rather than in the Configuration Parameters pane — it
configures nothing, sends nothing and is not saved, and a control that changes
what is on the screen has to sit above the panes it opens.

### Every box is sized to what it holds

The page is **3,355px** tall with nothing done on it, and it was 5,152px
before this build. None of the difference is content: the panes, the prose and
the forty-nine methods are exactly what they were. What was removed was white
space, in two kinds.

**The first is the readouts, and it is most of it.** Seventeen of the boxes on
this page are `<textarea>`s and most of them are *answers* — the two Exchange
readouts, the SVID Inspector's output, the certification request's three, the
held identity's two. On a page nobody has done anything on yet **every one of
those is empty**, and each was reserving eight or ten rows for an answer it did
not have: a hundred and eighty pixels of nothing between two panes a reader is
trying to compare. Each now declares `data-min-rows` and `data-max-rows`, opens
at the minimum, and is sized to its content by `fitTextarea()` — from
`setVal()`, which is the single write path for everything this page renders,
from an `input` listener on the boxes somebody types into, and from
`mountAutoFit()` at load, which covers a value restored from storage. The
ceiling is what the old fixed `rows` was really for and it is kept: a
two-hundred-line gRPC answer scrolls inside its own box rather than pushing
every pane below it out of sight.

**The second is the margins**, and there is one trap in it worth recording,
because it is the same one `css/spiffe.css` already carries a comment about for
`.spiffe-field`. Bootstrap's `input[type="text"] { margin-bottom: 10px }` is
specificity (0,1,1) and a bare `.spiffe-status` is (0,1,0), so the status line
kept a 10px bottom margin whatever this sheet said — and in the four panes
where a status line is the **only** thing in its flex row, that made a 20px row
30px tall. The fix is `input.spiffe-status`, naming the element the way
`.spiffe-field` had to.

`spiffe_page.js` asserts all of it, and where it asserts each half matters.
**On a freshly loaded page** (`everyBoxOpensAtItsMinimum()`, called from
`open()`) every textarea must declare both bounds, must open at no more than
four rows, and must already be fitted to whatever it holds — checked there
because by the time the protocol sections below have run, every one of those
boxes has something in it, which is the state that hides this. **After the
inspector has written one** (section 6) the output box must have *grown* to the
answer, which is what tells a box that fits from a box that was simply born
small.

### Why there is a CSR builder

**Five** of the forty-nine methods take a PKCS#10 certification request —
`AttestAgent`, `RenewAgent`, `MintX509SVID`, `BatchNewX509SVID` and
`NewDownstreamX509CA` — because in SPIFFE the requester keeps its own private
key and the authority never sees it. The signature on the request **is** the
proof of possession, and it is what lets an authority certify a key it has
never met. Without a way to build one, five methods on this page would be
unreachable in practice, which would make "every method is here" a claim about
a list rather than about what can be done.

It is `x509.js`'s **`certificationRequest()`**, shared with the PKI page, which
has always had somewhere to put "request a certificate from somebody else" and
no way to build the request. Two things in it are load-bearing and both are
already-paid-for lessons from `issueCertificate()` beside it: **the ECDSA
signature must be minimally encoded** (SPIRE verifies a CSR's signature before
it will mint anything, and an OpenSSL-backed verifier re-encodes what it parsed
and compares bytes — one P-521 request in 256 is otherwise refused as a bad
signature, with a message naming neither the encoding nor the curve), and
**Ed25519 is signed by hand**, because pkijs's engine does not know the
algorithm.

One SPIFFE convention is worth knowing before filling in `subjectAltName`: the
identity of an X509-SVID is the **URI subjectAltName** and nothing else. The
subject DN is decoration — SPIRE issues `C=US, O=SPIRE` to everything — so a
reader who looks at the subject for the identity is looking at the one field
that never carries it. `MintX509SVID` is the one method that reads the URI SAN,
because it has no registration entry to take an identity from.

### The key-material opt-out

This page holds a **private key**, so it carries the checkbox the SAML,
WS-Trust and WS-Federation panes do: **`spiffe_save_identity`**, checked by
default. Clearing it removes `spiffe_identity_cert`, `spiffe_identity_key`,
`spiffe_identity_id` and `spiffe_identity_bundle` **on the spot** — an opt-out
that left yesterday's private key in storage would not be one — and the purge
lives in `saveState()` as well as in the change handler, so no code path can
leave the pair behind. It runs on load too, so upgrading with the box already
clear cleans up. A **missing** checkbox keeps saving, rather than silently
dropping an identity the user expects to still be there. Every other field on
the page is remembered either way.

### Bytes fields take base64, and node's decoder is lenient

Every `bytes` field in these protos — a CSR, an attestation payload, a DER
certificate — goes on the wire as base64. **A join token is text and its field
is `bytes`**, so sending the token as-is means protobufjs base64-decodes it and
the far end gets something shorter and different. `Buffer.from(token,'utf8')
.toString('base64')` is the whole of the fix, and the failure without it names
the token rather than the encoding.

---

## The mock STS

`sts/spiffe/` is a SPIFFE issuing authority for one trust domain
(`spiffe.trustDomain`, `example.org`), in all three server-side shapes, on
**four sockets**. `GET /spiffe` (and `?format=json`) describes all of it and
reports whether each socket actually bound — which nothing else can do, because
`/admin/sts-metadata` is built by walking the Express router and a gRPC listener
registers no route. See `docs/mock-sts.md` and the mock's own
`spiffe/CLAUDE.md`.

**Nothing there is attested**, and that is a narrower sentence than it sounds.
Node has no portable way to read a Unix socket's peer credentials, so a
Workload API caller is identified by its **transport**, the **endpoint** it
reached and its **peer address** — and the selectors are spelt `transport:`,
`endpoint:` and `peer:`, never `unix:` or `k8s:`, because writing `unix:uid:1000`
for a uid nothing read would be inventing an attested fact. What *did* change is
the other half: the SPIRE Server API's TCP port is mutual TLS and every method
is authorized against SPIRE's own table.

Four settings there change what a client sees more than anything else:

| Setting | Why it matters |
|---|---|
| `spiffe.autoCreateEntries` **off** | a caller matching no entry gets an **empty SVID list** — what a real agent does for an unregistered workload, and the only way to run a client's "I have no identity" path |
| `spiffe.attestWorkloads` | selector matching decides which entries answer: the entry's selectors must be a **subset** of the caller's, not equal and not merely intersecting |
| `spiffe.acceptAssertedSelectors` | a caller may assert its own selectors in an `x-sts-mock-workload-selector` header. **Nothing verifies them** — they are the caller's claim, not the service's invention — and it exists so a client's "these matched and those did not" path can be exercised at all |
| `spiffe.adminIds` | SPIRE's own `admin_ids`. The only route from "I can fetch an identity" to "I can drive the registry" that does not already require an administrator |

**Turning `autoCreateEntries` off is not enough on its own**, and working out
why is worth the paragraph. Selector matching narrows to entries whose
selectors are a subset of the caller's, and any earlier Workload API call has
already caused an entry to be **invented** carrying that caller's own stable
selectors — which is a subset of anything the same caller can present, so it
matches for ever. Note which way the arithmetic runs: *asserting* an extra
selector only **widens** the caller's set, so it can make more entries match and
never fewer. There is no request that would miss it. The invented entry has to
be deleted first, which is what `tests/spiffe_protocol.js` does — and the mock
invents it again on the next call once the setting goes back.

### A defect found and fixed while building this

The mock minted the SPIRE Server API's **own listener certificate** with
`spiffe.svidTtl` — an hour by default — and handed it to
`grpc.ServerCredentials.createSsl()`, which holds it for the life of the
process. After an hour of uptime every mutual-TLS client was refused with
`certificate has expired`, and that failure names the **client's** trust store
rather than the server's clock: the obvious first move is to re-fetch the
bundle, which is perfectly good and changes nothing. A fresh container hides it
completely, so it appeared as a SPIRE Server API that works right after a
restart and not otherwise. It now uses `spiffe.caTtl`, which is the true bound —
nothing the authority signs can outlive it — so the listener's certificate lasts
exactly as long as the trust domain it speaks for.

---

## The tests

Four jobs, split by what each one **needs** rather than by what it covers,
which is the division the SCIM three make and for the same reason: a failure in
the first names a rule, in the second a server, in the third the api's own
contract, and in the fourth a page.

| Job | Needs | What only it can see |
|---|---|---|
| `spiffe_engine.js` | **nothing** — never gated, runs on every target including the static ones | the grammar against the specification's own rules; the bundle reader against documents wrong in one way each; the 49-method catalogue against the vendored protos **both ways round**; those protos against the mock's copies byte for byte; every address and socket refusal **by its code**; a PKCS#10 request in four key algorithms verified with **OpenSSL** |
| `spiffe_protocol.js` | the mock's SPIFFE surfaces | all forty-nine methods **actually sent**, as four different entities, with every authorization refusal asserted as the answer it is — and an SVID rotation watched on a held stream |
| `api_spiffe.js` | the api | the **status-code rule**: 400 / 502 / 200-with-the-code |
| `spiffe_page.js` | the api and Chrome | that all forty-nine reach the pickers; the SVID hand-off; the CSR built with Web Crypto (a different implementation from the node one); the three offline readers; the key-material opt-out; and the **shape of the page** — one pane owning every setting, no duplicated id, every fold closed, every control with a tooltip |

**The coverage floor in `spiffe_protocol.js` is a count of methods SENT, not of
assertions.** A method can be in the catalogue, in the picker and on the page
and never have been called, which is exactly the gap that file exists to close.

**It holds the `sts-spiffe` lock** (`JOB_LOCKS` in `tests/run-report.js`),
because it sets `spiffe.adminIds`, shortens `spiffe.svidTtl` and turns
`spiffe.autoCreateEntries` off on a shared process. Each is read first and put
back **per setting** in a `finally` — never with `reset-all`, which would also
undo whatever a concurrent job had pinned. A job fetching an SVID inside that
window would get an empty list, which reads as a Workload API that stopped
issuing.

**Ordering inside that file is load-bearing**: the rotation section runs
*before* the no-identity one, because the latter deletes the invented entry and
leaves `autoCreateEntries` off until the restore runs — a stream held
afterwards is answered with an empty SVID list, which fails as "no certificate
came back" and names rotation for what is really an ordering mistake.

**The `local` entity needs a shared volume.** The mock's SPIRE Server API Unix
socket ships **off**; `docker-compose-run-tests.yml` turns it on at
`/spire-sock/server.sock` and mounts that directory into the tests container,
because `local` is a whole class in SPIRE's table that nothing else can reach
and `Debug.GetInfo` is the only method in it. Without the socket the suite can
assert the refusal and never see the method answer. On a host run the socket is
inside the container's filesystem and the section skips **with a reason** rather
than passing vacuously.

`SPIFFE_AVAILABLE` gates the other three, defaulting to the LDAP answer (the
same question asked of a deployment — "does this target have an api at all")
but its **own** variable, because a target could perfectly well be api-backed
with a directory reachable and no SPIRE server.

---

## Where everything is

| | |
|---|---|
| the page | `client/public/spiffe.html`, `client/public/css/spiffe.css` |
| the bundle | `client/src/spiffe.js`, `client/src/spiffe_history.js` |
| the gRPC client | `api/spiffe_client.js` |
| the protos | `api/protos/` (21 files, vendored verbatim) |
| the shared modules | `common/spiffe/spiffe_id.js`, `common/spiffe/spiffe_bundle.js` |
| the CSR builder | `client/src/x509.js`'s `certificationRequest()` |
| the api's settings | `api/env/*.js`: `spiffeAllowedPorts`, `spiffeAllowedSocketPaths`, `spiffeMaxStreamMessages`, `spiffeStreamTimeout` |
| the page's defaults | `client/src/env/*.js`: `spiffeTrustDomainDefault`, `spiffeWorkloadAddressDefault`, `spiffeServerAddressDefault`, `spiffeBundleUrlDefault` — read by `init()`'s `seed()`, which fills a field only when storage left it empty. **They were declared and read by nothing at all until this build**, so a deployment that set one got an empty box and no complaint from anywhere. `local.js` sets the server address to `http://localhost:8081`, which `parseAddress()` **refuses**: a gRPC address is `host:port`, `tcp://host:port` or `unix:///path`, and an unrecognised scheme is refused rather than defaulted because grpc-js would dial a host called `http`. The refusal names the scheme, and the field's tooltip says so before the call |
| the mock | `sts/spiffe/` — and its own `spiffe/CLAUDE.md`, which is the authority on what that service does and does not check |
