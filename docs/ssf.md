# Shared Signals (SSF) — the seventeenth protocol, and the first that talks back

Read this before touching `client/public/ssf.html`, `client/src/ssf*.js`,
`api/ssf_proxy.js`, `api/ssf_receiver.js`, `POST /ssf/call`, the api's push
receiver, or any of the four `tests/*ssf*.js`.

**OpenID Shared Signals Framework 1.0**, approved as a Final Specification on
2 September 2025, over **RFC 8417** (Security Event Tokens), **RFC 9493**
(Subject Identifiers), **RFC 8935** (push delivery) and **RFC 8936** (poll
delivery). The transmitter this workflow is built against is the mock STS's
`/ssf`, whose own notes are in `sts/ssf/CLAUDE.md`.

**This is part one of three.** SSF is the plumbing; **CAEP** and **RISC** are
two different vocabularies spoken over it, and neither is implemented yet. The
whole of this workflow is arranged so that adding one is rows in a table — see
*The one thing to hold on to* below.

---

## The problem it solves, because it is not obvious from the endpoints

SAML and OpenID Connect authenticate at **one instant**. After that the relying
party holds a session or a token that stays valid for its lifetime — often hours
or days — regardless of what happens next. Fire somebody at ten and their
session keeps working until the token expires. Shortening token lifetimes to fix
that trades security for load and user friction.

Shared Signals inverts it: the identity provider **tells** the relying party
when something changed. That is the whole idea, and every design decision below
follows from the fact that this is the one protocol here where the traffic
originates at the far end.

**The hard part is not receiving the events.** It is what an application does
with *session revoked* when its own session store, its caches and its downstream
service tokens all have independent lifetimes. A signal that arrives in 200ms
and is enforced forty minutes later at token refresh is not continuous access
evaluation, it is a faster audit log. Nothing in this debugger can test that for
you; what it can do is make every part of the wire visible, which is the half
that is otherwise guesswork.

---

## The one thing to hold on to: SSF is the pipe and not the vocabulary

SSF defines how two parties agree a **stream**, who the events on it are about,
what they travel in and how they get there — and **exactly two events of its
own**, both about the pipe:

| Event | What it is |
|---|---|
| `…/ssf/event-type/verification` | The receiver asked "is this stream alive?" and this is the answer travelling the **ordinary delivery path**. It is the only end-to-end test a stream has: a 200 from the management API says the configuration was accepted and says nothing about whether an event can reach the receiver. |
| `…/ssf/event-type/stream-updated` | The stream's status changed and the receiver is being told **in band**. It is the one event a receiver gets without asking, and the one whose absence is hardest to notice: a stream quietly paused at the transmitter looks exactly like a service where nothing has happened lately. |

The vocabularies are:

* **CAEP** — the enterprise SESSION vocabulary. Session revoked, token claims
  change, credential change, assurance level change, device compliance change.
  It says *this session is no longer trustworthy*.
* **RISC** — the account-lifecycle vocabulary, aimed ACROSS providers rather
  than within one enterprise. Account disabled, purged, credentials
  compromised, credential change required, identifier changed or recycled. It
  says *this account is no longer trustworthy*.

Those are two different sentences and the distinction is the reason there are
two specifications.

### What that means for this code

`client/src/ssf_events.js` is the vocabulary and **is the only file the next two
parts change**. `client/src/ssf_client.js` is the pipe — the subject grammar,
the SET envelope, stream configurations, both deliveries — and it names no event
type anywhere. The same split holds in the mock (`sts/ssf/ssf_events.js` against
everything else in that directory), on the console page, and in the management
API.

**If a function in `ssf_client.js` ever grows a branch that names one of SSF's
two event types, that is the design going wrong**, and it will have to be undone
twice.

The page says which vocabularies are here and which are not, rather than leaving
a two-item list to be read as a broken page: `FAMILIES` in `ssf_events.js` marks
CAEP and RISC `implemented: false` with a sentence each, and `tests/ssf_engine.js`
asserts that an absent family says so.

---

## The five modules, and why none of them has a DOM

| Module | What it holds |
|---|---|
| `client/src/ssf_client.js` | **The pipe.** RFC 9493's eight subject formats with their closed member sets and SSF's complex subject; discovery and the endpoint lookup; stream configurations; the RFC 8417 envelope and every finding a SET can produce; both deliveries. |
| `client/src/ssf_events.js` | **The vocabulary.** SSF's two event types, the three families, and the validator. |
| `client/src/ssf_history.js` | The two histories — the token sets and the event messages — and the redaction. |
| `api/ssf_proxy.js` | What `POST /ssf/call` will and will not forward. No axios and no network. |
| `api/ssf_receiver.js` | The push inbox the api hosts on the page's behalf. No express and no network. |

`client/src/ssf.js` is the DOM and nothing else, which is the rule `scim.js` and
`digital_signature.js` follow. What it buys is that `tests/ssf_engine.js` drives
the interesting half in node with no browser — and the defects that matter in
this protocol are never crashes:

* a subject identifier with an extra member, which every conforming receiver
  MUST reject and which looks perfectly fine in a log;
* an `exp` on a SET, which asks a receiver to discard history (RFC 8417 section
  4.1.4 forbids one);
* `events_requested` read back as `events_delivered`, so a receiver waits for
  event types nothing will ever send;
* a delivery method spelt `push` rather than `urn:ietf:rfc:8935`;
* a SET sent as `application/jwt`, which a receiver dispatching on the media
  type drops with no error anybody sees;
* a `sub` claim where SSF puts `sub_id`, so a client reads nothing.

Every one of those produces a workflow that works perfectly against itself.

---

## The subject grammar is written twice on purpose

`common/krb5` is vendored into the mock because **one wire codec must not exist
twice**. RFC 9493 is the opposite case and the two look alike, so the reasoning
is worth stating.

A subject identifier is JSON, and the defect that matters in it is a READING —
an accepted extra member, a missing required one, a format name spelt from
memory. If both ends read one implementation, a misunderstanding they SHARE is
one neither can see: the round trip passes and the workflow interoperates with
nothing.

So `client/src/ssf_client.js` has this side's grammar, `sts/ssf/ssf_subjects.js`
has the mock's, they were written independently, and **`tests/ssf_protocol.js`
drives one against the other over the wire** — all eight formats, the complex
subject, and three refusals. That is the argument `common/pq_jose.js` makes in
the mock about the composite construction, applied to a grammar instead of to a
signature.

### The eight formats, and the rule that catches people

`account` (an `acct:` URI), `email`, `issuer_subject_id`, `opaque`,
`phone_number`, `decentralized_identifier`, `uri`, `aliases`.

**Each format's member set is CLOSED.** RFC 9493 section 3 gives every format an
exhaustive list of members and a conforming receiver must REJECT an identifier
carrying one it does not recognise — it cannot tell whether the extra member
NARROWS the subject. That is the check `ssf_client.js` makes and the mock makes
independently, and it is the one nothing else would.

Three value rules are worth knowing because a comparison depends on them:

* `phone_number` is **E.164** — a leading `+` and digits only. `+1 206 555 0100`
  is a DIFFERENT subject from `+12065550100` to any receiver that compares them.
* `account.uri` must carry the `acct:` scheme. A bare address is the `email`
  format and a `mailto:` is the `uri` one — three formats, one string, and the
  scheme is what tells them apart.
* `opaque.id` has **no** shape rule, by definition. A check on it would be this
  tool inventing one.

`aliases` **may not contain another `aliases`** (section 3.2.8). This workflow
refuses that rather than flattening it, because flattening builds a document a
conforming receiver rejects and the sender never finds out.

### The complex subject is what makes CAEP possible

SSF 1.0 section 4 lets a `sub_id` be an object whose members — `user`, `device`,
`session`, `tenant`, `org_unit`, `group` — are each themselves a subject
identifier. That is what makes *"this session was revoked"* expressible at all:
the person is not revoked, one session of theirs is.

A complex subject is told from a simple one by the **absence of `format`**,
which is the specification's own discriminator. The obvious alternative — "does
it have a member called `user`?" — is wrong for an `opaque` subject whose id
happens to be spelt that way, and `tests/ssf_engine.js` asserts exactly that
case.

`critical_subject_members` in the transmitter's metadata names the members a
receiver MUST understand. Publishing one is a promise, so this workflow refuses
to SEND a complex subject that omits it — the transmitter would refuse it
anyway, and the message is more useful on this side.

---

## Discovery: this workflow composes no paths

SSF fixes **no endpoint paths**. Every one of them is published in the
transmitter's configuration metadata, so `ssf.js` reads them out of that document
and composes none — a transmitter that publishes its stream management API at
`/v1/streams/manage` is driven with nothing typed, and a member the document does
not carry produces a sentence naming it rather than a request to a path this tool
invented.

The document is looked for at `/.well-known/ssf-configuration` in **both**
shapes, insertion first: RFC 8414 inserts the well-known segment before the
issuer's path and OpenID Connect Discovery appends it, and a transmitter
published under a path can be either. That is the same arrangement
`metadata_client.js` makes for an issuer.

`METADATA_MEMBERS` in `ssf_client.js` carries every member with what it is FOR
and whether SSF makes it required, and the page draws the whole table beside the
document it fetched — because **a reader cannot tell a missing OPTIONAL member
from a missing REQUIRED one by looking**. A member this build does not know is
REPORTED and not refused: SSF metadata extends, and one that is not in the table
is a transmitter doing something extra rather than something wrong.

Two members decide more than they look like they do:

* **`default_subjects`** says what an EMPTY subject list means, and the two
  answers are opposites. `ALL`: the stream is about everybody and adding a
  subject narrows nothing. `NONE`: it is about nobody until one is added. A
  receiver that guesses wrong gets every event in the estate or gets none, and
  both look like a broken transmitter — which is why SSF makes it discoverable
  rather than leaving it to be inferred.
* **`delivery_methods_supported`** values are the **RFC numbers as URNs**.
  `urn:ietf:rfc:8935` is push and `urn:ietf:rfc:8936` is poll; `"push"` and
  `"poll"` are not method identifiers, and that catches everybody once. The page
  offers the friendly word and sends the URN.

---

## The stream, and the two members most often confused

`events_requested` is the **ask** and `events_delivered` is the **answer** — the
intersection of the ask with what the transmitter supports.

**SSF has no refusal for an event type a transmitter will not agree to.** Its
absence from `events_delivered` is the only notice a receiver gets, so a client
that reads the first back as the second waits for events nothing will ever send.
`readStreamConfiguration()` compares the two and the page draws the difference as
a finding; `tests/ssf_engine.js` asserts it.

`PUT` **replaces** and `PATCH` **merges**, and the difference is real: a PUT that
behaved like a PATCH would let a receiver believe it had cleared
`events_requested` when it had not, and the symptom is event types still arriving
after they were "removed". `tests/ssf_protocol.js` asserts both directions
against the mock.

`aud` is **required** and this workflow refuses to send a configuration without
one. So does the mock, and `sts/ssf/CLAUDE.md` argues why it does not default it
to the authenticated caller: a receiver whose audience was invented for it never
learns the member is required, and the audience it checks for ITSELF in would be
a name the transmitter chose.

### The three statuses, and the one that matters

`enabled`, `paused`, `disabled`. **A paused stream keeps queueing and delivers
nothing; a disabled one drops what is waiting.** That is the difference between
*"I was not listening"* and *"it did not happen"*, and it is the whole reason a
receiver taking a maintenance window pauses rather than disables.
`tests/ssf_protocol.js` asserts both halves against a real transmitter: an event
asked for during a pause comes back after the resume, and one queued before a
disable does not survive it.

---

## Delivery, and the one asymmetry that cannot be designed away

**RFC 8936 poll delivery works in a browser. RFC 8935 push delivery cannot.**

Poll has the receiver come to the transmitter, which a page can do. Push has the
transmitter POST to the receiver — so the receiver has to be REACHABLE, and **a
browser is not an HTTP server**. That is a property of the two specifications
rather than of this tool, and no amount of proxying changes it.

So the api hosts an RFC 8935 endpoint on the page's behalf
(`api/ssf_receiver.js`): the page asks for an inbox, gets a URL, puts it in the
stream's `delivery.endpoint_url`, and drains what arrives. **On the hosted
static sites there is no api and therefore no push**, and the page says so in its
`callPath` row rather than offering a stream that would be agreed and silently
deliver nothing.

### The push inbox is an unauthenticated endpoint that accepts data

Which is the most dangerous shape anything in the api has, so it is worth
knowing what bounds it. It HAS to be unauthenticated — what pushes to it is
somebody else's transmitter, and the only credential in that exchange is the
`authorization_header` the receiver chose — so the bounds are structural rather
than a gate:

1. an inbox exists only because somebody asked, and its id is 32 hex characters
   of `crypto.randomBytes`;
2. every inbox expires (`ssfReceiverTtlMs`, an hour) and is swept from every
   entry point rather than on a timer;
3. the counts are capped — inboxes, events per inbox, and the OLDEST event goes
   when the ring fills, because a receiver that has stopped draining most wants
   what has happened lately;
4. each event is size-capped;
5. `ssfReceiverEnabled` turns the whole thing off, and it is false wherever
   there is no api at all.

**Nothing is executed, rendered or forwarded**, and the api verifies no
signature: it holds no key of the transmitter's, and a receiver that refused what
it could not verify would be unable to show anybody WHY — which is the question
the workflow exists to answer. The PAGE verifies.

### `ack` and `setErrs` both take an event off the queue

`ack` names what the receiver STORED. `setErrs` names what it REFUSED, and that
one catches people: a receiver that could not process an event will not process
it next time either, so a transmitter that redelivered would poll-loop for ever.
The refusal is recorded on the stream instead, where a person can see it.

`moreAvailable` is the member a client most often ignores, and ignoring it means
assuming one poll drains the queue. The page lifts it out and says so.

---

## Push delivery crosses TLS now, and the mock had to be told

The api serves **https** (`common/tls_listener.js`), and `POST /ssf/receiver`
builds the `deliveryEndpoint` it hands back from `req.protocol` — so the URL
that goes into a stream's `delivery.endpoint_url` is
`https://api:4000/ssf/receiver/:id` with nothing having been told to change.
Two consequences, and both were found by tests rather than anticipated.

**The transmitter has to trust that certificate.** The mock STS is the only
service here that makes an outbound connection TO the api, and a push is it.
The stack's certificate is therefore handed to that container as
`NODE_EXTRA_CA_CERTS` in every compose file — which is the whole reason the
pair is generated ONCE, on the host, before compose starts, rather than by each
service at its own startup: an environment cannot carry an anchor for a
certificate that does not exist yet. Without it the push dies at the handshake
and the page waits for an event that was never delivered, which reads as a
transmitter that sent nothing.

**And the api has to trust its own.** `POST /ssf/call` is a proxy the caller
aims, and this workflow legitimately aims it at this same service's own
receiver — which is how `tests/api_ssf.js` asserts the third outcome (a far-end
refusal comes back as a 200 carrying it) with no transmitter in the picture.
Before `api/sts_truststore.sh` learned to write a **bundle** rather than point
`NODE_EXTRA_CA_CERTS` at one file, that call failed verification and the proxy
reported a **502** — "the far end did not deliver" — so a receiver correctly
refusing a malformed Security Event Token was indistinguishable from a network
failure. `NODE_EXTRA_CA_CERTS` names one file and node reads it once, so two
anchors is a concatenation or it is nothing.

## The Security Event Token, and the three things implementations get wrong

A SET is a JWT whose payload carries an `events` **map** from event-type URI to
that event's payload. Not an array, and not a single event — the map is what lets
one token carry a set of events that happened together, and it is why the media
type says "secevent" rather than "event".

* **`typ` is `secevent+jwt`.** RFC 8417 section 2.2 makes it a SHOULD that
  behaves like a MUST: a receiver that dispatches on it — several do — drops a
  token without it with no error anybody sees. The page can send the wrong media
  type **on purpose**, because that is the only way to find out whether a
  receiver under test has this right.
* **There is no `exp` and that is not an oversight.** Section 4.1.4 says a SET
  MUST NOT be considered to expire: it records that something HAPPENED, and a
  fact does not stop being true. An implementation that adds one is asking
  receivers to discard history.
* **`sub` is not the subject.** Section 2.2 discourages `sub` and SSF uses
  `sub_id` (RFC 9493) instead, because the thing an event is about may be a
  person AND a device AND a session at once and a string cannot say that. A
  client that reads `sub` silently reads nothing from a conforming transmitter,
  and the mock's `ssf.legacySubClaim` exists to catch exactly that client.

`toe` is **not** `iat`. The Time Of Event is when the thing happened; `iat` is
when the token was minted. A token issued now may report something from an hour
ago, and a receiver deciding whether to end a session cares about the first.

`inspectSet()` and `inspectSetHeader()` report **every check by name** rather
than one boolean, and the page draws them that way. A single *"valid: true"* over
a token whose `aud` is somebody else is the most dangerous thing this page could
say.

---

## Post-quantum, and why a SET is the document that most wants it

Every signature in this workflow goes through **`jws.js`**, which is the module
that already does every JWS in this application — so this page gets every
registered algorithm for no code at all, including **ML-DSA** at three sizes,
**SLH-DSA**, and the six **composite ML-DSA + traditional** algorithms.
`ssf.signingAlgorithm` picks one at the mock.

**A SET is the document in this application most worth signing post-quantum.** It
records that something HAPPENED, RFC 8417 forbids it to expire, and it is
therefore read long after it was written — which is precisely the case a
harvest-now-decrypt-later argument is about. Every other signed artefact here
has a lifetime measured in minutes or hours.

`tests/ssf_engine.js` signs and verifies a SET with one algorithm from **every**
family `jws.js` offers, and `tests/ssf_protocol.js` pushes an ML-DSA-signed one
at the mock.

### It found a defect in the mock's centralized crypto

RFC 8417's `typ` is asked for through `helpers.signJwtAs()`. `jsonwebtoken`
merges a caller's `options.header`, so the library path had always honoured it —
but the mock's two hand-rolled signers, the `ownSigner` branch (EdDSA and
ES256K) and the post-quantum branch, each hard-coded `typ: 'JWT'` and ignored
`options.header` entirely. The same call produced a different header depending on
which algorithm was chosen, and no caller could have seen that coming.
`protectedHeaderFor()` in `sts/common/crypto.js` is the fix.

---

## Two call paths, and what a static deployment loses

Every call this page makes can go two ways, exactly as the SCIM page's can.
FRONTEND is a `fetch` from the browser and is the default; BACKEND goes through
`POST /ssf/call`. The browser path works with **no api at all**, which is why
this page ships to the hosted static sites and its landing card is not greyed.

The api path exists for three things a browser cannot do — and the first bites
harder here than on the SCIM page:

* **CORS.** A transmitter's stream management API is a control plane: it decides
  who gets told that somebody's session was revoked, and it sends no
  `Access-Control-Allow-Origin`. All the page can see is `TypeError: Failed to
  fetch`, which is indistinguishable from a DNS failure, a dead host and a bad
  certificate.
* **A self-signed certificate**, which a browser refuses and which a debugger
  pointed at somebody's staging transmitter meets constantly.
* **The exchange itself.** A browser withholds the headers it adds and CORS
  withholds most of those that come back, so a browser-direct call can only ever
  be reported by halves.

On a build with no api the BackEnd option is **switched off** rather than merely
marked — the distinction `css/pki.css` records about its own disabled pane: a
radio that only looks grey is still selectable with a keyboard, and the refusal
would then come from a fetch to an api that is not there, which reads as a broken
page. `tests/ssf_page.js` asserts it, and asserts that the note says push
delivery is unavailable too.

### The three outcomes

A refusal by the api is a **400**. A network failure is a **502**. **An SSF error
from the transmitter is a 200**, carrying that status and its RFC 8935
`{err, description}`.

The third matters more here than anywhere else this pattern is used, because of
what an SSF refusal SAYS: `invalid_audience` on a stream whose `aud` is wrong, a
404 on a stream_id that was deleted, a 403 naming the scope, a 400 naming the
member of a subject identifier RFC 9493 does not define. Every one of those is
the transmitter explaining exactly what is wrong, in a sentence, and they are the
most useful thing this workflow can put on the screen. An endpoint that reported
them as failures would throw all of it away.

---

## The two histories, and where each one lives

The workflow keeps **both**, and they answer different questions.

**The token history** is every set of tokens used in this session, the way the
OAuth2 / OIDC results page keeps one — because an SSF receiver's whole
relationship with a transmitter runs on a bearer token, a stream outlives the
token that created it, and *"which token was I holding when that stream stopped
answering"* has no other way of being asked. It is a **separate store** from that
page's `token_history` and not a second view of it: these are the tokens this
workflow HAS USED, which is a different set from the tokens that page has
obtained.

It is in **`sessionStorage`**, which is the opposite of what the OAuth2 / OIDC
page does with its own and is deliberate. That page's history is the point of the
page; here a token is a CREDENTIAL this workflow is using to drive somebody's
control plane, and the page can do everything it does without one surviving a
tab. `token_handoff.js` makes the same choice for the same reason.

**The message history** is every Security Event Token sent or received, whole,
with what it decoded to and what every check said. It is in **`localStorage`**,
and the reason is that a SET is **evidence rather than a credential** — holding
one grants nothing and presenting one to anybody achieves nothing — and evidence
is what a debugger most needs to survive a navigation. What IS stripped is the
`Authorization` header of the exchange that carried it, which is a credential and
is the one part of a push that is.

`tests/ssf_page.js` asserts both stores, and asserts that the access token, the
ID Token and the transmitting private key reach neither.

---

## The hand-off carries the whole token set, and that is new

The SCIM page introduced `token_handoff.js`: a page marks itself as waiting, the
browser goes to the OAuth2 / OIDC workflow, and the access token comes back. That
page wants a bearer token and nothing else.

This workflow needs more, and the reason is worth stating: **an access token this
project's mock issues is opaque to a client**, so a page holding one cannot say
who is signed in. The identity is in the **ID Token**. A hand-off that carried
only the bearer credential would leave this page showing an authenticated user it
could not name — and the ticket asked for exactly that.

So `deliver()` takes an optional third argument and `take()` answers with an
optional `set` member: `{ idToken, refreshToken, tokenType, scope, expiresIn }`.
It is **additive** — a caller that passes nothing is unaffected, and `take()`'s
existing answer goes on meaning what it meant — and `oauth2_oidc_2.js` fills it
at all three of its token-bearing responses.

The page reads the ID Token's claims **without verifying them**, and says so.
This workflow does not consume an ID Token, so checking its signature would be
answering a question nothing here asks; the JWT Tools page is where that is done
properly. A page that implied otherwise would be the worst kind of wrong.

---

## What this workflow deliberately does not do

* **It generates no event on its own**, and neither does the mock. Every SET
  either was asked for at the verification endpoint or was built by hand in the
  Transmit pane. That is honest rather than unfinished: **SSF defines no event
  about a session**, so anything that emitted one would be inventing a
  vocabulary. It changes with CAEP.
* **It does not retry a failed push.** `sts/ssf/ssf_http.js` argues it: a mock
  that retried would make a receiver's one-shot failure invisible, because a
  client answering 500 then 202 looks from its own logs like a client that works.
* **It verifies no signature it has no key for**, and reports that as NOT
  CHECKED rather than as valid. A page that showed "no key" as a pass would be
  teaching the opposite of what this protocol needs.
* **It offers no `alg: none` when transmitting.** A SET says somebody's session
  was revoked; an unsigned one says anybody who can reach the endpoint can claim
  it. The Digital Signature page is where an unsecured JWS is built on purpose,
  and this page still REPORTS one that arrives.

---

## The four tests, and what each is for

| File | Needs | What only it can see |
|---|---|---|
| `tests/ssf_engine.js` | nothing | Every rule, against the specifications' own text. All eight subject formats and every refusal, the SET envelope signed with every algorithm family including the post-quantum ones, stream configurations, both deliveries, the vocabulary table, the two histories, and every bound on the api's two modules. Never skips. |
| `tests/ssf_protocol.js` | a transmitter | One grammar against another over the wire. The whole stream lifecycle, every subject format the mock's own reader accepts, what a pause keeps that a disable drops, poll and push end to end — it hosts an RFC 8935 listener of its own — and both deliberate defects. |
| `tests/api_ssf.js` | the api | The wiring: the body parser for `application/secevent+jwt` (without which every push reads as an empty body), the three outcomes as HTTP statuses, the address policy still covering this endpoint, and the push receiver. |
| `tests/ssf_page.js` | a browser | That the bundle ran at all, the `callPath` row, both histories, the extended hand-off, the `ssf-` classes and a clean console. |

They are four rather than one so that a failure NAMES something: a rule, a
transmitter, the api's contract, or a page. `ssf_protocol.js` and `ssf_page.js`
share the `sts-ssf` job lock, because the first turns the mock's two deliberate
defects on one at a time and a job polling that transmitter inside that window
would report a bad signature as its own failure.

---

## Settings

### The api (`api/env/*.js`)

| Setting | What |
|---|---|
| `ssfMaxRequestBytes` | The largest request body `POST /ssf/call` forwards. Separate from `maxContentLength`, which bounds the response: an Add Subject carrying a fifty-member `aliases` identifier is a large request and an EMPTY response. |
| `ssfReceiverEnabled` | Whether this api hosts a push inbox. Only an explicit `false` turns it off. |
| `ssfReceiverTtlMs` | How long an inbox lives. |
| `ssfReceiverMaxInboxes`, `ssfReceiverMaxEvents`, `ssfReceiverMaxEventBytes` | The three caps. |

There is deliberately **no `ssfAllowedPorts`**, for the reason there is no
`scimAllowedPorts`: SSF is HTTP, and a port allowlist for HTTP would have to
carry 80, 443 and every alternate somebody runs a service on.

### The client (`client/src/env/*.js`)

`ssfTransmitterUrlDefault` — the transmitter's base URL, resolved **by the
browser** by default (like `scimBaseUrlDefault`, unlike `ldapUrlDefault`).
Switching `callPath` to BackEnd moves the resolution to the api, and on the
containerized stack that is a different host.

### The mock transmitter

Twenty-seven rows in the `SSF` group of `sts/common/config.js`, drawn on
`/admin/ssf`. `sts/ssf/CLAUDE.md` argues the ones with consequences; the two to
know first are `ssf.signingAlgorithm` (which reaches the whole post-quantum
table) and `ssf.defaultSubjects` (which decides what an empty subject list
means).
