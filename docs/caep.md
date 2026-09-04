# CAEP — the session vocabulary, and the first event nobody asked for

Read this before touching `client/src/ssf_events.js`'s CAEP rows,
`client/src/caep_session.js`, the *Profile* and *CAEP session* panes on
`client/public/ssf.html`, or any of `tests/caep_engine.js`,
`tests/caep_protocol.js` and `tests/caep_page.js`.

**OpenID Continuous Access Evaluation Profile 1.0**, approved as a Final
Specification on 2 September 2025, spoken over the Shared Signals pipe that
`docs/ssf.md` describes. **This is part two of three.** SSF was the plumbing;
CAEP is what happened to a **session**; RISC — what happened to an **account**
— is part three and is not here.

The transmitter this workflow is built against is the mock STS's `/ssf` and
`/admin/caep`, whose own notes are in `sts/ssf/CLAUDE.md`.

---

## The one paragraph to read first

SSF defines **two** events, both about the pipe. CAEP defines **eight**, all
about a session, and the sentence they exist to carry is *this session is no
longer trustworthy*. RISC's is *this account is no longer trustworthy*. Those
are two different sentences and the difference is the whole reason there are
two profiles rather than one.

Everything below follows from a second fact: **a CAEP event is about a SESSION
and a subject identifier normally names a PERSON.** SSF 1.0 section 4's
*complex subject* exists to close that gap — the person is not revoked, one
session of theirs is — and almost every mistake worth catching in this profile
is a consequence of getting it wrong.

---

## The eight event types

| Type | Required members | Optional |
|---|---|---|
| `session-revoked` | — | — |
| `session-established` | — | `fp_ua`, `acr`, `amr` (**array**), `ext_id` |
| `session-presented` | — | `fp_ua`, `ext_id` |
| `token-claims-change` | `claims` (object) | — |
| `credential-change` | `credential_type`, `change_type` | `friendly_name`, `x509_issuer`, `x509_serial`, `fido2_aaguid` |
| `assurance-level-change` | `namespace`, `current_level` | `previous_level`, `change_direction` |
| `device-compliance-change` | `previous_status`, `current_status` | — |
| `risk-level-change` | `principal`, `current_level` | `previous_level`, `risk_reason` |

And **four claims CAEP section 2 gives every one of them**, all OPTIONAL:
`event_timestamp`, `initiating_entity` (`admin`/`user`/`policy`/`system`),
`reason_admin` and `reason_user`.

They are in `client/src/ssf_events.js`'s table and nowhere else, which is what
that file's header promised while it had two rows in it.

### The five things implementations get wrong, and none of them is a crash

* **`reason_admin` and `reason_user` are LANGUAGE MAPS.** `{"en": "Policy 4.2
  was violated"}`, not a string. It is the commonest mistake in the profile and
  it has **no symptom**: a receiver indexing by language reads nothing from a
  string and reports no error. Both ends of this project refuse a string.
* **`event_timestamp` is OPTIONAL**, which surprises everybody — a receiver
  deciding whether to end a session wants it more than anything else in the
  payload, and a conforming transmitter need not send one. It is also a
  **number** of seconds; the string `"1757000000"` parses everywhere and is
  compared numerically nowhere. The mock's `caep.omitEventTimestamp` produces
  the legal-and-awkward event on purpose.
* **`event_timestamp` is not the SET's `toe` and not `iat`.** `toe` is RFC
  8417's claim on the *token*; this is a member of the event *payload*, and
  CAEP is the specification that defines it. A transmitter may send both, and a
  receiver reading only one of them from a transmitter that sends only the
  other reads nothing at all.
* **`amr` is an ARRAY.** A session authenticated by a password AND a security
  key has two values; a receiver reading a bare string sees one. It is
  **refused** here rather than wrapped, because wrapping hides a sender that
  can only ever say one.
* **`token-claims-change` MERGES.** `claims` carries only what moved, with its
  new value — so a group taken away is the new *list* rather than the group
  that went, and a receiver that replaced rather than merged would drop every
  claim the event was silent about, which is most of them.

### Three enumerations are OPEN and three are closed

`credential_type`, `namespace` (assurance) and `principal` (risk) are lists
CAEP says two parties may extend, so a value outside them is **carried with a
warning**. Refusing would make this workflow unable to build a vendor's own
credential type, which is exactly what a debugger is for; accepting silently
would be worse, because nothing would say that a receiver which has not been
told about it will ignore the event.

`change_type`, `change_direction`, the two compliance statuses, the three risk
levels and `initiating_entity` are **closed** and are refused.

**And one case-sensitivity trap:** `principal` is `SESSION` in upper case and
the complex subject's member is `session` in lower. Both spellings are correct
in their own place and neither is correct in the other's.

---

## The subject: why every CAEP event carries a complex one

`caep_session.js`'s `complexSubject()` builds

```json
{ "user":    { "format": "issuer_subject_id", "iss": "…", "sub": "…" },
  "session": { "format": "opaque", "id": "…" },
  "device":  { "format": "opaque", "id": "…" } }
```

`user` is an issuer/subject pair because that is the identifier a receiver
**already holds** — it is what an ID Token's `iss` and `sub` said. `session`
and `device` are `opaque`, because neither has a shape anybody else can parse
and RFC 9493 says so by defining no rule for that format's `id`.

**A complex subject is told from a plain one by the ABSENCE of `format`**,
which is the specification's own discriminator. The obvious alternative — "does
it have a member called `user`?" — is wrong for an `opaque` subject whose id
happens to be spelt that way.

**Leaving the session out is legal and is the most useful thing this page can
send at a receiver under test.** The subject then names only the person, which
asks the receiver to end *every* session they have — a much larger instruction
than the one that was meant, and one that looks perfectly reasonable in a log.
The pane says so and does not refuse.

`critical_subject_members` is what would make the shape safe: a transmitter
publishing `session` there promises that every complex subject on its streams
carries one, so a receiver that does not understand the member MUST refuse the
event rather than act on the person named beside it. The mock's
`ssf.criticalSubjectMembers` ships **empty**, because turning it on makes every
complex subject refusable by a receiver that has not been told — and this is a
debugger whose job is to let both cases be seen.

### And the rule without which CAEP delivers nothing

A receiver adds the **person** to a stream. That is the only identifier it can
know in advance. Every CAEP event names a **complex** subject whose `user`
member is exactly that identifier — and those two are different
`subjectKey()`s, so a transmitter that matched exactly would refuse every
session event to the receiver that asked for the person, silently, because a
transmitter's refusal to send is not a message anybody receives.

`sts/ssf/ssf_streams.js`'s `streamCoversSubject()` therefore covers a complex
subject when the stream names **any one of its members**. It is deliberately
one level and not recursive: SSF section 4 forbids a complex subject to nest
another, so a member is always a plain identifier.

---

## The debugger's half

### The profile switch

A three-way choice at the top of `ssf.html` — **Pure SSF**, **CAEP**, **RISC** —
stored under `ssf_profile` and restored before the menus are built.

**What it changes is every event list on the page, and both of them matter.**
The Transmit pane's menu and the stream's `events_requested` checkboxes are two
halves of one decision: narrowing the menu without the checkboxes would let
somebody agree a stream for event types the page then has no way to send, and
SSF has no refusal for that — the stream would look perfectly healthy and
deliver nothing.

**What it does NOT change is which panes are there.** Every pane on that page
is used by all three vocabularies: CAEP events travel on the same streams,
through the same deliveries, in the same envelope, so hiding the Stream pane in
CAEP mode would be hiding the thing they travel on. What CAEP *adds* is the
session those events are about.

**RISC is listed and says it is not implemented.** A workflow that omitted the
option would leave a reader unable to tell *this tool does not do RISC* from
*I have not found it yet*, and those are different sentences.

### `caep_session.js` — the model, and why it is not vocabulary

A row in `ssf_events.js` says what an event MEANS. This says what has HAPPENED
to one session — which is not a property of any event type, cannot be derived
from the catalogue, and is the only thing the pane shows that a protocol trace
does not already contain. Putting it in the catalogue would have made that
table's shape specific to CAEP, and RISC would have had to undo it.

**No DOM**, so `tests/caep_engine.js` drives all of it in node.

The state machine has **one hard refusal**: a `session-presented` about a
session that has already been revoked. That sentence says a session this
transmitter has declared dead was just used and honoured — either a transmitter
contradicting itself or a receiver about to be told to trust something it was
told to stop trusting. Everything else that looks wrong is a **warning**,
because refusing to build an odd-looking event would remove the ability to
reproduce one.

Two warnings are worth knowing because nothing else can produce them:
`device-compliance-change` and `risk-level-change` both carry the PREVIOUS
value, and comparing it against what the model holds is the only way to notice
that an event went missing. **That gap is invisible from either event on its
own**, and it is the whole reason CAEP makes those members required.

**The counts are not the list.** `counts` never forgets and `events` keeps the
last forty; *how many session-revoked have gone out* and *what were the last
few* are two different questions.

### The session is seeded from ANY of five browser sign-ins, and that is the fix to the biggest thing this workflow implied

**Until 2026-09-03 this pane read an ID Token and nothing else**, which made
the whole workflow look like an OAuth2 / OIDC feature. It never was. CAEP is a
vocabulary about **sessions**: nothing in `session-revoked` names a token
endpoint, and the profile exists precisely because SAML and OpenID Connect both
authenticate at one instant and leave a session good for hours afterwards. The
mock made the same point from the other end all along — every browser sign-in
there reaches ONE funnel, `authn.startSession()`, and every one of them emits.

`client/src/session_handoff.js` is the route. It is a **sibling** of
`token_handoff.js` and not a generalization of it, for a reason that decided
the design: that module carries a BEARER TOKEN — its slot is the access token,
its `deliver()` refuses a call without one, its scope member is advice about an
OAuth grant — and four of the five sign-ins here produce none of those. Bending
it would have meant a token slot holding something that is not a token, checked
by a guard that had to stop checking.

**What differs between the five is not the identity — it is whether a SESSION
IDENTIFIER exists at all**, and for three of them it does not:

| protocol | where the session identifier comes from |
|---|---|
| OAuth 2.0 / OIDC | the ID Token's `sid` claim, **when the OP issues one** |
| SAML 2.0 | `<saml:AuthnStatement SessionIndex="…">` |
| SAML 1.1 | **nothing** — the protocol has no session index |
| WS-Federation | the SessionIndex of the SAML 2.0 token it carries; a SAML 1.1 token has none, and the IdP chooses which to send |
| SPNEGO | **nothing** — a service ticket names a SERVICE, not a session |

That is the most useful thing the pane reports, because an event naming an
identifier this workflow invented is **well-formed, validates, is accepted by a
receiver, and revokes a session nobody has**. Nothing downstream can tell the
two apart. So `sidFromTheWire` crosses beside the value, an invented one is
marked `debugger-sid-…` in the value itself, and each protocol's warning is
written in its OWN words rather than reporting a missing `sid` claim — which
would name a document three of them never carried.

**WS-Federation is the one that goes either way**, and it is why that flag is
computed from what was FOUND rather than from the profile's name: the same
workflow against the same IdP can hand over a real SessionIndex one run and
nothing the next. Getting that backwards is what the feature shipped with for
one revision — `deliver()` wrote the fact under one member name and the seeder
read another, so a genuine SessionIndex came back marked as invented. Nothing
failed; the note was simply wrong, in the one direction that matters.
`tests/caep_engine.js` now drives the round trip rather than each half.

### The OAuth2 / OIDC seeding, and there are three shapes

| What came back | What the pane says |
|---|---|
| an ID Token with a `sid` | filled from it, **without verifying it** |
| an ID Token with no `sid` | the session identifier was **generated here**, and the value says `debugger-sid-…` so nobody pastes it into a real system |
| **no ID Token at all** | says so, and every field stays editable |

The third is not an error path: **client credentials and resource owner
password are two of the six supported grants and neither issues an ID Token.**
A page that showed an authenticated user it could not name would be the worst
kind of wrong.

It reads claims and **verifies nothing**, and says so on the screen: this
workflow does not consume an ID Token, so checking its signature here would
answer a question nothing on the page asks. The JWT Tools page is where that is
done properly.

### Simulating: the pane drives the Transmit pane rather than signing privately

Every one of the eight buttons fills the Transmit pane's type, payload and
`sub_id`, then builds, signs and pushes through the machinery that was already
there. That is deliberate: the signing key, the algorithm, the media type, the
`iss`/`aud`/`txn` and the receiver endpoint are one set of controls, visible,
with the finished token in the box below them. A CAEP pane that signed
privately would be a second implementation of everything that matters and would
hide the artifact.

**The state is applied before the push and the count after it.** The model
decides whether the event may happen at all — refusing after signing would mean
a token existed for something the page says cannot have happened — and the
count is of what was actually sent.

### Reset, and its one failure mode

*Reset the session and start over* deletes the stream at the transmitter, drops
the push inbox, empties the message, operations and token histories, and puts
the session model back keeping its identity.

**It reports each step separately, and the reason is the step that can fail.** A
reset that could not delete the stream — an expired credential, a transmitter
that is down — and said nothing would leave somebody debugging yesterday's
stream while believing they had started over. That is far worse than a button
that says what it could not do. It asks first, because everything on that list
is somebody's work.

*Reset this session only*, in the CAEP pane, touches nothing at the
transmitter and says so.

---

## The mock's half: the first event nobody asked for

**`GET /ssf`'s list of what this service deliberately does not do used to lead
with "it generates no event on its own".** That was honest while the only
vocabulary was the pipe's own: SSF defines no event about a session, so a
transmitter that emitted one would have been inventing a vocabulary. CAEP *is*
that vocabulary, and the sentence had to go.

Three acts the mock can actually observe now emit on their own:

| Act | Event | Where |
|---|---|---|
| a session is created | `session-established` | `authn.startSession()` — the ONE funnel every browser SSO profile there reaches |
| a session is presented and honoured | `session-presented` | `authn.notePresented()`, from **all four** browser SSO endpoints |
| a session ends | `session-revoked` | `authn.dropSession()`, which every sign-out door reaches |

**`session-presented` was emitted from the OAuth2 authorization endpoint ALONE
until 2026-09-03, and that was the one real gap in this feature.** The other
two were protocol-independent from the day CAEP landed, because both go through
a funnel; a presentation has no funnel — it is a thing each protocol endpoint
decides it is doing — and only `oauth-oidc/oauth2.js` said so. `saml2_sso.js`,
`saml11_sso.js` and `wsfed.js` each called `sessionOf(req)` to answer a request
out of an existing session, which *is* single sign-on, and reported nothing.

A receiver watching a SAML session therefore saw it start and end with every
single sign-on between the two missing — **silently**, because the evidence was
a count of zero, and in this protocol a count of zero is also what *nobody
asked for that type* looks like. The three calls are in place now and
`sts/tests/caep_presented_every_protocol.js` holds them there, in the
submodule, asserting both that `notePresented()` is protocol-independent and
that every browser SSO profile actually calls it.

`caep.autoEmit` puts the old behaviour back rather than leaving it only in the
history of the file.

**The first presentation of a brand-new session is not reported.** Every
sign-in ends with the browser coming back to the authorization endpoint, which
*is* a presentation — so without that rule `session-established` and
`session-presented` would arrive milliseconds apart on every flow, and the
event that is supposed to mean *single sign-on happened* would mean nothing.

The other five events describe things nothing there does — no device reports
compliance to a mock and no risk engine talks to one — so they are emitted by
hand from `/admin/caep` or `POST /admin-api/caep/emit`.

### Monitoring → CAEP sessions

`/admin/caep-sessions` is one row per session the mock has held, **including
the ones it no longer holds**, with the CAEP state it is in, its assurance
level, its device compliance, its risk level and a count per event type.

The register outliving the session is the point rather than a leak: the session
store forgets one the moment it is signed out, so a row saying `revoked` is the
only remaining evidence that it existed and was revoked. Beside it, **which
streams would take a CAEP event at all** — because a count of zero almost
always means nobody asked for that type, and SSF gives a receiver no other
notice of that.

---

## What this workflow deliberately does not do

* **It does not consume CAEP events into a session store.** It shows what
  arrived, what every check said and what state the model is in; enforcing a
  revocation is the receiving application's job, and `docs/ssf.md`'s opening
  argument is that the enforcement — not the receiving — is the hard part.
* **It implements no CAEP Interoperability Profile conformance.** That draft
  pins required event types, endpoint attributes and OAuth authorization, and
  claiming it while it is a draft would be an idle claim.
* **It generates no event on its own.** The *page* is a transmitter you drive;
  the mock is the thing that emits without being asked, and that asymmetry is
  the point — one end of every exchange has to be the one under test.

---

## The test files, and what only each of them can see

| File | Needs | What only it can catch |
|---|---|---|
| `tests/caep_engine.js` | nothing | the eight URIs written out from the specification, every required member and closed enumeration, the language-map refusal, the state machine's hard refusal, the counters against the ring |
| `tests/caep_protocol.js` | a transmitter | that the eight are agreed on a stream, that a sign-in / single sign-on / sign-out each put an event on it with nobody asking, that `caep.autoEmit` off really stops it, and **that the mock's independent reading of CAEP section 3 requires exactly the members this build does** |
| `tests/caep_page.js` | a browser | that the profile switch narrows both lists, that six different grants each seed the session and that the pane says which of the three shapes it got, that every event can be built and signed on an origin with no `crypto.subtle`, and that the reset says what it did |

`caep_protocol.js` is **the only test in this suite whose subject is something
the far end decided to do.** Everything else drives a request and reads the
answer; that one signs somebody in and waits.

### `caep_session_protocols.js` — the event-type x sign-in-protocol matrix

**Five jobs, one per sign-in protocol**, each signing in over its own protocol
and then driving **all eight event types** over the session that produced —
three by really doing the thing (a sign-in, a single sign-on, a sign-out) and
five through `POST /admin-api/caep/emit`, because no device reports compliance
to a mock and no risk engine talks to one.

It is one job per protocol rather than one per combination — the opposite of
the federation grid next door — and the difference is where the cost is. There
each point is a different sign-in and the sign-in is the whole job; here the
sign-in is done once and the eight events over it are a few hundred
milliseconds each, so forty jobs would pay for forty sign-ins to run the same
eight events five times. The report still names the protocol, which is the
property that mattered about the grid.

**Both deliveries, and they prove different things.** Poll (RFC 8936) is the
receiver coming to the transmitter — ordinary HTTPS with a JSON body, so it is
what the page does with no api at all and the only delivery the deployed static
sites can use. Push (RFC 8935) goes through `POST /ssf/receiver` on the api,
because **a page is not an HTTP server** — the one thing in this tree a browser
genuinely cannot do. Sending the same eight both ways is what catches a
transmitter that composes an event correctly for one path and not the other.

**The PUSH half is skipped, by name, on a target with no api** — which is what
`./remote-run-tests.sh https://test.idptools.com` is. Push needs a receiver and
a page is not an HTTP server, so it needs `POST /ssf/receiver` on the api, and
a static deployment has none; `run-report.js` therefore hands the job
`SSF_PUSH_AVAILABLE=false` (from the same fact the SCIM and SSF api jobs are
gated on) and it skips that section and reports 26 checks instead of 35. It is
a SECTION skip and not a job skip on purpose: the sign-in and the poll half say
everything they said before, and poll is the only delivery those sites can use
anyway. Until 2026-09-04 nothing was passed, so four of these five jobs failed
nine checks each on every remote run, naming an api at `https://localhost:4000`
that was never part of the target.

**And it does not merely count arrivals.** Every collected SET goes through the
debugger's own `ssf_client.js` envelope reader and `ssf_events.js` catalogue,
because the defects this profile produces are never crashes and eight malformed
events look exactly like eight good ones from a counter. The mock has its own
reading of RFC 9493 and this side has its own, so agreement there is two
readings agreeing rather than one implementation agreeing with itself.

**Ordering is load-bearing**: `session-revoked` runs LAST, because the model's
one hard refusal is an event about a session that has already ended — driving
it earlier makes the five that follow refusals, and the failure then names the
state machine rather than the ordering.

**SPNEGO is scheduled and skips itself**, with a reason. The mock side is ready
— `/authn/spnego` calls `startSession()` like every other door — but that
endpoint answers `401 WWW-Authenticate: Negotiate`, and answering it needs a
Kerberos service ticket: a KDC, a keytab and a credential cache, which only
`krb5_mit_client.js` has the machinery for. It is a *scheduled* skip rather
than an absent job on purpose: a job nobody schedules is a gap nobody can see.
