# RISC — the account vocabulary, and the event nobody can send

Read this before touching `client/src/ssf_events.js`'s RISC rows,
`client/src/risc_account.js`, the *Profile* selector and the RISC Account pane
on `client/public/ssf.html`, or `tests/risc_engine.js`.

**OpenID RISC Profile Specification 1.0**, published 29 August 2025 and
approved as a Final Specification on 2 September 2025, spoken over the Shared
Signals pipe that `docs/ssf.md` describes. **This is part three of three, and
the last.** SSF was the plumbing; CAEP is what happened to a **session**; RISC
is what happened to an **account**.

The transmitter this workflow is built against is the mock STS's `/ssf` and
`/admin/risc`, whose own notes are in `sts/ssf/CLAUDE.md`.

---

## The one paragraph to read first

CAEP says *this session is no longer trustworthy*. RISC says *this account is
no longer trustworthy*. Those are two different sentences and the second is the
larger by orders of magnitude: **a revoked session is one sign-in at one
relying party, and a purged account is every session that person has anywhere,
for ever.** CAEP is aimed WITHIN an enterprise and RISC ACROSS providers — its
origin is a consumer provider noticing that an account has been taken over and
telling every site that account signs in to.

Everything below follows from a second fact, and it is the one that decides how
this pane has to be used: **eleven of the fourteen event types carry no payload
members at all, so the subject IS the entire message.** `account-purged` says
nothing but its own type and who it is about. A subject naming the wrong person
is therefore not a partly wrong event — it is a wholly wrong one, with nothing
else in it to notice by.

That is the exact inversion of CAEP, where the subject NARROWS (the person, on
that device, in that session) and the payload says what happened.

---

## The fourteen event types

| Type | Members | Notes |
|---|---|---|
| `account-credential-change-required` | — | a change was REQUIRED, not that one happened |
| `account-purged` | — | permanent. The only terminal state here |
| `account-disabled` | `reason` (open: `hijacking`, `bulk-account`) | may be enabled again |
| `account-enabled` | — | RISC's only good news, and the one everybody forgets |
| `identifier-changed` | `new-value` | **subject MUST be `email` or `phone_number`, and carries the OLD value** |
| `identifier-recycled` | — | same subject rule. The quietest takeover there is |
| `credential-compromise` | `credential_type` (**required**), `event_timestamp`, `reason_admin`, `reason_user` | the only row with a required member, and the only one with any common claims |
| `opt-in` | — | the only event sendable about an opted-out account |
| `opt-out-initiated` | — | and exchange CARRIES ON |
| `opt-out-cancelled` | — | **two Ls**, and it is the specification's spelling |
| `opt-out-effective` | — | an event announcing that there will be no more events |
| `recovery-activated` | — | a judgement, not a fact |
| `recovery-information-changed` | — | what a NON-authoritative provider sends |
| `sessions-revoked` | — | **deprecated** by RISC itself, in favour of CAEP's `session-revoked` |

### The five things implementations get wrong, and none of them is a crash

* **`new-value` IS THE ONLY HYPHENATED MEMBER NAME IN ANY OF THE THREE
  VOCABULARIES.** Everything else in SSF, CAEP and RISC is `snake_case`, so
  `new_value` is what a hand types — and the event validates, delivers, and
  tells the receiver nothing about what the identifier became, because the
  member is optional and its absence is legal. `nearestMember()` in
  `ssf_events.js` names the near miss; the generator deliberately does **not**
  silently correct it, because a debugger that repaired the commonest mistake
  in an event type would be hiding it.
* **`identifier-changed`'s subject carries the OLD value**, which is the
  reverse of every other event in Shared Signals. The mistake produces an event
  saying that an address the receiver has never heard of has become the one it
  already holds — well-formed, delivered, and meaningless.
* **The four common claims are not common here.** CAEP section 2 gives
  `event_timestamp`, `initiating_entity`, `reason_admin` and `reason_user` to
  all eight of its events. RISC gives THREE — no `initiating_entity` — and
  gives them to exactly ONE of its fourteen. Porting CAEP's builder across
  would attach four members to fourteen rows and produce thirteen events
  carrying members their specification does not define; nothing would fail,
  because an unrecognised member is carried and ignored.
* **`sessions-revoked` and `session-revoked` differ by one letter and mean
  different things** — every session this person has, against the one the
  subject names. RISC 1.0 section 2.11 deprecates its own event in favour of
  CAEP's. It is offered here anyway, and warned about on every event: a
  workflow that could not build a deprecated event could not be used to find
  out what a receiver does with one, and receivers in the field still send and
  expect it.
* **`opt-out-cancelled` carries the British double L.** A transmitter writing
  `opt-out-canceled` produces a URI a conforming receiver silently ignores.

### One reading is genuinely open, and this build says which way it went

RISC does **not** repeat CAEP's requirement that `reason_admin` and
`reason_user` be objects keyed by a BCP 47 language tag. That makes a bare
string arguably conforming to RISC and certainly unreadable to a receiver built
against CAEP. Both ends of this project send and expect the **map**, because it
is the reading that is right under both — and `docs/caep.md` records why the
string form has no symptom at all.

And `event_timestamp` means something different here: RISC section 2.7 words it
as when the transmitter **discovered** the compromise rather than when it
happened. A credential found in a breach corpus was compromised long before
anybody noticed, so a receiver reading it as an occurrence time dates the
incident from the wrong end.

---

## The subject: why RISC's is plain and CAEP's is not

**This is the line of JSON that separates the two profiles.** SSF section 4's
*complex subject* exists because a CAEP event is about one SESSION of one
person and a subject identifier names the person — so `{user, session, device}`
is how *that person, on that device, in that session* is expressible at all.

A RISC event is about the ACCOUNT. The person IS the subject, there is nothing
to narrow, and a complex subject here would say *this account was disabled, on
this device*, which is a sentence with no meaning.

**Which format is a choice, and it is the consequential one on the pane**,
because eleven of the fourteen carry no payload:

| format | what it buys |
|---|---|
| `issuer_subject_id` | the identifier a receiver ALREADY holds — it is what an ID Token's `iss` and `sub` said. The default |
| `email` | what a receiver keying on an address expects — and `identifier-recycled` exists precisely because that key is unsafe |
| `phone_number` | RFC 9493's spelling. The RISC text says "phone", which is the OLDER RISC subject-type name and not what SSF 1.0 uses |
| `opaque`, `account` | offered, and rarely what a receiver holds |

**And the two identifier events override it.** `risc_account.js`'s
`subjectFor()` reads the catalogue row's `subjectFormats` rather than the URI,
so that rule is a property of the table. A subject outside the list is a
**warning** and not a refusal, and the difference from `ssf_client.js`'s
refusal of a malformed subject is the whole distinction: that one is
MECHANICAL — a malformed subject names nobody — and this is a conformance
opinion about an event that is perfectly deliverable and merely wrong.

---

## The opt-out gate, and the exception without which it is a trap

RISC section 2.8 gives an account three states and a diagram with four arrows:

```
opt-in --opt-out-initiated--> opt-out-initiated --opt-out-effective--> opt-out
   ^                                  |                                   |
   +-------- opt-out-cancelled -------+                                   |
   +------------------------- opt-in -------------------------------------+
```

The final state means the account is **not participating in event exchange**,
so a conforming transmitter stops sending about it. **The four opt-out events
are never gated, and that exception is the whole rule rather than a
convenience:**

* `opt-out-effective` is the event that ANNOUNCES the silence. Gating it would
  enter that state without telling anybody, so a receiver would see the signals
  simply stop — indistinguishable at the far end from a transmitter that has
  gone down.
* `opt-in` is sent FROM the opt-out state by definition. It is the only way a
  receiver ever learns the account came back, and gating it would make the
  opt-out permanent for every receiver in the world.

The middle state exchanges everything, and the specification says why: it
exists **to stop a hijacker from opting out the moment they take an account
over** and silencing the very events that would report them.

The checkbox on the pane is how the non-conforming case gets built on purpose,
and a suppressed event is counted APART from the total — it is the one number
on the pane that says a receiver heard nothing deliberately, and nothing else
can tell that from a stream nobody agreed.

---

## The debugger's half

### `risc_account.js` — the model, and why it is `caep_session.js`'s sibling

A session and an account are not the same kind of thing. A session begins, is
used and ends, and one person has many; an account IS the person and outlives
every session on it. A model serving both would have had one object that is
sometimes one and sometimes the other.

**No DOM**, so `tests/risc_engine.js` drives all of it in node.

**The state is three things and not one.** A lifecycle (`active`, `disabled`,
`purged`), an opt-out state and a credential standing, moving independently: an
account can be opted out and perfectly healthy, or compromised and still
enabled, or purged with a compromise discovered afterwards.

**The one hard refusal is `account-enabled` on a purged account** — the exact
analogue of the CAEP model's refusal of a `session-presented` on a revoked
session. It is asked by `refusals()` BEFORE anything is built, because a
refusal after signing is a note in a log about a token that already exists.
Everything else that looks wrong is a warning.

**And the register remembers what an address WAS.** `formerIdentifiers` is what
stops `identifier-changed` — the one event whose whole subject is the key —
from making one person look like two at exactly the moment their identifier
changed.

### The seeding problem is not CAEP's, and it is sharper

CAEP's was the SESSION IDENTIFIER: three of the five browser sign-in protocols
cannot supply one, so its pane routinely names a session the workflow invented.
**RISC has no such problem** — every one of the five names a PERSON, which is
all a RISC subject needs, and eleven of the fourteen need nothing else.

**RISC's problem is the other two.** `identifier-changed` and
`identifier-recycled` must carry an address or a number, and an ID Token's
`email` claim is **unverified unless `email_verified` says otherwise** —
OpenID Connect is explicit that it need not be. RISC is equally explicit that
only the provider **authoritative** over an identifier should send those two.
So an identifier event built from an unverified claim is this workflow
asserting an authority it does not have, about an address that may belong to
somebody else — and it is well-formed, delivers, and is undetectable at the far
end.

The pane reports it and does not block it, because reproducing it is exactly
what this page is for. Where no address came at all, one is generated and
**marked in the value** (`debugger-…@example.invalid`), for the reason the CAEP
pane marks an invented session identifier: a plausible address would eventually
be sent at somebody else's mailbox.

The four non-OIDC protocols carry no statement about verification at all, and
the note under the protocol selector says so in those words rather than
reporting a missing `email_verified` claim — which would name a document they
never carried.

### Simulating: the pane drives the Transmit pane, and the ORDER is the design

Every one of the fourteen buttons fills the Transmit pane's type, payload and
`sub_id`, then builds, signs and pushes through the machinery that was already
there — the same argument `docs/caep.md` makes.

**The order is: refuse, then gate, then apply, then push, then count**, and
each step is where it is because of what the one before it would otherwise
leave behind:

* the REFUSAL is asked before anything is built, because a refusal after
  signing is a note about a token that already exists;
* the GATE is asked before the state is applied, because an event that is not
  sent must not move the model — this page is the transmitter, and nothing
  happened;
* the STATE is applied before the push, so a token never exists for something
  this page says cannot have happened;
* the COUNT is of what was actually sent.

---

## The mock's half

`sts/ssf/risc.js` is `caep.js`'s sibling on the other side, and the differences
are the same three. Its own notes are in `sts/ssf/CLAUDE.md`; what matters from
this side:

**It emits when its own DIRECTORY changes, which is a different observer from
CAEP's.** CAEP watches `authn.js` — the authentication layer. RISC watches
`ldap/ldap_server.js` — the provisioning layer:

| Act | Event | Reached over |
|---|---|---|
| a person is deleted | `account-purged` | SCIM, LDAP, the console |
| `active` goes false | `account-disabled` | the same |
| `active` goes true | `account-enabled` | the same |
| `mail` or a number moves | `identifier-changed` | the same |

The observer sits on the STORE and not on a door, which is why it has five call
sites. A RISC feature that only noticed the SCIM one would report a
deprovisioning done with a PATCH and stay silent about one done with an
`ldapmodify` — which is not a smaller feature, it is a transmitter that lies by
omission about half its own traffic, and it is precisely the defect CAEP
shipped with for one revision.

**One directory write can be two events**, which is why the mock's `observe()`
answers with a list where CAEP's answers with one event: a `PUT /Users/:id`
that sets `active` false AND changes a mail address is two RISC events about
one act.

**And `active` still deactivates nobody there.** No endpoint reads it, no bind
is refused and no token is withheld; `/admin/scim` says so, because a mock that
silently pretended would teach a provisioning client that its deprovisioning
path works. What changed is that the service now SAYS so, over RISC — which is
exactly the division the profile draws: a transmitter reports and a receiver
decides.

### Monitoring → RISC accounts

`/admin/risc-accounts` is one row per account the mock has been told anything
about, **including accounts that no longer exist**, with the three states, a
count per event type, and the events it built and deliberately did NOT send.

The register outliving the account is starker than the CAEP one outliving a
session: a purged account is gone from the directory entirely, so the row is
the only remaining evidence anywhere that receivers were told.

### RISC section 3.1 — the only deliberate defect a specification asks for

Google's production RISC transmitter spells a subject identifier's
discriminator `subject_type` rather than `format`. The specification records
this, says the usage is deprecated, says new services MUST NOT use it, and then
tells relying parties they need code to work around it anyway — because that
transmitter is the one their users' accounts live behind.

`risc.googleSubjectType` on the mock renames the member on every RISC subject
it sends, and on nothing else: CAEP and SSF's own events keep `format`, because
their specifications never had the problem. It is how a receiver finds out
whether it has that code before it is pointed at Google.

---

## What this workflow deliberately does not do

* **It does not act on a RISC event.** It shows what arrived, what every check
  said and what state the model is in; enforcing an account disable is the
  receiving application's job, and `docs/ssf.md`'s opening argument is that the
  enforcement — not the receiving — is the hard part. It is harder here than
  for CAEP: an account signal reaches every session, every cached token and
  every downstream service credential that person has.
* **It has no `identifier-changed` about a phone number in the pane's
  suggestion.** The field is there and the format is offered; the suggested
  value is derived from the address, because that is the case anybody
  reproduces.
* **It claims no RISC conformance profile.** There is no interoperability
  profile for RISC as there is (in draft) for CAEP, and claiming one would be
  an idle claim.

---

## The test file, and what only it can see

| File | Needs | What only it can catch |
|---|---|---|
| `tests/risc_engine.js` | nothing | the fourteen URIs written out from the specification, the ONE required member and the ELEVEN types with none, the three common claims on one event and the absent fourth, the only hyphenated member name in the three vocabularies and the near miss that names it, the two rows whose subject format overrides the pane's, the three state machines and the one refusal, and section 2.8's gate with its exception |

**ONE FILE AND NOT THREE, WHERE CAEP HAS THREE, AND THAT IS DELIBERATE.** The
protocol and page halves of a vocabulary over this pipe are the PIPE's halves:
the streams, the deliveries, the envelope and the subject grammar are
vocabulary-independent, which is the whole claim `ssf_events.js`'s header
makes, and `ssf_protocol.js`, `caep_protocol.js`, `ssf_page.js` and
`caep_page.js` already drive every one of them. What RISC adds that those
cannot reach is the catalogue and the model, and neither needs a network or a
browser. The mock's own `sts/tests/risc_register.js` asserts the other side's
independent reading.

The two ends' readings are independent by construction — the URIs and member
names are the WIRE and are identical by necessity; which members are required,
which enumerations are open, which subject formats a row insists on, and what a
state machine refuses are READINGS, and if both ends of this project read one
implementation a misunderstanding they SHARE is one neither can see.
