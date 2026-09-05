// File: risc_account.js
//
// ---------------------------------------------------------------------------
// THE ACCOUNT A RISC EVENT IS ABOUT, AND THE THREE STATE MACHINES THAT FOLLOW
// IT.
//
// `ssf_events.js` carries RISC's fourteen event types, because that file is
// the VOCABULARY and the whole design of this workflow says a vocabulary is
// rows in its table. This file is what those rows are ABOUT.
//
// It is `caep_session.js`'s SIBLING and not a generalization of it, and the
// reason decided both files: **a session and an account are not the same kind
// of thing.** A session begins, is used and ends, and one person has many; an
// account IS the person, has no beginning this workflow can see, and outlives
// every session on it. CAEP says *this session is no longer trustworthy* and
// RISC says *this account is no longer trustworthy*, and the second is the
// larger sentence by orders of magnitude — a revoked session is one sign-in at
// one relying party, and a purged account is every session that person has
// anywhere, for ever.
//
// A model serving both would have had one object that is sometimes one and
// sometimes the other, and every function on it would have had to ask which.
//
// ---------------------------------------------------------------------------
// NO DOM, LIKE EVERY OTHER ENGINE HERE, AND FOR A REASON THIS ONE MAKES
// PARTICULARLY WELL.
//
// The defects that matter in a RISC implementation are never crashes and never
// visible on a screen:
//
//   * an `identifier-changed` whose subject names the NEW address — the event
//     is well-formed, delivers, and tells the receiver that an address it has
//     never heard of has become the one it already holds;
//   * `new_value` for `new-value` — validates, delivers, says nothing;
//   * any event at all about an account that has opted OUT, which RISC section
//     2.8 says is not participating in event exchange;
//   * `opt-out-effective` SUPPRESSED by an over-eager opt-out gate, so a
//     receiver waits for signals that stopped without notice;
//   * `sessions-revoked` where `session-revoked` was meant — one letter, and
//     the difference between every session this person has and the one the
//     subject names.
//
// Every one of those produces a workflow that works perfectly against itself.
// `tests/risc_engine.js` drives all of it in node.
//
// ---------------------------------------------------------------------------
// THE STATE IS THREE THINGS AND NOT ONE, WHICH IS THE FIRST REAL DIFFERENCE
// FROM THE CAEP MODEL.
//
// A CAEP session has one `state`, because a session is alive or it is not. An
// account has a LIFECYCLE (active, disabled, purged), an OPT-OUT state (RISC
// section 2.8's own three) and a CREDENTIAL standing — and they move
// independently. An account can be opted out and perfectly healthy, or
// compromised and still enabled, or purged with a compromise discovered
// afterwards. Folding them into one word would have meant choosing which of
// three questions this pane answers.
//
// **THE ONE HARD REFUSAL IS `account-enabled` ON A PURGED ACCOUNT**, which is
// the exact analogue of `caep_session.js`'s refusal of a `session-presented`
// on a revoked session: it says a thing this transmitter declared permanently
// deleted is usable again. Everything else that looks wrong is a WARNING,
// because refusing to build an odd-looking event would remove the ability to
// reproduce one.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
var ssfClient = require("./ssf_client");
var ssfEvents = require("./ssf_events");
// The protocol table, shared with the pages that PRODUCE a handoff so that
// both ends answer "which sign-in was this" the same way. See
// seedFromSession() — and note that RISC needs LESS of that module than CAEP
// does, for a reason worth reading there.
var sessionHandoff = require("./session_handoff");

var log = bunyan.createLogger({
  name: "risc_account",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var RISC_PREFIX = ssfEvents.RISC_PREFIX;

// The three lifecycle states. `purged` is TERMINAL — RISC calls it
// "permanently deleted", which is the strongest word in the vocabulary and the
// only one this model enforces anything on.
var LIFECYCLE_STATES = ['active', 'disabled', 'purged'];

// RISC section 2.8's three, in the order its own diagram walks them.
var OPT_STATES = ['opt-in', 'opt-out-initiated', 'opt-out'];

// The four events that ARE a state rather than a report of one — RISC section
// 2.8 words each of them as *"the account is in the X state"* — mapped to the
// state each declares. They are also the four an opt-out gate must never
// suppress; see `gate()`.
var OPT_OUT_EVENTS = {
  'opt-in': 'opt-in',
  'opt-out-initiated': 'opt-out-initiated',
  'opt-out-cancelled': 'opt-in',
  'opt-out-effective': 'opt-out'
};

// How many simulated events one account remembers. A RING, and the counters
// are not — see `apply()` and `record()` — because "how many account-disabled
// have gone out about this person" and "what were the last few" are two
// different questions.
var EVENTS_KEPT = 40;

// ---------------------------------------------------------------------------
// A NEW ACCOUNT.
//
// Everything is overridable and everything has a default that is honestly
// SHAPED rather than plausible. The lifecycle starts `active` because that is
// what an account nobody has said anything about IS; the credential standing
// starts EMPTY rather than at "not compromised", because *this workflow has
// not been told* and *this workflow was told no* are different facts and a
// pane showing the second for the first would be inventing the one thing a
// reader came to look up.
// ---------------------------------------------------------------------------
function newAccount(seed) {
  log.debug("Entering newAccount().");
  var asked = seed || {};
  var account = {
    iss: String(asked.iss || ''),
    sub: String(asked.sub || ''),
    name: String(asked.name || ''),
    email: String(asked.email || ''),
    phone: String(asked.phone || ''),
    // WHETHER THE PROVIDER SAID THE ADDRESS WAS VERIFIED. It travels beside
    // the value rather than gating it, for the reason `caep_session.js`
    // carries `sidFromTheWire`: an event naming an unverified address is
    // well-formed, delivers, and may be about somebody else entirely.
    emailVerified: !!asked.emailVerified,
    phoneVerified: !!asked.phoneVerified,
    // Every address this account has been known by, so that a later event
    // naming a superseded one is still recognisably about this row. It is
    // the model's memory of its own identifier changes, and it is what stops
    // `identifier-changed` — the one event whose whole subject is the key —
    // from making one person look like two.
    formerIdentifiers: [],
    protocol: String(asked.protocol || ''),
    source: {
      sub: asked.sub ? (asked.from || 'the ID Token') : 'generated here',
      iss: asked.iss ? (asked.from || 'the ID Token') : 'you',
      email: asked.email ? (asked.from || 'the ID Token') : 'generated here'
    },
    startedAt: nowSeconds(),
    lifecycle: 'active',
    optOut: 'opt-in',
    credentialStanding: '',
    credentialChangeRequired: false,
    recoveryActivated: false,
    identifierChanges: [],
    credentials: [],
    counts: {},
    total: 0,
    suppressed: 0,
    events: []
  };
  if (!account.email) {
    account.email = generatedEmail(account.sub);
  }
  log.debug("Leaving newAccount(). sub=" + account.sub);
  return account;
}

// An address this page made up, marked as one IN THE VALUE. A plausible
// address would be indistinguishable from a real one, and somebody would
// eventually send an `identifier-changed` about a mailbox belonging to
// somebody else entirely — which is well-formed, delivers, and is the one
// mistake in this vocabulary with a person on the other end of it.
function generatedEmail(sub) {
  log.debug("Entering generatedEmail().");
  var name = String(sub || 'unknown').replace(/[^A-Za-z0-9._-]/g, '');
  var out = 'debugger-' + (name || 'unknown') + '@example.invalid';
  log.debug("Leaving generatedEmail(). " + out);
  return out;
}

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

// ---------------------------------------------------------------------------
// SEED FROM WHAT THE OAuth2 / OIDC WORKFLOW HANDED OVER.
//
// **IT TAKES CLAIMS AND NOT A TOKEN, AND IT VERIFIES NOTHING** — the same
// division `caep_session.js` draws, for its reason: this workflow does not
// CONSUME an ID Token, so checking its signature here would answer a question
// nothing on the page asks, and the JWT Tools page is where that is done
// properly.
//
// ---------------------------------------------------------------------------
// **WHAT IS MISSING HERE IS NOT WHAT WAS MISSING FOR CAEP**, and the contrast
// is the most useful thing this function reports.
//
// CAEP's problem was the SESSION IDENTIFIER: three of the five browser sign-in
// protocols cannot supply one at all, so the pane routinely names a session
// this workflow invented. RISC has no such problem — every one of the five
// names a PERSON, which is all a RISC subject needs, and eleven of the
// fourteen event types need nothing else.
//
// **RISC'S PROBLEM IS THE OTHER TWO, AND IT IS SHARPER.**
// `identifier-changed` and `identifier-recycled` must carry an email address
// or a phone number as their subject, and an ID Token's `email` claim is
// **unverified unless `email_verified` says otherwise** — OpenID Connect is
// explicit that it need not be. RISC is equally explicit that only the
// provider AUTHORITATIVE over an identifier should send those two events. So
// an `identifier-changed` built from an unverified claim is a workflow
// asserting authority it does not have, about an address that may belong to
// somebody else, and it is well-formed and undetectable at the far end.
//
// That is reported rather than blocked, because a debugger pointed at
// somebody's receiver is entitled to name whatever subject it likes — and
// because the case is worth being able to REPRODUCE.
// ---------------------------------------------------------------------------
function seedFrom(claims, previous) {
  log.debug("Entering seedFrom().");
  var body = (claims && typeof claims === 'object') ? claims : {};
  var problems = [];
  if (!body.sub) {
    problems.push('There is no `sub` claim to name the person with. That is ' +
        'the ordinary case for a grant with no ID Token — client ' +
        'credentials and resource owner password both produce one — and ' +
        'the subject below is this page\'s invention until you type a real ' +
        'one. It matters more in RISC than in CAEP: eleven of the fourteen ' +
        'event types carry no payload at all, so the subject IS the ' +
        'message.');
  }
  var account = newAccount({
    iss: body.iss || (previous && previous.iss) || '',
    sub: body.sub || '',
    name: body.name || body.preferred_username || '',
    email: body.email || '',
    emailVerified: body.email_verified === true,
    phone: body.phone_number || '',
    phoneVerified: body.phone_number_verified === true
  });
  identifierProblems(account, body.email ? 'the ID Token' : '')
    .forEach(function (one) {
      problems.push(one);
    });
  log.debug("Leaving seedFrom(). " + problems.length + " problem(s).");
  return { account: account, problems: problems };
}

// ---------------------------------------------------------------------------
// SEEDING FROM A SIGN-IN THAT WAS NOT AN OAuth2 / OIDC ONE.
//
// It takes what `session_handoff.js` carries, from any of the five browser
// sign-in protocols, and produces the same `{ account, problems }` the caller
// already handles.
//
// **IT USES LESS OF THAT MODULE THAN `caep_session.js` DOES, AND THE
// DIFFERENCE IS THE WHOLE DISTINCTION BETWEEN THE TWO PROFILES.** That file
// calls `sessionIdIsReal()` and prints a per-protocol sentence about where a
// session identifier would have come from, because three of the five carry
// none. This one never asks: a RISC subject names a PERSON, every one of the
// five carries one, and the session identifier beside it is simply not what
// these fourteen events are about. The `sid` is carried onto the row anyway —
// it costs nothing and a reader comparing this pane with the CAEP one beside
// it should not have to wonder where it went — but nothing here reads it.
// ---------------------------------------------------------------------------
function seedFromSession(descriptor, previous) {
  log.debug("Entering seedFromSession().");
  var asked = (descriptor && typeof descriptor === 'object') ? descriptor : {};
  var protocol = String(asked.protocol || '');
  var label = sessionHandoff.labelForProtocol(protocol);
  var problems = [];
  if (!asked.sub) {
    problems.push('There is no subject to name the person with. The ' + label +
        ' sign-in did not carry one this workflow could read, and the ' +
        'subject below is this page\'s invention until you type a real one.');
  }
  var account = newAccount({
    protocol: protocol,
    from: 'the ' + label + ' sign-in',
    iss: asked.iss || (previous && previous.iss) || '',
    sub: asked.sub || '',
    name: asked.name || '',
    email: asked.email || '',
    // NOT ASSUMED VERIFIED. Only OpenID Connect has a claim that says so, and
    // the other four protocols carry an address — where they carry one at all
    // — with nothing beside it about whether the provider checked it.
    emailVerified: asked.emailVerified === true,
    phone: asked.phone || '',
    phoneVerified: asked.phoneVerified === true
  });
  identifierProblems(account, asked.email ? 'the ' + label + ' sign-in' : '')
    .forEach(function (one) {
      problems.push(one);
    });
  log.debug("Leaving seedFromSession(). " + protocol + ", " +
      problems.length + " problem(s).");
  return { account: account, problems: problems };
}

// What is wrong with the ADDRESS, which for two of the fourteen event types is
// the whole message. Split out because both seeders need it and because the
// two sentences are different: an address this page invented and an address a
// provider handed over without saying it had checked it are two different
// kinds of wrong, and only the second looks fine.
function identifierProblems(account, from) {
  log.debug("Entering identifierProblems().");
  var problems = [];
  if (!from) {
    problems.push('No email address came with this sign-in, so the one ' +
        'below was GENERATED HERE and says so in the value. It only ' +
        'matters for two of the fourteen event types — identifier-changed ' +
        'and identifier-recycled, whose subject MUST be an address or a ' +
        'number and carries the OLD value — and for those two an invented ' +
        'address makes the event about nothing. The other twelve name the ' +
        'person and are unaffected.');
  } else if (!account.emailVerified) {
    problems.push('The email address came from ' + from + ' and NOTHING ' +
        'SAID IT WAS VERIFIED. OpenID Connect is explicit that `email` need ' +
        'not be, and RISC is equally explicit that only the provider ' +
        'AUTHORITATIVE over an identifier should send identifier-changed or ' +
        'identifier-recycled about it. Sending one from here is this ' +
        'workflow asserting an authority it does not have, about an address ' +
        'that may belong to somebody else — and the event is well-formed, ' +
        'delivers, and is undetectable at the far end. It is allowed, ' +
        'because reproducing it is exactly what this page is for.');
  }
  log.debug("Leaving identifierProblems(). " + problems.length + ".");
  return problems;
}

// ---------------------------------------------------------------------------
// THE SUBJECT, AND WHY IT IS A PLAIN ONE.
//
// **THIS IS THE LINE OF JSON THAT SEPARATES THE TWO PROFILES.** SSF section
// 4's complex subject exists because a CAEP event is about one SESSION of one
// person and a subject identifier names the person — so `{user, session,
// device}` is how *that person, on that device, in that session* is expressed
// at all. A RISC event is about the ACCOUNT. The person IS the subject, there
// is nothing to narrow, and a complex subject here would say *this account was
// disabled, on this device*, which is a sentence with no meaning.
//
// **WHICH FORMAT IS A CHOICE, AND IT IS THE CONSEQUENTIAL ONE**, because
// eleven of the fourteen carry no payload members at all. `issuer_subject_id`
// is the identifier a receiver ALREADY HOLDS — it is what an ID Token's `iss`
// and `sub` said — and `email` is what a receiver keying on an address
// expects, which `identifier-recycled` exists precisely to warn is unsafe.
//
// **AND THE TWO IDENTIFIER EVENTS OVERRIDE IT.** Their subject must be an
// address or a number and must carry the OLD value, so honouring a caller's
// `issuer_subject_id` there would send a subject containing none of the
// message. `subjectFor()` reads the row rather than the URI, so that rule is a
// property of the catalogue.
//
// It is built through `ssf_client.js`'s grammar and checked by it, which is the
// one place this file could have grown a second reading of RFC 9493 and does
// not.
// ---------------------------------------------------------------------------
function subjectFor(account, uri, options) {
  log.debug("Entering subjectFor(). " + (uri || ''));
  var asked = options || {};
  var row = ssfEvents.EVENT_BY_URI[String(uri || '')];
  var forced = row && Object.prototype.toString.call(row.subjectFormats) ===
    '[object Array]' ? row.subjectFormats : null;
  var format = String(asked.format || 'issuer_subject_id');
  if (forced && forced.indexOf(format) < 0) {
    format = forced[0];
  }
  var subject;
  if (format === 'email') {
    subject = { format: 'email', email: String(account.email || '') };
  } else if (format === 'phone_number') {
    subject = { format: 'phone_number',
      phone_number: String(account.phone || '') };
  } else if (format === 'opaque') {
    subject = { format: 'opaque', id: String(account.sub || '') };
  } else if (format === 'account') {
    subject = { format: 'account',
      uri: 'acct:' + String(account.email || account.sub || '') };
  } else {
    subject = { format: 'issuer_subject_id',
      iss: String(account.iss || ''), sub: String(account.sub || '') };
  }
  log.debug("Leaving subjectFor(). " + subject.format);
  return subject;
}

// What is wrong with that subject, through the pipe's own grammar plus the
// catalogue's per-row format rule. A separate call rather than something
// `subjectFor()` does, because the pane draws the subject and the findings in
// two different places — and a builder that refused to return a bad subject
// would leave nothing to show.
function checkSubject(subject, uri, criticalMembers) {
  log.debug("Entering checkSubject().");
  // A LIST in, an OPTIONS OBJECT on — the same trap `caep_session.js` records:
  // `validateSubjectId()` takes `{ criticalMembers, path }` and passing a bare
  // array is silently accepted and turns the check OFF.
  var verdict = ssfClient.validateSubjectId(subject, {
    criticalMembers: criticalMembers || [],
    path: 'sub_id'
  });
  ssfEvents.checkSubjectFormat(uri, subject).forEach(function (one) {
    verdict.warnings = (verdict.warnings || []).concat([one]);
  });
  log.debug("Leaving checkSubject(). ok=" + verdict.ok);
  return verdict;
}

// ---------------------------------------------------------------------------
// WHAT THE PANE SHOULD PRE-FILL FOR ONE EVENT TYPE.
//
// It is derived FROM THE ACCOUNT rather than from constants, which is the
// whole value of the function — and for RISC it does very little, because
// eleven of the fourteen have nothing to fill. That is not a gap: an event
// with nothing to say still carries `{}`, and a pane that invented members for
// one would be building something no specification defines.
// ---------------------------------------------------------------------------
function suggest(account, uri) {
  log.debug("Entering suggest(). " + uri);
  var short = shortNameOf(uri);
  var values = {};
  if (short === 'account-disabled') {
    values = { reason: 'hijacking' };
  } else if (short === 'credential-compromise') {
    values = { credential_type: 'password' };
  } else if (short === 'identifier-changed') {
    // The NEW address, and the OLD one is the subject. Suggested as a
    // recognisable variation of what the account holds rather than as a
    // constant, so that a reader can see at a glance which of the two ends
    // of the change is in which place.
    values = { 'new-value': nextAddress(account.email) };
  }
  log.debug("Leaving suggest(). " + Object.keys(values).length + " value(s).");
  return values;
}

// A plausible successor to an address, for the one event that needs one. It is
// derived so that the pane's suggestion and the subject beside it are visibly
// the same person — an unrelated constant there would make the most confusing
// event in the vocabulary harder to read rather than easier.
function nextAddress(email) {
  log.debug("Entering nextAddress().");
  var text = String(email || '');
  var at = text.indexOf('@');
  var out = at > 0
    ? text.slice(0, at) + '.new' + text.slice(at)
    : 'somebody.else@example.com';
  log.debug("Leaving nextAddress(). " + out);
  return out;
}

function shortNameOf(uri) {
  var text = String(uri || '');
  return text.indexOf(RISC_PREFIX) === 0
    ? text.slice(RISC_PREFIX.length) : '';
}

// ---------------------------------------------------------------------------
// A WHOLE PAYLOAD.
//
// **THE THREE COMMON CLAIMS ARE ADDED ONLY WHERE THE ROW DEFINES THEM**, which
// is one of the fourteen. CAEP's equivalent adds four to every event because
// CAEP section 2 gives them to every event; RISC gives three to
// `credential-compromise` and to nothing else, and a builder that attached
// them everywhere would produce thirteen events carrying members their
// specification does not define. Nothing would fail — an unrecognised member
// is carried and ignored — which is exactly why the guard is here rather than
// left to whoever calls it.
// ---------------------------------------------------------------------------
function buildPayload(account, uri, values, options) {
  log.debug("Entering buildPayload(). " + uri);
  var asked = options || {};
  var payload = ssfEvents.generateEvent(uri,
    values || suggest(account, uri));
  var row = ssfEvents.EVENT_BY_URI[uri];
  var takesThem = !!row && (row.members || []).some(function (member) {
    return member.name === 'reason_admin';
  });
  if (!takesThem) {
    log.debug("Leaving buildPayload(). This type defines none of the three.");
    return payload;
  }
  if (asked.eventTimestamp !== false) {
    payload.event_timestamp = typeof asked.eventTimestamp === 'number'
      ? asked.eventTimestamp : nowSeconds();
  }
  var tag = String(asked.language || 'en');
  if (asked.reasonAdmin) {
    payload.reason_admin = {};
    payload.reason_admin[tag] = String(asked.reasonAdmin);
  }
  if (asked.reasonUser) {
    payload.reason_user = {};
    payload.reason_user[tag] = String(asked.reasonUser);
  }
  log.debug("Leaving buildPayload(). " +
            Object.keys(payload).length + " member(s).");
  return payload;
}

// ---------------------------------------------------------------------------
// THE OPT-OUT GATE, AND THE EXCEPTION WITHOUT WHICH IT IS A TRAP.
//
// RISC section 2.8 says an account in the final `opt-out` state is NOT
// participating in event exchange, so a conforming transmitter stops sending
// about it. This page IS a transmitter you drive, so it reports the gate
// rather than enforcing it: `honour` off is how the non-conforming case gets
// built on purpose.
//
// **THE FOUR OPT-OUT EVENTS ARE NEVER GATED, AND THAT EXCEPTION IS THE WHOLE
// RULE.** `opt-out-effective` is the event that ANNOUNCES the account has
// reached the silent state — gating it would enter that state without telling
// anybody, so a receiver would see the signals simply stop, which at the far
// end is indistinguishable from a transmitter that has gone down. And `opt-in`
// is sent FROM that state by definition: it is the only way a receiver ever
// learns the account came back, and gating it would make the opt-out permanent
// for every receiver in the world.
//
// The middle state exchanges everything, and the specification says why: it
// exists to stop a hijacker from opting out the moment they take an account
// over and silencing the very events that would report them.
// ---------------------------------------------------------------------------
function gate(account, uri, honour) {
  log.debug("Entering gate(). " + uri);
  var short = shortNameOf(uri);
  if (OPT_OUT_EVENTS[short]) {
    log.debug("Leaving gate(). An opt-out event is never suppressed.");
    return { send: true, why: '' };
  }
  if (honour === false) {
    log.debug("Leaving gate(). Not honouring the opt-out.");
    return { send: true, why: '' };
  }
  if (account.optOut !== 'opt-out') {
    log.debug("Leaving gate(). " + account.optOut + " exchanges.");
    return { send: true, why: '' };
  }
  var why = 'This account is in the RISC opt-out state, so a CONFORMING ' +
    'transmitter sends nothing about it but an opt-out event — RISC section ' +
    '2.8 says an opted-out account is not participating in event exchange. ' +
    'Clear the box to send anyway, which is how a receiver that ignores an ' +
    'opt-out gets to be shown doing it.';
  log.debug("Leaving gate(). Suppressed.");
  return { send: false, why: why };
}

// The one rule this model refuses outright, asked WITHOUT changing anything.
// A second function rather than a flag on `apply()`, because a state machine
// with a branch that sometimes writes is one where the next rule added writes
// in both modes by accident — and the symptom would be a model following an
// event the page had refused to send.
function refusals(account, uri) {
  log.debug("Entering refusals(). " + uri);
  var errors = [];
  if (account && account.lifecycle === 'purged' &&
      shortNameOf(uri) === 'account-enabled') {
    errors.push('This account is PURGED, which RISC defines as permanently ' +
        'deleted, so it cannot be enabled. That sentence is either a ' +
        'transmitter contradicting itself or a receiver about to be told to ' +
        'restore access to something that does not exist, and it is the one ' +
        'thing this model refuses outright. Reset the account to send it.');
  }
  log.debug("Leaving refusals(). " + errors.length + " refusal(s).");
  return errors;
}

// ---------------------------------------------------------------------------
// THE STATE MACHINE.
//
// Collected findings rather than a boolean, for the reason `ssf_client.js`
// gives about a subject: an event built on a form is usually wrong in more
// than one way.
//
// **THE OPT-OUT TRANSITIONS ARE THE SPECIFICATION'S OWN DIAGRAM AND ARE STILL
// ONLY WARNINGS.** RISC section 2.8's figure allows exactly four moves;
// anything else is a transmitter that has lost track of its own state, which
// is worth SEEING rather than being unable to produce. And the state is
// APPLIED even when the move was illegal, because the state an event DECLARES
// is the state the receiver will believe — a model that refused to follow
// would be showing something the far end does not think.
// ---------------------------------------------------------------------------
function apply(account, uri, payload) {
  log.debug("Entering apply(). " + uri);
  var body = (payload && typeof payload === 'object') ? payload : {};
  var errors = refusals(account, uri);
  var warnings = [];
  var short = shortNameOf(uri);

  if (!short) {
    // An SSF or CAEP event on a RISC account is not an error — all three
    // travel on the same stream — and it changes nothing about the account.
    log.debug("Leaving apply(). Not a RISC event.");
    return { ok: true, errors: errors, warnings: warnings,
      lifecycle: account.lifecycle, optOut: account.optOut };
  }

  if (errors.length) {
    log.debug("Leaving apply(). Refused.");
    return { ok: false, errors: errors, warnings: warnings,
      lifecycle: account.lifecycle, optOut: account.optOut };
  }

  if (account.lifecycle === 'purged' && short !== 'account-purged') {
    warnings.push('This account is PURGED and something is still being said ' +
        'about it. That is not forbidden — a compromise can be discovered ' +
        'after a deletion — and a receiver that has already removed the ' +
        'account has nothing left to apply it to, which is what makes it ' +
        'worth noticing.');
  }

  if (short === 'account-disabled') {
    if (account.lifecycle === 'disabled') {
      warnings.push('This account was already disabled. A second disable is ' +
          'harmless and a receiver should be idempotent about it, which is ' +
          'exactly the thing worth testing.');
    }
    if (account.lifecycle !== 'purged') {
      account.lifecycle = 'disabled';
    }
    if (typeof body.reason === 'string' && body.reason === 'bulk-account') {
      warnings.push('"bulk-account" is a signal about the PROVIDER rather ' +
          'than about this person: it says the account was one of a ' +
          'population created by a script, and it asks a receiver to look ' +
          'at everything else that arrived at the same time. "hijacking" is ' +
          'the one that is about somebody.');
    }
  } else if (short === 'account-enabled') {
    if (account.lifecycle === 'active') {
      warnings.push('This account was not disabled, so there was nothing to ' +
          'enable. A receiver acting on the pair will have nothing to undo ' +
          '— harmless here, and the shape of a transmitter that sends the ' +
          'whole state on every write rather than the change.');
    }
    account.lifecycle = 'active';
  } else if (short === 'account-purged') {
    if (account.lifecycle === 'purged') {
      warnings.push('This account was already purged.');
    }
    account.lifecycle = 'purged';
  } else if (short === 'account-credential-change-required') {
    account.credentialChangeRequired = true;
    warnings.push('This says a credential change was REQUIRED and not that ' +
        'one happened. Nothing here says the person complied and they may ' +
        'never; what a receiver learns is that this provider no longer ' +
        'trusts what it currently holds.');
  } else if (short === 'credential-compromise') {
    account.credentialStanding = 'compromised';
    account.credentials.unshift({
      at: nowSeconds(),
      credentialType: String(body.credential_type || ''),
      discoveredAt: typeof body.event_timestamp === 'number'
        ? body.event_timestamp : 0
    });
    account.credentials = account.credentials.slice(0, 10);
    if (typeof body.event_timestamp !== 'number') {
      warnings.push('There is no `event_timestamp`, which is legal and is ' +
          'the member this event most needs: RISC words it as when the ' +
          'compromise was DISCOVERED rather than when it happened, and a ' +
          'credential found in a breach corpus was compromised long before ' +
          'anybody noticed.');
    }
  } else if (short === 'identifier-changed') {
    var now = String(body['new-value'] || '');
    if (!now) {
      warnings.push('There is no `new-value`, so this says an identifier ' +
          'the receiver holds is stale without saying what to hold instead. ' +
          'That is legal — the member is optional — and it is nearly ' +
          'useless. NOTE THE HYPHEN: `new_value` is not the member RISC ' +
          'defines and is carried as an extension a receiver ignores.');
    }
    if (account.email &&
        account.formerIdentifiers.indexOf(account.email) < 0) {
      account.formerIdentifiers.push(account.email);
    }
    account.identifierChanges.unshift({ at: nowSeconds(),
      from: account.email, to: now });
    account.identifierChanges = account.identifierChanges.slice(0, 10);
    if (now) {
      account.email = now;
      // The address the model now holds came off an event this page built,
      // not off a provider, so nothing has said it is verified.
      account.emailVerified = false;
    }
  } else if (short === 'identifier-recycled') {
    warnings.push('THIS IDENTIFIER NOW BELONGS TO SOMEBODY ELSE. A receiver ' +
        'keyed on an email address rather than on an iss_sub pair will let ' +
        'the new owner into the old owner\'s account, and nothing anywhere ' +
        'was compromised — which is the whole argument for not keying on an ' +
        'address, and the reason this event type exists.');
    if (account.email &&
        account.formerIdentifiers.indexOf(account.email) < 0) {
      account.formerIdentifiers.push(account.email);
    }
  } else if (short === 'recovery-activated') {
    account.recoveryActivated = true;
    warnings.push('A recovery flow is how a legitimate owner gets back in ' +
        'AND how an attacker who controls the recovery channel takes over, ' +
        'and a transmitter cannot tell which. A receiver is expected to ' +
        'weigh it rather than act on it.');
  } else if (short === 'sessions-revoked') {
    warnings.push('This is the PLURAL event: every session this account ' +
        'has, everywhere, which is a far larger instruction than CAEP\'s ' +
        'session-revoked whose subject names ONE of them. The two names ' +
        'differ by one letter.');
  } else if (OPT_OUT_EVENTS[short]) {
    applyOptOut(account, short, warnings);
  }

  log.debug("Leaving apply(). " + errors.length + " error(s), " +
            warnings.length + " warning(s).");
  return { ok: errors.length === 0, errors: errors, warnings: warnings,
    lifecycle: account.lifecycle, optOut: account.optOut };
}

// RISC section 2.8's figure, written out.
function applyOptOut(account, short, warnings) {
  log.debug("Entering applyOptOut(). " + short);
  var from = account.optOut;
  var legal = {
    'opt-out-initiated': ['opt-in'],
    'opt-out-cancelled': ['opt-out-initiated'],
    'opt-out-effective': ['opt-out-initiated'],
    'opt-in': ['opt-out', 'opt-out-initiated']
  };
  if ((legal[short] || []).indexOf(from) < 0) {
    warnings.push('RISC section 2.8\'s state diagram has no ' + short + ' ' +
        'out of the "' + from + '" state — it allows one only from ' +
        (legal[short] || []).join(' or ') + '. It is applied anyway, ' +
        'because the state this event DECLARES is the state the receiver ' +
        'will believe, and a model that refused to follow would be showing ' +
        'something the far end does not think.');
  }
  if (short === 'opt-out-effective' && from === 'opt-in') {
    warnings.push('This skipped opt-out-initiated, which is the state that ' +
        'exists to stop a hijacker opting out the moment they take an ' +
        'account over and silencing the events that would report them.');
  }
  account.optOut = OPT_OUT_EVENTS[short];
  log.debug("Leaving applyOptOut(). " + from + " -> " + account.optOut);
}

// ---------------------------------------------------------------------------
// COUNT ONE EVENT THAT WAS ACTUALLY BUILT.
//
// Separate from `apply()` on purpose, for `caep_session.js`'s reason:
// `apply()` answers "may this happen and what does it change"; this records
// that it DID. A pane that counted inside apply() would count a refused event,
// and the refusals are the interesting half.
//
// **THE COUNT IS NOT THE LIST.** `counts` never forgets and `events` keeps the
// last forty.
// ---------------------------------------------------------------------------
function record(account, uri, detail) {
  log.debug("Entering record(). " + uri);
  var extra = detail || {};
  account.counts[uri] = (account.counts[uri] || 0) + 1;
  account.total += 1;
  account.events.unshift({
    at: nowSeconds(),
    uri: uri,
    name: (ssfEvents.EVENT_BY_URI[uri] || {}).name || uri,
    jti: String(extra.jti || ''),
    outcome: String(extra.outcome || ''),
    warnings: extra.warnings || []
  });
  account.events = account.events.slice(0, EVENTS_KEPT);
  log.debug("Leaving record(). " + account.total + " event(s).");
  return account.total;
}

// One event this page built and deliberately did NOT send, because the account
// had opted out. It is counted separately from `total` and that is the whole
// point of the number: it is the one count on this pane that says a receiver
// heard nothing ON PURPOSE, which nothing else can distinguish from a stream
// nobody agreed.
function recordSuppressed(account, uri) {
  log.debug("Entering recordSuppressed(). " + uri);
  account.suppressed += 1;
  log.debug("Leaving recordSuppressed(). " + account.suppressed + ".");
  return account.suppressed;
}

// Put the account back to where a fresh one starts, KEEPING THE IDENTITY. What
// is thrown away is what RISC has said about it; who they are is still true.
//
// It is a reset and not a delete for a reason sharper here than in the CAEP
// model: taking the row away is what `account-purged` MEANS, and a control
// that faked it would be the one confusion this pane cannot afford.
function reset(account) {
  log.debug("Entering reset().");
  account.lifecycle = 'active';
  account.optOut = 'opt-in';
  account.credentialStanding = '';
  account.credentialChangeRequired = false;
  account.recoveryActivated = false;
  account.identifierChanges = [];
  account.credentials = [];
  account.counts = {};
  account.total = 0;
  account.suppressed = 0;
  account.events = [];
  account.startedAt = nowSeconds();
  log.debug("Leaving reset().");
  return account;
}

// What the pane draws: the three states, the identifiers, and a count per
// event type in catalogue order. One function, so that the pane and
// `tests/risc_engine.js` read the same thing.
function describe(account) {
  log.debug("Entering describe().");
  var counts = ssfEvents.RISC_EVENTS.map(function (row) {
    return { uri: row.uri, name: row.name,
      short: row.uri.slice(RISC_PREFIX.length),
      deprecated: String(row.deprecated || ''),
      count: account.counts[row.uri] || 0 };
  });
  var out = {
    lifecycle: account.lifecycle,
    lifecycleWhat: lifecycleWhat(account.lifecycle),
    optOut: account.optOut,
    optOutWhat: optOutWhat(account.optOut),
    credentialStanding: account.credentialStanding,
    credentialChangeRequired: account.credentialChangeRequired,
    recoveryActivated: account.recoveryActivated,
    email: account.email,
    emailVerified: account.emailVerified,
    phone: account.phone,
    formerIdentifiers: account.formerIdentifiers.slice(),
    identifierChanges: account.identifierChanges.slice(),
    credentials: account.credentials.slice(),
    counts: counts,
    total: account.total,
    suppressed: account.suppressed,
    events: account.events.slice()
  };
  log.debug("Leaving describe(). " + out.total + " event(s).");
  return out;
}

function lifecycleWhat(state) {
  log.debug("Entering lifecycleWhat(). " + state);
  var text = '';
  if (state === 'purged') {
    text = 'PERMANENTLY DELETED. A receiver that honoured it has removed ' +
      'the account and everything keyed on it, and nothing said afterwards ' +
      'has anything left to apply to. It is the only terminal state in the ' +
      'vocabulary.';
  } else if (state === 'disabled') {
    text = 'Disabled, and it MAY come back. That is what separates it from ' +
      'a purge, and account-enabled is the event everybody forgets to ' +
      'implement — a receiver that acts on the disable and ignores the ' +
      'enable has locked somebody out permanently over a resolved incident.';
  } else {
    text = 'The account exists and nothing has been said against it.';
  }
  log.debug("Leaving lifecycleWhat().");
  return text;
}

function optOutWhat(state) {
  log.debug("Entering optOutWhat(). " + state);
  var text = '';
  if (state === 'opt-out') {
    text = 'NOT PARTICIPATING. RISC section 2.8 says a conforming ' +
      'transmitter sends nothing about this account but an opt-out event, ' +
      'and the two exceptions are the reason the rule works at all: ' +
      'opt-out-effective announces the silence and opt-in is the only way ' +
      'out of it.';
  } else if (state === 'opt-out-initiated') {
    text = 'The person asked to stop AND EXCHANGE CARRIES ON. That delay is ' +
      'deliberate: it stops a hijacker opting out the moment they take an ' +
      'account over and silencing the events that would report them.';
  } else {
    text = 'Participating in RISC event exchange.';
  }
  log.debug("Leaving optOutWhat().");
  return text;
}

module.exports = {
  LIFECYCLE_STATES: LIFECYCLE_STATES,
  OPT_STATES: OPT_STATES,
  OPT_OUT_EVENTS: OPT_OUT_EVENTS,
  EVENTS_KEPT: EVENTS_KEPT,
  newAccount: newAccount,
  seedFrom: seedFrom,
  seedFromSession: seedFromSession,
  subjectFor: subjectFor,
  checkSubject: checkSubject,
  suggest: suggest,
  buildPayload: buildPayload,
  gate: gate,
  refusals: refusals,
  apply: apply,
  record: record,
  recordSuppressed: recordSuppressed,
  reset: reset,
  describe: describe,
  lifecycleWhat: lifecycleWhat,
  optOutWhat: optOutWhat
};
