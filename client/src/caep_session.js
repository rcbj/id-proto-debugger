// File: caep_session.js
//
// ---------------------------------------------------------------------------
// THE SESSION A CAEP EVENT IS ABOUT, AND THE STATE MACHINE THAT FOLLOWS IT.
//
// `ssf_events.js` carries CAEP's eight event types, because that file is the
// VOCABULARY and the whole design of this workflow says a vocabulary is rows
// in its table. This file is what those rows are ABOUT.
//
// **WHY THAT IS A SEPARATE FILE AND NOT MORE ROWS.** A row says what an event
// MEANS. This says what has HAPPENED to one session — which is not a property
// of any event type, cannot be derived from the catalogue, and is the only
// thing the CAEP pane shows that a protocol trace does not already contain.
// Putting it in the catalogue would have made that table's shape specific to
// CAEP, which is the mistake `ssf_events.js`'s header spends a paragraph
// warning about, and RISC would have had to undo it.
//
// ---------------------------------------------------------------------------
// NO DOM, LIKE EVERY OTHER ENGINE HERE, AND FOR A REASON THIS ONE MAKES
// PARTICULARLY WELL.
//
// The defects that matter in a CAEP implementation are never crashes and never
// visible on a screen:
//
//   * a `session-presented` about a session that was already revoked — a
//     transmitter contradicting itself, which a receiver will act on;
//   * a `device-compliance-change` whose `previous_status` is not the status
//     the receiver actually holds, which is the ONLY evidence that an event
//     went missing and is invisible from either event on its own;
//   * a `token-claims-change` applied as a REPLACEMENT rather than a merge,
//     which silently drops every claim the event did not mention;
//   * a complex subject that names the person and forgets the session, so a
//     receiver ends every session that person has.
//
// Every one of those produces a workflow that works perfectly against itself.
// `tests/caep_engine.js` drives all of it in node.
//
// ---------------------------------------------------------------------------
// IT SIMULATES A SESSION; IT DOES NOT HOLD ONE.
//
// The session here is a MODEL, seeded from whatever the OAuth2 / OIDC workflow
// handed over — an ID Token's `sub`, `iss`, `sid`, `acr` and `amr` — and
// editable in every field. That is the honest shape for a debugger: this page
// is pretending to be a transmitter, and a transmitter's session is the one
// thing it has that a receiver has to take on trust.
//
// **AND IT IS WHY THE `sid` MATTERS MORE THAN IT LOOKS.** OpenID Connect's
// `sid` claim (RFC 9552 / OIDC Session Management) is the identifier a real
// transmitter would name in the subject, and an ID Token that carries one is
// the difference between an event about A SESSION and an event about a person
// with a session identifier this page invented. `seedFrom()` says which of the
// two happened, and the pane draws it.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
var ssfClient = require("./ssf_client");
var ssfEvents = require("./ssf_events");

var log = bunyan.createLogger({
  name: "caep_session",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var CAEP_PREFIX = ssfEvents.CAEP_PREFIX;

// The three states CAEP can put a session in, and the ONE that is not a
// synonym for the other two. `established` and `presented` are both "this
// session is alive"; `revoked` is the whole point of the profile.
var STATES = ['established', 'presented', 'revoked'];

// How many simulated events one session remembers. It is a RING and the
// counters are not — see `apply()` — because "how many session-revoked have
// gone out" and "what were the last few" are two different questions, and a
// pane that answered the first out of the second would say ten where there
// were forty.
var EVENTS_KEPT = 40;

// ---------------------------------------------------------------------------
// A NEW SESSION.
//
// Everything is overridable, and everything has a default that is honestly
// SHAPED rather than plausible: the session id is generated here and says so,
// so that nobody mistakes it for something a transmitter minted.
// ---------------------------------------------------------------------------
function newSession(seed) {
  log.debug("Entering newSession().");
  var asked = seed || {};
  var session = {
    iss: String(asked.iss || ''),
    sub: String(asked.sub || ''),
    name: String(asked.name || ''),
    sid: String(asked.sid || generatedId('sid')),
    deviceId: String(asked.deviceId || generatedId('dev')),
    tenant: String(asked.tenant || ''),
    acr: String(asked.acr || ''),
    amr: toStringArray(asked.amr),
    // Where the identifiers came from, which the pane draws. "generated"
    // beside a session id is not a defect and IS something a reader has to
    // know: an event naming a session this page invented is about nothing at
    // the far end.
    source: {
      sub: asked.sub ? 'the ID Token' : 'generated here',
      sid: asked.sid ? 'the ID Token' : 'generated here',
      iss: asked.iss ? 'the ID Token' : 'you'
    },
    startedAt: nowSeconds(),
    state: 'established',
    assurance: { namespace: '', level: '', previousLevel: '' },
    compliance: '',
    risk: { level: '', previousLevel: '', reason: '' },
    claims: {},
    credentials: [],
    counts: {},
    total: 0,
    events: []
  };
  log.debug("Leaving newSession(). sid=" + session.sid);
  return session;
}

// An identifier this page made up, marked as one IN THE VALUE. A random hex
// string would be indistinguishable from a transmitter's, and somebody would
// eventually paste one into a real system and wonder why nothing matched.
function generatedId(kind) {
  log.debug("Entering generatedId(). " + kind);
  var bytes = new Uint8Array(8);
  if (typeof window !== 'undefined' && window.crypto &&
      window.crypto.getRandomValues) {
    window.crypto.getRandomValues(bytes);
  } else {
    for (var i = 0; i < bytes.length; i += 1) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
  var hex = Array.prototype.map.call(bytes, function (one) {
    return ('0' + one.toString(16)).slice(-2);
  }).join('');
  log.debug("Leaving generatedId().");
  return 'debugger-' + kind + '-' + hex;
}

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

function toStringArray(value) {
  if (Object.prototype.toString.call(value) === '[object Array]') {
    return value.filter(function (one) {
      return typeof one === 'string';
    });
  }
  if (typeof value === 'string' && value.trim()) {
    return value.trim().split(/[\s,]+/);
  }
  return [];
}

// ---------------------------------------------------------------------------
// SEED FROM WHAT THE OAuth2 / OIDC WORKFLOW HANDED OVER.
//
// **IT TAKES CLAIMS AND NOT A TOKEN, AND IT VERIFIES NOTHING.** The hand-off
// already decoded the ID Token; this workflow does not CONSUME one, so
// checking its signature here would be answering a question nothing on this
// page asks, and the JWT Tools page is where that is done properly. What this
// does do is say which fields it actually found, because the difference
// between an event about a real session and an event about an identifier this
// page invented is exactly the `sid` claim.
//
// A grant with NO ID Token — client credentials, resource owner password —
// reaches this with an empty object, and that is a supported case rather than
// an error: those flows produce a session at the authorization server too, and
// what is missing is this page's ability to NAME it. The `problems` list says
// so and the pane draws it; nothing is blocked, because a debugger pointed at
// somebody's transmitter is entitled to name whatever subject it likes.
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
        'one.');
  }
  if (!body.sid) {
    problems.push('There is no `sid` claim, so the session identifier below ' +
        'was GENERATED HERE. An event naming it is about nothing at the far ' +
        'end. A transmitter that emits CAEP normally puts its own session ' +
        'identifier in the ID Token; paste one in if you have it.');
  }
  var session = newSession({
    iss: body.iss || (previous && previous.iss) || '',
    sub: body.sub || '',
    name: body.name || body.preferred_username || body.email || '',
    sid: body.sid || '',
    acr: body.acr || '',
    amr: body.amr,
    tenant: body.tid || body.tenant || '',
    deviceId: previous && previous.deviceId ? previous.deviceId : ''
  });
  log.debug("Leaving seedFrom(). " + problems.length + " problem(s).");
  return { session: session, problems: problems };
}

// ---------------------------------------------------------------------------
// THE COMPLEX SUBJECT, AND WHY EVERY CAEP EVENT WANTS ONE.
//
// SSF 1.0 section 4 lets a `sub_id` be an object whose members are each
// themselves a subject identifier, and CAEP is the reason it exists: the
// person is not revoked, ONE SESSION OF THEIRS IS. A subject naming only the
// person asks a receiver to end every session they have — which is a much
// larger instruction than the one that was meant, and it looks perfectly
// reasonable in a log.
//
// `user` is an issuer/subject pair because that is the identifier a receiver
// ALREADY HOLDS: it is what an ID Token's `iss` and `sub` said. `session` and
// `device` are `opaque`, because neither has a shape anybody else can parse
// and RFC 9493 says so by defining no rule for that format's `id`.
//
// **IT IS BUILT THROUGH `ssf_client.js`'s GRAMMAR AND CHECKED BY IT**, which
// is the one place this file could have grown a second reading of RFC 9493 and
// does not. There is one grammar on this side; the mock has its own, written
// independently, and `tests/caep_protocol.js` drives one against the other.
// ---------------------------------------------------------------------------
function complexSubject(session, options) {
  log.debug("Entering complexSubject().");
  var asked = options || {};
  var subject = {};
  if (asked.includeUser !== false) {
    subject.user = { format: 'issuer_subject_id',
      iss: String(session.iss || ''), sub: String(session.sub || '') };
  }
  if (asked.includeSession !== false) {
    subject.session = { format: 'opaque', id: String(session.sid || '') };
  }
  if (asked.includeDevice && session.deviceId) {
    subject.device = { format: 'opaque', id: String(session.deviceId) };
  }
  if (asked.includeTenant && session.tenant) {
    subject.tenant = { format: 'opaque', id: String(session.tenant) };
  }
  log.debug("Leaving complexSubject(). " +
            Object.keys(subject).length + " member(s).");
  return subject;
}

// What is wrong with that subject, through the pipe's own grammar. It is a
// separate call rather than something `complexSubject()` does, because the
// pane draws the subject and the findings in two different places — and a
// builder that refused to return a bad subject would leave nothing to show.
function checkSubject(subject, criticalMembers) {
  log.debug("Entering checkSubject().");
  // A LIST in, an OPTIONS OBJECT on. `validateSubjectId()` takes
  // `{ criticalMembers, path }` and the page holds a bare array — passing the
  // array straight through is silently accepted by that function and turns
  // the check OFF, which is the shape of bug this whole workflow exists to
  // catch in other people's code.
  var verdict = ssfClient.validateSubjectId(subject, {
    criticalMembers: criticalMembers || [],
    path: 'sub_id'
  });
  log.debug("Leaving checkSubject(). ok=" + verdict.ok);
  return verdict;
}

// ---------------------------------------------------------------------------
// WHAT THE PANE SHOULD PRE-FILL FOR ONE EVENT TYPE.
//
// It is derived FROM THE SESSION rather than from constants, and that is the
// whole value of the function: `previous_level` is the level the session is
// actually at, `previous_status` is the compliance it is actually in, and
// `amr` is what it was actually authenticated with. A pane that pre-filled
// constants would produce events that contradict the state it is drawing two
// inches away — and a receiver that noticed would be right.
// ---------------------------------------------------------------------------
function suggest(session, uri) {
  log.debug("Entering suggest(). " + uri);
  var short = uri.indexOf(CAEP_PREFIX) === 0
    ? uri.slice(CAEP_PREFIX.length) : '';
  var values = {};
  if (short === 'session-established') {
    values = { acr: session.acr, amr: session.amr, ext_id: session.sid };
  } else if (short === 'session-presented') {
    values = { ext_id: session.sid };
  } else if (short === 'token-claims-change') {
    values = { claims: { groups: ['staff'] } };
  } else if (short === 'credential-change') {
    values = { credential_type: 'fido2-platform', change_type: 'revoke',
      friendly_name: 'the security key on this laptop' };
  } else if (short === 'assurance-level-change') {
    values = {
      namespace: session.assurance.namespace || 'NIST-AAL',
      // The move this page offers by default is a DECREASE, deliberately.
      // An increase is the case everybody thinks of and the one a receiver
      // usually handles; a session whose assurance quietly fell because a
      // second factor's window closed is the case that is forgotten.
      current_level: session.assurance.level === 'aal2' ? 'aal1' : 'aal2',
      previous_level: session.assurance.level || 'aal1',
      change_direction: session.assurance.level === 'aal2'
        ? 'decrease' : 'increase'
    };
  } else if (short === 'device-compliance-change') {
    var was = session.compliance || 'compliant';
    values = { previous_status: was,
      current_status: was === 'compliant' ? 'not-compliant' : 'compliant' };
  } else if (short === 'risk-level-change') {
    values = { principal: 'SESSION',
      previous_level: session.risk.level || 'LOW',
      current_level: session.risk.level === 'HIGH' ? 'MEDIUM' : 'HIGH',
      risk_reason: 'impossible travel' };
  }
  log.debug("Leaving suggest(). " + Object.keys(values).length + " value(s).");
  return values;
}

// A whole payload: the catalogue's generator plus whichever of the four common
// claims the caller asked for. ONE function, so that the pane, a test and
// anything else produce the same shape — three builders would be three chances
// for one of them to forget `event_timestamp`.
function buildPayload(session, uri, values, options) {
  log.debug("Entering buildPayload(). " + uri);
  var asked = options || {};
  var payload = ssfEvents.generateEvent(uri,
    values || suggest(session, uri));
  if (asked.eventTimestamp !== false) {
    payload.event_timestamp = typeof asked.eventTimestamp === 'number'
      ? asked.eventTimestamp : nowSeconds();
  }
  if (['admin', 'user', 'policy', 'system']
      .indexOf(asked.initiatingEntity) >= 0) {
    payload.initiating_entity = asked.initiatingEntity;
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
// THE STATE MACHINE.
//
// Collected findings rather than a boolean, for the reason `ssf_client.js`
// gives about a subject: an event built on a form is usually wrong in more
// than one way.
//
// **THE ONE HARD REFUSAL IS `session-presented` ON A REVOKED SESSION.** That
// sentence says a session this transmitter has already declared dead was just
// used and honoured — either a transmitter contradicting itself, or a receiver
// about to be told to trust something it was told to stop trusting.
// Everything else that looks wrong is a WARNING, because this is a debugger
// and refusing to build an odd-looking event would remove the ability to
// reproduce one, which is the whole point of the page.
//
// `device-compliance-change` and `risk-level-change` both carry the PREVIOUS
// value, and comparing it against what this model holds is the check nothing
// else can make: a receiver holding "compliant" that gets an event whose
// `previous_status` is "not-compliant" has missed one, and that gap is
// invisible from either event on its own. It is the whole reason CAEP makes
// those members required.
// ---------------------------------------------------------------------------
function apply(session, uri, payload) {
  log.debug("Entering apply(). " + uri);
  var body = (payload && typeof payload === 'object') ? payload : {};
  var errors = [];
  var warnings = [];
  var short = uri.indexOf(CAEP_PREFIX) === 0
    ? uri.slice(CAEP_PREFIX.length) : '';

  if (!short) {
    // An SSF event on a CAEP session is not an error — the pipe's own two
    // travel on the same stream — and it changes nothing about the session.
    log.debug("Leaving apply(). Not a CAEP event.");
    return { ok: true, errors: errors, warnings: warnings,
      state: session.state };
  }

  if (short === 'session-established') {
    if (session.state === 'revoked') {
      warnings.push('This session was revoked and is being established ' +
          'again. That is legitimate — an identifier can be reused — and a ' +
          'receiver that kept the revocation will ignore everything about ' +
          'it from here on, which is worth seeing happen.');
    }
    session.state = 'established';
    if (typeof body.acr === 'string' && body.acr) {
      session.acr = body.acr;
    }
    if (Object.prototype.toString.call(body.amr) === '[object Array]') {
      session.amr = body.amr.slice();
    }
  } else if (short === 'session-presented') {
    if (session.state === 'revoked') {
      errors.push('This session is REVOKED, so it cannot have been ' +
          'presented and honoured. That is either a transmitter ' +
          'contradicting itself or a receiver about to be told to trust ' +
          'something it was told to stop trusting, and it is the one thing ' +
          'this model refuses outright. Reset the session to send it.');
    } else {
      session.state = 'presented';
    }
  } else if (short === 'session-revoked') {
    if (session.state === 'revoked') {
      warnings.push('This session was already revoked. A second revocation ' +
          'is harmless and a receiver should be idempotent about it — which ' +
          'is exactly the thing worth testing, so it is allowed.');
    }
    session.state = 'revoked';
  } else if (short === 'token-claims-change') {
    if (session.state === 'revoked') {
      warnings.push('The claims behind a REVOKED session changed. Nothing ' +
          'is wrong with saying so and there is nothing left to apply it ' +
          'to, which is what makes it worth noticing.');
    }
    if (body.claims && typeof body.claims === 'object') {
      // MERGED and not replaced, which is what `claims` means: the member
      // carries only what MOVED, with its new value. A receiver that
      // replaced would drop every claim the event did not mention — which
      // is most of them.
      Object.keys(body.claims).forEach(function (name) {
        session.claims[name] = body.claims[name];
      });
    }
  } else if (short === 'credential-change') {
    session.credentials.unshift({
      at: nowSeconds(),
      credentialType: String(body.credential_type || ''),
      changeType: String(body.change_type || ''),
      friendlyName: String(body.friendly_name || '')
    });
    session.credentials = session.credentials.slice(0, 10);
    if (String(body.change_type) === 'delete' ||
        String(body.change_type) === 'revoke') {
      warnings.push('A credential was taken away and THE SESSION IS STILL ' +
          'GOOD. That is correct rather than a gap — losing a second factor ' +
          'does not invalidate the session it was used to establish — and ' +
          'it is the CAEP event a receiver acts on without ending anything.');
    }
  } else if (short === 'assurance-level-change') {
    if (session.assurance.level && typeof body.previous_level === 'string' &&
        body.previous_level !== session.assurance.level) {
      warnings.push('This event says the previous assurance level was "' +
          body.previous_level + '" and this session is at "' +
          session.assurance.level + '". One event has been missed, or two ' +
          'transmitters are talking about the same session.');
    }
    session.assurance = {
      namespace: String(body.namespace || session.assurance.namespace || ''),
      level: String(body.current_level || ''),
      previousLevel: String(body.previous_level ||
        session.assurance.level || '')
    };
    if (String(body.change_direction) === 'decrease') {
      warnings.push('Assurance went DOWN. That is the direction everybody ' +
          'forgets can happen without a new sign-in — an expired second ' +
          'factor, or a session carried past the window its step-up was ' +
          'good for — and it is the case a receiver most often has no ' +
          'handling for.');
    }
  } else if (short === 'device-compliance-change') {
    if (session.compliance && typeof body.previous_status === 'string' &&
        body.previous_status !== session.compliance) {
      warnings.push('This event says the device was "' +
          body.previous_status + '" and this session holds "' +
          session.compliance + '". THAT GAP IS INVISIBLE FROM EITHER EVENT ' +
          'ON ITS OWN, and it is the whole reason CAEP makes ' +
          'previous_status required.');
    }
    session.compliance = String(body.current_status ||
      session.compliance || '');
  } else if (short === 'risk-level-change') {
    if (session.risk.level && typeof body.previous_level === 'string' &&
        body.previous_level !== session.risk.level) {
      warnings.push('This event says the previous risk level was "' +
          body.previous_level + '" and this session holds "' +
          session.risk.level + '". One event has been missed.');
    }
    session.risk = {
      level: String(body.current_level || ''),
      previousLevel: String(body.previous_level || session.risk.level || ''),
      reason: String(body.risk_reason || '')
    };
  }

  log.debug("Leaving apply(). " + errors.length + " error(s), " +
            warnings.length + " warning(s).");
  return { ok: errors.length === 0, errors: errors, warnings: warnings,
    state: session.state };
}

// ---------------------------------------------------------------------------
// COUNT ONE EVENT THAT WAS ACTUALLY BUILT.
//
// Separate from `apply()` on purpose. `apply()` answers "may this happen and
// what does it change"; this records that it DID. A pane that counted inside
// apply() would count a refused event, and the refusals are the interesting
// half.
//
// **THE COUNT IS NOT THE LIST.** `counts` never forgets and `events` keeps the
// last forty, because "how many session-revoked have gone out" and "what were
// the last few" are two different questions.
// ---------------------------------------------------------------------------
function record(session, uri, detail) {
  log.debug("Entering record(). " + uri);
  var extra = detail || {};
  session.counts[uri] = (session.counts[uri] || 0) + 1;
  session.total += 1;
  session.events.unshift({
    at: nowSeconds(),
    uri: uri,
    name: (ssfEvents.EVENT_BY_URI[uri] || {}).name || uri,
    jti: String(extra.jti || ''),
    outcome: String(extra.outcome || ''),
    warnings: extra.warnings || []
  });
  session.events = session.events.slice(0, EVENTS_KEPT);
  log.debug("Leaving record(). " + session.total + " event(s).");
  return session.total;
}

// Put the session back to where a fresh one starts, KEEPING THE IDENTITY. What
// is thrown away is what CAEP has said about it; who it is and when it started
// are still true. A reset that regenerated the identifiers would silently move
// the subject under a stream that had already been told about the old one,
// which is the failure this button exists to avoid rather than cause.
function reset(session) {
  log.debug("Entering reset().");
  session.state = 'established';
  session.assurance = { namespace: '', level: '', previousLevel: '' };
  session.compliance = '';
  session.risk = { level: '', previousLevel: '', reason: '' };
  session.claims = {};
  session.credentials = [];
  session.counts = {};
  session.total = 0;
  session.events = [];
  session.startedAt = nowSeconds();
  log.debug("Leaving reset().");
  return session;
}

// What the pane draws: the state, the four things CAEP can change about a
// session, and a count per event type in catalogue order. It is one function
// so that the pane and `tests/caep_engine.js` read the same thing.
function describe(session) {
  log.debug("Entering describe().");
  var counts = ssfEvents.CAEP_EVENTS.map(function (row) {
    return { uri: row.uri, name: row.name,
      short: row.uri.slice(CAEP_PREFIX.length),
      count: session.counts[row.uri] || 0 };
  });
  var out = {
    state: session.state,
    stateWhat: stateWhat(session.state),
    assurance: session.assurance.level
      ? (session.assurance.namespace + ' ' + session.assurance.level) : '',
    compliance: session.compliance,
    risk: session.risk.level,
    riskReason: session.risk.reason,
    claims: session.claims,
    credentials: session.credentials.slice(),
    counts: counts,
    total: session.total,
    events: session.events.slice()
  };
  log.debug("Leaving describe(). " + out.total + " event(s).");
  return out;
}

function stateWhat(state) {
  log.debug("Entering stateWhat(). " + state);
  var text = '';
  if (state === 'revoked') {
    text = 'A receiver that honoured the revocation has ended this session ' +
      'and every token issued on it. Nothing further about it should be ' +
      'acted on.';
  } else if (state === 'presented') {
    text = 'The session was used and honoured — single sign-on. It is the ' +
      'one CAEP event about something entirely ordinary.';
  } else {
    text = 'The session exists and nothing has been said against it.';
  }
  log.debug("Leaving stateWhat().");
  return text;
}

module.exports = {
  STATES: STATES,
  EVENTS_KEPT: EVENTS_KEPT,
  newSession: newSession,
  seedFrom: seedFrom,
  complexSubject: complexSubject,
  checkSubject: checkSubject,
  suggest: suggest,
  buildPayload: buildPayload,
  apply: apply,
  record: record,
  reset: reset,
  describe: describe,
  stateWhat: stateWhat
};
