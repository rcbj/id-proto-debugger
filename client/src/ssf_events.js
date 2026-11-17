// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: ssf_events.js
//
// ---------------------------------------------------------------------------
// THE EVENT VOCABULARY, AND THE ONE FILE THE NEXT TWO PARTS OF THIS WORK
// CHANGE.
//
// The Shared Signals Framework is a PIPE. `ssf_client.js` is the pipe — the
// subject grammar, the SET envelope, the stream management, both deliveries —
// and it names no event type anywhere. THIS file is the vocabulary, and it
// exists as a file of its own for one reason: CAEP and RISC are two more
// vocabularies over the same pipe, and adding them must be rows in the table
// below and NOTHING ELSE. If a function in `ssf_client.js` ever grows a branch
// naming an event type, that is this separation going wrong.
//
// SSF 1.0 defines exactly two of its own, and both are about the pipe rather
// than about a person:
//
//   VERIFICATION    the receiver asked "is this stream alive?" and this is the
//                   answer travelling the ORDINARY DELIVERY PATH. It is the
//                   only end-to-end test a stream has — a 200 from the
//                   management API says the configuration was accepted and
//                   says nothing about whether an event can reach the
//                   receiver.
//   STREAM UPDATED  the stream's own status changed, and the receiver is being
//                   told IN BAND rather than having to poll the status
//                   endpoint. It is the one event a receiver gets without
//                   asking for it, and the one whose absence is hardest to
//                   notice: a stream quietly paused at the transmitter looks
//                   exactly like a service where nothing has happened lately.
//
// **BOTH VOCABULARIES ARE HERE NOW** — CAEP's eight since 2026-09-03 and
// RISC's fourteen since 2026-09-04 — and the claim this header made while the
// table had two rows in it held: adding them was rows in the table below, plus
// two models of what those rows are ABOUT (`caep_session.js` and
// `risc_account.js`), which is not vocabulary and cannot be derived from a
// catalogue. `ssf_client.js` still names no event type anywhere.
//
// CAEP: session revoked, established and presented, token claims change,
// credential change, assurance level change, device compliance change and risk
// level change — all about a SESSION, all carrying `reason_admin`,
// `reason_user`, `initiating_entity` and an `event_timestamp`, and all with a
// COMPLEX subject, because "this session was revoked" is a sentence about a
// session and not about a person.
//
// RISC: account disabled, enabled and purged, credential change required,
// credential compromise, identifier changed and recycled, the four opt-out
// events, recovery activated, recovery information changed and one deprecated
// event — all about an ACCOUNT, all with a PLAIN subject, and eleven of the
// fourteen with no payload members at all. The two answer different questions
// and the distinction is the whole reason there are two: CAEP says "this
// session is no longer trustworthy", RISC says "this account is no longer
// trustworthy".
//
// ---------------------------------------------------------------------------
// NO DOM. Values in, values out, so `tests/ssf_engine.js` drives every event
// type, every member and every generator in node — which is the only kind of
// check that can say anything about a payload, where a wrong answer and a
// right one are both a small JSON object.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");

var log = bunyan.createLogger({
  name: "ssf_events",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// The URI prefix SSF's own event types share. Written once because both rows
// below and both vocabularies that come after them hang off it, and a typo in
// one produces an event a receiver silently ignores — there is no "unknown
// event type" error in this protocol.
var SSF_PREFIX = require("./catalog/ssf_prefix.json");

// The two VOCABULARY prefixes. Both have rows in the table below now, and
// each is written once because a prefix is the thing most likely to be typed
// from memory and got subtly wrong — there is no "unknown event type" error
// in this protocol, so a receiver silently ignores what it does not
// recognise.
var CAEP_PREFIX = require("./catalog/caep_prefix.json");
var RISC_PREFIX = require("./catalog/risc_prefix.json");

// ---------------------------------------------------------------------------
// THE CATALOGUE, AND WHERE ITS ROWS LIVE.
//
// The rows are DATA and are written once, in models/catalog/ssf_events.tsp,
// as typed TypeSpec consts; models/tools/generate.mjs writes each to
// client/src/catalog/<name>.json and this module requires them. The row model
// there is closed, so a row with a member its model does not declare, an
// enumeration member with no `values`, or a CAEP row without a subject is a
// compile error rather than an event nobody can read. tests/data_model.js
// fails when the tables exported here stop equalling those files.
//
//   uri        the event type, which is the KEY in a SET's `events` map
//   family     'ssf', 'caep' or 'risc'
//   subject    'none' | 'optional' | 'required'. THE TWO SSF EVENTS ARE THE
//              ONLY ONES IN ANY OF THE THREE VOCABULARIES WITH NO SUBJECT AT
//              ALL, and the reason is worth keeping: they are about the
//              STREAM. A receiver that insisted on a subject could not be
//              verified.
//   members    the payload's own members, with `required` on each
//   generate   builds a payload from what a form holds, filling what it can.
//              Every row has one, so "send me one of these" is one call from
//              the page and from a test alike. It is CODE, so it is the one
//              thing a row has that is written here: GENERATE below, keyed by
//              the row's `uri`, attached by withGenerators().
// ---------------------------------------------------------------------------
var GENERATE = {};

// Whether two values from the catalogue are the same JSON. Both sides come
// out of one generator, so their keys are in one order and a string compare
// is exact.
function sameJson(a, b) {
  log.debug("Entering sameJson().");
  var same = JSON.stringify(a) === JSON.stringify(b);
  log.debug("Leaving sameJson(). " + same);
  return same;
}

// The one object in `pool` that is the same JSON as `value`, or `value`.
function sharedOne(value, pool) {
  log.debug("Entering sharedOne().");
  var found = pool.filter(function (one) {
    return sameJson(one, value);
  })[0];
  log.debug("Leaving sharedOne(). " + (found ? "shared" : "own"));
  return found || value;
}

// The catalogue's rows with each one's generator attached. A row is COPIED
// rather than written to, so the JSON a require() caches stays exactly what
// the generator wrote. A row with no generator is refused at load: it would
// otherwise be an event type the page lists and cannot send.
//
// SHARING IS RESTORED HERE, because JSON cannot say it. In the model a CAEP
// row's last four members ARE the CAEP_MEMBER_* consts and both credential
// lists ARE CAEP_CREDENTIAL_TYPES; the generated file holds a copy of each at
// every use. So a member equal to one of `members`, and a `values` list
// equal to one of `lists`, is replaced by that one object — which is what
// lets tests/risc_engine.js hold RISC's credential_type list to CAEP's BY
// IDENTITY, as RISC 1.0 section 2.7 defines it by reference. Equality and not
// a name decides it, so a list that drifted would stop being shared and that
// test would say so.
function withGenerators(rows, members, lists) {
  log.debug("Entering withGenerators(). " + rows.length + " row(s).");
  var sharedMembers = members || [];
  var sharedLists = lists || [];
  var out = rows.map(function (row) {
    var copy = {};
    Object.keys(row).forEach(function (key) {
      copy[key] = row[key];
    });
    if (typeof GENERATE[row.uri] !== 'function') {
      throw new Error('ssf_events: "' + row.uri + '" is in the catalogue ' +
          'and has no generate() function here.');
    }
    copy.members = row.members.map(function (member) {
      var one = sharedOne(member, sharedMembers);
      if (one === member && member.values) {
        var values = sharedOne(member.values, sharedLists);
        if (values !== member.values) {
          one = {};
          Object.keys(member).forEach(function (key) {
            one[key] = member[key];
          });
          one.values = values;
        }
      }
      return one;
    });
    copy.generate = GENERATE[row.uri];
    return copy;
  });
  log.debug("Leaving withGenerators().");
  return out;
}

GENERATE[SSF_PREFIX + 'verification'] = function (values) {
  log.debug("Entering generate(). verification");
  var asked = values || {};
  var payload = {};
  if (typeof asked.state === 'string' && asked.state !== '') {
    payload.state = asked.state;
  }
  log.debug("Leaving generate(). verification");
  return payload;
};

GENERATE[SSF_PREFIX + 'stream-updated'] = function (values) {
  log.debug("Entering generate(). stream-updated");
  var asked = values || {};
  var allowed = ['enabled', 'paused', 'disabled'];
  var payload = {
    status: allowed.indexOf(asked.status) >= 0 ? asked.status : 'enabled'
  };
  if (typeof asked.reason === 'string' && asked.reason !== '') {
    payload.reason = asked.reason;
  }
  log.debug("Leaving generate(). stream-updated");
  return payload;
};

var SSF_EVENTS = withGenerators(require("./catalog/ssf_events.json"));

// ---------------------------------------------------------------------------
// CAEP — THE SESSION VOCABULARY (OpenID Continuous Access Evaluation Profile
// 1.0, final 2 September 2025).
//
// **THESE ROWS WERE WRITTEN INDEPENDENTLY OF THE MOCK'S, AND THAT IS THE SAME
// ARGUMENT `ssf_client.js` MAKES ABOUT RFC 9493.** The URIs and the member
// names are the WIRE and are identical by necessity; everything around them —
// which members are required, what each value may be, which enumerations are
// closed and which the specification leaves open — is a READING. If both ends
// of this project read one implementation, a misunderstanding they SHARE is
// one neither can see: the round trip passes and the workflow interoperates
// with nothing. `sts/ssf/ssf_events.js` has the other reading and
// `tests/caep_protocol.js` drives one against the other over the wire.
//
// **WHAT CAEP SAYS THAT SSF DOES NOT.** SSF's two events are about the PIPE.
// These eight are about a SESSION, and the sentence they carry is *this
// session is no longer trustworthy* — which is a different sentence from
// RISC's *this account is no longer trustworthy*, and the whole reason there
// are two profiles rather than one.
//
// **EVERY ONE OF THEM IS `subject: 'required'`**, which is the half that is
// got wrong, and the subject a conforming transmitter sends is normally SSF's
// COMPLEX one: the person is not revoked, one session of theirs is. A subject
// naming only the person asks a receiver to end every session that person
// has — a much larger instruction than the one that was meant, and one that
// looks perfectly reasonable in a log.
// ---------------------------------------------------------------------------

// The four claims CAEP section 2 gives EVERY event, all of them optional.
// Written once in the catalogue, as a const of its own per member, and listed
// at the end of each CAEP row's members there: eight copies of four member
// descriptions is eight places for a spelling to drift, and there is
// no "unknown member" error in this protocol — a receiver reading
// `reason-admin` for `reason_admin` finds nothing and says nothing.
//
// **`event_timestamp` IS NOT THE SET's `toe` AND IT IS NOT `iat`.** `toe` is
// RFC 8417's claim on the TOKEN; this is a member of the event PAYLOAD, and
// CAEP is the specification that defines it. A transmitter may legitimately
// send both, and a receiver that reads only one of them from a transmitter
// that sends only the other reads nothing at all.
var CAEP_COMMON_MEMBERS = require("./catalog/caep_common_members.json");

// ---------------------------------------------------------------------------
// THE CREDENTIAL TYPES, WRITTEN ONCE BECAUSE TWO SPECIFICATIONS SHARE THEM BY
// REFERENCE RATHER THAN BY COINCIDENCE.
//
// CAEP 1.0 defines this list for `credential-change`. RISC 1.0 section 2.7
// then says that `credential-compromise`'s `credential_type` "must be one of
// the values specified for the similarly named field in the Credential Change
// event defined in the CAEP Specification" — so the two lists are not merely
// alike, they are the SAME list, and a second copy of it would be one that can
// drift out of a relationship the specification states outright.
//
// It is OPEN in both places: the specification allows types two parties agree
// between themselves, so a value outside it is carried with a warning.
// ---------------------------------------------------------------------------
var CREDENTIAL_TYPES = require("./catalog/caep_credential_types.json");

GENERATE[CAEP_PREFIX + 'session-revoked'] = function () {
  log.debug("Entering generate(). session-revoked");
  log.debug("Leaving generate(). session-revoked");
  return {};
};

GENERATE[CAEP_PREFIX + 'session-established'] = function (values) {
  log.debug("Entering generate(). session-established");
  var asked = values || {};
  var payload = {};
  if (typeof asked.fp_ua === 'string' && asked.fp_ua !== '') {
    payload.fp_ua = asked.fp_ua;
  }
  if (typeof asked.acr === 'string' && asked.acr !== '') {
    payload.acr = asked.acr;
  }
  if (Object.prototype.toString.call(asked.amr) === '[object Array]' &&
      asked.amr.length) {
    payload.amr = asked.amr.slice();
  }
  if (typeof asked.ext_id === 'string' && asked.ext_id !== '') {
    payload.ext_id = asked.ext_id;
  }
  log.debug("Leaving generate(). session-established");
  return payload;
};

GENERATE[CAEP_PREFIX + 'session-presented'] = function (values) {
  log.debug("Entering generate(). session-presented");
  var asked = values || {};
  var payload = {};
  if (typeof asked.fp_ua === 'string' && asked.fp_ua !== '') {
    payload.fp_ua = asked.fp_ua;
  }
  if (typeof asked.ext_id === 'string' && asked.ext_id !== '') {
    payload.ext_id = asked.ext_id;
  }
  log.debug("Leaving generate(). session-presented");
  return payload;
};

GENERATE[CAEP_PREFIX + 'token-claims-change'] = function (values) {
  log.debug("Entering generate(). token-claims-change");
  var asked = values || {};
  var claims = (asked.claims && typeof asked.claims === 'object' &&
    Object.prototype.toString.call(asked.claims) !== '[object Array]')
    ? asked.claims
    : { groups: ['everyone'] };
  log.debug("Leaving generate(). token-claims-change");
  return { claims: claims };
};

GENERATE[CAEP_PREFIX + 'credential-change'] = function (values) {
  log.debug("Entering generate(). credential-change");
  var asked = values || {};
  var changes = ['create', 'revoke', 'update', 'delete'];
  var payload = {
    credential_type: (typeof asked.credential_type === 'string' &&
      asked.credential_type !== '') ? asked.credential_type : 'password',
    change_type: changes.indexOf(asked.change_type) >= 0
      ? asked.change_type : 'update'
  };
  ['friendly_name', 'x509_issuer', 'x509_serial', 'fido2_aaguid']
    .forEach(function (name) {
      if (typeof asked[name] === 'string' && asked[name] !== '') {
        payload[name] = asked[name];
      }
    });
  log.debug("Leaving generate(). credential-change");
  return payload;
};

GENERATE[CAEP_PREFIX + 'assurance-level-change'] = function (values) {
  log.debug("Entering generate(). assurance-level-change");
  var asked = values || {};
  var payload = {
    namespace: (typeof asked.namespace === 'string' &&
      asked.namespace !== '') ? asked.namespace : 'NIST-AAL',
    current_level: (typeof asked.current_level === 'string' &&
      asked.current_level !== '') ? asked.current_level : 'aal2'
  };
  if (typeof asked.previous_level === 'string' &&
      asked.previous_level !== '') {
    payload.previous_level = asked.previous_level;
  }
  if (['increase', 'decrease'].indexOf(asked.change_direction) >= 0) {
    payload.change_direction = asked.change_direction;
  }
  log.debug("Leaving generate(). assurance-level-change");
  return payload;
};

GENERATE[CAEP_PREFIX + 'device-compliance-change'] = function (values) {
  log.debug("Entering generate(). device-compliance-change");
  var asked = values || {};
  var allowed = ['compliant', 'not-compliant'];
  var payload = {
    previous_status: allowed.indexOf(asked.previous_status) >= 0
      ? asked.previous_status : 'compliant',
    current_status: allowed.indexOf(asked.current_status) >= 0
      ? asked.current_status : 'not-compliant'
  };
  log.debug("Leaving generate(). device-compliance-change");
  return payload;
};

GENERATE[CAEP_PREFIX + 'risk-level-change'] = function (values) {
  log.debug("Entering generate(). risk-level-change");
  var asked = values || {};
  var levels = ['LOW', 'MEDIUM', 'HIGH'];
  var payload = {
    principal: (typeof asked.principal === 'string' &&
      asked.principal !== '') ? asked.principal : 'SESSION',
    current_level: levels.indexOf(asked.current_level) >= 0
      ? asked.current_level : 'MEDIUM'
  };
  if (levels.indexOf(asked.previous_level) >= 0) {
    payload.previous_level = asked.previous_level;
  }
  if (typeof asked.risk_reason === 'string' && asked.risk_reason !== '') {
    payload.risk_reason = asked.risk_reason;
  }
  log.debug("Leaving generate(). risk-level-change");
  return payload;
};

var CAEP_EVENTS = withGenerators(require("./catalog/caep_events.json"),
  CAEP_COMMON_MEMBERS, [CREDENTIAL_TYPES]);

// ---------------------------------------------------------------------------
// RISC — THE ACCOUNT VOCABULARY (OpenID RISC Profile Specification 1.0,
// published 29 August 2025 and final on 2 September 2025). PART THREE, AND
// THE LAST.
//
// **THESE ROWS WERE WRITTEN INDEPENDENTLY OF THE MOCK'S, AND THAT IS THE SAME
// ARGUMENT THE CAEP BLOCK ABOVE MAKES.** The URIs and the member names are the
// WIRE and are identical by necessity; everything around them — which members
// are required, which enumerations are open, which subject formats an event
// insists on, what a state machine may refuse — is a READING. If both ends of
// this project read one implementation, a misunderstanding they SHARE is one
// neither can see. `sts/ssf/ssf_events.js` has the other reading and
// `tests/risc_protocol.js` drives one against the other over the wire.
//
// **WHAT RISC SAYS THAT CAEP DOES NOT.** CAEP's eight are about a SESSION and
// carry *this session is no longer trustworthy*. These fourteen are about an
// ACCOUNT and carry *this account is no longer trustworthy*. The second is the
// larger sentence by orders of magnitude — a revoked session is one sign-in at
// one relying party, and a purged account is every session that person has
// anywhere, for ever — and the difference in scope is the whole reason there
// are two profiles rather than one. CAEP is aimed WITHIN an enterprise; RISC
// ACROSS providers, and its origin is a consumer provider noticing that an
// account has been taken over and telling every site that account signs in to.
//
// ---------------------------------------------------------------------------
// FOUR THINGS HERE SURPRISE SOMEBODY WHO HAS JUST READ THE CAEP BLOCK, AND
// EVERY ONE OF THEM IS THE SPECIFICATION RATHER THAN A CHOICE MADE HERE.
//
// **ELEVEN OF THE FOURTEEN HAVE NO PAYLOAD MEMBERS AT ALL, AND ONLY ONE HAS A
// REQUIRED ONE.** A CAEP row is mostly members; a RISC row is mostly `{}`. The
// consequence is worth stating outright because it decides how this workflow
// has to be used: **the subject carries the entire message.** `account-purged`
// says nothing but its own type and who it is about, so a subject naming the
// wrong person is not a partly wrong event — it is a wholly wrong one, with
// nothing else in it to notice by.
//
// **THE FOUR COMMON CLAIMS ARE NOT COMMON HERE.** CAEP section 2 gives
// `event_timestamp`, `initiating_entity`, `reason_admin` and `reason_user` to
// every one of its eight. RISC gives THREE of them — there is no
// `initiating_entity` — and gives them to exactly ONE of its fourteen,
// `credential-compromise`. Reusing CAEP's common members here would attach
// four members to fourteen rows and produce thirteen events carrying members
// their specification does not define. Nothing would fail: an unrecognised
// member is carried and ignored by a conforming receiver, which is exactly why
// this is written down rather than left to the table.
//
// **ONE MEMBER NAME IN THE WHOLE OF SHARED SIGNALS USES A HYPHEN**, and it is
// `identifier-changed`'s `new-value`. Every other member of every event in all
// three vocabularies is `snake_case`. A transmitter that writes `new_value`
// from habit produces an event that is well-formed, delivers, and tells the
// receiver nothing about what the identifier changed TO — silently, because
// the member is optional and its absence is legal. `nearestMember()` below
// names the near miss rather than leaving "unknown member" to be read as an
// extension somebody meant.
//
// **AND ONE OF THE FOURTEEN IS DEPRECATED BY ITS OWN SPECIFICATION.**
// `sessions-revoked` — plural — says every session the account has is gone,
// and RISC 1.0 section 2.11 says new implementations MUST use CAEP's
// `session-revoked` — singular — instead. The two names differ by one letter
// and mean different things, which is exactly the pair somebody types from
// memory. It is in this table, sendable, and warned about on every event:
// leaving it out would make this workflow unable to reproduce the traffic of
// the many deployments that still send one, and unable to find out what a
// receiver does with it.
//
// ---------------------------------------------------------------------------
// AND ONE THING ABOUT THE SUBJECT THAT IS NEW TO THIS FILE.
//
// Two of the fourteen say their subject MUST be an email address or a phone
// number, and MUST carry the OLD value — which is the reverse of every other
// event in all three vocabularies, where the subject names who the event is
// about in the present tense. `subjectFormats` on those two rows is what says
// so; `checkSubjectFormat()` reports a subject outside the list as a WARNING
// rather than an error, because such an event is perfectly deliverable and
// merely wrong, and refusing to build one would remove the ability to find out
// what a receiver does with it. That is a different judgement from the missing
// subject `ssf_client.js` refuses, and the difference is that one is a
// mechanism and this is a conformance opinion.
// ---------------------------------------------------------------------------

// The three claims RISC gives to `credential-compromise` and to nothing else.
// A named list of three rather than four inlined members, because the COUNT
// and the ABSENCE of `initiating_entity` are the facts worth being able to
// check — `tests/risc_engine.js` asserts both.
var RISC_COMMON_MEMBERS = require("./catalog/risc_common_members.json");

GENERATE[RISC_PREFIX + 'account-credential-change-required'] = function () {
  log.debug("Entering generate(). account-credential-change-required");
  log.debug("Leaving generate(). account-credential-change-required");
  return {};
};

GENERATE[RISC_PREFIX + 'account-purged'] = function () {
  log.debug("Entering generate(). account-purged");
  log.debug("Leaving generate(). account-purged");
  return {};
};

GENERATE[RISC_PREFIX + 'account-disabled'] = function (values) {
  log.debug("Entering generate(). account-disabled");
  var asked = values || {};
  var payload = {};
  if (typeof asked.reason === 'string' && asked.reason !== '') {
    payload.reason = asked.reason;
  }
  log.debug("Leaving generate(). account-disabled");
  return payload;
};

GENERATE[RISC_PREFIX + 'account-enabled'] = function () {
  log.debug("Entering generate(). account-enabled");
  log.debug("Leaving generate(). account-enabled");
  return {};
};

GENERATE[RISC_PREFIX + 'identifier-changed'] = function (values) {
  log.debug("Entering generate(). identifier-changed");
  var asked = values || {};
  var payload = {};
  // IT READS THE SPECIFICATION'S SPELLING AND ONLY THAT ONE. Accepting
  // `new_value` here would make this page kind to whoever typed it and
  // useless to them: the whole point of this workflow is to show what is
  // actually going on the wire, and silently repairing the commonest
  // mistake in this event type would hide it. `validateEvent()` names the
  // near miss instead.
  if (typeof asked['new-value'] === 'string' &&
      asked['new-value'] !== '') {
    payload['new-value'] = asked['new-value'];
  }
  log.debug("Leaving generate(). identifier-changed");
  return payload;
};

GENERATE[RISC_PREFIX + 'identifier-recycled'] = function () {
  log.debug("Entering generate(). identifier-recycled");
  log.debug("Leaving generate(). identifier-recycled");
  return {};
};

GENERATE[RISC_PREFIX + 'credential-compromise'] = function (values) {
  log.debug("Entering generate(). credential-compromise");
  var asked = values || {};
  var payload = {
    credential_type: (typeof asked.credential_type === 'string' &&
      asked.credential_type !== '') ? asked.credential_type : 'password'
  };
  log.debug("Leaving generate(). credential-compromise");
  return payload;
};

GENERATE[RISC_PREFIX + 'opt-in'] = function () {
  log.debug("Entering generate(). opt-in");
  log.debug("Leaving generate(). opt-in");
  return {};
};

GENERATE[RISC_PREFIX + 'opt-out-initiated'] = function () {
  log.debug("Entering generate(). opt-out-initiated");
  log.debug("Leaving generate(). opt-out-initiated");
  return {};
};

GENERATE[RISC_PREFIX + 'opt-out-cancelled'] = function () {
  log.debug("Entering generate(). opt-out-cancelled");
  log.debug("Leaving generate(). opt-out-cancelled");
  return {};
};

GENERATE[RISC_PREFIX + 'opt-out-effective'] = function () {
  log.debug("Entering generate(). opt-out-effective");
  log.debug("Leaving generate(). opt-out-effective");
  return {};
};

GENERATE[RISC_PREFIX + 'recovery-activated'] = function () {
  log.debug("Entering generate(). recovery-activated");
  log.debug("Leaving generate(). recovery-activated");
  return {};
};

GENERATE[RISC_PREFIX + 'recovery-information-changed'] = function () {
  log.debug("Entering generate(). recovery-information-changed");
  log.debug("Leaving generate(). recovery-information-changed");
  return {};
};

GENERATE[RISC_PREFIX + 'sessions-revoked'] = function () {
  log.debug("Entering generate(). sessions-revoked");
  log.debug("Leaving generate(). sessions-revoked");
  return {};
};

var RISC_EVENTS = withGenerators(require("./catalog/risc_events.json"),
  RISC_COMMON_MEMBERS, [CREDENTIAL_TYPES]);

// THE THREE VOCABULARIES IN ONE TABLE. SSF's own first, because they are about
// the pipe every one of the others travels on; then CAEP's eight about a
// SESSION, then RISC's fourteen about an ACCOUNT.
var EVENTS = SSF_EVENTS.concat(CAEP_EVENTS).concat(RISC_EVENTS);

var CAEP_EVENT_URIS = CAEP_EVENTS.map(function (row) {
  return row.uri;
});

var RISC_EVENT_URIS = RISC_EVENTS.map(function (row) {
  return row.uri;
});

var EVENT_BY_URI = {};
EVENTS.forEach(function (row) {
  EVENT_BY_URI[row.uri] = row;
});

var EVENT_URIS = EVENTS.map(function (row) {
  return row.uri;
});

// The families this build implements, so the page can say what is here and
// what is not RATHER THAN leaving a reader to infer it from an empty list.
// `implemented: false` rows are drawn greyed with the sentence beside them —
// a workflow that silently offered two event types where a reader expected
// eighteen would read as broken rather than as staged.
var FAMILIES = require("./catalog/ssf_event_families.json");

// ---------------------------------------------------------------------------
// THE THREE PROFILES THE PAGE OFFERS, AND WHY THIS IS A TABLE RATHER THAN
// THREE BRANCHES IN `ssf.js`.
//
// A reader arrives at this workflow wanting one of three things — to exercise
// the PIPE, to send and receive SESSION events, or to send and receive ACCOUNT
// events — and the page reconfigures itself around the answer. What "pure SSF"
// means is not a preference: it is *the ssf family and no other*, which is a
// fact about this table and not about the DOM.
//
// **RISC IS HERE AND IS `implemented: false`, WHICH IS THE POINT OF LISTING
// IT.** A workflow that simply omitted the option would leave a reader unable
// to tell "this tool does not do RISC" from "I have not found it yet", and
// those are different sentences. The page draws it, greys it, and says which
// part of the work it is.
// ---------------------------------------------------------------------------
var PROFILES = require("./catalog/ssf_profiles.json");

var PROFILE_BY_ID = {};
PROFILES.forEach(function (row) {
  PROFILE_BY_ID[row.id] = row;
});

// Every event type one vocabulary defines, in catalogue order. The page's
// stream checkboxes and its Transmit menu are both built from this, so that
// choosing a profile narrows BOTH — a menu narrowed without the checkboxes
// would let somebody agree a stream for events the page cannot then send.
function eventsForFamily(family) {
  log.debug("Entering eventsForFamily(). " + family);
  var out = EVENTS.filter(function (row) {
    return row.family === String(family || '');
  });
  log.debug("Leaving eventsForFamily(). " + out.length + " type(s).");
  return out;
}

// Which profile a reader has chosen, defaulting to the pipe. An unknown value
// — an older stored preference, a hand-edited localStorage — answers `ssf`
// rather than throwing: this is a debugger, and a page that failed to load
// because of a stored string would be the worst way to find that out.
function profileOf(id) {
  log.debug("Entering profileOf(). " + id);
  var row = PROFILE_BY_ID[String(id || '')] || PROFILE_BY_ID.ssf;
  log.debug("Leaving profileOf(). " + row.id);
  return row;
}

// ---------------------------------------------------------------------------
// VALIDATE ONE EVENT PAYLOAD.
//
// **AN UNRECOGNISED MEMBER IS A WARNING AND NOT AN ERROR, WHICH IS THE
// OPPOSITE OF THE SUBJECT RULE IN `ssf_client.js`, AND THE DIFFERENCE IS THE
// SPECIFICATIONS' OWN.** RFC 9493 closes a Subject Identifier's member set
// because an unrecognised member might NARROW the subject — so a receiver that
// ignored one could act on the wrong person. An event payload has no such
// rule: the vocabularies extend, and a receiver is expected to ignore what it
// does not know. Refusing here would make this workflow unable to build a
// vendor's own extension, which is exactly what a debugger is for.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// ONE MEMBER'S VALUE AGAINST ITS ROW.
//
// Three lines inside validateEvent() while every member was a string or a
// closed enum. CAEP needs four more shapes, and each of the four is a document
// that would be built here, accepted by a JSON parser, and mean nothing at the
// far end:
//
//   number    `event_timestamp` as the STRING "1757000000". Parsed by
//             everything, compared numerically by nobody.
//   strings   `amr` as a bare string. A session authenticated by a password
//             AND a security key has two values, and a receiver reading a
//             string sees one. It is REFUSED rather than wrapped, because
//             wrapping would hide a sender that can only ever say one.
//   object    `claims`, which is the entire payload of token-claims-change.
//             An array there parses and means nothing.
//   langmap   `reason_admin` / `reason_user`. CAEP makes these objects keyed
//             by a BCP 47 language tag, and a plain string is the commonest
//             mistake in the whole profile — with NO SYMPTOM, because a
//             receiver indexing by language reads nothing from one and
//             reports no error.
//
// **AND ONE THAT IS A WARNING RATHER THAN AN ERROR.** `openenum` is a list the
// specification says two parties may extend — `credential_type`, `namespace`,
// `principal` — so a value outside it is CARRIED and noted. Refusing would
// make this workflow unable to build a vendor's own credential type, which is
// exactly what a debugger is for. A closed `enum` is still refused.
// ---------------------------------------------------------------------------
function checkMember(member, value, errors, warnings) {
  log.debug("Entering checkMember(). " + member.name);
  if (member.type === 'string' && typeof value !== 'string') {
    errors.push('"' + member.name + '" must be a string.');
    log.debug("Leaving checkMember(). Not a string.");
    return;
  }
  if (member.type === 'number' && typeof value !== 'number') {
    errors.push('"' + member.name + '" must be a NUMBER of seconds since ' +
        'the epoch, not a string. A quoted timestamp parses everywhere and ' +
        'is compared numerically nowhere.');
    log.debug("Leaving checkMember(). Not a number.");
    return;
  }
  if (member.type === 'strings') {
    var isArray =
      Object.prototype.toString.call(value) === '[object Array]';
    var allStrings = isArray && value.every(function (one) {
      return typeof one === 'string';
    });
    if (!allStrings) {
      errors.push('"' + member.name + '" must be an ARRAY of strings. A ' +
          'bare string is refused rather than wrapped: a session ' +
          'authenticated two ways has two values, and wrapping would hide ' +
          'a sender that can only ever say one.');
    }
    log.debug("Leaving checkMember(). strings.");
    return;
  }
  if (member.type === 'object') {
    if (!value || typeof value !== 'object' ||
        Object.prototype.toString.call(value) === '[object Array]') {
      errors.push('"' + member.name + '" must be a JSON object.');
    }
    log.debug("Leaving checkMember(). object.");
    return;
  }
  if (member.type === 'langmap') {
    if (!value || typeof value !== 'object' ||
        Object.prototype.toString.call(value) === '[object Array]') {
      errors.push('"' + member.name + '" must be an OBJECT KEYED BY A ' +
          'LANGUAGE TAG — {"en": "..."} — and not a string. That is CAEP ' +
          'section 2, and a receiver indexing it by language reads nothing ' +
          'from a string and reports no error, so this is refused here or ' +
          'nowhere.');
      log.debug("Leaving checkMember(). Not a language map.");
      return;
    }
    Object.keys(value).forEach(function (tag) {
      if (typeof value[tag] !== 'string') {
        errors.push('"' + member.name + '.' + tag + '" must be a string.');
      }
      if (!/^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*$/.test(tag)) {
        warnings.push('"' + tag + '" is not shaped like a BCP 47 language ' +
            'tag. It is carried — nothing here owns that registry — and a ' +
            'receiver looking for "en" will not find it.');
      }
    });
    log.debug("Leaving checkMember(). langmap.");
    return;
  }
  if (member.type === 'enum' && member.values.indexOf(value) < 0) {
    errors.push('"' + member.name + '" must be one of ' +
        member.values.join(', ') + '.');
    log.debug("Leaving checkMember(). Outside a closed enum.");
    return;
  }
  if (member.type === 'openenum' && member.values.indexOf(value) < 0) {
    warnings.push('"' + String(value) + '" is not one of the values CAEP ' +
        'lists for "' + member.name + '" (' + member.values.join(', ') +
        '). That list is OPEN — two parties may agree their own — so it is ' +
        'CARRIED rather than refused, and a receiver that has not been told ' +
        'about it will ignore the event.');
  }
  log.debug("Leaving checkMember(). " + member.name + " checked.");
}

// A member name that differs from one this row defines only by hyphen versus
// underscore. One comparison rather than a table of known typos, so it stays
// true for a vocabulary nobody has written yet.
function nearestMember(name, members) {
  log.debug("Entering nearestMember(). " + name);
  var flat = String(name).replace(/[-_]/g, '_');
  var found = '';
  (members || []).forEach(function (member) {
    if (!found && member.name !== name &&
        String(member.name).replace(/[-_]/g, '_') === flat) {
      found = member.name;
    }
  });
  log.debug("Leaving nearestMember(). " + (found || '(none)'));
  return found;
}

// ---------------------------------------------------------------------------
// WHAT IS WRONG WITH THE SUBJECT OF ONE EVENT, WHERE THE ROW NARROWS IT.
//
// `ssf_client.js` refuses a subject that is not a valid RFC 9493 identifier,
// and that refusal is MECHANICAL — a malformed subject names nobody, so the
// event is about nothing. This is the other kind, and it is a WARNING for
// exactly that reason.
//
// RISC's two identifier events say the subject MUST be an email address or a
// phone number, because for those two the identifier IS the message: the
// subject carries the OLD value and the payload carries at most the new one.
// An `iss_sub` subject there is perfectly deliverable and merely wrong, and
// refusing to build one would remove the ability to find out what a receiver
// does with it, which is the whole point of this page.
//
// It is driven by `row.subjectFormats` rather than by the URI, so it is a
// property of the table and not a branch naming a vocabulary.
// ---------------------------------------------------------------------------
function checkSubjectFormat(uri, subject) {
  log.debug("Entering checkSubjectFormat(). " + uri);
  var warnings = [];
  var row = EVENT_BY_URI[uri];
  var formats = row && Object.prototype.toString.call(row.subjectFormats) ===
    '[object Array]' ? row.subjectFormats : null;
  if (!formats || !subject || typeof subject !== 'object') {
    log.debug("Leaving checkSubjectFormat(). Nothing to say.");
    return warnings;
  }
  var format = String(subject.format || '');
  if (!format || format === 'complex') {
    warnings.push('"' + uri + '" wants a subject in one of these formats: ' +
        formats.join(', ') + '. This one is a COMPLEX subject — its ' +
        '`format` is "complex" rather than one identifier\'s — which names ' +
        'a person and possibly a session, and this event is about an ' +
        'IDENTIFIER rather than about either.');
    log.debug("Leaving checkSubjectFormat(). Complex subject.");
    return warnings;
  }
  if (formats.indexOf(format) < 0) {
    warnings.push('"' + uri + '" says its subject MUST be ' +
        formats.join(' or ') + ' and this one is "' + format + '". It is ' +
        'BUILT anyway — the event is perfectly deliverable and merely ' +
        'wrong, and refusing would remove the ability to find out what a ' +
        'receiver does with it. What is lost is the message itself: the ' +
        'subject of these two events carries the identifier that changed, ' +
        'so a subject naming the person instead says that something about ' +
        'them moved without saying what.');
  }
  log.debug("Leaving checkSubjectFormat(). " + warnings.length +
            " warning(s).");
  return warnings;
}

function validateEvent(uri, payload) {
  log.debug("Entering validateEvent(). " + uri);
  var errors = [];
  var warnings = [];
  var row = EVENT_BY_URI[uri];
  if (!row) {
    errors.push('"' + String(uri) + '" is not an event type this build ' +
        'implements. It knows ' + EVENT_URIS.length + ': SSF\'s two about ' +
        'the pipe, CAEP\'s eight about a session and RISC\'s fourteen ' +
        'about an account.');
    log.debug("Leaving validateEvent(). Unknown type.");
    return { ok: false, errors: errors, warnings: warnings };
  }
  var body = (payload && typeof payload === 'object' &&
    Object.prototype.toString.call(payload) !== '[object Array]')
    ? payload : null;
  if (!body) {
    errors.push('The payload of "' + uri + '" must be a JSON object. An ' +
        'event with nothing to say still carries {} — the event TYPE is the ' +
        'key in the events map and the payload is its value.');
    log.debug("Leaving validateEvent(). Not an object.");
    return { ok: false, errors: errors, warnings: warnings };
  }
  // A ROW ITS OWN SPECIFICATION DEPRECATES SAYS SO, ON EVERY EVENT, AND IT IS
  // A WARNING RATHER THAN A REFUSAL. RISC 1.0 section 2.11 deprecates
  // `sessions-revoked` in favour of CAEP's `session-revoked`; a workflow that
  // could not build the deprecated one could not be used to find out what a
  // receiver does with it, and receivers in the field still send and expect
  // it. Written against `row.deprecated` rather than against the URI, so the
  // next deprecation is a field and not a branch.
  if (row.deprecated) {
    warnings.push('"' + uri + '" is DEPRECATED by its own specification, ' +
        'which says new implementations must use "' + row.deprecated + '" ' +
        'instead. It is still built and still sent. The two names differ by ' +
        'one letter and mean different things — every session the account ' +
        'has, against the one the subject names — so this is the pair to ' +
        'check when a receiver ends more sessions than anybody intended.');
  }
  var known = {};
  row.members.forEach(function (member) {
    known[member.name] = member;
  });
  row.members.forEach(function (member) {
    if (member.required &&
        !Object.prototype.hasOwnProperty.call(body, member.name)) {
      errors.push('"' + uri + '" requires a "' + member.name + '" member.');
    }
  });
  Object.keys(body).forEach(function (name) {
    var member = known[name];
    if (!member) {
      // A NEAR MISS IS NAMED, and it is worth a sentence of its own. Every
      // member in SSF and CAEP is snake_case and exactly one in RISC is not —
      // `identifier-changed`'s `new-value` — so `new_value` typed from habit
      // is an event that validates, delivers and tells the receiver nothing.
      // It is written against the ROW's own member names rather than against
      // that one spelling, so it catches the reverse mistake too and needs no
      // maintenance when a vocabulary adds a member.
      var nearMiss = nearestMember(name, row.members);
      warnings.push('"' + name + '" is not a member "' + uri + '" defines. ' +
          (nearMiss
            ? 'It differs from "' + nearMiss + '", which IS one, only in a ' +
              'hyphen or an underscore — and this is the one place in the ' +
              'three vocabularies where that matters, because "new-value" ' +
              'is the only hyphenated member name in any of them. What you ' +
              'sent is carried as an EXTENSION and the member the ' +
              'specification defines is absent, so a conforming receiver ' +
              'reads nothing and reports no error. '
            : '') +
          'It is CARRIED rather than refused: an event vocabulary extends, ' +
          'and a receiver is expected to ignore what it does not know.');
      return;
    }
    checkMember(member, body[name], errors, warnings);
  });
  log.debug("Leaving validateEvent(). " + errors.length + " problem(s).");
  return { ok: errors.length === 0, errors: errors, warnings: warnings };
}

// Build a payload for one type from whatever a form holds.
function generateEvent(uri, values) {
  log.debug("Entering generateEvent(). " + uri);
  var row = EVENT_BY_URI[uri];
  if (!row) {
    log.debug("Leaving generateEvent(). Unknown type.");
    return {};
  }
  var payload = row.generate(values);
  log.debug("Leaving generateEvent().");
  return payload;
}

// What an arriving SET's `events` map says, one row per type. A token may
// carry several — that is what the map is FOR — and a page that showed only
// the first would be dropping events silently.
//
// A type this catalogue does not name is still a document. `document` is
// that one events-map entry, pretty-printed. The catalogue is not extended
// to name it, and validateEvent() still refuses to build one.
function describeEvents(events) {
  log.debug("Entering describeEvents().");
  var map = (events && typeof events === 'object') ? events : {};
  var rows = Object.keys(map).map(function (uri) {
    var row = EVENT_BY_URI[uri];
    var verdict = row ? validateEvent(uri, map[uri])
      : { ok: true, errors: [], warnings: [] };
    return {
      uri: uri,
      name: row ? row.name : uri,
      family: row ? row.family : familyOf(uri),
      known: !!row,
      payload: map[uri],
      document: row ? '' : printEventDocument(uri, map[uri]),
      what: row ? row.what : '',
      errors: verdict.errors,
      warnings: verdict.warnings
    };
  });
  log.debug("Leaving describeEvents(). " + rows.length + " event(s).");
  return rows;
}

// One unknown events-map entry, as JSON. The key is the type URI and the
// value is the payload that arrived, including a payload that is not an
// object. Nothing here names members or fills defaults.
function printEventDocument(uri, payload) {
  log.debug("Entering printEventDocument().");
  var doc = {};
  doc[uri] = payload;
  var text;
  try {
    text = JSON.stringify(doc, null, 2);
  } catch (e) {
    text = String(payload);
  }
  log.debug("Leaving printEventDocument().");
  return text;
}

// Which vocabulary a type belongs to, by prefix. An unknown type is still
// worth PLACING — "a CAEP event this build does not implement" is a far more
// useful thing to draw than "unknown", and it is what tells somebody the
// transmitter is ahead of this tool rather than wrong.
function familyOf(uri) {
  log.debug("Entering familyOf().");
  var text = String(uri || '');
  var found = FAMILIES.filter(function (row) {
    return text.indexOf(row.prefix) === 0;
  })[0];
  log.debug("Leaving familyOf(). " + (found ? found.id : 'unknown'));
  return found ? found.id : '';
}

module.exports = {
  SSF_PREFIX: SSF_PREFIX,
  CAEP_PREFIX: CAEP_PREFIX,
  RISC_PREFIX: RISC_PREFIX,
  EVENTS: EVENTS,
  SSF_EVENTS: SSF_EVENTS,
  CAEP_EVENTS: CAEP_EVENTS,
  CAEP_EVENT_URIS: CAEP_EVENT_URIS,
  CAEP_COMMON_MEMBERS: CAEP_COMMON_MEMBERS,
  RISC_EVENTS: RISC_EVENTS,
  RISC_EVENT_URIS: RISC_EVENT_URIS,
  RISC_COMMON_MEMBERS: RISC_COMMON_MEMBERS,
  CREDENTIAL_TYPES: CREDENTIAL_TYPES,
  checkSubjectFormat: checkSubjectFormat,
  PROFILES: PROFILES,
  PROFILE_BY_ID: PROFILE_BY_ID,
  eventsForFamily: eventsForFamily,
  profileOf: profileOf,
  EVENT_URIS: EVENT_URIS,
  EVENT_BY_URI: EVENT_BY_URI,
  FAMILIES: FAMILIES,
  validateEvent: validateEvent,
  generateEvent: generateEvent,
  describeEvents: describeEvents,
  familyOf: familyOf
};
