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
// **WHAT WILL ARRIVE WITH CAEP AND RISC**, so that a reader of this file today
// knows what shape it is being kept for. CAEP: session revoked, token claims
// change, credential change, assurance level change, device compliance change
// — all about a SESSION, all carrying `reason_admin`, `reason_user` and an
// `event_timestamp`, and all with a COMPLEX subject, because "this session was
// revoked" is a sentence about a session and not about a person. RISC: account
// disabled, purged, credentials compromised, credential change required,
// identifier changed, identifier recycled — all about an ACCOUNT. The two
// answer different questions and the distinction is the whole reason there are
// two: CAEP says "this session is no longer trustworthy", RISC says "this
// account is no longer trustworthy".
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
var SSF_PREFIX = 'https://schemas.openid.net/secevent/ssf/event-type/';

// The two prefixes the next parts will use, written down now because they are
// the thing most likely to be typed from memory and got subtly wrong. Neither
// is used yet.
var CAEP_PREFIX = 'https://schemas.openid.net/secevent/caep/event-type/';
var RISC_PREFIX = 'https://schemas.openid.net/secevent/risc/event-type/';

// ---------------------------------------------------------------------------
// THE CATALOGUE.
//
//   uri        the event type, which is the KEY in a SET's `events` map
//   family     'ssf' today; 'caep' and 'risc' are parts two and three
//   subject    'none' | 'optional' | 'required'. THE TWO SSF EVENTS ARE THE
//              ONLY ONES IN ANY OF THE THREE VOCABULARIES WITH NO SUBJECT AT
//              ALL, and the reason is worth keeping: they are about the
//              STREAM. A receiver that insisted on a subject could not be
//              verified.
//   members    the payload's own members, with `required` on each
//   generate   builds a payload from what a form holds, filling what it can.
//              Every row has one, so "send me one of these" is one call from
//              the page and from a test alike.
// ---------------------------------------------------------------------------
var EVENTS = [
  {
    uri: SSF_PREFIX + 'verification',
    family: 'ssf',
    name: 'Verification',
    subject: 'none',
    what: 'THE ONLY END-TO-END TEST A STREAM HAS. Creating the stream, ' +
          'reading it back and adding a subject all exercise the management ' +
          'API and prove nothing about whether an event can actually be ' +
          'delivered. This travels the ordinary delivery path, so a 202 from ' +
          'the push endpoint — or a poll that returns it — is the first ' +
          'evidence the pipe works.',
    howItIsAsked: 'A receiver POSTs {stream_id, state} to the ' +
          'verification_endpoint. The transmitter answers 204 and sends the ' +
          'event SEPARATELY, over the stream. Those are two different ' +
          'exchanges and a receiver that expected the event in the response ' +
          'to its own request waits forever.',
    members: [
      { name: 'state', required: false, type: 'string',
        what: 'Whatever the receiver put in its verification request, echoed ' +
              'back UNCHANGED. It is the only thing tying this event to the ' +
              'request that asked for it — without it, a receiver watching ' +
              'two streams cannot tell which one just answered.' }
    ],
    generate: function (values) {
      log.debug("Entering generate(). verification");
      var asked = values || {};
      var payload = {};
      if (typeof asked.state === 'string' && asked.state !== '') {
        payload.state = asked.state;
      }
      log.debug("Leaving generate(). verification");
      return payload;
    }
  },
  {
    uri: SSF_PREFIX + 'stream-updated',
    family: 'ssf',
    name: 'Stream Updated',
    subject: 'none',
    what: 'The stream\'s status changed and the receiver is being told IN ' +
          'BAND. It is the one event a receiver gets without asking for it, ' +
          'and the one whose absence is hardest to notice: a stream quietly ' +
          'paused at the transmitter looks exactly like a service where ' +
          'nothing has happened lately.',
    howItIsAsked: 'Nobody asks. A transmitter sends it when the status ' +
          'changes — including when the change was made by the receiver ' +
          'itself at the status endpoint, which is not redundant: the ' +
          'acknowledgement of a request and an event on the stream are two ' +
          'different assurances, and only the second one says the delivery ' +
          'path is working.',
    members: [
      { name: 'status', required: true, type: 'enum',
        values: ['enabled', 'paused', 'disabled'],
        what: 'The stream\'s new status. PAUSED keeps queueing and delivers ' +
              'nothing; DISABLED drops what is waiting. That is the ' +
              'difference between "I was not listening" and "it did not ' +
              'happen".' },
      { name: 'reason', required: false, type: 'string',
        what: 'Why, in words, for a person reading a log. Nothing parses ' +
              'it.' }
    ],
    generate: function (values) {
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
    }
  }
];

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
var FAMILIES = [
  { id: 'ssf', label: 'SSF — the framework itself', prefix: SSF_PREFIX,
    implemented: true,
    what: 'Two event types, both about the PIPE rather than about a person: ' +
          'is this stream alive, and has its status changed.' },
  { id: 'caep', label: 'CAEP — Continuous Access Evaluation Profile',
    prefix: CAEP_PREFIX, implemented: false,
    what: 'The enterprise SESSION vocabulary: session revoked, token claims ' +
          'change, credential change, assurance level change, device ' +
          'compliance change. It says "this session is no longer ' +
          'trustworthy". NOT IMPLEMENTED YET — it is the second part of this ' +
          'work, and it will be rows in this file\'s table and nothing ' +
          'else.' },
  { id: 'risc', label: 'RISC — Risk Incident Sharing and Coordination',
    prefix: RISC_PREFIX, implemented: false,
    what: 'The account-lifecycle vocabulary, aimed ACROSS providers rather ' +
          'than within one enterprise: account disabled, purged, credentials ' +
          'compromised, credential change required, identifier changed or ' +
          'recycled. It says "this account is no longer trustworthy", which ' +
          'is a different sentence from CAEP\'s. NOT IMPLEMENTED YET — the ' +
          'third part of this work.' }
];

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
function validateEvent(uri, payload) {
  log.debug("Entering validateEvent(). " + uri);
  var errors = [];
  var warnings = [];
  var row = EVENT_BY_URI[uri];
  if (!row) {
    errors.push('"' + String(uri) + '" is not an event type this build ' +
        'implements. SSF defines two — ' + EVENT_URIS.join(' and ') + ' — ' +
        'and CAEP and RISC are parts two and three of this work.');
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
      warnings.push('"' + name + '" is not a member "' + uri + '" defines. ' +
          'It is CARRIED rather than refused: an event vocabulary extends, ' +
          'and a receiver is expected to ignore what it does not know.');
      return;
    }
    var value = body[name];
    if (member.type === 'string' && typeof value !== 'string') {
      errors.push('"' + name + '" must be a string.');
      return;
    }
    if (member.type === 'enum' && member.values.indexOf(value) < 0) {
      errors.push('"' + name + '" must be one of ' +
          member.values.join(', ') + '.');
    }
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
function describeEvents(events) {
  log.debug("Entering describeEvents().");
  var map = (events && typeof events === 'object') ? events : {};
  var rows = Object.keys(map).map(function (uri) {
    var row = EVENT_BY_URI[uri];
    var verdict = row ? validateEvent(uri, map[uri])
      : { ok: false, errors: [], warnings: [] };
    return {
      uri: uri,
      name: row ? row.name : uri,
      family: row ? row.family : familyOf(uri),
      known: !!row,
      payload: map[uri],
      what: row ? row.what : '',
      errors: verdict.errors,
      warnings: verdict.warnings
    };
  });
  log.debug("Leaving describeEvents(). " + rows.length + " event(s).");
  return rows;
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
  EVENT_URIS: EVENT_URIS,
  EVENT_BY_URI: EVENT_BY_URI,
  FAMILIES: FAMILIES,
  validateEvent: validateEvent,
  generateEvent: generateEvent,
  describeEvents: describeEvents,
  familyOf: familyOf
};
