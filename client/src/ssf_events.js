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
var SSF_PREFIX = 'https://schemas.openid.net/secevent/ssf/event-type/';

// The two VOCABULARY prefixes. Both have rows in the table below now, and
// each is written once because a prefix is the thing most likely to be typed
// from memory and got subtly wrong — there is no "unknown event type" error
// in this protocol, so a receiver silently ignores what it does not
// recognise.
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
var SSF_EVENTS = [
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
// Written once and concatenated onto each row below: eight copies of four
// member descriptions is eight places for a spelling to drift, and there is
// no "unknown member" error in this protocol — a receiver reading
// `reason-admin` for `reason_admin` finds nothing and says nothing.
//
// **`event_timestamp` IS NOT THE SET's `toe` AND IT IS NOT `iat`.** `toe` is
// RFC 8417's claim on the TOKEN; this is a member of the event PAYLOAD, and
// CAEP is the specification that defines it. A transmitter may legitimately
// send both, and a receiver that reads only one of them from a transmitter
// that sends only the other reads nothing at all.
var CAEP_COMMON_MEMBERS = [
  { name: 'event_timestamp', required: false, type: 'number',
    what: 'When the thing described actually happened, in seconds since the ' +
          'epoch. OPTIONAL in CAEP section 2, which surprises people — a ' +
          'receiver deciding whether to end a session wants it more than it ' +
          'wants anything else in the payload, and a conforming transmitter ' +
          'need not send one. A receiver that assumes it is there is one ' +
          'this page can catch, by leaving it out.' },
  { name: 'initiating_entity', required: false, type: 'enum',
    values: ['admin', 'user', 'policy', 'system'],
    what: 'Who invoked it. It is the member that lets a receiver tell "an ' +
          'administrator revoked this" from "a risk engine did" — two facts ' +
          'that call for two different responses and are indistinguishable ' +
          'without it.' },
  { name: 'reason_admin', required: false, type: 'langmap',
    what: 'Why, for a log and for an auditor. IT IS AN OBJECT KEYED BY A ' +
          'LANGUAGE TAG — {"en": "Policy 4.2 was violated"} — and not a ' +
          'string. That is the commonest mistake in the whole profile and ' +
          'it has no symptom: a receiver indexing by language reads nothing ' +
          'from a string and reports no error.' },
  { name: 'reason_user', required: false, type: 'langmap',
    what: 'The same, in words meant for the person it happened to. Two ' +
          'members rather than one because what an auditor needs to read ' +
          'and what may be shown on a screen are rarely the same sentence.' }
];

// One row's own members plus the four above, in that order — the pane draws
// them in this order and a table whose columns move between rows is harder to
// read than one with a column too many.
function withCommonMembers(members) {
  log.debug("Entering withCommonMembers().");
  var out = (members || []).concat(CAEP_COMMON_MEMBERS);
  log.debug("Leaving withCommonMembers(). " + out.length + " member(s).");
  return out;
}

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
var CREDENTIAL_TYPES = ['password', 'pin', 'x509', 'fido2-platform',
  'fido2-roaming', 'fido-u2f', 'verifiable-credential', 'phone-voice',
  'phone-sms', 'app'];

var CAEP_EVENTS = [
  {
    uri: CAEP_PREFIX + 'session-revoked',
    family: 'caep',
    name: 'Session Revoked',
    subject: 'required',
    what: 'THE EVENT THE WHOLE PROFILE EXISTS FOR. The session named by the ' +
          'subject is no longer good, whatever its token says its lifetime ' +
          'is. It carries NO event-specific member at all, and that is not ' +
          'an oversight: everything it has to say is in the subject and in ' +
          'the four common claims, and there is nothing to qualify.',
    howItIsAsked: 'Nobody asks. A transmitter sends it when a session ends ' +
          '— an administrator signing somebody out, a policy engine, the ' +
          'person themselves. Where the subject is a COMPLEX one the ' +
          'revocation applies to any session matching every part of it at ' +
          'once, which is how "that person, on that device" is said.',
    members: withCommonMembers([]),
    generate: function () {
      log.debug("Entering generate(). session-revoked");
      log.debug("Leaving generate(). session-revoked");
      return {};
    }
  },
  {
    uri: CAEP_PREFIX + 'session-established',
    family: 'caep',
    name: 'Session Established',
    subject: 'required',
    what: 'A session was created. It is what CLOSES THE LOOP: without it a ' +
          'receiver only ever hears about sessions ENDING, so it can never ' +
          'hold an inventory of what is open and cannot notice a sign-in it ' +
          'did not expect.',
    howItIsAsked: 'Nobody asks. A transmitter sends it at the moment ' +
          'somebody signs in. This stack\'s mock does exactly that unless ' +
          'caep.autoEmit is turned off over there.',
    members: withCommonMembers([
      { name: 'fp_ua', required: false, type: 'string',
        what: 'A fingerprint of the user agent, computed by the ' +
              'transmitter. Its whole value is comparing two of them, so ' +
              'what it is made of is the transmitter\'s business and no ' +
              'receiver should parse one.' },
      { name: 'acr', required: false, type: 'string',
        what: 'The authentication context class, with OpenID Connect\'s own ' +
              'meaning.' },
      { name: 'amr', required: false, type: 'strings',
        what: 'The authentication methods, as an ARRAY — OpenID Connect\'s ' +
              '`amr`. A bare string is refused here rather than wrapped: a ' +
              'session authenticated by a password AND a security key has ' +
              'two values, and wrapping would hide a sender that can only ' +
              'ever say one.' },
      { name: 'ext_id', required: false, type: 'string',
        what: 'The transmitter\'s own identifier for this session, for a ' +
              'receiver correlating with something it already holds.' }
    ]),
    generate: function (values) {
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
    }
  },
  {
    uri: CAEP_PREFIX + 'session-presented',
    family: 'caep',
    name: 'Session Presented',
    subject: 'required',
    what: 'The session was USED — presented at the transmitter and ' +
          'honoured. It is the one CAEP event about something entirely ' +
          'ordinary, and it is there so a receiver can see a live session ' +
          'it is not itself being asked about, and can spot the same ' +
          'session in two places at once.',
    howItIsAsked: 'Nobody asks. A transmitter sends it when an existing ' +
          'session answers a request — which is single sign-on. A ' +
          'transmitter that sent one for the sign-in\'s own return trip ' +
          'would emit it milliseconds after session-established every time, ' +
          'and the event would stop meaning anything.',
    members: withCommonMembers([
      { name: 'fp_ua', required: false, type: 'string',
        what: 'The user agent fingerprint observed THIS time. Comparing it ' +
              'with the one on the session-established event is the whole ' +
              'point of the member: the same session presented from a ' +
              'different agent is the abnormality this event exists to make ' +
              'visible.' },
      { name: 'ext_id', required: false, type: 'string',
        what: 'The transmitter\'s own identifier for the session.' }
    ]),
    generate: function (values) {
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
    }
  },
  {
    uri: CAEP_PREFIX + 'token-claims-change',
    family: 'caep',
    name: 'Token Claims Change',
    subject: 'required',
    what: 'A claim behind the token changed while the token is still valid ' +
          '— a role, a group, a tenant. It is the event that makes the ' +
          'access-token-lifetime argument go away: a receiver does not have ' +
          'to wait for a refresh to find out that somebody left the group ' +
          'that authorises them.',
    howItIsAsked: 'Nobody asks. A transmitter sends it when the underlying ' +
          'claim moves — a directory write, a role assignment withdrawn.',
    members: withCommonMembers([
      { name: 'claims', required: true, type: 'object',
        what: 'The claims that changed, with their NEW values. It is not a ' +
              'whole token and it is not a diff: a receiver applies what is ' +
              'here over what it holds. So a group taken away is the new ' +
              'LIST rather than the group that went, which catches ' +
              'everybody once.' }
    ]),
    generate: function (values) {
      log.debug("Entering generate(). token-claims-change");
      var asked = values || {};
      var claims = (asked.claims && typeof asked.claims === 'object' &&
        Object.prototype.toString.call(asked.claims) !== '[object Array]')
        ? asked.claims
        : { groups: ['everyone'] };
      log.debug("Leaving generate(). token-claims-change");
      return { claims: claims };
    }
  },
  {
    uri: CAEP_PREFIX + 'credential-change',
    family: 'caep',
    name: 'Credential Change',
    subject: 'required',
    what: 'A credential was enrolled, renewed, revoked or deleted. It is ' +
          'the CAEP event a receiver acts on WITHOUT ending anything: a ' +
          'second factor being deleted does not invalidate the session it ' +
          'was used to establish, and it does change what that session ' +
          'should be allowed to do next.',
    howItIsAsked: 'Nobody asks. A transmitter sends it from wherever ' +
          'credentials are managed — an enrolment page, an administrator ' +
          'revoking a key.',
    members: withCommonMembers([
      { name: 'credential_type', required: true, type: 'openenum',
        values: CREDENTIAL_TYPES,
        what: 'Which kind. The list is CAEP\'s own and it is OPEN — the ' +
              'specification allows types two parties agree between ' +
              'themselves — so a value not on it is CARRIED with a warning ' +
              'rather than refused. Refusing would make this workflow ' +
              'unable to build a vendor\'s own type, which is exactly what ' +
              'a debugger is for.' },
      { name: 'change_type', required: true, type: 'enum',
        values: ['create', 'revoke', 'update', 'delete'],
        what: 'What happened to it. CLOSED, unlike the type above: these ' +
              'four are the whole lifecycle and a fifth would be a receiver ' +
              'guessing.' },
      { name: 'friendly_name', required: false, type: 'string',
        what: 'What the person calls it — "my work phone". For a screen, ' +
              'not for a decision.' },
      { name: 'x509_issuer', required: false, type: 'string',
        what: 'The certificate\'s issuer (RFC 5280), where the credential ' +
              'is an X.509 one.' },
      { name: 'x509_serial', required: false, type: 'string',
        what: 'The certificate\'s serial number (RFC 5280). Serial numbers ' +
              'are unique per ISSUER and not globally, which is what makes ' +
              'this member useless without the one above it.' },
      { name: 'fido2_aaguid', required: false, type: 'string',
        what: 'The authenticator\'s AAGUID, where the credential is a FIDO2 ' +
              'one. It names a MODEL of authenticator rather than the ' +
              'individual one, which is what makes it publishable at all.' }
    ]),
    generate: function (values) {
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
    }
  },
  {
    uri: CAEP_PREFIX + 'assurance-level-change',
    family: 'caep',
    name: 'Assurance Level Change',
    subject: 'required',
    what: 'The strength of the authentication behind this session moved. A ' +
          'DECREASE is the interesting one and it is easy to forget it can ' +
          'happen at all: a second factor that has expired, or a session ' +
          'carried past the window its step-up was good for, both lower ' +
          'assurance without anybody signing in again.',
    howItIsAsked: 'Nobody asks. A transmitter sends it after a step-up, ' +
          'after a step-down, or when the window a factor was good for ' +
          'closes.',
    members: withCommonMembers([
      { name: 'namespace', required: true, type: 'openenum',
        values: ['RFC8176', 'RFC6711', 'ISO-IEC-29115', 'NIST-IAL',
                 'NIST-AAL', 'NIST-FAL'],
        what: 'WHICH SCALE THE TWO LEVELS ARE ON, and it is required ' +
              'because the event is useless without it: "aal2" means ' +
              'nothing until you know it is NIST\'s. The list is open — two ' +
              'parties may agree an alias — so an unlisted namespace is ' +
              'carried with a warning.' },
      { name: 'current_level', required: true, type: 'string',
        what: 'The level the session is at NOW, spelt the way the namespace ' +
              'above spells it. A free string precisely because the ' +
              'namespace decides its shape.' },
      { name: 'previous_level', required: false, type: 'string',
        what: 'Where it was before. Optional and worth sending: without it ' +
              'a receiver can see that assurance changed and not whether it ' +
              'went UP.' },
      { name: 'change_direction', required: false, type: 'enum',
        values: ['increase', 'decrease'],
        what: 'Which way, said outright rather than inferred. It exists ' +
              'because a receiver cannot order two levels in a namespace it ' +
              'does not understand — which is the ordinary case across two ' +
              'organisations.' }
    ]),
    generate: function (values) {
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
    }
  },
  {
    uri: CAEP_PREFIX + 'device-compliance-change',
    family: 'caep',
    name: 'Device Compliance Change',
    subject: 'required',
    what: 'The device the session runs on fell out of, or back into, ' +
          'compliance with whatever the estate\'s policy is. The subject is ' +
          'normally a COMPLEX one naming the device as well as the person, ' +
          'because the same person on a second device is unaffected and a ' +
          'receiver cannot tell that from a subject naming only them.',
    howItIsAsked: 'Nobody asks. A device management service tells the ' +
          'transmitter and the transmitter tells the receivers.',
    members: withCommonMembers([
      { name: 'previous_status', required: true, type: 'enum',
        values: ['compliant', 'not-compliant'],
        what: 'What the device WAS. Required, and that is what makes this ' +
              'event safe to act on out of order: a receiver holding ' +
              '"compliant" that gets an event whose previous status is ' +
              '"not-compliant" knows it has missed one, and that gap is ' +
              'invisible from either event on its own.' },
      { name: 'current_status', required: true, type: 'enum',
        values: ['compliant', 'not-compliant'],
        what: 'What it is now. The hyphen in "not-compliant" is the ' +
              'specification\'s and is worth checking against — ' +
              '"noncompliant" is silently ignored by a conforming ' +
              'receiver.' }
    ]),
    generate: function (values) {
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
    }
  },
  {
    uri: CAEP_PREFIX + 'risk-level-change',
    family: 'caep',
    name: 'Risk Level Change',
    subject: 'required',
    what: 'A risk engine changed its mind about somebody. It is the only ' +
          'CAEP event that is a JUDGEMENT rather than a fact — the other ' +
          'seven report something that happened — which is why it carries a ' +
          'reason and why a receiver is expected to weigh it rather than ' +
          'act on it.',
    howItIsAsked: 'Nobody asks. A risk engine tells the transmitter when a ' +
          'signal moves.',
    members: withCommonMembers([
      { name: 'principal', required: true, type: 'openenum',
        values: ['USER', 'DEVICE', 'SESSION', 'TENANT', 'ORG_UNIT', 'GROUP'],
        what: 'WHAT the level is about, and it is required because the ' +
              'subject alone cannot say: a complex subject names a person ' +
              'AND a device AND a session, and "risk went to HIGH" about ' +
              'the device is a different fact from the same sentence about ' +
              'the person. THE VALUES ARE UPPER CASE HERE and lower case in ' +
              'a complex subject\'s member names, which catches everybody ' +
              'once.' },
      { name: 'current_level', required: true, type: 'enum',
        values: ['LOW', 'MEDIUM', 'HIGH'],
        what: 'The level now. Three values, upper case, closed.' },
      { name: 'previous_level', required: false, type: 'enum',
        values: ['LOW', 'MEDIUM', 'HIGH'],
        what: 'The level before, which is what lets a receiver notice a ' +
              'missed event.' },
      { name: 'risk_reason', required: false, type: 'string',
        what: 'What contributed. RECOMMENDED rather than required, and it ' +
              'decides whether a receiver can do anything but step up: ' +
              '"impossible travel" and "credential seen in a breach corpus" ' +
              'call for different answers.' }
    ]),
    generate: function (values) {
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
    }
  }
];

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
// `credential-compromise`. Reusing `withCommonMembers()` here would attach
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
var RISC_COMMON_MEMBERS = [
  { name: 'event_timestamp', required: false, type: 'number',
    what: 'When the transmitter DISCOVERED the compromise, in seconds since ' +
          'the epoch. RISC section 2.7 words it as discovery rather than as ' +
          'occurrence, and that is not pedantry: a credential found in a ' +
          'breach corpus was compromised long before anybody noticed, so a ' +
          'receiver reading this as "when it happened" dates the incident ' +
          'from the wrong end.' },
  { name: 'reason_admin', required: false, type: 'langmap',
    what: 'Why, for an administrator. This build sends and expects the ' +
          'LANGUAGE-MAP shape CAEP defines — {"en": "..."} — and RISC 1.0 ' +
          'does not actually repeat that requirement, which makes a bare ' +
          'string arguably conforming to RISC and certainly unreadable to a ' +
          'receiver built against CAEP. The map is the reading that is right ' +
          'under both.' },
  { name: 'reason_user', required: false, type: 'langmap',
    what: 'The same, in words meant for the person it happened to.' }
];

var RISC_EVENTS = [
  {
    uri: RISC_PREFIX + 'account-credential-change-required',
    family: 'risc',
    name: 'Account Credential Change Required',
    subject: 'required',
    what: 'The account named by the subject was REQUIRED to change a ' +
          'credential — a forced password reset, most often. It is not a ' +
          'report that a credential changed: nothing here says one did, and ' +
          'the person may never comply. What a receiver learns is that this ' +
          'provider no longer trusts what it currently holds.',
    howItIsAsked: 'Nobody asks. A transmitter sends it when it decides a ' +
          'credential has to be replaced — a breach, an expiry policy, an ' +
          'administrator.',
    members: [],
    generate: function () {
      log.debug("Entering generate(). account-credential-change-required");
      log.debug("Leaving generate(). account-credential-change-required");
      return {};
    }
  },
  {
    uri: RISC_PREFIX + 'account-purged',
    family: 'risc',
    name: 'Account Purged',
    subject: 'required',
    what: 'The account was PERMANENTLY DELETED. It is the one terminal ' +
          'event in the vocabulary and the model treats it as one: nothing ' +
          'can be said about a purged account afterwards except by ' +
          'contradiction. The distinction from account-disabled is the whole ' +
          'of its meaning — a disabled account may come back and this one ' +
          'may not.',
    howItIsAsked: 'Nobody asks. A transmitter sends it when the account is ' +
          'deleted at its end.',
    members: [],
    generate: function () {
      log.debug("Entering generate(). account-purged");
      log.debug("Leaving generate(). account-purged");
      return {};
    }
  },
  {
    uri: RISC_PREFIX + 'account-disabled',
    family: 'risc',
    name: 'Account Disabled',
    subject: 'required',
    what: 'The account was disabled and MAY BE ENABLED AGAIN. It is the ' +
          'ordinary account-takeover signal, and the pair it forms with ' +
          'account-enabled is what makes it different from a purge.',
    howItIsAsked: 'Nobody asks. A transmitter sends it when it locks the ' +
          'account — a risk engine, an abuse team, an administrator.',
    members: [
      { name: 'reason', required: false, type: 'openenum',
        values: ['hijacking', 'bulk-account'],
        what: 'Why, as one of two words RISC names — and what those two are ' +
              'FOR is worth knowing. "hijacking" says this ONE account was ' +
              'taken over, which is a signal about a person. "bulk-account" ' +
              'says it was one of a population created by a script, which is ' +
              'a signal about the PROVIDER and asks a receiver to look at ' +
              'everything else that arrived at the same time. The ' +
              'specification says "possible values" rather than closing the ' +
              'list, so a third word is carried with a warning.' }
    ],
    generate: function (values) {
      log.debug("Entering generate(). account-disabled");
      var asked = values || {};
      var payload = {};
      if (typeof asked.reason === 'string' && asked.reason !== '') {
        payload.reason = asked.reason;
      }
      log.debug("Leaving generate(). account-disabled");
      return payload;
    }
  },
  {
    uri: RISC_PREFIX + 'account-enabled',
    family: 'risc',
    name: 'Account Enabled',
    subject: 'required',
    what: 'The account was enabled. It is RISC\'s only GOOD NEWS and it is ' +
          'the one everybody forgets to implement: a receiver that acts on ' +
          'account-disabled and ignores this one has locked somebody out ' +
          'permanently on the strength of an incident that was resolved.',
    howItIsAsked: 'Nobody asks. A transmitter sends it when the lock comes ' +
          'off.',
    members: [],
    generate: function () {
      log.debug("Entering generate(). account-enabled");
      log.debug("Leaving generate(). account-enabled");
      return {};
    }
  },
  {
    uri: RISC_PREFIX + 'identifier-changed',
    family: 'risc',
    name: 'Identifier Changed',
    subject: 'required',
    subjectFormats: ['email', 'phone_number'],
    what: 'The identifier IN THE SUBJECT changed, and the subject carries ' +
          'the OLD value — which is the reverse of every other event in all ' +
          'three vocabularies and the thing that catches everybody. RISC ' +
          'says only the provider AUTHORITATIVE over the identifier should ' +
          'send this: an email provider may say john.doe@ became john.roe@, ' +
          'and a site where that address is merely a username may not — it ' +
          'sends recovery-information-changed instead.',
    howItIsAsked: 'Nobody asks. The provider that owns the address or the ' +
          'number sends it when the person changes one.',
    members: [
      { name: 'new-value', required: false, type: 'string',
        what: 'What the identifier became. **THE ONLY HYPHENATED MEMBER ' +
              'NAME IN ANY OF THE THREE VOCABULARIES** — everything else in ' +
              'SSF, CAEP and RISC is snake_case — so `new_value` typed from ' +
              'habit produces an event that delivers and says nothing. It ' +
              'is OPTIONAL, and a transmitter that leaves it out tells a ' +
              'receiver that an address it holds is stale without telling ' +
              'it what to hold instead: legal, and nearly useless.' }
    ],
    generate: function (values) {
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
    }
  },
  {
    uri: RISC_PREFIX + 'identifier-recycled',
    family: 'risc',
    name: 'Identifier Recycled',
    subject: 'required',
    subjectFormats: ['email', 'phone_number'],
    what: 'The identifier in the subject was RECYCLED and now belongs to ' +
          'SOMEBODY ELSE. It is the event whose absence causes the quietest ' +
          'account takeover there is: a mail provider reissues a lapsed ' +
          'address, a relying party keyed on the address by itself lets the ' +
          'new owner into the old owner\'s account, and nothing anywhere was ' +
          'compromised. It is the whole argument for keying on an ' +
          'iss_sub pair rather than on an email address.',
    howItIsAsked: 'Nobody asks. The provider that owns the address sends it ' +
          'when it hands one to a new person.',
    members: [],
    generate: function () {
      log.debug("Entering generate(). identifier-recycled");
      log.debug("Leaving generate(). identifier-recycled");
      return {};
    }
  },
  {
    uri: RISC_PREFIX + 'credential-compromise',
    family: 'risc',
    name: 'Credential Compromise',
    subject: 'required',
    what: 'A credential belonging to this account was FOUND compromised — ' +
          'seen in a breach corpus, or reported. THE ONLY ONE OF THE ' +
          'FOURTEEN WITH A REQUIRED MEMBER, and the only one carrying any ' +
          'of the claims CAEP gives to all eight of its own. A receiver acts ' +
          'on it differently by type: a compromised password is a reset, and ' +
          'a compromised hardware key is a revocation.',
    howItIsAsked: 'Nobody asks. A transmitter sends it when its own ' +
          'monitoring finds the credential somewhere it should not be.',
    members: [
      { name: 'credential_type', required: true, type: 'openenum',
        values: CREDENTIAL_TYPES,
        what: 'Which kind of credential was found compromised. **RISC ' +
              'SECTION 2.7 DEFINES THIS BY REFERENCE TO CAEP\'s ' +
              'credential-change**, so the two lists are the same list ' +
              'rather than two alike ones — which is why there is one ' +
              'CREDENTIAL_TYPES in this file and not a copy per vocabulary. ' +
              'It is OPEN in both places, so a vendor\'s own type is carried ' +
              'with a warning.' }
    ].concat(RISC_COMMON_MEMBERS),
    generate: function (values) {
      log.debug("Entering generate(). credential-compromise");
      var asked = values || {};
      var payload = {
        credential_type: (typeof asked.credential_type === 'string' &&
          asked.credential_type !== '') ? asked.credential_type : 'password'
      };
      log.debug("Leaving generate(). credential-compromise");
      return payload;
    }
  },
  {
    uri: RISC_PREFIX + 'opt-in',
    family: 'risc',
    name: 'Opt In',
    subject: 'required',
    what: 'The account is participating in RISC exchange again. It is one ' +
          'of the four events that ARE a state transition rather than a ' +
          'report of one — RISC section 2.8 defines each of them as "the ' +
          'account is in the X state" — and it is the only event that may be ' +
          'sent about an account which has opted OUT, because without it a ' +
          'receiver would never learn that one came back.',
    howItIsAsked: 'Nobody asks. The person opted back in at the ' +
          'transmitter, and the transmitter says so.',
    members: [],
    generate: function () {
      log.debug("Entering generate(). opt-in");
      log.debug("Leaving generate(). opt-in");
      return {};
    }
  },
  {
    uri: RISC_PREFIX + 'opt-out-initiated',
    family: 'risc',
    name: 'Opt Out Initiated',
    subject: 'required',
    what: 'The person asked to stop RISC exchange, AND IT CARRIES ON FOR A ' +
          'WHILE ANYWAY. That delay is the point of the state existing at ' +
          'all: RISC section 2.8 says it is there to stop a hijacker from ' +
          'opting out the moment they take an account over and silencing the ' +
          'very events that would report them.',
    howItIsAsked: 'Nobody asks. The person asked at the transmitter.',
    members: [],
    generate: function () {
      log.debug("Entering generate(). opt-out-initiated");
      log.debug("Leaving generate(). opt-out-initiated");
      return {};
    }
  },
  {
    uri: RISC_PREFIX + 'opt-out-cancelled',
    family: 'risc',
    name: 'Opt Out Cancelled',
    subject: 'required',
    what: 'The opt-out was called off and the account is back in the opt-in ' +
          'state. **THE SPELLING IS BRITISH AND IT IS THE ' +
          'SPECIFICATION\'S** — "cancelled" with two Ls — so a transmitter ' +
          'writing "opt-out-canceled" produces a URI a conforming receiver ' +
          'silently ignores, because there is no unknown-event-type error in ' +
          'this protocol.',
    howItIsAsked: 'Nobody asks. The person changed their mind before the ' +
          'opt-out took effect.',
    members: [],
    generate: function () {
      log.debug("Entering generate(). opt-out-cancelled");
      log.debug("Leaving generate(). opt-out-cancelled");
      return {};
    }
  },
  {
    uri: RISC_PREFIX + 'opt-out-effective',
    family: 'risc',
    name: 'Opt Out Effective',
    subject: 'required',
    what: 'The opt-out has taken effect and no further RISC events will be ' +
          'sent about this account. IT IS THE LAST ONE — an event announcing ' +
          'that there will be no more events — which is what makes it the ' +
          'one an opt-out gate must never suppress. Suppressing it would ' +
          'leave a receiver waiting for signals that stopped without notice, ' +
          'which at the far end is indistinguishable from a transmitter that ' +
          'has gone down.',
    howItIsAsked: 'Nobody asks. The transmitter\'s waiting period ended.',
    members: [],
    generate: function () {
      log.debug("Entering generate(). opt-out-effective");
      log.debug("Leaving generate(). opt-out-effective");
      return {};
    }
  },
  {
    uri: RISC_PREFIX + 'recovery-activated',
    family: 'risc',
    name: 'Recovery Activated',
    subject: 'required',
    what: 'The account went through a recovery flow. It is a signal about ' +
          'RISK rather than about a change: a recovery is how a legitimate ' +
          'owner gets back in and it is also how an attacker who controls ' +
          'the recovery channel takes over, and the transmitter cannot tell ' +
          'which. A receiver is expected to weigh it, not act on it.',
    howItIsAsked: 'Nobody asks. Somebody used the "forgot my password" door.',
    members: [],
    generate: function () {
      log.debug("Entering generate(). recovery-activated");
      log.debug("Leaving generate(). recovery-activated");
      return {};
    }
  },
  {
    uri: RISC_PREFIX + 'recovery-information-changed',
    family: 'risc',
    name: 'Recovery Information Changed',
    subject: 'required',
    what: 'A recovery address or number was added, changed or removed. It ' +
          'is what a provider sends about an identifier IT IS NOT ' +
          'AUTHORITATIVE OVER — RISC says so where identifier-changed says ' +
          'the opposite — so the pair of them is the same act reported by ' +
          'two different kinds of provider. It carries no member saying ' +
          'WHICH information moved, deliberately: that would be publishing ' +
          'somebody\'s recovery address to every receiver on the stream.',
    howItIsAsked: 'Nobody asks. The person edited their recovery settings.',
    members: [],
    generate: function () {
      log.debug("Entering generate(). recovery-information-changed");
      log.debug("Leaving generate(). recovery-information-changed");
      return {};
    }
  },
  {
    uri: RISC_PREFIX + 'sessions-revoked',
    family: 'risc',
    name: 'Sessions Revoked',
    subject: 'required',
    // RISC 1.0 section 2.11 deprecates this in favour of CAEP's
    // `session-revoked`. The row carries WHAT REPLACES IT rather than a
    // boolean, so the warning can name it — and because the next deprecation
    // in any of these vocabularies should be a field and not a branch.
    deprecated: CAEP_PREFIX + 'session-revoked',
    what: 'EVERY session the account has, everywhere, is gone — which is a ' +
          'far larger instruction than CAEP\'s session-revoked, whose ' +
          'subject names ONE of them. **DEPRECATED by RISC 1.0 section ' +
          '2.11**, which says new implementations MUST use CAEP\'s singular ' +
          'event instead. The two names differ by one letter and mean ' +
          'different things, so this is the pair to check when a receiver ' +
          'ends more sessions than anybody intended. It is here, and ' +
          'sendable, because a debugger that could not produce a deprecated ' +
          'event could not be used to find out what a receiver does with ' +
          'one.',
    howItIsAsked: 'Nobody asks — and nobody should be sending it. Receivers ' +
          'in the field still do.',
    members: [],
    generate: function () {
      log.debug("Entering generate(). sessions-revoked");
      log.debug("Leaving generate(). sessions-revoked");
      return {};
    }
  }
];

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
var FAMILIES = [
  { id: 'ssf', label: 'SSF — the framework itself', prefix: SSF_PREFIX,
    implemented: true,
    what: 'Two event types, both about the PIPE rather than about a person: ' +
          'is this stream alive, and has its status changed.' },
  { id: 'caep', label: 'CAEP — Continuous Access Evaluation Profile',
    prefix: CAEP_PREFIX, implemented: true,
    what: 'The enterprise SESSION vocabulary, in eight event types: session ' +
          'revoked, established and presented, token claims change, ' +
          'credential change, assurance level change, device compliance ' +
          'change and risk level change. It says "this session is no longer ' +
          'trustworthy", and every one of them names a SESSION rather than ' +
          'a person — which is what SSF\'s complex subject is for.' },
  { id: 'risc', label: 'RISC — Risk Incident Sharing and Coordination',
    prefix: RISC_PREFIX, implemented: true,
    what: 'The account-lifecycle vocabulary, aimed ACROSS providers rather ' +
          'than within one enterprise, in fourteen event types: account ' +
          'disabled, enabled and purged, credential change required, ' +
          'credential compromise, identifier changed and recycled, four ' +
          'opt-out events, recovery activated and recovery information ' +
          'changed, and one the specification deprecates in favour of a CAEP ' +
          'event. It says "this account is no longer trustworthy", which is ' +
          'a different sentence from CAEP\'s and the whole reason there are ' +
          'two profiles. ELEVEN OF THE FOURTEEN CARRY NO PAYLOAD MEMBERS AT ' +
          'ALL, so the SUBJECT is the entire message — which is the opposite ' +
          'of CAEP, where the subject narrows and the payload says what ' +
          'happened.' }
];

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
var PROFILES = [
  { id: 'ssf', family: 'ssf', label: 'Pure SSF',
    implemented: true,
    what: 'The framework itself. Two event types, both about the PIPE ' +
          'rather than about a person: is this stream alive, and has its ' +
          'status changed. Everything else on this page is the machinery ' +
          'both vocabularies run on.' },
  { id: 'caep', family: 'caep', label: 'CAEP',
    implemented: true,
    what: 'Continuous Access Evaluation Profile 1.0. Eight event types ' +
          'about a SESSION — it says "this session is no longer ' +
          'trustworthy". The CAEP Session pane appears, and every event ' +
          'list on this page narrows to these eight.' },
  { id: 'risc', family: 'risc', label: 'RISC',
    implemented: true,
    what: 'RISC Profile Specification 1.0, published 29 August 2025 and ' +
          'final on 2 September 2025. Fourteen event types about an ' +
          'ACCOUNT — it says "this account is no longer trustworthy", which ' +
          'is a larger sentence than CAEP\'s by orders of magnitude: a ' +
          'revoked session is one sign-in at one relying party, and a purged ' +
          'account is every session that person has anywhere, for ever. The ' +
          'RISC Account pane appears, and every event list on this page ' +
          'narrows to these fourteen.' }
];

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
  if (!format) {
    warnings.push('"' + uri + '" wants a subject in one of these formats: ' +
        formats.join(', ') + '. This one is a COMPLEX subject — it has no ' +
        '`format` of its own — which names a person and possibly a session, ' +
        'and this event is about an IDENTIFIER rather than about either.');
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
