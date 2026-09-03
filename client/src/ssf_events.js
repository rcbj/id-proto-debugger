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
        values: ['password', 'pin', 'x509', 'fido2-platform',
                 'fido2-roaming', 'fido-u2f', 'verifiable-credential',
                 'phone-voice', 'phone-sms', 'app'],
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

// The two vocabularies in one table. SSF's own first, because they are about
// the pipe every one of the others travels on.
var EVENTS = SSF_EVENTS.concat(CAEP_EVENTS);

var CAEP_EVENT_URIS = CAEP_EVENTS.map(function (row) {
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
    prefix: RISC_PREFIX, implemented: false,
    what: 'The account-lifecycle vocabulary, aimed ACROSS providers rather ' +
          'than within one enterprise: account disabled, purged, credentials ' +
          'compromised, credential change required, identifier changed or ' +
          'recycled. It says "this account is no longer trustworthy", which ' +
          'is a different sentence from CAEP\'s and is the whole reason ' +
          'there are two profiles. NOT IMPLEMENTED YET — the third part of ' +
          'this work, and it will be rows in this file\'s table.' }
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
    implemented: false,
    what: 'Risk Incident Sharing and Coordination 1.0, the account ' +
          'lifecycle vocabulary aimed ACROSS providers — it says "this ' +
          'account is no longer trustworthy". NOT IMPLEMENTED YET: it is ' +
          'the third part of this work. Choosing it leaves the pipe working ' +
          'and offers no event types, which is what an unimplemented ' +
          'vocabulary honestly looks like.' }
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
