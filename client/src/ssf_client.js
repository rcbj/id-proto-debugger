// File: ssf_client.js
//
// ---------------------------------------------------------------------------
// THE SHARED SIGNALS FRAMEWORK, WITH NO DOM IN IT.
//
// SSF 1.0 (OpenID, final 2 September 2025) is the plumbing under CAEP and
// RISC: it says how a RECEIVER and a TRANSMITTER agree a STREAM, who the
// events on it are about, what those events travel in, and how they get
// delivered. It carries almost no vocabulary of its own — two event types,
// both about the pipe — and that separation is the single most important thing
// to hold on to while reading this file, because it is what makes the module
// shaped the way it is:
//
//   * RFC 9493 SUBJECT IDENTIFIERS say WHO. Eight formats plus SSF's complex
//     subject, and each format's member set is CLOSED.
//   * RFC 8417 SECURITY EVENT TOKENS are the envelope. A JWT with an `events`
//     map, no `exp`, and the subject in `sub_id` rather than `sub`.
//   * RFC 8935 (push) and RFC 8936 (poll) are the two deliveries.
//   * The STREAM MANAGEMENT API is the control plane, and every one of its
//     endpoints is DISCOVERED rather than fixed — SSF publishes them in the
//     transmitter's configuration metadata, so this module composes no path.
//
// **CAEP AND RISC ARE PARTS TWO AND THREE OF THIS WORK**, and everything here
// is written so that adding them is rows in `ssf_events.js`'s table and
// nothing else. If any function in this file grows a branch that names one of
// SSF's own two event types, that is the design going wrong.
//
// ---------------------------------------------------------------------------
// NO DOM, AND THAT IS WHAT THE TESTS ARE FOR.
//
// The rule `jws.js`, `scim_client.js` and the encryption engines follow:
// everything here is values in and values out, so `tests/ssf_engine.js` drives
// the whole of it in node against the specifications' own text. That is the
// only kind of check that can catch what actually goes wrong in this protocol,
// which is never a crash:
//
//   * a subject identifier with an extra member, which a conforming receiver
//     MUST reject and which looks perfectly fine in a log;
//   * an `exp` on a SET, which asks a receiver to discard history (RFC 8417
//     section 4.1.4 forbids it);
//   * `events_requested` read back as `events_delivered`, so a receiver
//     believes it will get types nothing will ever send;
//   * a delivery method spelt `push` rather than `urn:ietf:rfc:8935`;
//   * a PATCH that behaves like a PUT, so a member the caller omitted quietly
//     goes back to its default.
//
// Every one of those produces a workflow that works perfectly against itself.
//
// ---------------------------------------------------------------------------
// THE SUBJECT GRAMMAR IS WRITTEN OUT HERE AND IS **NOT** SHARED WITH THE MOCK.
//
// `common/krb5` is vendored into the mock STS because one wire CODEC must not
// exist twice. This is the opposite case and the reason is worth stating,
// because the two look alike: a subject identifier is JSON, and the defect
// that matters in it is a READING — an accepted extra member, a missing
// required one, a format name spelt from memory. If both ends read one
// implementation, a misunderstanding they share is one neither can see, and
// the round trip passes while interoperating with nothing. So the mock has
// `sts/ssf/ssf_subjects.js`, this file has its own, and
// `tests/ssf_protocol.js` drives one against the other OVER THE WIRE. It is
// the argument `common/pq_jose.js` makes in the mock, applied to a grammar
// instead of to a signature.
//
// ---------------------------------------------------------------------------
// THE CRYPTOGRAPHY IS `jws.js`'s AND NONE OF IT IS HERE.
//
// A SET is a JWS, so signing and verifying one goes through the module that
// already does every JWS in this application — which is what gives this
// workflow every registered algorithm for no code at all, POST-QUANTUM ONES
// INCLUDED: ML-DSA at three sizes, SLH-DSA, and the six composite ML-DSA +
// traditional algorithms. **A SET is the document in this application most
// worth signing that way**: it records that something HAPPENED, RFC 8417
// section 4.1.4 forbids it to expire, and it is therefore read long after it
// was written — which is the case a harvest-now-decrypt-later argument is
// actually about.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
var jws = require("./jws");

// The log level comes from the same configuration the pages use. A consumer
// outside the browser bundles (the node-based tests load this module directly)
// may not have one, so fall back to info rather than failing to load.
var log = bunyan.createLogger({
  name: "ssf_client",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// ---------------------------------------------------------------------------
// RFC 9493 SECTION 3 — THE EIGHT SUBJECT IDENTIFIER FORMATS.
//
// `members` is the format's CLOSED set and `required` is what a conforming
// identifier must carry. For seven of the eight those lists are identical,
// which is the specification's own shape rather than a shortcut: RFC 9493
// defines no optional member on any format except Aliases, whose `identifiers`
// is required and whose CONTENTS are the variable part.
//
// `what` and `example` are for the page — a picker with eight formats in it is
// useless without a sentence and a specimen for each — and neither is read by
// the validator.
// ---------------------------------------------------------------------------
var SUBJECT_FORMATS = [
  { format: 'account',
    label: 'Account (acct: URI)',
    members: ['uri'], required: ['uri'],
    what: 'An "acct" URI (RFC 7565): a user at a service, the identifier ' +
          'form WebFinger uses. NOT a mailto: and not a bare address — the ' +
          'scheme is what tells this format from "email".',
    example: { format: 'account', uri: 'acct:alice@example.com' } },
  { format: 'email',
    label: 'Email address',
    members: ['email'], required: ['email'],
    what: 'An RFC 5322 addr-spec. The commonest subject in practice and the ' +
          'one most likely to be RECYCLED, which is why RISC has an event ' +
          'type about exactly that.',
    example: { format: 'email', email: 'alice@example.com' } },
  { format: 'issuer_subject_id',
    label: 'Issuer and subject (iss + sub)',
    members: ['iss', 'sub'], required: ['iss', 'sub'],
    what: 'The pair an OpenID Connect ID Token is identified by. The only ' +
          'format that is globally unique by construction rather than by ' +
          'convention, and the one to reach for when the transmitter is also ' +
          'the OP you signed in at.',
    example: { format: 'issuer_subject_id',
               iss: 'https://issuer.example.com/', sub: '145234573' } },
  { format: 'opaque',
    label: 'Opaque identifier',
    members: ['id'], required: ['id'],
    what: 'A string meaningful only to the two parties that agreed it. It ' +
          'says nothing about what KIND of thing it names, which is the ' +
          'point: a transmitter that must not leak an email address uses ' +
          'this.',
    example: { format: 'opaque', id: '11112222333344445555' } },
  { format: 'phone_number',
    label: 'Phone number (E.164)',
    members: ['phone_number'], required: ['phone_number'],
    what: 'E.164: a leading "+" and digits only. No spaces, no punctuation, ' +
          'no extension — "+1 206 555 0100" is a DIFFERENT subject from ' +
          '"+12065550100" to any receiver that compares them.',
    example: { format: 'phone_number', phone_number: '+12065550100' } },
  { format: 'decentralized_identifier',
    label: 'Decentralized identifier (DID)',
    members: ['url'], required: ['url'],
    what: 'A DID or a DID URL (W3C DID Core). The identifier resolves to a ' +
          'document rather than to a record at the transmitter, which is the ' +
          'one format here whose subject can be described without asking ' +
          'anybody.',
    example: { format: 'decentralized_identifier',
               url: 'did:example:123456789abcdefghi' } },
  { format: 'uri',
    label: 'URI',
    members: ['uri'], required: ['uri'],
    what: 'Any URI. The escape hatch, and the one to reach for LAST: a ' +
          'receiver can do nothing with it but compare it, so a format that ' +
          'says what kind of thing this is is always better.',
    example: { format: 'uri', uri: 'https://example.com/users/1234' } },
  { format: 'aliases',
    label: 'Aliases (several identifiers for one subject)',
    members: ['identifiers'], required: ['identifiers'],
    what: 'SEVERAL identifiers for ONE subject, so a receiver that knows the ' +
          'person by any of them can act. It MUST NOT contain another ' +
          '"aliases" identifier — section 3.2.8 forbids the nesting outright.',
    example: { format: 'aliases', identifiers: [
      { format: 'email', email: 'alice@example.com' },
      { format: 'phone_number', phone_number: '+12065550100' }
    ] } }
];

var SUBJECT_FORMAT_BY_NAME = {};
SUBJECT_FORMATS.forEach(function (row) {
  SUBJECT_FORMAT_BY_NAME[row.format] = row;
});

var SUBJECT_FORMAT_NAMES = SUBJECT_FORMATS.map(function (row) {
  return row.format;
});

// ---------------------------------------------------------------------------
// THE COMPLEX SUBJECT — SSF's own addition, not RFC 9493's.
//
// SSF 1.0 section 4 lets a `sub_id` be an object whose members are each
// themselves a Subject Identifier, so one event can name the person AND the
// device AND the session it is about. That is what makes "this session was
// revoked" expressible at all: the person is not revoked, one session of
// theirs is — which is the whole distinction CAEP rests on.
//
// The six names are CLOSED. A transmitter's `critical_subject_members` names
// the ones a receiver MUST understand, which is a different list and is
// configuration rather than grammar.
// ---------------------------------------------------------------------------
var COMPLEX_SUBJECT_MEMBERS = [
  { name: 'user', what: 'The person.' },
  { name: 'device', what: 'The device they are on.' },
  { name: 'session', what: 'The one session, of possibly many. This is the ' +
      'member that makes "revoke this session and not this person" ' +
      'expressible.' },
  { name: 'tenant', what: 'The tenant, in a multi-tenant service.' },
  { name: 'org_unit', what: 'The organizational unit within the tenant.' },
  { name: 'group', what: 'The group membership the event is about.' }
];

var COMPLEX_SUBJECT_MEMBER_NAMES = COMPLEX_SUBJECT_MEMBERS.map(
  function (row) {
    return row.name;
  });

// E.164: a plus and between 1 and 15 digits. See the format's `what`.
var E164 = /^\+[1-9][0-9]{1,14}$/;
// An addr-spec, checked loosely on purpose: a grammar strict enough to be
// interesting about email addresses refuses valid ones. What is checked is
// what a COMPARISON depends on — one "@", something either side, no space.
var ADDR_SPEC = /^[^\s@]+@[^\s@]+$/;
var ACCT_URI = /^acct:[^\s@]+@[^\s@]+$/;
var DID_URL = /^did:[a-z0-9]+:[^\s]+$/;
// Any absolute URI, and deliberately not `new URL()`: that refuses several
// URIs which are perfectly legal here (a bare `urn:`, a `tag:`).
var ABSOLUTE_URI = /^[A-Za-z][A-Za-z0-9+.\-]*:[^\s]+$/;

// Keyed by FORMAT.MEMBER rather than by member alone, because `uri` on the
// `uri` format and `uri` on the `account` format are different rules — and
// that difference is the whole of what tells those two formats apart on the
// wire.
var SUBJECT_VALUE_RULES = {
  'account.uri': function (value) {
    return ACCT_URI.test(value) ? '' :
      'is not an "acct" URI (RFC 7565). It has to begin "acct:" and carry a ' +
      'user and a host, as in acct:alice@example.com. A bare address is the ' +
      '"email" format and a mailto: is the "uri" one.';
  },
  'email.email': function (value) {
    return ADDR_SPEC.test(value) ? '' :
      'is not an email address: one "@", something either side of it, and ' +
      'no whitespace.';
  },
  'phone_number.phone_number': function (value) {
    return E164.test(value) ? '' :
      'is not an E.164 number. RFC 9493 section 3.2.5 wants a leading "+" ' +
      'and digits only, so "+1 206 555 0100" is a DIFFERENT subject from ' +
      '"+12065550100" to any receiver that compares them.';
  },
  'decentralized_identifier.url': function (value) {
    return DID_URL.test(value) ? '' :
      'is not a DID or a DID URL. It has to begin "did:", name a method and ' +
      'carry a method-specific identifier.';
  },
  'uri.uri': function (value) {
    return ABSOLUTE_URI.test(value) ? '' :
      'is not an absolute URI: it needs a scheme and a colon.';
  },
  'issuer_subject_id.iss': function (value) {
    return ABSOLUTE_URI.test(value) ? '' :
      'is not an absolute URI. An issuer identifier always is — it is the ' +
      'same string the ID Token carries.';
  }
};

// Everything with no rule of its own is a non-empty string and nothing more.
// `opaque.id` is the case that matters: it is opaque BY DEFINITION, so a check
// on its shape would be this module inventing a rule.
function checkSubjectMember(format, member, value) {
  log.debug("Entering checkSubjectMember(). " + format + "." + member);
  if (typeof value !== 'string' || value === '') {
    log.debug("Leaving checkSubjectMember(). Not a non-empty string.");
    return 'must be a non-empty string';
  }
  var rule = SUBJECT_VALUE_RULES[format + '.' + member];
  if (!rule) {
    log.debug("Leaving checkSubjectMember(). No shape rule.");
    return '';
  }
  var problem = rule(value);
  log.debug("Leaving checkSubjectMember(). " + (problem ? "refused" : "ok"));
  return problem;
}

// ---------------------------------------------------------------------------
// VALIDATE ONE SIMPLE SUBJECT IDENTIFIER.
//
// Returns `{ ok, format, errors }`, with EVERY problem collected rather than
// the first one thrown. A subject built on a form is usually wrong in more
// than one way at once, and a validator that reports one error per attempt is
// one somebody stops reading.
//
// `path` is where this identifier sits in the document ("sub_id",
// "sub_id.user", "sub_id.identifiers[1]"), so a message names the member the
// reader can actually find on the screen.
// ---------------------------------------------------------------------------
function validateSubject(subject, path) {
  log.debug("Entering validateSubject(). " + (path || 'sub_id'));
  var where = path || 'sub_id';
  var errors = [];
  if (!subject || typeof subject !== 'object' ||
      Object.prototype.toString.call(subject) === '[object Array]') {
    errors.push(where + ' must be a JSON object.');
    log.debug("Leaving validateSubject(). Not an object.");
    return { ok: false, format: '', errors: errors };
  }
  var format = subject.format;
  if (typeof format !== 'string' || format === '') {
    errors.push(where + ' has no "format" member. RFC 9493 makes it ' +
        'REQUIRED on every Subject Identifier — without it a receiver ' +
        'cannot know which members to read. The eight are: ' +
        SUBJECT_FORMAT_NAMES.join(', ') + '.');
    log.debug("Leaving validateSubject(). No format.");
    return { ok: false, format: '', errors: errors };
  }
  var row = SUBJECT_FORMAT_BY_NAME[format];
  if (!row) {
    errors.push(where + ' names the format "' + format + '", which RFC 9493 ' +
        'does not define. The eight are: ' + SUBJECT_FORMAT_NAMES.join(', ') +
        '.');
    log.debug("Leaving validateSubject(). Unknown format.");
    return { ok: false, format: format, errors: errors };
  }

  // THE CLOSED MEMBER SET. This is the check that catches the defect nothing
  // else does: a subject with an extra member looks fine in a log and is
  // refused by every conforming receiver.
  Object.keys(subject).forEach(function (name) {
    if (name === 'format') {
      return;
    }
    if (row.members.indexOf(name) < 0) {
      errors.push(where + ' carries "' + name + '", which the "' + format +
          '" format does not define. RFC 9493 section 3 gives each format a ' +
          'CLOSED set of members: a receiver that met an unrecognised one ' +
          'could not tell whether it NARROWS the subject, so it must reject ' +
          'the identifier rather than ignore the member. This format has: ' +
          row.members.join(', ') + '.');
    }
  });

  row.required.forEach(function (name) {
    if (!Object.prototype.hasOwnProperty.call(subject, name)) {
      errors.push(where + ' has no "' + name + '", which the "' + format +
          '" format requires.');
    }
  });

  if (format === 'aliases') {
    validateAliases(subject, where, errors);
  } else {
    row.members.forEach(function (name) {
      if (!Object.prototype.hasOwnProperty.call(subject, name)) {
        return;
      }
      var problem = checkSubjectMember(format, name, subject[name]);
      if (problem) {
        errors.push(where + '.' + name + ' ' + problem);
      }
    });
  }

  log.debug("Leaving validateSubject(). " + errors.length + " problem(s).");
  return { ok: errors.length === 0, format: format, errors: errors };
}

// The Aliases format's own rules, split out because they are the only ones
// that recurse and the only ones with a NESTING ban to enforce.
function validateAliases(subject, where, errors) {
  log.debug("Entering validateAliases().");
  var list = subject.identifiers;
  if (Object.prototype.toString.call(list) !== '[object Array]') {
    errors.push(where + '.identifiers must be an array of Subject ' +
        'Identifiers.');
    log.debug("Leaving validateAliases(). Not an array.");
    return;
  }
  if (!list.length) {
    errors.push(where + '.identifiers is empty. An Aliases identifier that ' +
        'names nobody identifies nobody.');
    log.debug("Leaving validateAliases(). Empty.");
    return;
  }
  list.forEach(function (one, index) {
    var inner = where + '.identifiers[' + index + ']';
    if (one && typeof one === 'object' && one.format === 'aliases') {
      errors.push(inner + ' is itself an "aliases" identifier. RFC 9493 ' +
          'section 3.2.8 forbids the nesting outright. It is refused rather ' +
          'than flattened, because flattening would build a document a ' +
          'conforming receiver rejects and the sender would never find out.');
      return;
    }
    validateSubject(one, inner).errors.forEach(function (message) {
      errors.push(message);
    });
  });
  log.debug("Leaving validateAliases().");
}

// ---------------------------------------------------------------------------
// VALIDATE A `sub_id`, SIMPLE OR COMPLEX.
//
// The two are told apart by the presence of `format`, which is SSF 1.0 section
// 4's own discriminator. That is worth being explicit about, because the
// obvious alternative — "does it have a member called `user`?" — is wrong for
// an `opaque` subject whose id happens to be spelt that way.
//
// `criticalMembers` is the transmitter's published `critical_subject_members`.
// A complex subject missing one is refused HERE, before it is sent, because a
// transmitter that published a critical member will refuse it anyway and the
// message is more useful on this side.
// ---------------------------------------------------------------------------
function validateSubjectId(subject, options) {
  log.debug("Entering validateSubjectId().");
  var settings = options || {};
  var where = settings.path || 'sub_id';
  if (!subject || typeof subject !== 'object' ||
      Object.prototype.toString.call(subject) === '[object Array]') {
    log.debug("Leaving validateSubjectId(). Not an object.");
    return { ok: false, complex: false, format: '',
      errors: [where + ' must be a JSON object.'] };
  }
  if (Object.prototype.hasOwnProperty.call(subject, 'format')) {
    var simple = validateSubject(subject, where);
    log.debug("Leaving validateSubjectId(). Simple.");
    return { ok: simple.ok, complex: false, format: simple.format,
      errors: simple.errors };
  }

  var errors = [];
  var names = Object.keys(subject);
  if (!names.length) {
    errors.push(where + ' is an empty object. A complex subject with no ' +
        'members names nobody, and a SIMPLE one would have carried a ' +
        '"format".');
  }
  names.forEach(function (name) {
    if (COMPLEX_SUBJECT_MEMBER_NAMES.indexOf(name) < 0) {
      errors.push(where + ' carries "' + name + '", which is neither one of ' +
          'the six complex subject members SSF 1.0 section 4 defines (' +
          COMPLEX_SUBJECT_MEMBER_NAMES.join(', ') + ') nor the "format" a ' +
          'SIMPLE identifier would carry. If this was meant to be a simple ' +
          'one, it is missing its "format".');
      return;
    }
    validateSubject(subject[name], where + '.' + name).errors
      .forEach(function (message) {
        errors.push(message);
      });
  });

  (settings.criticalMembers || []).forEach(function (name) {
    if (!Object.prototype.hasOwnProperty.call(subject, name)) {
      errors.push(where + ' has no "' + name + '" member, and this ' +
          'transmitter publishes "' + name + '" in ' +
          'critical_subject_members — a promise that every complex subject ' +
          'on its streams carries one. It will refuse this.');
    }
  });

  log.debug("Leaving validateSubjectId(). Complex, " + errors.length +
      " problem(s).");
  return { ok: errors.length === 0, complex: true, format: '',
    errors: errors };
}

// A stable string for one subject, so "is this the same subject" is a lookup.
// NOT a canonical serialization and must not be read as one: the members are
// sorted and joined with characters that cannot appear in a member name, which
// is enough to key a store and nothing more. An `aliases` identifier keys on
// its SORTED members, so the same two identifiers in the other order are one
// subject — which is what the format means.
function subjectKey(subject) {
  log.debug("Entering subjectKey().");
  if (!subject || typeof subject !== 'object') {
    log.debug("Leaving subjectKey(). Not an object.");
    return '';
  }
  if (Object.prototype.hasOwnProperty.call(subject, 'format')) {
    if (subject.format === 'aliases' &&
        Object.prototype.toString.call(subject.identifiers) ===
          '[object Array]') {
      var parts = subject.identifiers.map(subjectKey).sort();
      log.debug("Leaving subjectKey(). Aliases.");
      return 'aliases[' + parts.join('|') + ']';
    }
    var row = SUBJECT_FORMAT_BY_NAME[subject.format];
    var members = (row ? row.members : Object.keys(subject)
      .filter(function (name) {
        return name !== 'format';
      })).slice().sort();
    var body = members.map(function (name) {
      return name + '=' + String(subject[name] == null ? '' : subject[name]);
    }).join(';');
    log.debug("Leaving subjectKey(). Simple.");
    return subject.format + '{' + body + '}';
  }
  var complex = Object.keys(subject).slice().sort().map(function (name) {
    return name + '=' + subjectKey(subject[name]);
  }).join(';');
  log.debug("Leaving subjectKey(). Complex.");
  return 'complex{' + complex + '}';
}

// A one-line rendering for a table or a log line. It is for PEOPLE and nothing
// reads it back.
function describeSubject(subject) {
  log.debug("Entering describeSubject().");
  if (!subject || typeof subject !== 'object') {
    log.debug("Leaving describeSubject(). Nothing.");
    return '(no subject)';
  }
  if (!Object.prototype.hasOwnProperty.call(subject, 'format')) {
    var parts = Object.keys(subject).map(function (name) {
      return name + ': ' + describeSubject(subject[name]);
    });
    log.debug("Leaving describeSubject(). Complex.");
    return parts.join(', ') || '(empty complex subject)';
  }
  if (subject.format === 'aliases') {
    var inner = Object.prototype.toString.call(subject.identifiers) ===
      '[object Array]'
      ? subject.identifiers.map(describeSubject).join(' = ')
      : '(no identifiers)';
    log.debug("Leaving describeSubject(). Aliases.");
    return inner;
  }
  var row = SUBJECT_FORMAT_BY_NAME[subject.format];
  var values = (row ? row.members : []).map(function (name) {
    return String(subject[name] == null ? '' : subject[name]);
  }).filter(Boolean);
  log.debug("Leaving describeSubject(). Simple.");
  return values.join(' / ') || subject.format;
}

// ---------------------------------------------------------------------------
// THE TWO DELIVERY METHODS.
//
// The values are the RFC NUMBERS AS URNS, and that catches everybody once: a
// stream configuration asking for `"push"` is asking for nothing SSF defines,
// and a transmitter that accepted it would be inventing a method identifier.
// `deliveryUrn()` normalises the shorthand so the PAGE can offer the friendly
// word while the wire carries the URN.
// ---------------------------------------------------------------------------
var DELIVERY_PUSH = 'urn:ietf:rfc:8935';
var DELIVERY_POLL = 'urn:ietf:rfc:8936';

var DELIVERY_METHODS = [
  { method: DELIVERY_PUSH, short: 'push', label: 'Push (RFC 8935)',
    needsEndpoint: true,
    browserCanReceive: false,
    what: 'The transmitter POSTs each SET to a URL this receiver gives it. ' +
          'A BROWSER CANNOT BE THE FAR END OF THIS — a page is not an HTTP ' +
          'server — so this workflow asks its api layer to host an endpoint ' +
          'and puts that URL on the stream. On a deployment with no api ' +
          'there is nothing to host and this method is unavailable, which is ' +
          'a property of the specification rather than of this tool.' },
  { method: DELIVERY_POLL, short: 'poll', label: 'Poll (RFC 8936)',
    needsEndpoint: false,
    browserCanReceive: true,
    what: 'This receiver POSTs to the transmitter and is handed whatever has ' +
          'queued up, acknowledging what it stored. Nothing has to be ' +
          'reachable but the transmitter, which is why a browser can be a ' +
          'receiver over this method and not over the other one.' }
];

function deliveryUrn(value) {
  log.debug("Entering deliveryUrn(). " + value);
  var text = String(value || '').trim();
  var row = DELIVERY_METHODS.filter(function (one) {
    return one.method === text || one.short === text;
  })[0];
  log.debug("Leaving deliveryUrn(). " + (row ? row.method : '(unknown)'));
  return row ? row.method : text;
}

function deliveryLabel(value) {
  log.debug("Entering deliveryLabel().");
  var row = DELIVERY_METHODS.filter(function (one) {
    return one.method === value;
  })[0];
  log.debug("Leaving deliveryLabel().");
  return row ? row.label : String(value || '(none)');
}

// ---------------------------------------------------------------------------
// THE TRANSMITTER CONFIGURATION METADATA (SSF 1.0 section 6).
//
// Every member, what it is FOR, and whether SSF makes it required. The page
// draws this table beside the document it fetched, which is the whole point:
// a metadata document is a list of URLs and enumerations, and a reader cannot
// tell a missing OPTIONAL member from a missing REQUIRED one by looking.
//
// `endpoint` marks the members that are URLs this workflow will call, which is
// what `endpointFor()` below reads — so the page composes NO path and a
// transmitter that publishes its stream management API at
// `/v1/streams/manage` is driven with nothing typed.
// ---------------------------------------------------------------------------
var METADATA_MEMBERS = [
  { name: 'spec_version', required: false,
    what: 'Which version of SSF this transmitter implements. "1_0-final" is ' +
          'the September 2025 final specification; a draft value means the ' +
          'wire may differ from everything on this page.' },
  { name: 'issuer', required: true,
    what: 'THE `iss` OF EVERY SET THIS TRANSMITTER SIGNS. A receiver ' +
          'compares the two, so a token whose `iss` is not this string is ' +
          'not this transmitter\'s — which is the first check to make on ' +
          'anything that arrives.' },
  { name: 'jwks_uri', required: true,
    what: 'Where the keys are. Every SET is a JWS, so this is what a ' +
          'signature is verified against.' },
  { name: 'delivery_methods_supported', required: false,
    what: 'Which of the two methods it will agree to, as URNs. A ' +
          'transmitter that offers only poll cannot push, whatever a stream ' +
          'asks for.' },
  { name: 'configuration_endpoint', required: false, endpoint: true,
    what: 'The stream management API: one path, five methods. SSF fixes no ' +
          'path, so this is where it is and nothing composes one.' },
  { name: 'status_endpoint', required: false, endpoint: true,
    what: 'Read or set a stream\'s status.' },
  { name: 'add_subject_endpoint', required: false, endpoint: true,
    what: 'Name somebody a stream is about.' },
  { name: 'remove_subject_endpoint', required: false, endpoint: true,
    what: 'Stop naming them. Idempotent — removing a subject that is not ' +
          'there is a success.' },
  { name: 'verification_endpoint', required: false, endpoint: true,
    what: 'Ask for a verification event. THE ONLY END-TO-END TEST A STREAM ' +
          'HAS: everything else exercises the management API and proves ' +
          'nothing about whether an event can be delivered.' },
  { name: 'critical_subject_members', required: false,
    what: 'The members of a COMPLEX subject a receiver of this ' +
          'transmitter\'s events must understand. Naming one is a promise ' +
          'that every complex subject carries it.' },
  { name: 'default_subjects', required: false,
    what: 'WHAT AN EMPTY SUBJECT LIST MEANS, and the two answers are ' +
          'opposites. ALL: the stream is about everybody and adding a ' +
          'subject narrows nothing. NONE: it is about nobody until one is ' +
          'added. A receiver that guesses wrong gets every event in the ' +
          'estate or gets none, and both look like a broken transmitter.' },
  { name: 'authorization_schemes', required: false,
    what: 'How to authenticate to the endpoints above, as `spec_urn` values ' +
          '— so a receiver DISCOVERS the scheme rather than guessing. SSF ' +
          '1.0 section 8 requires those endpoints to be protected.' }
];

// The well-known path RFC 8414's registry carries for this document. It is
// `ssf-configuration` and it is a SIBLING of `openid-configuration` rather
// than a member of it.
var WELL_KNOWN_SUFFIX = '/.well-known/ssf-configuration';

// Where a transmitter's metadata lives, given its base URL. Both shapes are
// offered for the reason `metadata_client.js` offers both for an issuer:
// RFC 8414 INSERTS the well-known segment before the issuer's path and OpenID
// Connect Discovery APPENDS it, and a transmitter published under a path can
// be either. Insertion first, which is what RFC 8414 specifies.
function metadataCandidates(base) {
  log.debug("Entering metadataCandidates().");
  var text = String(base || '').trim().replace(/\/+$/, '');
  if (!text) {
    log.debug("Leaving metadataCandidates(). No base.");
    return [];
  }
  var out = [];
  var match = /^(https?:\/\/[^/]+)(\/.*)?$/i.exec(text);
  if (match) {
    var origin = match[1];
    var path = match[2] || '';
    // RFC 8414 section 3.1: the well-known segment goes between the host and
    // the issuer's path.
    out.push(origin + WELL_KNOWN_SUFFIX + path);
    if (path) {
      // And the OpenID Connect Discovery shape, appended.
      out.push(text + WELL_KNOWN_SUFFIX);
    }
  } else {
    out.push(text + WELL_KNOWN_SUFFIX);
  }
  log.debug("Leaving metadataCandidates(). " + out.length + " candidate(s).");
  return out;
}

// Read a fetched metadata document: what it says, what it is missing, and what
// this workflow can therefore do with it. Nothing is thrown — a transmitter's
// document is somebody else's and the page has to be able to SHOW a bad one.
function readMetadata(document) {
  log.debug("Entering readMetadata().");
  var doc = (document && typeof document === 'object') ? document : {};
  var rows = METADATA_MEMBERS.map(function (member) {
    var present = Object.prototype.hasOwnProperty.call(doc, member.name);
    return {
      name: member.name,
      what: member.what,
      required: !!member.required,
      endpoint: !!member.endpoint,
      present: present,
      value: present ? doc[member.name] : null
    };
  });
  var missing = rows.filter(function (row) {
    return row.required && !row.present;
  }).map(function (row) {
    return row.name;
  });
  var unknown = Object.keys(doc).filter(function (name) {
    return !METADATA_MEMBERS.some(function (member) {
      return member.name === name;
    });
  });
  var methods = Object.prototype.toString.call(
    doc.delivery_methods_supported) === '[object Array]'
    ? doc.delivery_methods_supported.map(deliveryUrn)
    : [];
  var out = {
    rows: rows,
    missing: missing,
    // NOT an error. SSF's metadata is extensible and a member this workflow
    // does not know is a transmitter doing something extra, not something
    // wrong — so it is REPORTED rather than refused, which is the same rule
    // ssf_events.js applies to an unrecognised event payload member.
    unknown: unknown,
    issuer: String(doc.issuer || ''),
    jwksUri: String(doc.jwks_uri || ''),
    deliveryMethods: methods,
    canPush: methods.indexOf(DELIVERY_PUSH) >= 0,
    canPoll: methods.indexOf(DELIVERY_POLL) >= 0,
    defaultSubjects: String(doc.default_subjects || '').toUpperCase(),
    criticalSubjectMembers: Object.prototype.toString.call(
      doc.critical_subject_members) === '[object Array]'
      ? doc.critical_subject_members.map(String) : [],
    authorizationSchemes: Object.prototype.toString.call(
      doc.authorization_schemes) === '[object Array]'
      ? doc.authorization_schemes : []
  };
  out.ok = missing.length === 0;
  log.debug("Leaving readMetadata(). " + missing.length + " missing.");
  return out;
}

// The URL for one operation, taken from the metadata and NEVER composed. A
// transmitter that publishes its stream management API at /v1/streams/manage
// is driven with nothing typed; a member the document does not carry produces
// a sentence naming it rather than a request to a path this workflow invented.
function endpointFor(metadata, member) {
  log.debug("Entering endpointFor(). " + member);
  var doc = (metadata && typeof metadata === 'object') ? metadata : {};
  var url = String(doc[member] || '').trim();
  if (!url) {
    log.debug("Leaving endpointFor(). Not published.");
    return { ok: false, url: '',
      error: 'This transmitter publishes no "' + member + '" in its ' +
        'configuration metadata, so there is nowhere to send this. SSF fixes ' +
        'no paths — every endpoint is discovered — so this workflow will not ' +
        'guess one.' };
  }
  log.debug("Leaving endpointFor(). " + url);
  return { ok: true, url: url, error: '' };
}

// ---------------------------------------------------------------------------
// THE STREAM CONFIGURATION (SSF 1.0 section 7.1.1).
//
// `owner` is the half readers get wrong, and it is why this table exists: some
// members are the RECEIVER's to set and some are the TRANSMITTER's to answer
// with, and a page that let somebody type a `stream_id` or an `iss` would be
// offering a control with no effect.
//
// **`events_requested` AND `events_delivered` ARE THE PAIR TO READ TWICE.**
// The first is the ask and the second is the answer — the intersection of the
// ask with what the transmitter supports — and a receiver that reads the first
// back as the second believes it will get event types nothing will ever send.
// ---------------------------------------------------------------------------
var STREAM_MEMBERS = [
  { name: 'stream_id', owner: 'transmitter',
    what: 'The stream\'s identifier, minted by the transmitter. A receiver ' +
          'that could choose one could overwrite somebody else\'s stream.' },
  { name: 'iss', owner: 'transmitter',
    what: 'The `iss` every SET on this stream will carry. The transmitter\'s ' +
          'own, and it matches its metadata.' },
  { name: 'aud', owner: 'receiver',
    what: 'Who the SETs are addressed to. A string or an array, and a ' +
          'receiver checks for ITSELF in it — an event whose `aud` is ' +
          'somebody else is one to refuse with invalid_audience.' },
  { name: 'events_supported', owner: 'transmitter',
    what: 'Everything this transmitter can send, whatever this stream asked ' +
          'for.' },
  { name: 'events_requested', owner: 'receiver',
    what: 'What this receiver ASKED for. An empty list asks for everything ' +
          'supported.' },
  { name: 'events_delivered', owner: 'transmitter',
    what: 'WHAT WILL ACTUALLY BE SENT: the intersection of the two above. ' +
          'Compare it with events_requested — a type in one and not the ' +
          'other is a type this transmitter would not agree to, and its ' +
          'absence is the only notice you get.' },
  { name: 'delivery', owner: 'receiver',
    what: 'The method, and for push the endpoint_url and an optional ' +
          'authorization_header the transmitter will send with each POST. ' +
          'The method values are the RFC numbers as URNs.' },
  { name: 'min_verification_interval', owner: 'transmitter',
    what: 'How often this transmitter is willing to be asked for a ' +
          'verification event. The TRANSMITTER\'s statement, which is why ' +
          'asking for something smaller is refused rather than ignored.' },
  { name: 'format', owner: 'receiver',
    what: 'Which RFC 9493 format the transmitter should name a DEFAULT ' +
          'subject in — the subjects it includes because the stream covers ' +
          'everybody rather than because somebody was added.' },
  { name: 'description', owner: 'receiver',
    what: 'Free text. Nothing reads it.' }
];

// Build the body of a stream create or update from what the page holds.
// Members the transmitter owns are dropped rather than sent: a request
// carrying a `stream_id` on a create is a receiver asking for something no
// transmitter will honour, and sending it would make the refusal harder to
// read than the omission.
function buildStreamConfiguration(values) {
  log.debug("Entering buildStreamConfiguration().");
  var asked = values || {};
  var body = {};
  if (asked.aud !== undefined && asked.aud !== '') {
    body.aud = asked.aud;
  }
  if (Object.prototype.toString.call(asked.events_requested) ===
      '[object Array]') {
    body.events_requested = asked.events_requested.slice();
  }
  var method = deliveryUrn(asked.deliveryMethod || '');
  if (method) {
    body.delivery = { method: method };
    if (method === DELIVERY_PUSH) {
      body.delivery.endpoint_url = String(asked.endpointUrl || '');
      if (asked.authorizationHeader) {
        body.delivery.authorization_header =
          String(asked.authorizationHeader);
      }
    }
  }
  if (asked.format) {
    body.format = String(asked.format);
  }
  if (asked.description !== undefined && asked.description !== '') {
    body.description = String(asked.description);
  }
  if (asked.stream_id) {
    // NOT part of the Stream Configuration and not sent as one. It is how the
    // update, delete, status, subject and poll requests NAME the stream, and
    // those carry it in their own body — which is why it is set here only
    // when the caller asked for it.
    body.stream_id = String(asked.stream_id);
  }
  log.debug("Leaving buildStreamConfiguration().");
  return body;
}

// What is wrong with a configuration this page is about to send, as sentences.
// Checked HERE rather than only at the transmitter because two of the three
// produce refusals a reader cannot act on: "invalid_request" on a delivery
// method says nothing about the URN, and an empty `aud` produces events
// addressed to nobody that a receiver then refuses one at a time.
function checkStreamConfiguration(body, metadata) {
  log.debug("Entering checkStreamConfiguration().");
  var errors = [];
  var warnings = [];
  var doc = readMetadata(metadata);
  var config = body || {};
  if (!config.aud) {
    errors.push('"aud" is required. It is who the SETs on this stream are ' +
        'addressed to, and a receiver checks for itself in it.');
  }
  if (config.delivery) {
    var method = config.delivery.method;
    if (DELIVERY_METHODS.every(function (one) {
      return one.method !== method;
    })) {
      errors.push('"delivery.method" is "' + String(method) + '". SSF ' +
          'defines two and both are RFC NUMBERS AS URNS: ' + DELIVERY_PUSH +
          ' for push and ' + DELIVERY_POLL + ' for poll. "push" and "poll" ' +
          'are not method identifiers, which catches everybody once.');
    } else if (doc.deliveryMethods.length &&
               doc.deliveryMethods.indexOf(method) < 0) {
      errors.push('This transmitter publishes ' +
          doc.deliveryMethods.join(' and ') + ' in ' +
          'delivery_methods_supported and this stream asks for ' + method +
          '. It will refuse.');
    }
    if (method === DELIVERY_PUSH && !config.delivery.endpoint_url) {
      errors.push('Push delivery needs a "delivery.endpoint_url" — it is ' +
          'where the transmitter POSTs each event. A browser cannot be an ' +
          'HTTP server, so this workflow asks its api layer for one.');
    }
    if (method === DELIVERY_POLL && config.delivery.endpoint_url) {
      warnings.push('A poll stream carries no receiver-side endpoint: RFC ' +
          '8936\'s poll endpoint is the TRANSMITTER\'s, and it publishes ' +
          'one in the stream configuration it hands back. What is set here ' +
          'is a URL nothing will call.');
    }
  }
  if (config.format &&
      SUBJECT_FORMAT_NAMES.indexOf(String(config.format)) < 0) {
    errors.push('"format" is "' + config.format + '", which is not one of ' +
        'RFC 9493\'s eight Subject Identifier formats: ' +
        SUBJECT_FORMAT_NAMES.join(', ') + '.');
  }
  log.debug("Leaving checkStreamConfiguration(). " + errors.length +
      " problem(s).");
  return { ok: errors.length === 0, errors: errors, warnings: warnings };
}

// What a transmitter answered, read back. `surprises` is the half worth
// drawing: a member the receiver asked for and did not get.
function readStreamConfiguration(answer, asked) {
  log.debug("Entering readStreamConfiguration().");
  var doc = (answer && typeof answer === 'object') ? answer : {};
  var wanted = (asked && typeof asked === 'object') ? asked : {};
  var requested = Object.prototype.toString.call(wanted.events_requested) ===
    '[object Array]' ? wanted.events_requested : [];
  var delivered = Object.prototype.toString.call(doc.events_delivered) ===
    '[object Array]' ? doc.events_delivered : [];
  var surprises = [];
  requested.forEach(function (uri) {
    if (delivered.indexOf(uri) < 0) {
      surprises.push('This stream asked for "' + uri + '" and the ' +
          'transmitter did not agree to it: it is absent from ' +
          'events_delivered. THAT ABSENCE IS THE ONLY NOTICE — SSF has no ' +
          'refusal for an unsupported event type, so a receiver that does ' +
          'not compare the two lists waits for events nothing will send.');
    }
  });
  if (wanted.delivery && doc.delivery &&
      wanted.delivery.method !== doc.delivery.method) {
    surprises.push('This stream asked for ' +
        deliveryLabel(wanted.delivery.method) + ' delivery and the ' +
        'transmitter answered with ' + deliveryLabel(doc.delivery.method) +
        '.');
  }
  var out = {
    streamId: String(doc.stream_id || ''),
    issuer: String(doc.iss || ''),
    audience: doc.aud,
    eventsSupported: Object.prototype.toString.call(doc.events_supported) ===
      '[object Array]' ? doc.events_supported : [],
    eventsRequested: Object.prototype.toString.call(doc.events_requested) ===
      '[object Array]' ? doc.events_requested : [],
    eventsDelivered: delivered,
    delivery: doc.delivery || null,
    minVerificationInterval: Number(doc.min_verification_interval || 0),
    format: String(doc.format || ''),
    description: String(doc.description || ''),
    surprises: surprises,
    raw: doc
  };
  log.debug("Leaving readStreamConfiguration(). " + out.streamId);
  return out;
}

// The three statuses of SSF 1.0 section 7.1.2, with the sentence that
// separates the middle one — which is the whole reason a receiver has a pause.
var STREAM_STATUSES = [
  { status: 'enabled', what: 'Events are delivered.' },
  { status: 'paused', what: 'The transmitter KEEPS QUEUEING and delivers ' +
      'nothing, so what happened while the stream was paused is still there ' +
      'when it is enabled again.' },
  { status: 'disabled', what: 'What is queued is DROPPED. That is the ' +
      'difference between "I was not listening" and "it did not happen", ' +
      'and it is why a receiver taking a maintenance window pauses rather ' +
      'than disables.' }
];

var STREAM_STATUS_NAMES = STREAM_STATUSES.map(function (row) {
  return row.status;
});

// ---------------------------------------------------------------------------
// RFC 8936 POLL DELIVERY.
//
// `ack` names what this receiver has STORED and `setErrs` what it REFUSED, and
// both take an event off the transmitter's queue. The second one catches
// people out and is worth the sentence: a receiver that could not process an
// event will not process it next time either, so a transmitter that
// redelivered would poll-loop forever.
// ---------------------------------------------------------------------------
function buildPollRequest(options) {
  log.debug("Entering buildPollRequest().");
  var asked = options || {};
  var body = {
    // Not an RFC 8936 member. A real poll endpoint is per stream; a
    // transmitter that publishes ONE URL for every stream needs to be told
    // which, and the mock STS this workflow is written against takes it in
    // the body. It is included only when the caller has one, so a transmitter
    // with a per-stream endpoint sees an ordinary RFC 8936 request.
    maxEvents: Number(asked.maxEvents) > 0 ? Number(asked.maxEvents) : 10,
    returnImmediately: asked.returnImmediately !== false
  };
  if (asked.streamId) {
    body.stream_id = String(asked.streamId);
  }
  var acks = Object.prototype.toString.call(asked.ack) === '[object Array]'
    ? asked.ack.map(String).filter(Boolean) : [];
  if (acks.length) {
    body.ack = acks;
  }
  if (asked.setErrs && typeof asked.setErrs === 'object' &&
      Object.keys(asked.setErrs).length) {
    body.setErrs = asked.setErrs;
  }
  log.debug("Leaving buildPollRequest(). maxEvents=" + body.maxEvents);
  return body;
}

// What came back. `moreAvailable` is the member a client most often ignores,
// and ignoring it means one poll is assumed to drain the queue — so it is
// lifted out and the page draws it.
function readPollResponse(answer) {
  log.debug("Entering readPollResponse().");
  var doc = (answer && typeof answer === 'object') ? answer : {};
  var sets = (doc.sets && typeof doc.sets === 'object') ? doc.sets : {};
  var out = {
    jtis: Object.keys(sets),
    sets: sets,
    moreAvailable: doc.moreAvailable === true,
    problems: []
  };
  if (!doc.sets) {
    out.problems.push('This answer carries no "sets" member. RFC 8936 ' +
        'section 2.2 makes it the whole of the response body — an empty ' +
        'poll is `{"sets": {}}` rather than an empty document.');
  }
  log.debug("Leaving readPollResponse(). " + out.jtis.length + " set(s).");
  return out;
}

// ---------------------------------------------------------------------------
// RFC 8935 PUSH DELIVERY, from THIS side — the debugger acting as the
// TRANSMITTER, which is the half that makes the workflow symmetric.
//
// The media type is the thing to get right and the thing that is silently
// wrong everywhere: RFC 8417 section 2.3 gives a SET
// `application/secevent+jwt`, and a receiver that dispatches on the type — and
// several do — drops one sent as `application/jwt` with no error anybody sees.
// ---------------------------------------------------------------------------
var SET_MEDIA_TYPE = 'application/secevent+jwt';

function buildPushRequest(token, options) {
  log.debug("Entering buildPushRequest().");
  var asked = options || {};
  var headers = {
    'Content-Type': asked.mediaType || SET_MEDIA_TYPE,
    Accept: 'application/json'
  };
  if (asked.authorizationHeader) {
    headers.Authorization = String(asked.authorizationHeader);
  }
  log.debug("Leaving buildPushRequest().");
  return { method: 'POST', headers: headers, body: String(token || '') };
}

// What a receiver said about a push. Three outcomes rather than two, and the
// third is what a transmitter most needs: a 400 with `{err, description}` is
// the receiver REFUSING, which is a completely different fact from a network
// failure and the most interesting thing a receiver ever says.
function readPushResponse(status, body) {
  log.debug("Entering readPushResponse(). status=" + status);
  var doc = null;
  if (body && typeof body === 'object') {
    doc = body;
  } else if (typeof body === 'string' && body.trim()) {
    try {
      doc = JSON.parse(body);
    } catch (e) {
      // Not JSON. Almost always something in FRONT of the receiver — a load
      // balancer, a WAF — and the raw text is then the diagnosis.
      doc = null;
    }
  }
  var out = {
    status: Number(status) || 0,
    accepted: status === 202 || status === 200 || status === 204,
    refused: false,
    err: '',
    description: '',
    note: ''
  };
  if (out.accepted && status !== 202) {
    out.note = 'This receiver answered ' + status + ' rather than the 202 ' +
        'RFC 8935 section 2.3 specifies. The event was accepted; a stricter ' +
        'transmitter might not have treated it as delivered.';
  }
  if (!out.accepted && doc && doc.err) {
    out.refused = true;
    out.err = String(doc.err);
    out.description = String(doc.description || '');
    out.note = 'The receiver REFUSED this event, which is a different thing ' +
        'from a network failure: it read the SET and would not take it.';
  }
  log.debug("Leaving readPushResponse(). accepted=" + out.accepted);
  return out;
}

// ---------------------------------------------------------------------------
// THE SECURITY EVENT TOKEN (RFC 8417).
//
// `buildSetClaims()` returns the CLAIM SET, unsigned, because two callers want
// it that way for different reasons: the page shows what it is about to send,
// and `signSet()` signs it. A builder that only returned a signed token would
// make "show me what you are going to send" impossible without signing
// something nobody asked for.
//
// **THERE IS NO `exp` AND THERE MUST NOT BE.** RFC 8417 section 4.1.4 says a
// SET MUST NOT be considered to expire: it records that something HAPPENED,
// and a fact does not stop being true. An implementation that adds one is
// asking receivers to discard history.
//
// **`toe` IS NOT `iat`.** The Time Of Event is when the thing happened; `iat`
// is when the token was minted. A token issued now may report something from
// an hour ago, and a receiver deciding whether to end a session cares about
// the first.
// ---------------------------------------------------------------------------
function buildSetClaims(options) {
  log.debug("Entering buildSetClaims().");
  var asked = options || {};
  var events = {};
  events[String(asked.uri || '')] = asked.payload || {};
  var claims = {
    iss: String(asked.issuer || ''),
    jti: String(asked.jti || newJti()),
    iat: Number(asked.iat) > 0 ? Number(asked.iat)
      : Math.floor(Date.now() / 1000),
    aud: asked.audience,
    events: events
  };
  if (asked.subject) {
    claims.sub_id = asked.subject;
  }
  if (asked.txn) {
    claims.txn = String(asked.txn);
  }
  if (Number(asked.toe) > 0) {
    claims.toe = Number(asked.toe);
  }
  log.debug("Leaving buildSetClaims(). jti=" + claims.jti);
  return claims;
}

// A jti. `crypto.getRandomValues` where there is one and `Math.random` where
// there is not, which is the node test's case — a jti is a DEDUPLICATION key
// rather than a secret, so the fallback costs nothing that matters and having
// one is what lets this module load outside a browser.
function newJti() {
  log.debug("Entering newJti().");
  var bytes = new Uint8Array(16);
  var i;
  if (typeof crypto !== 'undefined' && crypto && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
  } else {
    for (i = 0; i < bytes.length; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
  var out = '';
  for (i = 0; i < bytes.length; i++) {
    out += ('0' + bytes[i].toString(16)).slice(-2);
  }
  log.debug("Leaving newJti().");
  return out;
}

// The protected header of a SET. `typ` is `secevent+jwt` and it is a SHOULD in
// RFC 8417 section 2.2 that behaves like a MUST in practice: a receiver that
// dispatches on it drops a token without one on the floor with no error
// anybody sees.
//
// **`alg` IS THE JOSE VALUE AND NOT THE SELECTION.** `jws.js` identifies an
// algorithm by a SELECTION id, and two of those are not `alg` values at all:
// RFC 8037 registers one `alg` — `EdDSA` — for both Edwards curves and puts
// the curve in the KEY, so that module offers `EdDSA-Ed25519` and
// `EdDSA-Ed448` to choose between them. A header carrying the selection would
// name an algorithm the JOSE registry does not have, and no verifier on earth
// would accept it. So the spec is resolved and `spec.alg` is what goes on the
// wire; a selection this build does not know falls back to the string given,
// which is what makes a caller's typo visible as a refusal rather than as a
// silently different algorithm.
function setHeader(alg, options) {
  log.debug("Entering setHeader().");
  var asked = options || {};
  var wire = String(alg);
  try {
    wire = jws.algSpec(alg).alg;
  } catch (e) {
    // Not a selection this build knows. The caller's string is used as it
    // stands so the refusal comes from the signer, naming the algorithm.
    log.debug("setHeader(): " + alg + " is not in the table.");
  }
  var header = { alg: wire, typ: asked.typ || 'secevent+jwt' };
  if (asked.kid) {
    header.kid = String(asked.kid);
  }
  log.debug("Leaving setHeader(). " + header.alg);
  return header;
}

// Sign a SET. Every algorithm `jws.js` knows, which is every registered one
// plus the post-quantum and composite families — see the header. It is a
// promise because several of those are.
//
// **THE HEADER IS BUILT HERE AND HANDED OVER VERBATIM**, rather than left to
// `jws.js` to assemble from a `typ`. A JWS is the base64url of exactly those
// bytes, so the member ORDER is part of what is signed; building it in one
// place is what keeps a SET this workflow made and a SET it re-signs
// byte-identical, which is the property `tests/ssf_engine.js` asserts.
function signSet(claims, key, alg, options) {
  log.debug("Entering signSet(). alg=" + alg);
  var asked = options || {};
  log.debug("Leaving signSet(). Handed to jws.js.");
  return jws.signJwsAsync({
    algId: alg,
    payload: JSON.stringify(claims),
    privateKey: key,
    protectedHeader: setHeader(alg, asked),
    serialization: 'compact',
    backend: asked.backend
  }).then(function (result) {
    // `jws.js` answers with the whole assembly — the header, the signing
    // input, the backend it used — and `serialized` is the compact token.
    // Only the token is returned here, because a SET is a compact JWS and
    // nothing on this workflow ever wants the other serializations: handing
    // back the assembly would make every caller reach into it for the one
    // member, and the first caller to forget would push an object at a
    // receiver.
    log.debug("signSet(): assembled a compact SET.");
    return result.serialized;
  });
}

// Verify one. The algorithm is the CALLER's — `algId` — and never the token's,
// which is RFC 8725 section 3.1: a verifier that took the algorithm from the
// header would let the token choose both halves of its own check. The page
// takes it from the key it resolved, so a transmitter that changed algorithm
// is a mismatch REPORTED rather than accommodated.
function verifySet(token, key, alg, options) {
  log.debug("Entering verifySet(). alg=" + alg);
  var asked = options || {};
  log.debug("Leaving verifySet(). Handed to jws.js.");
  return jws.verifyJwsAsync({
    jws: token,
    publicKey: key,
    algId: alg,
    backend: asked.backend
  });
}

// ---------------------------------------------------------------------------
// READ A SET THAT ARRIVED, AND SAY WHAT IS WRONG WITH IT.
//
// This is where a debugger earns its place. A receiver's own code answers "did
// it verify"; what a person needs is every check BY NAME, because a single
// "valid: true" over a token whose `aud` is somebody else is the most
// dangerous thing this page could say.
//
// The findings are graded rather than pooled: `errors` are things RFC 8417 or
// SSF forbid, `warnings` are things that are legal and nearly always a
// mistake. `exp` is the one worth knowing: it is not illegal to put one on a
// JWT, and on a SET it means the transmitter is asking receivers to discard
// history.
// ---------------------------------------------------------------------------
function inspectSet(claims, options) {
  log.debug("Entering inspectSet().");
  var asked = options || {};
  var doc = (claims && typeof claims === 'object') ? claims : {};
  var errors = [];
  var warnings = [];
  var notes = [];

  ['iss', 'jti', 'iat', 'aud', 'events'].forEach(function (name) {
    if (doc[name] === undefined) {
      errors.push('No "' + name + '" claim. RFC 8417 section 2.2 makes it ' +
          'required on every Security Event Token.');
    }
  });
  if (doc.exp !== undefined) {
    errors.push('This SET carries an "exp". RFC 8417 section 4.1.4 says a ' +
        'SET MUST NOT be considered to expire: it records that something ' +
        'HAPPENED, and a fact does not stop being true. A transmitter that ' +
        'sets one is asking receivers to discard history.');
  }
  if (doc.sub !== undefined) {
    warnings.push('This SET carries a "sub" claim. RFC 8417 section 2.2 ' +
        'discourages it and SSF puts the subject in "sub_id" instead, ' +
        'because the thing an event is about may be a person AND a device ' +
        'AND a session at once and a string cannot say that. A client that ' +
        'reads "sub" will silently read nothing from a conforming ' +
        'transmitter.');
  }
  var types = (doc.events && typeof doc.events === 'object')
    ? Object.keys(doc.events) : [];
  if (doc.events !== undefined && !types.length) {
    errors.push('The "events" claim is empty. It is a MAP from event-type ' +
        'URI to that event\'s payload, which is why one token can carry a ' +
        'SET of events that happened together — an empty one says nothing ' +
        'happened.');
  }
  if (Object.prototype.toString.call(doc.events) === '[object Array]') {
    errors.push('The "events" claim is an ARRAY. RFC 8417 makes it an ' +
        'object keyed by event-type URI, which is what lets a receiver ' +
        'dispatch on a type without walking a list.');
  }
  if (asked.expectedIssuer && doc.iss &&
      String(doc.iss) !== String(asked.expectedIssuer)) {
    errors.push('The "iss" is "' + doc.iss + '" and this stream\'s ' +
        'transmitter is "' + asked.expectedIssuer + '". This token did not ' +
        'come from the transmitter this stream was agreed with.');
  }
  if (asked.expectedAudience && doc.aud !== undefined) {
    var audience = Object.prototype.toString.call(doc.aud) === '[object Array]'
      ? doc.aud.map(String) : [String(doc.aud)];
    if (audience.indexOf(String(asked.expectedAudience)) < 0) {
      errors.push('The "aud" is ' + audience.join(', ') + ' and this ' +
          'receiver is "' + asked.expectedAudience + '". A receiver checks ' +
          'for ITSELF in the audience, and an event addressed to somebody ' +
          'else is one to refuse with invalid_audience.');
    }
  }
  if (doc.sub_id !== undefined) {
    var verdict = validateSubjectId(doc.sub_id, {
      criticalMembers: asked.criticalMembers || [] });
    verdict.errors.forEach(function (message) {
      errors.push(message);
    });
    if (verdict.ok) {
      notes.push('Subject: ' + describeSubject(doc.sub_id));
    }
  }
  if (doc.toe !== undefined && doc.iat !== undefined &&
      Number(doc.toe) > Number(doc.iat)) {
    warnings.push('The "toe" (' + doc.toe + ') is LATER than the "iat" (' +
        doc.iat + '), so this token says the event happened after the token ' +
        'was minted. One of the two clocks is wrong.');
  }
  var out = {
    ok: errors.length === 0,
    errors: errors,
    warnings: warnings,
    notes: notes,
    types: types,
    jti: String(doc.jti || ''),
    issuer: String(doc.iss || ''),
    audience: doc.aud,
    issuedAt: Number(doc.iat || 0),
    timeOfEvent: Number(doc.toe || 0),
    transaction: String(doc.txn || ''),
    subject: doc.sub_id || null
  };
  log.debug("Leaving inspectSet(). " + errors.length + " error(s), " +
      warnings.length + " warning(s).");
  return out;
}

// Read the header of a SET and say what is wrong with IT — one function
// because the header's two problems are both silent. A missing `typ` is
// dropped by a receiver that dispatches on it; `alg: none` is an unsigned
// event, which for a document that says somebody's session was revoked is the
// worst thing on this page.
function inspectSetHeader(header) {
  log.debug("Entering inspectSetHeader().");
  var doc = (header && typeof header === 'object') ? header : {};
  var errors = [];
  var warnings = [];
  var alg = String(doc.alg || '');
  if (!alg) {
    errors.push('The protected header has no "alg".');
  }
  if (alg === 'none') {
    errors.push('This SET is UNSIGNED (alg: none). A Security Event Token ' +
        'says that somebody\'s session was revoked or their account ' +
        'disabled; an unsigned one says that anybody who can reach the ' +
        'endpoint can claim it.');
  }
  var typ = String(doc.typ || '');
  if (typ !== 'secevent+jwt') {
    warnings.push('The "typ" is ' + (typ ? '"' + typ + '"' : 'absent') +
        ' and RFC 8417 section 2.2 gives a SET "secevent+jwt". It is a ' +
        'SHOULD that behaves like a MUST: a receiver that dispatches on the ' +
        'type drops a token without it with no error anybody sees.');
  }
  log.debug("Leaving inspectSetHeader(). " + errors.length + " error(s).");
  return { ok: errors.length === 0, errors: errors, warnings: warnings,
    alg: alg, typ: typ, kid: String(doc.kid || '') };
}

// Split a compact JWS into its header and claims WITHOUT verifying anything.
// A page has to be able to show a token it cannot verify — that is most of
// them, since the key is somebody else's — so this never throws.
function parseSet(token) {
  log.debug("Entering parseSet().");
  var out = { ok: false, header: null, claims: null, signature: '',
    problem: '' };
  var parts = String(token || '').trim().split('.');
  if (parts.length !== 3) {
    out.problem = 'This is not a compact JWS: a Security Event Token has ' +
        'three dot-separated parts and this has ' + parts.length + '.';
    log.debug("Leaving parseSet(). Not three parts.");
    return out;
  }
  out.signature = parts[2];
  try {
    out.header = JSON.parse(fromBase64Url(parts[0]));
    out.claims = JSON.parse(fromBase64Url(parts[1]));
    out.ok = true;
  } catch (e) {
    // Undecodable. Reported rather than thrown: what arrived IS the answer.
    out.problem = 'The header or the payload would not decode as base64url ' +
        'JSON: ' + e.message;
  }
  log.debug("Leaving parseSet(). " + (out.problem || 'read'));
  return out;
}

// base64url to text, without depending on which runtime this is. `atob` in a
// browser and Buffer in node, so the node tests drive the same path the page
// does rather than a second one.
function fromBase64Url(text) {
  log.debug("Entering fromBase64Url().");
  var padded = String(text).replace(/-/g, '+').replace(/_/g, '/');
  while (padded.length % 4) {
    padded += '=';
  }
  if (typeof Buffer !== 'undefined' && Buffer.from) {
    log.debug("Leaving fromBase64Url(). node.");
    return Buffer.from(padded, 'base64').toString('utf8');
  }
  var binary = atob(padded);
  var bytes = new Uint8Array(binary.length);
  var i;
  for (i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  log.debug("Leaving fromBase64Url(). browser.");
  return new TextDecoder().decode(bytes);
}

module.exports = {
  // RFC 9493
  SUBJECT_FORMATS: SUBJECT_FORMATS,
  SUBJECT_FORMAT_NAMES: SUBJECT_FORMAT_NAMES,
  COMPLEX_SUBJECT_MEMBERS: COMPLEX_SUBJECT_MEMBERS,
  COMPLEX_SUBJECT_MEMBER_NAMES: COMPLEX_SUBJECT_MEMBER_NAMES,
  validateSubject: validateSubject,
  validateSubjectId: validateSubjectId,
  subjectKey: subjectKey,
  describeSubject: describeSubject,
  // Delivery
  DELIVERY_PUSH: DELIVERY_PUSH,
  DELIVERY_POLL: DELIVERY_POLL,
  DELIVERY_METHODS: DELIVERY_METHODS,
  deliveryUrn: deliveryUrn,
  deliveryLabel: deliveryLabel,
  // Discovery
  WELL_KNOWN_SUFFIX: WELL_KNOWN_SUFFIX,
  METADATA_MEMBERS: METADATA_MEMBERS,
  metadataCandidates: metadataCandidates,
  readMetadata: readMetadata,
  endpointFor: endpointFor,
  // Streams
  STREAM_MEMBERS: STREAM_MEMBERS,
  STREAM_STATUSES: STREAM_STATUSES,
  STREAM_STATUS_NAMES: STREAM_STATUS_NAMES,
  buildStreamConfiguration: buildStreamConfiguration,
  checkStreamConfiguration: checkStreamConfiguration,
  readStreamConfiguration: readStreamConfiguration,
  // Delivery, in both directions
  buildPollRequest: buildPollRequest,
  readPollResponse: readPollResponse,
  SET_MEDIA_TYPE: SET_MEDIA_TYPE,
  buildPushRequest: buildPushRequest,
  readPushResponse: readPushResponse,
  // RFC 8417
  buildSetClaims: buildSetClaims,
  newJti: newJti,
  setHeader: setHeader,
  signSet: signSet,
  verifySet: verifySet,
  parseSet: parseSet,
  inspectSet: inspectSet,
  inspectSetHeader: inspectSetHeader
};
