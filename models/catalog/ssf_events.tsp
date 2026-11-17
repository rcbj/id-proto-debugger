// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/catalog/ssf_events.tsp
//
// THE SHARED SIGNALS EVENT VOCABULARY: SSF 1.0's two event types about the
// PIPE, CAEP 1.0's eight about a SESSION and RISC 1.0's fourteen about an
// ACCOUNT, with each payload member and the shape it must have.
// client/src/ssf_events.js reads these rows from client/src/catalog/ and keeps
// only the code: the generator each row needs, checkMember(), validateEvent(),
// describeEvents() and the rest. ssf_client.js, which is the pipe, still names
// no event type anywhere; this file is the one place a type is named.
//
// THESE ROWS ARE THIS PROJECT'S READING OF THE THREE SPECIFICATIONS, written
// from the specifications and independently of iya-sts's. The URIs and member
// names are the wire and match by necessity; which members are required,
// which enumerations are closed and which a specification leaves open, and
// which subject formats an event insists on are a READING, and if both ends
// read one copy a misunderstanding they share is one neither can see.
// tests/caep_protocol.js and tests/risc_protocol.js drive the two readings
// against each other over the wire.
//
// Every const below is written to client/src/catalog/<name lower case>.json.
// The prefixes, the credential types and the common members are consts of
// their own so each is WRITTEN once: a prefix typed from memory and got
// subtly wrong produces an event a receiver silently ignores, because there
// is no "unknown event type" error in this protocol, and the same goes for a
// member name that drifts between eight copies.

namespace IdProtoDebugger.Catalog;

/** The three vocabularies this build implements. */
alias SsfEventFamily = "ssf" | "caep" | "risc";

/**
 * What a payload member's value must be. checkMember() in
 * client/src/ssf_events.js is what enforces each:
 *
 * - `string`, `number`: the JSON type. `event_timestamp` as the STRING
 *   "1757000000" parses everywhere and is compared numerically nowhere.
 * - `strings`: an ARRAY of strings (`amr`). A bare string is refused rather
 *   than wrapped, because wrapping would hide a sender that can only ever say
 *   one value.
 * - `object`: a JSON object and not an array (`claims`).
 * - `langmap`: an object keyed by a BCP 47 language tag (`reason_admin`,
 *   `reason_user`). A plain string is the commonest mistake in CAEP and has
 *   no symptom at the far end.
 */
alias ScalarMemberType = "string" | "number" | "strings" | "object" | "langmap";

/** One payload member whose value is free within its JSON type. */
model ScalarEventMember {
  /** The member's name in the payload, spelt exactly as on the wire. */
  name: string;

  /** Whether an event of this type is refused without it. */
  required: boolean;

  type: ScalarMemberType;

  /** What the member says, for the page and for a reader of this file. */
  what: string;
}

/**
 * One payload member whose value comes from a list. `enum` is CLOSED, so a
 * value outside `values` is refused. `openenum` is a list the specification
 * lets two parties extend (`credential_type`, `namespace`, `principal`,
 * `reason`), so a value outside it is CARRIED with a warning: refusing would
 * leave this workflow unable to build a vendor's own value, which is exactly
 * what a debugger is for.
 */
model EnumEventMember {
  name: string;
  required: boolean;
  type: "enum" | "openenum";
  values: string[];
  what: string;
}

/** A payload member: `values` exactly when its type is a list. */
union EventMember {
  ScalarEventMember,
  EnumEventMember,
}

/**
 * The RFC 9493 subject identifier formats an event may insist on. Only
 * RISC's two identifier events narrow it, and checkSubjectFormat() reports a
 * subject outside the list as a WARNING: such an event is deliverable and
 * merely wrong.
 */
alias SubjectFormat =
  | "account"
  | "email"
  | "iss_sub"
  | "opaque"
  | "phone_number"
  | "did"
  | "uri"
  | "aliases";

/**
 * One event type. The template arguments fix, per vocabulary, the family and
 * whether a subject is carried, so a row in the wrong table or with the wrong
 * subject rule is a compile error. Each row also has a `generate` function in
 * client/src/ssf_events.js, keyed by `uri`; that is code and is not here, and
 * the module refuses to load a row that has none.
 */
model SsfEventRow<
  Family extends SsfEventFamily,
  Subject extends "none" | "optional" | "required"
> {
  /** The event type, which is the KEY in a SET's `events` map. */
  uri: string;

  family: Family;

  /** The name the page draws. */
  name: string;

  /**
   * Whether the SET carries a subject. THE TWO SSF EVENTS ARE THE ONLY ONES
   * IN ANY OF THE THREE VOCABULARIES WITH NONE AT ALL, because they are about
   * the STREAM: a receiver that insisted on a subject could not be verified.
   */
  subject: Subject;

  /** The subject formats this event insists on, where it narrows them. */
  subjectFormats?: SubjectFormat[];

  /**
   * The event type that REPLACES this one, where its own specification
   * deprecates it. A URI rather than a boolean, so the warning can name the
   * replacement, and a field rather than a branch, so the next deprecation in
   * any of these vocabularies is data.
   */
  deprecated?: string;

  /** What the event says. */
  what: string;

  /** Who sends it and when. */
  howItIsAsked: string;

  /** The payload's own members, in the order the page draws them. */
  members: EventMember[];
}

/**
 * A vocabulary, so the page can say what is here and what is not rather than
 * leaving a reader to infer it from an empty list. `implemented: false` would
 * be drawn greyed with the sentence beside it.
 */
model SsfEventFamilyRow {
  id: SsfEventFamily;
  label: string;

  /** The URI prefix the family's event types share; familyOf() reads it. */
  prefix: string;

  implemented: boolean;
  what: string;
}

/**
 * One of the three things a reader arrives at the SSF page wanting: to
 * exercise the PIPE, or to send and receive SESSION or ACCOUNT events. The
 * page reconfigures itself around the answer, and what each means is a fact
 * about this catalogue rather than about the DOM.
 */
model SsfProfileRow {
  id: SsfEventFamily;
  family: SsfEventFamily;
  label: string;
  implemented: boolean;
  what: string;
}

/** The URI prefix of SSF's own two event types. */
const SSF_PREFIX: string =
  "https://schemas.openid.net/secevent/ssf/event-type/";

/** The URI prefix of CAEP's eight. */
const CAEP_PREFIX: string =
  "https://schemas.openid.net/secevent/caep/event-type/";

/** The URI prefix of RISC's fourteen. */
const RISC_PREFIX: string =
  "https://schemas.openid.net/secevent/risc/event-type/";

/**
 * THE CREDENTIAL TYPES, WRITTEN ONCE BECAUSE TWO SPECIFICATIONS SHARE THEM BY
 * REFERENCE RATHER THAN BY COINCIDENCE. CAEP 1.0 defines this list for
 * `credential-change`; RISC 1.0 section 2.7 says `credential-compromise`'s
 * `credential_type` "must be one of the values specified for the similarly
 * named field in the Credential Change event defined in the CAEP
 * Specification". So they are the SAME list, and a second copy would be one
 * that can drift out of a relationship the specification states outright.
 * OPEN in both places.
 */
const CAEP_CREDENTIAL_TYPES: string[] = #[
  "password",
  "pin",
  "x509",
  "fido2-platform",
  "fido2-roaming",
  "fido-u2f",
  "verifiable-credential",
  "phone-voice",
  "phone-sms",
  "app"
];

// THE FOUR CLAIMS CAEP SECTION 2 GIVES EVERY ONE OF ITS EVENTS, all optional,
// written once and listed at the end of each CAEP row's members: eight copies
// of four descriptions would be eight places for a spelling to drift, and
// there is no "unknown member" error in this protocol. `event_timestamp` IS
// NOT THE SET's `toe` AND IT IS NOT `iat`: `toe` is RFC 8417's claim on the
// TOKEN, and this is a member of the event PAYLOAD that CAEP defines.

const CAEP_MEMBER_EVENT_TIMESTAMP: EventMember = #{
  name: "event_timestamp",
  required: false,
  type: "number",
  what: "When the thing described actually happened, in seconds since the epoch. OPTIONAL in CAEP section 2, which surprises people — a receiver deciding whether to end a session wants it more than it wants anything else in the payload, and a conforming transmitter need not send one. A receiver that assumes it is there is one this page can catch, by leaving it out."
};

const CAEP_MEMBER_INITIATING_ENTITY: EventMember = #{
  name: "initiating_entity",
  required: false,
  type: "enum",
  values: #["admin", "user", "policy", "system"],
  what: "Who invoked it. It is the member that lets a receiver tell \"an administrator revoked this\" from \"a risk engine did\" — two facts that call for two different responses and are indistinguishable without it."
};

const CAEP_MEMBER_REASON_ADMIN: EventMember = #{
  name: "reason_admin",
  required: false,
  type: "langmap",
  what: "Why, for a log and for an auditor. IT IS AN OBJECT KEYED BY A LANGUAGE TAG — {\"en\": \"Policy 4.2 was violated\"} — and not a string. That is the commonest mistake in the whole profile and it has no symptom: a receiver indexing by language reads nothing from a string and reports no error."
};

const CAEP_MEMBER_REASON_USER: EventMember = #{
  name: "reason_user",
  required: false,
  type: "langmap",
  what: "The same, in words meant for the person it happened to. Two members rather than one because what an auditor needs to read and what may be shown on a screen are rarely the same sentence."
};

/** CAEP section 2's four common members, in the order each row lists them. */
const CAEP_COMMON_MEMBERS: EventMember[] = #[
  CAEP_MEMBER_EVENT_TIMESTAMP,
  CAEP_MEMBER_INITIATING_ENTITY,
  CAEP_MEMBER_REASON_ADMIN,
  CAEP_MEMBER_REASON_USER
];

// THE THREE CLAIMS RISC GIVES TO `credential-compromise` AND TO NOTHING ELSE.
// RISC gives three of CAEP's four (there is no `initiating_entity`) to one of
// its fourteen events, so CAEP's common members are NOT reused for RISC: that
// would attach members their specification does not define to thirteen rows,
// and nothing would fail. tests/risc_engine.js asserts the count and the
// absence.

const RISC_MEMBER_EVENT_TIMESTAMP: EventMember = #{
  name: "event_timestamp",
  required: false,
  type: "number",
  what: "When the transmitter DISCOVERED the compromise, in seconds since the epoch. RISC section 2.7 words it as discovery rather than as occurrence, and that is not pedantry: a credential found in a breach corpus was compromised long before anybody noticed, so a receiver reading this as \"when it happened\" dates the incident from the wrong end."
};

const RISC_MEMBER_REASON_ADMIN: EventMember = #{
  name: "reason_admin",
  required: false,
  type: "langmap",
  what: "Why, for an administrator. This build sends and expects the LANGUAGE-MAP shape CAEP defines — {\"en\": \"...\"} — and RISC 1.0 does not actually repeat that requirement, which makes a bare string arguably conforming to RISC and certainly unreadable to a receiver built against CAEP. The map is the reading that is right under both."
};

const RISC_MEMBER_REASON_USER: EventMember = #{
  name: "reason_user",
  required: false,
  type: "langmap",
  what: "The same, in words meant for the person it happened to."
};


/** The three RISC gives to `credential-compromise`. */
const RISC_COMMON_MEMBERS: EventMember[] = #[
  RISC_MEMBER_EVENT_TIMESTAMP,
  RISC_MEMBER_REASON_ADMIN,
  RISC_MEMBER_REASON_USER
];

// SSF 1.0'S OWN TWO EVENT TYPES, both about the pipe rather than about a
// person. VERIFICATION is the only end-to-end test a stream has: a 200 from
// the management API says the configuration was accepted and nothing about
// whether an event can reach the receiver. STREAM UPDATED tells the receiver
// IN BAND that the stream's status changed, and is the one event whose
// absence is hardest to notice.
const SSF_EVENTS: SsfEventRow<"ssf", "none">[] = #[
  #{
    uri: "${SSF_PREFIX}verification",
    family: "ssf",
    name: "Verification",
    subject: "none",
    what: "THE ONLY END-TO-END TEST A STREAM HAS. Creating the stream, reading it back and adding a subject all exercise the management API and prove nothing about whether an event can actually be delivered. This travels the ordinary delivery path, so a 202 from the push endpoint — or a poll that returns it — is the first evidence the pipe works.",
    howItIsAsked: "A receiver POSTs {stream_id, state} to the verification_endpoint. The transmitter answers 204 and sends the event SEPARATELY, over the stream. Those are two different exchanges and a receiver that expected the event in the response to its own request waits forever.",
    members: #[
      #{
        name: "state",
        required: false,
        type: "string",
        what: "Whatever the receiver put in its verification request, echoed back UNCHANGED. It is the only thing tying this event to the request that asked for it — without it, a receiver watching two streams cannot tell which one just answered."
      }
    ]
  },
  #{
    uri: "${SSF_PREFIX}stream-updated",
    family: "ssf",
    name: "Stream Updated",
    subject: "none",
    what: "The stream's status changed and the receiver is being told IN BAND. It is the one event a receiver gets without asking for it, and the one whose absence is hardest to notice: a stream quietly paused at the transmitter looks exactly like a service where nothing has happened lately.",
    howItIsAsked: "Nobody asks. A transmitter sends it when the status changes — including when the change was made by the receiver itself at the status endpoint, which is not redundant: the acknowledgement of a request and an event on the stream are two different assurances, and only the second one says the delivery path is working.",
    members: #[
      #{
        name: "status",
        required: true,
        type: "enum",
        values: #["enabled", "paused", "disabled"],
        what: "The stream's new status. PAUSED keeps queueing and delivers nothing; DISABLED drops what is waiting. That is the difference between \"I was not listening\" and \"it did not happen\"."
      },
      #{
        name: "reason",
        required: false,
        type: "string",
        what: "Why, in words, for a person reading a log. Nothing parses it."
      }
    ]
  }
];

// CAEP 1.0 (final 2 September 2025): THE SESSION VOCABULARY. The sentence each
// carries is "this session is no longer trustworthy". EVERY ONE IS
// `subject: "required"`, and the subject a conforming transmitter sends is
// normally SSF's COMPLEX one: the person is not revoked, one session of theirs
// is, and a subject naming only the person asks a receiver to end every
// session that person has.
const CAEP_EVENTS: SsfEventRow<"caep", "required">[] = #[
  #{
    uri: "${CAEP_PREFIX}session-revoked",
    family: "caep",
    name: "Session Revoked",
    subject: "required",
    what: "THE EVENT THE WHOLE PROFILE EXISTS FOR. The session named by the subject is no longer good, whatever its token says its lifetime is. It carries NO event-specific member at all, and that is not an oversight: everything it has to say is in the subject and in the four common claims, and there is nothing to qualify.",
    howItIsAsked: "Nobody asks. A transmitter sends it when a session ends — an administrator signing somebody out, a policy engine, the person themselves. Where the subject is a COMPLEX one the revocation applies to any session matching every part of it at once, which is how \"that person, on that device\" is said.",
    members: #[
      CAEP_MEMBER_EVENT_TIMESTAMP,
      CAEP_MEMBER_INITIATING_ENTITY,
      CAEP_MEMBER_REASON_ADMIN,
      CAEP_MEMBER_REASON_USER
    ]
  },
  #{
    uri: "${CAEP_PREFIX}session-established",
    family: "caep",
    name: "Session Established",
    subject: "required",
    what: "A session was created. It is what CLOSES THE LOOP: without it a receiver only ever hears about sessions ENDING, so it can never hold an inventory of what is open and cannot notice a sign-in it did not expect.",
    howItIsAsked: "Nobody asks. A transmitter sends it at the moment somebody signs in.",
    members: #[
      #{
        name: "fp_ua",
        required: false,
        type: "string",
        what: "A fingerprint of the user agent, computed by the transmitter. Its whole value is comparing two of them, so what it is made of is the transmitter's business and no receiver should parse one."
      },
      #{
        name: "acr",
        required: false,
        type: "string",
        what: "The authentication context class, with OpenID Connect's own meaning."
      },
      #{
        name: "amr",
        required: false,
        type: "strings",
        what: "The authentication methods, as an ARRAY — OpenID Connect's `amr`. A bare string is refused here rather than wrapped: a session authenticated by a password AND a security key has two values, and wrapping would hide a sender that can only ever say one."
      },
      #{
        name: "ext_id",
        required: false,
        type: "string",
        what: "The transmitter's own identifier for this session, for a receiver correlating with something it already holds."
      },
      CAEP_MEMBER_EVENT_TIMESTAMP,
      CAEP_MEMBER_INITIATING_ENTITY,
      CAEP_MEMBER_REASON_ADMIN,
      CAEP_MEMBER_REASON_USER
    ]
  },
  #{
    uri: "${CAEP_PREFIX}session-presented",
    family: "caep",
    name: "Session Presented",
    subject: "required",
    what: "The session was USED — presented at the transmitter and honoured. It is the one CAEP event about something entirely ordinary, and it is there so a receiver can see a live session it is not itself being asked about, and can spot the same session in two places at once.",
    howItIsAsked: "Nobody asks. A transmitter sends it when an existing session answers a request — which is single sign-on. A transmitter that sent one for the sign-in's own return trip would emit it milliseconds after session-established every time, and the event would stop meaning anything.",
    members: #[
      #{
        name: "fp_ua",
        required: false,
        type: "string",
        what: "The user agent fingerprint observed THIS time. Comparing it with the one on the session-established event is the whole point of the member: the same session presented from a different agent is the abnormality this event exists to make visible."
      },
      #{
        name: "ext_id",
        required: false,
        type: "string",
        what: "The transmitter's own identifier for the session."
      },
      CAEP_MEMBER_EVENT_TIMESTAMP,
      CAEP_MEMBER_INITIATING_ENTITY,
      CAEP_MEMBER_REASON_ADMIN,
      CAEP_MEMBER_REASON_USER
    ]
  },
  #{
    uri: "${CAEP_PREFIX}token-claims-change",
    family: "caep",
    name: "Token Claims Change",
    subject: "required",
    what: "A claim behind the token changed while the token is still valid — a role, a group, a tenant. It is the event that makes the access-token-lifetime argument go away: a receiver does not have to wait for a refresh to find out that somebody left the group that authorises them.",
    howItIsAsked: "Nobody asks. A transmitter sends it when the underlying claim moves — a directory write, a role assignment withdrawn.",
    members: #[
      #{
        name: "claims",
        required: true,
        type: "object",
        what: "The claims that changed, with their NEW values. It is not a whole token and it is not a diff: a receiver applies what is here over what it holds. So a group taken away is the new LIST rather than the group that went, which catches everybody once."
      },
      CAEP_MEMBER_EVENT_TIMESTAMP,
      CAEP_MEMBER_INITIATING_ENTITY,
      CAEP_MEMBER_REASON_ADMIN,
      CAEP_MEMBER_REASON_USER
    ]
  },
  #{
    uri: "${CAEP_PREFIX}credential-change",
    family: "caep",
    name: "Credential Change",
    subject: "required",
    what: "A credential was enrolled, renewed, revoked or deleted. It is the CAEP event a receiver acts on WITHOUT ending anything: a second factor being deleted does not invalidate the session it was used to establish, and it does change what that session should be allowed to do next.",
    howItIsAsked: "Nobody asks. A transmitter sends it from wherever credentials are managed — an enrolment page, an administrator revoking a key.",
    members: #[
      #{
        name: "credential_type",
        required: true,
        type: "openenum",
        values: CAEP_CREDENTIAL_TYPES,
        what: "Which kind. The list is CAEP's own and it is OPEN — the specification allows types two parties agree between themselves — so a value not on it is CARRIED with a warning rather than refused. Refusing would make this workflow unable to build a vendor's own type, which is exactly what a debugger is for."
      },
      #{
        name: "change_type",
        required: true,
        type: "enum",
        values: #["create", "revoke", "update", "delete"],
        what: "What happened to it. CLOSED, unlike the type above: these four are the whole lifecycle and a fifth would be a receiver guessing."
      },
      #{
        name: "friendly_name",
        required: false,
        type: "string",
        what: "What the person calls it — \"my work phone\". For a screen, not for a decision."
      },
      #{
        name: "x509_issuer",
        required: false,
        type: "string",
        what: "The certificate's issuer (RFC 5280), where the credential is an X.509 one."
      },
      #{
        name: "x509_serial",
        required: false,
        type: "string",
        what: "The certificate's serial number (RFC 5280). Serial numbers are unique per ISSUER and not globally, which is what makes this member useless without the one above it."
      },
      #{
        name: "fido2_aaguid",
        required: false,
        type: "string",
        what: "The authenticator's AAGUID, where the credential is a FIDO2 one. It names a MODEL of authenticator rather than the individual one, which is what makes it publishable at all."
      },
      CAEP_MEMBER_EVENT_TIMESTAMP,
      CAEP_MEMBER_INITIATING_ENTITY,
      CAEP_MEMBER_REASON_ADMIN,
      CAEP_MEMBER_REASON_USER
    ]
  },
  #{
    uri: "${CAEP_PREFIX}assurance-level-change",
    family: "caep",
    name: "Assurance Level Change",
    subject: "required",
    what: "The strength of the authentication behind this session moved. A DECREASE is the interesting one and it is easy to forget it can happen at all: a second factor that has expired, or a session carried past the window its step-up was good for, both lower assurance without anybody signing in again.",
    howItIsAsked: "Nobody asks. A transmitter sends it after a step-up, after a step-down, or when the window a factor was good for closes.",
    members: #[
      #{
        name: "namespace",
        required: true,
        type: "openenum",
        values: #[
          "RFC8176",
          "RFC6711",
          "ISO-IEC-29115",
          "NIST-IAL",
          "NIST-AAL",
          "NIST-FAL"
        ],
        what: "WHICH SCALE THE TWO LEVELS ARE ON, and it is required because the event is useless without it: \"aal2\" means nothing until you know it is NIST's. The list is open — two parties may agree an alias — so an unlisted namespace is carried with a warning."
      },
      #{
        name: "current_level",
        required: true,
        type: "string",
        what: "The level the session is at NOW, spelt the way the namespace above spells it. A free string precisely because the namespace decides its shape."
      },
      #{
        name: "previous_level",
        required: false,
        type: "string",
        what: "Where it was before. Optional and worth sending: without it a receiver can see that assurance changed and not whether it went UP."
      },
      #{
        name: "change_direction",
        required: false,
        type: "enum",
        values: #["increase", "decrease"],
        what: "Which way, said outright rather than inferred. It exists because a receiver cannot order two levels in a namespace it does not understand — which is the ordinary case across two organisations."
      },
      CAEP_MEMBER_EVENT_TIMESTAMP,
      CAEP_MEMBER_INITIATING_ENTITY,
      CAEP_MEMBER_REASON_ADMIN,
      CAEP_MEMBER_REASON_USER
    ]
  },
  #{
    uri: "${CAEP_PREFIX}device-compliance-change",
    family: "caep",
    name: "Device Compliance Change",
    subject: "required",
    what: "The device the session runs on fell out of, or back into, compliance with whatever the estate's policy is. The subject is normally a COMPLEX one naming the device as well as the person, because the same person on a second device is unaffected and a receiver cannot tell that from a subject naming only them.",
    howItIsAsked: "Nobody asks. A device management service tells the transmitter and the transmitter tells the receivers.",
    members: #[
      #{
        name: "previous_status",
        required: true,
        type: "enum",
        values: #["compliant", "not-compliant"],
        what: "What the device WAS. Required, and that is what makes this event safe to act on out of order: a receiver holding \"compliant\" that gets an event whose previous status is \"not-compliant\" knows it has missed one, and that gap is invisible from either event on its own."
      },
      #{
        name: "current_status",
        required: true,
        type: "enum",
        values: #["compliant", "not-compliant"],
        what: "What it is now. The hyphen in \"not-compliant\" is the specification's and is worth checking against — \"noncompliant\" is silently ignored by a conforming receiver."
      },
      CAEP_MEMBER_EVENT_TIMESTAMP,
      CAEP_MEMBER_INITIATING_ENTITY,
      CAEP_MEMBER_REASON_ADMIN,
      CAEP_MEMBER_REASON_USER
    ]
  },
  #{
    uri: "${CAEP_PREFIX}risk-level-change",
    family: "caep",
    name: "Risk Level Change",
    subject: "required",
    what: "A risk engine changed its mind about somebody. It is the only CAEP event that is a JUDGEMENT rather than a fact — the other seven report something that happened — which is why it carries a reason and why a receiver is expected to weigh it rather than act on it.",
    howItIsAsked: "Nobody asks. A risk engine tells the transmitter when a signal moves.",
    members: #[
      #{
        name: "principal",
        required: true,
        type: "openenum",
        values: #["USER", "DEVICE", "SESSION", "TENANT", "ORG_UNIT", "GROUP"],
        what: "WHAT the level is about, and it is required because the subject alone cannot say: a complex subject names a person AND a device AND a session, and \"risk went to HIGH\" about the device is a different fact from the same sentence about the person. THE VALUES ARE UPPER CASE HERE and lower case in a complex subject's member names, which catches everybody once."
      },
      #{
        name: "current_level",
        required: true,
        type: "enum",
        values: #["LOW", "MEDIUM", "HIGH"],
        what: "The level now. Three values, upper case, closed."
      },
      #{
        name: "previous_level",
        required: false,
        type: "enum",
        values: #["LOW", "MEDIUM", "HIGH"],
        what: "The level before, which is what lets a receiver notice a missed event."
      },
      #{
        name: "risk_reason",
        required: false,
        type: "string",
        what: "What contributed. RECOMMENDED rather than required, and it decides whether a receiver can do anything but step up: \"impossible travel\" and \"credential seen in a breach corpus\" call for different answers."
      },
      CAEP_MEMBER_EVENT_TIMESTAMP,
      CAEP_MEMBER_INITIATING_ENTITY,
      CAEP_MEMBER_REASON_ADMIN,
      CAEP_MEMBER_REASON_USER
    ]
  }
];

// RISC 1.0 (final 2 September 2025): THE ACCOUNT VOCABULARY, "this account is
// no longer trustworthy". Four things here surprise somebody who has just read
// the CAEP rows, and each is the specification rather than a choice made here:
//
// - ELEVEN OF THE FOURTEEN HAVE NO PAYLOAD MEMBERS AT ALL and only one has a
//   required one, so the SUBJECT carries the entire message.
// - The common claims are RISC_COMMON_MEMBERS, on `credential-compromise`
//   only.
// - `identifier-changed`'s `new-value` is THE ONLY HYPHENATED MEMBER NAME in
//   all three vocabularies; nearestMember() names the `new_value` near miss.
// - `sessions-revoked` (plural) is deprecated by section 2.11 in favour of
//   CAEP's `session-revoked` (singular). It is here, and sendable, because a
//   debugger that could not produce it could not find out what a receiver
//   does with one.
//
// The two identifier events say their subject MUST be an email address or a
// phone number carrying the OLD value, which is the reverse of every other
// event; `subjectFormats` says so.
const RISC_EVENTS: SsfEventRow<"risc", "required">[] = #[
  #{
    uri: "${RISC_PREFIX}account-credential-change-required",
    family: "risc",
    name: "Account Credential Change Required",
    subject: "required",
    what: "The account named by the subject was REQUIRED to change a credential — a forced password reset, most often. It is not a report that a credential changed: nothing here says one did, and the person may never comply. What a receiver learns is that this provider no longer trusts what it currently holds.",
    howItIsAsked: "Nobody asks. A transmitter sends it when it decides a credential has to be replaced — a breach, an expiry policy, an administrator.",
    members: #[]
  },
  #{
    uri: "${RISC_PREFIX}account-purged",
    family: "risc",
    name: "Account Purged",
    subject: "required",
    what: "The account was PERMANENTLY DELETED. It is the one terminal event in the vocabulary and the model treats it as one: nothing can be said about a purged account afterwards except by contradiction. The distinction from account-disabled is the whole of its meaning — a disabled account may come back and this one may not.",
    howItIsAsked: "Nobody asks. A transmitter sends it when the account is deleted at its end.",
    members: #[]
  },
  #{
    uri: "${RISC_PREFIX}account-disabled",
    family: "risc",
    name: "Account Disabled",
    subject: "required",
    what: "The account was disabled and MAY BE ENABLED AGAIN. It is the ordinary account-takeover signal, and the pair it forms with account-enabled is what makes it different from a purge.",
    howItIsAsked: "Nobody asks. A transmitter sends it when it locks the account — a risk engine, an abuse team, an administrator.",
    members: #[
      #{
        name: "reason",
        required: false,
        type: "openenum",
        values: #["hijacking", "bulk-account"],
        what: "Why, as one of two words RISC names — and what those two are FOR is worth knowing. \"hijacking\" says this ONE account was taken over, which is a signal about a person. \"bulk-account\" says it was one of a population created by a script, which is a signal about the PROVIDER and asks a receiver to look at everything else that arrived at the same time. The specification says \"possible values\" rather than closing the list, so a third word is carried with a warning."
      }
    ]
  },
  #{
    uri: "${RISC_PREFIX}account-enabled",
    family: "risc",
    name: "Account Enabled",
    subject: "required",
    what: "The account was enabled. It is RISC's only GOOD NEWS and it is the one everybody forgets to implement: a receiver that acts on account-disabled and ignores this one has locked somebody out permanently on the strength of an incident that was resolved.",
    howItIsAsked: "Nobody asks. A transmitter sends it when the lock comes off.",
    members: #[]
  },
  #{
    uri: "${RISC_PREFIX}identifier-changed",
    family: "risc",
    name: "Identifier Changed",
    subject: "required",
    subjectFormats: #["email", "phone_number"],
    what: "The identifier IN THE SUBJECT changed, and the subject carries the OLD value — which is the reverse of every other event in all three vocabularies and the thing that catches everybody. RISC says only the provider AUTHORITATIVE over the identifier should send this: an email provider may say john.doe@ became john.roe@, and a site where that address is merely a username may not — it sends recovery-information-changed instead.",
    howItIsAsked: "Nobody asks. The provider that owns the address or the number sends it when the person changes one.",
    members: #[
      #{
        name: "new-value",
        required: false,
        type: "string",
        what: "What the identifier became. **THE ONLY HYPHENATED MEMBER NAME IN ANY OF THE THREE VOCABULARIES** — everything else in SSF, CAEP and RISC is snake_case — so `new_value` typed from habit produces an event that delivers and says nothing. It is OPTIONAL, and a transmitter that leaves it out tells a receiver that an address it holds is stale without telling it what to hold instead: legal, and nearly useless."
      }
    ]
  },
  #{
    uri: "${RISC_PREFIX}identifier-recycled",
    family: "risc",
    name: "Identifier Recycled",
    subject: "required",
    subjectFormats: #["email", "phone_number"],
    what: "The identifier in the subject was RECYCLED and now belongs to SOMEBODY ELSE. It is the event whose absence causes the quietest account takeover there is: a mail provider reissues a lapsed address, a relying party keyed on the address by itself lets the new owner into the old owner's account, and nothing anywhere was compromised. It is the whole argument for keying on an iss_sub pair rather than on an email address.",
    howItIsAsked: "Nobody asks. The provider that owns the address sends it when it hands one to a new person.",
    members: #[]
  },
  #{
    uri: "${RISC_PREFIX}credential-compromise",
    family: "risc",
    name: "Credential Compromise",
    subject: "required",
    what: "A credential belonging to this account was FOUND compromised — seen in a breach corpus, or reported. THE ONLY ONE OF THE FOURTEEN WITH A REQUIRED MEMBER, and the only one carrying any of the claims CAEP gives to all eight of its own. A receiver acts on it differently by type: a compromised password is a reset, and a compromised hardware key is a revocation.",
    howItIsAsked: "Nobody asks. A transmitter sends it when its own monitoring finds the credential somewhere it should not be.",
    members: #[
      #{
        name: "credential_type",
        required: true,
        type: "openenum",
        values: CAEP_CREDENTIAL_TYPES,
        what: "Which kind of credential was found compromised. **RISC SECTION 2.7 DEFINES THIS BY REFERENCE TO CAEP's credential-change**, so the two lists are the same list rather than two alike ones — which is why there is one CREDENTIAL_TYPES in this file and not a copy per vocabulary. It is OPEN in both places, so a vendor's own type is carried with a warning."
      },
      RISC_MEMBER_EVENT_TIMESTAMP,
      RISC_MEMBER_REASON_ADMIN,
      RISC_MEMBER_REASON_USER
    ]
  },
  #{
    uri: "${RISC_PREFIX}opt-in",
    family: "risc",
    name: "Opt In",
    subject: "required",
    what: "The account is participating in RISC exchange again. It is one of the four events that ARE a state transition rather than a report of one — RISC section 2.8 defines each of them as \"the account is in the X state\" — and it is the only event that may be sent about an account which has opted OUT, because without it a receiver would never learn that one came back.",
    howItIsAsked: "Nobody asks. The person opted back in at the transmitter, and the transmitter says so.",
    members: #[]
  },
  #{
    uri: "${RISC_PREFIX}opt-out-initiated",
    family: "risc",
    name: "Opt Out Initiated",
    subject: "required",
    what: "The person asked to stop RISC exchange, AND IT CARRIES ON FOR A WHILE ANYWAY. That delay is the point of the state existing at all: RISC section 2.8 says it is there to stop a hijacker from opting out the moment they take an account over and silencing the very events that would report them.",
    howItIsAsked: "Nobody asks. The person asked at the transmitter.",
    members: #[]
  },
  #{
    uri: "${RISC_PREFIX}opt-out-cancelled",
    family: "risc",
    name: "Opt Out Cancelled",
    subject: "required",
    what: "The opt-out was called off and the account is back in the opt-in state. **THE SPELLING IS BRITISH AND IT IS THE SPECIFICATION'S** — \"cancelled\" with two Ls — so a transmitter writing \"opt-out-canceled\" produces a URI a conforming receiver silently ignores, because there is no unknown-event-type error in this protocol.",
    howItIsAsked: "Nobody asks. The person changed their mind before the opt-out took effect.",
    members: #[]
  },
  #{
    uri: "${RISC_PREFIX}opt-out-effective",
    family: "risc",
    name: "Opt Out Effective",
    subject: "required",
    what: "The opt-out has taken effect and no further RISC events will be sent about this account. IT IS THE LAST ONE — an event announcing that there will be no more events — which is what makes it the one an opt-out gate must never suppress. Suppressing it would leave a receiver waiting for signals that stopped without notice, which at the far end is indistinguishable from a transmitter that has gone down.",
    howItIsAsked: "Nobody asks. The transmitter's waiting period ended.",
    members: #[]
  },
  #{
    uri: "${RISC_PREFIX}recovery-activated",
    family: "risc",
    name: "Recovery Activated",
    subject: "required",
    what: "The account went through a recovery flow. It is a signal about RISK rather than about a change: a recovery is how a legitimate owner gets back in and it is also how an attacker who controls the recovery channel takes over, and the transmitter cannot tell which. A receiver is expected to weigh it, not act on it.",
    howItIsAsked: "Nobody asks. Somebody used the \"forgot my password\" door.",
    members: #[]
  },
  #{
    uri: "${RISC_PREFIX}recovery-information-changed",
    family: "risc",
    name: "Recovery Information Changed",
    subject: "required",
    what: "A recovery address or number was added, changed or removed. It is what a provider sends about an identifier IT IS NOT AUTHORITATIVE OVER — RISC says so where identifier-changed says the opposite — so the pair of them is the same act reported by two different kinds of provider. It carries no member saying WHICH information moved, deliberately: that would be publishing somebody's recovery address to every receiver on the stream.",
    howItIsAsked: "Nobody asks. The person edited their recovery settings.",
    members: #[]
  },
  // RISC 1.0 section 2.11 deprecates this in favour of CAEP's
  // `session-revoked`. The row carries WHAT REPLACES IT rather than a
  // boolean, so the warning can name it.
  #{
    uri: "${RISC_PREFIX}sessions-revoked",
    family: "risc",
    name: "Sessions Revoked",
    subject: "required",
    deprecated: "${CAEP_PREFIX}session-revoked",
    what: "EVERY session the account has, everywhere, is gone — which is a far larger instruction than CAEP's session-revoked, whose subject names ONE of them. **DEPRECATED by RISC 1.0 section 2.11**, which says new implementations MUST use CAEP's singular event instead. The two names differ by one letter and mean different things, so this is the pair to check when a receiver ends more sessions than anybody intended. It is here, and sendable, because a debugger that could not produce a deprecated event could not be used to find out what a receiver does with one.",
    howItIsAsked: "Nobody asks — and nobody should be sending it. Receivers in the field still do.",
    members: #[]
  }
];

/** The three vocabularies; familyOf() places an unknown type by `prefix`. */
const SSF_EVENT_FAMILIES: SsfEventFamilyRow[] = #[
  #{
    id: "ssf",
    label: "SSF — the framework itself",
    prefix: SSF_PREFIX,
    implemented: true,
    what: "Two event types, both about the PIPE rather than about a person: is this stream alive, and has its status changed."
  },
  #{
    id: "caep",
    label: "CAEP — Continuous Access Evaluation Profile",
    prefix: CAEP_PREFIX,
    implemented: true,
    what: "The enterprise SESSION vocabulary, in eight event types: session revoked, established and presented, token claims change, credential change, assurance level change, device compliance change and risk level change. It says \"this session is no longer trustworthy\", and every one of them names a SESSION rather than a person — which is what SSF's complex subject is for."
  },
  #{
    id: "risc",
    label: "RISC — Risk Incident Sharing and Coordination",
    prefix: RISC_PREFIX,
    implemented: true,
    what: "The account-lifecycle vocabulary, aimed ACROSS providers rather than within one enterprise, in fourteen event types: account disabled, enabled and purged, credential change required, credential compromise, identifier changed and recycled, four opt-out events, recovery activated and recovery information changed, and one the specification deprecates in favour of a CAEP event. It says \"this account is no longer trustworthy\", which is a different sentence from CAEP's and the whole reason there are two profiles. ELEVEN OF THE FOURTEEN CARRY NO PAYLOAD MEMBERS AT ALL, so the SUBJECT is the entire message — which is the opposite of CAEP, where the subject narrows and the payload says what happened."
  }
];

/** The three profiles the SSF page offers, in the order it draws them. */
const SSF_PROFILES: SsfProfileRow[] = #[
  #{
    id: "ssf",
    family: "ssf",
    label: "Pure SSF",
    implemented: true,
    what: "The framework itself. Two event types, both about the PIPE rather than about a person: is this stream alive, and has its status changed. Everything else on this page is the machinery both vocabularies run on."
  },
  #{
    id: "caep",
    family: "caep",
    label: "CAEP",
    implemented: true,
    what: "Continuous Access Evaluation Profile 1.0. Eight event types about a SESSION — it says \"this session is no longer trustworthy\". The CAEP Session pane appears, and every event list on this page narrows to these eight."
  },
  #{
    id: "risc",
    family: "risc",
    label: "RISC",
    implemented: true,
    what: "RISC Profile Specification 1.0, published 29 August 2025 and final on 2 September 2025. Fourteen event types about an ACCOUNT — it says \"this account is no longer trustworthy\", which is a larger sentence than CAEP's by orders of magnitude: a revoked session is one sign-in at one relying party, and a purged account is every session that person has anywhere, for ever. The RISC Account pane appears, and every event list on this page narrows to these fourteen."
  }
];
