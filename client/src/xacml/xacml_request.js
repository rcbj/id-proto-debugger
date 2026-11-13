// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: xacml_request.js
//
// ---------------------------------------------------------------------------
// ONE AUTHORIZATION REQUEST, BUILT ONE WAY, FOR EVERY PEP (#306, part E of
// #88, 2026-09-27).
//
// #88 section 7: every authorization question this service asks — may this
// be ISSUED, may this surface be REACHED, how should it REACT to a risk or a
// signal, and what a remote PEP asks on somebody else's behalf — is one
// shape, and the protocol adapter's job is to fill it in:
//
//   principal, principal_type       access-subject subject-id, subject-kind
//   target                          resource resource-id
//   requested actions               action action-id
//   roles, requested scopes, ...    the vocabulary below, in their category
//   protocol, grant type, consent   the environment
//
// Until this file each PEP built that request itself — the issuance PEP, the
// access PEP, the risk and signal PEPs and the remote PEP each carried its
// own `attribute()` and its own array of categories — and the five copies had
// already drifted in the small ways that matter to a policy: one dropped an
// empty value and another sent it, two asked for the attributes back in the
// result and two did not. The drift was harmless only because no policy had
// yet been written that could see it. This is the one place a request is
// made, and a PEP says WHAT it knows rather than how XACML spells it.
//
// ---------------------------------------------------------------------------
// **IT IS AN ENGINE MODULE, NOT A SERVICE ONE (rcbj's decision on #306).**
// It requires `xacml_model.js` and the helpers logger and nothing else, so
// the remote PEP container copies it beside the engine (`xacml-pep/
// engine.js`'s `MODULES`, and a COPY line in its Dockerfile that
// `tests/xacml_pep.js` holds to that list) and builds its requests with the
// same code this service does. That is also why the VOCABULARY is here and
// not in `xacml_templates.ts`: the templates are the service's, a remote PEP
// cannot load them, and one spelling of each identifier has to be somewhere
// both can read. `xacml_templates.ts` takes the shared ones from here.
//
// **IT DECIDES NOTHING.** Which facts a PEP puts in is that PEP's business;
// the builder only makes sure they are spelt, typed and grouped one way.
// ---------------------------------------------------------------------------

const { log } = require('../xacml_runtime');
const model = require('./xacml_model');

// ---------------------------------------------------------------------------
// THE VOCABULARY OF #88 SECTION 7 THAT IS NOT XACML'S OWN. XACML supplies
// subject-id, resource-id and action-id (`model.ATTRIBUTE`); the rest are
// this service's, URI-shaped so `xacml_pip.ts` never mistakes one for a
// directory attribute name (see `xacml_templates.ts`'s ISSUANCE_ATTRIBUTE
// header for why that matters).
// ---------------------------------------------------------------------------
const VOCABULARY = Object.freeze({
  // access-subject: the roles the principal holds (#303 made the PIP answer
  // it for a subject a request did not describe).
  ROLE: 'urn:sts:xacml:role',
  // access-subject: `user` or `application` — principal_type. A name alone
  // cannot say: `payroll-worker` could be either (#303).
  SUBJECT_KIND: 'urn:sts:xacml:subject-kind',
  // access-subject: the OAuth client the request came through, where that is
  // not the principal itself.
  CLIENT_ID: 'urn:sts:xacml:client-id',
  // resource: the audience the issued artefact is for (RFC 8707 resource,
  // RFC 8693 audience, an AppliesTo, a service principal).
  AUDIENCE: 'urn:sts:xacml:audience',
  // action: each scope value the request asked for — requested_scopes.
  REQUESTED_SCOPE: 'urn:sts:xacml:requested-scope',
  // environment: the protocol family the request arrived over.
  PROTOCOL: 'urn:sts:xacml:protocol',
  // environment: the OAuth grant type, where there is one.
  GRANT_TYPE: 'urn:sts:xacml:grant-type',
  // environment: the realm's mode, `development` or `product` (#305 — rcbj's
  // decision that the mode and the settings a rule depends on are facts in
  // the request, so the policy decides what differs between the two).
  MODE: 'urn:sts:xacml:mode',
  // environment: a setting's value, the setting's key after this prefix
  // (`urn:sts:xacml:setting:oauth2.consentRequired`), typed as it is.
  SETTING_PREFIX: 'urn:sts:xacml:setting:',
  // THE AUTHENTICATION CONTEXT CLASS a session met, where a question
  // carries one (#1168): `xacml_templates.ts`'s AUTHN_ATTRIBUTE.ACR is the
  // same identifier, which the UMA facts spell from here so the Rust
  // builder can mirror it.
  ACR: 'urn:sts:xacml:acr',
  // environment: which moment a scope is judged at (#305): `request` (an
  // endpoint still talking to the client, which refuses), `mint` (the
  // backstop every grant mints through, which narrows) or `consent`.
  SCOPE_STAGE: 'urn:sts:xacml:scope-stage',
  // THE FACTS OF A TRANSFER QUESTION (#98 D4, the design's section 6 —
  // "geofencing is policy, not code"), asked by `common/cell_transfer.ts`
  // when the service is deployed as cells. access-subject: the jurisdiction
  // the subject is HOMED in, where their personal data lives.
  HOME_JURISDICTION: 'urn:sts:xacml:home-jurisdiction',
  // environment: the jurisdiction of the cell being asked to hold the
  // session or serve the request.
  SERVING_JURISDICTION: 'urn:sts:xacml:serving-jurisdiction',
  // environment: the country the CLIENT is in, where the GeoIP data `risk/`
  // imports could say (ISO 3166-1 alpha-2, lower-case); absent when unknown,
  // and an absent country is not a country — no rule may read it as one.
  CLIENT_COUNTRY: 'urn:sts:xacml:client-country',
  // environment, a boolean: the realm's `cells.permittedTransfers` names
  // this home>serving pair (staying in one jurisdiction always is). The
  // realm's STATED loosening, as a fact; what it means is the policy's.
  TRANSFER_LISTED: 'urn:sts:xacml:transfer-listed',
  // resource: what would leave home — `session` (a session and the
  // credential-free projection of the entry it stands on), `request` (one
  // request, relayed) or `attributes` (residents' entries released to a
  // reader at another cell, #98 D11). The design's "data category".
  DATA_CATEGORY: 'urn:sts:xacml:data-category',
  // environment: WHY attributes are released (#98 D11) —
  // `directory-list` (an administrator listing another cell's residents),
  // `api` (a management-API call relayed with ?cell=), `attributes` (a
  // projection fetched for a token) or `scim-provision` (one person pushed
  // by their home cell to an outbound SCIM client's service provider, #553).
  PURPOSE: 'urn:sts:xacml:purpose',
  // environment: the trust realm the question is asked in.
  REALM: 'urn:sts:xacml:realm',
  // THE FACTS OF AN EXCHANGE QUESTION (#186): who may act for whom, and as
  // what, at an RFC 8693 token exchange, a WS-Trust OnBehalfOf / ActAs or a
  // Kerberos S4U request — one vocabulary for the three, so one policy
  // decides all of them. Gathered by `common/delegation_policy.ts`; nothing
  // here decides. S is the application the subject token was issued for, R
  // the one the new token is asked for, the actor the party acting (in the
  // intermediary-subject category). Every party is named by its application
  // identifier, or a person's subject, so the policy compares them itself.
  //
  // access-subject: the subject is protected by its own entry (Kerberos's
  // NOT_DELEGATED, `stsNotDelegated` / `appNotDelegated`).
  EXCHANGE_SUBJECT_NOT_DELEGATED:
    'urn:sts:xacml:exchange:subject-not-delegated',
  // access-subject: the subject's groups, each as its cn AND its normalised
  // DN, so a protected group or an actor's subject group matches either way.
  EXCHANGE_SUBJECT_GROUP: 'urn:sts:xacml:exchange:subject-group',
  // access-subject / intermediary-subject: the semantics this party allows
  // (`delegation`, `impersonation`), and its default. Absent is the policy's
  // to read: the built-in rules read an actor's empty set as delegation
  // only, a subject's as both.
  EXCHANGE_ALLOWED_SEMANTICS: 'urn:sts:xacml:exchange:allowed-semantics',
  EXCHANGE_DEFAULT_SEMANTICS: 'urn:sts:xacml:exchange:default-semantics',
  // intermediary-subject: `user` or `application`; whether an entry backs it
  // in this realm; the targets it may reach as somebody else
  // (appAllowedToDelegateTo, resolved); the people it may act for
  // (appDelegationSubjectGroup, normalised DNs).
  EXCHANGE_ACTOR_KIND: 'urn:sts:xacml:exchange:actor-kind',
  EXCHANGE_ACTOR_REGISTERED: 'urn:sts:xacml:exchange:actor-registered',
  EXCHANGE_ACTOR_DELEGATES_TO: 'urn:sts:xacml:exchange:actor-delegates-to',
  EXCHANGE_ACTOR_SUBJECT_GROUP: 'urn:sts:xacml:exchange:actor-subject-group',
  // resource: S, and what it requires and delegates to.
  EXCHANGE_SOURCE: 'urn:sts:xacml:exchange:source',
  EXCHANGE_SOURCE_REQUIRED_ROLE:
    'urn:sts:xacml:exchange:source-required-role',
  EXCHANGE_SOURCE_DELEGATES_TO: 'urn:sts:xacml:exchange:source-delegates-to',
  // resource: R — how many targets were asked for (an integer), whether R is
  // a registered application, what it requires, and whom it accepts as an
  // actor (appAllowedToActOnBehalfOf, resolved). R itself is resource-id.
  EXCHANGE_TARGET_COUNT: 'urn:sts:xacml:exchange:target-count',
  EXCHANGE_TARGET_REGISTERED: 'urn:sts:xacml:exchange:target-registered',
  EXCHANGE_TARGET_REQUIRED_ROLE:
    'urn:sts:xacml:exchange:target-required-role',
  EXCHANGE_TARGET_ACCEPTS: 'urn:sts:xacml:exchange:target-accepts',
  // action: the semantics the REQUEST asked for (the extension parameter,
  // the WS-Trust element, the Kerberos mechanism), and the semantics the
  // choosing question settled on.
  EXCHANGE_REQUESTED_SEMANTICS:
    'urn:sts:xacml:exchange:requested-semantics',
  EXCHANGE_SEMANTICS: 'urn:sts:xacml:exchange:semantics',
  // environment: the subject token carried may_act (RFC 8693 section 4.4),
  // and whether it names this actor — an identity comparison the door makes.
  EXCHANGE_MAY_ACT_PRESENT: 'urn:sts:xacml:exchange:may-act-present',
  EXCHANGE_MAY_ACT_NAMES_ACTOR: 'urn:sts:xacml:exchange:may-act-names-actor',
  // environment: the groups whose members are never acted for — the
  // realm's `delegation.protectedGroups` and the console roster — as cn and
  // normalised DN.
  EXCHANGE_PROTECTED_GROUP: 'urn:sts:xacml:exchange:protected-group',
  // #186: the party the subject NAMED as their delegate (`stsMayAct` on a
  // person, `appMayAct` on an application), as the `may_act` claim would
  // name it — the fact the `assign-may-act` question decides on.
  EXCHANGE_SUBJECT_DELEGATE: 'urn:sts:xacml:exchange:subject-delegate',
  // THE FACTS OF A QUESTION ASKED ACROSS A KERBEROS TRUST (#430 Phase 1,
  // defined now; the rules that read them are its Phase 3). Gathered from
  // the trust record (`kerberos/krb5_trusts.ts`) by the Kerberos side of
  // `delegation_policy.ts`; nothing here decides, and none is sent for a
  // question that crossed no trust.
  //
  // access-subject / intermediary-subject / resource: the KERBEROS REALM the
  // subject, the actor and the target (R) each belong to — `ALPHA.TEST` —
  // so a rule can tell a foreign front end (`SPN@OTHER`) from a local one.
  EXCHANGE_SUBJECT_REALM: 'urn:sts:xacml:exchange:subject-realm',
  EXCHANGE_ACTOR_REALM: 'urn:sts:xacml:exchange:actor-realm',
  EXCHANGE_TARGET_REALM: 'urn:sts:xacml:exchange:target-realm',
  // environment: the partner realm whose trust the question arrived across
  // (the realm that issued the presented ticket), the trust's type
  // (`external` or `trust-realm`), its direction as this realm holds it
  // (`inbound`, `outbound`, `bidirectional`), each of its attributes by name
  // ([MS-ADTS] 6.1.6.7.9's closed set: `non-transitive`, `quarantined`,
  // `forest-transitive`, `cross-organization`, `within-forest`,
  // `treat-as-external`, `no-tgt-delegation`, `enable-tgt-delegation`), the
  // realms the path crossed in order (the client's realm first, as RFC 4120
  // section 3.3.3.2's `transited` and the issuing realm make it), and how
  // many trusts it crossed (an integer).
  EXCHANGE_TRUST_PARTNER: 'urn:sts:xacml:exchange:trust-partner',
  EXCHANGE_TRUST_TYPE: 'urn:sts:xacml:exchange:trust-type',
  EXCHANGE_TRUST_DIRECTION: 'urn:sts:xacml:exchange:trust-direction',
  EXCHANGE_TRUST_ATTRIBUTE: 'urn:sts:xacml:exchange:trust-attribute',
  EXCHANGE_TRUST_PATH: 'urn:sts:xacml:exchange:trust-path',
  EXCHANGE_TRUST_HOPS: 'urn:sts:xacml:exchange:trust-hops',
  // AND WHAT PHASE 3 OF #430 READS BESIDE THEM, each sent only with a trust:
  // environment, a boolean — the trust is enabled (a disabled one refers and
  // accepts nothing, so this is the rule's belt to the KDC's braces); this
  // KDC's own Kerberos realm, so a rule can tell a foreign party from a
  // local one; action — the Kerberos mechanism (`S4U2Self`,
  // `S4U2Proxy-classic`, `S4U2Proxy-rbcd`, `forwarded`); intermediary-
  // subject — the realms whose users the actor may obtain S4U2Self tickets
  // for (`krb5S4uSelfRealm`); resource — what the target says of a TGT
  // forwarded to it across a trust (`krb5ForeignTgtDelegation`: `inherit`,
  // `deny`).
  EXCHANGE_TRUST_ENABLED: 'urn:sts:xacml:exchange:trust-enabled',
  EXCHANGE_LOCAL_REALM: 'urn:sts:xacml:exchange:local-realm',
  EXCHANGE_MECHANISM: 'urn:sts:xacml:exchange:mechanism',
  EXCHANGE_ACTOR_SELF_REALM: 'urn:sts:xacml:exchange:actor-self-realm',
  EXCHANGE_TARGET_FOREIGN_TGT_DELEGATION:
    'urn:sts:xacml:exchange:target-foreign-tgt-delegation',
  // THE FACTS OF A GNAP ACCESS RIGHT (#432 phase 3): one question per right,
  // action-id `issue-gnap-right`, the right's type (or its reference string)
  // as the resource-id. Gathered by `gnap/gnap_rights.ts`; nothing here
  // decides. RESOURCE: the right itself — `object` or `reference`, its five
  // common fields (RFC 9635 section 8) — whether the access-type catalogue
  // declares its type and what that entry declares, whether the client's
  // gnapAllowedAccess lists it, whether a reference names a registered
  // resource set, and whether it asks for one of this service's protected
  // scopes (#110) the client's entry does not declare.
  GNAP_RIGHT_KIND: 'urn:sts:xacml:gnap:right-kind',
  GNAP_RIGHT_ACTION: 'urn:sts:xacml:gnap:right-action',
  GNAP_RIGHT_LOCATION: 'urn:sts:xacml:gnap:right-location',
  GNAP_RIGHT_DATATYPE: 'urn:sts:xacml:gnap:right-datatype',
  GNAP_RIGHT_IDENTIFIER: 'urn:sts:xacml:gnap:right-identifier',
  GNAP_RIGHT_PRIVILEGE: 'urn:sts:xacml:gnap:right-privilege',
  GNAP_RIGHT_LISTED: 'urn:sts:xacml:gnap:right-listed',
  GNAP_REFERENCE_REGISTERED: 'urn:sts:xacml:gnap:reference-registered',
  GNAP_PROTECTED: 'urn:sts:xacml:gnap:protected',
  GNAP_PROTECTED_DECLARED: 'urn:sts:xacml:gnap:protected-declared',
  GNAP_CATALOGUED: 'urn:sts:xacml:gnap:catalogued',
  GNAP_TYPE_OWNER: 'urn:sts:xacml:gnap:type-owner',
  GNAP_TYPE_BEARER: 'urn:sts:xacml:gnap:type-bearer',
  GNAP_TYPE_MAX_LIFETIME: 'urn:sts:xacml:gnap:type-max-lifetime',
  GNAP_TYPE_ACR: 'urn:sts:xacml:gnap:type-acr',
  GNAP_TYPE_INTERACTION: 'urn:sts:xacml:gnap:type-interaction',
  GNAP_TYPE_CONSENT_ACTION: 'urn:sts:xacml:gnap:type-consent-action',
  GNAP_TYPE_DERIVABLE_FROM: 'urn:sts:xacml:gnap:type-derivable-from',
  GNAP_TYPE_INTROSPECTION_CLAIM:
    'urn:sts:xacml:gnap:type-introspection-claim',
  // THE RIGHT'S LIMITS AND WHO OWNS WHAT IT NAMES (#432 phase 5). The limits
  // as the right carries them (`limits`, the JSON) and each member with a
  // meaning decomposed (`common/access_limits.ts`): an amount (a double, in
  // its currency), a count, the receivers, the repeating interval and the
  // window's two ends. The owner of the right's identifier — from a
  // registered resource set or the resource server's lookup — whether one is
  // known, whether a declared lookup could not be answered, and, once an
  // approver is known, whether the approver is that owner (or a member of
  // that group). `owner-matches` is sent only with an approver.
  GNAP_LIMITS: 'urn:sts:xacml:gnap:limits',
  GNAP_LIMIT_AMOUNT: 'urn:sts:xacml:gnap:limit-amount',
  GNAP_LIMIT_CURRENCY: 'urn:sts:xacml:gnap:limit-currency',
  GNAP_LIMIT_COUNT: 'urn:sts:xacml:gnap:limit-count',
  GNAP_LIMIT_RECEIVER: 'urn:sts:xacml:gnap:limit-receiver',
  GNAP_LIMIT_INTERVAL: 'urn:sts:xacml:gnap:limit-interval',
  GNAP_LIMIT_NOT_BEFORE: 'urn:sts:xacml:gnap:limit-not-before',
  GNAP_LIMIT_NOT_AFTER: 'urn:sts:xacml:gnap:limit-not-after',
  GNAP_OWNER_KNOWN: 'urn:sts:xacml:gnap:owner-known',
  GNAP_OWNER: 'urn:sts:xacml:gnap:owner',
  GNAP_OWNER_SOURCE: 'urn:sts:xacml:gnap:owner-source',
  GNAP_OWNER_UNRESOLVED: 'urn:sts:xacml:gnap:owner-unresolved',
  GNAP_OWNER_MATCHES: 'urn:sts:xacml:gnap:owner-matches',
  // ACTION: the token the right is to be issued in — its label, the bearer
  // flag, the format it would be minted in and the resource servers it is
  // for.
  GNAP_TOKEN_LABEL: 'urn:sts:xacml:gnap:token-label',
  GNAP_TOKEN_BEARER: 'urn:sts:xacml:gnap:token-bearer',
  GNAP_TOKEN_FORMAT: 'urn:sts:xacml:gnap:token-format',
  GNAP_TOKEN_TARGET: 'urn:sts:xacml:gnap:token-target',
  // ACCESS-SUBJECT: the client — its REGISTERED class (a declared class_id
  // never raises trust, so it is never sent), whether its entry lists any
  // gnapAllowedAccess, and whether it refuses bearer tokens.
  GNAP_CLIENT_CLASS: 'urn:sts:xacml:gnap:client-class',
  GNAP_CLIENT_HAS_ALLOWED_ACCESS:
    'urn:sts:xacml:gnap:client-has-allowed-access',
  GNAP_CLIENT_BEARER_REFUSED: 'urn:sts:xacml:gnap:client-bearer-refused',
  // ENVIRONMENT: who approved and how (`pending` before anybody has,
  // `interaction`, `skipped`, `derived`, `remembered`, or — since #432
  // phase 6 — `owner`, the resource owner on their portal while somebody
  // else, or nobody, used the client), the session the
  // approval stands on (acr, amr), its risk (#62) and the registered device
  // (#164). UNDER NAMES OF THEIR OWN rather than the issuance's risk and
  // device attributes: the issuance's untargeted risk and device rules
  // decide the TOKEN through `gate.check()`, which is still asked, and a
  // right that carried their attributes would trip them on every
  // per-right question and answer it with an obligation no right reader
  // knows.
  GNAP_APPROVER: 'urn:sts:xacml:gnap:approver',
  GNAP_APPROVAL: 'urn:sts:xacml:gnap:approval',
  GNAP_SESSION_ACR: 'urn:sts:xacml:gnap:session-acr',
  GNAP_SESSION_AMR: 'urn:sts:xacml:gnap:session-amr',
  GNAP_RISK_LEVEL: 'urn:sts:xacml:gnap:risk-level',
  GNAP_RISK_SIGNAL: 'urn:sts:xacml:gnap:risk-signal',
  GNAP_DEVICE_RECOGNIZED: 'urn:sts:xacml:gnap:device-recognized',
  GNAP_DEVICE_STATUS: 'urn:sts:xacml:gnap:device-status',
  GNAP_DEVICE_COMPLIANCE: 'urn:sts:xacml:gnap:device-compliance',
  GNAP_DEVICE_ATTESTATION: 'urn:sts:xacml:gnap:device-attestation',
  GNAP_DEVICE_OWNER_MATCHES: 'urn:sts:xacml:gnap:device-owner-matches',
  // THE FACTS OF AN AUTHZEN QUESTION (#563), written by `authzen/` and
  // nothing else. AuthZEN's subject and resource each carry a TYPE beside
  // the id, and XACML has no identifier for either. access-subject:
  AUTHZEN_SUBJECT_TYPE: 'urn:sts:xacml:authzen:subject-type',
  // resource:
  AUTHZEN_RESOURCE_TYPE: 'urn:sts:xacml:authzen:resource-type',
  // environment, TRUSTED — from the caller's authentication and its entry,
  // never from the request body: who asked (a directory entry's DN or a
  // client_id), and the application the question is scoped to.
  AUTHZEN_CALLER: 'urn:sts:xacml:authzen:caller',
  AUTHZEN_APPLICATION: 'urn:sts:xacml:authzen:application',
  // environment, TRUSTED: every member the caller SENT, by its path
  // (`subject.properties.department`, `context.source_ip`), so a policy can
  // tell a property that was absent from one sent with an empty value.
  AUTHZEN_SUPPLIED: 'urn:sts:xacml:authzen:supplied',
  // THE FACTS OF A TOKEN-EXCHANGE QUESTION ASKED OVER AUTHZEN (#1181, the
  // OAuth 2.0 Token Exchange Binding), written by `exchange()` beside the
  // exchange vocabulary ONLY when `authzen/authzen_exchange.ts` asks, so a
  // local RFC 8693, WS-Trust or Kerberos question is the request it always
  // was. action: the token type short name of the gate action
  // (`issue:<type>:token_exchange`), as the binding registers it —
  // `access_token`, `id_jag`, `txn_token`.
  AUTHZEN_TOKEN_TYPE: 'urn:sts:xacml:authzen:token-type',
  // environment: `context.subject_token_type` and `context.actor_token_type`,
  // verbatim (RFC 8693 token type URIs), and how many entries deep the
  // subject token's `act` chain already is (an integer; 0 for none).
  AUTHZEN_SUBJECT_TOKEN_TYPE: 'urn:sts:xacml:authzen:subject-token-type',
  AUTHZEN_ACTOR_TOKEN_TYPE: 'urn:sts:xacml:authzen:actor-token-type',
  AUTHZEN_ACT_DEPTH: 'urn:sts:xacml:authzen:act-depth',
  // environment, TRUSTED, and only after `authzen/authzen_access_request.ts`
  // VERIFIED a presented `context.approval` against its store (#1180): the
  // approval's id, until when it holds (a dateTime) and who approved it. A
  // policy that requires an approval reads these; the values a PEP sent
  // beside the id never reach a request.
  AUTHZEN_APPROVAL_ID: 'urn:sts:xacml:authzen:approval-id',
  AUTHZEN_APPROVED_UNTIL: 'urn:sts:xacml:authzen:approved-until',
  AUTHZEN_APPROVER: 'urn:sts:xacml:authzen:approver',
  // THE FACTS OF A FINE-GRAINED AUTHORIZATION QUESTION (#564): one RFC 9396
  // authorization detail, asked of the policy of the RESOURCE application
  // that declares its type. Written by `xacml/fga_map.ts` alone, through
  // `fga()` below. resource, TRUSTED — from the registry, never from the
  // detail: the application that owns the type (its identifier), the
  // detail's type, and a SHA-256 of the type's canonical definition, so a
  // policy can be pinned to the definition it was written against.
  FGA_APPLICATION: 'urn:sts:xacml:fga:application',
  FGA_DETAIL_TYPE: 'urn:sts:xacml:fga:detail-type',
  FGA_DEFINITION_DIGEST: 'urn:sts:xacml:fga:definition-digest',
  // environment, TRUSTED: the moment the question is asked at — FGA_STAGES
  // below — and every member path of the detail that reached the request
  // (`actions`, `amount.currency`), so a policy can tell a member sent
  // empty from one not sent. A member the type lists in `notForPolicy` is
  // in neither.
  FGA_STAGE: 'urn:sts:xacml:fga:stage',
  FGA_SUPPLIED: 'urn:sts:xacml:fga:supplied',
  // THE DETAIL'S COMMON DATA FIELDS (RFC 9396 section 2.2), each mapped by
  // a BUILT-IN row whenever the detail carries it, so a policy may test
  // them with no declaration: `actions` and `privileges` (action, string
  // bags), `locations` and `datatypes` (resource, string bags) and
  // `identifier` (resource, one string). Strings rather than anyURI for
  // `locations`, as GNAP's right-location is, so one `string-is-in` reads
  // both protocols. A type's own `xacml` rows cover its other members.
  FGA_DETAIL_ACTION: 'urn:sts:xacml:fga:detail:action',
  FGA_DETAIL_LOCATION: 'urn:sts:xacml:fga:detail:location',
  FGA_DETAIL_DATATYPE: 'urn:sts:xacml:fga:detail:datatype',
  FGA_DETAIL_IDENTIFIER: 'urn:sts:xacml:fga:detail:identifier',
  FGA_DETAIL_PRIVILEGE: 'urn:sts:xacml:fga:detail:privilege',
  // THE FACTS OF A USER-MANAGED ACCESS QUESTION (#1168, phase 1): one
  // registered resource and one of its scopes, asked of up to three
  // policies in turn — the realm's `uma-authorization`, the resource
  // OWNER's own document, and the resource server's fine-grained policy
  // (#564) — by `uma/`'s PEP alone, through `uma()` below. Nothing here
  // decides: UMA 2.0 is a grant that names WHO is asked and WHAT about,
  // and every answer is the PDP's. Spelt the same in the Rust builder
  // (`tests/xacml_request.js` E2).
  //
  // resource, TRUSTED — from the registration and the protection API
  // token (PAT) that made it, never from the client: the resource's
  // `type`, the resource server (the application declared for `uma`),
  // the owner's subject and the owner's kind (`user`, `application`), and
  // whether the resource server is declared for the protocol.
  UMA_RESOURCE_TYPE: 'urn:sts:xacml:uma:resource-type',
  UMA_RESOURCE_SERVER: 'urn:sts:xacml:uma:resource-server',
  UMA_RESOURCE_SERVER_DECLARED:
    'urn:sts:xacml:uma:resource-server-declared',
  UMA_OWNER: 'urn:sts:xacml:uma:owner',
  UMA_OWNER_KIND: 'urn:sts:xacml:uma:owner-kind',
  // action: the scope being asked about, on every layer, beside the
  // action-id (the scope itself on the owner's layer; the forced issuance
  // action elsewhere — see `uma()`).
  UMA_SCOPE: 'urn:sts:xacml:uma:scope',
  // access-subject: HOW THE REQUESTING PARTY BECAME KNOWN. Booleans saying
  // whether anybody is known at all and whether they are the owner; the
  // source of what is known (`session`, `claim_token`, `pct`); the issuer
  // of a pushed claim token, and whether that issuer is one the realm
  // declared (true where no token was pushed); whether the client
  // registered the UMA grant type.
  UMA_REQUESTING_PARTY_KNOWN: 'urn:sts:xacml:uma:requesting-party-known',
  UMA_REQUESTING_PARTY_IS_OWNER:
    'urn:sts:xacml:uma:requesting-party-is-owner',
  UMA_CLAIM_SOURCE: 'urn:sts:xacml:uma:claim-source',
  UMA_CLAIM_ISSUER: 'urn:sts:xacml:uma:claim-issuer',
  UMA_CLAIM_ISSUER_DECLARED: 'urn:sts:xacml:uma:claim-issuer-declared',
  // access-subject: the DNs of the groups the requesting party is a DIRECT
  // member of, normalised, computed by the UMA endpoint from the directory
  // (#1192). A fact rather than `memberOf`, which nothing here maintains —
  // `ldap_server.js` says so — so a share with a group reads what the
  // group lists, as the console's rosters do.
  UMA_REQUESTING_PARTY_GROUP: 'urn:sts:xacml:uma:requesting-party-group',
  UMA_CLIENT_GRANT_DECLARED: 'urn:sts:xacml:uma:client-grant-declared',
  // access-subject: EACH GATHERED CLAIM, after this prefix under its own
  // name (`urn:sts:xacml:uma:claim:email`) — only from a VERIFIED token or
  // the sign-on session, never a value a client merely asserted.
  UMA_CLAIM_PREFIX: 'urn:sts:xacml:uma:claim:',
  // environment: WHICH LAYER is asking (`realm`, `owner`, `fga`), at which
  // STAGE (`assess`, `upgrade`, `approval`), how old the permission ticket
  // is in seconds, and whether an RPT was presented for upgrade.
  UMA_LAYER: 'urn:sts:xacml:uma:layer',
  UMA_STAGE: 'urn:sts:xacml:uma:stage',
  UMA_TICKET_AGE: 'urn:sts:xacml:uma:ticket-age',
  UMA_RPT_PRESENTED: 'urn:sts:xacml:uma:rpt-presented',
  // THE FACTS OF A PASSKEY QUESTION (#536): a passkey being registered
  // (`register-passkey`) or signing somebody in (`use-passkey`), gathered by
  // `common/passkey_policy.ts`. Nothing here decides; the built-in issuance
  // policy's passkey rules read these.
  //
  // environment: which groups of facts this question carries —
  // `backup-eligible`, `pin-length`, `serial`, `attestation`, `algorithm`
  // (#718). Each built-in
  // rule fires only on a question that carries its group, so a question
  // asked at one door never trips a rule another door asks.
  PASSKEY_FACTS: 'urn:sts:xacml:passkey:facts',
  // resource, a boolean: the authenticator data's BE flag (#528).
  PASSKEY_BACKUP_ELIGIBLE: 'urn:sts:xacml:passkey:backup-eligible',
  // resource, an integer: the minimum PIN length the key reported (CTAP
  // 2.1's minPinLength extension, #529); absent when it reported none.
  PASSKEY_MIN_PIN_LENGTH: 'urn:sts:xacml:passkey:min-pin-length',
  // resource: the device serial a trusted attestation certificate named
  // (#532), and a boolean saying whether it is one of the person's (their
  // entry holds it in the attribute the passkey policy names).
  PASSKEY_SERIAL: 'urn:sts:xacml:passkey:serial',
  PASSKEY_SERIAL_HELD: 'urn:sts:xacml:passkey:serial-held',
  // resource: what the key's RECORDED attestation says (#530) — whether it
  // was verified and trusted, and its AAGUID (lower case, no hyphens).
  PASSKEY_ATTESTATION_VERIFIED: 'urn:sts:xacml:passkey:attestation-verified',
  PASSKEY_ATTESTATION_TRUSTED: 'urn:sts:xacml:passkey:attestation-trusted',
  PASSKEY_AAGUID: 'urn:sts:xacml:passkey:aaguid',
  // resource: what the FIDO Metadata Service says of the model NOW —
  // whether it lists it, whether it is compromised, its certification level
  // as a RANK (0 none, 1 L1, 2 L1plus, 3 L2, 4 L2plus, 5 L3, 6 L3plus) so a
  // rule can compare it, and whether it holds a FIPS 140 certification.
  // Absent unless the metadata was asked; `metadata-unchecked` true when it
  // was asked and could not be read.
  PASSKEY_MODEL_LISTED: 'urn:sts:xacml:passkey:model-listed',
  PASSKEY_MODEL_COMPROMISED: 'urn:sts:xacml:passkey:model-compromised',
  PASSKEY_CERTIFICATION_RANK: 'urn:sts:xacml:passkey:certification-rank',
  PASSKEY_FIPS: 'urn:sts:xacml:passkey:fips',
  PASSKEY_METADATA_UNCHECKED: 'urn:sts:xacml:passkey:metadata-unchecked',
  // resource: the key's SIGNATURE ALGORITHM (#718), with the fact group
  // `algorithm` — its JOSE name as the ceremony recorded it (`ML-DSA-65`,
  // `ES256`; `credentials.keyAlgorithm()` derives it for a row that
  // recorded none); a boolean saying whether that algorithm is
  // post-quantum (RFC 9964's ML-DSA-44, -65 or -87), computed in ONE place,
  // `passkey_policy.ts`'s `question()`, never by a door; and the LANE the
  // key was created in (#643, `classical` or `pqc`). The rule is on the
  // ALGORITHM: with #643's switch off an ML-DSA key is made in the one
  // lane and its row carries no lane, so a rule on the lane would refuse a
  // post-quantum key. The lane is here for a realm's own rules.
  PASSKEY_ALGORITHM: 'urn:sts:xacml:passkey:algorithm',
  PASSKEY_POST_QUANTUM: 'urn:sts:xacml:passkey:post-quantum',
  PASSKEY_LANE: 'urn:sts:xacml:passkey:lane',
  // resource: AN UPGRADE OF A CLASSICAL PASSKEY (#939), with the fact group
  // `upgrade` — true where the registration is the second ceremony of an
  // upgrade, what its write does (`replace`, the ML-DSA key in the
  // classical one's place, or `alongside`, beside it in the post-quantum
  // lane), and the JOSE name of the algorithm of the passkey it upgrades.
  // Read by no built-in rule: a realm's own rule may forbid upgrades.
  PASSKEY_UPGRADE: 'urn:sts:xacml:passkey:upgrade',
  PASSKEY_UPGRADE_MODE: 'urn:sts:xacml:passkey:upgrade-mode',
  PASSKEY_UPGRADE_PREVIOUS_ALGORITHM:
    'urn:sts:xacml:passkey:upgrade-previous-algorithm',
  // resource: WHAT THE KEY'S ATTESTATION WAS SIGNED WITH (#941), with the
  // fact group `attestation-algorithm` — the statement's own signature
  // algorithm by its COSE name (`ML-DSA-65`, `ES256`; absent for apple and
  // none); a bag of every certificate's signature algorithm, leaf first
  // and the anchor last (`ML-DSA-65`, `sha256-ecdsa`,
  // `id-MLDSA65-ECDSA-P256-SHA512`); whether ALL of them are post-quantum;
  // whether the statement was verified and trusted (the `attestation`
  // group's two facts, sent here too where that group is not); and whether
  // they satisfy the selected profile's `attestationAlgorithms` list —
  // computed in ONE place, `passkey_policy.ts`'s `question()`, as
  // POST_QUANTUM is. The built-in rule reads ATTESTATION_ALGORITHM_ALLOWED
  // alone; the rest is for a realm's own rules.
  PASSKEY_ATTESTATION_STATEMENT_ALGORITHM:
    'urn:sts:xacml:passkey:attestation-statement-algorithm',
  PASSKEY_ATTESTATION_CERTIFICATE_ALGORITHM:
    'urn:sts:xacml:passkey:attestation-certificate-algorithm',
  PASSKEY_ATTESTATION_POST_QUANTUM:
    'urn:sts:xacml:passkey:attestation-post-quantum',
  PASSKEY_ATTESTATION_ALGORITHM_ALLOWED:
    'urn:sts:xacml:passkey:attestation-algorithm-allowed',
  // resource: WHETHER THE KEY'S ALGORITHM IS ONE THE SELECTED PASSKEY
  // PROFILE OFFERS AT REGISTRATION (#940), with the fact group
  // `profile-algorithm`, at register-passkey only — computed in ONE place,
  // `passkey_policy.ts`'s `question()`, from the algorithm (PASSKEY_ALGORITHM,
  // sent with the `algorithm` group) and the profile's resolved list, the
  // policy fact `registrationAlgorithms`. A boolean always sent with its
  // group, false for anything but true.
  PASSKEY_PROFILE_ALGORITHM_OFFERED:
    'urn:sts:xacml:passkey:profile-algorithm-offered',
  // resource: WHO ENROLLED THE KEY (#945), with the fact group `enrolment`
  // — sent only for a registration an ADMINISTRATOR ran in their own
  // browser on the person's behalf: a boolean, true, and the
  // administrator's username. No built-in rule reads them (the switch is
  // the passkey policy's `adminEnrolment`, enforced at the writer); they
  // are there so a realm's own rule can forbid an administrator's
  // enrolment, or allow it only for some people or some administrators.
  PASSKEY_ENROLLED_BY_ADMIN: 'urn:sts:xacml:passkey:enrolled-by-admin',
  PASSKEY_ENROLLED_BY: 'urn:sts:xacml:passkey:enrolled-by',
  // environment: the SELECTED passkey policy profile's rows (#527, #535),
  // each after this prefix under its own name
  // (`urn:sts:xacml:passkey-policy:backupEligibility`).
  PASSKEY_POLICY_PREFIX: 'urn:sts:xacml:passkey-policy:',
  // THE FACTS OF AN ACCOUNT RECOVERY (#724), carried in the `recovery`
  // group of a `recover-account` question. resource, strings: the recovery
  // DOOR (`forgot-password`, `password-reset`, `admin-password`,
  // `activation`, `recovery-code`, `email-code`, `email-link`; absent at a
  // session no recovery door led to), WHERE the question is asked (`door`,
  // before anything is written; `session`, at the start of a session), and
  // the kind of CREDENTIAL that answered at a session (`password`,
  // `webauthn`, `backup-code`, ...). Booleans: whether the door is
  // SELF-SERVICE (the person's own, rather than an operator's), whether the
  // person holds a passkey the recovery would replace (COVERED), and
  // whether a recovery is PENDING on their entry (a door was spent and no
  // passkey has signed them in since).
  PASSKEY_RECOVERY_DOOR: 'urn:sts:xacml:passkey:recovery-door',
  PASSKEY_RECOVERY_AT: 'urn:sts:xacml:passkey:recovery-at',
  PASSKEY_RECOVERY_CREDENTIAL: 'urn:sts:xacml:passkey:recovery-credential',
  PASSKEY_RECOVERY_SELF_SERVICE:
    'urn:sts:xacml:passkey:recovery-self-service',
  PASSKEY_RECOVERY_COVERED: 'urn:sts:xacml:passkey:recovery-covered',
  PASSKEY_RECOVERY_PENDING: 'urn:sts:xacml:passkey:recovery-pending',
  // environment, an integer: the rank of
  // `webauthn.attestationMinCertificationLevel`, absent when it is `none`.
  PASSKEY_REQUIRED_RANK: 'urn:sts:xacml:passkey:required-certification-rank'
});

// The principal types a request may name. Anything else is a person, which
// is what a request that never said meant.
const SUBJECT_KINDS = Object.freeze(['user', 'application']);

// THE STAGES A FINE-GRAINED AUTHORIZATION QUESTION IS ASKED AT (#564), as
// `urn:sts:xacml:fga:stage` carries them: the authorization endpoint, the
// token endpoint (a code or a direct grant), a refresh, a token exchange,
// the PAR endpoint — the five ISSUANCE stages, whose action-id is
// FGA_GRANT_ACTION — and `access`, AuthZEN's per-request question, whose
// action is the one the resource server asks about.
const FGA_STAGES = Object.freeze(['authorize', 'token', 'refresh',
                                  'exchange', 'par', 'access']);
const FGA_ISSUANCE_STAGES = Object.freeze(['authorize', 'token', 'refresh',
                                           'exchange', 'par']);
const FGA_GRANT_ACTION = 'grant-authorization-detail';

// THE THREE LAYERS A USER-MANAGED ACCESS QUESTION IS ASKED OF (#1168), as
// `urn:sts:xacml:uma:layer` carries them, and the STAGES it is asked at. The
// action-id is FORCED by the layer: `issue-uma-permission` for the realm's
// own policy, the SCOPE itself for the resource owner's document (which is
// only ever asked about UMA permissions over that owner's own resources, so
// a rule there reads `action-id == "read"` as a person would write it), and
// `grant-uma-permission` for the resource server's fine-grained policy
// (#564), whose issuance questions already force their action.
const UMA_LAYERS = Object.freeze(['realm', 'owner', 'fga']);
const UMA_STAGES = Object.freeze(['assess', 'upgrade', 'approval']);
const UMA_PERMISSION_ACTION = 'issue-uma-permission';
const UMA_FGA_ACTION = 'grant-uma-permission';
const UMA_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:uma-ticket';
const UMA_CLAIM_SOURCES = Object.freeze(['session', 'claim_token', 'pct']);

class AuthorizationRequest {
  // `options`:
  //   includeInResult  whether each attribute asks to be returned with the
  //                    result (the issuance and access PEPs say yes, the
  //                    reaction PEPs no). Default true.
  //   dropEmpty        whether an empty or absent VALUE is left out of its
  //                    bag rather than sent as ''. Default false: an empty
  //                    subject-id is how several PEPs say "nobody".
  //   returnPolicyIdList  default true.
  constructor(options) {
    log.debug("Entering AuthorizationRequest.constructor().");
    const given = options || {};
    this.includeInResult = given.includeInResult !== false;
    this.dropEmpty = !!given.dropEmpty;
    this.returnPolicyIdList = given.returnPolicyIdList !== false;
    // In the order a category was first named, so a request is built the
    // same every time and a reader of a logged one finds subject first.
    /** @type {Array<{category: string, attributes: any[]}>} */
    this.categories = [];
    log.debug("Leaving AuthorizationRequest.constructor().");
  }

  // The category's entry, made the first time it is named. Naming one with
  // no attributes is how a PEP sends an EMPTY category — the issuance and
  // access PEPs always send the environment, empty or not.
  category(id) {
    log.debug("Entering AuthorizationRequest.category().");
    let found = this.categories.filter(function (one) {
      return one.category === id;
    })[0];
    if (!found) {
      found = { category: id, attributes: [] };
      this.categories.push(found);
    }
    log.debug("Leaving AuthorizationRequest.category().");
    return found;
  }

  // ONE ATTRIBUTE, MULTI-VALUED: a bag rather than a value everywhere,
  // because every one of these genuinely is one. An empty list is sent as an
  // empty bag, which XACML reads as "nobody said" — the same as leaving the
  // attribute out.
  attribute(categoryId, attributeId, values, type) {
    log.debug("Entering AuthorizationRequest.attribute().");
    const self = this;
    const list = (values || []).filter(function (one) {
      return !self.dropEmpty ||
             (one !== undefined && one !== null && String(one) !== '');
    });
    this.category(categoryId).attributes.push({
      attributeId: attributeId,
      issuer: null,
      includeInResult: this.includeInResult,
      values: list.map(function (one) {
        return { type: type || model.TYPE.STRING, lexical: String(one) };
      })
    });
    log.debug("Leaving AuthorizationRequest.attribute().");
    return this;
  }

  // ---------------------------------------------------------------------------
  // THE FOUR CATEGORIES, by name.
  // ---------------------------------------------------------------------------
  subject(attributeId, values, type) {
    log.debug("Entering AuthorizationRequest.subject().");
    log.debug("Leaving AuthorizationRequest.subject().");
    return this.attribute(model.CATEGORY.ACCESS_SUBJECT, attributeId, values,
                          type);
  }

  resource(attributeId, values, type) {
    log.debug("Entering AuthorizationRequest.resource().");
    log.debug("Leaving AuthorizationRequest.resource().");
    return this.attribute(model.CATEGORY.RESOURCE, attributeId, values, type);
  }

  action(attributeId, values, type) {
    log.debug("Entering AuthorizationRequest.action().");
    log.debug("Leaving AuthorizationRequest.action().");
    return this.attribute(model.CATEGORY.ACTION, attributeId, values, type);
  }

  environment(attributeId, values, type) {
    log.debug("Entering AuthorizationRequest.environment().");
    log.debug("Leaving AuthorizationRequest.environment().");
    return this.attribute(model.CATEGORY.ENVIRONMENT, attributeId, values,
                          type);
  }

  // ---------------------------------------------------------------------------
  // THE FIELDS OF #88 SECTION 7.
  // ---------------------------------------------------------------------------

  // principal and principal_type. `kind` is sent only when given, so a PEP
  // whose question is always about a person need not say so.
  principal(name, kind) {
    log.debug("Entering AuthorizationRequest.principal().");
    this.subject(model.ATTRIBUTE.SUBJECT_ID, [name == null ? '' : name]);
    if (kind !== undefined && kind !== null) {
      this.subject(VOCABULARY.SUBJECT_KIND,
                   [SUBJECT_KINDS.indexOf(String(kind)) >= 0 ? String(kind)
                                                             : 'user']);
    }
    log.debug("Leaving AuthorizationRequest.principal().");
    return this;
  }

  // The roles the principal holds.
  roles(held) {
    log.debug("Entering AuthorizationRequest.roles().");
    log.debug("Leaving AuthorizationRequest.roles().");
    return this.subject(VOCABULARY.ROLE, held);
  }

  // target: what is being issued FOR or reached. A string by default — an
  // application handle is a client_id, a wtrealm or an entityID, and only
  // some of those are URIs (`xacml_role_pep.ts` argues it).
  target(id, type) {
    log.debug("Entering AuthorizationRequest.target().");
    log.debug("Leaving AuthorizationRequest.target().");
    return this.resource(model.ATTRIBUTE.RESOURCE_ID, [id], type);
  }

  // requested_actions: the action-id.
  requestedAction(id) {
    log.debug("Entering AuthorizationRequest.requestedAction().");
    log.debug("Leaving AuthorizationRequest.requestedAction().");
    return this.action(model.ATTRIBUTE.ACTION_ID, [id]);
  }

  // requested_scopes: each value, one bag.
  requestedScopes(values) {
    log.debug("Entering AuthorizationRequest.requestedScopes().");
    log.debug("Leaving AuthorizationRequest.requestedScopes().");
    return this.action(VOCABULARY.REQUESTED_SCOPE, values);
  }

  // The client the request came through.
  client(id) {
    log.debug("Entering AuthorizationRequest.client().");
    log.debug("Leaving AuthorizationRequest.client().");
    return this.subject(VOCABULARY.CLIENT_ID, id ? [id] : []);
  }

  // audience / resource indicator(s).
  audience(values) {
    log.debug("Entering AuthorizationRequest.audience().");
    log.debug("Leaving AuthorizationRequest.audience().");
    return this.resource(VOCABULARY.AUDIENCE, values);
  }

  protocol(name) {
    log.debug("Entering AuthorizationRequest.protocol().");
    log.debug("Leaving AuthorizationRequest.protocol().");
    return this.environment(VOCABULARY.PROTOCOL, name ? [name] : []);
  }

  grantType(name) {
    log.debug("Entering AuthorizationRequest.grantType().");
    log.debug("Leaving AuthorizationRequest.grantType().");
    return this.environment(VOCABULARY.GRANT_TYPE, name ? [name] : []);
  }

  // The realm's mode (#305).
  mode(name) {
    log.debug("Entering AuthorizationRequest.mode().");
    log.debug("Leaving AuthorizationRequest.mode().");
    return this.environment(VOCABULARY.MODE, name ? [name] : []);
  }

  // One setting's value (#305): a boolean as a boolean, anything else as a
  // string.
  setting(key, value) {
    log.debug("Entering AuthorizationRequest.setting().");
    const typed = typeof value === 'boolean';
    log.debug("Leaving AuthorizationRequest.setting().");
    return this.environment(VOCABULARY.SETTING_PREFIX + key,
                            value === undefined || value === null ? []
                                                                  : [value],
                            typed ? model.TYPE.BOOLEAN : undefined);
  }

  // The stage a scope is judged at (#305).
  stage(name) {
    log.debug("Entering AuthorizationRequest.stage().");
    log.debug("Leaving AuthorizationRequest.stage().");
    return this.environment(VOCABULARY.SCOPE_STAGE, name ? [name] : []);
  }

  // The party acting between the subject and the resource (XACML 3.0's
  // intermediary-subject category) — a delegation's actor.
  intermediary(name) {
    log.debug("Entering AuthorizationRequest.intermediary().");
    log.debug("Leaving AuthorizationRequest.intermediary().");
    return this.attribute(model.CATEGORY.INTERMEDIARY_SUBJECT,
                          model.ATTRIBUTE.SUBJECT_ID, [name]);
  }

  // THE FACTS OF A TRANSFER QUESTION (#98), each only when known: an empty
  // home or serving jurisdiction and an unknown client country are left out
  // rather than sent as '', because the built-in rule reads "the same
  // jurisdiction" as the two bags sharing a member and an absent fact must
  // never make two cells look alike. `listed` is always sent — it is the
  // realm's own list, and false is a fact.
  transfer(facts) {
    log.debug("Entering AuthorizationRequest.transfer().");
    const given = facts || {};
    const one = function (value) {
      log.debug("Entering one().");
      log.debug("Leaving one().");
      return value ? [String(value)] : [];
    };
    this.subject(VOCABULARY.HOME_JURISDICTION, one(given.home));
    this.environment(VOCABULARY.SERVING_JURISDICTION, one(given.serving));
    this.environment(VOCABULARY.CLIENT_COUNTRY, one(given.clientCountry));
    this.environment(VOCABULARY.TRANSFER_LISTED, [!!given.listed],
                     model.TYPE.BOOLEAN);
    this.resource(VOCABULARY.DATA_CATEGORY, one(given.category));
    this.environment(VOCABULARY.REALM, one(given.realm));
    this.environment(VOCABULARY.PURPOSE, one(given.purpose));
    log.debug("Leaving AuthorizationRequest.transfer().");
    return this;
  }

  // THE FACTS OF AN EXCHANGE QUESTION (#186). `facts` (each optional):
  //   subject { id, kind, roles, notDelegated, groups, semantics,
  //             defaultSemantics }
  //   actor   { id, kind, registered, roles, semantics, defaultSemantics,
  //             delegatesTo, subjectGroups }
  //   source  { id, requiredRoles, delegatesTo }   (S; id '' when unknown)
  //   target  { id, count, registered, requiredRoles, accepts }   (R)
  //   requestedSemantics, semantics, mayActPresent, mayActNamesActor,
  //   protectedGroups
  //   (#430) subject.realm, actor.realm, target.realm — Kerberos realms —
  //   and trust { partner, type, direction, attributes, path, hops,
  //   enabled } for a question asked across a Kerberos trust, with
  //   localRealm, mechanism, actor.selfRealms and
  //   target.foreignTgtDelegation beside it; absent, none of them is sent
  // An unknown identifier is left out rather than sent as '', so no absent
  // party can ever compare equal to another. Booleans are always sent.
  exchange(facts) {
    const given = facts || {};
    const V = VOCABULARY;
    const I = model.CATEGORY.INTERMEDIARY_SUBJECT;
    const one = function (value) {
      return value ? [String(value)] : [];
    };
    const list = function (values) {
      return (values || []).map(String).filter(function (v) { return !!v; });
    };
    const subject = given.subject || {};
    const actor = given.actor || {};
    const source = given.source || {};
    const target = given.target || {};
    this.subject(model.ATTRIBUTE.SUBJECT_ID, one(subject.id));
    this.subject(V.SUBJECT_KIND, [subject.kind === 'application'
      ? 'application' : 'user']);
    this.subject(V.ROLE, list(subject.roles));
    this.subject(V.EXCHANGE_SUBJECT_NOT_DELEGATED, [!!subject.notDelegated],
                 model.TYPE.BOOLEAN);
    this.subject(V.EXCHANGE_SUBJECT_GROUP, list(subject.groups));
    this.subject(V.EXCHANGE_ALLOWED_SEMANTICS, list(subject.semantics));
    this.subject(V.EXCHANGE_DEFAULT_SEMANTICS, one(subject.defaultSemantics));
    this.subject(V.EXCHANGE_SUBJECT_DELEGATE, list(subject.delegates));
    this.attribute(I, model.ATTRIBUTE.SUBJECT_ID, one(actor.id));
    this.attribute(I, V.EXCHANGE_ACTOR_KIND, [actor.kind === 'user'
      ? 'user' : 'application']);
    this.attribute(I, V.EXCHANGE_ACTOR_REGISTERED, [!!actor.registered],
                   model.TYPE.BOOLEAN);
    this.attribute(I, V.ROLE, list(actor.roles));
    this.attribute(I, V.EXCHANGE_ALLOWED_SEMANTICS, list(actor.semantics));
    this.attribute(I, V.EXCHANGE_DEFAULT_SEMANTICS,
                   one(actor.defaultSemantics));
    this.attribute(I, V.EXCHANGE_ACTOR_DELEGATES_TO, list(actor.delegatesTo));
    this.attribute(I, V.EXCHANGE_ACTOR_SUBJECT_GROUP,
                   list(actor.subjectGroups));
    this.resource(model.ATTRIBUTE.RESOURCE_ID, one(target.id));
    this.resource(V.EXCHANGE_TARGET_COUNT, [Number(target.count) || 0],
                  model.TYPE.INTEGER);
    this.resource(V.EXCHANGE_TARGET_REGISTERED, [!!target.registered],
                  model.TYPE.BOOLEAN);
    this.resource(V.EXCHANGE_TARGET_REQUIRED_ROLE, list(target.requiredRoles));
    this.resource(V.EXCHANGE_TARGET_ACCEPTS, list(target.accepts));
    this.resource(V.EXCHANGE_SOURCE, one(source.id));
    this.resource(V.EXCHANGE_SOURCE_REQUIRED_ROLE,
                  list(source.requiredRoles));
    this.resource(V.EXCHANGE_SOURCE_DELEGATES_TO, list(source.delegatesTo));
    this.action(V.EXCHANGE_REQUESTED_SEMANTICS,
                one(given.requestedSemantics));
    this.action(V.EXCHANGE_SEMANTICS, one(given.semantics));
    this.environment(V.EXCHANGE_MAY_ACT_PRESENT, [!!given.mayActPresent],
                     model.TYPE.BOOLEAN);
    this.environment(V.EXCHANGE_MAY_ACT_NAMES_ACTOR,
                     [!!given.mayActNamesActor], model.TYPE.BOOLEAN);
    this.environment(V.EXCHANGE_PROTECTED_GROUP, list(given.protectedGroups));
    // #430: only when known, so a question that names no Kerberos realm is
    // the request it always was, attribute for attribute.
    if (subject.realm) {
      this.subject(V.EXCHANGE_SUBJECT_REALM, one(subject.realm));
    }
    if (actor.realm) {
      this.attribute(I, V.EXCHANGE_ACTOR_REALM, one(actor.realm));
    }
    if (target.realm) {
      this.resource(V.EXCHANGE_TARGET_REALM, one(target.realm));
    }
    const trust = given.trust || null;
    if (trust) {
      this.environment(V.EXCHANGE_TRUST_PARTNER, one(trust.partner));
      this.environment(V.EXCHANGE_TRUST_TYPE, one(trust.type));
      this.environment(V.EXCHANGE_TRUST_DIRECTION, one(trust.direction));
      this.environment(V.EXCHANGE_TRUST_ATTRIBUTE, list(trust.attributes));
      this.environment(V.EXCHANGE_TRUST_PATH, list(trust.path));
      this.environment(V.EXCHANGE_TRUST_HOPS, [Number(trust.hops) || 0],
                       model.TYPE.INTEGER);
      this.environment(V.EXCHANGE_TRUST_ENABLED, [trust.enabled !== false],
                       model.TYPE.BOOLEAN);
      this.environment(V.EXCHANGE_LOCAL_REALM, one(given.localRealm));
      this.action(V.EXCHANGE_MECHANISM, one(given.mechanism));
      this.attribute(I, V.EXCHANGE_ACTOR_SELF_REALM, list(actor.selfRealms));
      this.resource(V.EXCHANGE_TARGET_FOREIGN_TGT_DELEGATION,
                    one(target.foreignTgtDelegation));
    }
    // #1181: ONLY for a question asked over AuthZEN's token-exchange
    // binding (`authzen/authzen_exchange.ts`), so every local question is
    // the request it always was, attribute for attribute. `authzen`:
    //   caller, application   trusted, from the authenticated caller
    //   subjectType, actorType the two gate tuples' subject.type
    //   tokenType             the gate action's token type short name
    //   subjectTokenType, actorTokenType, actDepth
    //                         the binding's context, read by its fixed rules
    //   supplied, attributes  as `authzen()` takes them: the paths sent, and
    //                         the realm catalogue's rows for anything else
    const asked = given.authzen || null;
    if (asked) {
      this.subject(V.AUTHZEN_SUBJECT_TYPE, one(asked.subjectType));
      this.attribute(I, V.AUTHZEN_SUBJECT_TYPE, one(asked.actorType));
      this.action(V.AUTHZEN_TOKEN_TYPE, one(asked.tokenType));
      this.environment(V.AUTHZEN_CALLER, one(asked.caller));
      this.environment(V.AUTHZEN_APPLICATION, one(asked.application));
      this.environment(V.AUTHZEN_SUBJECT_TOKEN_TYPE,
                       one(asked.subjectTokenType));
      this.environment(V.AUTHZEN_ACTOR_TOKEN_TYPE, one(asked.actorTokenType));
      this.environment(V.AUTHZEN_ACT_DEPTH, [Number(asked.actDepth) || 0],
                       model.TYPE.INTEGER);
      this.environment(V.AUTHZEN_SUPPLIED, list(asked.supplied));
      const self = this;
      (Array.isArray(asked.attributes) ? asked.attributes : [])
        .forEach(function (row) {
          self.attribute(row.category, row.attributeId, row.values,
                         row.dataType);
        });
    }
    return this;
  }

  // THE FACTS OF A PASSKEY QUESTION (#536). `facts` (each optional):
  //   groups          the fact groups carried (see PASSKEY_FACTS)
  //   backupEligible  a boolean; sent only with `backup-eligible`
  //   minPinLength    a whole number; sent only with `pin-length`, and left
  //                   out when the key reported none
  //   serial, serialHeld                       with `serial`
  //   attestation { verified, trusted, aaguid, listed, compromised, rank,
  //                 fips, unchecked }          with `attestation`
  //   algorithm, postQuantum, lane            with `algorithm` (#718)
  //   attestationAlgorithm { verified, trusted, statement, certificates,
  //                          postQuantum }, attestationAlgorithmAllowed
  //                                            with `attestation-algorithm`
  //                                            (#941)
  //   upgrade { mode, previousAlgorithm }      with `upgrade` (#939)
  //   policy.attestationAlgorithms             always (#941), a bag
  //   profileAlgorithmOffered                  with `profile-algorithm`
  //                                            (#940)
  //   policy { registrationMode, registrationAlgorithmsFrom }, and
  //   policy.registrationAlgorithms, a bag     always (#940)
  //   enrolledByAdmin, enrolledBy              with `enrolment` (#945)
  //   policy.adminEnrolment                    always (#945)
  //   policy { backupEligibility, enforcePinLength, minPinLength,
  //            pinLengthOnlyIfSupported, enforceAttestationAtSignIn,
  //            enterpriseSerialAttribute, postQuantumRequired,
  //            postQuantumAllowCredentials (#946) }  always
  //   settings { attestationPolicy, allowedAaguids, requiredRank,
  //              requireFips }                 with `attestation`
  //   recovery { door, at, credential, selfService, covered, pending }
  //                                            with `recovery` (#724)
  //   policy.recoveryAssurance                 always (#724)
  // An empty string and an unknown value are left out, never sent as '', so
  // no rule reads an absent fact as a value.
  passkey(facts) {
    log.debug("Entering AuthorizationRequest.passkey().");
    const given = facts || {};
    const V = VOCABULARY;
    const T = model.TYPE;
    const groups = (given.groups || []).map(String);
    const has = function (group) {
      log.debug("Entering has().");
      log.debug("Leaving has().");
      return groups.indexOf(group) >= 0;
    };
    const whole = function (value) {
      log.debug("Entering whole().");
      log.debug("Leaving whole().");
      return typeof value === 'number' && Number.isInteger(value)
        ? [value] : [];
    };
    const one = function (value) {
      log.debug("Entering one().");
      log.debug("Leaving one().");
      return value === undefined || value === null || String(value) === ''
        ? [] : [String(value)];
    };
    this.environment(V.PASSKEY_FACTS, groups);
    if (has('backup-eligible') && typeof given.backupEligible === 'boolean') {
      this.resource(V.PASSKEY_BACKUP_ELIGIBLE, [given.backupEligible],
                    T.BOOLEAN);
    }
    if (has('pin-length')) {
      this.resource(V.PASSKEY_MIN_PIN_LENGTH, whole(given.minPinLength),
                    T.INTEGER);
    }
    if (has('serial')) {
      this.resource(V.PASSKEY_SERIAL, one(given.serial));
      this.resource(V.PASSKEY_SERIAL_HELD, [!!given.serialHeld], T.BOOLEAN);
    }
    const att = given.attestation || null;
    if (has('attestation') && att) {
      this.resource(V.PASSKEY_ATTESTATION_VERIFIED, [!!att.verified],
                    T.BOOLEAN);
      this.resource(V.PASSKEY_ATTESTATION_TRUSTED, [!!att.trusted],
                    T.BOOLEAN);
      this.resource(V.PASSKEY_AAGUID, one(att.aaguid));
      const flag = function (value) {
        log.debug("Entering flag().");
        log.debug("Leaving flag().");
        return typeof value === 'boolean' ? [value] : [];
      };
      this.resource(V.PASSKEY_MODEL_LISTED,
                    flag(att.listed), T.BOOLEAN);
      this.resource(V.PASSKEY_MODEL_COMPROMISED,
                    flag(att.compromised), T.BOOLEAN);
      this.resource(V.PASSKEY_CERTIFICATION_RANK, whole(att.rank), T.INTEGER);
      this.resource(V.PASSKEY_FIPS, flag(att.fips), T.BOOLEAN);
      this.resource(V.PASSKEY_METADATA_UNCHECKED, att.unchecked ? [true] : [],
                    T.BOOLEAN);
    }
    // THE KEY'S ALGORITHM (#718). `postQuantum` is sent as given, a
    // boolean, and false for anything else: the question computed it, and
    // a fact the rule reads as "not post-quantum" must never be absent, or
    // a requirement would let a key through by its silence.
    if (has('algorithm')) {
      this.resource(V.PASSKEY_ALGORITHM, one(given.algorithm));
      this.resource(V.PASSKEY_POST_QUANTUM, [given.postQuantum === true],
                    T.BOOLEAN);
      this.resource(V.PASSKEY_LANE, one(given.lane));
    }
    // WHAT THE ATTESTATION WAS SIGNED WITH (#941). The verdict is sent as
    // a boolean always with its group, false for anything but true, for
    // the post-quantum fact's reason: an absent "allowed" must never let a
    // key through by its silence.
    if (has('attestation-algorithm')) {
      const a = given.attestationAlgorithm || {};
      this.resource(V.PASSKEY_ATTESTATION_STATEMENT_ALGORITHM,
                    one(a.statement));
      this.resource(V.PASSKEY_ATTESTATION_CERTIFICATE_ALGORITHM,
                    (Array.isArray(a.certificates) ? a.certificates : [])
                      .map(String).filter(Boolean));
      this.resource(V.PASSKEY_ATTESTATION_POST_QUANTUM,
                    [a.postQuantum === true], T.BOOLEAN);
      if (!has('attestation')) {
        this.resource(V.PASSKEY_ATTESTATION_VERIFIED, [a.verified === true],
                      T.BOOLEAN);
        this.resource(V.PASSKEY_ATTESTATION_TRUSTED, [a.trusted === true],
                      T.BOOLEAN);
      }
      this.resource(V.PASSKEY_ATTESTATION_ALGORITHM_ALLOWED,
                    [given.attestationAlgorithmAllowed === true], T.BOOLEAN);
    }
    // AN UPGRADE (#939): true with its group, and what it does.
    if (has('upgrade')) {
      const u = given.upgrade || {};
      this.resource(V.PASSKEY_UPGRADE, [true], T.BOOLEAN);
      this.resource(V.PASSKEY_UPGRADE_MODE, one(u.mode));
      this.resource(V.PASSKEY_UPGRADE_PREVIOUS_ALGORITHM,
                    one(u.previousAlgorithm));
    }
    // WHETHER THE PROFILE OFFERS THE KEY'S ALGORITHM (#940), for the
    // post-quantum fact's reason: false for anything but true, so silence
    // never lets a key through.
    if (has('profile-algorithm')) {
      this.resource(V.PASSKEY_PROFILE_ALGORITHM_OFFERED,
                    [given.profileAlgorithmOffered === true], T.BOOLEAN);
    }
    // WHO ENROLLED IT (#945): an administrator. The boolean is sent as true
    // with its group, for a realm's own rule.
    if (has('enrolment')) {
      this.resource(V.PASSKEY_ENROLLED_BY_ADMIN,
                    [given.enrolledByAdmin === true], T.BOOLEAN);
      this.resource(V.PASSKEY_ENROLLED_BY, one(given.enrolledBy));
    }
    const policy = given.policy || {};
    const P = V.PASSKEY_POLICY_PREFIX;
    this.environment(P + 'backupEligibility', one(policy.backupEligibility));
    this.environment(P + 'enforcePinLength', [policy.enforcePinLength === true],
                     T.BOOLEAN);
    this.environment(P + 'minPinLength', whole(policy.minPinLength),
                     T.INTEGER);
    this.environment(P + 'pinLengthOnlyIfSupported',
                     [policy.pinLengthOnlyIfSupported === true], T.BOOLEAN);
    this.environment(P + 'enforceAttestationAtSignIn',
                     [policy.enforceAttestationAtSignIn === true], T.BOOLEAN);
    this.environment(P + 'enterpriseSerialAttribute',
                     one(policy.enterpriseSerialAttribute));
    this.environment(P + 'postQuantumRequired',
                     one(policy.postQuantumRequired));
    // HOW THE PASSKEY STEP NAMED THE KEYS (#946): `narrow` or
    // `list-and-refuse`, resolved from the realm's setting where the
    // profile's row is `realm`. Read by no built-in rule.
    this.environment(P + 'postQuantumAllowCredentials',
                     one(policy.postQuantumAllowCredentials));
    this.environment(P + 'recoveryAssurance', one(policy.recoveryAssurance));
    // #945: whether an administrator may enrol a passkey, `off` or `on`.
    this.environment(P + 'adminEnrolment', one(policy.adminEnrolment));
    this.environment(P + 'attestationAlgorithms',
                     (Array.isArray(policy.attestationAlgorithms)
                       ? policy.attestationAlgorithms : []).map(String));
    // A POPULATION'S REGISTRATION ALGORITHMS (#940): the profile's mode as
    // its row says it (`realm`, `pq-only`, `pq-first`, `classical-only`),
    // the algorithms a registration under it may make as resolved (the
    // realm's where the profile follows it), and whether those came from
    // the profile (`profile`) or the realm (`realm`) — the last is what the
    // built-in `profile-algorithm` rule is gated on.
    this.environment(P + 'registrationMode', one(policy.registrationMode));
    this.environment(P + 'registrationAlgorithms',
                     (Array.isArray(policy.registrationAlgorithms)
                       ? policy.registrationAlgorithms : []).map(String));
    this.environment(P + 'registrationAlgorithmsFrom',
                     one(policy.registrationAlgorithmsFrom));
    const recovery = given.recovery || null;
    if (has('recovery') && recovery) {
      this.resource(V.PASSKEY_RECOVERY_DOOR, one(recovery.door));
      this.resource(V.PASSKEY_RECOVERY_AT, one(recovery.at));
      this.resource(V.PASSKEY_RECOVERY_CREDENTIAL, one(recovery.credential));
      this.resource(V.PASSKEY_RECOVERY_SELF_SERVICE,
                    [recovery.selfService === true], T.BOOLEAN);
      this.resource(V.PASSKEY_RECOVERY_COVERED,
                    [recovery.covered === true], T.BOOLEAN);
      this.resource(V.PASSKEY_RECOVERY_PENDING,
                    [recovery.pending === true], T.BOOLEAN);
    }
    const settings = given.settings || null;
    if (has('attestation') && settings) {
      this.setting('webauthn.attestationPolicy',
                   String(settings.attestationPolicy || ''));
      this.environment(V.SETTING_PREFIX + 'webauthn.attestationAllowedAaguids',
                       (settings.allowedAaguids || []).map(String));
      this.environment(V.PASSKEY_REQUIRED_RANK,
                       Number(settings.requiredRank) > 0
                         ? [Number(settings.requiredRank)] : [], T.INTEGER);
      this.setting('webauthn.attestationRequireFips',
                   settings.requireFips === true);
    }
    log.debug("Leaving AuthorizationRequest.passkey().");
    return this;
  }

  // THE FACTS OF A GNAP ACCESS RIGHT (#432 phase 3). `facts` (each optional):
  //   right     { kind, type, actions, locations, datatypes, identifier,
  //               privileges, listed, referenceRegistered, protected,
  //               protectedDeclared, limits: { json, amount, currency,
  //               count, receivers, interval, notBefore, notAfter } }
  //   owner     { known, owner, source, unresolved, matches } (#432
  //               phase 5)
  //   catalogue { catalogued, owner, bearer (null when undeclared),
  //               maxLifetimeS (null when undeclared), acr, interaction,
  //               consentActions, derivableFrom, introspectionClaims }
  //   token     { label, bearer, format, targets }
  //   client    { id, class, hasAllowedAccess, bearerRefused }
  //   approver, approval
  //   session   { acr, amr }, risk { level, signals },
  //   device    { recognized, status, compliance, attestation, ownerMatches }
  // A fact that is not known is left out rather than sent empty, so a rule
  // reading it is inapplicable — `boolean-is-in` over an empty bag is false.
  // The resource-id, principal, action-id, mode, stage and settings are the
  // caller's, through the methods above.
  gnapRight(facts) {
    log.debug("Entering AuthorizationRequest.gnapRight().");
    const given = facts || {};
    const V = VOCABULARY;
    const B = model.TYPE.BOOLEAN;
    const one = function (value) {
      log.debug("Entering one().");
      log.debug("Leaving one().");
      return value ? [String(value)] : [];
    };
    const list = function (values) {
      log.debug("Entering list().");
      log.debug("Leaving list().");
      return (Array.isArray(values) ? values : []).map(String)
        .filter(function (v) { return !!v; });
    };
    const bool = function (value) {
      log.debug("Entering bool().");
      log.debug("Leaving bool().");
      return typeof value === 'boolean' ? [value] : [];
    };
    const right = given.right || {};
    const catalogue = given.catalogue || {};
    const token = given.token || {};
    const client = given.client || {};
    const session = given.session || {};
    const risk = given.risk || {};
    const device = given.device || {};
    this.resource(V.GNAP_RIGHT_KIND, one(right.kind));
    this.resource(V.GNAP_RIGHT_ACTION, list(right.actions));
    this.resource(V.GNAP_RIGHT_LOCATION, list(right.locations));
    this.resource(V.GNAP_RIGHT_DATATYPE, list(right.datatypes));
    this.resource(V.GNAP_RIGHT_IDENTIFIER, one(right.identifier));
    this.resource(V.GNAP_RIGHT_PRIVILEGE, list(right.privileges));
    this.resource(V.GNAP_RIGHT_LISTED, bool(right.listed), B);
    this.resource(V.GNAP_REFERENCE_REGISTERED,
                  bool(right.referenceRegistered), B);
    this.resource(V.GNAP_PROTECTED, bool(right.protected), B);
    this.resource(V.GNAP_PROTECTED_DECLARED, bool(right.protectedDeclared), B);
    const limits = right.limits || null;
    if (limits) {
      this.resource(V.GNAP_LIMITS, one(limits.json));
      this.resource(V.GNAP_LIMIT_AMOUNT, typeof limits.amount === 'number'
        ? [limits.amount] : [], model.TYPE.DOUBLE);
      this.resource(V.GNAP_LIMIT_CURRENCY, one(limits.currency));
      this.resource(V.GNAP_LIMIT_COUNT, typeof limits.count === 'number'
        ? [limits.count] : [], model.TYPE.INTEGER);
      this.resource(V.GNAP_LIMIT_RECEIVER, list(limits.receivers));
      this.resource(V.GNAP_LIMIT_INTERVAL, one(limits.interval));
      this.resource(V.GNAP_LIMIT_NOT_BEFORE, one(limits.notBefore));
      this.resource(V.GNAP_LIMIT_NOT_AFTER, one(limits.notAfter));
    }
    const owner = given.owner || {};
    this.resource(V.GNAP_OWNER_KNOWN, bool(owner.known), B);
    this.resource(V.GNAP_OWNER, one(owner.owner));
    this.resource(V.GNAP_OWNER_SOURCE, one(owner.source));
    this.resource(V.GNAP_OWNER_UNRESOLVED, bool(owner.unresolved), B);
    this.resource(V.GNAP_OWNER_MATCHES, bool(owner.matches), B);
    this.resource(V.GNAP_CATALOGUED, bool(catalogue.catalogued), B);
    this.resource(V.GNAP_TYPE_OWNER, one(catalogue.owner));
    this.resource(V.GNAP_TYPE_BEARER, bool(catalogue.bearer), B);
    this.resource(V.GNAP_TYPE_MAX_LIFETIME,
                  typeof catalogue.maxLifetimeS === 'number'
                    ? [catalogue.maxLifetimeS] : [], model.TYPE.INTEGER);
    this.resource(V.GNAP_TYPE_ACR, one(catalogue.acr));
    this.resource(V.GNAP_TYPE_INTERACTION, one(catalogue.interaction));
    this.resource(V.GNAP_TYPE_CONSENT_ACTION, list(catalogue.consentActions));
    this.resource(V.GNAP_TYPE_DERIVABLE_FROM, list(catalogue.derivableFrom));
    this.resource(V.GNAP_TYPE_INTROSPECTION_CLAIM,
                  list(catalogue.introspectionClaims));
    this.action(V.GNAP_TOKEN_LABEL, one(token.label));
    this.action(V.GNAP_TOKEN_BEARER, bool(token.bearer), B);
    this.action(V.GNAP_TOKEN_FORMAT, one(token.format));
    this.action(V.GNAP_TOKEN_TARGET, list(token.targets));
    this.subject(V.CLIENT_ID, one(client.id));
    this.subject(V.GNAP_CLIENT_CLASS, one(client.class));
    this.subject(V.GNAP_CLIENT_HAS_ALLOWED_ACCESS,
                 bool(client.hasAllowedAccess), B);
    this.subject(V.GNAP_CLIENT_BEARER_REFUSED, bool(client.bearerRefused), B);
    this.environment(V.GNAP_APPROVER, one(given.approver));
    this.environment(V.GNAP_APPROVAL, one(given.approval));
    this.environment(V.GNAP_SESSION_ACR, one(session.acr));
    this.environment(V.GNAP_SESSION_AMR, list(session.amr));
    this.environment(V.GNAP_RISK_LEVEL, one(risk.level));
    this.environment(V.GNAP_RISK_SIGNAL, list(risk.signals));
    this.environment(V.GNAP_DEVICE_RECOGNIZED, bool(device.recognized), B);
    this.environment(V.GNAP_DEVICE_STATUS, one(device.status));
    this.environment(V.GNAP_DEVICE_COMPLIANCE, one(device.compliance));
    this.environment(V.GNAP_DEVICE_ATTESTATION, one(device.attestation));
    this.environment(V.GNAP_DEVICE_OWNER_MATCHES, bool(device.ownerMatches),
                     B);
    log.debug("Leaving AuthorizationRequest.gnapRight().");
    return this;
  }

  // THE FACTS OF AN AUTHZEN QUESTION (#563). `facts`:
  //   subject { type, id }, action { name }, resource { type, id }
  //                       the four AuthZEN requires, already validated
  //   realm, caller, application
  //                       trusted, from the authenticated caller
  //   supplied            the paths of every member the caller sent
  //   approval            a VERIFIED approval (#1180), { approvalId,
  //                       approvedUntil, approver }, or null
  //   attributes          [{ category, attributeId, dataType, values }],
  //                       each a catalogue row's, the values lexical
  // The subject's id is XACML's own subject-id, the action's name its
  // action-id and the resource's id its resource-id; everything else in the
  // body reaches the request only through the catalogue
  // (`authzen/authzen_map.ts`). An unknown application is left out rather
  // than sent as '', so no rule reads an absent one as a value.
  authzen(facts) {
    log.debug("Entering AuthorizationRequest.authzen().");
    const given = facts || {};
    const V = VOCABULARY;
    const one = function (value) {
      log.debug("Entering one().");
      log.debug("Leaving one().");
      return value ? [String(value)] : [];
    };
    const subject = given.subject || {};
    const action = given.action || {};
    const resource = given.resource || {};
    this.principal(subject.id);
    this.subject(V.AUTHZEN_SUBJECT_TYPE, one(subject.type));
    this.requestedAction(action.name);
    this.target(resource.id);
    this.resource(V.AUTHZEN_RESOURCE_TYPE, one(resource.type));
    this.protocol('authzen');
    this.environment(V.REALM, one(given.realm));
    this.environment(V.AUTHZEN_CALLER, one(given.caller));
    this.environment(V.AUTHZEN_APPLICATION, one(given.application));
    this.environment(V.AUTHZEN_SUPPLIED,
                     (Array.isArray(given.supplied) ? given.supplied : [])
                       .map(String));
    const approval = given.approval || null;
    if (approval && approval.approvalId) {
      this.environment(V.AUTHZEN_APPROVAL_ID, one(approval.approvalId));
      this.environment(V.AUTHZEN_APPROVED_UNTIL, one(approval.approvedUntil),
                       model.TYPE.DATETIME);
      this.environment(V.AUTHZEN_APPROVER, one(approval.approver));
    }
    const self = this;
    (Array.isArray(given.attributes) ? given.attributes : [])
      .forEach(function (row) {
        self.attribute(row.category, row.attributeId, row.values,
                       row.dataType);
      });
    log.debug("Leaving AuthorizationRequest.authzen().");
    return this;
  }

  // THE FACTS OF A FINE-GRAINED AUTHORIZATION QUESTION (#564). `facts`:
  //   realm, protocol      trusted; the protocol `oauth2` unless named
  //   subject { id, kind } the principal and principal_type; BOTH left out
  //                        when there is no id (the PAR endpoint, before
  //                        anybody signed in — #564's P4)
  //   clientId             the OAuth client the detail came through
  //   application          the identifier of the application that owns
  //                        the detail's type
  //   detailType, definitionDigest
  //   stage                one of FGA_STAGES
  //   action               the action-id; at an ISSUANCE stage it is
  //                        always FGA_GRANT_ACTION, whatever is given, so
  //                        no caller can ask an issuance question as
  //                        anything else
  //   resourceId           the resource-id; the detail's type unless given
  //                        (AuthZEN's resource.id at `access`)
  //   grantType            the OAuth grant, where there is one
  //   supplied             every member path that reached the request
  //   attributes           [{ category, attributeId, dataType, values }] —
  //                        the built-in common-field rows' and the type's
  //                        `xacml` rows', the values lexical
  // Everything but `attributes` and `supplied` is the adapter's own
  // knowledge (`xacml/fga_map.ts`), never the detail's; the rows cannot name
  // any of it, because every identifier above is in `urn:sts:xacml:` or is
  // XACML's own, and the row grammar refuses both
  // (`xacml_attribute_rows.ts`). A fact not known is left out rather than
  // sent as '', so no rule reads an absent one as a value.
  fga(facts) {
    log.debug("Entering AuthorizationRequest.fga().");
    const given = facts || {};
    const V = VOCABULARY;
    const one = function (value) {
      log.debug("Entering one().");
      log.debug("Leaving one().");
      return value ? [String(value)] : [];
    };
    const subject = given.subject || {};
    const stage = String(given.stage || '');
    const issuance = FGA_ISSUANCE_STAGES.indexOf(stage) >= 0;
    // NOBODY IS NOT A SUBJECT CALLED ''. `principal()` writes '' for an
    // absent name, which is how several PEPs say "nobody" to a policy that
    // expects it; a fine-grained policy is written by an application's
    // administrator, who would read `subject-id == ""` as a person with an
    // empty name — or, worse, a rule comparing it to a list would simply not
    // match and fall through. So with no id there is NO subject-id and no
    // subject kind at all: an empty bag, which a policy tests as absence
    // (a designator with MustBePresent, or `stringBagSize(...) == 0`). The
    // client is still a fact, and stays.
    if (subject.id !== undefined && subject.id !== null &&
        String(subject.id) !== '') {
      this.principal(subject.id, subject.kind);
    }
    this.client(given.clientId);
    const action = issuance ? FGA_GRANT_ACTION : String(given.action || '');
    if (action) {
      this.requestedAction(action);
    }
    this.target(given.resourceId || given.detailType || '');
    this.resource(V.FGA_APPLICATION, one(given.application));
    this.resource(V.FGA_DETAIL_TYPE, one(given.detailType));
    this.resource(V.FGA_DEFINITION_DIGEST, one(given.definitionDigest));
    this.protocol(given.protocol || 'oauth2');
    this.environment(V.REALM, one(given.realm));
    this.environment(V.FGA_STAGE, one(stage));
    if (given.grantType) {
      this.grantType(given.grantType);
    }
    this.environment(V.FGA_SUPPLIED,
                     (Array.isArray(given.supplied) ? given.supplied : [])
                       .map(String));
    const self = this;
    (Array.isArray(given.attributes) ? given.attributes : [])
      .forEach(function (row) {
        self.attribute(row.category, row.attributeId, row.values,
                       row.dataType);
      });
    log.debug("Leaving AuthorizationRequest.fga().");
    return this;
  }

  // AN AUTHZEN QUESTION DECIDED BY AN APPLICATION'S FINE-GRAINED POLICY
  // (#564, P4). Chained after `authzen()`, which has written the question
  // as AuthZEN always does — subject, action, resource, the catalogue's rows
  // and AuthZEN's trusted facts, `protocol = authzen` among them — and adds
  // the two facts an FGA policy reads to know what it is being asked:
  //   application   the identifier of the application whose policy decides
  //                 (resource, `urn:sts:xacml:fga:application`, as `fga()`
  //                 writes it, so one target matches both questions)
  //   stage         always `access`, whatever is given: this is the
  //                 per-request question, never an issuance one
  // Nothing else: the subject, action and resource are AuthZEN's, already
  // written, and writing them again would make a bag of two.
  fgaAccess(facts) {
    log.debug("Entering AuthorizationRequest.fgaAccess().");
    const given = facts || {};
    const V = VOCABULARY;
    this.resource(V.FGA_APPLICATION,
                  given.application ? [String(given.application)] : []);
    this.environment(V.FGA_STAGE, ['access']);
    log.debug("Leaving AuthorizationRequest.fgaAccess().");
    return this;
  }

  // THE FACTS OF A USER-MANAGED ACCESS QUESTION (#1168): one resource, one
  // scope, one layer. `facts`:
  //   realm                trusted
  //   layer                one of UMA_LAYERS; anything else is `realm`
  //   stage                one of UMA_STAGES; anything else is `assess`
  //   resource { id, type, resourceServer, resourceServerDeclared, owner,
  //              ownerKind }
  //                        the registration's facts, from the store and the
  //                        PAT that made it — never the client's
  //   scope                the one scope being asked about
  //   requestingParty { id, kind, known, isOwner, claimSource, claimIssuer,
  //                     claimIssuerDeclared, acr, groups }
  //                        who is asking, once anybody is known. With no id
  //                        there is NO subject-id and no subject kind at all
  //                        (`fga()`'s rule): the built-in rule that requires
  //                        one then reaches a missing attribute, which the
  //                        PEP answers as `need_info`
  //   clientId, clientGrantDeclared
  //                        the OAuth client presenting the ticket, and
  //                        whether it registered the UMA grant type
  //   claims { name: [values] }
  //                        the gathered claims, each VERIFIED, under
  //                        UMA_CLAIM_PREFIX
  //   ticketAgeS, rptPresented
  //   mode, settings { key: value }
  //                        as every issuance question carries them
  // The action-id is forced by the layer (UMA_LAYERS above), so no caller can
  // ask the realm's or the resource server's policy as anything else; the
  // scope is `urn:sts:xacml:uma:scope` on every layer as well. A fact not
  // known is left out rather than sent as '', so no rule reads an absent one
  // as a value; the booleans are always sent, false for anything but true.
  uma(facts) {
    log.debug("Entering AuthorizationRequest.uma().");
    const given = facts || {};
    const V = VOCABULARY;
    const one = function (value) {
      log.debug("Entering one().");
      log.debug("Leaving one().");
      return value === undefined || value === null || value === ''
        ? [] : [String(value)];
    };
    const yes = function (value) {
      log.debug("Entering yes().");
      log.debug("Leaving yes().");
      return [value === true ? 'true' : 'false'];
    };
    const layer = UMA_LAYERS.indexOf(String(given.layer)) >= 0
      ? String(given.layer) : 'realm';
    const stage = UMA_STAGES.indexOf(String(given.stage)) >= 0
      ? String(given.stage) : 'assess';
    const resource = given.resource || {};
    const party = given.requestingParty || {};
    const scope = String(given.scope || '');
    // NOBODY IS NOT A SUBJECT CALLED '' — `fga()` argues it. The attribute is
    // absent until somebody is known, which is what lets a MustBePresent
    // designator on subject-id turn into the missing-attribute status the
    // PEP reads as "ask the requesting party for claims".
    if (party.id !== undefined && party.id !== null &&
        String(party.id) !== '') {
      this.principal(party.id, party.kind);
    }
    this.client(given.clientId);
    this.subject(V.UMA_REQUESTING_PARTY_KNOWN, yes(party.known),
                 model.TYPE.BOOLEAN);
    this.subject(V.UMA_REQUESTING_PARTY_IS_OWNER, yes(party.isOwner),
                 model.TYPE.BOOLEAN);
    this.subject(V.UMA_CLAIM_SOURCE,
                 UMA_CLAIM_SOURCES.indexOf(String(party.claimSource)) >= 0
                   ? [String(party.claimSource)] : []);
    this.subject(V.UMA_CLAIM_ISSUER, one(party.claimIssuer));
    this.subject(V.UMA_CLAIM_ISSUER_DECLARED,
                 yes(party.claimIssuerDeclared !== false),
                 model.TYPE.BOOLEAN);
    this.subject(V.UMA_CLIENT_GRANT_DECLARED,
                 yes(given.clientGrantDeclared), model.TYPE.BOOLEAN);
    this.subject(V.ACR, one(party.acr));
    this.subject(V.UMA_REQUESTING_PARTY_GROUP,
                 (Array.isArray(party.groups) ? party.groups : [])
                   .map(String).filter(Boolean));
    const self = this;
    const claims = given.claims && typeof given.claims === 'object'
      ? given.claims : {};
    Object.keys(claims).sort().forEach(function (name) {
      const values = Array.isArray(claims[name]) ? claims[name]
        : [claims[name]];
      self.subject(V.UMA_CLAIM_PREFIX + name,
                   values.filter(function (value) {
                     return value !== undefined && value !== null;
                   }).map(String));
    });
    const action = layer === 'owner' ? scope
      : (layer === 'fga' ? UMA_FGA_ACTION : UMA_PERMISSION_ACTION);
    if (action) {
      this.requestedAction(action);
    }
    this.action(V.UMA_SCOPE, one(scope));
    this.target(String(resource.id || ''));
    this.resource(V.UMA_RESOURCE_TYPE, one(resource.type));
    this.resource(V.UMA_RESOURCE_SERVER, one(resource.resourceServer));
    this.resource(V.UMA_RESOURCE_SERVER_DECLARED,
                  yes(resource.resourceServerDeclared), model.TYPE.BOOLEAN);
    this.resource(V.UMA_OWNER, one(resource.owner));
    this.resource(V.UMA_OWNER_KIND,
                  SUBJECT_KINDS.indexOf(String(resource.ownerKind)) >= 0
                    ? [String(resource.ownerKind)] : []);
    this.protocol('uma');
    this.grantType(UMA_GRANT_TYPE);
    this.environment(V.REALM, one(given.realm));
    this.environment(V.UMA_LAYER, [layer]);
    this.environment(V.UMA_STAGE, [stage]);
    const age = Number(given.ticketAgeS);
    this.environment(V.UMA_TICKET_AGE,
                     Number.isFinite(age) && age >= 0
                       ? [String(Math.floor(age))] : [],
                     model.TYPE.INTEGER);
    this.environment(V.UMA_RPT_PRESENTED, yes(given.rptPresented),
                     model.TYPE.BOOLEAN);
    if (given.mode) {
      this.mode(given.mode);
    }
    const settings = given.settings && typeof given.settings === 'object'
      ? given.settings : {};
    Object.keys(settings).sort().forEach(function (key) {
      self.setting(key, settings[key]);
    });
    log.debug("Leaving AuthorizationRequest.uma(). layer=" + layer);
    return this;
  }

  // The request, in the engine's shape (`xacml_model.js`).
  build() {
    log.debug("Entering AuthorizationRequest.build().");
    const out = {
      returnPolicyIdList: this.returnPolicyIdList,
      combinedDecision: false,
      categories: this.categories.map(function (one) {
        return { category: one.category, id: null, content: null,
                 attributes: one.attributes.slice(0) };
      })
    };
    log.debug("Leaving AuthorizationRequest.build(). " +
              out.categories.length + " categories.");
    return out;
  }
}

module.exports = {
  AuthorizationRequest: AuthorizationRequest,
  VOCABULARY: VOCABULARY,
  SUBJECT_KINDS: SUBJECT_KINDS,
  FGA_STAGES: FGA_STAGES,
  FGA_ISSUANCE_STAGES: FGA_ISSUANCE_STAGES,
  FGA_GRANT_ACTION: FGA_GRANT_ACTION,
  UMA_LAYERS: UMA_LAYERS,
  UMA_STAGES: UMA_STAGES,
  UMA_PERMISSION_ACTION: UMA_PERMISSION_ACTION,
  UMA_FGA_ACTION: UMA_FGA_ACTION,
  UMA_GRANT_TYPE: UMA_GRANT_TYPE,
  UMA_CLAIM_SOURCES: UMA_CLAIM_SOURCES
};
