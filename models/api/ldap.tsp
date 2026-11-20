// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/api/ldap.tsp
//
// LDAP (RFC 4511): seven operations and a limits document. The protocol is
// BER over a TCP socket, so the whole of it lives in api/ldap_client.js and
// the page never touches a socket. See docs/v0.9.6/ldap.md.
//
// THE THREE OUTCOMES, which every answer below keeps apart:
//
// * 400 — this service refused: a scheme that is not ldap(s), a port that is
//   not allowed, a blocked address, an operation missing its DN.
// * 502 — the directory could not be reached: nothing listening, a name that
//   does not resolve, a timeout.
// * 200 — the directory ANSWERED, and `ok: false` with a result code is an
//   answer, not a failure: `noSuchObject`, `invalidCredentials`,
//   `entryAlreadyExists` are the most useful things a directory says.
//
// WHERE THE CHECKS ARE. The schema holds the JSON shape and `url`'s
// presence, which the route itself used to check. Everything about a
// value — an empty DN, the URL's scheme and port, the scope's spelling,
// the address — is api/ldap_client.js's, which is also a library other code
// calls, and each such member says so with @checkedInCode.

import "@typespec/http";
import "@typespec/openapi";
import "../lib/debugger_lib.tsp";
import "./common.tsp";

using Http;
using OpenAPI;
using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Api.Ldap;

// ---------------------------------------------------------------------------
// Requests.
// ---------------------------------------------------------------------------

/** The connection and the simple bind every operation starts with. */
model Connection {
  /** ldap:// or ldaps:// URL of the directory server. */
  @refusal(#{
    message: "url is required, and must be an ldap:// or ldaps:// URL naming the directory server."
  })
  @checkedInCode("api/ldap_client.js: the scheme is ldap or ldaps (ELDAPBADURL), the port is in ldapAllowedPorts (ELDAPPORTNOTALLOWED), the address passes the address policy (EBLOCKEDADDRESS)")
  @minLength(1)
  url: string;

  /** The bind DN. Absent, null or empty is an anonymous bind. */
  @passthrough
  bindDn?: string | null;

  /** The simple-bind password. Never echoed; its length is. */
  @passthrough
  password?: string | null;

  /** Only an explicit false turns off certificate verification on ldaps. */
  rejectUnauthorized?: boolean | null;
}

/** A search (RFC 4511 section 4.5). */
model SearchRequest {
  ...Connection;

  /** The search base. Empty is the root DSE. */
  @passthrough
  baseDn?: string | null;

  /** base, one or sub, any case. Absent is sub. */
  @checkedInCode("api/ldap_client.js: base, one or sub, compared case-insensitively (ELDAPBADSCOPE)")
  scope?: string | null;

  /** An RFC 4515 filter, sent as written. Absent is (objectClass=*). */
  @passthrough
  filter?: string | null;

  /** The attributes to return. Empty is all user attributes. */
  @passthrough
  attributes?: unknown[] | null;

  /** The client's own cap on entries, below ldapMaxEntries. */
  @checkedInCode("api/ldap_client.js: parsed as an integer; anything not a positive integer means ldapMaxEntries")
  sizeLimit?: int64 | string | null;
}

/** An add (RFC 4511 section 4.7). */
model AddRequest {
  ...Connection;

  /** The DN of the entry to create. */
  @checkedInCode("api/ldap_client.js: an empty DN is refused (ELDAPNODN)")
  @passthrough
  dn?: string | null;

  /** Attribute name to a value or an array of values, each sent as text. */
  @checkedInCode("api/ldap_client.js: at least one attribute (ELDAPNOATTRIBUTES)")
  @passthrough
  attributes?: Record<unknown> | null;
}

/** A delete (RFC 4511 section 4.8). */
model DeleteRequest {
  ...Connection;

  /** The DN of the entry to remove. */
  @checkedInCode("api/ldap_client.js: an empty DN is refused (ELDAPNODN)")
  @passthrough
  dn?: string | null;
}

/** One change of a modify. */
model Change {
  /** add, delete or replace, any case. */
  @checkedInCode("api/ldap_client.js: add, delete or replace (ELDAPBADCHANGE)")
  operation?: string | null;

  /** The attribute changed. */
  @checkedInCode("api/ldap_client.js: required (ELDAPBADCHANGE)")
  @passthrough
  type?: string | null;

  /** A value or an array of values, each sent as text. */
  @passthrough
  values?: unknown;
}

/** A modify (RFC 4511 section 4.6), which is also how membership changes. */
model ModifyRequest {
  ...Connection;

  /** The DN of the entry to change. */
  @checkedInCode("api/ldap_client.js: an empty DN is refused (ELDAPNODN)")
  @passthrough
  dn?: string | null;

  /** The changes, applied in order. */
  @checkedInCode("api/ldap_client.js: at least one (ELDAPNOCHANGES); each is checked as Change says")
  @passthrough
  changes?: unknown;
}

/** A modifyDN (RFC 4511 section 4.9): a rename, or a move as well. */
model ModifyDnRequest {
  ...Connection;

  /** The DN of the entry to rename. */
  @checkedInCode("api/ldap_client.js: dn and newRdn are both required (ELDAPNODN)")
  @passthrough
  dn?: string | null;

  /** Its new relative DN. */
  @checkedInCode("api/ldap_client.js: dn and newRdn are both required (ELDAPNODN)")
  @passthrough
  newRdn?: string | null;

  /** A new parent DN, to move the entry as well. */
  @passthrough
  newSuperior?: string | null;
}

/** A compare (RFC 4511 section 4.10). */
model CompareRequest {
  ...Connection;

  /** The DN of the entry. */
  @checkedInCode("api/ldap_client.js: dn and attribute are both required (ELDAPNODN)")
  @passthrough
  dn?: string | null;

  /** The attribute compared. */
  @checkedInCode("api/ldap_client.js: dn and attribute are both required (ELDAPNODN)")
  @passthrough
  attribute?: string | null;

  /** The value it is compared against. */
  @passthrough
  value?: unknown;
}

// ---------------------------------------------------------------------------
// Answers.
// ---------------------------------------------------------------------------

/** An LDAP result code, with ldapjs's name for it. */
model ResultCode {
  code: int32 | null;
  name: string;
}

/** Where the connection went. */
model Target {
  url: string;
  host: string;
  address: string;
  port: int32;
  secure: boolean;
  resolved: boolean;
}

/** The bind that preceded the operation. The password is never echoed. */
model BindReport {
  dn: string;
  anonymous: boolean;
  passwordChars: int32;
  result: ResultCode | null;
}

/** Split rather than summed: a slow connect is the network, a slow bind is
 *  the directory deciding. */
model Timing {
  totalMs: int64;
  connectMs: int64 | null;
  bindMs: int64 | null;
}

/** One entry of a search, flattened: each attribute's values as text. */
model Entry {
  dn: string;
  attributes: Record<string[]>;
}

/**
 * What the directory said. `ok` is false for every result code but success
 * (and, for a compare, compareTrue and compareFalse, which are both answers);
 * `stoppedAt: "bind"` says the bind was refused and nothing followed it.
 */
model Answer {
  operation: "bind" | "search" | "add" | "delete" | "modify" | "modifyDN" |
    "compare";
  ok: boolean;
  result: ResultCode | null;
  diagnosticMessage: string;
  target: Target;
  bind: BindReport;
  timing: Timing;

  /** What was sent, as this service understood it. */
  request?: Record<unknown>;

  stoppedAt?: "bind";
  operationMs?: int64;

  // Search only.
  entries?: Entry[];
  entryCount?: int32;
  truncated?: string | null;

  // Compare only.
  matched?: boolean | null;
}

/** A refusal or a network failure. `code` names which (ELDAP...). */
model Failure {
  error: string;
  code?: string | null;
}

/** What the LDAP client will and will not do. */
model Limits {
  /** The ports a URL may name, or "any". */
  allowedPorts: int32[] | "any";

  addressPolicyEnabled: boolean;
  schemes: string[];
  scopes: string[];
  modifyOperations: string[];

  /** A referral is recorded, never followed. */
  followsReferrals: false;

  startTls: false;
  saslMechanisms: string[];
  limits: {
    connectTimeout: int64;
    callTimeout: int64;
    maxResultBytes: int64;
    maxEntries: int64;
  };
}

alias Answers = Ok<Answer> |
  BadRequest<Failure | IdProtoDebugger.Api.ModelRefusal> |
  BadGateway<Failure>;

// ---------------------------------------------------------------------------
// Operations.
// ---------------------------------------------------------------------------

/** Bind to a directory: the authentication exchange, on its own. */
@tag("LDAP")
@route("/ldap/bind")
@post
@operationId("ldapBind")
op bind(@body body: Connection): Answers;

/** Search a directory. */
@tag("LDAP")
@route("/ldap/search")
@post
@operationId("ldapSearch")
op search(@body body: SearchRequest): Answers;

/** Add an entry: a user, a group, a container. */
@tag("LDAP")
@route("/ldap/add")
@post
@operationId("ldapAdd")
op add(@body body: AddRequest): Answers;

/** Delete an entry. */
@tag("LDAP")
@route("/ldap/delete")
@post
@operationId("ldapDelete")
op delete(@body body: DeleteRequest): Answers;

/** Modify an entry's attributes. */
@tag("LDAP")
@route("/ldap/modify")
@post
@operationId("ldapModify")
op modify(@body body: ModifyRequest): Answers;

/** Rename or move an entry. */
@tag("LDAP")
@route("/ldap/modifydn")
@post
@operationId("ldapModifyDn")
op modifyDn(@body body: ModifyDnRequest): Answers;

/** Compare an attribute value without reading the entry. compareTrue (6)
 *  and compareFalse (5) are both answers. */
@tag("LDAP")
@route("/ldap/compare")
@post
@operationId("ldapCompare")
op compare(@body body: CompareRequest): Answers;

/**
 * What the LDAP client will and will not do, so the page can say so before
 * a call fails. A build without LDAP answers 404 here.
 */
@tag("LDAP")
@route("/ldap/limits")
@get
@operationId("ldapLimits")
op limits(): Ok<Limits>;
