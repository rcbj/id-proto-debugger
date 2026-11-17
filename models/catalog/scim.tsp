// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/catalog/scim.tsp
//
// SCIM 2.0's CATALOGUES: the rows client/src/scim_client.js and
// client/src/scim_scenarios.js read, written here once as typed consts.
// This is this project's reading of RFC 7643 and RFC 7644, written from those
// documents. Nothing here reads or copies iya-sts's SCIM code or models.
//
// What stayed in the modules is CODE: the digest algorithm table (each row
// carries the hash FUNCTION), and each scenario's `build()` — the scenario
// rows here are its data, and scim_scenarios.js attaches the builder by id.
//
// The strings are single literals on purpose: TypeSpec has no concatenation,
// and a triple-quoted string keeps its newlines, which the page would show.

namespace IdProtoDebugger.Catalog;

// ---------------------------------------------------------------------------
// RFC 7644 section 3.12, Table 9: the scimType error codes.
// ---------------------------------------------------------------------------

/**
 * Every `scimType` RFC 7644 section 3.12 defines, each with what it means to
 * somebody reading it off the page. CLOSED: a server may not invent one, so a
 * member this model lacks is a compile error rather than an eleventh code.
 */
model ScimErrorTypes {
  invalidFilter: string;
  tooMany: string;
  uniqueness: string;
  mutability: string;
  invalidSyntax: string;
  invalidPath: string;
  noTarget: string;
  invalidValue: string;
  invalidVers: string;
  sensitive: string;
}

// ---------------------------------------------------------------------------
// RFC 7644 section 2: the authentication schemes.
// ---------------------------------------------------------------------------

/** This page's own name for each of the section 2 schemes, plus `none`. */
union ScimAuthSchemeId {
  "none", "bearer", "dpop", "basic", "digest", "hoba", "cookie", "clientcert",
}

/**
 * The `type` a ServiceProviderConfig's `authenticationSchemes` entry carries
 * for the scheme (RFC 7643 section 5 names oauth, oauth2, oauthbearertoken,
 * httpbasic and httpdigest; the other three follow its pattern). Empty for
 * `none`, which no server advertises.
 */
union ScimAuthSchemeType {
  "", "oauthbearertoken", "oauth2", "httpbasic", "httpdigest", "hoba",
  "httpcookie", "tlsclientauth",
}

/** One authentication scheme the SCIM page can apply. */
model ScimAuthScheme {
  id: ScimAuthSchemeId;
  label: string;
  type: ScimAuthSchemeType;
  /** The document that defines the scheme. */
  spec: string;
  /** False when nothing goes in an Authorization header (cookie, cert). */
  sendsCredential: boolean;
  /** True when a per-request signature or digest has to be computed. */
  needsProof: boolean;
  /** True when the credential carries an OAuth scope. */
  scoped: boolean;
  /** Usable on the browser path. */
  browser: boolean;
  /** Usable on the api path. */
  backend: boolean;
  what: string;
}

// ---------------------------------------------------------------------------
// RFC 7644 sections 3.2 through 3.12, and section 4: the endpoints.
// ---------------------------------------------------------------------------

/** The section 3.4.2 query parameters. */
union ScimQueryParameter {
  "filter", "sortBy", "sortOrder", "startIndex", "count", "attributes",
  "excludedAttributes",
}

/** The page's grouping of the operations. */
union ScimOperationGroup {
  "discovery", "user", "group", "query",
}

/** The HTTP methods RFC 7644 uses. */
union ScimMethod {
  "GET", "POST", "PUT", "PATCH", "DELETE",
}

/** The scope this page predicts an operation needs. */
union ScimScopeNeed {
  "none", "read", "write",
}

/** What the request body is, or null for none. */
union ScimBodyKind {
  "User", "Group", "SearchRequest", "PatchOp", "BulkRequest",
}

/** One SCIM endpoint operation. */
model ScimOperation {
  id: string;
  label: string;
  group: ScimOperationGroup;
  /** The resource type the operation acts on, when it acts on one. */
  resourceType?: "User" | "Group";
  method: ScimMethod;
  /** Relative to the base URL; `{id}` is substituted. */
  path: string;
  need: ScimScopeNeed;
  body: ScimBodyKind | null;
  /** The query parameters the operation accepts, in the editor's order. */
  query: ScimQueryParameter[];
  /** The label of the `{id}` field, when the path has one that is a name. */
  idLabel?: string;
  /** An example `{id}`, when the path has one that is a name. */
  idExample?: string;
  /** The section that defines the operation. */
  section: string;
  what: string;
}

// ---------------------------------------------------------------------------
// The generator's vocabulary.
// ---------------------------------------------------------------------------

/**
 * The words randomUser() and randomGroup() draw from. Each list is drawn
 * from by index with the seeded generator, so ORDER IS PART OF THE DATA: a
 * reordered list names different people for the same seed.
 */
model ScimUserVocabulary {
  givenNames: string[];
  familyNames: string[];
  honorificPrefixes: string[];
  honorificSuffixes: string[];
  titles: string[];
  userTypes: string[];
  departments: string[];
  divisions: string[];
  organizations: string[];
  costCenters: string[];
  locales: string[];
  languages: string[];
  timezones: string[];
  streets: string[];
  localities: string[];
  regions: string[];
  countries: string[];
  /** RFC 7643 section 4.1.2's canonical `ims` types. */
  imTypes: string[];
  /** RFC 7643 section 4.1.2's canonical `photos` types. */
  photoTypes: string[];
  groupNouns: string[];
}

// ---------------------------------------------------------------------------
// The scenario harness (client/src/scim_scenarios.js).
// ---------------------------------------------------------------------------

/** The section 3.4.2.2 filter forms the tour sends. */
union ScimFilterTourOp {
  "eq", "ne", "co", "sw", "ew", "pr", "gt", "ge", "lt", "le", "and", "or",
  "not", "complex",
}

/** One filter in the tour. */
model ScimFilterTourRow {
  `op`: ScimFilterTourOp;
  /** A template: {userName}, {family}, {tag} and {prefix} are substituted. */
  filter: string;
  /** Whether the user just created should be in the result. */
  expectMatch: boolean;
  what: string;
}

/** The settings a scenario reads, which are the controls the page shows. */
union ScimScenarioSetting {
  "seed", "prefix", "userCount", "groupCount",
}

/** One scenario's definition; its `build()` stays in the module. */
model ScimScenario {
  id: string;
  label: string;
  takes: ScimScenarioSetting[];
  /** Whether the scenario writes to the server. */
  writes: boolean;
  /** Whether it needs a server with authentication turned on. */
  needsAuth?: boolean;
  what: string;
}

/** One phase a random scenario may draw, by scenario id, with its weight. */
model ScimRandomPhase {
  id: string;
  weight: int32;
}

/**
 * RFC 7644 section 3.12's error codes. `scimType` is the single most useful
 * thing in a SCIM error, because the HTTP status alone cannot tell
 * `uniqueness` (this userName is taken) from `invalidValue` (this userName
 * is not allowed). Both are 400 on many servers.
 */
const SCIM_ERROR_TYPES: ScimErrorTypes = #{
  invalidFilter: "The filter is not valid section 3.4.2.2 grammar, or asks for something this server cannot evaluate.",
  tooMany: "The filter matched more than the server is willing to return. Narrow it or page it.",
  uniqueness: "A value that has to be unique is already somebody else's — on a User that is almost always userName.",
  mutability: "A read-only attribute was written, or an immutable one was changed after it was set.",
  invalidSyntax: "The body is not the structure this operation expects — a missing or wrong \"schemas\" member is the usual cause.",
  invalidPath: "The PATCH \"path\" is not valid section 3.5.2 path grammar.",
  noTarget: "The PATCH path is valid grammar but names nothing on this resource, and the operation needs a target that exists.",
  invalidValue: "A value is the wrong type, is missing when required, or is not one this attribute accepts.",
  invalidVers: "The version in the request is not one this server speaks.",
  sensitive: "The request put something sensitive in the URL. Send it in a POST body instead — that is what /.search is for."
};

/**
 * THE AUTHENTICATION SCHEMES, which are RFC 7644 SECTION 2's SIX AND NOT AN
 * INVENTED SET (DPoP is its proof-of-possession token), plus `none` and
 * HTTP Digest.
 *
 * That section names TLS client authentication, HOBA, bearer tokens,
 * proof-of-possession tokens, cookies and HTTP Basic (which it discourages,
 * in those words), and states the only two normative things about any of
 * them: a server SHALL advertise what it supports in `WWW-Authenticate`, and
 * it MUST be able to map an authenticated client to an access control policy.
 *
 * **DO NOT ADD AN API KEY ROW.** A shared secret in a custom header is what
 * most provisioning integrations actually use in the field, it is in no
 * specification, and a client built against it here would interoperate with
 * nothing.
 *
 * `needsProof` marks the ones that cannot be composed from configuration
 * alone: DPoP needs a signed proof JWT over this exact method and URL, HOBA a
 * signature over an origin-bound string, and Digest a hash over the server's
 * nonce. The module produces the STRING TO BE SIGNED and the header FORMAT
 * and the page produces any signature — which keeps the cryptography where
 * the key is and keeps the module loadable in node.
 *
 * `sendsCredential` is false for the two that put nothing in an
 * Authorization header: a cookie rides on the request because the browser
 * attaches it, and a client certificate is chosen during the TLS handshake.
 * Both are therefore unavailable to the api path and only one of them is
 * available to the browser path, which the page says rather than leaving to
 * be discovered.
 */
const SCIM_AUTH_SCHEMES: ScimAuthScheme[] = #[
  #{
    id: "none",
    label: "None (anonymous)",
    type: "",
    spec: "RFC 7644 section 2",
    sendsCredential: false,
    needsProof: false,
    scoped: false,
    browser: true,
    backend: true,
    what: "Send nothing. Against a server with authentication turned on this is the 401 that shows you what the WWW-Authenticate challenge says you may use — which is the SHALL in section 2 and the fastest way to find out what a server will accept."
  },
  #{
    id: "bearer",
    label: "OAuth 2.0 Bearer token",
    type: "oauthbearertoken",
    spec: "RFC 6750",
    sendsCredential: true,
    needsProof: false,
    scoped: true,
    browser: true,
    backend: true,
    what: "Authorization: Bearer <token>. The scope is what decides what you may do: the read scope to read and the write scope to write. Get one from the OAuth2 / OIDC workflow with any grant, or paste one."
  },
  #{
    id: "dpop",
    label: "OAuth 2.0 DPoP (proof of possession)",
    type: "oauth2",
    spec: "RFC 9449",
    sendsCredential: true,
    needsProof: true,
    scoped: true,
    browser: true,
    backend: true,
    what: "Authorization: DPoP <token> plus a DPoP proof JWT signed over THIS method and URL and carrying the access token's hash. The proof is minted per request, so a captured one is not replayable against another endpoint."
  },
  #{
    id: "basic",
    label: "HTTP Basic",
    type: "httpbasic",
    spec: "RFC 7617",
    sendsCredential: true,
    needsProof: false,
    scoped: false,
    browser: true,
    backend: true,
    what: "Authorization: Basic base64(user:password). Section 2 names it and discourages it in the same sentence. It carries no scope, so a server that accepts it usually lets the caller do everything."
  },
  #{
    id: "digest",
    label: "HTTP Digest",
    type: "httpdigest",
    spec: "RFC 7616",
    sendsCredential: true,
    needsProof: true,
    scoped: false,
    browser: true,
    backend: true,
    what: "Two requests, not one: the first is answered 401 with a nonce, and the second carries a digest computed over it. This page makes both and shows you both, because the handshake is the interesting part and a library normally hides it."
  },
  #{
    id: "hoba",
    label: "HOBA (HTTP Origin-Bound Authentication)",
    type: "hoba",
    spec: "RFC 7486",
    sendsCredential: true,
    needsProof: true,
    scoped: false,
    browser: true,
    backend: false,
    what: "A signature by a key you registered, over a string bound to this origin and this realm. No password crosses the wire at all. The signing key lives in this browser, which is why the api cannot make this call for you."
  },
  #{
    id: "cookie",
    label: "Session cookie",
    type: "httpcookie",
    spec: "RFC 7644 section 2 (\"Cookies\")",
    sendsCredential: false,
    needsProof: false,
    scoped: false,
    browser: true,
    backend: false,
    what: "Nothing is added to the request: the browser attaches the cookie if it has one for that origin and the request is made with credentials. Sign in to the server first. The api has no session and no cookie jar, so this is a browser-only scheme."
  },
  #{
    id: "clientcert",
    label: "TLS client certificate",
    type: "tlsclientauth",
    spec: "RFC 8446 / RFC 5280",
    sendsCredential: false,
    needsProof: false,
    scoped: false,
    browser: true,
    backend: false,
    what: "Chosen during the TLS handshake and never in a header, so no code here can put it there — the browser offers what its keychain holds when the server asks. Nothing is added to the request; this row exists so the page can say that rather than appear to have left the scheme out."
  }
];

/**
 * THE ENDPOINTS. RFC 7644 sections 3.2 through 3.12, and section 4.
 *
 * `need` is the scope this page PREDICTS (it is the access control policy
 * of the test peer, iya-sts) and is NOT a claim about somebody else's server
 * — it is there so that a 403 can be shown beside the prediction that
 * expected it. `discovery` needs nothing anywhere: a client has to be able
 * to read a ServiceProviderConfig before it knows how to authenticate, which
 * is the one bootstrapping problem section 2 leaves to the reader.
 *
 * `query` lists the section 3.4.2 parameters each operation accepts. It is
 * not decorative: the page builds its query-string editor from it, so an
 * operation that does not accept `sortBy` does not offer one. The list
 * operations take all seven; the single-resource ones take only
 * `attributes` and `excludedAttributes`.
 */
const SCIM_OPERATIONS: ScimOperation[] = #[
  #{
    id: "serviceProviderConfig",
    label: "ServiceProviderConfig",
    group: "discovery",
    method: "GET",
    path: "/ServiceProviderConfig",
    need: "none",
    body: null,
    query: #[],
    section: "RFC 7644 section 4",
    what: "What this server supports: filtering, sorting, PATCH, bulk, ETag, changePassword, and the authentication schemes it advertises. Read it first — everything else on this page is a promise it made."
  },
  #{
    id: "resourceTypes",
    label: "ResourceTypes",
    group: "discovery",
    method: "GET",
    path: "/ResourceTypes",
    need: "none",
    body: null,
    query: #[],
    section: "RFC 7644 section 4",
    what: "The resource types this server has, and for each one its endpoint and the schema extensions it carries."
  },
  #{
    id: "resourceType",
    label: "One ResourceType",
    group: "discovery",
    method: "GET",
    path: "/ResourceTypes/{id}",
    need: "none",
    body: null,
    query: #[],
    idLabel: "Type name",
    idExample: "User",
    section: "RFC 7644 section 4",
    what: "One of them, by name — \"User\" or \"Group\". Note the id here is a NAME and not a resource id; that asymmetry is in the specification."
  },
  #{
    id: "schemas",
    label: "Schemas",
    group: "discovery",
    method: "GET",
    path: "/Schemas",
    need: "none",
    body: null,
    query: #[],
    section: "RFC 7643 section 7",
    what: "Every attribute this server knows, with its characteristics: required, canonical values, mutability, returned, uniqueness. This is the document that says whether a field you sent was ever going to be stored."
  },
  #{
    id: "schema",
    label: "One Schema",
    group: "discovery",
    method: "GET",
    path: "/Schemas/{id}",
    need: "none",
    body: null,
    query: #[],
    idLabel: "Schema URN",
    idExample: "urn:ietf:params:scim:schemas:core:2.0:User",
    section: "RFC 7643 section 7",
    what: "One schema by its URN."
  },
  #{
    id: "listUsers",
    label: "List users",
    group: "user",
    resourceType: "User",
    method: "GET",
    path: "/Users",
    need: "read",
    body: null,
    query: #["filter", "sortBy", "sortOrder", "startIndex", "count", "attributes", "excludedAttributes"],
    section: "RFC 7644 section 3.4.2",
    what: "The list, filtered, sorted, paged and projected by the query string. An empty filter means everybody, which is what count and startIndex are for."
  },
  #{
    id: "createUser",
    label: "Create user",
    group: "user",
    resourceType: "User",
    method: "POST",
    path: "/Users",
    need: "write",
    body: "User",
    query: #["attributes", "excludedAttributes"],
    section: "RFC 7644 section 3.3",
    what: "201 with the created resource and a Location header. userName is the one required attribute and the one with a uniqueness constraint, so this is where a 409 comes from."
  },
  #{
    id: "searchUsers",
    label: "Search users (POST /.search)",
    group: "user",
    resourceType: "User",
    method: "POST",
    path: "/Users/.search",
    need: "read",
    body: "SearchRequest",
    query: #[],
    section: "RFC 7644 section 3.4.3",
    what: "The same query as a POST body. It exists for a filter too long for a URL and for one carrying something that should not be in a server's access log."
  },
  #{
    id: "readUser",
    label: "Read user",
    group: "user",
    resourceType: "User",
    method: "GET",
    path: "/Users/{id}",
    need: "read",
    body: null,
    query: #["attributes", "excludedAttributes"],
    section: "RFC 7644 section 3.4.1",
    what: "One user by id. The id is opaque — do not build it, use the one the create or the list gave you."
  },
  #{
    id: "replaceUser",
    label: "Replace user (PUT)",
    group: "user",
    resourceType: "User",
    method: "PUT",
    path: "/Users/{id}",
    need: "write",
    body: "User",
    query: #["attributes", "excludedAttributes"],
    section: "RFC 7644 section 3.5.1",
    what: "Replaces the resource with what you send. Every attribute you leave out is one you are asking to have removed — which is the difference between this and PATCH and the mistake this operation exists to let you make on purpose."
  },
  #{
    id: "modifyUser",
    label: "Modify user (PATCH)",
    group: "user",
    resourceType: "User",
    method: "PATCH",
    path: "/Users/{id}",
    need: "write",
    body: "PatchOp",
    query: #["attributes", "excludedAttributes"],
    section: "RFC 7644 section 3.5.2",
    what: "add, replace and remove against a path — and the path grammar is the part everybody gets wrong: emails[type eq \"work\"].value is a path, not a property name. A PATCH that changes nothing answers 204 with no body."
  },
  #{
    id: "deleteUser",
    label: "Delete user",
    group: "user",
    resourceType: "User",
    method: "DELETE",
    path: "/Users/{id}",
    need: "write",
    body: null,
    query: #[],
    section: "RFC 7644 section 3.6",
    what: "204 and no body. There is no soft delete in SCIM — active:false is a different thing and does not do this."
  },
  #{
    id: "listGroups",
    label: "List groups",
    group: "group",
    resourceType: "Group",
    method: "GET",
    path: "/Groups",
    need: "read",
    body: null,
    query: #["filter", "sortBy", "sortOrder", "startIndex", "count", "attributes", "excludedAttributes"],
    section: "RFC 7644 section 3.4.2",
    what: "The list. A group's members come back as ids with a $ref."
  },
  #{
    id: "createGroup",
    label: "Create group",
    group: "group",
    resourceType: "Group",
    method: "POST",
    path: "/Groups",
    need: "write",
    body: "Group",
    query: #["attributes", "excludedAttributes"],
    section: "RFC 7644 section 3.3",
    what: "displayName is the required attribute. Members may be sent at creation or added afterwards with a PATCH."
  },
  #{
    id: "searchGroups",
    label: "Search groups (POST /.search)",
    group: "group",
    resourceType: "Group",
    method: "POST",
    path: "/Groups/.search",
    need: "read",
    body: "SearchRequest",
    query: #[],
    section: "RFC 7644 section 3.4.3",
    what: "The same query as a POST body."
  },
  #{
    id: "readGroup",
    label: "Read group",
    group: "group",
    resourceType: "Group",
    method: "GET",
    path: "/Groups/{id}",
    need: "read",
    body: null,
    query: #["attributes", "excludedAttributes"],
    section: "RFC 7644 section 3.4.1",
    what: "One group by id, with its members resolved."
  },
  #{
    id: "replaceGroup",
    label: "Replace group (PUT)",
    group: "group",
    resourceType: "Group",
    method: "PUT",
    path: "/Groups/{id}",
    need: "write",
    body: "Group",
    query: #["attributes", "excludedAttributes"],
    section: "RFC 7644 section 3.5.1",
    what: "Replaces it, membership included. Sending a group with no members empties it."
  },
  #{
    id: "modifyGroup",
    label: "Modify group (PATCH)",
    group: "group",
    resourceType: "Group",
    method: "PATCH",
    path: "/Groups/{id}",
    need: "write",
    body: "PatchOp",
    query: #["attributes", "excludedAttributes"],
    section: "RFC 7644 section 3.5.2",
    what: "How membership is normally changed: add or remove against the \"members\" path. Membership is a fact about the GROUP, so it is never changed through a User resource."
  },
  #{
    id: "deleteGroup",
    label: "Delete group",
    group: "group",
    resourceType: "Group",
    method: "DELETE",
    path: "/Groups/{id}",
    need: "write",
    body: null,
    query: #[],
    section: "RFC 7644 section 3.6",
    what: "204. Deleting a group deletes the membership, not the members."
  },
  #{
    id: "searchAll",
    label: "Search everything (POST /.search)",
    group: "query",
    method: "POST",
    path: "/.search",
    need: "read",
    body: "SearchRequest",
    query: #[],
    section: "RFC 7644 section 3.4.3",
    what: "One query across BOTH resource types at once, which is the one thing the per-type /.search cannot do. The ListResponse comes back mixed, so read each entry's schemas to tell a User from a Group."
  },
  #{
    id: "bulk",
    label: "Bulk",
    group: "query",
    method: "POST",
    path: "/Bulk",
    need: "write",
    body: "BulkRequest",
    query: #[],
    section: "RFC 7644 section 3.7",
    what: "Many operations in one request, each with a bulkId the later ones can reference as bulkId:name. There is no read operation inside a bulk, so it is a write however harmless the contents look."
  },
  #{
    id: "me",
    label: "/Me",
    group: "query",
    method: "GET",
    path: "/Me",
    need: "read",
    body: null,
    query: #["attributes", "excludedAttributes"],
    section: "RFC 7644 section 3.11",
    what: "An alias for whoever the request authenticated as. A server with no authenticated subject has nothing to alias, and this project's mock answers 501 saying so — which is a more useful answer than a 404 or a guess."
  }
];

/**
 * THE VOCABULARY the generator draws from.
 *
 * Deliberately BORING and deliberately ASCII. A generator that produced
 * realistic-looking names would put somebody's actual name in somebody's test
 * directory, and one that produced interesting Unicode would make every
 * failure a question about encoding rather than about SCIM. The characters
 * RFC 4514 reserves — the ones that cannot go in a DN unescaped — have their
 * own negative case in the scenarios instead, where the point is to be
 * refused.
 */
const SCIM_USER_VOCABULARY: ScimUserVocabulary = #{
  givenNames: #["Ada", "Bram", "Cleo", "Dara", "Emil", "Fen", "Gale", "Hana", "Ivo", "Juno", "Kit", "Lior", "Mira", "Nils", "Oona", "Piet", "Quin", "Rune", "Sena", "Taro", "Ulla", "Vera", "Wim", "Xan", "Yuki", "Zev"],
  familyNames: #["Aalto", "Bergman", "Coelho", "Dahl", "Esposito", "Fournier", "Garza", "Haas", "Ibarra", "Jansen", "Kovac", "Lindqvist", "Moreau", "Novak", "Oyelaran", "Pereira", "Quesada", "Rasmussen", "Silva", "Tanaka", "Ustinov", "Vogel", "Weber", "Xiong", "Yilmaz", "Zima"],
  honorificPrefixes: #["Dr.", "Prof.", "Ms.", "Mr.", "Mx."],
  honorificSuffixes: #["PhD", "Jr.", "III", "MSc"],
  titles: #["Systems Engineer", "Directory Architect", "Support Analyst", "Security Lead", "Product Manager", "Data Steward", "Field Technician", "Compliance Officer"],
  userTypes: #["Employee", "Contractor", "Intern", "Vendor", "Partner"],
  departments: #["Engineering", "Operations", "Finance", "Legal", "Research", "Support"],
  divisions: #["Platform", "Directory", "Identity", "Infrastructure"],
  organizations: #["Example Corp", "Example Holdings", "Example Labs"],
  costCenters: #["CC-1000", "CC-2000", "CC-3000", "CC-4000"],
  locales: #["en-US", "en-GB", "de-DE", "fr-FR", "ja-JP", "pt-BR"],
  languages: #["en", "en-US", "de", "fr", "ja", "pt-BR"],
  timezones: #["America/Los_Angeles", "America/New_York", "Europe/London", "Europe/Berlin", "Asia/Tokyo", "Australia/Sydney"],
  streets: #["1 Directory Way", "42 Schema Street", "7 Bind Lane", "100 Filter Road", "15 Attribute Close"],
  localities: #["Springfield", "Riverton", "Fairview", "Ashford", "Kingsmere"],
  regions: #["CA", "NY", "TX", "WA", "IL"],
  countries: #["US", "GB", "DE", "FR", "JP", "BR"],
  imTypes: #["aim", "gtalk", "icq", "xmpp", "msn", "skype", "qq", "yahoo"],
  photoTypes: #["photo", "thumbnail"],
  groupNouns: #["Engineering", "Operations", "Directory Admins", "Auditors", "Support", "Contractors", "Reviewers", "Release Managers"]
};

/**
 * THE FILTER TOUR.
 *
 * RFC 7644 section 3.4.2.2 defines these operators and a server advertises
 * filter support as one boolean — so a client that has only ever sent `eq`
 * has no idea which of the others its server actually evaluates. Each row is
 * a filter TEMPLATE substituted at plan time.
 *
 * `pr` takes no comparison value and `not`/`and`/`or` are grouping
 * rather than comparison, which is why they are separate rows rather than a
 * value on one.
 */
const SCIM_FILTER_TOUR: ScimFilterTourRow[] = #[
  #{
    `op`: "eq",
    filter: "userName eq \"{userName}\"",
    expectMatch: true,
    what: "equal — the one every client sends"
  },
  #{
    `op`: "ne",
    filter: "userName ne \"{userName}\"",
    expectMatch: false,
    what: "not equal"
  },
  #{
    `op`: "co",
    filter: "userName co \"{tag}\"",
    expectMatch: true,
    what: "contains"
  },
  #{
    `op`: "sw",
    filter: "userName sw \"{prefix}\"",
    expectMatch: true,
    what: "starts with"
  },
  #{
    `op`: "ew",
    filter: "userName ew \"{tag}\"",
    expectMatch: true,
    what: "ends with"
  },
  #{
    `op`: "pr",
    filter: "userName pr",
    expectMatch: true,
    what: "present — no comparison value at all"
  },
  #{
    `op`: "gt",
    filter: "meta.created gt \"2000-01-01T00:00:00Z\"",
    expectMatch: true,
    what: "greater than, on a dateTime"
  },
  #{
    `op`: "ge",
    filter: "meta.created ge \"2000-01-01T00:00:00Z\"",
    expectMatch: true,
    what: "greater than or equal"
  },
  #{
    `op`: "lt",
    filter: "meta.created lt \"2999-01-01T00:00:00Z\"",
    expectMatch: true,
    what: "less than"
  },
  #{
    `op`: "le",
    filter: "meta.created le \"2999-01-01T00:00:00Z\"",
    expectMatch: true,
    what: "less than or equal"
  },
  #{
    `op`: "and",
    filter: "userName eq \"{userName}\" and active eq true",
    expectMatch: true,
    what: "and"
  },
  #{
    `op`: "or",
    filter: "userName eq \"{userName}\" or userName eq \"nobody\"",
    expectMatch: true,
    what: "or"
  },
  #{
    `op`: "not",
    filter: "not (userName eq \"nobody\")",
    expectMatch: true,
    what: "not, with the grouping parentheses it needs"
  },
  #{
    `op`: "complex",
    filter: "emails[type eq \"work\"]",
    expectMatch: true,
    what: "a complex attribute filter — the value filter grammar, which is where a hand-rolled parser stops working"
  }
];

/**
 * THE SCENARIOS.
 *
 * Each row is a definition rather than a plan: its `build(options)`, which
 * is code and stays in scim_scenarios.js, produces the steps, because the
 * count of users, the seed and the prefix are the caller's. `takes` says
 * which of those a scenario reads, so the page can show only the controls a
 * scenario actually uses instead of a fixed form with fields that do nothing
 * on most of them.
 */
const SCIM_SCENARIOS: ScimScenario[] = #[
  #{
    id: "discovery",
    label: "Discovery — what does this server support?",
    takes: #[],
    writes: false,
    what: "Reads the three documents a client should read before it sends anything: the ServiceProviderConfig, the ResourceTypes and the Schemas. Needs no scope anywhere, which is what makes it the right first thing to run against a server you have not met."
  },
  #{
    id: "user-lifecycle",
    label: "One user, all the way round",
    takes: #["seed", "prefix"],
    writes: true,
    what: "Create a user carrying every optional attribute RFC 7643 section 4.1 defines, read it back, replace it with a PUT, modify it with three PATCH operations, then delete it and confirm the id is gone. The read-back is the interesting step: what comes back is what the server actually STORED, and the difference from what was sent is the answer to \"does this field work\"."
  },
  #{
    id: "provision-team",
    label: "Provision a team",
    takes: #["userCount", "seed", "prefix"],
    writes: true,
    what: "Create N users, create a group, add all of them to it in one PATCH, read the group back, remove one member, then tear the whole thing down. This is what a provisioning integration does on its first run, and the membership PATCH is where most of them are wrong: membership is a fact about the GROUP and is never changed through a User resource."
  },
  #{
    id: "deprovision",
    label: "Deprovision — create N, then delete N",
    takes: #["userCount", "seed", "prefix"],
    writes: true,
    what: "The single most common thing a SCIM client is built to do and the least often tested. Each delete is followed by a read that expects a 404, because a delete that answers 204 and leaves the resource behind is a deprovisioning path that has never actually worked."
  },
  #{
    id: "modify-sweep",
    label: "Modify a population",
    takes: #["userCount", "seed", "prefix"],
    writes: true,
    what: "Create N users and then PATCH every one of them three ways: replace a simple attribute, add a value to a multi-valued one, and remove a sub-attribute through a value filter path — emails[type eq \"home\"], which is the section 3.5.2 path grammar that a server treating a path as a property name gets wrong."
  },
  #{
    id: "bulk",
    label: "Bulk — many operations, one request",
    takes: #["userCount", "seed", "prefix"],
    writes: true,
    what: "One BulkRequest that creates N users and a group whose members are those users, referenced as bulkId:name — the feature that makes a bulk more than a loop, because the group is created in the same request as the users it contains. Then one more bulk that deletes the lot."
  },
  #{
    id: "paging",
    label: "Paging and sorting",
    takes: #["userCount", "seed", "prefix"],
    writes: true,
    what: "Create N users, then walk the list a page at a time with count and startIndex, sorted both ways. SCIM paging is 1-INDEXED — startIndex 1 is the first resource, not the second — which is the off-by-one every client written against a 0-indexed API brings with it."
  },
  #{
    id: "filter-tour",
    label: "Every filter operator",
    takes: #["seed", "prefix"],
    writes: true,
    what: "Create one user, then send all fourteen forms of RFC 7644 section 3.4.2.2 filter against it: the ten comparison operators, the three grouping ones, and a complex value filter. A server advertises filtering as one boolean, so this is the only way to find out which of them it really evaluates."
  },
  #{
    id: "search-post",
    label: "Query by POST (/.search)",
    takes: #["seed", "prefix"],
    writes: true,
    what: "The same queries as a POST body — per resource type and then across both at once, which the per-type endpoint cannot do. Note that attributes and excludedAttributes are ARRAYS in a SearchRequest and a comma-separated string in a query string; that asymmetry is in the specification and is why a /.search often returns everything when the caller asked for two fields."
  },
  #{
    id: "enterprise",
    label: "The enterprise extension",
    takes: #["seed", "prefix"],
    writes: true,
    what: "Create two users, set the second as the first's manager, and PATCH the section 4.3 extension attributes through their full URN paths — which is what makes an extension attribute different from a core one and is the part a client that has only sent core attributes has never exercised."
  },
  #{
    id: "negatives",
    label: "The refusals",
    takes: #["seed", "prefix"],
    writes: true,
    what: "Every error this server can be made to produce on purpose: a refused userName, a duplicate one, an id that names nothing, a filter that cannot be parsed, a PATCH path that is not path grammar, and /Me. A client's error handling is the half that is never exercised, because a permissive server is hard to make say no — so these steps expect the refusal and FAIL if the server allows it."
  },
  #{
    id: "scope-refusal",
    label: "Read scope cannot write",
    takes: #[],
    writes: true,
    needsAuth: true,
    what: "Sends a write with a credential that carries only the read scope and expects a 403. It is the one scenario that asserts the access control policy rather than the protocol, so it needs a server with authentication turned on and a second, read-only credential configured in the pane above."
  }
];

/**
 * The phases a random scenario is composed of, each a scenario above with
 * its relative weight. What is random is the SHAPE — which phases run, in
 * what order, over how many users — and it is seeded.
 */
const SCIM_RANDOM_PHASES: ScimRandomPhase[] = #[
  #{
    id: "user-lifecycle",
    weight: 2
  },
  #{
    id: "provision-team",
    weight: 3
  },
  #{
    id: "deprovision",
    weight: 2
  },
  #{
    id: "modify-sweep",
    weight: 2
  },
  #{
    id: "bulk",
    weight: 2
  },
  #{
    id: "paging",
    weight: 1
  },
  #{
    id: "filter-tour",
    weight: 1
  },
  #{
    id: "search-post",
    weight: 1
  },
  #{
    id: "enterprise",
    weight: 1
  },
  #{
    id: "negatives",
    weight: 1
  }
];
