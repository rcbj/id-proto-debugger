// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: vp_query_engine.js
//
// ---------------------------------------------------------------------------
// Predicate queries (client/src/vp_query.js; #474), in node, held to the
// specifications' own text and examples and to anoncreds-rs v0.2.3
// (tests/anoncreds_witness.js):
//
//   * DIF Presentation Exchange 2.1.1: a definition read and refused where
//     it is malformed; the Predicate Feature's own filter examples mapped
//     (minimum -> >=, exclusiveMinimum -> >, maximum -> <=,
//     exclusiveMaximum -> <, const, not const, enum, not enum); a filter
//     that is not restricted to one refused; submission requirements (all,
//     pick with count / min / max, from_nested); presentation_submission
//     built and checked, and refused for another definition, a path that
//     selects nothing, an unknown descriptor and an unmet requirement;
//   * OpenID4VP 1.0 section 6.4.1 exactly: values by exact type and value
//     (age_over_18 = true against true and against false; "18" is not 18),
//     claim_sets falling back to the next option, no option satisfiable;
//   * the debugger's DCQL extension: ignored unless critical, a critical
//     entry not understood refusing, a predicate also named in claims
//     refusing (a 1.0 wallet would disclose it);
//   * fail-closed plans: a required predicate SD-JWT VC cannot prove is
//     refused, a preferred one too unless allowed, an mdoc age bound
//     answered by age_over_NN (and refused when it is false), AnonCreds
//     refusing a non-integer attribute, an unsatisfied predicate, a
//     revealed-and-predicated attribute;
//   * AnonCreds through the new paths, against anoncreds-rs: our wallet
//     proves the PE predicate and the DCQL-extension predicate and
//     anoncreds-rs verifies; anoncreds-rs proves the request the query maps
//     onto and our Verifier check (verifyForQuery) accepts it; a weaker
//     predicate is refused; a raw AnonCreds request (the specification's
//     own object, with a YYYYMMDD date predicate) proven both ways; the W3C
//     form; and the [verifier] engine (vp_verifier.js) checking a
//     presentation_definition answer and a DCQL-extension answer.
//
// Fails, naming the image, when the anoncreds witness is not available.
// ---------------------------------------------------------------------------

const assert = require("assert");
const fs = require("fs");
const path = require("path");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "vp_query_engine",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

function repoRoot() {
  log.debug("Entering repoRoot().");
  var candidates = [path.resolve(__dirname, ".."),
                    path.resolve(__dirname, "..", "source-tree")];
  for (var i = 0; i < candidates.length; i++) {
    if (fs.existsSync(path.join(candidates[i], "client", "package.json"))) {
      log.debug("Leaving repoRoot(). " + candidates[i]);
      return candidates[i];
    }
  }
  log.debug("Leaving repoRoot(). None found.");
  return candidates[0];
}

const SRC = path.join(repoRoot(), "client", "src");
const paths = require("./module_paths.js");
function load(name) {
  log.debug("Entering load(). " + name);
  log.debug("Leaving load().");
  return paths.requireSharedModule([path.join(SRC, name)],
                                   "client/src/" + name);
}
const q = load("vp_query.js");
const ours = load("anoncreds.js");
const wallet = load("anoncreds_wallet.js");
const w3c = load("anoncreds_w3c.js");
const witness = require("./anoncreds_witness.js");

const ISSUER = "did:example:predicate-issuer";

function errorsOf(fn) {
  log.debug("Entering errorsOf().");
  var r = fn();
  log.debug("Leaving errorsOf().");
  return r.errors.join(" ");
}

// --- Presentation Exchange 2.1.1 ----------------------------------------
function presentationExchange() {
  log.debug("Entering presentationExchange().");
  // The Predicate Feature's own filter examples, in its order.
  var cases = [
    [{ type: "number", exclusiveMinimum: 10000 }, "range", ">", 10000],
    [{ type: "number", exclusiveMaximum: 85 }, "range", "<", 85],
    [{ type: "number", minimum: 18 }, "range", ">=", 18],
    [{ type: "number", maximum: 65536 }, "range", "<=", 65536]];
  cases.forEach(function (c) {
    var ops = q.predicateOps(c[0]);
    assert.strictEqual(ops.kind, c[1]);
    assert.deepStrictEqual([ops.bounds[0].p_type, ops.bounds[0].p_value],
                           [c[2], c[3]], JSON.stringify(c[0]));
  });
  assert.deepStrictEqual(q.predicateOps({ const: "Chad" }),
    { kind: "const", value: "Chad", negated: false }, "equal-to");
  assert.deepStrictEqual(q.predicateOps({ not: { const: "Karen" } }),
    { kind: "const", value: "Karen", negated: true }, "not equal-to");
  assert.strictEqual(q.predicateOps({ type: "string", enum: ["red",
    "yellow", "blue"] }).kind, "enum", "in-set");
  assert.ok(q.predicateOps({ not: { enum: ["red"] } }).negated,
            "not-in-set");
  assert.ok(q.predicateOps({ type: "number", minimum: 18,
    pattern: "x" }).error, "a range filter with another keyword is not " +
    "restricted to the predicate operation");
  assert.ok(q.predicateOps({ type: "number", exclusiveMinimum: true })
    .error, "draft-04's boolean exclusiveMinimum is refused");
  assert.ok(q.predicateOps(undefined).error, "a predicate needs a filter");
  assert.strictEqual(q.filterMatches({ type: "integer", minimum: 18 }, 18),
                     true);
  assert.strictEqual(q.filterMatches({ type: "integer", minimum: 18 }, 17),
                     false);
  assert.strictEqual(q.filterMatches({ type: "string", madeUp: 1 }, "x"),
                     false, "an unimplemented keyword fails closed");
  assert.strictEqual(q.filterMatches({ type: "string", format: "date",
    formatMaximum: "2008-11-18" }, "2001-02-03"), true, "a date bound");

  var good = { id: "pd1", input_descriptors: [{ id: "adult",
    format: { anoncreds: {} },
    constraints: { limit_disclosure: "required", fields: [
      { path: ["$.credentialSubject.name", "$.name"] },
      { id: "age18", path: ["$.credentialSubject.age", "$.age"],
        filter: { type: "integer", minimum: 18 }, predicate: "required" }]
    } }] };
  var read = q.readDefinition(good);
  assert.deepStrictEqual(read.errors, [], "a good definition reads");
  assert.strictEqual(read.descriptors[0].fields[1].ops.bounds[0].p_type,
                     ">=");
  assert.match(errorsOf(function () {
    return q.readDefinition({ input_descriptors: [] });
  }), /id is a non-empty string.*input_descriptors is a non-empty array/);
  assert.match(errorsOf(function () {
    return q.readDefinition({ id: "x", input_descriptors: [{ id: "a",
      constraints: { fields: [{ path: ["$.age"], predicate: "always",
        filter: { type: "number", minimum: 1 } }] } }] });
  }), /"required" or "preferred"/, "predicate's value is checked");
  assert.match(errorsOf(function () {
    return q.readDefinition({ id: "x", input_descriptors: [{ id: "a",
      constraints: { fields: [{ path: ["$.age"], predicate: "required" }]
      } }] });
  }), /MUST also have a filter/, "predicate without filter");
  assert.match(errorsOf(function () {
    return q.readDefinition({ id: "x", input_descriptors: [{ id: "a",
      constraints: { fields: [{ path: ["age"] }] } }] });
  }), /begins with \$/, "a path that is not JSONPath");
  assert.match(errorsOf(function () {
    return q.readDefinition({ id: "x", input_descriptors: [{ id: "a" },
      { id: "a" }] });
  }), /not unique/, "descriptor ids are unique");
  assert.match(errorsOf(function () {
    return q.readDefinition({ id: "x", input_descriptors: [{ id: "a",
      group: ["A"] }], submission_requirements: [{ rule: "pick",
      from: "B", count: 1 }] });
  }), /names group "B"/, "a requirement names an existing group");

  // Submission requirements.
  var sr = q.readDefinition({ id: "sr", input_descriptors: [
    { id: "a", group: ["A"] }, { id: "b", group: ["A"] },
    { id: "c", group: ["B"] }],
    submission_requirements: [
      { rule: "pick", from: "A", count: 1 },
      { rule: "pick", from_nested: [{ rule: "all", from: "B" },
                                    { rule: "pick", from: "A", min: 2 }],
        max: 1, min: 1 }] });
  assert.deepStrictEqual(sr.errors, []);
  assert.ok(q.submissionRequirementsMet(sr, ["a", "c"]).ok, "a + c");
  assert.ok(!q.submissionRequirementsMet(sr, ["a", "b", "c"]).ok,
            "count 1 refuses two from A");
  assert.ok(!q.submissionRequirementsMet(sr, ["a"]).ok,
            "the nested pick needs one of its two");
  assert.ok(!q.submissionRequirementsMet(read, []).ok,
            "with no requirements every descriptor is required");

  // presentation_submission.
  var token = { "@context": [], type: ["VerifiablePresentation"],
                verifiableCredential: [{ id: "vc0" }] };
  var sub = q.buildSubmission("pd1", [{ id: "adult", format: "di_vp",
    path: "$", path_nested: { id: "adult", format: "di_vc",
                              path: "$.verifiableCredential[0]" } }]);
  var chk = q.checkSubmission(read, sub, token);
  assert.deepStrictEqual(chk.errors, [], "a good submission checks");
  assert.deepStrictEqual(chk.answered, ["adult"]);
  assert.match(q.checkSubmission(read, Object.assign({}, sub,
    { definition_id: "other" }), token).errors.join(" "),
    /definition_id/, "another definition");
  var nowhere = JSON.parse(JSON.stringify(sub));
  nowhere.descriptor_map[0].path_nested.path = "$.verifiableCredential[3]";
  assert.match(q.checkSubmission(read, nowhere, token).errors.join(" "),
               /selects nothing/, "a path that selects nothing");
  var unknown = JSON.parse(JSON.stringify(sub));
  unknown.descriptor_map[0].id = "minor";
  assert.match(q.checkSubmission(read, unknown, token).errors.join(" "),
    /no Input Descriptor.*not answered/, "an unknown descriptor, and the " +
    "real one then unanswered");
  assert.match(q.checkSubmission(read, null, token).errors.join(" "),
               /no presentation_submission/);
  assert.deepStrictEqual(q.parseJsonPath("$['Given Name'][0].x"),
                         ["Given Name", 0, "x"]);
  assert.strictEqual(q.jsonPathOf(["credentialSubject", "Given Name"]),
                     "$.credentialSubject['Given Name']");
  log.info("PASS Presentation Exchange 2.1.1: the Predicate Feature's " +
           "examples mapped, malformed definitions refused, submission " +
           "requirements and presentation_submission checked.");
  log.debug("Leaving presentationExchange().");
}

// A lookup over a flat claim map, as the wallet's heldLookup() is.
function flatLookup(claims) {
  log.debug("Entering flatLookup().");
  log.debug("Leaving flatLookup().");
  return function (p) {
    var name = q.attributeOf(p);
    return Object.prototype.hasOwnProperty.call(claims, name) ?
      { found: true, value: claims[name] } : { found: false };
  };
}

// --- OpenID4VP 1.0 section 6.4.1 -----------------------------------------
function valuesMatching() {
  log.debug("Entering valuesMatching().");
  var dcql = { credentials: [{ id: "pid", format: "dc+sd-jwt",
    claims: [{ path: ["age_over_18"], values: [true] }] }] };
  var model = q.normalise({ dcql_query: dcql });
  var held = function (claims) {
    log.debug("Entering held().");
    log.debug("Leaving held().");
    return { format: "dc+sd-jwt", lookup: flatLookup(claims) };
  };
  var yes = q.planFor(model, model.items[0], held({ age_over_18: true }));
  assert.ok(yes.ok, "true matches [true]");
  assert.deepStrictEqual(yes.disclose, ["age_over_18"]);
  var no = q.planFor(model, model.items[0], held({ age_over_18: false }));
  assert.ok(!no.ok, "false does not match [true]");
  assert.strictEqual(no.claims.rows[0].status, "value-mismatch");
  assert.match(no.refusals.join(" "), /not returned/,
               "and the credential is not returned");
  var text = q.planFor(model, model.items[0], held({ age_over_18: "true" }));
  assert.ok(!text.ok, "the string \"true\" is not the boolean true " +
            "(exact type and value)");
  // claim_sets: section 6.4.1's shape, the first satisfiable option.
  var sets = q.normalise({ dcql_query: { credentials: [{ id: "c",
    format: "dc+sd-jwt", claims: [
      { id: "a", path: ["last_name"] },
      { id: "b", path: ["postal_code"], values: ["90210", "90211"] },
      { id: "c", path: ["locality"] },
      { id: "d", path: ["region"] }],
    claim_sets: [["a", "b"], ["a", "c", "d"]] }] } });
  var fallback = q.planFor(sets, sets.items[0], held({ last_name: "Doe",
    postal_code: "10001", locality: "NYC", region: "NY" }));
  assert.ok(fallback.ok, "the second option is used when the first's " +
            "value does not match");
  assert.strictEqual(fallback.claims.chosenSet, 1);
  assert.deepStrictEqual(fallback.disclose, ["last_name", "locality",
                                             "region"],
                         "and postal_code is not disclosed");
  var first = q.planFor(sets, sets.items[0], held({ last_name: "Doe",
    postal_code: "90210", locality: "LA", region: "CA" }));
  assert.strictEqual(first.claims.chosenSet, 0, "the first option wins");
  var none = q.planFor(sets, sets.items[0], held({ last_name: "Doe",
    postal_code: "10001" }));
  assert.ok(!none.ok && none.disclose.length === 0, "no option: no claims " +
            "and not returned");
  var all = q.normalise({ dcql_query: { credentials: [{ id: "c",
    format: "dc+sd-jwt", claims: [{ path: ["age"], values: [18] }] }] } });
  assert.ok(!q.planFor(all, all.items[0], held({ age: "18" })).ok,
            "\"18\" is not 18");
  log.info("PASS OpenID4VP 1.0 section 6.4.1: values by exact type and " +
           "value (age_over_18 true and false), claim_sets fallback, no " +
           "option satisfiable.");
  log.debug("Leaving valuesMatching().");
}

// --- the DCQL extension ---------------------------------------------------
function extension() {
  log.debug("Entering extension().");
  var base = function () {
    log.debug("Entering base().");
    log.debug("Leaving base().");
    return { id: "pid", format: "anoncreds", claims: [{ path: ["name"] }],
             x_debugger_predicates: [{ id: "adult", path: ["age"],
               filter: { type: "integer", minimum: 18 } }] };
  };
  var plain = q.readExtension(base());
  assert.ok(plain.present && !plain.critical && !plain.honoured,
            "not critical: present but not honoured");
  assert.match(plain.note, /ignored/);
  var crit = base();
  crit.x_debugger_crit = ["x_debugger_predicates"];
  var honoured = q.readExtension(crit);
  assert.ok(honoured.honoured && !honoured.refuse);
  assert.strictEqual(honoured.predicates[0].ops.bounds[0].p_type, ">=");
  var unknown = base();
  unknown.x_debugger_crit = ["x_debugger_predicates", "x_other"];
  assert.match(q.readExtension(unknown).refuse, /does not understand/,
               "a crit entry not understood refuses the query");
  var dup = base();
  dup.x_debugger_crit = ["x_debugger_predicates"];
  dup.claims.push({ path: ["age"] });
  assert.match(q.readExtension(dup).refuse, /also requests/,
               "a predicate also in claims refuses");
  var empty = { id: "x", format: "anoncreds",
                x_debugger_crit: ["x_debugger_predicates"] };
  assert.match(q.readExtension(empty).refuse, /has none/);
  var bad = base();
  bad.x_debugger_crit = ["x_debugger_predicates"];
  bad.x_debugger_predicates[0].filter = { type: "integer", minimum: 18,
                                          pattern: "x" };
  assert.match(q.readExtension(bad).refuse, /malformed/);
  // Not critical: the plan proves nothing and discloses nothing extra.
  var model = q.normalise({ dcql_query: { credentials: [base()] } });
  var plan = q.planFor(model, model.items[0], { format: "anoncreds",
    lookup: flatLookup({ name: "Alice", age: "28" }) });
  assert.deepStrictEqual([plan.ok, plan.disclose, plan.predicates.length],
                         [true, ["name"], 0], "ignored: name only, no " +
                         "predicate, age not disclosed");
  // The builder never puts a predicate's claim in claims.
  var built = q.buildQuery({ language: "dcql", id: "pid", format: "anoncreds",
    reveal: ["name"], predicates: [{ name: "age", p_type: ">=",
                                     p_value: 18 }] }).dcql_query;
  assert.deepStrictEqual(built.credentials[0].claims, [{ path: ["name"] }]);
  assert.deepStrictEqual(built.credentials[0].x_debugger_crit,
                         ["x_debugger_predicates"]);
  log.info("PASS the DCQL predicate extension: ignored unless critical, " +
           "unknown crit and a predicate also in claims refused, the " +
           "builder keeping predicates out of claims.");
  log.debug("Leaving extension().");
}

// --- fail-closed plans ----------------------------------------------------
function failClosed() {
  log.debug("Entering failClosed().");
  var pe = function (format, mode, filter, attr) {
    log.debug("Entering pe().");
    log.debug("Leaving pe().");
    return q.normalise({ presentation_definition: { id: "p",
      input_descriptors: [{ id: "d", format: (function () {
        var f = {};
        f[format] = {};
        return f;
      })(), constraints: { fields: [{ path: ["$." + (attr || "age")],
        filter: filter || { type: "integer", minimum: 18 },
        predicate: mode }] } }] } });
  };
  var m = pe("dc+sd-jwt", "required");
  var sdjwt = q.planFor(m, m.items[0], { format: "dc+sd-jwt",
    lookup: flatLookup({ age: 30 }) });
  assert.ok(!sdjwt.ok && sdjwt.disclose.length === 0, "SD-JWT VC refuses " +
            "a required predicate and discloses nothing");
  assert.match(sdjwt.refusals.join(" "), /refused rather than answered/);
  m = pe("dc+sd-jwt", "preferred");
  assert.ok(!q.planFor(m, m.items[0], { format: "dc+sd-jwt",
    lookup: flatLookup({ age: 30 }) }).ok, "preferred: refused by default");
  var allowed = q.planFor(m, m.items[0], { format: "dc+sd-jwt",
    lookup: flatLookup({ age: 30 }) }, { allowPreferredDisclosure: true });
  assert.ok(allowed.ok && allowed.disclose.indexOf("age") !== -1 &&
            allowed.predicates[0].method === "disclose", "preferred and " +
            "allowed: the value is disclosed, and said to be");
  m = pe("mso_mdoc", "required", null, "age_in_years");
  var mdocYes = q.planFor(m, m.items[0], { format: "mso_mdoc",
    lookup: flatLookup({ age_over_18: true, birth_date: "2000-01-01" }) });
  assert.ok(mdocYes.ok, "an mdoc answers age_in_years >= 18 with " +
            "age_over_18");
  assert.deepStrictEqual(mdocYes.disclose, ["age_over_18"]);
  assert.strictEqual(mdocYes.predicates[0].method, "issuer-boolean");
  var mdocNo = q.planFor(m, m.items[0], { format: "mso_mdoc",
    lookup: flatLookup({ age_over_18: false }) });
  assert.ok(!mdocNo.ok, "age_over_18 false: refused");
  m = pe("anoncreds", "required");
  assert.match(q.planFor(m, m.items[0], { format: "anoncreds",
    lookup: flatLookup({ age: "twenty" }) }).refusals.join(" "),
    /encoded as an integer/, "AnonCreds: a non-integer attribute");
  assert.match(q.planFor(m, m.items[0], { format: "anoncreds",
    lookup: flatLookup({ age: "16" }) }).refusals.join(" "),
    /does not satisfy/, "AnonCreds: an unsatisfied predicate");
  m = pe("anoncreds", "required", { type: "number", minimum: 17.5 });
  assert.match(q.planFor(m, m.items[0], { format: "anoncreds",
    lookup: flatLookup({ age: "18" }) }).refusals.join(" "),
    /p_value is an integer/, "AnonCreds: a non-integer bound");
  m = q.normalise({ presentation_definition: { id: "p", input_descriptors:
    [{ id: "d", constraints: { fields: [{ path: ["$.age"] },
      { path: ["$.age"], filter: { type: "integer", minimum: 18 },
        predicate: "required" }] } }] } });
  assert.match(q.planFor(m, m.items[0], { format: "anoncreds",
    lookup: flatLookup({ age: "30" }) }).refusals.join(" "),
    /both requested and predicated/);
  m = pe("anoncreds", "required", { const: "Chad" }, "name");
  assert.match(q.planFor(m, m.items[0], { format: "anoncreds",
    lookup: flatLookup({ name: "Chad" }) }).refusals.join(" "),
    /cannot prove/, "AnonCreds proves no equality predicate");
  log.info("PASS fail-closed: required and (by default) preferred " +
           "predicates refused where the format cannot prove them; an mdoc " +
           "age bound answered by age_over_NN; AnonCreds' integer, " +
           "satisfaction and reveal rules.");
  log.debug("Leaving failClosed().");
}

// --- AnonCreds against anoncreds-rs --------------------------------------
function makeIssuer(ac, n, attrs) {
  log.debug("Entering makeIssuer(). " + n);
  var sid = ISSUER + "/schema/" + n;
  var cid = ISSUER + "/creddef/" + n;
  var schema = ac.Schema.create({ name: "s" + n, version: "1.0",
    issuerId: ISSUER, attributeNames: attrs });
  var made = ac.CredentialDefinition.create({ schemaId: sid,
    issuerId: ISSUER, schema: schema, signatureType: "CL", tag: "t" + n,
    supportRevocation: false });
  log.debug("Leaving makeIssuer().");
  return { sid: sid, cid: cid, schema: schema.toJson(),
           cd: made.credentialDefinition.toJson(),
           cdp: made.credentialDefinitionPrivate.toJson(),
           kcp: made.keyCorrectnessProof.toJson() };
}

// anoncreds-rs issues to our holder: the wallet bundle, the link secret JWK,
// and anoncreds-rs's own processing of the credential.
function issue(ac, iss, raw, asW3c) {
  log.debug("Entering issue().");
  var ls = ours.createLinkSecret();
  var offer = ac.CredentialOffer.create({ schemaId: iss.sid,
    credentialDefinitionId: iss.cid, keyCorrectnessProof: iss.kcp }).toJson();
  var made = ours.createCredentialRequest({ credentialOffer: offer,
    credentialDefinition: iss.cd, linkSecret: ls, linkSecretId: "ls",
    entropy: "predicates" });
  var opts = { credentialDefinition: iss.cd,
    credentialDefinitionPrivate: iss.cdp, credentialOffer: offer,
    credentialRequest: made.credentialRequest, attributeRawValues: raw };
  var cred;
  var theirs;
  if (asW3c) {
    var w = ac.W3cCredential.create(opts).process({
      credentialRequestMetadata: made.credentialRequestMetadata,
      linkSecret: ls, credentialDefinition: iss.cd });
    cred = w.toJson();
    theirs = w;
  } else {
    var issued = ac.Credential.create(opts).toJson();
    cred = ours.processCredential(issued, { credentialRequestMetadata:
      made.credentialRequestMetadata, linkSecret: ls,
      credentialDefinition: iss.cd });
    theirs = ac.Credential.fromJson(issued).process({
      credentialRequestMetadata: made.credentialRequestMetadata,
      linkSecret: ls, credentialDefinition: iss.cd });
  }
  var bundle = JSON.stringify({ format: "anoncreds", credential: cred,
    schema: iss.schema, schema_id: iss.sid, credential_definition: iss.cd,
    cred_def_id: iss.cid });
  log.debug("Leaving issue().");
  return { bundle: bundle, ls: ls, lsJwk: wallet.linkSecretJwk(ls),
           theirs: theirs };
}

function ctxFor(iss, request) {
  log.debug("Entering ctxFor().");
  var schemas = {};
  schemas[iss.sid] = iss.schema;
  var cds = {};
  cds[iss.cid] = iss.cd;
  log.debug("Leaving ctxFor().");
  return { presentationRequest: request, schemas: schemas,
           credentialDefinitions: cds };
}

function theyAccept(ac, pres, ctx, isW3c) {
  log.debug("Entering theyAccept().");
  try {
    var ok = (isW3c ? ac.W3cPresentation : ac.Presentation)
      .fromJson(pres).verify(ctx);
    log.debug("Leaving theyAccept(). " + ok);
    return ok;
  } catch (e) {
    log.debug("Leaving theyAccept(). " + e.message);
    return false;
  }
}

// The wallet's path: a query normalised, planned against the held bundle
// (lookup as heldLookup() builds it), presented with the plan's predicates.
function walletPresents(query, held, oid4vpNonce) {
  log.debug("Entering walletPresents().");
  var model = q.normalise(query);
  var b = wallet.parseBundle(held.bundle);
  var plan = q.planFor(model, model.items[0], { format: "anoncreds",
    lookup: wallet.claimLookup(b), w3c: b.w3c,
    ids: { schema_id: b.schemaId, cred_def_id: b.credDefId } });
  log.debug("Leaving walletPresents().");
  return { model: model, plan: plan, made: plan.ok ? wallet.present(
    held.bundle, plan.disclose, held.lsJwk, oid4vpNonce,
    plan.anoncredsPredicates) : null };
}

async function anoncredsInterop() {
  log.debug("Entering anoncredsInterop().");
  var ac = (await witness.load()).ac;
  var iss = makeIssuer(ac, 1, ["name", "age", "birthdate_dateint"]);
  var alice = issue(ac, iss, { name: "Alice", age: "28",
                               birthdate_dateint: "19980301" });
  var nonce = "oid4vp-nonce-predicates";
  var languages = ["pe", "dcql"];
  for (const language of languages) {
    var query = q.buildQuery({ language: language, id: "pid",
      format: "anoncreds", reveal: ["name"],
      predicates: [{ name: "age", p_type: ">=", p_value: 18 },
                   { name: "age", p_type: "<", p_value: 65 }],
      restrictions: [{ cred_def_id: iss.cid }] });
    var r = walletPresents(query, alice, nonce);
    assert.ok(r.plan.ok, language + ": the plan proves both bounds: " +
              r.plan.refusals.join(" "));
    assert.deepStrictEqual(r.plan.notRevealed, ["age"]);
    var pres = r.made.presentation;
    assert.deepStrictEqual(Object.keys(pres.requested_proof.revealed_attrs),
                           ["name"], language + ": age is not revealed");
    assert.strictEqual(theyAccept(ac, pres, ctxFor(iss, r.made.request)),
                       true, language + ": anoncreds-rs verifies our " +
                       "predicate proof");
    // Our Verifier check rebuilds the request from the query alone.
    var v = wallet.verifyForQuery(Object.assign({ presentation: pres,
      item: r.model.items[0], nonce: nonce }, ctxFor(iss, null)));
    assert.ok(v.valid, language + ": verifyForQuery accepts it: " +
              v.errors.join("; "));
    assert.deepStrictEqual(v.predicates.map(function (p) {
      return p.answered;
    }), [true, true]);
    // anoncreds-rs proves the request the query maps onto; we verify it.
    var request = v.request;
    var theirs = ac.Presentation.create(Object.assign({ credentials:
      [{ credential: alice.theirs }], credentialsProve: [
        { entryIndex: 0, referent: "name", isPredicate: false,
          reveal: true }].concat(Object.keys(request.requested_predicates)
          .map(function (ref) {
            return { entryIndex: 0, referent: ref, isPredicate: true,
                     reveal: true };
          })), selfAttest: {}, linkSecret: alice.ls },
      ctxFor(iss, request))).toJson();
    v = wallet.verifyForQuery(Object.assign({ presentation: theirs,
      item: r.model.items[0], nonce: nonce }, ctxFor(iss, null)));
    assert.ok(v.valid, language + ": anoncreds-rs's presentation of the " +
              "mapped request verifies here: " + v.errors.join("; "));
    // A WEAKER predicate is not the one asked for.
    var weaker = JSON.parse(JSON.stringify(query));
    var target = weaker.presentation_definition ?
      weaker.presentation_definition.input_descriptors[0].constraints
        .fields.filter(function (f) {
          return f.predicate;
        })[0].filter : weaker.dcql_query.credentials[0]
        .x_debugger_predicates[0].filter;
    target.minimum = 17;
    var wr = walletPresents(weaker, alice, nonce);
    v = wallet.verifyForQuery(Object.assign({ presentation:
      wr.made.presentation, item: r.model.items[0], nonce: nonce },
      ctxFor(iss, null)));
    assert.ok(!v.valid, language + ": a proof of age >= 17 does not " +
              "answer age >= 18");
    // A credential under another credential definition.
    var elsewhere = JSON.parse(JSON.stringify(r.model.items[0]));
    elsewhere.restrictions = [{ cred_def_id: "did:example:other/creddef" }];
    v = wallet.verifyForQuery(Object.assign({ presentation: pres,
      item: elsewhere, nonce: nonce }, ctxFor(iss, null)));
    assert.match(v.errors.join(" "), /restrictions/, language + ": the " +
                 "Verifier holds the presentation to the query's " +
                 "restrictions");
    // Another nonce.
    v = wallet.verifyForQuery(Object.assign({ presentation: pres,
      item: r.model.items[0], nonce: "another" }, ctxFor(iss, null)));
    assert.ok(!v.valid, language + ": another nonce is refused");
  }
  // A credential that does not satisfy: the wallet refuses, nothing is made.
  var minor = issue(ac, iss, { name: "Bob", age: "16",
                               birthdate_dateint: "20100101" });
  var refused = walletPresents(q.buildQuery({ language: "pe",
    format: "anoncreds", predicates: [{ name: "age", p_type: ">=",
                                        p_value: 18 }] }), minor, nonce);
  assert.ok(!refused.plan.ok && !refused.made, "a minor's wallet refuses");
  assert.throws(function () {
    wallet.present(minor.bundle, [], minor.lsJwk, nonce,
      [{ referent: "x", name: "age", p_type: ">=", p_value: 18 }]);
  }, /does not satisfy age >= 18/, "and so does presentRequest()");
  // A wrong restriction refuses.
  var other = walletPresents(q.buildQuery({ language: "pe",
    format: "anoncreds", predicates: [{ name: "age", p_type: ">=",
    p_value: 18 }], restrictions: [{ cred_def_id: "other" }] }), alice,
    nonce);
  assert.match(other.plan.refusals.join(" "), /restrictions/);
  log.info("PASS AnonCreds predicates through the new paths: our wallet " +
           "proves the PE predicate and the DCQL-extension predicate (age " +
           ">= 18 and < 65, age not revealed) and anoncreds-rs verifies; " +
           "anoncreds-rs's proof of the mapped request verifies here; a " +
           "weaker predicate, another nonce, a minor and a wrong " +
           "restriction are refused.");
  await rawRequest(ac, iss, alice);
  await w3cForm(ac);
  log.debug("Leaving anoncredsInterop().");
}

// The AnonCreds specification's own request object, with its date
// predicate convention (YYYYMMDD), proven both ways.
async function rawRequest(ac, iss, alice) {
  log.debug("Entering rawRequest().");
  var threshold = q.ageThresholdDateInt(18, new Date("2026-11-18"));
  assert.strictEqual(threshold, 20081118, "18 years before 2026-11-18");
  assert.strictEqual(q.ageThresholdDateInt(18, new Date("2028-02-29")),
                     20100228, "29 February in a year without one");
  var request = { name: "proof of age", version: "1.0",
    nonce: ours.createNonce(),
    requested_attributes: { attr1: { name: "name",
                                     restrictions: [{ cred_def_id: iss.cid }]
                                   } },
    requested_predicates: { adult: { name: "birthdate_dateint",
      p_type: "<=", p_value: threshold,
      restrictions: [{ cred_def_id: iss.cid }] } } };
  assert.deepStrictEqual(q.readAnoncredsRequest(request).errors, []);
  assert.match(q.readAnoncredsRequest({ name: "x", version: "1",
    nonce: "abc", requested_attributes: { a: { name: "n", names: ["m"] } },
    requested_predicates: { p: { name: "n", p_type: "==", p_value: 1.5 } }
  }).errors.join(" "), /decimal digits.*not both.*p_type.*integer/);
  var made = wallet.presentRequest(alice.bundle, request, alice.lsJwk);
  assert.strictEqual(theyAccept(ac, made.presentation, ctxFor(iss,
    request)), true, "anoncreds-rs verifies our proof of the raw request");
  var theirs = ac.Presentation.create(Object.assign({ credentials:
    [{ credential: alice.theirs }], credentialsProve: [
      { entryIndex: 0, referent: "attr1", isPredicate: false, reveal: true },
      { entryIndex: 0, referent: "adult", isPredicate: true, reveal: true }],
    selfAttest: {}, linkSecret: alice.ls }, ctxFor(iss, request))).toJson();
  var v = wallet.verifyForQuery(Object.assign({ presentation: theirs,
    request: request }, ctxFor(iss, null)));
  assert.ok(v.valid, "we verify anoncreds-rs's: " + v.errors.join("; "));
  // Read back as either language, the request keeps its predicate.
  var conv = q.specFromAnoncredsRequest(request, "pe");
  var model = q.normalise(q.buildQuery(conv.spec));
  assert.strictEqual(model.items[0].predicates[0].ops.bounds[0].p_value,
                     threshold);
  assert.deepStrictEqual(model.items[0].restrictions,
                         [{ cred_def_id: iss.cid }]);
  log.info("PASS a raw AnonCreds presentation request (birthdate_dateint " +
           "<= YYYYMMDD) proven by our wallet and verified by anoncreds-rs, " +
           "and anoncreds-rs's verified here; read into Presentation " +
           "Exchange with its restriction.");
  log.debug("Leaving rawRequest().");
}

async function w3cForm(ac) {
  log.debug("Entering w3cForm().");
  var iss = makeIssuer(ac, 2, ["name", "age"]);
  var held = issue(ac, iss, { name: "Carol", age: "40" }, true);
  var nonce = "w3c-predicates";
  var query = q.buildQuery({ language: "pe", id: "pid", format: "di_vc",
    reveal: ["name"], predicates: [{ name: "age", p_type: ">",
                                     p_value: 21 }] });
  var r = walletPresents(query, held, nonce);
  assert.ok(r.plan.ok, "W3C: planned: " + r.plan.refusals.join(" "));
  var pres = r.made.presentation;
  assert.ok(w3c.isW3cPresentation(pres), "the wallet answers in the W3C " +
            "form");
  assert.strictEqual(pres.verifiableCredential[0].credentialSubject.age,
                     true, "the predicate's attribute is true, not 40");
  assert.strictEqual(theyAccept(ac, pres, ctxFor(iss, r.made.request),
                                true), true, "anoncreds-rs verifies it");
  var v = wallet.verifyForQuery(Object.assign({ presentation: pres,
    item: r.model.items[0], nonce: nonce }, ctxFor(iss, null)));
  assert.ok(v.valid, "and verifyForQuery: " + v.errors.join("; "));
  log.info("PASS the W3C form: a PE predicate (age > 21) proven, shown as " +
           "true, verified by anoncreds-rs and here.");
  log.debug("Leaving w3cForm().");
}

async function main() {
  log.debug("Entering main().");
  presentationExchange();
  valuesMatching();
  extension();
  failClosed();
  await anoncredsInterop();
  log.info("vp_query_engine: all checks passed.");
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error("FAILED: " + (e && e.stack || e));
  process.exitCode = 1;
});
