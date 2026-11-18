// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: anoncreds_engine.js
//
// ---------------------------------------------------------------------------
// AnonCreds (client/src/anoncreds.js; #479), held to anoncreds-rs v0.2.3 —
// the implementation the AnonCreds ecosystem runs — in every direction. The
// specification publishes no test vectors, and a CL implementation checked
// only against itself can verify its own proofs and interoperate with
// nothing, so anoncreds-rs (tests/anoncreds_witness.js) is the issuer, a
// second holder and a second verifier here:
//
//   * the fixed vectors anoncreds-clsignatures and anoncreds-rs test with:
//     the hash, and twelve attribute encodings;
//   * anoncreds-rs issues against OUR credential request, and we process
//     the credential (signature, signature correctness proof); anoncreds-rs
//     processing the same issuance reaches the same v;
//   * OUR presentations verify in anoncreds-rs, and ITS verify here: a
//     revealed attribute, a revealed group, an unrevealed referent, a
//     self-attested one, predicates of all four types including over a
//     negative value, two credentials under one link secret, restrictions;
//   * what must fail here: a changed revealed value, another nonce, a
//     forged c_list, two credentials under different link secrets, a
//     tampered key correctness proof (the request refuses it), a tampered
//     signature correctness proof (processing refuses it), an unmet
//     restriction — and a predicate the request did not ask for, which
//     anoncreds-rs 0.2.3 itself accepts (it never compares p_value), shown
//     so that the stricter check here is deliberate.
//
// Fails, naming the image, when the witness is not available.
// ---------------------------------------------------------------------------

const assert = require("assert");
const fs = require("fs");
const path = require("path");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "anoncreds_engine",
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

const paths = require("./module_paths.js");
const ours = paths.requireSharedModule([path.join(repoRoot(), "client",
  "src", "anoncreds.js")], "client/src/anoncreds.js");
const witness = require("./anoncreds_witness.js");
const rev = paths.requireSharedModule([path.join(repoRoot(), "client", "src",
  "anoncreds_revocation.js")], "client/src/anoncreds_revocation.js");
const os = require("os");

const ISSUER = "did:example:issuer";
const VECTORS = [
  ["101 Wilson Lane", "6808694323716498273433342828078430055056538172353" +
   "2936263016368251445461241953"],
  ["87121", "87121"],
  ["SLC", "10132735397958824686987324976605818899568111372261859362104363" +
   "8294296500696424"],
  ["UT", "938566296706578303519912209890311304993135593325494276379406457" +
   "77813964461231"],
  ["", "1029873362495540970295352123225813227897999006481980349933793970" +
   "01115665086549"],
  ["None", "9976940453552036077599142056910345044278994565524076048776132" +
   "2098828903685777"],
  ["2147483647", "2147483647"],
  ["2147483648", "26221484005389514539852548961319751347124425277437769688" +
   "639924217837557266135"],
  ["-2147483648", "-2147483648"],
  ["-2147483649", "689569154250959395799094005664528720853538646671221128" +
   "03508671228696852865689"],
  ["0.0", "6283860721856435363002847347393995732894362630645868686733253488" +
   "9076311281879"],
  ["\u0000", "49846369543417741186729467304575255505141344055555831574636" +
   "310663216789168157"]
];

function vectors() {
  log.debug("Entering vectors().");
  var h = ours.hashInts([
    BigInt("0xff9d2eedfee9cffd9ef6dbffedff3fcb" +
           "ef4caecb9bffe79bfa94d3fdf6abfbff"),
    BigInt("0xff9d2eedfee9cffd9ef6dbffedff3fcbef4caecb9bffe79bfa9168615ccbc546")
  ]);
  assert.strictEqual(h.toString(16), "2c2566c22e04ab3f18b3ba693823175002f1" +
                     "0f400811363d26bbb33633ac8bad", "the hash vector");
  VECTORS.forEach(function (v) {
    assert.strictEqual(ours.encodeAttribute(v[0]), v[1],
                       "encoding of " + JSON.stringify(v[0]));
  });
  log.info("PASS the hash vector and twelve attribute encodings.");
  log.debug("Leaving vectors().");
}

// An issuer (anoncreds-rs): a schema and a credential definition.
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

// anoncreds-rs issues to OUR holder; returns our processed credential and
// anoncreds-rs's processing of the same.
function issueToUs(ac, iss, ls, raw) {
  log.debug("Entering issueToUs().");
  var offer = ac.CredentialOffer.create({ schemaId: iss.sid,
    credentialDefinitionId: iss.cid, keyCorrectnessProof: iss.kcp }).toJson();
  var made = ours.createCredentialRequest({ credentialOffer: offer,
    credentialDefinition: iss.cd, linkSecret: ls, linkSecretId: "ls",
    entropy: "holder-entropy" });
  var issued = ac.Credential.create({ credentialDefinition: iss.cd,
    credentialDefinitionPrivate: iss.cdp, credentialOffer: offer,
    credentialRequest: made.credentialRequest,
    attributeRawValues: raw }).toJson();
  var mine = ours.processCredential(issued, { credentialRequestMetadata:
    made.credentialRequestMetadata, linkSecret: ls,
    credentialDefinition: iss.cd });
  var theirs = ac.Credential.fromJson(issued).process({
    credentialRequestMetadata: made.credentialRequestMetadata,
    linkSecret: ls, credentialDefinition: iss.cd }).toJson();
  log.debug("Leaving issueToUs().");
  return { mine: mine, theirs: theirs, issued: issued, offer: offer,
           made: made };
}

function verifyBoth(ac, pres, ctx, label) {
  log.debug("Entering verifyBoth(). " + label);
  var theirs = ac.Presentation.fromJson(pres).verify(ctx);
  var mine = ours.verifyPresentation(pres, ctx);
  log.debug("Leaving verifyBoth().");
  return { theirs: theirs, mine: mine };
}

async function interop() {
  log.debug("Entering interop().");
  var w = await witness.load();
  var ac = w.ac;
  var person = makeIssuer(ac, 1, ["name", "age", "Given Name"]);
  var licence = makeIssuer(ac, 2, ["class", "points"]);
  var ls = ours.createLinkSecret();
  var a = issueToUs(ac, person, ls, { name: "Alice", age: "-7",
                                      "Given Name": "Al ☺" });
  assert.strictEqual(a.mine.signature.p_credential.v,
                     a.theirs.signature.p_credential.v,
                     "both holders reach the same v");
  var b = issueToUs(ac, licence, ls, { class: "B", points: "3" });
  log.info("PASS anoncreds-rs issued against our requests; our processing " +
           "(signature, signature correctness proof) agrees with its own.");

  var schemas = {};
  schemas[person.sid] = person.schema;
  schemas[licence.sid] = licence.schema;
  var cds = {};
  cds[person.cid] = person.cd;
  cds[licence.cid] = licence.cd;
  var preq = { nonce: ours.createNonce(), name: "pr", version: "1.0",
    requested_attributes: {
      one: { name: "name", restrictions: { cred_def_id: person.cid } },
      grp: { names: ["Given Name", "name"] },
      hidden: { name: "class" },
      phone: { name: "phone" } },
    requested_predicates: {
      le: { name: "age", p_type: "<=", p_value: -7 },
      lt: { name: "age", p_type: "<", p_value: 0 },
      gt: { name: "age", p_type: ">", p_value: -100 },
      ge: { name: "points", p_type: ">=", p_value: 3,
            restrictions: [{ schema_name: "s2" }] } } };
  var prove = [
    { entryIndex: 0, referent: "one", isPredicate: false, reveal: true },
    { entryIndex: 0, referent: "grp", isPredicate: false, reveal: true },
    { entryIndex: 0, referent: "le", isPredicate: true, reveal: true },
    { entryIndex: 0, referent: "lt", isPredicate: true, reveal: true },
    { entryIndex: 0, referent: "gt", isPredicate: true, reveal: true },
    { entryIndex: 1, referent: "hidden", isPredicate: false, reveal: false },
    { entryIndex: 1, referent: "ge", isPredicate: true, reveal: true }];
  var opts = { presentationRequest: preq, credentialsProve: prove,
               selfAttest: { phone: "555-0100" }, linkSecret: ls,
               schemas: schemas, credentialDefinitions: cds };
  var ctx = { presentationRequest: preq, schemas: schemas,
              credentialDefinitions: cds };
  var mine = ours.createPresentation(Object.assign({ credentials:
    [{ credential: a.mine }, { credential: b.mine }] }, opts));
  var r = verifyBoth(ac, mine, ctx, "ours");
  assert.ok(r.theirs, "anoncreds-rs verifies our presentation");
  assert.ok(r.mine.valid, "and so do we: " + r.mine.errors.join("; "));
  var theirs = ac.Presentation.create(Object.assign({ credentials:
    [{ credential: a.theirs }, { credential: b.theirs }] }, opts)).toJson();
  r = verifyBoth(ac, theirs, ctx, "theirs");
  assert.ok(r.theirs, "anoncreds-rs verifies its own");
  assert.ok(r.mine.valid, "we verify anoncreds-rs's presentation: " +
            r.mine.errors.join("; "));
  assert.deepStrictEqual(r.mine.warnings, [], "no raw/encoded warnings");
  log.info("PASS two credentials under one link secret — a revealed " +
           "attribute, a group, an unrevealed and a self-attested " +
           "referent, <=, <, > over a negative value and >=, with " +
           "restrictions — ours verifying in anoncreds-rs, theirs here.");
  negatives(ac, mine, ctx, opts, person, a, b);
  log.debug("Leaving interop().");
}

// anoncreds-rs answers a bad presentation with false or by throwing
// ("Proof rejected: ..."); both are a refusal.
function theyAccept(ac, pres, ctx) {
  log.debug("Entering theyAccept().");
  try {
    var ok = ac.Presentation.fromJson(pres).verify(ctx);
    log.debug("Leaving theyAccept(). " + ok);
    return ok;
  } catch (e) {
    log.debug("Leaving theyAccept(). Rejected: " + e.message);
    return false;
  }
}

function negatives(ac, mine, ctx, opts, person, a) {
  log.debug("Entering negatives().");
  var copy = function (o) {
    return JSON.parse(JSON.stringify(o));
  };
  var changed = copy(mine);
  changed.requested_proof.revealed_attrs.one.raw = "Mallory";
  changed.requested_proof.revealed_attrs.one.encoded =
    ours.encodeAttribute("Mallory");
  assert.ok(!ours.verifyPresentation(changed, ctx).valid,
            "a changed revealed value fails here");
  assert.ok(!theyAccept(ac, changed, ctx),
            "and in anoncreds-rs");
  var otherNonce = Object.assign({}, ctx, { presentationRequest:
    Object.assign({}, ctx.presentationRequest, { nonce: "12345" }) });
  assert.ok(!ours.verifyPresentation(mine, otherNonce).valid,
            "another nonce fails here");
  assert.ok(!theyAccept(ac, mine, otherNonce),
            "and in anoncreds-rs");
  var forged = copy(mine);
  forged.proof.aggregated_proof.c_list[0][3] ^= 1;
  assert.ok(/c_list/.test(ours.verifyPresentation(forged, ctx).errors
    .join(" ")), "a forged c_list is named here");
  // Two credentials whose link-secret responses differ: not one holder.
  var split = copy(mine);
  split.proof.proofs[1].primary_proof.eq_proof.m.master_secret = "12345";
  assert.ok(/different link secret/.test(ours.verifyPresentation(split,
    ctx).errors.join(" ")), "two link secrets are named here");
  assert.ok(!theyAccept(ac, split, ctx),
            "and refused in anoncreds-rs");
  // A predicate the request did not ask for: proved <= -7, asked <= -8.
  var stricter = copy(ctx.presentationRequest);
  stricter.requested_predicates.le.p_value = -8;
  var askedOther = Object.assign({}, ctx, { presentationRequest: stricter });
  assert.ok(/no sub-proof proves age <= -8/.test(ours.verifyPresentation(
    mine, askedOther).errors.join(" ")), "a predicate other than the " +
    "request's fails here");
  assert.strictEqual(theyAccept(ac, mine, askedOther), true,
    "anoncreds-rs 0.2.3 accepts it (it never compares p_value), which is " +
    "why this check is ours");
  var unmet = copy(ctx.presentationRequest);
  unmet.requested_attributes.one.restrictions = { cred_def_id: "other" };
  assert.ok(/restrictions/.test(ours.verifyPresentation(mine, Object.assign(
    {}, ctx, { presentationRequest: unmet })).errors.join(" ")),
    "an unmet restriction fails here");
  // The issuance proofs.
  var kcp = copy(a.offer);
  kcp.key_correctness_proof.c = String(BigInt(kcp.key_correctness_proof.c) +
                                       BigInt(1));
  assert.throws(function () {
    ours.createCredentialRequest({ credentialOffer: kcp,
      credentialDefinition: person.cd, linkSecret: opts.linkSecret,
      entropy: "x" });
  }, /key correctness proof/, "a tampered key correctness proof is " +
    "refused before any request is made");
  var scp = copy(a.issued);
  scp.signature_correctness_proof.se = String(BigInt(
    scp.signature_correctness_proof.se) + BigInt(1));
  assert.throws(function () {
    ours.processCredential(scp, { credentialRequestMetadata:
      a.made.credentialRequestMetadata, linkSecret: opts.linkSecret,
      credentialDefinition: person.cd });
  }, /signature correctness proof/, "a tampered signature correctness " +
    "proof is refused");
  var otherValue = copy(a.issued);
  otherValue.values.name.encoded = ours.encodeAttribute("Mallory");
  assert.throws(function () {
    ours.processCredential(otherValue, { credentialRequestMetadata:
      a.made.credentialRequestMetadata, linkSecret: opts.linkSecret,
      credentialDefinition: person.cd });
  }, /does not verify/, "a credential whose value was changed is refused");
  assert.throws(function () {
    ours.createPresentation(Object.assign({}, opts, { credentials:
      [{ credential: a.mine }], presentationRequest: { nonce: "1",
        name: "x", version: "1", requested_attributes: { r: { name: "age" } },
        requested_predicates: { p: { name: "age", p_type: ">=",
                                     p_value: -9 } } },
      credentialsProve: [
        { entryIndex: 0, referent: "r", isPredicate: false, reveal: true },
        { entryIndex: 0, referent: "p", isPredicate: true, reveal: true }] }));
  }, /both revealed/, "an attribute both revealed and predicated is " +
    "refused, as CL refuses it");
  log.info("PASS what must fail: a changed value, another nonce, a forged " +
           "c_list, two link secrets, a predicate the request did not ask " +
           "for (accepted by anoncreds-rs 0.2.3), an unmet restriction, and " +
           "tampered issuance proofs and values.");
  log.debug("Leaving negatives().");
}

// --- revocation: the CKS accumulator and the non-revocation proof -------
// A revocable registry from anoncreds-rs, for each of its two issuance
// modes: our holder requests (ur), processes (three pairing checks), builds
// its revocation state from the tails file and presents with a
// non-revocation proof that anoncreds-rs verifies; anoncreds-rs's own
// presentation verifies here; and after revocation our holder refuses and
// a proof against the later accumulator fails.
async function revocation() {
  log.debug("Entering revocation().");
  var ac = (await witness.load()).ac;
  var tailsDir = fs.mkdtempSync(path.join(os.tmpdir(), "ac-tails-"));
  var I = ISSUER;
  for (const byDefault of [true, false]) {
    var tag = byDefault ? "default" : "ondemand";
    var sid = I + "/schema/rev-" + tag;
    var cid = I + "/creddef/rev-" + tag;
    var rid = I + "/revreg/rev-" + tag;
    var schema = ac.Schema.create({ name: "rev-" + tag, version: "1.0",
      issuerId: I, attributeNames: ["name", "age"] });
    var made = ac.CredentialDefinition.create({ schemaId: sid, issuerId: I,
      schema: schema, signatureType: "CL", tag: tag, supportRevocation: true });
    var cdO = made.credentialDefinition;
    var cd = cdO.toJson();
    var reg = ac.RevocationRegistryDefinition.create({
      credentialDefinition: cdO, credentialDefinitionId: cid, tag: tag,
      issuerId: I, revocationRegistryType: "CL_ACCUM",
      maximumCredentialNumber: 8, tailsDirectoryPath: tailsDir });
    var rrdO = reg.revocationRegistryDefinition;
    var rrdp = reg.revocationRegistryDefinitionPrivate;
    var rrd = rrdO.toJson();
    var t0 = 1700000000;
    var slO = ac.RevocationStatusList.create({ credentialDefinition: cdO,
      revocationRegistryDefinitionId: rid, revocationRegistryDefinition: rrdO,
      revocationRegistryDefinitionPrivate: rrdp, issuerId: I,
      issuanceByDefault: byDefault, timestamp: t0 });
    var offer = ac.CredentialOffer.create({ schemaId: sid,
      credentialDefinitionId: cid,
      keyCorrectnessProof: made.keyCorrectnessProof }).toJson();
    var ls = ours.createLinkSecret();
    var req = ours.createCredentialRequest({ credentialOffer: offer,
      credentialDefinition: cd, linkSecret: ls, linkSecretId: "ls",
      entropy: "rev-" + tag });
    assert.ok(req.credentialRequest.blinded_ms.ur, tag + ": ur is sent");
    var issued = ac.Credential.create({ credentialDefinition: cdO,
      credentialDefinitionPrivate: made.credentialDefinitionPrivate,
      credentialOffer: offer, credentialRequest: req.credentialRequest,
      attributeRawValues: { name: "Bob", age: "40" },
      revocationConfiguration: new ac.CredentialRevocationConfig({
        registryDefinition: rrdO, registryDefinitionPrivate: rrdp,
        statusList: slO, registryIndex: 5 }) }).toJson();
    if (!byDefault) {
      slO.update({ credentialDefinition: cdO, revocationRegistryDefinition:
        rrdO, revocationRegistryDefinitionPrivate: rrdp, issued: [5],
        timestamp: t0 });
    }
    var mine = ours.processCredential(issued, { credentialRequestMetadata:
      req.credentialRequestMetadata, linkSecret: ls, credentialDefinition: cd,
      revocationRegistryDefinition: rrd });
    var tails = new Uint8Array(fs.readFileSync(rrdO.getTailsLocation()));
    var sl = Object.assign({ revRegDefId: rid }, slO.toJson());
    var state = rev.revocationState({ credential: mine,
      credentialDefinition: cd, revocationRegistryDefinition: rrd,
      revocationStatusList: sl, tailsBytes: tails });
    var preq = { nonce: ours.createNonce(), name: "pr", version: "1.0",
      requested_attributes: { a1: { name: "name" } },
      requested_predicates: { p1: { name: "age", p_type: ">=",
                                    p_value: 18 } },
      non_revoked: { from: t0, to: t0 + 10 } };
    var schemas = {};
    schemas[sid] = schema.toJson();
    var cds = {};
    cds[cid] = cd;
    var rrds = {};
    rrds[rid] = rrd;
    var ctx = { presentationRequest: preq, schemas: schemas,
                credentialDefinitions: cds,
                revocationRegistryDefinitions: rrds,
                revocationStatusLists: [sl] };
    var prove = [
      { entryIndex: 0, referent: "a1", isPredicate: false, reveal: true },
      { entryIndex: 0, referent: "p1", isPredicate: true, reveal: true }];
    var pres = ours.createPresentation({ presentationRequest: preq,
      credentials: [{ credential: mine, timestamp: t0,
                      revocationState: state }],
      credentialsProve: prove, selfAttest: {}, linkSecret: ls,
      schemas: schemas, credentialDefinitions: cds });
    assert.ok(pres.proof.proofs[0].non_revoc_proof, tag + ": a " +
              "non-revocation proof is made");
    var rrdsO = {};
    rrdsO[rid] = rrdO;
    var theirCtx = Object.assign({}, ctx, { revocationRegistryDefinitions:
      rrdsO, revocationStatusLists: [slO] });
    assert.strictEqual(theyAccept(ac, pres, theirCtx), true, tag +
                       ": anoncreds-rs verifies our non-revocation proof");
    var v = ours.verifyPresentation(pres, ctx);
    assert.ok(v.valid, tag + ": and so do we: " + v.errors.join("; "));
    if (byDefault) {
      var theirState = ac.CredentialRevocationState.create({
        revocationRegistryDefinition: rrdO, revocationStatusList: slO,
        revocationRegistryIndex: 5, tailsPath: rrdO.getTailsLocation() });
      var proc = ac.Credential.fromJson(issued).process({
        credentialRequestMetadata: req.credentialRequestMetadata,
        linkSecret: ls, credentialDefinition: cdO,
        revocationRegistryDefinition: rrdO });
      var theirs = ac.Presentation.create({ presentationRequest: preq,
        credentials: [{ credential: proc, timestamp: t0,
                        revocationState: theirState }],
        credentialsProve: prove, selfAttest: {}, linkSecret: ls,
        schemas: schemas, credentialDefinitions: cds }).toJson();
      v = ours.verifyPresentation(theirs, ctx);
      assert.ok(v.valid, "we verify anoncreds-rs's non-revocation proof: " +
                v.errors.join("; "));
      var stripped = JSON.parse(JSON.stringify(theirs));
      stripped.proof.proofs[0].non_revoc_proof = null;
      assert.ok(/carries no non-revocation proof/.test(
        ours.verifyPresentation(stripped, ctx).errors.join(" ")),
        "a stripped non-revocation proof is named (anoncreds-rs 0.2.3 " +
        "would verify the rest as if none had been asked for)");
    }
    slO.update({ credentialDefinition: cdO, revocationRegistryDefinition:
      rrdO, revocationRegistryDefinitionPrivate: rrdp, revoked: [5],
      timestamp: t0 + 100 });
    var revoked = Object.assign({ revRegDefId: rid }, slO.toJson());
    assert.throws(function () {
      rev.revocationState({ credential: mine, credentialDefinition: cd,
        revocationRegistryDefinition: rrd, revocationStatusList: revoked,
        tailsBytes: tails });
    }, /no witness/, tag + ": a revoked credential gets no state");
    var later = Object.assign({}, sl, { currentAccumulator:
      revoked.currentAccumulator });
    assert.ok(!ours.verifyPresentation(pres, Object.assign({}, ctx,
      { revocationStatusLists: [later] })).valid, tag + ": the proof " +
      "fails against the accumulator after revocation");
    log.info("PASS revocation, issuance " + (byDefault ? "by default" :
      "on demand") + ": our request, processing, witness and non-" +
      "revocation proof against anoncreds-rs; revoked refused.");
  }
  fs.rmSync(tailsDir, { recursive: true, force: true });
  log.debug("Leaving revocation().");
}

async function main() {
  log.debug("Entering main().");
  vectors();
  await interop();
  await revocation();
  log.info("anoncreds_engine: all checks passed.");
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error("FAILED: " + (e && e.stack || e));
  process.exitCode = 1;
});
