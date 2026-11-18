// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: acdc_engine.js
//
// ---------------------------------------------------------------------------
// client/src/acdc.js in node (#480), held to signify-ts 0.4.1 — the
// released KERIA client vLEI credentials are issued through — and to the
// ACDC and CESR specifications' own vectors:
//
//   1. signify-ts issues: an inception, a registry (vcp), a credential with
//      its SAIDs, its iss, the two anchoring interaction events and their
//      CESR attachments, built with signify's own functions exactly as its
//      Credentials.issue() and Registries.create() build them (no KERIA:
//      the agent only stores what the client made). acdc.js verifies the
//      stream; then revokes nothing and tampers once.
//   2. acdc.js issues; signify-ts reads every event back (Serder), checks
//      every SAID (Saider.verify) and every signature (Verfer.verify), and
//      its attachment encoders produce the same -I triple and -V/-G
//      couples ours did.
//   3. The specifications' vectors: the CESR salt and sequence-number
//      encodings, and the ACDC spec's v2 rip SAID over its bytes as given.
//   4. What must fail: a tampered attribute, KEL signatures that do not
//      verify, a revoked credential, a v2 event (refused by name).
//
// No browser and no services, so this never skips.
// ---------------------------------------------------------------------------

const assert = require("assert");
const fs = require("fs");
const path = require("path");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "acdc_engine",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});
log.info("Log initialized. logLevel=" + log.level());

// In a checkout the sources are beside tests/; in the tests image they are
// the complete copy at /usr/src/source-tree.
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
const acdc = paths.requireSharedModule([path.join(repoRoot(), "client", "src",
  "acdc.js")], "client/src/acdc.js");

// signify-ts is ESM with an import-only export map.
async function loadSignify() {
  log.debug("Entering loadSignify().");
  // Its export map hides package.json, so the module is found by walking up
  // to a node_modules that has it.
  var file = null;
  (require.resolve.paths("signify-ts") || []).some(function (dir) {
    var candidate = path.join(dir, "signify-ts", "dist", "index.js");
    if (fs.existsSync(candidate)) file = candidate;
    return !!file;
  });
  if (!file) {
    throw new Error("signify-ts is not installed (tests/package.json).");
  }
  var s = Object.assign({}, await import(file));
  await s.ready();
  // Two it does not re-export from its index.
  var core = path.join(path.dirname(file), "keri", "core");
  s.vdr = (await import(path.join(core, "vdring.js"))).vdr;
  var utils = await import(path.join(core, "utils.js"));
  s.serializeIssExnAttachment = utils.serializeIssExnAttachment;
  s.serializeACDCAttachment = utils.serializeACDCAttachment;
  log.debug("Leaving loadSignify().");
  return s;
}

const text = function (b) {
  return Buffer.from(b).toString("utf8");
};

// ---------------------------------------------------------------------------
// 1. signify-ts issues, acdc.js verifies.
// ---------------------------------------------------------------------------

function signifyIssue(s) {
  log.debug("Entering signifyIssue().");
  var salter = new s.Salter({ raw: new TextEncoder()
    .encode("idprotodebugger1") });
  var signer = salter.signer(s.MtrDex.Ed25519_Seed, true, "0", s.Tier.low);
  var next = salter.signer(s.MtrDex.Ed25519_Seed, true, "1", s.Tier.low);
  var icp = s.incept({ keys: [signer.verfer.qb64],
    ndigs: [new s.Diger({}, next.verfer.qb64b).qb64],
    code: s.MtrDex.Blake3_256 });
  var pre = icp.pre;
  var vcp = s.vdr.incept({ pre: pre, cnfg: ["NB"] });
  var ixn1 = s.interact({ pre: pre, sn: 1, data: [{ i: vcp.pre, s: "0",
    d: vcp.sad.d }], dig: icp.sad.d, version: undefined, kind: undefined });
  var dt = new Date().toISOString().replace("Z", "000+00:00");
  var subject = s.Saider.saidify({ d: "", name: "Sunspot College",
                                   level: "gold", dt: dt })[1];
  var schema = s.Saider.saidify({ $id: "", $schema:
    "http://json-schema.org/draft-07/schema#", title: "Signify test",
    type: "object" }, undefined, undefined, "$id")[1];
  var cred = s.Saider.saidify({
    v: s.versify(s.Protocols.ACDC, undefined, s.Serials.JSON, 0), d: "",
    u: undefined, i: pre, ri: vcp.pre, s: schema.$id, a: subject,
    e: undefined, r: undefined })[1];
  var iss = s.Saider.saidify({
    v: s.versify(s.Protocols.KERI, undefined, s.Serials.JSON, 0),
    t: s.Ilks.iss, d: "", i: cred.d, s: "0", ri: vcp.pre, dt: dt })[1];
  var ixn2 = s.interact({ pre: pre, sn: 2, data: [{ i: iss.i, s: iss.s,
    d: iss.d }], dig: ixn1.sad.d, version: undefined, kind: undefined });
  var issSerder = new s.Serder(iss);
  var credSerder = new s.Serder(cred);
  var signedEvent = function (serder) {
    var sig = signer.sign(new TextEncoder().encode(serder.raw), 0);
    return text(s.messagize(serder, [sig]));
  };
  var couple = function (sn, said) {
    return text(s.serializeIssExnAttachment({ sn: sn, sad: { d: said } }));
  };
  var stream = signedEvent(icp) + signedEvent(ixn1) + signedEvent(ixn2) +
    vcp.raw + couple(1, ixn1.sad.d) + issSerder.raw + couple(2, ixn2.sad.d) +
    credSerder.raw + text(s.serializeACDCAttachment({ pre: cred.d, sn: 0,
                                                      sad: iss }));
  log.debug("Leaving signifyIssue().");
  return { stream: stream, schema: schema, cred: cred, iss: iss, ixn2: ixn2,
           signer: signer, pre: pre };
}

async function theirsVerifiedHere(s) {
  log.debug("Entering theirsVerifiedHere().");
  var t = signifyIssue(s);
  var r = acdc.verifyPresentation(t.stream, { schema: t.schema });
  assert.ok(r.valid, "signify-ts's issuance verifies here: " + r.reason +
            " " + JSON.stringify(r.checks.filter(function (c) {
              return !c.ok;
            })));
  assert.strictEqual(r.checks.length, 12, "every check ran");
  var tampered = t.stream.replace("Sunspot College", "Sunspot Collegf");
  assert.ok(!acdc.verifyPresentation(tampered).valid, "a changed attribute " +
            "breaks the credential's SAID");
  log.info("PASS signify-ts 0.4.1 issued a KEL, a registry, a credential " +
           "and its anchors; all " + r.checks.length + " checks pass here, " +
           "and a changed attribute fails.");
  log.debug("Leaving theirsVerifiedHere().");
}

// ---------------------------------------------------------------------------
// 2. acdc.js issues, signify-ts checks.
// ---------------------------------------------------------------------------

async function oursCheckedThere(s) {
  log.debug("Entering oursCheckedThere().");
  var ours = acdc.issue({ attributes: { name: "Sunspot College",
                                        level: "gold" } });
  var messages = acdc.parseStream(ours.stream);
  var verfer = new s.Verfer({ qb64: ours.key.verkey });
  messages.forEach(function (m, i) {
    var serder = new s.Serder(m.sad);
    assert.strictEqual(serder.raw, text(m.raw), "message " + i + ": signify " +
                       "serializes our event to the same bytes");
    // signify's Saider dummies one label; an icp or vcp also has i equal
    // to d, so its copy carries i already dummied.
    var sad = m.sad.t === "icp" || m.sad.t === "vcp" ?
        Object.assign({}, m.sad, { i: new Array(45).join("#") }) : m.sad;
    assert.ok(new s.Saider({ qb64: m.sad.d }).verify(sad, true, true,
                                                       undefined, "d"),
              "message " + i + " (" + (m.sad.t || "acdc") + "): signify " +
              "verifies its SAID");
    m.att.sigs.forEach(function (sig) {
      assert.ok(verfer.verify(sig.sig, m.raw), "message " + i + ": signify " +
                "verifies our signature");
    });
  });
  assert.ok(new s.Saider({ qb64: ours.acdc.a.d }).verify(ours.acdc.a, true,
                                                          false, undefined,
                                                          "d"),
            "signify verifies the attribute block's SAID");
  var triple = text(s.serializeACDCAttachment({ pre: ours.acdc.d, sn: 0,
                                                sad: ours.iss }));
  assert.ok(ours.stream.endsWith(JSON.stringify(ours.acdc) + triple),
            "signify writes the same -I triple after the ACDC");
  var couple = text(s.serializeIssExnAttachment({ sn: 2,
                                                  sad: ours.ixns[1] }));
  assert.ok(ours.stream.indexOf(JSON.stringify(ours.iss) + couple) !== -1,
            "and the same -V/-G couple after the iss");
  log.info("PASS acdc.js issued; signify-ts serializes every event to the " +
           "same bytes, verifies every SAID and signature, and writes the " +
           "same CESR attachments.");
  log.debug("Leaving oursCheckedThere().");
  return ours;
}

// ---------------------------------------------------------------------------
// 3. The specifications' vectors, and 4. refusals.
// ---------------------------------------------------------------------------

function vectors() {
  log.debug("Entering vectors().");
  assert.strictEqual(acdc.encodeMatter("0A", new TextEncoder().encode(
    "acdcspecworkraw0")), "0ABhY2Rjc3BlY3dvcmtyYXcw", "ACDC spec: the " +
    "first salt UUID");
  assert.strictEqual(acdc.seqner(0), "0AAAAAAAAAAAAAAAAAAAAAAA",
                     "CESR spec: sequence number 0");
  var rip = "{\"v\":\"ACDCCAACAAJSONAADa.\",\"t\":\"rip\"," +
    "\"d\":\"EPtolmh_NE2vC" +
    "02oFc7FOiWkPcEiKUPWm5uu_Gv1JZDw\",\"u\":\"0ABhY2Rjc3BlY3dvcmtyYXcy\"," +
    "\"i\":\"ECsGDKWAYtHBCkiDrzajkxs3Iw2g-dls3bLUsRP4yVdT\",\"n\":\"0\"," +
    "\"dt\":\"2025-07-04T17:52:00.000000+00:00\"}";
  assert.ok(acdc.checkSaid(rip).ok, "the ACDC spec's registry inception " +
            "SAID, over its bytes");
  assert.ok(!acdc.checkSaid(rip.replace("17:52", "17:53")).ok,
            "and not over different bytes");
  assert.throws(function () {
    acdc.parseStream(rip);
  }, /version 2/, "a v2 message is refused by name");
  log.info("PASS the specifications' vectors: salt and sequence number " +
           "encodings, the v2 rip SAID over its bytes, v2 refused by name.");
  log.debug("Leaving vectors().");
}

async function refusals(ours) {
  log.debug("Entering refusals().");
  // Re-sign the issuer's KEL with another key: every signature fails.
  var forged = ours.stream.replace(/-AAB[A-Za-z0-9_-]{88}/g, function () {
    return "-AAB" + acdc.encodeIndexed(new Uint8Array(64), 0);
  });
  var r = acdc.verifyPresentation(forged);
  assert.ok(!r.valid && /verified signature/.test(r.reason), "signatures " +
            "that do not verify: " + r.reason);
  var revoked = acdc.verifyPresentation(acdc.revoke(ours));
  assert.ok(!revoked.valid && revoked.revoked, "a revoked credential is " +
            "reported revoked");
  log.info("PASS refusals: forged KEL signatures, and a revocation.");
  log.debug("Leaving refusals().");
}

async function main() {
  log.debug("Entering main().");
  var s = await loadSignify();
  await theirsVerifiedHere(s);
  var ours = await oursCheckedThere(s);
  vectors();
  await refusals(ours);
  log.info("acdc_engine: all checks passed.");
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error("FAILED: " + (e && e.stack || e));
  process.exitCode = 1;
});
