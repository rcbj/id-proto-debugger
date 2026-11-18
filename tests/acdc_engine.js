// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: acdc_engine.js
//
// ---------------------------------------------------------------------------
// client/src/acdc.js in node (#480), held to signify-ts 0.4.1 — the
// released KERIA client vLEI credentials are issued through — and to the
// KERI, ACDC and CESR specifications' own vectors (keri-ts and cesr-ts are
// acdc_keri_ts.js's):
//
//   1. signify-ts issues: an inception, a registry (vcp), a credential with
//      its SAIDs, its iss, the two anchoring interaction events and their
//      CESR attachments, built with signify's own functions exactly as its
//      Credentials.issue() and Registries.create() build them (no KERIA:
//      the agent only stores what the client made). acdc.js verifies the
//      stream; a changed attribute does not.
//   2. acdc.js issues; signify-ts reads every event back (Serder), checks
//      every SAID (Saider.verify) and every signature (Verfer.verify), and
//      its attachment encoders produce the same -I triple and -V/-G
//      couples ours did.
//   3. IPEX both ways: signify-ts's exchange() and messagize() build a
//      grant that verifies here; ours is re-serialized by signify-ts to the
//      same bytes, its e.d and signature verify there, and signify's
//      exchange() writes the same pathed attachments.
//   4. The specifications' vectors (tests/fixtures/acdc_vectors.json): the
//      KERI v2 icp/ixn/rot/dip/drt/rct and next-key digests, the ACDC v2
//      rip/acm (full and most compact)/upd/bup, the transcript ACDC whose
//      4.0 only a byte-level SAID check survives, the schemas, the blinded
//      state BLIDs, the CESR -X group and path encodings.
//   5. The specifications' KEYS: the annex derives them from a salt with
//      argon2id (keripy's Salter), so Amy's and Cal's inceptions are
//      rebuilt, signed and witnessed, and Cal's accreditation ACDC — the
//      spec's own bytes — verifies end to end through its rip and an upd.
//      Its schema's erratum (it requires "score") is reported.
//   6. What must fail: KEL signatures, a weighted threshold short, a
//      witness short, an unapproved delegation, duplicity, a rotation to
//      uncommitted keys, a changed attribute (v1 and v2), a changed
//      aggregate block, a wrong schema, backer receipts short, edges (I2I,
//      DI2I, NOT, OR, AND, NAND, NOR, AVG refused, a revoked or missing far
//      node), a forged grant, a CBOR body.
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
    if (fs.existsSync(candidate)) {
      file = candidate;
    }
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
  log.debug("Entering text().");
  log.debug("Leaving text().");
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
    log.debug("Entering signedEvent().");
    log.debug("Leaving signedEvent().");
    var sig = signer.sign(new TextEncoder().encode(serder.raw), 0);
    return text(s.messagize(serder, [sig]));
  };
  var couple = function (sn, said) {
    log.debug("Entering couple().");
    log.debug("Leaving couple().");
    return text(s.serializeIssExnAttachment({ sn: sn, sad: { d: said } }));
  };
  var stream = signedEvent(icp) + signedEvent(ixn1) + signedEvent(ixn2) +
    vcp.raw + couple(1, ixn1.sad.d) + issSerder.raw + couple(2, ixn2.sad.d) +
    credSerder.raw + text(s.serializeACDCAttachment({ pre: cred.d, sn: 0,
                                                      sad: iss }));
  log.debug("Leaving signifyIssue().");
  return { stream: stream, schema: schema, cred: cred, iss: iss, ixn2: ixn2,
           signer: signer, pre: pre, icp: icp, issSerder: issSerder,
           credSerder: credSerder };
}

async function theirsVerifiedHere(s) {
  log.debug("Entering theirsVerifiedHere().");
  var t = signifyIssue(s);
  var r = acdc.verifyPresentation(t.stream, { schema: t.schema });
  assert.ok(r.valid, "signify-ts's issuance verifies here: " + r.reason +
            " " + JSON.stringify(r.checks.filter(function (c) {
              return !c.ok;
            })));
  assert.ok(r.checks.length >= 11, "every check ran: " + r.checks.length);
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
// 3. IPEX both ways.
// ---------------------------------------------------------------------------

var WHEN = "2025-01-01T00:00:00.000000+00:00";

async function grants(s) {
  log.debug("Entering grants().");
  var enc = new TextEncoder();
  var t = signifyIssue(s);
  var recipient = acdc.makeController({}).prefix;
  var ancSig = t.signer.sign(enc.encode(t.ixn2.raw), 0);
  var ancAtc = text(s.messagize(t.ixn2, [ancSig])).slice(t.ixn2.raw.length);
  var acdcAtc = text(s.serializeACDCAttachment({ pre: t.cred.d, sn: 0,
                                                 sad: t.iss }));
  var issAtc = text(s.serializeIssExnAttachment({ sn: 2, sad: t.ixn2.sad }));
  var made = s.exchange("/ipex/grant", { m: "" }, t.pre, recipient, WHEN,
    undefined, undefined, { acdc: [t.credSerder, acdcAtc],
                            iss: [t.issSerder, issAtc],
                            anc: [t.ixn2, ancAtc] });
  var sig = t.signer.sign(enc.encode(made[0].raw), 0);
  var theirs = text(s.messagize(made[0], [sig], ["SealEvent", { i: t.pre,
    s: "0", d: t.icp.sad.d }])) + text(made[1]);
  var r = acdc.verifyExchange(t.stream + theirs, { schema: t.schema });
  assert.ok(r.valid, "signify-ts's grant verifies here: " + r.reason);
  var forged = theirs.replace(/-AAB(A.{40})(.)/, function (m, a, b) {
    return "-AAB" + a + (b === "A" ? "B" : "A");
  });
  assert.ok(!acdc.verifyExchange(t.stream + forged).valid, "a grant whose " +
            "signature is changed does not");
  log.info("PASS signify-ts's IPEX grant (exchange(), messagize() with its " +
           "-F seal, -L pathed e.acdc / e.iss / e.anc) verifies here, and " +
           "the credential it carries.");
  var holder = acdc.makeController({});
  var ours = acdc.issue({ attributes: { name: "Sunspot College" },
                          recipient: holder.prefix });
  var g = acdc.grant(ours, { when: WHEN });
  var m = acdc.parseStream(g.text)[0];
  var serder = new s.Serder(m.sad);
  assert.strictEqual(serder.raw, m.text, "signify serializes our exn to " +
                     "the same bytes");
  assert.ok(new s.Saider({ qb64: m.sad.d }).verify(m.sad, true, true,
                                                    undefined, "d"),
            "signify verifies the exn's SAID");
  assert.ok(new s.Saider({ qb64: m.sad.e.d }).verify(m.sad.e, true, false,
                                                      undefined, "d"),
            "and e.d over the embeds");
  assert.ok(new s.Verfer({ qb64: ours.key.verkey }).verify(
    m.att.transSigGroups[0].sigs[0].sig, m.raw), "and our signature");
  var anc = ours.issAnchor;
  assert.deepStrictEqual(m.att.pathed.map(function (x) {
    return x.path.join(".");
  }), ["e.acdc", "e.iss", "e.anc"], "three pathed groups");
  var ourAcdcAtc = acdc.group("SealSourceTriples", ours.acdc.d +
    acdc.seqner(0) + ours.iss.d, 1, 1);
  assert.strictEqual(ourAcdcAtc, text(s.serializeACDCAttachment({
    pre: ours.acdc.d, sn: 0, sad: ours.iss })), "the e.acdc attachment");
  var signifyIss = text(s.serializeIssExnAttachment({ sn: parseInt(anc.s,
    16), sad: anc }));
  var ancText = ours.ctl.events.filter(function (e) {
    return e.sad.d === anc.d;
  })[0].text.slice(JSON.stringify(anc).length);
  var again = s.exchange("/ipex/grant", { m: "" }, ours.ctl.prefix,
    holder.prefix, WHEN, undefined, undefined,
    { acdc: [new s.Serder(ours.acdc), ourAcdcAtc],
      iss: [new s.Serder(ours.iss), signifyIss],
      anc: [new s.Serder(anc), ancText] });
  assert.strictEqual(again[0].raw, m.text, "signify's exchange() builds " +
                     "the same exn from the same embeds");
  assert.ok(g.text.endsWith(text(again[1])), "and the same pathed " +
            "attachments after the signature group");
  log.info("PASS our IPEX grant: signify-ts re-serializes it to the same " +
           "bytes, verifies its SAID, e.d and signature, and its exchange() " +
           "builds the same exn and pathed attachments.");
  log.debug("Leaving grants().");
}

// ---------------------------------------------------------------------------
// 4. The specifications' vectors.
// ---------------------------------------------------------------------------

const V = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures",
                                               "acdc_vectors.json"), "utf8"));

function body(t) {
  log.debug("Entering body().");
  log.debug("Leaving body().");
  return acdc.parseStream(t)[0];
}

function vectors() {
  log.debug("Entering vectors().");
  assert.strictEqual(acdc.encodeMatter("0A", new TextEncoder().encode(
    "acdcspecworkraw0")), "0ABhY2Rjc3BlY3dvcmtyYXcw", "ACDC spec: the " +
    "first salt UUID");
  assert.strictEqual(acdc.seqner(0), "0AAAAAAAAAAAAAAAAAAAAAAA",
                     "CESR spec: sequence number 0");
  assert.strictEqual(acdc.encodeNumber(1), "MAAB", "a v2 Number");
  assert.strictEqual(acdc.encodePath([]), "6AABAAA-", "the empty path");
  assert.strictEqual(acdc.encodePath(["e", "acdc"]), "4AACA-e-acdc");
  assert.strictEqual(acdc.encodePath(["e", "iss"]), "5AACAA-e-iss");
  assert.strictEqual(acdc.encodePath(["a", "personal"]), "4AADA-a-personal",
                     "CESR spec: a SAD path");
  assert.strictEqual(acdc.encodePath(["5", "3", "name"]),
                     "6AADAAA-5-3-name", "CESR spec: a SAD path");
  assert.deepStrictEqual(acdc.decodePath(acdc.decodeMatter(
    "6AADAAA-5-3-name")), ["5", "3", "name"]);
  var gc = acdc.decodeCounter("-_AAACAA", 1);
  assert.ok(gc.major === 2 && gc.minor === 0, "the genus version counter");
  // The CESR spec's -X example: one group, three -K signatures.
  var x = acdc.parseStream(V.keri.icp + V.cesr.tsg)[0].att;
  assert.strictEqual(x.transSigGroups.length, 1);
  assert.strictEqual(x.transSigGroups[0].sigs.length, 3, "-KBC: three " +
                     "signatures in 0x42 quadlets");
  assert.strictEqual(x.transSigGroups[0].i,
                     "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB");
  Object.keys(V.keri).concat(Object.keys(V.acdc)).forEach(function (k) {
    var t = V.keri[k] !== undefined ? V.keri[k] : V.acdc[k];
    if (typeof t !== "string") {
      return;
    }
    assert.strictEqual(acdc.checkBody(body(t)), "", "spec vector " + k);
  });
  var icp = body(V.keri.icp).sad;
  var rot = body(V.keri.rot).sad;
  V.keri.icpNextKeys.forEach(function (key, i) {
    assert.strictEqual(acdc.digestQb64(key), icp.n[i], "icp's next-key " +
                       "digest " + i);
  });
  assert.deepStrictEqual(rot.k, V.keri.icpNextKeys, "the rotation's keys " +
                         "are the ones icp committed to");
  V.keri.rotNextKeys.forEach(function (key, i) {
    assert.strictEqual(acdc.digestQb64(key), rot.n[i]);
  });
  var tf = body(V.acdc.transcriptFull);
  assert.ok(V.acdc.transcriptFull.indexOf("\"english\":4.0") !== -1,
            "the transcript carries Python's 4.0");
  assert.strictEqual(tf.sad.d, body(V.acdc.transcriptCompact).sad.d,
                     "full and most compact form, one SAID");
  var ca = acdc.checkAcdcSaid(tf);
  assert.ok(ca.ok && ca.compact === V.acdc.transcriptCompact,
            "the most compact form spliced from the received bytes IS the " +
            "spec's compact form, 4.0 and all");
  var resaid = acdc.checkAcdcSaid(body(JSON.stringify(JSON.parse(
    V.acdc.transcriptFull)).replace("ACDCCAACAAJSONAAXG.",
                                    "ACDCCAACAAJSONAAXE.")));
  assert.ok(!resaid.ok, "re-serialized by JSON.stringify (4.0 -> 4) the " +
            "SAIDs no longer verify: " + resaid.problems[0]);
  assert.ok(acdc.checkSaid(V.schemas.accreditation, ["$id"]).ok);
  assert.ok(acdc.checkSaid(V.schemas.designatedAliases, ["$id"]).ok,
            "keri-ts's designated-aliases schema SAID");
  // Blinded states (the -a group) and their BLIDs.
  var bup = body(V.acdc.bobBup1 + V.blinded.placeholder);
  var bs = bup.att.blindedStates[0];
  assert.strictEqual(acdc.blindedStateId(bs), bs.d, "the placeholder BLID");
  assert.strictEqual(bup.sad.b, bs.d, "names the bup's b");
  assert.ok(bs.tdValue === "" && bs.tsValue === "", "empty td, ts (1AAP)");
  var issued = body(V.acdc.bobBup1 + V.blinded.issued).att.blindedStates[0];
  assert.strictEqual(acdc.blindedStateId(issued), issued.d,
                     "the issued BLID");
  assert.strictEqual(issued.tsValue, "issued", "0Missued is the tag issued");
  var deb = [V.acdc.debRip, V.acdc.debUpdIssued, V.acdc.debUpdRevoked]
    .map(function (t) {
      return body(t).sad;
    });
  assert.ok(deb[1].p === deb[0].d && deb[2].p === deb[1].d &&
            deb[1].rd === deb[0].d, "the public registry's chain");
  log.info("PASS the specifications' vectors: KERI v2 events and next-key " +
           "digests, ACDC v2 rip/acm/upd/bup, the transcript ACDC's most " +
           "compact form spliced from its bytes (4.0 kept), the schemas, " +
           "the BLIDs, the CESR -X group, paths and numbers.");
  log.debug("Leaving vectors().");
}

// ---------------------------------------------------------------------------
// 5. The specifications' keys.
// ---------------------------------------------------------------------------

const argon2id = require("@noble/hashes/argon2").argon2id;
const ed25519 = require("@noble/curves/ed25519").ed25519;

// keripy's Salter.signers(temp=True): seed = argon2id(path = hex(i), salt,
// t 1, m 8 KiB, p 1).
function specKey(i, salt, transferable) {
  log.debug("Entering specKey(). " + i);
  var seed = argon2id(i.toString(16), salt, { t: 1, m: 8, p: 1, dkLen: 32 });
  log.debug("Leaving specKey().");
  return acdc.keyFromSeed(seed, transferable);
}

// A v2 key event body with its signature and its witness's receipt.
function signedV2(raw, key, wit) {
  log.debug("Entering signedV2().");
  var msg = new TextEncoder().encode(raw);
  var inner = acdc.group("ControllerIdxSigs", acdc.encodeIndexed(
    ed25519.sign(msg, key.seed), 0, "ed25519"), 1, 2) +
    acdc.group("WitnessIdxSigs", acdc.encodeIndexed(ed25519.sign(msg,
      wit.seed), 0, "ed25519"), 1, 2);
  log.debug("Leaving signedV2().");
  return raw + acdc.group("AttachmentGroup", inner, 0, 2);
}

function specKeys() {
  log.debug("Entering specKeys().");
  var exam = "acdcspecworkexam";
  var wits = "acdcspecworkwits";
  assert.strictEqual(specKey(0, exam).verkey,
                     "DA8-J0EW88RMYqtUHQDqT4q2YH2iBFlW8HobHKV74yi_",
                     "argon2id reproduces the annex's signers[0]");
  var amy = signedV2(V.acdc.amyIcp, specKey(0, exam), specKey(0, wits,
                                                               false));
  var ka = acdc.processKels(acdc.parseStream(amy));
  var amyAid = body(V.acdc.amyIcp).sad.i;
  assert.ok(ka[amyAid].ok, "Amy's inception, signed and witnessed: " +
            ka[amyAid].reason);
  // Cal: signers[4], next signers[5] (the annex puts the next KEY in n),
  // witness wigners[2].
  var k4 = specKey(4, exam);
  var w2 = specKey(2, wits, false);
  var calIcp = acdc.saidify({ v: acdc.versionString("KERI", 0, 2), t: "icp",
    d: "", i: "", s: "0", kt: "1", k: [k4.verkey], nt: "1",
    n: [specKey(5, exam).verkey], bt: "1", b: [w2.verkey], c: [], a: [] },
    ["d", "i"]);
  var rip = body(V.acdc.calRip).sad;
  var acm = body(V.acdc.calAcmFull).sad;
  assert.strictEqual(calIcp.i, rip.i, "Cal's AID rebuilt from the annex's " +
                     "keys");
  var ixn = function (sn, prior, seal) {
    log.debug("Entering ixn(). " + sn);
    log.debug("Leaving ixn().");
    return acdc.saidify({ v: acdc.versionString("KERI", 0, 2), t: "ixn",
                          d: "", i: calIcp.i, s: sn, p: prior, a: [seal] });
  };
  var upd = acdc.saidify({ v: acdc.versionString("ACDC", 0, 2), t: "upd",
    d: "", rd: rip.d, n: "1", p: rip.d, dt: WHEN, td: acm.d, ts: "issued" });
  var ixn1 = ixn("1", calIcp.d, { i: rip.d, s: "0", d: rip.d });
  var ixn2 = ixn("2", ixn1.d, { i: rip.d, s: "1", d: upd.d });
  var kel = [calIcp, ixn1, ixn2].map(function (e) {
    return signedV2(JSON.stringify(e), k4, w2);
  }).join("");
  var stream = kel + V.acdc.calRip + JSON.stringify(upd);
  var full = acdc.verifyPresentation(stream + V.acdc.calAcmFull);
  assert.ok(full.valid, "the spec's accreditation ACDC, full form, " +
            "through the spec's rip and Cal's KEL: " + full.reason);
  var compact = acdc.verifyPresentation(stream + V.acdc.calAcmCompact);
  assert.ok(compact.valid, "and in its most compact form: " +
            compact.reason);
  var schema = acdc.verifyPresentation(stream + V.acdc.calAcmFull,
                                       { schema: V.schemas.accreditation });
  assert.ok(!schema.valid && /score/.test(schema.reason), "the spec's " +
            "schema requires score and the credential has level (an " +
            "erratum), so validation fails naming it: " + schema.reason);
  var upd2 = acdc.saidify({ v: acdc.versionString("ACDC", 0, 2), t: "upd",
    d: "", rd: rip.d, n: "2", p: upd.d, dt: WHEN, td: acm.d,
    ts: "revoked" });
  var ixn3 = ixn("3", ixn2.d, { i: rip.d, s: "2", d: upd2.d });
  var revoked = acdc.verifyPresentation(stream + signedV2(
    JSON.stringify(ixn3), k4, w2) + JSON.stringify(upd2) +
    V.acdc.calAcmFull);
  assert.ok(!revoked.valid && revoked.revoked, "revoked by an upd");
  var unanchored = acdc.verifyPresentation(kel.slice(0, kel.indexOf(
    JSON.stringify(ixn2))) + V.acdc.calRip + JSON.stringify(upd) +
    V.acdc.calAcmFull);
  assert.ok(!unanchored.valid && /seal/.test(unanchored.reason),
            "an upd no KEL event seals: " + unanchored.reason);
  log.info("PASS the specifications' keys: Amy's and Cal's v2 inceptions " +
           "rebuilt with argon2id, signed and witnessed; the spec's " +
           "accreditation ACDC (full and most compact) verifies through the " +
           "spec's rip; revoked; unanchored refused; the schema erratum " +
           "named.");
  log.debug("Leaving specKeys().");
}

// ---------------------------------------------------------------------------
// 6. What must fail.
// ---------------------------------------------------------------------------

function refused(stream, opts, pattern, what) {
  log.debug("Entering refused(). " + what);
  var r = acdc.verifyPresentation(stream, opts);
  assert.ok(!r.valid, what + ": verified");
  if (pattern) {
    assert.ok(pattern.test(r.reason), what + ": " + r.reason);
  }
  log.debug("Leaving refused().");
  return r;
}

// A controller's stream with its first event's signatures cut to one.
function oneSignature(ctl) {
  log.debug("Entering oneSignature().");
  var m = acdc.parseStream(ctl.stream)[0];
  log.debug("Leaving oneSignature().");
  return m.text + acdc.group("ControllerIdxSigs", m.att.sigs[0].qb64, 1, 1);
}

function kelRefusals(ours) {
  log.debug("Entering kelRefusals().");
  var forged = ours.stream.replace(/-AAB[A-Za-z0-9_-]{88}/g, function () {
    return "-AAB" + acdc.encodeIndexed(new Uint8Array(64), 0);
  });
  refused(forged, {}, /verified signature/, "KEL signatures that do not " +
          "verify");
  var w = acdc.makeController({ signers: 3, kt: ["1/2", "1/2", "1/2"] });
  var one = acdc.processKels(acdc.parseStream(oneSignature(w)))[w.prefix];
  assert.ok(!one.ok && /do not satisfy kt/.test(one.reason), "one of three " +
            "half-weighted signatures: " + one.reason);
  var c = acdc.makeController({ signers: 2, kt: [["1/2", "1/2"], ["1"]] });
  assert.ok(!acdc.processKels(acdc.parseStream(c.stream))[c.prefix].ok,
            "a second clause over a third key that does not exist");
  var wit = acdc.makeController({ witnesses: 2 });
  var bare = wit.stream.replace(/-BAC[A-Za-z0-9_-]{176}/, "");
  var wb = acdc.processKels(acdc.parseStream(bare))[wit.prefix];
  assert.ok(!wb.ok && /fully witnessed/.test(wb.reason), "witness receipts " +
            "stripped: " + wb.reason);
  var dgr = acdc.makeController({});
  var del = acdc.makeController({ delegator: dgr });
  var noApproval = acdc.processKels(acdc.parseStream(dgr.events[0].text +
                                                     del.stream));
  assert.ok(!noApproval[del.prefix].ok && /not anchored/.test(
    noApproval[del.prefix].reason), "a dip its delegator has not " +
    "anchored: " + noApproval[del.prefix].reason);
  var d1 = acdc.makeController({});
  acdc.interact(d1, []);
  var fork = acdc.makeController({ keys: d1.keys, nextKeys: d1.next });
  acdc.interact(fork, [{ i: fork.prefix, s: "0", d: fork.icp.d }]);
  var dup = acdc.processKels(acdc.parseStream(d1.stream +
                                              fork.events[1].text));
  assert.ok(!dup[d1.prefix].ok && /duplicity/.test(dup[d1.prefix].reason),
            "two different events at one sequence number: " +
            dup[d1.prefix].reason);
  var r1 = acdc.makeController({});
  r1.next = [acdc.newKey()];
  acdc.rotate(r1);
  var rr = acdc.processKels(acdc.parseStream(r1.stream))[r1.prefix];
  assert.ok(!rr.ok && /prior next threshold/.test(rr.reason), "a rotation " +
            "to keys icp did not commit to: " + rr.reason);
  log.info("PASS KEL refusals: forged signatures, a weighted threshold " +
           "short, an impossible clause, witness receipts missing, an " +
           "unapproved delegation, duplicity, a rotation to uncommitted keys.");
  log.debug("Leaving kelRefusals().");
}

function credentialRefusals(ours) {
  log.debug("Entering credentialRefusals().");
  var revoked = acdc.verifyPresentation(acdc.revoke(ours));
  assert.ok(!revoked.valid && revoked.revoked, "a revoked credential is " +
            "reported revoked");
  var v2 = acdc.issue({ version: 2, attributes: { name: "Sunspot College" } });
  refused(v2.stream.replace("Sunspot College", "Sunspot Collegf"), {},
          /SAID/, "a changed attribute in a v2 ACDC");
  var ag = acdc.issue({ version: 2, aggregate: [{ x: "one" }, { y: "two" }] });
  var shown = acdc.withAcdcText(ag, acdc.discloseAggregate(ag.acdc, [2]));
  assert.ok(acdc.verifyPresentation(shown).valid, "one block disclosed");
  refused(shown.replace("\"two\"", "\"twO\""), {}, /A\[2\]/,
          "a changed disclosed block");
  refused(ours.stream, { schema: Object.assign({}, ours.schema,
    { required: ["v", "d", "i", "s", "nope"] }) }, /SAID/, "a schema whose " +
    "$id is not its SAID");
  var typed = acdc.issue({ attributes: { name: "x" } });
  var bad = Object.assign({}, typed.schema);
  bad.properties = Object.assign({}, bad.properties);
  bad.properties.a = { oneOf: [{ type: "string" }, { type: "object",
    properties: { name: { type: "number" } } }] };
  bad = acdc.saidify(Object.assign(bad, { $id: "" }), ["$id"]);
  var wrong = acdc.issue({ attributes: { name: "x" }, schema: bad });
  refused(wrong.stream, { schema: bad }, /validates against its schema/,
          "an attribute of the wrong type for its schema");
  var bk = acdc.issue({ backers: 2, attributes: { name: "x" } });
  assert.ok(acdc.verifyPresentation(bk.stream).valid, "a backer registry");
  refused(bk.stream.replace(/-BAC[A-Za-z0-9_-]{176}-G/g, "-G").replace(
    /-V[A-Za-z0-9_-]{2}-GAB/g, "-VAS-GAB"), {}, /backer receipts/,
          "backer receipts stripped");
  assert.throws(function () {
    acdc.parseStream("{\"v\":\"KERI10CBOR000040_\"}");
  }, /CBOR/, "a CBOR body is refused by name");
  log.info("PASS credential refusals: revoked, a changed v2 attribute, a " +
           "changed disclosed block, a schema whose $id is not its SAID, an " +
           "attribute against its schema, backer receipts missing, CBOR.");
  log.debug("Leaving credentialRefusals().");
}

function edges() {
  log.debug("Entering edges().");
  var chain = acdc.issueChain({});
  assert.ok(acdc.verifyPresentation(chain.stream).valid, "a valid chain (I2I)");
  refused(acdc.revoke(chain.parent) + chain.child.stream, {}, /REVOKED/,
          "a chain whose far node is revoked");
  refused(chain.child.stream, {}, /not in the stream/, "a far node not " +
          "presented");
  var stranger = acdc.issueChain({ parent: { recipient:
    acdc.makeController({}).prefix } });
  refused(stranger.stream, {}, /I2I/, "I2I: the issuer is not the far " +
          "node's issuee");
  var ni2i = acdc.issueChain({ parent: { recipient:
    acdc.makeController({}).prefix }, operator: "NI2I" });
  assert.ok(acdc.verifyPresentation(ni2i.stream).valid, "NI2I lifts it");
  var not = acdc.issueChain({ operator: ["NOT"] });
  refused(not.stream, {}, /NOT/, "NOT over a valid far node");
  var notRevoked = acdc.issueChain({ operator: ["NI2I", "NOT"] });
  assert.ok(acdc.verifyPresentation(acdc.revoke(notRevoked.parent) +
    notRevoked.child.stream).valid, "NOT over a revoked far node is valid");
  // DI2I: a delegate of the far node's issuee may issue.
  var holder = acdc.makeController({});
  var parent = acdc.issue({ attributes: { role: "parent" },
                            recipient: holder.prefix });
  var delegate = acdc.makeController({ delegator: holder });
  var edge = function (o) {
    log.debug("Entering edge().");
    log.debug("Leaving edge().");
    return { parent: { n: parent.acdc.d, s: parent.schema.$id, o: o } };
  };
  var other = acdc.makeController({ delegator: holder });
  var di2i = acdc.issue({ issuer: delegate, edges: edge("DI2I"),
                          attributes: { role: "child" } });
  var i2i = acdc.issue({ issuer: other, edges: edge("I2I"),
                         attributes: { role: "child" } });
  var base = parent.stream + holder.stream;
  assert.ok(acdc.verifyPresentation(base + di2i.stream).valid, "DI2I: the " +
            "issuer is a delegate of the far node's issuee");
  refused(base + i2i.stream, {}, /I2I/, "I2I does not admit a delegate");
  // Edge groups.
  var missing = acdc.digestQb64("no such credential");
  var group = function (op) {
    log.debug("Entering group(). " + op);
    log.debug("Leaving group().");
    return { g: { o: op, ok: { d: "", n: parent.acdc.d, s: parent.schema.$id,
                               o: "NI2I" },
                  gone: { d: "", n: missing, o: "NI2I" } } };
  };
  var verdict = function (op) {
    log.debug("Entering verdict(). " + op);
    var t = acdc.issue({ edges: group(op), attributes: { x: 1 } });
    var r = acdc.verifyPresentation(parent.stream + t.stream);
    log.debug("Leaving verdict().");
    return r;
  };
  assert.ok(verdict("OR").valid, "OR: one of two far nodes valid");
  assert.ok(!verdict("AND").valid, "AND: one of two is not enough");
  assert.ok(verdict("NAND").valid, "NAND: not all valid");
  assert.ok(!verdict("NOR").valid, "NOR: one is valid");
  var avg = verdict("AVG");
  assert.ok(!avg.valid && /not a validity operator/.test(avg.reason),
            "AVG is refused by name: " + avg.reason);
  var v2 = acdc.issueChain({ version: 2 });
  assert.ok(acdc.verifyPresentation(v2.stream).valid, "a v2 chain");
  log.info("PASS edges: I2I, NI2I, DI2I (through delegation), NOT, a " +
           "revoked or missing far node, AND / OR / NAND / NOR groups, AVG " +
           "refused by name, a v2 chain.");
  log.debug("Leaving edges().");
}

async function main() {
  log.debug("Entering main().");
  var s = await loadSignify();
  await theirsVerifiedHere(s);
  var ours = await oursCheckedThere(s);
  await grants(s);
  vectors();
  specKeys();
  kelRefusals(ours);
  credentialRefusals(ours);
  edges();
  log.info("acdc_engine: all checks passed.");
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error("FAILED: " + (e && e.stack || e));
  process.exitCode = 1;
});
