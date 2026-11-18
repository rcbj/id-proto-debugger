// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: acdc_keri_ts.js
//
// ---------------------------------------------------------------------------
// client/src/acdc.js in node (#480), held BOTH WAYS to keri-ts 2.2.9 and
// cesr-ts 2.2.1, the released TypeScript KERI and CESR libraries, through
// acdc_keri_ts_lib.mjs (in-memory stores; no services, never skips):
//
//   keri-ts -> acdc.js
//     1. CESR version 2 KELs (keri-ts's default), numeric, weighted and
//        multi-clause thresholds, rotation, and a v1 KEL;
//     2. a delegated KEL (dip, drt) with its delegator's approving seals;
//     3. a witnessed KEL: keri-ts witness habitats' receipts, by indexed
//        signature and by rct; short of bt is refused;
//     4. a v1 credential presentation, issued and revoked;
//     5. an IPEX grant of it, and the holder's admit;
//     6. version 2 ACDC messages: rip, acm (full and most compact), upd,
//        bup with its blinded state's BLID, acg with its aggregate's AGID.
//   acdc.js -> keri-ts
//     7. our KELs (v1, v2, weighted, multi-clause, witnessed, delegated with
//        drt) accepted by keri-ts's Kevery with the same key state;
//     8. our credentials accepted by its Tevery and Verifier: a no-backer
//        and a backer registry, revocation, a chain, and a chain whose far
//        node is revoked (keri-ts: revokedChain; acdc.js: invalid);
//     9. our IPEX grant accepted by its Exchanger;
//    10. our v2 ACDCs (with edges, rules, an aggregate, a disclosure)
//        verified by cesr-ts's SerderACDC, and a tampered one refused;
//    11. thresholds: acdc_threshold.js agrees with cesr-ts's Tholder.
// ---------------------------------------------------------------------------

const assert = require("assert");
const fs = require("fs");
const path = require("path");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "acdc_keri_ts",
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
const tholder = paths.requireSharedModule([path.join(repoRoot(), "client",
  "src", "acdc_threshold.js")], "client/src/acdc_threshold.js");

// The text with the base64 character at `at` changed.
function flip(text, at) {
  log.debug("Entering flip().");
  log.debug("Leaving flip().");
  return text.slice(0, at) + (text.charAt(at) === "A" ? "B" : "A") +
    text.slice(at + 1);
}

function kelsOk(stream, what) {
  log.debug("Entering kelsOk(). " + what);
  var kevers = acdc.processKels(acdc.parseStream(stream));
  Object.keys(kevers).forEach(function (pre) {
    assert.ok(kevers[pre].ok, what + ": " + pre + " " + kevers[pre].reason);
  });
  log.debug("Leaving kelsOk().");
  return kevers;
}

// ---------------------------------------------------------------------------
// keri-ts -> acdc.js
// ---------------------------------------------------------------------------

async function theirKels(k) {
  log.debug("Entering theirKels().");
  var cases = [{ version: 2 }, { version: 2, weighted: true },
               { version: 2, weighted: "nested" }, { version: 1 },
               { version: 1, weighted: true }];
  for (var i = 0; i < cases.length; i++) {
    var r = await k.makeKel(cases[i]);
    var kevers = kelsOk(r.replay, JSON.stringify(cases[i]));
    var ours = kevers[r.pre];
    assert.strictEqual(ours.sn, r.state.sn, "the same sequence number");
    assert.strictEqual(ours.last, r.state.said, "the same latest event");
    assert.deepStrictEqual(ours.keys, r.state.keys, "the same current keys");
    if (!cases[i].weighted) {
      var at = r.replay.search(/-[KA]A[A-Za-z0-9_-]{2}[A-D]/) + 44;
      var bad = acdc.processKels(acdc.parseStream(flip(r.replay, at)))[r.pre];
      assert.ok(!bad.ok, "a changed signature is refused");
    }
  }
  log.info("PASS keri-ts KELs (v2 numeric, weighted, multi-clause; v1 " +
           "numeric and weighted; icp, rot, ixn) verify here with keri-ts's " +
           "key state, and a changed signature does not.");
  var d2 = await k.makeDelegatedKel({ version: 2 });
  var d1 = await k.makeDelegatedKel({ version: 1 });
  [d2, d1].forEach(function (d, i) {
    var kv = kelsOk(d.delegatorKel + d.delegateKel, "delegated v" +
                    (2 - i));
    assert.strictEqual(kv[d.delegate].delegator, d.delegator);
    assert.strictEqual(kv[d.delegate].events.length, 2, "dip and drt");
    var alone = acdc.processKels(acdc.parseStream(d.delegateKel));
    assert.ok(!alone[d.delegate].ok && /delegator/.test(
      alone[d.delegate].reason), "a delegate without its delegator's KEL " +
      "is refused: " + alone[d.delegate].reason);
  });
  log.info("PASS keri-ts delegated KELs (v2 and v1 dip, drt, -S / -G " +
           "couples) verify here; without the delegator they do not.");
  var w2 = await k.makeWitnessedKel({ version: 2 });
  var w1 = await k.makeWitnessedKel({ version: 1 });
  [w2, w1].forEach(function (w) {
    kelsOk(w.replay, "witnessed replay");
    kelsOk(w.icpAlone + w.receipts.join(""), "icp and the witnesses' rct");
    var bare = acdc.processKels(acdc.parseStream(w.icpAlone))[w.pre];
    assert.ok(!bare.ok && /fully witnessed/.test(bare.reason),
              "an icp without its receipts: " + bare.reason);
    var one = acdc.processKels(acdc.parseStream(w.icpAlone +
                                                w.coupleReceipt))[w.pre];
    assert.ok(!one.ok && /only 1 of the 2/.test(one.reason),
              "one receipt of bt 2: " + one.reason);
  });
  log.info("PASS keri-ts witnessed KELs (bt 2, two witness habitats; -L/-B " +
           "indexed receipts, rct, -M/-C couples) verify here; short of bt " +
           "they do not.");
  log.debug("Leaving theirKels().");
}

async function theirCredentials(k) {
  log.debug("Entering theirCredentials().");
  var c = await k.makeCredential({});
  var r = acdc.verifyPresentation(c.stream, { schema: c.schema });
  assert.ok(r.valid, "keri-ts's credential verifies here: " + r.reason);
  var rv = await k.makeCredential({ revoke: true });
  var rr = acdc.verifyPresentation(rv.stream, { schema: rv.schema });
  assert.ok(!rr.valid && rr.revoked, "and its revocation is seen");
  var g = await k.makeGrant();
  var gr = acdc.verifyExchange(g.credential + g.holderKel + g.grant,
                               { schema: g.schema });
  assert.ok(gr.valid, "keri-ts's grant verifies here: " + gr.reason);
  var admit = acdc.parseStream(g.admit)[0].sad.d;
  var ar = acdc.verifyExchange(g.credential + g.holderKel + g.grant +
                               g.admit, { said: admit });
  assert.ok(ar.valid, "and the holder's admit: " + ar.reason);
  var forged = flip(g.grant, g.grant.indexOf("-FAB") + 4 + 44 + 24 + 44 +
                    4 + 40);
  assert.ok(!acdc.verifyExchange(g.credential + g.holderKel + forged).valid,
            "a grant with a changed signature does not");
  log.info("PASS keri-ts's v1 credential (KEL, vcp, iss, ACDC with -I) " +
           "verifies here with its schema, its revocation is seen, and its " +
           "IPEX grant and the holder's admit verify.");
  var v = await k.makeV2Acdc();
  ["rip", "acmFull", "acmCompact", "upd", "bup", "acg"].forEach(function (n) {
    var m = acdc.parseStream(v[n])[0];
    assert.strictEqual(acdc.checkBody(m), "", "keri-ts's " + n +
                       " verifies here");
  });
  assert.strictEqual(acdc.parseStream(v.acmFull)[0].sad.d, v.said);
  assert.strictEqual(acdc.parseStream(v.acmCompact)[0].sad.d, v.said,
                     "full and most compact form share one SAID");
  assert.strictEqual(acdc.blindedStateId(v.blind), v.blind.d,
                     "the blinded state's BLID");
  assert.strictEqual(acdc.parseStream(v.bup)[0].sad.b, v.blind.d);
  assert.strictEqual(acdc.parseStream(v.acg)[0].sad.A[0], v.agid,
                     "the aggregate's AGID");
  log.info("PASS keri-ts's v2 ACDC messages verify here: rip, acm full and " +
           "most compact (one SAID), upd, bup (its BLID), acg (its AGID).");
  log.debug("Leaving theirCredentials().");
}

// ---------------------------------------------------------------------------
// acdc.js -> keri-ts
// ---------------------------------------------------------------------------

function accepted(r, what) {
  log.debug("Entering accepted(). " + what);
  var bad = r.decisions.filter(function (d) {
    return d.kind !== "accept";
  });
  assert.strictEqual(bad.length, 0, what + ": keri-ts " +
                     JSON.stringify(bad));
  log.debug("Leaving accepted().");
}

async function ourKels(k) {
  log.debug("Entering ourKels().");
  var cases = [
    { gen: 1 }, { gen: 2 },
    { gen: 2, signers: 3, kt: ["1/2", "1/2", "1/2"],
      nt: ["1/2", "1/2", "1/2"] },
    { gen: 1, signers: 3, kt: [["1/2", "1/2"], ["1"]], nt: "2" },
    { gen: 2, witnesses: 3, toad: 2 },
    { gen: 1, witnesses: 2 },
    { gen: 2, delegated: true }, { gen: 1, delegated: true }];
  for (var i = 0; i < cases.length; i++) {
    var o = Object.assign({}, cases[i]);
    if (o.delegated) {
      o.delegator = acdc.makeController({ gen: o.gen });
    }
    var ctl = acdc.makeController(o);
    acdc.interact(ctl, []);
    acdc.rotate(ctl);
    acdc.interact(ctl, []);
    var stream = acdc.kelStream(ctl);
    var r = await k.kelAccept(stream);
    accepted(r, JSON.stringify(cases[i]));
    var st = r.states[ctl.prefix];
    assert.strictEqual(st.sn, ctl.sn, "keri-ts's key state: sn");
    assert.deepStrictEqual(st.keys, ctl.keys.map(function (x) {
      return x.verkey;
    }), "keri-ts's key state: the rotated keys");
    if (o.delegated) {
      assert.strictEqual(st.delpre, o.delegator.prefix);
    }
  }
  var plain = acdc.makeController({ gen: 2 });
  var broken = flip(plain.stream, plain.stream.indexOf("-KAW") + 44);
  var rb = await k.kelAccept(broken);
  assert.ok(rb.decisions[0].kind !== "accept", "keri-ts refuses our KEL " +
            "with a changed signature too");
  log.info("PASS keri-ts accepts our KELs — v1 and v2, numeric, weighted " +
           "and multi-clause thresholds, rotation, witnesses with their " +
           "receipts, delegation (dip, drt) — with the same key state.");
  log.debug("Leaving ourKels().");
}

async function ourCredentials(k) {
  log.debug("Entering ourCredentials().");
  var nb = acdc.issue({ attributes: { name: "Sunspot College" } });
  var bk = acdc.issue({ backers: 2, attributes: { name: "Sunspot" } });
  var pairs = [[nb.stream, nb, "iss"], [acdc.revoke(nb), nb, "rev"],
               [bk.stream, bk, "bis"], [acdc.revoke(bk), bk, "brv"]];
  for (var i = 0; i < pairs.length; i++) {
    var r = await k.credentialAccept(pairs[i][0],
                                     JSON.stringify(pairs[i][1].schema));
    var c = r.credentials[pairs[i][1].acdc.d];
    assert.ok(c && c.saved && c.telState === pairs[i][2], "keri-ts " +
              "accepts our credential (" + pairs[i][2] + "): " +
              JSON.stringify(r));
  }
  var chain = acdc.issueChain({});
  var schemas = [JSON.stringify(chain.parent.schema),
                 JSON.stringify(chain.child.schema)];
  var rc = await k.credentialAccept(chain.stream, schemas);
  assert.ok(rc.credentials[chain.child.acdc.d].saved, "keri-ts accepts our " +
            "chained credential: " + JSON.stringify(rc.decisions));
  assert.ok(acdc.verifyPresentation(chain.stream, { schemas: schemas })
    .valid, "and so does acdc.js");
  var revoked = acdc.revoke(chain.parent) + chain.child.stream;
  var rr = await k.credentialAccept(revoked, schemas);
  assert.ok(!rr.credentials[chain.child.acdc.d].saved && rr.decisions.some(
    function (d) {
      return d.reason === "revokedChain";
    }), "keri-ts refuses a chain whose far node is revoked");
  var ours = acdc.verifyPresentation(revoked, { schemas: schemas });
  assert.ok(!ours.valid && /REVOKED/.test(ours.reason), "so does acdc.js: " +
            ours.reason);
  var holder = acdc.makeController({});
  var g = acdc.issue({ attributes: { name: "x" }, recipient: holder.prefix });
  var ex = await k.exnAccept(g.stream + holder.stream + acdc.grant(g).text);
  assert.ok(ex.length === 1 && ex[0].stored, "keri-ts's Exchanger accepts " +
            "our grant: " + JSON.stringify(ex));
  log.info("PASS keri-ts accepts our credentials (no-backer and backer " +
           "registries, issued and revoked; a chain), refuses a chain to a " +
           "revoked credential as acdc.js does, and accepts our IPEX grant.");
  var v2 = [acdc.issue({ version: 2, attributes: { name: "x" },
                         rules: { l: "terms" } }),
            acdc.issueChain({ version: 2 }).child,
            acdc.issue({ version: 2, aggregate: [{ x: 1 }, { y: 2 }] })];
  v2.forEach(function (t) {
    var full = JSON.stringify(t.acdc);
    assert.strictEqual(k.serderSaid(full, true).said, t.acdc.d,
                       "cesr-ts verifies our v2 ACDC");
    assert.strictEqual(k.serderSaid(JSON.stringify(t.compact), true).said,
                       t.acdc.d, "and its most compact form");
    assert.strictEqual(k.serderSaid(JSON.stringify(t.rip), true).said,
                       t.rip.d, "and its rip");
    assert.strictEqual(k.serderSaid(JSON.stringify(t.upd), true).said,
                       t.upd.d, "and its upd");
    assert.ok(k.serderSaid(full.replace(t.acdc.s, acdc.digestQb64("x")), true)
      .error, "and refuses it changed");
  });
  var agg = v2[2];
  assert.strictEqual(k.aggregateId(agg.acdc.A), agg.acdc.A[0],
                     "cesr-ts's AGID of our aggregate");
  assert.strictEqual(k.serderSaid(acdc.discloseAggregate(agg.acdc, [2]),
                                  true).said, agg.acdc.d,
                     "and of a selective disclosure from it");
  log.info("PASS cesr-ts verifies our v2 ACDCs (full and most compact, " +
           "edges, rules, an aggregate and a disclosure from it), rip and " +
           "upd, and refuses one changed.");
  log.debug("Leaving ourCredentials().");
}

function thresholds(k) {
  log.debug("Entering thresholds().");
  var siths = ["1", "2", "3", ["1/2", "1/2", "1/2"], ["1/3", "1/3", "1/3"],
               ["1", "1/2", "1/4", "1/4"], [["1/2", "1/2"], ["1"]],
               [["1/2", "1/2", "1/2"], ["1/2", "1/2"]],
               [{ "1/2": ["1", "1"] }, "1/2"],
               [{ "1/3": ["1/2", "1/2"] }, "1/3", "1/3"]];
  var count = 0;
  siths.forEach(function (sith) {
    var th = tholder.parse(sith);
    var n = th.weighted ? th.size : 3;
    for (var mask = 0; mask < (1 << n); mask++) {
      var idx = [];
      for (var b = 0; b < n; b++) {
        if (mask & (1 << b)) {
          idx.push(b);
        }
      }
      assert.strictEqual(tholder.satisfy(th, idx),
                         k.tholderSatisfy(sith, idx),
                         JSON.stringify(sith) + " " + JSON.stringify(idx));
      count++;
    }
  });
  [["2/3", "1/4"], [["1/2"]], [{ "1/2": ["1/4"] }, "1"], ["3/2"]]
    .forEach(function (bad) {
      assert.throws(function () {
        tholder.parse(bad);
      }, "an unsatisfiable threshold is refused: " + JSON.stringify(bad));
    });
  log.info("PASS acdc_threshold.js agrees with cesr-ts's Tholder on " + count +
           " (threshold, signer set) pairs — numeric, weighted, " +
           "multi-clause, nested — and refuses unsatisfiable ones.");
  log.debug("Leaving thresholds().");
}

async function main() {
  log.debug("Entering main().");
  var k = await import(path.join(__dirname, "acdc_keri_ts_lib.mjs"));
  await theirKels(k);
  await theirCredentials(k);
  await ourKels(k);
  await ourCredentials(k);
  thresholds(k);
  log.info("acdc_keri_ts: all checks passed.");
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error("FAILED: " + (e && e.stack || e));
  process.exitCode = 1;
});
