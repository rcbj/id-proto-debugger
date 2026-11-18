// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: acdc_keri_ts_lib.mjs
//
// ---------------------------------------------------------------------------
// keri-ts 2.2.9 and cesr-ts 2.2.1 — the released TypeScript KERI and CESR
// libraries (Apache-2.0) — driven as a reference for client/src/acdc.js
// (#480). Not a job: acdc_keri_ts.js imports it.
//
// keri-ts's runtime is effection-generator based: a Habery is opened, and
// every message dispatched, inside effection's run(). The stores are
// in-memory (keri-ts's MemStoreOpener), so nothing is written to disk and
// the native LMDB binding is never opened. A fixed salt makes every key and
// prefix deterministic.
//
// PRODUCE: keri-ts builds a KEL (v1 or v2; numeric, weighted or
// multi-clause thresholds), a delegated KEL (dip/drt approved by the
// delegator's anchoring ixn), a witnessed KEL (real keri-ts witness
// habitats' receipts), v2 ACDC messages (rip, acm full and compact, upd,
// bup, acg with an aggregate), a v1 credential presentation stream, and an
// IPEX grant with the holder's admit.
//
// CONSUME: keri-ts's Kevery accepts (or escrows, or rejects) a stream; its
// Tevery and Verifier accept a credential; its Exchanger accepts an exn;
// cesr-ts's SerderACDC verifies a v2 ACDC's most-compact-form SAID; its
// Tholder evaluates a threshold; its Aggor computes an AGID.
// ---------------------------------------------------------------------------

import { createRequire } from "module";
import { run } from "effection";
import {
  openHabery, createProtocolProcessor, Regery, Credentialer, Tevery,
  Verifier, pinSchemaBytes, exportCredentialStream, Schemer, credential,
  ipexCredentialGrant, ipexAdmitExn, regcept, acdcmap, acdcagg, update,
  blindate,
} from "keri-ts/runtime";
import { MemStoreOpener, Reger, openOwner } from "keri-ts/db";
import {
  parseBytes, Vrsn_1_0, Vrsn_2_0, Tholder, Aggor, Kinds, SerderACDC,
  SerderKERI, makeBlindState,
} from "cesr-ts";

const require = createRequire(import.meta.url);
const bunyan = require("bunyan");
const log = bunyan.createLogger({
  name: "acdc_keri_ts_lib",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

const enc = new TextEncoder();
const dec = new TextDecoder();

export const SALT_A = "0ACDEyMzQ1Njc4OWxtbm9wcQ";
export const SALT_B = "0ACZZyMzQ1Njc4OWxtbm9wcQ";
export const SALT_C = "0ACYYyMzQ1Njc4OWxtbm9wcQ";
export const STAMP = "2025-01-01T00:00:00.000000+00:00";

function txt(b) {
  log.debug("Entering txt().");
  log.debug("Leaving txt().");
  return dec.decode(b);
}

function bytes(s) {
  log.debug("Entering bytes().");
  log.debug("Leaving bytes().");
  return typeof s === "string" ? enc.encode(s) : s;
}

function cat(parts) {
  log.debug("Entering cat().");
  const list = [...parts];
  const out = new Uint8Array(list.reduce((n, x) => n + x.length, 0));
  let p = 0;
  for (const x of list) {
    out.set(x, p);
    p += x.length;
  }
  log.debug("Leaving cat().");
  return out;
}

function vrsnOf(v) {
  log.debug("Entering vrsnOf().");
  log.debug("Leaving vrsnOf().");
  return v === 1 ? Vrsn_1_0 : Vrsn_2_0;
}

// An in-memory Habery; `salt` makes every key deterministic.
function* habery(name, salt) {
  log.debug("Entering habery(). " + name);
  const opener = new MemStoreOpener();
  const hby = yield* openHabery(Object.assign({ name: name, temp: true,
    opener: opener, skipConfig: true }, salt ? { salt: salt } : {}));
  log.debug("Leaving habery().");
  return { hby: hby, opener: opener };
}

// An in-memory Reger (the TEL and credential store) beside a Habery.
function* openReger(opener, name) {
  log.debug("Entering openReger().");
  const id = { name: name, base: "", temp: true };
  const reger = yield* openOwner(new Reger(opener.create(Reger.Family, id)),
                                 "Reger", id);
  log.debug("Leaving openReger().");
  return reger;
}

// keri-ts's replay of one identifier's KEL (Baser.clonePreIter).
function clone(hby, pre) {
  log.debug("Entering clone().");
  log.debug("Leaving clone().");
  return cat(hby.db.clonePreIter(pre, 0));
}

function describe(decision) {
  log.debug("Entering describe().");
  if (!decision) {
    log.debug("Leaving describe(). None.");
    return { kind: "none" };
  }
  const d = { kind: decision.kind };
  for (const k of ["reason", "message"]) {
    if (decision[k] !== undefined && typeof decision[k] !== "object") {
      d[k] = String(decision[k]);
    }
  }
  log.debug("Leaving describe().");
  return d;
}

// Dispatch a stream, frame by frame; every decision.
function* feed(proc, kvy, stream, opts) {
  log.debug("Entering feed().");
  const local = !!(opts && opts.local);
  const decisions = [];
  for (const fr of parseBytes(bytes(stream))) {
    const r = yield* proc.dispatch(fr, { escrows: true, local: local }, kvy);
    decisions.push(Object.assign({ ilk: fr.body.ilk || null,
      said: fr.body.said || null,
      pre: fr.body.ked ? fr.body.ked.i || null : null },
                                 describe(r.decision)));
  }
  yield* proc.processEscrowsOnce();
  log.debug("Leaving feed().");
  return decisions;
}

function* feedInto(hby, stream, opts) {
  log.debug("Entering feedInto().");
  const proc = createProtocolProcessor(hby);
  const out = yield* feed(proc, proc.makeKevery(), stream, opts);
  log.debug("Leaving feedInto().");
  return out;
}

function keyState(hby, pre) {
  log.debug("Entering keyState().");
  const k = hby.db.getKever(pre);
  if (!k) {
    log.debug("Leaving keyState(). None.");
    return null;
  }
  log.debug("Leaving keyState().");
  return { prefix: pre, sn: k.sn, said: k.serder.said,
           keys: k.verfers.map((v) => v.qb64),
           kt: k.tholder ? k.tholder.sith : null,
           delpre: k.delpre || null };
}

// ------------------------------------------------------------- PRODUCE

// icp, rot and an ixn carrying a seal, replayed. weighted: true gives three
// keys with ["1/2","1/2","1/2"]; "nested" gives [["1/2","1/2"],["1"]].
export async function makeKel(opts) {
  log.debug("Entering makeKel().");
  const o = opts || {};
  const out = await run(function* () {
    const { hby } = yield* habery("kel", o.salt || SALT_A);
    let args = { version: vrsnOf(o.version) };
    if (o.weighted) {
      const sith = o.weighted === "nested" ? [["1/2", "1/2"], ["1"]] :
        ["1/2", "1/2", "1/2"];
      args = Object.assign(args, { icount: 3, ncount: 3, isith: sith,
                                   nsith: sith });
    }
    const hab = hby.makeHab("ctl", undefined, args);
    hab.rotate({});
    hab.interact({ data: [{ i: hab.pre, s: "1",
                            d: hab.kever.serder.said }] });
    return { pre: hab.pre, replay: txt(clone(hby, hab.pre)),
             state: keyState(hby, hab.pre) };
  });
  log.debug("Leaving makeKel().");
  return out;
}

// A delegator and its delegate (dip, then drt), each delegated event
// approved by an anchoring ixn of the delegator.
export async function makeDelegatedKel(opts) {
  log.debug("Entering makeDelegatedKel().");
  const o = opts || {};
  const out = await run(function* () {
    const vr = vrsnOf(o.version);
    const D = (yield* habery("dgr", SALT_A)).hby;
    const E = (yield* habery("dge", SALT_B)).hby;
    const dh = D.makeHab("delegator", undefined, { version: vr });
    yield* feedInto(E, clone(D, dh.pre));
    const eh = E.makeHab("delegate", undefined, { delpre: dh.pre,
                                                  version: vr });
    yield* feedInto(D, clone(E, eh.pre));
    let s = eh.kever.serder;
    dh.interact({ data: [{ i: s.pre, s: s.snh, d: s.said }] });
    yield* feedInto(E, clone(D, dh.pre));
    eh.rotate({});
    s = eh.kever.serder;
    dh.interact({ data: [{ i: s.pre, s: s.snh, d: s.said }] });
    yield* feedInto(E, clone(D, dh.pre));
    return { delegator: dh.pre, delegate: eh.pre,
             delegatorKel: txt(clone(D, dh.pre)),
             delegateKel: txt(clone(E, eh.pre)) };
  });
  log.debug("Leaving makeDelegatedKel().");
  return out;
}

// An icp with two keri-ts witness habitats and bt 2, the witnesses'
// receipts (rct with -B / -L indexed signatures) absorbed and replayed.
export async function makeWitnessedKel(opts) {
  log.debug("Entering makeWitnessedKel().");
  const o = opts || {};
  const out = await run(function* () {
    const vr = vrsnOf(o.version);
    const W = (yield* habery("wit", SALT_A)).hby;
    const C = (yield* habery("ctl", SALT_B)).hby;
    const w1 = W.makeHab("w1", undefined, { transferable: false,
                                            version: vr });
    const w2 = W.makeHab("w2", undefined, { transferable: false,
                                            version: vr });
    const ch = C.makeHab("ctl", undefined, { wits: [w1.pre, w2.pre],
                                             toad: 2, version: vr });
    const icp = clone(C, ch.pre);
    yield* feedInto(W, icp, { local: true });
    const s = ch.kever.serder;
    const receipts = [txt(w1.witness(s)), txt(w2.witness(s))];
    const couple = txt(w1.receipt(s));
    yield* feedInto(C, receipts.join(""));
    return { pre: ch.pre, icpAlone: txt(icp), receipts: receipts,
             coupleReceipt: couple, replay: txt(clone(C, ch.pre)) };
  });
  log.debug("Leaving makeWitnessedKel().");
  return out;
}

// Version 2 ACDC messages from keri-ts's builders: rip, acm full and
// compact (one SAID), upd, a blinded state and its bup, an aggregate and
// the acg that carries it.
export async function makeV2Acdc() {
  log.debug("Entering makeV2Acdc().");
  const issuer = (await makeKel()).pre;
  const issuee = (await makeKel({ salt: SALT_B })).pre;
  const rip = regcept(issuer, { uuid: "0ABhY2Rjc3BlY3dvcmtyYXc",
                                stamp: STAMP });
  const common = {
    uuid: "0ABhY2Rjc3BlY3dvcmtyYXd", regid: rip.said,
    attribute: { d: "", u: "0ACbm9uY2Vub25jZW5vbmNl", name: "Alice" },
    issuee: issuee,
    edge: { d: "", u: "0ADZWRnZWVkZ2VlZGdlZWRn", boss: { n: rip.said } },
    rule: { d: "", usage: "test only" }
  };
  const acmFull = acdcmap(issuer, common);
  const acmCompact = acdcmap(issuer, Object.assign({}, common,
                                                   { compactify: true }));
  const upd = update(rip.said, rip.said, acmFull.said, "issued",
                     { sn: 1, stamp: STAMP });
  const blind = makeBlindState({ salt: SALT_C, sn: BigInt(2),
                                 acdc: acmFull.said, state: "revoked" });
  const bup = blindate(rip.said, upd.said, blind.d.qb64,
                       { sn: 2, stamp: STAMP });
  const ael = ["",
    { d: "", u: "0ACbm9uY2Vub25jZW5vbmNl", name: "Alice" },
    { d: "", u: "0ACbm9uY2Vub25jZW5vbmNm", age: 30 }];
  const agg = new Aggor({ ael: ael, makify: true, kind: Kinds.json });
  const acg = acdcagg(issuer, { uuid: common.uuid, regid: rip.said,
    aggregate: agg.ael, edge: { d: "" }, rule: { d: "", usage: "x" } });
  log.debug("Leaving makeV2Acdc().");
  return { issuer: issuer, rip: txt(rip.raw), acmFull: txt(acmFull.raw),
           acmCompact: txt(acmCompact.raw), said: acmFull.said,
           upd: txt(upd.raw), bup: txt(bup.raw),
           blind: { d: blind.d.qb64, u: blind.u.qb64, td: blind.td.qb64,
                    ts: blind.ts.qb64 },
           agid: agg.agid, acg: txt(acg.raw) };
}

// A draft-07 schema for keri-ts's v1 credential: a {d, i, dt, name} block.
export function witnessSchema() {
  log.debug("Entering witnessSchema().");
  log.debug("Leaving witnessSchema().");
  return {
    $id: "", $schema: "http://json-schema.org/draft-07/schema#",
    title: "keri-ts reference credential", description: "acdc_keri_ts",
    type: "object", credentialType: "KeriTsReference", version: "1.0.0",
    properties: {
      v: { type: "string" }, d: { type: "string" }, u: { type: "string" },
      i: { type: "string" }, ri: { type: "string" }, s: { type: "string" },
      a: { oneOf: [{ type: "string" }, { type: "object",
        properties: { d: { type: "string" }, i: { type: "string" },
                      dt: { type: "string", format: "date-time" },
                      name: { type: "string" } },
        required: ["d", "i", "dt", "name"], additionalProperties: false }] }
    },
    required: ["v", "d", "i", "ri", "s", "a"], additionalProperties: false
  };
}

// A v1 credential, its registry and its iss (and rev) issued by keri-ts
// to a holder.
function* issueCredential(opts) {
  log.debug("Entering issueCredential().");
  const o = opts || {};
  const { hby: I, opener } = yield* habery("iss", SALT_A);
  const ih = I.makeHab("issuer", undefined, { version: Vrsn_1_0 });
  const { hby: H } = yield* habery("hld", SALT_B);
  const hh = H.makeHab("holder", undefined, { version: Vrsn_1_0 });
  yield* feedInto(I, clone(H, hh.pre));
  const reger = yield* openReger(opener, "iss");
  const rgy = new Regery(I, { reger: reger });
  const registry = rgy.makeRegistry("reg", ih,
    { nonce: "0ABZazAFH587nU2w_OtwMQr-" });
  const schemer = new Schemer({ sed: witnessSchema() });
  pinSchemaBytes(I, schemer.raw);
  const cr = new Credentialer(I, { reger: reger, vry: rgy.vry });
  const creder = credential({ issuer: ih.pre, registry: registry.regk,
    schema: schemer.said, recipient: hh.pre, data: { name: "Alice" },
    dt: STAMP });
  cr.validate(creder);
  cr.issue(registry, creder);
  if (o.revoke) {
    registry.revoke(creder.said);
  }
  log.debug("Leaving issueCredential().");
  return { I: I, ih: ih, H: H, hh: hh, reger: reger, schemer: schemer,
           creder: creder };
}

// keri-ts's presentation stream of a credential (KEL, vcp, iss [, rev],
// the ACDC with its -I triple) and its schema.
export async function makeCredential(opts) {
  log.debug("Entering makeCredential().");
  const out = await run(function* () {
    const c = yield* issueCredential(opts);
    return { stream: txt(exportCredentialStream(c.I, c.reger,
                                                c.creder.said).bytes),
             schema: txt(c.schemer.raw), said: c.creder.said };
  });
  log.debug("Leaving makeCredential().");
  return out;
}

// An IPEX grant of keri-ts's credential to its holder, the holder's admit,
// and what a recipient needs beside them.
export async function makeGrant() {
  log.debug("Entering makeGrant().");
  const out = await run(function* () {
    const c = yield* issueCredential();
    const g = ipexCredentialGrant({ hby: c.I, reger: c.reger, hab: c.ih,
      recipient: c.hh.pre, credentialSaid: c.creder.said, message: "",
      options: { stamp: STAMP } });
    const pair = ipexAdmitExn(c.hh, "", g.grant, { stamp: STAMP });
    const admit = cat([c.hh.endorse(pair[0], { pipelined: false }),
                       pair[1]]);
    return { credential: txt(exportCredentialStream(c.I, c.reger,
                                                    c.creder.said).bytes),
             schema: txt(c.schemer.raw), holderKel: txt(clone(c.H,
                                                              c.hh.pre)),
             grant: txt(g.wire), grantSaid: g.grant.said,
             admit: txt(admit) };
  });
  log.debug("Leaving makeGrant().");
  return out;
}

// ------------------------------------------------------------- CONSUME

// keri-ts's Kevery on a stream: each decision, and the key state of every
// identifier it accepted.
export async function kelAccept(stream) {
  log.debug("Entering kelAccept().");
  const out = await run(function* () {
    const { hby } = yield* habery("ver");
    const decisions = yield* feedInto(hby, stream);
    const states = {};
    decisions.forEach(function (d) {
      if (d.pre && !states[d.pre]) {
        states[d.pre] = keyState(hby, d.pre);
      }
    });
    return { decisions: decisions, states: states };
  });
  log.debug("Leaving kelAccept().");
  return out;
}

// keri-ts's Kevery, Tevery and Verifier on a credential presentation, the
// schemas (a JSON text or a list of them) pinned first: whether each
// credential was saved, and its TEL state.
export async function credentialAccept(stream, schemaText) {
  log.debug("Entering credentialAccept().");
  const out = await run(function* () {
    const { hby, opener } = yield* habery("ver");
    const reger = yield* openReger(opener, "ver");
    const proc = createProtocolProcessor(hby);
    proc.tvy = new Tevery({ db: hby.db, reger: reger,
                            cues: proc.protocolCues });
    proc.vry = new Verifier(hby, { reger: reger, cues: proc.protocolCues });
    [].concat(schemaText || []).forEach(function (text) {
      pinSchemaBytes(hby, enc.encode(text));
    });
    const decisions = yield* feed(proc, proc.makeKevery(), stream);
    const creds = {};
    for (const fr of parseBytes(bytes(stream))) {
      if (fr.body.proto !== "ACDC") {
        continue;
      }
      const ri = fr.body.ked.ri;
      const tever = proc.tvy.tevers.get(ri);
      const vc = tever ? tever.vcState(fr.body.said) : null;
      creds[fr.body.said] = { saved: !!reger.saved.get([fr.body.said]),
                              telState: vc ? vc.et : null };
    }
    return { decisions: decisions, credentials: creds };
  });
  log.debug("Leaving credentialAccept().");
  return out;
}

// keri-ts's Exchanger on a stream: an exn is stored only once its sender's
// signatures verify against the sender's KEL, which precedes it.
export async function exnAccept(stream) {
  log.debug("Entering exnAccept().");
  const out = await run(function* () {
    const { hby } = yield* habery("ver");
    const decisions = yield* feedInto(hby, stream);
    return decisions.filter(function (d) {
      return d.ilk === "exn";
    }).map(function (d) {
      return Object.assign({ stored: !!hby.db.exns.get([d.said]) }, d);
    });
  });
  log.debug("Leaving exnAccept().");
  return out;
}

// cesr-ts's SerderACDC / SerderKERI on a body: its SAID, or the error.
export function serderSaid(text, acdc) {
  log.debug("Entering serderSaid().");
  try {
    const s = acdc ? new SerderACDC({ raw: enc.encode(text) }) :
      new SerderKERI({ raw: enc.encode(text) });
    log.debug("Leaving serderSaid().");
    return { said: s.said };
  } catch (e) {
    log.debug("Leaving serderSaid(). Refused.");
    return { error: e.message };
  }
}

// cesr-ts's Tholder: does a threshold accept these signer indices?
export function tholderSatisfy(sith, indices) {
  log.debug("Entering tholderSatisfy().");
  log.debug("Leaving tholderSatisfy().");
  return new Tholder(sith).satisfy(indices);
}

// cesr-ts's Aggor: the JSON-kind AGID of an aggregate list.
export function aggregateId(ael) {
  log.debug("Entering aggregateId().");
  log.debug("Leaving aggregateId().");
  return new Aggor({ ael: ael, kind: Kinds.json }).agid;
}
