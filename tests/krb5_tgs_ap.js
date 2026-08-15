// File: krb5_tgs_ap.js
//
// The whole protocol, end to end: AS → TGS → AP, with mutual authentication and
// per-message tokens. The client is common/krb5; the KDC and the service are the
// sts/ submodule's.
//
// ---------------------------------------------------------------------------
// What this proves that the AS test does not.
//
// krb5_as_exchange.js gets a TGT. That is half the protocol and the easy half: a
// KDC that issues tickets is straightforward. The other half is a ticket being
// PRESENTED to something that decrypts it, checks it, and proves itself back — and
// until something does that, "the ticket looks right" is the strongest claim
// available about any of this.
//
// Four things here fail in ways nothing else catches:
//
//  1. **A TGS-REQ carries the TGT as pre-authentication**, in a PA-TGS-REQ whose
//     value is an entire AP-REQ, whose Authenticator carries a checksum over the
//     encoded KDC-REQ-BODY. If the body is re-encoded between checksumming it and
//     sending it, the KDC sees a checksum over something else — and the error is
//     KRB_AP_ERR_INAPP_CKSUM, which names the checksum rather than the encoding.
//  2. **The TGS-REP's enc-part is at key usage 8, or 9 when a subkey was sent.**
//     Both paths are exercised, because a client that always tries one fails
//     whenever the other applies and the symptom is an integrity failure.
//  3. **The 0x8003 checksum is not a checksum.** It carries the GSS flags, and its
//     integers are LITTLE-endian in a protocol where everything else is big-endian.
//     A service reads MUTUAL out of it to decide whether it must prove itself.
//  4. **Mutual authentication is an ECHO, and it has to be checked.** The AP-REP
//     returns the Authenticator's ctime encrypted under the session key. A client
//     that asks for mutual authentication and does not verify the echo has not
//     performed it — it has only asked.
//
// And the negatives, which are the point: a replayed Authenticator, a ticket for the
// wrong service, a stale key version, a tampered request body, a clock outside the
// tolerance.
//
// No browser, and no running service: the KDC and the protected service are started
// in-process on ephemeral ports.
// ---------------------------------------------------------------------------
const assert = require("assert");
const fs = require("fs");
const net = require("net");
const path = require("path");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "krb5_tgs_ap",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

function shared(name) {
  return paths.requireSharedModule(
    [__dirname + "/../common/krb5/" + name, __dirname + "/" + name], name);
}
const prim = shared("krb5_primitives.js");
const msgs = shared("krb5_messages.js");
const kcrypto = shared("krb5_crypto.js");
const gss = shared("krb5_gss.js");
const client = shared("krb5_client.js");
const kpac = shared("krb5_pac.js");

// The mock KDC and service live in the sts/ SUBMODULE. Between a change being
// written in a sibling mock-sts checkout and this repository's gitlink moving,
// the submodule genuinely does not have the file — so the sibling is accepted
// and announced loudly, because a green run against an unpushed working copy
// corresponds to no commit. Both the resolution order and the two loud warnings
// live in module_paths.js, so the two Kerberos tests that need the mock KDC
// cannot drift apart on which copy they picked up. Set MOCK_STS_DIR to test an
// uncommitted change to a module the submodule already has — without it, the
// stale submodule copy is found and used.
function stsModule(name) {
  return paths.mockStsModule(name, function (message) { log.warn(message); });
}

const REALM = "EXAMPLE.COM";
const SERVICE = ["HTTP", "web.example.com"];

// The long-term passwords and the domain SID the mock KDC uses, so the PAC's
// signatures can be verified here the way a real service and a real KDC would
// verify them. They are the mock's own defaults (krb5_principals.js); a
// mismatch shows up as a signature that does not verify, which is why they are
// named here rather than inlined.
const KRBTGT_PASSWORD = process.env.KRB5_KRBTGT_PASSWORD || 
    "krbtgt-mock-password";
const SERVICE_PASSWORD = "service-account-password";
// The inter-realm trust: ONE shared secret, held as krbtgt/PARTNER.COM in both
// realms.
const TRUST_PASSWORD = process.env.KRB5_TRUST_PASSWORD || 
    "inter-realm-trust-password";
// And the target realm's own ticket-granting key, which is NOT the trust key.
const PARTNER_KRBTGT_PASSWORD = process.env.KRB5_TRUSTED_KRBTGT_PASSWORD ||
  "partner-krbtgt-password";
const DOMAIN_SID = process.env.KRB5_DOMAIN_SID || 
    "S-1-5-21-1004336348-1177238915-682003330";
// The second realm's domain SID, which must DIFFER from the first: a PAC
// identifies an account by its own domain's SID, and two realms sharing one SID
// would hide every mistake about which domain a PAC describes.
const PARTNER_DOMAIN_SID = process.env.KRB5_TRUSTED_DOMAIN_SID ||
  "S-1-5-21-2035427030-2118130302-1178042555";
let kdcModule = null;
let serviceModule = null;
let kdcPort = 0;
let servicePort = 0;

// Talk to a length-prefixed listener. The KDC and the protected service use the
// same framing on purpose, so one function reaches both.
function sendFramed(port, bytes) {
  log.debug("Leaving sendFramed().");
  log.debug("Entering sendFramed().");
  return new Promise(function (resolve, reject) {
    const socket = new net.Socket();
    let buffer = Buffer.alloc(0);
    let settled = false;
    function finish(err, value) {
      log.debug("Entering finish().");
      if (settled) {
        log.debug("Leaving finish().");
        return;
      }
      settled = true;
      socket.destroy();
      if (err) {
        log.debug("Leaving finish().");
        return reject(err);
      }
      resolve(value);
      log.debug("Leaving finish().");
    }
    const timer = setTimeout(function () { finish(new Error("timed out after 10s")); }, 
        10000);
    socket.on("connect", function () {
      const framed = Buffer.alloc(4 + bytes.length);
      framed.writeUInt32BE(bytes.length, 0);
      Buffer.from(bytes).copy(framed, 4);
      socket.write(framed);
    });
    socket.on("data", function (chunk) {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length < 4) {
        return;
      }
      const declared = buffer.readUInt32BE(0);
      if (buffer.length < 4 + declared) {
        return;
      }
      clearTimeout(timer);
      finish(null, buffer.subarray(4, 4 + declared));
    });
    socket.on("end", function () {
      clearTimeout(timer);
      // A clean close with no reply is meaningful: the protected service does
      // that when mutual authentication was not requested.
      if (!buffer.length) finish(null, null);
    });
    socket.on("error", function (e) { clearTimeout(timer); finish(e); });
    socket.connect(port, "127.0.0.1");
  });
}

// ---------------------------------------------------------------------------
// Getting a TGT, which the AS test already covers — done briefly here because
// everything below needs one.
// ---------------------------------------------------------------------------
async function getTgt(principalName, password, extraPadata, realm, saltOverride, kdcOptions) {
  log.debug("Entering getTgt().");
  const bare = msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.AS_REQ,
    reqBody: {
      kdcOptions: kdcOptions || [msgs.KDC_OPTION.FORWARDABLE, 
          msgs.KDC_OPTION.RENEWABLE],
      cname: { type: msgs.NAME_TYPE.PRINCIPAL, name: [principalName] },
      realm: realm || REALM,
      sname: {
        type: msgs.NAME_TYPE.SRV_INST,
        name: ["krbtgt", realm || REALM]
      },
      till: new Date(Date.now() + 10 * 3600 * 1000),
      nonce: client.randomNonce(),
      etypes: [18, 17]
    }
  });
  const first = msgs.readKdcResponse(await sendFramed(kdcPort, bare));
  assert.strictEqual(first.error.errorCode, 25, "expected PREAUTH_REQUIRED " +
      "for " + principalName);
  const info = msgs.readEtypeInfo2(
    first.error.eDataPaData.filter(function (pa) { return pa.type === 19; })[0].value)
    .filter(function (e) { return e.etype === 18; })[0];

  const profile = kcrypto.etypeById(18);
  // The KDC tells the client the salt in PA-ETYPE-INFO2 and that is what should
  // be used; `saltOverride` exists only so a test can prove a WRONG salt fails.
  const key = await profile.stringToKey(password,
    saltOverride || prim.utf8(info.salt), info.s2kparams);
  const nonce = client.randomNonce();
  const withPreauth = msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.AS_REQ,
    padata: [{
      type: msgs.PA_TYPE.ENC_TIMESTAMP,
      value: msgs.encEncryptedData({
        etype: 18,
        cipher: await profile.encrypt(key, 
            kcrypto.KEY_USAGE.AS_REQ_PA_ENC_TIMESTAMP,
          msgs.encPaEncTsEnc(new Date(), 0))
      })
    }].concat(extraPadata || []),
    reqBody: {
      kdcOptions: kdcOptions || [msgs.KDC_OPTION.FORWARDABLE, 
          msgs.KDC_OPTION.RENEWABLE],
      cname: { type: msgs.NAME_TYPE.PRINCIPAL, name: [principalName] },
      realm: realm || REALM,
      sname: {
        type: msgs.NAME_TYPE.SRV_INST,
        name: ["krbtgt", realm || REALM]
      },
      till: new Date(Date.now() + 10 * 3600 * 1000),
      nonce: nonce,
      etypes: [18, 17]
    }
  });
  const response = msgs.readKdcResponse(await sendFramed(kdcPort, withPreauth));
  assert.strictEqual(response.kind, "AS-REP", "expected a TGT for " + 
      principalName);
  const rep = response.rep;
  const part = msgs.readEncKdcRepPart(
    await profile.decrypt(key, kcrypto.KEY_USAGE.AS_REP_ENCPART, 
        rep.encPart.cipher));
  assert.strictEqual(part.nonce, nonce, "the AS-REP's nonce must match");
  log.debug("Leaving getTgt().");
  return {
    ticket: rep.ticket,
    sessionKey: part.key.key,
    etype: part.key.etype,
    client: rep.cname,
    realm: rep.crealm,
    authtime: part.authtime,
    renewTill: part.renewTill,
    flagNames: msgs.ticketFlagNames(part.flags || []),
    endtime: part.endtime
  };
}

// ---------------------------------------------------------------------------
// The TGS exchange.
// ---------------------------------------------------------------------------
async function theTgsExchangeIssuesAServiceTicket(tgt) {
  log.debug("Entering theTgsExchangeIssuesAServiceTicket().");

  // Without a subkey: the reply comes back at key usage 8.
  const built = await client.buildTgsReq({
    tgt: tgt,
    sname: { type: msgs.NAME_TYPE.SRV_HST, name: SERVICE },
    subkey: null
  });
  const result = await client.readTgsRep({
    tgt: tgt,
    reply: await sendFramed(kdcPort, built.request),
    nonce: built.nonce,
    subkey: null
  });
  assert.ok(result.ok, "the TGS exchange failed: " +
    (result.error ? result.error.error.name + " — " + result.error.eText : 
        "unknown"));
  assert.ok(/key usage 8/.test(result.openedWith),
    "with no subkey the reply must be at key usage 8, got: " + 
        result.openedWith);
  assert.deepStrictEqual(result.service.name, SERVICE, "the ticket must be " +
      "for the service asked for");
  assert.deepStrictEqual(result.client.name, tgt.client.name, "and issued to " +
      "the same client");
  assert.strictEqual(prim.toHex(result.sessionKey).length, 64, "an aes256 " +
      "session key is 32 bytes");
  assert.notStrictEqual(prim.toHex(result.sessionKey), 
      prim.toHex(tgt.sessionKey),
    "the service ticket must carry a NEW session key, not the TGT's");

  // The flags: inherited from the TGT, minus `initial`. A service may rely on
  // that distinction, so a KDC that copied `initial` across would be lying
  // about how the ticket was obtained.
  assert.ok(result.flagNames.indexOf("initial") === -1,
    "a ticket from the TGS exchange must NOT be flagged initial — only the " +
        "AS exchange issues one: " +
    result.flagNames.join(", "));
  assert.ok(result.flagNames.indexOf("pre-authent") !== -1,
    "but pre-authent is inherited from the TGT: " + 
        result.flagNames.join(", "));
  assert.ok(result.flagNames.indexOf("ok-as-delegate") !== -1,
    "and this service is flagged ok-as-delegate: " + 
        result.flagNames.join(", "));
  assert.ok(result.endtime <= tgt.endtime,
    "a service ticket cannot outlive the TGT that bought it (" + 
        result.endtime.toISOString() +
    " vs " + tgt.endtime.toISOString() + ")");

  // With a subkey: the reply comes back at key usage 9 instead. Both paths
  // matter because the KDC chooses based on what was sent.
  const profile = kcrypto.etypeById(tgt.etype);
  const subkey = {
    etype: tgt.etype,
    key: kcrypto.randomBytes(profile.keyBytes)
  };
  const builtWithSubkey = await client.buildTgsReq({
    tgt: tgt, sname: {
      type: msgs.NAME_TYPE.SRV_HST,
      name: SERVICE
    }, subkey: subkey });
  const withSubkey = await client.readTgsRep({
    tgt: tgt,
    reply: await sendFramed(kdcPort, builtWithSubkey.request),
    nonce: builtWithSubkey.nonce,
    subkey: subkey
  });
  assert.ok(withSubkey.ok, "the TGS exchange with a subkey failed");
  assert.ok(/key usage 9/.test(withSubkey.openedWith),
    "with a subkey the reply must be at key usage 9, got: " + 
        withSubkey.openedWith);

  log.info("the TGS exchange issued a ticket for " + SERVICE.join("/") + " (" +
    kcrypto.etypeName(result.etype) + ", flags [" + 
        result.flagNames.join(", ") + "])");
  log.debug("Leaving theTgsExchangeIssuesAServiceTicket().");
  return result;
}

// The PAC the LIVE KDC minted, in both kinds of ticket.
//
// tests/krb5_pac.js checks the codec against itself and against [MS-PAC]'s byte
// offsets. What this checks is different and cannot be checked there: that the
// mock KDC, having gone through the whole AS and TGS exchange, produced a PAC
// whose signatures verify with the keys a real verifier would use — the
// SERVICE's key for the server signature and the krbtgt key for the rest.
//
// Both tickets are opened, and that pair is the point. In a TGT the service key
// and the krbtgt key are the SAME key, so a KDC that used the krbtgt key for
// the server signature everywhere would pass every TGT test ever written and
// produce service tickets no Windows service accepts. Only the service ticket
// can tell the two apart.
async function theKdcIssuesAVerifiablePac(tgt, serviceTicket) {
  log.debug("Entering theKdcIssuesAVerifiablePac().");
  const profile = kcrypto.etypeById(tgt.etype);
  const krbtgtKey = {
    etype: tgt.etype,
    key: await profile.stringToKey(KRBTGT_PASSWORD, prim.utf8(REALM + 
        "krbtgt"), null),
    label: "the krbtgt key"
  };
  const serviceKey = {
    etype: serviceTicket.etype,
    key: await kcrypto.etypeById(serviceTicket.etype)
      .stringToKey(SERVICE_PASSWORD, prim.utf8(REALM + "HTTPweb"), null),
    label: "the service's key"
  };

  // Open each ticket and pull the PAC out of it. The tickets are opaque to the
  // client that holds them, which is why this needs the long-term keys.
  async function pacIn(ticket, key, what) {
    log.debug("Entering pacIn().");
    const encPart = ticket.encPart;
    const part = msgs.readEncTicketPart(await kcrypto.etypeById(encPart.etype)
      .decrypt(key.key, kcrypto.KEY_USAGE.KDC_REP_TICKET, encPart.cipher));
    assert.ok(part.authorizationData,
      what + " carries no authorization-data at all, so it carries no PAC. A " +
          "Windows service " +
      "reading groups out of this ticket would find nothing.");
    const found = kpac.findPacs(part.authorizationData);
    assert.strictEqual(found.length, 1,
      what + " should carry exactly one PAC, found " + found.length);
    assert.strictEqual(found[0].path, "AD-IF-RELEVANT → AD-WIN2K-PAC",
      what + "'s PAC must be nested inside AD-IF-RELEVANT, not at the top " +
          "level: " + found[0].path);
    log.debug("Leaving pacIn().");
    return { pac: kpac.parsePac(found[0].bytes), part: part };
  }

  // --- the TGT, encrypted to krbtgt ---
  const inTgt = await pacIn(tgt.ticket, krbtgtKey, "the TGT");
  assert.deepStrictEqual(inTgt.pac.problems, [],
    "the TGT's PAC should be well formed: " + inTgt.pac.problems.join(" | "));

  const tgtInfo = kpac.bufferOfType(inTgt.pac, kpac.TYPE.LOGON_INFO).parsed;
  assert.strictEqual(tgtInfo.effectiveName, "alice",
    "the PAC must name the account the ticket was issued to");
  assert.strictEqual(tgtInfo.userSid, DOMAIN_SID + "-1104",
    "and carry its SID, which is what a service authorizes on: " + 
        tgtInfo.userSid);
  assert.ok(tgtInfo.groups.some(function (g) { return g.relativeId === 512; }),
    "alice is a Domain Admin in the principal table, so her PAC must say so: " +
    tgtInfo.groups.map(function (g) { return g.relativeId; }).join(", "));
  assert.ok(tgtInfo.extraSids.some(function (e) { return e.text === "S-1-18-1"; }),
    "and carry the asserted-identity SID a real AD puts in a password " +
        "logon's PAC: " +
    tgtInfo.extraSids.map(function (e) { return e.text; }).join(", "));
  assert.deepStrictEqual(tgtInfo.notes, [],
    "the KDC's own PAC should raise no consistency notes: " + 
        tgtInfo.notes.join(" | "));

  // A TGT is encrypted TO krbtgt, so [MS-PAC] sections 2.8.2/2.8.3 say it
  // should carry neither the ticket signature nor the extended KDC signature.
  // Asserting their ABSENCE is what stops the KDC quietly emitting all four
  // everywhere, which would teach a client to require signatures a real domain
  // does not send.
  assert.strictEqual(kpac.countOfType(inTgt.pac, kpac.TYPE.TICKET_CHECKSUM), 0,
    "a TGT is encrypted to krbtgt, so it should carry NO ticket signature");
  assert.strictEqual(kpac.countOfType(inTgt.pac, 
      kpac.TYPE.EXTENDED_KDC_CHECKSUM), 0,
    "and no extended KDC signature either");

  // In a TGT the service IS krbtgt, so one key verifies everything.
  const tgtSigs = await kpac.verifySignatures(inTgt.pac,
    { serverKey: krbtgtKey, kdcKey: krbtgtKey });
  assert.strictEqual(tgtSigs.length, 2, 
      "a TGT's PAC has two signatures, got " + tgtSigs.length);
  tgtSigs.forEach(function (s) {
    assert.strictEqual(s.verified, true,
      "the TGT's " + s.name + " does not verify with the krbtgt key: " + 
          s.note);
  });

  // --- the service ticket, where the two keys differ ---
  const inService = await pacIn(serviceTicket.ticket, serviceKey, 
      "the service ticket");
  assert.deepStrictEqual(inService.pac.problems, [],
    "the service ticket's PAC should be well formed: " + 
        inService.pac.problems.join(" | "));

  assert.strictEqual(kpac.countOfType(inService.pac, 
      kpac.TYPE.TICKET_CHECKSUM), 1,
    "a service ticket is NOT encrypted to krbtgt, so [MS-PAC] section 2.8.2 " +
        "says it SHOULD " +
    "carry a ticket signature");
  assert.strictEqual(kpac.countOfType(inService.pac, 
      kpac.TYPE.EXTENDED_KDC_CHECKSUM), 1,
    "and an extended KDC signature (the CVE-2022-37967 hardening)");

  // The server signature with the SERVICE's key, the rest with krbtgt. This is
  // the assertion the TGT cannot make.
  const serviceSigs = await kpac.verifySignatures(inService.pac, {
    serverKey: serviceKey,
    kdcKey: krbtgtKey,
    // The ticket signature covers the EncTicketPart with this PAC's ad-data
    // replaced by a single zero byte — reconstructed here exactly as a KDC
    // would.
    ticketBytes: msgs.encEncTicketPart(Object.assign({}, inService.part, {
      authorizationData: kpac.wrapPacAsAuthorizationData(new Uint8Array([0]))
    }))
  });
  assert.strictEqual(serviceSigs.length, 4,
    "a service ticket's PAC has all four signatures, got " + 
        serviceSigs.length + ": " +
    serviceSigs.map(function (s) { return s.name; }).join(", "));
  serviceSigs.forEach(function (s) {
    assert.strictEqual(s.verified, true,
      "the service ticket's " + s.name + " does not verify: " + s.note);
  });

  // And the discrimination: the krbtgt key must NOT verify the server signature
  // on a service ticket. Without this, using the wrong key everywhere would
  // pass above.
  const wrongWay = await kpac.verifySignatures(inService.pac,
    { serverKey: krbtgtKey, kdcKey: krbtgtKey });
  const serverWithKrbtgt = wrongWay.filter(function (s) {
    return s.type === kpac.TYPE.SERVER_CHECKSUM;
  })[0];
  assert.strictEqual(serverWithKrbtgt.verified, false,
    "the server signature on a SERVICE ticket must be made with the " +
        "service's own key, not the " +
    "krbtgt key — that is what lets a service verify the PAC by itself. It " +
        "verified with krbtgt, " +
    "so the KDC is signing with the wrong key and no service would accept " +
        "these tickets.");

  // The client-info buffer ties the PAC to this ticket's client and to the
  // ORIGINAL authentication time, which is the same in the TGT and in the
  // ticket bought with it.
  const clientInfo = kpac.bufferOfType(inService.pac, 
      kpac.TYPE.CLIENT_INFO).parsed;
  assert.strictEqual(clientInfo.name, "alice");
  assert.strictEqual(clientInfo.clientId.date.getTime(),
    Math.floor(inService.part.authtime.getTime() / 1000) * 1000,
    "PAC_CLIENT_INFO's ClientId is the INITIAL authentication time, which a " +
        "service checks " +
    "against the ticket's authtime: " + clientInfo.clientId.text + " vs " +
    inService.part.authtime.toISOString());

  log.info("the KDC's PACs verify: the TGT's 2 signatures under krbtgt, and " +
      "the service ticket's " +
    "4 with the server signature under " + SERVICE.join("/") + "'s own key");
  log.debug("Leaving theKdcIssuesAVerifiablePac().");
}

// A principal whose PAC records the misconfiguration that makes it interesting.
// The point is not that these accounts exist — krb5_as_exchange.js already
// drives their KDC behaviour — but that the PAC and the behaviour AGREE. An
// account the KDC treats as needing no pre-authentication whose PAC does not
// say DONT_REQUIRE_PREAUTH is a mock that would teach somebody the wrong thing
// about a real domain.
async function thePacAgreesWithTheAccountsBehaviour() {
  log.debug("Entering thePacAgreesWithTheAccountsBehaviour().");
  // getTgt() cannot be reused here: it performs the two-message dance, and the
  // whole point of this account is that its AS-REQ is answered in ONE message.
  // So the bare request is sent and the AS-REP read directly — and the client's
  // own key is never needed, because everything asserted below is inside the
  // TICKET, which is sealed with the krbtgt key.
  const bare = msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.AS_REQ,
    reqBody: {
      kdcOptions: [msgs.KDC_OPTION.FORWARDABLE],
      cname: { type: msgs.NAME_TYPE.PRINCIPAL, name: ["noreauth"] },
      realm: REALM,
      sname: { type: msgs.NAME_TYPE.SRV_INST, name: ["krbtgt", REALM] },
      till: new Date(Date.now() + 10 * 3600 * 1000),
      nonce: client.randomNonce(),
      etypes: [18]
    }
  });
  const reply = msgs.readKdcResponse(await sendFramed(kdcPort, bare));
  assert.ok(!reply.error,
    "the noreauth account should be answered with a TGT rather than " +
        "KDC_ERR_PREAUTH_REQUIRED — " +
    "that is the whole reason it exists: " +
    (reply.error ? reply.error.error.name + " (" + reply.error.errorCode + 
        ")" : ""));
  const profile = kcrypto.etypeById(reply.rep.ticket.encPart.etype);
  const krbtgtKey = await profile.stringToKey(KRBTGT_PASSWORD, 
      prim.utf8(REALM + "krbtgt"), null);
  const part = msgs.readEncTicketPart(await profile.decrypt(krbtgtKey,
    kcrypto.KEY_USAGE.KDC_REP_TICKET, reply.rep.ticket.encPart.cipher));
  const found = kpac.findPacs(part.authorizationData);
  assert.strictEqual(found.length, 1, "the noreauth account's TGT should " +
      "carry a PAC too");
  const info = kpac.bufferOfType(kpac.parsePac(found[0].bytes), 
      kpac.TYPE.LOGON_INFO).parsed;

  assert.ok(info.userAccountControlNames.indexOf("DONT_REQUIRE_PREAUTH") !== -1,
    "this account's AS-REQ was answered in ONE message rather than two, and " +
        "the reason is a " +
    "UserAccountControl bit. Its PAC has to carry that bit, or the workflow " +
        "shows an exchange " +
    "with no visible cause: " + info.userAccountControlNames.join(", "));
  // pre-authent must NOT be set on the ticket, because pre-authentication did
  // not happen — the two facts have to line up.
  assert.ok(part.flags.indexOf(msgs.TICKET_FLAG.PRE_AUTHENT) === -1,
    "and the ticket must NOT be flagged pre-authent, since no " +
        "pre-authentication took place: " +
    msgs.ticketFlagNames(part.flags).join(", "));

  log.info("the noreauth account's PAC says DONT_REQUIRE_PREAUTH, matching " +
      "the one-message " +
    "exchange the KDC actually performed");
  log.debug("Leaving thePacAgreesWithTheAccountsBehaviour().");
}

// Declining the PAC, and the reason this is a test rather than a note.
//
// PA-PAC-REQUEST has THREE states — include=TRUE, include=FALSE, and absent —
// and the request page offers a checkbox, which has two. Unticking it used to
// send NO padata, which means "the KDC decides", and a KDC decides to include a
// PAC: the control promised a ticket without one and delivered a ticket with
// one. That is the class of bug where a UI does something plausible and nothing
// fails.
//
// So both halves are asserted: an explicit decline produces a TGT with no PAC,
// AND the service ticket bought with that TGT has none either. The second half
// is the one worth having — a KDC that re-derived the PAC at the TGS exchange
// would hand back a service ticket with a full PAC from a TGT that had none,
// and since nobody looks inside a TGT that would go unnoticed.
async function decliningThePacYieldsATicketWithoutOne() {
  log.debug("Entering decliningThePacYieldsATicketWithoutOne().");
  const declined = await getTgt("alice", "hunter2",
    [{ type: msgs.PA_TYPE.PAC_REQUEST, value: msgs.encPaPacRequest(false) }]);
  const profile = kcrypto.etypeById(declined.etype);
  const krbtgtKey = await profile.stringToKey(KRBTGT_PASSWORD, 
      prim.utf8(REALM + "krbtgt"), null);

  const tgtPart = msgs.readEncTicketPart(await profile.decrypt(krbtgtKey,
    kcrypto.KEY_USAGE.KDC_REP_TICKET, declined.ticket.encPart.cipher));
  assert.strictEqual(kpac.findPacs(tgtPart.authorizationData || []).length, 0,
    "a client that sent include-pac=FALSE must get a TGT with NO PAC. It has " +
        "one, so the " +
    "checkbox on the request page does not do what its label says.");

  // And the ticket bought with it.
  const built = await client.buildTgsReq({
    tgt: declined, sname: {
      type: msgs.NAME_TYPE.SRV_HST,
      name: SERVICE
    }, subkey: null });
  const result = await client.readTgsRep({
    tgt: declined,
    reply: await sendFramed(kdcPort, built.request),
    nonce: built.nonce,
    subkey: null
  });
  assert.ok(result.ok, "the TGS exchange with a PAC-less TGT should still " +
      "succeed: " +
    (result.error ? result.error.error.name : "unknown"));

  const serviceKey = await kcrypto.etypeById(result.etype)
    .stringToKey(SERVICE_PASSWORD, prim.utf8(REALM + "HTTPweb"), null);
  const servicePart = msgs.readEncTicketPart(await kcrypto.etypeById(result.etype)
    .decrypt(serviceKey, kcrypto.KEY_USAGE.KDC_REP_TICKET, 
        result.ticket.encPart.cipher));
  assert.strictEqual(kpac.findPacs(servicePart.authorizationData || []).length, 
      0,
    "a service ticket bought with a PAC-less TGT must also have no PAC — a " +
        "real KDC carries the " +
    "client's authorization data forward from the TGT rather than looking " +
        "the account up again, " +
    "so acquiring a PAC by asking for a service ticket is not something a " +
        "client can do.");

  // The positive control: with the SAME code path but no decline, a PAC is
  // present. Without this the assertions above would pass against a KDC that
  // never issues one.
  const granted = await getTgt("alice", "hunter2");
  const grantedPart = msgs.readEncTicketPart(await profile.decrypt(krbtgtKey,
    kcrypto.KEY_USAGE.KDC_REP_TICKET, granted.ticket.encPart.cipher));
  assert.strictEqual(kpac.findPacs(grantedPart.authorizationData || []).length, 
      1,
    "and without the decline the same request must produce a PAC — otherwise " +
        "the assertions " +
    "above are satisfied by a KDC that simply never issues one");

  // And the third state. PAC_ATTRIBUTES_INFO distinguishes a PAC the client
  // ASKED for from one it was given because it said nothing, and that
  // distinction is where the bug that made this whole section necessary was
  // hiding: readPaPacRequest returns an OBJECT, so comparing it to `true` left
  // both states unset and every PAC looked implicitly granted — including the
  // ones that had been explicitly requested. `granted` above sent no
  // PA-PAC-REQUEST at all, so it is the IMPLICIT case: a KDC still includes a
  // PAC, and says that it decided to.
  const implicitAttrs = kpac.bufferOfType(
    kpac.parsePac(kpac.findPacs(grantedPart.authorizationData)[0].bytes),
    kpac.TYPE.ATTRIBUTES_INFO);
  assert.ok(implicitAttrs && implicitAttrs.parsed,
    "the KDC should emit a PAC_ATTRIBUTES_INFO buffer");
  assert.deepStrictEqual(implicitAttrs.parsed.flagNames, 
      ["PAC_WAS_GIVEN_IMPLICITLY"],
    "a client that sent NO PA-PAC-REQUEST still gets a PAC — Active " +
        "Directory decides to include " +
    "one — but it must be recorded as given implicitly: " +
    implicitAttrs.parsed.flagNames.join(", "));

  // And the third state: an explicit include-pac=TRUE, which must be
  // distinguishable from the implicit grant. These two differing is what proves
  // the padata was read at all — with the bug above, every PAC came back marked
  // implicit, including this one.
  const asked = await getTgt("alice", "hunter2",
    [{ type: msgs.PA_TYPE.PAC_REQUEST, value: msgs.encPaPacRequest(true) }]);
  const askedPart = msgs.readEncTicketPart(await profile.decrypt(krbtgtKey,
    kcrypto.KEY_USAGE.KDC_REP_TICKET, asked.ticket.encPart.cipher));
  assert.deepStrictEqual(
    kpac.bufferOfType(kpac.parsePac(kpac.findPacs(askedPart.authorizationData)[0].bytes),
      kpac.TYPE.ATTRIBUTES_INFO).parsed.flagNames,
    ["PAC_WAS_REQUESTED"],
    "and a client that sent include-pac=TRUE must have its PAC recorded as " +
        "REQUESTED rather than " +
    "as given implicitly — if these two cases agree, the padata is not being " +
        "read");

  log.info("an explicit include-pac=FALSE produced a TGT and a service " +
      "ticket with no PAC, TRUE " +
    "produced one recorded as REQUESTED, and an absent PA-PAC-REQUEST one " +
        "recorded as IMPLICIT");
  log.debug("Leaving decliningThePacYieldsATicketWithoutOne().");
}

// The cross-realm referral, chased all the way to a usable service ticket.
//
// This is the case a client gets wrong silently. Asking your own KDC for a service in
// another realm does not produce an error: it produces a perfectly ordinary, successful
// TGS-REP whose `sname` is **krbtgt/OTHER-REALM** rather than the service you named. The
// only signal is that difference. A client that assumes success means "here is your
// service ticket" hands a ticket-granting ticket to a web server, and the web server
// says the ticket does not decrypt — a message about a ticket, for a problem about a
// realm, several steps away from the actual mistake.
//
// So four things are asserted, and the third is the one that makes the rest mean
// something:
//
//  1. The referral is issued rather than KDC_ERR_S_PRINCIPAL_UNKNOWN.
//  2. The client DETECTS it, by comparing the reply's sname with what it asked for.
//  3. Following it produces a ticket the target realm's service can actually open —
//     end to end, with a PAC that verifies under that realm's keys.
//  4. A service in a realm there is NO trust with is still refused, so assertion 1 is
//     not being satisfied by a KDC that refers everything.
async function aCrossRealmReferralIsIssuedAndCanBeFollowed(tgt) {
  log.debug("Entering aCrossRealmReferralIsIssuedAndCanBeFollowed().");
  const PARTNER_REALM = "PARTNER.COM";
  const PARTNER_SERVICE = ["HTTP", "app.partner.com"];

  // --- 1. Ask our own realm for a service that lives in the other one.
  const built = await client.buildTgsReq({
    tgt: tgt,
    sname: { type: msgs.NAME_TYPE.SRV_HST, name: PARTNER_SERVICE },
    subkey: null
  });
  const referred = await client.readTgsRep({
    tgt: tgt,
    reply: await sendFramed(kdcPort, built.request),
    nonce: built.nonce,
    subkey: null,
    requestedSname: built.sname
  });
  assert.ok(referred.ok,
    "asking for a service in a trusted realm must NOT be an error — the KDC " +
        "refers the client " +
    "instead: " + (referred.error ? referred.error.error.name : "unknown"));

  // --- 2. The client has to notice.
  assert.ok(referred.referral,
    "the reply is a REFERRAL and the client must say so. It names " +
    msgs.principalToString(referred.service, referred.serviceRealm) + 
        " rather than the " +
    PARTNER_SERVICE.join("/") + " that was asked for, and a client that does " +
        "not compare those " +
    "two will present a ticket-granting ticket to a web server.");
  assert.strictEqual(referred.referral.toRealm, PARTNER_REALM,
    "and must name the realm to go and ask next: " + 
        JSON.stringify(referred.referral));
  assert.deepStrictEqual(referred.service.name, ["krbtgt", PARTNER_REALM],
    "the ticket issued is a ticket-granting ticket for the other realm");
  assert.ok(referred.flagNames.indexOf("initial") === -1,
    "a referral ticket was not obtained with a password, so it must not be " +
        "flagged initial: " +
    referred.flagNames.join(", "));

  // The referral ticket is sealed with the TRUST key — a key this realm's own
  // krbtgt does not have. Proving that is what distinguishes a real referral
  // from a KDC that just renamed the sname on a local ticket.
  const trustEtype = referred.ticket.encPart.etype;
  const trustProfile = kcrypto.etypeById(trustEtype);
  const trustKey = await trustProfile.stringToKey(TRUST_PASSWORD,
    prim.utf8(REALM + "krbtgt"), null);
  const localKrbtgtKey = await trustProfile.stringToKey(KRBTGT_PASSWORD,
    prim.utf8(REALM + "krbtgt"), null);
  const referralPart = msgs.readEncTicketPart(await trustProfile.decrypt(trustKey,
    kcrypto.KEY_USAGE.KDC_REP_TICKET, referred.ticket.encPart.cipher));
  await assert.rejects(
    trustProfile.decrypt(localKrbtgtKey, kcrypto.KEY_USAGE.KDC_REP_TICKET,
      referred.ticket.encPart.cipher),
    "the referral ticket must be sealed with the TRUST key, not with this " +
        "realm's own krbtgt key " +
    "— the other realm's KDC can only open it because the two realms share " +
        "that one secret");

  // RFC 4120 section 3.3.3.2: `transited` lists the realms traversed EXCLUDING
  // the client's and the server's own, so one hop across a direct trust
  // transits nothing.
  assert.ok(!referralPart.transited || 
      referralPart.transited.contents.length === 0,
    "a direct trust transits no intermediate realm, so `transited` must be " +
        "empty: " +
    JSON.stringify(referralPart.transited));
  assert.strictEqual(referralPart.crealm, REALM,
    "the client's realm travels with the ticket unchanged");

  // --- 3. Follow it: same TGS exchange, other realm, using the referral as the
  // TGT.
  const followed = await client.buildTgsReq({
    tgt: referred,
    sname: { type: msgs.NAME_TYPE.SRV_HST, name: PARTNER_SERVICE },
    realm: PARTNER_REALM,
    subkey: null
  });
  const serviceTicket = await client.readTgsRep({
    tgt: referred,
    reply: await sendFramed(kdcPort, followed.request),
    nonce: followed.nonce,
    subkey: null,
    requestedSname: followed.sname
  });
  assert.ok(serviceTicket.ok,
    "the other realm's KDC must accept the referral ticket and issue the " +
        "service ticket: " +
    (serviceTicket.error ? serviceTicket.error.error.name + " — " + 
        serviceTicket.error.eText
                         : "unknown"));
  assert.strictEqual(serviceTicket.referral, null,
    "and THIS reply is not a referral — it names the service that was asked " +
        "for");
  assert.deepStrictEqual(serviceTicket.service.name, PARTNER_SERVICE);
  assert.strictEqual(serviceTicket.serviceRealm, PARTNER_REALM,
    "the ticket is issued by and for " + PARTNER_REALM);
  assert.strictEqual(serviceTicket.client.name.join("/"), "alice",
    "and it is still for alice, whose account lives in " + REALM);

  // The partner service can open it, and the PAC inside verifies under the
  // PARTNER realm's keys — which it only can because that KDC RE-SIGNED it. The
  // signatures it arrived with were made with the trust key and the other
  // realm's krbtgt.
  const svcProfile = kcrypto.etypeById(serviceTicket.etype);
  const partnerServiceKey = {
    etype: serviceTicket.etype,
    key: await svcProfile.stringToKey("partner-service-password",
      prim.utf8(PARTNER_REALM + "HTTPapp"), null),
    label: "the partner service's key"
  };
  // PARTNER.COM's OWN krbtgt key, which is a different secret from the trust
  // key. That distinction is the whole point of the assertions below: if the
  // two were the same password, "signed with the target realm's krbtgt" and
  // "signed with the trust key" would be indistinguishable and every check here
  // would pass for the wrong reason.
  const partnerKrbtgtKey = {
    etype: serviceTicket.etype,
    key: await svcProfile.stringToKey(PARTNER_KRBTGT_PASSWORD,
      prim.utf8(PARTNER_REALM + "krbtgt"), null),
    label: "PARTNER.COM's own krbtgt key"
  };
  const svcPart = msgs.readEncTicketPart(await svcProfile.decrypt(partnerServiceKey.key,
    kcrypto.KEY_USAGE.KDC_REP_TICKET, serviceTicket.ticket.encPart.cipher));
  const carried = kpac.findPacs(svcPart.authorizationData || []);
  assert.strictEqual(carried.length, 1,
    "the service ticket must carry the client's PAC across the trust");
  const crossPac = kpac.parsePac(carried[0].bytes);
  assert.deepStrictEqual(crossPac.problems, [],
    "and it must still be well formed after re-signing: " + 
        crossPac.problems.join(" | "));

  const crossInfo = kpac.bufferOfType(crossPac, kpac.TYPE.LOGON_INFO).parsed;
  assert.strictEqual(crossInfo.userSid, DOMAIN_SID + "-1104",
    "the PAC still describes alice's account in HER domain — a re-signed PAC " +
        "keeps its contents, " +
    "and the SID a service authorizes on does not become a SID of the " +
        "resource domain: " +
    crossInfo.userSid);
  assert.ok(crossInfo.groups.some(function (g) { return g.relativeId === 512; }),
    "including her group memberships, carried across unchanged");

  const crossSigs = await kpac.verifySignatures(crossPac, {
    serverKey: partnerServiceKey,
    kdcKey: partnerKrbtgtKey,
    ticketBytes: msgs.encEncTicketPart(Object.assign({}, svcPart, {
      authorizationData: kpac.wrapPacAsAuthorizationData(new Uint8Array([0]))
    }))
  });
  crossSigs.forEach(function (s) {
    assert.strictEqual(s.verified, true,
      "after a referral the PAC must verify under " + PARTNER_REALM + 
          "'s OWN keys — its " + s.name +
      " does not (" + s.note + "). A KDC that carried the signatures across " +
          "without recomputing " +
      "them would fail here, and the service would reject a PAC that is " +
          "perfectly genuine.");
  });

  // And the old signatures must be GONE: if the ticket still verified under the
  // issuing realm's keys, nothing had been re-signed.
  const staleSigs = await kpac.verifySignatures(crossPac, {
    serverKey: {
      etype: serviceTicket.etype,
      key: trustKey,
      label: "the trust key"
    },
    kdcKey: {
      etype: serviceTicket.etype,
      key: localKrbtgtKey,
      label: REALM + "'s krbtgt key"
    }
  });
  assert.strictEqual(
    staleSigs.filter(function (s) { return s.type === kpac.TYPE.SERVER_CHECKSUM; })[0].verified,
    false,
    "the PAC must NOT still verify under the ISSUING realm's keys — if it " +
        "does, the target realm " +
    "passed the signatures through instead of recomputing them");

  // --- 4. The control: a realm there is no trust with is still an error.
  const noTrust = await client.buildTgsReq({
    tgt: tgt,
    sname: {
      type: msgs.NAME_TYPE.SRV_HST,
      name: ["HTTP", "app.elsewhere.invalid"]
    },
    subkey: null
  });
  const refused = await client.readTgsRep({
    tgt: tgt,
    reply: await sendFramed(kdcPort, noTrust.request),
    nonce: noTrust.nonce,
    subkey: null,
    requestedSname: noTrust.sname
  });
  assert.ok(!refused.ok,
    "a service in a realm there is no trust with must be REFUSED. If " +
        "everything gets a referral, " +
    "the referral assertions above prove nothing.");
  assert.strictEqual(refused.error.errorCode, 7,
    "and the refusal is KDC_ERR_S_PRINCIPAL_UNKNOWN, got " + 
        refused.error.error.name);

  log.info("a referral to " + PARTNER_REALM + " was issued under the trust " +
      "key, detected by the " +
    "client, followed to a service ticket " + PARTNER_SERVICE.join("/") + 
        " could open, and its " +
    "PAC verified under " + PARTNER_REALM + "'s own keys after re-signing");
  log.debug("Leaving aCrossRealmReferralIsIssuedAndCanBeFollowed().");
}

// The second realm answering for its OWN client, which is not the same code
// path as answering a referral and fails differently when it is wrong.
//
// `krbtgt/PARTNER.COM` exists in BOTH databases: in EXAMPLE.COM it is the
// trust, and in PARTNER.COM it is that realm's own ticket-granting service,
// with a different key. So the presented ticket has to be looked up in the
// realm the TICKET came from, not in the KDC's default realm. Get that wrong
// and a ticket issued inside PARTNER.COM is opened — or sealed — with the trust
// key, and the failure is an integrity check, which names the crypto rather
// than the lookup.
//
// A referral test cannot catch this: there the ticket's realm and the default
// realm happen to be the same, so both the right and the wrong lookup find the
// same entry.
async function theTrustedRealmServesItsOwnClients() {
  log.debug("Entering theTrustedRealmServesItsOwnClients().");
  const PARTNER_REALM = "PARTNER.COM";
  const carol = await getTgt("carol", "partner-user-password", null, 
      PARTNER_REALM);
  assert.strictEqual(carol.realm, PARTNER_REALM,
    "the TGT must be issued by and for " + PARTNER_REALM);

  const built = await client.buildTgsReq({
    tgt: carol,
    sname: { type: msgs.NAME_TYPE.SRV_HST, name: ["HTTP", "app.partner.com"] },
    realm: PARTNER_REALM,
    subkey: null
  });
  const result = await client.readTgsRep({
    tgt: carol,
    reply: await sendFramed(kdcPort, built.request),
    nonce: built.nonce,
    subkey: null,
    requestedSname: built.sname
  });
  assert.ok(result.ok,
    PARTNER_REALM + " must serve its own client without a referral: " +
    (result.error ? result.error.error.name + " — " + result.error.eText : 
        "unknown"));
  assert.strictEqual(result.referral, null,
    "a service in the client's OWN realm is not a referral");

  // The PAC is signed with PARTNER.COM's own krbtgt key — not the trust key,
  // which is the other principal of the same name.
  const svcProfile = kcrypto.etypeById(result.etype);
  const serviceKey = {
    etype: result.etype,
    key: await svcProfile.stringToKey("partner-service-password",
      prim.utf8(PARTNER_REALM + "HTTPapp"), null),
    label: "the partner service's key"
  };
  const part = msgs.readEncTicketPart(await svcProfile.decrypt(serviceKey.key,
    kcrypto.KEY_USAGE.KDC_REP_TICKET, result.ticket.encPart.cipher));
  const found = kpac.findPacs(part.authorizationData || []);
  assert.strictEqual(found.length, 1, "carol's service ticket must carry a " +
      "PAC");
  const info = kpac.bufferOfType(kpac.parsePac(found[0].bytes), 
      kpac.TYPE.LOGON_INFO).parsed;
  assert.strictEqual(info.effectiveName, "carol");

  // carol's SID must be in PARTNER.COM's domain, not EXAMPLE.COM's. The domain
  // SID in a PAC identifies the account's OWN domain, and it is the thing a
  // service compares against — a PAC that carried the KDC's default domain SID
  // would describe an account that does not exist while looking entirely well
  // formed. Two domains with different SIDs is the only arrangement in which
  // that mistake is visible at all.
  assert.strictEqual(info.logonDomainId.text, PARTNER_DOMAIN_SID,
    "carol's account lives in " + PARTNER_REALM + ", so her PAC's " +
        "LogonDomainId must be that " +
    "domain's SID and not the KDC's default: " + info.logonDomainId.text);
  assert.strictEqual(info.userSid, PARTNER_DOMAIN_SID + "-2104",
    "and her account SID follows from it: " + info.userSid);
  assert.strictEqual(info.logonDomainName, "PARTNER",
    "as does the NetBIOS domain name: " + info.logonDomainName);

  const sigs = await kpac.verifySignatures(kpac.parsePac(found[0].bytes), {
    serverKey: serviceKey,
    kdcKey: {
      etype: result.etype,
      key: await svcProfile.stringToKey(PARTNER_KRBTGT_PASSWORD,
        prim.utf8(PARTNER_REALM + "krbtgt"), null),
      label: PARTNER_REALM + "'s own krbtgt key"
    },
    ticketBytes: msgs.encEncTicketPart(Object.assign({}, part, {
      authorizationData: kpac.wrapPacAsAuthorizationData(new Uint8Array([0]))
    }))
  });
  sigs.forEach(function (s) {
    assert.strictEqual(s.verified, true,
      "a ticket issued inside " + PARTNER_REALM + " must be signed with THAT " +
          "realm's own krbtgt " +
      "key, not with the trust key that shares its principal name — its " + 
          s.name + " does not " +
      "verify (" + s.note + ")");
  });

  log.info(PARTNER_REALM + " served its own client carol end to end, with " +
      "the PAC signed by its " +
    "own krbtgt key rather than by the trust");
  log.debug("Leaving theTrustedRealmServesItsOwnClients().");
}

// ---------------------------------------------------------------------------
// Delegation: S4U2Self, S4U2Proxy, and the two ways it can be authorized.
//
// The names are unhelpful, so what these actually do:
//
//   S4U2Self  — a service asks for a ticket TO ITSELF on behalf of a user who is not
//               involved at all: no password, no ticket, no consent. That is how a
//               service which authenticated somebody by other means gets a Kerberos
//               identity for them. It is not a privilege — the ticket is to yourself.
//   S4U2Proxy — the service then reaches ANOTHER service as that user, presenting the
//               first ticket as evidence. THIS is the privilege, and what stands between
//               the two is one attribute on one account.
//
// The attribute can be either of two, on OPPOSITE accounts, and the difference is the
// whole security story:
//
//   * classic  — msDS-AllowedToDelegateTo on the FRONT-END, listing what it may reach.
//                Only a domain admin can set it.
//   * RBCD     — msDS-AllowedToActOnBehalfOfOtherIdentity on the BACK-END, listing who
//                may act on its behalf. Whoever controls that object can set it, which
//                turns "I can write to this computer account" into "I can reach this
//                service as anybody".
//
// Both are exercised, because they are the same messages with opposite trust. So are the
// asymmetries that make RBCD the easier path: classic needs FORWARDABLE evidence (and so
// needs TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION on the front end), RBCD needs neither —
// but RBCD does need PA-PAC-OPTIONS, without which [MS-SFU] requires KDC_ERR_BADOPTION.
async function delegationWorksBothWaysAndIsRefusedOtherwise() {
  log.debug("Entering delegationWorksBothWaysAndIsRefusedOtherwise().");
  const FRONTEND = ["HTTP", "frontend.example.com"];
  const BACKEND = ["HTTP", "backend.example.com"];
  const RBCD_TARGET = ["HTTP", "rbcd.example.com"];
  const alice = { type: msgs.NAME_TYPE.PRINCIPAL, name: ["alice"] };

  // The front-end service authenticates as ITSELF. A service account gets a TGT
  // the same way a user does — which is the starting point people find
  // surprising.
  const frontendTgt = await getTgt("HTTP/frontend.example.com", 
      "frontend-service-password",
    null, REALM, prim.utf8(REALM + "HTTPfrontend"));

  // --- S4U2Self: a ticket to itself, as alice, with alice nowhere in sight.
  const selfReq = await client.buildS4u2SelfReq({
    tgt: frontendTgt,
    user: alice,
    sname: { type: msgs.NAME_TYPE.SRV_HST, name: FRONTEND }
  });
  const evidence = await client.readTgsRep({
    tgt: frontendTgt,
    reply: await sendFramed(kdcPort, selfReq.request),
    nonce: selfReq.nonce,
    subkey: null,
    requestedSname: selfReq.sname
  });
  assert.ok(evidence.ok, "S4U2Self failed: " +
    (evidence.error ? evidence.error.error.name + " — " + 
        evidence.error.eText : "unknown"));
  assert.strictEqual(evidence.client.name.join("/"), "alice",
    "the ticket must be issued for ALICE even though alice was never " +
        "involved — no password, no " +
    "ticket of hers, nothing she consented to. That is what S4U2Self is: " +
    evidence.client.name.join("/"));
  assert.deepStrictEqual(evidence.service.name, FRONTEND,
    "and it must be a ticket to the requesting service ITSELF");
  assert.ok(evidence.flagNames.indexOf("forwardable") !== -1,
    "it must be FORWARDABLE, because this account has " +
        "TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION — " +
    "without that flag the ticket still comes back and simply cannot be used " +
        "as evidence, which " +
    "fails two steps later looking like something else entirely: " + 
        evidence.flagNames.join(", "));

  // The PAC inside describes ALICE, which is what makes the delegated ticket
  // useful — and it is the KDC that supplied her groups, not the service asking
  // on her behalf.
  const feKey = await kcrypto.etypeById(evidence.etype)
    .stringToKey("frontend-service-password", prim.utf8(REALM + 
        "HTTPfrontend"), null);
  const evPart = msgs.readEncTicketPart(await kcrypto.etypeById(evidence.etype)
    .decrypt(feKey, kcrypto.KEY_USAGE.KDC_REP_TICKET, 
        evidence.ticket.encPart.cipher));
  const evPac = kpac.parsePac(kpac.findPacs(evPart.authorizationData || 
      [])[0].bytes);
  const evInfo = kpac.bufferOfType(evPac, kpac.TYPE.LOGON_INFO).parsed;
  assert.strictEqual(evInfo.effectiveName, "alice");
  assert.strictEqual(evInfo.userSid, DOMAIN_SID + "-1104",
    "with alice's real SID and groups, supplied by the KDC: " + evInfo.userSid);
  assert.ok(evInfo.groups.some(function (g) { return g.relativeId === 512; }),
    "including Domain Admins — a service performing S4U2Self for a " +
        "privileged user gets a ticket " +
    "carrying that user's privileges, which is why the next step is the one " +
        "that is gated");

  // --- S4U2Proxy, classic: authorized by msDS-AllowedToDelegateTo on the FRONT
  // end.
  const proxyReq = await client.buildS4u2ProxyReq({
    tgt: frontendTgt,
    evidenceTicket: evidence.ticket,
    sname: { type: msgs.NAME_TYPE.SRV_HST, name: BACKEND }
  });
  const delegated = await client.readTgsRep({
    tgt: frontendTgt,
    reply: await sendFramed(kdcPort, proxyReq.request),
    nonce: proxyReq.nonce,
    subkey: null,
    requestedSname: proxyReq.sname
  });
  assert.ok(delegated.ok, "classic S4U2Proxy failed: " +
    (delegated.error ? delegated.error.error.name + " — " + 
        delegated.error.eText : "unknown"));
  assert.strictEqual(delegated.client.name.join("/"), "alice",
    "the delegated ticket is for ALICE, and the service that asked for it " +
        "appears nowhere in it");
  assert.deepStrictEqual(delegated.service.name, BACKEND);

  // The audit trail. It is the only record in the ticket that delegation
  // happened at all.
  const beKey = await kcrypto.etypeById(delegated.etype)
    .stringToKey("backend-service-password", prim.utf8(REALM + "HTTPbackend"), 
        null);
  const dPart = msgs.readEncTicketPart(await kcrypto.etypeById(delegated.etype)
    .decrypt(beKey, kcrypto.KEY_USAGE.KDC_REP_TICKET, 
        delegated.ticket.encPart.cipher));
  const dPac = kpac.parsePac(kpac.findPacs(dPart.authorizationData || 
      [])[0].bytes);
  const dInfo = kpac.bufferOfType(dPac, kpac.TYPE.LOGON_INFO).parsed;
  assert.strictEqual(dInfo.effectiveName, "alice",
    "the back-end sees alice's own PAC, carried over from the evidence " +
        "ticket rather than " +
    "rebuilt — a KDC must not invent authorization data for an account " +
        "because a service asked");
  const delegInfo = kpac.bufferOfType(dPac, kpac.TYPE.DELEGATION_INFO);
  assert.ok(delegInfo && delegInfo.parsed,
    "the delegated ticket must carry S4U_DELEGATION_INFO. Without it nothing " +
        "in the ticket says " +
    "this was a delegation rather than alice authenticating directly. " +
        "Buffers present: " +
    dPac.buffers.map(function (b) { return b.type; }).join(", "));
  assert.strictEqual(delegInfo.parsed.s4u2proxyTarget, 
      "HTTP/backend.example.com",
    "naming the target: " + delegInfo.parsed.s4u2proxyTarget);
  assert.deepStrictEqual(delegInfo.parsed.transitedServices, 
      ["HTTP/frontend.example.com"],
    "and every service delegated through: " +
    JSON.stringify(delegInfo.parsed.transitedServices));

  // The PAC is re-signed for the back end, so that service can verify it alone.
  const dSigs = await kpac.verifySignatures(dPac, {
    serverKey: {
      etype: delegated.etype,
      key: beKey,
      label: "the back end's key"
    },
    kdcKey: {
      etype: delegated.etype,
      key: await kcrypto.etypeById(delegated.etype)
        .stringToKey(KRBTGT_PASSWORD, prim.utf8(REALM + "krbtgt"), null),
      label: "the krbtgt key"
    },
    ticketBytes: msgs.encEncTicketPart(Object.assign({}, dPart, {
      authorizationData: kpac.wrapPacAsAuthorizationData(new Uint8Array([0]))
    }))
  });
  dSigs.forEach(function (s) {
    assert.strictEqual(s.verified, true,
      "the delegated PAC must verify for the back end — its " + s.name + 
          " does not: " + s.note);
  });

  // --- S4U2Proxy, RBCD: authorized by the TARGET instead, and needing the
  // padata.
  const withoutPadata = await client.buildS4u2ProxyReq({
    tgt: frontendTgt,
    evidenceTicket: evidence.ticket,
    sname: { type: msgs.NAME_TYPE.SRV_HST, name: RBCD_TARGET },
    resourceBased: false
  });
  const refusedForPadata = await client.readTgsRep({
    tgt: frontendTgt,
    reply: await sendFramed(kdcPort, withoutPadata.request),
    nonce: withoutPadata.nonce,
    subkey: null,
    requestedSname: withoutPadata.sname
  });
  assert.ok(!refusedForPadata.ok,
    "RBCD without PA-PAC-OPTIONS must be REFUSED — [MS-SFU] requires " +
        "KDC_ERR_BADOPTION, and a " +
    "KDC that allowed it anyway would make the padata look optional");
  assert.strictEqual(refusedForPadata.error.errorCode, 13,
    "and the code is KDC_ERR_BADOPTION, got " + 
        refusedForPadata.error.error.name);
  assert.ok(/resource-based bit/.test(refusedForPadata.error.eText || ""),
    "with a message that names what is missing, since the error code alone " +
        "says nothing about " +
    "padata: " + refusedForPadata.error.eText);

  const rbcdReq = await client.buildS4u2ProxyReq({
    tgt: frontendTgt,
    evidenceTicket: evidence.ticket,
    sname: { type: msgs.NAME_TYPE.SRV_HST, name: RBCD_TARGET },
    resourceBased: true
  });
  const rbcd = await client.readTgsRep({
    tgt: frontendTgt,
    reply: await sendFramed(kdcPort, rbcdReq.request),
    nonce: rbcdReq.nonce,
    subkey: null,
    requestedSname: rbcdReq.sname
  });
  assert.ok(rbcd.ok, "resource-based S4U2Proxy failed: " +
    (rbcd.error ? rbcd.error.error.name + " — " + rbcd.error.eText : 
        "unknown"));
  assert.strictEqual(rbcd.client.name.join("/"), "alice",
    "RBCD reaches the target as alice just as classic delegation does — the " +
        "difference is only " +
    "in WHICH account granted the permission, which is exactly why it is so " +
        "easily overlooked");

  // --- The refusals. Without these, the successes above prove nothing.
  const notAllowed = await client.buildS4u2ProxyReq({
    tgt: frontendTgt,
    evidenceTicket: evidence.ticket,
    // A service nobody authorized this front end to reach.
    sname: { type: msgs.NAME_TYPE.SRV_HST, name: SERVICE }
  });
  const refused = await client.readTgsRep({
    tgt: frontendTgt,
    reply: await sendFramed(kdcPort, notAllowed.request),
    nonce: notAllowed.nonce,
    subkey: null,
    requestedSname: notAllowed.sname
  });
  assert.ok(!refused.ok,
    "delegating to a service NOTHING authorized must be refused. If it " +
        "succeeds, constrained " +
    "delegation is not constrained and every assertion above is meaningless.");
  assert.strictEqual(refused.error.errorCode, 13, "got " + 
      refused.error.error.name);
  assert.ok(/msDS-AllowedToDelegateTo/.test(refused.error.eText || "") &&
            
                
                    
                        
                            
                                
                                    /msDS-AllowedToActOnBehalfOfOtherIdentity/.test(refused.error.eText || 
                ""),
    "and the refusal should name BOTH attributes that could have permitted " +
        "it, because which one " +
    "is missing is the thing the reader needs: " + refused.error.eText);

  // Evidence addressed to somebody else: a service may only delegate with a
  // ticket that was issued TO it. Otherwise any service ticket would be a
  // delegation credential. A ticket alice legitimately holds for a DIFFERENT
  // service. ONE TGT throughout: two calls to getTgt() would produce two TGTs
  // with different session keys, and the request would then be built with one
  // and read with the other — which fails as an integrity error and looks like
  // a KDC problem.
  const aliceTgt = await getTgt("alice", "hunter2");
  const aliceRequest = await client.buildTgsReq({
    tgt: aliceTgt, sname: {
      type: msgs.NAME_TYPE.SRV_HST,
      name: SERVICE
    }, subkey: null });
  const aliceTicket = await client.readTgsRep({
    tgt: aliceTgt,
    reply: await sendFramed(kdcPort, aliceRequest.request),
    nonce: aliceRequest.nonce,
    subkey: null
  });
  assert.ok(aliceTicket.ok, "alice should be able to get her own service " +
      "ticket");
  const someoneElsesEvidence = await client.buildS4u2ProxyReq({
    tgt: frontendTgt,
    evidenceTicket: aliceTicket.ticket,
    sname: { type: msgs.NAME_TYPE.SRV_HST, name: BACKEND }
  });
  const wrongEvidence = await client.readTgsRep({
    tgt: frontendTgt,
    reply: await sendFramed(kdcPort, someoneElsesEvidence.request),
    nonce: someoneElsesEvidence.nonce,
    subkey: null,
    requestedSname: someoneElsesEvidence.sname
  });
  assert.ok(!wrongEvidence.ok,
    "evidence addressed to ANOTHER service must be refused — a service may " +
        "only delegate with a " +
    "ticket issued to itself, or every service ticket anyone holds becomes a " +
        "delegation credential");
  assert.ok(/addressed to itself/.test(wrongEvidence.error.eText || ""),
    "and the reason should say so: " + wrongEvidence.error.eText);

  // A forged PA-FOR-USER checksum: the padata is integrity-protected with the
  // TGT session key, so a service cannot name a user by editing the bytes.
  const forged = await client.buildS4u2SelfReq({
    tgt: frontendTgt, user: alice, sname: {
      type: msgs.NAME_TYPE.SRV_HST,
      name: FRONTEND
    }
  });
  const tampered = Buffer.from(forged.request);
  // Flip a byte inside the PA-FOR-USER checksum. Its position is found rather
  // than assumed: a fixed offset would silently start hitting a different
  // field.
  const marker = Buffer.from(msgs.encPaForUser({
    userName: alice,
    userRealm: REALM,
    cksum: await client.forUserChecksum(frontendTgt.sessionKey, alice, REALM, 
        "Kerberos"),
    authPackage: "Kerberos"
  }));
  const at = tampered.indexOf(marker);
  assert.ok(at >= 0, "the PA-FOR-USER padata should be locatable in the " +
      "request to tamper with it");
  tampered[at + marker.length - 1] ^= 0xff;
  const forgedReply = await client.readTgsRep({
    tgt: frontendTgt,
    reply: await sendFramed(kdcPort, tampered),
    nonce: forged.nonce,
    subkey: null,
    requestedSname: forged.sname
  });
  assert.ok(!forgedReply.ok,
    "a PA-FOR-USER whose checksum does not verify must be refused: that " +
        "checksum is what stops a " +
    "service naming a user by editing bytes");
  assert.ok(/checksum does not verify/.test(forgedReply.error.eText || ""),
    "and should say which check failed: " + forgedReply.error.eText);

  log.info("S4U2Self produced a forwardable evidence ticket for alice; " +
      "classic S4U2Proxy reached " +
    "the back end with S4U_DELEGATION_INFO recording the hop; RBCD reached " +
        "its target once " +
    "PA-PAC-OPTIONS was sent; and five refusals held");
  log.debug("Leaving delegationWorksBothWaysAndIsRefusedOtherwise().");
}


// The flag that is invisible where it is set:
// TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION.
//
// `notrusted` has the same msDS-AllowedToDelegateTo as `frontend` and lacks
// only that one attribute. The consequence is a two-step failure that points at
// the wrong thing: S4U2Self SUCCEEDS and hands back a ticket that is merely not
// forwardable, and classic S4U2Proxy then refuses it — complaining about the
// evidence ticket, which is not where the misconfiguration is. Two accounts
// differing in exactly one attribute is what makes that attributable.
//
// It also covers the sname rule: S4U2Self is a request for a ticket to
// YOURSELF, and a service asking for one to a different service is not S4U2Self
// at all.
async function protocolTransitionNeedsItsOwnFlag() {
  log.debug("Entering protocolTransitionNeedsItsOwnFlag().");
  const NOTRUSTED = ["HTTP", "notrusted.example.com"];
  const BACKEND = ["HTTP", "backend.example.com"];
  const alice = { type: msgs.NAME_TYPE.PRINCIPAL, name: ["alice"] };

  const tgt = await getTgt("HTTP/notrusted.example.com", 
      "notrusted-service-password",
    null, REALM, prim.utf8(REALM + "HTTPnotrusted"));

  // S4U2Self still works. That is the trap.
  const selfReq = await client.buildS4u2SelfReq({
    tgt: tgt, user: alice, sname: {
      type: msgs.NAME_TYPE.SRV_HST,
      name: NOTRUSTED
    } });
  const evidence = await client.readTgsRep({
    tgt: tgt,
    reply: await sendFramed(kdcPort, selfReq.request),
    nonce: selfReq.nonce,
    subkey: null,
    requestedSname: selfReq.sname
  });
  assert.ok(evidence.ok,
    "S4U2Self must still SUCCEED without the flag — that is precisely why " +
        "its absence is hard to " +
    "attribute: " + (evidence.error ? evidence.error.error.name : ""));
  assert.strictEqual(evidence.client.name.join("/"), "alice");
  assert.ok(evidence.flagNames.indexOf("forwardable") === -1,
    "but the ticket must NOT be forwardable, because this account lacks " +
    "TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION: " + evidence.flagNames.join(", "));

  // And the failure lands one step later, on the evidence rather than on the
  // flag.
  const proxyReq = await client.buildS4u2ProxyReq({
    tgt: tgt,
    evidenceTicket: evidence.ticket,
    sname: { type: msgs.NAME_TYPE.SRV_HST, name: BACKEND }
  });
  const refused = await client.readTgsRep({
    tgt: tgt,
    reply: await sendFramed(kdcPort, proxyReq.request),
    nonce: proxyReq.nonce,
    subkey: null,
    requestedSname: proxyReq.sname
  });
  assert.ok(!refused.ok,
    "classic S4U2Proxy requires FORWARDABLE evidence, so this must be " +
        "refused even though " +
    "msDS-AllowedToDelegateTo does permit the pair");
  assert.strictEqual(refused.error.errorCode, 13, "got " + 
      refused.error.error.name);
  assert.ok(/TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION/.test(refused.error.eText || 
      ""),
    "and the message must name the flag that is actually missing, because " +
        "the visible symptom is " +
    "about the evidence ticket: " + refused.error.eText);
  assert.ok(/resource-based delegation would not have needed either/.test(refused.error.eText || 
      ""),
    "and should note that RBCD needs neither, which is why RBCD is the " +
        "easier path: " +
    refused.error.eText);

  // S4U2Self naming somebody else's service is not S4U2Self.
  const wrongSname = await client.buildS4u2SelfReq({
    tgt: tgt, user: alice, sname: {
      type: msgs.NAME_TYPE.SRV_HST,
      name: BACKEND
    } });
  const refusedSname = await client.readTgsRep({
    tgt: tgt,
    reply: await sendFramed(kdcPort, wrongSname.request),
    nonce: wrongSname.nonce,
    subkey: null,
    requestedSname: wrongSname.sname
  });
  assert.ok(!refusedSname.ok,
    "S4U2Self asks for a ticket to YOURSELF. Naming another service must be " +
        "refused — otherwise " +
    "PA-FOR-USER alone would obtain a ticket to anything as anybody, with no " +
        "delegation " +
    "authorization involved at all.");
  assert.ok(/ticket to YOURSELF/.test(refusedSname.error.eText || ""),
    "and the reason should say so: " + refusedSname.error.eText);

  log.info("without TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION, S4U2Self " +
      "succeeded but returned a " +
    "non-forwardable ticket and classic S4U2Proxy refused it, naming the " +
        "missing flag");
  log.debug("Leaving protocolTransitionNeedsItsOwnFlag().");
}


// Renewals. A renewable ticket is not an immortal one, and the rules that make
// that true are the interesting part.
//
// The one worth asserting hardest is that **authtime is preserved**. A renewed
// ticket must not look freshly authenticated — a service that reads authtime to
// decide how recently the user proved themselves would otherwise be told a lie
// that grows with each renewal. And renew-till does not move, so a ticket
// renewed repeatedly still dies on schedule.
async function renewalsExtendWithoutReauthenticating(tgt) {
  log.debug("Entering renewalsExtendWithoutReauthenticating().");
  assert.ok(tgt.renewTill,
    "this test needs a renewable TGT — getTgt asks for RENEWABLE, so a " +
        "missing renew-till means " +
    "the KDC did not grant it");

  // Assert the inputs before asserting the outputs. `tgt.authtime` being absent
  // would make the authtime comparison below compare a value with itself —
  // which it did, and three mutations walked straight through it.
  assert.ok(tgt.authtime instanceof Date,
    "this test needs the TGT's authtime to compare against; got " + 
        tgt.authtime);

  // A DELIBERATE one-second wait, and the only sleep in this file. It is not a
  // bet on something finishing — the suite's rule against sleeps is about
  // waiting for events — it forces a CLOCK BOUNDARY. KerberosTime has
  // one-second resolution and this whole test runs inside a single second, so a
  // KDC that reset authtime to "now" on renewal would produce a value identical
  // to the original and the assertion below could not tell. That is not
  // hypothetical: the mutation went undetected until this wait existed.
  await new Promise(function (resolve) { setTimeout(resolve, 1100); });

  const renewReq = await client.buildRenewReq({
    tgt: tgt,
    sname: { type: msgs.NAME_TYPE.SRV_INST, name: ["krbtgt", REALM] },
    // Ask for FAR longer than renew-till, not merely longer than the endtime.
    // Asking for less than renew-till cannot detect a KDC that fails to cap at
    // all, because the request itself is then the lower bound — and an uncapped
    // renewal is a ticket that never expires.
    till: new Date(tgt.renewTill.getTime() + 30 * 24 * 3600 * 1000)
  });
  const renewed = await client.readTgsRep({
    tgt: tgt,
    reply: await sendFramed(kdcPort, renewReq.request),
    nonce: renewReq.nonce,
    subkey: null,
    requestedSname: renewReq.sname
  });
  assert.ok(renewed.ok, "the renewal failed: " +
    (renewed.error ? renewed.error.error.name + " — " + renewed.error.eText : 
        "unknown"));

  assert.strictEqual(renewed.authtime.getTime(), tgt.authtime.getTime(),
    "a renewal must PRESERVE authtime — the user did not authenticate again, " +
        "and a service that " +
    "reads authtime to judge freshness would be deceived by a KDC that moved " +
        "it. Got " +
    renewed.authtime.toISOString() + ", expected " + 
        tgt.authtime.toISOString());
  assert.ok(renewed.endtime > tgt.endtime,
    "and it must actually extend the ticket: " + 
        renewed.endtime.toISOString() + " vs " +
    tgt.endtime.toISOString());
  assert.strictEqual(renewed.endtime.getTime(), tgt.renewTill.getTime(),
    "and it must be capped exactly AT renew-till, since that is what was " +
        "asked to be exceeded. " +
    "renew-till does not move; an uncapped renewal is a ticket that never " +
        "expires. Got " +
    renewed.endtime.toISOString() + ", renew-till " + 
        tgt.renewTill.toISOString());
  assert.strictEqual(renewed.renewTill.getTime(), tgt.renewTill.getTime(),
    "and renew-till itself must be unchanged by the renewal");

  // The reply and the TICKET have to agree. They are built from separate
  // fields, so a KDC can extend renew-till inside the ticket while reporting
  // the original in the reply — and the ticket is the half that gets presented.
  // Only the krbtgt key can see in, which is why this is checked here rather
  // than by the client.
  const renewKrbtgtKey = await kcrypto.etypeById(renewed.etype)
    .stringToKey(KRBTGT_PASSWORD, prim.utf8(REALM + "krbtgt"), null);
  const renewedPart = msgs.readEncTicketPart(await kcrypto.etypeById(renewed.etype)
    .decrypt(renewKrbtgtKey, kcrypto.KEY_USAGE.KDC_REP_TICKET, 
        renewed.ticket.encPart.cipher));
  assert.strictEqual(renewedPart.renewTill.getTime(), tgt.renewTill.getTime(),
    "renew-till INSIDE the renewed ticket must be unchanged too — a ticket " +
        "whose renew-till " +
    "creeps forward on every renewal never expires, and the reply would not " +
        "show it: " +
    renewedPart.renewTill.toISOString() + " vs " + tgt.renewTill.toISOString());
  assert.strictEqual(renewedPart.authtime.getTime(), tgt.authtime.getTime(),
    "and so must authtime inside the ticket, which is the copy a service " +
        "actually reads");
  assert.strictEqual(renewedPart.endtime.getTime(), renewed.endtime.getTime(),
    "the ticket's endtime and the reply's must agree, or the client and the " +
        "service disagree " +
    "about when it dies");
  assert.ok(renewed.flagNames.indexOf("initial") === -1,
    "a renewed ticket is not an initial one: " + renewed.flagNames.join(", "));

  // A renewal naming a different service is not a renewal.
  const wrongService = await client.buildRenewReq({
    tgt: tgt,
    sname: { type: msgs.NAME_TYPE.SRV_HST, name: SERVICE }
  });
  const refused = await client.readTgsRep({
    tgt: tgt,
    reply: await sendFramed(kdcPort, wrongService.request),
    nonce: wrongService.nonce,
    subkey: null,
    requestedSname: wrongService.sname
  });
  assert.ok(!refused.ok,
    "RENEW with a different sname must be refused — otherwise the option " +
        "would be a way to turn " +
    "a TGT into a service ticket while keeping the TGT's lifetime");
  assert.ok(/SAME service/.test(refused.error.eText || ""),
    "and should say so: " + refused.error.eText);

  // A ticket that is not renewable cannot be renewed, and the reason is that
  // renewability is requested when the ticket is first obtained.
  const notRenewable = await getTgt("bob", "correct horse battery staple", 
      null, REALM, null,
    [msgs.KDC_OPTION.FORWARDABLE]);
  assert.ok(!notRenewable.renewTill,
    "this part of the test needs a TGT obtained WITHOUT the RENEWABLE " +
        "option; it has renew-till " +
    notRenewable.renewTill + ", so the option list did not reach the KDC and " +
        "the assertion below " +
    "would pass for the wrong reason");
  const cannot = await client.buildRenewReq({
    tgt: notRenewable, sname: {
      type: msgs.NAME_TYPE.SRV_INST,
      name: ["krbtgt", REALM]
    } });
  const refusedNotRenewable = await client.readTgsRep({
    tgt: notRenewable,
    reply: await sendFramed(kdcPort, cannot.request),
    nonce: cannot.nonce,
    subkey: null,
    requestedSname: cannot.sname
  });
  assert.ok(!refusedNotRenewable.ok, "a non-renewable ticket must not be " +
      "renewable");
  assert.ok(/cannot be added afterwards/.test(refusedNotRenewable.error.eText || 
      ""),
    "and the message should say renewability is asked for when the ticket is " +
        "FIRST obtained: " +
    refusedNotRenewable.error.eText);

  // A ticket whose renew-till has already PASSED. The KDC only ever issues
  // renew-till a week out, so this one is minted here with the krbtgt key —
  // which the test holds anyway to read inside tickets. Forging it is the only
  // way to reach the check without either waiting a week or reconfiguring the
  // KDC's lifetime for every other assertion above.
  const expiredRenewTill = new Date(Date.now() - 3600 * 1000);
  const forgedSessionKey = kcrypto.randomBytes(kcrypto.etypeById(18).keyBytes);
  const staleTgt = {
    // The ticket as an OBJECT, not encoded bytes: everywhere else in this file
    // `tgt.ticket` is the parsed structure straight off a reply, and
    // buildTgsReq re-encodes it.
    ticket: {
      realm: REALM,
      sname: { type: msgs.NAME_TYPE.SRV_INST, name: ["krbtgt", REALM] },
      encPart: {
        etype: 18,
        cipher: await kcrypto.etypeById(18).encrypt(renewKrbtgtKey,
          kcrypto.KEY_USAGE.KDC_REP_TICKET, msgs.encEncTicketPart({
            // Flagged renewable, so the refusal below must come from renew-till
            // and not from the flag check — otherwise it would pass for the
            // wrong reason.
            flags: [msgs.TICKET_FLAG.RENEWABLE, msgs.TICKET_FLAG.FORWARDABLE],
            key: { etype: 18, key: forgedSessionKey },
            crealm: REALM, cname: {
              type: msgs.NAME_TYPE.PRINCIPAL,
              name: ["alice"]
            },
            authtime: new Date(Date.now() - 7200 * 1000),
            starttime: new Date(Date.now() - 7200 * 1000),
            endtime: new Date(Date.now() + 3600 * 1000),
            renewTill: expiredRenewTill
          }))
      }
    },
    sessionKey: forgedSessionKey,
    etype: 18,
    client: { type: msgs.NAME_TYPE.PRINCIPAL, name: ["alice"] },
    realm: REALM
  };
  const staleReq = await client.buildRenewReq({
    tgt: staleTgt, sname: {
      type: msgs.NAME_TYPE.SRV_INST,
      name: ["krbtgt", REALM]
    } });
  const staleRefused = await client.readTgsRep({
    tgt: staleTgt,
    reply: await sendFramed(kdcPort, staleReq.request),
    nonce: staleReq.nonce,
    subkey: null,
    requestedSname: staleReq.sname
  });
  assert.ok(!staleRefused.ok,
    "a ticket whose renew-till has passed must not be renewable — that " +
        "instant is the hard limit " +
    "on a renewable ticket's life, and without the check it would never " +
        "expire at all");
  assert.ok(/renew-till passed/.test(staleRefused.error.eText || ""),
    "and the refusal must name renew-till rather than the ticket's endtime, " +
        "which is still in the " +
    "future here: " + staleRefused.error.eText);

  log.info("a renewal extended the ticket to " + 
      renewed.endtime.toISOString() + " with authtime " +
    "unchanged and renew-till respected; three refusals held, including a " +
        "ticket whose " +
    "renew-till had already passed");
  log.debug("Leaving renewalsExtendWithoutReauthenticating().");
}


// Unconstrained delegation, end to end: a forwarded TGT inside a KRB-CRED.
//
// This is the oldest form and by far the most dangerous, and the test exists to
// make the difference from S4U2Proxy concrete. There, every hop returns to the
// KDC and is checked against an attribute. Here the client hands over a
// ticket-granting ticket and the service can obtain tickets to ANYTHING as that
// client until it expires, with the KDC never consulted again. There is no list
// of permitted targets because there is no constraint.
//
// So the assertions are: the chain works (otherwise the capability is not
// demonstrated), the KRB-CRED can only be opened by the service it was sealed
// for, the forwarded ticket is FLAGGED as forwarded so a service can tell, and
// — the part that matters — an account flagged NOT_DELEGATED cannot be caught
// up in it at all.
async function forwardedCredentialsAreUnconstrained() {
  log.debug("Entering forwardedCredentialsAreUnconstrained().");
  const alice = await getTgt("alice", "hunter2");
  assert.ok(alice.flagNames.indexOf("forwardable") !== -1,
    "alice's TGT must be forwardable for any of this to be possible: " + 
        alice.flagNames.join(", "));

  // 1. Ask the KDC for a TGT flagged `forwarded`, to give away.
  const fwdReq = await client.buildForwardedTgtReq({ tgt: alice });
  const forwarded = await client.readTgsRep({
    tgt: alice,
    reply: await sendFramed(kdcPort, fwdReq.request),
    nonce: fwdReq.nonce,
    subkey: null,
    requestedSname: fwdReq.sname
  });
  assert.ok(forwarded.ok, "the KDC should issue a forwarded TGT: " +
    (forwarded.error ? forwarded.error.error.name + " — " + 
        forwarded.error.eText : "unknown"));
  assert.deepStrictEqual(forwarded.service.name, ["krbtgt", REALM],
    "what comes back is another TICKET-GRANTING ticket — a service ticket " +
        "would reach one " +
    "service, and the point of this is to reach all of them");
  assert.ok(forwarded.flagNames.indexOf("forwarded") !== -1,
    "and it must be FLAGGED forwarded, which is the only record a receiving " +
        "service has that " +
    "these credentials were handed over rather than presented by their " +
        "owner: " +
    forwarded.flagNames.join(", "));
  assert.ok(forwarded.flagNames.indexOf("forwardable") !== -1,
    "and still forwardable, or a second hop could not forward it onward");

  // 2. Wrap it for ONE service, with that AP exchange's key.
  const subkey = { etype: forwarded.etype,
                   key: kcrypto.randomBytes(kcrypto.etypeById(forwarded.etype).keyBytes) };
  const credential = await client.wrapDelegatedCredential({
    forwarded: forwarded,
    key: subkey
  });

  // 3. The service opens it and can now act as alice.
  const received = await client.readDelegatedCredential({
    bytes: credential,
    key: subkey
  });
  assert.strictEqual(received.client.name.join("/"), "alice",
    "the receiving service now holds alice's own ticket-granting ticket");
  assert.strictEqual(prim.toHex(received.sessionKey), 
      prim.toHex(forwarded.sessionKey),
    "with its session key, without which the ticket would be opaque and " +
        "useless");
  assert.ok(received.flagNames.indexOf("forwarded") !== -1,
    "and the flags travel with it: " + received.flagNames.join(", "));

  // And the capability itself: use it to get a service ticket as alice. This is
  // what "unconstrained" means, and asserting it is the only honest way to show
  // the difference from S4U2Proxy — no attribute anywhere permitted this
  // particular target.
  const asAlice = await client.buildTgsReq({
    tgt: received, sname: {
      type: msgs.NAME_TYPE.SRV_HST,
      name: SERVICE
    }, subkey: null });
  const stolen = await client.readTgsRep({
    tgt: received,
    reply: await sendFramed(kdcPort, asAlice.request),
    nonce: asAlice.nonce,
    subkey: null,
    requestedSname: asAlice.sname
  });
  assert.ok(stolen.ok,
    "the service can now obtain a ticket to an arbitrary target as alice, " +
        "with nothing in the " +
    "KDC authorizing that particular pair — which is precisely what " +
        "unconstrained delegation is " +
    "and why ok-as-delegate is only ADVICE to the client: " +
    (stolen.error ? stolen.error.error.name : ""));
  assert.strictEqual(stolen.client.name.join("/"), "alice");

  // A different key must not open the credential: it is sealed for one service.
  const wrongKey = { etype: subkey.etype,
                     key: kcrypto.randomBytes(kcrypto.etypeById(subkey.etype).keyBytes) };
  await assert.rejects(
    client.readDelegatedCredential({ bytes: credential, key: wrongKey }),
    "a KRB-CRED is encrypted for the ONE service the client chose — any " +
        "other key must fail, or " +
    "forwarding to one service would forward to everybody who saw the token");

  // The protection: an account flagged NOT_DELEGATED. It is refused at the AS
  // exchange, so it never even acquires a forwardable ticket to be forwarded.
  const sensitive = await getTgt("sensitive", "do-not-delegate-me");
  assert.ok(sensitive.flagNames.indexOf("forwardable") === -1,
    "a sensitive account's TGT must NOT be forwardable even though " +
        "FORWARDABLE was requested — " +
    "that refusal at the AS exchange is what protects it from every service " +
        "at once, rather than " +
    "relying on each service behaving: " + sensitive.flagNames.join(", "));
  const cannotForward = await client.buildForwardedTgtReq({ tgt: sensitive });
  const refused = await client.readTgsRep({
    tgt: sensitive,
    reply: await sendFramed(kdcPort, cannotForward.request),
    nonce: cannotForward.nonce,
    subkey: null,
    requestedSname: cannotForward.sname
  });
  assert.ok(!refused.ok,
    "and forwarding it must be refused outright");
  assert.ok(/needs a FORWARDABLE ticket to forward/.test(refused.error.eText || 
      ""),
    "here the refusal comes from the ticket not being forwardable — which is " +
        "the FIRST of two " +
    "checks, and asserting which one fired is what stops them masking each " +
        "other: " +
    refused.error.eText);

  // The SECOND check, reached only with a ticket the KDC would never issue: a
  // FORWARDABLE ticket for a sensitive account. That is exactly the case its
  // comment describes — one issued before the flag was set — and it is
  // reachable only by minting it here with the krbtgt key. Without this,
  // removing either check leaves the other firing and both look covered.
  const sensitiveEtype = 18;
  const sensitiveProfile = kcrypto.etypeById(sensitiveEtype);
  const forgedKrbtgtKey = await sensitiveProfile.stringToKey(KRBTGT_PASSWORD,
    prim.utf8(REALM + "krbtgt"), null);
  const forgedSession = kcrypto.randomBytes(sensitiveProfile.keyBytes);
  const staleForwardable = {
    ticket: {
      realm: REALM,
      sname: { type: msgs.NAME_TYPE.SRV_INST, name: ["krbtgt", REALM] },
      encPart: {
        etype: sensitiveEtype,
        cipher: await sensitiveProfile.encrypt(forgedKrbtgtKey, 
            kcrypto.KEY_USAGE.KDC_REP_TICKET,
          msgs.encEncTicketPart({
            flags: [msgs.TICKET_FLAG.FORWARDABLE, msgs.TICKET_FLAG.INITIAL],
            key: { etype: sensitiveEtype, key: forgedSession },
            crealm: REALM, cname: {
              type: msgs.NAME_TYPE.PRINCIPAL,
              name: ["sensitive"]
            },
            authtime: new Date(Date.now() - 60000),
            endtime: new Date(Date.now() + 3600 * 1000)
          }))
      }
    },
    sessionKey: forgedSession,
    etype: sensitiveEtype,
    client: { type: msgs.NAME_TYPE.PRINCIPAL, name: ["sensitive"] },
    realm: REALM
  };
  const staleFwdReq = await client.buildForwardedTgtReq({ tgt: staleForwardable });
  const staleRefused = await client.readTgsRep({
    tgt: staleForwardable,
    reply: await sendFramed(kdcPort, staleFwdReq.request),
    nonce: staleFwdReq.nonce,
    subkey: null,
    requestedSname: staleFwdReq.sname
  });
  assert.ok(!staleRefused.ok,
    "a forwardable ticket that predates the NOT_DELEGATED flag must STILL be " +
        "refused at the TGS " +
    "exchange — otherwise setting the flag would not take effect until every " +
        "outstanding ticket " +
    "expired");
  assert.ok(/is flagged NOT_DELEGATED, so its credentials/.test(staleRefused.error.eText || 
      ""),
    "and this refusal must be the ACCOUNT check rather than the forwardable " +
        "one: " +
    staleRefused.error.eText);

  // A KRB-CRED carrying a ticket with no key for it is refused rather than
  // half-read.
  const noKey = msgs.encKrbCred({
    tickets: [forwarded.ticket],
    encPart: {
      etype: subkey.etype,
      cipher: await kcrypto.etypeById(subkey.etype).encrypt(subkey.key,
        kcrypto.KEY_USAGE.KRB_CRED_ENCPART, 
            msgs.encEncKrbCredPart({ ticketInfo: [] }))
    }
  });
  await assert.rejects(
    client.readDelegatedCredential({ bytes: noKey, key: subkey }),
    /positional/,
    "a KRB-CRED whose tickets and ticket-info do not correspond must be " +
        "refused: they are paired " +
    "by POSITION, so a mismatch means no ticket can be matched with its key");

  log.info("alice's credentials were forwarded in a KRB-CRED, opened by the " +
      "one service they were " +
    "sealed for, and used to obtain a ticket to an unrelated target as her; " +
        "the sensitive " +
    "account could not be forwarded at all");
  log.debug("Leaving forwardedCredentialsAreUnconstrained().");
}

async function theTgsExchangeRefusesWhatItShould(tgt) {
  log.debug("Entering theTgsExchangeRefusesWhatItShould().");

  async function expectError(label, request, code, textMatch) {
    log.debug("Entering expectError().");
    const response = msgs.readKdcResponse(await sendFramed(kdcPort, request));
    assert.strictEqual(response.kind, "KRB-ERROR", label + ": expected an " +
        "error, got " + response.kind);
    assert.strictEqual(response.error.errorCode, code,
      label + ": expected " + msgs.describeError(code).name + ", got " + 
          response.error.error.name +
      (response.error.eText ? " — " + response.error.eText : ""));
    if (textMatch) {
      assert.ok(textMatch.test(response.error.eText || ""),
        label + ": e-text should explain — " + 
            JSON.stringify(response.error.eText));
    }
    log.debug(label + " -> " + response.error.error.name);
    log.debug("Leaving expectError().");
    return response.error;
  }

  // No PA-TGS-REQ at all: structurally impossible to answer.
  await expectError("a TGS-REQ with no TGT in it", msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.TGS_REQ,
    reqBody: {
      kdcOptions: [],
      realm: REALM,
      sname: { type: 3, name: SERVICE },
      till: new Date(Date.now() + 3600000),
      nonce: 1,
      etypes: [18]
    }
  }), 25, /must carry the TGT/);

  // An SPN that is not registered — on AD the single commonest TGS failure.
  const forUnknown = await client.buildTgsReq({
    tgt: tgt, sname: {
      type: msgs.NAME_TYPE.SRV_HST,
      name: ["HTTP", "nosuchhost.example.com"]
    } });
  const unknown = await expectError("an unregistered SPN", forUnknown.request, 
      7, /no such service/);
  assert.ok(/SPN/.test(unknown.eText || ""),
    "the refusal should name the Active Directory cause, since that is the " +
        "diagnosis: " + unknown.eText);

  // THE CHECKSUM CASE. The body is swapped after the Authenticator was built
  // over the original, which is exactly what a re-encoding bug produces — and
  // exactly what an attacker altering a request in flight would produce.
  const honest = await client.buildTgsReq({
    tgt: tgt,
    sname: { type: msgs.NAME_TYPE.SRV_HST, name: SERVICE }
  });
  const parsed = msgs.readKdcReq(honest.request);
  const tamperedBody = msgs.encKdcReqBody({
    kdcOptions: [msgs.KDC_OPTION.FORWARDABLE],
    realm: REALM,
    // A different service — the substitution that would matter.
    sname: { type: msgs.NAME_TYPE.SRV_HST, name: ["host", "ws01.example.com"] },
    till: new Date(Date.now() + 3600000),
    nonce: honest.nonce,
    etypes: [18]
  });
  const tampered = msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.TGS_REQ,
    padata: parsed.padata,
    reqBody: { raw: tamperedBody }
  });
  const cksumError = await expectError("a request body swapped after signing", 
      tampered, 50,
    /checksum does not match/);
  assert.ok(/key usage 6/.test(cksumError.eText || ""),
    "and should name the key usage, because that is the other reason a " +
        "checksum fails: " +
    cksumError.eText);

  log.debug("Leaving theTgsExchangeRefusesWhatItShould().");
}

// ---------------------------------------------------------------------------
// The AP exchange: presenting the ticket.
// ---------------------------------------------------------------------------
async function theServiceAcceptsTheTicketAndProvesItself(serviceTicket) {
  log.debug("Entering theServiceAcceptsTheTicketAndProvesItself().");
  const built = await client.buildApReq({
    ticket: serviceTicket,
    mutual: true
  });

  // What goes to a service is a GSS token, not a bare AP-REQ.
  assert.strictEqual(built.token[0], 0x60,
    "a service is handed an InitialContextToken, which begins with 0x60 — " +
        "not a bare AP-REQ (0x6e)");
  const decoded = gss.decodeInitialContextToken(built.token);
  assert.strictEqual(decoded.mechOid, "1.2.840.113554.1.2.2", "the Kerberos " +
      "mechanism OID");
  assert.strictEqual(decoded.tokIdName, "AP_REQ", "token id 01 00");

  // The 0x8003 checksum, which is not a checksum. Its integers are
  // little-endian.
  const apReq = msgs.readApReq(decoded.inner);
  const profile = kcrypto.etypeById(serviceTicket.etype);
  const authenticator = msgs.readAuthenticator(
    await profile.decrypt(serviceTicket.sessionKey, 
        kcrypto.KEY_USAGE.AP_REQ_AUTH,
      apReq.authenticator.cipher));
  assert.strictEqual(authenticator.cksum.type, 0x8003,
    "a GSS AP-REQ's Authenticator carries checksum type 0x8003 (32771), not " +
        "a real checksum");
  const parsedChecksum = gss.parseGssChecksum(authenticator.cksum.checksum);
  assert.strictEqual(parsedChecksum.bindingsLength, 16,
    "the Lgth field is 16, LITTLE-endian — the commonest single mistake in " +
        "Kerberos");
  assert.strictEqual(parsedChecksum.hasChannelBindings, false,
    "with no channel bindings the Bnd field is sixteen ZERO bytes, not absent");
  assert.ok(parsedChecksum.flagNames.indexOf("MUTUAL") !== -1,
    "and MUTUAL must be set, since that is what tells the service to prove " +
        "itself: " +
    parsedChecksum.flagNames.join("|"));

  // Now present it.
  const reply = await sendFramed(servicePort, built.token);
  assert.ok(reply, "the service sent nothing back, but mutual authentication " +
      "was requested");
  const context = await client.readApRep({
    reply: reply,
    ticket: serviceTicket,
    sentCtime: built.ctime,
    sentCusec: built.cusec
  });
  assert.ok(context.ok, "the service refused or failed to prove itself: " +
    (context.reason || (context.error && context.error.error.name)));
  assert.strictEqual(context.mutualOk, true,
    "the AP-REP must echo the Authenticator's ctime — that echo IS the " +
        "service's proof of identity, " +
    "because only something holding the service's long-term key could have " +
        "learned the session key " +
    "to produce it");
  assert.ok(context.wrapped, "and the AP-REP comes back GSS-wrapped too");
  assert.ok(context.acceptorSubkey, "this service offers an acceptor subkey");

  log.info("the AP exchange completed: the service accepted the ticket and " +
      "proved itself back");

  // Per-message tokens, keyed from the acceptor's subkey rather than the
  // session key — using the wrong one produces a token the far end cannot
  // verify.
  const established = {
    acceptorSubkey: context.acceptorSubkey,
    subkey: built.subkey,
    sessionKey: serviceTicket.sessionKey,
    etype: serviceTicket.etype
  };
  const keying = client.perMessageKey(established);
  assert.ok(/acceptor's subkey/.test(keying.which),
    
        
            
                
                    
                        
                            "once the acceptor has offered a subkey, per-message tokens must use it: " + 
        keying.which);

  const message = prim.utf8("the quick brown fox jumps over the lazy dog");
  const mic = await gss.getMic({
    key: keying.key,
    etype: keying.etype,
    role: "initiator",
    acceptorSubkey: keying.acceptorSubkey,
    message: message,
    sequenceNumber: 42
  });
  assert.strictEqual(mic[0], 0x04, "a MIC token's id is 04 04");
  assert.strictEqual(mic[1], 0x04, "a MIC token's id is 04 04");
  const verified = await gss.verifyMic({
    key: keying.key,
    etype: keying.etype,
    token: mic,
    message: message
  });
  assert.strictEqual(verified.ok, true, "the MIC must verify");
  assert.strictEqual(verified.senderRole, "initiator",
    "and the token itself says who signed it, which is how the verifier " +
        "picks the key usage");
  assert.strictEqual(verified.sequenceNumber, 42, "the sequence number is " +
      "inside the token");

  // A tampered message must fail.
  const tamperedMessage = prim.utf8("the quick brown fox jumps over the lazy " +
      "dig");
  assert.strictEqual((await gss.verifyMic({
    key: keying.key,
    etype: keying.etype,
    token: mic,
    message: tamperedMessage
  })).ok, false,
    "a MIC must not verify over a modified message");

  // Wrap and unwrap, which is the confidentiality half.
  const sealed = await gss.wrap({
    key: keying.key,
    etype: keying.etype,
    role: "initiator",
    acceptorSubkey: keying.acceptorSubkey,
    message: message,
    sequenceNumber: 43
  });
  assert.strictEqual(sealed[0], 0x05, "a Wrap token's id is 05 04");
  assert.strictEqual(sealed[1], 0x04, "a Wrap token's id is 05 04");
  const opened = await gss.unwrap({
    key: keying.key,
    etype: keying.etype,
    token: sealed
  });
  assert.strictEqual(prim.toHex(opened.message), prim.toHex(message),
    "what was wrapped must come back out");
  assert.strictEqual(opened.sequenceNumber, 43, "and the sequence number " +
      "with it");

  log.debug("Leaving theServiceAcceptsTheTicketAndProvesItself().");
  return built;
}

async function theServiceRefusesWhatItShould(serviceTicket, tgt, firstApReq) {
  log.debug("Entering theServiceRefusesWhatItShould().");

  async function expectRefusal(label, tokenBytes, code, textMatch) {
    log.debug("Entering expectRefusal().");
    const reply = await sendFramed(servicePort, tokenBytes);
    assert.ok(reply, label + ": the service sent nothing back; a refusal " +
        "must be an error TOKEN, " +
      "not a closed socket — a client that gets silence learns nothing");
    let bytes = reply;
    if (bytes[0] === 0x60) bytes = gss.decodeInitialContextToken(bytes).inner;
    // If the service ACCEPTED what should have been refused, say that — do not
    // let readKrbError throw a tag mismatch. "expected [APPLICATION 30] but
    // found [APPLICATION 15]" is technically the truth and tells a reader
    // nothing; for the replay case in particular the sentence that matters is
    // that the service accepted a replay.
    const identified = msgs.identify(bytes);
    assert.strictEqual(identified && identified.applicationNumber, 
        msgs.APPLICATION.KRB_ERROR,
      label + ": the service ACCEPTED this and answered " +
      ((identified && identified.name) || "something unrecognised") + 
          ", where " +
      msgs.describeError(code).name + " was required.");
    const error = msgs.readKrbError(bytes);
    assert.strictEqual(error.errorCode, code,
      label + ": expected " + msgs.describeError(code).name + ", got " + 
          error.error.name +
      (error.eText ? " — " + error.eText : ""));
    if (textMatch) {
      assert.ok(textMatch.test(error.eText || ""),
        label + ": e-text should explain — " + JSON.stringify(error.eText));
    }
    log.debug(label + " -> " + error.error.name);
    log.debug("Leaving expectRefusal().");
    return error;
  }

  // THE REPLAY. The same AP-REQ a second time must be refused — this is the
  // check a mock is most tempted to skip, and the only thing between a captured
  // AP-REQ and a free impersonation.
  const replay = await expectRefusal("the same AP-REQ presented twice", 
      firstApReq.token, 34,
    /replay|seen before/);
  assert.ok(/ctime|cusec/.test(replay.eText || ""),
    "the refusal should name what identifies a replay (client, ctime, " +
        "cusec): " + replay.eText);

  // A bare AP-REQ, not GSS-wrapped. A real service rejects this, and the
  // refusal has to say so rather than failing to parse.
  const bare = await expectRefusal("a bare AP-REQ with no GSS wrapper",
    firstApReq.apReq, 60, /InitialContextToken|0x60/);
  assert.ok(/bare AP-REQ|WRAPPED/.test(bare.eText || ""),
    "and should say what was expected: " + bare.eText);

  // A ticket for a DIFFERENT service. It will not decrypt with this service's
  // key, but the more specific answer is that it was never meant for this
  // service.
  const otherTicket = await client.buildTgsReq({
    tgt: tgt, sname: {
      type: msgs.NAME_TYPE.SRV_HST,
      name: ["host", "ws01.example.com"]
    } });
  const otherResult = await client.readTgsRep({
    tgt: tgt,
    reply: await sendFramed(kdcPort, otherTicket.request),
    nonce: otherTicket.nonce,
    subkey: null
  });
  assert.ok(otherResult.ok, "the TGS exchange for the other service should " +
      "have worked");
  const wrongService = await client.buildApReq({
    ticket: otherResult,
    mutual: true
  });
  await expectRefusal("a ticket for a different service", wrongService.token, 
      35,
    /this ticket is for host\/ws01/);

  // A stale key version: the ticket names a kvno the service does not hold.
  // Built by hand, because a KDC will not issue one.
  const staleKvno = msgs.encApReq({
    apOptions: [msgs.AP_OPTION.MUTUAL_REQUIRED],
    ticket: {
      realm: REALM,
      sname: { type: msgs.NAME_TYPE.SRV_HST, name: SERVICE },
      encPart: {
        etype: serviceTicket.etype,
        kvno: 99,
        cipher: serviceTicket.ticket.encPart.cipher
      }
    },
    authenticator: {
      etype: serviceTicket.etype,
      cipher: kcrypto.randomBytes(64)
    }
  });
  const stale = await expectRefusal("a ticket naming a key version the " +
      "service does not hold",
    gss.encodeInitialContextToken(gss.TOK_ID.AP_REQ, staleKvno), 44, 
        /key version/);
  assert.ok(/keytab is out of date/.test(stale.eText || ""),
    "KRB_AP_ERR_BADKEYVER's meaning is the least guessable of any of them, " +
        "so the refusal must " +
    "spell it out: " + stale.eText);

  // A stale clock. The Authenticator carries the time, so an old one is just an
  // old value — no clock needs moving.
  const profile = kcrypto.etypeById(serviceTicket.etype);
  const staleAuth = await client.buildApReq({
    ticket: serviceTicket,
    mutual: true,
    now: new Date(Date.now() - 20 * 60 * 1000)
  });
  const skewed = await expectRefusal("an Authenticator twenty minutes old", 
      staleAuth.token, 37,
    /clock is \d+ seconds/);
  assert.ok(/tolerance/.test(skewed.eText || ""),
    "and should quote the tolerance it was measured against: " + skewed.eText);

  // A checksum that is not 0x8003. A GSS caller must send that structure, and a
  // service that accepted anything else would not be reading the flags at all.
  const wrongChecksum = msgs.encAuthenticator({
    crealm: serviceTicket.realm,
    cname: serviceTicket.client,
    cksum: {
      type: profile.checksumType,
      checksum: await profile.checksum(
      serviceTicket.sessionKey, kcrypto.KEY_USAGE.AP_REQ_AUTH_CKSUM, 
          prim.utf8("not 0x8003"))
    },
    cusec: 1, ctime: new Date(), seqNumber: 7
  });
  const wrongChecksumToken = gss.encodeInitialContextToken(gss.TOK_ID.AP_REQ, 
      msgs.encApReq({
    apOptions: [msgs.AP_OPTION.MUTUAL_REQUIRED],
    ticket: serviceTicket.ticket,
    authenticator: {
      etype: serviceTicket.etype,
      cipher: await profile.encrypt(
      serviceTicket.sessionKey, kcrypto.KEY_USAGE.AP_REQ_AUTH, wrongChecksum)
    }
  }));
  await expectRefusal("an Authenticator whose checksum is not 0x8003", 
      wrongChecksumToken, 50,
    /32771|0x8003/);

  log.debug("Leaving theServiceRefusesWhatItShould().");
}

// A client that asks for mutual authentication must CHECK the echo. A service
// answering with someone else's ctime has not proved anything, and this is the
// assertion that says the client notices.
async function aFalseEchoIsNotMutualAuthentication(serviceTicket) {
  log.debug("Entering aFalseEchoIsNotMutualAuthentication().");
  const profile = kcrypto.etypeById(serviceTicket.etype);
  const sentCtime = new Date();
  const forged = msgs.encApRep({
    encPart: {
      etype: serviceTicket.etype,
      cipher: await profile.encrypt(serviceTicket.sessionKey, 
          kcrypto.KEY_USAGE.AP_REP_ENCPART,
        // A DIFFERENT ctime — everything else correct, and correctly encrypted.
        // Five seconds off, so it differs at the SECOND precision the wire uses
        // — a sub-second difference would be invisible on the wire and is not
        // what this case is about.
        msgs.encEncApRepPart({
          ctime: new Date(sentCtime.getTime() - 5000),
          cusec: 0
        }))
    }
  });
  const result = await client.readApRep({
    reply: gss.encodeInitialContextToken(gss.TOK_ID.AP_REP, forged),
    ticket: serviceTicket,
    sentCtime: sentCtime
  });
  assert.strictEqual(result.ok, false,
    "an AP-REP echoing the WRONG ctime must be rejected. Everything else " +
        "about it is correct and it " +
    "decrypts, so a client that does not compare the echo has asked for " +
        "mutual authentication " +
    "without performing it.");
  assert.ok(/echo/.test(result.reason || ""), "and must say why: " + 
      result.reason);
  log.debug("Leaving aFalseEchoIsNotMutualAuthentication().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. AS -> TGS -> AP against the mock KDC and the " +
      "mock service.");

  const kdcPath = stsModule("krb5_kdc.js");
  const servicePath = stsModule("krb5_service.js");
  if (!kdcPath || !servicePath) {
    throw new Error("could not find the mock KDC and service " +
        "(sts/krb5_kdc.js, sts/krb5_service.js). " +
      "sts/ is a SUBMODULE — run `git submodule update --init sts`; an " +
          "uninitialised submodule is an " +
      "EMPTY DIRECTORY rather than a missing one.");
  }
  process.env.KRB5_REALM = REALM;
  process.env.KRB5_KDC_PORT = "0";
  process.env.KRB5_SERVICE_PORT = "0";
  // A missing transitive dependency surfaces as "Cannot find module
  // './bbs2023.js'" from inside the submodule, which names the file and not the
  // reason. The tests image copies the sts/ modules individually, so a new
  // require inside the submodule needs a matching COPY in tests/Dockerfile.
  try {
    kdcModule = require(kdcPath);
    serviceModule = require(servicePath);
  } catch (e) {
    if (/Cannot find module/.test(e.message)) {
      throw new Error("the mock KDC or service loaded but one of its own " +
          "dependencies did not: " +
        e.message + ". tests/Dockerfile copies the sts/ modules individually " +
            "— that set is the " +
        "transitive closure of what krb5_kdc.js and krb5_service.js require, " +
            "and it has to be " +
        "recomputed when either grows a new require.");
    }
    throw e;
  }

  const kdcListeners = kdcModule.listen(0);
  await kdcListeners.whenReady;
  kdcPort = kdcListeners.port;
  const serviceServer = serviceModule.listen(0);
  await new Promise(function (resolve) {
    if (serviceServer.listening) {
      return resolve();
    }
    serviceServer.once("listening", resolve);
  });
  servicePort = serviceServer.address().port;
  log.info("the KDC is on " + kdcPort + " and " + SERVICE.join("/") + 
      " is on " + servicePort);

  try {
    const tgt = await getTgt("alice", "hunter2");
    const serviceTicket = await theTgsExchangeIssuesAServiceTicket(tgt);
    await theKdcIssuesAVerifiablePac(tgt, serviceTicket);
    await thePacAgreesWithTheAccountsBehaviour();
    await decliningThePacYieldsATicketWithoutOne();
    await aCrossRealmReferralIsIssuedAndCanBeFollowed(tgt);
    await theTrustedRealmServesItsOwnClients();
    await delegationWorksBothWaysAndIsRefusedOtherwise();
    await protocolTransitionNeedsItsOwnFlag();
    await renewalsExtendWithoutReauthenticating(tgt);
    await forwardedCredentialsAreUnconstrained();
    await theTgsExchangeRefusesWhatItShould(tgt);
    const firstApReq = await theServiceAcceptsTheTicketAndProvesItself(serviceTicket);
    await aFalseEchoIsNotMutualAuthentication(serviceTicket);
    await theServiceRefusesWhatItShould(serviceTicket, tgt, firstApReq);
    log.info("Test completed successfully.");
  } finally {
    try {
      kdcListeners.tcp.close();
    } catch (e) {
      // Already closed. This teardown is in a finally, so it runs after a
      // failure that may itself have closed the listener; a second close is
      // expected rather than exceptional, and reporting it would bury the
      // failure that actually ended the run.
    }
    try {
      kdcListeners.udp.close();
    } catch (e) {
      // Already closed — same reason as the TCP listener above.
    }
    try {
      serviceServer.close();
    } catch (e) {
      // Already closed — same reason as the TCP listener above.
    }
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("krb5_tgs_ap")
  .description("The TGS and AP exchanges end to end, with mutual " +
      "authentication and per-message tokens.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
      "starts its own services)"))
  .parse(process.argv);

test().then(function () {
  process.exit(0);
}).catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
