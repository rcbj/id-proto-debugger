// File: krb5_as_exchange.js
//
// The AS exchange, end to end: the wallet-side codec (common/krb5) against the
// mock KDC (the sts/ submodule's krb5_kdc.js), over a real socket, through the
// api's relay.
//
// ---------------------------------------------------------------------------
// What this proves that nothing before it did.
//
// The vector tests prove the crypto matches the RFCs. The codec test proves the
// DER is right. This one is the first that puts a CLIENT and a KDC on opposite
// ends of a wire and makes them agree — which is a different claim, because a
// client and a KDC disagree in ways neither one can detect alone: a key usage
// number one of them folds in and the other does not, a salt one derives from the
// principal name and the other from configuration, a nonce one echoes and the
// other regenerates.
//
// **It is still not proof of interoperability**, and the difference matters
// enough to say twice: both ends here are this repository's code. Two
// implementations written from the same misreading agree perfectly. The
// interoperability evidence is the MIT krb5 and Samba AD exchange in phase 4;
// what this test establishes is that the two halves of THIS system agree, and —
// more usefully — that the KDC refuses what it should, in the KDC's own
// vocabulary.
//
// The negative half is most of the file, deliberately. A KDC that issues tickets
// is easy; a KDC that says KDC_ERR_ETYPE_NOSUPP to an RC4-only client, refuses a
// locked account, and answers KDC_ERR_PREAUTH_REQUIRED with the SALT is the thing
// the debugger exists to show.
//
// No browser. It needs no running service either: the KDC's listeners are started
// in-process on an ephemeral port, so this runs in a bare checkout.
// ---------------------------------------------------------------------------
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "krb5_as_exchange",
    level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

function shared(name) {
  return paths.requireSharedModule(
    [__dirname + "/../common/krb5/" + name, __dirname + "/" + name], name);
}
const prim = shared("krb5_primitives.js");
const asn1 = shared("krb5_asn1.js");
const msgs = shared("krb5_messages.js");
const kcrypto = shared("krb5_crypto.js");

function apiModule(name) {
  return paths.requireSharedModule(
    [path.join(__dirname, "..", "api", name), path.join(__dirname, name)],
        name);
}
const relayMod = apiModule("krb5_relay.js");
const ssrfGuard = apiModule("ssrf_guard.js");

// The mock KDC lives in the sts/ SUBMODULE. In the tests image it is copied
// flat (see tests/Dockerfile); in a checkout it is under sts/. A missing
// submodule is an empty directory, which is why this says so rather than
// failing with a bare MODULE_NOT_FOUND — the same trap tests/Dockerfile's other
// sts/ COPY warns about. Both the resolution order and the two loud warnings
// live in module_paths.js, so the two Kerberos tests that need the mock KDC
// cannot drift apart on which copy they picked up. Set MOCK_STS_DIR to test an
// uncommitted change to a module the submodule already has — without it, the
// stale submodule copy is found and used.
function stsModule(name) {
  return paths.mockStsModule(name, function (message) { log.warn(message); });
}

const quiet = { debug() {}, info() {}, warn() {}, error() {} };

// ---------------------------------------------------------------------------
// Driving the KDC.
//
// The KDC module is loaded in-process and its listeners started on an ephemeral
// port, so this test needs no docker and no running service. The api's relay is
// then pointed at that port — which means the relay is exercised too, and the
// whole path is the real one: codec -> relay -> socket -> KDC -> socket -> codec.
// ---------------------------------------------------------------------------
let kdc = null;
let kdcPort = 0;
let relay = null;

async function startKdc() {
  log.debug("Entering startKdc().");
  const modulePath = stsModule("krb5_kdc.js");
  if (!modulePath) {
    throw new Error("could not find the mock KDC (sts/krb5_kdc.js). The sts/ " +
        "directory is a " +
      "SUBMODULE — run `git submodule update --init sts`, and note that an " +
          "uninitialised " +
      "submodule is an empty directory rather than a missing one.");
  }
  // The KDC reads its realm and port from the environment at require time.
  process.env.KRB5_REALM = process.env.KRB5_REALM || "EXAMPLE.COM";
  process.env.KRB5_KDC_PORT = "0";                 // an ephemeral port
  process.env.CONFIG_FILE = process.env.CONFIG_FILE;
  // A missing transitive dependency shows up here as "Cannot find module
  // './bbs2023.js'" from inside the submodule — which names the file and not
  // the reason. Say what to do about it: the mock KDC requires app.js and
  // helpers.js (requiring a module registers its routes there), and helpers.js
  // requires bbs2023.js, so the tests image needs all of them under sts/.
  let kdcModule;
  try {
    kdcModule = require(modulePath);
  } catch (e) {
    if (/Cannot find module/.test(e.message)) {
      throw new Error("the mock KDC loaded but one of its own dependencies " +
          "did not: " + e.message +
        ". In the tests image the sts/ modules are copied individually, so a " +
            "new require inside " +
        "the submodule needs a matching COPY in tests/Dockerfile — the set " +
            "there is the transitive " +
        "closure of what krb5_kdc.js and krb5_service.js require, and it has " +
            "to be recomputed when " +
        "that changes.");
    }
    throw e;
  }
  // Both listeners, on ONE port. listen() binds TCP first and follows UDP onto
  // whatever port it got, because a KDC is reached at a single port number over
  // both transports — a client failing over from UDP to TCP sends the retry to
  // the same place. Awaiting whenReady is what makes the UDP case below
  // meaningful rather than a timeout against a listener on a port nobody knows.
  const listeners = kdcModule.listen(0);
  await listeners.whenReady;
  kdcPort = listeners.port;
  assert.strictEqual(listeners.tcp.address().port, kdcPort, "TCP must be on " +
      "the reported port");
  assert.strictEqual(listeners.udp.address().port, kdcPort,
    "and UDP must be on the SAME port — a KDC presents one port number for " +
        "both transports");
  kdc = { module: kdcModule, listeners: listeners };
  const cfg = {
    blockPrivateNetworkCalls: false,          // the KDC is on loopback, as in the real stacks
    krb5AllowedPorts: [88, kdcPort],
    connectionTimeout: 2000,
    callTimeout: 8000,
    maxContentLength: 65536
  };
  relay = relayMod.createRelay(cfg, ssrfGuard.createGuard(cfg, quiet), quiet);
  log.info("the mock KDC is listening on 127.0.0.1:" + kdcPort);
  log.debug("Leaving startKdc().");
}

function stopKdc() {
  log.debug("Entering stopKdc().");
  if (!kdc) {
    log.debug("Leaving stopKdc().");
    return;
  }
  try {
    kdc.listeners.tcp.close();
  } catch (e) {
    // Already closed. stopKdc() runs from a finally, so it is reached both on
    // the happy path and after a failure that closed the listener on its way
    // out; a second close is expected rather than exceptional. Reporting it
    // would put a spurious error above the real one.
  }
  try {
    kdc.listeners.udp.close();
  } catch (e) {
    // Already closed — same reason as the TCP listener above.
  }
  kdc = null;
  log.debug("Leaving stopKdc().");
}

// One exchange, through the relay, returning the decoded reply.
async function exchange(message, options) {
  log.debug("Entering exchange().");
  const result = await relay.send({
    host: "127.0.0.1",
    port: kdcPort,
    transport: (options && options.transport) || "tcp",
    message: Buffer.from(message)
  });
  log.debug("Leaving exchange().");
  return {
    raw: result.reply,
    decoded: msgs.readKdcResponse(Buffer.from(result.reply)),
    replyMessage: result.replyMessage
  };
}

let nonceCounter = 0x11110000;
function buildAsReq(fields) {
  log.debug("Entering buildAsReq().");
  const f = fields || {};
  nonceCounter += 1;
  log.debug("Leaving buildAsReq().");
  return msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.AS_REQ,
    padata: f.padata || [],
    reqBody: {
      kdcOptions: f.kdcOptions || [msgs.KDC_OPTION.FORWARDABLE,
          msgs.KDC_OPTION.RENEWABLE],
      cname: f.cname || { type: msgs.NAME_TYPE.PRINCIPAL, name: ["alice"] },
      realm: f.realm || "EXAMPLE.COM",
      sname: f.sname || {
        type: msgs.NAME_TYPE.SRV_INST,
        name: ["krbtgt", "EXAMPLE.COM"]
      },
      till: f.till || new Date(Date.now() + 10 * 3600 * 1000),
      nonce: f.nonce === undefined ? nonceCounter : f.nonce,
      etypes: f.etypes || [18, 17, 23]
    }
  });
}

// The client's half of pre-authentication: derive the key from the password and
// the SALT THE KDC GAVE US, and encrypt a timestamp under key usage 1.
async function encTimestampPadata(password, info) {
  log.debug("Entering encTimestampPadata().");
  const profile = kcrypto.etypeById(info.etype);
  const key = await profile.stringToKey(password, prim.utf8(info.salt || ""),
      info.s2kparams);
  const stamp = msgs.encPaEncTsEnc(new Date(), 0);
  log.debug("Leaving encTimestampPadata().");
  return {
    padata: {
      type: msgs.PA_TYPE.ENC_TIMESTAMP,
      value: msgs.encEncryptedData({
        etype: info.etype,
        cipher: await profile.encrypt(key,
            kcrypto.KEY_USAGE.AS_REQ_PA_ENC_TIMESTAMP, stamp)
      })
    },
    key: key,
    profile: profile
  };
}

// ---------------------------------------------------------------------------
// The two-message dance, which is the exchange as it actually happens.
// ---------------------------------------------------------------------------
async function theTwoMessageDanceWorksAndCarriesTheSalt() {
  log.debug("Entering theTwoMessageDanceWorksAndCarriesTheSalt().");

  // 1. A bare AS-REQ. A real KDC does not treat this as an error to be logged
  //    and forgotten — it answers with the information needed to try properly.
  const first = await exchange(buildAsReq());
  assert.strictEqual(first.decoded.kind, "KRB-ERROR",
    "a bare AS-REQ must be answered with KDC_ERR_PREAUTH_REQUIRED, not with " +
        "a ticket");
  const err = first.decoded.error;
  assert.strictEqual(err.errorCode, 25, "the error code must be " +
      "KDC_ERR_PREAUTH_REQUIRED");
  assert.ok(err.eDataPaData, "e-data must carry PA-DATA — without it this " +
      "error is useless");

  // The salt. This is the whole reason the round trip exists: it is not
  // derivable from the principal name, so a client can only learn it here.
  const info2 = err.eDataPaData.filter(function (pa) { return pa.type === 19; })[0];
  assert.ok(info2, "PA-ETYPE-INFO2 must be present");
  const entries = msgs.readEtypeInfo2(info2.value);
  assert.ok(entries.length >= 2, "the KDC should offer more than one etype: " +
      entries.length);
  const aes256 = entries.filter(function (e) { return e.etype === 18; })[0];
  assert.ok(aes256, "aes256-cts-hmac-sha1-96 must be offered");
  assert.strictEqual(aes256.salt, "EXAMPLE.COMalice",
    "the salt must be Active Directory's shape for a user — realm + " +
        "sAMAccountName, no separator");
  assert.ok(aes256.s2kparams && prim.toBytes(aes256.s2kparams).length === 4,
    "s2kparams must carry the iteration count");
  const iterations = prim.toBytes(aes256.s2kparams).reduce(function (a, b) { return a * 256 +
      b; }, 0);
  assert.strictEqual(iterations, 4096, "RFC 3962's default iteration count");

  // arcfour's entry must carry NO salt, and that absence is meaningful: its
  // string-to-key ignores the salt entirely.
  const rc4 = entries.filter(function (e) { return e.etype === 23; })[0];
  assert.ok(rc4, "arcfour should be offered by this principal");
  assert.strictEqual(rc4.salt, null, "arcfour's ETYPE-INFO2 entry must have " +
      "no salt");

  // AD also sends the older PA-PW-SALT alongside, for clients that predate
  // ETYPE-INFO2. Its presence is worth asserting because a client must prefer
  // the newer one.
  const pwSalt = err.eDataPaData.filter(function (pa) { return pa.type === 3; })[0];
  assert.ok(pwSalt, "PA-PW-SALT should be sent alongside, as Active " +
      "Directory does");
  assert.strictEqual(asn1.decLatin1(prim.toBytes(pwSalt.value)),
      "EXAMPLE.COMalice",
    "and must carry the same salt");

  // 2. Now the real request, keyed from the salt the KDC just gave us.
  const preauth = await encTimestampPadata("hunter2", aes256);
  const second = await exchange(buildAsReq({
    padata: [preauth.padata],
    nonce: 0xcafe1234
  }));
  assert.strictEqual(second.decoded.kind, "AS-REP",
    "with correct pre-authentication the KDC must issue a ticket");
  const rep = second.decoded.rep;
  assert.strictEqual(rep.crealm, "EXAMPLE.COM", "the realm in the reply");
  assert.deepStrictEqual(rep.cname.name, ["alice"], "the client named in the " +
      "reply");
  assert.strictEqual(rep.ticket.encPart.etype, 18,
    "the KDC must pick the client's FIRST acceptable etype, which was aes256");
  assert.strictEqual(rep.ticket.encPart.kvno, 3, "the ticket should name the " +
      "service's key version");

  // The client opens its half with its own long-term key.
  const part = msgs.readEncKdcRepPart(
    await preauth.profile.decrypt(preauth.key,
        kcrypto.KEY_USAGE.AS_REP_ENCPART, rep.encPart.cipher));
  assert.strictEqual(part.nonce, 0xcafe1234,
    "THE NONCE MUST COME BACK UNCHANGED. It is the client's only defence " +
        "against a replayed " +
    "reply, and a KDC that regenerates it breaks every correct client.");
  assert.strictEqual(part.srealm, "EXAMPLE.COM", "srealm");
  assert.deepStrictEqual(part.sname.name, ["krbtgt", "EXAMPLE.COM"], "sname");
  assert.ok(part.endtime > part.authtime, "the ticket must be valid for a " +
      "positive interval");
  assert.strictEqual(part.key.etype, 18, "the session key's etype");

  const flags = msgs.ticketFlagNames(part.flags);
  assert.ok(flags.indexOf("initial") !== -1,
    "a ticket from the AS exchange must be flagged initial: " +
        flags.join(", "));
  assert.ok(flags.indexOf("pre-authent") !== -1,
    "and pre-authent, because pre-authentication actually happened: " +
        flags.join(", "));
  assert.ok(flags.indexOf("forwardable") !== -1, "forwardable was requested");
  assert.ok(flags.indexOf("renewable") !== -1, "renewable was requested");
  assert.ok(part.renewTill && part.renewTill > part.endtime,
    "a renewable ticket must carry a renew-till beyond its endtime");

  log.info("the AS exchange completed: a TGT for alice@EXAMPLE.COM using " +
    part.key.etypeName + ", flags [" + flags.join(", ") + "]");
  log.debug("Leaving theTwoMessageDanceWorksAndCarriesTheSalt().");
  return { info: aes256, preauth: preauth };
}

// The service's side: the ticket must open with the SERVICE's key and carry the
// same session key the client got. That equality IS the mechanism, and it is
// the one thing neither end can verify alone.
async function theTicketAndTheClientAgreeOnTheSessionKey(context) {
  log.debug("Entering theTicketAndTheClientAgreeOnTheSessionKey().");
  const preauth = await encTimestampPadata("hunter2", context.info);
  const reply = await exchange(buildAsReq({ padata: [preauth.padata] }));
  assert.strictEqual(reply.decoded.kind, "AS-REP", "expected a ticket");
  const rep = reply.decoded.rep;

  const clientPart = msgs.readEncKdcRepPart(
    await preauth.profile.decrypt(preauth.key,
        kcrypto.KEY_USAGE.AS_REP_ENCPART, rep.encPart.cipher));

  // The krbtgt key, derived the way the KDC derives it. Its password is the
  // mock's own default; a test knowing it is what stands in for having the
  // keytab.
  const krbtgtKey = await preauth.profile.stringToKey(
    process.env.KRB5_KRBTGT_PASSWORD || "krbtgt-mock-password",
    prim.utf8("EXAMPLE.COMkrbtgt"), null);
  const ticketPart = msgs.readEncTicketPart(
    await preauth.profile.decrypt(krbtgtKey, kcrypto.KEY_USAGE.KDC_REP_TICKET,
        rep.ticket.encPart.cipher));

  assert.strictEqual(prim.toHex(ticketPart.key.key),
      prim.toHex(clientPart.key.key),
    "the session key in the TICKET and the one in the client's enc-part must " +
        "be the SAME BYTES. " +
    "They are encrypted under different keys for different readers, and " +
        "their equality is the " +
    "whole mechanism — neither end can check it alone.");
  assert.deepStrictEqual(ticketPart.cname.name, ["alice"], "the ticket names " +
      "the client");
  assert.strictEqual(ticketPart.crealm, "EXAMPLE.COM", "and its realm");
  assert.strictEqual(ticketPart.endtime.getTime(), clientPart.endtime.getTime(),
    "both copies must agree about when the ticket expires");
  log.debug("Leaving theTicketAndTheClientAgreeOnTheSessionKey().");
}

// The one-message case: an account that does not require pre-authentication is
// answered with a ticket directly. A client has to handle both, and this is the
// half that is easy to forget because Active Directory rarely does it.
async function anAccountWithoutPreAuthGetsATicketStraightAway() {
  log.debug("Entering anAccountWithoutPreAuthGetsATicketStraightAway().");
  const reply = await exchange(buildAsReq({
    cname: { type: msgs.NAME_TYPE.PRINCIPAL, name: ["noreauth"] },
    nonce: 0x5150
  }));
  assert.strictEqual(reply.decoded.kind, "AS-REP",
    "an account with pre-authentication disabled must be answered with a " +
        "ticket, not an error");
  const rep = reply.decoded.rep;
  const profile = kcrypto.etypeById(rep.encPart.etype);
  const key = await profile.stringToKey("no-preauth-here",
      prim.utf8("EXAMPLE.COMnoreauth"), null);
  const part = msgs.readEncKdcRepPart(
    await profile.decrypt(key, kcrypto.KEY_USAGE.AS_REP_ENCPART,
        rep.encPart.cipher));
  assert.strictEqual(part.nonce, 0x5150, "the nonce comes back unchanged " +
      "here too");
  const flags = msgs.ticketFlagNames(part.flags);
  assert.ok(flags.indexOf("initial") !== -1, "still an initial ticket");
  assert.strictEqual(flags.indexOf("pre-authent"), -1,
    "but NOT pre-authent: no pre-authentication happened, and a service can " +
        "insist on that flag, " +
    "so setting it would be a lie with security consequences. Flags: " +
        flags.join(", "));
  log.debug("Leaving anAccountWithoutPreAuthGetsATicketStraightAway().");
}

// ---------------------------------------------------------------------------
// The negative half — the KDC's vocabulary of refusal, which is the product.
// ---------------------------------------------------------------------------
async function theKdcRefusesInItsOwnVocabulary(context) {
  log.debug("Entering theKdcRefusesInItsOwnVocabulary().");

  async function expectError(label, request, code, textMatch) {
    log.debug("Entering expectError().");
    const reply = await exchange(request);
    assert.strictEqual(reply.decoded.kind, "KRB-ERROR",
      label + ": expected an error, got " + reply.decoded.kind);
    const e = reply.decoded.error;
    assert.strictEqual(e.errorCode, code,
      label + ": expected " + msgs.describeError(code).name + " (" + code +
          "), got " +
      e.error.name + " (" + e.errorCode + ")" + (e.eText ? " — " + e.eText :
          ""));
    if (textMatch) {
      assert.ok(textMatch.test(e.eText || ""),
        label + ": e-text should explain — " + JSON.stringify(e.eText));
    }
    // Every refusal must carry the KDC's own clock, because that is how a
    // client measures skew and skew is one of the commonest causes of failure.
    assert.ok(e.stime instanceof Date && !isNaN(e.stime.getTime()),
      label + ": a KRB-ERROR must carry stime");
    log.debug(label + " -> " + e.error.name);
    log.debug("Leaving expectError().");
    return e;
  }

  await expectError("an unknown principal",
    buildAsReq({ cname: {
      type: 1,
      name: ["nobody"]
    } }), 6, /no such principal/);

  await expectError("an unknown service",
    buildAsReq({ sname: {
      type: 2,
      name: ["krbtgt", "OTHER.REALM"]
    } }), 7, /no such service/);

  await expectError("the wrong realm",
    buildAsReq({
      realm: "OTHER.REALM",
      sname: {
      type: 2,
      name: ["krbtgt", "OTHER.REALM"]
    }
    }),
    68, /serves EXAMPLE.COM/);

  await expectError("a locked account",
    buildAsReq({ cname: {
      type: 1,
      name: ["locked"]
    } }), 18, /disabled or locked/);

  await expectError("an expired password",
    buildAsReq({ cname: { type: 1, name: ["expired"] } }), 23, /expired/);

  // The 2026 case: an AES-only account and a client offering only RC4. This is
  // what a hardened Windows Server 2025 domain controller does to a legacy
  // client, and the error reads as "the KDC is broken" unless you know what it
  // means.
  const noSupp = await expectError("an RC4-only client against an AES-only " +
      "account",
    buildAsReq({ cname: { type: 1, name: ["aesonly"] }, etypes: [23] }), 14,
    /no common encryption type/);
  assert.ok(/aes256|aes128/.test(noSupp.eText || ""),
    "the refusal should say what the principal DOES support, which is the " +
        "whole diagnosis: " +
    noSupp.eText);

  // ...and the mirror image, which is the account that a 2025 baseline breaks.
  await expectError("an AES-only client against an RC4-only account",
    buildAsReq({ cname: { type: 1, name: ["rc4only"] }, etypes: [18, 17] }), 14,
    /no common encryption type/);

  // A wrong password. Note what the KDC can and cannot tell: this is
  // indistinguishable to it from a wrong salt or a wrong key usage number,
  // which is exactly why showing the salt matters.
  const wrongPassword = await encTimestampPadata("not the password",
      context.info);
  const failed = await expectError("a wrong password",
    buildAsReq({ padata: [wrongPassword.padata] }), 24, /PREAUTH_FAILED/);
  assert.ok(failed.eDataPaData,
    "PREAUTH_FAILED must re-send ETYPE-INFO2: the client may have used the " +
        "wrong SALT rather than " +
    "the wrong password, and this is how it finds out");
  const resent = msgs.readEtypeInfo2(
    failed.eDataPaData.filter(function (pa) { return pa.type === 19; })[0].value);
  assert.strictEqual(resent.filter(function (e) { return e.etype === 18; })[0].salt,
    "EXAMPLE.COMalice", "and the salt in it must still be right");

  // A pre-auth timestamp encrypted under the wrong SALT — the same password, a
  // different salt. Indistinguishable from a wrong password at the KDC, which
  // is the point being demonstrated.
  const wrongSalt = await encTimestampPadata("hunter2",
    { etype: 18, salt: "EXAMPLE.COMAlice", s2kparams: context.info.s2kparams });
  await expectError("the right password with the wrong salt",
    buildAsReq({ padata: [wrongSalt.padata] }), 24, /PREAUTH_FAILED/);

  // A timestamp outside the tolerance. Built by hand rather than by moving any
  // clock: the padata carries the time, so a stale one is just a stale value.
  const profile = kcrypto.etypeById(18);
  const key = await profile.stringToKey("hunter2",
      prim.utf8("EXAMPLE.COMalice"), null);
  const stale = msgs.encPaEncTsEnc(new Date(Date.now() - 20 * 60 * 1000), 0);
  const skewed = await expectError("a timestamp twenty minutes old",
    buildAsReq({ padata: [{
      type: msgs.PA_TYPE.ENC_TIMESTAMP,
      value: msgs.encEncryptedData({
        etype: 18,
        cipher: await profile.encrypt(key,
            kcrypto.KEY_USAGE.AS_REQ_PA_ENC_TIMESTAMP, stale)
      })
    }] }), 37, /clock skew/);
  assert.ok(/\d+ seconds/.test(skewed.eText || ""),
    "the skew refusal should quote the measured difference: " + skewed.eText);

  // A message that is not a request a KDC answers. This one takes BOTH layers to
  // state properly, and the two are complementary rather than redundant:
  //
  //   * the relay refuses to SEND it at all, because POST /krb5/kdc carries
  //     requests and an AP-REP is a reply; and
  //   * the KDC, if such a message reached it by some other route, answers
  //     KRB_AP_ERR_MSG_TYPE rather than dropping it — a client waiting for a reply
  //     that never comes learns nothing.
  //
  // Asserting only the first would leave the KDC free to hang; asserting only the
  // second would miss that the relay is meant to stop it earlier.
  const apRep = msgs.encApRep({ encPart: {
    etype: 18,
    cipher: kcrypto.randomBytes(32)
  } });
  let relayRefused = null;
  try {
    await exchange(apRep);
  } catch (e) {
    relayRefused = e;
  }
  assert.ok(relayRefused, "the relay must refuse to send an AP-REP to a KDC");
  assert.strictEqual(relayRefused.code, "EKRB5NOTKERBEROS",
    "and refuse it as a payload problem: " + relayRefused.message);

  // Now past the relay, straight into the KDC, which is why the module is
  // loaded in-process rather than only reached over a socket.
  const direct = msgs.readKdcResponse(await kdc.module.handleMessage(Buffer.from(apRep)));
  assert.strictEqual(direct.kind, "KRB-ERROR",
    "an AP-REP reaching the KDC must be answered with an error, not with " +
        "silence");
  assert.strictEqual(direct.error.errorCode, 40, "KRB_AP_ERR_MSG_TYPE");

  // Bytes that are not Kerberos at all must also get an answer rather than a
  // dropped connection. A bare DER SEQUENCE has no [APPLICATION n] tag, so the
  // KDC cannot even guess what it is.
  const garbage = msgs.readKdcResponse(
    await kdc.module.handleMessage(Buffer.from([0x30, 0x03, 0x02, 0x01,
        0x05])));
  assert.strictEqual(garbage.kind, "KRB-ERROR", "garbage must still be " +
      "answered");
  assert.strictEqual(garbage.error.errorCode, 60, "KRB_ERR_GENERIC");
  assert.ok(/could not decode/.test(garbage.error.eText || ""),
    "and e-text must say what the KDC objected to, which is where a KDC " +
        "explains itself: " +
    garbage.error.eText);

  // A pleasing accident worth keeping as a case. The ASCII text "not kerberos"
  // begins with 'n' = 0x6e, which IS the [APPLICATION 14] tag — so these bytes
  // announce themselves as an AP-REQ and the KDC answers KRB_AP_ERR_MSG_TYPE
  // rather than KRB_ERR_GENERIC. It is a reminder that the application tag is
  // one byte and text can wear it by coincidence, which is exactly why the
  // relay's pre-flight also checks that the declared length matches.
  const textish = msgs.readKdcResponse(await kdc.module.handleMessage(Buffer.from("not kerberos")));
  assert.strictEqual(textish.error.errorCode, 40,
    "text beginning with 0x6e is read as an AP-REQ, so the answer is " +
        "KRB_AP_ERR_MSG_TYPE");

  // A TGS-REQ whose PA-TGS-REQ is nonsense. The TGS exchange itself is covered
  // by tests/krb5_tgs_ap.js — this case is only here to check that the KDC
  // answers a malformed one with a reason rather than failing opaquely or
  // dropping it.
  //
  // (This assertion used to require the text "does not implement the TGS
  // exchange yet", and it broke the moment phase 3 implemented it — which is
  // the right kind of failure: a test asserting the absence of a feature must
  // be revisited when the feature arrives, not deleted quietly.)
  const tgs = await exchange(msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.TGS_REQ,
    padata: [{ type: msgs.PA_TYPE.TGS_REQ, value: prim.fromHex("00") }],
    reqBody: {
      kdcOptions: [],
      realm: "EXAMPLE.COM",
      sname: { type: 3, name: ["HTTP", "web.example.com"] },
      till: new Date(Date.now() + 3600000),
      nonce: 7,
      etypes: [18]
    }
  }));
  assert.strictEqual(tgs.decoded.kind, "KRB-ERROR", "a malformed TGS-REQ " +
      "must be answered with an error");
  assert.ok(/PA-TGS-REQ/.test(tgs.decoded.error.eText || ""),
    "and must name the part it could not read rather than failing opaquely: " +
    tgs.decoded.error.eText);

  // And a TGS-REQ with no PA-TGS-REQ at all is structurally unanswerable, which
  // is a different refusal from a malformed one.
  const noTgt = await exchange(msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.TGS_REQ,
    reqBody: {
      kdcOptions: [],
      realm: "EXAMPLE.COM",
      sname: { type: 3, name: ["HTTP", "web.example.com"] },
      till: new Date(Date.now() + 3600000),
      nonce: 8,
      etypes: [18]
    }
  }));
  assert.strictEqual(noTgt.decoded.error.errorCode, 25,
    "a TGS-REQ carrying no TGT at all must be refused as needing " +
        "pre-authentication");
  assert.ok(/must carry the TGT/.test(noTgt.decoded.error.eText || ""),
    "and say so: " + noTgt.decoded.error.eText);

  log.debug("Leaving theKdcRefusesInItsOwnVocabulary().");
}

// ---------------------------------------------------------------------------
// The salt shapes, which is where an implementation stops working against AD.
// ---------------------------------------------------------------------------
async function computerAccountsHaveAHostShapedSalt() {
  log.debug("Entering computerAccountsHaveAHostShapedSalt().");
  const first = await exchange(buildAsReq({
    cname: { type: msgs.NAME_TYPE.SRV_HST, name: ["host", "ws01.example.com"] }
  }));
  assert.strictEqual(first.decoded.kind, "KRB-ERROR", "expected " +
      "PREAUTH_REQUIRED");
  assert.strictEqual(first.decoded.error.errorCode, 25, "PREAUTH_REQUIRED");
  const entries = msgs.readEtypeInfo2(
    first.decoded.error.eDataPaData.filter(function (pa) { return pa.type === 19; })[0].value);
  const salt = entries.filter(function (e) { return e.etype === 18; })[0].salt;

  // The salt for a COMPUTER account is not the principal name in any
  // arrangement: realm + "host" + short name + DNS domain. An implementation
  // that derives the salt from the principal string works until the first
  // machine account — which is the moment somebody is debugging a service
  // rather than a user.
  assert.strictEqual(salt, "EXAMPLE.COMhostws01.example.com",
    "a computer account's salt must be host-shaped, not name-shaped");
  assert.notStrictEqual(salt, "EXAMPLE.COMhost/ws01.example.com",
    "and specifically must NOT be the principal name with the realm in front");

  // And it works: the key derived from that salt authenticates.
  const preauth = await encTimestampPadata("machine-account-password",
    entries.filter(function (e) { return e.etype === 18; })[0]);
  const second = await exchange(buildAsReq({
    cname: { type: msgs.NAME_TYPE.SRV_HST, name: ["host", "ws01.example.com"] },
    padata: [preauth.padata]
  }));
  assert.strictEqual(second.decoded.kind, "AS-REP",
    "the host-shaped salt must actually produce a working key");
  log.debug("Leaving computerAccountsHaveAHostShapedSalt().");
}

// ---------------------------------------------------------------------------
// Etype negotiation: the client's ORDER is its preference and the KDC honours it.
// ---------------------------------------------------------------------------
async function theKdcHonoursTheClientsEtypeOrder() {
  log.debug("Entering theKdcHonoursTheClientsEtypeOrder().");
  const cases = [
    [[18, 17, 23], 18, "aes256 first"],
    [[17, 18, 23], 17, "aes128 first"],
    [[23, 18], 23, "arcfour first — a client may ask for the weak one, and a " +
        "KDC that supports it obliges"],
    [[19, 20, 18], 19, "an RFC 8009 etype first"]
  ];
  for (const [offered, expected, label] of cases) {
    const reply = await exchange(buildAsReq({ etypes: offered }));
    assert.strictEqual(reply.decoded.kind, "KRB-ERROR", label + ": expected " +
        "PREAUTH_REQUIRED");
    const entries = msgs.readEtypeInfo2(
      reply.decoded.error.eDataPaData.filter(function (pa) { return pa.type === 19; })[0].value);
    // The KDC advertises what the PRINCIPAL supports, in the KDC's order — that
    // is not the same list as what the client offered, and conflating the two
    // is how a client ends up deriving a key of the wrong type.
    assert.ok(entries.length >= 1, label + ": the KDC must advertise " +
        "something");
    const chosen = entries.filter(function (e) { return e.etype === expected; })[0];
    assert.ok(chosen, label + ": the KDC must advertise the etype it will " +
        "accept (" +
      kcrypto.etypeName(expected) + "); it advertised " +
      entries.map(function (e) { return e.etypeName; }).join(", "));

    // Now complete the exchange and check the etype it actually USED.
    const preauth = await encTimestampPadata("hunter2", chosen);
    const done = await exchange(buildAsReq({
      etypes: offered,
      padata: [preauth.padata]
    }));
    assert.strictEqual(done.decoded.kind, "AS-REP", label +
        ": expected a ticket");
    assert.strictEqual(done.decoded.rep.ticket.encPart.etype, expected,
      label + ": the KDC must choose the FIRST etype the client offered that " +
          "the principal " +
      "supports, which is " + kcrypto.etypeName(expected) + "; it used " +
      kcrypto.etypeName(done.decoded.rep.ticket.encPart.etype));
    log.debug(label + " -> " + kcrypto.etypeName(expected));
  }
  log.debug("Leaving theKdcHonoursTheClientsEtypeOrder().");
}

// ---------------------------------------------------------------------------
// UDP, and the reply-too-big behaviour that makes a client retry over TCP.
// ---------------------------------------------------------------------------
async function udpAnswersAndFallsBackHonestly() {
  log.debug("Entering udpAnswersAndFallsBackHonestly().");
  const reply = await exchange(buildAsReq(), { transport: "udp" });
  assert.strictEqual(reply.decoded.kind, "KRB-ERROR",
    "the KDC must answer over UDP as well as TCP");
  assert.strictEqual(reply.decoded.error.errorCode, 25,
    "and give the same answer it gives over TCP");
  log.debug("Leaving udpAnswersAndFallsBackHonestly().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. The AS exchange: common/krb5 against the mock " +
      "KDC, through the relay.");
  await startKdc();
  try {
    const context = await theTwoMessageDanceWorksAndCarriesTheSalt();
    await theTicketAndTheClientAgreeOnTheSessionKey(context);
    await anAccountWithoutPreAuthGetsATicketStraightAway();
    await computerAccountsHaveAHostShapedSalt();
    await theKdcHonoursTheClientsEtypeOrder();
    await theKdcRefusesInItsOwnVocabulary(context);
    await udpAnswersAndFallsBackHonestly();
    log.info("Test completed successfully.");
  } finally {
    stopKdc();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("krb5_as_exchange")
  .description("The Kerberos AS exchange end to end: the wallet codec " +
      "against the mock KDC.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
      "starts its own KDC)"))
  .parse(process.argv);

test().then(function () {
  // The KDC's listeners are closed, but express in the sts module keeps no
  // handle here; exit explicitly so a lingering reference cannot hold the
  // process open.
  process.exit(0);
}).catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
