// File: krb5_spnego_http.js
//
// SPNEGO over HTTP, end to end: RFC 4559 carrying RFC 4178 carrying RFC 4121
// carrying an AP-REQ. The client is common/krb5; the KDC and the protected page
// are the sts/ submodule's.
//
// ---------------------------------------------------------------------------
// WHAT THIS PROVES THAT krb5_tgs_ap.js DOES NOT.
//
// That test presents a ticket over a raw socket, which is the AP exchange and
// nothing more. Everything here is the two layers above it, and each one has a
// way of failing that leaves the AP exchange looking perfectly healthy:
//
//  1. **The first 401 carries NO token.** RFC 4559 section 4. A server that
//     helpfully put one there would break every client, and a client that waits
//     for one hangs on a correct server.
//  2. **Only the initiator's FIRST token is wrapped.** The NegTokenInit rides
//     inside an RFC 2743 InitialContextToken (0x60 + the SPNEGO OID); every
//     token after it, in both directions, is a bare NegTokenResp beginning
//     0xa1. Wrapping the reply produces something no client will read.
//  3. **The mechListMIC covers the MechTypeList, not `[0] MechTypeList`**
//     — two bytes, RFC 4178 section 5. A MIC over the tagged form is the
//     commonest mistake in this protocol, so it is a NEGATIVE CASE below rather
//     than a comment: the ticket is perfect, and the request is refused.
//  4. **A rejection carries no reason.** SPNEGO's negState has no reason field,
//     so the only diagnosis available is the mechanism's own error token. The
//     negatives here assert that the KRB-ERROR is in the responseToken AND that
//     it names the right code — a reject with an empty responseToken is what an
//     acceptor that swallowed the error looks like, and it is indistinguishable
//     from a wrong password.
//
// The negatives are the substantial half deliberately. A SPNEGO acceptor that
// authenticates a good client looks finished and is worth very little: what
// makes it worth anything is refusing a replay, refusing a ticket for another
// service, refusing a mechanism list it cannot verify, and refusing a MIC
// computed over the wrong bytes — while still saying which of those happened.
//
// No browser and no running service: the KDC and the mock's Express app are
// started in-process on ephemeral ports.
// ---------------------------------------------------------------------------
const assert = require("assert");
const http = require("http");
const net = require("net");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "krb5_spnego_http",
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
const gss = shared("krb5_gss.js");
const spnego = shared("krb5_spnego.js");
const client = shared("krb5_client.js");

// The mock KDC, the protected service and the SPNEGO page all live in the sts/
// SUBMODULE. module_paths.js holds the resolution order and the loud warning
// when a sibling checkout is used instead, so the Kerberos tests cannot drift
// apart on which copy they picked up.
function stsModule(name) {
  return paths.mockStsModule(name, function (message) { log.warn(message); });
}

const REALM = "EXAMPLE.COM";
const SERVICE = ["HTTP", "web.example.com"];
const USER_PASSWORD = process.env.KRB5_USER_PASSWORD || "password!";

// What a Windows client actually offers, in this order. Kerberos first, its
// mis-typed Microsoft twin second, NTLM last as the fallback. Used as-is so
// that the mechanism-selection assertions are about a realistic list rather
// than a list chosen to make them pass.
const WINDOWS_MECHS = [spnego.KRB5_MECH_OID, spnego.MS_KRB5_MECH_OID,
    "1.3.6.1.4.1.311.2.2.10"];

let kdcPort = 0;
let httpPort = 0;

// ---------------------------------------------------------------------------
// Transport.
// ---------------------------------------------------------------------------
function sendFramed(port, bytes) {
  log.debug("Entering sendFramed().");
  log.debug("Leaving sendFramed().");
  return new Promise(function (resolve, reject) {
    const socket = new net.Socket();
    let buffer = Buffer.alloc(0);
    let settled = false;
    function finish(err, value) {
      if (settled) {
        return;
      }
      settled = true;
      socket.destroy();
      if (err) {
        return reject(err);
      }
      resolve(value);
    }
    const timer = setTimeout(function () {
      finish(new Error("timed out after 10s"));
    }, 10000);
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
      if (!buffer.length) {
        finish(null, null);
      }
    });
    socket.on("error", function (e) {
      clearTimeout(timer);
      finish(e);
    });
    socket.connect(port, "127.0.0.1");
  });
}

// One GET of the protected resource, with an optional Negotiate token.
//
// The `WWW-Authenticate` header is returned BOTH raw and decoded, because half
// the assertions here are about the header as a string — that the first
// challenge is the bare word `Negotiate` with nothing after it — and the other
// half about the token inside it.
function get(pathAndQuery, token) {
  log.debug("Entering get(). " + pathAndQuery);
  log.debug("Leaving get().");
  return new Promise(function (resolve, reject) {
    const headers = {};
    if (token) {
      headers.Authorization = "Negotiate " +
        Buffer.from(token).toString("base64");
    }
    const request = http.request({
      host: "127.0.0.1",
      port: httpPort,
      method: "GET",
      path: pathAndQuery,
      headers: headers
    }, function (response) {
      let body = "";
      response.setEncoding("utf8");
      response.on("data", function (chunk) { body += chunk; });
      response.on("end", function () {
        const raw = response.headers["www-authenticate"] || null;
        let negotiate = null;
        const match = raw && /^Negotiate\s+(\S+)/i.exec(raw);
        if (match) {
          negotiate = new Uint8Array(Buffer.from(match[1], "base64"));
        }
        resolve({
          status: response.statusCode,
          headers: response.headers,
          wwwAuthenticate: raw,
          negotiate: negotiate,
          body: body
        });
      });
    });
    request.on("error", reject);
    request.end();
  });
}

// The KRB-ERROR a rejection carries, or null. SPNEGO itself says only "no", so
// this is the whole of the diagnosis and every negative below asserts on it.
function errorInside(resp) {
  log.debug("Entering errorInside().");
  if (!resp.negotiate) {
    log.debug("Leaving errorInside(). No token.");
    return null;
  }
  const parsed = spnego.decodeNegotiationToken(resp.negotiate);
  if (!parsed.responseToken) {
    log.debug("Leaving errorInside(). No responseToken.");
    return null;
  }
  const inner = gss.decodeInitialContextToken(parsed.responseToken);
  log.debug("Leaving errorInside().");
  return msgs.readKrbError(inner.inner);
}

// ---------------------------------------------------------------------------
// Credentials. Covered in full by krb5_as_exchange.js and krb5_tgs_ap.js, so
// this is the short version — everything below needs a service ticket.
// ---------------------------------------------------------------------------
async function getTgt(principalName) {
  log.debug("Entering getTgt().");
  const bare = msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.AS_REQ,
    reqBody: {
      kdcOptions: [msgs.KDC_OPTION.FORWARDABLE, msgs.KDC_OPTION.RENEWABLE],
      cname: { type: msgs.NAME_TYPE.PRINCIPAL, name: [principalName] },
      realm: REALM,
      sname: { type: msgs.NAME_TYPE.SRV_INST, name: ["krbtgt", REALM] },
      till: new Date(Date.now() + 10 * 3600 * 1000),
      nonce: client.randomNonce(),
      etypes: [18, 17]
    }
  });
  const first = msgs.readKdcResponse(await sendFramed(kdcPort, bare));
  assert.strictEqual(first.error.errorCode, 25,
      "expected PREAUTH_REQUIRED for " + principalName);
  const info = msgs.readEtypeInfo2(
    first.error.eDataPaData.filter(function (pa) {
      return pa.type === 19;
    })[0].value).filter(function (e) { return e.etype === 18; })[0];
  const profile = kcrypto.etypeById(18);
  const key = await profile.stringToKey(USER_PASSWORD, prim.utf8(info.salt),
      info.s2kparams);
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
    }],
    reqBody: {
      kdcOptions: [msgs.KDC_OPTION.FORWARDABLE, msgs.KDC_OPTION.RENEWABLE],
      cname: { type: msgs.NAME_TYPE.PRINCIPAL, name: [principalName] },
      realm: REALM,
      sname: { type: msgs.NAME_TYPE.SRV_INST, name: ["krbtgt", REALM] },
      till: new Date(Date.now() + 10 * 3600 * 1000),
      nonce: nonce,
      etypes: [18, 17]
    }
  });
  const response = msgs.readKdcResponse(await sendFramed(kdcPort, withPreauth));
  assert.strictEqual(response.kind, "AS-REP", "expected a TGT for " +
      principalName);
  const part = msgs.readEncKdcRepPart(await profile.decrypt(key,
      kcrypto.KEY_USAGE.AS_REP_ENCPART, response.rep.encPart.cipher));
  log.debug("Leaving getTgt().");
  return {
    ticket: response.rep.ticket,
    sessionKey: part.key.key,
    etype: part.key.etype,
    client: response.rep.cname,
    realm: response.rep.crealm,
    endtime: part.endtime
  };
}

async function getServiceTicket(tgt, sname) {
  log.debug("Entering getServiceTicket().");
  const built = await client.buildTgsReq({
    tgt: tgt,
    sname: sname || { type: msgs.NAME_TYPE.SRV_HST, name: SERVICE },
    subkey: null
  });
  const result = await client.readTgsRep({
    tgt: tgt,
    reply: await sendFramed(kdcPort, built.request),
    nonce: built.nonce,
    subkey: null
  });
  assert.ok(result.ok, "the TGS exchange failed: " +
    (result.error ? result.error.error.name : "unknown"));
  log.debug("Leaving getServiceTicket().");
  return {
    ticket: result.ticket,
    sessionKey: result.sessionKey,
    etype: result.etype,
    client: tgt.client,
    realm: tgt.realm,
    service: (sname ? sname.name : SERVICE).join("/"),
    endtime: result.endtime
  };
}

// ---------------------------------------------------------------------------
// The client half of SPNEGO, written here rather than imported from the page's
// bundle.
//
// It is FIVE lines over the shared codec, and that is the point: the wire
// format is shared (one codec, or the two ends agree only with themselves) but
// the assembly is not, so a mistake in how the page puts a NegTokenInit
// together cannot make this test pass.
// ---------------------------------------------------------------------------
async function buildInit(ticket, options) {
  log.debug("Entering buildInit().");
  const opts = options || {};
  const mechs = opts.mechTypes || WINDOWS_MECHS;
  const built = await client.buildApReq({
    ticket: ticket,
    mutual: opts.mutual !== false,
    gssFlags: [gss.GSS_FLAG.MUTUAL, gss.GSS_FLAG.INTEG, gss.GSS_FLAG.CONF]
  });
  const mechListDer = spnego.mechTypeListDer(mechs);
  let mic = null;
  if (opts.mic) {
    mic = await spnego.computeMechListMic({
      key: built.subkey.key,
      etype: built.subkey.etype,
      role: "initiator",
      // The bytes to sign, which `opts.micOver` can make WRONG on purpose —
      // that is negative case 5.
      mechListDer: opts.micOver === "tagged"
        ? asn1.encContext(0, mechListDer)
        : mechListDer,
      sequenceNumber: 0
    });
  }
  const init = spnego.encodeNegTokenInit({
    mechTypes: mechs,
    mechToken: opts.mechToken || built.token,
    mechListMic: mic
  });
  log.debug("Leaving buildInit().");
  return {
    token: init.token,
    mechListDer: init.mechListDer,
    apReq: built.apReq,
    gssToken: built.token,
    subkey: built.subkey,
    ctime: built.ctime,
    cusec: built.cusec
  };
}

// ---------------------------------------------------------------------------
// POSITIVE 1. The unauthenticated request, and the header that is NOT there.
// ---------------------------------------------------------------------------
async function theFirstRequestIsRefusedWithABareChallenge() {
  log.debug("Entering theFirstRequestIsRefusedWithABareChallenge().");
  log.info("=== The unauthenticated request ===");
  const resp = await get("/spnego/protected", null);
  assert.strictEqual(resp.status, 401,
      "an unauthenticated request must be refused with 401, got " +
      resp.status);
  assert.ok(resp.wwwAuthenticate,
      "the 401 must carry a WWW-Authenticate header");
  assert.strictEqual(resp.wwwAuthenticate.trim(), "Negotiate",
    "the FIRST challenge must be the bare word `Negotiate` with no token " +
    "after it (RFC 4559 section 4). This server sent: " +
    JSON.stringify(resp.wwwAuthenticate) + ". A token here is not a harmless " +
    "extra — a client that reads it as the acceptor's first negotiation " +
    "token has nothing to answer.");
  assert.strictEqual(resp.negotiate, null,
      "and therefore no token to decode");
  log.info("401 with a bare `Negotiate` challenge, as RFC 4559 requires");
  log.debug("Leaving theFirstRequestIsRefusedWithABareChallenge().");
}

// ---------------------------------------------------------------------------
// POSITIVE 2. The optimistic token: one round trip, Kerberos inside SPNEGO.
// ---------------------------------------------------------------------------
async function theOptimisticTokenAuthenticatesInOneRoundTrip(serviceTicket) {
  log.debug("Entering theOptimisticTokenAuthenticatesInOneRoundTrip().");
  log.info("=== The optimistic NegTokenInit ===");
  const built = await buildInit(serviceTicket, {});
  const resp = await get("/spnego/protected", built.token);
  assert.strictEqual(resp.status, 200,
    "a valid ticket in a NegTokenInit must be accepted, got " + resp.status +
    ": " + resp.body.slice(0, 400));
  assert.ok(/alice@EXAMPLE\.COM/.test(resp.body),
      "and the page must name the authenticated client: " +
      resp.body.slice(0, 400));

  assert.ok(resp.negotiate,
    "the 200 must carry the acceptor's token in WWW-Authenticate. Without it " +
    "the client has authenticated to something it cannot identify — the " +
    "mutual half of the exchange happens in THIS header and nowhere else.");
  // The reply is a BARE NegTokenResp. Asserted on the first byte because the
  // failure it catches is an acceptor that wrapped its reply in an
  // InitialContextToken, which decodes as SPNEGO all the way up to the point
  // where nothing works.
  assert.strictEqual(resp.negotiate[0], 0xa1,
    "every token after the initiator's first is a BARE NegTokenResp " +
    "beginning " +
    "0xa1, with no InitialContextToken and no OID (RFC 4178 section 4.2). " +
    "This one begins 0x" + resp.negotiate[0].toString(16) +
    (resp.negotiate[0] === 0x60 ? " — it has been wrapped, which no client " +
        "will read." : "."));

  const parsed = spnego.decodeNegotiationToken(resp.negotiate);
  assert.strictEqual(parsed.kind, "NegTokenResp", "and must decode as one");
  assert.strictEqual(parsed.negState, spnego.NEG_STATE.ACCEPT_COMPLETED,
    "the negState must be accept-completed (0), got " + parsed.negState +
    " (" + parsed.negStateName + ")");
  assert.strictEqual(parsed.supportedMech, spnego.KRB5_MECH_OID,
    "and the acceptor must name the mechanism it selected in its FIRST " +
    "reply, which is the only reply that may carry it. Got: " +
    parsed.supportedMech);
  assert.ok(parsed.responseToken,
      "with the mechanism's own token — the AP-REP — inside responseToken");

  // Mutual authentication: the echo, checked rather than assumed. A client that
  // asks for it and does not compare the echo has not performed it.
  const outcome = await client.readApRep({
    reply: parsed.responseToken,
    ticket: serviceTicket,
    sentCtime: built.ctime,
    sentCusec: built.cusec
  });
  assert.ok(outcome.ok && outcome.mutualOk,
    "the AP-REP in the responseToken must echo the Authenticator's ctime and " +
    "cusec under the ticket's session key — that echo IS the server's proof " +
    "of identity: " + (outcome.reason || (outcome.error &&
        outcome.error.error.name) || ""));
  assert.ok(outcome.acceptorSubkey,
      "and the acceptor should offer a subkey, which becomes the context key");
  log.info("authenticated in one round trip; mutual authentication confirmed");
  log.debug("Leaving theOptimisticTokenAuthenticatesInOneRoundTrip().");
  return outcome;
}

// ---------------------------------------------------------------------------
// POSITIVE 3. The mechListMIC, in both directions.
// ---------------------------------------------------------------------------
async function theMechListMicIsVerifiedInBothDirections(serviceTicket) {
  log.debug("Entering theMechListMicIsVerifiedInBothDirections().");
  log.info("=== The mechListMIC ===");
  const built = await buildInit(serviceTicket, { mic: true });
  const resp = await get("/spnego/protected", built.token);
  assert.strictEqual(resp.status, 200,
    "a correct mechListMIC must be accepted, got " + resp.status + ": " +
    resp.body.slice(0, 400));
  assert.ok(/verified/.test(resp.body),
      "and the page must say the MIC verified: " + resp.body.slice(0, 400));

  const parsed = spnego.decodeNegotiationToken(resp.negotiate);
  assert.ok(parsed.mechListMic,
    "the acceptor must return a mechListMIC of its own. Only one direction " +
    "being protected is not the exchange RFC 4178 section 5 describes: the " +
    "initiator has no way to know the acceptor saw the list it sent.");

  // The acceptor's MIC is keyed differently from the client's, and getting
  // that wrong is invisible until it is checked from the other side. The
  // client signs with the subkey from its own Authenticator, because that is
  // the only context key that exists when the NegTokenInit is built; the
  // acceptor signs with the subkey IT offered, because RFC 4121 makes that the
  // context key once it exists.
  const outcome = await client.readApRep({
    reply: parsed.responseToken,
    ticket: serviceTicket,
    sentCtime: built.ctime,
    sentCusec: built.cusec
  });
  assert.ok(outcome.acceptorSubkey,
      "the acceptor must have offered a subkey for its MIC to be keyed with");
  const verdict = await spnego.verifyMechListMic({
    key: outcome.acceptorSubkey.key,
    etype: outcome.acceptorSubkey.etype,
    mic: parsed.mechListMic,
    mechListDer: built.mechListDer
  });
  assert.ok(verdict.ok,
    "the acceptor's mechListMIC must verify against the SAME MechTypeList " +
    "the client sent, keyed with the acceptor's subkey");
  assert.strictEqual(verdict.senderRole, "acceptor",
    "and the role is IN the token, so a verifier uses the SENDER's key usage " +
    "— 23 for an acceptor, 25 for an initiator. Got: " + verdict.senderRole);
  log.info("the mechListMIC verifies in both directions");
  log.debug("Leaving theMechListMicIsVerifiedInBothDirections().");
}

// ---------------------------------------------------------------------------
// POSITIVE 4. Microsoft's mis-typed Kerberos OID is still Kerberos.
// ---------------------------------------------------------------------------
async function theMicrosoftKerberosOidIsAccepted(serviceTicket) {
  log.debug("Entering theMicrosoftKerberosOidIsAccepted().");
  log.info("=== The MS Kerberos OID ===");
  const built = await buildInit(serviceTicket, {
    mechTypes: [spnego.MS_KRB5_MECH_OID, "1.3.6.1.4.1.311.2.2.10"]
  });
  const resp = await get("/spnego/protected", built.token);
  assert.strictEqual(resp.status, 200,
    "1.2.840.48018.1.2.2 is Microsoft's mis-typed Kerberos OID and every " +
    "Windows client offers it. An acceptor that treats it as an unknown " +
    "mechanism refuses every Windows client and reports it as a mechanism " +
    "mismatch. Got " + resp.status + ": " + resp.body.slice(0, 300));
  const parsed = spnego.decodeNegotiationToken(resp.negotiate);
  assert.strictEqual(parsed.supportedMech, spnego.MS_KRB5_MECH_OID,
    "and the acceptor must echo back the spelling the client offered, not " +
    "the one it prefers: got " + parsed.supportedMech);
  log.info("the MS Kerberos OID is selected and echoed back");
  log.debug("Leaving theMicrosoftKerberosOidIsAccepted().");
}

// ---------------------------------------------------------------------------
// POSITIVE 5. A bare Kerberos token, with no negotiation at all.
// ---------------------------------------------------------------------------
async function aBareKerberosTokenIsAcceptedAndSaidToBeOne(serviceTicket) {
  log.debug("Entering aBareKerberosTokenIsAcceptedAndSaidToBeOne().");
  log.info("=== A bare Kerberos token ===");
  const built = await client.buildApReq({
    ticket: serviceTicket,
    mutual: true,
    gssFlags: [gss.GSS_FLAG.MUTUAL]
  });
  const resp = await get("/spnego/protected", built.token);
  assert.strictEqual(resp.status, 200,
    "a bare RFC 4121 InitialContextToken — no SPNEGO around it — is legal " +
    "on HTTP and real clients send one. Got " + resp.status);
  assert.ok(/no negotiation|bare Kerberos/i.test(resp.body),
    "but the acceptor must SAY it was not a negotiation, because none of " +
    "SPNEGO's downgrade protection applies to it: " + resp.body.slice(0, 400));
  log.info("a bare Kerberos token is accepted, and named as one");
  log.debug("Leaving aBareKerberosTokenIsAcceptedAndSaidToBeOne().");
}

// ---------------------------------------------------------------------------
// POSITIVE 6. request-mic: the second round trip, and the continuation token.
// ---------------------------------------------------------------------------
async function requestMicCostsASecondRoundTripAndCompletes(serviceTicket) {
  log.debug("Entering requestMicCostsASecondRoundTripAndCompletes().");
  log.info("=== request-mic ===");
  const built = await buildInit(serviceTicket, {});
  const first = await get("/spnego/protected?mic=require", built.token);
  assert.strictEqual(first.status, 401,
    "an acceptor asking for the MIC has not finished, so it must not answer " +
    "200. Got " + first.status);
  const parsed = spnego.decodeNegotiationToken(first.negotiate);
  assert.strictEqual(parsed.negState, spnego.NEG_STATE.REQUEST_MIC,
    "and the state must be request-mic (3), which is legal only in the " +
    "acceptor's FIRST reply. Got " + parsed.negState + " (" +
    parsed.negStateName + ")");

  // The continuation: a bare NegTokenResp carrying the MIC and nothing else.
  const mic = await spnego.computeMechListMic({
    key: built.subkey.key,
    etype: built.subkey.etype,
    role: "initiator",
    mechListDer: built.mechListDer,
    sequenceNumber: 0
  });
  const second = await get("/spnego/protected?mic=require",
    spnego.encodeNegTokenResp({ mechListMic: mic }));
  assert.strictEqual(second.status, 200,
    "the continuation carrying the MIC must complete the context, got " +
    second.status + ": " + second.body.slice(0, 400));
  const done = spnego.decodeNegotiationToken(second.negotiate);
  assert.strictEqual(done.negState, spnego.NEG_STATE.ACCEPT_COMPLETED,
      "with accept-completed, got " + done.negStateName);
  assert.strictEqual(done.supportedMech, null,
    "and WITHOUT supportedMech: it is legal only in the acceptor's first " +
    "reply, and repeating it on a later one tells the initiator to " +
    "renegotiate. Got " + done.supportedMech);
  log.info("request-mic completes in two round trips");
  log.debug("Leaving requestMicCostsASecondRoundTripAndCompletes().");
}

// ---------------------------------------------------------------------------
// POSITIVE 7. Accepted, and nothing has proved who answered.
// ---------------------------------------------------------------------------
async function withoutMutualNothingProvesWhoAnswered(serviceTicket) {
  log.debug("Entering withoutMutualNothingProvesWhoAnswered().");
  log.info("=== No mutual authentication ===");
  const built = await buildInit(serviceTicket, {});
  const resp = await get("/spnego/protected?mutual=off", built.token);
  assert.strictEqual(resp.status, 200, "the ticket is still accepted");
  const parsed = spnego.decodeNegotiationToken(resp.negotiate);
  assert.strictEqual(parsed.negState, spnego.NEG_STATE.ACCEPT_COMPLETED,
      "and the context is complete");
  assert.strictEqual(parsed.responseToken, null,
    "but there is no AP-REP, so NOTHING has proved the server is who it " +
    "claims to be. That is a legitimate outcome and it is the difference " +
    "between authenticating a client and authenticating a connection.");
  log.info("accepted with no proof of the server's identity, and it says so");
  log.debug("Leaving withoutMutualNothingProvesWhoAnswered().");
}

// ---------------------------------------------------------------------------
// NEGATIVE 1. No mechanism in common.
// ---------------------------------------------------------------------------
async function noMechanismInCommonIsRejected(serviceTicket) {
  log.debug("Entering noMechanismInCommonIsRejected().");
  log.info("=== NEGATIVE: no mechanism in common ===");
  const built = await buildInit(serviceTicket, {
    mechTypes: ["1.3.6.1.4.1.311.2.2.10", "1.3.6.1.4.1.311.2.2.30"]
  });
  const resp = await get("/spnego/protected", built.token);
  assert.strictEqual(resp.status, 401,
    "a client offering only mechanisms the acceptor cannot perform must be " +
    "refused, got " + resp.status);
  const parsed = spnego.decodeNegotiationToken(resp.negotiate);
  assert.strictEqual(parsed.negState, spnego.NEG_STATE.REJECT,
      "with negState reject (2), got " + parsed.negStateName);
  assert.strictEqual(parsed.supportedMech, null,
    "and no supportedMech: there is nothing to select, and naming one here " +
    "would tell the client to retry with a mechanism that was never offered");

  // And the same when the acceptor is the one with nothing to offer.
  const good = await buildInit(serviceTicket, {});
  const none = await get("/spnego/protected?mech=none", good.token);
  assert.strictEqual(none.status, 401,
      "and an acceptor supporting nothing refuses a perfectly good ticket");
  assert.strictEqual(
    spnego.decodeNegotiationToken(none.negotiate).negState,
    spnego.NEG_STATE.REJECT, "with reject");
  log.info("both directions of `no mechanism in common` are rejected");
  log.debug("Leaving noMechanismInCommonIsRejected().");
}

// ---------------------------------------------------------------------------
// NEGATIVE 2. A mechanism list with no token: not a refusal.
//
// The interesting half is that this must NOT be a reject. A client that names
// its mechanisms and sends nothing is being pessimistic rather than wrong, and
// an acceptor that rejects it has broken every client that does not gamble.
// ---------------------------------------------------------------------------
async function aListWithNoTokenIsAnsweredWithAcceptIncomplete(serviceTicket) {
  log.debug("Entering aListWithNoTokenIsAnsweredWithAcceptIncomplete().");
  log.info("=== NEGATIVE: a mechanism list with no mechToken ===");
  const init = spnego.encodeNegTokenInit({ mechTypes: WINDOWS_MECHS });
  const resp = await get("/spnego/protected", init.token);
  assert.strictEqual(resp.status, 401, "not authenticated yet, so 401");
  const parsed = spnego.decodeNegotiationToken(resp.negotiate);
  assert.strictEqual(parsed.negState, spnego.NEG_STATE.ACCEPT_INCOMPLETE,
    "but accept-incomplete (1), NOT reject: the client named its mechanisms " +
    "and declined to gamble on one, which is legal and costs it the round " +
    "trip the optimistic token exists to avoid. Got " + parsed.negStateName);
  assert.strictEqual(parsed.supportedMech, spnego.KRB5_MECH_OID,
    "and the acceptor must say which mechanism it chose, or the client does " +
    "not know what token to build. Got " + parsed.supportedMech);
  log.info("a pessimistic NegTokenInit is answered with accept-incomplete");
  log.debug("Leaving aListWithNoTokenIsAnsweredWithAcceptIncomplete().");
}

// ---------------------------------------------------------------------------
// NEGATIVE 3. A mechListMIC over the WRONG BYTES.
//
// This is the case this test exists for. The ticket is perfect, the AP-REQ
// decrypts, the client is who it says it is — and the request is refused,
// because the MIC was computed over `[0] MechTypeList` rather than
// `MechTypeList`. Two bytes. RFC 4178 section 5 spells the distinction out
// because implementations kept getting it wrong, and an acceptor that let this
// through would have implemented the syntax and none of the protection.
// ---------------------------------------------------------------------------
async function aMicOverTheTaggedListIsRejected(serviceTicket) {
  log.debug("Entering aMicOverTheTaggedListIsRejected().");
  log.info("=== NEGATIVE: a mechListMIC over [0] MechTypeList ===");
  const built = await buildInit(serviceTicket, { mic: true,
      micOver: "tagged" });
  const resp = await get("/spnego/protected", built.token);
  assert.strictEqual(resp.status, 401,
    "a mechListMIC computed over the [0]-tagged form must be refused. The " +
    "ticket is perfectly good — what failed is the integrity check over the " +
    "mechanism list, and letting it through would leave the list forgeable. " +
    "Got " + resp.status);
  const parsed = spnego.decodeNegotiationToken(resp.negotiate);
  assert.strictEqual(parsed.negState, spnego.NEG_STATE.REJECT,
      "with reject, got " + parsed.negStateName);
  assert.ok(/mechListMIC/.test(resp.body),
      "and the page must name the MIC rather than the ticket: " +
      resp.body.slice(0, 400));
  log.info("a MIC over the tagged list is rejected, and named");
  log.debug("Leaving aMicOverTheTaggedListIsRejected().");
}

// ---------------------------------------------------------------------------
// NEGATIVE 4. A mechListMIC that was tampered with in transit.
// ---------------------------------------------------------------------------
async function aTamperedMicIsRejected(serviceTicket) {
  log.debug("Entering aTamperedMicIsRejected().");
  log.info("=== NEGATIVE: a tampered mechListMIC ===");
  const built = await client.buildApReq({
    ticket: serviceTicket,
    mutual: true,
    gssFlags: [gss.GSS_FLAG.MUTUAL, gss.GSS_FLAG.INTEG]
  });
  const mechListDer = spnego.mechTypeListDer(WINDOWS_MECHS);
  const mic = await spnego.computeMechListMic({
    key: built.subkey.key,
    etype: built.subkey.etype,
    role: "initiator",
    mechListDer: mechListDer,
    sequenceNumber: 0
  });
  // One byte of the checksum, flipped. The header stays intact so the token is
  // still well formed — the only thing wrong with it is that it is wrong.
  const tampered = prim.toBytes(mic).slice();
  tampered[tampered.length - 1] ^= 0x01;
  const init = spnego.encodeNegTokenInit({
    mechTypes: WINDOWS_MECHS,
    mechToken: built.token,
    mechListMic: tampered
  });
  const resp = await get("/spnego/protected", init.token);
  assert.strictEqual(resp.status, 401,
      "a mechListMIC with one bit flipped must be refused, got " +
      resp.status);
  assert.strictEqual(
    spnego.decodeNegotiationToken(resp.negotiate).negState,
    spnego.NEG_STATE.REJECT, "with reject");
  log.info("a tampered mechListMIC is rejected");
  log.debug("Leaving aTamperedMicIsRejected().");
}

// ---------------------------------------------------------------------------
// NEGATIVE 5. A downgraded mechanism list.
//
// The attack RFC 4178 section 5 exists to stop: an attacker on the wire strikes
// the client's preferred mechanism out of the list, so the acceptor selects a
// weaker one and neither end can tell. Here the AP-REQ is untouched and only
// the list is edited — the MIC the client computed no longer covers the list
// that arrived, and that is the whole detection.
// ---------------------------------------------------------------------------
async function anEditedMechanismListIsCaughtByTheMic(serviceTicket) {
  log.debug("Entering anEditedMechanismListIsCaughtByTheMic().");
  log.info("=== NEGATIVE: a downgraded mechanism list ===");
  const built = await client.buildApReq({
    ticket: serviceTicket,
    mutual: true,
    gssFlags: [gss.GSS_FLAG.MUTUAL, gss.GSS_FLAG.INTEG]
  });
  // The client signed the list it MEANT to send...
  const intended = [spnego.KRB5_MECH_OID, spnego.MS_KRB5_MECH_OID,
      "1.3.6.1.4.1.311.2.2.10"];
  const mic = await spnego.computeMechListMic({
    key: built.subkey.key,
    etype: built.subkey.etype,
    role: "initiator",
    mechListDer: spnego.mechTypeListDer(intended),
    sequenceNumber: 0
  });
  // ...and something on the wire sent a different one.
  const init = spnego.encodeNegTokenInit({
    mechTypes: [spnego.KRB5_MECH_OID],
    mechToken: built.token,
    mechListMic: mic
  });
  const resp = await get("/spnego/protected", init.token);
  assert.strictEqual(resp.status, 401,
    "an edited mechanism list must be caught by the MIC that covers it. " +
    "Everything else about this request is valid, which is exactly why the " +
    "MIC is the only thing that can notice. Got " + resp.status);
  assert.strictEqual(
    spnego.decodeNegotiationToken(resp.negotiate).negState,
    spnego.NEG_STATE.REJECT, "with reject");
  log.info("an edited mechanism list is caught");
  log.debug("Leaving anEditedMechanismListIsCaughtByTheMic().");
}

// ---------------------------------------------------------------------------
// NEGATIVE 6. A replayed AP-REQ, and the KRB-ERROR that says so.
// ---------------------------------------------------------------------------
async function aReplayedApReqIsRefusedAndSaysWhy(serviceTicket) {
  log.debug("Entering aReplayedApReqIsRefusedAndSaysWhy().");
  log.info("=== NEGATIVE: a replayed AP-REQ ===");
  const built = await buildInit(serviceTicket, {});
  const first = await get("/spnego/protected", built.token);
  assert.strictEqual(first.status, 200, "the first presentation is accepted");
  // Byte for byte the same token, which is what a captured request is.
  const second = await get("/spnego/protected", built.token);
  assert.strictEqual(second.status, 401,
    "the SAME token presented twice must be refused: the replay cache is the " +
    "only thing between a captured Authorization header and a free " +
    "impersonation. Got " + second.status);
  const parsed = spnego.decodeNegotiationToken(second.negotiate);
  assert.strictEqual(parsed.negState, spnego.NEG_STATE.REJECT, "with reject");
  const err = errorInside(second);
  assert.ok(err,
    "and the KRB-ERROR must be inside the responseToken. SPNEGO's negState " +
    "has no reason field at all, so an acceptor that swallows the " +
    "mechanism's error leaves a rejection that cannot be told from a wrong " +
    "password.");
  assert.strictEqual(err.errorCode, 34,
    "naming KRB_AP_ERR_REPEAT (34), got " + err.errorCode + " (" +
    err.error.name + ")");
  log.info("a replay is refused with KRB_AP_ERR_REPEAT inside responseToken");
  log.debug("Leaving aReplayedApReqIsRefusedAndSaysWhy().");
}

// ---------------------------------------------------------------------------
// THE SPN A CLIENT ACTUALLY DERIVES, which is not the configured one.
//
// RFC 4559 clients guess `HTTP/<the URL's host>` — browsers included — and
// nothing in SPNEGO carries the real SPN, so that guess is all a client has. This
// mock is reached at `localhost`, at `sts` on the containerized stack and at
// `127.0.0.1` from the AP page's defaults, while its configured account is
// `HTTP/web.example.com`: every one of those guesses used to be
// KDC_ERR_S_PRINCIPAL_UNKNOWN before the exchange even started, which is a real
// error with a real cause and exactly the wrong first experience of the workflow.
//
// The KDC now registers a service on first sight for the hosts it answers on, and
// the acceptor holds the key for those names as well as its canonical one. This
// section proves the whole chain with the DERIVED name — ticket issued, ticket
// accepted, page served — because the mock-side change is worth nothing if the
// acceptor still refuses what the KDC now issues.
// ---------------------------------------------------------------------------
async function theSpnAClientDerivesFromTheUrlIsAccepted(tgt) {
  log.debug("Entering theSpnAClientDerivesFromTheUrlIsAccepted().");
  log.info("=== the SPN a client derives from the URL ===");
  const advert = JSON.parse((await get("/spnego?format=json")).body);
  assert.ok(Array.isArray(advert.acceptsAnySpnForHosts) &&
      advert.acceptsAnySpnForHosts.length,
    "the advertisement must say which hosts this acceptor answers for, since " +
    "the client's derived SPN is otherwise a guess it cannot check: " +
    JSON.stringify(advert.acceptsAnySpnForHosts));
  assert.ok(advert.acceptsAnySpnForHosts.indexOf("localhost") !== -1,
    "including localhost, which is what this stack is reached by on a host " +
    "run: " + JSON.stringify(advert.acceptsAnySpnForHosts));

  for (const host of ["localhost", "sts", "127.0.0.1"]) {
    const derived = await getServiceTicket(tgt,
      { type: msgs.NAME_TYPE.SRV_HST, name: ["HTTP", host] });
    const built = await buildInit(derived, {});
    const resp = await get("/spnego/protected", built.token);
    // The failure detail is read only when there IS a failure: on a 200 the
    // responseToken is an AP-REP, and errorInside() throws on one — an assertion
    // message that cannot be built is a passing case that reports as a codec bug.
    const why = resp.status === 200 ? "" : (function () {
      const err = errorInside(resp);
      return err ? " with " + err.error.name : "";
    }());
    assert.strictEqual(resp.status, 200,
      "a ticket for HTTP/" + host + " — the SPN a client derives when it " +
      "reaches this service at " + host + " — must be accepted. Got " +
      resp.status + why);
    assert.ok(/protected content/i.test(resp.body || ""),
      "and the protected page must actually be served");
  }

  // The other side of the same coin: a host this service does not answer on is
  // still refused by the KDC, so the error stays reachable and this is not a
  // KDC that says yes to everything.
  let refused = null;
  try {
    await getServiceTicket(tgt,
      { type: msgs.NAME_TYPE.SRV_HST, name: ["HTTP", "elsewhere.invalid"] });
  } catch (e) {
    refused = e;
  }
  assert.ok(refused,
    "an SPN outside the hosts this mock answers on must still be refused by " +
    "the KDC — if everything is registered on demand, nothing above proves " +
    "the registration is scoped");
  log.info("the derived SPN works end to end, and a host outside the list " +
      "still does not");
  log.debug("Leaving theSpnAClientDerivesFromTheUrlIsAccepted().");
}

// ---------------------------------------------------------------------------
// NEGATIVE 7. A ticket for somebody else.
// ---------------------------------------------------------------------------
async function aTicketForAnotherServiceIsRefused(tgt) {
  log.debug("Entering aTicketForAnotherServiceIsRefused().");
  log.info("=== NEGATIVE: a ticket for another service ===");
  // A real ticket, from the same KDC, for a DIFFERENT service the mock also
  // holds a key for. It has to be a registered SPN or the KDC refuses to issue
  // it and this case never reaches the acceptor it is about.
  const other = await getServiceTicket(tgt,
    { type: msgs.NAME_TYPE.SRV_HST, name: ["HTTP", "frontend.example.com"] });
  const built = await buildInit(other, {});
  const resp = await get("/spnego/protected", built.token);
  assert.strictEqual(resp.status, 401,
    "a ticket naming a different service must be refused even though it is " +
    "a genuine ticket from the same KDC. Got " + resp.status);
  const err = errorInside(resp);
  assert.ok(err, "with a KRB-ERROR inside the responseToken");
  assert.strictEqual(err.errorCode, 35,
    "naming KRB_AP_ERR_NOT_US (35) — this ticket is not for me — got " +
    err.errorCode + " (" + err.error.name + ")");
  log.info("a ticket for another service is refused with NOT_US");
  log.debug("Leaving aTicketForAnotherServiceIsRefused().");
}

// ---------------------------------------------------------------------------
// NEGATIVE 8. A TGT presented as if it were a service ticket.
// ---------------------------------------------------------------------------
async function aTgtIsNotAServiceTicket(tgt) {
  log.debug("Entering aTgtIsNotAServiceTicket().");
  log.info("=== NEGATIVE: a TGT presented to a service ===");
  const built = await buildInit(tgt, {});
  const resp = await get("/spnego/protected", built.token);
  assert.strictEqual(resp.status, 401,
    "a TGT is a ticket to krbtgt, not to this service, and presenting one " +
    "is the commonest mistake a hand-written client makes. Got " +
    resp.status);
  const err = errorInside(resp);
  assert.ok(err && err.errorCode === 35,
    "and it must be refused with KRB_AP_ERR_NOT_US (35) rather than a " +
    "decryption failure, because naming the key would send somebody looking " +
    "at a keytab: got " + (err ? err.errorCode : "no error token"));
  log.info("a TGT is refused with NOT_US");
  log.debug("Leaving aTgtIsNotAServiceTicket().");
}

// ---------------------------------------------------------------------------
// NEGATIVE 9. The HTTP layer's own refusals.
// ---------------------------------------------------------------------------
async function theHttpLayerRefusesWhatItShould() {
  log.debug("Entering theHttpLayerRefusesWhatItShould().");
  log.info("=== NEGATIVE: the HTTP layer ===");

  // Another scheme entirely. Named, because a bare 401 sends people to look at
  // their ticket when what they sent was Basic.
  const basic = await new Promise(function (resolve, reject) {
    const request = http.request({
      host: "127.0.0.1", port: httpPort, method: "GET",
      path: "/spnego/protected",
      headers: { Authorization: "Basic YWxpY2U6cGFzc3dvcmQ=" }
    }, function (response) {
      let body = "";
      response.setEncoding("utf8");
      response.on("data", function (c) { body += c; });
      response.on("end", function () {
        resolve({ status: response.statusCode, body: body,
                  wwwAuthenticate: response.headers["www-authenticate"] });
      });
    });
    request.on("error", reject);
    request.end();
  });
  assert.strictEqual(basic.status, 401, "Basic must be refused");
  assert.ok(/Basic/.test(basic.body),
    "and the refusal must name the scheme that was offered, or the reader " +
    "goes looking at their ticket: " + basic.body.slice(0, 300));
  assert.strictEqual((basic.wwwAuthenticate || "").trim(), "Negotiate",
      "while still challenging with Negotiate");

  // Bytes that are not a negotiation token.
  const garbage = await get("/spnego/protected",
      new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x05]));
  assert.strictEqual(garbage.status, 401,
      "bytes that are not a negotiation token must be refused");
  assert.strictEqual(
    spnego.decodeNegotiationToken(garbage.negotiate).negState,
    spnego.NEG_STATE.REJECT, "with reject");

  // An AP-REQ sent bare, with neither wrapper. A real client mistake, and the
  // refusal has to name the wrapper rather than the ticket.
  const bareApReq = await get("/spnego/protected",
      new Uint8Array([0x6e, 0x03, 0x02, 0x01, 0x05]));
  assert.strictEqual(bareApReq.status, 401,
      "an unwrapped AP-REQ must be refused");
  assert.ok(/AP-REQ|wrapper|0x60/i.test(bareApReq.body),
    "and the refusal should point at the missing wrapper: " +
    bareApReq.body.slice(0, 400));

  log.info("the HTTP layer refuses what it should, and names what was wrong");
  log.debug("Leaving theHttpLayerRefusesWhatItShould().");
}

// ---------------------------------------------------------------------------
// NEGATIVE 10. A continuation with nothing to continue.
// ---------------------------------------------------------------------------
async function aContinuationWithNoNegotiationIsRefused() {
  log.debug("Entering aContinuationWithNoNegotiationIsRefused().");
  log.info("=== NEGATIVE: a continuation out of nowhere ===");
  const resp = await get("/spnego/protected",
    spnego.encodeNegTokenResp({ mechListMic: new Uint8Array(16) }));
  assert.strictEqual(resp.status, 401,
    "a bare NegTokenResp with no negotiation in progress must be refused, " +
    "got " + resp.status);
  assert.strictEqual(
    spnego.decodeNegotiationToken(resp.negotiate).negState,
    spnego.NEG_STATE.REJECT, "with reject");
  log.info("a continuation with nothing to continue is refused");
  log.debug("Leaving aContinuationWithNoNegotiationIsRefused().");
}

// ---------------------------------------------------------------------------
// The advertisement page, which is the one thing here that is not the protocol.
// ---------------------------------------------------------------------------
async function theProtectedPageIsAdvertised() {
  log.debug("Entering theProtectedPageIsAdvertised().");
  log.info("=== The advertisement ===");
  const html = await get("/spnego", null);
  assert.strictEqual(html.status, 200, "GET /spnego must answer 200");
  assert.ok(/HTTP\/web\.example\.com/.test(html.body),
    "and must publish the service principal name, because nothing in the " +
    "protocol exchange carries it — a client derives it from the URL, which " +
    "is why so many SPNEGO failures leave no evidence on the wire: " +
    html.body.slice(0, 300));
  assert.ok(/spnego\/protected/.test(html.body),
      "and must link the protected resource");

  const json = await get("/spnego?format=json", null);
  assert.strictEqual(json.status, 200, "?format=json must answer 200");
  const parsed = JSON.parse(json.body);
  assert.strictEqual(parsed.servicePrincipalName,
      "HTTP/web.example.com@EXAMPLE.COM",
      "with the SPN, got " + parsed.servicePrincipalName);
  assert.ok(parsed.mechanisms.some(function (m) {
    return m.oid === spnego.KRB5_MECH_OID;
  }), "and the mechanisms it accepts");
  log.info("the protected page is advertised, in both forms");
  log.debug("Leaving theProtectedPageIsAdvertised().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. SPNEGO over HTTP against the mock KDC and the " +
      "mock's protected page.");

  const kdcPath = stsModule("krb5_kdc.js");
  const appPath = stsModule("app.js");
  const spnegoPath = stsModule("spnego.js");
  if (!kdcPath || !appPath || !spnegoPath) {
    throw new Error("could not find the mock KDC, the express app and the " +
      "SPNEGO module (sts/krb5_kdc.js, sts/app.js, sts/spnego.js). sts/ is a " +
      "SUBMODULE — run `git submodule update --init sts`; an uninitialised " +
      "submodule is an EMPTY DIRECTORY rather than a missing one. If the " +
      "submodule IS initialised and only spnego.js is missing, the gitlink " +
      "predates it: push mock-sts and bump it.");
  }
  process.env.KRB5_REALM = REALM;
  process.env.KRB5_KDC_PORT = "0";
  process.env.KRB5_SERVICE_PORT = "0";

  let kdcModule;
  let app;
  try {
    kdcModule = require(kdcPath);
    app = require(appPath);
    // Requiring it registers /spnego and /spnego/protected on that app — the
    // mock's whole installation mechanism, and the reason there is nothing to
    // start here beyond the listener below.
    require(spnegoPath);
  } catch (e) {
    if (/Cannot find module/.test(e.message)) {
      throw new Error("the mock's SPNEGO module loaded but one of its own " +
        "dependencies did not: " + e.message + ". tests/Dockerfile copies " +
        "the sts/ modules individually — that set is the transitive closure " +
        "of what these files require, and it has to be recomputed when any " +
        "of them grows a new require.");
    }
    throw e;
  }

  const kdcListeners = kdcModule.listen(0);
  await kdcListeners.whenReady;
  kdcPort = kdcListeners.port;
  const server = await new Promise(function (resolve) {
    const s = app.listen(0, "127.0.0.1", function () { resolve(s); });
  });
  httpPort = server.address().port;
  log.info("the KDC is on " + kdcPort + " and the protected page is on " +
      httpPort);

  try {
    const tgt = await getTgt("alice");
    const serviceTicket = await getServiceTicket(tgt);

    await theProtectedPageIsAdvertised();
    await theFirstRequestIsRefusedWithABareChallenge();
    await theOptimisticTokenAuthenticatesInOneRoundTrip(serviceTicket);
    await theMechListMicIsVerifiedInBothDirections(serviceTicket);
    await theMicrosoftKerberosOidIsAccepted(serviceTicket);
    await aBareKerberosTokenIsAcceptedAndSaidToBeOne(serviceTicket);
    await requestMicCostsASecondRoundTripAndCompletes(serviceTicket);
    await withoutMutualNothingProvesWhoAnswered(serviceTicket);

    await noMechanismInCommonIsRejected(serviceTicket);
    await aListWithNoTokenIsAnsweredWithAcceptIncomplete(serviceTicket);
    await aMicOverTheTaggedListIsRejected(serviceTicket);
    await aTamperedMicIsRejected(serviceTicket);
    await anEditedMechanismListIsCaughtByTheMic(serviceTicket);
    await aReplayedApReqIsRefusedAndSaysWhy(serviceTicket);
    await theSpnAClientDerivesFromTheUrlIsAccepted(tgt);
    await aTicketForAnotherServiceIsRefused(tgt);
    await aTgtIsNotAServiceTicket(tgt);
    await theHttpLayerRefusesWhatItShould();
    await aContinuationWithNoNegotiationIsRefused();
    log.info("Test completed successfully.");
  } finally {
    try {
      kdcListeners.tcp.close();
    } catch (e) {
      // Already closed. This teardown runs after a failure that may itself
      // have closed the listener, and reporting a second close would bury the
      // failure that ended the run.
    }
    try {
      kdcListeners.udp.close();
    } catch (e) {
      // Already closed — same reason as above.
    }
    try {
      server.close();
    } catch (e) {
      // Already closed — same reason as above.
    }
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("krb5_spnego_http")
  .description("SPNEGO over HTTP end to end, with the negatives that make an " +
      "acceptor worth anything.")
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
