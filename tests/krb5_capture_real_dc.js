// File: krb5_capture_real_dc.js
//
// ---------------------------------------------------------------------------
// A TOOL, not a test. Records what a real Windows KDC actually put on the wire
// so that the recording can be asserted against forever, offline.
//
// WHY THIS EXISTS. tests/krb5_real_dc.js proves our CLIENT interoperates with
// Microsoft, but it can only run while a domain controller is up — which costs
// money, takes twenty minutes to build, and therefore runs approximately never.
// And it does not compare the MOCK KDC with Windows at all: it checks that our
// reader accepts what Windows sends, and our reader could be lenient enough to
// accept both Windows and a subtly wrong mock.
//
// So this captures the bytes. tests/krb5_windows_vectors.js then asserts
// against them on every ordinary run, with no AWS and no network — which turns
// one expensive afternoon into a permanent regression test.
//
// WHAT IS IN THE FILE. Every message in both directions, base64'd, plus the
// artifacts that can only be obtained with a key: the decrypted EncTicketPart
// and the PAC inside it. Also the service keytab, WITHOUT WHICH THE CAPTURE IS
// INERT — the ticket cannot be opened without it.
//
// ON THE SECRETS IN IT. The keytab and the account passwords are real, and they
// are also worthless: the realm they belong to is created per run and destroyed
// minutes later, exists only inside one VPC, and is never reachable again. They
// are kept because a capture that cannot be decrypted proves nothing. Do not
// copy this pattern for a realm that outlives its test.
//
// Usage (the same environment tests/krb5_real_dc.js takes):
//   node krb5_capture_real_dc.js --out captures/windows-2025.json
// ---------------------------------------------------------------------------
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "krb5_capture_real_dc",
  level: appconfig.LOG_LEVEL || "info"
});
log.info("Log initialized. logLevel=" + log.level());

function shared(name) {
  return paths.requireSharedModule(
    [__dirname + "/../common/krb5/" + name, __dirname + "/" + name], name);
}
const prim = shared("krb5_primitives.js");
const msgs = shared("krb5_messages.js");
const kcrypto = shared("krb5_crypto.js");
const keytabMod = shared("krb5_keytab.js");
const pacMod = shared("krb5_pac.js");
const client = shared("krb5_client.js");

function apiModule(name) {
  return paths.requireSharedModule(
    [path.join(__dirname, "..", "api", name), path.join(__dirname, name)],
    name);
}
const relayMod = apiModule("krb5_relay.js");
const ssrfGuard = apiModule("ssrf_guard.js");

const ENV = {
  host: process.env.KRB5_DC_HOST,
  port: parseInt(process.env.KRB5_DC_PORT || "88", 10),
  realm: process.env.KRB5_REALM,
  user: process.env.KRB5_USER,
  password: process.env.KRB5_PASSWORD,
  spn: process.env.KRB5_SPN,
  keytabB64: process.env.KRB5_KEYTAB_B64
};

const quiet = {
  debug: function () {},
  info: function () {},
  warn: function () {},
  error: function () {}
};
let relay = null;
const wire = [];

function b64(bytes) {
  log.debug("Entering b64().");
  log.debug("Leaving b64().");
  return Buffer.from(prim.toBytes(bytes)).toString("base64");
}

async function exchange(label, message) {
  log.debug("Entering exchange(). label=" + label);
  const result = await relay.send({
    host: ENV.host,
    port: ENV.port,
    transport: "tcp",
    message: Buffer.from(message)
  });
  const raw = Buffer.from(result.reply);
  wire.push({ label: label, request: b64(message), reply: b64(raw) });
  log.info("captured " + label + " (" + message.length + " -> " +
    raw.length + " bytes)");
  log.debug("Leaving exchange().");
  return { raw: raw, decoded: msgs.readKdcResponse(raw) };
}

let nonce = 0x7a110000;
function nextNonce() {
  log.debug("Entering nextNonce().");
  nonce += 1;
  log.debug("Leaving nextNonce().");
  return nonce;
}

function asReq(user, padata) {
  log.debug("Entering asReq().");
  log.debug("Leaving asReq().");
  return msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.AS_REQ,
    padata: padata || [],
    reqBody: {
      kdcOptions: [msgs.KDC_OPTION.FORWARDABLE, msgs.KDC_OPTION.RENEWABLE],
      cname: { type: msgs.NAME_TYPE.PRINCIPAL, name: [user] },
      realm: ENV.realm,
      sname: { type: msgs.NAME_TYPE.SRV_INST, name: ["krbtgt", ENV.realm] },
      till: new Date(Date.now() + 8 * 3600 * 1000),
      nonce: nextNonce(),
      etypes: [18, 17, 23]
    }
  });
}

async function capture(outPath) {
  log.debug("Entering capture().");
  const cfg = Object.assign({}, appconfig, {
    krb5AllowedPorts: [ENV.port],
    krb5RelayTimeoutMs: 20000,
    krb5MaxMessageBytes: 256 * 1024
  });
  relay = relayMod.createRelay(cfg, ssrfGuard.createGuard(cfg, quiet), quiet);

  // 1. The refusal, which carries ETYPE-INFO2 and therefore the salt.
  const bare = await exchange("as-req-no-preauth", asReq(ENV.user));
  assert.strictEqual(bare.decoded.kind, "KRB-ERROR", "expected a refusal");
  const info2 = (bare.decoded.error.eDataPaData || []).filter(function (pa) {
    return pa.type === msgs.PA_TYPE.ETYPE_INFO2;
  })[0];
  assert.ok(info2, "no ETYPE-INFO2 in the refusal");
  const entries = msgs.readEtypeInfo2(info2.value);
  const aes = entries.filter(function (e) { return e.etype === 18; })[0];
  assert.ok(aes, "the KDC offered no aes256");

  // 2. A WRONG password, so the capture carries a real PREAUTH_FAILED as well
  //    as a success. A negative from the real thing is worth as much as the
  //    positive: it is the shape a client has to tell apart from a wrong salt.
  const profile = kcrypto.etypeById(aes.etype);
  const wrongKey = await profile.stringToKey("not-the-password-" + Date.now(),
    prim.utf8(aes.salt), aes.s2kparams);
  const wrongPa = [{
    type: msgs.PA_TYPE.ENC_TIMESTAMP,
    value: msgs.encEncryptedData({
      etype: aes.etype,
      cipher: await profile.encrypt(wrongKey,
        kcrypto.KEY_USAGE.AS_REQ_PA_ENC_TIMESTAMP,
        msgs.encPaEncTsEnc(new Date(), 0))
    })
  }];
  const wrong = await exchange("as-req-wrong-password", asReq(ENV.user,
    wrongPa));
  assert.strictEqual(wrong.decoded.kind, "KRB-ERROR",
    "a wrong password must be refused");

  // 3. An account that does not exist — C_PRINCIPAL_UNKNOWN.
  const nobody = await exchange("as-req-unknown-principal",
    asReq("no-such-user-" + Date.now()));
  assert.strictEqual(nobody.decoded.kind, "KRB-ERROR", "expected a refusal");

  // 4. The real thing.
  const clientKey = await profile.stringToKey(ENV.password,
    prim.utf8(aes.salt), aes.s2kparams);
  const goodPa = [{
    type: msgs.PA_TYPE.ENC_TIMESTAMP,
    value: msgs.encEncryptedData({
      etype: aes.etype,
      cipher: await profile.encrypt(clientKey,
        kcrypto.KEY_USAGE.AS_REQ_PA_ENC_TIMESTAMP,
        msgs.encPaEncTsEnc(new Date(), 0))
    })
  }];
  const good = await exchange("as-req-preauth", asReq(ENV.user, goodPa));
  assert.strictEqual(good.decoded.kind, "AS-REP", "expected a ticket");
  const rep = good.decoded.rep;
  const part = msgs.readEncKdcRepPart(await profile.decrypt(clientKey,
    kcrypto.KEY_USAGE.AS_REP_ENCPART, rep.encPart.cipher));
  const tgt = {
    ticket: rep.ticket,
    sessionKey: part.key.key,
    etype: part.key.etype,
    client: rep.cname,
    realm: rep.crealm
  };

  // 5. The service ticket.
  const built = await client.buildTgsReq({
    tgt: tgt,
    sname: { type: msgs.NAME_TYPE.SRV_INST, name: ENV.spn.split("/") },
    subkey: null
  });
  const tgsSent = await exchange("tgs-req", built.request);
  const tgs = await client.readTgsRep({
    tgt: tgt, reply: tgsSent.raw, nonce: built.nonce, subkey: null
  });
  assert.ok(tgs.ok, "no service ticket");

  // 6. A TGS-REQ for an SPN nobody registered.
  //
  // Expected S_PRINCIPAL_UNKNOWN; what a real Windows DC actually does is
  // close the connection with a ZERO-LENGTH TCP frame, which api/krb5_frame.js
  // refuses — correctly, since an empty frame cannot be a Kerberos message.
  // That is a genuine interoperability observation rather than a failure of
  // this capture, so it is recorded and the capture continues. The refusal
  // text is recorded VERBATIM and may age as the message is improved; the
  // assertion in krb5_windows_vectors.js therefore matches on the byte count
  // and not on the sentence.
  let unknownSpnOutcome = null;
  try {
    const unknownSpn = await client.buildTgsReq({
      tgt: tgt,
      sname: {
        type: msgs.NAME_TYPE.SRV_INST,
        name: ["HTTP", "nothing-here-" + Date.now() + ".krb5test.local"]
      },
      subkey: null
    });
    const answer = await exchange("tgs-req-unknown-spn", unknownSpn.request);
    unknownSpnOutcome = {
      answered: true,
      kind: answer.decoded.kind,
      error: answer.decoded.error ? answer.decoded.error.error.name : null
    };
  } catch (e) {
    unknownSpnOutcome = { answered: false, relayRefusal: e.message };
    log.warn("unknown SPN: " + e.message);
  }

  // 7. What is only reachable with the service key: the ticket's inside, and
  //    the PAC. Recorded DECRYPTED as well as encrypted, so a reader of the
  //    fixture can check structure without holding the key.
  const keytab = keytabMod.parseKeytab(Buffer.from(ENV.keytabB64, "base64"));
  const entry = keytab.entries[0];
  const svcProfile = kcrypto.etypeById(entry.etype);
  const ticketPlain = await svcProfile.decrypt(entry.key,
    kcrypto.KEY_USAGE.KDC_REP_TICKET, tgs.ticket.encPart.cipher);
  const encTicket = msgs.readEncTicketPart(ticketPlain);
  const pacs = pacMod.findPacs(encTicket.authorizationData || []);
  assert.ok(pacs.length, "the service ticket carried no PAC");
  const pac = pacMod.parsePac(pacs[0].bytes);

  const out = {
    "//": "Captured from a real Windows Server domain controller. See " +
      "tests/krb5_capture_real_dc.js for what this is and why the secrets " +
      "in it are inert. Asserted by tests/krb5_windows_vectors.js.",
    capturedAt: new Date().toISOString(),
    source: {
      os: process.env.KRB5_DC_OS || "Windows Server 2025 Datacenter",
      amiName: process.env.KRB5_DC_AMI || null,
      realm: ENV.realm,
      user: ENV.user,
      spn: ENV.spn
    },
    salt: {
      etype: aes.etype,
      value: aes.salt,
      s2kparams: aes.s2kparams ? b64(aes.s2kparams) : null,
      offered: entries.map(function (e) {
        return { etype: e.etype, salt: e.salt };
      })
    },
    keytabB64: ENV.keytabB64,
    userPassword: ENV.password,
    wire: wire,
    decrypted: {
      encTicketPart: b64(ticketPlain),
      pacBytes: b64(pacs[0].bytes),
      pacPath: pacs[0].path,
      asRepEncPart: b64(await profile.decrypt(clientKey,
        kcrypto.KEY_USAGE.AS_REP_ENCPART, rep.encPart.cipher))
    },
    observed: {
      sessionEtype: part.key.etype,
      ticketEtype: rep.ticket.encPart.etype,
      ticketKvno: rep.ticket.encPart.kvno,
      serviceEtype: tgs.etype,
      keytabEtype: entry.etype,
      keytabKvno: entry.kvno,
      keytabPrincipal: entry.principal,
      pacBufferTypes: (pac.buffers || []).map(function (b) { return b.type; }),
      pacProblems: pac.problems || [],
      unknownSpn: unknownSpnOutcome
    }
  };

  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify(out, null, 2));
  log.info("wrote " + outPath + " (" + wire.length + " exchanges, " +
    fs.statSync(outPath).size + " bytes)");
  log.debug("Leaving capture().");
}

const program = new Command();
let outPath = path.join(__dirname, "captures", "windows-server-2025.json");
program
  .name("krb5_capture_real_dc")
  .description("Record a real Windows KDC's messages as a reusable fixture.")
  .addOption(new Option("-o, --out <path>", "Where to write the capture."))
  .action(function (options) {
    if (options.out) { outPath = path.resolve(options.out); }
  });
program.parse(process.argv);

capture(outPath).catch(function (error) {
  log.error(error && error.stack ? error.stack : String(error));
  process.exit(1);
});
