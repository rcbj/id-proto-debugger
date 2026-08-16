// File: krb5_real_dc.js
//
// ---------------------------------------------------------------------------
// The Kerberos codec against a REAL Microsoft KDC.
//
// Every other Kerberos test in this suite runs against the mock KDC in the
// rcbj/mock-sts submodule. That mock was written from the same reading of RFC
// 4120 and [MS-PAC] as the client it is being used to check, so the two agree
// by construction — and a disagreement with Windows would not show up in any of
// them. This test is the one that can only pass if the client interoperates
// with software this project did not write. docs/kerberos.md names it as the
// open risk; this is the thing that closes it.
//
// WHAT IT DRIVES. A single-DC forest on EC2, built by
// infra/terraform-krb5 and torn down after the run:
//
//   1. a bare AS-REQ, which a real AD KDC refuses with PREAUTH_REQUIRED while
//      naming the salt it wants — the salt is the first place a client and a
//      real DC part company, because AD derives it as <REALM><samAccountName>
//      with no separator and gets it from nowhere else;
//   2. an AS-REQ carrying PA-ENC-TIMESTAMP, which yields a TGT;
//   3. a TGS-REQ for the service's SPN, which yields a service ticket;
//   4. the service ticket DECRYPTED with the key Microsoft's own ktpass wrote
//      into a keytab — so krb5_keytab.js is parsing a real Microsoft file, not
//      one this project generated;
//   5. the PAC inside that ticket, parsed and its server signature verified;
//   6. an AP-REQ built by krb5_client.js and verified against the same key.
//
// WHAT GATES IT. Six environment variables, all supplied by infra/krb5-test.sh
// from the Terraform outputs. run-report.js skips this job when KRB5_DC_HOST is
// unset and says so; if the job DOES run, every variable is asserted rather
// than defaulted, because a real-DC test that quietly falls back to the mock
// is worse than no test at all.
//
// No browser, and no local services: node talks to the KDC through the api's
// own relay module, which is also the path the application uses.
// ---------------------------------------------------------------------------
const assert = require("assert");
const path = require("path");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "krb5_real_dc",
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
const gss = shared("krb5_gss.js");

function apiModule(name) {
  return paths.requireSharedModule(
    [path.join(__dirname, "..", "api", name), path.join(__dirname, name)],
    name);
}
const relayMod = apiModule("krb5_relay.js");
const ssrfGuard = apiModule("ssrf_guard.js");

// ---------------------------------------------------------------------------
// The environment, asserted rather than defaulted.
// ---------------------------------------------------------------------------
const ENV = {
  host: process.env.KRB5_DC_HOST,
  port: parseInt(process.env.KRB5_DC_PORT || "88", 10),
  realm: process.env.KRB5_REALM,
  user: process.env.KRB5_USER,
  password: process.env.KRB5_PASSWORD,
  spn: process.env.KRB5_SPN,
  keytabB64: process.env.KRB5_KEYTAB_B64
};

function requireEnvironment() {
  log.debug("Entering requireEnvironment().");
  const missing = Object.keys(ENV).filter(function (k) {
    return ENV[k] === undefined || ENV[k] === "";
  });
  assert.strictEqual(missing.length, 0,
    "this test drives a REAL domain controller and every one of its inputs " +
    "comes from the Terraform outputs. Missing: " + missing.join(", ") + ". " +
    "Run it through infra/krb5-test.sh, which applies the stack, waits for " +
    "the bootstrap, exports these and tears the stack down afterwards. It is " +
    "deliberately not defaulted: a real-DC test that silently falls back to " +
    "the mock KDC would report a pass for the one thing it exists to check.");
  assert.ok(ENV.port > 0 && ENV.port < 65536,
    "KRB5_DC_PORT is not a port: " + process.env.KRB5_DC_PORT);
  assert.ok(/@/.test(ENV.spn) === false,
    "KRB5_SPN should be the bare principal (HTTP/host.realm), not " +
    "principal@REALM: " + ENV.spn);
  log.info("Driving " + ENV.host + ":" + ENV.port + " realm=" + ENV.realm +
    " user=" + ENV.user + " spn=" + ENV.spn);
  log.debug("Leaving requireEnvironment().");
}

// ---------------------------------------------------------------------------
// Transport. The api's relay is used rather than a bare socket because it is
// the path the application itself takes to a KDC, so a change that breaks the
// relay against a real DC fails here too.
// ---------------------------------------------------------------------------
const quiet = {
  debug: function () {},
  info: function () {},
  warn: function () {},
  error: function () {}
};
let relay = null;

function makeRelay() {
  log.debug("Entering makeRelay().");
  const cfg = Object.assign({}, appconfig, {
    krb5AllowedPorts: [ENV.port],
    krb5RelayTimeoutMs: 20000,
    krb5MaxMessageBytes: 256 * 1024
  });
  relay = relayMod.createRelay(cfg, ssrfGuard.createGuard(cfg, quiet), quiet);
  log.debug("Leaving makeRelay().");
}

async function exchange(message, transport) {
  log.debug("Entering exchange(). transport=" + (transport || "tcp"));
  const result = await relay.send({
    host: ENV.host,
    port: ENV.port,
    transport: transport || "tcp",
    message: Buffer.from(message)
  });
  log.debug("Leaving exchange().");
  return {
    raw: Buffer.from(result.reply),
    decoded: msgs.readKdcResponse(Buffer.from(result.reply))
  };
}

let nonceCounter = 0x51150000;
function nextNonce() {
  log.debug("Entering nextNonce().");
  nonceCounter += 1;
  log.debug("Leaving nextNonce().");
  return nonceCounter;
}

function principal(name) {
  log.debug("Entering principal().");
  log.debug("Leaving principal().");
  return { type: msgs.NAME_TYPE.PRINCIPAL, name: [name] };
}

function spnPrincipal(spn) {
  log.debug("Entering spnPrincipal().");
  log.debug("Leaving spnPrincipal().");
  return { type: msgs.NAME_TYPE.SRV_INST, name: spn.split("/") };
}

function buildAsReq(padata) {
  log.debug("Entering buildAsReq().");
  log.debug("Leaving buildAsReq().");
  return msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.AS_REQ,
    padata: padata || [],
    reqBody: {
      kdcOptions: [msgs.KDC_OPTION.FORWARDABLE, msgs.KDC_OPTION.RENEWABLE],
      cname: principal(ENV.user),
      realm: ENV.realm,
      sname: { type: msgs.NAME_TYPE.SRV_INST, name: ["krbtgt", ENV.realm] },
      till: new Date(Date.now() + 8 * 3600 * 1000),
      nonce: nextNonce(),
      // AES first. Windows still offers RC4 on many domains and a client that
      // lets it win tests the weaker path by accident.
      etypes: [18, 17, 23]
    }
  });
}

// ---------------------------------------------------------------------------
// 1. The refusal, and the salt inside it.
// ---------------------------------------------------------------------------
async function theKdcDemandsPreAuthAndNamesItsSalt() {
  log.debug("Entering theKdcDemandsPreAuthAndNamesItsSalt().");
  log.info("=== A bare AS-REQ ===");
  const reply = await exchange(buildAsReq());
  assert.strictEqual(reply.decoded.kind, "KRB-ERROR",
    "a real AD KDC refuses an AS-REQ with no pre-authentication. This one " +
    "answered " + reply.decoded.kind + ", which means the account is " +
    "flagged DONT_REQUIRE_PREAUTH and the run is not testing what it claims.");
  const err = reply.decoded.error;
  assert.strictEqual(err.error.name, "KDC_ERR_PREAUTH_REQUIRED",
    "expected KDC_ERR_PREAUTH_REQUIRED, got " + err.error.name +
    " (" + err.errorCode + ")");

  const info = etypeInfoFrom(err);
  assert.ok(info, "the KRB-ERROR carried no PA-ETYPE-INFO2, so the client " +
    "has no salt to derive a key with. Windows always sends one on a preauth " +
    "refusal; its absence means the e-data did not parse.");
  assert.strictEqual(info.etype, 18,
    "the KDC should prefer aes256-cts-hmac-sha1-96 (18); it named etype " +
    info.etype + ". A domain answering RC4 here has AES disabled on the " +
    "account, which the bootstrap sets explicitly.");

  // The salt is the part a mock cannot teach you. AD builds it as the realm
  // concatenated with the sAMAccountName, no separator, realm upper-cased and
  // the account name in its stored case.
  const expected = ENV.realm + ENV.user;
  assert.strictEqual(info.salt, expected,
    "Active Directory derives a user's AES salt as <REALM><samAccountName> " +
    "with no separator. Expected " + JSON.stringify(expected) + ", the KDC " +
    "sent " + JSON.stringify(info.salt) + ". If these differ the password " +
    "will derive the wrong key and every later step fails as a bad password.");
  log.info("PREAUTH_REQUIRED, etype 18, salt " + JSON.stringify(info.salt));
  log.debug("Leaving theKdcDemandsPreAuthAndNamesItsSalt().");
  return info;
}

function etypeInfoFrom(err) {
  log.debug("Entering etypeInfoFrom().");
  const list = (err && err.eDataPaData) || [];
  const info2 = list.filter(function (pa) {
    return pa.type === msgs.PA_TYPE.ETYPE_INFO2;
  })[0];
  if (!info2) {
    log.debug("Leaving etypeInfoFrom(). None.");
    return null;
  }
  const entries = msgs.readEtypeInfo2(info2.value);
  const best = entries.filter(function (e) { return e.etype === 18; })[0] ||
    entries[0];
  log.debug("Leaving etypeInfoFrom(). ETYPE-INFO2.");
  return best;
}

// ---------------------------------------------------------------------------
// 2. The TGT.
// ---------------------------------------------------------------------------
async function theRealKdcIssuesATgt(info) {
  log.debug("Entering theRealKdcIssuesATgt().");
  log.info("=== AS-REQ with PA-ENC-TIMESTAMP ===");
  const profile = kcrypto.etypeById(info.etype);
  const clientKey = await profile.stringToKey(ENV.password,
    prim.utf8(info.salt), info.s2kparams);

  const stamp = msgs.encPaEncTsEnc(new Date(), 0);
  const padata = [{
    type: msgs.PA_TYPE.ENC_TIMESTAMP,
    value: msgs.encEncryptedData({
      etype: info.etype,
      cipher: await profile.encrypt(clientKey,
        kcrypto.KEY_USAGE.AS_REQ_PA_ENC_TIMESTAMP, stamp)
    })
  }];

  const reply = await exchange(buildAsReq(padata));
  assert.strictEqual(reply.decoded.kind, "AS-REP",
    "the KDC did not issue a ticket. It said: " +
    (reply.decoded.error ? reply.decoded.error.error.name
      : JSON.stringify(reply.decoded).slice(0, 200)));

  const rep = reply.decoded.rep;
  const part = msgs.readEncKdcRepPart(await profile.decrypt(clientKey,
    kcrypto.KEY_USAGE.AS_REP_ENCPART, rep.encPart.cipher));
  assert.ok(part.key && part.key.key,
    "the AS-REP's encrypted part carried no session key.");
  assert.strictEqual(part.key.etype, 18,
    "the session key should be aes256; the KDC chose etype " + part.key.etype);
  assert.strictEqual(rep.crealm, ENV.realm, "the reply names the wrong realm.");

  log.info("TGT issued, session etype " + part.key.etype + ", valid to " +
    (part.endtime && part.endtime.toISOString()));
  log.debug("Leaving theRealKdcIssuesATgt().");
  return {
    ticket: rep.ticket,
    sessionKey: part.key.key,
    etype: part.key.etype,
    client: rep.cname,
    realm: rep.crealm
  };
}

// ---------------------------------------------------------------------------
// 3. The service ticket.
// ---------------------------------------------------------------------------
async function theTgsExchangeIssuesAServiceTicket(tgt) {
  log.debug("Entering theTgsExchangeIssuesAServiceTicket().");
  log.info("=== TGS-REQ for " + ENV.spn + " ===");
  const built = await client.buildTgsReq({
    tgt: tgt,
    sname: spnPrincipal(ENV.spn),
    subkey: null
  });
  const sent = await exchange(built.request);
  const result = await client.readTgsRep({
    tgt: tgt,
    reply: sent.raw,
    nonce: built.nonce,
    subkey: null
  });
  assert.ok(result.ok,
    "no service ticket. The KDC said: " +
    (result.error ? result.error.error.name +
      " — S_PRINCIPAL_UNKNOWN here means the SPN is not mapped to the " +
      "service account, which the bootstrap asserts with setspn -L"
      : "unknown"));
  assert.deepStrictEqual(result.service.name, ENV.spn.split("/"),
    "the ticket names " + (result.service.name || []).join("/") +
    " rather than " + ENV.spn + ".");
  log.info("Service ticket issued for " + ENV.spn + " (" +
    kcrypto.etypeName(result.etype) + ", opened with " + result.openedWith +
    ")");
  log.debug("Leaving theTgsExchangeIssuesAServiceTicket().");
  return result;
}

// ---------------------------------------------------------------------------
// 4. The keytab Microsoft wrote, and the ticket it opens.
// ---------------------------------------------------------------------------
async function theKeytabOpensTheServiceTicket(serviceTicket) {
  log.debug("Entering theKeytabOpensTheServiceTicket().");
  log.info("=== ktpass keytab -> decrypt the ticket ===");
  const keytab = keytabMod.parseKeytab(Buffer.from(ENV.keytabB64, "base64"));
  assert.ok(keytab && keytab.entries && keytab.entries.length,
    "krb5_keytab.js read no entries out of the file ktpass produced. This " +
    "is a real Microsoft-generated keytab, so a parse failure here is a " +
    "finding about the parser rather than about the file.");
  log.info("keytab v" + keytab.version.toString(16) + ", " +
    keytab.entries.length + " entry(ies): " +
    keytab.entries.map(function (e) {
      return e.principal + " kvno " + e.kvno + " " + e.etypeName;
    }).join("; "));

  const wanted = ENV.spn + "@" + ENV.realm;
  const entry = keytab.entries.filter(function (e) {
    return e.principal === wanted;
  })[0] || keytab.entries[0];
  assert.ok(entry, "no keytab entry for " + wanted);
  assert.strictEqual(entry.principal, wanted,
    "the keytab's principal is " + entry.principal + ", not " + wanted);
  assert.strictEqual(entry.etype, 18,
    "ktpass was asked for AES256-SHA1, so the entry should be etype 18; it " +
    "is " + entry.etype + " (" + entry.etypeName + ").");

  const profile = kcrypto.etypeById(entry.etype);
  const plain = await profile.decrypt(entry.key,
    kcrypto.KEY_USAGE.KDC_REP_TICKET,
    serviceTicket.ticket.encPart.cipher);
  const encTicket = msgs.readEncTicketPart(plain);
  assert.ok(encTicket && encTicket.key && encTicket.key.key,
    "the ticket decrypted but carried no session key.");
  assert.strictEqual(prim.toHex(encTicket.key.key),
    prim.toHex(serviceTicket.sessionKey),
    "the session key inside the TICKET and the one the KDC gave the client " +
    "must be the same bytes; they are encrypted for different readers.");

  const cname = (encTicket.cname && encTicket.cname.name || []).join("/");
  assert.strictEqual(cname, ENV.user,
    "the ticket names " + JSON.stringify(cname) + " rather than " +
    JSON.stringify(ENV.user) + ".");
  log.info("Ticket decrypts with the ktpass key; client is " + cname);
  log.debug("Leaving theKeytabOpensTheServiceTicket().");
  return {
    encTicket: encTicket,
    serviceKey: { etype: entry.etype, key: entry.key },
    profile: profile
  };
}

// ---------------------------------------------------------------------------
// 5. The PAC, which is the least forgiving structure in the protocol and the
//    one a mock is least likely to have got right.
// ---------------------------------------------------------------------------
async function theTicketCarriesAWindowsPac(opened) {
  log.debug("Entering theTicketCarriesAWindowsPac().");
  log.info("=== the PAC ===");
  const found = pacMod.findPacs(opened.encTicket.authorizationData || []);
  assert.ok(found && found.length,
    "the service ticket carries no PAC. Windows puts one in every ticket it " +
    "issues, nested inside AD-IF-RELEVANT, so its absence means the " +
    "authorization-data was not walked correctly rather than that the KDC " +
    "omitted it.");
  log.info("PAC found at " + found[0].path);

  const pac = pacMod.parsePac(found[0].bytes);
  assert.ok(pac, "the PAC did not parse.");
  assert.ok(!pac.problems || !pac.problems.length,
    "krb5_pac.js reported problems with a PAC minted by Windows itself, " +
    "which makes each one a finding: " + JSON.stringify(pac.problems));

  const logon = pacMod.bufferOfType(pac, pacMod.TYPE.LOGON_INFO);
  assert.ok(logon && logon.parsed, "the PAC has no Logon Information buffer.");
  assert.strictEqual(String(logon.parsed.effectiveName).toLowerCase(),
    ENV.user.toLowerCase(),
    "the PAC's logon information names " +
    JSON.stringify(logon.parsed.effectiveName) + " rather than " +
    JSON.stringify(ENV.user) + ".");
  assert.ok(logon.parsed.userSid, "the PAC carries no user SID, which is the " +
    "thing a Windows service actually authorizes on.");
  log.info("PAC names " + logon.parsed.effectiveName + ", SID " +
    logon.parsed.userSid + ", " +
    ((logon.parsed.groups || []).length) + " group(s)");

  // The server signature is the one a service can check on its own: taken over
  // the PAC with the signatures zeroed, using the service's long-term key. The
  // KDC signature needs the krbtgt key, which a service does not have and this
  // test deliberately never learns.
  const sigs = await pacMod.verifySignatures(pac, {
    serverKey: opened.serviceKey
  });
  const server = sigs.filter(function (x) {
    return x.type === pacMod.TYPE.SERVER_CHECKSUM;
  })[0];
  assert.ok(server, "the PAC has no server signature buffer.");
  assert.strictEqual(server.verified, true,
    "the PAC's server signature did not verify with the service key from " +
    "the keytab. That is the check a Kerberised service makes before " +
    "trusting a PAC, and it failing against a real DC means our signature " +
    "coverage or our zeroing is wrong: " + server.note);
  log.info("PAC server signature (" + server.signatureTypeName +
    ") verifies with the ktpass key");
  log.debug("Leaving theTicketCarriesAWindowsPac().");
}

// ---------------------------------------------------------------------------
// 6. The AP-REQ.
// ---------------------------------------------------------------------------
async function theApReqVerifiesAgainstTheServiceKey(serviceTicket, opened) {
  log.debug("Entering theApReqVerifiesAgainstTheServiceKey().");
  log.info("=== AP-REQ ===");
  const built = await client.buildApReq({
    ticket: serviceTicket,
    mutual: true
  });
  assert.ok(built && built.token && built.token.length,
    "buildApReq() produced no GSS token.");
  assert.strictEqual(built.token[0], 0x60,
    "a service is handed an InitialContextToken, which begins with 0x60.");

  const decoded = gss.decodeInitialContextToken(built.token);
  assert.strictEqual(decoded.mechOid, "1.2.840.113554.1.2.2",
    "the token must name the Kerberos v5 mechanism.");
  assert.strictEqual(decoded.tokIdName, "AP_REQ",
    "the token id must be AP_REQ (01 00), got " + decoded.tokIdName);
  const apReq = msgs.readApReq(decoded.inner);

  // What the service does on receipt: open the ticket with its long-term key,
  // then open the authenticator with the session key that was inside it.
  const ticketPlain = await opened.profile.decrypt(opened.serviceKey.key,
    kcrypto.KEY_USAGE.KDC_REP_TICKET, apReq.ticket.encPart.cipher);
  const encTicket = msgs.readEncTicketPart(ticketPlain);
  const sessionProfile = kcrypto.etypeById(encTicket.key.etype);
  const authPlain = await sessionProfile.decrypt(encTicket.key.key,
    kcrypto.KEY_USAGE.AP_REQ_AUTH, apReq.authenticator.cipher);
  const authenticator = msgs.readAuthenticator(authPlain);

  assert.strictEqual((authenticator.cname.name || []).join("/"), ENV.user,
    "the authenticator names the wrong client.");
  assert.strictEqual(authenticator.crealm, ENV.realm,
    "the authenticator names the wrong realm.");
  const skewMs = Math.abs(Date.now() - authenticator.ctime.getTime());
  assert.ok(skewMs < 5 * 60 * 1000,
    "the authenticator's timestamp is " + Math.round(skewMs / 1000) + "s off " +
    "this clock; a real service would refuse it as outside the skew.");
  log.info("AP-REQ opens with the keytab key; authenticator names " +
    authenticator.cname.name.join("/") + "@" + authenticator.crealm);
  log.debug("Leaving theApReqVerifiesAgainstTheServiceKey().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. Kerberos against a real Windows KDC.");
  try {
    // Inside the try so a missing input is reported the same way a protocol
    // failure is — one logged error and exit 1, rather than a raw stack trace
    // that reads as a crash in the harness.
    requireEnvironment();
    makeRelay();
    const info = await theKdcDemandsPreAuthAndNamesItsSalt();
    const tgt = await theRealKdcIssuesATgt(info);
    const serviceTicket = await theTgsExchangeIssuesAServiceTicket(tgt);
    const opened = await theKeytabOpensTheServiceTicket(serviceTicket);
    await theTicketCarriesAWindowsPac(opened);
    await theApReqVerifiesAgainstTheServiceKey(serviceTicket, opened);
    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error && error.stack ? error.stack : String(error));
    process.exit(1);
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("krb5_real_dc")
  .description("Kerberos against a real Windows Server domain controller.")
  .addOption(new Option("-u, --url <url>",
    "Ignored; accepted so the runner can invoke every test the same way."))
  .action(function () {});

program.parse(process.argv).opts();

test();
