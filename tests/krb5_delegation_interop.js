// File: krb5_delegation_interop.js
//
// ---------------------------------------------------------------------------
// S4U2Self, classic S4U2Proxy and RBCD — the SAME assertions against EITHER
// KDC.
//
// WHY A SECOND DELEGATION TEST. tests/krb5_tgs_ap.js already drives S4U against
// the mock, and drives it harder than this does: it forges tickets, swaps keys
// and checks refusals a real domain controller cannot be persuaded to produce.
// That coverage stays where it is. What it cannot do is tell you whether the
// mock and Active Directory agree, because it only ever asks the mock — and the
// mock was written from the same reading of [MS-SFU] as the client it checks,
// so a shared misreading is invisible to both.
//
// This file is the other half: one set of assertions, run twice, once per KDC.
// The overlap with krb5_tgs_ap.js on the mock side is deliberate and is the
// whole point — if the two KDCs ever diverge, the same assertion fails on one
// and passes on the other, which is the only way the difference becomes
// visible. Do not "de-duplicate" this against that file; doing so removes the
// property it exists for.
//
// WHICH KDC. KRB5_DELEG_TARGET selects it:
//
//   mock     (default) the KDC in the sts/ submodule, started in-process on an
//            ephemeral port. No AWS, no network, no services.
//   windows  a real Windows Server domain controller, described by the JSON the
//            bootstrap uploaded — KRB5_DC_JSON names the file that
//            infra/krb5-test.sh has already fetched from S3.
//
// THE ONE ASYMMETRY THAT IS NOT A BUG. On the mock, a service principal's NAME
// is its SPN: `HTTP/frontend.example.com` is what the account is called and
// what the AS-REQ names. In AD those are two different things — the account is
// `svc-frontend` and the SPN is an attribute on it — so the AS
// exchange must name the ACCOUNT and the delegation must name the SPN. Every
// target below therefore carries both, and conflating them is the mistake this
// note exists to prevent: an AS-REQ for an SPN gets C_PRINCIPAL_UNKNOWN from
// Windows, which reads as a missing account rather than as the wrong name.
//
// Node only. Never skipped on the mock; the Windows job skips without a DC.
// ---------------------------------------------------------------------------
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "krb5_delegation_interop",
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
const pacMod = shared("krb5_pac.js");
const client = shared("krb5_client.js");

function apiModule(name) {
  return paths.requireSharedModule(
    [path.join(__dirname, "..", "api", name), path.join(__dirname, name)],
    name);
}
const relayMod = apiModule("krb5_relay.js");
const ssrfGuard = apiModule("ssrf_guard.js");

const TARGET = (process.env.KRB5_DELEG_TARGET || "mock").toLowerCase();
const quiet = {
  debug: function () {},
  info: function () {},
  warn: function () {},
  error: function () {}
};

let relay = null;
let kdcHost = "127.0.0.1";
let kdcPort = 0;
let kdcListeners = null;

// ---------------------------------------------------------------------------
// The fixture, in whichever shape this target has it.
//
// Each role carries `asName` (what an AS-REQ names) and `spn` (what delegation
// names). On the mock they are the same string; on Windows they are not. See
// the note at the top.
// ---------------------------------------------------------------------------
async function mockTarget() {
  log.debug("Entering mockTarget().");
  const kdcPath = paths.mockStsModule("krb5_kdc.js", function (m) {
    log.warn(m);
  });
  assert.ok(kdcPath, "could not find the mock KDC (sts/krb5_kdc.js). The " +
    "sts/ directory is a submodule; run `git submodule update --init sts`.");
  let kdcModule;
  try {
    kdcModule = require(kdcPath);
  } catch (e) {
    throw new Error("the mock KDC loaded but one of its own dependencies did " +
      "not: " + e.message + ". tests/Dockerfile copies the sts/ modules " +
      "individually, and that set has to be recomputed when one grows a new " +
      "require.");
  }
  kdcListeners = kdcModule.listen(0);
  await kdcListeners.whenReady;
  kdcPort = kdcListeners.port;
  const realm = "EXAMPLE.COM";
  const domain = "example.com";
  log.info("the mock KDC is on " + kdcPort);
  log.debug("Leaving mockTarget().");
  return {
    what: "the mock KDC",
    realm: realm,
    impersonate: "alice",
    frontend: {
      asName: "HTTP/frontend." + domain,
      spn: "HTTP/frontend." + domain,
      password: "frontend-service-password"
    },
    backend: {
      asName: "HTTP/backend." + domain,
      spn: "HTTP/backend." + domain,
      password: "backend-service-password"
    },
    notrusted: {
      asName: "HTTP/notrusted." + domain,
      spn: "HTTP/notrusted." + domain,
      password: "notrusted-service-password"
    },
    rbcd: {
      asName: "HTTP/rbcd." + domain,
      spn: "HTTP/rbcd." + domain,
      password: "rbcd-service-password"
    }
  };
}

function windowsTarget() {
  log.debug("Entering windowsTarget().");
  const file = process.env.KRB5_DC_JSON;
  assert.ok(file, "KRB5_DELEG_TARGET=windows needs KRB5_DC_JSON naming the " +
    "bootstrap's dc.json. infra/krb5-test.sh fetches it from the artifacts " +
    "bucket and sets this; it is not defaulted, because a delegation test " +
    "that quietly fell back to the mock would report a pass for the one " +
    "thing it exists to check.");
  assert.ok(fs.existsSync(file), "no such file: " + file);
  const dc = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.ok(dc.delegation && dc.delegation.frontend,
    "dc.json carries no delegation fixture. The stack was applied with " +
    "provision_delegation = false, or the bootstrap failed before it got " +
    "that far — check stage2.log in the artifacts bucket.");
  const d = dc.delegation;
  kdcHost = process.env.KRB5_DC_HOST || dc.kdc_host;
  kdcPort = parseInt(process.env.KRB5_DC_PORT || "88", 10);
  assert.ok(kdcHost, "no KDC address: set KRB5_DC_HOST.");
  const role = function (r) {
    assert.ok(d[r], "dc.json has no delegation role '" + r + "'");
    return { asName: d[r].account, spn: d[r].spn, password: d[r].password };
  };
  log.info("driving the real Windows KDC at " + kdcHost + ":" + kdcPort);
  log.debug("Leaving windowsTarget().");
  return {
    what: "a real Windows Server KDC",
    realm: dc.realm,
    impersonate: dc.test_user,
    frontend: role("frontend"),
    backend: role("backend"),
    notrusted: role("notrusted"),
    rbcd: role("rbcd")
  };
}

function makeRelay() {
  log.debug("Entering makeRelay().");
  // The key names here are the relay's own, not invented: see
  // tests/krb5_as_exchange.js, which builds the same shape.
  //
  // blockPrivateNetworkCalls is FALSE only for the in-process mock, which
  // listens on loopback — the address policy blocks that by default and
  // rightly, since a relay reaching 127.0.0.1 is the SSRF the guard exists for.
  // Against Windows the policy stays ON, and the public address passes it.
  const cfg = {
    blockPrivateNetworkCalls: TARGET === "mock",
    krb5AllowedPorts: [88, kdcPort],
    connectionTimeout: 5000,
    callTimeout: 20000,
    maxContentLength: 256 * 1024
  };
  cfg.blockPrivateNetworkCalls = (TARGET !== "mock");
  relay = relayMod.createRelay(cfg, ssrfGuard.createGuard(cfg, quiet), quiet);
  log.debug("Leaving makeRelay().");
}

async function exchange(message) {
  log.debug("Entering exchange().");
  const result = await relay.send({
    host: kdcHost,
    port: kdcPort,
    transport: "tcp",
    message: Buffer.from(message)
  });
  const raw = Buffer.from(result.reply);
  log.debug("Leaving exchange().");
  return { raw: raw, decoded: msgs.readKdcResponse(raw) };
}

let nonce = 0x4d100000;
function nextNonce() {
  log.debug("Entering nextNonce().");
  nonce += 1;
  log.debug("Leaving nextNonce().");
  return nonce;
}

function nameOf(text) {
  log.debug("Entering nameOf().");
  log.debug("Leaving nameOf().");
  return text.indexOf("/") >= 0
    ? { type: msgs.NAME_TYPE.SRV_INST, name: text.split("/") }
    : { type: msgs.NAME_TYPE.PRINCIPAL, name: [text] };
}

// ---------------------------------------------------------------------------
// A TGT for any principal, with the salt taken from the KDC rather than
// guessed.
//
// Asking for the salt is what makes this work on both KDCs from one code path:
// the mock salts a service as REALM + a squashed form of its name, Active
// Directory salts it as REALM + sAMAccountName, and neither is derivable from
// the other. The salt arrives in the PREAUTH_REQUIRED refusal, which is the
// only place it is ever published. See docs/kerberos.md.
// ---------------------------------------------------------------------------
async function tgtFor(principalText, password, realm, kdcOptions) {
  log.debug("Entering tgtFor(). principal=" + principalText);
  const bare = msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.AS_REQ,
    padata: [],
    reqBody: {
      kdcOptions: kdcOptions || [msgs.KDC_OPTION.FORWARDABLE,
        msgs.KDC_OPTION.RENEWABLE],
      cname: nameOf(principalText),
      realm: realm,
      sname: { type: msgs.NAME_TYPE.SRV_INST, name: ["krbtgt", realm] },
      till: new Date(Date.now() + 8 * 3600 * 1000),
      nonce: nextNonce(),
      etypes: [18, 17, 23]
    }
  });
  const refusal = await exchange(bare);
  assert.strictEqual(refusal.decoded.kind, "KRB-ERROR",
    "expected PREAUTH_REQUIRED for " + principalText + ", got " +
    refusal.decoded.kind);
  const pa = (refusal.decoded.error.eDataPaData || []).filter(function (p) {
    return p.type === msgs.PA_TYPE.ETYPE_INFO2;
  })[0];
  assert.ok(pa, "no ETYPE-INFO2 for " + principalText + ", so no salt");
  const entries = msgs.readEtypeInfo2(pa.value);
  const info = entries.filter(function (e) { return e.etype === 18; })[0] ||
    entries[0];
  const profile = kcrypto.etypeById(info.etype);
  const key = await profile.stringToKey(password, prim.utf8(info.salt || ""),
    info.s2kparams);

  const withPa = msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.AS_REQ,
    padata: [{
      type: msgs.PA_TYPE.ENC_TIMESTAMP,
      value: msgs.encEncryptedData({
        etype: info.etype,
        cipher: await profile.encrypt(key,
          kcrypto.KEY_USAGE.AS_REQ_PA_ENC_TIMESTAMP,
          msgs.encPaEncTsEnc(new Date(), 0))
      })
    }],
    reqBody: {
      kdcOptions: kdcOptions || [msgs.KDC_OPTION.FORWARDABLE,
        msgs.KDC_OPTION.RENEWABLE],
      cname: nameOf(principalText),
      realm: realm,
      sname: { type: msgs.NAME_TYPE.SRV_INST, name: ["krbtgt", realm] },
      till: new Date(Date.now() + 8 * 3600 * 1000),
      nonce: nextNonce(),
      etypes: [18, 17, 23]
    }
  });
  const reply = await exchange(withPa);
  assert.strictEqual(reply.decoded.kind, "AS-REP",
    "no TGT for " + principalText + ": " +
    (reply.decoded.error ? reply.decoded.error.error.name : "unknown"));
  const rep = reply.decoded.rep;
  const part = msgs.readEncKdcRepPart(await profile.decrypt(key,
    kcrypto.KEY_USAGE.AS_REP_ENCPART, rep.encPart.cipher));
  log.debug("Leaving tgtFor().");
  return {
    ticket: rep.ticket,
    sessionKey: part.key.key,
    etype: part.key.etype,
    client: rep.cname,
    realm: rep.crealm,
    longTermKey: { etype: info.etype, key: key },
    salt: info.salt
  };
}

// ---------------------------------------------------------------------------
// 1. S4U2Self, and whether the evidence comes back FORWARDABLE.
// ---------------------------------------------------------------------------
async function s4u2Self(t, role, expectForwardable) {
  log.debug("Entering s4u2Self(). role=" + role);
  const svc = t[role];
  log.info("=== S4U2Self as " + svc.asName + " for " + t.impersonate + " ===");
  const tgt = await tgtFor(svc.asName, svc.password, t.realm);

  const built = await client.buildS4u2SelfReq({
    tgt: tgt,
    user: { type: msgs.NAME_TYPE.PRINCIPAL, name: [t.impersonate] },
    userRealm: t.realm,
    sname: nameOf(svc.spn),
    nonce: nextNonce()
  });
  const sent = await exchange(built.request);
  const read = await client.readTgsRep({
    tgt: tgt, reply: sent.raw, nonce: built.nonce, subkey: null,
    requestedSname: built.sname
  });
  assert.ok(read.ok, "S4U2Self failed for " + svc.asName + ": " +
    (read.error ? read.error.error.name + " — " + (read.error.eText || "")
      : "unknown"));

  // The ticket names the IMPERSONATED user, not the service that asked.
  assert.strictEqual((read.client.name || []).join("/"), t.impersonate,
    "the S4U2Self ticket should name " + t.impersonate + "; it names " +
    (read.client.name || []).join("/"));

  // And the flag that decides whether classic S4U2Proxy can use it. This is
  // the protocol-transition half, granted by TrustedToAuthForDelegation on the
  // requesting account and by nothing else.
  const forwardable = (read.flagNames || [])
    .indexOf("forwardable") !== -1;
  assert.strictEqual(forwardable, expectForwardable,
    "S4U2Self for " + svc.asName + " returned a ticket that is " +
    (forwardable ? "FORWARDABLE" : "NOT forwardable") + "; expected the " +
    (expectForwardable ? "opposite, which means protocol transition " +
      "(TrustedToAuthForDelegation) is not in effect on that account"
      : "opposite, which means that account HAS protocol transition when the " +
        "fixture says it should not — the negative case below then proves " +
        "nothing"));
  log.info("S4U2Self ok: names " + t.impersonate + ", forwardable=" +
    forwardable);
  log.debug("Leaving s4u2Self().");
  return { tgt: tgt, evidence: read };
}

// ---------------------------------------------------------------------------
// 2. S4U2Proxy, by whichever of the two routes was asked for.
// ---------------------------------------------------------------------------
async function s4u2Proxy(t, from, toRole, resourceBased) {
  log.debug("Entering s4u2Proxy(). to=" + toRole + " rbcd=" + !!resourceBased);
  const target = t[toRole];
  log.info("=== S4U2Proxy to " + target.spn +
    (resourceBased ? " (resource-based)" : " (classic)") + " ===");
  const built = await client.buildS4u2ProxyReq({
    tgt: from.tgt,
    evidenceTicket: from.evidence.ticket,
    sname: nameOf(target.spn),
    nonce: nextNonce(),
    resourceBased: !!resourceBased
  });
  const sent = await exchange(built.request);
  const read = await client.readTgsRep({
    tgt: from.tgt, reply: sent.raw, nonce: built.nonce, subkey: null,
    requestedSname: built.sname
  });
  log.debug("Leaving s4u2Proxy().");
  return read;
}

async function classicS4u2ProxyReachesTheBackEnd(t) {
  log.debug("Entering classicS4u2ProxyReachesTheBackEnd().");
  const from = await s4u2Self(t, "frontend", true);
  const read = await s4u2Proxy(t, from, "backend", false);
  assert.ok(read.ok, "classic S4U2Proxy to " + t.backend.spn + " failed: " +
    (read.error ? read.error.error.name + " — " + (read.error.eText || "")
      : "unknown") + ". BADOPTION here usually means " +
    "msDS-AllowedToDelegateTo on " + t.frontend.asName + " does not name " +
    t.backend.spn + " exactly.");
  assert.strictEqual((read.client.name || []).join("/"), t.impersonate,
    "the delegated ticket must still name the impersonated user");
  assert.deepStrictEqual(read.service.name, t.backend.spn.split("/"),
    "the ticket is for the wrong service");

  // The PAC inside it must still be the impersonated user's, which is the
  // whole point: the back-end authorizes on that, not on who asked.
  const key = (await tgtFor(t.backend.asName, t.backend.password, t.realm))
    .longTermKey;
  const profile = kcrypto.etypeById(key.etype);
  const plain = await profile.decrypt(key.key,
    kcrypto.KEY_USAGE.KDC_REP_TICKET, read.ticket.encPart.cipher);
  const encTicket = msgs.readEncTicketPart(plain);
  const pacs = pacMod.findPacs(encTicket.authorizationData || []);
  assert.ok(pacs.length, "the delegated ticket carries no PAC");
  const pac = pacMod.parsePac(pacs[0].bytes);
  const logon = pacMod.bufferOfType(pac, pacMod.TYPE.LOGON_INFO);
  assert.ok(logon && logon.parsed, "no logon information in the PAC");
  assert.strictEqual(String(logon.parsed.effectiveName).toLowerCase(),
    t.impersonate.toLowerCase(),
    "the PAC in the delegated ticket names " + logon.parsed.effectiveName +
    " rather than the impersonated " + t.impersonate);
  log.info("classic S4U2Proxy ok: " + t.impersonate + " reached " +
    t.backend.spn + ", PAC names " + logon.parsed.effectiveName);
  log.debug("Leaving classicS4u2ProxyReachesTheBackEnd().");
}

async function resourceBasedS4u2ProxyReachesItsTarget(t) {
  log.debug("Entering resourceBasedS4u2ProxyReachesItsTarget().");
  const from = await s4u2Self(t, "frontend", true);
  const read = await s4u2Proxy(t, from, "rbcd", true);
  assert.ok(read.ok, "resource-based S4U2Proxy to " + t.rbcd.spn +
    " failed: " + (read.error ? read.error.error.name + " — " +
      (read.error.eText || "") : "unknown") + ". The permission for this " +
    "route lives on the TARGET, as msDS-AllowedToActOnBehalfOfOtherIdentity " +
    "on " + t.rbcd.asName + ", and must name " + t.frontend.asName + ".");
  assert.strictEqual((read.client.name || []).join("/"), t.impersonate,
    "the RBCD ticket must name the impersonated user");
  assert.deepStrictEqual(read.service.name, t.rbcd.spn.split("/"),
    "the RBCD ticket is for the wrong service");
  log.info("resource-based S4U2Proxy ok: " + t.impersonate + " reached " +
    t.rbcd.spn);
  log.debug("Leaving resourceBasedS4u2ProxyReachesItsTarget().");
}

// ---------------------------------------------------------------------------
// 3. The negative that names its own cause.
//
// svc-notrusted has the same msDS-AllowedToDelegateTo list as the front end and
// is NOT trusted for protocol transition. So S4U2Self still succeeds — that is
// the confusing part — and hands back a ticket that is not forwardable, and
// classic S4U2Proxy then refuses it. Two accounts one attribute apart is the
// only way to attribute the refusal to the attribute.
// ---------------------------------------------------------------------------
async function withoutProtocolTransitionClassicDelegationFails(t) {
  log.debug("Entering withoutProtocolTransitionClassicDelegationFails().");
  const from = await s4u2Self(t, "notrusted", false);
  const read = await s4u2Proxy(t, from, "backend", false);
  assert.ok(!read.ok,
    "classic S4U2Proxy SUCCEEDED for " + t.notrusted.asName + ", which is " +
    "not trusted for protocol transition. Its S4U2Self evidence was not " +
    "forwardable, so this route must refuse it — a KDC that allows it has " +
    "made TrustedToAuthForDelegation decorative.");
  log.info("without protocol transition classic S4U2Proxy is refused: " +
    (read.error ? read.error.error.name : "(no error name)"));
  log.debug("Leaving withoutProtocolTransitionClassicDelegationFails().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. Kerberos delegation against " + TARGET + ".");
  let t = null;
  try {
    if (TARGET === "mock") {
      t = await mockTarget();
    } else if (TARGET === "windows") {
      t = windowsTarget();
    } else {
      throw new Error("KRB5_DELEG_TARGET must be 'mock' or 'windows', got " +
        JSON.stringify(TARGET));
    }
    makeRelay();
    log.info("target: " + t.what + ", realm " + t.realm + ", impersonating " +
      t.impersonate);

    await classicS4u2ProxyReachesTheBackEnd(t);
    await resourceBasedS4u2ProxyReachesItsTarget(t);
    await withoutProtocolTransitionClassicDelegationFails(t);
    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error && error.stack ? error.stack : String(error));
    process.exitCode = 1;
  } finally {
    if (kdcListeners) {
      try {
        kdcListeners.tcp.close();
      } catch (e) {
        // Already closed: this runs from a finally, so it is reached both on
        // the happy path and after a failure that closed the listener on its
        // way out. A second close is expected rather than exceptional.
      }
      try {
        kdcListeners.udp.close();
      } catch (e) {
        // Already closed — same reason as the TCP listener above.
      }
    }
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("krb5_delegation_interop")
  .description("S4U2Self, S4U2Proxy and RBCD against the mock or a real KDC.")
  .addOption(new Option("-u, --url <url>", "Ignored; accepted for uniformity."))
  .action(function () {});
program.parse(process.argv).opts();

test();
