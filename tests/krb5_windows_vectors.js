// File: krb5_windows_vectors.js
//
// ---------------------------------------------------------------------------
// What a real Windows KDC actually sent, asserted offline, forever.
//
// tests/krb5_real_dc.js proves the client interoperates with Microsoft, but it
// needs a domain controller on EC2 — twenty minutes to build, real money, and
// therefore run approximately never. This test asserts the RECORDING of that
// exchange (tests/captures/windows-server-2025.json, written by
// tests/krb5_capture_real_dc.js) with no AWS, no network and no services, so
// the evidence survives into every ordinary run.
//
// WHAT THIS CATCHES THAT THE MOCK CANNOT. The mock KDC in the sts/ submodule
// was written from the same reading of RFC 4120 and [MS-PAC] as the client it
// checks, so the two agree by construction and a shared misreading is invisible
// to both. These bytes came from software this project did not write. If a
// change to the codec starts rejecting them, or reads a different value out of
// them, that is a regression against Microsoft and not against ourselves.
//
// WHAT IT DELIBERATELY DOES NOT DO. It does not compare byte-for-byte against a
// re-encoding. Kerberos messages carry timestamps, nonces and a fresh session
// key, so our AS-REQ will never be byte-identical to the captured one and
// asserting that it is would be a test of nothing but the clock. What is
// asserted is what we READ out of Microsoft's bytes.
//
// Node only. Never skipped: the capture is committed.
// ---------------------------------------------------------------------------
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "krb5_windows_vectors",
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

const CAPTURE = path.join(__dirname, "captures", "windows-server-2025.json");

function loadCapture() {
  log.debug("Entering loadCapture().");
  assert.ok(fs.existsSync(CAPTURE),
    "the Windows capture is missing: " + CAPTURE + ". It is committed, so " +
    "its absence means a bad checkout rather than a skip. Regenerate it with " +
    "./infra/krb5-test.sh and tests/krb5_capture_real_dc.js.");
  const c = JSON.parse(fs.readFileSync(CAPTURE, "utf8"));
  assert.ok(c.wire && c.wire.length >= 5,
    "the capture carries only " + ((c.wire || []).length) + " exchanges.");
  log.info("capture from " + c.source.os + " (" + c.source.amiName + "), " +
    c.wire.length + " exchanges, taken " + c.capturedAt);
  log.debug("Leaving loadCapture().");
  return c;
}

function replyFor(capture, label) {
  log.debug("Entering replyFor(). label=" + label);
  const entry = capture.wire.filter(function (w) {
    return w.label === label;
  })[0];
  assert.ok(entry, "the capture has no exchange labelled " + label);
  log.debug("Leaving replyFor().");
  return Buffer.from(entry.reply, "base64");
}

// ---------------------------------------------------------------------------
// 1. The refusal, and the salt — the single value a client cannot derive.
// ---------------------------------------------------------------------------
function theRefusalCarriesAdsSalt(capture) {
  log.debug("Entering theRefusalCarriesAdsSalt().");
  const decoded = msgs.readKdcResponse(replyFor(capture, "as-req-no-preauth"));
  assert.strictEqual(decoded.kind, "KRB-ERROR",
    "a bare AS-REQ to a real AD KDC is refused; we read " + decoded.kind);
  assert.strictEqual(decoded.error.error.name, "KDC_ERR_PREAUTH_REQUIRED",
    "Windows refused with " + decoded.error.error.name);

  const pa = decoded.error.eDataPaData;
  assert.ok(pa && pa.length, "the refusal's e-data did not parse as PA-DATA.");
  const info2 = pa.filter(function (p) {
    return p.type === msgs.PA_TYPE.ETYPE_INFO2;
  })[0];
  assert.ok(info2, "Windows always sends PA-ETYPE-INFO2 on a preauth " +
    "refusal; we did not find one, which means the e-data walk is wrong.");

  const entries = msgs.readEtypeInfo2(info2.value);
  const aes = entries.filter(function (e) { return e.etype === 18; })[0];
  assert.ok(aes, "no aes256 entry in Microsoft's ETYPE-INFO2.");

  // The headline interoperability fact. AD builds a user's AES salt as the
  // realm concatenated with the sAMAccountName, no separator — it is not
  // derivable from anything else, and getting it wrong makes every correct
  // password look wrong.
  assert.strictEqual(aes.salt, capture.salt.value,
    "we read the salt as " + JSON.stringify(aes.salt) + "; Windows sent " +
    JSON.stringify(capture.salt.value));
  assert.strictEqual(aes.salt, capture.source.realm + capture.source.user,
    "AD's salt is <REALM><samAccountName> with no separator. Read " +
    JSON.stringify(aes.salt));

  // ---------------------------------------------------------------------
  // s2kparams is ABSENT, and this is a place the mock actively misleads.
  //
  // The mock KDC always sends s2kparams carrying 4096, and
  // tests/krb5_as_exchange.js asserts it is there ("s2kparams must carry the
  // iteration count"). That is true of the mock and FALSE of Active
  // Directory: Windows Server 2025 omits the field entirely and relies on the
  // RFC 3962 section 4 default, which is also 4096.
  //
  // So a client that REQUIRED s2kparams — dereferenced it, or refused an
  // entry without it — would pass every test in this suite and then fail
  // against every real domain in the world, with a wrong-password error. The
  // assertion below is therefore on the absence, and the proof that we cope
  // is section 3: it derives the key with a null s2kparams and opens
  // Microsoft's AS-REP with it.
  // ---------------------------------------------------------------------
  assert.strictEqual(aes.s2kparams, null,
    "Windows Server 2025 sends no s2kparams for aes256; this capture has " +
    JSON.stringify(aes.s2kparams) + ". If a newer Windows started sending " +
    "one, that is worth knowing rather than worth silently accepting.");
  assert.strictEqual(capture.salt.s2kparams, null,
    "the capture and the live read disagree about s2kparams.");
  log.info("salt " + JSON.stringify(aes.salt) + ", NO s2kparams (the RFC " +
    "3962 default applies), etypes offered: " +
    entries.map(function (e) { return e.etype; }).join(","));
  log.debug("Leaving theRefusalCarriesAdsSalt().");
}

// ---------------------------------------------------------------------------
// 2. The two refusals a client has to tell apart.
// ---------------------------------------------------------------------------
function theRefusalsAreDistinguishable(capture) {
  log.debug("Entering theRefusalsAreDistinguishable().");
  const wrong = msgs.readKdcResponse(replyFor(capture,
    "as-req-wrong-password"));
  assert.strictEqual(wrong.kind, "KRB-ERROR", "expected an error");
  assert.strictEqual(wrong.error.error.name, "KDC_ERR_PREAUTH_FAILED",
    "a wrong password is PREAUTH_FAILED; Windows said " +
    wrong.error.error.name);

  const nobody = msgs.readKdcResponse(replyFor(capture,
    "as-req-unknown-principal"));
  assert.strictEqual(nobody.kind, "KRB-ERROR", "expected an error");
  assert.strictEqual(nobody.error.error.name, "KDC_ERR_C_PRINCIPAL_UNKNOWN",
    "an account that does not exist is C_PRINCIPAL_UNKNOWN; Windows said " +
    nobody.error.error.name);

  // These two matter together: a client that cannot tell them apart tells a
  // user to check their password when the account does not exist, or the
  // reverse. Windows makes them different codes and so must we.
  assert.notStrictEqual(wrong.error.errorCode, nobody.error.errorCode,
    "a wrong password and an unknown account came back as the same code.");
  log.info("PREAUTH_FAILED and C_PRINCIPAL_UNKNOWN read distinctly");
  log.debug("Leaving theRefusalsAreDistinguishable().");
}

// ---------------------------------------------------------------------------
// 3. The AS-REP, opened with the key derived from Microsoft's own salt.
// ---------------------------------------------------------------------------
async function theAsRepOpensWithAKeyDerivedFromTheSalt(capture) {
  log.debug("Entering theAsRepOpensWithAKeyDerivedFromTheSalt().");
  const decoded = msgs.readKdcResponse(replyFor(capture, "as-req-preauth"));
  assert.strictEqual(decoded.kind, "AS-REP",
    "Microsoft issued a ticket; we read " + decoded.kind);
  const rep = decoded.rep;
  assert.strictEqual(rep.crealm, capture.source.realm, "crealm");
  assert.deepStrictEqual(rep.cname.name, [capture.source.user], "cname");
  assert.strictEqual(rep.ticket.encPart.etype, capture.observed.ticketEtype,
    "the TGT's enc-part etype");
  assert.strictEqual(rep.ticket.encPart.kvno, capture.observed.ticketKvno,
    "the krbtgt key version Windows used");

  // string-to-key against Microsoft's salt and iteration count, then open the
  // reply. This is the whole of RFC 3962 section 4 checked against a real DC.
  const profile = kcrypto.etypeById(capture.salt.etype);
  const key = await profile.stringToKey(capture.userPassword,
    prim.utf8(capture.salt.value),
    capture.salt.s2kparams ? Buffer.from(capture.salt.s2kparams, "base64")
      : null);
  const part = msgs.readEncKdcRepPart(await profile.decrypt(key,
    kcrypto.KEY_USAGE.AS_REP_ENCPART, rep.encPart.cipher));
  assert.ok(part.key && part.key.key,
    "the AS-REP's encrypted part opened but carried no session key.");
  assert.strictEqual(part.key.etype, capture.observed.sessionEtype,
    "session key etype");
  assert.deepStrictEqual(part.sname.name, ["krbtgt", capture.source.realm],
    "the TGT is for the krbtgt service");

  // And the recorded plaintext must match what we just decrypted — which is
  // what makes the capture self-checking rather than merely self-consistent.
  assert.strictEqual(
    Buffer.from(prim.toBytes(await profile.decrypt(key,
      kcrypto.KEY_USAGE.AS_REP_ENCPART, rep.encPart.cipher))).toString("base64"),
    capture.decrypted.asRepEncPart,
    "the AS-REP enc-part we decrypt now differs from what was recorded.");
  log.info("AS-REP opens with a key derived from Microsoft's salt; session " +
    "etype " + part.key.etype);
  log.debug("Leaving theAsRepOpensWithAKeyDerivedFromTheSalt().");
}

// ---------------------------------------------------------------------------
// 4. The keytab ktpass wrote, and the service ticket it opens.
// ---------------------------------------------------------------------------
async function theKtpassKeytabOpensTheServiceTicket(capture) {
  log.debug("Entering theKtpassKeytabOpensTheServiceTicket().");
  const keytab = keytabMod.parseKeytab(Buffer.from(capture.keytabB64,
    "base64"));
  assert.strictEqual(keytab.entries.length, 1,
    "ktpass -crypto AES256-SHA1 writes one entry; we read " +
    keytab.entries.length);
  const entry = keytab.entries[0];
  assert.strictEqual(entry.principal, capture.observed.keytabPrincipal,
    "keytab principal");
  assert.strictEqual(entry.etype, capture.observed.keytabEtype, "keytab etype");
  assert.strictEqual(entry.kvno, capture.observed.keytabKvno, "keytab kvno");
  assert.strictEqual(prim.toBytes(entry.key).length, 32,
    "an aes256 key is 32 bytes; we read " + prim.toBytes(entry.key).length);

  const tgs = msgs.readKdcResponse(replyFor(capture, "tgs-req"));
  assert.strictEqual(tgs.kind, "TGS-REP", "expected a service ticket");
  const profile = kcrypto.etypeById(entry.etype);
  const plain = await profile.decrypt(entry.key,
    kcrypto.KEY_USAGE.KDC_REP_TICKET, tgs.rep.ticket.encPart.cipher);
  assert.strictEqual(Buffer.from(prim.toBytes(plain)).toString("base64"),
    capture.decrypted.encTicketPart,
    "the EncTicketPart we decrypt now differs from what was recorded.");

  const encTicket = msgs.readEncTicketPart(plain);
  assert.deepStrictEqual(encTicket.cname.name, [capture.source.user],
    "the ticket names the wrong client");
  assert.strictEqual(encTicket.crealm, capture.source.realm, "crealm");
  log.info("ktpass keytab (v" + keytab.version.toString(16) + ") opens " +
    "Microsoft's service ticket");
  log.debug("Leaving theKtpassKeytabOpensTheServiceTicket().");
}

// ---------------------------------------------------------------------------
// 5. The PAC Windows actually minted.
// ---------------------------------------------------------------------------
async function theWindowsPacParsesAndVerifies(capture) {
  log.debug("Entering theWindowsPacParsesAndVerifies().");
  const encTicket = msgs.readEncTicketPart(
    Buffer.from(capture.decrypted.encTicketPart, "base64"));
  const found = pacMod.findPacs(encTicket.authorizationData || []);
  assert.ok(found.length, "no PAC in Microsoft's service ticket.");
  assert.strictEqual(found[0].path, capture.decrypted.pacPath,
    "the PAC is nested at " + found[0].path + ", recorded as " +
    capture.decrypted.pacPath);

  const pac = pacMod.parsePac(found[0].bytes);
  assert.deepStrictEqual(pac.problems || [], [],
    "krb5_pac.js reports problems with a PAC minted by Windows itself, which " +
    "makes each one a finding: " + JSON.stringify(pac.problems));

  // Every buffer Windows sent must be one we RECOGNISE and PARSE. An
  // unrecognised buffer is not fatal to a client, but it is a gap in the
  // decoder the debugger exists to be.
  const types = pac.buffers.map(function (b) { return b.type; });
  assert.deepStrictEqual(types, capture.observed.pacBufferTypes,
    "Windows sent buffer types " + capture.observed.pacBufferTypes.join(",") +
    "; we read " + types.join(","));
  pac.buffers.forEach(function (b) {
    assert.ok(b.parsed,
      "buffer type " + b.type + " (" + pacMod.bufferTypeName(b.type) +
      ") did not parse" + (b.error ? ": " + b.error : "."));
  });

  // What a modern Windows DC puts in a SERVICE ticket, recorded because it is
  // not what one might assume: both post-CVE-2020-17049 signatures are here
  // (ticket checksum, extended KDC checksum) and PAC_ATTRIBUTES_INFO (17) and
  // PAC_REQUESTOR (18) are NOT. The mock puts 17 and 18 in a service ticket;
  // see the note in docs/kerberos.md.
  assert.ok(types.indexOf(pacMod.TYPE.TICKET_CHECKSUM) >= 0,
    "Windows Server 2025 includes a ticket checksum in a service ticket's PAC");
  assert.ok(types.indexOf(pacMod.TYPE.EXTENDED_KDC_CHECKSUM) >= 0,
    "and an extended KDC checksum");

  const logon = pacMod.bufferOfType(pac, pacMod.TYPE.LOGON_INFO);
  assert.ok(logon && logon.parsed, "no logon information buffer");
  assert.strictEqual(String(logon.parsed.effectiveName).toLowerCase(),
    capture.source.user.toLowerCase(), "the PAC names the wrong account");
  assert.ok(/^S-1-5-21-\d+-\d+-\d+-\d+$/.test(logon.parsed.userSid),
    "the PAC's user SID is not a domain SID: " + logon.parsed.userSid);

  // The signature a service can actually check: over the PAC with the
  // signatures zeroed, under the service's own long-term key.
  const keytab = keytabMod.parseKeytab(Buffer.from(capture.keytabB64,
    "base64"));
  const entry = keytab.entries[0];
  const sigs = await pacMod.verifySignatures(pac, {
    serverKey: { etype: entry.etype, key: entry.key }
  });
  const server = sigs.filter(function (s) {
    return s.type === pacMod.TYPE.SERVER_CHECKSUM;
  })[0];
  assert.ok(server, "no server signature in Microsoft's PAC");
  assert.strictEqual(server.verified, true,
    "the server signature on a Windows-minted PAC does not verify with the " +
    "ktpass key. Our signature coverage or our zeroing disagrees with " +
    "Microsoft: " + server.note);

  // The other three need the krbtgt key, which a service never has. They must
  // be reported as unchecked rather than as failures — a verifier that calls
  // an unverifiable signature "bad" is worse than one that says nothing.
  const kdcSig = sigs.filter(function (s) {
    return s.type === pacMod.TYPE.KDC_CHECKSUM;
  })[0];
  assert.ok(kdcSig, "no KDC signature buffer");
  assert.notStrictEqual(kdcSig.verified, true,
    "the KDC signature cannot verify without the krbtgt key, which this " +
    "capture deliberately does not carry.");
  log.info("Windows PAC: " + types.length + " buffers, " +
    logon.parsed.effectiveName + " / " + logon.parsed.userSid +
    ", server signature (" + server.signatureTypeName + ") verifies");
  log.debug("Leaving theWindowsPacParsesAndVerifies().");
}

// ---------------------------------------------------------------------------
// 6. What Windows did that our own KDC never would.
// ---------------------------------------------------------------------------
function theZeroLengthFrameIsRecorded(capture) {
  log.debug("Entering theZeroLengthFrameIsRecorded().");
  const observed = capture.observed.unknownSpn;
  assert.ok(observed, "the capture recorded nothing for the unknown SPN.");
  // Windows answered a TGS-REQ for an unregistered SPN by closing the
  // connection with a ZERO-LENGTH TCP frame rather than by sending
  // S_PRINCIPAL_UNKNOWN. api/krb5_relay.js refuses that, correctly — but the
  // message a user sees has to name the cause, because "0 bytes" on its own
  // reads as a broken relay rather than as a KDC declining to answer.
  if (observed.answered === false) {
    assert.ok(/0 bytes/.test(observed.relayRefusal || ""),
      "the recorded refusal is not the zero-length one: " +
      observed.relayRefusal);
    log.info("recorded: Windows closes the connection on an unknown SPN " +
      "rather than sending S_PRINCIPAL_UNKNOWN");
  } else {
    log.info("recorded: Windows answered the unknown SPN with " +
      observed.error);
  }
  log.debug("Leaving theZeroLengthFrameIsRecorded().");
}

// ---------------------------------------------------------------------------
// 7. What the DECODER PAGE says about all this.
//
// krb5_describe.js is the whole content of kerberos_decoder.html, and the
// absent s2kparams is exactly the kind of thing a person pastes bytes into that
// page to understand. It used to print nothing at all when the field was
// missing, which left "the KDC asked for the default" indistinguishable from
// "the decoder did not look".
// ---------------------------------------------------------------------------
async function theDecoderExplainsTheAbsentS2kParams(capture) {
  log.debug("Entering theDecoderExplainsTheAbsentS2kParams().");
  const describe = shared("krb5_describe.js");
  // describe() takes what a user PASTES — base64 text — and is async, so this
  // exercises the page's real entry point rather than an internal helper.
  const entry = capture.wire.filter(function (w) {
    return w.label === "as-req-no-preauth";
  })[0];
  const doc = await describe.describe(entry.reply);
  const flat = JSON.stringify(doc);

  assert.ok(/RFC 3962 default/.test(flat),
    "the decoder does not say where the iteration count came from when " +
    "Windows sends no s2kparams. A reader cannot then tell a defaulted count " +
    "from an unexamined one.");
  assert.ok(/4096/.test(flat),
    "the decoder does not name the effective iteration count (4096).");
  assert.ok(/no s2kparams sent/i.test(flat),
    "the decoder does not say the field was absent.");
  assert.ok(new RegExp(capture.salt.value).test(flat),
    "the decoder does not show the salt Windows sent.");
  log.info("the decoder names the salt, the effective 4096 iterations, and " +
    "that they came from the RFC 3962 default rather than from s2kparams");
  log.debug("Leaving theDecoderExplainsTheAbsentS2kParams().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. Windows KDC vectors, offline.");
  try {
    const capture = loadCapture();
    theRefusalCarriesAdsSalt(capture);
    theRefusalsAreDistinguishable(capture);
    await theAsRepOpensWithAKeyDerivedFromTheSalt(capture);
    await theKtpassKeytabOpensTheServiceTicket(capture);
    await theWindowsPacParsesAndVerifies(capture);
    theZeroLengthFrameIsRecorded(capture);
    await theDecoderExplainsTheAbsentS2kParams(capture);
    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error && error.stack ? error.stack : String(error));
    process.exit(1);
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("krb5_windows_vectors")
  .description("Assert a recorded real-Windows KDC exchange, offline.")
  .addOption(new Option("-u, --url <url>", "Ignored; accepted for uniformity."))
  .action(function () {});
program.parse(process.argv).opts();

test();
