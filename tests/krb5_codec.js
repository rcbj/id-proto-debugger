// File: krb5_codec.js
//
// common/krb5/krb5_asn1.js and krb5_messages.js — Kerberos v5's DER encoding and
// the messages built out of it.
//
// ---------------------------------------------------------------------------
// What this test is for, and what a round trip does NOT prove.
//
// A codec that encodes and decodes its own output consistently is trivially easy
// to write and useless: every field could be under the wrong context tag, the
// flag bits could be reversed, and the round trip would still pass. A KDC would
// then answer the resulting message with "cannot decode", or — worse — answer it
// correctly having read a different request from the one that was meant.
//
// So the assertions here come in three kinds, and the middle one is the one that
// earns its keep:
//
//  1. **Round trips**, which catch asymmetry between a reader and a writer.
//  2. **Byte-exact expectations**, hand-derived from the DER rules and the RFC's
//     grammar, for the structures where a wrong tag or a wrong integer encoding
//     is otherwise invisible. These are the assertions that would fail if a
//     field moved to the wrong tag number.
//  3. **Compatibility behaviours** that only a real deployment produces: an
//     AS-REP whose enc-part is tagged EncTGSRepPart, a checksum type that is a
//     NEGATIVE integer, a KRB-ERROR carrying ETYPE-INFO2 in its e-data, and a
//     relayed Ticket whose original bytes must survive re-encoding.
//
// Plus the negative half: this codec parses bytes a stranger pasted into a web
// page, so refusing malformed, hostile and oversized input is part of what it
// does rather than an edge case.
//
// No browser and no services: node only, so it never skips.
// ---------------------------------------------------------------------------
const assert = require("assert");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "krb5_codec",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var prim = paths.requireSharedModule(
  [__dirname + "/../common/krb5/krb5_primitives.js", __dirname + "/krb5_primitives.js"],
  "krb5_primitives.js");
var asn1 = paths.requireSharedModule(
  [__dirname + "/../common/krb5/krb5_asn1.js", __dirname + "/krb5_asn1.js"], "krb5_asn1.js");
var msg = paths.requireSharedModule(
  [__dirname + "/../common/krb5/krb5_messages.js", __dirname + "/krb5_messages.js"],
  "krb5_messages.js");
var kcrypto = paths.requireSharedModule(
  [__dirname + "/../common/krb5/krb5_crypto.js", __dirname + "/krb5_crypto.js"], "krb5_crypto.js");

const hex = (b) => prim.toHex(b);
const unhex = (s) => prim.fromHex(s);

function eq(label, got, want) {
  const g = typeof got === "string" ? got : hex(got);
  const w = String(want).replace(/\s/g, "").toLowerCase();
  assert.strictEqual(g, w, label + "\n  got  " + g + "\n  want " + w);
  log.debug("ok: " + label);
}

// A SEQUENCE header computed from its parts, for the byte-exact expectations
// below.
//
// The point of those expectations is to pin every TAG NUMBER and every inner
// encoding — that is what catches a field moving to the wrong context tag, which
// a round trip cannot see. The outer LENGTH byte is not part of that: it is
// arithmetic, and hand-arithmetic in an oracle is how this test file acquired
// three wrong expectations in a row, each of which cost a round of suspecting
// correct code. So the tags are written out and the length is computed.
function seq(...partsHex) {
  const body = partsHex.join("").replace(/\s/g, "");
  const len = body.length / 2;
  assert.ok(len < 128, "seq() helper only covers the short form; got " + len + " bytes");
  return "30" + (len < 16 ? "0" : "") + len.toString(16) + body;
}

function mustThrow(what, fn, matching) {
  let threw = null;
  try { fn(); } catch (e) { threw = e; }
  assert.ok(threw, "expected a refusal: " + what);
  if (matching) {
    assert.ok(matching.test(threw.message),
      what + ": refused, but the message does not say why (" + threw.message + ")");
  }
  log.debug("refused as it should: " + what + " (" + threw.message + ")");
}

// ---------------------------------------------------------------------------
// DER, at the byte level.
// ---------------------------------------------------------------------------
function derEncodesMinimally() {
  log.debug("Entering derEncodesMinimally().");

  // Lengths: short form below 128, long form at and above it. A KDC is entitled
  // to refuse a non-minimal length and some do.
  eq("length 0", asn1.encodeLength(0), "00");
  eq("length 127 (short form)", asn1.encodeLength(127), "7f");
  eq("length 128 (long form begins)", asn1.encodeLength(128), "8180");
  eq("length 255", asn1.encodeLength(255), "81ff");
  eq("length 256", asn1.encodeLength(256), "820100");
  eq("length 65535", asn1.encodeLength(65535), "82ffff");

  // INTEGERs, two's complement and minimal.
  eq("INTEGER 0", asn1.encInteger(0), "020100");
  eq("INTEGER 1", asn1.encInteger(1), "020101");
  eq("INTEGER 5 (pvno)", asn1.encInteger(5), "020105");
  eq("INTEGER 127", asn1.encInteger(127), "02017f");
  // 128 needs a leading zero or it would read as -128.
  eq("INTEGER 128 (leading zero required)", asn1.encInteger(128), "02020080");
  eq("INTEGER 255", asn1.encInteger(255), "020200ff");
  eq("INTEGER 65536", asn1.encInteger(65536), "0203010000");
  // A nonce is a UInt32 and routinely has its top bit set.
  eq("INTEGER 4294967295 (a nonce)", asn1.encInteger(4294967295), "020500ffffffff");

  // NEGATIVE integers are not hypothetical: -138 is the HMAC-MD5 checksum type,
  // used by etype 23 and by S4U2Self's PA-FOR-USER. An unsigned-only encoder
  // emits 0x0086 here and the KDC rejects the message as malformed.
  eq("INTEGER -1", asn1.encInteger(-1), "0201ff");
  eq("INTEGER -128", asn1.encInteger(-128), "020180");
  eq("INTEGER -129 (two bytes)", asn1.encInteger(-129), "0202ff7f");
  eq("INTEGER -138 (cksumtype HMAC-MD5)", asn1.encInteger(-138), "0202ff76");
  // And back.
  [0, 1, 5, 127, 128, 255, 65536, 4294967295, -1, -128, -129, -138, -32768].forEach(function (n) {
    const back = asn1.decInteger(asn1.readTlv(asn1.encInteger(n), 0));
    assert.strictEqual(back, n, "INTEGER round trip for " + n);
  });

  // KerberosFlags: bit 0 is the MOST significant bit of the FIRST octet, so
  // forwardable (bit 1) is 0x40 of byte 0. Reversed, a request asks for a
  // different set of options and the KDC answers it correctly and uselessly.
  eq("flags: forwardable (bit 1)", asn1.encFlags([msg.KDC_OPTION.FORWARDABLE]), "0305 00 40000000");
  eq("flags: renewable (bit 8)", asn1.encFlags([msg.KDC_OPTION.RENEWABLE]), "0305 00 00800000");
  eq("flags: canonicalize (bit 15)", asn1.encFlags([msg.KDC_OPTION.CANONICALIZE]), "0305 00 00010000");
  eq("flags: renew (bit 30)", asn1.encFlags([msg.KDC_OPTION.RENEW]), "0305 00 00000002");
  eq("flags: forwardable+renewable+canonicalize",
     asn1.encFlags([1, 8, 15]), "0305 00 40810000");
  assert.deepStrictEqual(asn1.bitsFromFlags(asn1.flagsFromBits([1, 8, 15])), [1, 8, 15],
    "flag bits must round trip");

  // KerberosTime is exactly YYYYMMDDHHMMSSZ. toISOString() would add
  // milliseconds, which a strict KDC answers with "cannot decode".
  const when = new Date(Date.UTC(2026, 7, 13, 9, 5, 7, 456));
  assert.strictEqual(asn1.formatKerberosTime(when), "20260813090507Z",
    "KerberosTime must have no fractional seconds");
  eq("GeneralizedTime encoding", asn1.encKerberosTime(when), "180f" + hex(prim.utf8("20260813090507Z")));
  assert.strictEqual(asn1.parseKerberosTime("20260813090507Z").getTime(),
    Date.UTC(2026, 7, 13, 9, 5, 7, 0), "KerberosTime must parse back to the same instant");

  log.debug("Leaving derEncodesMinimally().");
}

// ---------------------------------------------------------------------------
// The shared structures, pinned to bytes.
//
// These expectations were derived by hand from RFC 4120's grammar and the DER
// rules, and they are the assertions that catch a field sitting under the wrong
// context tag — which a round trip cannot see.
// ---------------------------------------------------------------------------
function structuresEncodeToTheExpectedBytes() {
  log.debug("Entering structuresEncodeToTheExpectedBytes().");

  // PrincipalName ::= SEQUENCE { name-type [0] Int32, name-string [1] SEQUENCE OF KerberosString }
  //   30 10
  //     A0 03 02 01 01           [0] INTEGER 1 (NT-PRINCIPAL)
  //     A1 09 30 07 1B 05 "alice"  [1] SEQUENCE OF GeneralString
  eq("PrincipalName alice",
     msg.encPrincipalName({ type: msg.NAME_TYPE.PRINCIPAL, name: ["alice"] }),
     seq("a003020101", "a109" + "3007" + "1b05" + hex(prim.utf8("alice"))));

  // A two-component service principal, NT-SRV-INST — krbtgt/EXAMPLE.COM.
  const krbtgt = msg.encPrincipalName({ type: msg.NAME_TYPE.SRV_INST, name: ["krbtgt", "EXAMPLE.COM"] });
  const readBack = msg.readPrincipalName(asn1.readTlv(krbtgt, 0));
  assert.strictEqual(readBack.type, 2, "krbtgt must be NT-SRV-INST (2)");
  assert.deepStrictEqual(readBack.name, ["krbtgt", "EXAMPLE.COM"], "both components must survive");

  // EncryptedData ::= SEQUENCE { etype [0], kvno [1] OPTIONAL, cipher [2] }
  // The optional kvno must be ABSENT, not present-and-empty: an empty [1] is a
  // decode error at the far end.
  eq("EncryptedData without kvno",
     msg.encEncryptedData({ etype: 18, cipher: unhex("aabb") }),
     seq("a003020112", "a204" + "0402aabb"));
  eq("EncryptedData with kvno 3",
     msg.encEncryptedData({ etype: 18, kvno: 3, cipher: unhex("aabb") }),
     seq("a003020112", "a103020103", "a204" + "0402aabb"));

  // Checksum with the NEGATIVE type. This is the byte sequence a Windows KDC
  // expects for an S4U2Self PA-FOR-USER checksum.
  eq("Checksum type -138",
     msg.encChecksum({ type: -138, checksum: unhex("00112233445566778899aabbccddeeff") }),
     seq("a0040202ff76", "a112" + "0410" + "00112233445566778899aabbccddeeff"));

  // PA-DATA's fields are [1] and [2], NOT [0] and [1]. Getting this wrong
  // produces padata a KDC silently ignores, so the AS-REQ looks like it carried
  // no pre-authentication and the KDC asks for it again — a loop that reads as
  // "my password is being rejected".
  eq("PA-DATA uses tags [1] and [2]",
     msg.encPaData({ type: msg.PA_TYPE.ENC_TIMESTAMP, value: unhex("cafe") }),
     seq("a103020102", "a204" + "0402cafe"));
  const pa = msg.readPaData(asn1.readTlv(msg.encPaData({ type: 19, value: unhex("00") }), 0));
  assert.strictEqual(pa.type, 19, "padata-type must be read from tag [1]");
  assert.strictEqual(pa.typeName, "ETYPE_INFO2", "a known padata type must be named");

  log.debug("Leaving structuresEncodeToTheExpectedBytes().");
}

// ---------------------------------------------------------------------------
// AS-REQ / TGS-REQ.
// ---------------------------------------------------------------------------
function kdcRequestsRoundTrip() {
  log.debug("Entering kdcRequestsRoundTrip().");
  const till = new Date(Date.UTC(2026, 7, 14, 0, 0, 0));
  const from = new Date(Date.UTC(2026, 7, 13, 12, 0, 0));
  const rtime = new Date(Date.UTC(2026, 7, 20, 0, 0, 0));
  // EVERY OPTIONAL FIELD IS POPULATED HERE, DELIBERATELY.
  //
  // Mutation-testing this file caught the gap: a reader that silently drops an
  // OPTIONAL field passes a re-encode comparison as long as no test ever sets
  // that field, and `rtime: null` hard-coded into the reader went undetected.
  // Behind that, the same blind spot hid a real defect — the writer had
  // `addresses` hard-coded to null in three places, so a captured message
  // carrying them could be decoded and never re-encoded. Populate everything, or
  // the round trip only covers the fields somebody happened to think of.
  const req = {
    msgType: msg.MSG_TYPE.AS_REQ,
    padata: [{ type: msg.PA_TYPE.PAC_REQUEST, value: msg.encPaPacRequest(true) }],
    reqBody: {
      kdcOptions: [msg.KDC_OPTION.FORWARDABLE, msg.KDC_OPTION.RENEWABLE, msg.KDC_OPTION.CANONICALIZE],
      cname: { type: msg.NAME_TYPE.PRINCIPAL, name: ["alice"] },
      realm: "EXAMPLE.COM",
      sname: { type: msg.NAME_TYPE.SRV_INST, name: ["krbtgt", "EXAMPLE.COM"] },
      from: from,
      till: till,
      rtime: rtime,
      nonce: 3735928559,                  // top bit set, so the UInt32 path matters
      etypes: kcrypto.DEFAULT_ETYPE_PREFERENCE,
      // Addressless tickets are the norm and AD issues them, which is exactly why
      // this is here: the rarely-used field is the one that rots.
      addresses: [{ type: 2, address: unhex("0a000001") }],
      encAuthorizationData: { etype: 18, cipher: unhex("0badc0de") },
      additionalTickets: [{
        realm: "EXAMPLE.COM",
        sname: { type: 3, name: ["HTTP", "web.example.com"] },
        encPart: { etype: 18, cipher: unhex("deadbeef") }
      }]
    }
  };
  const bytes = msg.encKdcReq(req);

  // The outermost tag identifies the message before anything is parsed, which is
  // what the api's relay uses to decide a payload is Kerberos at all.
  assert.strictEqual(bytes[0], 0x6a, "an AS-REQ must be tagged [APPLICATION 10] (0x6a)");
  assert.deepStrictEqual(msg.identify(bytes), { applicationNumber: 10, name: "AS-REQ" },
    "identify() must name an AS-REQ");

  const back = msg.readKdcReq(bytes);
  assert.strictEqual(back.pvno, 5, "pvno");
  assert.strictEqual(back.msgType, msg.MSG_TYPE.AS_REQ, "msg-type");
  assert.strictEqual(back.padata.length, 1, "padata count");
  assert.strictEqual(back.padata[0].type, 128, "PA-PAC-REQUEST type");
  assert.strictEqual(msg.readPaPacRequest(back.padata[0].value).includePac, true,
    "the PAC request must decode as true");
  assert.deepStrictEqual(back.reqBody.kdcOptions, [1, 8, 15], "kdc-options bits");
  assert.deepStrictEqual(msg.kdcOptionNames(back.reqBody.kdcOptions),
    ["forwardable", "renewable", "canonicalize"], "kdc-options must render by name");
  assert.strictEqual(back.reqBody.realm, "EXAMPLE.COM", "realm, unfolded");
  assert.deepStrictEqual(back.reqBody.cname.name, ["alice"], "cname");
  assert.deepStrictEqual(back.reqBody.sname.name, ["krbtgt", "EXAMPLE.COM"], "sname");
  assert.strictEqual(back.reqBody.nonce, 3735928559, "a nonce with its top bit set");
  assert.deepStrictEqual(back.reqBody.etypes, kcrypto.DEFAULT_ETYPE_PREFERENCE, "etype list and ORDER");
  // Each field is asserted PRESENT before it is dereferenced, so a reader that
  // drops one fails with the field's name rather than with "cannot read
  // properties of null" twenty lines into a stack trace.
  ["from", "till", "rtime", "addresses", "encAuthorizationData", "additionalTickets"]
    .forEach(function (field) {
      assert.ok(back.reqBody[field] !== null && back.reqBody[field] !== undefined,
        "the KDC-REQ-BODY reader dropped the OPTIONAL field '" + field + "', which was present on the wire");
    });
  assert.strictEqual(back.reqBody.till.getTime(), till.getTime(), "till");
  assert.strictEqual(back.reqBody.from.getTime(), from.getTime(), "from");
  assert.strictEqual(back.reqBody.rtime.getTime(), rtime.getTime(), "rtime");
  assert.strictEqual(back.reqBody.addresses.length, 1, "addresses");
  eq("the address survives", back.reqBody.addresses[0].address, "0a000001");
  eq("enc-authorization-data survives", back.reqBody.encAuthorizationData.cipher, "0badc0de");
  assert.strictEqual(back.reqBody.additionalTickets.length, 1, "additional-tickets");
  assert.deepStrictEqual(back.reqBody.additionalTickets[0].sname.name, ["HTTP", "web.example.com"],
    "the additional ticket's SPN — this is the S4U2Proxy evidence-ticket slot");

  // And an absent OPTIONAL must read as null rather than undefined, so a caller
  // can tell "not present" from "present and empty".
  const minimal = msg.readKdcReq(msg.encKdcReq({
    msgType: msg.MSG_TYPE.AS_REQ,
    reqBody: { kdcOptions: [], realm: "EXAMPLE.COM", till: till, nonce: 1, etypes: [18] }
  }));
  assert.strictEqual(minimal.reqBody.from, null, "an absent OPTIONAL must read as null");
  assert.strictEqual(minimal.reqBody.rtime, null, "absent rtime");
  assert.strictEqual(minimal.reqBody.addresses, null, "absent addresses");
  assert.strictEqual(minimal.reqBody.additionalTickets, null, "absent additional-tickets");
  assert.deepStrictEqual(minimal.padata, [], "absent padata reads as an empty list");

  // Re-encoding what was read must reproduce the bytes exactly. This is the
  // assertion that fails if a reader quietly drops a field.
  eq("AS-REQ re-encodes byte-for-byte", msg.encKdcReq(back), hex(bytes));

  // A TGS-REQ differs only in its tags and msg-type, and the KDC-REQ-BODY it
  // carries is what the Authenticator's checksum covers — so the body's own
  // bytes are kept rather than re-encoded.
  const tgs = msg.encKdcReq({
    msgType: msg.MSG_TYPE.TGS_REQ,
    padata: [{ type: msg.PA_TYPE.TGS_REQ, value: unhex("00") }],
    reqBody: req.reqBody
  });
  assert.strictEqual(tgs[0], 0x6c, "a TGS-REQ must be tagged [APPLICATION 12] (0x6c)");
  const tgsBack = msg.readKdcReq(tgs);
  assert.strictEqual(tgsBack.msgType, msg.MSG_TYPE.TGS_REQ, "TGS-REQ msg-type");
  assert.ok(tgsBack.reqBody.raw && tgsBack.reqBody.raw.length > 0,
    "the KDC-REQ-BODY's own bytes must be retained — a checksum is computed over them");
  eq("a body relayed by its raw bytes is unchanged",
     msg.encKdcReq({ msgType: msg.MSG_TYPE.TGS_REQ, padata: tgsBack.padata, reqBody: tgsBack.reqBody }),
     hex(tgs));

  log.debug("Leaving kdcRequestsRoundTrip().");
}

// ---------------------------------------------------------------------------
// AS-REP, and the EncTGSRepPart compatibility case.
// ---------------------------------------------------------------------------
async function kdcRepliesRoundTripAndTolerateTheIrregularTag() {
  log.debug("Entering kdcRepliesRoundTripAndTolerateTheIrregularTag().");
  const e = kcrypto.etypeById(18);
  const clientKey = await e.stringToKey("hunter2", prim.utf8("EXAMPLE.COMalice"), null);
  const serviceKey = await e.stringToKey("servicepw", prim.utf8("EXAMPLE.COMkrbtgt"), null);
  const now = new Date(Date.UTC(2026, 7, 13, 12, 0, 0));
  const end = new Date(Date.UTC(2026, 7, 13, 22, 0, 0));
  const sessionKey = kcrypto.randomBytes(32);

  // A ticket whose enc-part really is encrypted, so the whole path is exercised.
  const encTicketPart = msg.encEncTicketPart({
    flags: [msg.TICKET_FLAG.FORWARDABLE, msg.TICKET_FLAG.INITIAL, msg.TICKET_FLAG.PRE_AUTHENT],
    key: { etype: 18, key: sessionKey },
    crealm: "EXAMPLE.COM",
    cname: { type: msg.NAME_TYPE.PRINCIPAL, name: ["alice"] },
    authtime: now, endtime: end
  });
  const ticket = {
    realm: "EXAMPLE.COM",
    sname: { type: msg.NAME_TYPE.SRV_INST, name: ["krbtgt", "EXAMPLE.COM"] },
    encPart: {
      etype: 18,
      cipher: await e.encrypt(serviceKey, kcrypto.KEY_USAGE.KDC_REP_TICKET, encTicketPart)
    }
  };

  const repPartFields = {
    key: { etype: 18, key: sessionKey },
    lastReq: [{ type: 0, value: now }],
    nonce: 3735928559,
    flags: [msg.TICKET_FLAG.FORWARDABLE, msg.TICKET_FLAG.INITIAL, msg.TICKET_FLAG.PRE_AUTHENT],
    authtime: now, endtime: end,
    srealm: "EXAMPLE.COM",
    sname: { type: msg.NAME_TYPE.SRV_INST, name: ["krbtgt", "EXAMPLE.COM"] }
  };

  // The correct tag, [APPLICATION 25].
  const asRep = msg.encKdcRep({
    msgType: msg.MSG_TYPE.AS_REP,
    crealm: "EXAMPLE.COM",
    cname: { type: msg.NAME_TYPE.PRINCIPAL, name: ["alice"] },
    ticket: ticket,
    encPart: {
      etype: 18,
      cipher: await e.encrypt(clientKey, kcrypto.KEY_USAGE.AS_REP_ENCPART,
        msg.encEncKdcRepPart(repPartFields, msg.APPLICATION.ENC_AS_REP_PART))
    }
  });
  assert.strictEqual(asRep[0], 0x6b, "an AS-REP must be tagged [APPLICATION 11] (0x6b)");

  const response = msg.readKdcResponse(asRep);
  assert.strictEqual(response.kind, "AS-REP", "readKdcResponse must classify an AS-REP");
  const rep = response.rep;
  assert.strictEqual(rep.crealm, "EXAMPLE.COM", "crealm");
  assert.strictEqual(rep.ticket.encPart.etypeName, "aes256-cts-hmac-sha1-96",
    "the ticket's etype must be named, not just numbered");

  const plain = await e.decrypt(clientKey, kcrypto.KEY_USAGE.AS_REP_ENCPART, rep.encPart.cipher);
  const part = msg.readEncKdcRepPart(plain);
  assert.strictEqual(part.taggedAs, "EncASRepPart", "the normal tag must be reported as such");
  eq("the session key survives the whole path", part.key.key, hex(sessionKey));
  assert.strictEqual(part.nonce, 3735928559, "the nonce must match the request's");
  assert.deepStrictEqual(msg.ticketFlagNames(part.flags),
    ["forwardable", "initial", "pre-authent"], "ticket flags must render by name");

  // The service side reads its own ticket with its own key.
  const tp = msg.readEncTicketPart(
    await e.decrypt(serviceKey, kcrypto.KEY_USAGE.KDC_REP_TICKET, rep.ticket.encPart.cipher));
  eq("the ticket carries the same session key", tp.key.key, hex(sessionKey));
  assert.deepStrictEqual(tp.cname.name, ["alice"], "the ticket names the client");

  // THE COMPATIBILITY CASE. RFC 4120 section 5.4.2 records implementations that
  // tag an AS-REP's enc-part as EncTGSRepPart. A client that insists on
  // [APPLICATION 25] passes every test against its own mock and then fails in
  // the field with "cannot decode", which reads as a crypto problem.
  const irregular = msg.encEncKdcRepPart(repPartFields, msg.APPLICATION.ENC_TGS_REP_PART);
  assert.strictEqual(irregular[0], 0x7a, "EncTGSRepPart must be tagged [APPLICATION 26] (0x7a)");
  const irregularPart = msg.readEncKdcRepPart(irregular);
  assert.strictEqual(irregularPart.taggedAs, "EncTGSRepPart",
    "the irregular tag must be ACCEPTED and REPORTED, not silently normalised");
  eq("the same fields come back from the irregular tag", irregularPart.key.key, hex(sessionKey));

  log.debug("Leaving kdcRepliesRoundTripAndTolerateTheIrregularTag().");
}

// ---------------------------------------------------------------------------
// A relayed Ticket must survive byte-for-byte.
//
// A Ticket is encrypted under a key its holder does not have, and its DER is
// covered by checksums computed elsewhere. So it is carried, not rebuilt — and
// the test constructs a ticket with a deliberately NON-MINIMAL length header to
// prove the codec carries the original bytes rather than re-deriving them. A
// codec that re-encodes would silently normalise that header and break a
// checksum computed over the original.
// ---------------------------------------------------------------------------
function relayedTicketsAreByteExact() {
  log.debug("Entering relayedTicketsAreByteExact().");
  const inner = asn1.encTaggedSequence([
    { tag: 0, value: asn1.encInteger(5) },
    { tag: 1, value: asn1.encGeneralString("EXAMPLE.COM") },
    { tag: 2, value: msg.encPrincipalName({ type: 2, name: ["krbtgt", "EXAMPLE.COM"] }) },
    { tag: 3, value: msg.encEncryptedData({ etype: 18, cipher: kcrypto.randomBytes(40) }) }
  ]);
  // A long-form length where the short form would do: legal to parse, and
  // exactly what a re-encoding codec would quietly "fix".
  const nonMinimal = prim.concat([
    new Uint8Array([0x61, 0x81, inner.length]), inner
  ]);
  const t = msg.readTicket(nonMinimal);
  eq("a ticket's raw bytes are the ORIGINAL bytes, non-minimal header included",
     t.raw, hex(nonMinimal));
  eq("re-encoding a read ticket reproduces it exactly", msg.encTicket(t), hex(nonMinimal));
  assert.notStrictEqual(hex(msg.encTicket({
    realm: t.realm, sname: t.sname, encPart: t.encPart
  })), hex(nonMinimal),
    "building the same ticket from FIELDS should normalise the header — which is why raw is kept");
  log.debug("Leaving relayedTicketsAreByteExact().");
}

// ---------------------------------------------------------------------------
// KRB-ERROR, and the pre-authentication round trip that depends on it.
//
// KDC_ERR_PREAUTH_REQUIRED is not a failure — it is where the salt comes from,
// and the salt is not guessable (Active Directory's default is the realm plus
// the sAMAccountName for a user, but a host-shaped string for a computer
// account). A client that treats this error as an error cannot authenticate to
// AD at all.
// ---------------------------------------------------------------------------
function krbErrorsCarryTheSalt() {
  log.debug("Entering krbErrorsCarryTheSalt().");
  const stime = new Date(Date.UTC(2026, 7, 13, 12, 0, 30));
  const etypeInfo2 = msg.encEtypeInfo2([
    { etype: 18, salt: "EXAMPLE.COMalice", s2kparams: unhex("00001000") },
    { etype: 23, salt: null, s2kparams: null }        // arcfour is unsalted
  ]);
  const err = msg.encKrbError({
    stime: stime, susec: 123456,
    errorCode: 25,
    realm: "EXAMPLE.COM",
    sname: { type: 2, name: ["krbtgt", "EXAMPLE.COM"] },
    eText: "NEEDED_PREAUTH",
    eData: asn1.encSequenceOf([msg.encPaData({ type: msg.PA_TYPE.ETYPE_INFO2, value: etypeInfo2 })])
  });
  assert.strictEqual(err[0], 0x7e, "a KRB-ERROR must be tagged [APPLICATION 30] (0x7e)");

  const response = msg.readKdcResponse(err);
  assert.strictEqual(response.kind, "KRB-ERROR",
    "a KDC's error must be classified as an error, not treated as a parse failure");
  const e = response.error;
  assert.strictEqual(e.errorCode, 25, "error-code");
  assert.strictEqual(e.error.name, "KDC_ERR_PREAUTH_REQUIRED", "the code must be named");
  assert.ok(/salt/i.test(e.error.meaning),
    "the description for PREAUTH_REQUIRED must say it carries the salt, since that is the point");
  assert.strictEqual(e.stime.getTime(), stime.getTime(), "stime — which is how clock skew is measured");
  assert.strictEqual(e.crealm, null, "an absent OPTIONAL crealm reads as null");

  // e-data decoded without the caller having to know it is PA-DATA.
  assert.ok(e.eDataPaData, "e-data must be decoded as PA-DATA on this error");
  assert.strictEqual(e.eDataPaData[0].type, 19, "e-data carries PA-ETYPE-INFO2");
  const info = msg.readEtypeInfo2(e.eDataPaData[0].value);
  assert.strictEqual(info.length, 2, "both ETYPE-INFO2 entries");
  assert.strictEqual(info[0].etype, 18, "first entry's etype");
  assert.strictEqual(info[0].etypeName, "aes256-cts-hmac-sha1-96", "named etype");
  assert.strictEqual(info[0].salt, "EXAMPLE.COMalice", "THE SALT — not guessable, must come from here");
  eq("s2kparams (the iteration count)", info[0].s2kparams, "00001000");
  assert.strictEqual(info[1].salt, null, "arcfour's entry has no salt, and that is meaningful");

  // An error whose e-data is NOT PA-DATA must not throw — on other error codes
  // it is something else entirely, and a decoder that dies there loses the error
  // message the user actually needed.
  const other = msg.readKrbError(msg.encKrbError({
    stime: stime, susec: 0, errorCode: 14, realm: "EXAMPLE.COM",
    sname: { type: 2, name: ["krbtgt", "EXAMPLE.COM"] },
    eData: unhex("deadbeef")
  }));
  assert.strictEqual(other.eDataPaData, null, "unparseable e-data must read as null");
  assert.ok(/not a SEQUENCE OF PA-DATA/.test(other.eDataNote || ""),
    "and must say why, rather than looking like there was no e-data");
  assert.ok(/RC4|AES/.test(other.error.meaning),
    "ETYPE_NOSUPP's description should name the 2026 cause, since that is the whole diagnosis");

  log.debug("Leaving krbErrorsCarryTheSalt().");
}

// ---------------------------------------------------------------------------
// PA-ENC-TIMESTAMP: the second half of the pre-authentication round trip.
// ---------------------------------------------------------------------------
async function preAuthTimestampUsesTheSaltAndItsOwnKeyUsage() {
  log.debug("Entering preAuthTimestampUsesTheSaltAndItsOwnKeyUsage().");
  const e = kcrypto.etypeById(18);
  const salt = "EXAMPLE.COMalice";
  const key = await e.stringToKey("hunter2", prim.utf8(salt), unhex("00001000"));
  const when = new Date(Date.UTC(2026, 7, 13, 12, 0, 5));

  const tsEnc = msg.encPaEncTsEnc(when, 654321);
  const padata = {
    type: msg.PA_TYPE.ENC_TIMESTAMP,
    value: msg.encEncryptedData({
      etype: 18,
      // Key usage 1, and ONLY key usage 1: the KDC decrypts with that number and
      // any other produces an integrity failure it reports as PREAUTH_FAILED —
      // i.e. as a wrong password.
      cipher: await e.encrypt(key, kcrypto.KEY_USAGE.AS_REQ_PA_ENC_TIMESTAMP, tsEnc)
    })
  };

  // The KDC's side.
  const seen = msg.readPaData(asn1.readTlv(msg.encPaData(padata), 0));
  const enc = msg.readEncryptedData(asn1.readTlv(seen.value, 0));
  const decrypted = await e.decrypt(key, kcrypto.KEY_USAGE.AS_REQ_PA_ENC_TIMESTAMP, enc.cipher);
  const ts = msg.readPaEncTsEnc(decrypted);
  assert.strictEqual(ts.patimestamp.getTime(), when.getTime(), "the timestamp must survive");
  assert.strictEqual(ts.pausec, 654321, "microseconds");

  // A KDC that used the wrong usage number sees a wrong password.
  await assert.rejects(
    () => e.decrypt(key, kcrypto.KEY_USAGE.AS_REP_ENCPART, enc.cipher),
    /integrity check failed/,
    "decrypting a PA-ENC-TIMESTAMP under the wrong key usage must fail");

  // And the salt matters: the same password with the wrong salt is a different key.
  const wrongSaltKey = await e.stringToKey("hunter2", prim.utf8("EXAMPLE.COMAlice"), unhex("00001000"));
  await assert.rejects(
    () => e.decrypt(wrongSaltKey, kcrypto.KEY_USAGE.AS_REQ_PA_ENC_TIMESTAMP, enc.cipher),
    /integrity check failed/,
    "a salt differing only in case must produce a different key — AD's salt is case-sensitive");

  log.debug("Leaving preAuthTimestampUsesTheSaltAndItsOwnKeyUsage().");
}

// ---------------------------------------------------------------------------
// AP-REQ / AP-REP and the Authenticator.
// ---------------------------------------------------------------------------
async function apExchangeRoundTrips() {
  log.debug("Entering apExchangeRoundTrips().");
  const e = kcrypto.etypeById(18);
  const sessionKey = kcrypto.randomBytes(32);
  const ctime = new Date(Date.UTC(2026, 7, 13, 12, 30, 0));

  const auth = msg.encAuthenticator({
    crealm: "EXAMPLE.COM",
    cname: { type: 1, name: ["alice"] },
    cksum: { type: -138, checksum: unhex("00112233445566778899aabbccddeeff") },
    cusec: 12345,
    ctime: ctime,
    subkey: { etype: 18, key: kcrypto.randomBytes(32) },
    seqNumber: 1234567890
  });
  const apReq = msg.encApReq({
    apOptions: [msg.AP_OPTION.MUTUAL_REQUIRED],
    ticket: { realm: "EXAMPLE.COM", sname: { type: 3, name: ["HTTP", "web.example.com"] },
              encPart: { etype: 18, cipher: kcrypto.randomBytes(64) } },
    authenticator: { etype: 18, cipher: await e.encrypt(sessionKey, kcrypto.KEY_USAGE.AP_REQ_AUTH, auth) }
  });
  assert.strictEqual(apReq[0], 0x6e, "an AP-REQ must be tagged [APPLICATION 14] (0x6e)");

  const back = msg.readApReq(apReq);
  assert.deepStrictEqual(msg.apOptionNames(back.apOptions), ["mutual-required"],
    "ap-options must render by name");
  assert.deepStrictEqual(back.ticket.sname.name, ["HTTP", "web.example.com"], "the SPN");
  const readAuth = msg.readAuthenticator(
    await e.decrypt(sessionKey, kcrypto.KEY_USAGE.AP_REQ_AUTH, back.authenticator.cipher));
  assert.strictEqual(readAuth.cksum.type, -138,
    "a negative checksum type must survive the whole round trip");
  assert.strictEqual(readAuth.ctime.getTime(), ctime.getTime(), "ctime");
  assert.strictEqual(readAuth.seqNumber, 1234567890, "seq-number");
  assert.ok(readAuth.subkey && readAuth.subkey.key.length === 32, "the subkey must survive");

  // The mutual-authentication reply.
  const apRep = msg.encApRep({
    encPart: { etype: 18, cipher: await e.encrypt(sessionKey, kcrypto.KEY_USAGE.AP_REP_ENCPART,
      msg.encEncApRepPart({ ctime: ctime, cusec: 12345, seqNumber: 987654321 })) }
  });
  assert.strictEqual(apRep[0], 0x6f, "an AP-REP must be tagged [APPLICATION 15] (0x6f)");
  const repPart = msg.readEncApRepPart(
    await e.decrypt(sessionKey, kcrypto.KEY_USAGE.AP_REP_ENCPART, msg.readApRep(apRep).encPart.cipher));
  assert.strictEqual(repPart.ctime.getTime(), ctime.getTime(),
    "the AP-REP echoes the authenticator's ctime — that echo IS the mutual authentication");
  assert.strictEqual(repPart.seqNumber, 987654321, "the acceptor's sequence number");

  log.debug("Leaving apExchangeRoundTrips().");
}

// ---------------------------------------------------------------------------
// S4U2Self's PA-FOR-USER, which is why negative integers had to work.
// ---------------------------------------------------------------------------
function paForUserRoundTrips() {
  log.debug("Entering paForUserRoundTrips().");
  const bytes = msg.encPaForUser({
    userName: { type: msg.NAME_TYPE.PRINCIPAL, name: ["bob"] },
    userRealm: "EXAMPLE.COM",
    cksum: { type: -138, checksum: unhex("00112233445566778899aabbccddeeff") },
    authPackage: "Kerberos"
  });
  const back = msg.readPaForUser(bytes);
  assert.deepStrictEqual(back.userName.name, ["bob"], "the impersonated user");
  assert.strictEqual(back.userRealm, "EXAMPLE.COM", "the user's realm");
  assert.strictEqual(back.cksum.type, -138, "KERB_CHECKSUM_HMAC_MD5 is negative");
  assert.strictEqual(back.authPackage, "Kerberos", "auth-package");
  log.debug("Leaving paForUserRoundTrips().");
}

// ---------------------------------------------------------------------------
// The structural tree, which is the decoder page's fallback for bytes no reader
// recognises. Its value is showing a codec bug: a field under the wrong context
// tag is obvious here and invisible in a semantic view that skipped it.
// ---------------------------------------------------------------------------
function theTreeViewDescribesUnknownBytes() {
  log.debug("Entering theTreeViewDescribesUnknownBytes().");
  const bytes = msg.encPrincipalName({ type: 1, name: ["alice", "admin"] });
  const nodes = asn1.tree(bytes);
  assert.strictEqual(nodes.length, 1, "one top-level element");
  assert.strictEqual(nodes[0].tagName, "SEQUENCE", "the outer element is a SEQUENCE");
  assert.strictEqual(nodes[0].children.length, 2, "two context-tagged fields");
  assert.strictEqual(nodes[0].children[0].tagName, "[0]", "the first field's tag is shown as [0]");
  assert.strictEqual(nodes[0].children[0].children[0].text, "1", "and its INTEGER is rendered");
  const names = nodes[0].children[1].children[0].children.map(function (c) { return c.text; });
  assert.deepStrictEqual(names, ["alice", "admin"], "the name components are readable");

  // Opaque bytes render as hex rather than throwing.
  const opaque = asn1.tree(asn1.encOctetString(unhex("deadbeef")));
  assert.strictEqual(opaque[0].text, "deadbeef", "an OCTET STRING renders as hex");

  // A flags BIT STRING names the bits that are set.
  const flagTree = asn1.tree(asn1.encFlags([1, 8]));
  assert.ok(/1, 8/.test(flagTree[0].text), "a KerberosFlags renders which bits are set: " + flagTree[0].text);
  log.debug("Leaving theTreeViewDescribesUnknownBytes().");
}

// ---------------------------------------------------------------------------
// The negative half.
//
// This codec parses bytes pasted into a web page by whoever is using it, and
// bytes returned by a host the user named. Both are untrusted.
// ---------------------------------------------------------------------------
function refusesMalformedAndHostileInput() {
  log.debug("Entering refusesMalformedAndHostileInput().");

  mustThrow("empty input", () => asn1.readTlv(new Uint8Array(0), 0), /truncated/);
  mustThrow("a tag with no length", () => asn1.readTlv(unhex("30"), 0), /truncated/);
  mustThrow("a length claiming more than is present",
    () => asn1.readTlv(unhex("300a0102"), 0), /claims 10 bytes but only 2 remain/);
  mustThrow("an indefinite length (BER, not DER)",
    () => asn1.readTlv(unhex("3080020101 0000"), 0), /indefinite/);
  mustThrow("a length field of five bytes",
    () => asn1.readTlv(unhex("3085 0100000000"), 0), /length field of 5 bytes/);

  mustThrow("not a Kerberos message at all",
    () => msg.readKdcReq(unhex("3003020101")), /not a Kerberos message/);
  mustThrow("a Kerberos message of the wrong type",
    () => msg.readKdcReq(msg.encApRep({ encPart: { etype: 18, cipher: unhex("00") } })),
    /expected AS-REQ .* or TGS-REQ/);
  mustThrow("an AP-REP read as a KDC response",
    () => msg.readKdcResponse(msg.encApRep({ encPart: { etype: 18, cipher: unhex("00") } })),
    /neither a reply nor an error/);
  assert.strictEqual(msg.identify(unhex("3003020101")), null,
    "identify() must answer null rather than throwing for non-Kerberos bytes");

  // A protocol version this codec does not speak must be named, because a pvno
  // of 4 means something quite different is on the other end.
  const v4 = asn1.encApplication(10, asn1.encTaggedSequence([
    { tag: 1, value: asn1.encInteger(4) },
    { tag: 2, value: asn1.encInteger(10) },
    { tag: 4, value: msg.encKdcReqBody({ kdcOptions: [], realm: "X", till: new Date(), nonce: 1, etypes: [18] }) }
  ]));
  mustThrow("pvno 4", () => msg.readKdcReq(v4), /protocol version 4/);

  // A context tag wrapping more than one element is malformed and must not be
  // silently reduced to its first element.
  const doubled = asn1.encSequence([asn1.encContext(0, prim.concat([asn1.encInteger(1), asn1.encInteger(2)]))]);
  mustThrow("a context tag wrapping two elements",
    () => asn1.readTaggedSequence(asn1.readTlv(doubled, 0).value), /wraps 2 elements/);

  // A SEQUENCE whose members are not context-tagged is not one of these
  // structures.
  mustThrow("an untagged SEQUENCE where a tagged one belongs",
    () => asn1.readTaggedSequence(asn1.readTlv(asn1.encSequence([asn1.encInteger(1)]), 0).value),
    /expected a context tag/);

  // Type confusion: an OCTET STRING where an INTEGER belongs.
  mustThrow("an OCTET STRING read as an INTEGER",
    () => asn1.decInteger(asn1.readTlv(asn1.encOctetString(unhex("01")), 0)),
    /expected an INTEGER/);

  // KerberosTime with fractional seconds — what a well-meaning implementation
  // built on toISOString() emits.
  mustThrow("a KerberosTime with milliseconds",
    () => asn1.parseKerberosTime("20260813090507.456Z"), /YYYYMMDDHHMMSSZ/);
  mustThrow("a KerberosTime with an offset",
    () => asn1.parseKerberosTime("20260813090507+0100"), /YYYYMMDDHHMMSSZ/);

  // An input larger than the parser will consider. A length field is an
  // attacker-controlled allocation, and the decoder page parses whatever is
  // pasted into it.
  mustThrow("an input over the size limit",
    () => asn1.readApplication(new Uint8Array(asn1.MAX_INPUT_BYTES + 1)), /refusing to parse/);
  mustThrow("a tree over the size limit",
    () => asn1.tree(new Uint8Array(asn1.MAX_INPUT_BYTES + 1)), /refusing to parse/);

  // Deeply nested input must hit the depth limit rather than the stack — and for
  // the TREE view the limit is a display cap, not a refusal: bytes pasted into
  // the decoder page should render as far as they go. What must not happen is a
  // silent cap, where a constructed element renders as a hex leaf and so reads as
  // opaque data. It has to say it stopped.
  var nested = asn1.encInteger(1);
  for (var i = 0; i < 40; i++) nested = asn1.encSequence([nested]);
  var deep = asn1.tree(nested);
  var node = deep[0], levels = 0;
  while (node && node.children) { node = node.children[0]; levels++; }
  assert.ok(levels > 8, "the tree must expand a good way down, got " + levels + " levels");
  assert.strictEqual(node.depthLimited, true,
    "the deepest rendered node must be MARKED as depth-limited, not left looking like a leaf");
  assert.ok(/nesting deeper than/.test(node.text),
    "and must say so in the text the page will show: " + node.text);

  // The reading path, unlike the tree, DOES refuse: a message nested past the
  // limit is malformed rather than merely awkward to display.
  mustThrow("a tagged sequence nested past the depth limit",
    () => asn1.readTaggedSequence(asn1.readTlv(nested, 0).value, asn1.MAX_DEPTH),
    /nested deeper than|expected a context tag/);

  // A non-integer where an INTEGER belongs, caught on the WRITE side: a float
  // reaching the encoder would otherwise be truncated silently.
  mustThrow("a non-integer INTEGER", () => asn1.encInteger(1.5), /whole number/);
  mustThrow("a flag bit out of range", () => asn1.encFlags([32]), /out of range/);
  mustThrow("an unparseable principal", () => msg.parsePrincipal("///"), /empty principal/);

  log.debug("Leaving refusesMalformedAndHostileInput().");
}

// ---------------------------------------------------------------------------
// Principal parsing, which is where a user's typing meets the protocol.
// ---------------------------------------------------------------------------
function principalsParseWithTheRightNameTypes() {
  log.debug("Entering principalsParseWithTheRightNameTypes().");
  const cases = [
    ["alice", msg.NAME_TYPE.PRINCIPAL, ["alice"], null],
    ["alice@EXAMPLE.COM", msg.NAME_TYPE.PRINCIPAL, ["alice"], "EXAMPLE.COM"],
    ["krbtgt/EXAMPLE.COM", msg.NAME_TYPE.SRV_INST, ["krbtgt", "EXAMPLE.COM"], null],
    ["krbtgt/EXAMPLE.COM@EXAMPLE.COM", msg.NAME_TYPE.SRV_INST, ["krbtgt", "EXAMPLE.COM"], "EXAMPLE.COM"],
    ["HTTP/web.example.com", msg.NAME_TYPE.SRV_HST, ["HTTP", "web.example.com"], null],
    ["MSSQLSvc/db.example.com:1433", msg.NAME_TYPE.SRV_HST, ["MSSQLSvc", "db.example.com:1433"], null]
  ];
  cases.forEach(function (c) {
    const p = msg.parsePrincipal(c[0]);
    assert.strictEqual(p.type, c[1], c[0] + ": name-type");
    assert.deepStrictEqual(p.name, c[2], c[0] + ": components");
    assert.strictEqual(p.realm, c[3], c[0] + ": realm");
  });
  // The realm is NOT folded to upper case: a lower-case realm is the commonest
  // configuration error there is, and hiding it would be the wrong kindness.
  assert.strictEqual(msg.parsePrincipal("alice@example.com").realm, "example.com",
    "the realm must be left exactly as typed");
  assert.strictEqual(msg.principalToString({ name: ["HTTP", "web.example.com"] }, "EXAMPLE.COM"),
    "HTTP/web.example.com@EXAMPLE.COM", "display form");
  log.debug("Leaving principalsParseWithTheRightNameTypes().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. Verifying the Kerberos v5 DER codec and message structures (RFC 4120).");
  derEncodesMinimally();
  structuresEncodeToTheExpectedBytes();
  kdcRequestsRoundTrip();
  await kdcRepliesRoundTripAndTolerateTheIrregularTag();
  relayedTicketsAreByteExact();
  krbErrorsCarryTheSalt();
  await preAuthTimestampUsesTheSaltAndItsOwnKeyUsage();
  await apExchangeRoundTrips();
  paForUserRoundTrips();
  theTreeViewDescribesUnknownBytes();
  principalsParseWithTheRightNameTypes();
  refusesMalformedAndHostileInput();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("krb5_codec")
  .description("Verify the Kerberos v5 DER codec: byte-exact encodings, round trips, and the compatibility cases.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>", "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
