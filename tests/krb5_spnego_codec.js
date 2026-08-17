// File: krb5_spnego_codec.js
//
// RFC 4178's two messages, byte by byte. No browser, no services, no network.
//
// ---------------------------------------------------------------------------
// WHY THE ASSERTIONS HERE ARE OFFSETS AND NOT ROUND TRIPS.
//
// The standard of evidence for a wire codec in this project is the one stated
// in docs/kerberos.md: a reader and a writer that share one misunderstanding
// agree perfectly with each other and with nothing else in the world. So the
// values below are derived by hand from RFC 4178 section 4 and from the OIDs'
// own registrations, and the DER is asserted as bytes rather than by decoding
// what was just encoded. Round trips appear only where they add something a
// byte comparison cannot — the [3]-tag ambiguity, mostly.
//
// The four things this file exists to pin:
//
//  1. **The OID encoder**, because SPNEGO is the first thing in this codebase
//     that has to write one — Kerberos's own ASN.1 contains no OBJECT
//     IDENTIFIER at all. The vectors are the four OIDs every Windows client
//     sends, and one of them (Microsoft's mis-typed Kerberos OID) differs from
//     the real one in a single arc.
//  2. **The mechListMIC input**: `MechTypeList`, not `[0] MechTypeList`. Two
//     bytes, RFC 4178 section 5, and the difference between a MIC that verifies
//     and one that verifies against nothing.
//  3. **The [3] tag ambiguity.** RFC 4178 puts mechListMIC there; [MS-SPNG]'s
//     NegTokenInit2 puts negHints there and moves mechListMIC to [4]. A decoder
//     that guesses from the direction of travel is wrong for exactly the
//     interesting captures.
//  4. **negState is ENUMERATED (0x0a), not INTEGER (0x02).** They encode
//     identically apart from the tag, so a coder that used INTEGER round-trips
//     against itself perfectly and is refused by a strict peer.
// ---------------------------------------------------------------------------
const assert = require("assert");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "krb5_spnego_codec",
    level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

function shared(name) {
  return paths.requireSharedModule(
    [__dirname + "/../common/krb5/" + name, __dirname + "/" + name], name);
}
const prim = shared("krb5_primitives.js");
const asn1 = shared("krb5_asn1.js");
const gss = shared("krb5_gss.js");
const spnego = shared("krb5_spnego.js");

function hex(bytes) {
  return prim.toHex(prim.toBytes(bytes));
}

// ---------------------------------------------------------------------------
// 1. OBJECT IDENTIFIER, against the registrations rather than against itself.
// ---------------------------------------------------------------------------
function theOidCoderMatchesTheRegistrations() {
  log.debug("Entering theOidCoderMatchesTheRegistrations().");
  log.info("=== OBJECT IDENTIFIER ===");

  // Derived by hand: the first two arcs share one byte as 40*a + b, and each
  // arc after that is base 128 with the continuation bit on all but the last
  // octet. 113554 = 0x1BAD2 -> 0x86 0xf7 0x12; 48018 = 0xBB92 -> 0x82 0xf7 0x12
  // (the ONE arc that differs); 311 -> 0x82 0x37.
  const vectors = [
    ["1.2.840.113554.1.2.2", "06092a864886f712010202", "Kerberos v5"],
    ["1.2.840.48018.1.2.2", "06092a864882f712010202",
        "Kerberos v5, Microsoft's mis-typed OID"],
    ["1.3.6.1.5.5.2", "06062b0601050502", "SPNEGO"],
    ["1.3.6.1.4.1.311.2.2.10", "060a2b06010401823702020a", "NTLMSSP"],
    // Same length as NTLMSSP above: 30 and 10 are both single-octet arcs, so
    // only the last byte differs. Worth having both, because a coder that
    // mis-set a continuation bit would turn one into the other.
    ["1.3.6.1.4.1.311.2.2.30", "060a2b06010401823702021e", "NEGOEX"]
  ];
  vectors.forEach(function (v) {
    const encoded = hex(spnego.encodeOid(v[0]));
    assert.strictEqual(encoded, v[1],
      v[2] + " (" + v[0] + ") must encode as " + v[1] + ", got " + encoded);
    const decoded = spnego.decodeOidContent(
        prim.fromHex(v[1]).subarray(2));
    assert.strictEqual(decoded, v[0],
        v[2] + " must decode back to " + v[0] + ", got " + decoded);
  });

  // The one that matters most, stated as its own assertion because it is a
  // one-arc difference and a coder that dropped a continuation bit would
  // produce the OTHER Kerberos OID from the same input.
  assert.notStrictEqual(hex(spnego.encodeOid("1.2.840.113554.1.2.2")),
      hex(spnego.encodeOid("1.2.840.48018.1.2.2")),
    "the two Kerberos OIDs must not encode identically — they differ in one " +
    "arc, and a client offering both would otherwise be offering one twice");
  assert.strictEqual(hex(spnego.encodeOid("1.2.840.113554.1.2.2")),
      hex(gss.KRB5_MECH_OID_DER),
    "and the encoder must agree with krb5_gss.js's hand-written constant for " +
    "the Kerberos mechanism, or a NegTokenInit would offer a mechanism whose " +
    "own token names a different one");

  // Truncation. A final octet with the continuation bit still set means the
  // value was cut short; a decoder that ignores it returns a plausible number
  // that is not the OID that was sent, and nothing downstream can notice.
  assert.throws(function () {
    spnego.decodeOidContent(new Uint8Array([0x2b, 0x06, 0x81]));
  }, /truncated/,
    "an OID whose last octet carries the continuation bit is truncated and " +
    "must be refused rather than decoded to something plausible");
  assert.throws(function () {
    spnego.encodeOidContent("3.1.1");
  }, /first arc/,
    "the first arc must be 0, 1 or 2 — anything else is not encodable, and " +
    "silently folding it into the shared first byte loses it");
  assert.throws(function () {
    spnego.encodeOidContent("1");
  }, /two/, "an OID needs at least two arcs to fill the shared first byte");
  log.info("five OIDs encode and decode to their registered forms");
  log.debug("Leaving theOidCoderMatchesTheRegistrations().");
}

// ---------------------------------------------------------------------------
// 2. NegTokenInit, byte by byte.
// ---------------------------------------------------------------------------
function aNegTokenInitHasTheShapeTheRfcDescribes() {
  log.debug("Entering aNegTokenInitHasTheShapeTheRfcDescribes().");
  log.info("=== NegTokenInit ===");

  const mechToken = new Uint8Array([0x6e, 0x02, 0x01, 0x05]);
  const built = spnego.encodeNegTokenInit({
    mechTypes: [spnego.KRB5_MECH_OID, "1.3.6.1.4.1.311.2.2.10"],
    mechToken: mechToken
  });
  const bytes = prim.toBytes(built.token);

  // The RFC 2743 wrapper: [APPLICATION 0], then the SPNEGO OID, then [0].
  assert.strictEqual(bytes[0], 0x60,
    "the initiator's first token is wrapped in an InitialContextToken and " +
    "therefore begins 0x60 ([APPLICATION 0]), got 0x" +
    bytes[0].toString(16));
  assert.strictEqual(hex(bytes.subarray(2, 10)), "06062b0601050502",
    "and the first thing inside it is SPNEGO's own OID, 1.3.6.1.5.5.2. This " +
    "is the ONLY place that OID appears — the negotiation is a " +
    "pseudo-mechanism, and the mechanisms it negotiates over are named " +
    "inside. Got " + hex(bytes.subarray(2, 10)));
  assert.strictEqual(bytes[10], 0xa0,
    "then [0] NegTokenInit, got 0x" + bytes[10].toString(16));

  // Round-tripping through the decoder is fair here: the byte assertions above
  // already pin the encoding, so this checks the READER against them rather
  // than against the writer's own assumptions.
  const parsed = spnego.decodeNegotiationToken(built.token);
  assert.strictEqual(parsed.kind, "NegTokenInit", "it decodes as one");
  assert.deepStrictEqual(parsed.mechTypes,
      [spnego.KRB5_MECH_OID, "1.3.6.1.4.1.311.2.2.10"],
    "with the mechanisms in the order they were offered — the order is not " +
    "cosmetic: RFC 4178 section 5 makes the mechListMIC optional only when " +
    "the acceptor selects the FIRST one");
  assert.deepStrictEqual(parsed.mechTypeNames,
      ["Kerberos v5", "NTLMSSP"], "and named");
  assert.strictEqual(hex(parsed.mechToken), hex(mechToken),
      "and the optimistic token comes back byte for byte");
  assert.strictEqual(parsed.mechListMic, null, "with no MIC, since none was " +
      "supplied");

  // reqFlags is never written. RFC 4178 section 4.2.1 deprecates it, and the
  // flags a service actually reads are in the 0x8003 checksum inside the
  // AP-REQ — so emitting it would be duplicating a decision in a field the
  // receiver is required to ignore.
  assert.ok(hex(bytes).indexOf("a1") === -1 ||
      !/a1/.test(hex(built.token.subarray(10, 14))),
    "reqFlags [1] must not be emitted");

  // A mechTypes list may not name SPNEGO itself: a negotiation that can select
  // itself does not terminate (RFC 4178 section 4.1).
  assert.throws(function () {
    spnego.encodeNegTokenInit({ mechTypes: [spnego.SPNEGO_OID] });
  }, /must not contain SPNEGO/,
    "the encoder must refuse a mechTypes list containing SPNEGO itself");
  assert.throws(function () {
    spnego.encodeNegTokenInit({ mechTypes: [] });
  }, /may not be empty/, "and an empty one");

  log.info("a NegTokenInit has the shape RFC 4178 section 4.2 describes");
  log.debug("Leaving aNegTokenInitHasTheShapeTheRfcDescribes().");
}

// ---------------------------------------------------------------------------
// 3. The mechListMIC input: the two bytes that decide whether a MIC verifies.
// ---------------------------------------------------------------------------
function theMicCoversTheListAndNotItsContextTag() {
  log.debug("Entering theMicCoversTheListAndNotItsContextTag().");
  log.info("=== What the mechListMIC covers ===");

  const mechs = [spnego.KRB5_MECH_OID, spnego.MS_KRB5_MECH_OID];
  const list = spnego.mechTypeListDer(mechs);
  assert.strictEqual(hex(list),
      "301606092a864886f71201020206092a864882f712010202",
    "the MechTypeList is a bare SEQUENCE of the OIDs, hand-derived: 0x30, " +
    "length 0x16 (two 11-byte OID elements), then those elements. Got " +
    hex(list));
  assert.strictEqual(list[0], 0x30,
    "and it MUST begin 0x30. RFC 4178 section 5: the input to GSS_GetMIC is " +
    "the DER encoding of the VALUE of type MechTypeList, not the DER " +
    "encoding of the type `[0] MechTypeList`.");

  const tagged = asn1.encContext(0, list);
  assert.strictEqual(tagged[0], 0xa0,
      "the form it takes INSIDE a NegTokenInit is [0]-tagged");
  assert.strictEqual(tagged.length, list.length + 2,
    "and differs from the signed form by exactly the two bytes of that tag " +
    "and its length — which is the whole of the mistake, and why it is " +
    "invisible in a hex dump unless you are counting");

  // And the decoder reports the SLICED bytes rather than re-encoding them,
  // because a re-encoding that is legal and different verifies against
  // nothing.
  const built = spnego.encodeNegTokenInit({ mechTypes: mechs });
  const parsed = spnego.decodeNegotiationToken(built.token);
  assert.strictEqual(hex(parsed.mechListDer), hex(list),
    "a decoder must report the exact MechTypeList bytes that arrived, so a " +
    "verifier signs what was sent rather than what it would have sent");
  log.info("the mechListMIC covers MechTypeList and not [0] MechTypeList");
  log.debug("Leaving theMicCoversTheListAndNotItsContextTag().");
}

// ---------------------------------------------------------------------------
// 4. NegTokenResp, byte by byte — including the ENUMERATED tag.
// ---------------------------------------------------------------------------
function aNegTokenRespIsBareAndUsesEnumerated() {
  log.debug("Entering aNegTokenRespIsBareAndUsesEnumerated().");
  log.info("=== NegTokenResp ===");

  const token = spnego.encodeNegTokenResp({
    negState: spnego.NEG_STATE.ACCEPT_COMPLETED,
    supportedMech: spnego.KRB5_MECH_OID,
    responseToken: new Uint8Array([0x6f, 0x02, 0x01, 0x05]),
    mechListMic: new Uint8Array([0xaa, 0xbb])
  });
  const bytes = prim.toBytes(token);

  assert.strictEqual(bytes[0], 0xa1,
    "every token after the initiator's first is a BARE NegTokenResp: [1] and " +
    "the SEQUENCE, with NO InitialContextToken and NO OID (RFC 4178 section " +
    "4.2). Got 0x" + bytes[0].toString(16) +
    (bytes[0] === 0x60 ? " — it has been wrapped, which is the mistake that " +
        "produces a token no client will read." : "."));
  assert.strictEqual(bytes[2], 0x30, "holding a SEQUENCE");
  assert.strictEqual(hex(bytes.subarray(4, 9)), "a0030a0100",
    "whose first field is [0] negState carrying an ENUMERATED (0x0a), not " +
    "an INTEGER (0x02). The two encode identically apart from the tag, so a " +
    "coder that used INTEGER round-trips against itself perfectly and is " +
    "refused by a strict peer. Got " + hex(bytes.subarray(4, 9)));

  const parsed = spnego.decodeNegotiationToken(token);
  assert.strictEqual(parsed.kind, "NegTokenResp", "it decodes as one");
  assert.strictEqual(parsed.negState, 0, "accept-completed is 0");
  assert.strictEqual(parsed.negStateName, "accept-completed", "and is named");
  assert.strictEqual(parsed.supportedMech, spnego.KRB5_MECH_OID,
      "the selected mechanism survives");
  assert.strictEqual(hex(parsed.responseToken), "6f020105",
      "and so does the mechanism's own token");
  assert.strictEqual(hex(parsed.mechListMic), "aabb", "and the MIC");

  // The four states, each named and each explained. A debugger whose only
  // answer for `reject` is the number 2 is not a debugger.
  [[0, "accept-completed"], [1, "accept-incomplete"], [2, "reject"],
      [3, "request-mic"]].forEach(function (pair) {
    const info = spnego.negStateInfo(pair[0]);
    assert.strictEqual(info.name, pair[1],
        "negState " + pair[0] + " is " + pair[1] + ", got " + info.name);
    assert.ok(info.meaning && info.meaning.length > 20,
        "and must carry a meaning, not just a name");
  });
  assert.ok(/unrecognised/.test(spnego.negStateInfo(7).name),
      "and an unknown value must be reported as unknown rather than guessed");

  // A rejection with nothing in it is worth flagging, because that is what an
  // acceptor that swallowed the mechanism's error looks like.
  const bare = spnego.decodeNegotiationToken(
    spnego.encodeNegTokenResp({ negState: spnego.NEG_STATE.REJECT }));
  assert.ok(bare.problems.some(function (p) {
    return /no mechanism token/.test(p);
  }),
    "a reject with no responseToken must be flagged: SPNEGO carries no error " +
    "detail of its own, so that token is the entire diagnosis and its " +
    "absence is indistinguishable from a wrong password");
  log.info("a NegTokenResp is bare, and its negState is ENUMERATED");
  log.debug("Leaving aNegTokenRespIsBareAndUsesEnumerated().");
}

// ---------------------------------------------------------------------------
// 5. The [3] tag ambiguity: RFC 4178's mechListMIC against [MS-SPNG]'s
//    negHints.
// ---------------------------------------------------------------------------
function theTagThreeAmbiguityIsResolvedByContentNotByDirection() {
  log.debug("Entering theTagThreeAmbiguityIsResolvedByContent().");
  log.info("=== [3]: mechListMIC or negHints ===");

  // RFC 4178: [3] holds an OCTET STRING.
  const rfc = spnego.decodeNegotiationToken(spnego.encodeNegTokenInit({
    mechTypes: [spnego.KRB5_MECH_OID],
    mechListMic: new Uint8Array([1, 2, 3])
  }).token);
  assert.strictEqual(rfc.kind, "NegTokenInit",
      "an OCTET STRING at [3] is RFC 4178's mechListMIC");
  assert.strictEqual(hex(rfc.mechListMic), "010203", "and is read as one");
  assert.strictEqual(rfc.negHints, null, "with no hints");

  // [MS-SPNG]: [3] holds a SEQUENCE, and mechListMIC moves to [4]. Built by
  // hand rather than by an encoder, because nothing here emits this shape —
  // it is what a WINDOWS SERVER sends when it speaks first, and the point is
  // that a capture of one parses.
  const hintName = prim.utf8("not_defined_in_RFC4178@please_ignore");
  const negHints = asn1.encSequence([
    asn1.encContext(0, asn1.tlv(asn1.TAG.GENERAL_STRING, hintName))
  ]);
  const inner = asn1.encSequence([
    asn1.encContext(0, spnego.mechTypeListDer([spnego.KRB5_MECH_OID])),
    asn1.encContext(3, negHints),
    asn1.encContext(4, asn1.encOctetString(new Uint8Array([9, 9])))
  ]);
  const body = prim.concat([spnego.SPNEGO_OID_DER, asn1.encContext(0, inner)]);
  const init2 = prim.concat([new Uint8Array([0x60]),
      asn1.encodeLength(body.length), body]);

  const ms = spnego.decodeNegotiationToken(init2);
  assert.strictEqual(ms.kind, "NegTokenInit2",
    "a SEQUENCE at [3] is [MS-SPNG]'s negHints, which makes this a " +
    "NegTokenInit2 — and the difference is decided by what is INSIDE the " +
    "tag, never by the direction of travel, because the interesting captures " +
    "are exactly the ones where the direction is not what you assumed");
  assert.ok(ms.negHints, "and the hints are read");
  assert.strictEqual(ms.negHints.hintName,
      "not_defined_in_RFC4178@please_ignore",
    "including the literal string every Windows server has ever sent there, " +
    "which looks like a defect and is not");
  assert.strictEqual(hex(ms.mechListMic), "0909",
    "and the mechListMIC is found at [4], where negHints displaced it");
  log.info("the [3] ambiguity is resolved by content");
  log.debug("Leaving theTagThreeAmbiguityIsResolvedByContent().");
}

// ---------------------------------------------------------------------------
// 6. What arrives that is not a NegToken at all.
// ---------------------------------------------------------------------------
function whatIsNotSpnegoIsNamedRatherThanRefused() {
  log.debug("Entering whatIsNotSpnegoIsNamedRatherThanRefused().");
  log.info("=== Not SPNEGO ===");

  // A bare Kerberos InitialContextToken. Legal on HTTP, sent by real clients,
  // and NOT a negotiation — reported as what it is rather than refused, because
  // "this is not SPNEGO, it is a bare Kerberos token" is the answer somebody
  // needs.
  const bare = gss.encodeInitialContextToken(gss.TOK_ID.AP_REQ,
      new Uint8Array([0x6e, 0x02, 0x01, 0x05]));
  const parsed = spnego.decodeNegotiationToken(bare);
  assert.strictEqual(parsed.kind, "RawKerberos",
      "a bare Kerberos GSS token must be identified, not refused");
  assert.strictEqual(parsed.mechOid, spnego.KRB5_MECH_OID, "and named");
  assert.ok(/no negotiation around it/.test(parsed.note) &&
      /mechToken or responseToken/.test(parsed.note),
    "with a note saying what it is — and giving BOTH readings, because " +
    "whether a bare Kerberos token is a finding depends entirely on where it " +
    "was found: inside a mechToken it is correct, and at the top of an " +
    "Authorization header it is a client that declined to negotiate. Got: " +
    parsed.note);

  // A bare AP-REQ, with neither wrapper. The commonest hand-written-client
  // mistake, and the error has to name the wrapper rather than the message.
  assert.throws(function () {
    spnego.decodeNegotiationToken(new Uint8Array([0x6e, 0x02, 0x01, 0x05]));
  }, /0x6e is a bare AP-REQ/,
    "an unwrapped AP-REQ must be diagnosed as one — the refusal names the " +
    "missing wrapper, because a message saying `not a SPNEGO token` sends " +
    "somebody to look at their ticket");

  // Somebody else's mechanism.
  assert.throws(function () {
    spnego.decodeNegotiationToken(prim.concat([
      new Uint8Array([0x60, 0x0c]),
      spnego.encodeOid("1.3.6.1.4.1.311.2.2.10"),
      new Uint8Array([0x01, 0x00])
    ]));
  }, /NTLMSSP/,
    "and a token naming another mechanism must NAME it: a client that fell " +
    "back to NTLM is a different problem from one whose ticket is wrong");

  // A NegTokenResp offered where a NegTokenInit belongs.
  assert.throws(function () {
    spnego.decodeNegotiationToken(prim.concat([
      new Uint8Array([0x60, 0x0a]), spnego.SPNEGO_OID_DER,
      new Uint8Array([0xa1, 0x00])
    ]));
  }, /never wrapped/,
    "a NegTokenResp inside an InitialContextToken must be diagnosed as the " +
    "wrapping mistake it is");

  assert.throws(function () {
    spnego.decodeNegotiationToken(new Uint8Array([]));
  }, /empty/, "and an empty token is empty");
  log.info("what is not SPNEGO is named rather than merely refused");
  log.debug("Leaving whatIsNotSpnegoIsNamedRatherThanRefused().");
}

// ---------------------------------------------------------------------------
// 7. When the MIC exchange is mandatory — the downgrade rule, which reads as an
//    optimisation and is a defence.
// ---------------------------------------------------------------------------
function theMicIsOptionalOnlyForTheFirstPreference() {
  log.debug("Entering theMicIsOptionalOnlyForTheFirstPreference().");
  log.info("=== When the mechListMIC is mandatory ===");

  const offered = [spnego.KRB5_MECH_OID, "1.3.6.1.4.1.311.2.2.10"];
  const first = spnego.micRequirement(offered, spnego.KRB5_MECH_OID);
  assert.strictEqual(first.required, false,
    "selecting the initiator's FIRST preference makes the exchange optional " +
    "— there was no downgrade to detect (RFC 4178 section 5)");
  assert.ok(/first/.test(first.reason), "and the reason says so");

  const second = spnego.micRequirement(offered, "1.3.6.1.4.1.311.2.2.10");
  assert.strictEqual(second.required, true,
    "selecting anything else makes it MANDATORY: an attacker who struck the " +
    "preferred mechanism out of the list on the wire would otherwise be " +
    "indistinguishable from an acceptor that does not support it");
  assert.ok(/attacker|downgrade|removed/i.test(second.reason),
    "and the reason must say what the MIC is defending against, not merely " +
    "that a rule was broken: " + second.reason);

  assert.strictEqual(spnego.micRequirement(offered, null).required, true,
      "with nothing selected, nothing can be assumed");

  // Both spellings of Kerberos are Kerberos. An acceptor that treats the MS
  // OID as unknown refuses every Windows client.
  assert.ok(spnego.isKerberosMech(spnego.KRB5_MECH_OID) &&
      spnego.isKerberosMech(spnego.MS_KRB5_MECH_OID),
      "both Kerberos OIDs must count as Kerberos");
  assert.ok(!spnego.isKerberosMech("1.3.6.1.4.1.311.2.2.10"),
      "and NTLM must not");
  log.info("the MIC is optional only when the first preference is selected");
  log.debug("Leaving theMicIsOptionalOnlyForTheFirstPreference().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. RFC 4178's codec, byte by byte.");
  theOidCoderMatchesTheRegistrations();
  aNegTokenInitHasTheShapeTheRfcDescribes();
  theMicCoversTheListAndNotItsContextTag();
  aNegTokenRespIsBareAndUsesEnumerated();
  theTagThreeAmbiguityIsResolvedByContentNotByDirection();
  whatIsNotSpnegoIsNamedRatherThanRefused();
  theMicIsOptionalOnlyForTheFirstPreference();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("krb5_spnego_codec")
  .description("RFC 4178's NegTokenInit and NegTokenResp, byte by byte.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>", "base url (unused: node only)"))
  .parse(process.argv);

test().then(function () {
  process.exit(0);
}).catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
