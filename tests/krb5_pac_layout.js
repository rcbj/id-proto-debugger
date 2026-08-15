// File: krb5_pac.js
//
// common/krb5/krb5_pac.js and krb5_ndr.js — the Windows PAC, [MS-PAC].
//
// ---------------------------------------------------------------------------
// Why a round trip is worth almost nothing here, and what is done instead.
//
// The PAC is the worst case for self-consistency testing. Its logon information is
// NDR, where alignment padding and referent-id pointers mean that a reader and a
// writer sharing ONE misunderstanding agree perfectly with each other and with
// nothing else in the world. Read FILETIME as an 8-aligned 64-bit integer in both
// halves and every field still round-trips — the two just insert and skip the same
// four bytes of padding no real KDC ever wrote. So the assertions here come in four
// kinds, and only the first two would catch that:
//
//  1. **Byte offsets derived from the IDL BY HAND** — [MS-PAC] section 2.5's field
//     list counted out with a pencil, not read back off the writer. `UserId` is at
//     struct offset 100 because six FILETIMEs are 48 bytes, six RPC_UNICODE_STRINGs
//     are 48 more, and LogonCount and BadPasswordCount are 2 each. An extra pad byte
//     anywhere above it moves that number, and nothing else in this file would notice.
//  2. **Fixed byte patterns from the spec**: PACTYPE's Version field, the 8-byte
//     alignment of every buffer offset, and [MS-RPCE]'s `01 10 08 00 cc cc cc cc`.
//  3. **Structures with MORE THAN ONE element**, which is not padding pedantry: an
//     ExtraSids array defers ALL its SID pointers past the END of the array, so a
//     reader that follows each pointer as it goes is correct for one element and
//     wrong for two. A one-element test passes on the broken implementation.
//  4. **The four signatures separately**, including the case that matters: altering
//     the PAC's contents breaks the server and extended KDC signatures and leaves the
//     KDC signature VERIFYING, because that one covers only the server signature's
//     bytes. That is the shape of CVE-2022-37967, and a test that only checked "some
//     signature failed" would pass just as well against a verifier that checked the
//     wrong one.
//
// Plus the negative half. These bytes come out of a ticket somebody else's KDC issued,
// so refusing a PAC that lies about its own sizes is part of the job, and so is
// reporting the internal MUSTs [MS-PAC] states — a PAC whose extra SIDs are present
// while the D flag is clear parses perfectly and is ignored by every real service.
//
// No browser and no services: node only, so it never skips.
// ---------------------------------------------------------------------------
const assert = require("assert");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "krb5_pac",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var prim = paths.requireSharedModule(
  [__dirname + "/../common/krb5/krb5_primitives.js", __dirname + "/krb5_primitives.js"],
  "krb5_primitives.js");
var kcrypto = paths.requireSharedModule(
  [__dirname + "/../common/krb5/krb5_crypto.js", __dirname + "/krb5_crypto.js"], "krb5_crypto.js");
var asn1 = paths.requireSharedModule(
  [__dirname + "/../common/krb5/krb5_asn1.js", __dirname + "/krb5_asn1.js"], "krb5_asn1.js");
var msg = paths.requireSharedModule(
  [__dirname + "/../common/krb5/krb5_messages.js", __dirname + "/krb5_messages.js"],
  "krb5_messages.js");
var ndr = paths.requireSharedModule(
  [__dirname + "/../common/krb5/krb5_ndr.js", __dirname + "/krb5_ndr.js"], "krb5_ndr.js");
var pac = paths.requireSharedModule(
  [__dirname + "/../common/krb5/krb5_pac.js", __dirname + "/krb5_pac.js"], "krb5_pac.js");

const hex = (b) => prim.toHex(b);
const DOMAIN = "S-1-5-21-1004336348-1177238915-682003330";

function u32At(bytes, offset) {
  return ((bytes[offset]) | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) |
    (bytes[offset + 3] << 24)) >>> 0;
}

function u16At(bytes, offset) {
  return bytes[offset] | (bytes[offset + 1] << 8);
}

// readAuthorizationData takes a PARSED TLV, not raw bytes. Getting that wrong throws
// from inside the DER reader with a message about a missing tag, which reads as a
// broken encoder rather than as a caller handing it the wrong kind of thing.
function readAd(bytes) {
  return msg.readAuthorizationData(asn1.readTlv(prim.toBytes(bytes), 0, 0));
}

// A key of a given etype, deterministic so a failure is reproducible.
function keyOf(etype, seed) {
  var profile = kcrypto.etypeById(etype);
  var k = new Uint8Array(profile.keyBytes === undefined ? 32 : profile.keyBytes);
  for (var i = 0; i < k.length; i++) k[i] = (seed + i * 7) & 0xff;
  return { etype: etype, key: k };
}

function sampleLogonInfo(overrides) {
  var base = {
    logonTime: new Date("2026-08-14T12:00:00Z"),
    passwordLastSet: new Date("2026-01-02T03:04:05Z"),
    effectiveName: "alice",
    fullName: "Alice Example",
    logonServer: "DC01",
    logonDomainName: "EXAMPLE",
    logonDomainId: DOMAIN,
    userId: 1104,
    primaryGroupId: 513,
    logonCount: 42,
    badPasswordCount: 1,
    // THREE groups and TWO extra SIDs deliberately: see the header, kind 3.
    groups: [{ relativeId: 513 }, { relativeId: 512 }, { relativeId: 572 }],
    extraSids: [{ sid: "S-1-18-1" }, { sid: "S-1-5-32-544" }],
    userAccountControl: 0x00000010 | 0x00000200
  };
  Object.keys(overrides || {}).forEach(function (k) { base[k] = overrides[k]; });
  return base;
}

async function buildSample(overrides) {
  var spec = {
    serverKey: keyOf(18, 0x11),
    kdcKey: keyOf(18, 0x77),
    includeExtendedKdcSignature: true,
    logonInfo: sampleLogonInfo((overrides || {}).logonInfo),
    clientInfo: { name: "alice", clientId: new Date("2026-08-14T12:00:00Z") },
    upnDns: {
      upn: "alice@example.com",
      dnsDomainName: "EXAMPLE.COM",
      samName: "alice",
      sid: DOMAIN + "-1104"
    },
    attributes: 0x00000001,
    requestorSid: DOMAIN + "-1104"
  };
  Object.keys(overrides || {}).forEach(function (k) {
    if (k !== "logonInfo") spec[k] = overrides[k];
  });
  return { bytes: await pac.buildPac(spec), spec: spec };
}

// ---------------------------------------------------------------------------
// 1. The PACTYPE header and the buffer table, against [MS-PAC] sections 2.3 and 2.4.
// ---------------------------------------------------------------------------
async function theHeaderMatchesTheSpecByteForByte() {
  log.debug("Entering theHeaderMatchesTheSpecByteForByte().");
  var built = await buildSample();
  var b = built.bytes;

  var cBuffers = u32At(b, 0);
  assert.strictEqual(u32At(b, 4), 0,
    "PACTYPE.Version MUST be 0x00000000 ([MS-PAC] section 2.3); it is " + u32At(b, 4));
  assert.ok(cBuffers >= 7 && cBuffers <= 16,
    "cBuffers should count the buffers actually emitted, got " + cBuffers);

  // The buffer table: ulType, cbBufferSize, then an EIGHT-byte offset. A reader that
  // treated Offset as 4 bytes would find every entry after the first shifted, so this
  // asserts the stride explicitly.
  var seenTypes = [];
  for (var i = 0; i < cBuffers; i++) {
    var at = 8 + i * 16;
    var type = u32At(b, at);
    var size = u32At(b, at + 4);
    var offset = u32At(b, at + 8);
    var offsetHigh = u32At(b, at + 12);
    seenTypes.push(type);
    assert.strictEqual(offsetHigh, 0, "buffer " + i + "'s offset should not need 64 bits");
    assert.strictEqual(offset % 8, 0,
      "buffer " + i + " (type " + type + ") is at offset " + offset + "; [MS-PAC] section 2.4 " +
      "requires a multiple of 8, and Windows rejects a PAC that breaks it");
    assert.ok(offset + size <= b.length,
      "buffer " + i + " runs past the end of the PAC");
  }

  [pac.TYPE.LOGON_INFO, pac.TYPE.CLIENT_INFO, pac.TYPE.SERVER_CHECKSUM,
   pac.TYPE.KDC_CHECKSUM].forEach(function (t) {
    assert.ok(seenTypes.indexOf(t) !== -1,
      "a PAC in a ticket MUST carry " + pac.bufferTypeName(t) + " ([MS-PAC] section 2.4)");
  });

  var parsed = pac.parsePac(b);
  assert.deepStrictEqual(parsed.problems, [],
    "a PAC this code built should have nothing to report: " + parsed.problems.join(" | "));
  log.debug("Leaving theHeaderMatchesTheSpecByteForByte(). " + cBuffers + " buffers.");
}

// ---------------------------------------------------------------------------
// 2. The NDR layout of KERB_VALIDATION_INFO, at offsets counted out of the IDL.
//
// This is the assertion that catches a phantom pad byte, and the reason it is written
// as absolute numbers rather than as "whatever the writer produced".
// ---------------------------------------------------------------------------
async function theLogonInfoSitsWhereTheIdlSaysItDoes() {
  log.debug("Entering theLogonInfoSitsWhereTheIdlSaysItDoes().");
  var built = await buildSample();
  var parsed = pac.parsePac(built.bytes);
  var entry = pac.bufferOfType(parsed, pac.TYPE.LOGON_INFO);
  var b = entry.bytes;

  // [MS-RPCE] section 2.2.6's sixteen bytes: version 1, little-endian/ASCII 0x10,
  // common header length 8, 0xCC filler; then ObjectBufferLength and a zero filler.
  assert.strictEqual(hex(b.subarray(0, 8)), "01100800cccccccc",
    "the type-marshalling common header should be 01 10 08 00 cc cc cc cc, got " +
    hex(b.subarray(0, 8)));
  assert.strictEqual(u32At(b, 12), 0, "the private header's filler should be zero");
  assert.strictEqual(u32At(b, 8), b.length - 16,
    "ObjectBufferLength should count every byte after the private header");

  // The top-level referent id at offset 16 — non-zero, and NOT an offset.
  assert.notStrictEqual(u32At(b, 16), 0,
    "the pointer to KERB_VALIDATION_INFO must be a non-NULL referent id");

  // The struct starts at 20. Every offset below is counted from [MS-PAC] section 2.5's
  // field list by hand:
  //   6 × FILETIME (2 ULONGs each, so 8 bytes and 4-BYTE alignment) ......  0 .. 47
  //   6 × RPC_UNICODE_STRING (2+2+4) ...................................... 48 .. 95
  //   LogonCount, BadPasswordCount (2 + 2) ................................ 96 .. 99
  //   UserId .............................................................. 100
  //   PrimaryGroupId ...................................................... 104
  //   GroupCount .......................................................... 108
  //   GroupIds (referent) ................................................. 112
  //   UserFlags ........................................................... 116
  //   UserSessionKey (16 raw bytes) ....................................... 120 .. 135
  // Because nothing in this structure is 8-aligned, a correct encoder inserts NO
  // padding at all and these numbers are exact.
  var S = 20;
  assert.strictEqual(u32At(b, S + 100), 1104,
    "UserId belongs at struct offset 100. Reading " + u32At(b, S + 100) + " there means a field " +
    "above it is the wrong size — the usual culprit is treating FILETIME as an 8-ALIGNED " +
    "64-bit integer, which inserts four bytes of padding NDR never wrote");
  assert.strictEqual(u32At(b, S + 104), 513, "PrimaryGroupId belongs at struct offset 104");
  assert.strictEqual(u32At(b, S + 108), 3, "GroupCount belongs at struct offset 108");
  assert.notStrictEqual(u32At(b, S + 112), 0, "the GroupIds referent id belongs at struct offset 112");
  assert.strictEqual(u32At(b, S + 116), pac.USER_FLAG_EXTRA_SIDS,
    "UserFlags belongs at struct offset 116, and should carry D (EXTRA_SIDS) = 0x20 because this " +
    "PAC has extra SIDs. 0x40 there would mean the bit diagram was read from the wrong end");

  // EffectiveName's own header at struct offset 48: "alice" is 5 characters, so its
  // Length and MaximumLength are 10 BYTES — not 5, and not 12.
  assert.strictEqual(u16At(b, S + 48), 10,
    "EffectiveName.Length is in BYTES, so 'alice' is 10");
  assert.strictEqual(u16At(b, S + 50), 10, "EffectiveName.MaximumLength should match");

  // The six FILETIMEs: LogonTime present, LogoffTime the "never" sentinel.
  assert.strictEqual(hex(b.subarray(S, S + 8)) !== "0000000000000000", true,
    "LogonTime should be set");
  assert.strictEqual(hex(b.subarray(S + 8, S + 16)), "ffffffffffffff7f",
    "LogoffTime should be the 0x7FFFFFFFFFFFFFFF 'never' sentinel, little-endian");

  log.debug("Leaving theLogonInfoSitsWhereTheIdlSaysItDoes().");
}

// ---------------------------------------------------------------------------
// 3. What the reader makes of it — and the multi-element cases specifically.
// ---------------------------------------------------------------------------
async function theReaderRecoversEveryField() {
  log.debug("Entering theReaderRecoversEveryField().");
  var built = await buildSample();
  var parsed = pac.parsePac(built.bytes);
  var info = pac.bufferOfType(parsed, pac.TYPE.LOGON_INFO).parsed;

  assert.strictEqual(info.effectiveName, "alice");
  assert.strictEqual(info.fullName, "Alice Example");
  assert.strictEqual(info.logonServer, "DC01");
  assert.strictEqual(info.logonDomainName, "EXAMPLE");
  assert.strictEqual(info.logonDomainId.text, DOMAIN);
  assert.strictEqual(info.userId, 1104);
  assert.strictEqual(info.logonCount, 42);
  assert.strictEqual(info.badPasswordCount, 1);

  // The SID a service actually authorizes on is assembled, not transmitted.
  assert.strictEqual(info.userSid, DOMAIN + "-1104",
    "the account's SID is LogonDomainId + UserId; a PAC never carries it whole");
  assert.strictEqual(info.primaryGroupSid, DOMAIN + "-513");

  // Three groups, in order, with the well-known ones named.
  assert.strictEqual(info.groups.length, 3, "all three groups should be read");
  assert.deepStrictEqual(info.groups.map(function (g) { return g.relativeId; }), [513, 512, 572],
    "the groups should come back in the order they were written");
  assert.strictEqual(info.groups[1].name, "Domain Admins",
    "RID 512 should be named, because 'S-1-5-21-…-512' is work the reader should not have to do");
  assert.ok(info.groups[0].attributeNames.indexOf("ENABLED") !== -1,
    "the default group attributes should include ENABLED");

  // TWO extra SIDs — the case that distinguishes a correct deferred-pointer reader.
  assert.strictEqual(info.extraSids.length, 2,
    "both extra SIDs should be read. One would pass even with the pointers followed in " +
    "the wrong place, which is why there are two");
  assert.strictEqual(info.extraSids[0].text, "S-1-18-1");
  assert.strictEqual(info.extraSids[1].text, "S-1-5-32-544",
    "the SECOND extra SID is the one a reader that follows each pointer as it goes gets wrong");
  assert.strictEqual(info.extraSids[0].name, "Authentication authority asserted identity",
    "S-1-18-1 should be named: it records HOW the identity was established, which is the " +
    "whole question in an S4U trace");
  assert.strictEqual(info.extraSids[1].name, "BUILTIN\\Administrators");

  assert.deepStrictEqual(info.userAccountControlNames, ["NORMAL_ACCOUNT", "DONT_EXPIRE_PASSWORD"],
    "UserAccountControl uses [MS-SAMR]'s USER_ACCOUNT codes, where NORMAL_ACCOUNT is 0x10 — " +
    "NOT the LDAP userAccountControl bits, where it is 0x200");
  assert.deepStrictEqual(info.userFlagNames, ["D EXTRA_SIDS"],
    "with extra SIDs present and nothing else set, D and only D should be reported");
  assert.deepStrictEqual(info.notes, [],
    "a well-formed PAC should raise no consistency notes: " + info.notes.join(" | "));

  assert.strictEqual(info.logonTime.date.toISOString(), "2026-08-14T12:00:00.000Z",
    "a FILETIME is 100-nanosecond intervals since 1601, and must survive the conversion");
  assert.strictEqual(info.logoffTime.never, true,
    "0x7FFFFFFFFFFFFFFF means 'never', and rendering it as a date in the year 30828 would be " +
    "technically correct and useless");

  // The simple buffers.
  var client = pac.bufferOfType(parsed, pac.TYPE.CLIENT_INFO).parsed;
  assert.strictEqual(client.name, "alice");
  assert.strictEqual(client.clientId.date.toISOString(), "2026-08-14T12:00:00.000Z");

  var upn = pac.bufferOfType(parsed, pac.TYPE.UPN_DNS_INFO).parsed;
  assert.strictEqual(upn.upn, "alice@example.com");
  assert.strictEqual(upn.dnsDomainName, "EXAMPLE.COM");
  assert.strictEqual(upn.samName, "alice",
    "the SAM name is only present when the S flag is set, and must be read at ITS offset");
  assert.strictEqual(upn.sid.text, DOMAIN + "-1104");
  assert.strictEqual(upn.extended, true);

  var attrs = pac.bufferOfType(parsed, pac.TYPE.ATTRIBUTES_INFO).parsed;
  assert.deepStrictEqual(attrs.flagNames, ["PAC_WAS_REQUESTED"]);
  assert.strictEqual(attrs.flagsLength, 2, "FlagsLength is a count of BITS, not bytes");

  var requestor = pac.bufferOfType(parsed, pac.TYPE.REQUESTOR_SID).parsed;
  assert.strictEqual(requestor.sid.text, DOMAIN + "-1104");

  log.debug("Leaving theReaderRecoversEveryField().");
}

// Resource groups — the OTHER group list, and the one nothing else here reaches.
//
// It has its own domain SID, its own array and its own UserFlags bit (H), and the
// attributes on its entries carry SE_GROUP_RESOURCE. This section exists because
// without it a wrong value for that flag is invisible: the ordinary group list never
// sets it, so `0x20000000` could be `0x10` and every other assertion in this file
// would still pass. It is also the list that makes a domain-local group grant access
// on a resource in another domain, so getting it wrong is not cosmetic.
async function resourceGroupsAreReadWithTheirOwnDomainSid() {
  log.debug("Entering resourceGroupsAreReadWithTheirOwnDomainSid().");
  var RESOURCE_DOMAIN = "S-1-5-21-99-98-97";
  var built = await buildSample({
    logonInfo: {
      resourceGroupDomainSid: RESOURCE_DOMAIN,
      // Two again, and with DIFFERENT attributes, so the array is walked properly and
      // the flags are not read off the first entry for all of them.
      resourceGroups: [
        { relativeId: 1200, attributes: 0x20000007 },
        { relativeId: 1201, attributes: 0x20000004 }
      ]
    }
  });
  var info = pac.bufferOfType(pac.parsePac(built.bytes), pac.TYPE.LOGON_INFO).parsed;

  assert.strictEqual(info.resourceGroupDomainSid.text, RESOURCE_DOMAIN,
    "the resource groups' domain SID is a separate field from LogonDomainId — they are groups " +
    "in the RESOURCE's domain, not the account's");
  assert.strictEqual(info.resourceGroups.length, 2, "both resource groups should be read");
  assert.deepStrictEqual(info.resourceGroups.map(function (g) { return g.relativeId; }),
    [1200, 1201]);
  assert.ok(info.resourceGroups[0].attributeNames.indexOf("RESOURCE (domain-local)") !== -1,
    "SE_GROUP_RESOURCE is 0x20000000 — bit 2 of [MS-PAC]'s diagram, counting from the LEFT " +
    "where the rightmost bit is the least significant. Reading that diagram the other way " +
    "gives 0x10, which is USE_FOR_DENY_ONLY, an almost opposite meaning. Got: " +
    info.resourceGroups[0].attributeNames.join(", "));
  assert.ok(info.resourceGroups[1].attributeNames.indexOf("ENABLED") !== -1 &&
    info.resourceGroups[1].attributeNames.indexOf("MANDATORY") === -1,
    "the second entry's attributes must be read from the second entry: " +
    info.resourceGroups[1].attributeNames.join(", "));

  // The H flag has to be derived, or a real service ignores the whole list.
  assert.ok(info.userFlagNames.indexOf("H RESOURCE_GROUPS") !== -1,
    "resource groups require the H flag ([MS-PAC] section 2.5), and the builder should set it " +
    "rather than leaving it to the caller: " + info.userFlagNames.join(", "));
  assert.deepStrictEqual(info.notes, [],
    "and with H set correctly there should be nothing to report: " + info.notes.join(" | "));

  // 0x10 must NOT be read as SE_GROUP_RESOURCE. Asserting the negative directly is
  // what makes the value above load-bearing rather than incidental.
  var denyOnly = pac.groupAttributeNames(0x00000010);
  assert.ok(denyOnly.indexOf("RESOURCE (domain-local)") === -1,
    "0x10 is USE_FOR_DENY_ONLY, not SE_GROUP_RESOURCE: " + denyOnly.join(", "));
  assert.ok(pac.groupAttributeNames(0x20000000).indexOf("RESOURCE (domain-local)") !== -1,
    "and 0x20000000 is");

  // SE_GROUP_LOGON_ID is TWO bits (0xC0000000), so a bitwise-any test would report it
  // for either half alone.
  assert.ok(/LOGON_ID/.test(pac.groupAttributeNames(0xC0000000).join(",")),
    "0xC0000000 is SE_GROUP_LOGON_ID");
  assert.ok(!/LOGON_ID/.test(pac.groupAttributeNames(0x80000000).join(",")),
    "but half of it is not — SE_GROUP_LOGON_ID needs both bits, so it must be matched exactly");

  log.debug("Leaving resourceGroupsAreReadWithTheirOwnDomainSid().");
}

// ---------------------------------------------------------------------------
// 4. The four signatures, separately — including the CVE-2022-37967 shape.
// ---------------------------------------------------------------------------
async function eachSignatureIsCheckedAgainstItsOwnKeyAndItsOwnBytes() {
  log.debug("Entering eachSignatureIsCheckedAgainstItsOwnKeyAndItsOwnBytes().");
  var serverKey = keyOf(18, 0x11);
  var kdcKey = keyOf(18, 0x77);
  var built = await buildSample();
  var parsed = pac.parsePac(built.bytes);

  function byType(results, t) {
    return results.filter(function (r) { return r.type === t; })[0];
  }

  var all = await pac.verifySignatures(parsed, { serverKey: serverKey, kdcKey: kdcKey });
  [pac.TYPE.SERVER_CHECKSUM, pac.TYPE.KDC_CHECKSUM, pac.TYPE.EXTENDED_KDC_CHECKSUM].forEach(
    function (t) {
      var r = byType(all, t);
      assert.ok(r, pac.bufferTypeName(t) + " should be reported on");
      assert.strictEqual(r.verified, true,
        pac.bufferTypeName(t) + " should verify against the key it was made with: " + r.note);
    });

  // A service holds only its own key. It must be able to check the server signature
  // and must be TOLD, by name, that it cannot check the others — not shown a failure.
  var serviceOnly = await pac.verifySignatures(parsed, { serverKey: serverKey });
  assert.strictEqual(byType(serviceOnly, pac.TYPE.SERVER_CHECKSUM).verified, true,
    "a service can verify the server signature with its own long-term key — that is the point of it");
  assert.strictEqual(byType(serviceOnly, pac.TYPE.KDC_CHECKSUM).verified, null,
    "without the krbtgt key the KDC signature is UNKNOWN, not failed. Reporting it as failed " +
    "would tell a service its ticket was forged every single time");
  assert.ok(/no krbtgt key was supplied/.test(byType(serviceOnly, pac.TYPE.KDC_CHECKSUM).note),
    "and the reason should say which key was missing, got: " +
    byType(serviceOnly, pac.TYPE.KDC_CHECKSUM).note);

  // Alter the logon information. This is the interesting case.
  var tampered = new Uint8Array(built.bytes);
  var logonAt = pac.bufferOfType(parsed, pac.TYPE.LOGON_INFO).offset;
  tampered[logonAt + 40] ^= 0xff;
  var after = await pac.verifySignatures(pac.parsePac(tampered),
    { serverKey: serverKey, kdcKey: kdcKey });
  assert.strictEqual(byType(after, pac.TYPE.SERVER_CHECKSUM).verified, false,
    "altering the PAC must break the server signature, which covers the whole structure");
  assert.strictEqual(byType(after, pac.TYPE.EXTENDED_KDC_CHECKSUM).verified, false,
    "and the extended KDC signature, which also covers the whole structure");
  assert.strictEqual(byType(after, pac.TYPE.KDC_CHECKSUM).verified, true,
    "but the KDC signature STILL verifies, because it covers only the server signature's " +
    "bytes and those were not touched. This is exactly why the extended KDC signature was " +
    "added (CVE-2022-37967) — a verifier that checks the KDC signature alone sees nothing wrong");

  // A key of the wrong etype cannot verify, and the reason must say so rather than
  // reading as a bad signature.
  var wrongEtype = await pac.verifySignatures(parsed,
    { serverKey: keyOf(17, 0x22), kdcKey: kdcKey });
  var s = byType(wrongEtype, pac.TYPE.SERVER_CHECKSUM);
  assert.strictEqual(s.verified, false);
  assert.ok(/belongs to etype 18.*supplied is etype 17/.test(s.note),
    "an etype mismatch should be named as such — it is what a KDC and a service disagreeing " +
    "about encryption types looks like from outside. Got: " + s.note);

  // The ticket signature: asked for without the bytes it covers, the builder must
  // refuse rather than sign the wrong thing.
  var refused = null;
  try {
    await pac.buildPac({
      serverKey: serverKey, kdcKey: kdcKey, includeTicketSignature: true,
      logonInfo: sampleLogonInfo(), clientInfo: { name: "alice" }
    });
  } catch (e) {
    refused = e.message;
  }
  assert.ok(refused && /ad-data replaced by a single zero byte/.test(refused),
    "asking for a ticket signature without an EncTicketPart should be refused with an " +
    "explanation of what it covers, got: " + refused);

  log.debug("Leaving eachSignatureIsCheckedAgainstItsOwnKeyAndItsOwnBytes().");
}

// The ticket signature end to end: it binds a PAC to ONE ticket, so the bytes it
// covers have to be built the way [MS-PAC] section 2.8.2 says — the EncTicketPart's
// DER with this PAC's ad-data replaced by a single zero byte.
async function theTicketSignatureBindsThePacToOneTicket() {
  log.debug("Entering theTicketSignatureBindsThePacToOneTicket().");
  var serverKey = keyOf(18, 0x11);
  var kdcKey = keyOf(18, 0x77);

  function encTicketPartWith(adData, endtime) {
    return msg.encEncTicketPart({
      flags: [msg.TICKET_FLAG.FORWARDABLE],
      key: { etype: 18, key: keyOf(18, 0x33).key },
      crealm: "EXAMPLE.COM",
      cname: msg.parsePrincipal("alice"),
      transited: { type: 1, contents: new Uint8Array(0) },
      authtime: new Date("2026-08-14T12:00:00Z"),
      endtime: endtime,
      authorizationData: adData
    });
  }

  var endtime = new Date("2026-08-14T22:00:00Z");
  // The signed form: one zero byte where the PAC will go.
  var signedOver = encTicketPartWith([{ type: pac.AD_TYPE.WIN2K_PAC, data: new Uint8Array([0]) }],
    endtime);

  var bytes = await pac.buildPac({
    serverKey: serverKey, kdcKey: kdcKey,
    includeTicketSignature: true, includeExtendedKdcSignature: true,
    ticketBytes: signedOver,
    logonInfo: sampleLogonInfo(),
    clientInfo: { name: "alice", clientId: new Date("2026-08-14T12:00:00Z") }
  });

  var parsed = pac.parsePac(bytes);
  var ok = await pac.verifySignatures(parsed,
    { serverKey: serverKey, kdcKey: kdcKey, ticketBytes: signedOver });
  var ticketResult = ok.filter(function (r) { return r.type === pac.TYPE.TICKET_CHECKSUM; })[0];
  assert.strictEqual(ticketResult.verified, true,
    "the ticket signature should verify over the EncTicketPart with the ad-data blanked: " +
    ticketResult.note);

  // The same PAC against a DIFFERENT ticket must fail — that is the property.
  var otherTicket = encTicketPartWith(
    [{ type: pac.AD_TYPE.WIN2K_PAC, data: new Uint8Array([0]) }],
    new Date("2026-08-15T22:00:00Z"));
  var moved = await pac.verifySignatures(parsed,
    { serverKey: serverKey, kdcKey: kdcKey, ticketBytes: otherTicket });
  assert.strictEqual(
    moved.filter(function (r) { return r.type === pac.TYPE.TICKET_CHECKSUM; })[0].verified, false,
    "the same PAC lifted into a ticket with a different endtime must fail its ticket signature — " +
    "that binding is the entire purpose of the buffer");

  // And without the ticket, the verifier must say WHY rather than pass or fail.
  var noTicket = await pac.verifySignatures(parsed, { serverKey: serverKey, kdcKey: kdcKey });
  var unknown = noTicket.filter(function (r) { return r.type === pac.TYPE.TICKET_CHECKSUM; })[0];
  assert.strictEqual(unknown.verified, null,
    "with no EncTicketPart supplied the ticket signature is unknown, not failed");
  assert.ok(/EncTicketPart it covers was not supplied/.test(unknown.note),
    "and it should say so: " + unknown.note);

  log.debug("Leaving theTicketSignatureBindsThePacToOneTicket().");
}

// ---------------------------------------------------------------------------
// 5. Finding the PAC where it actually lives: two containers deep.
// ---------------------------------------------------------------------------
async function thePacIsFoundInsideAdIfRelevant() {
  log.debug("Entering thePacIsFoundInsideAdIfRelevant().");
  var built = await buildSample();
  var ad = pac.wrapPacAsAuthorizationData(built.bytes);

  assert.strictEqual(ad.length, 1, "the wrapper is a single AD-IF-RELEVANT element");
  assert.strictEqual(ad[0].type, pac.AD_TYPE.IF_RELEVANT,
    "the outer element must be ad-type 1. A PAC placed at the top level as ad-type 128 is " +
    "what a non-Windows client will refuse outright, because AD-IF-RELEVANT is the wrapper " +
    "that means 'ignore what you do not understand'");

  // Round-trip through DER, as a real ticket would.
  var reread = readAd(msg.encAuthorizationData(ad));
  var found = pac.findPacs(reread);
  assert.strictEqual(found.length, 1, "exactly one PAC should be found");
  assert.strictEqual(hex(found[0].bytes), hex(built.bytes),
    "and its bytes must survive the two layers of wrapping unchanged");
  assert.strictEqual(found[0].path, "AD-IF-RELEVANT → AD-WIN2K-PAC",
    "the path should say where it was found, so 'no PAC' can be told from 'a PAC somewhere odd'");

  // A search that only looked at the top level would find nothing here — assert the
  // negative directly, so the unwrapping cannot be removed without this failing.
  var topLevelOnly = reread.filter(function (e) { return e.type === pac.AD_TYPE.WIN2K_PAC; });
  assert.strictEqual(topLevelOnly.length, 0,
    "there is deliberately no ad-type 128 at the top level: that is what makes the previous " +
    "assertion mean something");

  // Nested one deeper (AD-MANDATORY-FOR-KDC around AD-IF-RELEVANT), which real KDCs do.
  var deeper = [{
    type: pac.AD_TYPE.MANDATORY_FOR_KDC,
    data: msg.encAuthorizationData(ad)
  }];
  var deepFound = pac.findPacs(readAd(msg.encAuthorizationData(deeper)));
  assert.strictEqual(deepFound.length, 1, "a PAC two containers deep should still be found");
  assert.strictEqual(deepFound[0].path, "AD-MANDATORY-FOR-KDC → AD-IF-RELEVANT → AD-WIN2K-PAC");

  // An unopenable container must not lose the PAC beside it, and must not throw.
  var mixed = readAd(msg.encAuthorizationData([
    { type: pac.AD_TYPE.IF_RELEVANT, data: new Uint8Array([0x30, 0x05, 0xff, 0xff, 0xff]) },
    ad[0]
  ]));
  var mixedFound = pac.findPacs(mixed);
  assert.strictEqual(mixedFound.length, 1,
    "a container this code cannot parse must not cost us the PAC in the next element");

  log.debug("Leaving thePacIsFoundInsideAdIfRelevant().");
}

// ---------------------------------------------------------------------------
// 6. The negative half: malformed PACs, and the MUSTs that parse fine and mean
//    something is wrong.
// ---------------------------------------------------------------------------
async function malformedPacsAreRefusedOrReported() {
  log.debug("Entering malformedPacsAreRefusedOrReported().");
  var built = await buildSample();

  function corrupt(fn) {
    var c = new Uint8Array(built.bytes);
    fn(c);
    return c;
  }
  function setU32(b, at, v) {
    b[at] = v & 0xff; b[at + 1] = (v >>> 8) & 0xff;
    b[at + 2] = (v >>> 16) & 0xff; b[at + 3] = (v >>> 24) & 0xff;
  }
  function throwsWith(bytes, pattern, what) {
    var caught = null;
    try {
      pac.parsePac(bytes);
    } catch (e) {
      caught = e.message;
    }
    assert.ok(caught, what + " should have been refused, but parsed");
    assert.ok(pattern.test(caught),
      what + " should be refused with a message naming the problem; got: " + caught);
  }

  // A buffer count that could not fit in the bytes present.
  throwsWith(corrupt(function (b) { setU32(b, 0, 5000); }),
    /declares 5000 buffers|table alone would need/, "a PAC claiming 5000 buffers");
  throwsWith(corrupt(function (b) { setU32(b, 0, 0); }), /zero buffers/,
    "a PAC claiming no buffers");

  // A non-zero Version is a MUST violation that still parses: it must be REPORTED,
  // not thrown, because the rest of the structure is still worth reading.
  var wrongVersion = pac.parsePac(corrupt(function (b) { setU32(b, 4, 1); }));
  assert.ok(wrongVersion.problems.some(function (p) { return /Version is 1/.test(p); }),
    "a PACTYPE Version other than 0 should be reported: " + wrongVersion.problems.join(" | "));
  assert.ok(pac.bufferOfType(wrongVersion, pac.TYPE.LOGON_INFO).parsed,
    "and the buffers should still be parsed — a debugger is for looking at broken things");

  // A buffer offset that is not a multiple of 8: reported, and the buffer still read
  // where it actually is.
  var misaligned = pac.parsePac(corrupt(function (b) {
    var at = 8;                                     // the first table entry's Offset
    setU32(b, at + 8, u32At(b, at + 8) + 4);
  }));
  assert.ok(misaligned.problems.some(function (p) { return /not a multiple of 8/.test(p); }),
    "a buffer offset that is not 8-aligned should be reported — Windows rejects the PAC for it: " +
    misaligned.problems.join(" | "));

  // A buffer that claims to run past the end: recorded against that buffer, with the
  // others still parsed. One bad buffer must not cost the reader the other six.
  var overrun = pac.parsePac(corrupt(function (b) {
    setU32(b, 8 + 4, 0xffff);                       // the first entry's cbBufferSize
  }));
  var bad = pac.bufferOfType(overrun, pac.TYPE.LOGON_INFO);
  assert.ok(bad.error && /outside the/.test(bad.error),
    "a buffer running past the end should be recorded against it: " + bad.error);
  assert.ok(pac.bufferOfType(overrun, pac.TYPE.CLIENT_INFO).parsed,
    "and the other buffers must still be parsed");

  // The required-buffer rules, checked by removing one from the table.
  var noClientInfo = pac.parsePac(corrupt(function (b) {
    for (var i = 0; i < u32At(b, 0); i++) {
      if (u32At(b, 8 + i * 16) === pac.TYPE.CLIENT_INFO) setU32(b, 8 + i * 16, 0x777);
    }
  }));
  assert.ok(noClientInfo.problems.some(function (p) {
    return /no Client name and ticket information buffer/.test(p);
  }), "a missing PAC_CLIENT_INFO should be reported: " + noClientInfo.problems.join(" | "));

  // A duplicated logon-information buffer. [MS-PAC] says ignore the second, which is
  // precisely why it has to be counted: a second buffer is somewhere to hide a
  // different set of groups.
  var doubled = pac.parsePac(corrupt(function (b) {
    for (var i = 0; i < u32At(b, 0); i++) {
      if (u32At(b, 8 + i * 16) === pac.TYPE.ATTRIBUTES_INFO) {
        setU32(b, 8 + i * 16, pac.TYPE.LOGON_INFO);
        return;
      }
    }
  }));
  assert.ok(doubled.problems.some(function (p) { return /There are 2 Logon information/.test(p); }),
    "two logon-information buffers should be reported: " + doubled.problems.join(" | "));

  log.debug("Leaving malformedPacsAreRefusedOrReported().");
}

// The internal MUSTs of KERB_VALIDATION_INFO. Each of these produces a PAC that reads
// perfectly and behaves differently on a real Windows service, which is the only
// reason to check them deliberately.
async function theConsistencyRulesAreReported() {
  log.debug("Entering theConsistencyRulesAreReported().");

  // Extra SIDs present, D flag deliberately cleared — a real service ignores them.
  var noDFlag = await buildSample({ logonInfo: { userFlags: 0 } });
  var info = pac.bufferOfType(pac.parsePac(noDFlag.bytes), pac.TYPE.LOGON_INFO).parsed;
  assert.ok(info.notes.some(function (n) { return /EXTRA_SIDS flag \(D\) is not set/.test(n); }),
    "extra SIDs with the D flag clear should be reported — the SIDs are there and every real " +
    "service will ignore them, which reads as a KDC that never added them: " + info.notes.join(" | "));
  assert.strictEqual(info.extraSids.length, 2,
    "and the SIDs themselves should still be listed, since that is the evidence");

  // An NTLM-only flag on a Kerberos PAC.
  var ntlmFlag = await buildSample({
    logonInfo: { userFlags: pac.USER_FLAG_EXTRA_SIDS | 0x00000001 }
  });
  var ntlmInfo = pac.bufferOfType(pac.parsePac(ntlmFlag.bytes), pac.TYPE.LOGON_INFO).parsed;
  assert.ok(ntlmInfo.notes.some(function (n) { return /set only by NTLM/.test(n); }),
    "an NTLM-only UserFlags bit should be reported on a Kerberos PAC: " + ntlmInfo.notes.join(" | "));

  // UserId 0 changes where the account's own SID comes from — silently, if unreported.
  var zeroUser = await buildSample({ logonInfo: { userId: 0 } });
  var zeroInfo = pac.bufferOfType(pac.parsePac(zeroUser.bytes), pac.TYPE.LOGON_INFO).parsed;
  assert.ok(zeroInfo.notes.some(function (n) { return /UserId is 0/.test(n); }),
    "UserId 0 means the first ExtraSids entry IS the account, and must be said: " +
    zeroInfo.notes.join(" | "));

  // A group attribute [MS-PAC] requires to be zero.
  var denyOnly = await buildSample({
    logonInfo: { groups: [{ relativeId: 513, attributes: 0x00000007 | 0x00000010 }] }
  });
  var denyInfo = pac.bufferOfType(pac.parsePac(denyOnly.bytes), pac.TYPE.LOGON_INFO).parsed;
  assert.ok(denyInfo.groups[0].attributeNames.some(function (n) {
    return /USE_FOR_DENY_ONLY.*not permitted in a PAC/.test(n);
  }), "SE_GROUP_USE_FOR_DENY_ONLY is a real access-token flag that [MS-PAC] forbids here, so it " +
     "should be named AND marked as not permitted: " + denyInfo.groups[0].attributeNames.join(", "));

  // A conformant count that disagrees with the field count must be refused, not
  // trusted — that disagreement is how a declared length becomes an over-read.
  var built = await buildSample();
  var parsed = pac.parsePac(built.bytes);
  var logonEntry = pac.bufferOfType(parsed, pac.TYPE.LOGON_INFO);
  var tampered = new Uint8Array(built.bytes);
  // GroupCount sits at struct offset 108, i.e. buffer offset 20 + 108.
  var groupCountAt = logonEntry.offset + 20 + 108;
  tampered[groupCountAt] = 9;
  var reparsed = pac.parsePac(tampered);
  assert.ok(/GroupCount is 9 but the array's own conformant count is 3/
    .test(pac.bufferOfType(reparsed, pac.TYPE.LOGON_INFO).error || ""),
    "a GroupCount that disagrees with the array's own count must be refused, got: " +
    pac.bufferOfType(reparsed, pac.TYPE.LOGON_INFO).error);

  log.debug("Leaving theConsistencyRulesAreReported().");
}

// ---------------------------------------------------------------------------
// 7. The NDR reader's own guards, reached directly. These are the paths a hostile
//    PAC takes, and they are hard to reach through a well-formed one.
// ---------------------------------------------------------------------------
function theNdrReaderRefusesHostileInput() {
  log.debug("Entering theNdrReaderRefusesHostileInput().");

  function throwsWith(fn, pattern, what) {
    var caught = null;
    try {
      fn();
    } catch (e) {
      caught = e.message;
    }
    assert.ok(caught, what + " should have thrown");
    assert.ok(pattern.test(caught), what + " should name the problem; got: " + caught);
  }

  throwsWith(function () {
    ndr.createReader(new Uint8Array(ndr.MAX_NDR_BYTES + 1));
  }, /refusing to read/, "an oversized NDR stream");

  throwsWith(function () {
    var r = ndr.createReader(new Uint8Array([1, 2]));
    r.u32();
  }, /ran off the end/, "a 32-bit read with two bytes left");

  throwsWith(function () {
    // 0xFFFFFF as a count: not credible, and the message should point at byte order.
    var r = ndr.createReader(new Uint8Array([0xff, 0xff, 0xff, 0x00]));
    r.arrayCount("thing(s)");
  }, /not credible.*LITTLE-endian/, "an absurd array count");

  throwsWith(function () {
    // A SID claiming 200 sub-authorities.
    ndr.readSid(ndr.createReader(new Uint8Array([1, 200, 0, 0, 0, 0, 0, 5])));
  }, /the maximum is 15/, "a SID with too many sub-authorities");

  throwsWith(function () {
    ndr.readTypeMarshallingHeaders(ndr.createReader(
      new Uint8Array([1, 0x00, 8, 0, 0xcc, 0xcc, 0xcc, 0xcc, 0, 0, 0, 0, 0, 0, 0, 0])));
  }, /0x00 would be big-endian/, "big-endian NDR");

  throwsWith(function () {
    ndr.parseSidText("not-a-sid");
  }, /is not a SID/, "a SID that is not one");

  // The reader and the writer must agree on a SID's text form, including the
  // big-endian identifier authority in the middle of a little-endian structure.
  var w = ndr.createWriter();
  ndr.writeSid(w, "S-1-5-21-1-2-3-1104");
  var readBack = ndr.readSid(ndr.createReader(w.build()));
  assert.strictEqual(readBack.text, "S-1-5-21-1-2-3-1104",
    "a SID's identifier authority is the one BIG-endian field in the structure");
  assert.strictEqual(readBack.authority, 5);

  // FILETIME's two sentinels and a real value.
  [["never", true], [null, false]].forEach(function (pair) {
    var fw = ndr.createWriter();
    fw.fileTime(pair[0]);
    var ft = ndr.readFileTime(ndr.createReader(fw.build()));
    assert.strictEqual(!!ft.never, pair[1], "the 'never' sentinel should round-trip");
  });
  var dw = ndr.createWriter();
  var when = new Date("2001-09-09T01:46:40Z");
  dw.fileTime(when);
  assert.strictEqual(ndr.readFileTime(ndr.createReader(dw.build())).date.toISOString(),
    when.toISOString(), "a FILETIME should survive the 1601 epoch conversion");

  log.debug("Leaving theNdrReaderRefusesHostileInput().");
}

// ---------------------------------------------------------------------------
// 8. Every etype the signatures can use, and the one that cannot be computed.
// ---------------------------------------------------------------------------
async function everySignatureEtypeWorks() {
  log.debug("Entering everySignatureEtypeWorks().");
  // 18/17 are the two [MS-PAC] section 2.8 defines for AES; 23 is RC4's -138, which is
  // still what an older domain will hand you.
  var cases = [
    [18, 16, "HMAC_SHA1_96_AES256"],
    [17, 15, "HMAC_SHA1_96_AES128"],
    [23, -138, "KERB_CHECKSUM_HMAC_MD5"]
  ];
  for (var i = 0; i < cases.length; i++) {
    var etype = cases[i][0], expectType = cases[i][1], expectName = cases[i][2];
    var key = keyOf(etype, 0x40 + i);
    var bytes = await pac.buildPac({
      serverKey: key, kdcKey: key,
      logonInfo: sampleLogonInfo(),
      clientInfo: { name: "alice" }
    });
    var parsed = pac.parsePac(bytes);
    var sig = pac.bufferOfType(parsed, pac.TYPE.SERVER_CHECKSUM).parsed;
    assert.strictEqual(sig.signatureType, expectType,
      "etype " + etype + " should produce signature type " + expectType);
    assert.ok(sig.signatureTypeName.indexOf(expectName) === 0,
      "and should be named " + expectName + ", got " + sig.signatureTypeName);
    assert.strictEqual(sig.signature.length, expectType === -138 ? 16 : 12,
      "[MS-PAC] section 2.8 fixes the signature length per type");
    var results = await pac.verifySignatures(parsed, { serverKey: key, kdcKey: key });
    results.forEach(function (r) {
      if (r.type === pac.TYPE.SERVER_CHECKSUM || r.type === pac.TYPE.KDC_CHECKSUM) {
        assert.strictEqual(r.verified, true,
          "etype " + etype + "'s " + r.name + " should verify: " + r.note);
      }
    });
  }

  // -138 is 0xFFFFFF76 on the wire. Read unsigned it is 4294967158 and matches nothing,
  // so assert the signed reading explicitly.
  var rc4Key = keyOf(23, 0x99);
  var rc4Pac = await pac.buildPac({
    serverKey: rc4Key, kdcKey: rc4Key, logonInfo: sampleLogonInfo(), clientInfo: { name: "alice" }
  });
  var rc4Parsed = pac.parsePac(rc4Pac);
  var at = pac.bufferOfType(rc4Parsed, pac.TYPE.SERVER_CHECKSUM).offset;
  assert.strictEqual(hex(rc4Pac.subarray(at, at + 4)), "76ffffff",
    "KERB_CHECKSUM_HMAC_MD5 is -138, which is 0xFFFFFF76 little-endian on the wire");

  // A signature type nothing here can compute must be reported, not thrown away.
  var unknown = new Uint8Array(rc4Pac);
  unknown[at] = 0x55; unknown[at + 1] = 0x00; unknown[at + 2] = 0x00; unknown[at + 3] = 0x00;
  var unknownParsed = pac.parsePac(unknown);
  var unknownSig = pac.bufferOfType(unknownParsed, pac.TYPE.SERVER_CHECKSUM).parsed;
  assert.strictEqual(unknownSig.signatureType, 0x55,
    "an unrecognised signature type should still be reported as a number");
  assert.ok(/signature type 85/.test(unknownSig.signatureTypeName),
    "and named as unrecognised, got " + unknownSig.signatureTypeName);
  var unknownResults = await pac.verifySignatures(unknownParsed,
    { serverKey: rc4Key, kdcKey: rc4Key });
  var r = unknownResults.filter(function (x) { return x.type === pac.TYPE.SERVER_CHECKSUM; })[0];
  assert.strictEqual(r.verified, false);
  assert.ok(/not one this code can compute/.test(r.note),
    "and the verifier should say it cannot compute that type rather than reporting a bad " +
    "signature, got: " + r.note);

  log.debug("Leaving everySignatureEtypeWorks().");
}

async function test() {
  log.debug("Entering test().");
  await theHeaderMatchesTheSpecByteForByte();
  await theLogonInfoSitsWhereTheIdlSaysItDoes();
  await theReaderRecoversEveryField();
  await resourceGroupsAreReadWithTheirOwnDomainSid();
  await eachSignatureIsCheckedAgainstItsOwnKeyAndItsOwnBytes();
  await theTicketSignatureBindsThePacToOneTicket();
  await thePacIsFoundInsideAdIfRelevant();
  await malformedPacsAreRefusedOrReported();
  await theConsistencyRulesAreReported();
  theNdrReaderRefusesHostileInput();
  await everySignatureEtypeWorks();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("krb5_pac")
  .description("Verify the Windows PAC codec: the NDR layout at hand-derived offsets, all four " +
               "signatures, and the malformed cases.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>", "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
