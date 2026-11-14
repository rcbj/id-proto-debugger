// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: krb5_pac.js
//
// ---------------------------------------------------------------------------
// The Windows PAC — [MS-PAC], the Privilege Attribute Certificate.
//
// This is the part of Kerberos that Windows added and that RFC 4120 knows nothing
// about, and it is the part that actually decides what you can do. A Kerberos ticket
// proves WHO you are; it says nothing about your group memberships, and a Windows
// service authorizes on groups. So the KDC puts a structure inside the ticket listing
// the account's SID, its primary group, every group it belongs to, its account flags
// and its logon times — and the service reads THAT, not the ticket's cname. Which is
// why a debugger that decodes a ticket and stops at `cname` has shown you the least
// interesting half: "authentication succeeded but access was denied" is nearly always
// a question about this structure, and until you can read it you are guessing.
//
// ---------------------------------------------------------------------------
// WHERE IT LIVES, which is three layers deep and easy to get lost in.
//
//   EncTicketPart.authorization-data           (RFC 4120 section 5.2.6)
//     └── ad-type 1, AD-IF-RELEVANT            ← a CONTAINER: its ad-data is itself
//         └── ad-type 128, AD-WIN2K-PAC              another AuthorizationData
//             └── PACTYPE  ← this module starts here
//
// AD-IF-RELEVANT means "ignore what you do not understand rather than failing", which
// is the only reason a non-Windows Kerberos client can use an AD ticket at all. A
// reader that looks for ad-type 128 at the top level finds nothing, and concludes
// there is no PAC, on a ticket that has one. `findPac()` unwraps the containers.
//
// ---------------------------------------------------------------------------
// TWO ENCODINGS IN ONE TICKET. Everything outside is ASN.1 DER, big-endian lengths,
// tag-length-value. Everything from PACTYPE inward is a **little-endian C struct
// layout**, and the logon information inside it is **NDR** — the RPC marshalling,
// with referent-id pointers and alignment padding (see `krb5_ndr.js`, whose header
// lists the five rules that each cause a silent misread). Nothing signals the
// transition. The give-away in a hex dump is `01 10 08 00 cc cc cc cc` at the start
// of the logon-information buffer: that is [MS-RPCE]'s type-marshalling header, and
// the 0xCC filler bytes are the landmark.
//
// ---------------------------------------------------------------------------
// FOUR SIGNATURES, AND THEY ARE NOT INTERCHANGEABLE. This is the part worth reading
// before touching `verifySignatures()`, because the four are computed over DIFFERENT
// bytes with DIFFERENT keys, and the ORDER they are generated in is load-bearing:
//
//   Ticket signature       (type 16) — over the DER of the EncTicketPart with the
//                                      PAC's own ad-data replaced by a SINGLE ZERO
//                                      BYTE. krbtgt key. Generated FIRST.
//   Extended KDC signature (type 19) — over the whole PAC. krbtgt key. Generated
//                                      BEFORE the server signature.
//   Server signature       (type  6) — over the whole PAC with the server and KDC
//                                      signature fields zeroed. The SERVICE's key,
//                                      so the service can check it itself.
//   KDC signature          (type  7) — over the SERVER SIGNATURE'S BYTES ALONE, not
//                                      over the PAC. krbtgt key. Generated LAST.
//
// Two consequences. First, a service can verify the server signature but NOT the KDC
// signature — it does not have the krbtgt key, which is the whole point: only a KDC
// can confirm a KDC issued this. Second, the zeroing rule is what makes verification
// possible at all, and it follows from the generation order rather than from a
// separate rule: at the moment each signature is computed, the ones generated after
// it are still zero, so a verifier reconstructs that state by zeroing them again.
// [MS-PAC] states this explicitly for the server signature ("with the Signature
// fields of both PAC_SIGNATURE_DATA structures set to zero") and leaves it implied
// for the extended one, where the ordering statement in section 2.8.3 supplies it.
//
// All four use key usage **KERB_NON_KERB_CKSUM_SALT (17)** — the same number
// PA-FOR-USER uses, which is not a coincidence so much as a reused constant.
//
// Golden Ticket, Silver Ticket and CVE-2022-37967 all live in these four lines.
// A forged PAC needs the key for whichever signature the verifier actually checks;
// the ticket and extended KDC signatures exist precisely because for years nobody
// checked enough of them. This module verifies each one it can and reports the rest
// BY NAME as unverifiable-for-want-of-a-key, rather than reducing four different
// facts to one green tick.
// ---------------------------------------------------------------------------

var prim = require("./krb5_primitives.js");
var kcrypto = require("./krb5_crypto.js");
var asn1 = require("./krb5_asn1.js");
var msgs = require("./krb5_messages.js");
var ndr = require("./krb5_ndr.js");
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "krb5_pac",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      // No CONFIG_FILE resolvable here — a node caller rather than a bundle.
      return "info";
    }
  })()
});

// The authorization-data types this module has to walk through or name. The
// first two are RFC 4120's; the rest are MS-KILE's.
var AD_TYPE = {
  IF_RELEVANT: 1,
  KDC_ISSUED: 4,
  AND_OR: 5,
  MANDATORY_FOR_KDC: 8,
  WIN2K_PAC: 128,
  ETYPE_NEGOTIATION: 129,
  TOKEN_RESTRICTIONS: 141,
  LOCAL: 142,
  AP_OPTIONS: 143,
  SERVICE_TARGET: 144
};

var AD_TYPE_NAMES = {
  1: "AD-IF-RELEVANT",
  4: "AD-KDCIssued",
  5: "AD-AND-OR",
  8: "AD-MANDATORY-FOR-KDC",
  128: "AD-WIN2K-PAC",
  129: "AD-ETYPE-NEGOTIATION",
  141: "KERB-AD-RESTRICTION-ENTRY",
  142: "KERB-LOCAL",
  143: "KERB-AP-OPTIONS",
  144: "KERB-SERVICE-TARGET"
};

function adTypeName(t) {
  return AD_TYPE_NAMES[t] || ("ad-type " + t);
}

// PAC_INFO_BUFFER ulType values, [MS-PAC] section 2.4.
var TYPE = {
  LOGON_INFO: 1,
  CREDENTIALS_INFO: 2,
  SERVER_CHECKSUM: 6,
  KDC_CHECKSUM: 7,
  CLIENT_INFO: 10,
  DELEGATION_INFO: 11,
  UPN_DNS_INFO: 12,
  CLIENT_CLAIMS: 13,
  DEVICE_INFO: 14,
  DEVICE_CLAIMS: 15,
  TICKET_CHECKSUM: 16,
  ATTRIBUTES_INFO: 17,
  REQUESTOR_SID: 18,
  EXTENDED_KDC_CHECKSUM: 19,
  REQUESTOR_GUID: 20
};

var TYPE_NAMES = {
  1: "Logon information (KERB_VALIDATION_INFO)",
  2: "Credentials information (PAC_CREDENTIAL_INFO)",
  6: "Server checksum",
  7: "KDC checksum",
  10: "Client name and ticket information (PAC_CLIENT_INFO)",
  11: "Constrained delegation information (S4U_DELEGATION_INFO)",
  12: "UPN and DNS information (UPN_DNS_INFO)",
  13: "Client claims information (PAC_CLIENT_CLAIMS_INFO)",
  14: "Device information (PAC_DEVICE_INFO)",
  15: "Device claims information (PAC_DEVICE_CLAIMS_INFO)",
  16: "Ticket checksum",
  17: "PAC attributes (PAC_ATTRIBUTES_INFO)",
  18: "PAC requestor SID (PAC_REQUESTOR_SID)",
  19: "Extended KDC checksum",
  20: "PAC requestor GUID"
};

function bufferTypeName(t) {
  return TYPE_NAMES[t] || ("unknown buffer type " + t);
}

// Every signature buffer, in the order they are GENERATED — which is the order
// `buildPac()` must fill them in, and the reason a verifier can zero the right
// ones.
var SIGNATURE_TYPES_IN_GENERATION_ORDER = [
  TYPE.TICKET_CHECKSUM,
  TYPE.EXTENDED_KDC_CHECKSUM,
  TYPE.SERVER_CHECKSUM,
  TYPE.KDC_CHECKSUM
];

function isSignatureBuffer(t) {
  return SIGNATURE_TYPES_IN_GENERATION_ORDER.indexOf(t) !== -1;
}

// [MS-PAC] section 2.8's SignatureType table, and the etype whose crypto
// profile each one belongs to. Only these three appear from a Windows KDC; 19
// and 20 are here because this project's own mock KDC can be driven with
// AES-SHA2, which Windows has never supported — so seeing one is a fact about
// the KDC, worth saying rather than rejecting.
var SIGNATURE_TYPE = {
  HMAC_MD5: -138,             // 0xFFFFFF76, RFC 4757 — 16 bytes
  HMAC_SHA1_96_AES128: 15,    // RFC 3962 — 12 bytes
  HMAC_SHA1_96_AES256: 16     // RFC 3962 — 12 bytes
};

var SIGNATURE_TYPE_TO_ETYPE = {
  "-138": 23,
  "15": 17,
  "16": 18,
  "19": 19,
  "20": 20
};

var SIGNATURE_TYPE_NAMES = {
  "-138": "KERB_CHECKSUM_HMAC_MD5",
  "15": "HMAC_SHA1_96_AES128",
  "16": "HMAC_SHA1_96_AES256",
  "19": "HMAC_SHA256_128_AES128 (not a Windows signature type)",
  "20": "HMAC_SHA384_192_AES256 (not a Windows signature type)"
};

// All four PAC signatures use this one. Named for what [MS-KILE] calls it,
// because the number alone reads like an arbitrary choice.
var KERB_NON_KERB_CKSUM_SALT = 17;

function profileForSignatureType(signatureType) {
  var etype = SIGNATURE_TYPE_TO_ETYPE[String(signatureType)];
  if (etype === undefined) {
    throw new Error("krb5: PAC signature type " + signatureType +
        " is not one this code can compute" +
      " ([MS-PAC] section 2.8 defines -138, 15 and 16)");
  }
  return kcrypto.etypeById(etype);
}

function signatureTypeName(t) {
  return SIGNATURE_TYPE_NAMES[String(t)] || ("signature type " + t);
}

// SE_GROUP_* attributes on a GROUP_MEMBERSHIP or KERB_SID_AND_ATTRIBUTES entry.
//
// [MS-PAC] section 2.2.1 defines exactly these FIVE and says "all other bits
// MUST be set to zero and MUST be ignored on receipt" — note where RESOURCE
// sits: bit 2 of the diagram, which is 0x20000000, not 0x10 as counting from
// the left would suggest.
var GROUP_ATTRIBUTES = [
  [0x00000001, "MANDATORY"],
  [0x00000002, "ENABLED_BY_DEFAULT"],
  [0x00000004, "ENABLED"],
  [0x00000008, "OWNER"],
  [0x20000000, "RESOURCE (domain-local)"]
];

// The remaining SE_GROUP_* values from [SIDATT]. They are real flags in a
// Windows access token and NOT permitted in a PAC, so one appearing here is a
// finding rather than something to render as though the PAC defined it.
// USE_FOR_DENY_ONLY is the one to spot: the group is present and grants
// nothing, so a service can deny on it while the account genuinely "is a
// member".
var GROUP_ATTRIBUTES_OUTSIDE_MS_PAC = [
  [0x00000010, "USE_FOR_DENY_ONLY"],
  [0x00000020, "INTEGRITY"],
  [0x00000040, "INTEGRITY_ENABLED"],
  [0xC0000000, "LOGON_ID"]
];

// UserAccountControl, from [MS-SAMR] section 2.2.1.13's USER_ACCOUNT codes.
//
// NOT the LDAP `userAccountControl` attribute's bits. The two tables share most
// of their NAMES and none of their VALUES — LDAP's USER_NORMAL_ACCOUNT is
// 0x0200 where SAMR's is 0x0010 — and [MS-PAC] cites SAMR. Mixing them up
// produces a flag list that is entirely wrong while looking entirely plausible,
// which is a lie a debugger has no business telling: "Trusted for delegation"
// against an account that is not is how someone spends a day chasing the wrong
// thing.
var USER_ACCOUNT_CONTROL = [
  [0x00000001, "ACCOUNT_DISABLED"],
  [0x00000002, "HOME_DIRECTORY_REQUIRED"],
  [0x00000004, "PASSWORD_NOT_REQUIRED"],
  [0x00000008, "TEMP_DUPLICATE_ACCOUNT"],
  [0x00000010, "NORMAL_ACCOUNT"],
  [0x00000020, "MNS_LOGON_ACCOUNT"],
  [0x00000040, "INTERDOMAIN_TRUST_ACCOUNT"],
  [0x00000080, "WORKSTATION_TRUST_ACCOUNT"],
  [0x00000100, "SERVER_TRUST_ACCOUNT"],
  [0x00000200, "DONT_EXPIRE_PASSWORD"],
  [0x00000400, "ACCOUNT_AUTO_LOCKED"],
  [0x00000800, "ENCRYPTED_TEXT_PASSWORD_ALLOWED"],
  [0x00001000, "SMARTCARD_REQUIRED"],
  [0x00002000, "TRUSTED_FOR_DELEGATION"],
  [0x00004000, "NOT_DELEGATED"],
  [0x00008000, "USE_DES_KEY_ONLY"],
  [0x00010000, "DONT_REQUIRE_PREAUTH"],
  [0x00020000, "PASSWORD_EXPIRED"],
  [0x00040000, "TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION"],
  [0x00080000, "NO_AUTH_DATA_REQUIRED"],
  [0x00100000, "PARTIAL_SECRETS_ACCOUNT"],
  [0x00200000, "USE_AES_KEYS"]
];

// KERB_VALIDATION_INFO's UserFlags. Only D and H are meaningful for Kerberos —
// the rest are set by NTLM and MUST be zero here, so seeing one IS the finding.
//
// The letters are [MS-PAC] section 2.5's own, kept in the names because the
// spec refers to these bits by letter and nothing else. Read that bit diagram
// carefully: the LEFTMOST cell is bit 0 and the RIGHTMOST is the LEAST
// significant bit, so A is 0x1 and L — eighteenth from the left — is 0x2000.
// Counting the other way puts D (EXTRA_SIDS) at 0x40 instead of 0x20, which
// makes the builder emit extra SIDs a real service then ignores, and makes the
// reader report a UserFlags value made of the wrong names. Cross-checked
// against Samba's netlogon.idl, which spells the same bits as
// NETLOGON_EXTRA_SIDS 0x20 / NETLOGON_RESOURCE_GROUPS 0x200.
var USER_FLAGS = [
  [0x00000001, "A GUEST (NTLM only)"],
  [0x00000002, "B NO_ENCRYPTION (NTLM only)"],
  [0x00000008, "C LANMAN_KEY (NTLM only)"],
  [0x00000020, "D EXTRA_SIDS"],                      // ExtraSids is populated
  [0x00000040, "E SUB_AUTH (NTLM only)"],
  [0x00000080, "F MACHINE_ACCOUNT (NTLM only)"],
  [0x00000100, "G DC_NTLM2 (NTLM only)"],
  [0x00000200,
      "H RESOURCE_GROUPS"],                 // ResourceGroupIds is populated
  [0x00000400, "I PROFILE_PATH (NTLM only)"],
  [0x00000800, "J NTLMV2 (NTLM only)"],
  [0x00001000, "K LMV2 (NTLM only)"],
  [0x00002000, "L LMV2_NTLMV2 (NTLM only)"]
];

var USER_FLAG_EXTRA_SIDS = 0x00000020;
var USER_FLAG_RESOURCE_GROUPS = 0x00000200;

// PAC_ATTRIBUTES_INFO flags, [MS-PAC] section 2.14.
var PAC_ATTRIBUTE_FLAGS = [
  [0x00000001, "PAC_WAS_REQUESTED"],
  [0x00000002, "PAC_WAS_GIVEN_IMPLICITLY"]
];

// UPN_DNS_INFO flags, [MS-PAC] section 2.10.
var UPN_DNS_FLAG_NO_UPN_ATTRIBUTE = 0x00000001;   // U
var UPN_DNS_FLAG_EXTENDED = 0x00000002;           // S

// Well-known RIDs within a domain, and well-known SIDs that are not
// domain-relative. Rendering `S-1-5-21-…-512` without saying "Domain Admins"
// beside it is work the reader then has to do by hand, every time.
var WELL_KNOWN_RIDS = {
  500: "Administrator",
  501: "Guest",
  502: "krbtgt",
  512: "Domain Admins",
  513: "Domain Users",
  514: "Domain Guests",
  515: "Domain Computers",
  516: "Domain Controllers",
  517: "Cert Publishers",
  518: "Schema Admins",
  519: "Enterprise Admins",
  520: "Group Policy Creator Owners",
  521: "Read-only Domain Controllers",
  525: "Protected Users",
  526: "Key Admins",
  527: "Enterprise Key Admins",
  553: "RAS and IAS Servers",
  571: "Allowed RODC Password Replication Group",
  572: "Denied RODC Password Replication Group",
  498: "Enterprise Read-only Domain Controllers"
};

var WELL_KNOWN_SIDS = {
  "S-1-1-0": "Everyone",
  "S-1-5-2": "NT AUTHORITY\\NETWORK",
  "S-1-5-9": "Enterprise Domain Controllers",
  "S-1-5-11": "NT AUTHORITY\\Authenticated Users",
  "S-1-5-14": "NT AUTHORITY\\REMOTE INTERACTIVE LOGON",
  "S-1-5-15": "NT AUTHORITY\\This Organization",
  "S-1-5-17": "NT AUTHORITY\\IUSR",
  "S-1-5-18": "NT AUTHORITY\\SYSTEM",
  "S-1-5-32-544": "BUILTIN\\Administrators",
  "S-1-5-32-545": "BUILTIN\\Users",
  "S-1-5-32-546": "BUILTIN\\Guests",
  "S-1-5-32-548": "BUILTIN\\Account Operators",
  "S-1-5-32-549": "BUILTIN\\Server Operators",
  "S-1-5-32-550": "BUILTIN\\Print Operators",
  "S-1-5-32-551": "BUILTIN\\Backup Operators",
  "S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
  "S-1-5-64-10": "NTLM Authentication",
  "S-1-5-64-14": "SChannel Authentication",
  "S-1-5-64-21": "Digest Authentication",
  // The two that matter most when debugging S4U: they record HOW the identity
  // was established, so a service can refuse an identity the KDC merely
  // asserted.
  "S-1-18-1": "Authentication authority asserted identity",
  "S-1-18-2": "Service asserted identity",
  "S-1-18-3": "Fresh public key identity",
  "S-1-18-4": "Key trust identity",
  "S-1-18-5": "Key property MFA",
  "S-1-18-6": "Key property attestation",
  "S-1-5-21-0-0-0-496": "Compounded Authentication",
  "S-1-5-21-0-0-0-497": "Claims Valid"
};

function flagNames(table, value) {
  var out = [];
  table.forEach(function (entry) {
    // >>> 0 because 0x80000000 is negative as a signed 32-bit int, and a bare &
    // would make SE_GROUP_LOGON_ID never match.
    if (((value >>> 0) & (entry[0] >>> 0)) !== 0) out.push(entry[1]);
  });
  return out;
}

function unknownFlagBits(table, value) {
  var known = 0;
  table.forEach(function (e) { known = (known | e[0]) >>> 0; });
  return ((value >>> 0) & ~known) >>> 0;
}

// Group attributes, naming the five [MS-PAC] defines and calling out any of the
// other SE_GROUP_* values as what they are: bits the spec requires to be zero
// here.
function groupAttributeNames(value) {
  log.debug("Entering groupAttributeNames().");
  var names = flagNames(GROUP_ATTRIBUTES, value);
  GROUP_ATTRIBUTES_OUTSIDE_MS_PAC.forEach(function (entry) {
    // An exact mask match, because SE_GROUP_LOGON_ID is TWO bits — a
    // bitwise-any test would report it for either half alone. Note the SECOND
    // `>>> 0`: `&` yields a SIGNED int32, so for a mask with the top bit set
    // the result is negative and comparing it to the unsigned mask is false for
    // the one value that should match.
    var mask = entry[0] >>> 0;
    if ((((value >>> 0) & mask) >>> 0) === mask) {
      names.push(entry[1] + " (not permitted in a PAC — [MS-PAC] requires " +
          "all other bits zero)");
    }
  });
  log.debug("Leaving groupAttributeNames().");
  return names;
}

function ridName(rid) {
  return WELL_KNOWN_RIDS[rid] || null;
}

function sidName(text) {
  log.debug("Entering sidName().");
  if (WELL_KNOWN_SIDS[text]) {
    log.debug("Leaving sidName().");
    return WELL_KNOWN_SIDS[text];
  }
  // A domain-relative SID: S-1-5-21-<three sub-authorities>-<RID>.
  var m = /^S-1-5-21-\d+-\d+-\d+-(\d+)$/.exec(text);
  if (m) {
    log.debug("Leaving sidName().");
    return ridName(Number(m[1]));
  }
  log.debug("Leaving sidName().");
  return null;
}

// ---------------------------------------------------------------------------
// Finding the PAC inside an EncTicketPart's authorization-data.
// ---------------------------------------------------------------------------

// Walks AD-IF-RELEVANT (and the other container types) to whatever depth they
// nest, which is what makes ad-type 128 findable. Returns every PAC found —
// plural because a ticket with two is malformed in a way worth reporting rather
// than a case to silently take the first of.
function findPacs(authorizationData) {
  log.debug("Entering findPacs().");
  var found = [];
  var seen = 0;

  function walk(entries, path, depth) {
    log.debug("Entering walk().");
    if (!entries || depth > 4) {
      log.debug("Leaving walk().");
      return;
    }
    entries.forEach(function (ad) {
      if (++seen > 64) {
        return;
      }                    // a bounded walk over foreign bytes
      var here = path.concat([adTypeName(ad.type)]);
      if (ad.type === AD_TYPE.WIN2K_PAC) {
        found.push({ bytes: prim.toBytes(ad.data), path: here.join(" → ") });
        return;
      }
      if (ad.type === AD_TYPE.IF_RELEVANT ||
          ad.type === AD_TYPE.MANDATORY_FOR_KDC) {
        // The container's ad-data is itself a DER AuthorizationData.
        try {
          // readAuthorizationData wants a parsed TLV, not the raw OCTET STRING
          // contents — the container's ad-data is a nested DER document.
          walk(msgs.readAuthorizationData(asn1.readTlv(prim.toBytes(ad.data),
              0, 0)),
            here, depth + 1);
        } catch (e) {
          // A container this code cannot open is not a failure of the ticket:
          // other ad-types legitimately carry things we do not parse. Say so
          // and move on.
          log.debug("krb5_pac: could not open " + here.join(" → ") + ": " +
              e.message);
        }
      }
    });
    log.debug("Leaving walk().");
  }

  walk(authorizationData, [], 0);
  log.debug("Leaving findPacs().");
  return found;
}

// ---------------------------------------------------------------------------
// Parsing.
// ---------------------------------------------------------------------------

var MAX_BUFFERS = 64;

// PACTYPE, [MS-PAC] section 2.3. NOT NDR — a plain little-endian struct, with
// every buffer offset a multiple of 8.
function parsePac(bytes) {
  log.debug("Entering parsePac().");
  var all = prim.toBytes(bytes);
  var r = ndr.createReader(all);
  var problems = [];

  var cBuffers = r.u32();
  var version = r.u32();
  if (version !== 0) {
    problems.push("The PACTYPE Version is " + version + "; [MS-PAC] section " +
        "2.3 requires 0.");
  }
  if (cBuffers === 0) {
    log.debug("Leaving parsePac().");
    throw new Error("krb5: this PAC declares zero buffers");
  }
  if (cBuffers > MAX_BUFFERS) {
    log.debug("Leaving parsePac().");
    throw new Error("krb5: this PAC declares " + cBuffers + " buffers (a " +
        "real one has a handful) — " +
      "these bytes are probably not a PAC, or not being read little-endian");
  }
  if (8 + cBuffers * 16 > all.length) {
    log.debug("Leaving parsePac().");
    throw new Error("krb5: this PAC declares " + cBuffers + " buffers, whose " +
        "table alone would need " +
      (8 + cBuffers * 16) + " bytes of a " + all.length + "-byte structure");
  }

  var buffers = [];
  for (var i = 0; i < cBuffers; i++) {
    var ulType = r.u32();
    var cbBufferSize = r.u32();
    var off = r.u64();
    var entry = {
      type: ulType,
      typeName: bufferTypeName(ulType),
      size: cbBufferSize,
      offset: off.value,
      bytes: null,
      parsed: null,
      error: null
    };
    if (off.high !== 0 || off.value + cbBufferSize > all.length) {
      entry.error = "This buffer claims " + cbBufferSize +
          " bytes at offset " + off.value +
        ", which is outside the " + all.length + "-byte PAC.";
      problems.push("Buffer " + i + " (" + entry.typeName + "): " +
          entry.error);
    } else {
      if (off.value % 8 !== 0) {
        problems.push("Buffer " + i + " (" + entry.typeName +
            ") starts at offset " + off.value +
          ", which is not a multiple of 8 — [MS-PAC] section 2.4 requires " +
              "it. Windows will " +
          "reject this PAC.");
      }
      entry.bytes = all.subarray(off.value, off.value + cbBufferSize);
    }
    buffers.push(entry);
  }

  var pac = {
    cBuffers: cBuffers,
    version: version,
    buffers: buffers,
    problems: problems,
    raw: all
  };

  buffers.forEach(function (entry) {
    if (!entry.bytes) {
      return;
    }
    try {
      entry.parsed = parseBuffer(entry.type, entry.bytes);
    } catch (e) {
      // One unreadable buffer must not cost the reader the other six. Record it
      // against the buffer and carry on — the whole point of this page is
      // looking at something that is already wrong.
      entry.error = e.message;
      problems.push(entry.typeName + " did not parse: " + e.message);
    }
  });

  checkRequiredBuffers(pac);
  log.debug("Leaving parsePac().");
  return pac;
}

function bufferOfType(pac, type) {
  for (var i = 0; i < pac.buffers.length; i++) {
    if (pac.buffers[i].type === type) {
      return pac.buffers[i];
    }
  }
  return null;
}

function countOfType(pac, type) {
  return pac.buffers.filter(function (b) { return b.type === type; }).length;
}

// [MS-PAC] section 2.4 says which buffers MUST be present. Absence is worth
// naming because it changes what a Windows service will do with the ticket —
// and a duplicate is worth naming because the rule is "ignore the second", so a
// forged second buffer is invisible unless somebody counts.
function checkRequiredBuffers(pac) {
  log.debug("Entering checkRequiredBuffers().");
  [
    [TYPE.LOGON_INFO, "Logon information"],
    [TYPE.CLIENT_INFO, "Client name and ticket information"]
  ].forEach(function (pair) {
    var n = countOfType(pac, pair[0]);
    if (n === 0) {
      pac.problems.push("There is no " + pair[1] + " buffer. [MS-PAC] " +
          "section 2.4 requires one.");
    } else if (n > 1) {
      pac.problems.push("There are " + n + " " + pair[1] + " buffers. Only " +
          "the first is used; " +
        "the rest MUST be ignored, so a second one is a place to hide " +
            "something.");
    }
  });
  [TYPE.SERVER_CHECKSUM, TYPE.KDC_CHECKSUM].forEach(function (t) {
    if (countOfType(pac, t) === 0) {
      pac.problems.push("There is no " + bufferTypeName(t) + " buffer. A PAC " +
          "in a ticket always " +
        "carries one; without it nothing about this PAC can be verified.");
    }
  });
  log.debug("Leaving checkRequiredBuffers().");
}

function parseBuffer(type, bytes) {
  log.debug("Entering parseBuffer().");
  switch (type) {
    case TYPE.LOGON_INFO:
      log.debug("Leaving parseBuffer().");
      return parseLogonInfo(bytes);
    case TYPE.CLIENT_INFO:
      log.debug("Leaving parseBuffer().");
      return parseClientInfo(bytes);
    case TYPE.UPN_DNS_INFO:
      log.debug("Leaving parseBuffer().");
      return parseUpnDnsInfo(bytes);
    case TYPE.ATTRIBUTES_INFO:
      log.debug("Leaving parseBuffer().");
      return parseAttributesInfo(bytes);
    case TYPE.REQUESTOR_SID:
      log.debug("Leaving parseBuffer().");
      return parseRequestorSid(bytes);
    case TYPE.REQUESTOR_GUID:
      log.debug("Leaving parseBuffer().");
      return parseRequestorGuid(bytes);
    case TYPE.DELEGATION_INFO:
      log.debug("Leaving parseBuffer().");
      return parseDelegationInfo(bytes);
    case TYPE.CLIENT_CLAIMS:
    case TYPE.DEVICE_CLAIMS:
      log.debug("Leaving parseBuffer().");
      return parseClaimsInfo(bytes);
    case TYPE.SERVER_CHECKSUM:
    case TYPE.KDC_CHECKSUM:
    case TYPE.TICKET_CHECKSUM:
    case TYPE.EXTENDED_KDC_CHECKSUM:
      log.debug("Leaving parseBuffer().");
      return parseSignature(bytes);
    default:
      // Device info and credentials are not decoded here. Returning null
      // rather than throwing keeps them listed with their sizes, which is
      // honest: "present, not decoded" is different from "absent". The two
      // claims buffers ARE decoded, since 2026-10-06 (iya-sts #493).
      log.debug("Leaving parseBuffer().");
      return null;
  }
  log.debug("Leaving parseBuffer().");
}

// PAC_SIGNATURE_DATA, [MS-PAC] section 2.8.
function parseSignature(bytes) {
  log.debug("Entering parseSignature().");
  var b = prim.toBytes(bytes);
  if (b.length < 4) {
    log.debug("Leaving parseSignature().");
    throw new Error("krb5: a signature buffer of " + b.length + " bytes");
  }
  var r = ndr.createReader(b);
  var raw = r.u32();
  // SignatureType is a SIGNED 32-bit value: KERB_CHECKSUM_HMAC_MD5 is
  // 0xFFFFFF76, which is -138. Reading it unsigned gives 4294967158 and matches
  // nothing.
  var signatureType = raw > 0x7fffffff ? raw - 0x100000000 : raw;
  var rest = b.subarray(4);
  var expected = null;
  try {
    expected = profileForSignatureType(signatureType).checksumBytes;
  } catch (e) {
    // An unknown signature type is a fact to report, not a parse failure: the
    // signature bytes are still worth showing.
    expected = null;
  }
  var signature = expected === null ? rest : rest.subarray(0,
      Math.min(expected, rest.length));
  // A trailing 2 bytes is an RODC identifier — the first 16 bits of the key
  // version number, present only when the issuing KDC is read-only. Anything
  // else trailing is a length that does not match the signature type.
  var trailing = expected === null ? new Uint8Array(0) :
      rest.subarray(signature.length);
  log.debug("Leaving parseSignature().");
  return {
    signatureType: signatureType,
    signatureTypeName: signatureTypeName(signatureType),
    signature: signature,
    expectedLength: expected,
    rodcIdentifier: trailing.length === 2 ? (
        trailing[0] | (trailing[1] << 8)) : null,
    trailing: trailing.length === 2 ? null : trailing,
    // Where in the buffer the signature bytes start, which is what the zeroing
    // needs.
    signatureOffsetInBuffer: 4
  };
}

// PAC_CLIENT_INFO, [MS-PAC] section 2.7. A plain struct, not NDR.
function parseClientInfo(bytes) {
  log.debug("Entering parseClientInfo().");
  var r = ndr.createReader(bytes);
  var clientId = ndr.readFileTime(r);
  var nameLength = r.u16();
  if (nameLength % 2 !== 0) {
    log.debug("Leaving parseClientInfo().");
    throw new Error("krb5: PAC_CLIENT_INFO NameLength is " + nameLength +
        " bytes, which is odd — " +
      "the name is UTF-16, so it must be even");
  }
  if (nameLength > r.remaining) {
    log.debug("Leaving parseClientInfo().");
    throw new Error("krb5: PAC_CLIENT_INFO says its name is " + nameLength +
        " bytes but only " +
      r.remaining + " remain in the buffer");
  }
  var name = "";
  for (var i = 0; i < nameLength / 2; i++) name += String.fromCharCode(r.u16());
  log.debug("Leaving parseClientInfo().");
  return { clientId: clientId, name: name };
}

// UPN_DNS_INFO, [MS-PAC] section 2.10. Offsets are from the START OF THIS
// BUFFER, not from the start of the PAC — a distinction that costs an afternoon
// if missed, because the small offsets land inside the PACTYPE header and
// decode as noise.
function parseUpnDnsInfo(bytes) {
  log.debug("Entering parseUpnDnsInfo().");
  var b = prim.toBytes(bytes);
  var r = ndr.createReader(b);
  var upnLength = r.u16();
  var upnOffset = r.u16();
  var dnsLength = r.u16();
  var dnsOffset = r.u16();
  var flags = r.u32();

  function utf16At(offset, length, what) {
    log.debug("Entering utf16At().");
    if (length === 0) {
      log.debug("Leaving utf16At().");
      return null;
    }
    if (length % 2 !== 0) {
      log.debug("Leaving utf16At().");
      throw new Error("krb5: UPN_DNS_INFO's " + what + " length is " + length +
          ", which is odd");
    }
    if (offset + length > b.length) {
      log.debug("Leaving utf16At().");
      throw new Error("krb5: UPN_DNS_INFO's " + what + " claims " + length +
          " bytes at offset " +
        offset + ", past the end of its " + b.length + "-byte buffer");
    }
    var s = "";
    for (var i = 0; i < length; i += 2) s += String.fromCharCode(b[offset +
        i] | (b[offset + i + 1] << 8));
    log.debug("Leaving utf16At().");
    return s;
  }

  var info = {
    flags: flags,
    flagNames: (flags & UPN_DNS_FLAG_NO_UPN_ATTRIBUTE ? ["U (no " +
        "userPrincipalName attribute; " +
      "this UPN was constructed)"] : []).concat(
      flags & UPN_DNS_FLAG_EXTENDED ? ["S (extended with the SAM name and " +
          "SID)"] : []),
    upn: utf16At(upnOffset, upnLength, "UPN"),
    dnsDomainName: utf16At(dnsOffset, dnsLength, "DNS domain name"),
    samName: null,
    sid: null,
    extended: (flags & UPN_DNS_FLAG_EXTENDED) !== 0
  };

  if (info.extended) {
    // The four extra fields exist only when S is set, so they are read only
    // then — reading them unconditionally would pick up the UPN's own
    // characters and report a SAM name made of them.
    r.seek(12);
    var samLength = r.u16();
    var samOffset = r.u16();
    var sidLength = r.u16();
    var sidOffset = r.u16();
    info.samName = utf16At(samOffset, samLength, "SAM name");
    if (sidLength) {
      if (sidOffset + sidLength > b.length) {
        log.debug("Leaving parseUpnDnsInfo().");
        throw new Error("krb5: UPN_DNS_INFO's SID claims " + sidLength +
            " bytes at offset " +
          sidOffset + ", past the end of its " + b.length + "-byte buffer");
      }
      var sr = ndr.createReader(b.subarray(sidOffset, sidOffset + sidLength));
      info.sid = ndr.readSid(sr);
    }
  }
  log.debug("Leaving parseUpnDnsInfo().");
  return info;
}

// PAC_ATTRIBUTES_INFO, [MS-PAC] section 2.14.
function parseAttributesInfo(bytes) {
  log.debug("Entering parseAttributesInfo().");
  var r = ndr.createReader(bytes);
  var flagsLength = r.u32();          // in BITS, not bytes
  var words = [];
  while (r.remaining >= 4) words.push(r.u32());
  var flags = words.length ? words[0] : 0;
  log.debug("Leaving parseAttributesInfo().");
  return {
    flagsLength: flagsLength,
    flags: flags,
    words: words,
    flagNames: flagNames(PAC_ATTRIBUTE_FLAGS, flags),
    unknownBits: unknownFlagBits(PAC_ATTRIBUTE_FLAGS, flags)
  };
}

// PAC_REQUESTOR_SID, [MS-PAC] section 2.15: "a single SID structure", with no
// NDR conformance ahead of it.
function parseRequestorSid(bytes) {
  var r = ndr.createReader(bytes);
  var sid = ndr.readSid(r);
  return { sid: sid, name: sidName(sid.text) };
}

function parseRequestorGuid(bytes) {
  log.debug("Entering parseRequestorGuid().");
  var b = prim.toBytes(bytes);
  if (b.length < 16) {
    log.debug("Leaving parseRequestorGuid().");
    throw new Error("krb5: a GUID buffer of " + b.length + " bytes; 16 are " +
        "needed");
  }
  // A GUID's first three fields are little-endian and its last two are not,
  // which is why it cannot just be hex-dumped in order.
  function le(o, n) {
    var v = 0;
    for (var i = n - 1; i >= 0; i--) v = v * 256 + b[o + i];
    return v;
  }
  var hex = function (v, w) {
    var s = v.toString(16);
    while (s.length < w) s = "0" + s;
    return s;
  };
  var tail = "";
  for (var i = 8; i < 16; i++) tail += hex(b[i], 2);
  log.debug("Leaving parseRequestorGuid().");
  return {
    guid: hex(le(0, 4), 8) + "-" + hex(le(4, 2), 4) + "-" + hex(le(6, 2), 4) +
        "-" +
      tail.slice(0, 4) + "-" + tail.slice(4)
  };
}

// S4U_DELEGATION_INFO, [MS-PAC] section 2.9 — NDR, like the logon information.
//
// The AUDIT TRAIL of a constrained-delegation chain: the service the ticket may
// be forwarded to, and every service it has already been delegated through. A
// KDC appends to it on each S4U2proxy hop, so this is where "who actually asked
// for this, on whose behalf, via what" is answered — and it is the buffer to
// read first when a delegation works from one host and not another.
//
// Its transited list is an array of POINTERS to RPC_UNICODE_STRINGs, which
// means two levels of deferral: the array's element pointers come first, then
// each string's own header, and only then the characters. Reading it as an
// array of inline strings gets the first element right and everything after it
// wrong.
function parseDelegationInfo(bytes) {
  log.debug("Entering parseDelegationInfo().");
  var r = ndr.createReader(bytes);
  var headers = ndr.readTypeMarshallingHeaders(r);
  if (!r.pointer()) {
    log.debug("Leaving parseDelegationInfo().");
    throw new Error("krb5: the delegation information's top-level pointer is " +
        "NULL");
  }
  var target = ndr.readUnicodeStringHeader(r);
  var listSize = r.u32();
  var listPresent = r.pointer();

  ndr.readUnicodeStringValue(r, target);

  var services = [];
  if (listPresent) {
    var declared = r.arrayCount("transited service(s)");
    if (declared !== listSize) {
      log.debug("Leaving parseDelegationInfo().");
      throw new Error("krb5: TransitedListSize is " + listSize +
          " but the array's own conformant " +
        "count is " + declared);
    }
    // Every element's RPC_UNICODE_STRING HEADER first — the headers are the
    // array's elements — and only then each one's characters, in the same
    // order.
    var headersList = [];
    for (var i = 0; i < declared; i++) headersList.push(ndr.readUnicodeStringHeader(r));
    headersList.forEach(function (h) {
      ndr.readUnicodeStringValue(r, h);
      services.push(h.value);
    });
  } else if (listSize !== 0) {
    log.debug("Leaving parseDelegationInfo().");
    throw new Error("krb5: TransitedListSize is " + listSize + " but the " +
        "array pointer is NULL");
  }

  log.debug("Leaving parseDelegationInfo().");
  return {
    ndr: headers,
    s4u2proxyTarget: target.value,
    transitedServices: services,
    bytesUnread: r.remaining
  };
}

function encodeDelegationInfo(spec) {
  log.debug("Entering encodeDelegationInfo().");
  var w = ndr.createWriter();
  var lengthOffset = ndr.writeTypeMarshallingHeaders(w);
  var bodyStart = w.offset;
  w.pointer(true);

  var services = spec.transitedServices || [];
  ndr.writeUnicodeStringHeader(w, spec.s4u2proxyTarget);
  w.u32(services.length);
  w.pointer(services.length > 0);

  ndr.writeUnicodeStringValue(w, spec.s4u2proxyTarget);
  if (services.length) {
    w.u32(services.length);
    // Headers for every element first, then every element's characters — see
    // the reader.
    services.forEach(function (name) { ndr.writeUnicodeStringHeader(w,
        name); });
    services.forEach(function (name) { ndr.writeUnicodeStringValue(w, name); });
  }

  w.align(8);
  log.debug("Leaving encodeDelegationInfo().");
  return w.patchU32(lengthOffset, w.offset - bodyStart).build();
}

// ---------------------------------------------------------------------------
// CLAIMS — PAC_CLIENT_CLAIMS_INFO (type 13) and PAC_DEVICE_CLAIMS_INFO (type
// 15), [MS-PAC] section 2.11, whose bytes are [MS-ADTS] section 2.2.18's
// CLAIMS_SET_METADATA wrapping a CLAIMS_SET.
//
// TWO NDR STREAMS, ONE INSIDE THE OTHER, and that is the first thing to get
// right. The buffer is a type-serialized CLAIMS_SET_METADATA (the same
// `01 10 08 00 cc cc cc cc` header the logon information starts with). Its
// `ClaimsSet` member is a conformant BYTE array — opaque bytes, as far as the
// outer stream is concerned — and THOSE bytes are a second, complete,
// type-serialized stream: a CLAIMS_SET with a header of its own, possibly
// compressed. A reader that walks straight from the metadata into the claims
// arrays reads the inner header as a claims-array count.
//
// THE SHAPE OF ONE CLAIMS_SET, as the IDL gives it:
//
//   CLAIMS_SET          { ULONG ulClaimsArrayCount; CLAIMS_ARRAY *ClaimsArrays;
//                         USHORT usReservedType; ULONG ulReservedFieldSize;
//                         BYTE *ReservedField; }
//   CLAIMS_ARRAY        { CLAIMS_SOURCE_TYPE usClaimsSourceType;
//                         ULONG ulClaimsCount; CLAIM_ENTRY *ClaimEntries; }
//   CLAIM_ENTRY         { LPWSTR Id; CLAIM_TYPE Type;
//                         [switch_is(Type)] union { ULONG ValueCount;
//                                                   <type> *Values; } }
//
// FOUR THINGS ABOUT IT ARE SILENT WHEN WRONG, in the krb5_ndr.js sense — each
// produces a structure that parses and says something false:
//
//  1. **Every enum is SIXTEEN bits.** CLAIM_TYPE, CLAIMS_SOURCE_TYPE and the
//     compression format are MIDL enums without `v1_enum`, which NDR marshals
//     as a short. Reading one as a ULONG swallows the two bytes after it.
//  2. **The union's discriminant is marshalled AGAIN**, as a second 16-bit copy
//     of `Type` straight after the first, before the arm. A reader that takes
//     the struct's `Type` as the switch and goes on to the arm reads the
//     discriminant as the low half of ValueCount. In NDR32 there is no 8-byte
//     alignment in front of it, whatever the IDL's NDR64 flag says.
//  3. **An id is a `[string]` LPWSTR**: a conformant VARYING array whose counts
//     INCLUDE the terminating NUL. The RPC_UNICODE_STRING writer in
//     krb5_ndr.js counts no terminator, so it cannot be reused for this.
//  4. **The 64-bit values are 8-aligned in the deferred array**, after its
//     4-byte conformant count, so there are four bytes of padding between the
//     count and the first value whenever the count lands on an offset that is
//     4 mod 8. They are also full 64-bit integers, which a JavaScript Number
//     cannot hold; they are read and written through BigInt and reported as
//     DECIMAL STRINGS, so a value survives JSON and a round trip exactly.
//
// The deferred order is the NDR rule krb5_ndr.js states as rule 4, applied
// twice: all of an array's fixed parts first, then each element's referents in
// order — and a referent that itself holds pointers (a string claim's array of
// LPWSTR pointers) has its own referents immediately after it, before the
// next element's id.
//
// COMPRESSION is READ and never WRITTEN. [MS-ADTS] lets a KDC compress the
// inner stream; the only format a Windows KDC uses and [MS-PAC] interop needs
// is COMPRESSION_FORMAT_XPRESS_HUFF ([MS-XCA] section 2.1, LZ77+Huffman), which
// `decompressXpressHuffman()` below decodes. LZNT1 and plain XPRESS are
// declared by the enum and used by nobody for claims, so a set in either is
// REPORTED, by name, rather than decoded. Nothing here compresses: an
// uncompressed set is always valid, and a compressor is code whose only effect
// would be to make this KDC's output harder to read.
// ---------------------------------------------------------------------------

var CLAIM_TYPE = {
  INT64: 1,
  UINT64: 2,
  STRING: 3,
  BOOLEAN: 6
};

var CLAIM_TYPE_NAMES = {
  1: "INT64",
  2: "UINT64",
  3: "STRING",
  6: "BOOLEAN"
};

var CLAIMS_SOURCE_TYPE = {
  AD: 1,
  CERTIFICATE: 2
};

var CLAIMS_SOURCE_TYPE_NAMES = {
  1: "AD",
  2: "CERTIFICATE"
};

var CLAIMS_COMPRESSION = {
  NONE: 0,
  LZNT1: 2,
  XPRESS: 3,
  XPRESS_HUFF: 4
};

var CLAIMS_COMPRESSION_NAMES = {
  0: "COMPRESSION_FORMAT_NONE",
  2: "COMPRESSION_FORMAT_LZNT1",
  3: "COMPRESSION_FORMAT_XPRESS",
  4: "COMPRESSION_FORMAT_XPRESS_HUFF"
};

// The IDL's own `[range(0, 10*1024*1024)]` on every count and size here. The
// NDR reader's MAX_NDR_BYTES (1 MiB) is lower and is what actually bounds a
// read; this is what a DECOMPRESSED size is checked against before anything is
// allocated, because that number is chosen by whoever compressed the set.
var CLAIMS_MAX_SIZE = 10 * 1024 * 1024;

function claimTypeName(t) {
  return CLAIM_TYPE_NAMES[t] || ("claim type " + t);
}

// A 64-bit value from the two halves NDR leaves it in, as a decimal string.
function u64Text(r, signed) {
  var lo = BigInt(r.u32());
  var hi = BigInt(r.u32());
  var v = (hi << BigInt(32)) | lo;
  if (signed && hi >= BigInt(0x80000000)) {
    v -= BigInt(1) << BigInt(64);
  }
  return v.toString();
}

// A value as a BigInt, from a Number, a BigInt or a decimal string, held to the
// type's range. Throws a sentence naming the claim, because the caller is a KDC
// that has to say which configured claim it could not put in a ticket.
function claimBigInt(value, type, id) {
  log.debug("Entering claimBigInt().");
  var v;
  try {
    if (typeof value === "bigint") {
      v = value;
    } else if (typeof value === "number") {
      if (!Number.isInteger(value)) {
        throw new Error("not an integer");
      }
      v = BigInt(value);
    } else {
      var text = String(value).trim();
      if (!/^-?\d+$/.test(text)) {
        throw new Error("not a decimal integer");
      }
      v = BigInt(text);
    }
  } catch (e) {
    log.debug("Leaving claimBigInt().");
    throw new Error("krb5: the claim " + id + " has the value '" + value +
        "', which is not a " + claimTypeName(type) + ": " + e.message);
  }
  var min = type === CLAIM_TYPE.INT64 ? -(BigInt(1) << BigInt(63)) :
      BigInt(0);
  var max = type === CLAIM_TYPE.INT64 ? (BigInt(1) << BigInt(63)) - BigInt(1) :
      (BigInt(1) << BigInt(64)) - BigInt(1);
  if (v < min || v > max) {
    log.debug("Leaving claimBigInt().");
    throw new Error("krb5: the claim " + id + " has the value " + v +
        ", which is outside the range of a " + claimTypeName(type));
  }
  log.debug("Leaving claimBigInt().");
  return v;
}

function writeU64(w, big) {
  var u = big < BigInt(0) ? big + (BigInt(1) << BigInt(64)) : big;
  w.align(8);
  w.u32(Number(u & BigInt(0xffffffff)));
  w.u32(Number(u >> BigInt(32)));
}

// A `[string]` LPWSTR's deferred half: maximum count, offset, actual count —
// all three counting the terminating NUL — then the code units and the NUL.
function writeTerminatedString(w, text) {
  var s = String(text);
  w.u32(s.length + 1);
  w.u32(0);
  w.u32(s.length + 1);
  for (var i = 0; i < s.length; i++) w.u16(s.charCodeAt(i));
  w.u16(0);
}

function readTerminatedString(r, what) {
  log.debug("Entering readTerminatedString().");
  var header = ndr.readUnicodeStringValue(r, { present: true });
  if (header.value === null) {
    log.debug("Leaving readTerminatedString().");
    throw new Error("krb5: " + what + " is missing");
  }
  log.debug("Leaving readTerminatedString().");
  return header.value;
}

// Every value of one claim, normalised to what the encoder writes: strings for
// STRING, decimal strings for the integers, true/false for BOOLEAN. Throws
// naming the claim when a value cannot be encoded.
function claimValuesFor(claim) {
  log.debug("Entering claimValuesFor().");
  var values = Array.isArray(claim.values) ? claim.values : [claim.values];
  if (!values.length) {
    log.debug("Leaving claimValuesFor().");
    throw new Error("krb5: the claim " + claim.id + " has no values; " +
        "[MS-ADTS] 2.2.18.4 requires at least one");
  }
  var out = values.map(function (value) {
    if (claim.type === CLAIM_TYPE.STRING) {
      if (value === null || value === undefined) {
        throw new Error("krb5: the claim " + claim.id + " has an empty " +
            "string value");
      }
      var s = String(value);
      if (s.indexOf("\u0000") >= 0) {
        throw new Error("krb5: the claim " + claim.id + " has a value " +
            "containing NUL, which a [string] LPWSTR cannot carry");
      }
      return s;
    }
    if (claim.type === CLAIM_TYPE.BOOLEAN) {
      if (value === true || value === "true" || value === 1 ||
          value === "1") {
        return true;
      }
      if (value === false || value === "false" || value === 0 ||
          value === "0") {
        return false;
      }
      throw new Error("krb5: the claim " + claim.id + " has the value '" +
          value + "', which is not a BOOLEAN");
    }
    return claimBigInt(value, claim.type, claim.id);
  });
  log.debug("Leaving claimValuesFor().");
  return out;
}

// CLAIMS_SET, type-serialized. spec: { arrays: [{ sourceType, claims: [{ id,
// type, values }] }] } — `sourceType` defaults to AD, `type` is a CLAIM_TYPE
// number. An array with no claims is written as one with a NULL entries
// pointer, which is legal; a set with no arrays is written with a count of
// zero, which [MS-ADTS]'s range(1, …) forbids, so the KDC writes no buffer at
// all in that case rather than calling this.
function encodeClaimsSet(spec) {
  log.debug("Entering encodeClaimsSet().");
  var arrays = (spec && spec.arrays) || [];
  // Validated and normalised up front, so a value that cannot be encoded is
  // refused before a byte is written rather than half way through.
  var prepared = arrays.map(function (array) {
    return {
      sourceType: array.sourceType === undefined ? CLAIMS_SOURCE_TYPE.AD :
          array.sourceType,
      claims: (array.claims || []).map(function (claim) {
        if (!claim || typeof claim.id !== "string" || !claim.id) {
          throw new Error("krb5: a claim with no id");
        }
        if (!CLAIM_TYPE_NAMES[claim.type]) {
          throw new Error("krb5: the claim " + claim.id + " has the type " +
              claim.type + ", which is not one of INT64 (1), UINT64 (2), " +
              "STRING (3) or BOOLEAN (6)");
        }
        return { id: claim.id, type: claim.type,
                 values: claimValuesFor(claim) };
      })
    };
  });

  var w = ndr.createWriter();
  var lengthOffset = ndr.writeTypeMarshallingHeaders(w);
  var bodyStart = w.offset;
  w.pointer(true);                                  // the top-level referent
  w.u32(prepared.length);
  w.pointer(prepared.length > 0);
  w.u16(0);                                         // usReservedType
  w.u32(0);                                         // ulReservedFieldSize
  w.pointer(false);                                 // ReservedField

  if (prepared.length) {
    w.u32(prepared.length);
    prepared.forEach(function (array) {
      w.u16(array.sourceType);
      w.u32(array.claims.length);
      w.pointer(array.claims.length > 0);
    });
    prepared.forEach(function (array) {
      if (!array.claims.length) {
        return;
      }
      w.u32(array.claims.length);
      // Every entry's fixed part first — rule 4.
      array.claims.forEach(function (claim) {
        w.pointer(true);                            // Id
        w.u16(claim.type);                          // Type
        w.u16(claim.type);                          // the union's discriminant
        w.u32(claim.values.length);
        w.pointer(true);                            // the values
      });
      // Then each entry's referents, in field order.
      array.claims.forEach(function (claim) {
        writeTerminatedString(w, claim.id);
        w.u32(claim.values.length);
        if (claim.type === CLAIM_TYPE.STRING) {
          claim.values.forEach(function () { w.pointer(true); });
          claim.values.forEach(function (s) { writeTerminatedString(w, s); });
        } else if (claim.type === CLAIM_TYPE.BOOLEAN) {
          claim.values.forEach(function (b) {
            writeU64(w, b ? BigInt(1) : BigInt(0));
          });
        } else {
          claim.values.forEach(function (v) { writeU64(w, v); });
        }
      });
    });
  }

  w.align(8);
  var built = w.patchU32(lengthOffset, w.offset - bodyStart).build();
  log.debug("Leaving encodeClaimsSet(). " + built.length + " bytes.");
  return built;
}

// CLAIMS_SET_METADATA around an UNCOMPRESSED claims set — the buffer a KDC puts
// in a PAC as type 13. `spec` is encodeClaimsSet()'s.
function encodeClaimsSetMetadata(spec) {
  log.debug("Entering encodeClaimsSetMetadata().");
  var inner = encodeClaimsSet(spec);
  var w = ndr.createWriter();
  var lengthOffset = ndr.writeTypeMarshallingHeaders(w);
  var bodyStart = w.offset;
  w.pointer(true);                                  // the top-level referent
  w.u32(inner.length);                              // ulClaimsSetSize
  w.pointer(true);                                  // ClaimsSet
  w.u16(CLAIMS_COMPRESSION.NONE);                   // never compressed here
  w.u32(inner.length);                              // ulUncompressedClaimsSetSize
  w.u16(0);                                         // usReservedType
  w.u32(0);                                         // ulReservedFieldSize
  w.pointer(false);                                 // ReservedField
  w.u32(inner.length);                              // the conformant count
  w.bytes(inner);
  w.align(8);
  var built = w.patchU32(lengthOffset, w.offset - bodyStart).build();
  log.debug("Leaving encodeClaimsSetMetadata(). " + built.length + " bytes.");
  return built;
}

function parseClaimsSet(bytes) {
  log.debug("Entering parseClaimsSet().");
  var r = ndr.createReader(bytes);
  var headers = ndr.readTypeMarshallingHeaders(r);
  if (!r.pointer()) {
    log.debug("Leaving parseClaimsSet().");
    throw new Error("krb5: the claims set's top-level pointer is NULL");
  }
  var arrayCount = r.u32();
  var arraysPresent = r.pointer();
  var reservedType = r.u16();
  var reservedFieldSize = r.u32();
  var reservedPresent = r.pointer();

  var arrays = [];
  if (arraysPresent) {
    var declared = r.arrayCount("claims array(s)");
    if (declared !== arrayCount) {
      log.debug("Leaving parseClaimsSet().");
      throw new Error("krb5: ulClaimsArrayCount is " + arrayCount +
          " but the array's own conformant count is " + declared);
    }
    for (var i = 0; i < declared; i++) {
      var sourceType = r.u16();
      var claimsCount = r.u32();
      arrays.push({
        sourceType: sourceType,
        sourceTypeName: CLAIMS_SOURCE_TYPE_NAMES[sourceType] ||
            ("source type " + sourceType),
        claimsCount: claimsCount,
        present: r.pointer(),
        claims: []
      });
    }
    arrays.forEach(function (array) {
      if (!array.present) {
        if (array.claimsCount !== 0) {
          throw new Error("krb5: a claims array declares " +
              array.claimsCount + " claim(s) and a NULL entries pointer");
        }
        return;
      }
      var n = r.arrayCount("claim entr(ies)");
      if (n !== array.claimsCount) {
        throw new Error("krb5: ulClaimsCount is " + array.claimsCount +
            " but the entries' own conformant count is " + n);
      }
      var fixed = [];
      for (var j = 0; j < n; j++) {
        var idPresent = r.pointer();
        var type = r.u16();
        var discriminant = r.u16();
        if (discriminant !== type) {
          throw new Error("krb5: a claim entry's Type is " + type +
              " and its union's discriminant is " + discriminant);
        }
        var valueCount = r.u32();
        fixed.push({ idPresent: idPresent, type: type,
                     valueCount: valueCount, valuesPresent: r.pointer() });
      }
      fixed.forEach(function (f) {
        var id = f.idPresent ? readTerminatedString(r, "a claim id") : null;
        var values = [];
        if (f.valuesPresent) {
          var vn = r.arrayCount("claim value(s)");
          if (vn !== f.valueCount) {
            throw new Error("krb5: the claim " + id + " declares " +
                f.valueCount + " value(s) and its array holds " + vn);
          }
          if (f.type === CLAIM_TYPE.STRING) {
            var present = [];
            for (var k = 0; k < vn; k++) present.push(r.pointer());
            present.forEach(function (p) {
              values.push(p ? readTerminatedString(r, "a claim value") :
                  null);
            });
          } else if (f.type === CLAIM_TYPE.INT64 ||
                     f.type === CLAIM_TYPE.UINT64 ||
                     f.type === CLAIM_TYPE.BOOLEAN) {
            for (var m = 0; m < vn; m++) {
              r.align(8);
              var text = u64Text(r, f.type === CLAIM_TYPE.INT64);
              values.push(f.type === CLAIM_TYPE.BOOLEAN ? text !== "0" : text);
            }
          } else {
            throw new Error("krb5: the claim " + id + " has the type " +
                f.type + ", which [MS-ADTS] 2.2.18.2 does not define");
          }
        }
        array.claims.push({
          id: id,
          type: f.type,
          typeName: claimTypeName(f.type),
          values: values
        });
      });
    });
  }
  var reserved = null;
  if (reservedPresent) {
    var rn = r.arrayCount("reserved byte(s)");
    reserved = prim.toHex(r.bytes(rn));
  }
  arrays.forEach(function (array) { delete array.present; });
  // The stream is padded to a multiple of 8 (as encodeClaimsSet() pads it);
  // that padding is not unread content.
  if ((8 - (r.offset % 8)) % 8 <= r.remaining) {
    r.align(8);
  }
  log.debug("Leaving parseClaimsSet().");
  return {
    ndr: headers,
    arrays: arrays,
    reservedType: reservedType,
    reservedFieldSize: reservedFieldSize,
    reservedField: reserved,
    bytesUnread: r.remaining
  };
}

// PAC_CLIENT_CLAIMS_INFO / PAC_DEVICE_CLAIMS_INFO. An EMPTY buffer is legal and
// means "no claims" — a Windows KDC sends one rather than the header around
// nothing — so it is answered as such rather than as truncated NDR.
function parseClaimsInfo(bytes) {
  log.debug("Entering parseClaimsInfo().");
  var b = prim.toBytes(bytes);
  if (!b.length) {
    log.debug("Leaving parseClaimsInfo(). Empty.");
    return { empty: true, compressionFormat: null, claimsSet: null,
             claims: [] };
  }
  var r = ndr.createReader(b);
  var headers = ndr.readTypeMarshallingHeaders(r);
  if (!r.pointer()) {
    log.debug("Leaving parseClaimsInfo().");
    throw new Error("krb5: the claims metadata's top-level pointer is NULL");
  }
  var claimsSetSize = r.u32();
  var setPresent = r.pointer();
  var compression = r.u16();
  var uncompressedSize = r.u32();
  var reservedType = r.u16();
  var reservedFieldSize = r.u32();
  var reservedPresent = r.pointer();
  var raw = null;
  if (setPresent) {
    var declared = r.u32();
    if (declared !== claimsSetSize) {
      log.debug("Leaving parseClaimsInfo().");
      throw new Error("krb5: ulClaimsSetSize is " + claimsSetSize +
          " but the array's own conformant count is " + declared);
    }
    raw = r.bytes(declared);
  }
  if (reservedPresent) {
    r.bytes(r.u32());
  }
  var out = {
    empty: false,
    ndr: headers,
    claimsSetSize: claimsSetSize,
    compressionFormat: compression,
    compressionName: CLAIMS_COMPRESSION_NAMES[compression] ||
        ("compression format " + compression),
    uncompressedClaimsSetSize: uncompressedSize,
    reservedType: reservedType,
    reservedFieldSize: reservedFieldSize,
    claimsSet: null,
    claims: []
  };
  if (!raw) {
    log.debug("Leaving parseClaimsInfo(). No claims set.");
    return out;
  }
  var inner;
  if (compression === CLAIMS_COMPRESSION.NONE) {
    inner = raw;
  } else if (compression === CLAIMS_COMPRESSION.XPRESS_HUFF) {
    inner = decompressXpressHuffman(raw, uncompressedSize);
  } else {
    log.debug("Leaving parseClaimsInfo().");
    throw new Error("krb5: this claims set is compressed with " +
        out.compressionName + ", which no KDC uses for claims and this " +
        "codec does not decode; only COMPRESSION_FORMAT_XPRESS_HUFF is read");
  }
  out.claimsSet = parseClaimsSet(inner);
  out.claims = claimsOf(out.claimsSet);
  log.debug("Leaving parseClaimsInfo(). " + out.claims.length + " claim(s).");
  return out;
}

// Every claim of a parsed set, flattened, each carrying its source type — the
// shape a reader usually wants ("what does this ticket claim?").
function claimsOf(claimsSet) {
  var out = [];
  ((claimsSet && claimsSet.arrays) || []).forEach(function (array) {
    array.claims.forEach(function (claim) {
      out.push({ sourceType: array.sourceType, id: claim.id,
                 type: claim.type, typeName: claim.typeName,
                 values: claim.values.slice() });
    });
  });
  return out;
}

// ---------------------------------------------------------------------------
// [MS-XCA] section 2.2: LZ77+Huffman ("XPRESS Huffman") DECOMPRESSION, the one
// compression a claims set arrives in.
//
// The input is a run of chunks, each producing up to 65536 bytes of output.
// A chunk starts with 256 bytes holding 512 four-bit code LENGTHS — the low
// nibble of byte i is symbol 2i, the high nibble symbol 2i+1, a zero meaning
// the symbol does not occur — from which a CANONICAL Huffman code is built:
// symbols sorted by (length, value), codes handed out in that order. Symbols
// 0–255 are literal bytes; 256–511 are matches, whose low four bits are a
// length code and whose high four the number of offset bits that follow.
//
// THE BITSTREAM IS READ AS LITTLE-ENDIAN SIXTEEN-BIT WORDS, MOST SIGNIFICANT
// BIT FIRST, and an extended match length is a BYTE read from the input at the
// current position — between words, not out of the bitstream. That
// interleaving is the trap: a decoder that takes the length byte from the bit
// buffer reads the right first match and garbage after it.
//
// BOUNDED: the output size is the one the metadata declared, checked against
// CLAIMS_MAX_SIZE before anything is allocated; a match may not reach before
// the start of the output or past its end; and a Huffman table that is not a
// complete code is refused, because one with holes decodes some bit patterns
// to nothing at all.
// ---------------------------------------------------------------------------
function buildXpressHuffmanTable(tableBytes) {
  log.debug("Entering buildXpressHuffmanTable().");
  var lengths = new Uint8Array(512);
  var symbols = [];
  for (var i = 0; i < 256; i++) {
    lengths[2 * i] = tableBytes[i] & 0x0f;
    lengths[2 * i + 1] = tableBytes[i] >> 4;
  }
  for (var s = 0; s < 512; s++) {
    if (lengths[s]) symbols.push(s);
  }
  if (!symbols.length) {
    log.debug("Leaving buildXpressHuffmanTable().");
    throw new Error("krb5: an XPRESS Huffman chunk whose table declares no " +
        "symbol");
  }
  symbols.sort(function (a, b) {
    return (lengths[a] - lengths[b]) || (a - b);
  });
  var decode = new Uint16Array(1 << 15);
  var code = 0;
  var length = lengths[symbols[0]];
  var filled = 0;
  symbols.forEach(function (sym) {
    if (lengths[sym] > length) {
      code <<= (lengths[sym] - length);
      length = lengths[sym];
    }
    var span = 1 << (15 - length);
    var start = code * span;
    if (start + span > decode.length) {
      throw new Error("krb5: an XPRESS Huffman table that oversubscribes " +
          "its code space");
    }
    decode.fill(sym, start, start + span);
    filled += span;
    code++;
  });
  if (filled !== decode.length) {
    log.debug("Leaving buildXpressHuffmanTable().");
    throw new Error("krb5: an XPRESS Huffman table that is not a complete " +
        "code (" + filled + " of " + decode.length + " patterns decode)");
  }
  log.debug("Leaving buildXpressHuffmanTable().");
  return { decode: decode, lengths: lengths };
}

function decompressXpressHuffman(input, outputSize) {
  log.debug("Entering decompressXpressHuffman(). out=" + outputSize);
  var src = prim.toBytes(input);
  if (!(outputSize > 0) || outputSize > CLAIMS_MAX_SIZE) {
    log.debug("Leaving decompressXpressHuffman().");
    throw new Error("krb5: a compressed claims set declares an uncompressed " +
        "size of " + outputSize + " (it must be 1 to " + CLAIMS_MAX_SIZE +
        ")");
  }
  var out = new Uint8Array(outputSize);
  var outPos = 0;
  var inPos = 0;
  // Reads past the end are zero: the stream's last word may be padding, and
  // every read is bounded by the output size rather than by trusting the
  // input to end where it says.
  function byteAt(p) {
    return p < src.length ? src[p] : 0;
  }
  function u16At(p) {
    return byteAt(p) | (byteAt(p + 1) << 8);
  }
  while (outPos < outputSize) {
    if (inPos + 260 > src.length) {
      log.debug("Leaving decompressXpressHuffman().");
      throw new Error("krb5: a compressed claims set ends at byte " + inPos +
          " with " + (outputSize - outPos) + " byte(s) still to produce");
    }
    var table = buildXpressHuffmanTable(src.subarray(inPos, inPos + 256));
    inPos += 256;
    var bits = ((u16At(inPos) << 16) | u16At(inPos + 2)) >>> 0;
    inPos += 4;
    var extra = 16;
    var chunkEnd = Math.min(outPos + 65536, outputSize);
    while (outPos < chunkEnd) {
      var symbol = table.decode[bits >>> 17];
      var used = table.lengths[symbol];
      bits = (bits << used) >>> 0;
      extra -= used;
      if (extra < 0) {
        bits = (bits | (u16At(inPos) << (-extra))) >>> 0;
        inPos += 2;
        extra += 16;
      }
      if (symbol < 256) {
        out[outPos++] = symbol;
        continue;
      }
      symbol -= 256;
      var matchLength = symbol & 15;
      var offsetBits = symbol >> 4;
      if (matchLength === 15) {
        matchLength = byteAt(inPos);
        inPos += 1;
        if (matchLength === 255) {
          matchLength = u16At(inPos);
          inPos += 2;
          if (matchLength === 0) {
            matchLength = (u16At(inPos) | (u16At(inPos + 2) << 16)) >>> 0;
            inPos += 4;
          }
          if (matchLength < 15) {
            log.debug("Leaving decompressXpressHuffman().");
            throw new Error("krb5: an XPRESS Huffman match length that " +
                "underflows");
          }
          matchLength -= 15;
        }
        matchLength += 15;
      }
      matchLength += 3;
      var offset = (1 << offsetBits) +
          (offsetBits ? (bits >>> (32 - offsetBits)) : 0);
      if (offsetBits) {
        bits = (bits << offsetBits) >>> 0;
        extra -= offsetBits;
        if (extra < 0) {
          bits = (bits | (u16At(inPos) << (-extra))) >>> 0;
          inPos += 2;
          extra += 16;
        }
      }
      if (offset > outPos || outPos + matchLength > outputSize) {
        log.debug("Leaving decompressXpressHuffman().");
        throw new Error("krb5: an XPRESS Huffman match of " + matchLength +
            " byte(s) at distance " + offset + " from output position " +
            outPos + " reaches outside the " + outputSize + "-byte output");
      }
      for (var c = 0; c < matchLength; c++) {
        out[outPos] = out[outPos - offset];
        outPos++;
      }
    }
  }
  log.debug("Leaving decompressXpressHuffman(). " + outPos + " byte(s).");
  return out;
}

// KERB_VALIDATION_INFO, [MS-PAC] section 2.5 — the one that is NDR, and the one
// that carries every group membership. The field order below is the IDL's,
// verbatim; NDR is positional, so one field out of order silently misreads
// everything after it while keeping every value in range.
function parseLogonInfo(bytes) {
  log.debug("Entering parseLogonInfo().");
  var r = ndr.createReader(bytes);
  var headers = ndr.readTypeMarshallingHeaders(r);
  if (!r.pointer()) {
    log.debug("Leaving parseLogonInfo().");
    throw new Error("krb5: the logon information's top-level pointer is NULL " +
        "— there is a " +
      "KERB_VALIDATION_INFO buffer with no KERB_VALIDATION_INFO in it");
  }

  // --- the fixed part, in IDL order ---
  var info = {
    ndr: headers,
    logonTime: ndr.readFileTime(r),
    logoffTime: ndr.readFileTime(r),
    kickOffTime: ndr.readFileTime(r),
    passwordLastSet: ndr.readFileTime(r),
    passwordCanChange: ndr.readFileTime(r),
    passwordMustChange: ndr.readFileTime(r)
  };
  var effectiveName = ndr.readUnicodeStringHeader(r);
  var fullName = ndr.readUnicodeStringHeader(r);
  var logonScript = ndr.readUnicodeStringHeader(r);
  var profilePath = ndr.readUnicodeStringHeader(r);
  var homeDirectory = ndr.readUnicodeStringHeader(r);
  var homeDirectoryDrive = ndr.readUnicodeStringHeader(r);
  info.logonCount = r.u16();
  info.badPasswordCount = r.u16();
  info.userId = r.u32();
  info.primaryGroupId = r.u32();
  var groupCount = r.u32();
  var groupIdsPresent = r.pointer();
  info.userFlags = r.u32();
  info.userSessionKey = r.bytes(16);          // USER_SESSION_KEY: two 8-byte blocks
  var logonServer = ndr.readUnicodeStringHeader(r);
  var logonDomainName = ndr.readUnicodeStringHeader(r);
  var logonDomainIdPresent = r.pointer();
  info.reserved1 = [r.u32(), r.u32()];
  info.userAccountControl = r.u32();
  info.subAuthStatus = r.u32();
  info.lastSuccessfulILogon = ndr.readFileTime(r);
  info.lastFailedILogon = ndr.readFileTime(r);
  info.failedILogonCount = r.u32();
  info.reserved3 = r.u32();
  var sidCount = r.u32();
  var extraSidsPresent = r.pointer();
  var resourceGroupDomainSidPresent = r.pointer();
  var resourceGroupCount = r.u32();
  var resourceGroupIdsPresent = r.pointer();

  // --- the deferred part, in the order the pointers appeared (rule 4) ---
  ndr.readUnicodeStringValue(r, effectiveName);
  ndr.readUnicodeStringValue(r, fullName);
  ndr.readUnicodeStringValue(r, logonScript);
  ndr.readUnicodeStringValue(r, profilePath);
  ndr.readUnicodeStringValue(r, homeDirectory);
  ndr.readUnicodeStringValue(r, homeDirectoryDrive);

  info.groups = [];
  if (groupIdsPresent) {
    var declared = r.arrayCount("group membership(s)");
    if (declared !== groupCount) {
      log.debug("Leaving parseLogonInfo().");
      throw new Error("krb5: GroupCount is " + groupCount + " but the " +
          "array's own conformant count " +
        "is " + declared);
    }
    for (var g = 0; g < declared; g++) {
      var rid = r.u32();
      var attrs = r.u32();
      info.groups.push({
        relativeId: rid,
        attributes: attrs,
        attributeNames: groupAttributeNames(attrs),
        name: ridName(rid)
      });
    }
  } else if (groupCount !== 0) {
    log.debug("Leaving parseLogonInfo().");
    throw new Error("krb5: GroupCount is " + groupCount + " but the GroupIds " +
        "pointer is NULL");
  }

  ndr.readUnicodeStringValue(r, logonServer);
  ndr.readUnicodeStringValue(r, logonDomainName);
  info.logonDomainId = logonDomainIdPresent ? ndr.readConformantSid(r) : null;

  // ExtraSids: an array of KERB_SID_AND_ATTRIBUTES, whose SID pointers are all
  // deferred past the END of the array — every element's fixed part first, then
  // every referent. Reading each SID as the loop reaches it is right for one
  // element and wrong for two, which is a bug that passes its first test.
  info.extraSids = [];
  if (extraSidsPresent) {
    var declaredSids = r.arrayCount("extra SID(s)");
    if (declaredSids !== sidCount) {
      log.debug("Leaving parseLogonInfo().");
      throw new Error("krb5: SidCount is " + sidCount + " but the ExtraSids " +
          "array's own conformant " +
        "count is " + declaredSids);
    }
    var pending = [];
    for (var s = 0; s < declaredSids; s++) {
      var present = r.pointer();
      var sidAttrs = r.u32();
      pending.push({ present: present, attributes: sidAttrs });
    }
    pending.forEach(function (p) {
      var sid = p.present ? ndr.readConformantSid(r) : null;
      info.extraSids.push({
        sid: sid,
        text: sid ? sid.text : null,
        name: sid ? sidName(sid.text) : null,
        attributes: p.attributes,
        attributeNames: groupAttributeNames(p.attributes)
      });
    });
  } else if (sidCount !== 0) {
    log.debug("Leaving parseLogonInfo().");
    throw new Error("krb5: SidCount is " + sidCount + " but the ExtraSids " +
        "pointer is NULL");
  }

  info.resourceGroupDomainSid = resourceGroupDomainSidPresent ?
      ndr.readConformantSid(r) : null;
  info.resourceGroups = [];
  if (resourceGroupIdsPresent) {
    var declaredRes = r.arrayCount("resource group(s)");
    if (declaredRes !== resourceGroupCount) {
      log.debug("Leaving parseLogonInfo().");
      throw new Error("krb5: ResourceGroupCount is " + resourceGroupCount +
          " but the array's own " +
        "conformant count is " + declaredRes);
    }
    for (var rg = 0; rg < declaredRes; rg++) {
      var rrid = r.u32();
      var rattrs = r.u32();
      info.resourceGroups.push({
        relativeId: rrid,
        attributes: rattrs,
        attributeNames: groupAttributeNames(rattrs),
        name: ridName(rrid)
      });
    }
  }

  info.effectiveName = effectiveName.value;
  info.fullName = fullName.value;
  info.logonScript = logonScript.value;
  info.profilePath = profilePath.value;
  info.homeDirectory = homeDirectory.value;
  info.homeDirectoryDrive = homeDirectoryDrive.value;
  info.logonServer = logonServer.value;
  info.logonDomainName = logonDomainName.value;
  info.userFlagNames = flagNames(USER_FLAGS, info.userFlags);
  info.userAccountControlNames = flagNames(USER_ACCOUNT_CONTROL,
      info.userAccountControl);
  info.userSid = info.logonDomainId ? ndr.sidWithRid(info.logonDomainId,
      info.userId) : null;
  info.primaryGroupSid = info.logonDomainId
    ? ndr.sidWithRid(info.logonDomainId, info.primaryGroupId) : null;

  // Set BEFORE the notes are computed, because one of them reads it. (It read
  // `undefined` for as long as these two lines were the other way round, so
  // that check silently never fired — the kind of defect a passing round-trip
  // cannot see.)
  info.bytesUnread = r.remaining;
  info.notes = consistencyNotes(info, sidCount, resourceGroupCount);
  log.debug("Leaving parseLogonInfo().");
  return info;
}

// The internal cross-checks [MS-PAC] states as MUSTs. Each of these is a real
// misconfiguration or a forgery tell, and none of them stops the structure
// parsing — which is exactly why they have to be checked deliberately.
function consistencyNotes(info, sidCount, resourceGroupCount) {
  log.debug("Entering consistencyNotes().");
  var notes = [];
  if (sidCount !== 0 && !(info.userFlags & USER_FLAG_EXTRA_SIDS)) {
    notes.push("SidCount is " + sidCount + " but the EXTRA_SIDS flag (D) is " +
        "not set. [MS-PAC] " +
      "section 2.5 requires it, and a service that trusts the flag will " +
          "ignore these SIDs.");
  }
  if ((info.userFlags & USER_FLAG_EXTRA_SIDS) && sidCount === 0) {
    notes.push("The EXTRA_SIDS flag (D) is set but SidCount is 0.");
  }
  if (resourceGroupCount !== 0 &&
      !(info.userFlags & USER_FLAG_RESOURCE_GROUPS)) {
    notes.push("ResourceGroupCount is " + resourceGroupCount + " but the " +
        "RESOURCE_GROUPS flag (H) " +
      "is not set, which [MS-PAC] section 2.5 requires.");
  }
  if (info.userId === 0) {
    notes.push("UserId is 0, which means the account's own SID is the FIRST " +
        "SID in ExtraSids " +
      "rather than LogonDomainId + UserId.");
  }
  var ntlmOnly = info.userFlagNames.filter(function (n) { return n.indexOf("NTLM only") !== -1; });
  if (ntlmOnly.length) {
    notes.push("UserFlags carries " + ntlmOnly.join(", ") + ". [MS-PAC] " +
        "section 2.5 says these are " +
      "set only by NTLM and MUST be zero for Kerberos.");
  }
  if (info.reserved1[0] !== 0 || info.reserved1[1] !== 0) {
    notes.push("Reserved1 is not zero (" + info.reserved1.join(", ") +
        "); [MS-PAC] requires zero.");
  }
  var unknownUac = unknownFlagBits(USER_ACCOUNT_CONTROL,
      info.userAccountControl);
  if (unknownUac) {
    notes.push("UserAccountControl has undefined bits set (0x" +
        unknownUac.toString(16) + ").");
  }
  // NDR pads the marshalled object to a multiple of 8, so up to 7 trailing
  // bytes are expected and reporting them would be noise on every well-formed
  // PAC. More than that means a field was misread and the reader stopped early
  // — which is worth saying loudly, because every value above it will still
  // look reasonable.
  if (info.bytesUnread > 7) {
    notes.push(info.bytesUnread + " bytes of this buffer were not consumed. " +
        "NDR pads to a multiple " +
      "of 8, so at most 7 are expected; this many means a field was read at " +
          "the wrong offset and " +
      "the values above may be wrong even though they look plausible.");
  }
  log.debug("Leaving consistencyNotes().");
  return notes;
}

// ---------------------------------------------------------------------------
// Signature verification.
//
// Each signature is checked SEPARATELY and reported by name, because they answer
// different questions and a caller almost never has all the keys. A service has its
// own key and can confirm the server signature; only a KDC can confirm the other
// three. Collapsing that into one boolean is how "the PAC is valid" comes to mean
// nothing in particular.
// ---------------------------------------------------------------------------

// Reproduces the PAC as it stood when a given signature was computed, by
// zeroing the signature fields that were still zero at that moment (see the
// file header — the order the four are generated in is what makes this
// well-defined).
function pacWithSignaturesZeroed(pac, types) {
  log.debug("Entering pacWithSignaturesZeroed().");
  var copy = new Uint8Array(pac.raw);
  types.forEach(function (t) {
    pac.buffers.forEach(function (b) {
      if (b.type !== t || !b.bytes || !b.parsed) {
        return;
      }
      var from = b.offset + b.parsed.signatureOffsetInBuffer;
      for (var i = 0; i < b.parsed.signature.length; i++) copy[from + i] = 0;
    });
  });
  log.debug("Leaving pacWithSignaturesZeroed().");
  return copy;
}

// WHAT EACH SIGNATURE COVERS, in one place.
//
// This table is the only statement of it, deliberately: the four signatures are
// the part of [MS-PAC] most easily got subtly wrong, and there are two callers
// — one with named keys (a service, a KDC) and one with a POOL of keys it can
// try (the decoder page, which has whatever the reader pasted in). Writing the
// covered bytes out twice is how the two come to disagree, and the disagreement
// would show up as a PAC that verifies on one screen and not on another.
function signatureCoverage(pac, ticketBytes) {
  log.debug("Entering signatureCoverage().");
  var serverEntry = bufferOfType(pac, TYPE.SERVER_CHECKSUM);
  log.debug("Leaving signatureCoverage().");
  return [
    {
      type: TYPE.SERVER_CHECKSUM,
      role: "service key",
      data: pacWithSignaturesZeroed(pac, [TYPE.SERVER_CHECKSUM,
          TYPE.KDC_CHECKSUM]),
      note: "This is the one a SERVICE can check for itself — it is signed " +
          "with the service's " +
        "own long-term key."
    },
    {
      type: TYPE.KDC_CHECKSUM,
      role: "krbtgt key",
      data: serverEntry && serverEntry.parsed ? serverEntry.parsed.signature :
          null,
      missing: "there is no server signature for it to counter-sign",
      note: "A counter-signature over the server signature ALONE, not over " +
          "the PAC. Only a KDC " +
        "holds the key, which is what makes it the one a forged PAC cannot " +
            "produce."
    },
    {
      type: TYPE.EXTENDED_KDC_CHECKSUM,
      role: "krbtgt key",
      data: pacWithSignaturesZeroed(pac,
        [TYPE.SERVER_CHECKSUM, TYPE.KDC_CHECKSUM, TYPE.EXTENDED_KDC_CHECKSUM]),
      note: "Added by the CVE-2022-37967 hardening: the KDC signature covers " +
          "only the server " +
        "signature, so this one covers the whole PAC."
    },
    {
      type: TYPE.TICKET_CHECKSUM,
      role: "krbtgt key",
      data: ticketBytes ? prim.toBytes(ticketBytes) : null,
      missing: "the EncTicketPart it covers was not supplied. It is the DER " +
          "of the ticket with " +
        "this PAC's ad-data replaced by a single zero byte, so it binds the " +
            "PAC to ONE ticket",
      note: "Binds this PAC to one specific ticket, so a PAC cannot be " +
          "lifted out of one and " +
        "dropped into another."
    }
  ];
}

// keys: { serverKey, kdcKey, ticketBytes }, each optional. A key is { etype,
// key } as elsewhere in this codec; `ticketBytes` is the DER of the
// EncTicketPart with the PAC's ad-data replaced by one zero byte, which only
// the caller can produce because only the caller has the ticket.
async function verifySignatures(pac, keys) {
  log.debug("Entering verifySignatures().");
  var opts = keys || {};
  var results = [];

  async function check(type, keyLabel, key, data, note) {
    log.debug("Entering check().");
    var entry = bufferOfType(pac, type);
    if (!entry) {
      log.debug("Leaving check().");
      return;
    }
    var out = {
      type: type,
      name: bufferTypeName(type),
      signatureType: entry.parsed ? entry.parsed.signatureType : null,
      signatureTypeName: entry.parsed ? entry.parsed.signatureTypeName : null,
      verified: null,
      note: note || null
    };
    if (!entry.parsed) {
      out.note = "This signature buffer did not parse" + (entry.error ? ": " +
          entry.error : ".");
      results.push(out);
      log.debug("Leaving check().");
      return;
    }
    if (!key) {
      out.note = "Not checked: no " + keyLabel + " was supplied. " + (note ||
          "");
      results.push(out);
      log.debug("Leaving check().");
      return;
    }
    if (data === null) {
      out.note = "Not checked: " + (note || "the data it covers was not " +
          "available here.");
      results.push(out);
      log.debug("Leaving check().");
      return;
    }
    try {
      var profile = profileForSignatureType(entry.parsed.signatureType);
      if (profile.id !== key.etype) {
        // A mismatch here is a real diagnostic: it is what a KDC and a service
        // disagreeing about etypes looks like from the outside.
        out.verified = false;
        out.note = "This signature is " + entry.parsed.signatureTypeName +
            ", which belongs to etype " +
          profile.id + ", but the " + keyLabel + " supplied is etype " +
              key.etype + ". " +
          "The key cannot verify this signature whatever its value.";
        results.push(out);
        log.debug("Leaving check().");
        return;
      }
      out.verified = await profile.verifyChecksum(key.key,
          KERB_NON_KERB_CKSUM_SALT, data,
        entry.parsed.signature);
      out.note = out.verified
        ? "Verified with the " + keyLabel + "."
        : "DOES NOT verify with the " + keyLabel + " supplied. Either the " +
            "key is wrong or the PAC " +
          "has been altered since it was signed.";
    } catch (e) {
      out.verified = false;
      out.note = "Could not be checked: " + e.message;
    }
    results.push(out);
    log.debug("Leaving check().");
  }

  var coverage = signatureCoverage(pac, opts.ticketBytes);
  for (var i = 0; i < coverage.length; i++) {
    var c = coverage[i];
    await check(c.type, c.role, c.role === "service key" ? opts.serverKey :
        opts.kdcKey,
      c.data, c.data === null ? c.missing : c.note);
  }

  log.debug("Leaving verifySignatures(). " + results.length + " signature(s) " +
      "considered.");
  return results;
}

// The same four checks against a POOL of keys — what the decoder page has,
// since a reader pastes in whatever keys they happen to hold and cannot be
// expected to label them. Reports WHICH key verified, by label, because
// "verified" without saying with what answers a different question: on a TGT
// the service key and the krbtgt key are the SAME key, and noticing that is
// often the point.
//
// THE IMPORTANT DISTINCTION, and it took a cried-wolf failure to get right: a
// signature that no key in the pool verifies is `verified: null` — NOT `false`.
// On a service ticket the reader has the service's key and no possible way to
// have the krbtgt key, so "the KDC signature does not verify" would appear on
// every correct PAC anyone ever pastes in, and a warning that fires always is a
// warning nobody reads. `false` is reserved for a key whose ROLE the caller has
// asserted — pass `opts.serverKey` when you know a key IS the service's (the
// decoder page does: the key that decrypted the ticket is the service's key by
// definition), and a failure against that is a real finding.
async function verifySignaturesWithAnyKey(pac, keys, opts) {
  log.debug("Entering verifySignaturesWithAnyKey(). keys=" + (keys ||
      []).length);
  var pool = keys || [];
  var options = opts || {};
  var asserted = {
    "service key": options.serverKey || null,
    "krbtgt key": options.kdcKey || null
  };
  var results = [];
  var coverage = signatureCoverage(pac, options.ticketBytes);

  for (var i = 0; i < coverage.length; i++) {
    var c = coverage[i];
    var entry = bufferOfType(pac, c.type);
    if (!entry) continue;
    var out = {
      type: c.type,
      name: bufferTypeName(c.type),
      role: c.role,
      signatureType: entry.parsed ? entry.parsed.signatureType : null,
      signatureTypeName: entry.parsed ? entry.parsed.signatureTypeName : null,
      verified: null,
      verifiedBy: null,
      note: c.note
    };
    if (!entry.parsed) {
      out.note = "This signature buffer did not parse" + (entry.error ? ": " +
          entry.error : ".");
      results.push(out);
      continue;
    }
    if (c.data === null) {
      out.note = "Not checked: " + c.missing + ".";
      results.push(out);
      continue;
    }
    var profile = null;
    try {
      profile = profileForSignatureType(entry.parsed.signatureType);
    } catch (e) {
      out.verified = false;
      out.note = e.message;
      results.push(out);
      continue;
    }
    // A key whose role the caller has asserted gives a definite verdict.
    // Otherwise only keys of the signature's own etype are even worth trying.
    var claimed = asserted[c.role];
    var eligible = claimed ? [claimed] :
        pool.filter(function (k) { return k.etype === profile.id; });
    out.roleAsserted = !!claimed;

    if (claimed && claimed.etype !== profile.id) {
      // Worth stating plainly: it is what a KDC and a service disagreeing about
      // encryption types looks like from the outside.
      out.verified = false;
      out.note = "This signature is " + entry.parsed.signatureTypeName +
          ", which belongs to " +
        "etype " + profile.id + ", but the " + c.role + " supplied is etype " +
            claimed.etype +
        ". That key cannot verify this signature whatever its value.";
      results.push(out);
      continue;
    }
    if (!eligible.length) {
      out.note = "Not checked: this is " + entry.parsed.signatureTypeName +
          ", which needs an " +
        "etype " + profile.id + " key, and none was supplied. " + c.note;
      results.push(out);
      continue;
    }
    for (var j = 0; j < eligible.length; j++) {
      var ok = await profile.verifyChecksum(eligible[j].key,
          KERB_NON_KERB_CKSUM_SALT, c.data,
        entry.parsed.signature);
      if (ok) {
        out.verified = true;
        out.verifiedBy = eligible[j].label || "a supplied key";
        out.note = "Verified with " + out.verifiedBy + ", acting as the " +
            c.role + ". " + c.note;
        break;
      }
    }
    if (out.verified === null) {
      if (claimed) {
        out.verified = false;
        out.note = "DOES NOT verify with the " + c.role + " supplied. Either " +
            "that key is wrong or " +
          "this PAC has been altered since it was signed. " + c.note;
      } else {
        // Left as UNKNOWN on purpose — see this function's header.
        out.note = "Not confirmed: none of the " + eligible.length +
            " etype " + profile.id +
          " key(s) supplied verifies it, and none of them was identified as " +
              "the " + c.role +
          ". On a service ticket you would not hold the krbtgt key at all, " +
              "so this is the " +
          "expected result rather than a sign of tampering. " + c.note;
      }
    }
    results.push(out);
  }

  log.debug("Leaving verifySignaturesWithAnyKey(). " + results.length +
      " considered.");
  return results;
}

// ---------------------------------------------------------------------------
// Building — for the mock KDC, and for tests that need a PAC with one field wrong.
// ---------------------------------------------------------------------------

function encodeLogonInfo(spec) {
  log.debug("Entering encodeLogonInfo().");
  var w = ndr.createWriter();
  var lengthOffset = ndr.writeTypeMarshallingHeaders(w);
  var bodyStart = w.offset;
  w.pointer(true);                                  // the top-level referent

  var groups = spec.groups || [];
  var extraSids = spec.extraSids || [];
  var resourceGroups = spec.resourceGroups || [];

  w.fileTime(spec.logonTime || null);
  w.fileTime(spec.logoffTime === undefined ? "never" : spec.logoffTime);
  w.fileTime(spec.kickOffTime === undefined ? "never" : spec.kickOffTime);
  w.fileTime(spec.passwordLastSet || null);
  w.fileTime(spec.passwordCanChange || null);
  w.fileTime(spec.passwordMustChange === undefined ? "never" :
      spec.passwordMustChange);

  ndr.writeUnicodeStringHeader(w, spec.effectiveName);
  ndr.writeUnicodeStringHeader(w, spec.fullName === undefined ? null :
      spec.fullName);
  ndr.writeUnicodeStringHeader(w, spec.logonScript === undefined ? null :
      spec.logonScript);
  ndr.writeUnicodeStringHeader(w, spec.profilePath === undefined ? null :
      spec.profilePath);
  ndr.writeUnicodeStringHeader(w, spec.homeDirectory === undefined ? null :
      spec.homeDirectory);
  ndr.writeUnicodeStringHeader(w, spec.homeDirectoryDrive === undefined ?
      null : spec.homeDirectoryDrive);

  w.u16(spec.logonCount || 0);
  w.u16(spec.badPasswordCount || 0);
  w.u32(spec.userId);
  w.u32(spec.primaryGroupId);
  w.u32(groups.length);
  w.pointer(groups.length > 0);

  // The D and H flags are DERIVED rather than taken from the caller, because
  // [MS-PAC] makes them a MUST and a builder that lets them drift emits a PAC
  // whose extra SIDs a real service ignores — which then reads as a KDC that
  // did not add them. `userFlags` in the spec is for tests that need exactly
  // that defect.
  var derivedFlags = (extraSids.length ? USER_FLAG_EXTRA_SIDS : 0) |
    (resourceGroups.length ? USER_FLAG_RESOURCE_GROUPS : 0);
  w.u32(spec.userFlags === undefined ? derivedFlags : spec.userFlags);

  w.bytes(spec.userSessionKey || new Uint8Array(16));   // zero for Kerberos
  ndr.writeUnicodeStringHeader(w, spec.logonServer === undefined ? null :
      spec.logonServer);
  ndr.writeUnicodeStringHeader(w, spec.logonDomainName === undefined ? null :
      spec.logonDomainName);
  w.pointer(!!spec.logonDomainId);
  w.u32(0); w.u32(0);                                  // Reserved1[2]
  w.u32(spec.userAccountControl === undefined ? 0x00000010 :
      spec.userAccountControl);
  w.u32(spec.subAuthStatus || 0);
  w.fileTime(spec.lastSuccessfulILogon === undefined ? null :
      spec.lastSuccessfulILogon);
  w.fileTime(spec.lastFailedILogon === undefined ? null :
      spec.lastFailedILogon);
  w.u32(spec.failedILogonCount || 0);
  w.u32(0);                                            // Reserved3
  w.u32(extraSids.length);
  w.pointer(extraSids.length > 0);
  w.pointer(!!spec.resourceGroupDomainSid);
  w.u32(resourceGroups.length);
  w.pointer(resourceGroups.length > 0);

  // The deferred half, in the order the pointers were written.
  ndr.writeUnicodeStringValue(w, spec.effectiveName);
  ndr.writeUnicodeStringValue(w, spec.fullName === undefined ? null :
      spec.fullName);
  ndr.writeUnicodeStringValue(w, spec.logonScript === undefined ? null :
      spec.logonScript);
  ndr.writeUnicodeStringValue(w, spec.profilePath === undefined ? null :
      spec.profilePath);
  ndr.writeUnicodeStringValue(w, spec.homeDirectory === undefined ? null :
      spec.homeDirectory);
  ndr.writeUnicodeStringValue(w, spec.homeDirectoryDrive === undefined ? null :
      spec.homeDirectoryDrive);

  if (groups.length) {
    w.u32(groups.length);
    groups.forEach(function (g) {
      w.u32(g.relativeId);
      w.u32(g.attributes === undefined ? 0x00000007 : g.attributes);
    });
  }
  ndr.writeUnicodeStringValue(w, spec.logonServer === undefined ? null :
      spec.logonServer);
  ndr.writeUnicodeStringValue(w, spec.logonDomainName === undefined ? null :
      spec.logonDomainName);
  if (spec.logonDomainId) ndr.writeConformantSid(w, spec.logonDomainId);

  if (extraSids.length) {
    w.u32(extraSids.length);
    extraSids.forEach(function (e) {
      w.pointer(true);
      w.u32(e.attributes === undefined ? 0x00000007 : e.attributes);
    });
    // All the referents AFTER all the fixed parts — rule 4.
    extraSids.forEach(function (e) { ndr.writeConformantSid(w, e.sid); });
  }
  if (spec.resourceGroupDomainSid) ndr.writeConformantSid(w,
      spec.resourceGroupDomainSid);
  if (resourceGroups.length) {
    w.u32(resourceGroups.length);
    resourceGroups.forEach(function (g) {
      w.u32(g.relativeId);
      w.u32(g.attributes === undefined ? 0x20000007 : g.attributes);
    });
  }

  // NDR pads the marshalled object to a multiple of 8, and ObjectBufferLength
  // counts everything after the private header.
  w.align(8);
  var built = w.patchU32(lengthOffset, w.offset - bodyStart).build();
  log.debug("Leaving encodeLogonInfo().");
  return built;
}

function encodeClientInfo(spec) {
  var w = ndr.createWriter();
  w.fileTime(spec.clientId || null);
  var name = spec.name || "";
  w.u16(name.length * 2);
  for (var i = 0; i < name.length; i++) w.u16(name.charCodeAt(i));
  return w.build();
}

function encodeUpnDnsInfo(spec) {
  log.debug("Entering encodeUpnDnsInfo().");
  var extended = spec.samName !== undefined || spec.sid !== undefined;
  var headerBytes = extended ? 20 : 12;
  var parts = [];
  var at = headerBytes;

  function place(text) {
    log.debug("Entering place().");
    if (text === null || text === undefined) {
      log.debug("Leaving place().");
      return { offset: 0, length: 0 };
    }
    var b = new Uint8Array(text.length * 2);
    for (var i = 0; i < text.length; i++) {
      b[i * 2] = text.charCodeAt(i) & 0xff;
      b[i * 2 + 1] = (text.charCodeAt(i) >>> 8) & 0xff;
    }
    var placed = { offset: at, length: b.length };
    parts.push(b);
    at += b.length;
    log.debug("Leaving place().");
    return placed;
  }

  var upn = place(spec.upn);
  var dns = place(spec.dnsDomainName);
  var sam = extended ? place(spec.samName) : { offset: 0, length: 0 };
  var sid = { offset: 0, length: 0 };
  if (extended && spec.sid) {
    var sw = ndr.createWriter();
    ndr.writeSid(sw, spec.sid);
    var sb = sw.build();
    sid = { offset: at, length: sb.length };
    parts.push(sb);
    at += sb.length;
  }

  var w = ndr.createWriter();
  w.u16(upn.length); w.u16(upn.offset);
  w.u16(dns.length); w.u16(dns.offset);
  w.u32((spec.constructedUpn ? UPN_DNS_FLAG_NO_UPN_ATTRIBUTE : 0) |
        (extended ? UPN_DNS_FLAG_EXTENDED : 0));
  if (extended) {
    w.u16(sam.length); w.u16(sam.offset);
    w.u16(sid.length); w.u16(sid.offset);
  }
  parts.forEach(function (p) { w.bytes(p); });
  log.debug("Leaving encodeUpnDnsInfo().");
  return w.build();
}

function encodeAttributesInfo(flags) {
  var w = ndr.createWriter();
  w.u32(2);            // FlagsLength, in BITS: two flags are defined
  w.u32(flags);
  return w.build();
}

function encodeRequestorSid(sid) {
  var w = ndr.createWriter();
  ndr.writeSid(w, sid);
  return w.build();
}

function encodeSignaturePlaceholder(signatureType, length, rodcIdentifier) {
  var w = ndr.createWriter();
  w.u32(signatureType < 0 ? signatureType + 0x100000000 : signatureType);
  w.zeros(length);
  if (rodcIdentifier !== undefined &&
      rodcIdentifier !== null) w.u16(rodcIdentifier);
  return w.build();
}

// Assembles a PACTYPE from a list of { type, bytes }, padding each buffer's
// START to the 8-byte boundary [MS-PAC] section 2.4 requires. Returns the bytes
// plus, for each buffer, where it landed — which is what the signing pass needs
// in order to overwrite signature fields in place.
function assemblePac(entries) {
  log.debug("Entering assemblePac().");
  var headerBytes = 8 + entries.length * 16;
  var offset = headerBytes + ((8 - (headerBytes % 8)) % 8);
  var placed = entries.map(function (e) {
    var b = prim.toBytes(e.bytes);
    var at = offset;
    offset += b.length;
    offset += (8 - (offset % 8)) % 8;
    return { type: e.type, bytes: b, offset: at };
  });

  var out = new Uint8Array(offset);
  var w = ndr.createWriter();
  w.u32(entries.length);
  w.u32(0);                                    // Version MUST be 0
  placed.forEach(function (p) {
    w.u32(p.type);
    w.u32(p.bytes.length);
    w.u64(p.offset, 0);
  });
  out.set(w.build(), 0);
  placed.forEach(function (p) { out.set(p.bytes, p.offset); });
  log.debug("Leaving assemblePac().");
  return { bytes: out, placed: placed };
}

// Builds a signed PAC.
//
// spec: { logonInfo, clientInfo, upnDns, clientClaims, attributes,
//         requestorSid, serverKey, kdcKey, ticketBytes,
//         includeTicketSignature, includeExtendedKdcSignature,
//         rodcIdentifier }
//
// `clientClaims` is encodeClaimsSet()'s spec, written uncompressed as type 13.
//
// The four signatures are filled in the order [MS-PAC] requires — ticket, extended
// KDC, server, KDC — because each covers bytes the later ones have not written yet.
// Doing them in any other order produces a PAC whose signatures do not verify, and
// the error a Windows service returns for that is indistinguishable from a wrong key.
async function buildPac(spec) {
  log.debug("Entering buildPac(). client=" + (spec.clientInfo &&
      spec.clientInfo.name));
  var serverProfile = kcrypto.etypeById(spec.serverKey.etype);
  var kdcProfile = kcrypto.etypeById(spec.kdcKey.etype);
  var serverSigType = serverProfile.checksumType;
  var kdcSigType = kdcProfile.checksumType;

  var entries = [{
    type: TYPE.LOGON_INFO,
    bytes: encodeLogonInfo(spec.logonInfo)
  }];
  entries.push({
    type: TYPE.CLIENT_INFO,
    bytes: encodeClientInfo(spec.clientInfo)
  });
  if (spec.upnDns) entries.push({
    type: TYPE.UPN_DNS_INFO,
    bytes: encodeUpnDnsInfo(spec.upnDns)
  });
  // PAC_CLIENT_CLAIMS_INFO, when the caller has claims to state. A caller with
  // none passes nothing and gets no buffer — never an empty set, which
  // [MS-ADTS]'s range(1, …) on ulClaimsArrayCount forbids.
  if (spec.clientClaims) entries.push({
    type: TYPE.CLIENT_CLAIMS,
    bytes: encodeClaimsSetMetadata(spec.clientClaims)
  });
  if (spec.attributes !== undefined) {
    entries.push({
      type: TYPE.ATTRIBUTES_INFO,
      bytes: encodeAttributesInfo(spec.attributes)
    });
  }
  if (spec.requestorSid) {
    entries.push({
      type: TYPE.REQUESTOR_SID,
      bytes: encodeRequestorSid(spec.requestorSid)
    });
  }
  if (spec.delegationInfo) {
    entries.push({
      type: TYPE.DELEGATION_INFO,
      bytes: encodeDelegationInfo(spec.delegationInfo)
    });
  }
  if (spec.includeTicketSignature) {
    entries.push({
      type: TYPE.TICKET_CHECKSUM,
      bytes: encodeSignaturePlaceholder(kdcSigType, kdcProfile.checksumBytes,
          spec.rodcIdentifier)
    });
  }
  if (spec.includeExtendedKdcSignature) {
    entries.push({
      type: TYPE.EXTENDED_KDC_CHECKSUM,
      bytes: encodeSignaturePlaceholder(kdcSigType, kdcProfile.checksumBytes,
          spec.rodcIdentifier)
    });
  }
  entries.push({
    type: TYPE.SERVER_CHECKSUM,
    bytes: encodeSignaturePlaceholder(serverSigType,
        serverProfile.checksumBytes)
  });
  entries.push({
    type: TYPE.KDC_CHECKSUM,
    bytes: encodeSignaturePlaceholder(kdcSigType, kdcProfile.checksumBytes,
        spec.rodcIdentifier)
  });

  var bytes = await signAssembled(assemblePac(entries), spec);
  log.debug("Leaving buildPac(). bytes=" + bytes.length + ", buffers=" +
      entries.length);
  return bytes;
}

// The signing pass, shared by buildPac() and resignPac().
//
// Separate because a KDC signs a PAC in two situations and they must not
// diverge: when it MINTS one, and when it re-signs one somebody else minted — a
// cross-realm referral arriving at the target realm, or a renewal, both of
// which [MS-PAC] requires to recompute all four. Two copies of this order would
// eventually disagree, and a PAC signed in the wrong order fails in a way
// indistinguishable from a wrong key.
async function signAssembled(assembled, spec) {
  log.debug("Entering signAssembled().");
  var serverProfile = kcrypto.etypeById(spec.serverKey.etype);
  var kdcProfile = kcrypto.etypeById(spec.kdcKey.etype);
  var bytes = assembled.bytes;

  function signatureAt(type) {
    for (var i = 0; i < assembled.placed.length; i++) {
      if (assembled.placed[i].type === type) {
        return assembled.placed[i].offset + 4;
      }
    }
    return -1;
  }
  function has(type) { return signatureAt(type) >= 0; }
  function write(type, sig) {
    var at = signatureAt(type);
    if (at < 0) {
      throw new Error("krb5: no " + bufferTypeName(type) + " buffer to write " +
          "into");
    }
    bytes.set(sig, at);
  }

  // 1. The ticket signature, over bytes the caller supplies (only it has the
  //    ticket).
  if (has(TYPE.TICKET_CHECKSUM)) {
    if (!spec.ticketBytes) {
      log.debug("Leaving signAssembled().");
      throw new Error("krb5: a ticket signature was asked for but no " +
          "EncTicketPart bytes were " +
        "supplied to compute it over. It covers the DER of the ticket with " +
            "this PAC's ad-data " +
        "replaced by a single zero byte, which the caller has to build.");
    }
    write(TYPE.TICKET_CHECKSUM, await kdcProfile.checksum(spec.kdcKey.key,
      KERB_NON_KERB_CKSUM_SALT, prim.toBytes(spec.ticketBytes)));
  }

  // 2. The extended KDC signature, over the whole PAC while the server and KDC
  //    signatures are still zero — which they are, at this point in the order.
  if (has(TYPE.EXTENDED_KDC_CHECKSUM)) {
    write(TYPE.EXTENDED_KDC_CHECKSUM, await kdcProfile.checksum(spec.kdcKey.key,
      KERB_NON_KERB_CKSUM_SALT, bytes));
  }

  // 3. The server signature, over the whole PAC — the extended signature is now
  //    populated and is covered; the server and KDC fields are still zero.
  var serverSig = await serverProfile.checksum(spec.serverKey.key,
      KERB_NON_KERB_CKSUM_SALT, bytes);
  write(TYPE.SERVER_CHECKSUM, serverSig);

  // 4. The KDC signature, over the server signature's bytes alone.
  write(TYPE.KDC_CHECKSUM, await kdcProfile.checksum(spec.kdcKey.key,
    KERB_NON_KERB_CKSUM_SALT, serverSig));

  log.debug("Leaving signAssembled().");
  return bytes;
}

// Re-signs a PAC somebody else minted, keeping its contents BYTE-IDENTICAL.
//
// This is what the target realm's KDC does to a cross-realm referral: the
// client's account lives in the other realm and this KDC has no copy of it, so
// it cannot rebuild the PAC — it carries the existing buffers across and
// re-signs them with its own keys, because the signatures it arrived with were
// made with a key the service being issued to does not have.
//
// Rebuilding instead of re-signing would look identical in a mock where both
// realms happen to share one principal table, and would be wrong everywhere
// else. It would also quietly discard anything the issuing realm put in that a
// rebuild does not know how to state — device info, and claims the target
// realm has no register for — which is the sort of loss nobody notices.
//
// **THE CLAIMS BUFFERS ARE CARRIED AND RE-SIGNED, BYTE FOR BYTE** (types 13
// and 15), compressed or not: like every other content buffer they keep their
// bytes and are covered by the new signatures. This comment used to read as
// though a re-sign dropped them; it never did, and the claims codec added on
// 2026-10-06 (iya-sts #493) is what lets a reader now SEE that they arrived.
// A caller that must change the client's claims on the way — a KDC adding a
// service's own claims to a service ticket — passes `clientClaims` (a
// encodeClaimsSet() spec, written uncompressed in place of the old buffer) or
// `clientClaims: null` (the buffer is removed). Absent, the buffer is carried
// as it came. The device claims are always carried as they came.
//
// **SID filtering is NOT applied here.** Windows strips SIDs belonging to
// domains the trust is not authorized to assert, and that control is what stops
// the other realm claiming membership of groups in this one. Saying so is
// better than a silence that reads as "there is nothing to do here".
async function resignPac(pacBytes, spec) {
  log.debug("Entering resignPac().");
  var existing = parsePac(pacBytes);
  var kdcProfile = kcrypto.etypeById(spec.kdcKey.etype);
  var serverProfile = kcrypto.etypeById(spec.serverKey.etype);

  // Every buffer that is not a signature, in its original order and bytes.
  var entries = existing.buffers
    .filter(function (b) { return b.bytes && !isSignatureBuffer(b.type); })
    .map(function (b) { return { type: b.type, bytes: b.bytes }; });
  if (!entries.length) {
    throw new Error("krb5: this PAC has no content buffers to re-sign");
  }

  // An S4U2proxy hop ADDS or REPLACES the delegation information while carrying
  // everything else across, so re-signing has to be able to do that rather than
  // only preserve.
  if (Object.prototype.hasOwnProperty.call(spec, "clientClaims")) {
    var at = -1;
    entries.forEach(function (e, i) {
      if (e.type === TYPE.CLIENT_CLAIMS && at < 0) at = i;
    });
    entries = entries.filter(function (e) {
      return e.type !== TYPE.CLIENT_CLAIMS;
    });
    if (spec.clientClaims) {
      var claimsEntry = {
        type: TYPE.CLIENT_CLAIMS,
        bytes: encodeClaimsSetMetadata(spec.clientClaims)
      };
      // Where the old one was, or after the UPN_DNS_INFO where there was none
      // — the place buildPac() puts it.
      if (at < 0) {
        entries.forEach(function (e, i) {
          if (e.type === TYPE.UPN_DNS_INFO) at = i + 1;
        });
      }
      if (at < 0 || at > entries.length) at = entries.length;
      entries.splice(at, 0, claimsEntry);
    }
  }

  if (spec.delegationInfo) {
    entries = entries.filter(function (e) { return e.type !== TYPE.DELEGATION_INFO; });
    entries.push({
      type: TYPE.DELEGATION_INFO,
      bytes: encodeDelegationInfo(spec.delegationInfo)
    });
  }

  if (spec.includeTicketSignature) {
    entries.push({
      type: TYPE.TICKET_CHECKSUM,
      bytes: encodeSignaturePlaceholder(kdcProfile.checksumType,
          kdcProfile.checksumBytes,
        spec.rodcIdentifier)
    });
  }
  if (spec.includeExtendedKdcSignature) {
    entries.push({
      type: TYPE.EXTENDED_KDC_CHECKSUM,
      bytes: encodeSignaturePlaceholder(kdcProfile.checksumType,
          kdcProfile.checksumBytes,
        spec.rodcIdentifier)
    });
  }
  entries.push({
    type: TYPE.SERVER_CHECKSUM,
    bytes: encodeSignaturePlaceholder(serverProfile.checksumType,
        serverProfile.checksumBytes)
  });
  entries.push({
    type: TYPE.KDC_CHECKSUM,
    bytes: encodeSignaturePlaceholder(kdcProfile.checksumType,
        kdcProfile.checksumBytes,
      spec.rodcIdentifier)
  });

  var bytes = await signAssembled(assemblePac(entries), spec);
  log.debug("Leaving resignPac(). bytes=" + bytes.length + ", carried " +
      entries.length +
    " buffer(s) across.");
  return bytes;
}

// Wraps a PAC as an EncTicketPart authorization-data element: ad-type 128
// inside ad-type 1. The nesting is not optional — see the file header.
function wrapPacAsAuthorizationData(pacBytes) {
  return [{
    type: AD_TYPE.IF_RELEVANT,
    data: msgs.encAuthorizationData([{
      type: AD_TYPE.WIN2K_PAC,
      data: pacBytes
    }])
  }];
}

module.exports = {
  AD_TYPE: AD_TYPE,
  AD_TYPE_NAMES: AD_TYPE_NAMES,
  adTypeName: adTypeName,
  TYPE: TYPE,
  TYPE_NAMES: TYPE_NAMES,
  bufferTypeName: bufferTypeName,
  SIGNATURE_TYPE: SIGNATURE_TYPE,
  SIGNATURE_TYPES_IN_GENERATION_ORDER: SIGNATURE_TYPES_IN_GENERATION_ORDER,
  isSignatureBuffer: isSignatureBuffer,
  signatureTypeName: signatureTypeName,
  profileForSignatureType: profileForSignatureType,
  KERB_NON_KERB_CKSUM_SALT: KERB_NON_KERB_CKSUM_SALT,
  GROUP_ATTRIBUTES: GROUP_ATTRIBUTES,
  GROUP_ATTRIBUTES_OUTSIDE_MS_PAC: GROUP_ATTRIBUTES_OUTSIDE_MS_PAC,
  groupAttributeNames: groupAttributeNames,
  USER_ACCOUNT_CONTROL: USER_ACCOUNT_CONTROL,
  USER_FLAGS: USER_FLAGS,
  USER_FLAG_EXTRA_SIDS: USER_FLAG_EXTRA_SIDS,
  USER_FLAG_RESOURCE_GROUPS: USER_FLAG_RESOURCE_GROUPS,
  PAC_ATTRIBUTE_FLAGS: PAC_ATTRIBUTE_FLAGS,
  WELL_KNOWN_RIDS: WELL_KNOWN_RIDS,
  WELL_KNOWN_SIDS: WELL_KNOWN_SIDS,
  ridName: ridName,
  sidName: sidName,
  flagNames: flagNames,
  findPacs: findPacs,
  parsePac: parsePac,
  bufferOfType: bufferOfType,
  countOfType: countOfType,
  verifySignatures: verifySignatures,
  verifySignaturesWithAnyKey: verifySignaturesWithAnyKey,
  signatureCoverage: signatureCoverage,
  pacWithSignaturesZeroed: pacWithSignaturesZeroed,
  buildPac: buildPac,
  resignPac: resignPac,
  signAssembled: signAssembled,
  assemblePac: assemblePac,
  encodeLogonInfo: encodeLogonInfo,
  encodeClientInfo: encodeClientInfo,
  encodeUpnDnsInfo: encodeUpnDnsInfo,
  encodeAttributesInfo: encodeAttributesInfo,
  encodeRequestorSid: encodeRequestorSid,
  encodeDelegationInfo: encodeDelegationInfo,
  CLAIM_TYPE: CLAIM_TYPE,
  CLAIMS_SOURCE_TYPE: CLAIMS_SOURCE_TYPE,
  CLAIMS_COMPRESSION: CLAIMS_COMPRESSION,
  CLAIMS_MAX_SIZE: CLAIMS_MAX_SIZE,
  claimTypeName: claimTypeName,
  encodeClaimsSet: encodeClaimsSet,
  encodeClaimsSetMetadata: encodeClaimsSetMetadata,
  parseClaimsSet: parseClaimsSet,
  parseClaimsInfo: parseClaimsInfo,
  claimsOf: claimsOf,
  decompressXpressHuffman: decompressXpressHuffman,
  parseDelegationInfo: parseDelegationInfo,
  wrapPacAsAuthorizationData: wrapPacAsAuthorizationData
};
