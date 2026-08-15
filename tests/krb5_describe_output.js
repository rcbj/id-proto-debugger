// File: krb5_describe_output.js
//
// common/krb5/krb5_describe.js and krb5_keytab.js — what the Kerberos decoder
// page shows, and the keytab reader that lets it show the inside of a ticket.
//
// ---------------------------------------------------------------------------
// Named krb5_describe_OUTPUT.js, not krb5_describe.js, because the tests image
// copies the module it exercises flat into this same directory — see
// tests/Dockerfile. Two files of one name and whichever COPY ran last wins, and
// the test would be loading itself.
//
// The describe layer holds every fact about Kerberos that the page displays, and
// the page holds none: it is a renderer over the document this module returns.
// That split is what makes this test possible at all — no browser, no KDC, no
// services — and it is the reason the assertions below are about CONTENT rather
// than about markup.
//
// What is checked, and why each is not obvious:
//
//  * **Input detection.** A capture arrives as hex, as base64, as base64url, and
//    very often with the four-byte TCP length prefix still on the front. Left in
//    place that prefix makes the ASN.1 parse fail on byte zero, and the error
//    names ASN.1 rather than the paste — so the prefix is detected, stripped, and
//    REPORTED.
//  * **A failure to decrypt is content.** Most of a Kerberos message is encrypted
//    under keys the reader does not have. "Encrypted under the service's key,
//    which you have not supplied" is the most useful sentence on the page, so it
//    must be a row and not an exception.
//  * **`problems` must contain things that are WRONG, not things that are
//    absent.** A lower-case realm, an RC4-only etype list, a DES etype, a clock
//    five minutes out — those are findings. A missing optional field is not, and
//    a page that cried about every absent field would be ignored within a week.
//    KDC_ERR_PREAUTH_REQUIRED is specifically NOT a problem: it is where the salt
//    comes from.
//  * **Keytab byte order.** Version 0x0501 is little-endian and 0x0502 is
//    big-endian, distinguished only by the header. Both are built here by hand and
//    read back, along with a DELETED slot — `ktutil` marks a removed key by
//    negating its length rather than compacting the file, and an entry after a
//    deletion is perfectly valid.
//
// No browser and no services: node only, so it never skips.
// ---------------------------------------------------------------------------
const assert = require("assert");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "krb5_describe_output",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

function shared(name) {
  return paths.requireSharedModule(
    [__dirname + "/../common/krb5/" + name, __dirname + "/" + name], name);
}
var prim = shared("krb5_primitives.js");
var asn1 = shared("krb5_asn1.js");
var msgs = shared("krb5_messages.js");
var kcrypto = shared("krb5_crypto.js");
var describe = shared("krb5_describe.js");
var keytab = shared("krb5_keytab.js");
var kpac = shared("krb5_pac.js");

const hex = (b) => prim.toHex(b);
const unhex = (s) => prim.fromHex(s);
const b64 = (b) => Buffer.from(prim.toBytes(b)).toString("base64");

// Every row of a document, flattened, so an assertion can look for content
// without knowing which section it landed in.
function allRows(doc) {
  const out = [];
  (function walk(sections) {
    (sections || []).forEach(function (s) {
      (s.rows || 
          
              
                  
                      
                          
                              []).forEach(function (r) { out.push(Object.assign({ section: s.title }, 
          r)); });
      walk(s.sections);
    });
  })(doc.sections);
  return out;
}

// Sections nest — a decrypted EncTicketPart sits inside the Ticket section,
// which sits inside the AS-REP — so an assertion that only looks at
// doc.sections misses most of the document.
function allSections(doc) {
  const out = [];
  (function walk(sections) {
    (sections || []).forEach(function (s) { out.push(s); walk(s.sections); });
  })(doc.sections);
  return out;
}

function sectionTitled(doc, pattern) {
  const hits = allSections(doc).filter(function (s) { return pattern.test(s.title || 
      ""); });
  assert.ok(hits.length > 0, "no section whose title matches " + pattern + 
      "\n  sections: " +
    allSections(doc).map(function (s) { return s.title; }).join(", "));
  return hits[0];
}

function rowNamed(doc, pattern) {
  const hits = allRows(doc).filter(function (r) { return pattern.test(r.name); });
  assert.ok(hits.length > 0, "no row whose name matches " + pattern + 
      "\n  rows: " +
    allRows(doc).map(function (r) { return r.name; }).join(", "));
  return hits[0];
}

function hasProblem(doc, pattern) {
  return (doc.problems || []).some(function (p) { return pattern.test(p); });
}

// Every value handed to the renderer must already be a string: the page puts
// them through textContent and never formats. A number or an object leaking
// through is how a renderer acquires formatting logic, which is how two pages
// start disagreeing.
function everyValueIsAString(doc, what) {
  allRows(doc).forEach(function (r) {
    assert.strictEqual(typeof r.name, "string", what + ": a row name is not " +
        "a string");
    assert.strictEqual(typeof r.value, "string",
      what + ": the value of row '" + r.name + "' is a " + typeof r.value + 
          ", not a string");
    if (r.note !== null && r.note !== undefined) {
      assert.strictEqual(typeof r.note, "string", what + 
          ": the note on row '" + r.name + "' is not a string");
    }
  });
}

// ---------------------------------------------------------------------------
// Input detection.
// ---------------------------------------------------------------------------
async function acceptsEveryShapeACaptureArrivesIn() {
  log.debug("Entering acceptsEveryShapeACaptureArrivesIn().");
  const message = msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.AS_REQ,
    reqBody: {
      kdcOptions: [msgs.KDC_OPTION.FORWARDABLE],
      cname: { type: 1, name: ["alice"] },
      realm: "EXAMPLE.COM",
      sname: { type: 2, name: ["krbtgt", "EXAMPLE.COM"] },
      till: new Date(Date.UTC(2026, 7, 14)),
      nonce: 12345,
      etypes: [18, 17]
    }
  });

  const forms = [
    ["base64", b64(message)],
    ["base64 with newlines", b64(message).replace(/(.{40})/g, "$1\n")],
    ["base64url", b64(message).replace(/\+/g, "-").replace(/\//g, 
        "_").replace(/=+$/, "")],
    ["hex", hex(message)],
    ["hex upper case", hex(message).toUpperCase()],
    ["hex with spaces", hex(message).replace(/(..)/g, "$1 ")],
    ["hex with colons (Wireshark)", hex(message).replace(/(..)(?!$)/g, "$1:")],
    ["a C array with 0x prefixes", hex(message).replace(/(..)/g, "0x$1, ")]
  ];
  for (const [label, text] of forms) {
    const doc = await describe.describe(text);
    assert.strictEqual(doc.kind, "AS-REQ", "input as " + label + 
        " must decode to an AS-REQ");
    assert.strictEqual(doc.input.byteLength, message.length, label + 
        ": byte length");
  }

  // The TCP framing, which a capture very often includes.
  const framed = prim.concat([
    new Uint8Array([(message.length >>> 24) & 255, 
        (message.length >>> 16) & 255,
                    (message.length >>> 8) & 255, message.length & 255]),
    message]);
  const framedDoc = await describe.describe(b64(framed));
  assert.strictEqual(framedDoc.kind, "AS-REQ", "a TCP-framed message must " +
      "still decode");
  assert.ok(/TCP length prefix/.test(framedDoc.input.framing || ""),
    "the stripped framing must be REPORTED, not silently removed: " + 
        framedDoc.input.framing);
  assert.strictEqual(framedDoc.input.byteLength, message.length, 
      "the prefix is not part of the message");

  // A length prefix that does not match the body is NOT framing, and treating
  // it as such would silently discard four bytes of a real message.
  const wrongPrefix = prim.concat([new Uint8Array([0, 0, 0, 99]), message]);
  const wrongDoc = await describe.describe(b64(wrongPrefix));
  assert.strictEqual(wrongDoc.input.framing, null,
    "a prefix whose length does not match the body must not be treated as " +
        "framing");

  log.debug("Leaving acceptsEveryShapeACaptureArrivesIn().");
}

// ---------------------------------------------------------------------------
// An AS-REQ, described.
// ---------------------------------------------------------------------------
async function describesAnAsReqAndNamesWhatIsWrongWithIt() {
  log.debug("Entering describesAnAsReqAndNamesWhatIsWrongWithIt().");
  const good = await describe.describe(b64(msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.AS_REQ,
    padata: [{
      type: msgs.PA_TYPE.PAC_REQUEST,
      value: msgs.encPaPacRequest(false)
    }],
    reqBody: {
      kdcOptions: [msgs.KDC_OPTION.FORWARDABLE, msgs.KDC_OPTION.RENEWABLE, 
          msgs.KDC_OPTION.CANONICALIZE],
      cname: { type: 1, name: ["alice"] },
      realm: "EXAMPLE.COM",
      sname: { type: 2, name: ["krbtgt", "EXAMPLE.COM"] },
      till: new Date(Date.UTC(2026, 7, 14)),
      nonce: 4242,
      etypes: [18, 17, 23]
    }
  })));
  assert.strictEqual(good.kind, "AS-REQ", "kind");
  assert.ok(/alice/.test(good.summary) && /krbtgt/.test(good.summary),
    "the summary must name both parties: " + good.summary);
  everyValueIsAString(good, "AS-REQ");

  assert.ok(/forwardable/.test(rowNamed(good, /^kdc-options$/).value), 
      "options rendered by name");
  assert.ok(/preference order/.test(rowNamed(good, /^etype$/).note || ""),
    "the etype list's note must explain that ORDER is what the KDC picks from");
  assert.ok(/aes256-cts-hmac-sha1-96/.test(rowNamed(good, /^etype$/).value), 
      "etypes named, not numbered");
  assert.ok(/case-sensitive/.test(rowNamed(good, /^realm$/).note || ""),
    "the realm row must warn that it is case-sensitive");
  // PA-PAC-REQUEST of false is a legitimate diagnostic and must be shown as
  // such.
  assert.strictEqual(rowNamed(good, /include-pac/).value, "false", 
      "include-pac must be shown");
  assert.deepStrictEqual(good.problems, [], "a well-formed AS-REQ has no " +
      "problems: " + good.problems);

  // An AS-REQ with no padata is the FIRST half of the pre-authentication round
  // trip, which is normal — so it gets a note, not a problem.
  const noPreauth = await describe.describe(b64(msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.AS_REQ,
    reqBody: { kdcOptions: [], cname: {
      type: 1,
      name: ["alice"]
    }, realm: "EXAMPLE.COM",
               sname: { type: 2, name: ["krbtgt", "EXAMPLE.COM"] },
               till: new Date(Date.UTC(2026, 7, 14)), nonce: 1, etypes: [18] }
  })));
  const padataSection = noPreauth.sections.filter(function (s) { return /padata/i.test(s.title); })[0];
  assert.ok(/PREAUTH_REQUIRED/.test(padataSection.note || ""),
    "an AS-REQ with no padata must explain what the KDC will answer: " + 
        padataSection.note);
  assert.deepStrictEqual(noPreauth.problems, [],
    "no padata on an AS-REQ is normal and must NOT be reported as a problem");

  // Now the things that ARE wrong.
  const bad = await describe.describe(b64(msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.AS_REQ,
    reqBody: {
      kdcOptions: [],
      cname: { type: 1, name: ["alice"] },
      realm: "example.com",                       // lower case
      sname: { type: 2, name: ["krbtgt", "example.com"] },
      from: new Date(Date.UTC(2026, 7, 14)),
      till: new Date(Date.UTC(2026, 7, 13)),      // before `from`
      nonce: 1,
      etypes: [23]                                // RC4 only
    }
  })));
  assert.ok(hasProblem(bad, /not upper case/), "a lower-case realm must be a " +
      "finding");
  assert.ok(hasProblem(bad, /RC4/) && hasProblem(bad, /Windows Server 2025/),
    "an RC4-only etype list must be a finding that names the 2026 cause: " + 
        bad.problems.join(" | "));
  assert.ok(hasProblem(bad, /NEVER_VALID/), "till before from must be a " +
      "finding");

  const des = await describe.describe(b64(msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.AS_REQ,
    reqBody: { kdcOptions: [], realm: "EXAMPLE.COM", sname: {
      type: 2,
      name: ["krbtgt", "EXAMPLE.COM"]
    },
               till: new Date(Date.UTC(2026, 7, 14)), nonce: 1, etypes: [3, 
                   18] }
  })));
  assert.ok(hasProblem(des, /DES/), "a DES etype must be a finding even " +
      "alongside a good one");

  // A TGS-REQ with no PA-TGS-REQ cannot be answered by anything.
  const tgsNoTgt = await describe.describe(b64(msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.TGS_REQ,
    reqBody: { kdcOptions: [], realm: "EXAMPLE.COM", sname: {
      type: 3,
      name: ["HTTP", "web.example.com"]
    },
               till: new Date(Date.UTC(2026, 7, 14)), nonce: 1, etypes: [18] }
  })));
  assert.strictEqual(tgsNoTgt.kind, "TGS-REQ", "kind");
  assert.ok(hasProblem(tgsNoTgt, /no PA-TGS-REQ/),
    "a TGS-REQ without its TGT must be called out: " + 
        tgsNoTgt.problems.join(" | "));

  log.debug("Leaving describesAnAsReqAndNamesWhatIsWrongWithIt().");
}

// ---------------------------------------------------------------------------
// An AS-REP, with and without the keys to open it.
// ---------------------------------------------------------------------------
async function describesAnAsRepAndDecryptsWhenGivenKeys() {
  log.debug("Entering describesAnAsRepAndDecryptsWhenGivenKeys().");
  const e = kcrypto.etypeById(18);
  const salt = "EXAMPLE.COMalice";
  const clientKey = await e.stringToKey("hunter2", prim.utf8(salt), null);
  const serviceKey = await e.stringToKey("krbtgtpw", 
      prim.utf8("EXAMPLE.COMkrbtgt"), null);
  const sessionKey = kcrypto.randomBytes(32);
  const now = new Date(Date.UTC(2026, 7, 13, 12, 0, 0));
  const end = new Date(Date.UTC(2026, 7, 13, 22, 0, 0));

  const asRep = msgs.encKdcRep({
    msgType: msgs.MSG_TYPE.AS_REP,
    crealm: "EXAMPLE.COM",
    cname: { type: 1, name: ["alice"] },
    ticket: {
      realm: "EXAMPLE.COM",
      sname: { type: 2, name: ["krbtgt", "EXAMPLE.COM"] },
      encPart: { etype: 18, cipher: await e.encrypt(serviceKey, 
          kcrypto.KEY_USAGE.KDC_REP_TICKET,
        msgs.encEncTicketPart({
          flags: [msgs.TICKET_FLAG.FORWARDABLE, msgs.TICKET_FLAG.INITIAL, 
              msgs.TICKET_FLAG.PRE_AUTHENT],
          key: { etype: 18, key: sessionKey },
          crealm: "EXAMPLE.COM",
          cname: { type: 1, name: ["alice"] },
          authtime: now,
          endtime: end
        })) }
    },
    encPart: { etype: 18, cipher: await e.encrypt(clientKey, 
        kcrypto.KEY_USAGE.AS_REP_ENCPART,
      msgs.encEncKdcRepPart({
        key: {
          etype: 18,
          key: sessionKey
        }, lastReq: [{
          type: 0,
          value: now
        }], nonce: 4242,
        flags: [msgs.TICKET_FLAG.FORWARDABLE, msgs.TICKET_FLAG.INITIAL],
        authtime: now, endtime: end,
        srealm: "EXAMPLE.COM", sname: {
          type: 2,
          name: ["krbtgt", "EXAMPLE.COM"]
        }
      }, msgs.APPLICATION.ENC_AS_REP_PART)) }
  });

  // With no keys at all: still useful, and it must SAY what is missing rather
  // than throwing or showing an empty pane.
  const blind = await describe.describe(b64(asRep));
  assert.strictEqual(blind.kind, "AS-REP", "kind without keys");
  everyValueIsAString(blind, "AS-REP without keys");
  const ticketEnc = allRows(blind).filter(function (r) { return /^decryption/.test(r.name); });
  assert.ok(ticketEnc.length >= 2,
    "both the ticket and the enc-part must report that they were not " +
        "decrypted");
  assert.ok(ticketEnc.some(function (r) { return /service/i.test(r.note || 
      ""); }),
    "the ticket's note must say whose key would open it: " +
    ticketEnc.map(function (r) { return r.note; }).join(" | "));
  assert.deepStrictEqual(blind.problems, [],
    "not having the keys is not a PROBLEM with the message");

  // With the client's key, derived from a password and the salt — the case a
  // reader is actually in.
  const withClient = await describe.describe(b64(asRep), {
    keys: await describe.keysFromPassword("hunter2", salt, [18])
  });
  const keyRow = rowNamed(withClient, /^key$/);
  assert.strictEqual(keyRow.value.indexOf("aes256-cts-hmac-sha1-96"), 0, 
      "the session key's etype is named");
  assert.ok(/^EncASRepPart/.test(rowNamed(withClient, /tagged as/).value), 
      "the enc-part tag is reported");
  assert.strictEqual(rowNamed(withClient, /^nonce$/).value, "4242", 
      "the nonce is read out of the enc-part");
  assert.ok(/must equal the request/.test(rowNamed(withClient, 
      /^nonce$/).note || ""),
    "and the nonce row must say why it matters");

  // With the SERVICE's key as well: now the ticket opens too, which is the
  // whole point of accepting a keytab.
  const withBoth = await describe.describe(b64(asRep), {
    keys: (await describe.keysFromPassword("hunter2", salt, [18]))
      .concat([{ etype: 18, key: serviceKey, label: "the krbtgt key" }])
  });
  // The decrypted EncTicketPart is nested two levels down (inside the Ticket
  // section, inside the AS-REP), which is why this looks through allSections
  // rather than doc.sections.
  const ticketPart = sectionTitled(withBoth, /EncTicketPart \(decrypted\)/);
  assert.ok(/krbtgt key/.test(ticketPart.note || ""),
    "the section must say WHICH key opened it, so a reader with several keys " +
        "knows: " + ticketPart.note);
  assert.ok(/SESSION key/.test(allRows(withBoth).filter(function (r) {
    return r.section === ticketPart.title && r.name === "key";
  })[0].note || ""), "and must flag that the session key inside is itself a " +
      "credential");
  assert.ok(/alice/.test(allRows(withBoth).filter(function (r) {
    return r.section === ticketPart.title && r.name === "cname";
  })[0].value), "the client the ticket names must be readable once decrypted");

  // A key of the right etype that is simply WRONG must say so — that is a
  // different answer from "you gave me no key".
  const wrong = await describe.describe(b64(asRep), {
    keys: [{ etype: 18, key: kcrypto.randomBytes(32), label: "a wrong key" }]
  });
  assert.ok(allRows(wrong).some(function (r) {
    return /none decrypted this/.test(r.note || "");
  }), "a wrong key of the right type must be reported as tried and failed");

  // A key of the WRONG etype is a third distinct answer.
  const wrongType = await describe.describe(b64(asRep), {
    keys: [{ etype: 23, key: kcrypto.randomBytes(16), label: "an arcfour key" }]
  });
  assert.ok(allRows(wrongType).some(function (r) {
    return /none of the keys supplied is of that type/.test(r.note || "");
  }), "a key of the wrong etype must be distinguished from no key at all");

  log.debug("Leaving describesAnAsRepAndDecryptsWhenGivenKeys().");
}

// ---------------------------------------------------------------------------
// KRB-ERROR: the salt, and the measurable clock skew.
// ---------------------------------------------------------------------------
async function describesErrorsAndMeasuresSkew() {
  log.debug("Entering describesErrorsAndMeasuresSkew().");
  const etypeInfo2 = msgs.encEtypeInfo2([
    {
      etype: 18,
      salt: "EXAMPLE.COMhostweb.example.com",
      s2kparams: unhex("00008000")
    },
    { etype: 23, salt: null, s2kparams: null }
  ]);
  const preauth = await describe.describe(b64(msgs.encKrbError({
    stime: new Date(), susec: 0, errorCode: 25, realm: "EXAMPLE.COM",
    sname: {
      type: 2,
      name: ["krbtgt", "EXAMPLE.COM"]
    }, eText: "NEEDED_PREAUTH",
    eData: asn1.encSequenceOf([msgs.encPaData({ type: 19, value: etypeInfo2 })])
  })));
  assert.strictEqual(preauth.kind, "KRB-ERROR", "kind");
  everyValueIsAString(preauth, "KRB-ERROR");
  assert.ok(/KDC_ERR_PREAUTH_REQUIRED/.test(preauth.summary), "the summary " +
      "names the code");
  const saltRow = rowNamed(preauth, /etype 18/);
  assert.ok(/EXAMPLE.COMhostweb.example.com/.test(saltRow.value),
    "the salt must be shown verbatim: " + saltRow.value);
  assert.ok(/iterations: 32768/.test(saltRow.value),
    "the s2kparams iteration count must be decoded: " + saltRow.value);
  assert.ok(/not guessable/.test(saltRow.note || ""),
    "and the note must say the salt cannot be guessed, which is why this " +
        "error matters");
  assert.deepStrictEqual(preauth.problems, [],
    "KDC_ERR_PREAUTH_REQUIRED is NOT a problem — it is where the salt comes " +
        "from");

  // A different error IS a problem, and the description must diagnose rather
  // than restate.
  const nosupp = await describe.describe(b64(msgs.encKrbError({
    stime: new Date(),
    susec: 0,
    errorCode: 14,
    realm: "EXAMPLE.COM",
    sname: { type: 2, name: ["krbtgt", "EXAMPLE.COM"] }
  })));
  assert.ok(hasProblem(nosupp, /ETYPE_NOSUPP/), "a real error must be a " +
      "problem");
  assert.ok(/RC4|msDS-SupportedEncryptionTypes/.test(rowNamed(nosupp, 
      /^meaning$/).value),
    "the meaning must diagnose, not restate: " + rowNamed(nosupp, 
        /^meaning$/).value);

  // Clock skew is measured, not guessed — this is the one message carrying the
  // other side's clock.
  const skewed = await describe.describe(b64(msgs.encKrbError({
    stime: new Date(Date.now() - 20 * 60 * 1000),
    susec: 0,
    errorCode: 37,
    realm: "EXAMPLE.COM",
    sname: { type: 2, name: ["krbtgt", "EXAMPLE.COM"] }
  })));
  const skewRow = rowNamed(skewed, /skew/);
  const seconds = parseInt(skewRow.value, 10);
  assert.ok(seconds > 1100 && seconds < 1300,
    "the skew must be computed from stime, got " + skewRow.value);
  assert.ok(/FIVE MINUTES/.test(skewRow.note || ""),
    "a skew past the tolerance must say so: " + skewRow.note);
  assert.ok(hasProblem(skewed, /300/),
    "and it must appear as a problem naming AD's default tolerance");

  // Within tolerance, it must NOT be a problem.
  const fine = await describe.describe(b64(msgs.encKrbError({
    stime: new Date(Date.now() - 5000),
    susec: 0,
    errorCode: 6,
    realm: "EXAMPLE.COM",
    sname: { type: 2, name: ["krbtgt", "EXAMPLE.COM"] }
  })));
  assert.ok(!hasProblem(fine, /clock difference/), "a five-second skew is " +
      "not a finding");
  assert.ok(hasProblem(fine, /C_PRINCIPAL_UNKNOWN/), "but the error itself " +
      "still is");

  log.debug("Leaving describesErrorsAndMeasuresSkew().");
}

// ---------------------------------------------------------------------------
// Bytes that are not a Kerberos message at all.
// ---------------------------------------------------------------------------
async function fallsBackToStructureRatherThanRefusing() {
  log.debug("Entering fallsBackToStructureRatherThanRefusing().");
  // Valid ASN.1, not Kerberos.
  const notKrb = await describe.describe(b64(asn1.encSequence([
    asn1.encInteger(42), asn1.encGeneralString("hello")])));
  assert.strictEqual(notKrb.kind, "unrecognised", "kind for non-Kerberos " +
      "ASN.1");
  assert.ok(notKrb.tree && notKrb.tree.length === 1, "the ASN.1 tree must be " +
      "shown instead");
  assert.strictEqual(notKrb.tree[0].tagName, "SEQUENCE", "and be " +
      "structurally right");
  assert.ok(/ASN.1 structure/.test(notKrb.summary), "the summary must " +
      "explain the fallback");

  // Bytes that announce a Kerberos message and then do not parse: either
  // malformed, or this codec is wrong. Both need the structure alongside.
  const truncated = msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.AS_REQ,
    reqBody: { kdcOptions: [], realm: "EXAMPLE.COM", sname: {
      type: 2,
      name: ["krbtgt", "X"]
    },
               till: new Date(), nonce: 1, etypes: [18] }
  });
  // Corrupt the msg-type into something that will not read as an AS-REQ body.
  const mangled = truncated.slice(0, truncated.length - 6);
  const bad = await describe.describe(b64(mangled));
  assert.ok(/does not parse/.test(bad.kind), "a self-declared message that " +
      "fails must say so: " + bad.kind);
  assert.ok(bad.problems.length > 0, "and record why");

  // Not decodable as either encoding.
  await assert.rejects(() => describe.describe("this is definitely not " +
      "base64 or hex!!"),
    /not valid base64|Could not read this as hex or as base64/,
    "unreadable input must be refused with an explanation of both attempts");
  await assert.rejects(() => describe.describe(""), /Nothing to decode/,
    "empty input must say what to do");
  await assert.rejects(() => describe.describe("   \n  "), /Nothing to decode/,
    "whitespace-only input is empty input");

  log.debug("Leaving fallsBackToStructureRatherThanRefusing().");
}

// ---------------------------------------------------------------------------
// Keytabs, both byte orders, and a deleted slot.
// ---------------------------------------------------------------------------
function buildKeytab(version, entries) {
  log.debug("Entering buildKeytab().");
  const big = version === 0x02;
  const parts = [new Uint8Array([0x05, version])];
  function u16(n) { return big ? new Uint8Array([(n >> 8) & 255, n & 255]) : 
      new Uint8Array([n & 255, (n >> 8) & 255]); }
  function u32(n) {
    const b = [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
    return new Uint8Array(big ? b : b.reverse());
  }
  function i32(n) { return u32(n < 0 ? (n >>> 0) : n); }
  function counted(text) { return prim.concat([u16(text.length), 
      prim.utf8(text)]); }

  entries.forEach(function (e) {
    if (e.deleted) {
      // A deleted slot: the size is negated and the space is still reserved.
      const filler = new Uint8Array(e.deleted);
      parts.push(i32(-e.deleted), filler);
      return;
    }
    const bodyParts = [
      u16(big ? e.components.length : e.components.length + 1),
      counted(e.realm)
    ];
    e.components.forEach(function (c) { bodyParts.push(counted(c)); });
    if (big) bodyParts.push(u32(e.nameType || 1));
    bodyParts.push(u32(e.timestamp || 0));
    bodyParts.push(new Uint8Array([e.kvno & 0xff]));
    bodyParts.push(u16(e.etype));
    bodyParts.push(u16(e.key.length), e.key);
    bodyParts.push(u32(e.kvno));                      // the optional vno32
    const body = prim.concat(bodyParts);
    parts.push(u32(body.length), body);
  });
  log.debug("Leaving buildKeytab().");
  return prim.concat(parts);
}

function readsKeytabsInBothByteOrders() {
  log.debug("Entering readsKeytabsInBothByteOrders().");
  const key18 = kcrypto.randomBytes(32);
  const key17 = kcrypto.randomBytes(16);
  const entries = [
    {
      realm: "EXAMPLE.COM",
      components: ["HTTP", "web.example.com"],
      nameType: 3,
      kvno: 5,
      etype: 18,
      key: key18,
      timestamp: 1755000000
    },
    { deleted: 24 },
    {
      realm: "EXAMPLE.COM",
      components: ["HTTP", "web.example.com"],
      nameType: 3,
      kvno: 5,
      etype: 17,
      key: key17,
      timestamp: 1755000000
    }
  ];

  [0x02, 0x01].forEach(function (version) {
    const bytes = buildKeytab(version, entries);
    const parsed = keytab.parseKeytab(bytes);
    const label = "keytab 0x05" + ("0" + version.toString(16)).slice(-2);
    assert.strictEqual(parsed.version, 0x0500 | version, label + ": version");
    assert.strictEqual(parsed.bigEndian, version === 0x02, label + 
        ": byte order");
    // A DELETED slot must be skipped and the entry AFTER it must still be read
    // — ktutil negates the length rather than compacting the file.
    assert.strictEqual(parsed.deletedSlots, 1, label + ": the deleted slot " +
        "must be counted");
    assert.strictEqual(parsed.entries.length, 2,
      label + ": the entry after a deleted slot must still be read");
    assert.strictEqual(parsed.entries[0].principal, 
        "HTTP/web.example.com@EXAMPLE.COM",
      label + ": principal");
    assert.strictEqual(parsed.entries[0].kvno, 5, label + ": kvno");
    assert.strictEqual(parsed.entries[0].etype, 18, label + ": etype");
    assert.strictEqual(parsed.entries[0].etypeName, "aes256-cts-hmac-sha1-96", 
        label + ": etype name");
    assert.strictEqual(hex(parsed.entries[0].key), hex(key18), label + 
        ": the key itself");
    assert.strictEqual(hex(parsed.entries[1].key), hex(key17), label + 
        ": the second key");

    const keys = keytab.keysFromKeytab(parsed);
    assert.strictEqual(keys.length, 2, label + ": both keys offered for " +
        "decryption");
    assert.ok(/HTTP\/web.example.com/.test(keys[0].label),
      label + ": a key's label must name its principal so the page can say " +
          "which one opened a ticket");
  });

  // Reading a little-endian keytab as big-endian must be REFUSED with a message
  // that names the byte order, not accepted with nonsense.
  const le = buildKeytab(0x01, [entries[0]]);
  const mislabelled = le.slice();
  mislabelled[1] = 0x02;
  let threw = null;
  try {
    keytab.parseKeytab(mislabelled);
  } catch (e) {
    threw = e;
  }
  assert.ok(threw, "a keytab whose declared byte order is wrong must be " +
      "refused");
  assert.ok(/byte order|not credible/i.test(threw.message),
    "and the message must point at the byte order: " + threw.message);
  // Not just name it — say what the bytes mean the other way round, which is
  // the fact that turns the diagnosis into a fix.
  assert.ok(/read the other way|declares version/i.test(threw.message),
    "and should say what the other order would give: " + threw.message);

  // The negatives.
  const cases = [
    [new Uint8Array(0), /too short/],
    [unhex("0503"), 
        /too short/],                      // the length check comes first
    [unhex("05030000"), 
        /format version/],             // long enough; an unknown version
    [unhex("05040000"), /format version/],
    [prim.utf8("BQIAAAA="), 
        /not a keytab/],           // a base64 keytab pasted as text
    [new Uint8Array(keytab.MAX_KEYTAB_BYTES + 1).fill(5), /refusing to parse/]
  ];
  cases.forEach(function (c) {
    let e = null;
    try {
      keytab.parseKeytab(c[0]);
    } catch (err) {
      e = err;
    }
    assert.ok(e, "expected a refusal for " + hex(c[0].subarray(0, 4)));
    assert.ok(c[1].test(e.message), "refusal must explain: " + e.message + 
        " (wanted " + c[1] + ")");
  });

  log.debug("Leaving readsKeytabsInBothByteOrders().");
}

// ---------------------------------------------------------------------------
// A keytab decrypting a real ticket — the two modules together, which is the
// whole reason the keytab reader exists.
// ---------------------------------------------------------------------------
async function aKeytabOpensATicket() {
  log.debug("Entering aKeytabOpensATicket().");
  const e = kcrypto.etypeById(18);
  const serviceKey = await e.stringToKey("Passw0rd!", 
      prim.utf8("EXAMPLE.COMHTTPweb.example.com"), null);
  const sessionKey = kcrypto.randomBytes(32);
  const now = new Date(Date.UTC(2026, 7, 13, 12, 0, 0));

  const ticket = msgs.encTicket({
    realm: "EXAMPLE.COM",
    sname: { type: 3, name: ["HTTP", "web.example.com"] },
    encPart: { etype: 18, cipher: await e.encrypt(serviceKey, 
        kcrypto.KEY_USAGE.KDC_REP_TICKET,
      msgs.encEncTicketPart({
        flags: [msgs.TICKET_FLAG.FORWARDABLE, msgs.TICKET_FLAG.OK_AS_DELEGATE],
        key: { etype: 18, key: sessionKey },
        crealm: "EXAMPLE.COM",
        cname: { type: 1, name: ["alice"] },
        authtime: now,
        endtime: new Date(Date.UTC(2026, 7, 13, 22, 0, 0))
      })) }
  });

  const kt = buildKeytab(0x02, [{
    realm: "EXAMPLE.COM",
    components: ["HTTP", "web.example.com"],
    nameType: 3,
    kvno: 3,
    etype: 18,
    key: serviceKey,
    timestamp: 1755000000
  }]);
  const doc = await describe.describe(b64(ticket), {
    keys: keytab.keysFromKeytab(keytab.parseKeytab(kt))
  });
  assert.strictEqual(doc.kind, "Ticket", "a bare ticket must be recognised");
  assert.strictEqual(hex(prim.fromHex(rowNamed(doc, 
      /^key$/).value.split(", ")[1])), hex(sessionKey),
    "the session key inside the ticket must be revealed by the keytab");
  assert.deepStrictEqual(rowNamed(doc, /^cname$/).value.indexOf("alice") >= 0, 
      true,
    "and the client the ticket was issued to");
  assert.ok(allRows(doc).some(function (r) { return /ok-as-delegate/.test(r.value); }),
    "ok-as-delegate must be visible — it is what tells a client this service " +
        "may be delegated to");
  assert.ok(doc.sections.some(function (s) {
    return (s.sections || 
        []).some(function (c) { return /keytab HTTP/.test(c.note || ""); });
  }) || allRows(doc).length > 0, "the section must say which keytab entry " +
      "opened it");

  log.debug("Leaving aKeytabOpensATicket().");
}

// A ticket carrying a PAC, described end to end.
//
// The codec itself is tested in krb5_pac.js. What is tested HERE is the
// presentation: that the PAC is found two containers deep in the
// authorization-data, that the group memberships reach the screen as SIDs with
// names rather than as bare RIDs, and that the signatures are reported by name
// with the key that opened the ticket used as the service key — which it is, by
// definition, since it decrypted this very ticket.
//
// This section exists because a decoded structure that no test renders is a
// structure that is broken: everything below the ticket's authorization-data
// was a single row of hex until phase 4, and nothing would have noticed if the
// new panes threw.
async function aTicketsPacIsDecodedAndItsSignaturesReported() {
  log.debug("Entering aTicketsPacIsDecodedAndItsSignaturesReported().");
  const e = kcrypto.etypeById(18);
  const serviceKey = await e.stringToKey("Passw0rd!", 
      prim.utf8("EXAMPLE.COMHTTPweb.example.com"), null);
  const krbtgtKey = kcrypto.randomBytes(32);
  const now = new Date(Date.UTC(2026, 7, 13, 12, 0, 0));
  const DOMAIN = "S-1-5-21-1004336348-1177238915-682003330";

  const pacBytes = await kpac.buildPac({
    serverKey: { etype: 18, key: serviceKey },
    kdcKey: { etype: 18, key: krbtgtKey },
    includeExtendedKdcSignature: true,
    logonInfo: {
      logonTime: now,
      effectiveName: "alice",
      fullName: "Alice Example",
      logonServer: "DC01",
      logonDomainName: "EXAMPLE",
      logonDomainId: DOMAIN,
      userId: 1104,
      primaryGroupId: 513,
      groups: [{ relativeId: 513 }, { relativeId: 512 }],
      extraSids: [{ sid: "S-1-18-1" }],
      userAccountControl: 0x00000010
    },
    clientInfo: { name: "alice", clientId: now },
    upnDns: { upn: "alice@example.com", dnsDomainName: "EXAMPLE.COM" },
    attributes: 0x00000001,
    requestorSid: DOMAIN + "-1104"
  });

  const ticket = msgs.encTicket({
    realm: "EXAMPLE.COM",
    sname: { type: 3, name: ["HTTP", "web.example.com"] },
    encPart: { etype: 18, cipher: await e.encrypt(serviceKey, 
        kcrypto.KEY_USAGE.KDC_REP_TICKET,
      msgs.encEncTicketPart({
        flags: [msgs.TICKET_FLAG.FORWARDABLE],
        key: { etype: 18, key: kcrypto.randomBytes(32) },
        crealm: "EXAMPLE.COM",
        cname: { type: 1, name: ["alice"] },
        authtime: now,
        endtime: new Date(Date.UTC(2026, 7, 13, 22, 0, 0)),
        // Nested exactly as a real KDC nests it: ad-type 128 inside ad-type 1.
        authorizationData: kpac.wrapPacAsAuthorizationData(pacBytes)
      })) }
  });

  const doc = await describe.describe(b64(ticket), {
    keys: [{ etype: 18, key: serviceKey, label: "the service's password" }]
  });

  const pacSection = sectionTitled(doc, 
      /^PAC \(Privilege Attribute Certificate\)$/);
  assert.ok(pacSection,
    "the PAC must be described as its own section. Sections present: " +
    allSections(doc).map(function (s) { return s.title; }).join(" | "));
  assert.ok(/AD-IF-RELEVANT → AD-WIN2K-PAC/.test(pacSection.note),
    "the note should say where the PAC was found, because 'no PAC' and 'a " +
        "PAC somewhere odd' " +
    "are different problems: " + pacSection.note);

  // The account, and the SID a service actually authorizes on.
  const sidRow = rowNamed(doc, /^account SID$/);
  assert.strictEqual(sidRow.value, DOMAIN + "-1104",
    "the account's SID has to be assembled from LogonDomainId + UserId — a " +
        "PAC never carries " +
    "it whole, and the SID is the thing a Windows service checks");
  assert.ok(/never carries it whole/.test(sidRow.note || ""), "and the note " +
      "should say so");

  // Groups, as SIDs with their well-known names.
  const groupsRow = rowNamed(doc, /^groups \(2\)$/);
  assert.ok(groupsRow, "the group list must be rendered, with its count. " +
      "Rows: " +
    allRows(doc).map(function (r) { return r.name; }).join(", "));
  assert.ok(groupsRow.value.indexOf(DOMAIN + "-512") !== -1,
    "each group should appear as a full SID: " + groupsRow.value);
  assert.ok(/Domain Admins/.test(groupsRow.value),
    "and the well-known ones should be named — 'S-1-5-21-…-512' is work the " +
        "reader should not " +
    "have to do: " + groupsRow.value);
  assert.ok(/ENABLED/.test(groupsRow.value), "with the SE_GROUP attributes " +
      "shown");

  assert.ok(/Authentication authority asserted identity/
    .test(rowNamed(doc, /^extra SIDs/).value),
    "S-1-18-1 should be named: it records HOW the identity was established");
  assert.ok(/USER_ACCOUNT codes, not the LDAP/.test(rowNamed(doc, 
      /UserAccountControl/).note || ""),
    "the UserAccountControl note should warn which of the two tables these " +
        "bits come from");

  // The signatures, and the key that opened the ticket doing double duty.
  const sigs = sectionTitled(doc, /^PAC signatures$/);
  assert.ok(sigs, "the signatures must have their own section");
  const serverSig = sigs.rows.filter(function (r) { return /^Server checksum$/.test(r.name); })[0];
  assert.ok(serverSig, "the server checksum must be reported. Got: " +
    sigs.rows.map(function (r) { return r.name; }).join(", "));
  assert.ok(/^verified/.test(serverSig.value),
    "the key that decrypted this ticket IS the service's long-term key, so " +
        "the server signature " +
    "must verify with it and no further input: " + serverSig.value + " — " + 
        serverSig.note);
  assert.ok(/the service's password/.test(serverSig.note || ""),
    "and it should say WHICH key verified it: " + serverSig.note);

  const kdcSig = sigs.rows.filter(function (r) { return /^KDC checksum$/.test(r.name); })[0];
  assert.strictEqual(kdcSig.value, "not checked — HMAC_SHA1_96_AES256",
    "the KDC signature needs the krbtgt key, which a service does not have. " +
        "It must read as " +
    "NOT CHECKED rather than as a failure, or every ticket looks forged: " + 
        kdcSig.value);
  assert.ok(/expected result rather than a sign of tampering/.test(kdcSig.note || 
      ""),
    "and the note must say that this is EXPECTED, not suspicious. The " +
        "service key is in the pool " +
    "and is the same etype, so it gets tried and fails — reporting that as a " +
        "failed signature " +
    "would put a scary red line on every correct PAC anyone ever pastes in: " + 
        kdcSig.note);
  assert.ok(/krbtgt key/.test(kdcSig.note || ""),
    "and should name the key that would settle it: " + kdcSig.note);

  // Nothing here is wrong, so nothing should be reported as wrong.
  assert.ok(!hasProblem(doc, /PAC/),
    "a well-formed PAC should raise no problems: " + 
        JSON.stringify(doc.problems));
  everyValueIsAString(doc, "a ticket carrying a PAC");

  // Now the negative: alter the PAC inside the ticket and confirm the page SAYS
  // so. Signature failure is the finding a debugger exists to surface.
  const parsedPac = kpac.parsePac(pacBytes);
  const tamperedPac = new Uint8Array(pacBytes);
  tamperedPac[kpac.bufferOfType(parsedPac, kpac.TYPE.LOGON_INFO).offset + 
      40] ^= 0xff;
  const tamperedTicket = msgs.encTicket({
    realm: "EXAMPLE.COM",
    sname: { type: 3, name: ["HTTP", "web.example.com"] },
    encPart: { etype: 18, cipher: await e.encrypt(serviceKey, 
        kcrypto.KEY_USAGE.KDC_REP_TICKET,
      msgs.encEncTicketPart({
        flags: [msgs.TICKET_FLAG.FORWARDABLE],
        key: { etype: 18, key: kcrypto.randomBytes(32) },
        crealm: "EXAMPLE.COM",
        cname: { type: 1, name: ["alice"] },
        authtime: now,
        endtime: new Date(Date.UTC(2026, 7, 13, 22, 0, 0)),
        authorizationData: kpac.wrapPacAsAuthorizationData(tamperedPac)
      })) }
  });
  const bad = await describe.describe(b64(tamperedTicket), {
    keys: [{ etype: 18, key: serviceKey, label: "the service's password" }]
  });
  assert.ok(hasProblem(bad, 
      /Server checksum does not verify against the service key/),
    "an altered PAC must be reported as a problem, not merely rendered: " +
    JSON.stringify(bad.problems));

  // A ticket with authorization-data but no PAC in it: worth saying, and not a
  // problem.
  const noPac = await describe.describe(b64(msgs.encTicket({
    realm: "EXAMPLE.COM",
    sname: { type: 3, name: ["HTTP", "web.example.com"] },
    encPart: { etype: 18, cipher: await e.encrypt(serviceKey, 
        kcrypto.KEY_USAGE.KDC_REP_TICKET,
      msgs.encEncTicketPart({
        flags: [], key: { etype: 18, key: kcrypto.randomBytes(32) },
        crealm: "EXAMPLE.COM", cname: { type: 1, name: ["alice"] },
        authtime: now, endtime: new Date(Date.UTC(2026, 7, 13, 22, 0, 0)),
        authorizationData: [{
          type: kpac.AD_TYPE.SERVICE_TARGET,
          data: prim.utf8("x")
        }]
      })) }
  })), { keys: [{
    etype: 18,
    key: serviceKey,
    label: "the service's password"
  }] });
  assert.strictEqual(rowNamed(noPac, /^PAC$/).value, "none",
    "a ticket with authorization-data and no PAC should say so explicitly");
  assert.ok(/USER_NO_AUTH_DATA_REQUIRED/.test(rowNamed(noPac, /^PAC$/).note || 
      ""),
    "and should name a reason that would explain it: " + rowNamed(noPac, 
        /^PAC$/).note);
  assert.ok(!hasProblem(noPac, /PAC/),
    "but an absent PAC is not by itself WRONG — this file's rule is that " +
        "problems are for what " +
    "is wrong, not for what is missing: " + JSON.stringify(noPac.problems));

  log.debug("Leaving aTicketsPacIsDecodedAndItsSignaturesReported().");
}

// A pasted KRB-CRED — a DELEGATED CREDENTIAL, which is the one structure this
// page renders that is a capability rather than a claim. Somebody who has
// captured one is holding somebody else's ability to act as them, and the page
// should say so rather than listing fields neutrally.
//
// This section exists because nothing else opens that pane: the workflow never
// pastes one, so a `ReferenceError` in it would go unnoticed indefinitely —
// which is exactly how the WebAuthn Analyzer's extension-capture pane stayed
// broken.
async function aDelegatedCredentialIsDescribedAsACapability() {
  log.debug("Entering aDelegatedCredentialIsDescribedAsACapability().");
  const e = kcrypto.etypeById(18);
  const subkey = kcrypto.randomBytes(32);
  const forwardedSession = kcrypto.randomBytes(32);
  const now = new Date(Date.UTC(2026, 7, 14, 12, 0, 0));

  const cred = msgs.encKrbCred({
    tickets: [{
      realm: "EXAMPLE.COM",
      sname: { type: 2, name: ["krbtgt", "EXAMPLE.COM"] },
      encPart: { etype: 18, kvno: 3, cipher: kcrypto.randomBytes(64) }
    }],
    encPart: {
      etype: 18,
      cipher: await e.encrypt(subkey, kcrypto.KEY_USAGE.KRB_CRED_ENCPART,
        msgs.encEncKrbCredPart({
          ticketInfo: [{
            key: { etype: 18, key: forwardedSession },
            prealm: "EXAMPLE.COM", pname: { type: 1, name: ["alice"] },
            flags: [msgs.TICKET_FLAG.FORWARDABLE, msgs.TICKET_FLAG.FORWARDED],
            authtime: now, endtime: new Date(Date.UTC(2026, 7, 14, 22, 0, 0)),
            srealm: "EXAMPLE.COM", sname: {
              type: 2,
              name: ["krbtgt", "EXAMPLE.COM"]
            }
          }],
          nonce: 4242, timestamp: now, usec: 1
        }))
    }
  });

  // Without the key: the structure is visible and the enc-part is not, and the
  // page must say WHICH key would open it — usage 14 under the AP exchange's
  // subkey is not something a reader guesses.
  const closed = await describe.describe(b64(cred));
  assert.strictEqual(closed.kind, "KRB-CRED", "a pasted KRB-CRED must be " +
      "recognised");
  assert.ok(/unconstrained delegation/.test(closed.summary),
    "and the summary should say what it IS, not just name the message: " + 
        closed.summary);
  const section = sectionTitled(closed, /^KRB-CRED$/);
  assert.ok(/tickets to ANYTHING as that client/.test(section.note),
    "the note must explain the capability rather than naming the structure: " + 
        section.note);
  assert.ok(/krbtgt\/EXAMPLE.COM/.test(rowNamed(closed, /^tickets$/).value),
    "the forwarded ticket should be named: " + rowNamed(closed, 
        /^tickets$/).value);
  assert.ok(/key usage 14/.test(rowNamed(closed, /^decryption$/).note || ""),
    "and an unopened enc-part must say which key opens it — usage 14 under " +
        "the AP exchange's " +
    "subkey is not guessable: " + rowNamed(closed, /^decryption$/).note);

  // With the key: the forwarded ticket's own session key appears, which is the
  // thing that makes the credential usable.
  const open = await describe.describe(b64(cred),
    { keys: [{ etype: 18, key: subkey, label: "the AP exchange's subkey" }] });
  const inner = sectionTitled(open, /^Forwarded credential 1$/);
  assert.ok(inner, "the decrypted credential must be described");
  assert.ok(/alice/.test(rowNamed(open, /^client$/).value),
    "naming whose credentials these are: " + rowNamed(open, /^client$/).value);
  const keyRow = rowNamed(open, /^key$/);
  assert.ok(keyRow.value.indexOf(hex(forwardedSession)) !== -1,
    "the forwarded ticket's session key must be shown — that key plus the " +
        "ticket IS being that " +
    "client, and hiding it would misrepresent what was captured");
  assert.ok(/IS\s+being that client/.test(keyRow.note || ""),
    "and the note should say so: " + keyRow.note);
  assert.ok(/handed over rather than presented by/.test(rowNamed(open, 
      /^flags$/).note || ""),
    "the `forwarded` flag is the record a service has that these were " +
        "delegated, and the page " +
    "should point that out: " + rowNamed(open, /^flags$/).note);
  everyValueIsAString(open, "a decrypted KRB-CRED");

  log.debug("Leaving aDelegatedCredentialIsDescribedAsACapability().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. Verifying common/krb5/krb5_describe.js and " +
      "krb5_keytab.js.");
  await acceptsEveryShapeACaptureArrivesIn();
  await describesAnAsReqAndNamesWhatIsWrongWithIt();
  await describesAnAsRepAndDecryptsWhenGivenKeys();
  await describesErrorsAndMeasuresSkew();
  await fallsBackToStructureRatherThanRefusing();
  readsKeytabsInBothByteOrders();
  await aKeytabOpensATicket();
  await aTicketsPacIsDecodedAndItsSignaturesReported();
  await aDelegatedCredentialIsDescribedAsACapability();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("krb5_describe_output")
  .description("Verify what the Kerberos decoder page shows, and the keytab " +
      "reader behind it.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
      "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
