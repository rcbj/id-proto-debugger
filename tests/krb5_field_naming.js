// File: krb5_field_naming.js
//
// ---------------------------------------------------------------------------
// The names the hex view puts on bytes — common/krb5/krb5_field_names.js — and
// the wiring that gets that view onto a page.
//
// NAMED krb5_field_naming.js RATHER THAN AFTER ITS MODULE, and it has to be:
// the tests image copies both this file and common/krb5/krb5_field_names.js
// FLAT into one directory, so identical basenames mean the last COPY wins and
// either the test silently passes in 30ms without running or everything that
// requires the module breaks. tests/jwk_pem_encoding.js checks for exactly
// that and caught this pair. Same reason krb5_ranges.js is tested by
// krb5_ranges_offsets.js.
//
// The hex tab exists to answer "which bytes say that", and until this table
// existed it answered in the encoding's own terms: `[APPLICATION 10] → SEQUENCE
// → [4] → SEQUENCE → [1]`. True, and useless to anybody who has not memorised
// RFC 4120's ASN.1 module. The table turns that into `AS-REQ → req-body →
// cname`, which is the name the RFC, the KDC's logs and every other Kerberos
// tool use.
//
// **A wrong name here is worse than no name**, and that is what this file is
// for. Nothing crashes when a tag is mapped to the wrong field: the strip says
// `till` while the highlight covers `rtime`, entirely plausibly, and somebody
// reads a value off the screen that belongs to something else — the same class
// of failure tests/krb5_ranges_offsets.js guards for offsets, one level up.
//
// So the assertion that carries this file is not "every element has a name" but
// **name-to-bytes**: slice the buffer at the range called `AS-REQ → req-body →
// cname → name-string[0]` and the bytes there must decode to the client
// principal that was encoded. A table with two fields transposed cannot pass
// that, and neither can a walk that loses its place.
//
// Next to it, the check that catches the drift this table is exposed to: every
// context tag our own encoders emit must be named. `krb5_messages.js` carries
// the same tag numbers as argument lists — a field added there and forgotten
// here is a `[9]` in the hex view rather than an error, so the coverage check
// is what makes the second copy safe to have. See the note at the top of the
// module on why it is data rather than derived.
//
// The last section is static and reads the pages: a `_hex` div nothing fills,
// or a tab strip nothing wires, is a tab that renders empty — which looks
// exactly like a message that has not been sent yet.
//
// Node only. No browser, no services, never skipped.
// ---------------------------------------------------------------------------
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "krb5_field_naming",
  level: appconfig.LOG_LEVEL || "info"
});
log.info("Log initialized. logLevel=" + log.level());

function shared(name) {
  return paths.requireSharedModule(
    [__dirname + "/../common/krb5/" + name, __dirname + "/" + name], name);
}
const prim = shared("krb5_primitives.js");
const asn1 = shared("krb5_asn1.js");
const msgs = shared("krb5_messages.js");
const gss = shared("krb5_gss.js");
const rangesMod = shared("krb5_ranges.js");
const names = shared("krb5_field_names.js");

const CLIENT_SRC = path.join(__dirname, "..", "client", "src");
const PUBLIC_DIR = path.join(__dirname, "..", "client", "public");

// The principal, realm and service used throughout, so an assertion can name
// the string it expects to find in the bytes rather than a magic number.
const CLIENT_NAME = "alice";
const REALM = "EXAMPLE.COM";
const SERVICE = "krbtgt";

function sampleTicket() {
  log.debug("Entering sampleTicket().");
  log.debug("Leaving sampleTicket().");
  return msgs.encTicket({
    realm: REALM,
    sname: { type: msgs.NAME_TYPE.SRV_INST, name: [SERVICE, REALM] },
    encPart: {
      etype: 18,
      kvno: 3,
      cipher: prim.toBytes([1, 2, 3, 4, 5, 6, 7, 8])
    }
  });
}

function sampleAsReq() {
  log.debug("Entering sampleAsReq().");
  log.debug("Leaving sampleAsReq().");
  return msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.AS_REQ,
    padata: [{
      type: msgs.PA_TYPE.PAC_REQUEST,
      value: msgs.encPaPacRequest(true)
    }],
    reqBody: {
      kdcOptions: [msgs.KDC_OPTION.FORWARDABLE, msgs.KDC_OPTION.RENEWABLE],
      cname: { type: msgs.NAME_TYPE.PRINCIPAL, name: [CLIENT_NAME] },
      realm: REALM,
      sname: { type: msgs.NAME_TYPE.SRV_INST, name: [SERVICE, REALM] },
      till: new Date(Date.UTC(2026, 7, 20)),
      nonce: 0x11223344,
      etypes: [18, 17, 23]
    }
  });
}

function sampleAsRep() {
  log.debug("Entering sampleAsRep().");
  log.debug("Leaving sampleAsRep().");
  return msgs.encKdcRep({
    msgType: msgs.MSG_TYPE.AS_REP,
    padata: [{
      type: msgs.PA_TYPE.ETYPE_INFO2,
      value: msgs.encEtypeInfo2([{ etype: 18, salt: REALM + CLIENT_NAME }])
    }],
    crealm: REALM,
    cname: { type: msgs.NAME_TYPE.PRINCIPAL, name: [CLIENT_NAME] },
    ticket: { raw: sampleTicket() },
    encPart: { etype: 18, kvno: null, cipher: prim.toBytes([9, 9, 9, 9]) }
  });
}

function sampleApReq() {
  log.debug("Entering sampleApReq().");
  log.debug("Leaving sampleApReq().");
  return msgs.encApReq({
    apOptions: [msgs.AP_OPTION.MUTUAL_REQUIRED],
    ticket: { raw: sampleTicket() },
    authenticator: {
      etype: 18,
      kvno: null,
      cipher: prim.toBytes([7, 7, 7, 7])
    }
  });
}

function sampleKrbError() {
  log.debug("Entering sampleKrbError().");
  log.debug("Leaving sampleKrbError().");
  return msgs.encKrbError({
    ctime: new Date(Date.UTC(2026, 7, 17)),
    cusec: 7,
    stime: new Date(Date.UTC(2026, 7, 17)),
    susec: 11,
    errorCode: 25,
    crealm: REALM,
    cname: { type: msgs.NAME_TYPE.PRINCIPAL, name: [CLIENT_NAME] },
    realm: REALM,
    sname: { type: msgs.NAME_TYPE.SRV_INST, name: [SERVICE, REALM] },
    eText: "NEEDED_PREAUTH",
    eData: msgs.encEtypeInfo2([{ etype: 18, salt: REALM + CLIENT_NAME }])
  });
}

const SAMPLES = [
  { label: "AS-REQ", bytes: sampleAsReq },
  { label: "AS-REP", bytes: sampleAsRep },
  { label: "AP-REQ", bytes: sampleApReq },
  { label: "KRB-ERROR", bytes: sampleKrbError },
  { label: "Ticket", bytes: sampleTicket },
  {
    label: "GSS InitialContextToken",
    bytes: function () {
      return gss.encodeInitialContextToken(gss.TOK_ID.AP_REQ, sampleApReq());
    }
  }
];

function mapped(bytes) {
  log.debug("Entering mapped().");
  log.debug("Leaving mapped().");
  return rangesMod.rangesOf(prim.toBytes(bytes));
}

// The range whose field path is exactly this, or null. Exact rather than a
// suffix match, because "the path that ends in cname" is satisfied by a cname
// anywhere in the message — including the one inside the ticket, which is a
// different field with different bytes.
function rangeAt(m, fieldPath) {
  log.debug("Entering rangeAt(). " + fieldPath);
  const hits = m.ranges.filter(function (r) {
    return r.fieldPath === fieldPath;
  });
  log.debug("Leaving rangeAt(). " + hits.length + " hit(s).");
  return hits;
}

// ---------------------------------------------------------------------------
// THE ASSERTION THIS FILE IS FOR: a name points at the bytes it names.
//
// Every check below it would survive a table with two fields transposed. This
// one cannot: it reads the value out of the buffer at the offsets the named
// range reports and compares it with what was encoded.
// ---------------------------------------------------------------------------
function namesPointAtTheBytesTheyName() {
  log.debug("Entering namesPointAtTheBytesTheyName().");
  const req = prim.toBytes(sampleAsReq());
  const m = rangesMod.rangesOf(req);

  // Strings, read back out of the buffer at the reported offsets.
  [
    ["AS-REQ → req-body → cname → name-string[0]", CLIENT_NAME],
    ["AS-REQ → req-body → realm", REALM],
    ["AS-REQ → req-body → sname → name-string[0]", SERVICE],
    ["AS-REQ → req-body → sname → name-string[1]", REALM]
  ].forEach(function (pair) {
    const hits = rangeAt(m, pair[0]).filter(function (r) {
      // The [k] wrapper and the string inside it share a field path; the
      // string is the one carrying the value.
      return r.tagName === "GeneralString";
    });
    assert.strictEqual(hits.length, 1,
      "expected exactly one GeneralString called " + pair[0] + ", found " +
      hits.length + ". Either the table stopped naming it or the walk is " +
      "naming several elements the same thing.");
    const r = hits[0];
    // Read through the codec at the offset the RANGE reports, so this asserts
    // the name, the offset and the decode together.
    const value = asn1.decGeneralString(asn1.readTlv(req, r.start, 0));
    assert.strictEqual(value, pair[1],
      pair[0] + " names bytes " + r.start + ".." + r.end + ", which read " +
      JSON.stringify(value) + " rather than " + JSON.stringify(pair[1]) +
      ". The name and the bytes disagree, which is the failure this view " +
      "cannot afford: the strip would say one field while the highlight " +
      "covered another.");
  });

  // And an integer, so the check is not only about text: the nonce is a value
  // no other field of this message shares.
  const nonce = rangeAt(m, "AS-REQ → req-body → nonce").filter(function (r) {
    return r.tagName === "INTEGER";
  });
  assert.strictEqual(nonce.length, 1, "the nonce was not named exactly once");
  assert.strictEqual(
    asn1.decInteger(asn1.readTlv(req, nonce[0].start, 0)), 0x11223344,
    "the bytes called nonce do not decode to the nonce that was encoded");

  // The negative half: a name that points at nothing must not exist. `rtime`
  // was not encoded, so nothing may claim to be it — a walk that numbered its
  // fields positionally rather than by tag would name `till` as `rtime` here.
  assert.strictEqual(rangeAt(m, "AS-REQ → req-body → rtime").length, 0,
    "something is named rtime, which this request does not contain. A field " +
    "named by POSITION rather than by context tag looks exactly like this " +
    "as soon as an optional field is absent.");
  log.info("names point at the bytes they name (cname, realm, sname, nonce)");
  log.debug("Leaving namesPointAtTheBytesTheyName().");
}

// ---------------------------------------------------------------------------
// Every context tag our own encoders emit is named.
//
// This is the drift check. krb5_messages.js and krb5_field_names.js carry the
// same tag numbers in different shapes, so a field added to an encoder and not
// to the table shows up in the hex view as an unnamed `[9]` and nothing else
// notices.
//
// Returns the unnamed tags rather than asserting, so the mutation below can
// call it and check that it FINDS something.
// ---------------------------------------------------------------------------
function unnamedContextTags(bytes, label) {
  log.debug("Entering unnamedContextTags(). " + label);
  const m = mapped(bytes);
  const missing = [];
  m.ranges.forEach(function (r) {
    if (r.tag === null || (r.tag & 0xc0) !== 0x80) {
      return;
    }
    // `named`, not `field`: an unrecognised element inherits nothing, but it
    // does keep a path, so testing the NAME for emptiness would pass on the
    // very case this is looking for. That is not hypothetical — it is what
    // this check did until removingAFieldIsCaught() below was written.
    if (!r.named) {
      missing.push(label + ": " + r.path + " at offset " + r.start);
    }
  });
  log.debug("Leaving unnamedContextTags(). " + missing.length + " unnamed.");
  return missing;
}

function everyContextTagIsNamed() {
  log.debug("Entering everyContextTagIsNamed().");
  let checked = 0;
  const missing = [];
  SAMPLES.forEach(function (sample) {
    const bytes = sample.bytes();
    const m = mapped(bytes);
    const tags = m.ranges.filter(function (r) {
      return r.tag !== null && (r.tag & 0xc0) === 0x80;
    }).length;
    assert.ok(tags > 1, sample.label + " has " + tags + " context-tagged " +
      "element(s). Every message here is built from a tagged sequence, so a " +
      "count that low means the walk never descended and this check would " +
      "pass without looking at anything.");
    checked += tags;
    missing.push.apply(missing, unnamedContextTags(bytes, sample.label));
  });
  assert.deepStrictEqual(missing, [],
    "these context tags reached the hex view with no field name:\n  " +
    missing.join("\n  ") + "\nEvery one of them is a field some encoder in " +
    "common/krb5/krb5_messages.js writes, so the table in " +
    "common/krb5/krb5_field_names.js is behind the codec.");
  log.info("all " + checked + " context-tagged elements across " +
    SAMPLES.length + " messages are named");
  log.debug("Leaving everyContextTagIsNamed().");
}

// ---------------------------------------------------------------------------
// A structure names itself wherever it turns up, and only once.
// ---------------------------------------------------------------------------
function aTicketIsNamedTheSameWhereverItIs() {
  log.debug("Entering aTicketIsNamedTheSameWhereverItIs().");
  const alone = mapped(sampleTicket());
  assert.strictEqual(rangeAt(alone, "Ticket → realm").length > 0, true,
    "a Ticket on its own must be named from its own application tag — this " +
    "is what a decoded ticket pasted into the decoder page looks like, and " +
    "nothing above it says what it is.");

  const inRep = mapped(sampleAsRep());
  assert.ok(rangeAt(inRep, "AS-REP → ticket → realm").length > 0,
    "the ticket inside an AS-REP must be named by the FIELD that carries it");
  const doubled = inRep.ranges.filter(function (r) {
    return /→ ticket → Ticket/.test(r.fieldPath || "");
  });
  assert.deepStrictEqual(doubled.map(function (r) { return r.fieldPath; }), [],
    "the ticket is named twice — once as the field and once as the type. " +
    "`ticket` and `Ticket` are the same bytes, and saying both puts a " +
    "redundant step in front of every field a reader is actually pointing at.");

  // The ticket's own realm and the reply's crealm are different fields with
  // different paths, which is the property that makes an exact-path lookup
  // meaningful in the first place.
  const repRealms = inRep.ranges.filter(function (r) {
    return r.field === "realm" || r.field === "crealm";
  }).map(function (r) { return r.fieldPath; });
  assert.ok(repRealms.indexOf("AS-REP → crealm") !== -1 &&
      repRealms.indexOf("AS-REP → ticket → realm") !== -1,
    "an AS-REP carries a crealm of its own and a realm inside its ticket, " +
    "and they must be distinguishable: " + repRealms.join(", "));
  log.info("a Ticket names itself alone and is named by its field when nested");
  log.debug("Leaving aTicketIsNamedTheSameWhereverItIs().");
}

// ---------------------------------------------------------------------------
// The GSS token, which is what the AP page's "What went out" actually holds.
// ---------------------------------------------------------------------------
function theGssTokenIsNamedPartByPart() {
  log.debug("Entering theGssTokenIsNamedPartByPart().");
  const token = gss.encodeInitialContextToken(gss.TOK_ID.AP_REQ,
      sampleApReq());
  const m = mapped(token);
  ["GSS-InitialContextToken",
    "GSS-InitialContextToken → thisMech",
    "GSS-InitialContextToken → token id",
    "GSS-InitialContextToken → AP-REQ",
    "GSS-InitialContextToken → AP-REQ → ticket → realm"].forEach(
    function (wanted) {
      assert.ok(rangeAt(m, wanted).length > 0,
        "the GSS token has no element named " + wanted + ". Its three parts " +
        "are positional rather than context-tagged, so they are named by " +
        "ORDER — a walk that expected a wrapper sequence swallows the " +
        "mechanism OID and mis-names everything after it.");
    });
  log.info("the GSS InitialContextToken is named part by part");
  log.debug("Leaving theGssTokenIsNamedPartByPart().");
}

// ---------------------------------------------------------------------------
// The table refers only to structures it defines, and covers the codec's own
// application numbers.
// ---------------------------------------------------------------------------
function theTableHasNoDeadEnds() {
  log.debug("Entering theTableHasNoDeadEnds().");
  const dangling = [];
  Object.keys(names.TYPES).forEach(function (typeName) {
    const type = names.TYPES[typeName];
    Object.keys(type.fields || {}).forEach(function (tag) {
      const field = type.fields[tag];
      [field.type, field.of].forEach(function (referenced) {
        if (referenced && !names.structure(referenced)) {
          dangling.push(typeName + "[" + tag + "] " + field.name + " -> " +
            referenced);
        }
      });
    });
    (type.positional || []).forEach(function (slot) {
      if (slot.type && !names.structure(slot.type)) {
        dangling.push(typeName + " positional " + slot.name + " -> " +
          slot.type);
      }
    });
  });
  assert.deepStrictEqual(dangling, [],
    "these fields name a structure the table does not define, so the walk " +
    "stops naming anything below them — silently, since an unknown structure " +
    "is indistinguishable from an opaque one:\n  " + dangling.join("\n  "));

  Object.keys(names.ALIASES).forEach(function (from) {
    assert.ok(names.structure(from),
      "the alias " + from + " -> " + names.ALIASES[from] + " resolves to " +
      "nothing");
  });

  // Every application number the codec knows must be one this table can name.
  const uncovered = Object.keys(msgs.APPLICATION).filter(function (key) {
    return !names.typeForApplication(msgs.APPLICATION[key]);
  });
  assert.deepStrictEqual(uncovered, [],
    "krb5_messages.js encodes these [APPLICATION n] messages that the field " +
    "table cannot name: " + uncovered.join(", "));

  // And an AS-REQ and a TGS-REQ must be told apart, because "which exchange " +
  // "is this" is the first question a reader of these bytes has.
  assert.notStrictEqual(names.typeForApplication(msgs.APPLICATION.AS_REQ),
    names.typeForApplication(msgs.APPLICATION.TGS_REQ),
    "an AS-REQ and a TGS-REQ are named the same thing");
  assert.ok(names.structure(names.typeForApplication(
      msgs.APPLICATION.TGS_REQ)).fields,
    "a TGS-REQ resolves to a structure with no fields — the alias to the " +
    "KDC-REQ shape is broken, so every field of every TGS request would be " +
    "unnamed while the AS page looked perfect");
  log.info("the table has no dead ends and covers all " +
    Object.keys(msgs.APPLICATION).length + " application numbers");
  log.debug("Leaving theTableHasNoDeadEnds().");
}

// ---------------------------------------------------------------------------
// The mutation: take a field out of the table and the coverage check must say
// so.
//
// Without this, everyContextTagIsNamed() is a check whose failure mode nobody
// has seen. It is also the cheapest possible demonstration that `field` is
// read from the table rather than derived from the tag.
// ---------------------------------------------------------------------------
function removingAFieldIsCaught() {
  log.debug("Entering removingAFieldIsCaught().");
  const body = names.TYPES["KDC-REQ-BODY"];
  const saved = body.fields[7];
  assert.ok(saved && saved.name === "nonce",
    "expected KDC-REQ-BODY[7] to be nonce; the table moved and this " +
    "mutation is no longer removing what it thinks it is");
  try {
    delete body.fields[7];
    const missing = unnamedContextTags(sampleAsReq(), "AS-REQ");
    assert.ok(missing.length > 0,
      "with nonce removed from the table, every context tag was still " +
      "reported as named. The coverage check is reading something other " +
      "than the table — it would not notice a field the codec grew.");
    assert.ok(missing.join(" ").indexOf("[7]") !== -1,
      "a field was reported unnamed, but not the one that was removed: " +
      missing.join(", "));
  } finally {
    // Restored whatever happened above: the checks after this one share the
    // module, and a mutation left behind would make them assert against a
    // table this test broke.
    body.fields[7] = saved;
  }
  assert.deepStrictEqual(unnamedContextTags(sampleAsReq(), "AS-REQ"), [],
    "the table was not restored after the mutation");
  log.info("removing a field from the table is caught by the coverage check");
  log.debug("Leaving removingAFieldIsCaught().");
}

// ---------------------------------------------------------------------------
// The wiring, read off the pages. Static, because none of it can fail in a way
// a browser test would see: a hex tab that renders nothing looks exactly like a
// message that has not been sent yet.
// ---------------------------------------------------------------------------
// DISCOVERED, not listed. Every page that links css/kerberos.css is a page of
// this workflow, and each one names its own bundle in its <script> tag.
//
// A written-out list of five was the obvious thing and would already be wrong:
// a sixth page (SPNEGO over HTTP) arrived while this test was being written,
// carrying hex tabs of its own, and a fixed list would have said nothing about
// it — which is the failure mode this whole file exists to prevent, one level
// up. The pages are stated by the STYLESHEET they load rather than by a
// filename pattern because that is what makes a page part of this family;
// `spnego.html` does not begin with `kerberos`.
function kerberosPages() {
  log.debug("Entering kerberosPages().");
  const out = [];
  if (!fs.existsSync(PUBLIC_DIR)) {
    log.debug("Leaving kerberosPages(). No client/public.");
    return out;
  }
  fs.readdirSync(PUBLIC_DIR).forEach(function (name) {
    if (!/\.html$/.test(name)) {
      return;
    }
    const html = fs.readFileSync(path.join(PUBLIC_DIR, name), "utf8");
    if (html.indexOf("css/kerberos.css") === -1) {
      return;
    }
    const script = html.match(/<script[^>]*src="\/js\/([a-z0-9_]+)\.js"/);
    out.push({
      page: name,
      html: html,
      bundle: script ? script[1] + ".js" : null
    });
  });
  log.debug("Leaving kerberosPages(). " + out.length + " page(s).");
  return out;
}

function readClientFile(where, name) {
  log.debug("Entering readClientFile(). " + name);
  const file = path.join(where, name);
  assert.ok(fs.existsSync(file), name + " is missing from " + where +
    ". This check reads the pages and their bundles as TEXT; in the tests " +
    "image they arrive through the client/public and client/src COPY lines " +
    "in tests/Dockerfile.");
  log.debug("Leaving readClientFile().");
  return fs.readFileSync(file, "utf8");
}

function everyHexPaneIsReachableAndFilled() {
  log.debug("Entering everyHexPaneIsReachableAndFilled().");
  let panels = 0;
  const pages = kerberosPages();
  assert.ok(pages.length >= 5,
    "found " + pages.length + " page(s) linking css/kerberos.css under " +
    PUBLIC_DIR + ". There are five Kerberos pages at the least, so a count " +
    "below that means the pages are not where this check looks and every " +
    "assertion below it passed by having nothing to read. In the tests image " +
    "they arrive through the client/public COPY lines in tests/Dockerfile.");
  pages.forEach(function (entry) {
    const html = entry.html;
    assert.ok(entry.bundle, entry.page + " loads no /js/*.js bundle, so " +
      "nothing on it can run");
    // A page whose bundle is not written yet is REPORTED, not silently
    // skipped, and only its bundle-side checks are held back — the markup
    // checks below still run, which is what caught the SPNEGO page's hex tabs
    // before that page had any code at all.
    const bundlePath = path.join(CLIENT_SRC, entry.bundle);
    const bundle = fs.existsSync(bundlePath)
      ? fs.readFileSync(bundlePath, "utf8") : null;
    if (!bundle) {
      log.warn(entry.page + ": client/src/" + entry.bundle + " does not " +
        "exist yet, so this page's WIRING is unchecked. Its markup is " +
        "checked below. If that file was renamed rather than not-yet-" +
        "written, this check has quietly stopped covering a live page.");
    }
    // `<div id=...>` specifically, not any id ending in _hex: the decoder page
    // has an INPUT called krb_key_hex — a place to paste a raw key — and a
    // check that treated it as a pane demanded a tab strip around a text box.
    const hexIds = (html.match(/<div id="(krb_[a-z0-9_]*_hex)"/g) || [])
      .map(function (m) { return m.slice(9, -1); });
    if (!hexIds.length) {
      log.info(entry.page + ": no hex panes");
      return;
    }
    // A strip that is never wired is a tab that cannot be clicked, and the
    // panel behind it is `display: none` for ever.
    assert.ok(!bundle || /panes\.wireTabs\(\)/.test(bundle),
      entry.page + " has " + hexIds.length + " hex pane(s) but " +
      entry.bundle + " never calls panes.wireTabs(). The Hex button would " +
      "render, do nothing when clicked, and the pane behind it would stay " +
      "hidden — which reads as a page with no hex view rather than as a " +
      "missing call.");
    hexIds.forEach(function (id) {
      panels += 1;
      // Reachable: the div is inside a tab panel, and that panel's group has a
      // button pointing at it.
      const panel = new RegExp('data-krb-tabs="([a-z0-9_]+)"[^>]*' +
          'data-krb-tab="hex"[^>]*>\\s*<div id="' + id + '"');
      const match = html.match(panel);
      assert.ok(match, entry.page + ": " + id + " is not inside a " +
        'krb-tabpanel with data-krb-tab="hex". Nothing would ever show it.');
      const group = match[1];
      assert.ok(new RegExp('class="krb-tabs" data-krb-tabs="' + group + '"')
          .test(html),
        entry.page + ": " + id + ' is in tab group "' + group + '" and the ' +
        "page has no krb-tabs strip for that group, so there is no button " +
        "to select it.");
      assert.ok(new RegExp('data-krb-tab="hex"[^>]*>Hex<').test(html),
        entry.page + ": the strip for " + id + " has no Hex button");

      // Filled: either by the `_pane` → `_hex` convention that
      // renderMessage() applies, or by an explicit call naming this id.
      const companion = id.replace(/_hex$/, "_pane");
      const byConvention = bundle &&
        html.indexOf('id="' + companion + '"') !== -1 &&
        new RegExp('renderMessage\\(\\s*"' + companion + '"').test(bundle);
      const byHand = bundle &&
        new RegExp('(renderCompanionHex|render)\\(\\s*"' +
          '(' + id + '|' + companion + ')"').test(bundle);
      assert.ok(!bundle || byConvention || byHand,
        entry.page + ": nothing fills " + id + ". renderMessage() pairs " +
        companion + " with it automatically, but this page has no such " +
        "call and no explicit render either — so the tab is there and stays " +
        "empty, which is indistinguishable from an exchange that has not " +
        "run yet.");
    });
    log.info(entry.page + ": " + hexIds.length + " hex pane(s), each " +
      "reachable and filled");
  });
  assert.ok(panels >= 4,
    "only " + panels + " hex pane(s) across " + pages.length + " page(s). " +
    "The request and " +
    "reply of the AS, TGS and AP exchanges plus the held ticket are four at " +
    "the least, so a count below that means the panes were dropped from the " +
    "markup and every check above passed by having nothing to look at.");
  log.debug("Leaving everyHexPaneIsReachableAndFilled().");
}

// ---------------------------------------------------------------------------
// The convention itself, which everything above depends on and none of it
// checks.
//
// Every page but one gets its hex view because renderMessage() pairs
// `krb_x_pane` with `krb_x_hex`. Take that one call out of kerberos_panes.js
// and all seven panes go empty — and the checks above still pass, because each
// page's markup and each page's renderMessage() call are exactly where they
// were. Mutation-tested: deleting the call, with this section absent, left the
// whole file green.
// ---------------------------------------------------------------------------
function bodyOf(source, signature) {
  log.debug("Entering bodyOf(). " + signature);
  const from = source.indexOf(signature);
  assert.ok(from !== -1, "could not find " + signature +
    " in client/src/kerberos_panes.js — it was renamed, and the checks that " +
    "read it are now asserting nothing.");
  // To the next line that closes a function at column 0.
  const rest = source.slice(from);
  const end = rest.indexOf("\n}");
  assert.ok(end > 0, signature + " has no closing brace at column 0");
  log.debug("Leaving bodyOf().");
  return rest.slice(0, end);
}

function theCompanionConventionIsWired() {
  log.debug("Entering theCompanionConventionIsWired().");
  const src = readClientFile(CLIENT_SRC, "kerberos_panes.js");
  const renderMessage = bodyOf(src, "async function renderMessage(");
  assert.ok(/renderCompanionHex\(/.test(renderMessage),
    "renderMessage() no longer renders the companion hex view. Every hex tab " +
    "on the TGS and AP pages, and both on the AS page, is filled by that one " +
    "call — without it they render their heading and stay empty, which is " +
    "indistinguishable from an exchange nobody has run.");

  const companion = bodyOf(src, "function renderCompanionHex(");
  assert.ok(/_pane\$?\/?,\s*"_hex"/.test(companion.replace(/\s+/g, " ")) ||
      /replace\(\/_pane\$\/, "_hex"\)/.test(companion),
    "renderCompanionHex() no longer maps a `_pane` id to its `_hex` " +
    "companion, so the pairing every page relies on is gone");
  assert.ok(/require\("\.\/kerberos_hex\.js"\)/.test(companion),
    "renderCompanionHex() must require the hex module INSIDE the function: " +
    "kerberos_hex.js requires this module back, and a top-level require of " +
    "it here is a browserify cycle that fails at load with `panes.el is not " +
    "a function`, not a warning.");
  const top = src.slice(0, src.indexOf("function renderCompanionHex("));
  assert.ok(!/^var .*require\("\.\/kerberos_hex\.js"\)/m.test(top),
    "kerberos_panes.js requires kerberos_hex.js at module scope, which is " +
    "the cycle the note in renderCompanionHex() explains");
  log.info("the _pane -> _hex convention is wired, and wired without a cycle");
  log.debug("Leaving theCompanionConventionIsWired().");
}

// The renderer's own two claims, read off its source: that the gutter is built
// from per-byte cells carrying a range, and that the strip leads with the
// field name. Neither is visible without a browser, and both are what this
// change was for.
function theRendererHighlightsBothHalves() {
  log.debug("Entering theRendererHighlightsBothHalves().");
  const src = readClientFile(CLIENT_SRC, "kerberos_hex.js");
  const flat = src.replace(/\s+/g, " ");
  assert.ok(/make\("span", "krb-hex-a"/.test(flat),
    "kerberos_hex.js no longer builds per-character cells for the readable " +
    "column, so hovering a byte cannot highlight its character");
  assert.ok(/ascii\.setAttribute\("data-krb-range"/.test(flat),
    "the readable column's cells carry no data-krb-range, so paint() cannot " +
    "match them and only the hex half would light up");
  // Matched against the whitespace-collapsed source rather than a line, and
  // against the ARGUMENT rather than an assignment, so wrapping this call at 80
  // columns or moving it behind a helper does not silence the check. Every
  // source-reading test in this suite has been broken once by a reformat that
  // changed nothing about the property.
  assert.ok(/(line\(fieldLine, |fieldLine\.textContent = )r\.fieldPath/
      .test(flat),
    "the strip no longer leads with the field's name — the whole point of " +
    "the name table is that `AS-REQ → req-body → cname` is the first thing " +
    "read, not the ASN.1 path");
  assert.ok(/node\.title = text/.test(flat),
    "the strip's lines are clipped to one line each so the dump below them " +
    "cannot move; without a title carrying the full text, a long ASN.1 path " +
    "is simply lost");
  const css = readClientFile(path.join(PUBLIC_DIR, "css"), "kerberos.css");
  [".krb-hex-a", ".krb-hex-field", ".krb-hex-meta"].forEach(function (cls) {
    assert.ok(css.indexOf(cls) !== -1,
      cls + " is used by the hex view and defined in no stylesheet these " +
      "pages load. checkStylesheetsLoaded() in tests/navigation.js fails on " +
      "exactly this, one page at a time.");
  });
  log.info("the renderer highlights both halves and names the field first");
  log.debug("Leaving theRendererHighlightsBothHalves().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. Human-readable field names for the hex view.");
  try {
    namesPointAtTheBytesTheyName();
    everyContextTagIsNamed();
    aTicketIsNamedTheSameWhereverItIs();
    theGssTokenIsNamedPartByPart();
    theTableHasNoDeadEnds();
    removingAFieldIsCaught();
    everyHexPaneIsReachableAndFilled();
    theCompanionConventionIsWired();
    theRendererHighlightsBothHalves();
    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error && error.stack ? error.stack : String(error));
    process.exit(1);
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("krb5_field_naming")
  .description("RFC 4120 field names for the Kerberos hex view.")
  .addOption(new Option("-u, --url <url>", "Ignored; accepted for uniformity."))
  .action(function () {});
program.parse(process.argv).opts();

test();
