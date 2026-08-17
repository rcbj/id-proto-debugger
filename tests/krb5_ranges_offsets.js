// File: krb5_ranges_offsets.js
//
// ---------------------------------------------------------------------------
// Every byte range common/krb5/krb5_ranges.js reports must be ABSOLUTE.
//
// This is a one-assertion test wearing several hats. The hex view on the AS
// exchange page colours each byte by the field that owns it, and it gets those
// fields from rangesOf(). If an offset is relative to its parent rather than to
// the buffer, nothing crashes: the highlight simply covers the wrong bytes, and
// it looks entirely plausible while doing so. A person then reads the wrong
// field's value off the screen, which is worse than no hex view at all.
//
// The check that cannot pass on a relative offset: slice the ORIGINAL buffer at
// each reported start..end and require the bytes to equal the element's own
// re-encoded bytes. krb5_asn1.js's tree() would fail this at depth 1, which is
// why rangesOf() exists rather than reusing it.
//
// Node only. No browser, no services, never skipped.
// ---------------------------------------------------------------------------
const assert = require("assert");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "krb5_ranges_offsets",
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
const rangesMod = shared("krb5_ranges.js");

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
      cname: { type: msgs.NAME_TYPE.PRINCIPAL, name: ["alice"] },
      realm: "EXAMPLE.COM",
      sname: {
        type: msgs.NAME_TYPE.SRV_INST,
        name: ["krbtgt", "EXAMPLE.COM"]
      },
      till: new Date(Date.UTC(2026, 7, 20)),
      nonce: 0x11223344,
      etypes: [18, 17, 23]
    }
  });
}

// ---------------------------------------------------------------------------
// The assertion that cannot pass on a relative offset.
// ---------------------------------------------------------------------------
function everyRangeSlicesBackToItself(bytes, label) {
  log.debug("Entering everyRangeSlicesBackToItself(). " + label);
  const b = prim.toBytes(bytes);
  const mapped = rangesMod.rangesOf(b);
  assert.strictEqual(mapped.total, b.length, label + ": wrong total length");
  assert.ok(mapped.ranges.length > 5,
    label + ": only " + mapped.ranges.length + " range(s) — a KDC message has " +
    "more elements than that, so the walk stopped early");

  let deepest = 0;
  mapped.ranges.forEach(function (r) {
    if (r.tagName === "(unparsed)") {
      assert.fail(label + ": bytes at " + r.start + " did not parse (" +
        r.note + "). This message was built by our own encoder, so a tail we " +
        "cannot read is a codec bug rather than hostile input.");
    }
    deepest = Math.max(deepest, r.depth);

    assert.ok(r.start >= 0 && r.end <= b.length,
      label + ": range " + r.index + " (" + r.path + ") spans " + r.start +
      ".." + r.end + ", outside a " + b.length + "-byte buffer. That is the " +
      "signature of an offset that is relative to its parent.");
    assert.ok(r.headerEnd > r.start && r.headerEnd <= r.end,
      label + ": range " + r.index + " has a header ending at " + r.headerEnd +
      ", outside its own " + r.start + ".." + r.end);

    // Re-read the element AT the reported offset. If the offset is absolute
    // this parses and reports the same tag and the same total length; if it is
    // relative it either throws or reads some unrelated element.
    const reread = asn1.readTlv(b, r.start, 0);
    assert.strictEqual(reread.tag, r.tag,
      label + ": re-reading range " + r.index + " (" + r.path + ") at offset " +
      r.start + " gives tag 0x" + reread.tag.toString(16) + ", not the 0x" +
      r.tag.toString(16) + " that was recorded.");
    assert.strictEqual(reread.end, r.end,
      label + ": range " + r.index + " (" + r.path + ") says it ends at " +
      r.end + "; re-reading it at " + r.start + " ends at " + reread.end);
    assert.strictEqual(reread.valueStart, r.headerEnd,
      label + ": range " + r.index + " disagrees about where its value starts");
  });

  assert.ok(deepest >= 3,
    label + ": the deepest range is at depth " + deepest + ". A KDC-REQ nests " +
    "further than that, so the walk is not descending — and a walker that " +
    "never recurses trivially passes the absolute-offset check above.");
  log.info(label + ": " + mapped.ranges.length + " ranges, depth " + deepest +
    ", every one slices back to itself");
  log.debug("Leaving everyRangeSlicesBackToItself().");
  return mapped;
}

// ---------------------------------------------------------------------------
// Every byte is owned by the INNERMOST element covering it.
// ---------------------------------------------------------------------------
function everyByteIsOwnedByItsInnermostField(mapped) {
  log.debug("Entering everyByteIsOwnedByItsInnermostField().");
  const owner = rangesMod.ownerPerByte(mapped);
  assert.strictEqual(owner.length, mapped.total,
    "the owner map must have one entry per byte");

  const uncovered = owner.filter(function (o) { return o < 0; }).length;
  assert.strictEqual(uncovered, 0,
    uncovered + " byte(s) belong to no element. Every byte of a DER message is " +
    "inside the outermost element at least, so a gap means the walk skipped " +
    "something.");

  // Spot-check the property directly: for a sample of bytes, no OTHER range
  // covering that byte may be deeper than the one recorded as its owner.
  const byIndex = {};
  mapped.ranges.forEach(function (r) { byIndex[r.index] = r; });
  for (let i = 0; i < mapped.total; i += 3) {
    const mine = byIndex[owner[i]];
    mapped.ranges.forEach(function (r) {
      if (i >= r.start && i < r.end && r.depth > mine.depth) {
        assert.fail("byte " + i + " is owned by " + mine.path + " at depth " +
          mine.depth + ", but " + r.path + " at depth " + r.depth +
          " also covers it and is deeper");
      }
    });
  }
  log.info("every byte is owned, and by its innermost element");
  log.debug("Leaving everyByteIsOwnedByItsInnermostField().");
}

// ---------------------------------------------------------------------------
// The mutation that proves the check works: a relative offset must be caught.
// ---------------------------------------------------------------------------
function aRelativeOffsetWouldBeCaught(bytes) {
  log.debug("Entering aRelativeOffsetWouldBeCaught().");
  const b = prim.toBytes(bytes);
  const mapped = rangesMod.rangesOf(b);
  const nested = mapped.ranges.filter(function (r) { return r.depth >= 2; })[0];
  assert.ok(nested, "no nested range to mutate — the sample is too flat");

  // What a relative offset looks like: the child's start measured from its
  // parent's value rather than from the buffer.
  const parent = mapped.ranges.filter(function (r) {
    return r.depth === nested.depth - 1 && r.start <= nested.start &&
      r.end >= nested.end;
  }).pop();
  assert.ok(parent, "could not find the parent of " + nested.path);
  const relativeStart = nested.start - parent.headerEnd;
  assert.notStrictEqual(relativeStart, nested.start,
    "the sample's nesting is at offset 0, so a relative offset would be " +
    "indistinguishable from an absolute one here and this check proves " +
    "nothing. Use a message whose nested elements do not start at the top.");

  let caught = false;
  try {
    const reread = asn1.readTlv(b, relativeStart, 0);
    if (reread.tag !== nested.tag || reread.end !== nested.end) {
      caught = true;
    }
  } catch (e) {
    caught = true;
  }
  assert.ok(caught,
    "re-reading " + nested.path + " at its RELATIVE offset (" + relativeStart +
    " instead of " + nested.start + ") produced the same element, so the " +
    "absolute-offset assertion above would not have noticed the difference.");
  log.info("a relative offset for " + nested.path + " (" + relativeStart +
    " vs " + nested.start + ") is caught");
  log.debug("Leaving aRelativeOffsetWouldBeCaught().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. Absolute byte ranges for the hex view.");
  try {
    const req = sampleAsReq();
    const mapped = everyRangeSlicesBackToItself(req, "AS-REQ");
    everyByteIsOwnedByItsInnermostField(mapped);
    aRelativeOffsetWouldBeCaught(req);
    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error && error.stack ? error.stack : String(error));
    process.exit(1);
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("krb5_ranges_offsets")
  .description("Absolute byte ranges for the Kerberos hex view.")
  .addOption(new Option("-u, --url <url>", "Ignored; accepted for uniformity."))
  .action(function () {});
program.parse(process.argv).opts();

test();
