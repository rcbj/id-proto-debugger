// File: krb5_ranges.js
//
// ---------------------------------------------------------------------------
// Which bytes belong to which field.
//
// The decoded views answer "what does this message say". This answers "and
// WHERE, exactly" — a flat list of absolute byte ranges, one per ASN.1 element,
// each naming the element and the path that reaches it. It is what lets the
// hex view colour a byte by the field it belongs to.
//
// NO DOM HERE, like every other module in common/krb5. The rendering is in
// client/src/kerberos_hex.js; keeping the arithmetic separate is what lets
// tests/krb5_ranges_offsets.js check every offset with no browser.
//
// ---------------------------------------------------------------------------
// THE ONE THING THIS EXISTS TO GET RIGHT: offsets are ABSOLUTE.
//
// krb5_asn1.js's tree() already reports an offset per node, but it recurses by
// re-parsing the VALUE slice — `tree(t.value, d + 1)` — so a child's offset is
// relative to its parent's value and means nothing in the original buffer. Add
// them up naively and nested elements land in the wrong place, which in a hex
// view is not a crash but a lie: the highlight covers bytes of a different
// field and looks entirely plausible.
//
// So this walker carries a base and adds it at every level, and the test
// asserts that each range's bytes, sliced out of the ORIGINAL buffer at the
// reported offsets, equal the element's own bytes. That check is the point: it
// cannot pass if an offset is relative.
// ---------------------------------------------------------------------------
var asn1 = require("./krb5_asn1.js");
var prim = require("./krb5_primitives.js");
var names = require("./krb5_field_names.js");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "krb5_ranges",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      // No CONFIG_FILE resolvable here — a node caller rather than a bundle.
      return "info";
    }
  })()
});

// A hex view of a 64KB message would be 4,096 rows; a cap keeps a pasted blob
// from turning into a page nobody can scroll. Well above any real KDC message.
var MAX_RANGE_BYTES = 64 * 1024;

// Deeper than this and the ranges stop being useful to look at — and the walker
// must terminate on hostile input regardless of what krb5_asn1.js allows.
var MAX_DEPTH = 24;


// ---------------------------------------------------------------------------
// Is this element worth descending into?
//
// krb5_asn1.js has looksConstructed() and does NOT export it, so this is a copy
// of the same rule rather than a new one — deliberately, because the hex view
// must agree with the ASN.1 tree the decoded tab shows. Two different answers
// to "is this constructed" would colour a byte as one field while the tree
// beside it calls that byte another.
//
// The rule is stricter than DER's constructed bit alone: the bit must be set
// AND the value must parse cleanly into elements that exactly fill it. That
// second half is what stops an OCTET STRING whose contents happen to start
// with a plausible tag from being torn into fictitious children.
//
// If krb5_asn1.js ever exports it, delete this and use it.
// ---------------------------------------------------------------------------
function looksConstructed(t) {
  log.debug("Entering looksConstructed().");
  if ((t.tag & 0x20) === 0) {
    log.debug("Leaving looksConstructed(). Primitive tag.");
    return false;
  }
  if (t.length === 0) {
    log.debug("Leaving looksConstructed(). Empty.");
    return false;
  }
  try {
    var children = asn1.readChildren(t.value, 0);
    var fills = children.length > 0 &&
        children[children.length - 1].end === t.value.length;
    log.debug("Leaving looksConstructed(). fills=" + fills);
    return fills;
  } catch (e) {
    // Not parseable as a sequence of elements: treat as opaque, exactly as
    // krb5_asn1.js does.
    log.debug("Leaving looksConstructed(). Opaque.");
    return false;
  }
}

// ---------------------------------------------------------------------------
// Walk the DER and collect one range per element.
//
// Returns { total, ranges: [...] } where each range is
//
//   { index, start, end, headerEnd, depth, tag, tagName, path, constructed,
//     named, field, fieldPath, structure }
//
// `start`..`end` covers the WHOLE element, header included, because that is
// what a reader wants highlighted: the tag and length bytes are part of it,
// and a view that coloured only the value would leave two unexplained bytes in
// front of everything.
//
// `headerEnd` is where the value begins, so a renderer can shade the header
// differently if it wants to — the hex view does, faintly, because "these two
// bytes say what this is and how long" is worth seeing once.
//
// THE LAST THREE ARE THE NAMES, and they are the reason anybody but an ASN.1
// reader can use this. `path` says `[APPLICATION 10] → SEQUENCE → [4] →
// SEQUENCE → [1]`, which is what the ENCODING calls this element; `fieldPath`
// says `AS-REQ → req-body → cname`, which is what the RFC calls it, and
// `field` is that path's last segment. The table is
// common/krb5/krb5_field_names.js and the walk below carries its context down
// alongside the byte offsets — the two have to be threaded together because a
// context tag means nothing without knowing which structure it is inside, and
// that is exactly what the walk knows and a later pass over a flat list would
// not. `structure` is set where an element IS a named structure (a Ticket, a
// PrincipalName), which is what lets the strip say what it is looking at
// rather than only where it is.
//
// A name is left EMPTY rather than guessed at: an element this table does not
// recognise keeps its `path` and gets no `fieldPath`, because an invented field
// name is worse than none — it would be believed, and this view exists to be
// believed.
// ---------------------------------------------------------------------------
function rangesOf(bytes) {
  log.debug("Entering rangesOf().");
  var b = prim.toBytes(bytes);
  if (b.length > MAX_RANGE_BYTES) {
    log.debug("Leaving rangesOf(). Too large.");
    throw new Error("krb5: refusing to map " + b.length + " bytes of hex " +
        "(limit " + MAX_RANGE_BYTES + ")");
  }
  var ranges = [];

  function walk(slice, base, depth, path, context, fieldPath) {
    log.debug("Entering walk(). base=" + base + " depth=" + depth);
    var at = 0;
    // The element's index among its siblings, which is what names the members
    // of a SEQUENCE OF (padata[0], padata[1]) and the ordered members of a GSS
    // token. Counted here because only the walk knows it.
    var position = 0;
    while (at < slice.length) {
      var t;
      try {
        t = asn1.readTlv(slice, at, depth);
      } catch (e) {
        // Trailing bytes that are not an element. Recorded rather than thrown:
        // the hex view's job is to show what is there, and "these bytes did not
        // parse" is information. Stop walking this level.
        ranges.push({
          index: ranges.length,
          start: base + at,
          end: base + slice.length,
          headerEnd: base + at,
          depth: depth,
          tag: null,
          tagName: "(unparsed)",
          path: path.concat(["(unparsed)"]).join(" → "),
          named: false,
          field: null,
          fieldPath: fieldPath.concat(["(unparsed)"]).join(" → "),
          structure: null,
          constructed: false,
          note: e.message
        });
        log.debug("Leaving walk(). Unparsed tail.");
        return;
      }
      var name = asn1.describeTag(t.tag);
      var here = path.concat([name]);
      // One step of the naming machine, in step with one step of the byte walk.
      var named = names.step(context, t.tag, position);
      var namedPath = fieldPath;
      if (named.label && named.replaces) {
        // An element of a SEQUENCE OF: the index goes ON the list's name rather
        // than after it (`padata[0]`, not `padata → padata[0]`).
        namedPath = fieldPath.slice(0, -1).concat([named.label]);
      } else if (named.label) {
        namedPath = fieldPath.concat([named.label]);
      }
      ranges.push({
        index: ranges.length,
        start: base + t.start,
        end: base + t.end,
        headerEnd: base + t.valueStart,
        depth: depth,
        tag: t.tag,
        tagName: name,
        path: here.join(" → "),
        // The innermost NAMED thing this element is part of. For the INTEGER
        // inside `[1]` that is still `pvno`: the wrapper and its value are one
        // field, and a view that named only the wrapper would go blank on the
        // byte the reader is actually pointing at.
        //
        // `named` is what separates that inheritance from a LIE. An element the
        // table does not recognise also has no label, and so would inherit its
        // parent's name and be shown as it — a stray `[9]` in a req-body
        // reading `AS-REQ → req-body`, which is exactly the confident wrong
        // answer this view must not give. Unrecognised elements therefore keep
        // the encoding's own name for their last step and are flagged; the hex
        // view shows the ASN.1 path for them instead.
        named: named.known !== false,
        field: (named.known !== false && namedPath.length)
          ? namedPath[namedPath.length - 1] : null,
        fieldPath: named.known === false
          ? fieldPath.concat([name]).join(" → ")
          : namedPath.join(" → "),
        structure: named.type || null,
        constructed: looksConstructed(t)
      });
      if (looksConstructed(t) && depth < MAX_DEPTH) {
        // The base for the children is where this element's VALUE starts in the
        // original buffer. This single addition is the whole difference from
        // tree()'s relative offsets.
        walk(t.value, base + t.valueStart, depth + 1, here, named.context,
            namedPath);
      }
      at = t.end;
      position += 1;
    }
    log.debug("Leaving walk().");
  }

  walk(b, 0, 0, [], names.rootContext(), []);
  log.debug("Leaving rangesOf(). " + ranges.length + " range(s).");
  return { total: b.length, ranges: ranges };
}

// ---------------------------------------------------------------------------
// For each byte, the INNERMOST range that covers it.
//
// Ranges nest, so a byte is inside several; the innermost is the one worth
// naming, because that is the actual field. Returns an array of range indices,
// one per byte, with -1 where nothing covers it.
// ---------------------------------------------------------------------------
function ownerPerByte(mapped) {
  log.debug("Entering ownerPerByte().");
  var owner = new Array(mapped.total);
  var i;
  for (i = 0; i < mapped.total; i++) {
    owner[i] = -1;
  }
  // Sorted by depth so deeper writes land last and win. Stable on index for a
  // deterministic result when two ranges share a depth and a byte, which only
  // happens for the unparsed-tail marker.
  var byDepth = mapped.ranges.slice().sort(function (a, c) {
    return a.depth - c.depth || a.index - c.index;
  });
  byDepth.forEach(function (r) {
    for (var k = r.start; k < r.end && k < owner.length; k++) {
      owner[k] = r.index;
    }
  });
  log.debug("Leaving ownerPerByte().");
  return owner;
}

module.exports = {
  rangesOf: rangesOf,
  ownerPerByte: ownerPerByte,
  MAX_RANGE_BYTES: MAX_RANGE_BYTES,
  MAX_DEPTH: MAX_DEPTH
};
