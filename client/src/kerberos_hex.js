// File: kerberos_hex.js
//
// ---------------------------------------------------------------------------
// The hex tab: the message as bytes, coloured by the field each byte is in.
//
// The decoded tab answers "what does this say". This answers "and which bytes
// say it" — the question you actually have when a KDC rejects a message you
// believe is correct, or when a capture disagrees with a decoder.
//
// WHERE THE COLOURING COMES FROM. common/krb5/krb5_ranges.js walks the DER and
// returns one absolute byte range per ASN.1 element, plus, for each byte, the
// INNERMOST element that owns it. All the arithmetic is there and none of it is
// here, which is what lets tests/krb5_ranges_offsets.js check every offset with
// no browser — see the note at the top of that module on why the offsets must
// be absolute and how a relative one would look (plausible, and wrong).
//
// WHERE THE NAMES COME FROM, which is what makes the view usable by somebody
// who has not memorised RFC 4120's ASN.1 module. The same ranges carry
// `fieldPath` — `AS-REQ → req-body → cname` — from
// common/krb5/krb5_field_names.js, and that is what the strip leads with. The
// encoding's own path (`[APPLICATION 10] → SEQUENCE → [4] → SEQUENCE → [1]`)
// is still shown, second, because it is what you need when comparing against a
// capture or a spec; it is no longer what you have to read first.
//
// BOTH HALVES LIGHT UP. Every byte has two cells — the hex pair and the
// character in the readable gutter — and both carry the same range, so
// hovering either lights both. That is not decoration: the gutter is where a
// realm, a principal name and the `krbtgt` of a TGT are legible, and until the
// gutter was per-byte cells you could see which bytes a field occupied and,
// one column over, not see which characters they were.
//
// WHAT IS COLOURED, AND WHY THAT AND NOT MORE. At rest each top-level SECTION —
// the direct children of the outermost element — gets its own tint, so the
// shape of the message is visible without touching anything. Colouring every
// element instead gives a rainbow in which nothing stands out, and a message
// ten levels deep has more nesting than a palette has distinct colours.
// Everything finer than that is on demand: hovering a byte lights the exact
// element that owns it and names it in the strip above, and clicking pins that
// so the mouse can leave.
// ---------------------------------------------------------------------------
var panes = require("./kerberos_panes.js");
var prim = require("./krb5_primitives.js");
var rangesMod = require("./krb5_ranges.js");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "kerberos_hex",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      // No CONFIG_FILE resolvable here — a node caller rather than a bundle.
      return "info";
    }
  })()
});

var el = panes.el;
var make = panes.make;
var clear = panes.clear;

// Sixteen is the width every hex dump has used since od(1), and it is not
// arbitrary here either: the offset column stays four digits for anything under
// 64KB, and 16 bytes plus an ASCII gutter fits the pane without the horizontal
// scroll docs/kerberos.md's one-screen budget is about.
var BYTES_PER_ROW = 16;

// How many section tints there are. A KDC message has a handful of top-level
// children; more than this and they repeat, which is better than inventing
// colours nobody can tell apart.
var SECTION_TINTS = 6;

function hex2(n) {
  log.debug("Entering hex2().");
  log.debug("Leaving hex2().");
  return (n < 16 ? "0" : "") + n.toString(16);
}

function hex4(n) {
  log.debug("Entering hex4().");
  var s = n.toString(16);
  while (s.length < 4) { s = "0" + s; }
  log.debug("Leaving hex4().");
  return s;
}

// The ASCII gutter. Anything outside printable ASCII is a dot — the usual
// convention, and the reason it is worth having at all: principal names, realms
// and the "krbtgt" in a TGT are readable there, which is often the quickest way
// to confirm you are looking at the message you think you are.
function printable(byte) {
  log.debug("Entering printable().");
  log.debug("Leaving printable().");
  return (byte >= 0x20 && byte < 0x7f) ? String.fromCharCode(byte) : ".";
}

// Which top-level section a byte is in, for the resting tint. Depth-1 elements
// are the direct children of the outermost one — for an AS-REQ that is pvno,
// msg-type, padata and req-body, which is exactly the division worth seeing.
function sectionIndexPerByte(mapped) {
  log.debug("Entering sectionIndexPerByte().");
  var section = new Array(mapped.total);
  var i;
  for (i = 0; i < mapped.total; i++) { section[i] = -1; }
  var n = 0;
  mapped.ranges.forEach(function (r) {
    if (r.depth !== 1) { return; }
    for (var k = r.start; k < r.end && k < section.length; k++) {
      section[k] = n % SECTION_TINTS;
    }
    n += 1;
  });
  log.debug("Leaving sectionIndexPerByte(). " + n + " section(s).");
  return section;
}

// ---------------------------------------------------------------------------
// Render the hex view of `bytes` into the element with id `hostId`.
//
// Safe to call with nothing: an empty host says so rather than rendering an
// empty grid, because a blank hex pane and a hex pane for a zero-byte message
// look identical and mean very different things.
// ---------------------------------------------------------------------------
function render(hostId, bytes, label) {
  log.debug("Entering render(). host=" + hostId);
  var host = el(hostId);
  if (!host) {
    log.debug("Leaving render(). No host " + hostId + ".");
    return null;
  }
  clear(host);
  if (!bytes) {
    host.appendChild(make("p", "krb-note",
        "Nothing yet — run the exchange and the bytes appear here."));
    log.debug("Leaving render(). No bytes.");
    return null;
  }

  var b = prim.toBytes(bytes);
  var mapped;
  try {
    mapped = rangesMod.rangesOf(b);
  } catch (e) {
    // The dump is still worth showing without the colouring: bytes that will
    // not parse are exactly the bytes somebody wants to look at.
    host.appendChild(make("p", "krb-note krb-bad",
        "These bytes do not map to ASN.1 elements (" + e.message +
        "), so they are shown uncoloured."));
    mapped = { total: b.length, ranges: [] };
  }
  var owner = rangesMod.ownerPerByte(mapped);
  var section = sectionIndexPerByte(mapped);
  var byIndex = {};
  mapped.ranges.forEach(function (r) { byIndex[r.index] = r; });

  // The strip that names whatever is under the pointer. Above the dump so it
  // does not move as the mouse travels — a caption that jumps is unreadable.
  // Two lines: what the field IS CALLED, then where it is and what it is made
  // of. The name is the top line because it is the answer — a reader pointing
  // at a byte wants "cname", and "offset 63, 20 bytes" is what they want
  // second. Both live in one box so the dump below never moves.
  var strip = make("div", "krb-hex-path");
  var fieldLine = make("div", "krb-hex-field");
  var metaLine = make("div", "krb-hex-meta");
  strip.appendChild(fieldLine);
  strip.appendChild(metaLine);
  host.appendChild(strip);

  var dump = make("div", "krb-hex-dump");
  var cells = [];
  var row;
  var gutter;
  for (var i = 0; i < b.length; i++) {
    if (i % BYTES_PER_ROW === 0) {
      row = make("div", "krb-hex-row");
      row.appendChild(make("span", "krb-hex-off", hex4(i)));
      // The gutter is opened with the row and filled beside it, because its
      // characters are now cells in their own right rather than one string —
      // see the note on wireHighlighting().
      gutter = make("span", "krb-hex-ascii");
      dump.appendChild(row);
    }
    var idx = owner[i];
    var cell = make("span", "krb-hex-b", hex2(b[i]));
    var ascii = make("span", "krb-hex-a", printable(b[i]));
    if (section[i] >= 0) {
      cell.className += " krb-hex-s" + section[i];
      ascii.className += " krb-hex-s" + section[i];
    }
    var r = byIndex[idx];
    if (r && i < r.headerEnd) {
      // The tag and length bytes. Marked because "these two bytes say what this
      // is and how long it runs" is the single most useful thing to be able to
      // see in a DER dump, and it is invisible otherwise. Only on the hex side:
      // the gutter is one character per byte and an underline there is noise.
      cell.className += " krb-hex-hdr";
    }
    cell.setAttribute("data-krb-range", String(idx));
    cell.setAttribute("data-krb-at", String(i));
    ascii.setAttribute("data-krb-range", String(idx));
    ascii.setAttribute("data-krb-at", String(i));
    row.appendChild(cell);
    gutter.appendChild(ascii);
    cells.push(cell);
    cells.push(ascii);
    if (i % BYTES_PER_ROW === BYTES_PER_ROW - 1 || i === b.length - 1) {
      // Pad so the gutter lines up on a short final row. The padding carries no
      // range: it stands for no byte, so it must never light up.
      var pad = BYTES_PER_ROW - 1 - (i % BYTES_PER_ROW);
      while (pad > 0) {
        gutter.appendChild(make("span", "krb-hex-a", " "));
        pad -= 1;
      }
      row.appendChild(gutter);
    }
  }
  host.appendChild(dump);

  wireHighlighting(host, fieldLine, metaLine, cells, byIndex, label, b.length);
  log.info("hex view for " + hostId + ": " + b.length + " bytes, " +
      mapped.ranges.length + " element(s)");
  log.debug("Leaving render().");
  return mapped;
}

// ---------------------------------------------------------------------------
// Hover names a field; click pins it.
//
// TWO CELLS LIGHT UP FOR EVERY BYTE, and that is the point of doing it this
// way. The gutter used to be one string per row, which meant the readable half
// of the dump — the half where a realm, a principal name or the `krbtgt` in a
// TGT is legible — could not take part: you could see WHICH bytes a field
// occupied and, one column over, could not see which characters they were.
// Each gutter character is now its own cell carrying the same range, so
// highlighting is one loop over both halves and hovering the TEXT works as
// well as hovering the hex.
//
// Wired ONCE per view on the container rather than per cell: a 1,500-byte
// message is 3,000 cells, and 6,000 listeners on a pane rebuilt on every
// exchange is how a page starts leaking. Delegation also means the cells can be
// replaced without rewiring.
// ---------------------------------------------------------------------------
function wireHighlighting(host, fieldLine, metaLine, cells, byIndex, label,
    total) {
  log.debug("Entering wireHighlighting().");
  var pinned = -1;

  // Set a line's text and its tooltip together. The lines are clipped to one
  // line each so the dump below them cannot move (see css/kerberos.css), which
  // means the `title` is where a long ASN.1 path actually goes.
  function line(node, text) {
    log.debug("Entering line().");
    node.textContent = text;
    node.title = text;
    log.debug("Leaving line().");
  }

  function rest() {
    log.debug("Entering rest().");
    // The resting name is the MESSAGE's own — the outermost element's field
    // name, which for anything this workflow sends or receives is what it is
    // called: AS-REQ, KRB-ERROR, Ticket. Falling back to the caller's label
    // keeps a pasted blob that maps to nothing from saying nothing.
    var root = byIndex[0];
    var name = (root && root.fieldPath) || label || "Bytes";
    line(fieldLine, name);
    line(metaLine, total + " byte" + (total === 1 ? "" : "s") +
        " — hover a byte to name its field, click to pin it. The readable " +
        "column on the right is the same bytes.");
    log.debug("Leaving rest().");
  }

  function show(r, pinnedNow) {
    log.debug("Entering show().");
    var length = r.end - r.start;
    // The RFC's name for it, which is the whole reason this line exists. An
    // element the field table does not recognise keeps the encoding's own path
    // rather than being left blank — blank reads as a bug in the view.
    line(fieldLine, r.fieldPath || r.path);
    line(metaLine,
        (r.structure ? r.structure + " — " : "") +
        r.tagName +
        " — offset " + r.start + " (0x" + hex4(r.start) + "), " +
        length + " byte" + (length === 1 ? "" : "s") +
        (r.headerEnd > r.start ? ", of which " + (r.headerEnd - r.start) +
            " are tag and length" : "") +
        (r.path !== r.fieldPath && r.fieldPath ? "   ·   " + r.path : "") +
        (r.note ? "   ·   " + r.note : "") +
        (pinnedNow ? "   ·   pinned; click it again to release" : ""));
    log.debug("Leaving show().");
  }

  function paint(index) {
    log.debug("Entering paint(). index=" + index);
    for (var i = 0; i < cells.length; i++) {
      var mine = cells[i].getAttribute("data-krb-range") === String(index);
      var on = cells[i].className.indexOf(" krb-hex-on") >= 0;
      if (mine && !on) {
        cells[i].className += " krb-hex-on";
      } else if (!mine && on) {
        cells[i].className = cells[i].className.replace(/ krb-hex-on/g, "");
      }
    }
    log.debug("Leaving paint().");
  }

  host.addEventListener("mouseover", function (event) {
    var cell = event.target;
    if (!cell || !cell.getAttribute) { return; }
    var idx = cell.getAttribute("data-krb-range");
    if (idx === null) { return; }
    if (pinned >= 0) { return; }
    var r = byIndex[Number(idx)];
    if (!r) { return; }
    paint(Number(idx));
    show(r, false);
  });

  host.addEventListener("mouseleave", function () {
    if (pinned >= 0) { return; }
    paint(-1);
    rest();
  });

  host.addEventListener("click", function (event) {
    var cell = event.target;
    if (!cell || !cell.getAttribute) { return; }
    var idx = cell.getAttribute("data-krb-range");
    if (idx === null) { return; }
    var n = Number(idx);
    if (pinned === n) {
      // Clicking the pinned field again releases it, which is the only way back
      // to hovering without reloading.
      pinned = -1;
      paint(-1);
      rest();
      log.debug("unpinned");
      return;
    }
    pinned = n;
    paint(n);
    var r = byIndex[n];
    if (r) {
      show(r, true);
    } else {
      rest();
    }
    log.debug("pinned range " + n);
  });

  rest();
  log.debug("Leaving wireHighlighting().");
}

module.exports = {
  render: render,
  BYTES_PER_ROW: BYTES_PER_ROW,
  SECTION_TINTS: SECTION_TINTS
};
