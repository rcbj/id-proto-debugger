// File: xml_parse_inert.js
//
// The invariant behind CodeQL alert #147 and its eleven siblings
// (js/xss-through-dom, "DOM text reinterpreted as HTML").
//
// Those alerts all point at the same construct: text the user typed into a
// textarea is handed to `new DOMParser().parseFromString(xml,
// 'application/xml')` — in xmldsig.js, saml_request.js, saml_tools.js,
// wstrust_tools.js, wstrust_response.js and wsfed_response.js. CodeQL's sink
// model for parseFromString does not distinguish the MIME type, so an XML parse
// is reported exactly as an HTML parse would be.
//
// As written they are not exploitable, and the reason is worth stating
// precisely because it is also the thing this test keeps true:
//
//   1. `application/xml` parsing has no script semantics. The result is a
//      SEPARATE XMLDocument — not the page — and a <script> element in it is
//      just an element. ("Detached" would be the wrong word: the parsed root is
//      connected, to its own document. What matters is which document.)
//      (Sanitizing the input instead would be the wrong fix twice over: it
//      would not change this, and XML-DSIG signs the exact octets that get
//      canonicalized, so rewriting them invalidates the signature being made.)
//   2. Nothing puts that document into the live page. The parsed tree is
//      canonicalized or serialized back to a STRING, and the string lands in a
//      <textarea> through `.value` — not an HTML sink.
//   3. Where XML-derived values ARE rendered as HTML (the response pages'
//      detail tables), each one goes through esc()/xmlEscape() first.
//
// Point 1 is a property of the platform. Points 2 and 3 are properties of this
// code, and could be broken by a future edit — at which point the alerts would
// become true and nobody would notice, because they are already there. So this
// test asserts them:
//
//   * every DOMParser call in client/src asks for 'application/xml';
//   * the shared XML engine contains no HTML sink at all;
//   * no XML module inserts a parsed node into the LIVE document.
//
// No browser and no services: node only, so it never skips.
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { Command, Option } = require("commander");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "xml_parse_inert",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

const SRC_DIR = path.join(__dirname, "..", "client", "src");

// "That directory exists" is not "this is a checkout", and the difference is
// what this test skips on. The tests image stages most borrowed modules FLAT
// beside the scripts, but it also mirrors a handful of Kerberos bundles into
// /usr/src/client/src, because the two Kerberos pane tests resolve their files
// as ../client/src (tests/Dockerfile). So SRC_DIR is present in the image and
// holds eleven modules, none of which parses XML — the whole sweep below then
// ran over the mirror and failed with "found no parseFromString calls at all",
// which reads as the XML pages having moved rather than as the layout it is.
//
// client/package.json is what separates the two: it is outside client/src
// entirely, so no mirror of that directory can ever contain it, and a checkout
// cannot lack it. Ask for a file only a checkout has, never for the directory.
function isCheckout() {
  log.debug("Entering isCheckout().");
  const manifest = path.join(__dirname, "..", "client", "package.json");
  const present = fs.existsSync(manifest);
  log.debug("Leaving isCheckout(). " + manifest + " present=" + present);
  return present;
}

// The shared XML/crypto engine. It is the module every XML page reaches for, so
// an HTML sink appearing HERE would be reachable from all of them at once.
const XML_ENGINE = "xmldsig.js";

// Writing markup, as opposed to writing text.
const HTML_SINKS = [
  { pattern: /\.innerHTML\s*=/, name: "innerHTML" },
  { pattern: /\.outerHTML\s*=/, name: "outerHTML" },
  { pattern: /insertAdjacentHTML\s*\(/, name: "insertAdjacentHTML" },
  { pattern: /document\.write(ln)?\s*\(/, name: "document.write" },
  { pattern: /\$\([^)]*\)\s*\.html\s*\(/, name: "jQuery .html()" }
];

// Bringing a node from ANOTHER document into this one. These two APIs are the
// only way a node from the parsed XMLDocument becomes part of the live page,
// and naming them is what makes this check precise.
//
// Deliberately NOT listed: `document.body.appendChild(...)`. These pages append
// locally-created elements as a matter of course — a temporary <a> for a file
// download, the auto-submitting POST form — and none of those nodes came from a
// parse. Flagging the call by name would report five such sites as adoptions of
// parsed XML, which they are not. Provenance is not something a regular
// expression can follow, so this check does not pretend to: it covers the two
// adoption APIs exactly, and the general property is carried by the other two
// checks (nothing renders XML as markup, and the engine writes no markup at
// all). Note `doc.importNode(...)` — a method on the PARSED document — is
// legitimate and common here when assembling a <ds:Signature>; it is
// `document.importNode`, on the live global, that would be the problem.
const LIVE_DOM_ADOPTIONS = [
  { pattern: /(^|[^.\w])document\.importNode\s*\(/,
   name: "document.importNode" },
  { pattern: /(^|[^.\w])document\.adoptNode\s*\(/, name: "document.adoptNode" }
];

function sourceFiles() {
  log.debug("Entering sourceFiles().");
  const files = [];
  (function walk(dir) {
    fs.readdirSync(dir, { withFileTypes: true }).forEach(function (entry) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (/\.js$/.test(entry.name)) {
        files.push(full);
      }
    });
  })(SRC_DIR);
  log.debug("Leaving sourceFiles().");
  return files;
}

// A line that is only a comment is not code. The reasoning about these sinks
// lives in comments throughout these files, and quoting a sink while explaining
// why it is not used must not read as using one. Bracket depth of a fragment,
// with string literals removed first so a quoted bracket cannot skew it.
// Approximate by design — this is a source scan, and the only thing it decides
// is how many lines to read as one statement. Only the brackets that continue
// an EXPRESSION count: an open `{` starts a block, and reading on through a
// block would join this statement to whatever comes next.
function bracketDepth(text) {
  log.debug("Entering bracketDepth().");
  const bare = text.replace(/(["'`])(?:\\.|(?!\1)[^\\])*\1/g, "");
  let depth = 0;
  for (const ch of bare) {
    if (ch === "(" || ch === "[") depth += 1;
    if (ch === ")" || ch === "]") depth -= 1;
  }
  log.debug("Leaving bracketDepth().");
  return depth;
}

function codeLines(text) {
  log.debug("Entering codeLines().");
  const raw = text.split("\n").map(function (line, index) {
    return { number: index + 1, text: line };
  }).filter(function (line) {
    return !/^\s*(\/\/|\*|\/\*)/.test(line.text);
  });
  // Each entry carries its CONTINUATION lines too, joined into one string,
  // because these checks are about a statement and not about a line. A call
  // wrapped to stay inside 80 columns is still one call — parseFromString(x,
  // 'application/xml') states its MIME type just as plainly across two lines —
  // and a check that reads one line at a time silently stops working the day
  // somebody reformats the file. That is not hypothetical: the 80-column sweep
  // wrapped nine of these calls at once, and this check then reported every one
  // of them as a parse with no literal MIME type.
  const CONTINUES = /[,+&|=.([?:]\s*$/;
  log.debug("Leaving codeLines().");
  return raw.map(function (line, i) {
    let text = line.text;
    let k = i;
    while (k + 1 < raw.length && k - i < 6 &&
           (bracketDepth(text) > 0 || CONTINUES.test(text))) {
      k += 1;
      text += " " + raw[k].text.trim();
    }
    return { number: line.number, text: text };
  });
}


// --- 1. every parse is an XML parse -----------------------------------------

function everyParseIsXml() {
  log.debug("Entering everyParseIsXml().");
  log.info("[mime] Every DOMParser call must ask for application/xml.");
  let parseCalls = 0;
  const offences = [];
  sourceFiles().forEach(function (file) {
    codeLines(fs.readFileSync(file, "utf8")).forEach(function (line) {
      if (!/parseFromString\s*\(/.test(line.text)) return;
      parseCalls++;
      // The MIME type is the second argument. Accept the XML family; refuse
      // text/html outright, and refuse a call whose type cannot be read as a
      // literal (a variable could be anything at runtime).
      if (/parseFromString\s*\([^;]*?,\s*['"](application\/xml|text\/xml|application\/xhtml\+xml|image\/svg\+xml)['"]\s*\)/.test(line.text)) {
        return;
      }
      offences.push(path.relative(SRC_DIR, file) + ":" + line.number + "  " +
                    line.text.trim().slice(0, 110));
    });
  });
  assert.ok(parseCalls > 0,
            "found no parseFromString calls at all — has client/src moved?");
  assert.deepStrictEqual(offences, [],
    "these DOMParser calls do not parse as XML with a literal MIME type. " +
        "Parsing caller-supplied\n" +
    "text as text/html IS the vulnerability CodeQL js/xss-through-dom " +
        "describes:\n  " +
    offences.join("\n  "));
  log.info("[mime] OK — all " + parseCalls +
           " parseFromString calls use a literal XML MIME type.");
  log.debug("Leaving everyParseIsXml().");
}


// --- 2. the shared engine writes no markup ----------------------------------

function xmlEngineHasNoHtmlSink() {
  log.debug("Entering xmlEngineHasNoHtmlSink().");
  log.info("[engine] " + XML_ENGINE + " must contain no HTML sink.");
  const file = path.join(SRC_DIR, XML_ENGINE);
  assert.ok(fs.existsSync(file), XML_ENGINE +
            " is missing — this test needs updating.");
  const offences = [];
  codeLines(fs.readFileSync(file, "utf8")).forEach(function (line) {
    HTML_SINKS.forEach(function (sink) {
      if (sink.pattern.test(line.text)) {
        offences.push(XML_ENGINE + ":" + line.number + " uses " + sink.name +
                      " — " + line.text.trim().slice(0, 90));
      }
    });
  });
  assert.deepStrictEqual(offences, [],
    XML_ENGINE + " is the module that parses caller-supplied XML. It must " +
        "not also write markup:\n" +
    "that combination is what would turn CodeQL's js/xss-through-dom reports " +
        "on this file from a\n" +
    "modelling artefact into a real finding. Render through " +
        "esc()/xmlEscape() in the page instead.\n  " +
    offences.join("\n  "));
  log.info("[engine] OK — no innerHTML / outerHTML / insertAdjacentHTML / " +
           "document.write / .html().");
  log.debug("Leaving xmlEngineHasNoHtmlSink().");
}


// --- 3. a parsed document never reaches the live page -----------------------

function parsedNodesStayDetached() {
  log.debug("Entering parsedNodesStayDetached().");
  log.info("[detached] No XML module may adopt a parsed node into the live " +
           "document.");
  const offences = [];
  let xmlModules = 0;
  sourceFiles().forEach(function (file) {
    const text = fs.readFileSync(file, "utf8");
    if (!/parseFromString\s*\(/.test(text)) return;
    xmlModules++;
    codeLines(text).forEach(function (line) {
      LIVE_DOM_ADOPTIONS.forEach(function (sink) {
        if (sink.pattern.test(line.text)) {
          offences.push(path.relative(SRC_DIR, file) + ":" + line.number +
                        " uses " + sink.name +
                        " — " + line.text.trim().slice(0, 90));
        }
      });
    });
  });
  assert.ok(xmlModules > 0,
            "found no modules that parse XML — has client/src moved?");
  assert.deepStrictEqual(offences, [],
    "a module that parses caller-supplied XML also adopts nodes into the " +
        "live document. An inert\n" +
    "XMLDocument stops being inert the moment its nodes are adopted into the " +
        "page:\n  " +
    offences.join("\n  "));
  log.info("[detached] OK — " + xmlModules +
           " modules parse XML, none call document.importNode/adoptNode.");
  log.debug("Leaving parsedNodesStayDetached().");
}


async function test() {
  log.debug("Entering test().");
  // This test reads sources rather than running anything, so it needs the
  // checkout. The tests image stages individual modules flat and carries only a
  // PARTIAL mirror of client/src; say so rather than sweeping that mirror and
  // reporting either a silent pass or an absence that reads as a moved page.
  if (!isCheckout()) {
    log.info("SKIPPED — no client/package.json in this layout, so this is " +
             "the tests image (which carries only a partial mirror of " +
             "client/src) rather than a checkout; this check runs in a " +
             "checkout, where the sources are present.");
    log.debug("Leaving test().");
    return;
  }
  everyParseIsXml();
  xmlEngineHasNoHtmlSink();
  parsedNodesStayDetached();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("xml_parse_inert")
  .description("Verify that caller-supplied XML is parsed inertly and never " +
      "rendered as markup.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
