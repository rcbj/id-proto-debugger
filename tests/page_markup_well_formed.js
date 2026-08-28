// File: page_markup_well_formed.js
//
// ---------------------------------------------------------------------------
// EVERY PAGE'S ATTRIBUTE VALUES ARE CLOSED WHERE THEY LOOK CLOSED.
//
// A double-quoted attribute value ends at the NEXT double quote. So a title
// that quotes something —
//
//     title="The encrypted value. "As PBES2 JWE" writes a compact JWE here."
//
// — is not one attribute containing quotes. It is `title="The encrypted
// value. "` followed by three junk attribute names and an unterminated value
// that runs to whatever quote comes next. Nothing about it is a syntax error a
// browser will report; HTML has no such thing, and error recovery is a
// specified algorithm rather than a refusal.
//
// WHICH IS EXACTLY WHY THIS IS A SOURCE CHECK AND NOT A BROWSER ONE. Chrome's
// recovery on the file as authored happened to end the start tag in the right
// place and the page worked, locally, on every run of the containerized suite.
// The MINIFIER on the static build path made a different — equally legal —
// choice: it dropped the `</label>` and `</textarea>` around the affected
// field, so `<textarea id="enc_pbe_ciphertext">`'s raw-text content swallowed
// the whole of the next field and `enc_pbe_tag` DID NOT EXIST on the deployed
// site. AES-GCM then had no tag to verify, Decrypt refused, and the encryption
// job spent 150 seconds waiting for a box that was never going to fill. The
// failure named the box. Nothing named the page, the attribute, the minifier
// or the missing element, and the same test passed against a local stack.
//
// So: two implementations of one recovery algorithm disagree, and a page that
// depends on which one it met is a page that behaves differently deployed than
// it does in the suite. That is the defect this file makes impossible to ship
// rather than the minifier's behaviour, which is within its rights.
//
// The check is deliberately narrow. It does not validate HTML — it finds the
// one construct that has cost a run — and it reports the file, the line and
// the attribute, which is the whole of what somebody needs.
//
// No browser and no services: node only, so it never skips on a stack that is
// not up.
// ---------------------------------------------------------------------------
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { Command, Option } = require("commander");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "page_markup_well_formed",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

// Every page this project serves. `client/public` is the whole of it — the
// partials included, since a header or a footer with a broken attribute breaks
// every page that includes it.
const PUBLIC_DIR = path.join(__dirname, "..", "client", "public");

// This test reads sources, so it needs the checkout. The tests image stages
// individual modules flat and carries no client/public at all; say so rather
// than reporting an empty sweep as a pass. Same reasoning, same shape, as
// isCheckout() in tests/xml_parse_inert.js.
function isCheckout() {
  log.debug("Entering isCheckout().");
  const present = fs.existsSync(PUBLIC_DIR);
  log.debug("Leaving isCheckout(). " + PUBLIC_DIR + " present=" + present);
  return present;
}

function htmlFilesUnder(dir) {
  log.debug("Entering htmlFilesUnder(). " + dir);
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push.apply(out, htmlFilesUnder(full));
      continue;
    }
    if (/\.html$/.test(entry.name)) {
      out.push(full);
    }
  }
  log.debug("Leaving htmlFilesUnder(). " + out.length + " file(s).");
  return out;
}

// THE TWO SHAPES THIS HAS TAKEN, both found in this tree.
//
// The first is a double-quoted value, closed, and then more non-space text on
// the same tag that ends in another quote before any `<` or `>`. That is the
// signature of a value that was MEANT to contain the quotes: `a="x "y" z"`
// matches, and a legitimate pair of adjacent attributes (`a="x" b="y"`) does
// not, because the second quote there is preceded by `b=`. The `[^\s=<>/]`
// after the closing quote is what makes that distinction: a real next
// attribute is separated by whitespace, and this construct is not.
//
// The second is a quote on its own where an attribute name should start.
const PATTERNS = [
  {
    id: "an unescaped quote inside an attribute value",
    fix: "write the inner quotes as &quot;",
    re: new RegExp(
      "\\s([a-zA-Z_:][-a-zA-Z0-9_:.]*)=\"([^\"<>]*)\"([^\\s=<>/][^<>]*?)\"",
      "g")
  },
  {
    // The other half, and the one the pattern above cannot see because there
    // is no attribute NAME in front of it: a quote sitting where the next
    // attribute should start. `value="Regenerate" onclick="…();" "/>` — two
    // of these were in oauth2_oidc_1.html, and html-minifier-terser refuses
    // the whole file over them.
    id: "a stray quote where an attribute name should be",
    fix: "delete it",
    re: new RegExp("<[a-zA-Z][^<>]*?\\s(\")\\s*/?>", "g")
  }
];

function everyAttributeValueIsClosed() {
  log.debug("Entering everyAttributeValueIsClosed().");
  const files = htmlFilesUnder(PUBLIC_DIR);
  assert.ok(files.length > 10,
    "Only " + files.length + " HTML file(s) found under " + PUBLIC_DIR +
    ". This project serves dozens of pages, so a sweep this small is a " +
    "broken path rather than a clean tree — and a broken path reports a " +
    "pass.");
  const findings = [];
  for (const file of files) {
    const source = fs.readFileSync(file, "utf8");
    for (const pattern of PATTERNS) {
      pattern.re.lastIndex = 0;
      let match;
      while ((match = pattern.re.exec(source)) !== null) {
        const line = source.slice(0, match.index).split("\n").length;
        findings.push(path.relative(PUBLIC_DIR, file) + ":" + line + ": " +
          pattern.id + " (" + pattern.fix + ") — " +
          match[0].trim().slice(0, 120));
      }
    }
  }
  assert.deepStrictEqual(findings, [],
    "These tags do not mean what they look like they mean:\n  " +
    findings.join("\n  ") + "\n" +
    "A browser will recover from each of them and the page will usually " +
    "work; the static build's MINIFIER recovers differently — it has dropped " +
    "the closing tags around such a field, deleting an element the page's " +
    "own code needs, and it refuses a whole file over the second pattern. " +
    "See the header of this file.");
  log.info("OK — " + files.length + " page(s), no tag whose attributes are " +
    "parsed differently from the way they are written.");
  log.debug("Leaving everyAttributeValueIsClosed().");
}

// The other half of the same class, and the one a regex over attributes cannot
// see: an element the page's JavaScript addresses by id that no page defines.
// The encryption page's `enc_pbe_tag` was exactly this after the minifier ran —
// present in the source, absent from what was served — so the source check
// above would not have caught the DEPLOYED symptom on its own. What this can
// assert without a browser is the source side of the contract: every id a
// client module reads is authored somewhere in client/public.
//
// DELIBERATELY LIMITED TO THE ENCRYPTION PAGE'S PANES for now, because a sweep
// of every getElementById in client/src turns up ids built at runtime and ids
// belonging to elements the page creates itself, and a check with exceptions
// in it is a check somebody adds an exception to. These are the fields the
// encryption engines write their results into, they are all authored
// statically, and a missing one is silent in exactly the way that cost the run.
const ENCRYPTION_FIELDS = [
  "aes", "cc", "des", "rsa", "ecc", "kem", "ffc", "jwe", "pbe"
];

function everyEncryptionPaneHasItsFields() {
  log.debug("Entering everyEncryptionPaneHasItsFields().");
  const file = path.join(PUBLIC_DIR, "encryption_tools.html");
  const source = fs.readFileSync(file, "utf8");
  const missing = [];
  for (const prefix of ENCRYPTION_FIELDS) {
    for (const suffix of ["status", "plaintext", "ciphertext"]) {
      const id = "enc_" + prefix + "_" + suffix;
      if (source.indexOf("id=\"" + id + "\"") === -1) {
        missing.push(id);
      }
    }
  }
  assert.deepStrictEqual(missing, [],
    "encryption_tools.html does not author: " + missing.join(", ") + ". " +
    "Every pane on that page writes its outcome to a status line and its " +
    "result to a plaintext and a ciphertext box, and the engines address all " +
    "three by id.");
  // The tag boxes, which only the AEAD panes have — and which is the field
  // that went missing. Named individually rather than swept, so that removing
  // one deliberately is an edit here rather than a silent shrinking of the
  // list.
  const tagged = ["aes", "cc", "des", "pbe"];
  const missingTags = tagged.filter(function (prefix) {
    return source.indexOf("id=\"enc_" + prefix + "_tag\"") === -1;
  });
  assert.deepStrictEqual(missingTags, [],
    "encryption_tools.html does not author a tag box for: " +
    missingTags.join(", ") + ". An AEAD needs its tag to verify, and a pane " +
    "without that box refuses every decryption with \"this one is 0 bytes\" " +
    "— which reads as a bad ciphertext rather than as a missing element.");
  log.info("OK — every encryption pane authors its status, plaintext, " +
    "ciphertext and (where it is an AEAD) tag box.");
  log.debug("Leaving everyEncryptionPaneHasItsFields().");
}

async function test() {
  log.debug("Entering test().");
  if (!isCheckout()) {
    log.info("SKIPPED — there is no client/public in this layout, so this " +
      "is the tests image rather than a checkout; this check reads the " +
      "authored pages, which are only present in a checkout.");
    log.debug("Leaving test(). Not a checkout.");
    return;
  }
  everyAttributeValueIsClosed();
  everyEncryptionPaneHasItsFields();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("page_markup_well_formed")
  .description("Verify that no authored page closes an attribute value " +
      "early, which is what makes the static build's minifier drop the tags " +
      "around it.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
