// File: rfc9068.js
//
// ---------------------------------------------------------------------------
// RFC 9068 (JWT Profile for OAuth 2.0 Access Tokens), driven in node
// with no browser and no network. The rules under test are the
// resource server's reading of a token this debugger already holds:
//
//   * typ accepts "at+jwt" and "application/at+jwt" in any case
//   * groups, roles and entitlements are optional and, when present,
//     follow the multi-valued shape in RFC 7643 section 4.1.2
//   * auth_time, acr and amr stay the same across a later token
//   * the resource that was sent is the aud to compare, and the token
//     request's resource wins when that request included one
//
// A provider's behaviour is not an input and not a pass condition.
//
// NOTE ON OPTIONS: run-report.js spawns every job as
// `node <script>.js --url <BASE_URL>`. This job parses no arguments, so
// node ignores that pair. Do not add commander here without declaring
// `--url`.
// ---------------------------------------------------------------------------
const assert = require("assert");
const fs = require("fs");
const path = require("path");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "rfc9068",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      return "info";
    }
  })()
});
log.info("Log initialized. logLevel=" + log.level());

// In a checkout the sources are beside tests/. In the tests image they are
// the complete copy tests/Dockerfile stages at /usr/src/source-tree, which is
// ../source-tree from /usr/src/app (the image's ../client/src is a partial
// mirror). The first candidate holding client/package.json wins.
function repoRoot() {
  log.debug("Entering repoRoot().");
  var candidates = [path.resolve(__dirname, ".."),
                    path.resolve(__dirname, "..", "source-tree")];
  var i;
  for (i = 0; i < candidates.length; i++) {
    if (fs.existsSync(path.join(candidates[i], "client", "package.json"))) {
      log.debug("Leaving repoRoot(). " + candidates[i]);
      return candidates[i];
    }
  }
  log.debug("Leaving repoRoot(). None found.");
  return candidates[0];
}

const REPO = repoRoot();
const SRC = path.join(REPO, "client", "src");
const PUBLIC = path.join(REPO, "client", "public");
const paths = require("./module_paths.js");
const rfc9068 = paths.requireSharedModule(
    [path.join(SRC, "rfc9068.js")],
    "client/src/rfc9068.js");

function row(rows, claim) {
  log.debug("Entering row().");
  var found = null;
  var i;
  for (i = 0; i < rows.length; i++) {
    if (rows[i].claim === claim) found = rows[i];
  }
  log.debug("Leaving row().");
  return found;
}

function typAcceptance() {
  log.debug("Entering typAcceptance().");
  var accepted = ["at+jwt", "at+JWT", "AT+JWT",
      "application/at+jwt", "application/at+JWT",
      "APPLICATION/AT+JWT"];
  var i;
  for (i = 0; i < accepted.length; i++) {
    assert.strictEqual(rfc9068.typAccepted(accepted[i]), true,
        accepted[i]);
    assert.strictEqual(rfc9068.typFinding(accepted[i]).level, "pass",
        accepted[i]);
  }
  var rejected = ["JWT", "at+JWT ", " at+jwt", "", null, 1];
  for (i = 0; i < rejected.length; i++) {
    assert.strictEqual(rfc9068.typAccepted(rejected[i]), false,
        String(rejected[i]));
    assert.strictEqual(rfc9068.typFinding(rejected[i]).level, "fail",
        String(rejected[i]));
  }
  assert.strictEqual(rfc9068.typFinding(undefined).level, "fail");
  log.info("OK — typ accepts the profile's media type in any case.");
  log.debug("Leaving typAcceptance().");
}

// Section 4 puts the signature first. A report that did not verify it
// says so, and a clean report then does not read as an accepted token.
function signatureIsNeverSilent() {
  log.debug("Entering signatureIsNeverSilent().");
  var skipped = rfc9068.signatureNotVerifiedFinding();
  assert.strictEqual(skipped.level, "skip");
  assert.strictEqual(skipped.claim, "signature");
  assert.ok(/^SKIP  signature: /.test(rfc9068.formatFinding(skipped)));
  assert.strictEqual(rfc9068.summaryLine(0, true), "All checks passed.");
  assert.ok(rfc9068.summaryLine(0, false).indexOf("not verified") > 0,
      "a clean report without a signature reads as accepted");
  assert.strictEqual(rfc9068.summaryLine(2, false), "2 check(s) failed.");
  var detail = fs.readFileSync(
      path.join(SRC, "token_detail.js"), "utf8");
  var tools = fs.readFileSync(
      path.join(SRC, "jwt_tools.js"), "utf8");
  assert.ok(detail.indexOf("signatureNotVerifiedFinding") >= 0 &&
      detail.indexOf("summaryLine") >= 0,
      "token detail reports a clean run without the signature");
  assert.ok(tools.indexOf("signatureNotVerifiedFinding") >= 0,
      "JWT Tools omits the signature row when it did not verify");
  log.info("OK — a report that skipped the signature says so.");
  log.debug("Leaving signatureIsNeverSilent().");
}

function authorizationClaims() {
  log.debug("Entering authorizationClaims().");
  var absent = rfc9068.checkAuthorizationClaims({});
  assert.strictEqual(row(absent, "groups").level, "skip");
  assert.strictEqual(row(absent, "roles").level, "skip");
  assert.strictEqual(row(absent, "entitlements").level, "skip");

  var strings = rfc9068.checkAuthorizationClaim("groups",
      ["admins", ""]);
  assert.strictEqual(strings.level, "pass");
  assert.strictEqual(strings.message, "2 value(s)");

  var empty = rfc9068.checkAuthorizationClaim("roles", []);
  assert.strictEqual(empty.level, "pass");
  assert.strictEqual(empty.message, "0 value(s)");

  var scim = rfc9068.checkAuthorizationClaim("entitlements",
      [{ value: "read" }, { value: "write", display: "Write" }]);
  assert.strictEqual(scim.level, "pass");

  var missingValue = rfc9068.checkAuthorizationClaim("groups",
      [{ display: "Admins" }]);
  assert.strictEqual(missingValue.level, "fail");

  var scalar = rfc9068.checkAuthorizationClaim("groups", "admins");
  assert.strictEqual(scalar.level, "fail");
  log.info("OK — authorization claims follow the SCIM multi-value " +
      "shape, and absence is a skip.");
  log.debug("Leaving authorizationClaims().");
}

function authenticationContext() {
  log.debug("Entering authenticationContext().");
  var same = {
    auth_time: 1600000000,
    acr: "urn:mace:incommon:iap:silver",
    amr: ["pwd", "otp"]
  };
  var matched = rfc9068.compareAuthenticationContext(same, same);
  assert.strictEqual(row(matched, "auth_time").level, "pass");
  assert.strictEqual(row(matched, "acr").level, "pass");
  assert.strictEqual(row(matched, "amr").level, "pass");

  var bothGone = rfc9068.compareAuthenticationContext({}, {});
  assert.strictEqual(row(bothGone, "auth_time").level, "pass");
  assert.strictEqual(row(bothGone, "acr").level, "pass");
  assert.strictEqual(row(bothGone, "amr").level, "pass");
  assert.ok(row(bothGone, "auth_time").message.indexOf("Absent") >= 0);

  var oneSide = rfc9068.compareAuthenticationContext(
      { auth_time: 1600000000 }, {});
  assert.strictEqual(row(oneSide, "auth_time").level, "fail");
  assert.strictEqual(row(oneSide, "acr").level, "pass");

  var reordered = rfc9068.compareAuthenticationContext(
      { amr: ["otp", "pwd"] }, { amr: ["pwd", "otp"] });
  assert.strictEqual(row(reordered, "amr").level, "fail");

  var changed = rfc9068.compareAuthenticationContext(
      { acr: "1" }, { acr: "2" });
  assert.strictEqual(row(changed, "acr").level, "fail");
  log.info("OK — authentication context stays fixed, and absence on " +
      "both sides is the same value.");
  log.debug("Leaving authenticationContext().");
}

function resourceSelection() {
  log.debug("Entering resourceSelection().");
  var tokenWins = rfc9068.requestedResource(
      { sent: true, value: "https://authz.example" },
      { sent: true, value: " https://token.example " });
  assert.strictEqual(tokenWins, "https://token.example");

  var authzFallback = rfc9068.requestedResource(
      { sent: true, value: "https://authz.example" },
      { sent: false, value: "https://token.example" });
  assert.strictEqual(authzFallback, "https://authz.example");

  var blankTokenFallsThrough = rfc9068.requestedResource(
      { sent: true, value: "https://authz.example" },
      { sent: true, value: "  " });
  assert.strictEqual(blankTokenFallsThrough, "https://authz.example");

  var neither = rfc9068.requestedResource(
      { sent: false, value: "https://authz.example" },
      { sent: false, value: "https://token.example" });
  assert.strictEqual(neither, null);

  var unsent = rfc9068.requestedResource(
      { sent: false, value: "" },
      { sent: false, value: "" });
  assert.strictEqual(unsent, null);
  log.info("OK — the resource that was sent is the one aud follows.");
  log.debug("Leaving resourceSelection().");
}

function workflowComparison() {
  log.debug("Entering workflowComparison().");
  var payload = {
    iss: "https://as.example",
    client_id: "app",
    aud: ["https://api.example", "https://other.example"]
  };
  var rows = rfc9068.checkWorkflow(payload, {
    issuer: "https://as.example",
    clientId: "app",
    resource: "https://api.example"
  });
  assert.strictEqual(row(rows, "iss/workflow").level, "pass");
  assert.strictEqual(row(rows, "client_id/workflow").level, "pass");
  assert.strictEqual(row(rows, "aud/resource").level, "pass");

  var stringAud = rfc9068.checkWorkflow({
    iss: "https://as.example",
    client_id: "app",
    aud: "https://api.example"
  }, {
    issuer: "https://as.example",
    clientId: "other",
    resource: "https://api.example"
  });
  assert.strictEqual(row(stringAud, "aud/resource").level, "pass");
  assert.strictEqual(row(stringAud, "client_id/workflow").level, "fail");

  var missed = rfc9068.checkWorkflow(payload, {
    issuer: "https://other.example",
    clientId: "",
    resource: "https://missing.example"
  });
  assert.strictEqual(row(missed, "iss/workflow").level, "fail");
  assert.strictEqual(row(missed, "client_id/workflow").level, "skip");
  assert.strictEqual(row(missed, "aud/resource").level, "fail");

  var noResource = rfc9068.checkWorkflow(payload, {
    issuer: "",
    clientId: "app",
    resource: null
  });
  assert.strictEqual(row(noResource, "iss/workflow").level, "skip");
  assert.strictEqual(row(noResource, "aud/resource").level, "skip");
  assert.ok(row(noResource, "aud/resource").message
      .indexOf("No resource parameter was sent") >= 0);
  log.info("OK — iss, client_id and aud compare against the facts " +
      "the page supplies.");
  log.debug("Leaving workflowComparison().");
}

function compactRoundTrip() {
  log.debug("Entering compactRoundTrip().");
  function seg(obj) {
    log.debug("Entering seg().");
    var text = Buffer.from(JSON.stringify(obj)).toString("base64")
        .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    log.debug("Leaving seg().");
    return text;
  }
  var token = seg({ alg: "RS256", typ: "at+JWT" }) + "." +
      seg({ iss: "https://as.example", aud: "https://api.example" }) +
      ".";
  assert.strictEqual(rfc9068.segmentCount(token), 3);
  assert.strictEqual(rfc9068.segmentCount("a.b.c.d.e"), 5);
  assert.strictEqual(rfc9068.segmentCount(""), 0);
  var decoded = rfc9068.decodeCompact(token);
  assert.strictEqual(decoded.header.typ, "at+JWT");
  assert.strictEqual(decoded.payload.iss, "https://as.example");
  assert.strictEqual(rfc9068.decodeCompact("a.b.c.d.e"), null);
  assert.strictEqual(rfc9068.formatFinding(
      rfc9068.typFinding("at+JWT")).indexOf("PASS  typ:"), 0);
  log.info("OK — a compact JWS decodes, and a JWE does not.");
  log.debug("Leaving compactRoundTrip().");
}

function codeLines(source) {
  log.debug("Entering codeLines().");
  var text = source.replace(/\/\*[\s\S]*?\*\//g, "")
      .split("\n").filter(function (line) {
        return !/^\s*\/\//.test(line);
      }).join("\n");
  log.debug("Leaving codeLines().");
  return text;
}

function theEngineReachesNoDom() {
  log.debug("Entering theEngineReachesNoDom().");
  var source = fs.readFileSync(path.join(SRC, "rfc9068.js"), "utf8");
  var code = codeLines(source);
  var forbidden = ["document", "window", "localStorage",
      "sessionStorage", "jQuery", "DOMPurify", "innerHTML"];
  var i;
  for (i = 0; i < forbidden.length; i++) {
    assert.ok(code.indexOf(forbidden[i]) < 0,
        "client/src/rfc9068.js reaches " + forbidden[i]);
  }
  log.info("OK — the engine reaches no DOM.");
  log.debug("Leaving theEngineReachesNoDom().");
}

function tagFor(html, id) {
  log.debug("Entering tagFor().");
  var at = html.indexOf('id="' + id + '"');
  assert.ok(at >= 0, id + " is missing");
  var start = html.lastIndexOf("<", at);
  var end = html.indexOf(">", at);
  var tag = html.slice(start, end + 1);
  log.debug("Leaving tagFor().");
  return tag;
}

function thePagesCallTheEngine() {
  log.debug("Entering thePagesCallTheEngine().");
  var detail = fs.readFileSync(
      path.join(SRC, "token_detail.js"), "utf8");
  var tools = fs.readFileSync(
      path.join(SRC, "jwt_tools.js"), "utf8");
  var detailHtml = fs.readFileSync(
      path.join(PUBLIC, "token_detail.html"), "utf8");
  var toolsHtml = fs.readFileSync(
      path.join(PUBLIC, "jwt_tools.html"), "utf8");
  assert.ok(detail.indexOf('require("./rfc9068")') >= 0,
      "token detail does not load the engine");
  assert.ok(tools.indexOf('require("./rfc9068")') >= 0,
      "JWT Tools does not load the engine");
  assert.ok(detail.indexOf("typFinding") >= 0,
      "token detail still has its own typ rule");
  assert.ok(tools.indexOf("typFinding") >= 0,
      "JWT Tools still has its own typ rule");
  assert.ok(tools.indexOf("header.typ === 'at+jwt'") < 0,
      "JWT Tools still compares typ in one case only");
  var detailIds = ["rfc9068_select_on_access", "rfc9068_workflow",
      "rfc9068_verify", "rfc9068_decrypt", "rfc9068_authz_claims",
      "rfc9068_auth_context", "rfc9068_decryption_key"];
  var toolIds = ["jwt_rfc9068_verify", "jwt_rfc9068_decrypt",
      "jwt_rfc9068_workflow", "jwt_rfc9068_authz_claims",
      "jwt_rfc9068_auth_context"];
  var i;
  for (i = 0; i < detailIds.length; i++) {
    var detailTag = tagFor(detailHtml, detailIds[i]);
    assert.ok(detailTag.indexOf("checked") < 0,
        detailIds[i] + " ships checked");
  }
  for (i = 0; i < toolIds.length; i++) {
    var toolTag = tagFor(toolsHtml, toolIds[i]);
    assert.ok(toolTag.indexOf("checked") < 0,
        toolIds[i] + " ships checked");
  }
  var keyTag = tagFor(detailHtml, "rfc9068_decryption_key");
  assert.ok(keyTag.indexOf("stored") < 0,
      "the decryption key is marked stored");
  assert.ok(detail.indexOf('setItem("rfc9068_decryption_key"') < 0 &&
      detail.indexOf("setItem('rfc9068_decryption_key'") < 0,
      "the decryption key is written to storage");
  log.info("OK — both pages call the engine, and every new checkbox " +
      "ships clear.");
  log.debug("Leaving thePagesCallTheEngine().");
}

function test() {
  log.debug("Entering test().");
  log.info("Starting Test run.");
  typAcceptance();
  signatureIsNeverSilent();
  authorizationClaims();
  authenticationContext();
  resourceSelection();
  workflowComparison();
  compactRoundTrip();
  theEngineReachesNoDom();
  thePagesCallTheEngine();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

try {
  test();
} catch (e) {
  log.error(e.message);
  process.exit(1);
}
