// File: rfc9700_client.js
//
// ---------------------------------------------------------------------------
// RFC 9700 (OAuth 2.0 Security Best Current Practice) — the CLIENT side, as
// this debugger implements it.
//
// **Node only. No browser, no services, so it never skips.** That is the point
// of it: the browser test beside it (rfc9700_flows.js) drives one flow through
// a real identity provider and can only see what that provider happens to do,
// while everything here is decided by inputs this file chooses. A rule that
// only fires against a misbehaving server is a rule nothing exercises, and
// almost every rule in RFC 9700 is one of those.
//
// Three kinds of check, and the second is the one worth defending:
//
//   1. THE CATALOGUE. client/src/rfc9700.js holds one row per client-side
//      obligation, keyed to the fifteen-section checklist this work follows
//      (rcbj/mock-sts issue #2). Every section must be represented, every id
//      unique, every row complete. The catalogue is what the report, the
//      documentation and the tests all read, so a check with no row is
//      invisible to all three.
//
//   2. THE MODE-OFF CONTRACT. With the checkbox clear, this workflow must
//      behave exactly as it did before any of this existed — no check run, no
//      pane drawn, no request refused. That is invisible from inside a single
//      run: every RFC 9700 test naturally turns the mode ON, so nothing would
//      ever notice the day a check started firing unconditionally, and the
//      symptom would be the debugger refusing to talk to a provider somebody
//      is trying to debug. It is asserted here two ways — behaviourally
//      against the module, and lexically over the two page modules, requiring
//      an rfc9700.enabled() near every call into a check.
//
//   3. THE RULES THEMSELVES, driven directly. Each of the four check functions
//      is given inputs that should trip a specific requirement, and the exact
//      id is asserted — not merely that "something was reported". A finding
//      that fires under the wrong id is worse than none: it sends the reader
//      to the wrong section of the specification.
//
// Plus the SOURCE properties, for the rows marked enforced="always". Those are
// not behind the switch — they are this client's own posture (no open
// redirector, 303 not 307, no framing, no browser messaging, no token in a
// URL) and they are the ones a well-meaning edit removes silently. Each is
// asserted over the file that holds it.
// ---------------------------------------------------------------------------

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "rfc9700_client",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

// ---------------------------------------------------------------------------
// THE SUBJECT OF THIS TEST IS A SOURCE TREE, not a module, which is why it
// needs paths rather than requires.
//
// Two thirds of the checks below read `client/src`, `client/public` and
// `client/server.js` as text — an iframe anywhere, a postMessage with '*', a
// token in a query string, the headers on the callback. So the tests image
// cannot satisfy this one by copying a file next to the test the way it does
// for every other borrowed module: it copies the TREE, to /usr/src/client,
// which is where these three paths resolve from /usr/src/app. See
// tests/Dockerfile.
// ---------------------------------------------------------------------------
const REPO = path.resolve(__dirname, "..");
const SRC = path.join(REPO, "client", "src");
const PUBLIC = path.join(REPO, "client", "public");

// The module under test. Required from tests/, which has no CONFIG_FILE of the
// client's shape — rfc9700.js falls back to "info" for exactly this case, and
// the storage stand-ins it carries are what let it run with no browser.
//
// Through module_paths.js rather than a bare require(), for the reason
// tests/CLAUDE.md gives: node resolves a module's own requires from where THAT
// module lives, so rfc9700.js's `require("bunyan")` is looked for under
// client/node_modules — which neither the tests image nor a checkout that
// installed only the tests' dependencies has.
const paths = require("./module_paths.js");
const rfc9700 = paths.requireSharedModule([path.join(SRC, "rfc9700.js")],
                                          "client/src/rfc9700.js");

function read(file) {
  log.debug("Entering read(). file=" + file);
  log.debug("Leaving read().");
  return fs.readFileSync(file, "utf8");
}

// Strip line and block comments before a lexical search.
//
// Without this every check below is answerable by a comment — and this tree's
// comments discuss the very constructs being searched for at length, so it is
// not a theoretical objection: rfc9700.js's own catalogue quotes "postMessage"
// and "iframe" in the notes describing their absence.
function code(file) {
  log.debug("Entering code(). file=" + file);
  var text = read(file);
  var stripped = text
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .split("\n")
    .map(function (line) {
      var i = line.indexOf("//");
      // Only strip a // that is not inside a string. Approximated by refusing
      // to strip when the line has an odd number of quote characters before
      // it, which is enough for this tree and errs toward keeping code.
      if (i === -1) {
        return line;
      }
      var before = line.slice(0, i);
      var quotes = (before.match(/["']/g) || []).length;
      return (quotes % 2 === 0) ? before : line;
    })
    .join("\n");
  log.debug("Leaving code().");
  return stripped;
}

// The subject of every fabricated ID Token below. Nothing here reaches a
// server, so this is a literal rather than an account — but it is generated
// like every other username in this suite so that a payload printed by a
// failure names the file that built it, and so that a `sub` which is a PERSON
// stays visibly distinct from the 13.1 case whose `sub` is the client_id.
const SUBJECT = usernameFor("rfc9700-client");

var failures = 0;
function check(what, fn) {
  log.debug("Entering check(). what=" + what);
  try {
    fn();
    log.info("PASS  " + what);
  } catch (e) {
    failures++;
    log.error("FAIL  " + what + " — " + e.message);
  }
  log.debug("Leaving check().");
}

// Assert that a verdict reported exactly these requirement ids at MUST level,
// and no others. "Exactly" is the whole value of it: a check that fires the
// right rule and three wrong ones alongside sends a reader to four sections of
// the specification, three of which say nothing about what happened.
function assertBlocking(verdict, ids, what) {
  log.debug("Entering assertBlocking(). what=" + what);
  var got = verdict.blocked.map(function (f) { return f.id; }).sort();
  assert.deepStrictEqual(got, ids.slice().sort(),
    what + ": expected MUST findings [" + ids.join(", ") + "] and got [" +
    got.join(", ") + "]. Full report: " +
    verdict.findings.map(function (f) {
      return f.id + "/" + f.level + " " + f.message;
    }).join(" | "));
  assert.strictEqual(verdict.ok, ids.length === 0,
    what + ": ok should be " + (ids.length === 0) + ".");
  log.debug("Leaving assertBlocking().");
}

// Assert that a verdict mentions a requirement at all, at any level.
function assertMentions(verdict, id, what) {
  log.debug("Entering assertMentions(). id=" + id);
  assert.ok(verdict.findings.some(function (f) { return f.id === id; }),
    what + ": expected a finding for " + id + ". Got: " +
    verdict.findings.map(function (f) { return f.id; }).join(", "));
  log.debug("Leaving assertMentions().");
}

// A request that meets every rule, which each case below then breaks in one
// place. Written as a function rather than a constant because the cases mutate
// it, and a shared object would let one case's damage reach the next.
function goodRequest(overrides) {
  log.debug("Entering goodRequest().");
  var request = {
    grant: "oidc_authorization_code_flow",
    responseType: "code",
    authorizationEndpoint: "https://op.example.com/authorize",
    redirectUri: "https://client.example.com/callback",
    clientId: "client-1",
    clientSecret: "",
    authStyle: "header",
    scope: "openid profile",
    resource: "https://api.example.com/",
    state: "state-value",
    nonce: "nonce-value",
    usePKCE: true,
    codeChallengeMethod: "S256",
    endpoints: { "The token endpoint": "https://op.example.com/token" },
    sslValidate: true,
    metadata: {
      issuer: "https://op.example.com",
      code_challenge_methods_supported: ["S256"],
      response_types_supported: ["code"],
      response_modes_supported: ["query", "form_post"]
    },
    metadataUrl: "https://op.example.com/.well-known/openid-configuration",
    dpopEnabled: true
  };
  Object.keys(overrides || {}).forEach(function (k) {
    request[k] = overrides[k];
  });
  log.debug("Leaving goodRequest().");
  return request;
}

function run() {
  log.debug("Entering run().");

  // ======================================================================
  // 1. The catalogue.
  // ======================================================================
  check("every one of the fifteen sections has at least one row", function () {
    var sections = {};
    rfc9700.REQUIREMENTS.forEach(function (r) { sections[r.section] = true; });
    for (var n = 1; n <= 15; n++) {
      assert.ok(sections[n], "No requirement row carries section " + n +
        ". The checklist this work follows has fifteen sections and the " +
        "catalogue is what the report and the documentation read.");
    }
  });

  check("requirement ids are unique and well formed", function () {
    var seen = {};
    rfc9700.REQUIREMENTS.forEach(function (r) {
      assert.ok(/^\d+\.\d+$/.test(r.id), "Malformed requirement id: " + r.id);
      assert.ok(!seen[r.id], "Duplicate requirement id: " + r.id);
      seen[r.id] = true;
      assert.strictEqual(Number(r.id.split(".")[0]), r.section,
        "Requirement " + r.id + " is filed under section " + r.section +
        ", which its id does not match. The id is how a reader finds the " +
        "section, so the two disagreeing is worse than either alone.");
    });
  });

  check("every row is complete and its enforcement is a known value",
        function () {
    var allowed = ["enforced", "detected", "always", "no"];
    rfc9700.REQUIREMENTS.forEach(function (r) {
      assert.ok(r.title && r.title.length > 10,
        "Requirement " + r.id + " has no usable title.");
      assert.ok(r.note && r.note.length > 30,
        "Requirement " + r.id + " has no note. A row without one is a claim " +
        "with no reasoning attached, which is what this catalogue exists to " +
        "avoid.");
      assert.ok(r.level && r.level.length,
        "Requirement " + r.id + " states no RFC 9700 level.");
      assert.ok(allowed.indexOf(r.enforced) !== -1,
        "Requirement " + r.id + " claims enforcement '" + r.enforced +
        "', which is not one of " + allowed.join(", ") + ".");
    });
  });

  check("a row that claims nothing is done says why", function () {
    rfc9700.REQUIREMENTS.filter(function (r) {
      return r.enforced === "no";
    }).forEach(function (r) {
      assert.ok(/NOT IMPLEMENTED|not implemented/.test(r.note),
        "Requirement " + r.id + " is marked as not done and its note does " +
        "not say so in words. A silent omission and a documented one look " +
        "the same in a table.");
    });
  });

  // ======================================================================
  // 2. The mode-off contract.
  // ======================================================================
  check("the mode is off unless the stored value is exactly 'true'",
        function () {
    rfc9700.setEnabled(false);
    assert.strictEqual(rfc9700.enabled(), false, "Off did not read as off.");
    rfc9700.setEnabled(true);
    assert.strictEqual(rfc9700.enabled(), true, "On did not read as on.");
    // Anything unrecognised must read as OFF. That is the direction which
    // leaves the debugger able to talk to a broken provider, and it is the
    // direction an unreadable value should fail in.
    rfc9700.setEnabled(false);
    assert.strictEqual(rfc9700.enabled(), false,
      "A value that is not the string 'true' must read as off.");
  });

  check("neither page calls a check without asking whether the mode is on",
        function () {
    // A lexical rule rather than a call-graph analysis, and the scope it uses
    // is the ENCLOSING FUNCTION: from the nearest preceding top-level
    // `function name(` down to the call, an rfc9700.enabled() must appear.
    // Both page modules declare every function at top level, so that boundary
    // is exact here — and it is a boundary rather than a line count on
    // purpose, because a line window silently changes meaning every time a
    // function grows.
    //
    // It is why rfc9700GateAuthorizationRequest() carries a guard of its own
    // although both of its callers already ask: a guard that lives only at
    // the caller satisfies the contract and not this check, and the two
    // disagreeing is how the contract stops being asserted at all.
    ["oauth2_oidc_1.js", "oauth2_oidc_2.js"].forEach(function (name) {
      var lines = code(path.join(SRC, name)).split("\n");
      lines.forEach(function (line, i) {
        if (!/rfc9700\.check[A-Za-z]+\(/.test(line)) {
          return;
        }
        var start = 0;
        for (var j = i; j >= 0; j--) {
          if (/^function\s+\w+\s*\(/.test(lines[j])) {
            start = j;
            break;
          }
        }
        var scope = lines.slice(start, i + 1).join("\n");
        assert.ok(/rfc9700\.enabled\(\)/.test(scope),
          name + " line " + (i + 1) + " calls into an RFC 9700 check and the " +
          "function containing it (from line " + (start + 1) + ") never asks " +
          "rfc9700.enabled(). With the compliance switch off nothing here " +
          "may run: the call was " + line.trim());
      });
    });
  });

  check("the compliance checkbox exists on both pages and starts clear",
        function () {
    ["oauth2_oidc_1.html", "oauth2_oidc_2.html"].forEach(function (name) {
      var markup = read(path.join(PUBLIC, name));
      var input = markup.match(/<input[^>]*id="rfc9700_mode"[^>]*>/);
      assert.ok(input, name + " has no rfc9700_mode checkbox.");
      assert.ok(!/checked/.test(input[0]),
        name + "'s RFC 9700 checkbox ships CHECKED. It must not: with the " +
        "mode on by default this debugger refuses to talk to most of the " +
        "identity providers it exists to be pointed at.");
      assert.ok(/rfc9700_request_report|rfc9700_response_report/.test(markup) ||
                /rfc9700_token_report/.test(markup),
        name + " has no container for the RFC 9700 report.");
    });
  });

  // ======================================================================
  // 3. The rules, driven directly.
  // ======================================================================
  check("a compliant authorization request is not refused", function () {
    assertBlocking(rfc9700.checkAuthorizationRequest(goodRequest()), [],
                   "the compliant request");
  });

  check("1.2 — a wildcard redirect_uri is refused", function () {
    assertBlocking(rfc9700.checkAuthorizationRequest(goodRequest({
      redirectUri: "https://client.example.com/*"
    })), ["1.2"], "a wildcard redirect_uri");
  });

  check("1.3 — an http redirect_uri off the loopback is refused, and one ON " +
        "it is not", function () {
    assertBlocking(rfc9700.checkAuthorizationRequest(goodRequest({
      redirectUri: "http://client.example.com/callback"
    })), ["1.3"], "an http redirect_uri on a public host");
    // RFC 8252's exception, and the one this whole mode depends on locally:
    // the debugger's own callback is http://localhost:3000/callback.
    assertBlocking(rfc9700.checkAuthorizationRequest(goodRequest({
      redirectUri: "http://localhost:3000/callback"
    })), [], "an http redirect_uri on loopback");
    assertBlocking(rfc9700.checkAuthorizationRequest(goodRequest({
      redirectUri: "http://127.0.0.1:54321/callback"
    })), [], "an http redirect_uri on 127.0.0.1 with a high port");
  });

  check("1.4 and 8.1 — an http endpoint anywhere in the set is refused",
        function () {
    assertBlocking(rfc9700.checkAuthorizationRequest(goodRequest({
      authorizationEndpoint: "http://op.example.com/authorize"
    })), ["1.4"], "an http authorization endpoint");
    // The case a per-call check would miss: nine https endpoints and one that
    // is not, on an endpoint this particular flow never calls.
    assertBlocking(rfc9700.checkAuthorizationRequest(goodRequest({
      endpoints: {
        "The token endpoint": "https://op.example.com/token",
        "The UserInfo endpoint": "https://op.example.com/userinfo",
        "The revocation endpoint": "http://op.example.com/revoke"
      }
    })), ["8.1"], "one http endpoint among several https ones");
  });

  check("1.6 — PKCE is a MUST for a public client and a SHOULD for a " +
        "confidential one", function () {
    var publicClient = rfc9700.checkAuthorizationRequest(goodRequest({
      usePKCE: false, clientSecret: ""
    }));
    assertBlocking(publicClient, ["1.6"], "a public client without PKCE");
    var confidential = rfc9700.checkAuthorizationRequest(goodRequest({
      usePKCE: false, clientSecret: "s3cret"
    }));
    assertBlocking(confidential, [],
      "a confidential client without PKCE (a SHOULD, not a MUST)");
    assertMentions(confidential, "1.6",
      "a confidential client without PKCE");
  });

  check("1.7 — the plain PKCE method is refused", function () {
    assertBlocking(rfc9700.checkAuthorizationRequest(goodRequest({
      codeChallengeMethod: "plain"
    })), ["1.7"], "code_challenge_method=plain");
  });

  check("1.11 and 5.1 — the six grants that do not survive", function () {
    var expected = {
      implicit_grant: "1.11",
      oidc_implicit_flow: "1.11",
      oidc_implicit_flow_id_token: "1.11",
      oidc_hybrid_code_token: "1.11",
      oidc_hybrid_code_id_token_token: "1.11",
      resource_owner: "5.1"
    };
    Object.keys(expected).forEach(function (grant) {
      assert.ok(!rfc9700.grantAllowed(grant),
        grant + " is not disabled in RFC 9700 mode.");
      assert.ok(rfc9700.grantRefusalReason(grant).length > 40,
        grant + " is refused with no reason worth reading. Six controls " +
        "carrying one generic sentence tells a reader nothing about which " +
        "rule they have met.");
      assertBlocking(rfc9700.checkAuthorizationRequest(goodRequest({
        grant: grant, responseType: "token"
      })), [expected[grant]], grant);
    });
    // And the one hybrid that DOES survive, which is the interesting half:
    // code id_token returns no access token from the authorization endpoint.
    assert.ok(rfc9700.grantAllowed("oidc_hybrid_code_id_token"),
      "OIDC Hybrid (code id_token) is refused. It returns no access token " +
      "from the authorization endpoint and its id_token is the code " +
      "injection defence section 3 asks for, so it is the one hybrid RFC " +
      "9700 leaves standing.");
    assert.ok(rfc9700.grantAllowed("oidc_authorization_code_flow"));
    assert.ok(rfc9700.grantAllowed("client_credential"));
    assert.ok(rfc9700.grantAllowed("device_authorization_grant"));
  });

  check("2.1 and 3.3 — a request with no state, or no nonce, is refused",
        function () {
    assertBlocking(rfc9700.checkAuthorizationRequest(goodRequest({
      state: ""
    })), ["2.1"], "no state");
    assertBlocking(rfc9700.checkAuthorizationRequest(goodRequest({
      nonce: "", scope: "openid profile"
    })), ["3.3"], "an OpenID request with no nonce");
    // A request that is not an authentication request needs no nonce.
    assertBlocking(rfc9700.checkAuthorizationRequest(goodRequest({
      nonce: "", scope: "api.read", responseType: "code"
    })), [], "a plain OAuth2 request with no nonce");
  });

  check("7.1 — a request built from typed endpoints rather than from " +
        "metadata is refused", function () {
    assertBlocking(rfc9700.checkAuthorizationRequest(goodRequest({
      metadata: null
    })), ["7.1"], "no metadata retrieved");
  });

  check("7.2 — metadata claiming an issuer it did not come from is refused",
        function () {
    assertBlocking(rfc9700.checkAuthorizationRequest(goodRequest({
      metadata: { issuer: "https://evil.example.com" },
      metadataUrl: "https://op.example.com/.well-known/openid-configuration"
    })), ["7.2"], "an issuer from another origin");
    // Both discovery layouts resolve, because both are in use: OIDC appends
    // the well-known path to the issuer, RFC 8414 inserts it after the host.
    assert.strictEqual(rfc9700.issuerMismatch(
      "https://op.example.com/tenant-a",
      "https://op.example.com/tenant-a/.well-known/openid-configuration"),
      null, "The OIDC Discovery layout was reported as a mismatch.");
    assert.strictEqual(rfc9700.issuerMismatch(
      "https://op.example.com/tenant-a",
      "https://op.example.com/.well-known/oauth-authorization-server/tenant-a"),
      null, "The RFC 8414 layout was reported as a mismatch.");
    assert.ok(rfc9700.issuerMismatch(
      "https://op.example.com/tenant-b",
      "https://op.example.com/tenant-a/.well-known/openid-configuration"),
      "A document for tenant-a claiming to be tenant-b was accepted.");
  });

  check("8.2 — certificate validation switched off is refused", function () {
    assertBlocking(rfc9700.checkAuthorizationRequest(goodRequest({
      sslValidate: false
    })), ["8.2"], "SSL validation off");
  });

  check("4.1 to 4.3 — the SHOULD-level rows report and do not refuse",
        function () {
    var verdict = rfc9700.checkAuthorizationRequest(goodRequest({
      dpopEnabled: false, resource: "", scope: ""
    }));
    assertBlocking(verdict, [],
      "no DPoP, no resource indicator and no scope");
    ["4.1", "4.2", "4.3"].forEach(function (id) {
      assertMentions(verdict, id, "the SHOULD-level access-token rows");
    });
  });

  check("the device flow is judged on the rules that apply to it and not on " +
        "the ones that do not", function () {
    // RFC 8628 has no redirect_uri, no state, no nonce and no PKCE. Running
    // the redirect rules against it would refuse a compliant device flow for
    // lacking parameters it does not have, which reads as the mode being
    // broken rather than as the flow being wrong.
    assertBlocking(rfc9700.checkAuthorizationRequest(goodRequest({
      deviceFlow: true,
      grant: "device_authorization_grant",
      responseType: "",
      redirectUri: "",
      state: "",
      nonce: "",
      usePKCE: false,
      deviceAuthorizationEndpoint: "https://op.example.com/device"
    })), [], "a compliant device authorization request");
    // But TLS still applies to it.
    assertBlocking(rfc9700.checkAuthorizationRequest(goodRequest({
      deviceFlow: true,
      grant: "device_authorization_grant",
      responseType: "", redirectUri: "", state: "", nonce: "",
      usePKCE: false,
      deviceAuthorizationEndpoint: "http://op.example.com/device"
    })), ["1.4"], "an http device authorization endpoint");
  });

  check("10.4 — form_post is asked for only when it is advertised AND there " +
        "is a backend to receive it", function () {
    var advertised = { response_modes_supported: ["query", "form_post"] };
    var not = { response_modes_supported: ["query", "fragment"] };
    assert.strictEqual(rfc9700.wantsFormPost(advertised, true), true);
    assert.strictEqual(rfc9700.wantsFormPost(not, true), false);
    assert.strictEqual(rfc9700.wantsFormPost(null, true), false);
    // The half that is easy to forget: a deployed static site has no
    // /callback of ours at all, so a form_post response there would arrive
    // nowhere and the flow would simply stop with no error to point at.
    assert.strictEqual(rfc9700.wantsFormPost(advertised, false), false,
      "form_post was requested on a build with no backend to receive the " +
      "POST.");
  });

  // -- the authorization response ------------------------------------------
  function startTransaction(overrides) {
    log.debug("Entering startTransaction().");
    var t = {
      issuer: "https://op.example.com",
      state: "state-value",
      nonce: "nonce-value",
      codeVerifier: "verifier",
      clientId: "client-1",
      issParameterAdvertised: true
    };
    Object.keys(overrides || {}).forEach(function (k) { t[k] = overrides[k]; });
    rfc9700.beginTransaction(t);
    log.debug("Leaving startTransaction().");
  }

  check("2.2 — a response with no transaction behind it is refused",
        function () {
    rfc9700.clearTransaction();
    assertBlocking(rfc9700.checkAuthorizationResponse({
      state: "anything", code: "c"
    }), ["2.4"], "a response with no transaction in this session");
  });

  check("2.2 — a matching state passes and a mismatched one refuses",
        function () {
    startTransaction();
    assertBlocking(rfc9700.checkAuthorizationResponse({
      state: "state-value", iss: "https://op.example.com", code: "c"
    }), [], "a matching state");
    startTransaction();
    assertBlocking(rfc9700.checkAuthorizationResponse({
      state: "somebody-elses", iss: "https://op.example.com", code: "c"
    }), ["2.2"], "a mismatched state");
    startTransaction();
    assertBlocking(rfc9700.checkAuthorizationResponse({
      state: "", iss: "https://op.example.com", code: "c"
    }), ["2.2"], "no state at all");
  });

  check("2.3 — a state is single-use, so a replayed response is refused",
        function () {
    startTransaction();
    assertBlocking(rfc9700.checkAuthorizationResponse({
      state: "state-value", iss: "https://op.example.com", code: "c"
    }), [], "the first delivery");
    rfc9700.consumeState();
    assertBlocking(rfc9700.checkAuthorizationResponse({
      state: "state-value", iss: "https://op.example.com", code: "c"
    }), ["2.3"], "the same response delivered twice");
  });

  check("2.5 and 2.6 — the RFC 9207 iss parameter", function () {
    startTransaction();
    assertBlocking(rfc9700.checkAuthorizationResponse({
      state: "state-value", iss: "https://another-op.example.com", code: "c"
    }), ["2.5"], "a response issued by a different server");
    // Absent, and the server said it would be there.
    startTransaction({ issParameterAdvertised: true });
    assertBlocking(rfc9700.checkAuthorizationResponse({
      state: "state-value", code: "c"
    }), ["2.6"], "no iss from a server that advertises it");
    // Absent, and the server never claimed to send one: reported, not refused.
    startTransaction({ issParameterAdvertised: false });
    var quiet = rfc9700.checkAuthorizationResponse({
      state: "state-value", code: "c"
    });
    assertBlocking(quiet, [], "no iss from a server that does not advertise " +
      "it");
    assertMentions(quiet, "2.5", "a server that publishes no iss");
  });

  check("11.2 — an error about the client's own identity, delivered to the " +
        "redirect_uri, is reported", function () {
    startTransaction();
    var verdict = rfc9700.checkAuthorizationResponse({
      state: "state-value", iss: "https://op.example.com",
      error: "invalid_client"
    });
    assertMentions(verdict, "11.2", "an invalid_client error redirected back");
  });

  // -- the token request and response --------------------------------------
  check("3.1 — a code is redeemed once", function () {
    startTransaction();
    assertBlocking(rfc9700.checkTokenRequest({
      grantType: "authorization_code", code: "code-1", codeVerifier: "verifier"
    }), [], "the first redemption");
    rfc9700.noteCodeRedeemed("code-1");
    assertBlocking(rfc9700.checkTokenRequest({
      grantType: "authorization_code", code: "code-1", codeVerifier: "verifier"
    }), ["3.1"], "the second redemption of the same code");
    // A different code is unaffected.
    assertBlocking(rfc9700.checkTokenRequest({
      grantType: "authorization_code", code: "code-2", codeVerifier: "verifier"
    }), [], "a different code");
  });

  check("1.6 — a token request that drops the code_verifier is refused",
        function () {
    startTransaction();
    assertBlocking(rfc9700.checkTokenRequest({
      grantType: "authorization_code", code: "code-3", codeVerifier: ""
    }), ["1.6"], "a token request with no code_verifier after a challenge " +
      "was sent");
  });

  check("5.1 — the password grant is refused at the token request as well " +
        "as in the selector", function () {
    assertBlocking(rfc9700.checkTokenRequest({
      grantType: "password"
    }), ["5.1"], "the Resource Owner Password Credentials grant");
  });

  check("3.2 — a token set whose ID Token nonce does not match is discarded",
        function () {
    startTransaction();
    var good = rfc9700.checkTokenResponse({
      data: { id_token: jwt({ iss: "https://op.example.com",
                              nonce: "nonce-value", sub: SUBJECT }) },
      grantType: "authorization_code", clientId: "client-1"
    });
    assertBlocking(good, [], "an ID Token carrying the nonce that was sent");
    startTransaction();
    assertBlocking(rfc9700.checkTokenResponse({
      data: { id_token: jwt({ iss: "https://op.example.com",
                              nonce: "somebody-elses", sub: SUBJECT }) },
      grantType: "authorization_code", clientId: "client-1"
    }), ["3.2"], "an ID Token carrying another session's nonce");
    startTransaction();
    assertBlocking(rfc9700.checkTokenResponse({
      data: { id_token: jwt({ iss: "https://op.example.com", sub: SUBJECT }) },
      grantType: "authorization_code", clientId: "client-1"
    }), ["3.2"], "an ID Token with no nonce at all");
  });

  check("2.7 — an ID Token from another issuer is discarded", function () {
    startTransaction();
    assertBlocking(rfc9700.checkTokenResponse({
      data: { id_token: jwt({ iss: "https://evil.example.com",
                              nonce: "nonce-value", sub: SUBJECT }) },
      grantType: "authorization_code", clientId: "client-1"
    }), ["2.7"], "an ID Token issued by a different server");
  });

  check("13.1 — a user token whose sub is the client_id is reported",
        function () {
    startTransaction();
    var verdict = rfc9700.checkTokenResponse({
      data: { id_token: jwt({ iss: "https://op.example.com",
                              nonce: "nonce-value", sub: "client-1" }) },
      grantType: "authorization_code", clientId: "client-1"
    });
    assertBlocking(verdict, [], "a confusable subject is a SHOULD, not a " +
      "MUST");
    assertMentions(verdict, "13.1", "sub equal to client_id");
  });

  check("4.1 — a token requested with DPoP that comes back Bearer is " +
        "reported", function () {
    startTransaction({ dpop: true });
    var verdict = rfc9700.checkTokenResponse({
      data: { token_type: "Bearer", access_token: "opaque" },
      grantType: "authorization_code", clientId: "client-1"
    });
    assertMentions(verdict, "4.1", "DPoP asked for and Bearer returned");
    startTransaction({ dpop: true });
    var bound = rfc9700.checkTokenResponse({
      data: { token_type: "DPoP", access_token: "opaque" },
      grantType: "authorization_code", clientId: "client-1"
    });
    assert.ok(bound.findings.some(function (f) {
      return f.id === "4.1" && f.level === rfc9700.INFO;
    }), "A DPoP-bound token was not reported as bound.");
  });

  check("4.3 — a grant wider than the request is reported", function () {
    startTransaction();
    var verdict = rfc9700.checkTokenResponse({
      data: { scope: "openid profile admin", access_token: "opaque" },
      grantType: "authorization_code", clientId: "client-1",
      requestedScope: "openid profile"
    });
    assertMentions(verdict, "4.3", "a scope the client did not ask for");
    assert.ok(/admin/.test(verdict.findings.filter(function (f) {
      return f.id === "4.3";
    })[0].message), "The report does not name the extra scope.");
  });

  check("9.1 — a rotated refresh token is spent and cannot be sent again",
        function () {
    startTransaction();
    assertBlocking(rfc9700.checkTokenRequest({
      grantType: "refresh_token", refreshToken: "refresh-1"
    }), [], "the first use of a refresh token");
    rfc9700.noteRefreshRotated("refresh-1", "refresh-2");
    assertBlocking(rfc9700.checkTokenRequest({
      grantType: "refresh_token", refreshToken: "refresh-1"
    }), ["9.1"], "a refresh token the server has already replaced");
    assertBlocking(rfc9700.checkTokenRequest({
      grantType: "refresh_token", refreshToken: "refresh-2"
    }), [], "the token that replaced it");
  });

  check("9.2 — an unrotated, unbound refresh token is reported for a public " +
        "client", function () {
    startTransaction();
    var verdict = rfc9700.checkTokenResponse({
      data: { refresh_token: "same", token_type: "Bearer" },
      grantType: "refresh_token", clientId: "client-1",
      previousRefreshToken: "same"
    });
    assertMentions(verdict, "9.2", "the same refresh token returned");
    // Sender constraint is the accepted alternative to rotation.
    startTransaction();
    var boundInstead = rfc9700.checkTokenResponse({
      data: { refresh_token: "same", token_type: "DPoP" },
      grantType: "refresh_token", clientId: "client-1",
      previousRefreshToken: "same"
    });
    assert.ok(boundInstead.findings.some(function (f) {
      return f.id === "9.2" && f.level === rfc9700.INFO;
    }), "A DPoP-bound but unrotated refresh token was reported as a " +
        "failing. RFC 9700 section 4.14.2 accepts sender constraint OR " +
        "rotation.");
  });

  // ======================================================================
  // 4. The always-on rows, asserted over the source that holds them.
  // ======================================================================
  check("1.5 and 11.1 — /callback is not an open redirector", function () {
    var server = code(path.join(REPO, "client", "server.js"));
    // The destination is built in one place, from configuration.
    assert.ok(/function debuggerLandingUrl\(\)/.test(server),
      "client/server.js no longer builds its landing URL in one named place. " +
      "That function is what makes this rule inspectable in a sentence.");
    assert.ok(/appconfig\.uiUrl/.test(server),
      "The landing URL is no longer built from appconfig.uiUrl.");
    // And every Location BEGINS with that function's result.
    //
    // Beginning with it is the precise rule, and it is stronger than "nothing
    // off the request appears in it": /callback deliberately copies the
    // authorization response's parameters through, so request-derived text
    // does reach the header — after the '?' or the '#', where it is data on a
    // URL whose destination is this deployment's own page. What must never
    // happen is request-derived text deciding the origin or the path, and a
    // Location that starts with debuggerLandingUrl() cannot.
    //
    // Read as a STATEMENT rather than a line, because a reformat that wraps
    // the argument must not silence the check — a check a reformat can silence
    // is a check that will be silenced.
    var statements = server.split(";");
    var locations = 0;
    statements.forEach(function (statement) {
      if (!/['"]Location['"]\s*:/.test(statement)) {
        return;
      }
      locations++;
      var value = statement.split(/['"]Location['"]\s*:/)[1];
      assert.ok(/^\s*debuggerLandingUrl\(\)/.test(value),
        "A Location header in client/server.js does not begin with " +
        "debuggerLandingUrl(). Anything else lets the request influence the " +
        "origin or the path, which is an open redirector on a registered " +
        "redirect_uri — how an authorization code is stolen from a client " +
        "that did everything else right. The value was: " +
        value.trim().slice(0, 200));
    });
    assert.strictEqual(locations, 2,
      "Expected exactly two Location headers in client/server.js (the GET " +
      "callback and the form_post one) and found " + locations + ". A third " +
      "redirect is a third thing this rule has to hold for.");
  });

  check("12.1 — the callback redirects with 303, not 302 and not 307",
        function () {
    var server = code(path.join(REPO, "client", "server.js"));
    var codes = (server.match(/writeHead\((\d+)/g) || []).map(function (m) {
      return m.replace("writeHead(", "");
    });
    assert.ok(codes.length >= 2,
      "Expected both callback methods to redirect; found " + codes.length +
      " writeHead calls.");
    codes.forEach(function (c) {
      assert.strictEqual(c, "303",
        "client/server.js redirects with " + c + ". RFC 9700 section 4.12 " +
        "asks for 303: a 307 replays the method AND THE BODY, which on a " +
        "form_post authorization response is the response itself.");
    });
    assert.ok(/app\.post\(['"]\/callback['"]/.test(server),
      "There is no POST /callback, so response_mode=form_post — the remedy " +
      "RFC 9700 section 4.12.2 names — has nowhere to land.");
  });

  check("10.2 and 14.1 — the headers are sent, and unconditionally",
        function () {
    var server = code(path.join(REPO, "client", "server.js"));
    [["Referrer-Policy", "no-referrer"],
     ["X-Frame-Options", "DENY"],
     ["Content-Security-Policy", "frame-ancestors 'none'"]].forEach(
        function (pair) {
      var re = new RegExp("setHeader\\(\\s*'" + pair[0] + "'");
      assert.ok(re.test(server),
        "client/server.js does not send " + pair[0] + ".");
      assert.ok(server.indexOf(pair[1]) !== -1,
        "client/server.js sends " + pair[0] + " with a value other than \"" +
        pair[1] + "\".");
    });
    // They must not be behind the compliance switch. The switch lives in the
    // browser's localStorage and this process cannot read it, so a condition
    // here could only be a second, divergent setting.
    assert.ok(!/rfc9700/i.test(server.split("app.use")[1] || ""),
      "The security headers in client/server.js appear to be conditional. " +
      "They are about this deployment's own posture, are invisible to any " +
      "identity provider, and cannot break a flow, so they are always on.");
    // And the meta element, for the deployed static sites where no server of
    // ours is in front of the pages.
    ["oauth2_oidc_1.html", "oauth2_oidc_2.html"].forEach(function (name) {
      assert.ok(/<meta name="referrer" content="no-referrer">/.test(
        read(path.join(PUBLIC, name))),
        name + " carries no referrer meta element. The header covers the " +
        "local and containerized stacks; this covers the deployed static " +
        "sites, which have no server of ours in front of them.");
    });
  });

  check("14.2 — nothing in the client frames anything", function () {
    walkFiles([SRC, PUBLIC], function (file, text) {
      if (/\.(js|html)$/.test(file)) {
        assert.ok(!/<iframe/i.test(text),
          file + " contains an iframe. RFC 9700 section 4.16 forbids " +
          "framing an authorization endpoint, and a debugger that framed " +
          "one would be teaching the habit.");
        assert.ok(!/createElement\(\s*['"]iframe['"]/i.test(text),
          file + " creates an iframe element.");
      }
    });
  });

  check("15.1 — the OAuth2 / OIDC workflow uses no browser messaging",
        function () {
    ["oauth2_oidc_1.js", "oauth2_oidc_2.js", "rfc9700.js", "oauth_dpop.js",
     "op_metadata.js"].forEach(function (name) {
      var text = code(path.join(SRC, name));
      assert.ok(!/postMessage\(/.test(text),
        name + " uses postMessage. Section 15's failure modes are only " +
        "reachable by a workflow that does; this one's compliant answer is " +
        "that it does not, and that is asserted rather than assumed.");
      assert.ok(!/addEventListener\(\s*['"]message['"]/.test(text),
        name + " installs a message listener.");
    });
  });

  check("15.2 — no '*' target origin anywhere in the client", function () {
    walkFiles([SRC], function (file, text) {
      if (!/\.js$/.test(file)) {
        return;
      }
      var stripped = code(file);
      assert.ok(!/postMessage\([^)]*,\s*['"]\*['"]\s*\)/.test(stripped),
        file + " calls postMessage with '*' as the target origin. RFC 9700 " +
        "section 4.17 forbids it outright: it delivers the message to " +
        "whatever document happens to be there.");
    });
  });

  check("15.3 — the one message listener in the tree matches the sender " +
        "origin", function () {
    var text = code(path.join(SRC, "webauthn_analyzer.js"));
    assert.ok(/event\.origin\s*!==\s*window\.location\.origin/.test(text),
      "webauthn_analyzer.js's bridge listener does not compare event.origin " +
      "against this page's own origin. event.source is a different check: it " +
      "identifies the window a message came from, not the document in it, so " +
      "a window navigated elsewhere still satisfies it.");
  });

  check("4.4 and 9.3 — no token is ever put in a query parameter",
        function () {
    ["oauth2_oidc_1.js", "oauth2_oidc_2.js"].forEach(function (name) {
      var text = code(path.join(SRC, name));
      [/[?&]access_token=/, /[?&]refresh_token=/,
       /[?&]id_token=(?!hint)/].forEach(function (re) {
        var hit = text.match(re);
        assert.ok(!hit,
          name + " builds a URL carrying a token as a query parameter (" +
          (hit && hit[0]) + "). RFC 9700 section 4.3.2 forbids it: a URL " +
          "reaches server logs, browser history and the Referer header.");
      });
    });
  });

  check("10.3 — the two workflow pages load no third-party resource, and " +
        "the external links they do carry are pinned", function () {
    ["oauth2_oidc_1.html", "oauth2_oidc_2.html"].forEach(function (name) {
      var markup = read(path.join(PUBLIC, name));
      // Resources: script src, link href, img src. Every one must be
      // same-origin, which here means a site-absolute or relative path.
      var resources = markup.match(
        /<(?:script|link|img)\b[^>]*\b(?:src|href)="([^"]+)"/g) || [];
      resources.forEach(function (tag) {
        var url = tag.match(/(?:src|href)="([^"]+)"/)[1];
        assert.ok(!/^https?:\/\//i.test(url),
          name + " loads a third-party resource: " + url + ". RFC 9700 " +
          "section 4.11 asks that a page receiving an authorization response " +
          "carry none — every one of them sees the URL this page was loaded " +
          "with.");
      });
      // Links are the half of this rule not fully met — see requirement
      // 10.3's own note. Pinned rather than forbidden, so it cannot grow
      // quietly: each must be rel="noopener noreferrer", and the referrer
      // policy above suppresses the header for all of them.
      var links = markup.match(/<a\b[^>]*href="https?:\/\/[^"]+"[^>]*>/g) || [];
      links.forEach(function (tag) {
        assert.ok(/rel="[^"]*noreferrer/.test(tag),
          name + " carries an external link without rel=noreferrer: " +
          tag.slice(0, 160));
      });
    });
  });

  log.debug("Leaving run().");
}

// A JWT with the given claims and no signature worth the name. Every use of
// decodeClaims() in the module under test is a check whose failure is
// reported, never a decision to trust, so a real signature would add nothing
// here — and pretending otherwise would suggest this client verifies ID Token
// signatures, which is the token detail page's job and not this workflow's.
function jwt(claims) {
  log.debug("Entering jwt().");
  function b64u(obj) {
    return Buffer.from(JSON.stringify(obj)).toString("base64")
      .replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  }
  log.debug("Leaving jwt().");
  return b64u({ alg: "none", typ: "JWT" }) + "." + b64u(claims) + ".";
}

// Every file under the given roots, recursively, handed to fn as (path, text).
function walkFiles(roots, fn) {
  log.debug("Entering walkFiles().");
  roots.forEach(function (root) {
    var stack = [root];
    while (stack.length) {
      var current = stack.pop();
      var entries = fs.readdirSync(current, { withFileTypes: true });
      entries.forEach(function (entry) {
        var full = path.join(current, entry.name);
        if (entry.isDirectory()) {
          // node_modules is somebody else's code, and env/ holds generated
          // configuration. Neither is this application's own source.
          if (entry.name !== "node_modules") {
            stack.push(full);
          }
          return;
        }
        fn(full, fs.readFileSync(full, "utf8"));
      });
    }
  });
  log.debug("Leaving walkFiles().");
}

const program = new Command();
program
  .name("rfc9700_client")
  .description("RFC 9700, client side: the catalogue, the mode-off " +
               "contract, the rules, and the always-on posture.")
  .addOption(new Option("-u, --url <url>",
    "Ignored. Accepted so this test can be launched the same way as the " +
    "browser tests beside it."))
  .addOption(new Option("-b, --browser", "Ignored; this test opens none."))
  .action(function () {});
program.parse(process.argv);

run();
if (failures) {
  log.error(failures + " RFC 9700 client check(s) failed.");
  process.exit(1);
}
log.info("All RFC 9700 client checks passed.");
