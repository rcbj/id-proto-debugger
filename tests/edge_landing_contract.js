// File: edge_landing_contract.js
//
// ---------------------------------------------------------------------------
// The one part of the static deployments' edge landings that a browser cannot
// check for us: that the two halves of the hand-off contract still agree.
//
// infra/edge/edge_common.js is zipped and deployed into AWS by Terraform;
// client/src/edge_landing.js is browserified into the page by the site build.
// They ship separately and cannot import each other, so the sessionStorage key
// names, the ?posted marker and the response-page paths are written out twice.
//
// Rename one side alone and nothing fails until a deployed sign-in reports that
// nothing arrived — a message that names neither file and sends you looking at
// the IdP. Comparing them here costs milliseconds and fails with the cause.
//
// Both files are plain data with no dependencies, so they are require()d and
// compared directly rather than scraped. Called by tests/wsfed_sso.js and
// tests/saml_encrypted_sso.js — whichever runs first catches the drift.
//
// Skipped, with a log line rather than silently, when a layout has only one of
// the two files. Both are copied flat into the tests container (tests/Dockerfile)
// so this normally runs in CI as well as in a checkout.
// ---------------------------------------------------------------------------
const assert = require("assert");
const fs = require("fs");
const path = require("path");

function locate(candidates) {
  return candidates.filter(function (p) { return fs.existsSync(p); })[0];
}

// The fields compared, per landing. Keeping this explicit (rather than diffing
// whole objects) means adding a field on one side is a deliberate act on both.
const COMPARED = {
  wsfed: ["responsePage", "handoffParam", "wresultKey", "wctxKey", "waKey"],
  saml: ["responsePage", "handoffParam", "responseKey", "relayStateKey"]
};

function assertEdgeLandingContract(log) {
  const say = (log && log.info) ? log.info.bind(log) : console.log;
  say("Checking the edge landings' hand-off contract (infra/edge/edge_common.js vs client/src/edge_landing.js).");

  // Flat in the tests container, in their own trees in a checkout.
  const edgePath = locate([path.join(__dirname, "edge_common.js"),
                           path.join(__dirname, "..", "infra", "edge", "edge_common.js")]);
  const clientPath = locate([path.join(__dirname, "edge_landing.js"),
                             path.join(__dirname, "..", "client", "src", "edge_landing.js")]);
  if (!edgePath || !clientPath) {
    say("Skipping the edge-landing contract check: this layout has no " +
        (edgePath ? "edge_landing.js" : "edge_common.js") + ".");
    return false;
  }

  const edge = require(edgePath).CONTRACTS;
  const client = require(clientPath);

  assert.strictEqual(client.MARKER, edge.marker,
    "the landing marker differs: infra/edge/edge_common.js says '" + edge.marker +
    "', client/src/edge_landing.js says '" + client.MARKER + "'. remote-run-tests.sh probes for the " +
    "former, so the job would skip as 'no landing deployed' against a site that has one.");

  Object.keys(COMPARED).forEach(function (landing) {
    const clientSide = client[landing.toUpperCase()];
    assert(clientSide, "client/src/edge_landing.js no longer exports " + landing.toUpperCase() +
      ", which is the client half of the " + landing + " landing's hand-off contract.");
    COMPARED[landing].forEach(function (field) {
      assert.strictEqual(clientSide[field], edge[landing][field],
        "the " + landing + " landing and the page disagree about '" + field + "': " +
        "infra/edge/edge_common.js says '" + edge[landing][field] + "', " +
        "client/src/edge_landing.js says '" + clientSide[field] + "'. Deployed, that means the Lambda " +
        "puts the response where the page will not look for it, and every static sign-in reports that " +
        "nothing arrived. Change both.");
    });
  });

  say("The edge landings and edge_landing.js agree on the hand-off contract.");
  return true;
}

module.exports = { assertEdgeLandingContract: assertEdgeLandingContract };
