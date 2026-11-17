// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: api_model_gaps.js
//
// ---------------------------------------------------------------------------
// NO ANSWER THE API SENT DURING THIS RUN IS ONE ITS DOCUMENT DOES NOT DESCRIBE.
//
// api_model_wire.js holds the answers somebody RECORDED to the API document.
// This holds every other one: with `validateResponses` on (api/env/
// docker-tests.js), api/model_validate.js checks each answer against its
// operation's response schema in common/model/openapi.json and keeps a record
// of every disagreement, which GET /model/gaps returns. The suite runs this
// job LAST (`last: true` in run-report.js), after every other job has driven
// the api, so the record covers the whole run.
//
// A gap is the document being wrong about the api, or the api having changed
// without its model: either way the fix is in models/api/, and the gap names
// the operation, the status and the member.
//
// Skips — a configuration fact, not a defect — when the api answers 404,
// which is validateResponses off. Fails when the api cannot be reached.
// Node only.
// ---------------------------------------------------------------------------

const { declineToRun } = require("./expectation.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "api_model_gaps",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

const API_URL = (process.env.API_URL || "https://localhost:4000")
  .replace(/\/+$/, "");

async function main() {
  log.debug("Entering main().");
  let response;
  try {
    response = await fetch(API_URL + "/model/gaps");
  } catch (e) {
    log.debug("Leaving main(). The fetch failed.");
    throw new Error("could not reach " + API_URL + "/model/gaps: " +
      (e.cause ? e.cause.message : e.message) +
      ". Is the api running, and is API_URL right?");
  }
  if (response.status === 404) {
    declineToRun(log, "the api at " + API_URL + " keeps no record of its " +
      "answers: validateResponses is off in its configuration " +
      "(api/env/docker-tests.js turns it on).");
    log.debug("Leaving main(). Skipped.");
    return;
  }
  const body = await response.json();
  if (response.status !== 200 || !Array.isArray(body.gaps)) {
    log.debug("Leaving main(). Not the gaps document.");
    throw new Error("GET /model/gaps answered " + response.status + ": " +
                    JSON.stringify(body));
  }
  if (body.gaps.length) {
    body.gaps.forEach(function (gap) {
      log.error("MODEL GAP " + gap.operationId + " " + gap.status + " " +
        (gap.instancePath || "/") + " " + gap.keyword + ": " + gap.message +
        " (" + gap.count + " answer" + (gap.count === 1 ? "" : "s") + ")");
    });
    log.debug("Leaving main(). Gaps.");
    throw new Error(body.gaps.length + " kinds of answer this run are not " +
      "what common/model/openapi.json describes. Fix models/api/ (or the " +
      "handler), regenerate, and run again.");
  }
  log.info("Every answer the api sent this run is one its document " +
           "describes.");
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error(e && e.message ? e.message : String(e));
  process.exitCode = 1;
});
