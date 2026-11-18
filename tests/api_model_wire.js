// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: api_model_wire.js
//
// ---------------------------------------------------------------------------
// THE API ANSWERS WHAT IT ANSWERED BEFORE ITS MODEL, AND WHAT ITS MODEL SAYS.
//
// Every family of api endpoints moved onto common/model/openapi.json the same
// way (docs/data-model.md, "How a family switches"): its requests were sent
// to the api as it WAS, and each answer was written into
// fixtures/api_model/<family>.json. Then the family's model was written, the
// route was given its validator, and the hand-written check it replaced was
// deleted. This replays every one of those requests and requires:
//
//  1. the same status and the same body, member for member, apart from the
//     members a case names as `volatile` (a timing, a generated id);
//  2. an answer the document describes — the status is one the operation
//     lists, and the body matches that status's schema;
//  3. a case for every operation in the document, so a new operation cannot
//     arrive without its recordings.
//
// A case sends `body` (JSON), `form` (form-encoded) or `text` (under its
// `contentType`, as a Security Event Token is pushed); a 3xx is recorded
// with its `location`, which `volatile` may name like a body member.
//
// A case whose answer CHANGED on purpose carries `changed` (why) and
// `before` (what the api answered until then), so the delta is in the file
// rather than in somebody's memory of a review.
//
// Against a running api: API_URL (default https://localhost:4000), with the
// stack's anchor in NODE_EXTRA_CA_CERTS like every other api test here. The
// recordings were made with api/env/docker-tests.js, which is the
// configuration the containerized stack runs; a refusal that depends on a
// setting (an allowed port) depends on that file.
//
//   node api_model_wire.js                  replay and assert
//   node api_model_wire.js --record         re-record every case's `expect`
//   node api_model_wire.js --record --missing
//                                           record only cases that have none
//   node api_model_wire.js --family ldap    one family only
//
// Node only — no browser.
// ---------------------------------------------------------------------------

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "api_model_wire",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

const program = new Command();
program
  .option("--record", "write each case's answer into its fixture")
  .option("--missing", "with --record, only cases with no answer yet")
  .option("--family <name>", "one fixture family only")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);
const options = program.opts();

const API_URL = (process.env.API_URL || "https://localhost:4000")
  .replace(/\/+$/, "");
const FIXTURES = path.join(__dirname, "fixtures", "api_model");

// api/model_validate.js, which reads ../common/model/openapi.json from where
// it sits: tests/../api in a checkout, and the flat copy beside this file in
// the tests image (where ../common is /usr/src/common).
const modelValidate = paths.requireSharedModule([
  path.join(__dirname, "..", "api", "model_validate.js"),
  path.join(__dirname, "model_validate.js")
], "api/model_validate.js");

function readFamilies() {
  log.debug("Entering readFamilies().");
  const files = fs.readdirSync(FIXTURES).filter(function (f) {
    return f.endsWith(".json");
  }).sort();
  const families = files.map(function (f) {
    const file = path.join(FIXTURES, f);
    return { file: file, doc: JSON.parse(fs.readFileSync(file, "utf8")) };
  }).filter(function (family) {
    return !options.family || family.doc.family === options.family;
  });
  log.debug("Leaving readFamilies(). " + families.length);
  return families;
}

// A case sends `body` as JSON, or `form` as application/x-www-form-urlencoded
// (what an identity provider's browser POSTs), and redirects are NOT
// followed: a 3xx is recorded with its Location, which for the SAML and
// WS-Federation endpoints is the answer.
async function send(testCase) {
  log.debug("Entering send(). " + testCase.method + " " + testCase.path);
  const init = { method: testCase.method, headers: {}, redirect: "manual" };
  if (testCase.text !== undefined) {
    init.headers["Content-Type"] = testCase.contentType || "text/plain";
    init.body = String(testCase.text);
  } else if (testCase.form !== undefined) {
    init.headers["Content-Type"] = "application/x-www-form-urlencoded";
    init.body = new URLSearchParams(testCase.form).toString();
  } else if (testCase.body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(testCase.body);
  }
  let response;
  try {
    response = await fetch(API_URL + testCase.path, init);
  } catch (e) {
    log.debug("Leaving send(). The fetch failed.");
    throw new Error("could not reach " + API_URL + testCase.path + ": " +
      (e.cause ? e.cause.message : e.message) +
      ". Is the api running, and is API_URL right?");
  }
  const raw = await response.text();
  let body;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    body = { "(not JSON)": raw };
  }
  const answer = { status: response.status, body: body };
  const location = response.headers.get("location");
  if (location !== null) {
    answer.location = location;
  }
  log.debug("Leaving send(). " + response.status);
  return answer;
}

// Removes each dotted path a case names as volatile, so what is left is
// what must be identical.
function withoutVolatile(answer, volatile) {
  log.debug("Entering withoutVolatile().");
  const copy = JSON.parse(JSON.stringify(answer));
  (volatile || []).forEach(function (dotted) {
    if (dotted === "location") {
      delete copy.location;
      return;
    }
    const parts = dotted.split(".");
    let node = copy.body;
    for (let i = 0; i < parts.length - 1 && node; i++) {
      node = node[parts[i]];
    }
    if (node && typeof node === "object") {
      delete node[parts[parts.length - 1]];
    }
  });
  log.debug("Leaving withoutVolatile().");
  return copy;
}

// A NAME THAT CANNOT RESOLVE, however this machine's resolver says so. The
// fixtures send every unreachable target to an RFC 6761 `.invalid` name and
// recorded "getaddrinfo ENOTFOUND <name>". A resolver may instead answer
// EAI_AGAIN, or take long enough that the api's own connectionTimeout fires
// first ("Connection to <name>:<port> timed out after Nms
// (connectionTimeout)", code ECONNECTTIMEOUT); after a network failover on
// the integrator's host it did exactly that. All three mean the one thing
// the case is about, that the host is unreachable, so in both the recording
// and the answer each spelling is replaced by one token before comparing.
// Only for `.invalid` names, so a real target's failure is still compared
// exactly, and the status is never rewritten.
const UNREACHABLE = "<unreachable>";
const UNREACHABLE_TEXT = new RegExp(
  "getaddrinfo (?:ENOTFOUND|EAI_AGAIN) ([a-z0-9.-]+\\.invalid)" +
  "|Connection to ([a-z0-9.-]+\\.invalid)(?::\\d+)? timed out after " +
  "\\d+ms \\(connectionTimeout\\)\\.?", "g");
const UNREACHABLE_CODES = ["ENOTFOUND", "EAI_AGAIN", "ECONNECTTIMEOUT"];

function normalizeUnreachable(value) {
  log.debug("Entering normalizeUnreachable().");
  if (typeof value === "string") {
    log.debug("Leaving normalizeUnreachable(). String.");
    return value.replace(UNREACHABLE_TEXT, function (m, a, b) {
      return UNREACHABLE + " " + (a || b);
    });
  }
  if (Array.isArray(value)) {
    log.debug("Leaving normalizeUnreachable(). Array.");
    return value.map(normalizeUnreachable);
  }
  if (!value || typeof value !== "object") {
    log.debug("Leaving normalizeUnreachable(). Scalar.");
    return value;
  }
  const out = {};
  Object.keys(value).forEach(function (k) {
    out[k] = normalizeUnreachable(value[k]);
  });
  // The error code beside such a message, and only beside one.
  if (UNREACHABLE_CODES.indexOf(out.code) >= 0 &&
      JSON.stringify(out).indexOf(UNREACHABLE) >= 0) {
    out.code = UNREACHABLE;
  }
  log.debug("Leaving normalizeUnreachable(). Object.");
  return out;
}

async function record(families) {
  log.debug("Entering record().");
  for (const family of families) {
    let changed = 0;
    for (const testCase of family.doc.cases) {
      if (options.missing && testCase.expect) {
        continue;
      }
      testCase.expect = await send(testCase);
      changed = changed + 1;
      log.info("[" + family.doc.family + "] " + testCase.name + " -> " +
               testCase.expect.status);
    }
    fs.writeFileSync(family.file, JSON.stringify(family.doc, null, 2) + "\n");
    log.info("[" + family.doc.family + "] recorded " + changed + " cases " +
             "into " + path.basename(family.file));
  }
  log.debug("Leaving record().");
}

async function replay(families, model) {
  log.debug("Entering replay().");
  const failures = [];
  const covered = new Set();
  let count = 0;
  for (const family of families) {
    for (const testCase of family.doc.cases) {
      const label = "[" + family.doc.family + "] " + testCase.name;
      if (!testCase.expect) {
        failures.push(label + ": no recorded answer; run with --record " +
                      "--missing against the api it describes.");
        continue;
      }
      const op = model.operationFor(testCase.method,
                                    testCase.path.split("?")[0]);
      if (!op) {
        failures.push(label + ": " + testCase.method + " " + testCase.path +
                      " is no operation in the API document.");
        continue;
      }
      covered.add(op.operationId);
      const got = await send(testCase);
      count = count + 1;
      try {
        assert.deepStrictEqual(
            normalizeUnreachable(withoutVolatile(got, testCase.volatile)),
            normalizeUnreachable(withoutVolatile(testCase.expect,
                                                 testCase.volatile)));
      } catch (e) {
        failures.push(label + ": the answer is not the recorded one.\n" +
          "    recorded: " + JSON.stringify(testCase.expect) + "\n" +
          "    got:      " + JSON.stringify(got));
        continue;
      }
      const problems = model.answerProblems(op.operationId, got.status,
                                            got.body);
      if (problems.length) {
        failures.push(label + ": the answer is not what the document " +
          "describes for " + op.operationId + " " + got.status + ":\n" +
          problems.map(function (p) {
            return "    " + (p.instancePath || "/") + " " + p.keyword +
              ": " + p.message;
          }).join("\n"));
        continue;
      }
      log.info("ok  " + label + " (" + got.status + ")");
    }
  }
  if (!options.family) {
    Object.keys(model.operations).sort().forEach(function (id) {
      if (!covered.has(id)) {
        failures.push(id + " is in the API document and no fixture " +
          "replays it. Record its answers before its family switches.");
      }
    });
  }
  log.debug("Leaving replay(). " + failures.length + " failures.");
  return { failures: failures, count: count };
}

async function main() {
  log.debug("Entering main().");
  const families = readFamilies();
  if (!families.length) {
    throw new Error("no fixture family" + (options.family ?
      " named " + options.family : "") + " under " + FIXTURES);
  }
  if (options.record) {
    await record(families);
    log.debug("Leaving main(). Recorded.");
    return;
  }
  const model = modelValidate.createModel({});
  const result = await replay(families, model);
  if (result.failures.length) {
    result.failures.forEach(function (f) {
      log.error("FAIL " + f);
    });
    throw new Error(result.failures.length + " of the api's answers are " +
      "not what the model and its recordings say.");
  }
  log.info("All " + result.count + " recorded answers replayed, every one " +
           "described by the API document, and every operation covered.");
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error(e && e.stack ? e.stack : String(e));
  process.exitCode = 1;
});
