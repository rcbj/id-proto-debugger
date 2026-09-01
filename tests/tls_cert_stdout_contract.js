// File: tls_cert_stdout_contract.js
//
// THE STACK TLS CERTIFICATE IS HANDED FROM A NODE SCRIPT TO A SHELL FUNCTION
// OVER ONE CHANNEL, AND THAT CHANNEL HAS TO CARRY THREE LINES AND NOTHING
// ELSE.
//
// common/common.sh's generateStackTlsCertificate() runs
// common/generate_tls_cert.js and reads three `KEY=value` lines off its
// stdout. Every launcher calls it before compose starts, so the api, the
// client and the mock STS all bind — or fail to bind — on what comes back
// through it.
//
// ---------------------------------------------------------------------------
// WHY THIS NEEDS A TEST, AND WHY NOTHING ELSE WOULD HAVE CAUGHT IT.
//
// The generator is a CALLER of client/src/x509.js and key_material.js, and
// every module under client/src carries a bunyan logger whose stream is
// process.stdout and whose level is read from CONFIG_FILE — which the
// launchers export, which resolves from client/src/ because require() is
// relative to the module that calls it, and which in both ./env/local.js and
// ./env/docker-tests.js says "debug". So merely REQUIRING the authoring
// modules put ~885 JSON records on the channel the shell reads back, and
// common.sh's `eval` of it produced fourteen lines of
//
//   common/common.sh: line 392: name:pqc: command not found
//
// on ./docker-run-tests.sh — bash applying quote removal and brace expansion
// to `{"name":"pqc",…}` and reporting a module that had done nothing wrong,
// at a line number in a shell function that had not changed. Nothing failed:
// the assignments came last, so the certificate was still generated and the
// run went on. That is the shape of defect this file exists for — the next
// log line, or the next module required, lands somewhere that is not the end,
// and then the eval is not noise but a certificate the stack never gets.
//
// The fix has two halves and this holds both: the generator takes stdout away
// from everything but its own three lines (a saved reference to the real
// write, installed BEFORE the client modules are required, since those log at
// load), and common.sh PARSES rather than evals — reading only the three
// names it asked for, so no future call site can corrupt the result by adding
// a logger.
//
// ---------------------------------------------------------------------------
// AND ONE TRAP THE OBVIOUS PARSE FALLS INTO.
//
// `IFS='=' read -r var value` looks like the natural way to split
// `NAME=value` and is not: read STRIPS A TRAILING DELIMITER, so the base64
// SPKI pin arrives without its own `=` padding. A pin one character short is
// rejected by nothing — Chrome's --ignore-certificate-errors-spki-list simply
// never matches it, which is indistinguishable from the flag being ignored,
// on a stack whose certificate is self-signed anyway. So the pin is compared
// here against one computed independently with node's own crypto, through the
// shell, padding included.
//
// ---------------------------------------------------------------------------
// WHAT RUNS WHERE.
//
// The source checks are node-only and run everywhere, including the tests
// image (both files are COPYed in for them). The two behavioural sections
// need client/node_modules — the generator requires pkijs, asn1js and the
// @noble family — which is exactly the condition generateStackTlsCertificate()
// itself checks, and which the tests image does not satisfy: they run on the
// host launchers and say why they did not otherwise.
// ---------------------------------------------------------------------------
const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const bunyan = require("bunyan");
const { spawnSync } = require("child_process");
const { Command, Option } = require("commander");

var log = bunyan.createLogger({
  name: "tls_cert_stdout_contract",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      // No CONFIG_FILE, or it does not resolve from here. Falling back to
      // info loses only the configured verbosity.
      return "info";
    }
  })()
});

// Flat in the tests container, in the repository in a checkout — the same
// arrangement tests/compose_env_forwarding.js reads common.sh under.
function locate(candidates) {
  log.debug("Entering locate().");
  const found = candidates.filter(function (p) {
    return fs.existsSync(p);
  })[0];
  log.debug("Leaving locate(). " + (found || "none"));
  return found;
}

const GENERATOR_PATH = locate([
  path.join(__dirname, "generate_tls_cert.js"),
  path.join(__dirname, "..", "common", "generate_tls_cert.js")]);

const COMMON_SH_PATH = locate([
  path.join(__dirname, "common.sh"),
  path.join(__dirname, "..", "common", "common.sh")]);

// The repository root, or "" in the tests image. client/package.json is the
// discriminator for the same reason tests/CLAUDE.md gives for xml_parse_inert
// and jwk_pem_encoding: it sits OUTSIDE client/src, so no mirror of that
// directory into the image can ever come to contain it.
const REPO_ROOT = (function () {
  const root = path.join(__dirname, "..");
  if (fs.existsSync(path.join(root, "client", "package.json"))) {
    return root;
  }
  return "";
})();

// ---------------------------------------------------------------------------
// Section 1 — the generator's own source.
// ---------------------------------------------------------------------------

// Read a statement rather than a line: the 80-column rule means any of these
// calls may be wrapped, and tests/CLAUDE.md records four checks that stopped
// asserting the day somebody reformatted the file they read.
function statements(source) {
  log.debug("Entering statements().");
  const joined = source.split("\n").map(function (line) {
    return line.replace(/\/\/.*$/, "");
  }).join(" ").replace(/\s+/g, " ");
  log.debug("Leaving statements().");
  return joined;
}

function theGeneratorTakesStdoutAwayBeforeRequiringTheClientModules() {
  log.debug("Entering theGeneratorTakesStdoutAwayBeforeRequiringTheClient" +
            "Modules().");
  const source = fs.readFileSync(GENERATOR_PATH, "utf8");
  const flat = statements(source);

  assert.ok(/process\.stdout\.write\.bind\s*\(\s*process\.stdout\s*\)/
      .test(flat),
    GENERATOR_PATH + " no longer saves a reference to the real " +
    "process.stdout.write. Its three KEY=value lines have to be written " +
    "through one, because the write itself is redirected to stderr for the " +
    "rest of the run.");
  assert.ok(/process\.stdout\.write\s*=\s*function/.test(flat),
    GENERATOR_PATH + " no longer replaces process.stdout.write. Without " +
    "that, every bunyan logger in client/src writes its records to the " +
    "channel common/common.sh reads the certificate's paths off — see the " +
    "header of this test.");

  const patchAt = source.search(/process\.stdout\.write\s*=\s*function/);
  const requireAt = source.search(/require\('\.\.\/client\/src\//);
  assert.ok(requireAt !== -1,
    GENERATOR_PATH + " no longer requires client/src, so this test is " +
    "reading the wrong file or the generator has been rewritten. It must " +
    "fail rather than pass without checking anything.");
  assert.ok(patchAt !== -1 && patchAt < requireAt,
    "process.stdout.write is replaced AFTER the client modules are " +
    "required in " + GENERATOR_PATH + ". Those modules log at LOAD time " +
    "(pqc.js sizes every SLH-DSA parameter set as it builds its table), so " +
    "the records land on stdout before the guard is installed and the " +
    "shell reads them back as though they were assignments.");

  // console.log writes to stdout however the write is spelled, so the file
  // must not carry one at all.
  assert.ok(!/console\.log\s*\(/.test(flat),
    GENERATOR_PATH + " contains a console.log(). Everything this script " +
    "says about itself goes to stderr — its log shim is console.error " +
    "backed for exactly that reason — because stdout is parsed by " +
    "common/common.sh.");

  // The emissions themselves.
  const emissions = source.match(/^\s*\S+\('STACK_TLS_[A-Z_]+='.*$/gm) || [];
  assert.strictEqual(emissions.length, 3,
    "expected the three STACK_TLS_* emissions in " + GENERATOR_PATH +
    " and found " + emissions.length + ". common/common.sh reads exactly " +
    "STACK_TLS_KEY_FILE, STACK_TLS_CERT_FILE and STACK_TLS_SPKI_PIN.");
  emissions.forEach(function (line) {
    assert.ok(/writeStdout\(/.test(line),
      "this line writes an assignment through something other than the " +
      "saved stdout reference, so it goes to stderr with everything else " +
      "and common/common.sh sees no assignment at all: " + line.trim());
  });

  log.info("the generator takes stdout away before requiring client/src, " +
           "and prints its three assignments through the saved reference.");
  log.debug("Leaving theGeneratorTakesStdoutAwayBeforeRequiringTheClient" +
            "Modules().");
}

// ---------------------------------------------------------------------------
// Section 2 — the shell's half of the contract.
// ---------------------------------------------------------------------------

// From `generateStackTlsCertificate()` to the closing brace in column 1. Read
// as a unit because every assertion below is about THAT function: common.sh
// is 2700 lines and an `eval` elsewhere in it is somebody else's business.
function generateStackTlsCertificateBody(source) {
  log.debug("Entering generateStackTlsCertificateBody().");
  const lines = source.split("\n");
  var start = -1;
  for (var at = 0; at < lines.length; at++) {
    if (/^generateStackTlsCertificate\s*\(\s*\)/.test(lines[at])) {
      start = at;
      break;
    }
  }
  if (start === -1) {
    log.debug("Leaving generateStackTlsCertificateBody(). Not found.");
    return "";
  }
  const body = [];
  for (var here = start; here < lines.length; here++) {
    body.push(lines[here]);
    if (here > start && /^\}\s*$/.test(lines[here])) {
      break;
    }
  }
  log.debug("Leaving generateStackTlsCertificateBody(). " + body.length +
            " lines.");
  return body.join("\n");
}

function theLauncherParsesThatOutputRatherThanEvaluatingIt() {
  log.debug("Entering theLauncherParsesThatOutputRatherThanEvaluatingIt().");
  const body = generateStackTlsCertificateBody(
    fs.readFileSync(COMMON_SH_PATH, "utf8"));
  assert.ok(body,
    "generateStackTlsCertificate() was not found in " + COMMON_SH_PATH +
    ". This test asserts nothing without it and must fail rather than pass.");

  const code = body.split("\n").filter(function (line) {
    return !/^\s*#/.test(line);
  }).join("\n");

  assert.ok(!/\beval\b/.test(code),
    "generateStackTlsCertificate() evaluates something. The generator's " +
    "stdout is read back into shell variables and it is a channel other " +
    "code writes to — bunyan records from every module under client/src — " +
    "so it is PARSED here, never evaluated. An eval of a log line applies " +
    "quote removal, brace expansion and command substitution to it: the " +
    "records that produced `name:pqc: command not found` were harmless, " +
    "and a message carrying a backtick would not have been.");

  ["STACK_TLS_KEY_FILE", "STACK_TLS_CERT_FILE", "STACK_TLS_SPKI_PIN"]
    .forEach(function (name) {
      assert.ok(code.indexOf(name) !== -1,
        name + " is no longer named in generateStackTlsCertificate(). The " +
        "parse accepts the three assignments BY NAME, so a name it does " +
        "not list is silently dropped and the launcher continues with an " +
        "empty variable.");
    });

  assert.ok(!/IFS='='\s+read/.test(code) && !/IFS="="\s+read/.test(code),
    "generateStackTlsCertificate() splits the generator's output with " +
    "`IFS='=' read`, which strips a TRAILING delimiter — so the base64 " +
    "SPKI pin loses its own `=` padding. Nothing rejects a short pin: " +
    "Chrome's --ignore-certificate-errors-spki-list simply never matches " +
    "it, which looks exactly like the flag being ignored. Split with " +
    "${line%%=*} / ${line#*=} instead.");

  assert.ok(/STACK_TLS_SPKI_PIN:-/.test(code) ||
            /-z\s+"\$\{STACK_TLS_SPKI_PIN/.test(code),
    "generateStackTlsCertificate() no longer checks that it actually got " +
    "the three assignments. A parse that keeps only the names it wants " +
    "reports NOTHING when it finds none of them, so a generator that " +
    "printed only diagnostics would leave the launcher with three empty " +
    "variables and a zero exit code.");

  log.info("the launcher parses the generator's stdout by name, does not " +
           "eval it, and does not lose the pin's base64 padding.");
  log.debug("Leaving theLauncherParsesThatOutputRatherThanEvaluatingIt().");
}

// ---------------------------------------------------------------------------
// Section 3 — running it, which is the only half that can see a NEW writer.
// ---------------------------------------------------------------------------

// A CONFIG_FILE of this test's own, absolute, so `require(CONFIG_FILE)` from
// inside client/src resolves to it and every logger there is at debug. The
// launchers' own ./env/*.js say debug today; writing one here means this test
// still exercises the noisy case if that ever changes, and lets section 3
// ASSERT the noise was produced rather than passing because nothing logged.
function writeDebugConfig(dir) {
  log.debug("Entering writeDebugConfig().");
  const file = path.join(dir, "debug-config.js");
  fs.writeFileSync(file,
    "// Written by tests/tls_cert_stdout_contract.js. Every module under\n" +
    "// client/src reads its bunyan level from require(CONFIG_FILE).\n" +
    "module.exports = { logLevel: \"debug\", LOG_LEVEL: \"debug\" };\n");
  log.debug("Leaving writeDebugConfig().");
  return file;
}

// The base64 SHA-256 of the certificate's SubjectPublicKeyInfo, computed here
// rather than taken from the generator — the point is to have a second
// opinion on the value that crosses the channel, padding included.
function spkiPin(certPath) {
  log.debug("Entering spkiPin().");
  const der = new crypto.X509Certificate(fs.readFileSync(certPath))
    .publicKey.export({ type: "spki", format: "der" });
  const pin = crypto.createHash("sha256").update(der).digest("base64");
  log.debug("Leaving spkiPin().");
  return pin;
}

function onlyTheThreeAssignmentsReachStdout(outDir, configFile) {
  log.debug("Entering onlyTheThreeAssignmentsReachStdout().");
  const run = spawnSync(process.execPath,
    [path.join(REPO_ROOT, "common", "generate_tls_cert.js"),
     "--out-dir", outDir],
    { encoding: "utf8", cwd: REPO_ROOT,
      env: Object.assign({}, process.env, { CONFIG_FILE: configFile }) });
  assert.strictEqual(run.status, 0,
    "common/generate_tls_cert.js exited " + run.status + ". Its stderr " +
    "was:\n" + String(run.stderr || "").split("\n").slice(-20).join("\n"));

  const lines = String(run.stdout || "").split("\n").filter(function (line) {
    return line.trim() !== "";
  });
  const strays = lines.filter(function (line) {
    return !/^STACK_TLS_(KEY_FILE|CERT_FILE|SPKI_PIN)=\S/.test(line);
  });
  assert.deepStrictEqual(strays, [],
    "these lines reached the generator's stdout and are not assignments. " +
    "common/common.sh reads that channel for the certificate's paths, so " +
    "anything else on it is at best noise in the run log and at worst — " +
    "while it was an `eval` — shell input:\n" +
    strays.slice(0, 5).join("\n"));
  assert.strictEqual(lines.length, 3,
    "expected exactly three assignments on the generator's stdout and got " +
    lines.length + ": " + lines.join(" | "));

  // NOT VACUOUS: the run has to have produced the records that used to land
  // here, or this section proves only that a quiet program is quiet.
  const noise = String(run.stderr || "").split("\n").filter(function (line) {
    return /"name":"(pqc|crypto_bytes|x509|key_material)"/.test(line);
  });
  assert.ok(noise.length > 0,
    "no bunyan record from a client/src module reached stderr, so this " +
    "section did not exercise the case it exists for. The CONFIG_FILE " +
    "written by this test sets logLevel debug; if those modules stopped " +
    "reading it, the check has to follow them rather than pass.");

  const values = {};
  lines.forEach(function (line) {
    values[line.slice(0, line.indexOf("="))] =
      line.slice(line.indexOf("=") + 1);
  });
  assert.ok(fs.existsSync(values.STACK_TLS_CERT_FILE),
    "STACK_TLS_CERT_FILE names a file that does not exist: " +
    values.STACK_TLS_CERT_FILE);
  assert.strictEqual(values.STACK_TLS_SPKI_PIN,
    spkiPin(values.STACK_TLS_CERT_FILE),
    "the pin the generator printed is not the base64 SHA-256 of its " +
    "certificate's SubjectPublicKeyInfo.");

  log.info("the generator printed three assignments and nothing else, with " +
           noise.length + " client/src log records on stderr where they " +
           "belong.");
  log.debug("Leaving onlyTheThreeAssignmentsReachStdout().");
  return values;
}

// ---------------------------------------------------------------------------
// Section 4 — through the shell function the launchers actually call, under
// `set -x`, which is how all four of them run it.
// ---------------------------------------------------------------------------
function theShellFunctionReadsThemBackIntact(outDir, configFile) {
  log.debug("Entering theShellFunctionReadsThemBackIntact().");
  const script = [
    "set -u",
    ". \"" + COMMON_SH_PATH + "\"",
    "unset STACK_TLS_CERT_FILE STACK_TLS_KEY_FILE",
    "export STACK_TLS_DIR=\"" + outDir + "\"",
    // The launchers all run with xtrace on, and the function turns it off
    // around the generator and back on afterwards; run it the same way, so a
    // regression in that save/restore is visible here too.
    "set -x",
    "generateStackTlsCertificate \"" + REPO_ROOT + "\" > /dev/null",
    "rc=$?",
    "set +x",
    "printf 'RC=%s\\n' \"${rc}\"",
    "printf 'KEY=%s\\n' \"${STACK_TLS_KEY_FILE:-}\"",
    "printf 'CERT=%s\\n' \"${STACK_TLS_CERT_FILE:-}\"",
    "printf 'CA=%s\\n' \"${STACK_TLS_CA_FILE:-}\"",
    "printf 'PIN=%s\\n' \"${STACK_TLS_SPKI_PIN:-}\"",
  ].join("\n");

  const run = spawnSync("bash", ["-c", script],
    { encoding: "utf8", cwd: REPO_ROOT,
      env: Object.assign({}, process.env, { CONFIG_FILE: configFile }) });

  const read = {};
  String(run.stdout || "").split("\n").forEach(function (line) {
    const at = line.indexOf("=");
    if (at > 0) {
      read[line.slice(0, at)] = line.slice(at + 1);
    }
  });

  // THE SYMPTOM ITSELF. Every one of the fourteen lines on 2026-08-31 was a
  // `command not found` from the eval, and the whole run still reported
  // success — so the exit code is not what this asserts on.
  const complaints = String(run.stderr || "").split("\n")
    .filter(function (line) {
      return /command not found|syntax error|unexpected token/.test(line);
    });
  assert.deepStrictEqual(complaints, [],
    "the shell complained while reading the generator's output back. That " +
    "is the defect this test exists for: bunyan records on stdout, quote " +
    "removal and brace expansion applied to them, and a run that carries " +
    "on regardless:\n" + complaints.slice(0, 5).join("\n"));

  assert.strictEqual(read.RC, "0",
    "generateStackTlsCertificate() returned " + read.RC + ". Its stderr " +
    "ended:\n" + String(run.stderr || "").split("\n").slice(-15).join("\n"));
  assert.ok(read.KEY && fs.existsSync(read.KEY),
    "STACK_TLS_KEY_FILE did not come back out of the shell function as a " +
    "readable path (got: " + JSON.stringify(read.KEY) + ").");
  assert.ok(read.CERT && fs.existsSync(read.CERT),
    "STACK_TLS_CERT_FILE did not come back out of the shell function as a " +
    "readable path (got: " + JSON.stringify(read.CERT) + ").");
  assert.strictEqual(read.CA, read.CERT,
    "STACK_TLS_CA_FILE is meant to be the certificate itself — it is " +
    "self-signed, so the leaf IS the anchor — and it is not.");

  // The padding, which is the whole reason this reads the value back through
  // bash rather than trusting section 3.
  assert.strictEqual(read.PIN, spkiPin(read.CERT),
    "the SPKI pin that survived the shell is not the base64 SHA-256 of the " +
    "certificate's SubjectPublicKeyInfo. If it is the same string minus a " +
    "trailing `=`, the parse is stripping base64 padding — see the " +
    "`IFS='=' read` note in the header. Chrome would take that pin without " +
    "complaint and never match it.");
  assert.ok(/=$|[^=]$/.test(read.PIN) && read.PIN.length === 44,
    "an SPKI pin is the base64 of 32 bytes, which is 44 characters " +
    "including its padding; this one is " + read.PIN.length + ": " +
    read.PIN);

  log.info("generateStackTlsCertificate() read all three values back " +
           "intact, pin included, with a clean shell stderr.");
  log.debug("Leaving theShellFunctionReadsThemBackIntact().");
}

function test() {
  log.debug("Entering test().");
  assert.ok(GENERATOR_PATH,
    "common/generate_tls_cert.js was not found beside this test or in the " +
    "repository. It is COPYed into the tests image for exactly this check, " +
    "so a missing file is a missing COPY line rather than a reason to skip.");
  assert.ok(COMMON_SH_PATH,
    "common/common.sh was not found beside this test or in the repository. " +
    "generateStackTlsCertificate() is defined there and this test asserts " +
    "nothing without it.");

  theGeneratorTakesStdoutAwayBeforeRequiringTheClientModules();
  theLauncherParsesThatOutputRatherThanEvaluatingIt();

  // The two behavioural sections need what generateStackTlsCertificate()
  // itself needs: client/node_modules, where pkijs, asn1js and the @noble
  // family resolve. The tests image has the modules mirrored but not their
  // dependencies, which is why the flat copies exist for everything else.
  if (!REPO_ROOT ||
      !fs.existsSync(path.join(REPO_ROOT, "client", "node_modules"))) {
    log.warn("running the generator was skipped: this is not a checkout " +
             "with client/node_modules, so common/generate_tls_cert.js " +
             "would die on `Cannot find module 'pkijs'` — the same " +
             "condition generateStackTlsCertificate() checks by name. The " +
             "source checks above ran. Use ./local-run-tests.sh for the " +
             "other two sections.");
    log.info("Test completed successfully.");
    log.debug("Leaving test(). Source checks only.");
    return;
  }

  const work = fs.mkdtempSync(path.join(os.tmpdir(), "tls-stdout-"));
  try {
    const configFile = writeDebugConfig(work);
    onlyTheThreeAssignmentsReachStdout(path.join(work, "direct"), configFile);
    theShellFunctionReadsThemBackIntact(path.join(work, "shell"), configFile);
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }

  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("tls_cert_stdout_contract")
  .description("Verify that common/generate_tls_cert.js prints its three " +
               "assignments and nothing else, and that common/common.sh " +
               "parses rather than evaluates them.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

try {
  test();
} catch (e) {
  log.error(e.stack || e.message);
  process.exit(1);
}
