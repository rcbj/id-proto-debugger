// File: krb5_mit_client.js
//
// ---------------------------------------------------------------------------
// THE MOCK KDC, DRIVEN BY MIT KERBEROS ITSELF — `kinit`, `klist`, `kvno`,
// `kdestroy`, and `curl --negotiate`.
//
// Every other Kerberos test in this suite drives the mock with a client this
// project wrote. `krb5_as_exchange.js`, `krb5_tgs_ap.js` and
// `krb5_spnego_http.js` use `common/krb5/`; `kerberos_as_page.js`,
// `kerberos_tgs_ap_page.js`, `kerberos_spnego_page.js` and
// `kerberos_spnego_signin.js` drive the same code through the debugger's pages.
// All of them are worth having and NONE of them can answer the question this
// file exists for: **does any of it interoperate with a real Kerberos?**
//
// ---------------------------------------------------------------------------
// WHY THAT QUESTION IS NOT ACADEMIC.
//
// It was answered NO on 2026-08-27, for as long as the mock KDC had existed,
// and nothing here could have noticed. Its `KDC_ERR_PREAUTH_REQUIRED` carried
// `PA-ETYPE-INFO2` and `PA-PW-SALT` and not `PA-ENC-TIMESTAMP` — so it named
// the salt a client needs without ever naming the METHOD it wanted. RFC 4120
// section 5.9.1 makes that field the list of pre-authentication methods the KDC
// accepts, and MIT's client reads it to decide what to send next. Finding
// nothing it could run, `kinit` retried the same unauthenticated AS-REQ and
// gave
// up with `Generic preauthentication failure while getting initial
// credentials` — a message naming neither the padata list nor this KDC. Chrome
// and Firefox answer a `Negotiate` challenge through the same GSSAPI, so no
// browser could ever have signed in at `/spnego/protected` or `/authn/spnego`
// either.
//
// **THE REASON NOTHING NOTICED IS THE REASON THIS FILE EXISTS.** The debugger's
// client and every test in both repositories send PA-ENC-TIMESTAMP whether it
// was offered or not, because all of them were written against this KDC. Both
// ends shared the assumption, so both ends agreed, and every test passed. That
// is the shape of every interoperability defect a mock can have, and the only
// thing that finds one is an implementation nobody here wrote.
//
// So section 1 below IS the guard for that defect: `kinit` completing at all
// means the method list was honest. It is stated that way in the failure
// message, because "kinit failed" is otherwise the least informative sentence
// in Kerberos.
//
// ---------------------------------------------------------------------------
// WHAT IT COVERS, AND WHY THE REFUSALS ARE THE INTERESTING HALF.
//
// A KDC that issues a ticket to a correct password looks finished and is worth
// very little — the same argument `sts_dpop.js` and `sts_saml11.js` make. This
// file drives fourteen sections and NINE of them are refusals, each asserted
// against the KDC's OWN error rather than against the client's summary of it:
//
//   * both AS exchanges — the two-message dance with pre-authentication, and
//     the ONE-message case (`noreauth`), asserted apart by how many errors the
//     KDC returned along the way rather than by anything either end says;
//   * a wrong password, a revoked account, an expired password, an account
//     offering only an encryption type a 2025 client refuses, and two names the
//     KDC will never create;
//   * the TGS exchange, and an SPN for a host this service will not BE;
//   * SPNEGO over HTTP at both doors — the protected page that authenticates
//     and throws the identity away, and the sign-in that mints a session;
//   * that the session then satisfies `/oauth2/authorize`;
//   * a REPLAYED AP-REQ, refused;
//   * `kdestroy`, after which the same command cannot authenticate;
// * and `krb5.spnegoAuthentication` off, answering 403 and naming the setting.
//
// **THE KDC'S ANSWER IS READ OFF `KRB5_TRACE`, NOT OFF stderr**, and the
// `expired` account is why. The mock answers it `KDC_ERR_KEY_EXPIRED`, which is
// correct; MIT then does what a real client does next — asks for a
// `kadmin/changepw` ticket so the user can fix it — and the mock has no such
// service, so the LAST thing `kinit` prints is `Server not found in Kerberos
// database`. A test asserting on that message would be asserting the mock got
// the wrong answer when it got the right one. The trace carries what the KDC
// actually said, and that is what these assertions read.
//
// ---------------------------------------------------------------------------
// IT TOUCHES NOTHING OUTSIDE ITS OWN TEMPORARY DIRECTORY.
//
// `KRB5_CONFIG` and `KRB5CCNAME` are per-run, written under the system temp
// directory and stamped with the pid, so this needs no root, does not read or
// write `/etc/krb5.conf`, cannot disturb a Kerberos setup the machine already
// has, and two of these running at once cannot share a credential cache. The
// directory is removed at the end whatever happened.
//
// It SKIPS with a named reason when the MIT tools are absent or when curl was
// built without GSS-API — which is most machines — and it FAILS when they are
// there and the KDC is wrong. `tests/Dockerfile` installs `krb5-user` so the
// containerized suite always runs it.
//
// It holds the `sts-spnego-signin` JOB_LOCK: section 14 turns a process-wide
// setting off on a shared service, and section 12 asserts on a replay cache
// that a concurrent ticket-spending job would disturb.
// ---------------------------------------------------------------------------

const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
const registry = require("./sts_applications.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "krb5_mit_client",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

// The mock, as THIS PROCESS reaches it — which is what matters here, because
// this process is the client. Not the browser's view: there is no browser in
// this file at all.
var stsUrl = (process.env.STS_URL || "https://localhost:8081")
    .replace(/\/+$/, "");
// THE KDC AS THIS PROCESS DIALS IT, AND ITS OWN VARIABLE RATHER THAN THE ONE
// EVERY OTHER KERBEROS JOB CARRIES — the same split SPIFFE_TEST_* draws
// against SPIFFE_*, and for the identical reason.
//
// `KRB5_KDC_HOST` is the API'S view: the five page jobs type that address into
// a page and the api's relay resolves it, so it is the compose name `sts` on
// both stacks (local-tests.yml gives the api an `extra_hosts` entry for it).
// NOTHING resolves a name for this file — `kinit` opens the socket itself, out
// here — so `sts` means nothing on a host run and MIT says
// `Cannot contact any KDC for realm 'EXAMPLE.COM'`, a message naming neither
// the variable nor the stack. That is what it said on 2026-08-27, on the first
// run after this file was written, while the KDC was up and reachable from the
// same shell.
//
// So: `localhost` by default, which is right on a host launcher (every service
// on local-tests.yml is host-networked, so the mock's port 88 IS the host's),
// and `run-tests-in-container.sh` sets these two to `sts` for the bridge stack
// exactly as it does STS_URL and SPIFFE_TEST_*.
//
// `KRB5_KDC_HOST` is DELIBERATELY not read here as a fallback. Falling back to
// it would be the same variable standing for both views again, one layer down:
// a shell that exports it for the page jobs would silently re-break this one,
// and the failure would look like a KDC defect rather than an address.
var kdcHost = process.env.KRB5_TEST_KDC_HOST || "localhost";
var kdcPort = process.env.KRB5_TEST_KDC_PORT || "88";
var realm = process.env.KRB5_REALM || "EXAMPLE.COM";
// One password for every USER account in this KDC — a published test
// credential from its own principal table, not a secret.
var password = process.env.KRB5_PASSWORD || "password!";
// The OAuth client section 11 presents once the Kerberos session exists.
var clientId = process.env.CLIENT_ID || "krb5-mit-client";

// Where this run's Kerberos configuration and credential cache live. Under the
// system temp directory and stamped with the pid, so nothing here can collide
// with another job of the same run or with the machine's own Kerberos setup.
var krbDir = null;
var krbConfig = null;

// The tools, and whether they are usable at all. Filled in by preconditions().
var tools = { kinit: null, klist: null, kvno: null, kdestroy: null,
              curl: null };

// The SPN a client derives from the mock's URL — `HTTP/<host>`, which is what
// RFC 4559 clients and every browser do. Nothing in the exchange carries it.
var spn = null;
// Whether curl must be told about the mock's self-signed certificate, and how.
var curlTls = [];

// ---------------------------------------------------------------------------
// Running one of them. `spawnSync` rather than exec: the password goes in on
// STDIN, which keeps it off every process listing on the machine, and the
// arguments are a list so nothing is ever shell-quoted.
//
// KRB5_TRACE IS ALWAYS ON AND GOES TO A FILE, NEVER TO `/dev/stderr`.
//
// That is not a preference and it cost an afternoon. MIT writes the trace by
// opening the path in KRB5_TRACE, and when this process captures stdio the
// child's `/dev/stderr` IS A PIPE — the open fails or the writes go nowhere,
// silently, and the variable appears to do nothing. `KRB5_TRACE=/dev/stderr
// kinit alice` in a terminal prints thirty lines; the same thing under
// spawnSync prints none, so a test written against what a shell does reads
// every exchange as "the KDC returned no errors" and the refusal assertions
// below all pass for the wrong reason. A real file works, and is deleted after
// each call.
//
// The trace is where the KDC's OWN answer is legible, which is the whole
// reason for having it: `kinit`'s last line is the CLIENT's summary, and for
// an expired password those two say different things (see the REFUSALS table).
// ---------------------------------------------------------------------------
var traceSequence = 0;

function run(command, args, options) {
  log.debug("Entering run(). " + command + " " + (args || []).join(" "));
  const opts = options || {};
  const tracePath = path.join(krbDir, "trace-" + (traceSequence += 1) + ".txt");
  const result = spawnSync(command, args || [], {
    input: opts.input === undefined ? "" : opts.input,
    encoding: "utf8",
    timeout: opts.timeoutMs || 60000,
    env: Object.assign({}, process.env, {
      KRB5_CONFIG: krbConfig,
      KRB5CCNAME: opts.ccache || ("FILE:" + path.join(krbDir, "ccache")),
      KRB5_TRACE: tracePath
    }, opts.env || {})
  });
  let trace = "";
  try {
    trace = fs.readFileSync(tracePath, "utf8");
    fs.unlinkSync(tracePath);
  } catch (e) {
    // No trace file: a command that never got as far as opening one (curl,
    // which has no KRB5_TRACE of its own beyond libkrb5's), or one that failed
    // before any Kerberos call. Not an error — the caller's own assertions say
    // what went wrong, and `kdcErrors` is simply empty.
    trace = "";
  }
  const answer = {
    status: result.status,
    stdout: String(result.stdout || ""),
    stderr: String(result.stderr || ""),
    trace: trace,
    // THE KDC'S OWN ERRORS, IN ORDER, AS MIT DECODED THEM — and it logs the
    // two exchanges differently, which is worth knowing before trusting this
    // list. An AS-side refusal is `Received error from KDC: -N/message`; a
    // TGS-side one is `TGS request result: -N/message`, and the SUCCESSFUL
    // TGS exchange logs that same line with code 0. A parser reading only the
    // first form sees no error for a refused TGS request and reports "the KDC
    // said nothing" for a KDC that refused clearly — which is exactly what
    // section 6 met.
    kdcErrors: trace.split("\n")
      .map(function (line) {
        const as = line.match(/Received error from KDC: -?\d+\/(.*)$/);
        if (as) {
          return as[1].trim();
        }
        const tgs = line.match(/TGS request result: (-?\d+)\/(.*)$/);
        // Code 0 is `Success`, which is not an error however it is spelled.
        if (tgs && Number(tgs[1]) !== 0) {
          return tgs[2].trim();
        }
        return null;
      })
      .filter(Boolean)
  };
  log.debug("Leaving run(). status=" + answer.status + ", " +
      answer.kdcErrors.length + " KDC error(s).");
  return answer;
}

// `kinit <who>`, with the password on stdin. Returns the same shape as run().
function kinit(who, withPassword, ccacheName) {
  log.debug("Entering kinit(). who=" + who);
  const answer = run(tools.kinit, [who + "@" + realm], {
    input: (withPassword === undefined ? password : withPassword) + "\n",
    ccache: ccacheName ? "FILE:" + path.join(krbDir, ccacheName) : undefined
  });
  log.debug("Leaving kinit(). status=" + answer.status);
  return answer;
}

// One curl call, as a list of arguments. `-D -` puts the response headers on
// stdout ahead of the body, which is how every assertion below reads a status
// and a Set-Cookie without a second request.
function curl(args, options) {
  log.debug("Entering curl().");
  const answer = run(tools.curl,
      ["-s", "-S", "-D", "-", "-o", "-"].concat(curlTls).concat(args),
      options);
  const split = answer.stdout.indexOf("\r\n\r\n");
  answer.headers = split >= 0 ? answer.stdout.slice(0, split) : answer.stdout;
  answer.body = split >= 0 ? answer.stdout.slice(split + 4) : "";
  const status = answer.headers.match(/^HTTP\/[\d.]+ (\d+)/m);
  answer.httpStatus = status ? Number(status[1]) : 0;
  log.debug("Leaving curl(). http=" + answer.httpStatus);
  return answer;
}

// A header's value out of the block `-D -` produced, case-insensitively, and
// every occurrence rather than the first — `Set-Cookie` can legitimately
// repeat.
function headerValues(headers, name) {
  log.debug("Entering headerValues(). name=" + name);
  const wanted = String(name).toLowerCase();
  const found = String(headers).split(/\r?\n/).map(function (line) {
    const at = line.indexOf(":");
    if (at < 0) {
      return null;
    }
    return line.slice(0, at).trim().toLowerCase() === wanted
      ? line.slice(at + 1).trim() : null;
  }).filter(function (one) { return one !== null; });
  log.debug("Leaving headerValues(). " + found.length + " value(s).");
  return found;
}

// The management API, for the one section that closes the door and puts it
// back.
async function adminPost(pathname, body) {
  log.debug("Entering adminPost(). " + pathname);
  const response = await fetch(stsUrl + "/admin-api" + pathname, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(body || {})
  });
  const text = await response.text();
  let parsed = null;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    // Not JSON — an HTML error page, or an empty body. The status and the raw
    // text say more than a parse error would.
    log.debug("Leaving adminPost(). Not JSON.");
    throw new Error("POST /admin-api" + pathname + " answered " +
        response.status + " with something that is not JSON: " +
        text.slice(0, 300));
  }
  log.debug("Leaving adminPost(). ok=" + parsed.ok);
  return parsed;
}

// ---------------------------------------------------------------------------
// THE CONFIGURATION THIS RUN GIVES MIT KERBEROS.
//
// Written rather than assumed, because the machine's own /etc/krb5.conf knows
// nothing about a mock KDC on a high port and must not be touched to teach it.
//
// Six settings are load-bearing, and the last three were added after runs in
// which their absence cost this whole job — see the block beside them:
//
//   `kdc = host:port`     the only way to reach a KDC that is not on 88.
//   `udp_preference_limit = 1`
//                         send everything over TCP. A UDP AS-REP carrying a PAC
//                         exceeds a datagram on some paths, and the retry logic
//                         that follows turns one clear failure into a timeout.
//   `dns_lookup_kdc/realm = false`
// never ask DNS. Without these MIT looks for SRV records
//                         for EXAMPLE.COM, which on a machine with a wildcard
//                         resolver is a delay and on a corporate one is a
//                         different KDC entirely.
//   `dns_canonicalize_hostname = false`, `rdns = false`
//                         never ask DNS about the HOST either.
//   `qualify_shortname = ""`
//                         and do not append the RESOLVER'S SEARCH DOMAIN to a
//                         short one, which is a separate step the two above do
//                         not disable. Together they are what makes the name
//                         in the URL the name in the SPN.
//
// The enctype lists are deliberately the MODERN defaults and RC4 is
// deliberately
// absent from them — section 5 asserts that the `rc4only` account is refused,
// and it is refused because a 2025 client will not offer RC4. Adding it here to
// "make that account work" would delete the assertion.
// ---------------------------------------------------------------------------
function writeKrb5Config() {
  log.debug("Entering writeKrb5Config().");
  krbDir = fs.mkdtempSync(path.join(os.tmpdir(),
      "krb5-mit-client-" + process.pid + "-"));
  krbConfig = path.join(krbDir, "krb5.conf");
  const text = [
    "[libdefaults]",
    "    default_realm = " + realm,
    "    dns_lookup_kdc = false",
    "    dns_lookup_realm = false",
    // TWO MORE DNS LOOKUPS, AND THEY ARE THE ONES THAT BROKE THE
    // CONTAINERIZED RUN OF 2026-08-27. The two above stop MIT looking for a
    // KDC in DNS; neither stops it looking up the HOST. Before deriving the
    // SPN from a URL's hostname, GSSAPI canonicalizes that name — forward
    // (`dns_canonicalize_hostname`, on) and then in reverse (`rdns`, on) — and
    // uses whatever comes back.
    //
    // On a host run the mock is `localhost`, whose PTR is `localhost`, so the
    // SPN stays HTTP/localhost and nothing is visible. On the compose network
    // it is `sts`, and Docker's embedded resolver answers the PTR for that
    // container's address with `sts.<compose-network>.` — so GSSAPI asked the
    // KDC for HTTP/sts.<compose-network>, a host that is NOT in this service's
    // SERVICE_DOMAINS, got KDC_ERR_S_PRINCIPAL_UNKNOWN, and `curl --negotiate`
    // sent no Authorization header at all. What the test then saw was the
    // ORDINARY bare 401 — the same answer an unauthenticated request gets —
    // so the failure named the protected page and the SPN the mock volunteers,
    // and nothing named DNS.
    //
    // Off, DNS is not asked about the host at all.
    "    dns_canonicalize_hostname = false",
    "    rdns = false",
    // AND THE THIRD ONE, WHICH IS THE ONE THAT ACTUALLY FIXED IT — the two
    // above are necessary and were not sufficient, and the containerized run
    // of 2026-08-27 failed IDENTICALLY with them in place.
    //
    // Qualifying a SHORT hostname is a step of its own, and MIT does it
    // whether or not DNS canonicalization is on: with
    // `dns_canonicalize_hostname` false it appends `qualify_shortname`, whose
    // default is the RESOLVER'S SEARCH DOMAIN — the `search` line of
    // /etc/resolv.conf, which docker COPIES INTO EVERY CONTAINER from the
    // host's. So `sts` became `sts.<the host's search domain>` on the bridge
    // stack, and reproducing it needed no container at all: on the machine
    // this was found on the search domain is `lan`, so pointing this file at
    // any short name of the host turned `nakita` into `nakita.lan` and failed
    // in exactly the same place. No DNS query is made for either, and neither
    // setting above is in a position to stop it.
    //
    // GSSAPI then asked the KDC for a host that is not in
    // this service's SERVICE_DOMAINS, got KDC_ERR_S_PRINCIPAL_UNKNOWN, and
    // `curl --negotiate` sent NO Authorization header at all — so what the
    // test saw was the ORDINARY bare 401, the same answer an unauthenticated
    // request gets, and the failure named the protected page and the SPN the
    // mock volunteers while naming nothing about a hostname.
    //
    // The empty string is how MIT spells "do not qualify it at all", and the
    // QUOTES ARE PART OF THE SYNTAX: `qualify_shortname =` with nothing after
    // it is a parse error, and every command dies with `Improper format of
    // Kerberos configuration file while initializing krb5 library` — a message
    // about the file rather than about the line.
    //
    // The section 5 assertion is what proves this works, and it is worth
    // knowing that it cannot: `kvno HTTP/<host>` is handed a principal
    // ALREADY WRITTEN OUT and qualifies nothing, so it passed on the
    // containerized stack while the derivation curl performs was broken. Only
    // a hostbased name — GSSAPI's, and `kvno -S HTTP <host>` — goes through
    // this code path.
    "    qualify_shortname = \"\"",
    "    udp_preference_limit = 1",
    "    default_tkt_enctypes = aes256-cts-hmac-sha1-96 " +
    "aes128-cts-hmac-sha1-96",
    "    default_tgs_enctypes = aes256-cts-hmac-sha1-96 " +
    "aes128-cts-hmac-sha1-96",
    "    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96",
    "",
    "[realms]",
    "    " + realm + " = {",
    "        kdc = " + kdcHost + ":" + kdcPort,
    "    }",
    "",
    "[domain_realm]",
    // Both spellings, so a host named bare and a host named with a leading dot
    // both map to this realm. Without them GSSAPI derives a realm from the
    // hostname and looks for a KDC that does not exist.
    "    " + hostOf(stsUrl) + " = " + realm,
    "    ." + hostOf(stsUrl) + " = " + realm,
    ""
  ].join("\n");
  fs.writeFileSync(krbConfig, text, "utf8");
  log.info("this run's Kerberos configuration is " + krbConfig + ", pointing " +
      "at " + kdcHost + ":" + kdcPort + " for " + realm);
  log.debug("Leaving writeKrb5Config().");
}

function hostOf(url) {
  log.debug("Entering hostOf(). url=" + url);
  let host = String(url);
  try {
    host = new URL(String(url)).hostname;
  } catch (e) {
    // Not a URL this run can parse. The caller's own failure will say so far
    // better than a helper could; what matters here is not throwing.
    log.debug("Leaving hostOf(). Unparseable.");
    return host;
  }
  log.debug("Leaving hostOf(). " + host);
  return host;
}

function cleanUp() {
  log.debug("Entering cleanUp().");
  if (krbDir) {
    try {
      fs.rmSync(krbDir, { recursive: true, force: true });
      log.debug("Leaving cleanUp(). Removed " + krbDir);
      return;
    } catch (e) {
      // A leftover temp directory is untidy and harmless, and saying so is
      // better than failing a passing run over it.
      log.warn("could not remove " + krbDir + ": " + e.message);
    }
  }
  log.debug("Leaving cleanUp().");
}

// ---------------------------------------------------------------------------
// WHAT HAS TO BE TRUE BEFORE ANY OF THIS MEANS ANYTHING.
//
// Three different reasons to skip and one to fail, and naming which is the
// whole value of this function: "MIT Kerberos is not installed" and "the mock
// STS is not running" send you to different places, and "the mock has no KDC"
// is neither.
// ---------------------------------------------------------------------------
async function preconditions() {
  log.debug("Entering preconditions().");
  const names = ["kinit", "klist", "kvno", "kdestroy"];
  const missing = [];
  for (const name of names) {
    const found = spawnSync("sh", ["-c", "command -v " + name],
        { encoding: "utf8" });
    const resolved = String(found.stdout || "").trim();
    if (!resolved) {
      missing.push(name);
    } else {
      tools[name] = resolved;
    }
  }
  if (missing.length) {
    log.debug("Leaving preconditions(). No MIT tools.");
    return { ok: false, why: "MIT Kerberos is not installed here (missing: " +
      missing.join(", ") + "). This job drives the mock KDC with the REAL " +
      "client rather than with the one this project wrote, which is the only " +
      "way an interoperability defect can be found at all — install " +
      "`krb5-user` to run it. The containerized suite always has it; see " +
      "tests/Dockerfile." };
  }

  const curlPath = spawnSync("sh", ["-c", "command -v curl"],
      { encoding: "utf8" });
  tools.curl = String(curlPath.stdout || "").trim();
  if (!tools.curl) {
    log.debug("Leaving preconditions(). No curl.");
    return { ok: false, why: "curl is not installed here, and sections 8 to " +
      "14 use it as the GSSAPI HTTP client" };
  }
  // BUILT WITH GSS-API, which is a different question from "curl exists". A
  // curl without it accepts `--negotiate` silently and sends no Authorization
  // header at all, so the sign-in sections would fail as "the door refused a
  // ticket" when no ticket was ever offered.
  const features = spawnSync(tools.curl, ["-V"], { encoding: "utf8" });
  const banner = String(features.stdout || "");
  if (!/GSS-API/.test(banner) || !/SPNEGO/.test(banner)) {
    log.debug("Leaving preconditions(). curl without GSS-API.");
    return { ok: false, why: "this curl was built without GSS-API/SPNEGO " +
      "(its features line reads: " +
      (banner.split("\n").filter(function (line) {
        return /^Features:/.test(line); })[0] || "(none reported)") +
      "). It would accept --negotiate and send no Authorization header, so " +
      "the sign-in sections would report a refusal for a ticket that was " +
      "never offered." };
  }

  let table;
  try {
    const response = await fetch(stsUrl + "/krb5/principals");
    if (!response.ok) {
      log.debug("Leaving preconditions(). No KDC view.");
      return { ok: false, why: stsUrl + "/krb5/principals answered " +
        response.status + " — the mock STS may be an older build without the " +
        "KDC" };
    }
    table = await response.json();
  } catch (e) {
    log.debug("Leaving preconditions(). Unreachable.");
    return { ok: false, why: "could not reach the mock STS at " + stsUrl +
      " (" + e.message + ")" };
  }
  if (table.realm !== realm) {
    log.debug("Leaving preconditions(). Wrong realm.");
    return { ok: false, why: "the mock KDC serves realm " + table.realm +
      ", not " + realm + ". Set KRB5_REALM." };
  }

  // The certificate. The mock serves https on one it generated at startup, so
  // curl has no anchor for it — common/common.sh's trustStsCertificate()
  // exports STS_CA_FILE where a launcher has fetched it. Falling back to -k is
  // deliberate and is logged: this file's subject is Kerberos, and refusing to
  // run without a TLS anchor would take the whole of it away for a reason that
  // has nothing to do with what it tests.
  if (/^https:/i.test(stsUrl)) {
    if (process.env.STS_CA_FILE && fs.existsSync(process.env.STS_CA_FILE)) {
      curlTls = ["--cacert", process.env.STS_CA_FILE];
      log.info("curl will verify the mock's certificate against " +
          process.env.STS_CA_FILE);
    } else {
      curlTls = ["-k"];
      log.warn("STS_CA_FILE is not set, so curl will NOT verify the mock's " +
          "TLS certificate. That is the mock's per-start self-signed one and " +
          "this file tests Kerberos rather than TLS — but a launcher that " +
          "called trustStsCertificate() would have set it.");
    }
  }

  spn = "HTTP/" + hostOf(stsUrl);
  const hosts = (table.accountPolicy || {}).serviceHosts || [];
  log.debug("Leaving preconditions(). Ready.");
  return { ok: true, kdcPort: String(table.kdcPort), serviceHosts: hosts,
           policy: table.accountPolicy || {} };
}

// ---------------------------------------------------------------------------
// 1. THE TWO-MESSAGE AS EXCHANGE — and the guard for the defect this file was
//    written after.
//
// A client's first AS-REQ carries no pre-authentication. A real KDC answers
// KDC_ERR_PREAUTH_REQUIRED carrying the method list AND the salt, and the
// client
// sends a second request with an encrypted timestamp. That is TWO messages, and
// the assertion here is that exactly one KDC error was seen along the way: none
// would mean this account does not require pre-authentication (section 2's
// case), and two or more would mean something was refused.
// ---------------------------------------------------------------------------
function theTwoMessageAsExchange() {
  log.debug("Entering theTwoMessageAsExchange().");
  log.info("=== The AS exchange, with pre-authentication ===");
  const result = kinit("alice");
  assert.strictEqual(result.status, 0,
    "`kinit alice` failed against the mock KDC.\n\n" +
    "IF THE MESSAGE BELOW IS \"Generic preauthentication failure\", THIS IS " +
    "THE DEFECT THIS FILE WAS WRITTEN FOR: the KDC's " +
    "KDC_ERR_PREAUTH_REQUIRED must list PA-ENC-TIMESTAMP (padata type 2) in " +
    "its e-data. That field is the list of methods the KDC accepts (RFC 4120 " +
    "section 5.9.1), MIT reads it to decide what to send next, and a list of " +
    "ETYPE-INFO2 and PW-SALT alone names the salt without naming the method. " +
    "Every client this project wrote sends the timestamp whether it was " +
    "offered or not, so nothing else in either repository can see this.\n\n" +
    "kinit said: " + result.stderr.split("\n").filter(function (line) {
      return /^kinit:/.test(line); }).join(" ") + "\n" +
    "KDC errors: " + JSON.stringify(result.kdcErrors));
  assert.strictEqual(result.kdcErrors.length, 1,
    "the AS exchange for an account that REQUIRES pre-authentication should " +
    "cost exactly one KDC error — the KDC_ERR_PREAUTH_REQUIRED that carries " +
    "the salt — and this run saw " + result.kdcErrors.length + ": " +
    JSON.stringify(result.kdcErrors) + ". None at all would mean this " +
    "account does not require it, which is section 2's case and a different " +
    "exchange.");
  assert.ok(/pre-authentication required/i.test(result.kdcErrors[0]),
    "and that one error should be the pre-authentication demand: " +
    JSON.stringify(result.kdcErrors));

  const listed = run(tools.klist, []);
  assert.strictEqual(listed.status, 0,
    "`klist` could not read the credential cache kinit just wrote: " +
    listed.stderr.slice(0, 300));
  assert.ok(new RegExp("alice@" + realm).test(listed.stdout),
    "the cache should name alice@" + realm + " as its default principal: " +
    listed.stdout.slice(0, 400));
  assert.ok(new RegExp("krbtgt/" + realm + "@" + realm).test(listed.stdout),
    "and hold a ticket-granting ticket, which is what an AS exchange is FOR " +
    "— an AS-REP naming any other service would be this KDC answering a " +
    "question nobody asked: " + listed.stdout.slice(0, 400));
  log.info("MIT Kerberos completed the two-message AS exchange and holds a " +
      "TGT — so the KDC's method list is honest");
  log.debug("Leaving theTwoMessageAsExchange().");
}

// ---------------------------------------------------------------------------
// 2. THE ONE-MESSAGE AS EXCHANGE.
//
// `noreauth` is configured the other way round, and it exists so that the case
// a real KDC can also be in is reachable here. What separates it from section 1
// is not what either end SAYS — both end with a TGT — but how many round trips
// it took, which is exactly what the trace counts.
// ---------------------------------------------------------------------------
function theOneMessageAsExchange() {
  log.debug("Entering theOneMessageAsExchange().");
  log.info("=== The AS exchange, without pre-authentication ===");
  const result = kinit("noreauth", undefined, "ccache-noreauth");
  assert.strictEqual(result.status, 0,
    "`kinit noreauth` failed, and that account is configured to need no " +
    "pre-authentication at all: " + result.stderr.slice(0, 400));
  assert.strictEqual(result.kdcErrors.length, 0,
    "an account that does NOT require pre-authentication must be answered " +
    "with a ticket on the FIRST message — no KDC_ERR_PREAUTH_REQUIRED at all " +
    "— and this run saw " + JSON.stringify(result.kdcErrors) + ". A KDC that " +
    "demanded pre-authentication here would be ignoring the account's own " +
    "configuration, and the only visible difference is this count: both " +
    "exchanges end with a TGT.");
  log.info("MIT Kerberos got a TGT for noreauth in one message, with no " +
      "pre-authentication demanded");
  log.debug("Leaving theOneMessageAsExchange().");
}

// ---------------------------------------------------------------------------
// 3. ANY USERNAME AUTHENTICATES, which is this KDC's permissive equivalent.
//
// It checks no password anywhere else in this service; here it cannot not check
// one, because the password IS the key. So the permissiveness moved into the
// ACCOUNT POLICY — one password shared by every user account, an account
// created for any name on first sight — and this asserts the half a real client
// can see. The name is generated, so it is genuinely one the KDC has never
// seen.
// ---------------------------------------------------------------------------
function anyUsernameAuthenticates(ready) {
  log.debug("Entering anyUsernameAuthenticates().");
  log.info("=== A name this KDC has never seen ===");
  if (!ready.policy.anyUsernameAuthenticates) {
    log.warn("this KDC does not create accounts on first sight " +
        "(accountPolicy.anyUsernameAuthenticates is false), so this section " +
        "has nothing to assert.");
    log.debug("Leaving anyUsernameAuthenticates(). Not applicable.");
    return;
  }
  const invented = usernameFor("krb5-mit");
  const result = kinit(invented, undefined, "ccache-invented");
  assert.strictEqual(result.status, 0,
    "this KDC advertises accountPolicy.anyUsernameAuthenticates, so \"" +
    invented + "\" — a name generated for this run and therefore one it has " +
    "never seen — should be created on first sight and issued a TGT. It was " +
    "refused: " + JSON.stringify(result.kdcErrors) + " " +
    result.stderr.split("\n").filter(function (line) {
      return /^kinit:/.test(line); }).join(" "));
  log.info("the invented principal " + invented + " was created on first " +
      "sight and issued a TGT");
  log.debug("Leaving anyUsernameAuthenticates().");
}

// ---------------------------------------------------------------------------
// 4. THE REFUSALS, each asserted against the KDC'S OWN ERROR.
//
// One table, because these differ only in the account and the error — and a
// table is what makes it obvious that a case was DELETED rather than merely
// not written. Every one of them is a refusal a real KDC can produce and that
// this mock exists to let a client meet.
//
// `expired` is the case worth reading. The mock answers KDC_ERR_KEY_EXPIRED,
// which is right; MIT then asks for a `kadmin/changepw` ticket so the password
// can be changed, the mock has no such service, and the LAST thing kinit prints
// is "Server not found in Kerberos database". Asserting on that would be
// asserting the mock got it wrong when it got it right — so this reads the
// FIRST error, which is the KDC's answer to the question that was asked.
// ---------------------------------------------------------------------------
const REFUSALS = [
  { who: "alice", withPassword: "not-the-right-password",
    expect: /Preauthentication failed/i,
    what: "a wrong password",
    why: "the one credential this service genuinely verifies. If a wrong " +
         "password were accepted, every `amr` claim the SPNEGO sign-in makes " +
         "would be worthless — it reads `pwd` off the ticket's pre-authent " +
         "flag, which means only that the KDC checked something." },
  { who: "locked", expect: /credentials have been revoked/i,
    what: "a locked account",
    why: "KDC_ERR_CLIENT_REVOKED. A disabled account that could still get a " +
         "ticket is the refusal an administrator most expects to work." },
  { who: "expired", expect: /Password has expired/i, firstOnly: true,
    what: "an expired password",
    why: "KDC_ERR_KEY_EXPIRED, read as the FIRST error rather than the last: " +
         "MIT follows it by asking for a kadmin/changepw ticket, which this " +
         "mock does not serve, so the final message names a missing service " +
         "and not the expiry." },
  { who: "rc4only", expect: /no support for encryption type/i,
    what: "an account offering only RC4",
    why: "KDC_ERR_ETYPE_NOSUPP, and the refusal comes from the ENCTYPE " +
         "negotiation rather than from any credential: this run's krb5.conf " +
         "permits only AES, which is what a 2025 client permits. It is the " +
         "legacy account a modern baseline breaks, and it is here so that " +
         "breakage is reachable." },
  { who: "nosuchuser", expect: /Client not found in Kerberos database/i,
    what: "a name this KDC will never create",
    why: "KDC_ERR_C_PRINCIPAL_UNKNOWN. This KDC creates an account for any " +
         "name on first sight, so without a reserved list this error would " +
         "be unreachable — and a client that cannot provoke it cannot be " +
         "tested against it." },
  { who: "nobody", expect: /Client not found in Kerberos database/i,
    what: "the second reserved name",
    why: "both names in the reserved list are driven, because a list that " +
         "quietly became one entry would still pass with only the first." }
];

function everyRefusalIsTheKdcsOwn() {
  log.debug("Entering everyRefusalIsTheKdcsOwn().");
  log.info("=== The refusals a real client meets ===");
  REFUSALS.forEach(function (one, index) {
    const result = kinit(one.who, one.withPassword,
        "ccache-refusal-" + index);
    assert.notStrictEqual(result.status, 0,
      "`kinit " + one.who + "` SUCCEEDED, and " + one.what + " must be " +
      "refused. " + one.why);
    assert.ok(result.kdcErrors.length,
      "`kinit " + one.who + "` failed without the KDC refusing anything, so " +
      "this is a client-side or transport failure rather than the refusal " +
      "being asserted: " + result.stderr.slice(0, 400));
    const considered = one.firstOnly ? [result.kdcErrors[0]]
                                     : result.kdcErrors;
    assert.ok(considered.some(function (error) {
      return one.expect.test(error);
    }), "`kinit " + one.who + "` should be refused with something matching " +
      one.expect + " and the KDC said " + JSON.stringify(considered) +
      (one.firstOnly
        ? " (the FIRST error, deliberately — see the table)" : "") +
      ". " + one.why);
    log.info("[" + one.who + "] " + one.what + " — " +
        JSON.stringify(considered[0]));
  });
  log.debug("Leaving everyRefusalIsTheKdcsOwn().");
}

// ---------------------------------------------------------------------------
// 5. THE TGS EXCHANGE.
//
// `kvno` spends the TGT for a service ticket, which is the second half of
// Kerberos and the half the SPNEGO sections below depend on. The SPN is the one
// a client DERIVES from the mock's URL, not one read out of the mock's own
// table: that derivation is what every RFC 4559 client does, and buying a
// ticket for a name the client would not have asked for tests nothing.
// ---------------------------------------------------------------------------
function theTgsExchange() {
  log.debug("Entering theTgsExchange().");
  log.info("=== The TGS exchange: a service ticket for " + spn + " ===");
  const fresh = kinit("alice");
  assert.strictEqual(fresh.status, 0,
    "this section needs a TGT and kinit failed: " + fresh.stderr.slice(0, 300));

  const result = run(tools.kvno, [spn]);
  assert.strictEqual(result.status, 0,
    "`kvno " + spn + "` failed. That SPN is derived from the mock's own URL " +
    "the way every RFC 4559 client derives one, and this KDC creates a " +
    "service principal on first sight for a host it is willing to BE. If the " +
    "error is KDC_ERR_S_PRINCIPAL_UNKNOWN, this host is not in the mock's " +
    "serviceHosts and the SPNEGO sections below cannot work either: " +
    result.stderr.slice(0, 400));

  const listed = run(tools.klist, []);
  assert.ok(new RegExp(spn.replace("/", "\\/") + "@" + realm)
      .test(listed.stdout),
    "the credential cache should now hold a service ticket for " + spn +
    " beside the TGT: " + listed.stdout.slice(0, 400));
  assert.ok(new RegExp("krbtgt/" + realm).test(listed.stdout),
    "and the TGT must still be there — a TGS exchange SPENDS the TGT without " +
    "consuming it, and a cache holding only the service ticket would mean " +
    "the next exchange needs a password again: " + listed.stdout.slice(0, 400));
  log.info("MIT Kerberos exchanged the TGT for a service ticket for " + spn);
  log.debug("Leaving theTgsExchange().");
}

// ---------------------------------------------------------------------------
// 6. AN SPN FOR A HOST THIS SERVICE WILL NOT BE.
//
// The mock creates a service principal on first sight only for a host it is
// willing to answer for, and anything else stays KDC_ERR_S_PRINCIPAL_UNKNOWN.
// Without that refusal the "created on first sight" rule would mean this KDC
// issues tickets for every name ever asked of it, which is a different service.
// ---------------------------------------------------------------------------
function anSpnOutsideTheServiceHostsIsRefused(ready) {
  log.debug("Entering anSpnOutsideTheServiceHostsIsRefused().");
  log.info("=== NEGATIVE: an SPN for a host this service will not be ===");
  const wrong = "HTTP/nowhere.invalid";
  const result = run(tools.kvno, [wrong]);
  assert.notStrictEqual(result.status, 0,
    "`kvno " + wrong + "` SUCCEEDED. This KDC creates a service principal on " +
    "first sight only for a host it is willing to BE — it lists " +
    JSON.stringify(ready.serviceHosts) + " — and issuing a ticket for any " +
    "name asked of it would make every SPN in this realm meaningless.");
  // The principal is IN the message on the TGS side — "Server
  // HTTP/x@REALM not found in Kerberos database" — where the AS side says only
  // "Server not found in Kerberos database". One pattern covers both.
  assert.ok(result.kdcErrors.some(function (error) {
    return /Server\b.*not found in Kerberos database/i.test(error);
  }), "and the refusal must be KDC_ERR_S_PRINCIPAL_UNKNOWN — the error a " +
    "client can act on, because it names the SERVER rather than the client. " +
    "The KDC said " + JSON.stringify(result.kdcErrors) + ".");
  log.info("an SPN outside " + JSON.stringify(ready.serviceHosts) +
      " stays KDC_ERR_S_PRINCIPAL_UNKNOWN");
  log.debug("Leaving anSpnOutsideTheServiceHostsIsRefused().");
}

// ---------------------------------------------------------------------------
// 7. THE BARE CHALLENGE.
//
// What a client with no credential gets, and it is the whole visible surface of
// RFC 4559: a 401 whose WWW-Authenticate is the single word `Negotiate` with no
// token after it. A challenge carrying a token here would mean the acceptor had
// started a context with somebody who has not spoken yet.
// ---------------------------------------------------------------------------
function theChallengeIsBare() {
  log.debug("Entering theChallengeIsBare().");
  log.info("=== The unauthenticated request ===");
  const result = curl([stsUrl + "/authn/spnego"]);
  assert.strictEqual(result.httpStatus, 401,
    "an unauthenticated request to the sign-in door must be refused 401: it " +
    "is a door, and a 200 would mean it had signed somebody in with no " +
    "credential at all. Got " + result.httpStatus + ".");
  const challenges = headerValues(result.headers, "WWW-Authenticate");
  assert.ok(challenges.length,
    "and it must carry a challenge, or a client has not been asked for " +
    "anything: " + JSON.stringify(result.headers.slice(0, 300)));
  assert.ok(challenges.some(function (one) {
    return one.trim() === "Negotiate";
  }),
    "the challenge must be the bare word `Negotiate` with nothing after it " +
    "(RFC 4559 section 4). A token here would be the acceptor answering a " +
    "context that has not been started. Got " + JSON.stringify(challenges));
  log.info("the door challenges with a bare Negotiate");
  log.debug("Leaving theChallengeIsBare().");
}

// ---------------------------------------------------------------------------
// 8. SPNEGO AT THE PROTECTED PAGE — a real GSSAPI client, end to end.
//
// This is the sentence the whole file is for: `curl --negotiate` performs the
// RFC 4559 handshake with no help from anything this project wrote, and the
// mock accepts it. The page then names the principal from inside the ticket,
// which is the only evidence that the AP-REQ was DECRYPTED rather than merely
// well-formed.
//
// And it must set NO session, which is what separates this door from the next.
// ---------------------------------------------------------------------------
function theProtectedPageAcceptsARealTicket() {
  log.debug("Entering theProtectedPageAcceptsARealTicket().");
  log.info("=== SPNEGO at /spnego/protected, with MIT's own GSSAPI ===");
  const result = curl(["--negotiate", "-u", ":",
      stsUrl + "/spnego/protected"]);
  assert.strictEqual(result.httpStatus, 200,
    "`curl --negotiate` could not authenticate to " + stsUrl +
    "/spnego/protected. This is a REAL GSSAPI client and nothing in this " +
    "project wrote a byte of what it sent, which is what makes this the only " +
    "assertion here that can find an interoperability defect.\n\n" +
    // WHICH OF THE TWO FAILURES THIS IS, because they look identical and are
    // in different repositories. A bare `Negotiate` with no token after it is
    // the answer to a request carrying NO Authorization header, so the ticket
    // never left this machine and the defect is HERE — read the KDC errors
    // below, which are libkrb5's own out of curl's trace and name the SPN it
    // asked for. A `Negotiate <base64>` is the acceptor REFUSING a ticket it
    // was given, which is the mock's end.
    "The KDC told curl: " + JSON.stringify(result.kdcErrors) + "\n" +
    "Headers: " + result.headers.slice(0, 400));
  assert.ok(new RegExp("alice@" + realm).test(result.body),
    "and the page must name the principal from INSIDE the ticket, which is " +
    "the only evidence the AP-REQ was decrypted rather than merely parsed. " +
    "Body: " + result.body.replace(/\s+/g, " ").slice(0, 400));
  assert.strictEqual(headerValues(result.headers, "Set-Cookie").length, 0,
    "and the PROTECTED PAGE must mint no session — it authenticates and then " +
    "throws the identity away, which is the whole difference between it and " +
    "the sign-in door in section 9. A Set-Cookie here would mean the two " +
    "doors had become one.");
  log.info("MIT's GSSAPI authenticated to the protected page, which named " +
      "the principal and set no session");
  log.debug("Leaving theProtectedPageAcceptsARealTicket().");
}

// ---------------------------------------------------------------------------
// 9. THE SIGN-IN DOOR, and the session it mints.
// ---------------------------------------------------------------------------
function theTicketSignsThePersonIn() {
  log.debug("Entering theTicketSignsThePersonIn().");
  log.info("=== SPNEGO at /authn/spnego ===");
  const result = curl(["--negotiate", "-u", ":", stsUrl + "/authn/spnego"]);
  assert.strictEqual(result.httpStatus, 200,
    "`curl --negotiate` could not sign in at " + stsUrl + "/authn/spnego: " +
    result.headers.slice(0, 400));
  assert.ok(/you are signed in/i.test(result.body),
    "the door's answer must be the sign-in page rather than the protected " +
    "page's table: " + result.body.replace(/\s+/g, " ").slice(0, 400));
  assert.ok(new RegExp("urn:sts-mock:user:alice").test(result.body),
    "and it must name the subject the session carries — the principal with " +
    "its realm STRIPPED, so that somebody who typed \"alice\" at the " +
    "password screen and the same person arriving with a ticket are ONE " +
    "subject to every relying party: " +
    result.body.replace(/\s+/g, " ").slice(0, 400));

  const cookies = headerValues(result.headers, "Set-Cookie");
  assert.ok(cookies.length,
    "the door must SET A SESSION COOKIE, which is the whole difference " +
    "between this endpoint and the protected page and the only part of it " +
    "that outlives the request: " + result.headers.slice(0, 400));
  const session = (cookies.join("; ").match(/sts_mock_session=([^;\s]+)/) ||
      [])[1];
  assert.ok(session,
    "and it must be the session cookie every protocol in that service reads. " +
    "Set-Cookie: " + JSON.stringify(cookies));
  log.info("a real Kerberos ticket signed alice in and minted a session");
  log.debug("Leaving theTicketSignsThePersonIn().");
  return session;
}

// ---------------------------------------------------------------------------
// 10. THE SESSION SATISFIES AN APPLICATION.
//
// The payoff, and the same one `kerberos_spnego_signin.js` makes through the
// debugger — made here with no browser and no client of ours anywhere in the
// chain. The application is registered first, the way every job in this suite
// now does it.
// ---------------------------------------------------------------------------
async function theSessionSatisfiesAnApplication(session) {
  log.debug("Entering theSessionSatisfiesAnApplication().");
  log.info("=== The application flow the Kerberos session satisfies ===");
  await registry.provision(registry.baseOf(stsUrl), {
    identifier: clientId,
    name: "Kerberos CLI client",
    protocols: ["oauth2", "oidc"],
    fields: {
      oauthClientId: clientId,
      oauthRedirectUri: ["http://localhost:3000/callback"],
      oauthResponseType: ["code"],
      oauthGrantType: ["authorization_code"],
      oauthScope: ["openid"],
      oauthTokenEndpointAuthMethod: "none",
      oauthConfidential: "FALSE"
    },
    why: "the application a Kerberos-authenticated session completes a flow for"
  });

  const authorize = stsUrl + "/oauth2/authorize?response_type=code&client_id=" +
      encodeURIComponent(clientId) + "&redirect_uri=" +
      encodeURIComponent("http://localhost:3000/callback") +
      "&scope=openid&state=krb-cli&nonce=krb-cli-nonce";
  const result = curl(["-b", "sts_mock_session=" + session, authorize]);
  assert.ok(result.httpStatus >= 300 && result.httpStatus < 400,
    "an authorization request carrying the Kerberos session should redirect " +
    "straight to the application with a code — no sign-in screen, because " +
    "nobody has to authenticate twice. It answered " + result.httpStatus +
    ": " + result.headers.slice(0, 400));
  const location = headerValues(result.headers, "Location")[0] || "";
  assert.ok(/[?&]code=/.test(location),
    "and the redirect must carry an authorization code. A person who " +
    "authenticated with a Kerberos ticket has to be able to complete an " +
    "ordinary OAuth flow, or the session is a page rather than a sign-on. " +
    "Location: " + location);
  assert.ok(!/\/authn\/login/.test(location),
    "and it must not have gone to the password screen: " + location);
  log.info("the Kerberos session completed an OAuth flow with no screen drawn");
  log.debug("Leaving theSessionSatisfiesAnApplication().");
}

// ---------------------------------------------------------------------------
// 11. NEGATIVE: a replayed AP-REQ mints nothing.
//
// The one check here whose absence would be a SECURITY bug rather than a
// fidelity one. The bytes are captured from curl's own verbose output — the
// Authorization header it actually sent — and posted back verbatim, so this is
// a replay of the exact credential rather than a second authentication.
// ---------------------------------------------------------------------------
function aReplayedTicketMintsNothing() {
  log.debug("Entering aReplayedTicketMintsNothing().");
  log.info("=== NEGATIVE: the same AP-REQ, sent twice ===");
  // `-v` puts the request headers on stderr, prefixed with "> ". That is the
  // only way to see what a GSSAPI client actually sent: the token is built
  // inside libcurl and never passes through this process.
  const first = run(tools.curl, ["-s", "-v", "-o", "/dev/null"]
      .concat(curlTls)
      .concat(["--negotiate", "-u", ":", stsUrl + "/authn/spnego"]));
  const sent = (first.stderr.split("\n").filter(function (line) {
    return /^>\s*Authorization:\s*Negotiate\s/i.test(line);
  })[0] || "").replace(/^>\s*Authorization:\s*Negotiate\s+/i, "").trim();
  assert.ok(sent.length > 100,
    "curl's verbose output should carry the Authorization header it sent, " +
    "and this run captured " + sent.length + " characters. Without it there " +
    "is nothing to replay.");

  const replayed = curl(["-H", "Authorization: Negotiate " + sent,
      stsUrl + "/authn/spnego"]);
  assert.notStrictEqual(replayed.httpStatus, 200,
    "a REPLAYED AP-REQ was accepted with HTTP 200. An Authenticator is " +
    "single-use, and the acceptor's replay cache is what has to notice these " +
    "exact bytes have been seen before — a service that takes one twice " +
    "hands a second session to anybody who captured the first. This is the " +
    "one assertion in this file whose failure is a security bug rather than " +
    "a fidelity one.");
  assert.strictEqual(headerValues(replayed.headers, "Set-Cookie").length, 0,
    "and it must mint NOTHING. A refusal that still set a session cookie " +
    "would be worse than an acceptance, because the status line says one " +
    "thing and the client keeps another.");
  assert.ok(/replay|seen before|already/i.test(replayed.body),
    "and the refusal should NAME the replay rather than merely refusing — a " +
    "client told \"authentication failed\" goes and checks its password, " +
    "while one told its credential was seen before knows it was captured. " +
    "The door answered HTTP " + replayed.httpStatus + " with: " +
    replayed.body.replace(/\s+/g, " ").slice(0, 300));

  // AND A FRESH ONE STILL WORKS, which is what keeps the assertion above from
  // being satisfiable by an acceptor that has simply stopped working.
  const fresh = curl(["--negotiate", "-u", ":", stsUrl + "/authn/spnego"]);
  assert.strictEqual(fresh.httpStatus, 200,
    "after the replay was refused, a FRESH AP-REQ must still be accepted — " +
    "otherwise the refusal above proves only that the door stopped " +
    "answering. Got " + fresh.httpStatus + ".");
  log.info("the replayed AP-REQ was refused with HTTP " + replayed.httpStatus +
      " and minted nothing, and a fresh one still works");
  log.debug("Leaving aReplayedTicketMintsNothing().");
}

// ---------------------------------------------------------------------------
// 12. NEGATIVE: no ticket, no session.
//
// `kdestroy` throws the credential cache away, which is what signing out of
// Kerberos IS on a workstation. The same command that worked a moment ago must
// now be unable to authenticate — and the point is that the SERVER changed
// nothing: this is the client having no credential.
// ---------------------------------------------------------------------------
function kdestroyLeavesNothingToAuthenticateWith() {
  log.debug("Entering kdestroyLeavesNothingToAuthenticateWith().");
  log.info("=== NEGATIVE: after kdestroy ===");
  const destroyed = run(tools.kdestroy, []);
  assert.strictEqual(destroyed.status, 0,
    "`kdestroy` failed: " + destroyed.stderr.slice(0, 300));
  const listed = run(tools.klist, []);
  assert.notStrictEqual(listed.status, 0,
    "`klist` should report no credential cache after kdestroy, and it " +
    "succeeded: " + listed.stdout.slice(0, 300));

  const result = curl(["--negotiate", "-u", ":", stsUrl + "/authn/spnego"]);
  assert.strictEqual(result.httpStatus, 401,
    "with no ticket, the same `curl --negotiate` that signed in a moment ago " +
    "must be refused 401. The SERVER changed nothing here — this is the " +
    "client having no credential, which is the state every browser on a " +
    "machine without a ccache is in, and the reason that mock's sign-in page " +
    "carries a link to the password screen. Got " + result.httpStatus + ".");
  assert.strictEqual(headerValues(result.headers, "Set-Cookie").length, 0,
    "and nothing may be minted for a client that presented nothing.");
  log.info("with the credential cache destroyed, the same command is refused " +
      "401 and mints nothing");
  log.debug("Leaving kdestroyLeavesNothingToAuthenticateWith().");
}

// ---------------------------------------------------------------------------
// 13. NEGATIVE: the door, closed.
//
// A mode that ships ON has to assert the OFF state too. The refusal must be a
// 403 NAMING THE SETTING rather than a 404: the route still exists, and
// answering "no such page" sends somebody to look for a deployment problem when
// what they have is a configuration.
//
// This is why the file holds a JOB_LOCK — the setting is process-wide on a
// shared service.
// ---------------------------------------------------------------------------
async function theClosedDoorSignsNobodyIn() {
  log.debug("Entering theClosedDoorSignsNobodyIn().");
  log.info("=== NEGATIVE: krb5.spnegoAuthentication off ===");
  const off = await adminPost("/config/set",
      { key: "krb5.spnegoAuthentication", value: false });
  assert.ok(off.ok,
    "krb5.spnegoAuthentication could not be turned off through the " +
    "management API, so this section cannot run: " +
    JSON.stringify(off.errors || off));
  try {
    const fresh = kinit("alice");
    assert.strictEqual(fresh.status, 0,
      "this section needs a ticket to be refused WITH, and kinit failed: " +
      fresh.stderr.slice(0, 300));
    const result = curl(["--negotiate", "-u", ":", stsUrl + "/authn/spnego"]);
    assert.strictEqual(result.httpStatus, 403,
      "a closed door must answer 403 and not 404: the route still exists, it " +
      "is still on /admin/sts-metadata, and answering \"no such page\" sends " +
      "somebody to look for a deployment problem when what they have is a " +
      "setting. Got " + result.httpStatus + ".");
    assert.ok(/krb5\.spnegoAuthentication/.test(result.body),
      "and the refusal must NAME the setting, which is the difference " +
      "between a person turning it back on and a person reading source: " +
      result.body.replace(/\s+/g, " ").slice(0, 300));
    assert.strictEqual(headerValues(result.headers, "Set-Cookie").length, 0,
      "and a closed door must sign nobody in, ticket or no ticket.");

    // THE PROTECTED PAGE IS UNTOUCHED, which the mock's own refusal page
    // promises: turning the sign-in off takes the SESSION away and nothing
    // else. A reader told that should be able to rely on it.
    const still = curl(["--negotiate", "-u", ":",
        stsUrl + "/spnego/protected"]);
    assert.strictEqual(still.httpStatus, 200,
      "with the sign-in door closed, /spnego/protected must still perform " +
      "the whole handshake — that is what the refusal page tells the reader, " +
      "and the setting is about minting a session rather than about " +
      "accepting a ticket. Got " + still.httpStatus + ".");
    log.info("the closed door answers 403, names the setting, mints nothing, " +
        "and the protected page is untouched");
  } finally {
    // RESTORED THROUGH `reset` RATHER THAN BY WRITING THE OLD VALUE BACK: a
    // `set` leaves `source: override` behind for admin_api.js to trip over on
    // the next run. In a `finally` because a failed assertion above must not
    // leave the door shut for every other Kerberos job.
    const back = await adminPost("/config/reset",
        { key: "krb5.spnegoAuthentication" });
    if (!back.ok) {
      log.error("could not reset krb5.spnegoAuthentication: " +
          JSON.stringify(back.errors || back) + " — the SPNEGO sign-in door " +
          "may be left CLOSED on this instance, which every other Kerberos " +
          "job will read as its own failure.");
    } else {
      log.info("krb5.spnegoAuthentication is back to the service's own value");
    }
  }
  log.debug("Leaving theClosedDoorSignsNobodyIn().");
}

// ---------------------------------------------------------------------------
async function test() {
  log.debug("Entering test().");
  log.info("Starting Test run. sts=" + stsUrl + ", kdc=" + kdcHost + ":" +
      kdcPort + ", realm=" + realm);
  const ready = await preconditions();
  if (!ready.ok) {
    // Named, never silent. A skip that did not say which precondition failed
    // would be indistinguishable from a pass.
    log.warn("SKIPPED: " + ready.why);
    log.info("Test completed successfully (skipped).");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  if (ready.kdcPort && ready.kdcPort !== String(kdcPort)) {
    log.warn("the mock STS reports its KDC on port " + ready.kdcPort +
        "; using that.");
    kdcPort = ready.kdcPort;
  }

  writeKrb5Config();
  let failed = false;
  try {
    theTwoMessageAsExchange();
    theOneMessageAsExchange();
    anyUsernameAuthenticates(ready);
    everyRefusalIsTheKdcsOwn();
    theTgsExchange();
    anSpnOutsideTheServiceHostsIsRefused(ready);
    theChallengeIsBare();
    theProtectedPageAcceptsARealTicket();
    const session = theTicketSignsThePersonIn();
    await theSessionSatisfiesAnApplication(session);
    aReplayedTicketMintsNothing();
    kdestroyLeavesNothingToAuthenticateWith();
    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.stack || error.message);
    failed = true;
  }

  // Runs whatever happened above, for the reason its own note gives: leaving
  // the door shut is the one way this file can break somebody else's job.
  try {
    await theClosedDoorSignsNobodyIn();
  } catch (error) {
    log.error(error.stack || error.message);
    failed = true;
  }

  cleanUp();
  if (failed) {
    log.debug("Leaving test(). Failed.");
    process.exit(1);
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("krb5_mit_client")
  .description("Drive the mock KDC with MIT Kerberos itself — kinit, klist, " +
      "kvno, kdestroy and curl --negotiate — which is the only thing here " +
      "that can find an interoperability defect.")
  .addOption(new Option("-u, --url <url>",
      "ignored; kept for a uniform CLI across the suite"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  cleanUp();
  process.exit(1);
});
