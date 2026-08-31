// File: sts_persistence_postgres.js
//
// ---------------------------------------------------------------------------
// THE MOCK STS'S POSTGRES PERSISTENCE MODE: WHAT SURVIVES A RESTART, WHAT MUST
// NOT, AND THE THING TWO PROCESSES POINTED AT ONE DATABASE DO NOT DO.
//
// Every other job in this suite drives a mock STS that somebody else started
// and that nobody restarts. That is the right arrangement for a protocol test
// and it makes this feature untestable, because **persistence is a claim about
// what happens across a restart** — a value held in memory is correct on every
// endpoint for the whole life of the process that wrote it, and the damage
// appears in the NEXT one. So this job starts its own database, starts its own
// mock, restarts it, and reads what came back.
//
// It is the only job here that owns the service under test, which is also why
// it is the only one that can assert the OTHER half — the half that is a
// documented NON-goal and is the one a well-meaning change would break:
//
//   **NOTHING THIS SERVICE MINTS EVER PERSISTS, IN ANY MODE.** Sessions, access
//   tokens, ID Tokens, refresh tokens, authorization codes, pre-authorized
//   codes, SAML artifacts, Kerberos tickets, the replay caches, the statistics
//   and the audit log all go with the process. The signing key is REGENERATED
//   on every start, so a token restored from a database would verify against
//   nothing — and the `kid` is derived from the key material, so it must be a
//   different one after the restart.
//
// FOUR THINGS IT ASSERTS.
//
//   * **THE THREE THINGS THAT DO PERSIST come back**: the embedded directory
//     (which is also the applications registry, the federation register and the
//     SPIFFE registry — they are directory entries and nothing else), the trust
//     realm registry with each realm's own overrides, and the runtime appconfig
//     overrides. Each is written through a door a person uses and read back
//     from a process that did not write it.
//   * **THE THINGS THAT MUST NOT come back do not**, and the signing key is the
//     one that proves it rather than merely illustrating it.
//   * **PERSISTENCE IS NOT COORDINATION.** Two processes pointed at one
//     database each hold their own copy of the directory in memory and never
//     see each other's writes until they restart. `status.coordinates` is
//     `false` and the reply says so in a sentence; this starts a second
//     instance against the same database and demonstrates it, because a
//     `false` in a JSON reply is a claim and this is the evidence for it.
//   * **THE CONNECTION IS TLS, AND POSTGRES IS THE ONE ASKED.** The throwaway
//     container is given a generated key pair and `ssl=on`, the mock dials it
//     with `sslmode=require`, and the assertion is a `pg_stat_ssl` query — the
//     server's own row per backend — rather than anything this side decided.
//     That distinction is the whole point: a driver that asked for TLS and
//     then handed `pg` an option which quietly disabled it would satisfy every
//     check built out of the connection string, and `persistence_postgres.js`
//     strips `sslmode` before `pg` sees it precisely because those two answers
//     disagreed once already. The same database is then dialled again with no
//     `sslmode` and both the report and postgres have to say plaintext, since
//     a driver that turned TLS on unconditionally would make `sslmode=disable`
//     mean its opposite. Until 2026-08-31 the container had no certificate at
//     all, so only the plaintext half of that file was ever reached.
//   * **A DATABASE THAT IS NOT THERE STOPS THE SERVICE**, since 2026-08-28,
//     and this bullet said the opposite when it was written a few hours
//     earlier. The old rule was that a failure is RECORDED rather than thrown
//     and the mock keeps answering out of its seeded directory — on the
//     argument that "a mock that refused to start because a database blinked
//     would be the one failure mode a mock must not have". Half of that
//     survives and is still asserted elsewhere: a store that breaks WHILE
//     RUNNING is recorded and the service carries on. What changed is
//     STARTUP, because the two are not alike — a process that never opened
//     its store answers every endpoint out of a SEEDED directory while
//     presenting itself as the one that was configured, and everything
//     anybody does with it is thrown away by the next restart. So a
//     CONFIGURED store that cannot be opened now exits non-zero and says
//     which setting to look at. `persistence.mode=memory`, the default,
//     reaches none of it.
//
// ---------------------------------------------------------------------------
// WHAT IT NEEDS, AND WHY IT SKIPS RATHER THAN FAILS WITHOUT IT.
//
// Two things, and neither is present in the containerized suite:
//
//   * **A POSTGRES.** `STS_TEST_POSTGRES_URL` is used when it is set — for CI,
//     or for anybody who already has one — and otherwise this starts a
//     throwaway `postgres:18` container of its own on a free port and removes
//     it at the end. No database and no docker means SKIP. A database somebody
//     ELSE supplied keeps the TLS checks that read the report and drops the
//     two that read `pg_stat_ssl` through `docker exec`, with a warning saying
//     which and why: there is no container of ours to exec into, and its
//     `host` rules may be `hostssl`, where dialling in the clear is refused by
//     the far end rather than being the thing under test.
//   * **A COMPLETE MOCK STS TREE**, because it runs `node server.js` from it.
//     `MOCK_STS_DIR` first, then the `sts/` submodule beside this suite, then a
//     sibling `mock-sts` checkout — the same order and the same reasons as
//     tests/module_paths.js, which is where that list is argued. The tests
//     IMAGE carries about thirty sts modules and no `node_modules`, which is
//     why the check is "can this actually run" and not "does server.js exist":
//     a partial copy would otherwise look like a hit and fail three screens
//     later as a missing package.
//
// **IT NEVER TOUCHES THE SHARED MOCK, and that is deliberate rather than
// convenient.** mock-sts's own docker-compose.yml says it out loud: the suite's
// stack starts that service with no persistence at all, and *a test that
// persisted would be a test whose second run started from the first run's
// leavings*. So this job configures nothing on the instance every other job is
// using, holds no JOB_LOCK, and needs no realm to hide in — everything it makes
// is in a database and a process it also destroys.
//
// Needs no browser and no Keycloak.
// ---------------------------------------------------------------------------
const assert = require("assert");
const fs = require("fs");
const net = require("net");
const path = require("path");
const { Command, Option } = require("commander");
const { spawn, spawnSync } = require("child_process");
const common = require("./jwt_vc_json_common.js");
const names = require("./random_username.js");

var appconfig;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, the arrangement tests/wait_for.js has.
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_persistence_postgres",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

// The throwaway container's name carries this run's stamp, so two runs on one
// machine cannot collide and a leaked one says which run leaked it.
const CONTAINER = "sts-persistence-test-" + names.runStamp();
const IMAGE = process.env.STS_TEST_POSTGRES_IMAGE || "postgres:18";

// ---------------------------------------------------------------------------
// A SERVER KEY PAIR FOR THE THROWAWAY DATABASE, so that the driver's TLS
// branch is exercised at all.
//
// Until 2026-08-31 this container was started with no certificate, so the
// connection string carried no `sslmode`, and `persistence_postgres.js` took
// its `wantsTls === false` path on every run. That path is half the file: the
// other half strips `sslmode` out of the string before `pg` sees it and
// configures the socket itself — which exists because `pg` parses `sslmode`
// TOO, and a string saying `require` beside an explicit `ssl` option is two
// answers to one question that a real deployment already got wrong once. None
// of it was reachable from here.
//
// This mirrors the mock's own postgres/generate-tls.sh rather than inventing a
// second arrangement, minus the parts a throwaway has no use for: no volume,
// so nothing is kept between starts and the `already there` branch is gone,
// and one day of validity rather than 825 because this pair outlives the
// assertions by seconds. `host` rules are deliberately left ALONE — the compose
// stack rewrites them to `hostssl` so the server refuses plaintext, and doing
// that here would cost the plaintext half of what this job now checks. The
// point is a database that will speak either, so one container can show that
// the report tells them apart.
//
// bash and openssl are both in the Debian image already, which is the reason
// the mock pins postgres:18 rather than -alpine; the same reason holds here.
// `exec` so postgres keeps pid 1 and still receives `docker rm -f`'s signal.
const TLS_DIR = "/var/lib/postgresql/tls";
const TLS_COMMAND = [
  "set -e",
  "mkdir -p " + TLS_DIR,
  "openssl req -new -x509 -nodes -newkey rsa:2048 -sha256 -days 1" +
    " -subj '/CN=localhost/O=mock-sts-test'" +
    " -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'" +
    " -keyout " + TLS_DIR + "/server.key" +
    " -out " + TLS_DIR + "/server.crt 2>/dev/null",
  // Postgres refuses to start if the key is group- or world-readable, and the
  // message names the permission rather than the cause.
  "chmod 600 " + TLS_DIR + "/server.key",
  "chmod 644 " + TLS_DIR + "/server.crt",
  "chown postgres:postgres " + TLS_DIR + "/server.key " +
    TLS_DIR + "/server.crt",
  "exec docker-entrypoint.sh postgres -c ssl=on" +
    " -c ssl_cert_file=" + TLS_DIR + "/server.crt" +
    " -c ssl_key_file=" + TLS_DIR + "/server.key"
].join(" && ");

// Everything this job started, so that teardown can be one function that runs
// in a `finally` whether or not the assertions passed.
const started = { container: false, processes: [] };

// ---------------------------------------------------------------------------
// PRECONDITIONS. Two ways to skip and one to fail, and naming which is the
// whole value of this — "there is no docker here" and "the sts submodule is not
// initialised" send you to completely different places.
// ---------------------------------------------------------------------------
async function preconditions() {
  log.debug("Entering preconditions().");
  const root = mockStsRoot();
  if (!root) {
    log.debug("Leaving preconditions(). No runnable mock STS tree.");
    return { ok: false, why: "there is no COMPLETE mock STS checkout here to " +
      "run. This job starts the service itself, so it needs the whole tree " +
      "and its node_modules — not the thirty-odd modules the tests image " +
      "carries. Looked at: MOCK_STS_DIR, ../sts (the submodule; an " +
      "uninitialised one is an EMPTY DIRECTORY, so `git submodule update " +
      "--init --recursive` is the usual fix), and ../../mock-sts. Set " +
      "MOCK_STS_DIR to a working copy to run it." };
  }

  const url = process.env.STS_TEST_POSTGRES_URL;
  if (url) {
    log.info("[postgres] Using the database named by STS_TEST_POSTGRES_URL. " +
             "This job will CREATE ITS TABLES in it and leave them behind — " +
             "sts_ldap_entries, sts_realms, sts_appconfig and sts_schema — so " +
             "point that variable at a database you are willing to have them " +
             "in.");
    log.debug("Leaving preconditions(). A database was named.");
    return { ok: true, root: root, url: url, ownContainer: false };
  }

  const docker = which("docker");
  if (!docker) {
    log.debug("Leaving preconditions(). No docker and no database.");
    return { ok: false, why: "no database. STS_TEST_POSTGRES_URL is unset and " +
      "docker is not installed here, so there is nothing to start one with. " +
      "Either set that variable, or install docker — this job otherwise runs " +
      "a throwaway " + IMAGE + " on a free port and removes it at the end." };
  }
  log.debug("Leaving preconditions(). Will start a container.");
  return { ok: true, root: root, url: null, ownContainer: true };
}

// A COMPLETE mock STS tree, or "". The candidate order is tests/module_paths.js's
// and the reasons for it are argued there; what differs is the TEST applied to
// each candidate. That file is looking for one module to require, so existence
// is enough. This one is going to run `node server.js`, so a tree without its
// dependencies is not a candidate at all — and the tests image contains exactly
// such a tree, which is the case this check exists for.
function mockStsRoot() {
  log.debug("Entering mockStsRoot().");
  const candidates = [
    process.env.MOCK_STS_DIR,
    path.join(__dirname, "..", "sts"),
    path.join(__dirname, "..", "..", "mock-sts")
  ].filter(Boolean);
  for (const candidate of candidates) {
    const runnable = ["server.js", "package.json",
                      path.join("node_modules", "express"),
                      path.join("node_modules", "pg")].every(function (part) {
      return fs.existsSync(path.join(candidate, part));
    });
    if (runnable) {
      log.info("[mock] Running the mock STS out of " + candidate + ".");
      log.debug("Leaving mockStsRoot(). " + candidate);
      return candidate;
    }
    if (fs.existsSync(path.join(candidate, "server.js"))) {
      log.info("[mock] " + candidate + " has a server.js but not the " +
               "dependencies to run it (express, pg), so it is not a " +
               "candidate. That is what the tests image looks like.");
    }
  }
  log.debug("Leaving mockStsRoot(). None.");
  return "";
}

function which(command) {
  const found = spawnSync("sh", ["-c", "command -v " + command],
      { encoding: "utf8" });
  return String(found.stdout || "").trim();
}

// ---------------------------------------------------------------------------
// THE DATABASE.
// ---------------------------------------------------------------------------
async function startPostgres() {
  log.debug("Entering startPostgres().");
  const port = await freePort();
  const run = spawnSync("docker", ["run", "-d", "--name", CONTAINER,
    "-e", "POSTGRES_PASSWORD=sts", "-e", "POSTGRES_USER=sts",
    "-e", "POSTGRES_DB=sts",
    "-p", "127.0.0.1:" + port + ":5432", IMAGE,
    "bash", "-c", TLS_COMMAND], { encoding: "utf8" });
  assert.strictEqual(run.status, 0,
    "could not start " + IMAGE + ": " + String(run.stderr || "").slice(0, 400) +
    ". The image is pulled on first use, so a machine with no network and no " +
    "cached copy fails here.");
  started.container = true;

  // Ready means "accepting connections OVER TCP", which is not the same as "the
  // container is running" and — the part that cost a run on 2026-08-29 — not
  // the same as what a bare `pg_isready` reports either.
  //
  // The official image's entrypoint runs initdb, then starts a TEMPORARY
  // server to apply the initialisation scripts, stops it, and only then execs
  // the real one. That temporary server is started with `listen_addresses=''`,
  // so it answers on the container's UNIX SOCKET and on no TCP port at all —
  // and a plain `docker exec pg_isready` connects over that socket, so it says
  // READY about half a second before anything can dial 5432. This job's mock
  // connects from the HOST over the published port, so it arrived in that
  // window and died at startup with `Connection terminated unexpectedly` —
  // which reads as a broken database rather than as an early one, and named
  // neither this loop nor postgres.
  //
  // So the probe is a real query over TCP: `-h 127.0.0.1` forces the network
  // path (PGPASSWORD because a host connection is authenticated where a local
  // socket one is trusted), and `select 1` proves the server that answered can
  // also serve. `pg_isready` alone is kept for nothing; it cannot tell these
  // two servers apart.
  const until = Date.now() + 60000;
  while (Date.now() < until) {
    const ready = spawnSync("docker", ["exec", "-e", "PGPASSWORD=sts",
      CONTAINER, "psql", "-h", "127.0.0.1", "-U", "sts", "-d", "sts",
      "-tAc", "select 1"], { encoding: "utf8" });
    if (ready.status === 0 && String(ready.stdout || "").trim() === "1") {
      const plain = "postgres://sts:sts@127.0.0.1:" + port + "/sts";
      log.info("[postgres] " + IMAGE + " is up and answering over TCP on " +
               "127.0.0.1:" + port + " as container " + CONTAINER +
               ", with TLS available on it.");
      log.debug("Leaving startPostgres().");
      return { url: plain + "?sslmode=require", plain: plain, own: true };
    }
    await pause(500);
  }
  assert.fail("postgres did not become ready within sixty seconds. `docker " +
    "logs " + CONTAINER + "` says why; the container is left running when " +
    "this assertion fires so that it can be read.");
}

// ---------------------------------------------------------------------------
// THE MOCK. Started as a child process on ports nothing else is using, with
// every listener this service has moved out of the way — the two Kerberos
// sockets, LDAP and LDAPS, the two TLS listeners and SPIFFE's two TCP ports —
// because a sibling stack is usually already holding the defaults and a bind
// that fails is RECORDED rather than thrown here, so the symptom would be a
// puzzling absence rather than an error.
//
// SPIFFE's two UNIX SOCKETS are turned OFF rather than moved: a socket has one
// binder and the default path is shared, so moving them would need a directory
// as well.
// ---------------------------------------------------------------------------
async function startMock(root, databaseUrl, label) {
  log.debug("Entering startMock(). label=" + label);
  const httpPort = await freePort();
  const env = Object.assign({}, process.env, await portEnv(httpPort), {
    STS_PERSISTENCE_MODE: "postgres",
    // NOT `STS_PERSISTENCE_DATABASE_URL`, which is the name five of its six
    // siblings would suggest and which this job spent a while getting wrong.
    // A misspelling here is QUIET: the service dials the built-in default
    // (postgres://sts:sts@localhost:5432/sts), cannot reach it, falls back to
    // memory and reports `configuredMode: postgres, mode: memory` — which is
    // correct behaviour and looks like a broken database.
    STS_DATABASE_URL: databaseUrl,
    STS_LOG_LEVEL: "warn",
    // The mock resolves CONFIG_FILE against ITS OWN root, and this suite's
    // copy of that variable names a file under tests/. See
    // tests/module_paths.js, which exists for this exact collision.
    CONFIG_FILE: path.join(root, "env", "local.js")
  });

  const child = spawn("node", ["server.js"], {
    cwd: root, env: env, stdio: ["ignore", "pipe", "pipe"]
  });
  started.processes.push(child);
  const output = [];
  child.stdout.on("data", function (chunk) { output.push(String(chunk)); });
  child.stderr.on("data", function (chunk) { output.push(String(chunk)); });

  const base = "http://127.0.0.1:" + httpPort;
  const until = Date.now() + 45000;
  while (Date.now() < until) {
    if (child.exitCode !== null) {
      assert.fail("the mock STS (" + label + ") exited with " +
        child.exitCode + " before it was listening. Its output was:\n" +
        output.join("").slice(-2000));
    }
    try {
      const probe = await common.httpJson(base + "/admin-api/status");
      if (probe.status === 200) {
        log.info("[mock] " + label + " is listening on " + base + ".");
        log.debug("Leaving startMock().");
        return { base: base, child: child, output: output };
      }
    } catch (e) {
      // Not up yet. The loop's own timeout is the failure, and it can say
      // what the process printed, which a connection error cannot.
    }
    await pause(300);
  }
  assert.fail("the mock STS (" + label + ") did not answer on " + base +
    " within forty-five seconds. Its output was:\n" +
    output.join("").slice(-2000));
}

async function stopMock(instance, why) {
  log.debug("Entering stopMock(). why=" + why);
  if (!instance || !instance.child || instance.child.exitCode !== null) {
    log.debug("Leaving stopMock(). Already gone.");
    return;
  }
  const ended = new Promise(function (resolve) {
    instance.child.once("exit", resolve);
  });
  instance.child.kill("SIGTERM");
  const killed = await Promise.race([ended, pause(8000).then(function () {
    return "timeout";
  })]);
  if (killed === "timeout") {
    log.warn("the mock STS did not stop on SIGTERM; killing it.");
    instance.child.kill("SIGKILL");
    await ended;
  }
  log.info("[mock] Stopped (" + why + ").");
  log.debug("Leaving stopMock().");
}

// A port nothing is listening on, taken by binding to 0 and reading back what
// the kernel chose. There is a race between closing and the mock binding, and
// it is the standard one and the standard answer: the alternative is a fixed
// port, and a fixed port on a machine that runs several of these stacks at once
// is not a smaller risk, it is a certainty. See the local-stacks note in
// tests/CLAUDE.md.
function freePort() {
  return new Promise(function (resolve, reject) {
    const server = net.createServer();
    server.unref();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", function () {
      const port = server.address().port;
      server.close(function () { resolve(port); });
    });
  });
}

// Every listener this service has, moved out of the way. A sibling stack is
// usually already holding the defaults, and a bind that fails is RECORDED
// rather than thrown for the four socket families — so the symptom of a
// collision would be a puzzling absence rather than an error.
//
// SPIFFE's two UNIX SOCKETS are turned OFF rather than moved: a socket has one
// binder and the default path is shared, so moving them would need a directory
// as well.
//
// AND THE MAIN PORT IS PINNED TO PLAIN HTTP, which is not a port but belongs
// with them: it is the same act of pinning what this instance does rather
// than inheriting an ambient default. Every request either caller makes is
// `http://`, and the mock's default stopped being that. `global.https`
// derives from `oauth2.rfc9700`, and the mock's own env/local.js — which both
// callers name as CONFIG_FILE — has set `https: true` since its 2026-08-30
// "TLS on all supported services" change.
//
// It broke the two callers in OPPOSITE directions, which is why it is set
// here rather than in either of them. startMock() polls until the port
// answers: the instance came up perfectly, in about a second, serving TLS to
// a plain-http probe, and the failure was the wait loop's — "did not answer
// within forty-five seconds", which reads as a service that could not start
// rather than one that started and was not being spoken to. That cost four
// red runs of the live-site suite. startMockExpectingFailure() polls to prove
// the port NEVER answers, so the same change made it pass VACUOUSLY: with
// TLS on, that probe cannot answer whether the service bound a listener it
// should not have or not, and the check stopped checking without failing.
//
// Switching it off rather than teaching this job https is deliberate. What is
// under test here is what SURVIVES A RESTART; the transport is incidental,
// and a certificate regenerated on every start would put
// `rejectUnauthorized: false` into every request below to prove nothing.
async function portEnv(httpPort) {
  log.debug("Entering portEnv(). httpPort=" + httpPort);
  const env = {
    STS_PORT: String(httpPort),
    STS_HTTPS: "false",
    STS_SPIFFE_WORKLOAD_SOCKET_ENABLED: "false",
    STS_SPIFFE_SERVER_SOCKET_ENABLED: "false"
  };
  const others = ["STS_TLS_PORT", "STS_MTLS_PORT", "KRB5_KDC_PORT",
                  "KRB5_SERVICE_PORT", "LDAP_PORT", "LDAPS_PORT",
                  "STS_SPIFFE_WORKLOAD_PORT", "STS_SPIFFE_SERVER_PORT"];
  for (const name of others) {
    env[name] = String(await freePort());
  }
  log.debug("Leaving portEnv().");
  return env;
}

function pause(ms) {
  return new Promise(function (resolve) { setTimeout(resolve, ms); });
}

// ---------------------------------------------------------------------------
// Talking to whichever instance is being driven.
// ---------------------------------------------------------------------------
async function get(instance, path) {
  log.debug("Entering get(). path=" + path);
  const reply = await common.httpJson(instance.base + path);
  assert.strictEqual(reply.status, 200,
    "GET " + path + " should answer 200; it answered " + reply.status + " " +
    String(reply.raw).slice(0, 200));
  log.debug("Leaving get().");
  return reply.body;
}

async function post(instance, path, body) {
  log.debug("Entering post(). path=" + path);
  const reply = await common.httpJson(instance.base + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {})
  });
  assert.ok(reply.status === 200 && reply.body && reply.body.ok !== false,
    "POST " + path + " " + JSON.stringify(body) + " should succeed; it " +
    "answered " + reply.status + " " +
    JSON.stringify((reply.body && reply.body.errors) || reply.body).slice(0, 300));
  log.debug("Leaving post().");
  return reply.body;
}

async function status(instance) {
  const shown = await get(instance, "/admin-api/persistence");
  return shown.status;
}

// The store's own account of itself, after giving a scheduled flush time to
// happen. In postgres mode the write delay is zero — the driver writes in a
// transaction rather than coalescing — but this waits on `pending` rather than
// assuming that, so the file does not have to know.
async function settled(instance) {
  log.debug("Entering settled().");
  const until = Date.now() + 8000;
  let seen = await status(instance);
  while (Date.now() < until && seen.pending) {
    await pause(150);
    seen = await status(instance);
  }
  log.debug("Leaving settled(). writes=" + seen.writes +
            ", pending=" + seen.pending);
  return seen;
}

// ---------------------------------------------------------------------------
// WHAT POSTGRES ITSELF SAW OF THE MOCK'S CONNECTIONS.
//
// This is the half that cannot be faked by agreeing with ourselves. Every
// other TLS check available here reads something THIS SIDE decided — the
// connection string, or the report built out of it — and a driver that set
// `sslmode=require` and then handed `pg` an option that quietly disabled it
// would pass all of them. `pg_stat_ssl` is the server's own row per backend,
// so it answers what actually crossed the socket.
//
// `client_addr <> 127.0.0.1` is what separates the MOCK's connections from
// this job's own. The mock dials the published port from the host and arrives
// as the bridge gateway; the readiness probe and this very query run through
// `docker exec` and arrive as loopback. Without that filter this would be
// asserting about psql as much as about the service under test — and libpq's
// own default `sslmode` is `prefer`, so those loopback connections are
// encrypted too and the mistake would not show as a failure.
//
// It counts as well as tests, because `bool_and` over no rows is null and a
// pool with nothing open would otherwise read as agreement. Zero connections
// is a retry, never a pass.
// ---------------------------------------------------------------------------
function connectionsFromTheMock() {
  log.debug("Entering connectionsFromTheMock().");
  const sql =
    "select count(*) filter (where s.ssl)::text || ' ' || count(*)::text " +
    "from pg_stat_ssl s join pg_stat_activity a on a.pid = s.pid " +
    "where a.datname = 'sts' and a.client_addr is not null " +
    "and a.client_addr <> '127.0.0.1'::inet";
  const asked = spawnSync("docker", ["exec", "-e", "PGPASSWORD=sts",
    CONTAINER, "psql", "-h", "127.0.0.1", "-U", "sts", "-d", "sts",
    "-tAc", sql], { encoding: "utf8" });
  const answer = String(asked.stdout || "").trim().split(/\s+/);
  const out = { encrypted: Number(answer[0] || 0),
                total: Number(answer[1] || 0) };
  log.debug("Leaving connectionsFromTheMock(). " + out.encrypted + " of " +
            out.total + " encrypted.");
  return out;
}

// Wait for the pool to have opened something, then report it. A pool that is
// idle between writes may hold nothing at the instant of the first query.
async function settledConnections() {
  log.debug("Entering settledConnections().");
  const until = Date.now() + 15000;
  let seen = connectionsFromTheMock();
  while (Date.now() < until && seen.total === 0) {
    await pause(300);
    seen = connectionsFromTheMock();
  }
  log.debug("Leaving settledConnections(). total=" + seen.total);
  return seen;
}

// ---------------------------------------------------------------------------
// THE CONNECTION IS ENCRYPTED, AND THE SERVER AGREES.
// ---------------------------------------------------------------------------
async function theDatabaseConnectionIsEncrypted(instance, databaseUrl) {
  log.debug("Entering theDatabaseConnectionIsEncrypted().");
  log.info("=== The database connection, as postgres saw it ===");
  // The messages below say what the connection string asked for, so check
  // that it asked. A caller that wired the plaintext URL in here would
  // otherwise get a failure explaining a `require` that was never sent.
  assert.ok(/[?&]sslmode=require/i.test(databaseUrl),
    "this section asserts the TLS path and must be given the TLS connection " +
    "string; it was given one that does not ask for sslmode=require.");
  const seen = await settledConnections();
  assert.ok(seen.total > 0,
    "postgres reports no client backend from this host at all, so there is " +
    "nothing to judge and this check would otherwise pass by saying nothing. " +
    "The mock is running and its store is healthy, so a pool connection " +
    "should be open.");
  assert.strictEqual(seen.encrypted, seen.total,
    "every connection the mock made should be TLS — the connection string " +
    "carries sslmode=require and the driver configures the socket itself — " +
    "but postgres reports " + seen.encrypted + " of " + seen.total +
    " encrypted. A `require` that arrives in the clear means the driver's " +
    "own ssl option won over the string, which is the exact disagreement " +
    "persistence_postgres.js strips the parameter to prevent.");
  log.info("[tls] OK — postgres reports all " + seen.total + " of the mock's " +
           "connection(s) encrypted, which is the server's account of it " +
           "rather than ours.");
  log.debug("Leaving theDatabaseConnectionIsEncrypted().");
}

// ---------------------------------------------------------------------------
// AND PLAINTEXT IS STILL PLAINTEXT, WHICH IS THE OTHER HALF OF THE BRANCH.
//
// A driver that turned TLS on unconditionally would pass every check above and
// be wrong: `sslmode=disable` would then mean its opposite. So the same
// database is dialled again with no `sslmode` at all, and both the report and
// postgres have to say so. This is why the container's `host` rules were left
// permissive — a `hostssl` server would refuse this connection and the
// distinction could not be drawn on one container.
// ---------------------------------------------------------------------------
async function plaintextIsReportedAndSeenAsPlaintext(root, plainUrl) {
  log.debug("Entering plaintextIsReportedAndSeenAsPlaintext().");
  log.info("=== The same database with no sslmode ===");
  const instance = await startMock(root, plainUrl, "the plaintext instance");
  try {
    const seen = await status(instance);
    assert.strictEqual(seen.mode, "postgres",
      "it should still reach the database in the clear; it is in " +
      seen.mode + " and reports " + seen.lastError);
    assert.strictEqual(seen.database.encrypted, false,
      "and the report must say the connection is NOT encrypted; it says " +
      JSON.stringify(seen.database));
    assert.strictEqual(seen.database.sslmode, "not set",
      "naming the absent parameter rather than inventing a value; it says " +
      JSON.stringify(seen.database.sslmode));
    const onTheWire = await settledConnections();
    assert.ok(onTheWire.total > 0,
      "postgres reports no client backend from this host, so there is " +
      "nothing to judge.");
    assert.strictEqual(onTheWire.encrypted, 0,
      "and postgres must have seen none of them encrypted, or the driver " +
      "turned TLS on for a string that did not ask for it — which would " +
      "make sslmode=disable mean its opposite. It reports " +
      onTheWire.encrypted + " of " + onTheWire.total + " encrypted.");
    log.info("[plaintext] OK — with no sslmode the report says not " +
             "encrypted and postgres saw " + onTheWire.total +
             " unencrypted connection(s). The two branches are told apart.");
  } finally {
    await stopMock(instance, "the plaintext check is done");
  }
  log.debug("Leaving plaintextIsReportedAndSeenAsPlaintext().");
}

// ---------------------------------------------------------------------------
// THE STORE OPENED, AND SAYS WHAT IT IS WITHOUT SAYING THE PASSWORD.
// ---------------------------------------------------------------------------
async function theStoreOpened(instance, databaseUrl) {
  log.debug("Entering theStoreOpened().");
  log.info("=== The store opened, in postgres mode ===");
  const seen = await status(instance);
  assert.strictEqual(seen.mode, "postgres",
    "the store should be in postgres mode; it is in " + seen.mode +
    (seen.configuredMode === "postgres"
      ? " having been CONFIGURED for postgres, which means it fell back — " +
        seen.lastError
      : " and was configured for " + seen.configuredMode));
  assert.strictEqual(seen.enabled, true, "and it should be enabled.");
  assert.strictEqual(seen.healthy, true,
    "and healthy; it reports " + seen.lastError);
  assert.ok(seen.persistsDirectory && seen.persistsRealms &&
            seen.persistsAppconfig,
    "and all three things should be persisting; it reports " +
    JSON.stringify({ directory: seen.persistsDirectory,
                     realms: seen.persistsRealms,
                     appconfig: seen.persistsAppconfig }));

  // THE CONNECTION STRING CARRIES A PASSWORD and this reply is rendered on a
  // console page and returned by an UNGATED management API. What comes back is
  // the host, port, database and user parsed out of it, and never the string.
  assert.ok(seen.database && seen.database.host && seen.database.database,
    "the status should describe the database it is talking to; it says " +
    JSON.stringify(seen.database));
  const asText = JSON.stringify(seen);
  assert.ok(asText.indexOf("postgres://") < 0,
    "AND IT MUST NEVER ECHO THE CONNECTION STRING. It carries a password, and " +
    "this reply is drawn on /admin/persistence and returned by an API that is " +
    "not gated — so the whole point of parsing the host, port, database and " +
    "user out of it is lost the moment the string itself appears beside them. " +
    "The reply contains: " + asText.slice(0, 400));
  assert.ok(!/"password"|:sts@|sts:sts/.test(asText),
    "and no part of the credential either; the reply is " + asText.slice(0, 400));

  // THE TWO PLACES TLS LIVES HAVE TO AGREE. `sslmode` rides in the connection
  // string and is postgres's own spelling; whether the certificate is BELIEVED
  // is a setting, because `pg` takes that as a socket option and would ignore
  // it in a URL. The report is built out of both, so what it must not do is
  // disagree with the string it was built from — a page that said `encrypted`
  // about a connection dialled without `sslmode` is the misleading half of a
  // true sentence, and it is read by whoever is deciding whether a deployment
  // is safe.
  //
  // Asserted against the URL rather than against a constant, because
  // STS_TEST_POSTGRES_URL lets somebody bring their own database and this
  // property holds either way.
  const asked = /[?&]sslmode=(require|verify-ca|verify-full|prefer)/i
    .exec(databaseUrl);
  assert.strictEqual(seen.database.encrypted, !!asked,
    "the report's `encrypted` must agree with the connection string it was " +
    "built from. The string " + (asked ? "asks for TLS (sslmode=" + asked[1] +
    ")" : "does not ask for TLS") + " and the report says " +
    JSON.stringify(seen.database));
  if (asked) {
    assert.strictEqual(seen.database.sslmode, asked[1].toLowerCase(),
      "and it should name the mode that was actually asked for; it says " +
      JSON.stringify(seen.database.sslmode));
    assert.strictEqual(seen.database.verifyCertificate, false,
      "and report the certificate as NOT verified, which is the honest " +
      "description of the self-signed pair generated per container and the " +
      "default of persistence.databaseTlsRejectUnauthorized. Encrypted and " +
      "authenticated are two different answers; it says " +
      JSON.stringify(seen.database));
  }

  assert.strictEqual(seen.coordinates, false,
    "and it must say that it does NOT coordinate — see the section below, " +
    "which is the evidence for that claim rather than a repetition of it.");
  assert.ok(/not coordination/i.test(String(seen.note || "")),
    "and the note beside it should say so in a sentence an operator reads, " +
    "since that is what somebody deploys against; it says " +
    JSON.stringify(seen.note));
  log.info("[store] OK — postgres, healthy, all three things persisting, " +
           "talking to " + seen.database.user + "@" + seen.database.host +
           ":" + seen.database.port + "/" + seen.database.database +
           " over " + seen.database.sslmode +
           ", and the connection string appears nowhere in the reply.");
  log.debug("Leaving theStoreOpened().");
}

// ---------------------------------------------------------------------------
// WRITE ONE OF EACH OF THE THREE THINGS THAT PERSIST, THROUGH A DOOR A PERSON
// USES.
//
// Not through the persistence module: what is under test is the whole path from
// the management API down, which is what a person actually changes and the only
// path any of this is reachable by.
// ---------------------------------------------------------------------------
async function writeSomethingOfEachKind(instance) {
  log.debug("Entering writeSomethingOfEachKind().");
  log.info("=== Writing one of each of the three things that persist ===");
  const stamp = names.runStamp();
  const made = {
    realm: ("pgtest" + stamp).toLowerCase().replace(/[^a-z0-9-]/g, ""),
    person: names.usernameFor("pgtest-person"),
    application: "pgtest-app-" + stamp,
    settingKey: "krb5.clockSkew",
    settingValue: 0
  };

  // 1. THE REALM REGISTRY, with an override of its own on the row.
  await post(instance, "/admin-api/realms/create", {
    id: made.realm, name: "Postgres persistence test",
    overrides: { "saml2.entityId": "urn:pgtest:" + made.realm }
  });

  // 2. THE DIRECTORY — a person and an application, and the application in the
  // REALM, so that what comes back has to come back into the right subtree.
  await post(instance, "/admin-api/users/create", { username: made.person });
  await post(instance, "/realm/" + made.realm + "/admin-api/applications/create", {
    identifier: made.application, name: "Postgres persistence test",
    kind: "oauth2-client", protocols: ["oauth2"]
  });

  // 3. THE RUNTIME APPCONFIG OVERRIDES.
  const before = await get(instance, "/admin-api/config");
  made.settingValue = Number(settingRow(before, made.settingKey).value) + 11;
  await post(instance, "/admin-api/config/set",
      { key: made.settingKey, value: made.settingValue });

  const seen = await settled(instance);
  assert.ok(seen.writes > 0,
    "the store should have written something by now; it reports " +
    seen.writes + " write(s).");
  assert.strictEqual(seen.failures, 0,
    "and nothing should have failed: " + seen.lastError);
  assert.strictEqual(seen.pending, false,
    "and nothing should still be waiting.");
  log.info("[written] OK — realm " + made.realm + ", person " + made.person +
           ", application " + made.application + " in that realm, and " +
           made.settingKey + "=" + made.settingValue + ", in " + seen.writes +
           " write(s) with no failure.");
  log.debug("Leaving writeSomethingOfEachKind().");
  return made;
}

function settingRow(config, key) {
  let found;
  (config.groups || []).forEach(function (group) {
    (group.settings || []).forEach(function (setting) {
      if (setting.key === key) {
        found = setting;
      }
    });
  });
  return found;
}

// ---------------------------------------------------------------------------
// WHAT THE FIRST PROCESS MINTED, so that the restart can be asked about it.
//
// A token and its `kid`, taken from the JWKS rather than from the token, so
// that what is compared after the restart is the SERVICE's key rather than a
// header this test read once.
// ---------------------------------------------------------------------------
async function mintSomething(instance, made) {
  log.debug("Entering mintSomething().");
  const reply = await common.httpJson(instance.base + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=password&username=" + encodeURIComponent(made.person) +
          "&password=x&client_id=pgtest-client&scope=openid"
  });
  assert.strictEqual(reply.status, 200,
    "the token endpoint should mint a token; it answered " + reply.status);
  const jwks = await get(instance, "/oauth2/jwks");
  assert.ok(jwks.keys && jwks.keys.length,
    "the service should publish a JWKS; it published " + JSON.stringify(jwks));
  const held = {
    accessToken: reply.body.access_token,
    jti: claimOf(reply.body.access_token, "jti"),
    kid: jwks.keys[0].kid,
    audit: (await get(instance, "/admin-api/audit")).recorded,
    tokensHeld: (await get(instance, "/admin-api/tokens")).held
  };
  assert.ok(held.jti && held.kid,
    "and both a jti and a kid should have been read; got " +
    JSON.stringify({ jti: held.jti, kid: held.kid }));
  assert.ok(held.tokensHeld > 0,
    "and the service should be holding what it just issued; it holds " +
    held.tokensHeld);
  log.info("[minted] A token with jti " + held.jti + ", signed by " +
           held.kid + ". " + held.tokensHeld + " artifact(s) held and " +
           held.audit + " audit row(s) recorded.");
  log.debug("Leaving mintSomething().");
  return held;
}

function claimOf(jwt, name) {
  if (!jwt) {
    return "";
  }
  const parts = String(jwt).split(".");
  if (parts.length < 2) {
    return "";
  }
  try {
    return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"))[name] || "";
  } catch (e) {
    // A token this service minted always decodes; one that does not is worth
    // reporting as an absent claim rather than as a crash, because the
    // assertion that follows says more about what went wrong.
    return "";
  }
}

// ---------------------------------------------------------------------------
// THE RESTART, AND THE THREE THINGS THAT MUST COME BACK.
//
// This is the assertion no other job in this suite can make, and it is made
// against a process that did not write any of it.
// ---------------------------------------------------------------------------
async function everythingThatPersistsComesBack(instance, made) {
  log.debug("Entering everythingThatPersistsComesBack().");
  log.info("=== After a restart: what came back ===");
  const seen = await status(instance);
  assert.ok(seen.restoredAt,
    "the store should say WHEN it restored; a process that read nothing back " +
    "reports no instant at all, which is the difference between an empty " +
    "database and a database that was never read.");

  // The counts first, because they are the service's own account of the
  // restore and a mismatch between them and the entries below says which half
  // is wrong.
  assert.strictEqual(seen.restored.realms, 1,
    "ONE REALM should have been restored — this job made exactly one, and the " +
    "DEFAULT realm is never a row (it is a constant in realms.js, so a store " +
    "that carried one would be describing a realm nobody can remove). It " +
    "reports " + seen.restored.realms);
  assert.ok(seen.restored.entries > 0,
    "and the directory should have come back; it restored " +
    seen.restored.entries + " entr(ies).");
  assert.strictEqual(seen.restored.overrides, 1,
    "and the one runtime appconfig override; it restored " +
    seen.restored.overrides);

  // 1. THE REALM, and the override it was CREATED with — which is the field
  // that was documented, exampled, validated and silently dropped by the
  // shared action function for months, so it is worth following all the way
  // to a database and back.
  const realms = await get(instance, "/admin-api/realms");
  const row = (realms.realms || []).filter(function (one) {
    return one.id === made.realm;
  })[0];
  assert.ok(row, "the realm " + made.realm + " should be back; the registry " +
    "holds " + JSON.stringify((realms.realms || []).map(function (one) {
      return one.id;
    })));
  const entityId = ((row.settings || []).filter(function (setting) {
    return setting.key === "saml2.entityId";
  })[0] || {}).value;
  assert.strictEqual(entityId, "urn:pgtest:" + made.realm,
    "and the override it was created with should be on it; the row carries " +
    JSON.stringify(row.settings));

  // 2. THE DIRECTORY, in both realms — the person in the default one and the
  // application in the realm, so that a restore which put everything in one
  // subtree fails here rather than looking correct.
  const person = await get(instance,
      "/admin-api/users?user=" + encodeURIComponent(made.person));
  assert.strictEqual(person.known, true,
    "the person created before the restart should still be in the directory.");
  const application = await get(instance, "/realm/" + made.realm +
      "/admin-api/applications?application=" + encodeURIComponent(made.application));
  assert.strictEqual(application.found, true,
    "and the application should be back IN ITS REALM. The directory is a " +
    "store per realm, so a restore that dropped everything into one subtree " +
    "would leave this one invisible from the realm that owns it.");
  assert.ok(String(application.dn).indexOf("dc=" + made.realm + ",") > 0,
    "and its DN should still name that realm; it is " + application.dn);
  const inDefault = await get(instance,
      "/admin-api/applications?application=" + encodeURIComponent(made.application));
  assert.strictEqual(inDefault.found, false,
    "AND IT MUST NOT BE VISIBLE IN THE DEFAULT REALM. Two realms here are two " +
    "directories; a restore that flattened them would put every realm's " +
    "applications in everybody's registry.");

  // 3. THE APPCONFIG OVERRIDE, with its source.
  const config = await get(instance, "/admin-api/config");
  const setting = settingRow(config, made.settingKey);
  assert.strictEqual(Number(setting.value), made.settingValue,
    "the runtime override should be in force again; " + made.settingKey +
    " reads " + setting.value + " against the " + made.settingValue +
    " that was set before the restart.");
  assert.strictEqual(setting.source, "override",
    "and the row should say it came from an override rather than from the " +
    "appconfig file — the saved values are re-applied through the same " +
    "setOverride() a caller uses, so persistence adds no LAYER and the five " +
    "are unchanged. It says " + setting.source);
  log.info("[restored] OK — the realm and its create-time override, the " +
           "person, the application in its own realm's subtree and not in " +
           "anybody else's, and the appconfig override with its source.");
  log.debug("Leaving everythingThatPersistsComesBack().");
}

// ---------------------------------------------------------------------------
// AND THE HALF THAT IS A DOCUMENTED NON-GOAL.
//
// This is the one a well-meaning change breaks, because "the tokens went away"
// reads like a bug and is the whole design: the signing key is regenerated on
// every start, so a token restored from a database would verify against
// nothing at all. The `kid` is derived from the key material — two instances
// cannot claim one kid over different keys — which makes it the evidence
// rather than an illustration.
// ---------------------------------------------------------------------------
async function nothingThatWasMintedComesBack(instance, held) {
  log.debug("Entering nothingThatWasMintedComesBack().");
  log.info("=== After a restart: what did NOT come back ===");
  const jwks = await get(instance, "/oauth2/jwks");
  assert.notStrictEqual(jwks.keys[0].kid, held.kid,
    "THE SIGNING KEY MUST BE A NEW ONE. It is regenerated on every start and " +
    "the kid is derived from the key material, so a service that came back " +
    "with " + held.kid + " would be one that had persisted its private key — " +
    "and every token in that database would then be a live credential " +
    "surviving a restart, which is the opposite of what this store is for.");

  const introspected = await common.httpJson(instance.base + "/oauth2/introspect", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "token=" + encodeURIComponent(held.accessToken)
  });
  assert.strictEqual(introspected.status, 200,
    "introspection should answer 200 whatever it thinks of the token.");
  assert.strictEqual(introspected.body.active, false,
    "AND THE TOKEN MINTED BEFORE THE RESTART MUST BE DEAD. It was signed by a " +
    "key that no longer exists, so a service that still called it active " +
    "would be vouching for something it can no longer verify.");

  const tokens = await get(instance, "/admin-api/tokens");
  assert.strictEqual(tokens.held, 0,
    "and the service should be holding NOTHING it minted: sessions, access " +
    "tokens, ID Tokens, refresh tokens, codes, artifacts and tickets all go " +
    "with the process, in every mode. It holds " + tokens.held);

  const metrics = await get(instance, "/admin-api/metrics");
  assert.ok(metrics.uptimeMs < 120000,
    "and the statistics should be this process's rather than the last one's; " +
    "it reports an uptime of " + metrics.uptimeMs + "ms.");
  log.info("[not restored] OK — a new signing key (" + jwks.keys[0].kid +
           " rather than " + held.kid + "), the old token dead at " +
           "introspection, nothing held, and the statistics reset.");
  log.debug("Leaving nothingThatWasMintedComesBack().");
}

// ---------------------------------------------------------------------------
// PERSISTENCE IS NOT COORDINATION, AND THIS IS THE EVIDENCE RATHER THAN THE
// CLAIM.
//
// `status.coordinates` is `false` and the note beside it says what that means:
// two processes pointed at one database each hold their own copy of the
// directory in memory and will not see each other's writes until they restart.
// That sentence is the one somebody deploys against — it is the difference
// between "persistence" and "clustering" — so it is worth demonstrating rather
// than reading back.
//
// The demonstration has to be careful about WHEN. A second instance reads the
// store at startup, so anything written BEFORE it started is legitimately
// there. What must not appear is a write made AFTER it started, which is why
// the order below is: start the second, then write in the first, then look.
// ---------------------------------------------------------------------------
async function twoProcessesDoNotSeeEachOther(first, root, databaseUrl) {
  log.debug("Entering twoProcessesDoNotSeeEachOther().");
  log.info("=== Two processes, one database ===");
  const second = await startMock(root, databaseUrl, "the second instance");
  try {
    const seen = await status(second);
    assert.strictEqual(seen.mode, "postgres",
      "the second instance should have opened the same store; it is in " +
      seen.mode + " (" + seen.lastError + ")");
    assert.ok(seen.restored.entries > 0,
      "AND IT SHOULD HAVE READ WHAT THE FIRST ONE WROTE — everything written " +
      "before it started is legitimately there, and that is what makes the " +
      "negative below mean something. It restored " +
      JSON.stringify(seen.restored));

    // Now a write in the FIRST instance, after the second is up.
    const late = names.usernameFor("pgtest-late");
    await post(first, "/admin-api/users/create", { username: late });
    await settled(first);
    assert.strictEqual((await get(first,
        "/admin-api/users?user=" + encodeURIComponent(late))).known, true,
      "the first instance should of course see its own write.");

    const inSecond = await get(second,
        "/admin-api/users?user=" + encodeURIComponent(late));
    assert.strictEqual(inSecond.known, false,
      "AND THE SECOND INSTANCE MUST NOT SEE IT. Persistence here is not " +
      "coordination: each process holds its own copy of the directory in " +
      "memory and reads the store once, at startup. If this ever starts " +
      "passing it is because somebody made the store a live one — which " +
      "would be a good feature and a DIFFERENT one, and `coordinates` and " +
      "the note beside it would have to change in the same commit, along " +
      "with persistence/CLAUDE.md, which says running several copies " +
      "against one store is not yet a way to scale this service.");
    assert.strictEqual(seen.coordinates, false,
      "and the second instance must say so about itself too.");
    log.info("[coordination] OK — the second instance read what was already " +
             "in the store and did not see a write the first made after it " +
             "started, exactly as `coordinates: false` promises.");
  } finally {
    await stopMock(second, "the coordination check is done");
  }
  log.debug("Leaving twoProcessesDoNotSeeEachOther().");
}

// ---------------------------------------------------------------------------
// A CONFIGURED STORE THAT CANNOT BE OPENED STOPS THE SERVICE.
//
// This section asserted the OPPOSITE when it was written, and the reversal is
// the reason it is worth reading rather than skimming. The old rule — a
// failure is recorded, the mock falls back to memory and keeps answering — is
// still right for a store that breaks WHILE RUNNING, and `flush()` still
// behaves that way. It was wrong at STARTUP:
//
//   **A PROCESS THAT WAS TOLD TO PERSIST AND IS NOT PERSISTING LOOKS EXACTLY
//   LIKE ONE THAT IS.** Every endpoint answers, the console draws, and the
//   realms, applications and federation partners somebody creates are thrown
//   away at the next restart — which is the restart they will do precisely
//   because they expected the work to survive it. The fallback was reported on
//   /admin/persistence and in the log, and neither is where anybody is looking
//   while the service appears to be working.
//
// So this starts an instance pointed at a port nothing is listening on and
// asserts that it EXITS, non-zero, having said which setting to look at — and
// that it never bound a listener, because a service that answered anything at
// all would be the old behaviour with a worse ending.
//
// It is asserted with a DEAD PORT rather than a stopped container because the
// two are the same failure to this service and only one of them can be
// arranged without touching the database the rest of this job is using.
// ---------------------------------------------------------------------------
async function anUnreachableDatabaseIsFatal(root) {
  log.debug("Entering anUnreachableDatabaseIsFatal().");
  log.info("=== A database that is not there ===");
  const port = await freePort();
  const nowhere = "postgres://sts:sts@127.0.0.1:" + port + "/sts";
  const ended = await startMockExpectingFailure(root, nowhere);

  assert.notStrictEqual(ended.code, 0,
    "A MOCK CONFIGURED TO PERSIST AND UNABLE TO REACH ITS STORE MUST EXIT " +
    "NON-ZERO. It exited with " + ended.code + ". A zero exit or a running " +
    "process is the old behaviour — answering out of a seeded directory while " +
    "presenting itself as the configured one — which loses everything anybody " +
    "does with it at the next restart.\n" + ended.output.slice(-1200));

  // The message is the other half, and it is read out of the FATAL log record
  // rather than grepped out of the raw stream: this service logs bunyan JSON,
  // so every quotation mark in the sentence is escaped on the wire and a
  // regular expression written against the sentence as a person reads it does
  // not match. Parsing also means the assertions are about the record the
  // service chose to emit at level 60, rather than about anything that
  // happened to contain the word.
  const fatal = fatalMessage(ended.output);
  assert.ok(fatal,
    "the refusal must be logged at FATAL. An operator whose service will not " +
    "start filters for the highest level first, and a refusal logged at " +
    "`error` sits among the ordinary noise of a startup that then continues. " +
    "The last of what it printed was:\n" + ended.output.slice(-1200));
  assert.ok(/persistence\.mode is "postgres"/.test(fatal),
    "the failure must name the MODE it was configured for, so that somebody " +
    "who did not set it knows where it came from. It said:\n" + fatal);
  assert.ok(/ECONNREFUSED|could not be read|connect/i.test(fatal),
    "and it must name what actually went wrong rather than only that " +
    "something did. It said:\n" + fatal);
  assert.ok(/persistence\.mode=memory|STS_PERSISTENCE_MODE/.test(fatal),
    "AND IT MUST SAY THE WAY OUT. Running this service without a store is one " +
    "setting, and somebody who has just been refused a start is exactly the " +
    "person who needs to be told which. It said:\n" + fatal);

  assert.ok(!ended.everAnswered,
    "and it must never have answered a request. A process that bound a " +
    "listener and THEN exited would have had a window in which it served " +
    "/oauth2/authorize out of a seeded directory, which is the state this " +
    "refusal exists to make impossible — persistence.start() runs before the " +
    "listener binds for exactly that reason.");
  log.info("[fatal] OK — exited " + ended.code + " without ever answering, " +
           "naming the mode, the cause and the setting that turns " +
           "persistence off.");
  log.debug("Leaving anUnreachableDatabaseIsFatal().");
}

// The FATAL record out of a bunyan stream, as a person would read it. Level 60
// is bunyan's `fatal`, and taking the LAST one means a process that logged
// several says its final word here.
function fatalMessage(output) {
  log.debug("Entering fatalMessage().");
  let found = "";
  String(output).split("\n").forEach(function (line) {
    if (!line.trim()) {
      return;
    }
    try {
      const record = JSON.parse(line);
      if (record.level >= 60 && record.msg) {
        found = record.msg;
      }
    } catch (e) {
      // Not a bunyan record — a node stack trace, or a partial line from a
      // process that was still writing when it exited. Neither is what this
      // is looking for, and both are legitimately present.
    }
  });
  log.debug("Leaving fatalMessage(). " + (found ? "found" : "none"));
  return found;
}

// Start a mock that is EXPECTED to die, and report how it died. It is a
// separate function from startMock() rather than a flag on it, because the two
// wait for opposite things: one polls until a port answers and fails on exit,
// and this one waits for exit and fails if the port ever answers.
async function startMockExpectingFailure(root, databaseUrl) {
  log.debug("Entering startMockExpectingFailure().");
  const httpPort = await freePort();
  const env = Object.assign({}, process.env, await portEnv(httpPort), {
    STS_PERSISTENCE_MODE: "postgres",
    STS_DATABASE_URL: databaseUrl,
    STS_LOG_LEVEL: "warn",
    CONFIG_FILE: path.join(root, "env", "local.js")
  });
  const child = spawn("node", ["server.js"], {
    cwd: root, env: env, stdio: ["ignore", "pipe", "pipe"]
  });
  started.processes.push(child);
  const output = [];
  child.stdout.on("data", function (chunk) { output.push(String(chunk)); });
  child.stderr.on("data", function (chunk) { output.push(String(chunk)); });

  // Poll the port while waiting for the exit. A service that answers even once
  // has bound a listener it should never have bound, and the only way to see
  // that is to be asking while it is deciding.
  let everAnswered = false;
  const polling = setInterval(function () {
    common.httpJson("http://127.0.0.1:" + httpPort + "/admin-api/status")
      .then(function (reply) {
        if (reply.status === 200) {
          everAnswered = true;
        }
      })
      .catch(function () {
        // Connection refused, which is the expected answer throughout.
      });
  }, 150);

  const code = await Promise.race([
    new Promise(function (resolve) {
      child.once("exit", function (exitCode) { resolve(exitCode); });
    }),
    pause(45000).then(function () { return "did not exit"; })
  ]);
  clearInterval(polling);
  if (code === "did not exit") {
    child.kill("SIGKILL");
    assert.fail("the mock STS was pointed at a database that is not there and " +
      "was still running forty-five seconds later. It should have exited " +
      "non-zero at startup. Its output was:\n" + output.join("").slice(-1500));
  }
  log.debug("Leaving startMockExpectingFailure(). code=" + code);
  return { code: code, output: output.join(""), everAnswered: everAnswered };
}

// ---------------------------------------------------------------------------
// TEARDOWN. Everything this job started, whether or not the assertions passed —
// a leaked container holds a port and a leaked node process holds nine.
// ---------------------------------------------------------------------------
async function tearDown() {
  log.debug("Entering tearDown().");
  for (const child of started.processes) {
    if (child.exitCode === null) {
      try {
        child.kill("SIGKILL");
      } catch (e) {
        // Already gone between the check and the signal, which is the only
        // way this throws and is not worth reporting as a failure.
        log.debug("could not kill a child process: " + e.message);
      }
    }
  }
  if (started.container) {
    const removed = spawnSync("docker", ["rm", "-f", CONTAINER],
        { encoding: "utf8" });
    if (removed.status === 0) {
      log.info("[teardown] Removed the throwaway database container " +
               CONTAINER + ".");
    } else {
      log.warn("[teardown] Could not remove " + CONTAINER + ": " +
               String(removed.stderr || "").slice(0, 200) +
               ". Remove it by hand — it is holding a port.");
    }
  }
  log.debug("Leaving tearDown().");
}

async function test() {
  log.debug("Entering test().");
  const ready = await preconditions();
  if (!ready.ok) {
    // Named, never silent. A skip that did not say which precondition failed
    // is a skip nobody ever turns back into a run.
    log.warn("SKIPPED: " + ready.why);
    log.info("Test completed successfully (skipped).");
    log.debug("Leaving test(). Skipped.");
    return;
  }

  try {
    // `plain` is only ours to offer when the container is: a caller who set
    // STS_TEST_POSTGRES_URL gave one string and may have given a `hostssl`
    // server, where dialling in the clear is refused by the far end rather
    // than being the thing under test.
    const database = ready.ownContainer
      ? await startPostgres()
      : { url: ready.url, plain: null, own: false };
    const databaseUrl = database.url;

    let instance = await startMock(ready.root, databaseUrl, "the first instance");
    await theStoreOpened(instance, databaseUrl);
    const made = await writeSomethingOfEachKind(instance);
    const held = await mintSomething(instance, made);

    if (database.own) {
      await theDatabaseConnectionIsEncrypted(instance, databaseUrl);
    } else {
      log.warn("[tls] SKIPPED the pg_stat_ssl checks: they read the " +
               "database's own account of the connection through `docker " +
               "exec`, and STS_TEST_POSTGRES_URL names a database this job " +
               "did not start and has no container for. What the report says " +
               "about TLS was still checked against the connection string.");
    }

    await twoProcessesDoNotSeeEachOther(instance, ready.root, databaseUrl);

    log.info("=== Restarting the mock STS ===");
    await stopMock(instance, "so that the restart can be asserted");
    instance = await startMock(ready.root, databaseUrl, "after the restart");
    await everythingThatPersistsComesBack(instance, made);
    await nothingThatWasMintedComesBack(instance, held);
    await stopMock(instance, "the restart checks are done");

    if (database.plain) {
      await plaintextIsReportedAndSeenAsPlaintext(ready.root, database.plain);
    }

    await anUnreachableDatabaseIsFatal(ready.root);
    log.info("Test completed successfully.");
  } finally {
    await tearDown();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_persistence_postgres")
  .description("Start a Postgres and a mock STS against it, restart the mock, " +
      "and assert what survived, what did not, that two processes do not see " +
      "each other, and that a missing database is not fatal.")
  // Accepted and ignored: run-report.js passes --url to every job, and
  // tests/jwk_pem_encoding.js fails the suite if a job does not declare it.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this job starts the service it drives)"))
  .parse(process.argv);

test().catch(async function (e) {
  log.error(e.stack || e.message);
  await tearDown();
  process.exit(1);
});
