#!/bin/bash
#
# Runs the full Selenium test suite with code-coverage collection enabled and
# renders the reports. Frontend (browser) coverage is gathered from
# Istanbul-instrumented bundles; backend (API) coverage is gathered with c8.
#
# Outputs (gitignored):
#   ./coverage/frontend/report/index.html   - browser/frontend coverage
#   ./coverage/api/index.html                - API (Node) coverage
#
set -x

# The tests run inside the containerized stack (docker-compose-run-tests.yml),
# so the browser bundles must be built with the in-container hostnames
# (api:4000 / client:3000). Using local.js here bakes http://localhost:4000
# into the bundle, which is unreachable from inside the Selenium container and
# makes every token call fail with status:0.
CONFIG_FILE=./env/docker-tests.js
CURRENT_DIR=`echo "$(dirname "$(realpath "$0")")"`
COMMON_SH=${CURRENT_DIR}/common/common.sh
if [ -r "${COMMON_SH}" ];
then
  . ${COMMON_SH}
else
  echo "Cannot find ${COMMON_SH}."
  exit 1
fi
common_setup

export CONFIG_FILE="${CONFIG_FILE:-./env/docker-tests.js}"

# ---------------------------------------------------------------------------
# A LONGER PER-JOB WATCHDOG, BECAUSE INSTRUMENTATION IS WHY THIS RUN IS SLOW.
#
# run-report.js defaults to 900000ms and that is the right number for the PLAIN
# suite: its own comment reasons it out from real measurements (the longest job
# in the 2026-08-26 run was 389 seconds), and it is far enough above them to
# bound a hang without turning a slow machine into a failure.
#
# THIS RUN IS NOT THAT RUN. It is the same jobs under NODE_V8_COVERAGE, and on
# a GitHub runner that means two cores shared by a pool of them. Three jobs are
# CPU-bound cryptography and are nowhere near the others:
#
#     hbs_signatures   36s        LMS/HSS and XMSS, from the RFCs' vectors
#     pqc_engines      58s        FIPS 203/204/205 and the X-Wing draft
#     jws_engine       67s        every registered JWS alg, both backends
#
# — uninstrumented, on a twenty-core machine. Instrumented on two, they went
# past 900000ms and were killed, which is what took `develop` red on
# 2026-08-30 and `feature/269` with it. A job that is killed asserts nothing,
# and the report then blames three of the most valuable tests in the suite for
# a property of the runner.
#
# 2700000ms is 45 minutes per job, against a whole-run wall clock of about 50
# and a GitHub job limit of 360, so it still bounds a hang — it is simply
# calibrated for the instrumented run rather than the plain one.
#
# The caller's own value wins, so a run that wants the short watchdog back can
# ask for it, and 0 still disables the watchdog entirely.
# ---------------------------------------------------------------------------
export TEST_JOB_TIMEOUT_MS="${TEST_JOB_TIMEOUT_MS:-2700000}"

# ---------------------------------------------------------------------------
# THE MOCK STS'S LOG LEVEL, exposed here so a run can turn it down.
#
# `STS_LOG_LEVEL` is a setting of the mock (see sts/common/config.js), and an
# environment variable there OUTRANKS the appconfig file `CONFIG_FILE` selects
# — so this one variable overrides whatever env/local.js or env/docker-tests.js
# says without either file being edited. The compose files pass it through to
# every sts service in the BARE form, which means "only if the shell that ran
# this launcher has it": unset here, unset in the container, and the appconfig
# file's own level applies exactly as it did before this existed.
#
# WHY YOU WOULD SET IT. The mock logs every request, every response and every
# token or assertion both before and after signing, and it does that at DEBUG,
# which is its default and the point of a mock — when a test fails, that log is
# the only record of what was issued. It is also expensive: it is about half of
# that service's CPU, and a benchmark of it wrote 156MB in sixteen seconds. With
# several test jobs driving ONE instance at once, `STS_LOG_LEVEL=info` roughly
# doubles what that instance can answer.
#
# DEBUG IS DELIBERATELY STILL THE DEFAULT. Turning it down trades the record of
# what the mock did for throughput, and that is a choice a run makes rather than
# one that should be made for it.
#
#   STS_LOG_LEVEL=info ./run-coverage.sh
#
# EXPORTED ONLY WHEN IT HAS A VALUE, and the guard is not decoration. `export`
# on an unset variable does leave it unset, so the `if` changes nothing today —
# it is here to stop this being "simplified" later into a plain assignment with
# an empty default. An empty STS_LOG_LEVEL is not a harmless default: bunyan
# throws `unknown level name: ""` while the mock is still loading its modules,
# so the service does not start, and on the containerized stack that arrives as
# a compose healthcheck timeout rather than as anything naming a log level.
# ---------------------------------------------------------------------------
if [ -n "${STS_LOG_LEVEL:-}" ]; then
  export STS_LOG_LEVEL
fi

# ---------------------------------------------------------------------------
# HOW MANY JOBS RUN AT ONCE, and how long one may take before it is killed.
#
# The suite is ~200 independent jobs and run-report.js runs them in a POOL. Both
# settings are read INSIDE the tests container, so both have to cross two
# boundaries to get there: `sudo`, which empties the environment and forwards
# only what common/common.sh lists in COMPOSE_FORWARDED_VARS, and compose, which
# substitutes them into the tests service (docker-compose-run-tests.yml). Until
# 2026-08-27 neither name was on that list, so a value set here reached compose
# as empty and the pool sized itself from the CONTAINER's view of the cores as
# though nothing had been asked for — no warning, and a wall clock that looked
# like the default because it WAS the default.
#
#   TEST_CONCURRENCY   jobs at once. Unset means decide in the container: one
#                      less than its cores, held between 2 and 4. The cap is not
#                      politeness — the longest jobs are CPU-bound in-browser
#                      crypto, and on THIS stack Keycloak, Postgres, the mock
#                      STS, both walt.id containers and the WS-Fed side-car are
#                      all on the same machine, so raising it past the cores
#                      trades the suite's wall clock for those services'
#                      response times and buys nothing.
#   TEST_JOB_TIMEOUT_MS  per-job watchdog in ms (default 900000 — 15 minutes;
#                      0 disables it). Raise it if a heavily loaded pool starts
#                      reporting timeouts on jobs that pass alone.
#
#   TEST_CONCURRENCY=6 ./run-coverage.sh
#   TEST_CONCURRENCY=1 ./run-coverage.sh   # sequential, live output
#
# NOTHING ABOUT COVERAGE SERIALISES A RUN, which is worth saying because it
# looks as though it should. The three sinks are all per-process or per-payload:
# the api's c8 writes once when its container is stopped, the browser bundles
# POST each page's window.__coverage__ to the client server, which names every
# file with a timestamp AND a random suffix, and the in-process jobs get their
# own NODE_V8_COVERAGE directory entry per node process. No two jobs write the
# same path. What the instrumentation does cost is SPEED — an Istanbul-built
# bundle is several times slower to execute — so the pool's own default is if
# anything more conservative than this run wants, and a machine with the cores
# to spare will see more from raising TEST_CONCURRENCY here than on the plain
# suite.
#
# TEST_CONCURRENCY=1 IS THE FIRST THING TO TRY when a job fails in the pool and
# passes on its own: it restores the old one-at-a-time run exactly, streamed
# output included. What must not overlap is declared in JOB_LOCKS at the top of
# tests/run-report.js — the mock STS keeps its /admin configuration in memory
# and it survives between jobs, so a test that reconfigures a shared service
# and does not hold a lock fails in somebody ELSE's assertion.
#
# NEITHER IS ASSIGNED OR EXPORTED HERE, and unlike STS_LOG_LEVEL above that is
# not an oversight to be corrected. `VAR=x ./this-script` already puts the name
# in this shell, docker_compose()'s forwarding loop reads it with an `eval` on
# the shell variable rather than out of the exported environment, and it skips
# a name whose value is empty. So an assignment with an empty default would add
# nothing and a default with a VALUE would silently override what the caller
# asked for — the pool's own sizing (which can see the container's cores, as
# this shell cannot) is the better fallback. Leave this a comment.
# ---------------------------------------------------------------------------
# The base file plus the coverage override, which touches only api and client.
COMPOSE="docker_compose -f docker-compose-run-tests.yml -f docker-compose-coverage.yml"
# The BASE file alone is enough for `ps` / `logs` / a single-service `up` below:
# compose scopes those to this directory's project, and the override changes
# nothing about the side-cars.
BASE_COMPOSE_FILE=docker-compose-run-tests.yml

# ---------------------------------------------------------------------------
# The side-cars need the same preparation ./docker-run-tests.sh gives them; this
# script runs the same stack and had none of it.
#
# walt.id: BOTH services mount a configuration directory this repository does not
# contain — waltid/generated-config and waltid/generated-verifier-config are
# rendered per run, because each holds a freshly generated signing key and no key
# material is committed. Without the render, compose creates those paths as EMPTY
# directories, the services start with no configuration and exit, and because the
# suite runs with --abort-on-container-exit that takes the whole coverage run down
# with them. The URLs are the ones the BROWSER uses — compose DNS names, since the
# browser runs inside the tests container — and every URL walt.id publishes is
# built from them.
# ---------------------------------------------------------------------------
WALTID_BASE_URL=http://waltid-issuer:7005
WALTID_VERIFIER_BASE_URL=http://waltid-verifier:7003
WALTID_VERIFIER_CLIENT_ID=verifier2
WALTID_KEYCLOAK_AUTHORIZE_URL=http://keycloak:8080/realms/debugger-testing/protocol/openid-connect/auth
WALTID_KEYCLOAK_TOKEN_URL=http://keycloak:8080/realms/debugger-testing/protocol/openid-connect/token
WALTID_KEYCLOAK_CLIENT_ID=waltid-issuer
WALTID_KEYCLOAK_CLIENT_SECRET=waltid-issuer-test-secret
export WALTID_BASE_URL WALTID_KEYCLOAK_AUTHORIZE_URL WALTID_KEYCLOAK_TOKEN_URL
export WALTID_KEYCLOAK_CLIENT_ID WALTID_KEYCLOAK_CLIENT_SECRET
export WALTID_VERIFIER_BASE_URL WALTID_VERIFIER_CLIENT_ID

generateWaltidIssuerKey
check_return_code $?
generateWaltidVerifierKey
check_return_code $?
renderWaltidConfig "${CURRENT_DIR}"
check_return_code $?
# The browser extension, for tests/webauthn_extension.js. This launcher needs
# EVERYTHING the plain one does before compose builds — tests/Dockerfile COPYs
# extension/dist/ci, so without this the IMAGE BUILD fails with
# '"/extension/dist/ci": not found' three minutes in, and the coverage report
# that gets uploaded is empty rather than absent. Same omission this file has
# had before with the walt.id render.
EXTENSION_AUTOARM_ORIGINS="https://sts:8081" \
  buildBrowserExtension "${CURRENT_DIR}"   # same stack as docker-run-tests.sh
check_return_code $?

# The mock STS is a submodule (https://github.com/rcbj/mock-sts.git): the same
# class of hazard as the walt.id render above, and for the same reason it is
# checked here rather than left to the build. This run uses --abort-on-container-
# exit, so a service that cannot be built or started takes the whole run down.
requireMockStsCheckout "${CURRENT_DIR}"
# The api needs node-ldapjs too — the same library on the client side of
# the LDAP exchange, pinned as api/node-ldapjs. A separate submodule from
# the mock's, because npm resolves a `file:` dependency's own requires from
# where the real directory lives, so a copy outside api/ never reaches
# api/node_modules. Uninitialised, the image builds fine and the service
# dies at startup with `Cannot find module 'ldapjs'`.
requireApiLdapjsCheckout "${CURRENT_DIR}"
check_return_code $?

mkdir -p coverage/frontend/.nyc_output coverage/api

# Tear the stack down on ANY exit, including the early ones the checks below can
# take. The normal path downs the stack itself after rendering the report and
# clears this flag, so it is not done twice.
STACK_UP=0
coverageTeardown()
{
  if [ "${STACK_UP}" = "1" ];
  then
    ${COMPOSE} down
  fi
}
trap coverageTeardown EXIT

# Start from a clean slate, as ./docker-run-tests.sh does: leftover containers and
# the Keycloak DB volume from a previous run make provisioning 409 on a stale
# realm, and several services carry the same hard-coded container_name in
# local-tests.yml while being configured incompatibly there (host networking, a
# WildFly port-offset), so a container left behind by ./local-run-tests.sh is the
# wrong container for this run. Best-effort and quiet in both cases.
${COMPOSE} down -v --remove-orphans 2>/dev/null || true
if [ -f "local-tests.yml" ];
then
  CONFIG_FILE=./env/local.js docker_compose -f local-tests.yml down --remove-orphans 2>/dev/null || true
fi

# Bring the WS-Federation side-car up on its own first and stop if it does not
# stay up. It is the slowest and most fragile service here — Keycloak 8.0.1 on
# WildFly, which rolls back its whole boot on a single subsystem failure — and
# `up` reports success for a container that was created and then exited. Left to
# the run below, a death there would tear the stack down mid-suite with
# --abort-on-container-exit and the exit status would be attributed to the tests
# container instead.
STACK_UP=1
${COMPOSE} up --build -d keycloak-wsfed
check_return_code $?
requireComposeServiceRunning "${BASE_COMPOSE_FILE}" keycloak-wsfed
check_return_code $?

# And the walt.id services, waited for THROUGH THEIR PROXIES. The JVMs behind them
# (waltid-issuer-api / waltid-verifier-api) are built with Jib and have no shell,
# so they can carry no CMD-SHELL healthcheck; each proxy carries one probe for the
# whole chain, and both proxies publish their port to the host (7005 / 7003), so
# this launcher can ask directly. A walt.id service that dies during startup — a
# configuration value of the wrong shape is enough — leaves only a 502 from its
# proxy, and waiting here prints that container's own log instead of stalling on a
# healthcheck the tests service depends on and then aborting opaquely.
#
# These URLs are host-facing and for this wait only: the tests container derives
# its own compose-DNS ones in tests/run-tests-in-container.sh.
${COMPOSE} up --build -d waltid-issuer waltid-verifier
check_return_code $?
WALTID_ISSUER_URL=http://localhost:7005 WALTID_VERIFIER_URL=http://localhost:7003 \
  waitForWaltid "${BASE_COMPOSE_FILE}"

# Run the suite. Services are torn down when the tests container exits; stopping
# the API container lets c8 flush its coverage to ./coverage/api. Capture the
# tests container's exit code (--exit-code-from tests) so a failing test makes
# this script exit non-zero — do NOT mask it with `|| true`. We still render the
# report and tear down before exiting.
${COMPOSE} up --build --abort-on-container-exit --exit-code-from tests
TEST_RC=$?

# Render the frontend coverage report inside a throwaway client container, which
# has the instrumented source at the paths Istanbul recorded. A report-render
# failure should not override the test result, so this one stays best-effort.
${COMPOSE} run --rm --no-deps client \
  npx nyc report \
    --temp-dir /coverage/frontend/.nyc_output \
    --report-dir /coverage/frontend/report \
    --reporter=html --reporter=lcov --reporter=text-summary || true

${COMPOSE} down
STACK_UP=0

echo ""
echo "Frontend (browser) coverage: ./coverage/frontend/report/index.html"
echo "API (Node) coverage:         ./coverage/api/index.html"
# The third domain. Nothing renders it here: tests/run-report.js does it at the
# end of the suite, inside the tests container, because the raw V8 data names
# the paths the modules were loaded from and only that filesystem has them.
echo "Node (in-process) coverage:  ./coverage/node/index.html"

# Propagate the suite result as this script's exit code.
if [ "${TEST_RC}" -ne 0 ]; then
  echo "Test suite FAILED (exit ${TEST_RC})."
else
  echo "Test suite passed."
fi
exit ${TEST_RC}
