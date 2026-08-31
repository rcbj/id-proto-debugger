#!/bin/bash
set -x
#
# HOST launcher for the fully-containerized test suite.
#
# Builds and brings up the whole stack on a private compose network
# (docker-compose-run-tests.yml): postgres + keycloak + api + client + tests.
# The tests container runs the Selenium suite (tests/run-tests-in-container.sh)
# and compose exits when it does; this script's exit code reflects whether the
# tests passed (--exit-code-from tests). The stack is always torn down at the end.
#
# This is the command CLAUDE.md documents. To run the suite from a local shell
# with only the dependencies in containers, use ./local-run-tests.sh instead;
# to run against an already-deployed site, use ./remote-run-tests.sh.
#
# Usage:
#   ./docker-run-tests.sh
#   CONFIG_FILE=./env/docker-tests.js ./docker-run-tests.sh
#   STS_LOG_LEVEL=info ./docker-run-tests.sh   # quieten the mock STS; see below
#   TEST_CONCURRENCY=6 ./docker-run-tests.sh   # jobs at once; see below
#   TEST_CONCURRENCY=1 ./docker-run-tests.sh   # sequential, live output
#

# CONFIG_FILE selects the api/client build-time config baked into their images.
# The whole stack runs on a private compose network, so the browser (running
# INSIDE the tests container) reaches the api/client by their compose DNS names.
# That requires ./env/docker-tests.js (apiUrl=http://api:4000, uiUrl=
# http://client:3000, spEntityId=http://client:3000/saml/sp) — NOT ./env/local.js,
# whose localhost URLs only work when the browser runs on the host (see
# ./local-run-tests.sh). It must also match the runtime CONFIG_FILE the compose
# file pins for the api/client services. Baking local.js here made the SAML
# metadata load hit http://localhost:4000 from inside the container → connection
# refused. The tests container sets its own correct in-container SAML defaults
# (SAML_SP_ENTITY_ID, API_BASE_URL, ...) in tests/run-tests-in-container.sh, so
# no SAML env exports are needed (or reachable) from this host launcher.
CONFIG_FILE="${CONFIG_FILE:-./env/docker-tests.js}"
export CONFIG_FILE

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
#   STS_LOG_LEVEL=info ./docker-run-tests.sh
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
#   TEST_CONCURRENCY=6 ./docker-run-tests.sh
#   TEST_CONCURRENCY=1 ./docker-run-tests.sh   # sequential, live output
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

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose-run-tests.yml}"

CURRENT_DIR=`echo "$(dirname "$(realpath "$0")")"`
# Reuse the shared docker_compose() (handles sudo + docker-compose vs
# `docker compose` and propagates the real exit code) and check_return_code().
COMMON_SH=${CURRENT_DIR}/common/common.sh
if [ -r "${COMMON_SH}" ];
then
  . ${COMMON_SH}
else
  echo "Cannot find ${COMMON_SH}."
  exit 1
fi

# walt.id's issuer, and the identity provider it authenticates End-Users at.
# These are the addresses the BROWSER uses: every URL walt.id publishes in its
# metadata is built from WALTID_BASE_URL, and the authorize redirect goes to
# the browser too. renderWaltidConfig writes them into the container's
# configuration, and configureKeycloak registers the callback under the same
# base.
WALTID_BASE_URL=http://waltid-issuer:7005
# walt.id's verifier, behind its own CORS proxy. Same rule as the issuer: this is
# the address the BROWSER uses, and every URL the verifier hands the wallet — the
# request_uri it fetches, the response_uri it POSTs to — is built from it.
WALTID_VERIFIER_BASE_URL=http://waltid-verifier:7003
WALTID_VERIFIER_CLIENT_ID=verifier2
WALTID_KEYCLOAK_AUTHORIZE_URL=http://keycloak:8080/realms/debugger-testing/protocol/openid-connect/auth
WALTID_KEYCLOAK_TOKEN_URL=http://keycloak:8080/realms/debugger-testing/protocol/openid-connect/token
WALTID_KEYCLOAK_CLIENT_ID=waltid-issuer
WALTID_KEYCLOAK_CLIENT_SECRET=waltid-issuer-test-secret
export WALTID_BASE_URL WALTID_KEYCLOAK_AUTHORIZE_URL WALTID_KEYCLOAK_TOKEN_URL
export WALTID_KEYCLOAK_CLIENT_ID WALTID_KEYCLOAK_CLIENT_SECRET
export WALTID_VERIFIER_BASE_URL WALTID_VERIFIER_CLIENT_ID

# The mock STS is a submodule, so its source is fetched rather than committed
# here. Checked before the build for the same reason the walt.id render below
# happens before it: without the checkout, compose reports a missing Dockerfile
# and the tests image a missing COPY, neither of which mentions a submodule.
requireMockStsCheckout "${CURRENT_DIR}"
# The api needs node-ldapjs too — the same library on the client side of
# the LDAP exchange, pinned as api/node-ldapjs. A separate submodule from
# the mock's, because npm resolves a `file:` dependency's own requires from
# where the real directory lives, so a copy outside api/ never reaches
# api/node_modules. Uninitialised, the image builds fine and the service
# dies at startup with `Cannot find module 'ldapjs'`.
requireApiLdapjsCheckout "${CURRENT_DIR}"
check_return_code $?

# The walt.id issuer's configuration is rendered before compose brings the stack
# up: the container mounts the result, and the signing key it contains is
# generated per run and gitignored. See common/common.sh.
generateWaltidIssuerKey
check_return_code $?
generateWaltidVerifierKey
check_return_code $?
renderWaltidConfig "${CURRENT_DIR}"
check_return_code $?
EXTENSION_AUTOARM_ORIGINS="https://sts:8081" \
  buildBrowserExtension "${CURRENT_DIR}"   # the browser runs inside the compose network
check_return_code $?

# Always tear the stack down, even if the tests fail, so the next run starts clean.
teardown()
{
  docker_compose -f "${COMPOSE_FILE}" down
}
trap teardown EXIT

# Start from a clean slate: remove leftover containers AND the Keycloak DB volume
# from a previous run before bringing the stack up. The test data is disposable
# and recreated by configureKeycloak each run; a persisted volume leaves a stale
# 'debugger-testing' realm, so re-provisioning 409s ("Failed to create SAML
# user"). -v also guarantees a fresh DB. This likewise sidesteps a docker-compose
# v1 recreate bug ("KeyError: 'ContainerConfig'") pre-existing containers trigger.
docker_compose -f "${COMPOSE_FILE}" down -v --remove-orphans 2>/dev/null || true

# And tear down the LOCAL stack's containers as well, because several services —
# keycloak-wsfed among them — carry the same hard-coded `container_name` in both
# compose files while the two files configure them completely differently: the
# local one runs keycloak-wsfed on host networking with a WildFly port-offset of 2
# (so it binds 8082/8445), the containerized one on a bridge network with no offset
# (8080/8443, published as 8082:8080). A container left over from a local run is
# therefore the wrong container for this run, and the giveaway is a log that shows
# WildFly binding 8082 when this stack expects 8080. Best-effort and quiet: the
# file may not exist in a trimmed checkout, and nothing here should fail a run.
if [ -f "local-tests.yml" ];
then
  docker_compose -f local-tests.yml down --remove-orphans 2>/dev/null || true
fi

# THE BIND MOUNTS, CREATED HERE AND MADE WRITABLE BY ANY UID.
#
# Every image this repository builds now runs as an unprivileged user (uid
# 10001 — see the block at the foot of each Dockerfile), and two of them write
# through a bind mount: the tests container fills ./tests/report with the run,
# and under coverage the api and client fill ./coverage. A bind mount carries
# the HOST directory's ownership, so a container UID that does not match it
# cannot write there — and the failure is not loud: run-report.js reports a
# report it could not save, and the client's coverage handler is best-effort
# and says nothing at all.
#
# Matching the UID was not an option worth taking: a developer here is 1000, a
# GitHub Actions runner is 1001, and an image cannot be right for both. Docker
# also creates a MISSING bind-mount source itself, as root, which is how this
# used to work at all. So the directories are made here, before compose is
# called, mode 0777 — they hold build output, they are gitignored, and they are
# rewritten every run. The `sudo chown` steps in .github/workflows/tests.yml
# still run and are simply no longer load-bearing.
#
# Best-effort (`|| true`): a directory left behind by a run from BEFORE this
# change is owned by root, and a developer who is not root cannot chmod it. That
# is a stale-directory problem with a one-line fix the run should not fail on —
# `sudo rm -rf tests/report coverage` — and saying so beats aborting the suite.
mkdir -p tests/report || true
chmod 0777 tests/report || true

# Start the WS-Federation side-car FIRST, on its own, and stop here if it does not
# stay up.
#
# It is separated from the run below for two reasons. It is the slowest and most
# fragile service in the stack — Keycloak 8.0.1 on WildFly, which aborts its whole
# boot on a single subsystem failure — and `up` reports success for a container
# that was created and then exited, so nothing downstream would say why. And the
# run below uses --abort-on-container-exit: were this side-car to die there, it
# would tear the entire stack down mid-suite and the exit status would be
# attributed to the tests container. Failing here instead names the cause and
# prints the container's own log.
docker_compose -f "${COMPOSE_FILE}" up --build -d keycloak-wsfed
check_return_code $?
requireComposeServiceRunning "${COMPOSE_FILE}" keycloak-wsfed
check_return_code $?

# Build fresh images (so code changes are picked up), bring the stack up, and let
# the tests container drive the run. --abort-on-container-exit stops the stack as
# soon as the tests finish; --exit-code-from tests makes compose (and therefore
# this script) exit with the tests container's status. The side-car started above
# is left alone: compose does not recreate a service whose configuration is
# unchanged.
docker_compose -f "${COMPOSE_FILE}" up --build --abort-on-container-exit --exit-code-from tests
check_return_code $?

cat <<'EOF'
   _   _ _   _            _                                  _
  / \ | | | | |_ ___  ___| |_ ___   _ __   __ _ ___ ___  ___| |
 / _ \| | | | __/ _ \/ __| __/ __| | '_ \ / _` / __/ __|/ _ \ |
/ ___ \ | | | ||  __/\__ \ |_\__ \ | |_) | (_| \__ \__ \  __/_|
/_/   \_\_|_|  \__\___||___/\__|___/ | .__/ \__,_|___/___/\___(_)
                                     |_|
EOF

exit 0
