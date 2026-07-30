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

# Propagate the suite result as this script's exit code.
if [ "${TEST_RC}" -ne 0 ]; then
  echo "Test suite FAILED (exit ${TEST_RC})."
else
  echo "Test suite passed."
fi
exit ${TEST_RC}
