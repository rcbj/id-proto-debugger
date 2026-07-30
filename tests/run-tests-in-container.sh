#!/bin/bash
set -x
#
# IN-CONTAINER entrypoint for the tests image (tests/Dockerfile CMD). It runs
# INSIDE the tests container on the compose network, where common.sh has been
# copied next to it and the debugger/keycloak/api services are reachable by their
# compose DNS names (client:3000, keycloak:8080, ...).
#
# Do NOT run this from the host — use ./docker-run-tests.sh (repo root), which
# builds and brings up the whole containerized stack (docker-compose-run-tests.yml)
# and lets compose invoke this script inside the tests container.
#

init()
{
  # Defaults target the fully-containerized stack (client + keycloak on the
  # compose network). They can be overridden via the environment to run the
  # SAME suite against a deployed site while talking to a locally-spun-up
  # Keycloak — see docker-compose-live-tests.yml (e.g. DEBUGGER_BASE_URL set to
  # https://test.idptools.com with KEYCLOAK_BASE_URL=http://localhost:8080).
  DEBUGGER_BASE_URL="${DEBUGGER_BASE_URL:-http://client:3000}"
  KEYCLOAK_BASE_URL="${KEYCLOAK_BASE_URL:-http://keycloak:8080}"
  KEYCLOAK_LOCALHOST_BASE_URL="${KEYCLOAK_LOCALHOST_BASE_URL:-http://keycloak:8080}"
  # SAML: must match the client bundle's baked env (service DNS names).
  API_BASE_URL="${API_BASE_URL:-http://api:4000}"
  SAML_SP_ENTITY_ID="${SAML_SP_ENTITY_ID:-http://client:3000/saml/sp}"
  # WS-Trust STS (mock) reachable by its compose DNS name on the test network.
  # Must match the client bundle's baked wstrustStsUrlDefault (docker-tests.js).
  #
  # ONLY default this for the containerized stack: the bridge DNS name is valid
  # only there. On a DEPLOYED (HTTPS, backend-less) target the browser calls the
  # STS directly, and Chrome blocks http://sts:8081/sts as mixed content — every
  # WS-Trust job then times out waiting for the response page. The live-site stack
  # therefore passes WSTRUST_STS_URL explicitly as http://localhost:8081/sts (its
  # own host-networked sts service, loopback = potentially trustworthy); see
  # docker-compose-live-tests.yml. If it arrives unset/empty, run-report.js SKIPS
  # the WS-Trust jobs (as it skips the SAML Artifact job on a backend-less target)
  # rather than failing — mirroring remote-run-tests.sh.
  case "${DEBUGGER_BASE_URL}" in
    http://client:*)
      WSTRUST_STS_URL="${WSTRUST_STS_URL:-http://sts:8081/sts}"
      ;;
  esac
  # Exporting an unset variable passes nothing to children, so run-report.js sees
  # WSTRUST_STS_URL as undefined on non-containerized targets and skips.
  export WSTRUST_STS_URL
  # walt.id's issuer-api2 — the real OpenID4VCI issuer the interoperability job
  # runs against. Same reasoning as the STS above: the compose DNS name is only
  # valid on the containerized stack, and the BROWSER has to reach it, because
  # every URL walt.id publishes is built from the base URL it was configured
  # with. Unset elsewhere, so run-report.js skips that job rather than failing.
  case "${DEBUGGER_BASE_URL}" in
    http://client:*)
      WALTID_ISSUER_URL="${WALTID_ISSUER_URL:-http://waltid-issuer:7005}"
      # walt.id's verifier-api2, behind its own CORS proxy, for the PRESENTATION
      # interoperability job. Same rule again: the browser reaches it by this
      # name, and every URL the verifier hands the wallet is built from it.
      WALTID_VERIFIER_URL="${WALTID_VERIFIER_URL:-http://waltid-verifier:7003}"
      ;;
  esac
  export WALTID_ISSUER_URL WALTID_VERIFIER_URL
  # WS-Federation IdP side-car (Keycloak 8.0.1 + wsfed). Only the fully-containerized
  # run-tests stack provides it — it sets these on the tests service to its compose
  # DNS name (keycloak-wsfed:8080). Default EMPTY so deployed-site runs (live-tests,
  # no side-car) skip WS-Fed immediately instead of polling a missing host.
  KEYCLOAK_WSFED_BASE_URL="${KEYCLOAK_WSFED_BASE_URL:-}"
  KEYCLOAK_WSFED_LOCALHOST_BASE_URL="${KEYCLOAK_WSFED_LOCALHOST_BASE_URL:-}"
  export KEYCLOAK_WSFED_BASE_URL KEYCLOAK_WSFED_LOCALHOST_BASE_URL
  CONFIG_FILE="${CONFIG_FILE:-./env/local.js}"
  CURRENT_DIR=`echo "$(dirname "$(realpath "$0")")"`
  COMMON_SH=${CURRENT_DIR}/common.sh
  if [ -r "${COMMON_SH}" ];
  then
    . ${COMMON_SH}
  else
    echo "Cannot find ${COMMON_SH}."
    exit 1
  fi
  common_setup
  check_return_code $?
  # A fresh SP key pair for this run, generated inside this container: the tests
  # sign and decrypt with the private key, and configureKeycloak registers the
  # certificate on the SAML client. Nothing is baked into the image.
  generateSpKeyPair
  check_return_code $?
  NODEJS_BASE_DIR=.
}

# Run the suite via the report generator instead of runTests(). It executes
# the same tests once, continues past failures, and writes a timestamped
# HTML + JUnit + per-test log set under ./report. It exits non-zero if any
# test failed, so the check_return_code below still gates the success banner.
runReport()
{
  export DEBUGGER_BASE_URL
  # The SD-JWT VC issuance job needs to know where Keycloak is: it retrieves the
  # realm's RFC 8414 metadata document to configure the OIDC leg, and the URL
  # must be the one the BROWSER can reach (keycloak:8080 on the compose network,
  # localhost:8080 against a live site).
  export KEYCLOAK_BASE_URL
  # Export so run-report.js (and the test scripts it spawns) can
  # require(process.env.CONFIG_FILE) for centralized config (e.g. waitTime).
  export CONFIG_FILE
  node "${NODEJS_BASE_DIR}/run-report.js"
}

# Poll until Keycloak answers before configuring it. In the fully-containerized
# stack Keycloak is already up (compose depends_on: service_healthy), so this
# returns immediately; in the live-site stack (host networking, no healthcheck
# gate) this is what actually waits for Keycloak to come up.
waitForKeycloak()
{
  echo "Waiting for Keycloak at ${KEYCLOAK_LOCALHOST_BASE_URL} ..."
  local i=0
  local max=60
  local code
  while [ $i -lt $max ];
  do
    code=$(curl -s -o /dev/null -w '%{http_code}' \
      "${KEYCLOAK_LOCALHOST_BASE_URL}/realms/master/.well-known/openid-configuration" || true)
    if [ "${code}" = "200" ];
    then
      echo "Keycloak is ready."
      return 0
    fi
    i=$((i + 1))
    sleep 3
  done
  echo "ERROR: Keycloak did not become ready at ${KEYCLOAK_LOCALHOST_BASE_URL} within timeout." >&2
  exit 1
}

# Poll until the WS-Trust STS answers. Like waitForKeycloak, this matters for the
# live-site stack (host networking, no healthcheck gate); in the containerized
# stack compose already gated on the sts healthcheck. Any HTTP response counts as
# ready — WSTRUST_STS_URL may point at a real STS with no /healthcheck route.
# Non-fatal by design: if nothing answers, the WS-Trust jobs fail on their own with
# their page source / browser console diagnostics rather than aborting the suite.
waitForSts()
{
  if [ -z "${WSTRUST_STS_URL:-}" ];
  then
    echo "WSTRUST_STS_URL is not set — WS-Trust jobs will be skipped."
    return 0
  fi
  echo "Waiting for the WS-Trust STS at ${WSTRUST_STS_URL} ..."
  local i=0
  local max=30
  local code
  while [ $i -lt $max ];
  do
    code=$(curl -s -o /dev/null -w '%{http_code}' "${WSTRUST_STS_URL}" || true)
    if [ -n "${code}" ] && [ "${code}" != "000" ];
    then
      echo "STS is ready (HTTP ${code})."
      return 0
    fi
    i=$((i + 1))
    sleep 2
  done
  echo "WARNING: no response from the STS at ${WSTRUST_STS_URL} — the WS-Trust jobs will likely fail." >&2
  return 0
}

init
check_return_code $?
waitForKeycloak
check_return_code $?
waitForSts
# Delete any pre-existing debugger-testing realm so provisioning is idempotent.
# docker-run-tests.sh's startup `down -v` is meant to give us a fresh DB, but it
# is best-effort (swallowed under docker-compose v1); if a stale realm survives,
# configureKeycloak would 409 ("Failed to create SAML user"). See common.sh.
resetKeycloakRealm
check_return_code $?
configureKeycloak
check_return_code $?
# Provision the WS-Federation side-car (no-op unless KEYCLOAK_WSFED_LOCALHOST_BASE_URL
# is set by the run-tests compose; skips gracefully if it isn't reachable).
configureKeycloakWsfed
check_return_code $?
runReport
check_return_code $?
node --version
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
