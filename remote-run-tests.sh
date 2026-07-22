#!/bin/bash
set -x
#
# Runs the Selenium test suite against a debugger UI at an ARBITRARY base URL —
# the local dev server, https://test.idptools.com, or https://idptools.com —
# using a local Keycloak container this script starts on :8080.
#
# Unlike local-run-tests.sh, this does NOT start the local debugger/api stack:
# the target site is already deployed (or served by your own local dev server).
# It DOES start a local Keycloak container on :8080 (keycloak-tests.yml).
# Local-only for now (the browser must reach the http://localhost Keycloak, so
# it can't run from CI).
#
# Prerequisites (NOT started by this script):
#   - Docker (used to start the Keycloak container)
#   - The debugger site reachable at $DEBUGGER_BASE_URL
#   - Local Chrome + chromedriver on PATH (Selenium drives a local browser)
#
# Keycloak is left running after the tests for fast re-runs. Stop it with:
#   sudo docker compose -p idptools-kctest -f keycloak-tests.yml down
#
# Usage:
#   ./remote-run-tests.sh [debugger_base_url]
#
#   ./remote-run-tests.sh https://test.idptools.com
#   ./remote-run-tests.sh https://idptools.com
#   ./remote-run-tests.sh http://localhost:3000        # local dev server
#   DEBUGGER_BASE_URL=https://test.idptools.com ./remote-run-tests.sh
#
# Override Keycloak location with KEYCLOAK_BASE_URL (default http://localhost:8080).

init()
{
  # The one thing that varies per target: where the debugger UI lives. Accept it
  # as $1, or the DEBUGGER_BASE_URL env var, defaulting to the local dev server.
  DEBUGGER_BASE_URL="${1:-${DEBUGGER_BASE_URL:-http://localhost:3000}}"

  # Keycloak used for these tests — a local instance on :8080 by default.
  # KEYCLOAK_BASE_URL is what the browser (debugger UI) uses to reach Keycloak
  # (baked into the discovery endpoint the tests type into the UI);
  # KEYCLOAK_LOCALHOST_BASE_URL is what this shell uses for the admin API.
  KEYCLOAK_BASE_URL="${KEYCLOAK_BASE_URL:-http://localhost:8080}"
  KEYCLOAK_LOCALHOST_BASE_URL="${KEYCLOAK_LOCALHOST_BASE_URL:-${KEYCLOAK_BASE_URL}}"

  # Test-side config (waitTime, log level). If not set explicitly, pick the
  # config matching the target: the deployed sites use a 10s waitTime to
  # tolerate real-network latency; local uses the 2s default.
  if [ -z "${CONFIG_FILE:-}" ];
  then
    case "${DEBUGGER_BASE_URL}" in
      *test.idptools.com*) CONFIG_FILE="./env/test-idptools-com.js" ;;
      *idptools.com*)      CONFIG_FILE="./env/prod.js" ;;
      *)                   CONFIG_FILE="./env/local.js" ;;
    esac
  fi

  # Dedicated Keycloak container (isolated compose project so it never clashes
  # with local-run-tests.sh's stack).
  KEYCLOAK_COMPOSE_FILE="${KEYCLOAK_COMPOSE_FILE:-keycloak-tests.yml}"
  KEYCLOAK_COMPOSE_PROJECT="${KEYCLOAK_COMPOSE_PROJECT:-idptools-kctest}"

  CURRENT_DIR=`echo "$(dirname "$(realpath "$0")")"`

  # SAML client registration in Keycloak (configureKeycloak) must match the SAML
  # env baked into the deployed client bundle (client/src/env/*.js): the SP
  # entityID equals the AuthnRequest Issuer, and the ACS/SLO URLs are where the
  # IdP returns its response.
  #
  # A local dev server has the api backend (:4000), so the ACS/SLO are its real
  # /samlacs & /samlslo endpoints (common.sh derives them). The deployed sites are
  # BACKENDLESS static hosting — there is no server to receive the IdP's POST — so
  # the ACS/SLO are the static saml_response.html page and the client asks the IdP
  # for the Redirect binding, letting the browser read the response from the URL.
  # SAML_BACKEND_AVAILABLE tells run-report.js to skip the Artifact test (which
  # needs the server-side SOAP ArtifactResolve back-channel and cannot go static).
  case "${DEBUGGER_BASE_URL}" in
    *localhost*|*127.0.0.1*)
      API_BASE_URL="${API_BASE_URL:-http://localhost:4000}"
      SAML_SP_ENTITY_ID="${SAML_SP_ENTITY_ID:-http://localhost:3000/saml/sp}"
      SAML_BACKEND_AVAILABLE="${SAML_BACKEND_AVAILABLE:-true}"
      ;;
    *)
      API_BASE_URL="${API_BASE_URL:-${DEBUGGER_BASE_URL}}"
      SAML_SP_ENTITY_ID="${SAML_SP_ENTITY_ID:-${DEBUGGER_BASE_URL}/saml/sp}"
      SAML_ACS_URL="${SAML_ACS_URL:-${DEBUGGER_BASE_URL}/saml_response.html}"
      SAML_SLO_URL="${SAML_SLO_URL:-${DEBUGGER_BASE_URL}/saml_response.html}"
      SAML_BACKEND_AVAILABLE="${SAML_BACKEND_AVAILABLE:-false}"
      ;;
  esac

  # SP signing cert (base64 DER) registered on the Keycloak SAML client so it can
  # validate the AuthnRequest signature (tests/saml_sso.js signs with the matching
  # private key tests/fixtures/sp-key.pem).
  SAML_SP_SIGNING_CERT=$(grep -v -- '-----' "${CURRENT_DIR}/tests/fixtures/sp-cert.pem" | tr -d '\n\r')

  export DEBUGGER_BASE_URL KEYCLOAK_BASE_URL KEYCLOAK_LOCALHOST_BASE_URL CONFIG_FILE
  export API_BASE_URL SAML_SP_ENTITY_ID SAML_SP_SIGNING_CERT SAML_BACKEND_AVAILABLE
  # Only exported when set (backendless targets); otherwise common.sh derives them.
  [ -n "${SAML_ACS_URL:-}" ] && export SAML_ACS_URL
  [ -n "${SAML_SLO_URL:-}" ] && export SAML_SLO_URL

  # The target is a deployed HTTPS site with no API proxy: the browser can't fetch
  # the local http Keycloak descriptor cross-origin (CORS). Have common.sh's
  # configureKeycloak download the descriptor to a file so the SAML tests UPLOAD it
  # (shared with docker-compose-live-tests.yml — one implementation, no drift).
  export SAML_METADATA_UPLOAD=1
  export SAML_METADATA_FILE="${SAML_METADATA_FILE:-${CURRENT_DIR}/tests/saml-idp-metadata.xml}"

  COMMON_SH=${CURRENT_DIR}/common/common.sh
  if [ -r "${COMMON_SH}" ];
  then
    . ${COMMON_SH}
  else
    echo "Cannot find ${COMMON_SH}."
    exit 1
  fi
  common_setup
  check_return_code $?
  NODEJS_BASE_DIR=tests

  echo "==> Debugger under test: ${DEBUGGER_BASE_URL}"
  echo "==> Keycloak:            ${KEYCLOAK_BASE_URL}"
}

prepTestEnv()
{
  npm install --prefix tests
}

# Start the dedicated Keycloak container (idempotent — reuses it if already up).
startKeycloak()
{
  echo "Entering startKeycloak()."
  docker_compose -p "${KEYCLOAK_COMPOSE_PROJECT}" -f "${KEYCLOAK_COMPOSE_FILE}" up -d
  check_return_code $?
  waitForKeycloak
  echo "Leaving startKeycloak()."
}

# Poll until Keycloak's master realm answers (it takes ~20-40s to start).
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

# Delete the debugger-testing realm if it exists, so configureKeycloak re-creates
# every client with redirectUris / webOrigins matching the CURRENT
# DEBUGGER_BASE_URL. Without this, switching targets (local -> test -> prod)
# would leave stale redirect URIs from the previous run and the flows would fail.
resetKeycloakRealm()
{
  echo "Entering resetKeycloakRealm()."
  local token
  token=$(curl -s \
    -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=admin-cli" \
    -d "username=keycloak" \
    -d "password=keycloak" \
    -d "grant_type=password" | jq -r '.access_token')
  if [ -z "${token}" ] || [ "${token}" = "null" ];
  then
    echo "ERROR: could not authenticate to Keycloak at ${KEYCLOAK_LOCALHOST_BASE_URL}." >&2
    echo "       Is Keycloak running there with admin keycloak/keycloak?" >&2
    exit 1
  fi
  # 404 if the realm doesn't exist yet — harmless.
  curl -s -o /dev/null -X DELETE \
    "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing" \
    -H "Authorization: Bearer ${token}"
  echo "Leaving resetKeycloakRealm()."
}

# SAML IdP metadata is downloaded to a file inside configureKeycloak (gated by
# SAML_METADATA_UPLOAD, set in init) — see common.sh download_saml_metadata().

runReport()
{
  export DEBUGGER_BASE_URL
  # run-report.js (and the test scripts it spawns) require(process.env.CONFIG_FILE).
  export CONFIG_FILE
  node "${NODEJS_BASE_DIR}/run-report.js"
}

init "$@"
check_return_code $?
prepTestEnv
check_return_code $?
startKeycloak
check_return_code $?
resetKeycloakRealm
check_return_code $?
configureKeycloak
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
