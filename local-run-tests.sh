#!/bin/bash
set -x
#
# This script runs tests locally.
#
# Options:
#   --saml-dev   Build + start Keycloak and the debugger (api + client) and
#                provision Keycloak with SAML AuthnRequest signature validation
#                DISABLED, then leave the stack running WITHOUT running the tests
#                (for manual SAML testing with a browser-generated SP key).
#   -h|--help    Show usage.
#
SKIP_TESTS=0
SAML_SIG_VALIDATION=true

usage()
{
  cat <<USAGE
Usage: $(basename "$0") [--saml-dev] [-h|--help]

  (default)    Build + start the stack, provision Keycloak (SAML AuthnRequest
               signature validation ENABLED), and run the full test suite.

  --saml-dev   Build + start Keycloak and the debugger (api + client), provision
               Keycloak with SAML AuthnRequest signature validation DISABLED, and
               leave the stack running WITHOUT running the tests.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --saml-dev) SKIP_TESTS=1; SAML_SIG_VALIDATION=false ;;
    -h|--help)  usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
  shift
done
export SAML_SIG_VALIDATION

init()
{
  DEBUGGER_BASE_URL=http://localhost:3000
  KEYCLOAK_BASE_URL=http://localhost:8080
  KEYCLOAK_LOCALHOST_BASE_URL=http://localhost:8080
  # SAML: must match the client bundle's baked env (client/src/env/local.js).
  API_BASE_URL=http://localhost:4000
  SAML_SP_ENTITY_ID=http://localhost:3000/saml/sp
  # WS-Trust STS (mock) on the host (local-tests.yml, host networking). Must match
  # the client bundle's baked wstrustStsUrlDefault (local.js).
  WSTRUST_STS_URL=http://localhost:8081/sts
  export WSTRUST_STS_URL
  CONFIG_FILE=./env/local.js
  CURRENT_DIR=`echo "$(dirname "$(realpath "$0")")"`
  # SP signing cert (base64 DER) registered on the Keycloak SAML client so it can
  # validate the AuthnRequest signature (test signs with tests/fixtures/sp-key.pem).
  SAML_SP_SIGNING_CERT=$(grep -v -- '-----' "${CURRENT_DIR}/tests/fixtures/sp-cert.pem" | tr -d '\n\r')
  export SAML_SP_SIGNING_CERT
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
}

prepTestEnv()
{
  npm install --prefix tests
}

startDocker()
{
  # Start Docker containers
  CONFIG_FILE=./env/local.js docker_compose -f local-tests.yml build
  check_return_code $?
  CONFIG_FILE=./env/local.js docker_compose -f local-tests.yml up -d
  check_return_code $?
}

# Run the suite via the report generator instead of runTests(). It executes
# the same tests once, continues past failures, and writes an HTML + JUnit
# report to tests/report/. It exits non-zero if any test failed, so the
# check_return_code below still gates the "All tests passed" banner.
runReport()
{
  export DEBUGGER_BASE_URL
  # Export so run-report.js (and the test scripts it spawns) can
  # require(process.env.CONFIG_FILE) for centralized config (e.g. waitTime).
  export CONFIG_FILE
  node "${NODEJS_BASE_DIR}/run-report.js"
}

init
check_return_code $?
prepTestEnv
check_return_code $?
startDocker
check_return_code $?
sleep 60
check_return_code $?
configureKeycloak
check_return_code $?

if [ "${SKIP_TESTS}" = "1" ]; then
  cat <<EOF
============================================================================
Dev stack is UP — tests were NOT run.
  Debugger : ${DEBUGGER_BASE_URL}
  API      : ${API_BASE_URL}
  Keycloak : ${KEYCLOAK_BASE_URL}
SAML AuthnRequest signature validation is DISABLED on the Keycloak SAML client,
so a browser-generated (unregistered) SP key can drive the SAML flow.
Stop the stack with:
  CONFIG_FILE=./env/local.js docker compose -f local-tests.yml down
============================================================================
EOF
  exit 0
fi

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
