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
#   --wsfed-only Bring up ONLY what the WS-Federation test needs (api, client and
#                the Keycloak 8.0.1 + wsfed side-car), provision it, and run that
#                one test. A ~2-minute loop instead of the whole suite, and it
#                prints why the side-car is unusable when it is.
#   -h|--help    Show usage.
#
SKIP_TESTS=0
WSFED_ONLY=0
SAML_SIG_VALIDATION=true

usage()
{
  cat <<USAGE
Usage: $(basename "$0") [--saml-dev] [--wsfed-only] [-h|--help]

  (default)    Build + start the stack, provision Keycloak (SAML AuthnRequest
               signature validation ENABLED), and run the full test suite.

  --saml-dev   Build + start Keycloak and the debugger (api + client), provision
               Keycloak with SAML AuthnRequest signature validation DISABLED, and
               leave the stack running WITHOUT running the tests.

  --wsfed-only Build + start only api, client and the WS-Federation Keycloak
               side-car, provision the wsfed realm/client/user, and run just
               tests/wsfed_sso.js. Use this to work on the WS-Federation test
               without waiting for the full suite.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --saml-dev) SKIP_TESTS=1; SAML_SIG_VALIDATION=false ;;
    --wsfed-only) WSFED_ONLY=1 ;;
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
  # walt.id's issuer-api2 (local-tests.yml, host networking) — the real
  # OpenID4VCI issuer the interoperability job runs against.
  WALTID_ISSUER_URL=http://localhost:7005
  export WALTID_ISSUER_URL
  # walt.id's verifier, behind its own CORS proxy on 7003. Locating it here is what
  # switches the presentation interoperability job on; unset it and that job is
  # skipped rather than failed, the same way the issuer's is.
  WALTID_VERIFIER_URL=http://localhost:7003
  export WALTID_VERIFIER_URL
  # WS-Federation IdP side-car (Keycloak 8.0.1 + wsfed, local-tests.yml, host net,
  # WildFly port-offset 2 -> 8082). Browser-facing and admin-facing URLs are the
  # same on host networking. configureKeycloakWsfed provisions it and exports the
  # WSFED_* vars the WS-Fed test consumes.
  KEYCLOAK_WSFED_BASE_URL=http://localhost:8082
  KEYCLOAK_WSFED_LOCALHOST_BASE_URL=http://localhost:8082
  export KEYCLOAK_WSFED_BASE_URL KEYCLOAK_WSFED_LOCALHOST_BASE_URL
  CONFIG_FILE=./env/local.js
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
  check_return_code $?
  # The mock STS is a submodule, so its source is fetched rather than committed
  # here. Checked before anything builds: without the checkout, compose reports a
  # missing Dockerfile and nothing mentions a submodule.
  requireMockStsCheckout "${CURRENT_DIR}"
  check_return_code $?
  # A fresh SP key pair for this run: exported for the tests (which sign and
  # decrypt with it) and for configureKeycloak (which registers the certificate
  # on the SAML client). Nothing is written to the repository.
  generateSpKeyPair
  check_return_code $?
  # walt.id's issuer, and the identity provider it authenticates End-Users at.
  # These are the addresses the BROWSER uses: every URL walt.id publishes in its
  # metadata is built from WALTID_BASE_URL, and the authorize redirect goes to
  # the browser too. renderWaltidConfig writes them into the container's
  # configuration, and configureKeycloak registers the callback under the same
  # base.
  WALTID_BASE_URL=http://localhost:7005
  # The verifier's public address, which its urlPrefix names: under host
  # networking that is plain localhost.
  WALTID_VERIFIER_BASE_URL=http://localhost:7003
  WALTID_VERIFIER_CLIENT_ID=verifier2
  WALTID_KEYCLOAK_AUTHORIZE_URL=http://localhost:8080/realms/debugger-testing/protocol/openid-connect/auth
  WALTID_KEYCLOAK_TOKEN_URL=http://localhost:8080/realms/debugger-testing/protocol/openid-connect/token
  WALTID_KEYCLOAK_CLIENT_ID=waltid-issuer
  WALTID_KEYCLOAK_CLIENT_SECRET=waltid-issuer-test-secret
  export WALTID_BASE_URL WALTID_KEYCLOAK_AUTHORIZE_URL WALTID_KEYCLOAK_TOKEN_URL
  export WALTID_KEYCLOAK_CLIENT_ID WALTID_KEYCLOAK_CLIENT_SECRET
  export WALTID_VERIFIER_BASE_URL WALTID_VERIFIER_CLIENT_ID
  # The walt.id issuer's configuration is rendered before compose starts: the
  # container mounts the result, so the key exists on disk for this run only.
  generateWaltidIssuerKey
  check_return_code $?
  generateWaltidVerifierKey
  check_return_code $?
  renderWaltidConfig "${CURRENT_DIR}"
  check_return_code $?
  buildBrowserExtension "${CURRENT_DIR}"
  check_return_code $?
  NODEJS_BASE_DIR=tests
}

prepTestEnv()
{
  npm install --prefix tests
  # And the mock STS's own dependencies, because four tests run on the HOST and
  # load sts/bbs2023.js from the submodule in place: bbs2023_cryptosuite.js,
  # ldp_vc_issuance.js, ldp_vc_refresh.js and vc_did.js, each of which compares
  # the issuer's cryptosuite with the wallet's. That module reaches
  # @digitalbazaar/bbs-signatures through a dynamic `import()`, and ESM resolution
  # walks the directory tree from the importing FILE — it does not consult
  # NODE_PATH, so tests/module_paths.js cannot cover it the way it covers the
  # module's CommonJS requires. Without sts/node_modules those four fail at load
  # with ERR_MODULE_NOT_FOUND. The containerized suite is unaffected: there
  # bbs2023.js is copied flat beside the tests, next to tests/node_modules.
  #
  # `npm ci`, not `npm install`: mock-sts commits its lock, and `npm install`
  # REWRITES it (its lock still carries the pre-rename package name), which would
  # leave the submodule with a modified file after every run.
  if [ -f sts/package.json ];
  then
    npm ci --prefix sts
  fi
}

startDocker()
{
  # Clear the CONTAINERIZED stack's containers first. The two compose files give
  # several services the same hard-coded `container_name` — keycloak-wsfed, sts,
  # keycloak — while configuring them incompatibly (this file uses host networking
  # and a WildFly port-offset; docker-compose-run-tests.yml uses a bridge network
  # and published ports). A container left behind by ./docker-run-tests.sh is
  # therefore the wrong container for this run, and compose cannot create the right
  # one while that name is taken: `up` fails, or the side-car simply never appears
  # and the WS-Federation check below stops the run. docker-run-tests.sh does the
  # same in reverse. Best-effort and quiet — the file may be absent, and nothing
  # here should fail a run.
  if [ -f "docker-compose-run-tests.yml" ];
  then
    CONFIG_FILE=./env/docker-tests.js docker_compose -f docker-compose-run-tests.yml down --remove-orphans 2>/dev/null || true
  fi

  # Start Docker containers
  CONFIG_FILE=./env/local.js docker_compose -f local-tests.yml build
  check_return_code $?
  CONFIG_FILE=./env/local.js docker_compose -f local-tests.yml up -d
  check_return_code $?
  # The WS-Federation side-car must actually be running, not merely created: the
  # `up -d` above exits 0 for a container that started and then aborted its boot,
  # which is exactly how this side-car has failed. check_return_code stops the run
  # here, with the container's own log printed, rather than letting every WS-Fed
  # step downstream fail or skip for reasons that do not name the cause.
  CONFIG_FILE=./env/local.js requireComposeServiceRunning local-tests.yml keycloak-wsfed
  check_return_code $?
}

# Run the suite via the report generator instead of runTests(). It executes
# the same tests once, continues past failures, and writes an HTML + JUnit
# report to tests/report/. It exits non-zero if any test failed, so the
# check_return_code below still gates the "All tests passed" banner.
runReport()
{
  export DEBUGGER_BASE_URL
  # The SD-JWT VC issuance job retrieves the realm's RFC 8414 metadata to
  # configure its OIDC leg, so it needs to know where Keycloak is.
  export KEYCLOAK_BASE_URL
  # Export so run-report.js (and the test scripts it spawns) can
  # require(process.env.CONFIG_FILE) for centralized config (e.g. waitTime).
  export CONFIG_FILE
  node "${NODEJS_BASE_DIR}/run-report.js"
}

# ---------------------------------------------------------------------------
# --wsfed-only: the WS-Federation test on its own.
#
# The full run takes about ten minutes, which is a poor loop for one test — and
# this test is the one most often skipped, because it depends on a side-car that
# `docker compose up -d` will happily report as started whether or not it stayed
# up. So bring up only what it needs, say plainly whether the side-car is usable,
# and run it.
# ---------------------------------------------------------------------------
runWsfedOnly()
{
  echo "Entering runWsfedOnly()."
  # compose starts each service's dependencies too, so this pulls in postgres and
  # the main Keycloak only if api/client actually declare them.
  CONFIG_FILE=./env/local.js docker_compose -f local-tests.yml build api client keycloak-wsfed
  check_return_code $?
  CONFIG_FILE=./env/local.js docker_compose -f local-tests.yml up -d api client keycloak-wsfed
  check_return_code $?
  echo "Waiting for the WS-Federation side-car (Keycloak 8.0.1 on WildFly boots slowly) ..."
  sleep 20
  CONFIG_FILE=./env/local.js verifyComposeServicesRunning local-tests.yml
  # Fatal here for the same reason as in startDocker(): there is no point
  # provisioning, or running the test, against a container that is not there.
  CONFIG_FILE=./env/local.js requireComposeServiceRunning local-tests.yml keycloak-wsfed
  check_return_code $?
  configureKeycloakWsfed local-tests.yml
  check_return_code $?
  if [ -z "${WSFED_METADATA_URL:-}" ];
  then
    echo "The WS-Federation side-car could not be provisioned — see the reason above. Not running the test." >&2
    exit 1
  fi
  echo "WSFED_METADATA_URL=${WSFED_METADATA_URL}"
  echo "WSFED_REALM=${WSFED_REALM}  WSFED_USER=${WSFED_USER}"
  # Invoked exactly as tests/run-report.js does it: from the repository root, with
  # CONFIG_FILE relative to the test file (require() resolves against the module's
  # own directory, not the working directory).
  export DEBUGGER_BASE_URL CONFIG_FILE KEYCLOAK_BASE_URL
  node "${NODEJS_BASE_DIR}/wsfed_sso.js" --url "${DEBUGGER_BASE_URL}"
  local rc=$?
  echo "Leaving runWsfedOnly(). rc=${rc}"
  return ${rc}
}

init
check_return_code $?
prepTestEnv
check_return_code $?
if [ "${WSFED_ONLY}" = "1" ];
then
  runWsfedOnly
  check_return_code $?
  echo "WS-Federation test passed."
  exit 0
fi
startDocker
check_return_code $?
sleep 60
check_return_code $?
# `up -d` succeeds for a container that started and then exited, so ask separately
# what is actually running now that everything has had a minute to settle, and
# print the status and log of anything that is not. A side-car that is down this
# way is otherwise invisible until its test reports SKIPPED.
CONFIG_FILE=./env/local.js verifyComposeServicesRunning local-tests.yml
# The walt.id services are JVM services and start slower than the sleep above
# allows for; wait for them rather than letting their jobs fail on a connection
# error that says nothing about the cause. The compose file is passed so that a
# service which never comes up has its own log printed here.
waitForWaltid local-tests.yml
configureKeycloak
check_return_code $?
# Provision the WS-Federation side-car (no-op / skip if it isn't up). The compose
# file is passed so that a side-car which is not running has its own log printed
# here — `docker compose up -d` succeeds whether or not the container stayed up.
configureKeycloakWsfed local-tests.yml
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
