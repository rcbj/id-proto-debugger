#!/bin/bash
set -x

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
  NODEJS_BASE_DIR=.
}

# Run the suite via the report generator instead of runTests(). It executes
# the same tests once, continues past failures, and writes a timestamped
# HTML + JUnit + per-test log set under ./report. It exits non-zero if any
# test failed, so the check_return_code below still gates the success banner.
runReport()
{
  export DEBUGGER_BASE_URL
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

init
check_return_code $?
waitForKeycloak
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
