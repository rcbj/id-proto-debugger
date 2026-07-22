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

# Always tear the stack down, even if the tests fail, so the next run starts clean.
teardown()
{
  docker_compose -f "${COMPOSE_FILE}" down
}
trap teardown EXIT

# Build fresh images (so code changes are picked up), bring the stack up, and let
# the tests container drive the run. --abort-on-container-exit stops the stack as
# soon as the tests finish; --exit-code-from tests makes compose (and therefore
# this script) exit with the tests container's status.
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
