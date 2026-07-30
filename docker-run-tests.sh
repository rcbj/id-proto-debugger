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

# The walt.id issuer's configuration is rendered before compose brings the stack
# up: the container mounts the result, and the signing key it contains is
# generated per run and gitignored. See common/common.sh.
generateWaltidIssuerKey
check_return_code $?
generateWaltidVerifierKey
check_return_code $?
renderWaltidConfig "${CURRENT_DIR}"
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
