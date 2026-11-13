#!/bin/bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

set -x
#
# HOST launcher for the fully-containerized test suite.
#
# Builds and brings up the whole stack on a private compose network
# (docker-compose-run-tests.yml): postgres + keycloak + api + client + tests.
# The tests container runs the Selenium suite (tests/run-tests-in-container.sh)
# and compose exits when it does; this script's exit code reflects whether the
# tests passed (--exit-code-from tests). On that default run the stack is
# always torn down at the end.
#
# This is the command CLAUDE.md documents. It also carries every option
# ./local-run-tests.sh had — the focused loops, --saml-dev, --sts-url and
# --krb5-real-dc — which that launcher is being retired in favour of; see
# usage() below. To run against an already-deployed site, use
# ./remote-run-tests.sh.
#
# Usage:
#   ./docker-run-tests.sh
#   CONFIG_FILE=./env/docker-tests.js ./docker-run-tests.sh
#   STS_LOG_LEVEL=info ./docker-run-tests.sh   # quieten the mock STS; see below
#   TEST_CONCURRENCY=6 ./docker-run-tests.sh   # jobs at once; see below
#   TEST_CONCURRENCY=1 ./docker-run-tests.sh   # sequential, live output
#   ./docker-run-tests.sh --help                # the options
#
# ---------------------------------------------------------------------------
# THE OPTIONS, parsed before anything else is done so that a typo costs no
# build.
#
# The focused modes do NOT carry a second copy of the jobs they run. Each one
# names a subset of the jobs tests/run-report.js already builds (TEST_SELECT,
# see selectJobs() there), so a focused run drives exactly what the full suite
# drives — the same environment per identity provider, the same locks, the
# same HTML/JUnit report under tests/report/. What differs is the stack: only
# the services that subset needs are started, and the stack is LEFT UP
# afterwards, because for several of these (the delegation maps, the
# federation realms) what the run leaves behind is the point.
# ---------------------------------------------------------------------------
MODE=suite
MODE_WHAT=""
KEEP_STACK=0
# auto: publish no host ports when one the stack wants is already held;
# 1: never publish (--no-host-ports).
NO_HOST_PORTS=auto
SAML_SIG_VALIDATION=true
KRB5_REAL_DC_WHAT=test
STS_EXTERNAL_URL="${STS_EXTERNAL_URL:-}"

usage()
{
  cat <<USAGE
Usage: $(basename "$0") [one mode] [--sts-url=<base>] [--keep-stack] [-h|--help]

  (no mode)    Build the whole containerized stack, provision it, run the full
               suite in the tests container, and tear it all down.

  --no-host-ports
               Publish none of the stack's ports to this host. Nothing in
               the suite needs them — the tests container reaches every
               service by its compose name — so this is what lets the stack
               run beside another that holds 8081, 4000 and the rest. It is
               turned on by itself when one of those ports is already held,
               and says which. A kept stack is then reachable only from
               inside the compose network.

  --keep-stack The full suite as above, but LEFT UP afterwards (the run is
               made with \`docker compose run\` rather than \`up
               --abort-on-container-exit\`). Every focused mode below keeps
               the stack anyway.

  --saml-dev   Bring up the whole stack, provision Keycloak with SAML
               AuthnRequest signature validation DISABLED, run no test, and
               leave it up — for manual SAML work with a browser-generated SP
               key. The pages are built for this stack's compose names, so
               the host needs them in /etc/hosts:
                 127.0.0.1 client api sts keycloak

  --saml-only[=keycloak|sts|both]
               The SAML 2.0 Web Browser SSO jobs (tests/saml_sso.js over all
               three bindings, tests/saml_logout.js) against the Keycloak
               realm, iya-sts, or both (default). The sts half adds the four
               SAML 1.1 jobs (saml11_sso.js per binding, saml11_options.js),
               which have no Keycloak half. =sts starts no Keycloak at all.

  --wsfed-only[=keycloak|sts|both]
               Every tests/wsfed_sso.js job against the Keycloak 8.0.1 + wsfed
               side-car, iya-sts, or both (default). =sts skips the WildFly
               boot entirely.

  --delegation-only[=oauth|wstrust|both]
               The three-tier delegation chains against iya-sts:
               oauth2_delegation_chain.js (oauth), wstrust_delegation_chain.js
               for OnBehalfOf and ActAs (wstrust), or all three (default). The
               delegation maps land as SVG under
               tests/report/<run>/delegation/.

  --federation-only[=single|chain|choice|both|matrix|matrix:<app>/<fed>/<mech>]
               The federated sign-ins across trust realms of iya-sts.
               single = federation_sso.js, chain = federation_chain_sso.js,
               choice = federation_choice_sso.js, both (default) = all three,
               matrix = the forty-nine federation_matrix_sso.js points,
               matrix:<app>/<fed>/<mech> = one of them, each of <app> and
               <fed> one of oidc, oauth2, saml2, saml11, wsfed and <mech> one
               of password, webauthn. The realms are left configured on the
               running stack, at https://localhost:8081/realm/<id>/admin/.

  --krb5-real-dc[=test|capture|both]
               Create a Windows Server 2025 domain controller on AWS, run
               tests/krb5_real_dc.js (test, the default), refresh
               tests/captures/windows-server-2025.json (capture), or both,
               then destroy everything it made (infra/krb5-test.sh). Needs AWS
               credentials and node on the host; no docker. THIS COSTS MONEY —
               it is not free tier. KRB5_KEEP=1 keeps the instance.

  --sts-url=<base>
               Use a DEPLOYED iya-sts at <base> (for example
               https://test-idp.iyasec.io) instead of starting one: the \`sts\` service is not started
               (docker-compose-run-tests-external-sts.yml), every STS address
               the jobs are handed is rebased onto <base>, and Kerberos, LDAP
               and SPIFFE dial its host. Set ADMIN_API_CLIENT_SECRET to that
               deployment's sts-api-client secret, and optionally
               SPIFFE_TRUST_DOMAIN (default: <base>'s host minus its first
               label). It allows https://client:3000 by CORS there and creates
               its rfc9700 realm. Combines with the default run and with every
               focused mode.

  The focused modes run their jobs one at a time (TEST_CONCURRENCY=1) unless
  TEST_CONCURRENCY says otherwise, and leave the stack up. Stop it with
  \`docker compose -f docker-compose-run-tests.yml down -v\`, or by running this
  script again, which always starts from a clean stack.
USAGE
}

setMode()
{
  if [ "${MODE}" != "suite" ];
  then
    echo "--${MODE} and $1 each run one thing; pick one." >&2
    exit 1
  fi
  MODE="$2"
  MODE_WHAT="$3"
}

while [ $# -gt 0 ];
do
  case "$1" in
    --saml-dev) setMode "$1" saml-dev "" ;;
    --saml-only) setMode "$1" saml-only both ;;
    --saml-only=*) setMode "$1" saml-only "${1#*=}" ;;
    --wsfed-only) setMode "$1" wsfed-only both ;;
    --wsfed-only=*) setMode "$1" wsfed-only "${1#*=}" ;;
    --delegation-only) setMode "$1" delegation-only both ;;
    --delegation-only=*) setMode "$1" delegation-only "${1#*=}" ;;
    --federation-only) setMode "$1" federation-only both ;;
    --federation-only=*) setMode "$1" federation-only "${1#*=}" ;;
    --krb5-real-dc) setMode "$1" krb5-real-dc test ;;
    --krb5-real-dc=*) setMode "$1" krb5-real-dc "${1#*=}" ;;
    --sts-url=*) STS_EXTERNAL_URL="${1#*=}" ;;
    --keep-stack) KEEP_STACK=1 ;;
    --no-host-ports) NO_HOST_PORTS=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
  shift
done
STS_EXTERNAL_URL="${STS_EXTERNAL_URL%/}"

# Each mode's value, checked here, and turned into the subset of jobs and of
# services it needs. TEST_SELECT is read by tests/run-report.js; the selectors
# name a script and, where one script serves two identity providers, the env
# value that tells its jobs apart. A matrix point that matches nothing fails
# there rather than here, with every point's spelling in the message.
TEST_SELECT=""
NEED_KEYCLOAK=0
NEED_WSFED=0
case "${MODE}" in
  saml-only)
    case "${MODE_WHAT}" in
      keycloak|sts|both) ;;
      *) echo "Unknown --saml-only identity provider: ${MODE_WHAT}" >&2
         usage; exit 1 ;;
    esac
    if [ "${MODE_WHAT}" != "sts" ];
    then
      NEED_KEYCLOAK=1
      TEST_SELECT="${TEST_SELECT} saml_sso.js?SAML_IDP=keycloak"
      TEST_SELECT="${TEST_SELECT} saml_logout.js?SAML_IDP=keycloak"
    fi
    if [ "${MODE_WHAT}" != "keycloak" ];
    then
      TEST_SELECT="${TEST_SELECT} saml_sso.js?SAML_IDP=sts"
      TEST_SELECT="${TEST_SELECT} saml_logout.js?SAML_IDP=sts"
      TEST_SELECT="${TEST_SELECT} saml11_sso.js saml11_options.js"
    fi
    ;;
  wsfed-only)
    case "${MODE_WHAT}" in
      keycloak|sts|both) ;;
      *) echo "Unknown --wsfed-only identity provider: ${MODE_WHAT}" >&2
         usage; exit 1 ;;
    esac
    if [ "${MODE_WHAT}" != "sts" ];
    then
      NEED_WSFED=1
      TEST_SELECT="${TEST_SELECT} wsfed_sso.js?WSFED_IDP=keycloak"
    fi
    if [ "${MODE_WHAT}" != "keycloak" ];
    then
      TEST_SELECT="${TEST_SELECT} wsfed_sso.js?WSFED_IDP=sts"
    fi
    ;;
  delegation-only)
    case "${MODE_WHAT}" in
      oauth) TEST_SELECT="oauth2_delegation_chain.js" ;;
      wstrust) TEST_SELECT="wstrust_delegation_chain.js" ;;
      both) TEST_SELECT="oauth2_delegation_chain.js"
            TEST_SELECT="${TEST_SELECT} wstrust_delegation_chain.js" ;;
      *) echo "Unknown --delegation-only family: ${MODE_WHAT}" >&2
         usage; exit 1 ;;
    esac
    ;;
  federation-only)
    case "${MODE_WHAT}" in
      single) TEST_SELECT="federation_sso.js" ;;
      chain) TEST_SELECT="federation_chain_sso.js" ;;
      choice) TEST_SELECT="federation_choice_sso.js" ;;
      both) TEST_SELECT="federation_sso.js federation_chain_sso.js"
            TEST_SELECT="${TEST_SELECT} federation_choice_sso.js" ;;
      matrix) TEST_SELECT="federation_matrix_sso.js" ;;
      matrix:*/*/*)
        _point="${MODE_WHAT#matrix:}"
        _app="${_point%%/*}"
        _mech="${_point##*/}"
        _fed="${_point#*/}"
        _fed="${_fed%/*}"
        TEST_SELECT="federation_matrix_sso.js?FEDERATION_APP_PROTOCOL=${_app}"
        TEST_SELECT="${TEST_SELECT}&FEDERATION_FED_PROTOCOL=${_fed}"
        TEST_SELECT="${TEST_SELECT}&FEDERATION_MECHANISM=${_mech}"
        ;;
      *) echo "Unknown --federation-only depth: ${MODE_WHAT}" >&2
         usage; exit 1 ;;
    esac
    ;;
  krb5-real-dc)
    case "${MODE_WHAT}" in
      test|capture|both) KRB5_REAL_DC_WHAT="${MODE_WHAT}" ;;
      *) echo "Unknown --krb5-real-dc value: ${MODE_WHAT}" >&2
         usage; exit 1 ;;
    esac
    if [ -n "${STS_EXTERNAL_URL}" ];
    then
      echo "--krb5-real-dc starts no stack, so --sts-url means nothing" \
           "there." >&2
      exit 1
    fi
    ;;
  saml-dev)
    SAML_SIG_VALIDATION=false
    NEED_KEYCLOAK=1
    NEED_WSFED=1
    ;;
esac
TEST_SELECT="${TEST_SELECT# }"
case "${MODE}" in
  saml-only|wsfed-only|delegation-only|federation-only|saml-dev)
    KEEP_STACK=1
    ;;
esac

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

# ---------------------------------------------------------------------------
# --krb5-real-dc: the Kerberos interoperability work, against AWS.
#
# The one mode that starts NO stack and needs no docker: tests/krb5_real_dc.js
# loads the api's relay and SSRF guard as modules and opens the socket itself,
# so there is no api, no client, no Keycloak and no iya-sts in this path —
# just node on this host and a domain controller in us-west-2. That is also
# why it runs here rather than in the tests container: the AWS credentials
# and the CLI are the host's.
#
# The apply / wait-for-the-forest / teardown logic is NOT duplicated here. It
# lives once, in infra/krb5-test.sh, because the teardown is the only thing
# standing between a failed run and a Windows instance billing until somebody
# notices. All this does is decide which scripts run against the live DC.
# ---------------------------------------------------------------------------
runKrb5RealDc()
{
  echo "Entering runKrb5RealDc(). what=${KRB5_REAL_DC_WHAT}"
  local scripts=""
  case "${KRB5_REAL_DC_WHAT}" in
    test)    scripts="krb5_real_dc.js" ;;
    capture) scripts="krb5_capture_real_dc.js" ;;
    # The test first: a capture taken from a broken run is worse than none,
    # because krb5_windows_vectors.js would then assert the breakage.
    both)    scripts="krb5_real_dc.js krb5_capture_real_dc.js" ;;
  esac
  if ! command -v aws >/dev/null 2>&1;
  then
    echo "ERROR: --krb5-real-dc needs the AWS CLI on PATH." >&2
    echo "Leaving runKrb5RealDc(). rc=1"
    return 1
  fi
  if ! aws sts get-caller-identity >/dev/null 2>&1;
  then
    echo "ERROR: --krb5-real-dc needs working AWS credentials; none" \
         "resolved. Sign in, then re-run. Nothing has been created." >&2
    echo "Leaving runKrb5RealDc(). rc=1"
    return 1
  fi
  if ! command -v node >/dev/null 2>&1;
  then
    echo "ERROR: --krb5-real-dc runs its test on this host and needs node." >&2
    echo "Leaving runKrb5RealDc(). rc=1"
    return 1
  fi
  echo "AWS account: $(aws sts get-caller-identity --query Account \
    --output text 2>/dev/null)"
  cat <<'WARNING'
============================================================================
This creates a Windows Server 2025 domain controller on AWS. It is NOT free
tier (a forest promotion needs more than the 1 GiB a t3.micro has), it costs
a few cents an hour, and everything it makes is destroyed at the end by an
EXIT trap that runs even if the test fails.

Set KRB5_KEEP=1 to keep the instance for debugging instead.
============================================================================
WARNING
  # The test's own dependencies, on this host. The containerized suite never
  # needs them here, so they may well be absent.
  if ! npm install --prefix "${CURRENT_DIR}/tests";
  then
    echo "ERROR: npm install --prefix tests failed." >&2
    echo "Leaving runKrb5RealDc(). rc=1"
    return 1
  fi
  # The TESTS' configuration, resolved against tests/ — not the api/client
  # build configuration CONFIG_FILE names on the rest of this script.
  KRB5_TEST_SCRIPTS="${scripts}" \
    CONFIG_FILE=./env/local.js \
    "${CURRENT_DIR}/infra/krb5-test.sh"
  local rc=$?
  echo "Leaving runKrb5RealDc(). rc=${rc}"
  return ${rc}
}

if [ "${MODE}" = "krb5-real-dc" ];
then
  trap 'launcherExitStatus $? docker-run-tests.sh' EXIT
  runKrb5RealDc
  check_return_code $?
  echo "Kerberos real-DC work passed (${KRB5_REAL_DC_WHAT})."
  SUITE_PASSED=1
  exit 0
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

# The api needs node-ldapjs — the same library iya-sts's directory is built
# on, here on the client side of
# the LDAP exchange, pinned as api/node-ldapjs (this repository's one
# submodule), because npm resolves a `file:` dependency's own requires from
# where the real directory lives, so a copy outside api/ never reaches
# api/node_modules. Uninitialised, the image builds fine and the service
# dies at startup with `Cannot find module 'ldapjs'`.
requireApiLdapjsCheckout "${CURRENT_DIR}"
check_return_code $?
# Every image the stack pulls or builds FROM comes from a PRIVATE mirror on
# ghcr.io (docker-compose-run-tests.yml, .github/image-mirror.txt). Without a
# login the build fails on a pull error that names neither; this says which.
requireGhcrMirror
check_return_code $?
# iya-sts runs from the mirror's copy of its published release image
# (docker-compose-run-tests.yml, IYA_STS_IMAGE), and tests/Dockerfile copies
# its tree out of the same image, so it is pulled here, before anything
# builds, where a failure can say which image and why.
requireIyaStsImage "${CURRENT_DIR}"
check_return_code $?

# The walt.id issuer's configuration is rendered before compose brings the stack
# up: the container mounts the result, and the signing key it contains is
# generated per run and gitignored. See common/common.sh.
# ---------------------------------------------------------------------------
# THE STACK'S TLS PAIR, BEFORE THE BUILD.
#
# The api and the client serve https, and this is the pair they serve. It has
# to exist before compose starts, and not for their sake: the MOCK STS pushes
# Security Event Tokens to the api (RFC 8935), so its container is handed the
# anchor in its environment, and a certificate a service invents at its own
# startup cannot be in an environment built a moment earlier. One pair for
# both services; see common/tls_listener.js. STACK_TLS_DIR is the bind-mount
# source every compose file here names.
# ---------------------------------------------------------------------------
generateStackTlsCertificate "${CURRENT_DIR}"
check_return_code $?

generateWaltidIssuerKey
check_return_code $?
generateWaltidVerifierKey
check_return_code $?
renderWaltidConfig "${CURRENT_DIR}"
check_return_code $?
EXTENSION_AUTOARM_ORIGINS="https://sts:8081" \
  buildBrowserExtension "${CURRENT_DIR}"   # the browser runs inside the compose network
check_return_code $?

# The compose files this run is made of: the stack, and with --sts-url the
# override that takes iya-sts out of it.
COMPOSE_ARGS=(-f "${COMPOSE_FILE}")
if [ -n "${STS_EXTERNAL_URL}" ];
then
  COMPOSE_ARGS+=(-f docker-compose-run-tests-external-sts.yml)
  export STS_EXTERNAL_URL
fi

# ---------------------------------------------------------------------------
# THE HOST PORTS, AND RUNNING BESIDE A STACK THAT HOLDS THEM.
#
# The stack publishes 3000, 4000, 8080, 8081, 8082, 7003, 7005 and 5432 for a
# person looking from the host; the suite itself uses none of them. When one
# is already held — an iya-sts development stack on 8081, a docs preview on
# 4000 — `up` refuses the whole stack with "port is already allocated", and
# the only alternative was to stop somebody else's containers. So publishing
# is dropped instead (docker-compose-run-tests-no-host-ports.yml), and nothing
# outside this stack is touched. The ports are read from the merged
# configuration rather than listed here, so a port added to the compose file
# is covered without an edit.
# ---------------------------------------------------------------------------
heldHostPorts()
{
  echo "Entering heldHostPorts()." >&2
  local wanted held="" port
  # The JSON is cut to its outermost braces in node: compose ends it with no
  # newline, so docker_compose()'s own "Leaving docker_compose()." line is
  # glued to the closing brace and a line filter cannot remove it.
  wanted="$(docker_compose "${COMPOSE_ARGS[@]}" config --format json \
              2>/dev/null | grep -v '^Entering\|^Leaving' |
            node -e 'let r="";process.stdin.on("data",d=>r+=d).on("end",
              ()=>{try{const c=JSON.parse(r.slice(r.indexOf("{"),
                r.lastIndexOf("}")+1));const out=[];
              for(const s of Object.values(c.services||{}))
                for(const p of (s.ports||[]))
                  if(p.published)out.push(p.published);
              console.log(out.join(" "))}catch(e){}})' 2>/dev/null)"
  for port in ${wanted};
  do
    if ss -Hltn "sport = :${port}" 2>/dev/null | grep -q .;
    then
      held="${held} ${port}"
    fi
  done
  echo "Leaving heldHostPorts().${held:- none}" >&2
  echo "${held# }"
}

if [ "${NO_HOST_PORTS}" = "auto" ];
then
  HELD_PORTS="$(heldHostPorts)"
  if [ -n "${HELD_PORTS}" ];
  then
    echo "Host port(s) ${HELD_PORTS} are already held by something outside" \
         "this stack, so it will publish no host ports at all and leave" \
         "those alone (--no-host-ports). The suite does not need them."
    NO_HOST_PORTS=1
  fi
fi
if [ "${NO_HOST_PORTS}" = "1" ];
then
  COMPOSE_ARGS+=(-f docker-compose-run-tests-no-host-ports.yml)
fi

# Always tear the stack down, even if the tests fail, so the next run starts clean.
teardown()
{
  docker_compose "${COMPOSE_ARGS[@]}" down
}

# What a kept stack holds and how to reach it, printed by the EXIT trap so it
# is the last thing on the screen before the status line.
printKeptStack()
{
  echo "Entering printKeptStack()."
  local sts="${STS_EXTERNAL_URL:-https://localhost:8081}"
  cat <<KEPT
============================================================================
The stack is still UP. From this host:
  iya-sts   : ${sts}  (its /admin console takes a session from /authn/login)
  Keycloak  : http://localhost:8080   (admin: keycloak / keycloak)
  api       : https://localhost:4000
  debugger  : https://client:3000 — the pages are built for the compose
              names, so a browser here needs
                127.0.0.1 client api sts keycloak
              in /etc/hosts, and the stack's root CA
              (generated-tls-ca/stack-tls-root.pem) trusted.
  report    : tests/report/latest/report.html
Stop it with:
  docker compose ${COMPOSE_ARGS[*]} down -v
============================================================================
KEPT
  if [ "${NO_HOST_PORTS}" = "1" ];
  then
    echo "NOTE: this run published no host ports (--no-host-ports), so the" \
         "addresses above do not answer from this host; reach the stack from" \
         "inside it, e.g. docker exec -it client sh."
  fi
  case "${MODE}:${MODE_WHAT}" in
    federation-only:single|federation-only:both)
      cat <<FEDERATION
The single-hop realms:
  ${sts}/realm/federation-realm-1/admin/federation
      the relationship, its counters and its last error
  ${sts}/realm/federation-realm-1/admin/users
      somebody who has never had a credential checked in that realm
  ${sts}/realm/federation-realm-2/admin/users
      the same person, in the realm where a name was actually typed
FEDERATION
      ;;
  esac
  case "${MODE}:${MODE_WHAT}" in
    federation-only:chain|federation-only:both)
      cat <<CHAIN
The three realms of the N-layer chain, where the middle one is the bridge:
  ${sts}/realm/federation-realm-4/admin/federation
      TWO relationships, one in each direction — WS-Federation in from
      realm 5, SAML 2.0 out to realm 3; the identity-provider-side one
      carries fedAuthnMechanism=federation
  ${sts}/realm/federation-realm-5/admin/users
      the only realm of the three that ever drew a password field
  ${sts}/realm/federation-realm-3/admin/users
      the same person, two hops and two protocols away
CHAIN
      ;;
  esac
  case "${MODE}:${MODE_WHAT}" in
    federation-only:choice|federation-only:both)
      cat <<CHOICE
The pair where one application has TWO identity providers:
  ${sts}/realm/federation-choice-1/admin/applications
      webapp-sso-1, whose appFederationRelationship names both partners
  ${sts}/realm/federation-choice-1/admin/federation
      the SAML 2.0 and the OpenID Connect relationship, one sign-in each
  ${sts}/realm/federation-choice-2/admin/users
      the two people, in the realm where both names were typed
To see the chooser itself, start an authorization request for webapp-sso-1 at
  ${sts}/realm/federation-choice-1/oauth2/authorize
in a browser with no session for that realm.
CHOICE
      ;;
  esac
  case "${MODE}:${MODE_WHAT}" in
    federation-only:matrix*)
      cat <<MATRIX
The grid's two realms hold one application, two relationships and one person
PER COMBINATION:
  ${sts}/realm/federation-matrix-1/admin/federation
  ${sts}/realm/federation-matrix-2/admin/federation
      the second carries the fedAuthnMechanism that decided each point
  ${sts}/realm/federation-matrix-1/admin/users
MATRIX
      ;;
  esac
  if [ "${MODE}" = "delegation-only" ];
  then
    echo "The delegation maps (SVG) are in" \
         "tests/report/latest/delegation/:"
    ls -l tests/report/latest/delegation/ 2>/dev/null || true
  fi
  if [ "${MODE}" = "saml-dev" ];
  then
    echo "SAML AuthnRequest signature validation is DISABLED on the" \
         "Keycloak SAML client, so a browser-generated (unregistered) SP key" \
         "can drive the SAML flow. No test was run."
  fi
  echo "Leaving printKeptStack()."
}
# The EXIT trap tears down FIRST and reports LAST: the banner (on a pass) and
# the status this script exits with, so neither is buried under the teardown's
# container shutdown output. `$?` is captured as the first statement, before
# the teardown overwrites it, and handed back to `exit` explicitly. See
# launcherExitStatus() in common/common.sh.
#
# A focused mode, --saml-dev and --keep-stack LEAVE IT UP instead, failing
# or passing, and say how to stop it. The next run of this script starts
# with a `down -v` either way.
onExit()
{
  local status=$?
  echo "Entering onExit()."
  if [ "${KEEP_STACK}" = "1" ];
  then
    printKeptStack
  else
    teardown
  fi
  launcherExitStatus "${status}" "docker-run-tests.sh"
  exit "${status}"
}
trap onExit EXIT

# Start from a clean slate: remove leftover containers AND the Keycloak DB volume
# from a previous run before bringing the stack up. The test data is disposable
# and recreated by configureKeycloak each run; a persisted volume leaves a stale
# 'debugger-testing' realm, so re-provisioning 409s ("Failed to create SAML
# user"). -v also guarantees a fresh DB. This likewise sidesteps a docker-compose
# v1 recreate bug ("KeyError: 'ContainerConfig'") pre-existing containers trigger.
docker_compose "${COMPOSE_ARGS[@]}" down -v --remove-orphans 2>/dev/null || true

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

# ---------------------------------------------------------------------------
# THE PARTIAL / KEPT STACK: every run that is not the plain default one.
#
# The default run below is one `up --abort-on-container-exit`, which starts
# every service the tests container depends on and stops them all when it
# exits. Neither half suits these runs: a focused mode needs only part of the
# stack, and every one of them keeps it afterwards. So this path starts the
# services in dependency order, each stage with `--wait` (which blocks on the
# healthchecks the compose file already declares, and fails on a container
# that exits or never becomes healthy) and `--no-deps` (so that, say, the api's
# declared dependency on Keycloak does not start a Keycloak nobody asked for),
# and then runs the tests container with `compose run`, whose exit status is
# the suite's.
# ---------------------------------------------------------------------------

# Is $1 in the space-separated list $2?
inList()
{
  case " $2 " in
    *" $1 "*) return 0 ;;
  esac
  return 1
}

# `up -d --wait` for a stage of services, and on a failure the log of every
# one of them that is not running — `--wait` names the service and not why.
composeUpAndWait()
{
  echo "Entering composeUpAndWait(). $*"
  if docker_compose "${COMPOSE_ARGS[@]}" up -d --wait "$@";
  then
    echo "Leaving composeUpAndWait(). rc=0"
    return 0
  fi
  echo "ERROR: a service in this stage did not come up healthy: $*" >&2
  local s
  for s in "$@";
  do
    case "${s}" in
      --*) continue ;;
    esac
    reportContainerLog "${COMPOSE_FILE}" "${s}"
  done
  echo "Leaving composeUpAndWait(). rc=1"
  return 1
}

runPartialStack()
{
  echo "Entering runPartialStack(). mode=${MODE} what=${MODE_WHAT}"
  # WHICH SERVICES. The whole stack for the default run with --keep-stack and
  # for --saml-dev; for a focused mode, iya-sts, the api and the client, plus
  # whichever of the two Keycloaks that mode drives. iya-sts is in every subset
  # even where the mode drives Keycloak alone, because the api fetches its
  # certificate at startup and the RFC 9700 realm the tests container creates
  # is on it; it starts in seconds.
  local services
  if [ "${MODE}" = "suite" ] || [ "${MODE}" = "saml-dev" ];
  then
    services="$(docker_compose "${COMPOSE_ARGS[@]}" config --services \
                  2>/dev/null | grep -xE '[a-z0-9_-]+' | grep -vx tests |
                tr '\n' ' ')"
  else
    services="sts api client"
    [ "${NEED_KEYCLOAK}" = "1" ] && services="postgres keycloak ${services}"
    [ "${NEED_WSFED}" = "1" ] && services="${services} keycloak-wsfed"
  fi
  if [ -n "${STS_EXTERNAL_URL}" ];
  then
    # A deployed iya-sts: none of ours. The companion stays, pointed at the
    # deployment by the override file.
    local s rest=""
    for s in ${services};
    do
      [ "${s}" = "sts" ] || rest="${rest} ${s}"
    done
    services="${rest# }"
  fi
  echo "Services for this run: ${services}"

  # BUILD. The tests image is always built. iya-sts is not built at all: the
  # stack runs its published release image (IYA_STS_IMAGE), which `up` pulls.
  local builds="tests" s
  for s in api client keycloak-wsfed shibboleth-idp;
  do
    inList "${s}" "${services}" && builds="${builds} ${s}"
  done
  docker_compose "${COMPOSE_ARGS[@]}" build ${builds}
  check_return_code $?

  # START, in the order the compose file's depends_on describes.
  if inList keycloak "${services}";
  then
    composeUpAndWait postgres keycloak
    check_return_code $?
  fi
  if inList sts "${services}";
  then
    # No requireStsReachable() / requireStsSpiffeListeners() here, unlike
    # ./local-run-tests.sh: those guard against a stranger holding a HOST
    # port under host networking, and on this bridge network every listener
    # is in the container's own namespace — a squatter on the host can only
    # make the port PUBLISH fail, which `up` reports itself.
    composeUpAndWait --no-deps sts
    check_return_code $?
  fi
  local middle=""
  for s in ${services};
  do
    case "${s}" in
      postgres|keycloak|sts|api|client) ;;
      *) middle="${middle} ${s}" ;;
    esac
  done
  if [ -n "${middle}" ];
  then
    composeUpAndWait --no-deps ${middle}
    check_return_code $?
  fi
  composeUpAndWait --no-deps api client
  check_return_code $?

  # RUN. The values a focused run needs are handed to the tests container on
  # the command line rather than through the compose file, so the plain
  # default run's environment is exactly what it was. --use-aliases gives the
  # run container the service's own name on the network, which is what
  # SSF_RECEIVER_HOST (an RFC 8935 push from iya-sts to the tests container)
  # resolves.
  local run_env=(-e "TEST_STACK_SERVICES=${services}")
  [ -n "${TEST_SELECT}" ] && run_env+=(-e "TEST_SELECT=${TEST_SELECT}")
  if [ -n "${STS_EXTERNAL_URL}" ];
  then
    run_env+=(-e "STS_EXTERNAL_URL=${STS_EXTERNAL_URL}")
    [ -n "${SPIFFE_TRUST_DOMAIN:-}" ] &&
      run_env+=(-e "SPIFFE_TRUST_DOMAIN=${SPIFFE_TRUST_DOMAIN}")
  fi
  if [ "${MODE}" = "saml-dev" ];
  then
    run_env+=(-e TEST_PROVISION_ONLY=1)
    run_env+=(-e "SAML_SIG_VALIDATION=${SAML_SIG_VALIDATION}")
  fi
  docker_compose "${COMPOSE_ARGS[@]}" run --rm -T --no-deps --use-aliases \
    "${run_env[@]}" tests
  local rc=$?
  echo "Leaving runPartialStack(). rc=${rc}"
  return ${rc}
}

if [ "${MODE}" != "suite" ] || [ "${KEEP_STACK}" = "1" ] ||
   [ -n "${STS_EXTERNAL_URL}" ];
then
  # A focused run is one job at a time unless asked otherwise, as the loops it
  # replaces were: the output streams live and a failure reads in order.
  if [ "${MODE}" != "suite" ] && [ -z "${TEST_CONCURRENCY:-}" ];
  then
    TEST_CONCURRENCY=1
  fi
  runPartialStack
  check_return_code $?
  # --saml-dev ran no test, so no banner.
  if [ "${MODE}" != "saml-dev" ];
  then
    SUITE_PASSED=1
  fi
  exit 0
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
docker_compose "${COMPOSE_ARGS[@]}" up --build -d keycloak-wsfed
check_return_code $?
requireComposeServiceRunning "${COMPOSE_FILE}" keycloak-wsfed
check_return_code $?

# Build fresh images (so code changes are picked up), bring the stack up, and let
# the tests container drive the run. --abort-on-container-exit stops the stack as
# soon as the tests finish; --exit-code-from tests makes compose (and therefore
# this script) exit with the tests container's status. The side-car started above
# is left alone: compose does not recreate a service whose configuration is
# unchanged.
docker_compose "${COMPOSE_ARGS[@]}" up --build --abort-on-container-exit \
  --exit-code-from tests
check_return_code $?

# The banner is printed by the EXIT trap, after the teardown, so it is the last
# thing on the screen rather than the thing the teardown scrolls away.
SUITE_PASSED=1

exit 0
