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
#   --wsfed-only[=IDP]
#                Bring up ONLY what the WS-Federation test needs (api, client,
#                the mock STS and the Keycloak 8.0.1 + wsfed side-car),
#                provision it, and run that one test against BOTH identity
#                providers — the same pair run-report.js drives. A ~2-minute
#                loop instead of the whole suite, and it prints why an IdP is
#                unusable when it is. IDP may be "keycloak", "sts" or "both"
#                (the default): the mock alone starts in seconds where the
#                WildFly side-car needs twenty, so --wsfed-only=sts is the
#                fastest loop of all.
#   --krb5-real-dc[=WHAT]
#                Spin up a real Windows Server 2025 domain controller on AWS,
#                run the Kerberos interoperability work against it, and tear it
#                ALL down again. Needs working AWS credentials and nothing else
#                — no docker, no local stack: the test loads the api's relay
#                modules in-process and talks to the DC directly.
#                WHAT may be "test" (default, tests/krb5_real_dc.js), "capture"
#                (refresh tests/captures/windows-server-2025.json) or "both".
#                NOT free tier, and it is the only thing here that creates
#                billable infrastructure — see infra/terraform-krb5/README.md.
#   -h|--help    Show usage.
#
SKIP_TESTS=0
WSFED_ONLY=0
# Which identity provider(s) --wsfed-only drives. See docs/wsfed.md for why
# there are two and what each covers that the other cannot.
WSFED_ONLY_IDP=both
# --krb5-real-dc: 0 = off, else the work to run against the live DC.
KRB5_REAL_DC=0
KRB5_REAL_DC_WHAT=test
SAML_SIG_VALIDATION=true

usage()
{
  cat <<USAGE
Usage: $(basename "$0") [--saml-dev] [--wsfed-only[=keycloak|sts|both]]
                        [--krb5-real-dc[=test|capture|both]] [-h|--help]

  (default)    Build + start the stack, provision Keycloak (SAML AuthnRequest
               signature validation ENABLED), and run the full test suite.

  --saml-dev   Build + start Keycloak and the debugger (api + client), provision
               Keycloak with SAML AuthnRequest signature validation DISABLED, and
               leave the stack running WITHOUT running the tests.

  --wsfed-only[=IDP]
               Build + start only api, client, the mock STS and the WS-Fed
               Keycloak side-car, provision the wsfed realm/client/user, and run
               just tests/wsfed_sso.js against BOTH identity providers. Use this
               to work on the WS-Federation test without waiting for the full
               suite. IDP is "keycloak", "sts" or "both" (default) — the mock
               starts in seconds and the WildFly side-car does not, so
               --wsfed-only=sts is the fastest loop.

  --krb5-real-dc[=WHAT]
               Create a Windows Server 2025 domain controller on AWS, run the
               Kerberos interoperability work against it, then destroy every
               resource it made. Requires AWS credentials already in place;
               requires no docker and starts no local stack, because the test
               speaks to the DC directly through the api's relay modules loaded
               in-process. WHAT is one of:
                 test     (default) tests/krb5_real_dc.js
                 capture  refresh tests/captures/windows-server-2025.json,
                          the recording that krb5_windows_vectors.js asserts
                          offline on every ordinary run
                 both     the test, then the capture
               THIS COSTS MONEY. It is not free tier — a forest promotion needs
               more than 1 GiB — and it is the only option here that creates
               billable infrastructure. Teardown is on an EXIT trap, so it runs
               even when the test fails; KRB5_KEEP=1 keeps the box for
               debugging and tells you how to remove it.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --saml-dev) SKIP_TESTS=1; SAML_SIG_VALIDATION=false ;;
    --wsfed-only) WSFED_ONLY=1 ;;
    --wsfed-only=*) WSFED_ONLY=1; WSFED_ONLY_IDP="${1#*=}" ;;
    --krb5-real-dc) KRB5_REAL_DC=1 ;;
    --krb5-real-dc=*) KRB5_REAL_DC=1; KRB5_REAL_DC_WHAT="${1#*=}" ;;
    -h|--help)  usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
  shift
done
case "${WSFED_ONLY_IDP}" in
  keycloak|sts|both) ;;
  *) echo "Unknown --wsfed-only identity provider: ${WSFED_ONLY_IDP}" >&2
     usage; exit 1 ;;
esac
case "${KRB5_REAL_DC_WHAT}" in
  test|capture|both) ;;
  *) echo "Unknown --krb5-real-dc value: ${KRB5_REAL_DC_WHAT}" >&2
     usage; exit 1 ;;
esac
if [ "${KRB5_REAL_DC}" = "1" ] && [ "${WSFED_ONLY}" = "1" ];
then
  echo "--krb5-real-dc and --wsfed-only each run one thing; pick one." >&2
  exit 1
fi
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
  # The same mock STS also answers WS-FEDERATION, so the WS-Fed jobs run against
  # it as well as against the Keycloak side-car below. Kept separate from
  # WSTRUST_STS_URL, which may be pointed at a real Apache CXF STS that has no
  # passive endpoint at all.
  WSFED_STS_METADATA_URL=http://localhost:8081/FederationMetadata/2007-06/FederationMetadata.xml
  export WSFED_STS_METADATA_URL
  # And it hosts the TLS / mutual-TLS endpoint the PKI page presents a client
  # certificate to (its two HTTPS listeners, 8443 and 9443). This is its PLAIN
  # HTTP base: the test configures the far end's truststore over it and reads
  # the listeners' ports from the service rather than carrying a copy of them.
  #
  # Separate from WSTRUST_STS_URL for the same reason WSFED_STS_METADATA_URL is
  # — that one may be pointed at a real Apache CXF STS, which has no endpoint of
  # this kind — and it must be reachable by the API as well as by the test,
  # since the api is what opens the socket. Both are on this host here.
  STS_TLS_URL=http://localhost:8081
  export STS_TLS_URL
  # RFC 9700 (OAuth 2.0 Security BCP): a SECOND mock STS, started with
  # STS_OAUTH2_RFC9700=true, so that the OAuth2/OIDC matrix can be run a second
  # time with BOTH sides compliant. Setting this turns on five jobs in
  # tests/run-report.js; leaving it unset skips them.
  #
  # It has to be a second INSTANCE rather than a second setting: oauth2.rfc9700
  # derives global.https, and the main port's scheme is decided once, when the
  # listener is bound — so it is restart-only in that service and one process
  # cannot serve both passes. It is the `sts-rfc9700` service in
  # local-tests.yml, which is the SAME image as `sts` with a different
  # environment.
  #
  # https, and 8091: with the mode on there is no plain listener in that
  # process at all, and under host networking it shares this machine's
  # namespace with `sts`, so all seven of its listeners are moved off the first
  # instance's. See the note on the service. docs/rfc9700.md has the rest.
  #
  # SET ONLY IF THE SUBMODULE ACTUALLY HAS THE MODE. `oauth2_bcp.js` is where
  # it lives in the mock, and sts/ may be pinned to a commit that predates it —
  # in which case STS_OAUTH2_RFC9700 names a setting that does not exist, the
  # second instance comes up plain HTTP, and the five jobs would run against a
  # server that agrees with everything they ask. Skipping them says so in one
  # line and leaves the other 179 to run; the alternative — halting the whole
  # suite over an un-bumped gitlink — costs more than it catches, because the
  # jobs themselves already refuse a permissive STS BY NAME.
  if [ -f "sts/oauth2_bcp.js" ];
  then
    RFC9700_STS_URL=https://localhost:8091
    export RFC9700_STS_URL
  else
    echo "sts/oauth2_bcp.js is absent, so this checkout of the mock STS has no"
    echo "RFC 9700 mode and the five RFC 9700 flow jobs will be SKIPPED. Bump"
    echo "the sts/ submodule to a mock-sts commit that carries it. See"
    echo "docs/rfc9700.md. (tests/rfc9700_client.js is unaffected — it needs no"
    echo "service at all and runs either way.)"
  fi
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
  # The api needs node-ldapjs too — the same library on the client side of
  # the LDAP exchange, pinned as api/node-ldapjs. A separate submodule from
  # the mock's, because npm resolves a `file:` dependency's own requires from
  # where the real directory lives, so a copy outside api/ never reaches
  # api/node_modules. Uninitialised, the image builds fine and the service
  # dies at startup with `Cannot find module 'ldapjs'`.
  requireApiLdapjsCheckout "${CURRENT_DIR}"
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
  EXTENSION_AUTOARM_ORIGINS="http://localhost:8081" \
  buildBrowserExtension "${CURRENT_DIR}"   # the browser is on the host
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
  #
  # `--omit=dev` is spelled out even though sts/.npmrc says the same thing, and
  # the reason is that it DOES NOT APPLY HERE: npm reads .npmrc from the current
  # directory, not from --prefix, so the submodule's own file is invisible to
  # this invocation. Without the flag npm installs the devDependencies of the
  # mock's `file:node-ldapjs` dependency — tap, eslint and their trees, roughly
  # 200 packages nothing in this run loads — on every launcher run.
  if [ -f sts/package.json ];
  then
    npm ci --omit=dev --prefix sts
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
  # And BOTH mock STS instances, for the same reason and one more.
  #
  # THE ONE MORE, because it cost a whole run on 2026-08-20: 71 of 184 tests
  # failed and not one of them named the cause. Something outside compose — a
  # mock STS started by hand from a sibling checkout, in RFC 9700 mode, hours
  # earlier — was holding host port 8081. Under host networking that is the
  # port `sts` binds, its listen has no error handler, so the container threw
  # EADDRINUSE and exited seconds after `up -d` reported success. Every
  # STS-backed test then failed against a stranger: WS-Trust timed out waiting
  # for a response page, Kerberos got ECONNREFUSED on 88, and the jobs that
  # probe first (LDAP, PKI mutual-TLS, the DPoP server checks) reported PASS
  # while quietly skipping. requireStsReachable() below is what turns that back
  # into one line naming the port.
  CONFIG_FILE=./env/local.js requireComposeServiceRunning local-tests.yml sts
  check_return_code $?
  # Running is not answering, and on 8081 it is not even enough to know WHO is
  # answering. This names the port and says what it found.
  requireStsReachable http http://localhost:8081/healthcheck sts
  check_return_code $?
  # The compliant instance only has to be there when the five jobs that use it
  # are scheduled, which is the same condition that sets the URL above.
  if [ -n "${RFC9700_STS_URL:-}" ];
  then
    CONFIG_FILE=./env/local.js requireComposeServiceRunning local-tests.yml \
        sts-rfc9700
    check_return_code $?
    requireStsReachable https https://localhost:8091/healthcheck sts-rfc9700
    check_return_code $?
  fi
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
# --wsfed-only: the WS-Federation test on its own, against both identity
# providers.
#
# The full run takes about ten minutes, which is a poor loop for one test — and
# this test is the one most often skipped, because it depends on a side-car that
# `docker compose up -d` will happily report as started whether or not it stayed
# up. So bring up only what it needs, say plainly whether each IdP is usable,
# and run it.
#
# TWO IdPs, because the suite runs every WS-Federation case twice and a loop
# that drives only one of them is a loop that green-lights a change the real run
# then fails. They fail differently: Keycloak is somebody else's implementation
# and the only interoperability evidence here, while the mock STS actually READS
# the request — it refuses a wauth it cannot perform, a token type it does not
# offer and a wreqptr outright. See docs/wsfed.md. The mock also starts in
# seconds where the WildFly side-car needs twenty, so --wsfed-only=sts is worth
# having on its own.
# ---------------------------------------------------------------------------

# Run tests/wsfed_sso.js once, against the IdP described by the environment the
# caller sets. Invoked exactly as tests/run-report.js does it: from the
# repository root, with CONFIG_FILE relative to the test file (require()
# resolves against the module's own directory, not the working directory).
runWsfedAgainst()
{
  local label="$1"
  echo "Entering runWsfedAgainst(). label=${label}"
  echo "=== WS-Federation against ${label} ==="
  echo "WSFED_IDP=${WSFED_IDP}  WSFED_METADATA_URL=${WSFED_METADATA_URL}"
  echo "WSFED_REALM=${WSFED_REALM}  WSFED_USER=${WSFED_USER}"
  node "${NODEJS_BASE_DIR}/wsfed_sso.js" --url "${DEBUGGER_BASE_URL}"
  local rc=$?
  echo "Leaving runWsfedAgainst(). label=${label} rc=${rc}"
  return ${rc}
}

runWsfedOnly()
{
  echo "Entering runWsfedOnly(). idp=${WSFED_ONLY_IDP}"
  # Which services this loop needs. The mock STS is a second IdP, not a
  # dependency of the first, so a keycloak-only loop does not pay for it and an
  # sts-only loop does not wait on WildFly.
  local services="api client"
  case "${WSFED_ONLY_IDP}" in
    keycloak) services="${services} keycloak-wsfed" ;;
    sts)      services="${services} sts" ;;
    both)     services="${services} sts keycloak-wsfed" ;;
  esac
  # compose starts each service's dependencies too, so this pulls in postgres and
  # the main Keycloak only if api/client actually declare them.
  CONFIG_FILE=./env/local.js docker_compose -f local-tests.yml build ${services}
  check_return_code $?
  CONFIG_FILE=./env/local.js docker_compose -f local-tests.yml up -d ${services}
  check_return_code $?
  if [ "${WSFED_ONLY_IDP}" != "sts" ];
  then
    echo "Waiting for the WS-Federation side-car (Keycloak 8.0.1 on WildFly boots slowly) ..."
    sleep 20
  else
    echo "Waiting for the mock STS ..."
    sleep 5
  fi
  CONFIG_FILE=./env/local.js verifyComposeServicesRunning local-tests.yml

  # Provision the side-car only when this loop is driving it. Fatal for the same
  # reason as in startDocker(): there is no point provisioning, or running the
  # test, against a container that is not there.
  if [ "${WSFED_ONLY_IDP}" != "sts" ];
  then
    CONFIG_FILE=./env/local.js requireComposeServiceRunning local-tests.yml keycloak-wsfed
    check_return_code $?
    configureKeycloakWsfed local-tests.yml
    check_return_code $?
    if [ -z "${WSFED_METADATA_URL:-}" ];
    then
      echo "The WS-Federation side-car could not be provisioned — see the" >&2
      echo "reason above. Not running its half of the test." >&2
      exit 1
    fi
  fi
  if [ "${WSFED_ONLY_IDP}" != "keycloak" ];
  then
    CONFIG_FILE=./env/local.js requireComposeServiceRunning local-tests.yml sts
    check_return_code $?
  fi

  export DEBUGGER_BASE_URL CONFIG_FILE KEYCLOAK_BASE_URL
  local rc=0
  local failures=""

  # Each run happens in a SUBSHELL, and the exports are written out rather than
  # prefixed onto the call. `VAR=x somefunc` is the trap here: whether those
  # assignments survive the function is bash's posix-mode question, not a
  # settled one, so the second IdP could inherit the first one's metadata URL
  # and "fail" as a mismatched audience three pages later.
  if [ "${WSFED_ONLY_IDP}" != "sts" ];
  then
    (
      # The side-car's own provisioned values, exported by
      # configureKeycloakWsfed. The two overrides the mock needs are unset here:
      # Keycloak's endpoint IS derivable from its descriptor URL, and its
      # extension does not read the wreq at all.
      export WSFED_IDP=keycloak
      unset WSFED_SIGNIN_ENDPOINT WSFED_WREQ_TOKEN_TYPE
      export WSFED_METADATA_URL WSFED_REALM WSFED_USER
      runWsfedAgainst "the Keycloak 8.0.1 side-car"
    )
    if [ $? -ne 0 ]; then rc=1; failures="${failures} Keycloak"; fi
  fi

  if [ "${WSFED_ONLY_IDP}" != "keycloak" ];
  then
    (
      # The same values run-report.js gives the mock's jobs, and for the same
      # reasons: it registers no relying parties so the wtrealm is any string
      # and becomes the audience; it authenticates nobody so the username
      # becomes the subject; its passive endpoint does not sit under its
      # metadata path the way Keycloak's does; and it READS the inline wreq,
      # refusing a token type its fed:TokenTypesOffered does not list.
      export WSFED_IDP=sts
      export WSFED_METADATA_URL="${WSFED_STS_METADATA_URL}"
      export WSFED_REALM="${WSFED_STS_REALM:-urn:wsfed:sts:rp}"
      export WSFED_USER="${WSFED_STS_USER:-wsfed}"
      export WSFED_SIGNIN_ENDPOINT="${WSFED_STS_ENDPOINT:-http://localhost:8081/wsfed}"
      export WSFED_WREQ_TOKEN_TYPE="urn:oasis:names:tc:SAML:2.0:assertion"
      runWsfedAgainst "the mock STS"
    )
    if [ $? -ne 0 ]; then rc=1; failures="${failures} mock-STS"; fi
  fi

  if [ ${rc} -ne 0 ];
  then
    echo "WS-Federation failed against:${failures}" >&2
  fi
  echo "Leaving runWsfedOnly(). rc=${rc}"
  return ${rc}
}

# ---------------------------------------------------------------------------
# --krb5-real-dc: the Kerberos interoperability work, against AWS.
#
# This is the one option here that creates billable infrastructure, and the only
# one that needs no docker at all. tests/krb5_real_dc.js loads the api's relay
# and SSRF guard as MODULES and opens the socket itself, so there is no api
# service, no client, no Keycloak and no mock STS in this path — just node and a
# domain controller in us-west-2.
#
# The apply / wait-for-the-forest / teardown logic is NOT duplicated here. It
# lives once, in infra/krb5-test.sh, because the teardown is the only thing
# standing between a failed run and a Windows instance billing until somebody
# notices, and two copies of that would be one too many. All this function does
# is decide which scripts run against the live DC and hand them over.
# ---------------------------------------------------------------------------
runKrb5RealDc()
{
  echo "Entering runKrb5RealDc(). what=${KRB5_REAL_DC_WHAT}"
  local scripts=""
  case "${KRB5_REAL_DC_WHAT}" in
    test)    scripts="krb5_real_dc.js" ;;
    capture) scripts="krb5_capture_real_dc.js" ;;
    # The test first: if the client cannot complete the exchange there is no
    # point recording it, and a capture taken from a broken run is worse than
    # none because krb5_windows_vectors.js would then assert the breakage.
    both)    scripts="krb5_real_dc.js krb5_capture_real_dc.js" ;;
  esac

  command -v aws >/dev/null 2>&1 || {
    echo "ERROR: --krb5-real-dc needs the AWS CLI on PATH." >&2
    exit 1
  }
  if ! aws sts get-caller-identity >/dev/null 2>&1;
  then
    echo "ERROR: --krb5-real-dc needs working AWS credentials; none resolved." >&2
    echo "       Sign in, then re-run. Nothing has been created." >&2
    exit 1
  fi
  echo "AWS account: $(aws sts get-caller-identity --query Account --output text 2>/dev/null)"

  cat <<'WARNING'
============================================================================
This creates a Windows Server 2025 domain controller on AWS. It is NOT free
tier (a forest promotion needs more than the 1 GiB a t3.micro has), it costs
a few cents an hour, and everything it makes is destroyed at the end by an
EXIT trap that runs even if the test fails.

Set KRB5_KEEP=1 to keep the instance for debugging instead.
============================================================================
WARNING

  # CONFIG_FILE is passed through as the tests' own config, which is what the
  # relay and the logger read. infra/krb5-test.sh substitutes an sts-resolvable
  # one only where the mock STS is involved, and it is not involved here.
  KRB5_TEST_SCRIPTS="${scripts}" \
    CONFIG_FILE="${CONFIG_FILE}" \
    "${CURRENT_DIR}/infra/krb5-test.sh"
  local rc=$?
  echo "Leaving runKrb5RealDc(). rc=${rc}"
  return ${rc}
}

init
check_return_code $?
prepTestEnv
check_return_code $?
if [ "${KRB5_REAL_DC}" = "1" ];
then
  runKrb5RealDc
  check_return_code $?
  echo "Kerberos real-DC work passed (${KRB5_REAL_DC_WHAT})."
  exit 0
fi
if [ "${WSFED_ONLY}" = "1" ];
then
  runWsfedOnly
  check_return_code $?
  echo "WS-Federation test passed (idp=${WSFED_ONLY_IDP})."
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
