#!/bin/bash
set -x
#
# Runs the Selenium test suite against a debugger UI at an ARBITRARY base URL —
# the local dev server, https://test.idptools.com, or https://idptools.com —
# using the local identity-provider stack this script starts (keycloak-tests.yml).
#
# Unlike local-run-tests.sh, this does NOT start the debugger/api stack: the target
# site is already deployed (or served by your own local dev server). It DOES start
# everything the suite needs on the other side of the protocol, all on this host's
# loopback:
#
#   :8080  Keycloak 26.x            the identity provider for OAuth2 / OIDC / SAML
#   :8081  the mock STS             WS-Trust, and the OID4VCI issuer + OID4VP
#                                   verifier the SD-JWT VC tests drive
#   :8082  Keycloak 8.0.1 + wsfed   the WS-Federation IdP (26.x cannot do WS-Fed)
#   :7005  walt.id issuer-api2      a real OpenID4VCI issuer, for interoperability
#   :7003  walt.id verifier-api2    a real OpenID4VP verifier, likewise
#
# That works against an https deployed site because Selenium drives a LOCAL
# browser: Chrome treats http://localhost as potentially trustworthy, so the page
# may talk to these without a mixed-content block, and the mock STS and walt.id's
# CORS proxies send the headers a cross-origin fetch needs.
#
# This also runs in CI: .github/workflows/website-test-live{,-prod}.yml call this
# script directly rather than keeping a second copy of the setup. What the browser
# needs is to reach the services above on loopback, which holds on a GitHub-hosted
# runner because the job runs on the VM itself — the containers publish to that
# VM's localhost and Chrome runs beside them. It would STOP holding if the job
# were given a `container:`, which is what the old "local only" note here meant.
#
# Prerequisites (NOT started by this script):
#   - Docker (used to start the containers above)
#   - The debugger site reachable at $DEBUGGER_BASE_URL
#   - Local Chrome on PATH (Selenium drives a local browser and fetches a
#     matching driver itself)
#   - node, plus curl / jq / openssl, and xmllint for the WS-Trust schema job
#
# The stack is left running after the tests for fast re-runs. Stop it with:
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
  # /samlacs & /samlslo endpoints (common.sh derives them). On a deployed static
  # site it depends on what is at the edge — see probeEdgeLandings(), which runs
  # before configureKeycloak because the answer is what gets registered on the
  # client. SAML_BACKEND_AVAILABLE still tells run-report.js to skip the Artifact
  # test, whose server-side SOAP ArtifactResolve back-channel cannot go static
  # under any arrangement.
  case "${DEBUGGER_BASE_URL}" in
    *localhost*|*127.0.0.1*)
      API_BASE_URL="${API_BASE_URL:-http://localhost:4000}"
      SAML_SP_ENTITY_ID="${SAML_SP_ENTITY_ID:-http://localhost:3000/saml/sp}"
      SAML_BACKEND_AVAILABLE="${SAML_BACKEND_AVAILABLE:-true}"
      # A local dev server is served by client/Dockerfile's build, which carries
      # every page — the Kerberos ones included.
      KERBEROS_AVAILABLE="${KERBEROS_AVAILABLE:-${KERBEROS_PAGES_AVAILABLE:-true}}"
      # WS-Trust STS (mock) started on the host (keycloak-tests.yml). A local dev
      # site has the api backend, so the WS-Trust jobs can run here.
      WSTRUST_STS_URL="${WSTRUST_STS_URL:-http://localhost:8081/sts}"
      ;;
    *)
      API_BASE_URL="${API_BASE_URL:-${DEBUGGER_BASE_URL}}"
      SAML_SP_ENTITY_ID="${SAML_SP_ENTITY_ID:-${DEBUGGER_BASE_URL}/saml/sp}"
      SAML_BACKEND_AVAILABLE="${SAML_BACKEND_AVAILABLE:-false}"
      # Kerberos is not in a static build AT ALL — not merely backendless. It is
      # DER over port 88, so the whole workflow goes through the api's relay, and
      # client/static_site.js leaves all five pages out of dist/ and greys out
      # the landing card. Their jobs would otherwise run against a 404 and report
      # a missing element on a page nobody deployed.
      #
      # This switches off EVERY Kerberos job, not only the page ones. The codec,
      # the crypto vectors, the PAC layout, the mock-KDC exchanges and the rest
      # are node-only and would happily run here — but they exercise local code
      # and say nothing about the deployed site, so on this target they are
      # noise. They were also actively misleading: this branch sets CONFIG_FILE
      # to ./env/test-idptools-com.js, and the mock STS resolves a relative
      # CONFIG_FILE against sts/, where that file does not exist, so both
      # mock-KDC jobs failed here naming a config file. Run them against the
      # containerized stack or a local dev server instead.
      #
      # Set this to true for a remote target that IS api-backed. The former name
      # KERBEROS_PAGES_AVAILABLE is still read, by this script and by
      # run-report.js, so an existing environment keeps working.
      KERBEROS_AVAILABLE="${KERBEROS_AVAILABLE:-${KERBEROS_PAGES_AVAILABLE:-false}}"
      # SAML_ACS_URL / SAML_SLO_URL are NOT decided here. Where the IdP should
      # return its response depends on whether this target has the edge landings
      # deployed, which probeEdgeLandings() finds out with a real POST before
      # configureKeycloak registers the client. Set either variable explicitly to
      # override the probe.
      # A deployed static site has no api proxy, so the browser must call the STS
      # DIRECTLY. That works against the host-run mock STS over LOOPBACK — Chrome
      # treats http://localhost as potentially trustworthy (no mixed-content block,
      # unlike a container/bridge name), and the mock sends permissive CORS +
      # Private-Network-Access headers. run-report.js routes these jobs frontend
      # when SAML_BACKEND_AVAILABLE=false. Set WSTRUST_STS_URL empty to skip them.
      WSTRUST_STS_URL="${WSTRUST_STS_URL-http://localhost:8081/sts}"
      ;;
  esac

  export DEBUGGER_BASE_URL KEYCLOAK_BASE_URL KEYCLOAK_LOCALHOST_BASE_URL CONFIG_FILE
  export API_BASE_URL SAML_SP_ENTITY_ID SAML_BACKEND_AVAILABLE
  # Both names are exported: the new one is what run-report.js prefers, the
  # old one keeps anything that still reads it consistent with it.
  KERBEROS_PAGES_AVAILABLE="${KERBEROS_AVAILABLE}"
  export KERBEROS_AVAILABLE KERBEROS_PAGES_AVAILABLE
  # Only exported when set (backendless targets); otherwise common.sh derives them.
  [ -n "${SAML_ACS_URL:-}" ] && export SAML_ACS_URL
  [ -n "${SAML_SLO_URL:-}" ] && export SAML_SLO_URL
  # Points at the host-run mock STS (keycloak-tests.yml) for both target kinds —
  # via localhost either way. Exported only when non-empty: an empty value means
  # "skip the WS-Trust jobs" (run-report.js).
  if [ -n "${WSTRUST_STS_URL:-}" ];
  then
    export WSTRUST_STS_URL
  fi
  # The mock STS answers WS-FEDERATION too, and it is the only WS-Fed IdP a
  # live-site run has: the Keycloak side-car is not started here, so without
  # this every WS-Fed job would skip on a deployed target. Same host-run service
  # over loopback as WSTRUST_STS_URL above — the BROWSER navigates to it, and
  # Chrome treats http://localhost as potentially trustworthy even from an https
  # page, which a bridge name would not be. Set it empty to skip these jobs.
  WSFED_STS_METADATA_URL="${WSFED_STS_METADATA_URL-http://localhost:8081/FederationMetadata/2007-06/FederationMetadata.xml}"
  if [ -n "${WSFED_STS_METADATA_URL:-}" ];
  then
    export WSFED_STS_METADATA_URL
  fi

  # ---------------------------------------------------------------------------
  # The SD-JWT VC and WS-Federation side-cars, all on this host's loopback.
  #
  # Selenium drives a LOCAL browser here, so every one of these is reachable at
  # localhost even when the debugger itself is a deployed HTTPS site: Chrome treats
  # http://localhost as potentially trustworthy, so an https page may talk to it
  # without a mixed-content block (the same reasoning the STS above relies on), and
  # walt.id's CORS proxies supply the headers its services do not.
  #
  # OID4VCI_WALLET_URL is the one that is NOT localhost. The mock issuer's
  # Credential Offer pages and the mock verifier's request pages hand the End-User
  # back to the WALLET, and here the wallet is the site under test — so it is the
  # target base URL, exported for compose to substitute into keycloak-tests.yml's
  # sts service. Left at its default (localhost:3000) those links go nowhere, and
  # the failure is a timeout on a page that never loaded.
  OID4VCI_WALLET_URL="${OID4VCI_WALLET_URL:-${DEBUGGER_BASE_URL}}"
  # The mock Credential Issuer / Verifier is the STS service. Derived from the
  # WS-Trust URL so there is one place that says where the STS is.
  if [ -n "${WSTRUST_STS_URL:-}" ];
  then
    OID4VCI_ISSUER_URL="${OID4VCI_ISSUER_URL:-$(echo "${WSTRUST_STS_URL}" | sed 's|/sts/*$||')}"
  fi
  # walt.id's two services, each behind its own CORS proxy. These are the addresses
  # the BROWSER uses, and every URL walt.id publishes is built from them. Setting
  # them is also what switches the two interoperability jobs on: run-report.js
  # skips them when the corresponding URL is unset.
  WALTID_ISSUER_URL="${WALTID_ISSUER_URL:-http://localhost:7005}"
  WALTID_VERIFIER_URL="${WALTID_VERIFIER_URL:-http://localhost:7003}"
  WALTID_BASE_URL="${WALTID_BASE_URL:-${WALTID_ISSUER_URL}}"
  WALTID_VERIFIER_BASE_URL="${WALTID_VERIFIER_BASE_URL:-${WALTID_VERIFIER_URL}}"
  WALTID_VERIFIER_CLIENT_ID="${WALTID_VERIFIER_CLIENT_ID:-verifier2}"
  # walt.id's issuer authenticates End-Users at the Keycloak this script starts.
  WALTID_KEYCLOAK_AUTHORIZE_URL="${WALTID_KEYCLOAK_AUTHORIZE_URL:-${KEYCLOAK_BASE_URL}/realms/debugger-testing/protocol/openid-connect/auth}"
  WALTID_KEYCLOAK_TOKEN_URL="${WALTID_KEYCLOAK_TOKEN_URL:-${KEYCLOAK_BASE_URL}/realms/debugger-testing/protocol/openid-connect/token}"
  WALTID_KEYCLOAK_CLIENT_ID="${WALTID_KEYCLOAK_CLIENT_ID:-waltid-issuer}"
  WALTID_KEYCLOAK_CLIENT_SECRET="${WALTID_KEYCLOAK_CLIENT_SECRET:-waltid-issuer-test-secret}"
  # The WS-Federation side-car: Keycloak 8.0.1 on WildFly with a port-offset of 2,
  # so HTTP is 8082. Browser-facing and admin-facing are the same over loopback.
  KEYCLOAK_WSFED_BASE_URL="${KEYCLOAK_WSFED_BASE_URL:-http://localhost:8082}"
  KEYCLOAK_WSFED_LOCALHOST_BASE_URL="${KEYCLOAK_WSFED_LOCALHOST_BASE_URL:-${KEYCLOAK_WSFED_BASE_URL}}"

  export OID4VCI_WALLET_URL WALTID_ISSUER_URL WALTID_VERIFIER_URL
  export WALTID_BASE_URL WALTID_VERIFIER_BASE_URL WALTID_VERIFIER_CLIENT_ID
  export WALTID_KEYCLOAK_AUTHORIZE_URL WALTID_KEYCLOAK_TOKEN_URL
  export WALTID_KEYCLOAK_CLIENT_ID WALTID_KEYCLOAK_CLIENT_SECRET
  export KEYCLOAK_WSFED_BASE_URL KEYCLOAK_WSFED_LOCALHOST_BASE_URL
  [ -n "${OID4VCI_ISSUER_URL:-}" ] && export OID4VCI_ISSUER_URL
  # Compose runs under sudo, which resets the environment; docker_compose() in
  # common.sh forwards COMPOSE_PROJECT_NAME (and OID4VCI_WALLET_URL) explicitly, so
  # the helpers that inspect this stack look at the right project.
  export COMPOSE_PROJECT_NAME="${KEYCLOAK_COMPOSE_PROJECT}"

  # The target is a deployed HTTPS site with no API proxy: the browser can't fetch
  # the local http Keycloak descriptor cross-origin (CORS). Have common.sh's
  # configureKeycloak download the descriptor to a file so the SAML tests UPLOAD it.
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
  # The mock STS is a submodule, so its source is fetched rather than committed
  # here. This launcher builds it too (keycloak-tests.yml), so the checkout has to
  # exist before compose runs.
  requireMockStsCheckout "${CURRENT_DIR}"
  check_return_code $?
  # A fresh SP key pair for this run: the tests sign and decrypt with the private
  # key, configureKeycloak registers the certificate on the SAML client, and
  # nothing is written to the repository.
  generateSpKeyPair
  check_return_code $?
  # walt.id's configuration is rendered before compose brings anything up: both
  # services mount a directory this repository does not contain, because each holds
  # a freshly generated signing key and no key material is committed. Without this
  # compose creates those paths as EMPTY directories and the services exit.
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

  echo "==> Debugger under test: ${DEBUGGER_BASE_URL}"
  echo "==> Keycloak:            ${KEYCLOAK_BASE_URL}"
}

prepTestEnv()
{
  npm install --prefix tests
  # The mock STS's own dependencies: the four host-run tests that load
  # sts/bbs2023.js in place reach @digitalbazaar/bbs-signatures through a dynamic
  # import(), which resolves from that file's own directory and ignores NODE_PATH.
  # See the fuller note in local-run-tests.sh. `npm ci` so the submodule's
  # committed lock is not rewritten under it.
  if [ -f sts/package.json ];
  then
    npm ci --prefix sts
  fi
}

# ---------------------------------------------------------------------------
# Which of this target's IdP-response landings actually exist?
#
# Two protocols end with the IdP POSTing its result to the debugger, and static
# hosting cannot receive a POST. On S3+CloudFront both are answered by a
# Lambda@Edge (infra/edge/, deployed by infra/terraform{,-test}):
#
#   /wsfed     the WS-Federation wresult. There is NO alternative here: the
#              Passive Requestor Profile defines one way to return the token and
#              no redirect binding to fall back to.
#   /samlacs   the SAML Response. There IS an alternative — ask the IdP for the
#              HTTP-Redirect binding straight to the static saml_response.html —
#              and that is what this script used to do unconditionally. It works
#              for a modest assertion but saml-profiles-2.0-os section 4.1.2 says
#              Redirect MUST NOT carry the Response, and an ENCRYPTED assertion
#              is the case where that bites: ciphertext does not compress, so the
#              URL roughly doubles and runs at CloudFront's 8,192-byte cap.
#
# Nothing in this repository deploys those functions — the site bundle and the
# infrastructure ship separately — so a target can be perfectly up to date and
# still not have them. Probe with a real POST and look at what comes back:
#
#   * an edge landing generates a page carrying <meta name="wsfed-landing">;
#   * the api's routes 302 to the matching response page;
#   * S3 with nothing in front answers 403/405, which is the case worth naming.
#
# The results decide SAML_ACS_URL / SAML_SLO_URL (registered on the Keycloak
# client a few steps later, which is why this runs first) and set
# WSFED_LANDING_AVAILABLE / SAML_LANDING_AVAILABLE for run-report.js. A missing
# landing is never a failure here — it is a job that skips, or a SAML flow that
# falls back to the Redirect binding, with the reason said out loud.
# ---------------------------------------------------------------------------
probeOneLanding()
{
  # $1 = URL, $2 = the form field the landing expects. Echoes "edge", "api" or
  # "none"; the HTTP status goes to stderr for the trace.
  local url="$1" field="$2" body_file code body
  body_file=$(mktemp)
  code=$(curl -s -m 20 -o "${body_file}" -w '%{http_code}' \
    -X POST "${url}" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "${field}=<probe/>" || echo "000")
  body=$(head -c 2000 "${body_file}" 2>/dev/null)
  rm -f "${body_file}"
  echo "probeOneLanding: ${url} -> HTTP ${code}" >&2
  if echo "${body}" | grep -q 'name="wsfed-landing"';
  then
    echo "edge"
  elif [ "${code}" = "302" ] || [ "${code}" = "303" ];
  then
    echo "api"
  else
    echo "none"
  fi
}

probeEdgeLandings()
{
  echo "Entering probeEdgeLandings()."
  local wsfed_kind saml_kind

  # --- WS-Federation ---------------------------------------------------------
  WSFED_LANDING_URL="${WSFED_LANDING_URL:-${DEBUGGER_BASE_URL}/wsfed}"
  wsfed_kind=$(probeOneLanding "${WSFED_LANDING_URL}" wresult)
  if [ "${wsfed_kind}" = "none" ];
  then
    declare -gx WSFED_LANDING_AVAILABLE="false"
    echo "WARNING: ${WSFED_LANDING_URL} did not look like a landing, so the WS-Federation job will be" >&2
    echo "         SKIPPED. On a static deployment that means the Lambda@Edge is not deployed:" >&2
    echo "           ./infra/terraform-local.sh test apply     # or: prod apply" >&2
    echo "         and the site bundle must be built with wsfedEdgeLanding: true." >&2
  else
    declare -gx WSFED_LANDING_AVAILABLE="true"
    echo "WS-Federation landing at ${WSFED_LANDING_URL}: the ${wsfed_kind} landing."
  fi
  export WSFED_LANDING_URL

  # --- SAML ------------------------------------------------------------------
  SAML_LANDING_URL="${SAML_LANDING_URL:-${DEBUGGER_BASE_URL}/samlacs}"
  saml_kind=$(probeOneLanding "${SAML_LANDING_URL}" SAMLResponse)
  if [ "${saml_kind}" = "none" ];
  then
    declare -gx SAML_LANDING_AVAILABLE="false"
    # Fall back to what this script always did: the static response page, reached
    # over the Redirect binding. Out of profile, but it is the only thing that
    # works with nothing able to receive a POST, and it is what real deployments
    # without an edge function have to do.
    declare -gx SAML_ACS_URL="${SAML_ACS_URL:-${DEBUGGER_BASE_URL}/saml_response.html}"
    declare -gx SAML_SLO_URL="${SAML_SLO_URL:-${DEBUGGER_BASE_URL}/saml_response.html}"
    echo "WARNING: ${SAML_LANDING_URL} did not look like a landing. Falling back to the HTTP-Redirect" >&2
    echo "         binding into ${SAML_ACS_URL}; the EncryptedAssertion job will be SKIPPED, because" >&2
    echo "         Keycloak's encrypted client forces the POST binding (saml.force.post.binding=true)" >&2
    echo "         and a static page cannot receive a POST. Deploy the edge landing with:" >&2
    echo "           ./infra/terraform-local.sh test apply     # or: prod apply" >&2
    echo "         and build the site bundle with samlEdgeLanding: true." >&2
  else
    declare -gx SAML_LANDING_AVAILABLE="true"
    declare -gx SAML_ACS_URL="${SAML_ACS_URL:-${DEBUGGER_BASE_URL}/samlacs}"
    declare -gx SAML_SLO_URL="${SAML_SLO_URL:-${DEBUGGER_BASE_URL}/samlslo}"
    echo "SAML landing at ${SAML_LANDING_URL}: the ${saml_kind} landing. ACS=${SAML_ACS_URL} SLO=${SAML_SLO_URL}"
  fi
  export SAML_LANDING_URL

  echo "Leaving probeEdgeLandings(). WSFED_LANDING_AVAILABLE=${WSFED_LANDING_AVAILABLE} SAML_LANDING_AVAILABLE=${SAML_LANDING_AVAILABLE}"
  return 0
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

# The side-cars this stack now also carries: the WS-Federation Keycloak, and
# walt.id's issuer and verifier behind their CORS proxies.
#
# The WS-Federation one is checked strictly — `up` reports success for a container
# that was created and then exited, which is exactly how Keycloak 8.0.1 on WildFly
# fails — so the run stops here rather than letting its test fail later for reasons
# that name nothing. walt.id is waited for rather than required: its JVMs are built
# with Jib and carry no healthcheck of their own, so waitForWaltid() probes them
# through the proxies and prints the container's own log if one never answers.
startSideCars()
{
  echo "Entering startSideCars()."
  requireComposeServiceRunning "${KEYCLOAK_COMPOSE_FILE}" keycloak-wsfed
  check_return_code $?
  waitForWaltid "${KEYCLOAK_COMPOSE_FILE}"
  echo "Leaving startSideCars()."
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

# resetKeycloakRealm() is defined in common/common.sh (sourced by init above) so
# both this deployed-target runner and the containerized run share one copy — it
# deletes the debugger-testing realm so configureKeycloak re-creates every client
# with redirectUris / webOrigins matching the CURRENT DEBUGGER_BASE_URL. Without
# it, switching targets (local -> test -> prod) would leave stale redirect URIs
# from the previous run and the flows would fail.

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
# Before configureKeycloak, because what it finds decides SAML_ACS_URL/SAML_SLO_URL
# — the URLs registered on the Keycloak SAML clients.
probeEdgeLandings
check_return_code $?
startKeycloak
check_return_code $?
resetKeycloakRealm
check_return_code $?
configureKeycloak
check_return_code $?
startSideCars
check_return_code $?
# Provisions the wsfed realm, its relying-party client and user, and exports the
# WSFED_* vars the WS-Federation job is gated on. Skips (rather than fails) if the
# side-car is unusable — the check above has already stopped the run if it is down.
configureKeycloakWsfed "${KEYCLOAK_COMPOSE_FILE}"
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
