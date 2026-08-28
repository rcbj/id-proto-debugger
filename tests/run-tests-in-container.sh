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
  # Keycloak (e.g. DEBUGGER_BASE_URL=https://test.idptools.com with
  # KEYCLOAK_BASE_URL=http://localhost:8080). Note the live-site runs no longer
  # come through this script at all — remote-run-tests.sh drives them on the
  # host, browser included — so this override path is now only for a hand-run.
  DEBUGGER_BASE_URL="${DEBUGGER_BASE_URL:-http://client:3000}"
  KEYCLOAK_BASE_URL="${KEYCLOAK_BASE_URL:-http://keycloak:8080}"
  KEYCLOAK_LOCALHOST_BASE_URL="${KEYCLOAK_LOCALHOST_BASE_URL:-http://keycloak:8080}"
  # SAML: must match the client bundle's baked env (service DNS names).
  API_BASE_URL="${API_BASE_URL:-http://api:4000}"
  SAML_SP_ENTITY_ID="${SAML_SP_ENTITY_ID:-http://client:3000/saml/sp}"
  # THE api AND THE MOCK STS AS THIS CONTAINER REACHES THEM, and neither is
  # API_BASE_URL above. That one is the SAML / WS-Federation variable — the
  # address the identity provider is told to POST to, which common.sh registers
  # on the Keycloak client — while API_URL and STS_URL are what the seven
  # LDAP, SCIM and Kerberos-page jobs call THEMSELVES; run-report.js passes
  # them per job and defaults them to a HOST's view, http://localhost:4000 and
  # https://localhost:8081. Nothing set them here, and in this container those
  # two addresses are this container.
  #
  # The cost was silence rather than failure, which is why it survived so long:
  # api_ldap.js, ldap_page.js, scim_page.js, kerberos_as_page.js,
  # kerberos_tgs_ap_page.js, kerberos_spnego_page.js and
  # kerberos_delegation_page.js all treat an unreachable api or mock as "not
  # this deployment" and SKIP with a reason, so every one of them reported PASS
  # in about a tenth of a second on every containerized run — a browser test
  # cannot start Chrome in that time, which is the tell. Only scim_protocol.js,
  # which has no such fallback, failed and named the address.
  #
  # Both names resolve in this container AND in the api's, which matters
  # because two of those jobs ask the api to reach the mock for them:
  # SCIM_BASE_URL (https://sts:8081/scim/v2) and LDAP_URL (ldap://sts:389) are
  # the API's view and run-report.js already defaults them to the compose name.
  # Defaulted only for the containerized stack, like WSTRUST_STS_URL below: on
  # any other target run-report.js's own localhost defaults are the right
  # answer, and each of those jobs says for itself when there is no backend.
  case "${DEBUGGER_BASE_URL}" in
    http://client:*)
      API_URL="${API_URL:-http://api:4000}"
      STS_URL="${STS_URL:-https://sts:8081}"
      ;;
  esac
  export API_URL STS_URL
  # THE TWO SPIFFE gRPC ADDRESSES, and there are two SETS of them because two
  # different processes dial them.
  #
  #   SPIFFE_WORKLOAD_ADDRESS / SPIFFE_SERVER_ADDRESS are the API's view —
  #   `api_spiffe.js` and `spiffe_page.js` both ask the api to open the
  #   connection, exactly as SCIM_BASE_URL and LDAP_URL are the api's view.
  #   run-report.js already defaults these to the compose name, so they are
  #   here only for symmetry and for a stack that overrides them.
  #
  #   SPIFFE_TEST_* are THIS container's view, and they exist because
  #   `spiffe_protocol.js` drives the api's client IN PROCESS and opens the
  #   socket itself. On this stack the two happen to be the same name; on a
  #   host run they are not, and a single variable standing for both is the
  #   mistake KRB5_KDC_HOST records — `localhost` in the api's view means the
  #   api container, where nothing listens on either port.
  #
  # The mock STS binds both on 0.0.0.0 and neither is published to the host
  # here, which is fine: everything that dials them is on the bridge.
  case "${DEBUGGER_BASE_URL}" in
    http://client:*)
      SPIFFE_WORKLOAD_ADDRESS="${SPIFFE_WORKLOAD_ADDRESS:-sts:8092}"
      SPIFFE_SERVER_ADDRESS="${SPIFFE_SERVER_ADDRESS:-sts:8181}"
      SPIFFE_TEST_WORKLOAD_ADDRESS="${SPIFFE_TEST_WORKLOAD_ADDRESS:-sts:8092}"
      SPIFFE_TEST_SERVER_ADDRESS="${SPIFFE_TEST_SERVER_ADDRESS:-sts:8181}"
      SPIFFE_BUNDLE_URL="${SPIFFE_BUNDLE_URL:-https://sts:8081/spiffe/bundle}"
      ;;
  esac
  export SPIFFE_WORKLOAD_ADDRESS SPIFFE_SERVER_ADDRESS
  export SPIFFE_TEST_WORKLOAD_ADDRESS SPIFFE_TEST_SERVER_ADDRESS
  export SPIFFE_BUNDLE_URL
  # THE MOCK KDC AS *THIS CONTAINER* DIALS IT, and the SPIFFE_TEST_* pair above
  # is the precedent rather than a coincidence.
  #
  # KRB5_KDC_HOST — which run-report.js still defaults to the compose name for
  # the five Kerberos PAGE jobs — is the API's view: that address is typed into
  # a page and resolved by the relay inside the api container.
  # krb5_mit_client.js has no page and no relay; `kinit` opens the socket in
  # the test's own process, so it reads KRB5_TEST_KDC_HOST and run-report.js
  # defaults THAT to localhost, which is right on a host launcher
  # (local-tests.yml is host-networked, so the mock's port 88 is the host's).
  # Here it is not: nothing listens on 88 in this
  # container, and `kinit` would answer `Cannot contact any KDC for realm
  # EXAMPLE.COM` — a message naming neither the variable nor the stack.
  #
  # Only for the containerized stack, like STS_URL and WSTRUST_STS_URL above:
  # on any other target run-report.js's own localhost default is the right
  # answer, and the job says for itself when the KDC is not there.
  case "${DEBUGGER_BASE_URL}" in
    http://client:*)
      KRB5_TEST_KDC_HOST="${KRB5_TEST_KDC_HOST:-sts}"
      KRB5_TEST_KDC_PORT="${KRB5_TEST_KDC_PORT:-88}"
      ;;
  esac
  export KRB5_TEST_KDC_HOST KRB5_TEST_KDC_PORT
  # WS-Trust STS (mock) reachable by its compose DNS name on the test network.
  # Must match the client bundle's baked wstrustStsUrlDefault (docker-tests.js).
  #
  # ONLY default this for the containerized stack: the bridge DNS name is valid
  # only there. On a DEPLOYED (HTTPS, backend-less) target the browser calls the
  # STS directly, and the compose name resolves to nothing in a browser that is
  # not on this network — every WS-Trust job then times out waiting for a
  # response page. The live-site stack therefore passes WSTRUST_STS_URL
  # explicitly as https://localhost:8081/sts (its own host-networked sts
  # service), which is what remote-run-tests.sh does.
  #
  # **https**, HERE AND IN EVERY STS URL BELOW. That mock binds its main port as
  # TLS on this stack (STS_HTTPS=true on the `sts` service), because the RFC 9700
  # pass is a trust realm on it now rather than a second container and a realm
  # binds no socket of its own. It also settles the mixed-content question this
  # paragraph used to be about, in the direction that needs no exception: an
  # https page may call an https service wherever it is. If it arrives unset/empty, run-report.js SKIPS
  # the WS-Trust jobs (as it skips the SAML Artifact job on a backend-less target)
  # rather than failing.
  case "${DEBUGGER_BASE_URL}" in
    http://client:*)
      WSTRUST_STS_URL="${WSTRUST_STS_URL:-https://sts:8081/sts}"
      ;;
  esac
  # Exporting an unset variable passes nothing to children, so run-report.js sees
  # WSTRUST_STS_URL as undefined on non-containerized targets and skips.
  export WSTRUST_STS_URL
  # The same mock STS answers WS-FEDERATION as well as WS-Trust (its /wsfed
  # passive endpoint and the AD FS-style metadata path below), so the WS-Fed
  # jobs run against it in addition to the Keycloak side-car. Same DNS rule as
  # WSTRUST_STS_URL and for the same reason — this is a BROWSER-facing URL: the
  # page navigates to the IdP, so the name has to resolve in the browser, and
  # the compose name only does so on this stack. It is a separate variable from
  # WSTRUST_STS_URL rather than derived from it because that one may legitimately
  # point at a real Apache CXF STS, which has no WS-Federation endpoint at all;
  # deriving would turn "not this protocol" into a run of failing jobs.
  case "${DEBUGGER_BASE_URL}" in
    http://client:*)
      WSFED_STS_METADATA_URL="${WSFED_STS_METADATA_URL:-https://sts:8081/FederationMetadata/2007-06/FederationMetadata.xml}"
      ;;
  esac
  export WSFED_STS_METADATA_URL
  # The same mock also answers SAML 2.0 WEB BROWSER SSO, so the SAML jobs run
  # against it as well as against the Keycloak realm. Same DNS rule and the same
  # reason as the two above: this is a BROWSER-facing URL.
  #
  # THE PATH SEGMENT IS A DIGEST, computed here rather than guessed. That
  # service publishes metadata PER SERVICE PROVIDER, and the segment is the
  # entityID where that is safe in a URL path and `app-` plus twelve hex
  # characters of its SHA-256 where it is not. Ours is a URL, so it is the
  # digest — and note it is computed from THIS file's SAML_SP_ENTITY_ID, which
  # is the compose-DNS spelling and therefore a different digest from the host
  # run's. Nothing has to be provisioned for it: the mock accepts any entityID
  # and mints the document on the ask.
  case "${DEBUGGER_BASE_URL}" in
    http://client:*)
      SAML_STS_SP_SLUG="app-$(printf '%s' "${SAML_SP_ENTITY_ID}" | sha256sum | cut -c1-12)"
      SAML_STS_METADATA_URL="${SAML_STS_METADATA_URL:-https://sts:8081/saml2/metadata/${SAML_STS_SP_SLUG}}"
      SAML11_METADATA_URL="${SAML11_METADATA_URL:-https://sts:8081/saml11/metadata/${SAML_STS_SP_SLUG}}"
      ;;
  esac
  export SAML_STS_METADATA_URL
  # And SAML **1.1**, which that service also answers. Same slug, a different
  # document — /saml11/metadata publishes an IDPSSODescriptor whose
  # protocolSupportEnumeration names the 1.1 protocol and whose endpoints carry
  # the two browser PROFILE URIs plus Shibboleth's request one — and a SEPARATE
  # variable rather than a path substitution, because a relying party that
  # trusts a service for one version and not the other is the ordinary case.
  #
  # This is the ONE browser-SSO profile here with no Keycloak half: Keycloak
  # dropped SAML 1.1 years ago, so unsetting this skips the whole of it rather
  # than falling back to a second identity provider.
  export SAML11_METADATA_URL
  # RFC 9700 (OAuth 2.0 Security BCP): the compliant half of the OAuth2/OIDC
  # matrix, and it is a TRUST REALM on the mock above rather than a second one.
  #
  # It used to be a container of its own (`sts-rfc9700`, deleted from
  # docker-compose-run-tests.yml) because `oauth2.rfc9700` derives `global.https`
  # in that service and one process could not bind its main port two ways. That
  # flag is now the one setting there marked `realmRuntime` — restart-only for
  # the PROCESS, settable on a REALM, because a realm binds no socket — so the
  # same instance answers permissively at /oauth2/authorize for the twelve
  # permissive jobs and enforces the BCP at /realm/rfc9700/oauth2/authorize for
  # these five, each with its own issuer, signing key, codes and tokens.
  #
  # THE SCHEME IS THE PART THAT MOVED TO THE PROCESS: a realm cannot bind one,
  # and this pass is only honest over TLS, so STS_HTTPS=true is set on the `sts`
  # service and every STS URL above is https.
  #
  # Same DNS rule as the three above, and it is browser-facing for the same
  # reason: the page navigates to the authorization endpoint. Unset elsewhere,
  # so run-report.js skips the five RFC 9700 jobs rather than pointing them at
  # something that is not in that mode — which would pass while proving nothing.
  #
  # The realm is created below, once, after the certificate is trusted; it is
  # held in memory by a service that persists nothing, so there is nowhere to
  # declare it and nothing to declare it in.
  # THE REDIRECT URI THOSE JOBS SEND, and it is loopback ON PURPOSE.
  #
  # RFC 9700 requirement 1.3 (RFC 8252's loopback exception) is that a
  # redirect_uri is https, or http on 127.0.0.1 / [::1] / localhost. The
  # debugger enforces it in mode and refuses to send anything else — so on THIS
  # stack, where the pages are served from the plain-http name
  # http://client:3000, the client correctly refused every authorization
  # request and the three flow jobs failed at a sign-in screen that never
  # appeared. The product was right; the address was wrong.
  #
  # So the callback alone moves to loopback, and rfc9700_flows.js gives Chrome
  # `--host-resolver-rules=MAP localhost:3000 client:3000` so the browser can
  # actually reach it. That hop is stateless — /callback reads nothing and 303s
  # to appconfig.uiUrl, which is http://client:3000 — so every page the test
  # drives, and the transaction state in that origin's localStorage, stay
  # exactly where they were. It is also what a real user does: the debugger's
  # own callback IS http://localhost:3000/callback, which is the case
  # requirement 1.3 exists to permit.
  #
  # Unset everywhere else: a host run is already on localhost, and a deployed
  # target is https, so both satisfy 1.3 with their own /callback and the test
  # defaults to it.
  case "${DEBUGGER_BASE_URL}" in
    http://client:*)
      RFC9700_REDIRECT_URI="${RFC9700_REDIRECT_URI:-http://localhost:3000/callback}"
      ;;
  esac
  export RFC9700_REDIRECT_URI
  # The same mock STS hosts the TLS / mutual-TLS endpoint the PKI page presents
  # a client certificate to. This one is NOT browser-facing — the api opens the
  # socket, and this test talks to the plain HTTP port itself to configure the
  # far end's truststore — so the only requirement is that the name resolve in
  # BOTH this container and the api's, which the compose name does on this
  # stack and nowhere else. Unset elsewhere, so run-report.js skips that job
  # rather than pointing a deployed api at a host on somebody's laptop.
  case "${DEBUGGER_BASE_URL}" in
    http://client:*)
      STS_TLS_URL="${STS_TLS_URL:-https://sts:8081}"
      ;;
  esac
  export STS_TLS_URL
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

  # ------------------------------------------------------------------------
  # THE MOCK STS'S CERTIFICATE, AND THEN ITS RFC 9700 REALM.
  #
  # Both are done HERE rather than in a compose file because both need the
  # service to be answering, and neither can be declared anywhere: the
  # certificate is self-signed and regenerated on every start of that service,
  # and the realm is held in memory by a service that persists nothing.
  # compose's depends_on has already waited for its healthcheck, so this is the
  # first moment either exists.
  #
  # trustStsCertificate() installs the certificate for node
  # (NODE_EXTRA_CA_CERTS, inherited by every job run-report.js spawns) and for
  # Chrome (STS_SPKI_PIN, which browser_flags.js turns into an exact key pin).
  # Neither is fatal: a job that meets an untrusted certificate says so in its
  # own message, and one that finds no compliant realm is not scheduled at all.
  #
  # ONLY ON THE CONTAINERIZED STACK, the same condition as every STS URL above:
  # a deployed target's mock is somebody else's and this container has no
  # business reconfiguring it.
  # ------------------------------------------------------------------------
  case "${DEBUGGER_BASE_URL}" in
    http://client:*)
      trustStsCertificate https://sts:8081 || true
      if configureStsRfc9700Realm https://sts:8081;
      then
        RFC9700_STS_URL="${RFC9700_STS_URL:-https://sts:8081/realm/rfc9700}"
        export RFC9700_STS_URL
      else
        echo "The mock STS has no RFC 9700 trust realm, so the five RFC 9700"
        echo "flow jobs will be SKIPPED. The likeliest cause is an sts/"
        echo "submodule older than \`realmRuntime\` on oauth2.rfc9700 — before"
        echo "that the mode could only be given to a whole process, which is"
        echo "what the deleted sts-rfc9700 container was for. See"
        echo "docs/rfc9700.md. (tests/rfc9700_client.js is unaffected — it"
        echo "needs no service at all and runs either way.)"
      fi
      ;;
  esac

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
    # -k: that URL is https now (the mock binds its main port as TLS — see
    # STS_HTTPS on the `sts` service), on a certificate regenerated every start.
    # This loop asks whether anything is ANSWERING, which is a question about a
    # socket; whether the certificate is trusted is settled once, by
    # trustStsCertificate() in init(), for the jobs that actually verify.
    code=$(curl -s -k -o /dev/null -w '%{http_code}' "${WSTRUST_STS_URL}" || true)
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
