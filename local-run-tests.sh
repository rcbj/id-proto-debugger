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
#   --saml-only[=IDP]
#                Just the SAML 2.0 Web Browser SSO jobs — SSO over all three
#                bindings plus Single Logout — against the Keycloak realm, the
#                mock STS, or both (default), and against the mock the SAML 1.1
#                browser profiles as well. The mock needs nothing
#                provisioned and starts in seconds, so --saml-only=sts is the
#                fastest loop.
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
#   --delegation-only
#                Bring up ONLY what the three-tier delegation chain needs (api,
#                client and the mock STS) and run that one test: an OIDC
#                sign-in, then two RFC 8693 hops made as two further clients.
#                A ~1-minute loop instead of the whole suite, and it leaves the
#                DELEGATION MAP behind as SVG files — which is the only way to
#                see that picture at all, since the mock's register is in
#                memory and dies with the container.
#   --federation-only[=single|chain|both|matrix|matrix:<app>/<fed>/<mech>]
#                Bring up ONLY what the federated sign-ins need (client and the
#                mock STS) and run them. `single` is two TRUST REALMS of the one
#                mock — an OIDC application in the first, a SAML 2.0 identity
#                provider in the second. `chain` is THREE, where the middle one
#                answers the SAML 2.0 request by federating onward over
#                WS-Federation instead of asking for a password: an identity
#                BRIDGE, and the only case that exercises fedAuthnMechanism.
#                `both` is the default. `matrix` is the whole GRID — every
#                combination of the two protocol layers and of how the far end
#                authenticates, forty-nine points in its own pair of realms —
#                and `matrix:<app>/<fed>/<mech>` is one point of it. A ~1-minute loop instead of the whole
#                suite. It leaves the realms — and everything they recorded —
#                behind on a running stack, which is the point: /admin on any
#                of them is where the sign-in it just performed is visible.
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
# Environment:
#   STS_LOG_LEVEL   The mock STS's log level (trace|debug|info|warn|error|fatal).
#                   Unset, its appconfig file decides and that is debug — every
#                   request, response and signed artifact written down, which is
#                   what a failing test is read from. `info` trades that record
#                   for roughly twice the throughput, which is worth it when
#                   several jobs drive one instance at once. See the block in
#                   init() for the whole argument.
#
SKIP_TESTS=0
SAML_ONLY=0
# Which identity provider(s) --saml-only drives. Two of them answer the SAML 2.0
# Web Browser SSO profile now — the Keycloak realm, and the mock STS since
# 2026-08-24 — and the same jobs run against both for the reason the WS-Fed pair
# below run against both: a mock that is quietly more permissive than the real
# thing passes every test written against it alone.
SAML_ONLY_IDP=both
WSFED_ONLY=0
# Which identity provider(s) --wsfed-only drives. See docs/wsfed.md for why
# there are two and what each covers that the other cannot.
WSFED_ONLY_IDP=both
# --delegation-only: the three-tier delegation chains on their own, against the
# mock STS. There is no second identity provider to choose between here and
# there will not be one — Keycloak would need three clients, a user and a
# token-exchange permission per pair provisioned first, it has no WS-Trust
# endpoint at all, and the compliant realm refuses half of what these scenarios
# do on purpose.
DELEGATION_ONLY=0
# WHICH FAMILY, because there are two of these now and they are the same
# scenario in two protocols: one sign-in and two hops through a middle tier,
# recorded against ONE delegation model and drawn by ONE map.
#
#   oauth    tests/oauth2_delegation_chain.js — an OIDC sign-in, then two RFC
#            8693 token exchanges. The audience travels in an `aud` claim.
#   wstrust  tests/wstrust_delegation_chain.js — a SAML 2.0 HTTP-POST sign-in,
#            then two WS-Trust hops, run TWICE: once carrying <wst:OnBehalfOf>
#            and once <wst14:ActAs>. The audience travels in an assertion's
#            <saml:AudienceRestriction>, which is the same statement.
#   both     all three runs (the default). They share no name — different
#            person, different applications — so the pictures stay separate,
#            and the whole-map drawing then holds both chains, which is the
#            point of having one model for two families.
DELEGATION_ONLY_WHAT=both
# --federation-only: the federated sign-ins across trust realms of the one mock
# STS. No identity provider to choose between either, and for a sharper reason
# than the delegation chain has: the partner in these scenarios IS the mock, in
# another realm of the same process, so there is no second implementation for an
# option to select.
#
# WHAT there IS to select is the DEPTH, because there are two of these now and
# the second is not the first with a bigger number. `single` is one hop, into a
# realm that asks for a password; `chain` is two, into a realm that asks for
# nothing and federates AGAIN over a different protocol — which is the thing
# that has a name of its own, an identity BRIDGE, and the only one of the two
# that exercises fedAuthnMechanism at all. `both` is the default because they
# use disjoint realms and cost about fifteen seconds together.
FEDERATION_ONLY=0
FEDERATION_ONLY_DEPTH=both
# --krb5-real-dc: 0 = off, else the work to run against the live DC.
KRB5_REAL_DC=0
KRB5_REAL_DC_WHAT=test
SAML_SIG_VALIDATION=true

usage()
{
  cat <<USAGE
Usage: $(basename "$0") [--saml-dev] [--saml-only[=keycloak|sts|both]]
                        [--wsfed-only[=keycloak|sts|both]]
                        [--delegation-only[=oauth|wstrust|both]]
                        [--federation-only[=single|chain|both]]
                        [--krb5-real-dc[=test|capture|both]] [-h|--help]

  (default)    Build + start the stack, provision Keycloak (SAML AuthnRequest
               signature validation ENABLED), and run the full test suite.

  --saml-dev   Build + start Keycloak and the debugger (api + client), provision
               Keycloak with SAML AuthnRequest signature validation DISABLED, and
               leave the stack running WITHOUT running the tests.

  --saml-only[=IDP]
               Build + start only api, client and whichever identity provider is
               asked for, and run tests/saml_sso.js over all three bindings plus
               tests/saml_logout.js. IDP is "keycloak", "sts" or "both"
               (default).

               The two differ in what they can show. Keycloak is somebody else's
               implementation and the only interoperability evidence here, and it
               VALIDATES the AuthnRequest signature. The mock STS answers the
               HTTP Artifact binding with a real SOAP back channel, refuses a
               ProtocolBinding it does not implement by name, and needs NOTHING
               PROVISIONED — it accepts any entityID and mints a metadata
               document for anything asked for — so --saml-only=sts starts in
               seconds and is the fastest loop.

               The sts half runs SIX jobs the keycloak half cannot. Five are
               SAML 1.1 and all of them for one reason: Keycloak has
               spoken no SAML 1.1 for years. Three are tests/saml11_sso.js —
               the debugger's own SAML 1.1 service provider through its pages,
               once per binding — and one is tests/saml11_options.js, which
               asserts which SP/Request settings apply to 1.1 and which are
               switched off. The fifth is tests/sts_saml11.js, which uses no
               browser at all: it drives the mock's identity provider over HTTP
               with a relying party it writes itself, so that a shared
               misunderstanding between the two ends of the exchange cannot
               pass unnoticed.

               The SIXTH is tests/sts_saml_encryption.js and it is SAML 2.0:
               the mock encrypts and this half is where that is exercised.
               It writes its own service provider — its own key pair, its own
               XML Encryption decryptor — and is mostly negatives: an altered
               ciphertext, an EncryptedID encrypted to another key, and a
               decrypted fragment that must carry its own namespace. There is
               no keycloak half because tests/saml_encrypted_sso.js already
               drives that direction, in a browser, against Keycloak.

  --wsfed-only[=IDP]
               Build + start only api, client, the mock STS and the WS-Fed
               Keycloak side-car, provision the wsfed realm/client/user, and run
               just tests/wsfed_sso.js against BOTH identity providers. Use this
               to work on the WS-Federation test without waiting for the full
               suite. IDP is "keycloak", "sts" or "both" (default) — the mock
               starts in seconds and the WildFly side-car does not, so
               --wsfed-only=sts is the fastest loop.

  --delegation-only[=oauth|wstrust|both]
               Build + start only api, client and the mock STS, and run the
               three-tier delegation chains. WHICH is:

               oauth    tests/oauth2_delegation_chain.js. bob_end_user signs in
                        to webapp1 through the OIDC Authorization Code flow,
                        apigw1 exchanges that token for one aimed at esb1, and
                        esb1 exchanges again for sp1 — each hop as its own
                        client, out of a debugger workflow of its own. The
                        audience travels in an `aud` claim.
               wstrust  tests/wstrust_delegation_chain.js, TWICE. carol_end_user
                        signs in to portal1 over SAML 2.0 (HTTP-POST binding),
                        portal1 exchanges that assertion at the STS for one
                        addressed to https://esb.example.com, and esb exchanges
                        again for https://soap1.example.com. The audience
                        travels in the assertion's <saml:AudienceRestriction>,
                        which says exactly what an `aud` claim says. The first
                        run carries <wst:OnBehalfOf> (impersonation), the second
                        <wst14:ActAs> (composite delegation).
               both     all three (the default).

               They leave the DELEGATION MAP behind, as SVG. That register lives
               in the mock's memory and dies with the container, so the picture
               of a chain can only be drawn while the run is happening; the
               documents are written to tests/report/delegation/ (or to
               DELEGATION_ARTIFACT_DIR). There is no second identity provider
               to choose between: see the note beside DELEGATION_ONLY above.

  --federation-only[=single|chain|both|matrix|matrix:<app>/<fed>/<mech>]
               Build + start only client and the mock STS, and run the
               federated sign-ins. The realms are logical identity services in
               one process, told apart by a path prefix. WHICH is one of:

                 single  tests/federation_sso.js — ONE hop. An application in
                         federation-realm-1, federated over SAML 2.0 to
                         federation-realm-2, where a password is typed.
                 chain   tests/federation_chain_sso.js — TWO hops and three
                         protocols. An application in federation-realm-3,
                         federated over SAML 2.0 to federation-realm-4, which
                         asks for nothing itself and federates AGAIN over
                         WS-Federation to federation-realm-5, where a password
                         is typed. Realm 4 is a pure identity BRIDGE, and the
                         attribute that makes it one — fedAuthnMechanism on its
                         identity-provider-side relationship — is what this
                         case exists to exercise.
                 choice  tests/federation_choice_sso.js — ONE hop and TWO
                         partners. An application in federation-choice-1 named
                         on BOTH a SAML 2.0 and an OpenID Connect relationship
                         to federation-choice-2, so the mock draws its chooser
                         at /authn/select-idp instead of redirecting. It signs
                         in twice, once through each button, because what it
                         proves is that the CHOICE was honoured rather than a
                         partner picked — which is arithmetic on the two
                         relationships' counters.
                 both    the default: single, chain and choice. Disjoint
                         realms, about twenty-five seconds.
                 matrix  tests/federation_matrix_sso.js, forty-nine times —
                         every combination of five application protocols (oidc,
                         oauth2, saml2, saml11, wsfed), five federation
                         protocols (the same five) and two authentication
                         mechanisms at the far end (password, webauthn), less
                         the one `single` already drives. Its own pair of realms
                         (federation-matrix-1 and -2), so it shares nothing with
                         the two above. MINUTES rather than seconds: the suite
                         runs these as forty-nine pooled jobs and this loop runs
                         them in order, for a live stack to look at afterwards.
                 matrix:<app>/<fed>/<mech>
                         one point of that grid, which is how to reproduce a
                         failing combination — add -b to watch it.

               It leaves the stack up with every realm configured, which is the
               point of the option: /realm/<id>/admin/federation shows the
               relationships and their counters, and /admin/users on each realm
               shows the same person from each end of the chain. The realms live
               in the mock's memory and go with the container.

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
    --saml-only) SAML_ONLY=1 ;;
    --saml-only=*) SAML_ONLY=1; SAML_ONLY_IDP="${1#*=}" ;;
    --wsfed-only) WSFED_ONLY=1 ;;
    --wsfed-only=*) WSFED_ONLY=1; WSFED_ONLY_IDP="${1#*=}" ;;
    --delegation-only) DELEGATION_ONLY=1 ;;
    --delegation-only=*) DELEGATION_ONLY=1
                         DELEGATION_ONLY_WHAT="${1#*=}" ;;
    --federation-only) FEDERATION_ONLY=1 ;;
    --federation-only=*) FEDERATION_ONLY=1
                         FEDERATION_ONLY_DEPTH="${1#*=}" ;;
    --krb5-real-dc) KRB5_REAL_DC=1 ;;
    --krb5-real-dc=*) KRB5_REAL_DC=1; KRB5_REAL_DC_WHAT="${1#*=}" ;;
    -h|--help)  usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
  shift
done
case "${SAML_ONLY_IDP}" in
  keycloak|sts|both) ;;
  *) echo "Unknown --saml-only identity provider: ${SAML_ONLY_IDP}" >&2
     usage; exit 1 ;;
esac
case "${DELEGATION_ONLY_WHAT}" in
  oauth|wstrust|both) ;;
  *) echo "Unknown --delegation-only family: ${DELEGATION_ONLY_WHAT}" >&2
     usage; exit 1 ;;
esac
case "${WSFED_ONLY_IDP}" in
  keycloak|sts|both) ;;
  *) echo "Unknown --wsfed-only identity provider: ${WSFED_ONLY_IDP}" >&2
     usage; exit 1 ;;
esac
case "${FEDERATION_ONLY_DEPTH}" in
  single|chain|choice|both|matrix|matrix:*/*/*) ;;
  *) echo "Unknown --federation-only depth: ${FEDERATION_ONLY_DEPTH}" >&2
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
if [ "${SAML_ONLY}" = "1" ] && { [ "${WSFED_ONLY}" = "1" ] || [ "${KRB5_REAL_DC}" = "1" ]; };
then
  echo "--saml-only, --wsfed-only and --krb5-real-dc each run one thing; pick one." >&2
  exit 1
fi
if [ "${DELEGATION_ONLY}" = "1" ] && { [ "${SAML_ONLY}" = "1" ] ||
     [ "${WSFED_ONLY}" = "1" ] || [ "${KRB5_REAL_DC}" = "1" ]; };
then
  echo "--delegation-only, --saml-only, --wsfed-only and --krb5-real-dc each" \
       "run one thing; pick one." >&2
  exit 1
fi
if [ "${FEDERATION_ONLY}" = "1" ] && { [ "${SAML_ONLY}" = "1" ] ||
     [ "${WSFED_ONLY}" = "1" ] || [ "${DELEGATION_ONLY}" = "1" ] ||
     [ "${KRB5_REAL_DC}" = "1" ]; };
then
  echo "--federation-only, --delegation-only, --saml-only, --wsfed-only and" \
       "--krb5-real-dc each run one thing; pick one." >&2
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
  #
  # **https**, AND SO IS EVERY OTHER STS URL BELOW. That mock binds its main
  # port as TLS on this stack (STS_HTTPS=true on the `sts` service), because
  # the RFC 9700 pass is a TRUST REALM on this one instance now rather than a
  # second container — a realm binds no socket of its own — and that pass is
  # only honest over TLS. The certificate is self-signed and regenerated on
  # every start, which trustStsCertificate() deals with once the service
  # answers; nothing here needs an anchor in order to build a URL.
  WSTRUST_STS_URL=https://localhost:8081/sts
  export WSTRUST_STS_URL
  # The same mock STS also answers WS-FEDERATION, so the WS-Fed jobs run against
  # it as well as against the Keycloak side-car below. Kept separate from
  # WSTRUST_STS_URL, which may be pointed at a real Apache CXF STS that has no
  # passive endpoint at all.
  WSFED_STS_METADATA_URL=https://localhost:8081/FederationMetadata/2007-06/FederationMetadata.xml
  export WSFED_STS_METADATA_URL
  # And the same mock STS answers SAML 2.0 WEB BROWSER SSO since 2026-08-24, so
  # the SAML jobs can be run against it as well as against the Keycloak realm.
  #
  # THE PATH SEGMENT IS A DIGEST AND IT IS COMPUTED HERE RATHER THAN GUESSED.
  # That service publishes metadata PER SERVICE PROVIDER — a distinct identity
  # provider entityID and its own SSO, SLO and artifact endpoints, the way Okta
  # and Ping do — and the segment is the entityID itself where that is safe in a
  # URL path and `app-` plus twelve hex characters of its SHA-256 where it is
  # not. Ours is a URL, so it is the digest. The unscoped /saml2/metadata would
  # also work and is deliberately not what is used: the per-application document
  # is the feature, and a test configured from the generic one would never touch
  # it.
  #
  # It does NOT have to exist first. That service accepts any entityID and mints
  # the document on the ask, which is why there is no provisioning step for it
  # anywhere in THIS file. Since 2026-08-27 the TEST registers it — the service
  # provider goes into the mock's application registry, with its assertion
  # consumer service and this run's signing certificate, before the first
  # AuthnRequest — because an entry created by a sighting knows the entityID and
  # nothing else. It is done there rather than here so that what is registered
  # is what the page is about to send; see tests/sts_applications.js.
  SAML_STS_SP_SLUG="app-$(printf '%s' "${SAML_SP_ENTITY_ID}" | sha256sum | cut -c1-12)"
  SAML_STS_METADATA_URL="https://localhost:8081/saml2/metadata/${SAML_STS_SP_SLUG}"
  export SAML_STS_SP_SLUG SAML_STS_METADATA_URL
  # And SAML **1.1**, which that service also answers and which is the ONE
  # profile here with no Keycloak half — it dropped SAML 1.1 years ago. Same
  # slug, a different document: /saml11/metadata publishes an IDPSSODescriptor
  # whose protocolSupportEnumeration names the 1.1 protocol and whose endpoints
  # are bound with the two browser PROFILE URIs plus Shibboleth's request one.
  # A SEPARATE variable from the 2.0 URL rather than a path substitution,
  # because a relying party that trusts this service for one version and not the
  # other is the ordinary case, and the page reads the version off whichever
  # document it was given.
  SAML11_METADATA_URL="https://localhost:8081/saml11/metadata/${SAML_STS_SP_SLUG}"
  export SAML11_METADATA_URL
  # And it hosts the TLS / mutual-TLS endpoint the PKI page presents a client
  # certificate to (its two HTTPS listeners, 8443 and 9443). This is its MAIN
  # port, which is https here too: the test configures the far end's truststore
  # over it and reads
  # the listeners' ports from the service rather than carrying a copy of them.
  #
  # Separate from WSTRUST_STS_URL for the same reason WSFED_STS_METADATA_URL is
  # — that one may be pointed at a real Apache CXF STS, which has no endpoint of
  # this kind — and it must be reachable by the API as well as by the test,
  # since the api is what opens the socket. Both are on this host here.
  STS_TLS_URL=https://localhost:8081
  export STS_TLS_URL
  # RFC 9700 (OAuth 2.0 Security BCP): the compliant half of the OAuth2/OIDC
  # matrix, which is a TRUST REALM on the mock above rather than a second mock.
  #
  # It used to be a second INSTANCE — `sts-rfc9700` in local-tests.yml, on 8091
  # with all seven of its listeners moved off the first one's — because
  # `oauth2.rfc9700` derives `global.https` in that service and one process
  # could not bind its main port two ways. That flag is now the one setting
  # there marked `realmRuntime`: restart-only for the PROCESS, settable on a
  # REALM, because a realm binds no socket. So one instance serves both passes,
  # the twelve permissive jobs at /oauth2/authorize and the five compliant ones
  # at /realm/rfc9700/oauth2/authorize, each with its own issuer, signing key,
  # codes and tokens.
  #
  # THE SCHEME IS THE PART THAT MOVED TO THE PROCESS. A realm cannot bind one,
  # and the compliant pass is only honest over TLS — requirement 8.1 is that
  # every configured endpoint is https, and the debugger enforces it — so
  # STS_HTTPS=true is set on the `sts` service and every STS URL above is
  # https. That is the whole cost of dropping the second container.
  #
  # THE URL IS NOT SET HERE. The realm is held in memory by a service that
  # persists nothing, so it does not exist until something creates it — which
  # is configureStsRfc9700Realm(), after the stack is up. That call is also the
  # capability probe: it replaced a test for `oauth2_bcp.js` in the sts/
  # submodule, which was a PATH test and silently took its else branch when
  # mock-sts reorganised its directories, printing a confident and wrong
  # explanation while quietly dropping five jobs. Asking the running service
  # answers the same question about the code that is actually running — and
  # answers it about realms too, which a file probe could not have seen at all.
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
  #   STS_LOG_LEVEL=info ./local-run-tests.sh
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
  EXTENSION_AUTOARM_ORIGINS="https://localhost:8081" \
  buildBrowserExtension "${CURRENT_DIR}"   # the browser is on the host
  check_return_code $?
  NODEJS_BASE_DIR=tests
}

prepTestEnv()
{
  npm install --prefix tests
  # And the mock STS's own dependencies, because four tests run on the HOST and
  # load sts/common/vendored/bbs2023.js from the submodule in place:
  # bbs2023_cryptosuite.js,
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
  # And the mock STS, for the same reason and one more.
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
  # answering. This names the port and says what it found — including the case
  # this argument's `scheme` argument exists for, which is now the ORDINARY
  # arrangement rather than the exception: this instance is https, so anything
  # answering plain http on 8081 is somebody else's mock.
  requireStsReachable https https://localhost:8081/healthcheck sts
  check_return_code $?

  # ------------------------------------------------------------------------
  # THE CERTIFICATE, AND THEN THE RFC 9700 REALM. Both need the service to be
  # ANSWERING, which is why neither is in init() and both are here.
  #
  # The certificate first, because it is what everything downstream verifies
  # against — including the two curl calls the realm step makes, which do not
  # need it (they pass -k) but every node test and every browser after them
  # does. It is self-signed and regenerated on every start of that service, so
  # this is the earliest moment it exists.
  #
  # NEITHER IS FATAL, and that is deliberate in different ways. Without the
  # certificate the STS-backed jobs fail with their own messages, which name
  # the certificate; halting here would replace 180 results with none. Without
  # the realm the five RFC 9700 flow jobs are SKIPPED — RFC9700_STS_URL is left
  # unset and run-report.js does not schedule them — which is this project's
  # preferred failure for a capability the mock may not have: a stated reason
  # and the other 180 still run. The jobs themselves also refuse a permissive
  # server by name, so a realm that half-worked cannot pass quietly.
  # ------------------------------------------------------------------------
  trustStsCertificate https://localhost:8081 || true
  if configureStsRfc9700Realm https://localhost:8081;
  then
    RFC9700_STS_URL=https://localhost:8081/realm/rfc9700
    export RFC9700_STS_URL
  else
    echo "The mock STS has no RFC 9700 trust realm, so the five RFC 9700 flow"
    echo "jobs will be SKIPPED. The likeliest cause is an sts/ submodule older"
    echo "than \`realmRuntime\` on oauth2.rfc9700 — before that the mode could"
    echo "only be given to a whole process, which is what the deleted"
    echo "sts-rfc9700 container was for. See docs/rfc9700.md."
    echo "(tests/rfc9700_client.js is unaffected — it needs no service at all"
    echo "and runs either way.)"
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

# ---------------------------------------------------------------------------
# --saml-only: the SAML 2.0 Web Browser SSO jobs, against one identity provider
# or both.
#
# Same shape as --wsfed-only below and for the same reason. What each side is
# for:
#
#   keycloak  somebody else's implementation, and the only interoperability
#             evidence here. It VALIDATES the AuthnRequest signature against the
#             certificate configureKeycloak() registered for this run, so a
#             request the debugger builds sloppily fails THERE and passes at the
#             mock.
#   sts       the mock STS (sts/saml/saml2_sso.js). It answers the HTTP Artifact
#             binding with a real SOAP back channel, refuses a ProtocolBinding it
#             does not implement BY NAME, answers IsPassive with NoPassive rather
#             than a screen — and needs nothing provisioned, because it accepts
#             any entityID and mints a metadata document for anything asked for.
#
# The mock is deliberately more permissive in exactly one way that matters here:
# it verifies no request signature. So the pair answer different questions, which
# is why both run rather than one replacing the other.
# ---------------------------------------------------------------------------

# One SAML job against the IdP described by the environment the caller sets.
# Invoked exactly as tests/run-report.js does it: from the repository root, with
# CONFIG_FILE relative to the test file.
runSamlAgainst()
{
  local label="$1"
  local script="$2"
  echo "Entering runSamlAgainst(). label=${label} script=${script}"
  echo "=== ${script} against ${label} (binding=${SAML_BINDING:-redirect}) ==="
  echo "SAML_IDP=${SAML_IDP}  SAML_METADATA_URL=${SAML_METADATA_URL}"
  echo "SAML_SP_ENTITY_ID=${SAML_SP_ENTITY_ID}  SAML_USER=${SAML_USER}"
  node "${NODEJS_BASE_DIR}/${script}" --url "${DEBUGGER_BASE_URL}"
  local rc=$?
  echo "Leaving runSamlAgainst(). label=${label} rc=${rc}"
  return ${rc}
}

# Every SAML job for one identity provider: SSO over each of the three bindings,
# then Single Logout. The bindings are run in one subshell each so that a failure
# in one names its own binding rather than leaving the next to inherit its
# environment — the trap runWsfedOnly() writes down at length.
runSamlSuiteAgainst()
{
  local label="$1"
  echo "Entering runSamlSuiteAgainst(). label=${label}"
  local rc=0
  local failures=""
  local binding
  for binding in redirect post artifact;
  do
    (
      export SAML_BINDING="${binding}"
      runSamlAgainst "${label}" saml_sso.js
    )
    if [ $? -ne 0 ]; then rc=1; failures="${failures} sso/${binding}"; fi
  done
  # Single Logout on the redirect binding only. The test drives the binding
  # SELECTOR, which decides which SLO endpoint the LogoutRequest goes to, and
  # both identity providers publish the same endpoint for both bindings — so a
  # second pass would exercise the debugger's own POST form and nothing else
  # about either IdP.
  (
    export SAML_BINDING=redirect
    runSamlAgainst "${label}" saml_logout.js
  )
  if [ $? -ne 0 ]; then rc=1; failures="${failures} logout"; fi
  if [ ${rc} -ne 0 ];
  then
    echo "SAML failed against ${label}:${failures}" >&2
  fi
  echo "Leaving runSamlSuiteAgainst(). label=${label} rc=${rc}"
  return ${rc}
}

# SAML 1.1, which only the mock answers.
#
# NOT part of runSamlSuiteAgainst(), because that function is run once per
# identity provider and this profile has exactly one: Keycloak has spoken no
# SAML 1.1 for years, so a second pass would have nothing to run against. The
# three binding jobs drive the debugger's pages exactly as saml_sso.js does;
# saml11_options.js needs no identity provider at all; and sts_saml11.js needs
# no browser, because it writes its own relying party.
#
# Nothing has to be provisioned: the mock accepts any relying party identifier,
# creates the application entry on sight, and mints a metadata document for
# anything asked for.
runSaml11Suite()
{
  echo "Entering runSaml11Suite()."
  # Exported HERE rather than inherited: runSamlOnly() sets these inside the
  # subshell it runs the SAML 2.0 suite in, so at this level they are unset and
  # the 1.1 jobs would send an empty providerId — which the mock answers by
  # GUESSING the audience from the TARGET's origin, and the audience assertion
  # then fails naming a value nobody typed.
  export SAML_SP_ENTITY_ID
  export SAML_USER="${SAML_STS_USER:-${SAML_USER:-saml}}"
  echo "SAML11_METADATA_URL=${SAML11_METADATA_URL}"
  echo "SAML_SP_ENTITY_ID=${SAML_SP_ENTITY_ID}  SAML_USER=${SAML_USER}"
  local rc=0
  local failures=""
  local binding
  for binding in redirect post artifact;
  do
    (
      export SAML_BINDING="${binding}"
      export SAML_METADATA_URL=""
      runSamlAgainst "the mock STS (SAML 1.1)" saml11_sso.js
    )
    if [ $? -ne 0 ]; then rc=1; failures="${failures} sso11/${binding}"; fi
  done
  (
    runSamlAgainst "the mock STS (SAML 1.1)" saml11_options.js
  )
  if [ $? -ne 0 ]; then rc=1; failures="${failures} options11"; fi
  (
    echo "Entering runStsSaml11(). WSTRUST_STS_URL=${WSTRUST_STS_URL}"
    node "${NODEJS_BASE_DIR}/sts_saml11.js" --url "${DEBUGGER_BASE_URL}"
    # The subshell's status is the status of its LAST command, so the rc has to
    # be carried out deliberately — an echo after the node call would otherwise
    # make every run of it succeed. runSamlAgainst() does the same.
    sts_saml11_rc=$?
    echo "Leaving runStsSaml11(). rc=${sts_saml11_rc}"
    exit ${sts_saml11_rc}
  )
  if [ $? -ne 0 ]; then rc=1; failures="${failures} sts-saml11"; fi
  if [ ${rc} -ne 0 ];
  then
    echo "SAML 1.1 failed:${failures}" >&2
  fi
  echo "Leaving runSaml11Suite(). rc=${rc}"
  return ${rc}
}

runSamlOnly()
{
  echo "Entering runSamlOnly(). idp=${SAML_ONLY_IDP}"
  local services="api client"
  case "${SAML_ONLY_IDP}" in
    keycloak) services="${services} keycloak" ;;
    sts)      services="${services} sts" ;;
    both)     services="${services} keycloak sts" ;;
  esac
  CONFIG_FILE=./env/local.js docker_compose -f local-tests.yml build ${services}
  check_return_code $?
  CONFIG_FILE=./env/local.js docker_compose -f local-tests.yml up -d ${services}
  check_return_code $?
  if [ "${SAML_ONLY_IDP}" != "sts" ];
  then
    echo "Waiting for Keycloak ..."
    sleep 30
  else
    echo "Waiting for the mock STS ..."
    sleep 5
  fi
  CONFIG_FILE=./env/local.js verifyComposeServicesRunning local-tests.yml

  # Provision the realm only when this loop is driving it. There is deliberately
  # no equivalent for the mock: it accepts any entityID, needs no client, no
  # user and no certificate, and creates the application entry itself from the
  # first valid AuthnRequest.
  if [ "${SAML_ONLY_IDP}" != "keycloak" ];
  then
    CONFIG_FILE=./env/local.js requireComposeServiceRunning local-tests.yml sts
    check_return_code $?
    # The mock serves https on a certificate it regenerated when this `up -d`
    # started it, so nothing can have an anchor for it yet. Every job below
    # verifies — the node ones through NODE_EXTRA_CA_CERTS, the browser ones
    # through an SPKI pin — so this has to happen before any of them run. Not
    # fatal: a job that meets an untrusted certificate says so itself, and its
    # message names the certificate.
    trustStsCertificate https://localhost:8081 || true
  fi
  if [ "${SAML_ONLY_IDP}" != "sts" ];
  then
    CONFIG_FILE=./env/local.js requireComposeServiceRunning local-tests.yml keycloak
    check_return_code $?
    # Delete any pre-existing debugger-testing realm first, so provisioning is
    # idempotent. Nothing here tears the local stack down between runs — the
    # `up -d` in startDocker() reuses a running keycloak and its postgres
    # volume — so a realm left by the previous run survives, and every POST
    # below then 409s. The client and scope lookups still find the STALE
    # objects and only the user creation shows it, as a blank USER_ID and
    # "Required variable is blank." naming nothing. See common.sh.
    resetKeycloakRealm
    check_return_code $?
    # No compose-file argument: configureKeycloak() takes none, unlike
    # configureKeycloakWsfed(). It is what exports SAML_METADATA_URL and
    # SAML_USER for the realm, so the keycloak branch below reads them from
    # here rather than from init().
    configureKeycloak
    check_return_code $?
  fi

  export DEBUGGER_BASE_URL CONFIG_FILE KEYCLOAK_BASE_URL
  local rc=0
  local failures=""

  if [ "${SAML_ONLY_IDP}" != "sts" ];
  then
    (
      export SAML_IDP=keycloak
      export SAML_METADATA_URL="${SAML_METADATA_URL}"
      export SAML_SP_ENTITY_ID SAML_USER
      runSamlSuiteAgainst "the Keycloak realm"
    )
    if [ $? -ne 0 ]; then rc=1; failures="${failures} Keycloak"; fi
  fi

  if [ "${SAML_ONLY_IDP}" != "keycloak" ];
  then
    (
      export SAML_IDP=sts
      export SAML_METADATA_URL="${SAML_STS_METADATA_URL}"
      export SAML_SP_ENTITY_ID
      export SAML_USER="${SAML_STS_USER:-saml}"
      declareStsLogoutService
      runSamlSuiteAgainst "the mock STS"
    )
    if [ $? -ne 0 ]; then rc=1; failures="${failures} mock-STS"; fi
    runSaml11Suite
    if [ $? -ne 0 ]; then rc=1; failures="${failures} mock-STS/saml11"; fi
  fi

  if [ ${rc} -ne 0 ];
  then
    echo "SAML failed against:${failures}" >&2
  fi
  echo "Leaving runSamlOnly(). rc=${rc}"
  return ${rc}
}

# WHERE THE MOCK SENDS ITS LogoutResponse, declared rather than guessed.
#
# A <samlp:LogoutRequest> carries no return address — only SP metadata has one,
# and that service publishes metadata and does not consume it. So with nothing
# declared it falls back to the assertion consumer service URL the service
# provider last used, which is a GUESS, is logged as one, and happens to be right
# here because the api's /samlacs and /samlslo are the same handler.
#
# Declaring it makes the run exercise the DECLARED path, which is the one a real
# deployment uses; leaving it undeclared would mean the fallback is what is
# tested and nothing would say so. It goes through /admin-api, which is the
# management API and is deliberately NOT behind that console's gate.
#
# Failures here are reported and NOT fatal: the fallback is correct for this
# stack, so a mock started without the API reachable should still run the test
# rather than refuse to.
declareStsLogoutService()
{
  echo "Entering declareStsLogoutService()."
  local api="https://localhost:8081/admin-api/saml2"
  local slo="${SAML_STS_SLO_URL:-http://localhost:4000/samlslo}"
  curl -sS -o /dev/null -X POST "${api}/register" \
    -H 'Content-Type: application/json' \
    -d "{\"sp\":\"${SAML_SP_ENTITY_ID}\"}" \
    || echo "NOTE: could not register the service provider on the mock STS; it" \
            "will be created by the first AuthnRequest anyway." >&2
  curl -sS -o /dev/null -X POST "${api}/set-logout-service" \
    -H 'Content-Type: application/json' \
    -d "{\"sp\":\"${SAML_SP_ENTITY_ID}\",\"value\":\"${slo}\"}" \
    || echo "NOTE: could not declare the SingleLogoutService on the mock STS." \
            "The LogoutResponse will go to the assertion consumer service URL" \
            "instead, which is a guess that is right for this stack." >&2
  echo "Leaving declareStsLogoutService(). slo=${slo}"
}

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

# ---------------------------------------------------------------------------
# --delegation-only: the three-tier delegation chain on its own, and the only
# way to LOOK at the picture it makes.
#
# The mock STS keeps its delegation register in memory, so /admin/delegation/map
# can only draw this chain while the container that recorded it is still
# running. The full suite takes twenty minutes and then tears the stack down,
# which is a poor loop for a job whose product is a drawing. This brings up the
# three services the test needs, runs it, and says where the SVGs landed.
#
# One identity provider and no choice of one: see the note beside
# DELEGATION_ONLY at the top of this file.
# ---------------------------------------------------------------------------
runDelegationOnly()
{
  echo "Entering runDelegationOnly()."
  local services="api client sts"
  CONFIG_FILE=./env/local.js docker_compose -f local-tests.yml build ${services}
  check_return_code $?
  CONFIG_FILE=./env/local.js docker_compose -f local-tests.yml up -d ${services}
  check_return_code $?
  echo "Waiting for the mock STS ..."
  sleep 5
  CONFIG_FILE=./env/local.js verifyComposeServicesRunning local-tests.yml
  CONFIG_FILE=./env/local.js requireComposeServiceRunning local-tests.yml sts
  check_return_code $?
  # The mock serves https on a certificate it regenerated when this `up -d`
  # started it, so nothing can have an anchor for it yet. This job verifies in
  # node (NODE_EXTRA_CA_CERTS, for the admin API and the introspection call) and
  # in Chrome (an SPKI pin, for the browser-direct token requests), so it has to
  # happen before the test runs. Not fatal: the test says so itself, and its
  # message names the certificate.
  trustStsCertificate https://localhost:8081 || true

  # Where the drawings go. Named here rather than left to the test's default so
  # that the path printed below and the path written to are the same string.
  DELEGATION_ARTIFACT_DIR="${CURRENT_DIR}/tests/report/delegation"
  export DELEGATION_ARTIFACT_DIR
  export DEBUGGER_BASE_URL CONFIG_FILE WSTRUST_STS_URL

  # The runs, in the order a reader of the map would want them: the OAuth chain
  # first because it is the one this scenario was written for, then the two
  # WS-Trust ones. A FAILURE DOES NOT STOP THE REST — each is a story of its own
  # and the register keeps whatever completed, so a run that fails the third
  # still leaves two chains to look at — and the worst return code is what this
  # function answers with.
  local rc=0
  local one=0
  if [ "${DELEGATION_ONLY_WHAT}" = "oauth" ] ||
     [ "${DELEGATION_ONLY_WHAT}" = "both" ];
  then
    echo "=== The OAuth 2.0 chain: an OIDC sign-in and two RFC 8693 hops ==="
    node "${NODEJS_BASE_DIR}/oauth2_delegation_chain.js" \
      --url "${DEBUGGER_BASE_URL}"
    one=$?
    [ ${one} -ne 0 ] && rc=${one}
  fi
  if [ "${DELEGATION_ONLY_WHAT}" = "wstrust" ] ||
     [ "${DELEGATION_ONLY_WHAT}" = "both" ];
  then
    local element
    for element in onbehalfof actas;
    do
      echo "=== The WS-Trust chain: a SAML 2.0 POST sign-in and two" \
           "${element} hops ==="
      WSTRUST_DELEGATION_ELEMENT="${element}" \
        node "${NODEJS_BASE_DIR}/wstrust_delegation_chain.js" \
          --url "${DEBUGGER_BASE_URL}"
      one=$?
      [ ${one} -ne 0 ] && rc=${one}
    done
  fi

  if [ ${rc} -eq 0 ];
  then
    echo "The delegation maps are in ${DELEGATION_ARTIFACT_DIR}:"
    ls -l "${DELEGATION_ARTIFACT_DIR}" || true
  fi
  echo "Leaving runDelegationOnly(). rc=${rc}"
  return ${rc}
}

# ---------------------------------------------------------------------------
# --federation-only: the federated sign-ins, and the fastest way to LOOK at what
# they left in the realms.
#
# TWO TESTS, and the second is not the first with a bigger number. One hop into
# a realm that asks for a password is federation; two hops, where the middle
# realm asks for nothing at all and federates onward over a DIFFERENT protocol,
# is an identity bridge — and only the second exercises fedAuthnMechanism, the
# attribute on an identity-provider-side relationship that says what this
# service does when a partner asks it to authenticate somebody. They use
# disjoint realms (1-2 and 3-4-5) precisely so that either can be run alone and
# neither asserts on the other's counters.
#
# Both identity services in this scenario are the SAME mock STS process, told
# apart by a path prefix, so this loop is two containers rather than three — and
# it needs no api at all: the Token Request is made browser-direct, and every
# configuration call goes to /admin-api over HTTP from the test itself. `api` is
# started anyway because `client` declares it in local-tests.yml and compose
# would pull it in regardless; naming it here is the honest spelling of what
# comes up.
#
# The realms are created by the TEST rather than here. A trust realm lives in
# the mock's memory and there is nowhere to declare one, so provisioning it in
# this script would only move the same management API calls somewhere the
# containerized suite could not reach them.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# --federation-only=matrix: the whole grid, one point at a time, against the
# stack runFederationOnly() has already brought up.
#
# FORTY-NINE POINTS — five application protocols by five federation protocols by
# two authentication mechanisms, less the one federation_sso.js already drives.
# The suite runs them as forty-nine POOLED jobs; this loop runs them in order,
# on one machine, which is minutes rather than seconds and is not the normal
# path. It exists for the two things the pool cannot give: a live stack with
# every combination's realm state left in it, and a way to reproduce ONE point
# with the browser visible.
#
#   ./local-run-tests.sh --federation-only=matrix
#   ./local-run-tests.sh --federation-only=matrix:wsfed/oauth2/webauthn
#
# EVERY POINT RUNS EVEN WHEN AN EARLIER ONE FAILS, and the return code is the
# worst of them. Stopping at the first would answer the least interesting
# question — a grid is run to find out WHICH combinations are broken, and
# "the third one" is not that answer.
# ---------------------------------------------------------------------------
runFederationMatrix()
{
  echo "Entering runFederationMatrix()."
  local rc=0
  local one="${FEDERATION_ONLY_DEPTH#matrix}"
  one="${one#:}"
  local apps="oidc oauth2 saml2 saml11 wsfed"
  local feds="oidc oauth2 saml2 saml11 wsfed"
  local mechs="password webauthn"
  local ran=0
  local failed=""
  local app fed mech point
  for app in ${apps};
  do
    for fed in ${feds};
    do
      for mech in ${mechs};
      do
        point="${app}/${fed}/${mech}"
        # The one point federation_sso.js drives. Skipped here for the reason
        # tests/run-report.js skips it: running it twice buys nothing and puts
        # a second job's arithmetic in the same realms.
        if [ "${point}" = "oidc/saml2/password" ]; then continue; fi
        if [ -n "${one}" ] && [ "${point}" != "${one}" ]; then continue; fi
        echo "--- federation grid: ${point} ---"
        FEDERATION_APP_PROTOCOL="${app}" \
        FEDERATION_FED_PROTOCOL="${fed}" \
        FEDERATION_MECHANISM="${mech}" \
          node "${NODEJS_BASE_DIR}/federation_matrix_sso.js" \
               --url "${DEBUGGER_BASE_URL}"
        local pointRc=$?
        ran=$((ran + 1))
        if [ ${pointRc} -ne 0 ];
        then
          rc=${pointRc}
          failed="${failed} ${point}"
        fi
      done
    done
  done
  # A NARROWED RUN THAT MATCHED NOTHING IS A FAILURE, not a pass. A typo in the
  # point — `wsfed/oauth/webauthn`, say — would otherwise run nothing at all and
  # report success, which is the "test that quietly does nothing" this suite
  # keeps finding.
  if [ ${ran} -eq 0 ];
  then
    echo "No point of the federation grid matched \"${one}\". It is" \
         "<app>/<fed>/<mech>, each of oidc, oauth2, saml2, saml11, wsfed and" \
         "each of password, webauthn." >&2
    echo "Leaving runFederationMatrix(). rc=1"
    return 1
  fi
  echo "Ran ${ran} point(s) of the federation grid."
  if [ -n "${failed}" ];
  then
    echo "FAILED:${failed}" >&2
  else
    cat <<MATRIX
Every point passed, and the stack is still up. The two realms hold one
application, two relationships and one person PER COMBINATION:
  ${WSTRUST_STS_URL}/realm/federation-matrix-1/admin/federation
      one service-provider-side relationship per point, with its own counters
  ${WSTRUST_STS_URL}/realm/federation-matrix-2/admin/federation
      one identity-provider-side relationship per point, each carrying the
      fedAuthnMechanism that decided how the person was authenticated
  ${WSTRUST_STS_URL}/realm/federation-matrix-1/admin/users
      everybody who signed in without a credential ever being checked there
The console needs a sign-on session from /authn/login (any name, any password).
Both realms are in the mock's memory and go with the container.
MATRIX
  fi
  echo "Leaving runFederationMatrix(). rc=${rc}"
  return ${rc}
}

runFederationOnly()
{
  echo "Entering runFederationOnly()."
  local services="api client sts"
  CONFIG_FILE=./env/local.js docker_compose -f local-tests.yml build ${services}
  check_return_code $?
  CONFIG_FILE=./env/local.js docker_compose -f local-tests.yml up -d ${services}
  check_return_code $?
  echo "Waiting for the mock STS ..."
  sleep 5
  CONFIG_FILE=./env/local.js verifyComposeServicesRunning local-tests.yml
  CONFIG_FILE=./env/local.js requireComposeServiceRunning local-tests.yml sts
  check_return_code $?
  # The mock serves https on a certificate regenerated when this `up -d` started
  # it, so nothing can have an anchor for it yet. This job verifies in node (the
  # management API calls and the metadata read) and in Chrome (the sign-in
  # screens and the browser-direct Token Request), so both anchors have to be in
  # place before it runs. Not fatal: the test says so itself.
  trustStsCertificate https://localhost:8081 || true

  export DEBUGGER_BASE_URL CONFIG_FILE WSTRUST_STS_URL
  local rc=0
  # BOTH ARE RUN EVEN WHEN THE FIRST FAILS, and the `rc` is the worse of the
  # two. They configure disjoint realms and share no state, so a failure in one
  # says nothing about the other — and stopping at the first would hide which
  # of the two layers broke, which is the only question worth asking when a
  # chain stops working.
  if [ "${FEDERATION_ONLY_DEPTH}" = "single" ] || \
     [ "${FEDERATION_ONLY_DEPTH}" = "both" ];
  then
    node "${NODEJS_BASE_DIR}/federation_sso.js" --url "${DEBUGGER_BASE_URL}"
    rc=$?
  fi
  if [ "${FEDERATION_ONLY_DEPTH}" = "chain" ] || \
     [ "${FEDERATION_ONLY_DEPTH}" = "both" ];
  then
    node "${NODEJS_BASE_DIR}/federation_chain_sso.js" \
         --url "${DEBUGGER_BASE_URL}"
    local chainRc=$?
    [ ${chainRc} -ne 0 ] && rc=${chainRc}
  fi
  if [ "${FEDERATION_ONLY_DEPTH}" = "choice" ] || \
     [ "${FEDERATION_ONLY_DEPTH}" = "both" ];
  then
    node "${NODEJS_BASE_DIR}/federation_choice_sso.js" \
         --url "${DEBUGGER_BASE_URL}"
    local choiceRc=$?
    [ ${choiceRc} -ne 0 ] && rc=${choiceRc}
  fi
  case "${FEDERATION_ONLY_DEPTH}" in
    matrix|matrix:*)
      runFederationMatrix
      rc=$?
      ;;
  esac
  if [ ${rc} -eq 0 ];
  then
    if [ "${FEDERATION_ONLY_DEPTH}" = "single" ] || \
       [ "${FEDERATION_ONLY_DEPTH}" = "both" ];
    then
      cat <<FEDERATION
The stack is still up, and both realms are configured. What they now hold is the
interesting part:
  ${WSTRUST_STS_URL}/realm/federation-realm-1/admin/federation
      the relationship, its counters and its last error
  ${WSTRUST_STS_URL}/realm/federation-realm-1/admin/users
      somebody who has never had a credential checked in that realm
  ${WSTRUST_STS_URL}/realm/federation-realm-2/admin/users
      the same person, in the realm where a name was actually typed
The console needs a sign-on session from /authn/login (any name, any password).
Both realms are in the mock's memory and go with the container.
FEDERATION
    fi
    if [ "${FEDERATION_ONLY_DEPTH}" = "chain" ] || \
       [ "${FEDERATION_ONLY_DEPTH}" = "both" ];
    then
      cat <<CHAIN
And the THREE realms of the N-layer chain, where the middle one is the thing to
go and look at:
  ${WSTRUST_STS_URL}/realm/federation-realm-4/admin/federation
      TWO relationships, one in each direction — realm 4 consumes realm 5's
      WS-Federation tokens and asserts SAML 2.0 to realm 3, which is the whole
      of what an identity bridge is. The identity-provider-side one carries
      fedAuthnMechanism=federation and the id of the other beside it.
  ${WSTRUST_STS_URL}/realm/federation-realm-5/admin/users
      the only realm of the three that ever drew a password field
  ${WSTRUST_STS_URL}/realm/federation-realm-3/admin/users
      the same person, two hops and two protocols away, in the realm the
      application actually asked
CHAIN
    fi
    if [ "${FEDERATION_ONLY_DEPTH}" = "choice" ] || \
       [ "${FEDERATION_ONLY_DEPTH}" = "both" ];
    then
      cat <<CHOICE
And the pair where one application has TWO identity providers:
  ${WSTRUST_STS_URL}/realm/federation-choice-1/admin/applications
      webapp-sso-1, whose appFederationRelationship names both partners. Adding
      or removing a value there is what turns the chooser on and off.
  ${WSTRUST_STS_URL}/realm/federation-choice-1/admin/federation
      the two relationships side by side — one SAML 2.0, one OpenID Connect,
      both to the same realm — each having counted exactly one sign-in.
  ${WSTRUST_STS_URL}/realm/federation-choice-2/admin/users
      the two people, and the realm where both names were actually typed
To see the chooser itself, start an authorization request for webapp-sso-1 at
  ${WSTRUST_STS_URL}/realm/federation-choice-1/oauth2/authorize
in a browser with no session for that realm.
CHOICE
    fi
  fi
  echo "Leaving runFederationOnly(). rc=${rc}"
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
    # The mock serves https on a certificate it regenerated when this `up -d`
    # started it, so nothing can have an anchor for it yet. Every job below
    # verifies — the node ones through NODE_EXTRA_CA_CERTS, the browser ones
    # through an SPKI pin — so this has to happen before any of them run. Not
    # fatal: a job that meets an untrusted certificate says so itself, and its
    # message names the certificate.
    trustStsCertificate https://localhost:8081 || true
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
      export WSFED_SIGNIN_ENDPOINT="${WSFED_STS_ENDPOINT:-https://localhost:8081/wsfed}"
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
if [ "${SAML_ONLY}" = "1" ];
then
  runSamlOnly
  check_return_code $?
  echo "SAML tests passed (idp=${SAML_ONLY_IDP}); the sts half includes" \
       "SAML 1.1, which has no Keycloak equivalent."
  exit 0
fi
if [ "${WSFED_ONLY}" = "1" ];
then
  runWsfedOnly
  check_return_code $?
  echo "WS-Federation test passed (idp=${WSFED_ONLY_IDP})."
  exit 0
fi
if [ "${DELEGATION_ONLY}" = "1" ];
then
  runDelegationOnly
  check_return_code $?
  echo "The delegation chain(s) passed (${DELEGATION_ONLY_WHAT}): a sign-in" \
       "and two hops through a middle tier, once per protocol family."
  exit 0
fi
if [ "${FEDERATION_ONLY}" = "1" ];
then
  runFederationOnly
  check_return_code $?
  echo "The federated sign-in passed: an OIDC application in one trust realm," \
       "authenticated over SAML 2.0 in another."
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
# Same reason as in runSamlOnly(): the local stack is not torn down between
# runs, so a debugger-testing realm from the previous one is still there and
# every create below would 409. See resetKeycloakRealm() in common.sh.
resetKeycloakRealm
check_return_code $?
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
