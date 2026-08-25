#!/bin/bash
#
# ---------------------------------------------------------------------------
# THE API'S ENTRYPOINT, AND ITS ONLY JOB IS A TRUSTSTORE.
#
# The mock STS serves its main port over TLS in this project's test stacks
# (STS_HTTPS=true in local-tests.yml and docker-compose-run-tests.yml), because
# the RFC 9700 pass is only honest over https — requirement 8.1 is that every
# configured endpoint is https, and the debugger enforces it. That pass used to
# have a mock instance of its own; it is a TRUST REALM on the one instance now,
# and a realm cannot bind a socket of its own, so the scheme had to move to the
# process.
#
# The certificate that comes with it is SELF-SIGNED AND REGENERATED ON EVERY
# START of that service. Nothing can have an anchor for it ahead of time: it
# cannot be baked into this image, committed, or installed by whoever ran the
# launcher, because it does not exist until the mock is up. The api reaches the
# mock over that port for SCIM, for the WS-Trust / SAML / OIDC proxying the
# browser asks it to do, and for the Kerberos MS-KKDCP relay, and every one of
# those calls goes through `outboundHttpsAgent()`, which verifies. Without an
# anchor they fail as DEPTH_ZERO_SELF_SIGNED_CERT — a message that names a
# certificate and never names the mock.
#
# So the certificate is FETCHED HERE, once, before the server starts, and put
# where node looks: NODE_EXTRA_CA_CERTS. That is a truststore addition rather
# than a verification switch — `rejectUnauthorized` stays on everywhere, this
# service still refuses every other certificate it cannot build a chain for,
# and the one exception is the exact self-signed certificate the mock published
# on this run. `NODE_TLS_REJECT_UNAUTHORIZED=0` would have been one line and
# would also have disarmed api_ssrf_guard.js, api_tls_probe.js and
# url_safety_schemes.js, which assert refusals.
#
# IT IS A NO-OP UNLESS `STS_CERT_URL` IS SET, which is why it can be the image's
# entrypoint rather than a command override in two compose files: a deployed api
# has no mock STS, sets nothing, and execs its CMD unchanged.
#
# The fetch itself is made WITHOUT verification (`curl -k`), and that is the
# ordinary bootstrap for a certificate regenerated every start rather than a
# hole: it is the same act as trusting the PEM the endpoint hands back, done one
# step earlier. mock-sts's own README says so at /tls.
# ---------------------------------------------------------------------------
set -uo pipefail

if [ -n "${STS_CERT_URL:-}" ];
then
  STS_CA_FILE="${STS_CA_FILE:-/usr/src/app/sts-ca.pem}"
  echo "Entering sts_truststore. Fetching the mock STS certificate from ${STS_CERT_URL}"
  # --retry-connrefused as well as --retry: compose may have started this
  # container before the mock is listening, and depends_on only orders the
  # START. Forty attempts two seconds apart is longer than the mock's own
  # healthcheck start_period, so a slow build does not turn into a silent
  # untrusted certificate.
  if curl -sk --fail --retry 40 --retry-connrefused --retry-delay 2 \
          -o "${STS_CA_FILE}" "${STS_CERT_URL}";
  then
    export NODE_EXTRA_CA_CERTS="${STS_CA_FILE}"
    echo "Leaving sts_truststore. NODE_EXTRA_CA_CERTS=${STS_CA_FILE}"
  else
    # NOT fatal, and deliberately so. This service has a great deal to do that
    # has nothing to do with the mock, and a stack whose mock never came up
    # should fail on the test that needed it — with that test's own message —
    # rather than on an api container that would not start. The line above is
    # what a reader greps for when a dozen STS-backed jobs report a certificate
    # error at once.
    echo "WARNING: could not fetch the mock STS certificate from ${STS_CERT_URL}." >&2
    echo "         Calls from this service to that mock over https will fail" >&2
    echo "         verification (DEPTH_ZERO_SELF_SIGNED_CERT)." >&2
  fi
fi

exec "$@"
