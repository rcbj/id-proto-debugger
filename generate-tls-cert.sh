#!/bin/bash
#
# Generate the TLS certificate the api and the client serve.
#
# ---------------------------------------------------------------------------
# WHO NEEDS THIS AND WHO DOES NOT.
#
# The four test launchers (./local-run-tests.sh, ./docker-run-tests.sh,
# ./run-coverage.sh, ./remote-run-tests.sh) call
# generateStackTlsCertificate() themselves and need nothing from here. This
# script is for the one documented path that has no launcher in front of it —
# the repo-root CLAUDE.md's
#
#     CONFIG_FILE=./env/local.js docker-compose up
#
# — where compose mounts ./generated-tls and nothing has written it.
#
# Both services set `https: true` in their local configuration, so without a
# certificate they refuse to bind and say so, naming this script. That is
# deliberate: a service that quietly invented a key pair would be up, serving
# something nothing else in the stack trusts.
#
# The certificate is SELF-SIGNED, so your browser will show an interstitial
# the first time. Its SubjectAltNames cover localhost, client, api and the two
# loopback literals; the fingerprint is printed below if you want to check it.
# ---------------------------------------------------------------------------
set -e

CURRENT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "${CURRENT_DIR}"

check_return_code()
{
  if [ "${1}" -ne 0 ];
  then
    echo "Failed with exit code ${1}." >&2
    exit "${1}"
  fi
}

. "${CURRENT_DIR}/common/common.sh"

# The compose files' default bind-mount source, so `docker-compose up` finds
# it with nothing exported. STACK_TLS_DIR overrides it, and the launchers set
# their own throwaway directory instead.
STACK_TLS_DIR="${STACK_TLS_DIR:-${CURRENT_DIR}/generated-tls}"
export STACK_TLS_DIR

# Regenerating is the point of re-running this, so anything already there goes
# rather than being reused — generateStackTlsCertificate() treats an existing
# pair as one the caller supplied.
rm -f "${STACK_TLS_DIR}/stack-tls-cert.pem" "${STACK_TLS_DIR}/stack-tls-key.pem"
unset STACK_TLS_CERT_FILE STACK_TLS_KEY_FILE

generateStackTlsCertificate "${CURRENT_DIR}" "${1:-}"
check_return_code $?

echo
echo "Wrote:"
echo "  ${STACK_TLS_CERT_FILE}"
echo "  ${STACK_TLS_KEY_FILE}"
echo
echo "SHA-256 fingerprint:"
openssl x509 -in "${STACK_TLS_CERT_FILE}" -noout -fingerprint -sha256
echo
echo "Now: CONFIG_FILE=./env/local.js docker-compose up"
echo "Then open https://localhost:3000 and accept the certificate once."
