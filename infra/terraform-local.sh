#!/usr/bin/env bash
#
# Run Terraform for the idptools infrastructure — entirely inside Docker.
# Nothing but Docker (and the AWS CLI, for auth) runs on your host.
#
# Local auth model matches the deploy pipeline: your AWS SSO / `aws login`
# session is resolved to short-lived credentials on the host and passed into
# the container via a private --env-file (never written to a persistent file,
# survives sudo's env reset). State is remote (S3), so no volume mount needed.
#
# Usage:
#   ./infra/terraform-local.sh [env] [action]
#   env    = prod | test | krb5    (default: test)
#   action = init|validate|plan|apply|destroy|output   (default: plan)
#
# Examples:
#   ./infra/terraform-local.sh test plan
#   ./infra/terraform-local.sh prod apply
#   TF_ENV=prod TF_ACTION=plan ./infra/terraform-local.sh
#
# `krb5` is the ephemeral Kerberos KDC that tests/krb5_real_dc.js runs against.
# It is a separate root module with a separate state key, so destroying it cannot
# touch either static site. It needs to know which address may reach the KDC;
# this script resolves that from the host's public IP unless ALLOWED_CIDR says
# otherwise. Prefer ./infra/krb5-test.sh, which does apply -> wait -> test ->
# destroy as one operation and tears down even when the test fails.
#
# Override docker invocation with DOCKER (e.g. DOCKER="sudo docker").
set -euo pipefail

IMAGE_NAME="${IMAGE_NAME:-idptools-terraform}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

TF_ENV="${TF_ENV:-${1:-test}}"
TF_ACTION="${TF_ACTION:-${2:-plan}}"

command -v aws >/dev/null 2>&1 || {
  echo "ERROR: the AWS CLI is required on the host to resolve your SSO session." >&2
  exit 1
}

# Choose how to invoke docker: honor $DOCKER, else `docker`, else fall back to
# `sudo docker` if the daemon isn't reachable without it.
if [ -n "${DOCKER:-}" ]; then
  read -r -a DOCKER_CMD <<< "${DOCKER}"
elif docker info >/dev/null 2>&1; then
  DOCKER_CMD=(docker)
elif command -v sudo >/dev/null 2>&1; then
  DOCKER_CMD=(sudo docker)
else
  echo "ERROR: docker is required and not reachable." >&2
  exit 1
fi

echo "==> Resolving AWS SSO session${AWS_PROFILE:+ (profile: ${AWS_PROFILE})}"
CREDS_ENV_FILE="$(mktemp)"
chmod 600 "${CREDS_ENV_FILE}"
trap 'rm -f "${CREDS_ENV_FILE}"' EXIT
if ! aws configure export-credentials --format env-no-export > "${CREDS_ENV_FILE}" 2>/dev/null || [ ! -s "${CREDS_ENV_FILE}" ]; then
  echo "ERROR: could not resolve AWS credentials from your session." >&2
  echo "       Sign in first, e.g.:  aws sso login${AWS_PROFILE:+ --profile ${AWS_PROFILE}}   (or: aws login)" >&2
  exit 1
fi

echo "==> Building terraform image: ${IMAGE_NAME}"
"${DOCKER_CMD[@]}" build -t "${IMAGE_NAME}" -f "${REPO_ROOT}/infra/Dockerfile" "${REPO_ROOT}"

# The krb5 stack builds its security group from one address. Resolve it here
# rather than in the container: the container's egress address is the host's, but
# asking from inside adds a dependency on the image having curl and on the
# checkip service being reachable from a place that is harder to debug.
TF_VAR_ALLOWED_CIDR_ARG=()
if [ "${TF_ENV}" = "krb5" ];
then
  if [ -z "${ALLOWED_CIDR:-}" ];
  then
    MY_IP="$(curl -fsS --max-time 10 https://checkip.amazonaws.com 2>/dev/null | tr -d '[:space:]')"
    if [ -z "${MY_IP}" ];
    then
      echo "ERROR: could not resolve this host's public IP for the KDC's security" >&2
      echo "       group. Set ALLOWED_CIDR=<addr>/32 and re-run." >&2
      exit 1
    fi
    ALLOWED_CIDR="${MY_IP}/32"
  fi
  echo "==> KDC will accept Kerberos from ${ALLOWED_CIDR} only"
  TF_VAR_ALLOWED_CIDR_ARG=(-e "TF_VAR_allowed_cidr=${ALLOWED_CIDR}")
fi

echo "==> Running terraform: env=${TF_ENV} action=${TF_ACTION}"
"${DOCKER_CMD[@]}" run --rm \
  --env-file "${CREDS_ENV_FILE}" \
  -e TF_ENV="${TF_ENV}" \
  -e TF_ACTION="${TF_ACTION}" \
  -e AWS_REGION="${AWS_REGION:-us-west-2}" \
  "${TF_VAR_ALLOWED_CIDR_ARG[@]}" \
  "${IMAGE_NAME}"
