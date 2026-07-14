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
#   env    = prod | test           (default: test)
#   action = init|validate|plan|apply|destroy|output   (default: plan)
#
# Examples:
#   ./infra/terraform-local.sh test plan
#   ./infra/terraform-local.sh prod apply
#   TF_ENV=prod TF_ACTION=plan ./infra/terraform-local.sh
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

echo "==> Running terraform: env=${TF_ENV} action=${TF_ACTION}"
"${DOCKER_CMD[@]}" run --rm \
  --env-file "${CREDS_ENV_FILE}" \
  -e TF_ENV="${TF_ENV}" \
  -e TF_ACTION="${TF_ACTION}" \
  -e AWS_REGION="${AWS_REGION:-us-west-2}" \
  "${IMAGE_NAME}"
