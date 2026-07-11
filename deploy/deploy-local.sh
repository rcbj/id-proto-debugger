#!/usr/bin/env bash
#
# Build and deploy the static idptools.com site — entirely inside Docker.
# Nothing but Docker (and the AWS CLI, for auth) runs on your host.
#
# Local auth model: your AWS SSO / `aws login` session (AWS Identity Center
# OIDC). This script resolves that session into short-lived credentials on the
# host and passes them into the container as env vars — no static keys, no
# ~/.aws mount, and the temporary credentials never touch disk.
#
# (CI uses a different path — static keys from repo secrets — see
#  .github/workflows/website-deploy.yml.)
#
# Overridable via env vars:
#   DEPLOY_ENV (prod|test), S3_BUCKET, CLOUDFRONT_DISTRIBUTION_ID, AWS_REGION,
#   CONFIG_FILE, SKIP_DEPLOY, AWS_PROFILE, IMAGE_NAME
#
# Examples:
#   ./deploy/deploy-local.sh                    # prod: build + deploy (SSO login)
#   DEPLOY_ENV=test ./deploy/deploy-local.sh    # test: build + deploy
#   SKIP_DEPLOY=true ./deploy/deploy-local.sh   # build only (no AWS needed)
#   AWS_PROFILE=idptools ./deploy/deploy-local.sh
set -euo pipefail

IMAGE_NAME="${IMAGE_NAME:-idptools-static-deploy}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The pipeline runs in a container, so Docker is always required on the host.
command -v sudo docker >/dev/null 2>&1 || {
  echo "ERROR: docker is not installed or not on PATH. This pipeline runs" >&2
  echo "       entirely inside a container, so Docker is required." >&2
  exit 1
}

run_args=(--rm)
run_args+=(-e "DEPLOY_ENV=${DEPLOY_ENV:-prod}")
run_args+=(-e "AWS_REGION=${AWS_REGION:-us-west-2}")
run_args+=(-e "SKIP_DEPLOY=${SKIP_DEPLOY:-false}")

# Optional explicit overrides — only forwarded when set, so the container's
# per-environment (DEPLOY_ENV) defaults apply otherwise.
for v in S3_BUCKET CLOUDFRONT_DISTRIBUTION_ID CONFIG_FILE; do
  if [ -n "${!v:-}" ]; then run_args+=(-e "${v}=${!v}"); fi
done

# Short-lived credential file handed to the container; removed on exit.
CREDS_ENV_FILE=""
cleanup() { [ -n "${CREDS_ENV_FILE}" ] && rm -f "${CREDS_ENV_FILE}"; }
trap cleanup EXIT

# For a real deploy, resolve the developer's AWS SSO session into short-lived
# credentials and forward them to the container. Skipped for build-only runs.
if [ "${SKIP_DEPLOY:-false}" != "true" ]; then
  command -v aws >/dev/null 2>&1 || {
    echo "ERROR: the AWS CLI is required on the host to resolve your SSO login" >&2
    echo "       session. Install it, or set SKIP_DEPLOY=true to only build." >&2
    exit 1
  }

  echo "==> Resolving AWS SSO session${AWS_PROFILE:+ (profile: ${AWS_PROFILE})}"
  # Write resolved short-lived creds to a private env-file and pass it with
  # --env-file. This survives sudo's environment reset (the value-less
  # `-e VAR` passthrough does NOT, because sudo scrubs the variable before
  # docker sees it) and keeps credentials out of the process list.
  CREDS_ENV_FILE="$(mktemp)"
  chmod 600 "${CREDS_ENV_FILE}"
  if ! aws configure export-credentials --format env-no-export > "${CREDS_ENV_FILE}" 2>/dev/null || [ ! -s "${CREDS_ENV_FILE}" ]; then
    echo "ERROR: could not resolve AWS credentials from your session." >&2
    echo "       Sign in first, e.g.:  aws sso login${AWS_PROFILE:+ --profile ${AWS_PROFILE}}   (or: aws login)" >&2
    exit 1
  fi
  run_args+=(--env-file "${CREDS_ENV_FILE}")
fi

echo "==> Building deploy image: ${IMAGE_NAME}"
sudo docker build -t "${IMAGE_NAME}" -f "${REPO_ROOT}/deploy/Dockerfile" "${REPO_ROOT}"

echo "==> Running build + deploy in container"
sudo docker run "${run_args[@]}" "${IMAGE_NAME}"
