#!/usr/bin/env bash
#
# Container entrypoint: build the static client content, then deploy it to
# S3 and invalidate CloudFront. Runs identically locally and in CI.
#
# AWS credentials must be supplied from OUTSIDE the container (env vars, or a
# mounted ~/.aws profile/SSO session). This script does not create credentials.
#
# Configuration (env vars):
#   DEPLOY_ENV                   prod | test                     (prod)
#   S3_BUCKET                    target content bucket           (www.idptools.com)
#   CLOUDFRONT_DISTRIBUTION_ID   distribution to invalidate      (E1C72FI2JLYGWW)
#   AWS_REGION                   region for the bucket           (us-west-2)
#   CONFIG_FILE                  env config baked into bundles   (./env/prod.js)
#   SKIP_DEPLOY                  build only, do not push         (false)
set -euo pipefail

# Environment selection: prod (default) or test. Any of S3_BUCKET,
# CLOUDFRONT_DISTRIBUTION_ID, or CONFIG_FILE set explicitly still override the
# per-environment defaults below.
: "${DEPLOY_ENV:=prod}"
case "${DEPLOY_ENV}" in
  prod)
    : "${S3_BUCKET:=www.idptools.com}"
    : "${CLOUDFRONT_DISTRIBUTION_ID:=E1C72FI2JLYGWW}"
    : "${CONFIG_FILE:=./env/prod.js}"
    ;;
  test)
    : "${S3_BUCKET:=test.idptools.com}"
    : "${CLOUDFRONT_DISTRIBUTION_ID:=E21A46XVWQ32FG}"
    : "${CONFIG_FILE:=./env/test-idptools-com.js}"
    ;;
  *)
    echo "ERROR: unknown DEPLOY_ENV='${DEPLOY_ENV}' (expected 'prod' or 'test')." >&2
    exit 1
    ;;
esac
: "${AWS_REGION:=us-west-2}"
: "${SKIP_DEPLOY:=false}"

# --- Preflight: required tools must be present in the container ---
command -v node >/dev/null 2>&1 || { echo "ERROR: node not found in container." >&2; exit 1; }
command -v aws  >/dev/null 2>&1 || { echo "ERROR: aws CLI not found in container." >&2; exit 1; }

echo "==> [${DEPLOY_ENV}] Building static content (CONFIG_FILE=${CONFIG_FILE})"
cd /usr/src/app/client
CONFIG_FILE="${CONFIG_FILE}" npm run build

if [ "${SKIP_DEPLOY}" = "true" ]; then
  echo "==> SKIP_DEPLOY=true — build complete, not deploying."
  exit 0
fi

# --- Verify credentials were provided before touching AWS ---
if ! aws sts get-caller-identity >/dev/null 2>&1; then
  echo "ERROR: no valid AWS credentials available. Provide them via env vars" >&2
  echo "       (AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY[/AWS_SESSION_TOKEN]) or a" >&2
  echo "       mounted ~/.aws profile. Credentials must be established outside." >&2
  exit 1
fi

echo "==> Syncing dist/ -> s3://${S3_BUCKET} (region ${AWS_REGION})"
# No --acl: the content bucket uses BucketOwnerEnforced (ACLs disabled); public
# read is granted by the bucket policy, not per-object ACLs.
aws s3 sync dist "s3://${S3_BUCKET}" --delete --region "${AWS_REGION}"

echo "==> Invalidating CloudFront distribution ${CLOUDFRONT_DISTRIBUTION_ID}"
aws cloudfront create-invalidation \
  --distribution-id "${CLOUDFRONT_DISTRIBUTION_ID}" \
  --paths '/*'

echo "==> Done."
