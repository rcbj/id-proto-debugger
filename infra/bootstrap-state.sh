#!/usr/bin/env bash
#
# One-time bootstrap of the Terraform remote-state backend.
#
# Creates a versioned, encrypted, private S3 bucket to hold Terraform state for
# every environment (prod, test, ...). Locking uses S3-native lockfiles
# (Terraform >= 1.11), so no DynamoDB table is required.
#
# Idempotent: safe to re-run. Credentials must be established outside.
#
# This is deliberately NOT managed by Terraform (it is the thing that holds
# Terraform's state) and is a rare, one-time operation, so it runs directly
# against AWS rather than in the Terraform container.
set -euo pipefail

: "${STATE_BUCKET:=idptools-terraform-state-721850476504}"
: "${AWS_REGION:=us-west-2}"

command -v aws >/dev/null 2>&1 || { echo "ERROR: aws CLI not found." >&2; exit 1; }

echo "==> Ensuring state bucket: ${STATE_BUCKET} (${AWS_REGION})"
if aws s3api head-bucket --bucket "${STATE_BUCKET}" 2>/dev/null; then
  echo "    bucket already exists."
else
  aws s3api create-bucket \
    --bucket "${STATE_BUCKET}" \
    --region "${AWS_REGION}" \
    --create-bucket-configuration "LocationConstraint=${AWS_REGION}"
  echo "    created."
fi

echo "==> Enabling versioning"
aws s3api put-bucket-versioning \
  --bucket "${STATE_BUCKET}" \
  --versioning-configuration Status=Enabled

echo "==> Enforcing default encryption (SSE-S3)"
aws s3api put-bucket-encryption \
  --bucket "${STATE_BUCKET}" \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"},"BucketKeyEnabled":true}]}'

echo "==> Blocking all public access"
aws s3api put-public-access-block \
  --bucket "${STATE_BUCKET}" \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

echo "==> Done. State bucket ready: s3://${STATE_BUCKET}"
