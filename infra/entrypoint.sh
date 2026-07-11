#!/usr/bin/env bash
#
# Container entrypoint: run Terraform for one environment. State is remote (S3),
# so this works identically whether the container runs locally or in CI.
#
# AWS credentials must be supplied from OUTSIDE the container (env vars).
#
# Config (env vars):
#   TF_ENV       prod | test                                   (test)
#   TF_ACTION    init | validate | plan | apply | destroy | output   (plan)
#   AWS_REGION   region for provider + state backend           (us-west-2)
set -euo pipefail

: "${TF_ENV:=test}"
: "${TF_ACTION:=plan}"
: "${AWS_REGION:=us-west-2}"
export AWS_REGION

case "${TF_ENV}" in
  prod) TF_DIR=/workspace/infra/terraform ;;
  test) TF_DIR=/workspace/infra/terraform-test ;;
  *) echo "ERROR: unknown TF_ENV='${TF_ENV}' (expected 'prod' or 'test')." >&2; exit 1 ;;
esac

command -v terraform >/dev/null 2>&1 || { echo "ERROR: terraform not found in container." >&2; exit 1; }
command -v aws       >/dev/null 2>&1 || { echo "ERROR: aws CLI not found in container." >&2; exit 1; }

# The S3 backend needs valid credentials just to init, so check up front.
if ! aws sts get-caller-identity >/dev/null 2>&1; then
  echo "ERROR: no valid AWS credentials available. Provide them via env vars" >&2
  echo "       (AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY[/AWS_SESSION_TOKEN])." >&2
  exit 1
fi

cd "${TF_DIR}"

echo "==> [${TF_ENV}] terraform init"
terraform init -input=false

case "${TF_ACTION}" in
  init)     echo "==> init only." ;;
  validate) terraform validate ;;
  plan)     terraform plan -input=false ;;
  apply)    terraform apply -input=false -auto-approve ;;
  destroy)  terraform destroy -input=false -auto-approve ;;
  output)   terraform output ;;
  *) echo "ERROR: unknown TF_ACTION='${TF_ACTION}' (init|validate|plan|apply|destroy|output)." >&2; exit 1 ;;
esac

echo "==> [${TF_ENV}] ${TF_ACTION} complete."
