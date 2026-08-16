#!/usr/bin/env bash
#
# Container entrypoint: run Terraform for one environment. State is remote (S3),
# so this works identically whether the container runs locally or in CI.
#
# AWS credentials must be supplied from OUTSIDE the container (env vars).
#
# Config (env vars):
#   TF_ENV       prod | test | krb5                            (test)
#   TF_ACTION    init | validate | plan | apply | destroy | output   (plan)
#   AWS_REGION   region for provider + state backend           (us-west-2)
#
#   TF_VAR_allowed_cidr   required for TF_ENV=krb5: the one address permitted to
#                         reach the ephemeral KDC.
#
# Each environment is a SEPARATE ROOT MODULE with a SEPARATE STATE KEY, and that
# is what makes `destroy` safe to run against one of them. Terraform can only
# destroy what is in the state it is pointed at, so a destroy of krb5 cannot
# reach a bucket, distribution or DNS record belonging to prod or test — there is
# no shared resource and no cross-stack data source.
set -euo pipefail

: "${TF_ENV:=test}"
: "${TF_ACTION:=plan}"
: "${AWS_REGION:=us-west-2}"
export AWS_REGION

case "${TF_ENV}" in
  prod) TF_DIR=/workspace/infra/terraform      ; TF_STATE_KEY="idptools.com/prod.tfstate" ;;
  test) TF_DIR=/workspace/infra/terraform-test ; TF_STATE_KEY="idptools.com/test.tfstate" ;;
  # Ephemeral Kerberos KDC for tests/krb5_real_dc.js. Nothing here outlives a
  # test run; see infra/terraform-krb5/README.md.
  krb5) TF_DIR=/workspace/infra/terraform-krb5 ; TF_STATE_KEY="krb5-interop/dc.tfstate" ;;
  *) echo "ERROR: unknown TF_ENV='${TF_ENV}' (expected 'prod', 'test' or 'krb5')." >&2; exit 1 ;;
esac

# The KDC's security group is built from this and there is no default, because a
# stale or absent value produces a KDC that is up and healthy and unreachable —
# which the test reports as a Kerberos timeout, naming the protocol rather than
# the firewall.
if [ "${TF_ENV}" = "krb5" ] && [ "${TF_ACTION}" != "output" ] && [ "${TF_ACTION}" != "init" ];
then
  if [ -z "${TF_VAR_allowed_cidr:-}" ];
  then
    echo "ERROR: TF_ENV=krb5 needs TF_VAR_allowed_cidr (e.g. 203.0.113.4/32)." >&2
    echo "       infra/krb5-test.sh resolves it for you; pass it explicitly if" >&2
    echo "       you are calling this directly." >&2
    exit 1
  fi
fi

command -v terraform >/dev/null 2>&1 || { echo "ERROR: terraform not found in container." >&2; exit 1; }
command -v aws       >/dev/null 2>&1 || { echo "ERROR: aws CLI not found in container." >&2; exit 1; }

# The S3 backend needs valid credentials just to init, so check up front.
if ! aws sts get-caller-identity >/dev/null 2>&1; then
  echo "ERROR: no valid AWS credentials available. Provide them via env vars" >&2
  echo "       (AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY[/AWS_SESSION_TOKEN])." >&2
  exit 1
fi

cd "${TF_DIR}"

# Say which state is about to be operated on. This line is the reassurance that
# a destroy is aimed where it is meant to be aimed, and it is cheap.
echo "==> [${TF_ENV}] ${TF_DIR}"
echo "==> [${TF_ENV}] state: s3://idptools-terraform-state-721850476504/${TF_STATE_KEY}"

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
