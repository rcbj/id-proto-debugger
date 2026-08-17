#!/usr/bin/env bash
#
# Stand up a real Windows KDC, run tests/krb5_real_dc.js against it, tear it
# down. One operation, and the teardown happens whatever the test did.
#
# ---------------------------------------------------------------------------
# Why this exists rather than "run terraform, then run the test".
#
# The instance costs money for as long as it is up and there is nothing else
# that will ever remove it — no schedule, no CI job, no other stack referencing
# it. An EXIT trap is therefore the only thing standing between a failed test run
# and a domain controller left running until somebody reads a bill. The trap is
# installed BEFORE the apply, so it also fires when the apply itself dies
# half-way and leaves a VPC and an instance behind.
#
# Set KRB5_KEEP=1 to skip the teardown and leave the stack up for debugging. It
# prints what to run to remove it by hand; nothing else will.
#
# KRB5_TEST_SCRIPTS chooses what runs against the live DC (default
# krb5_real_dc.js). ./local-run-tests.sh --krb5-real-dc uses it to offer the
# capture refresh as well as the test.
# ---------------------------------------------------------------------------
#
# Usage:
#   ./infra/krb5-test.sh                 apply, test, destroy
#   KRB5_KEEP=1 ./infra/krb5-test.sh     leave it running afterwards
#   ALLOWED_CIDR=1.2.3.4/32 ./infra/krb5-test.sh
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF_DIR="${REPO_ROOT}/infra/terraform-krb5"
STATE_KEY="krb5-interop/dc.tfstate"
: "${AWS_REGION:=us-west-2}"
: "${CONFIG_FILE:=./env/test.js}"
: "${BOOTSTRAP_TIMEOUT_SECS:=2400}"
export AWS_REGION

say() { echo "==> $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

command -v aws       >/dev/null 2>&1 || die "the aws CLI is required."
command -v terraform >/dev/null 2>&1 || die "terraform is required."
command -v node      >/dev/null 2>&1 || die "node is required."

aws sts get-caller-identity >/dev/null 2>&1 || \
  die "no usable AWS credentials. Sign in first."

# ---------------------------------------------------------------------------
# Hand the credentials to Terraform explicitly.
#
# A working `aws` CLI is NOT enough: the CLI resolves SSO sessions and
# credential_process entries that the Terraform AWS provider does not read the
# same way, so `terraform plan` fails with "No valid credential sources found"
# on a machine where `aws sts get-caller-identity` has just succeeded — and the
# S3 backend can initialise while the provider cannot, which makes the failure
# read as a provider bug rather than as an auth one. infra/terraform-local.sh
# solves this by exporting into the container; this script runs Terraform on the
# host, so it does the same thing into its own environment.
# ---------------------------------------------------------------------------
refresh_credentials() {
  local f
  f="$(mktemp)"
  chmod 600 "${f}"
  if aws configure export-credentials --format env-no-export > "${f}" 2>/dev/null \
     && [ -s "${f}" ];
  then
    set -a
    # shellcheck disable=SC1090
    . "${f}"
    set +a
    rm -f "${f}"
    return 0
  fi
  rm -f "${f}"
  return 1
}
refresh_credentials || true

# ---------------------------------------------------------------------------
# Who may reach the KDC. Resolved per run, because it is the address of this
# machine and not a property of the configuration.
# ---------------------------------------------------------------------------
if [ -z "${ALLOWED_CIDR:-}" ];
then
  MY_IP="$(curl -fsS --max-time 10 https://checkip.amazonaws.com 2>/dev/null | tr -d '[:space:]')"
  [ -n "${MY_IP}" ] || die "could not resolve this host's public IP; set ALLOWED_CIDR."
  ALLOWED_CIDR="${MY_IP}/32"
fi
export TF_VAR_allowed_cidr="${ALLOWED_CIDR}"
say "KDC will accept Kerberos from ${ALLOWED_CIDR} only"

cd "${TF_DIR}" || die "no ${TF_DIR}"

# ---------------------------------------------------------------------------
# Teardown, installed before anything is created.
# ---------------------------------------------------------------------------
# teardown() RETURNS; it never exits. The trap owns the exit status, so the
# script's verdict is the TEST's verdict and not the destroy's — a green test
# followed by a slow-but-successful destroy must still be a pass, and a red test
# must not be masked by a clean teardown.
TORN_DOWN=0
teardown() {
  if [ "${TORN_DOWN}" = "1" ]; then return 0; fi
  TORN_DOWN=1
  if [ "${KRB5_KEEP:-0}" = "1" ];
  then
    echo
    say "KRB5_KEEP=1 — the stack is STILL UP and still costing money."
    say "Remove it with:"
    say "  cd ${TF_DIR} && TF_VAR_allowed_cidr=${ALLOWED_CIDR} terraform destroy -auto-approve"
    return 0
  fi
  echo
  # ---------------------------------------------------------------------
  # Refresh the credentials FIRST, and this is not belt-and-braces.
  #
  # The credentials exported at startup are short-lived, and the wait for the
  # forest can be forty minutes. On 2026-08-16 they expired during that wait
  # and the destroy failed with ExpiredToken — leaving a Windows instance
  # running with nothing left to remove it, which is the exact outcome the
  # trap exists to prevent. The teardown is the one step that must not inherit
  # a stale token.
  # ---------------------------------------------------------------------
  refresh_credentials || say "could not refresh credentials; trying anyway"
  say "Tearing down (state ${STATE_KEY} only — the site stacks are in"
  say "different state files and are not reachable from here)"
  if ! terraform destroy -input=false -auto-approve >/dev/null 2>&1;
  then
    say "first destroy failed; retrying once with output"
    if ! terraform destroy -input=false -auto-approve;
    then
      echo "ERROR: TEARDOWN FAILED — resources may still be RUNNING." >&2
      echo "       cd ${TF_DIR} && \\" >&2
      echo "         TF_VAR_allowed_cidr=${ALLOWED_CIDR} terraform destroy" >&2
      return 1
    fi
  fi
  say "Torn down."
  return 0
}
trap 'rc=$?; teardown || rc=1; exit ${rc}' EXIT
trap 'echo; say "interrupted"; exit 130' INT TERM

say "terraform init"
terraform init -input=false >/dev/null || die "init failed"

say "terraform apply (a Windows instance takes a few minutes to appear)"
terraform apply -input=false -auto-approve || die "apply failed"

KDC_HOST="$(terraform output -raw kdc_host)"
KDC_PORT="$(terraform output -raw kdc_port)"
REALM="$(terraform output -raw realm)"
USER_NAME="$(terraform output -raw test_user)"
USER_PW="$(terraform output -raw test_user_password)"
SPN="$(terraform output -raw spn)"
BUCKET="$(terraform output -raw artifacts_bucket)"
INSTANCE="$(terraform output -raw instance_id)"

say "instance ${INSTANCE} at ${KDC_HOST}, realm ${REALM}"

# ---------------------------------------------------------------------------
# Wait for the bootstrap.
#
# Polling S3 rather than SSM on purpose: the thing most likely to go wrong is the
# forest promotion, and a half-promoted DC is exactly the state in which the SSM
# agent stops answering. A status object the instance PUT before anything broke
# is still readable when the instance is not.
# ---------------------------------------------------------------------------
say "waiting for the domain controller to build (up to $((BOOTSTRAP_TIMEOUT_SECS / 60)) min)"
DEADLINE=$(( $(date +%s) + BOOTSTRAP_TIMEOUT_SECS ))
STATUS=""
while [ "$(date +%s)" -lt "${DEADLINE}" ]; do
  if aws s3 cp "s3://${BUCKET}/bootstrap/status.json" /tmp/krb5-status.json \
      --region "${AWS_REGION}" --only-show-errors >/dev/null 2>&1;
  then
    STATUS="$(node -e 'try{process.stdout.write(String(require("/tmp/krb5-status.json").status||""))}catch(e){}' 2>/dev/null)"
    [ -n "${STATUS}" ] && break
  fi
  sleep 20
  printf '.'
done
echo

if [ "${STATUS}" != "ok" ];
then
  refresh_credentials || true
  say "bootstrap did not report success (status='${STATUS:-<none>}')"
  aws s3 cp "s3://${BUCKET}/bootstrap/stage2.log" /tmp/krb5-stage2.log \
    --region "${AWS_REGION}" --only-show-errors >/dev/null 2>&1 && \
    { echo "---- stage2.log (tail) ----"; tail -40 /tmp/krb5-stage2.log; }
  aws s3 cp "s3://${BUCKET}/bootstrap/stage1.log" /tmp/krb5-stage1.log \
    --region "${AWS_REGION}" --only-show-errors >/dev/null 2>&1 && \
    { echo "---- stage1.log (tail) ----"; tail -40 /tmp/krb5-stage1.log; }

  # -----------------------------------------------------------------------
  # Fall back to SSM, and this exists because of how the first run failed.
  #
  # status was '<none>' — not "failed", ABSENT. Nothing was uploaded at all,
  # including the failure marker, because the bootstrap's only way to report
  # anything is an `aws s3 cp` from the instance. So the one situation the
  # reporting is for is the one in which it is silent, and the run ended with
  # no evidence of any kind.
  #
  # SSM was up the whole time (the console log shows the agent running two
  # minutes after the promotion reboot) and this script never asked it
  # anything. It does now: whatever is wrong, this is the channel most likely
  # to still answer, and it reads the logs off the box directly.
  # -----------------------------------------------------------------------
  say "asking SSM for the on-instance logs"
  CMD_ID="$(aws ssm send-command --instance-ids "${INSTANCE}" \
      --document-name "AWS-RunPowerShellScript" --region "${AWS_REGION}" \
      --parameters 'commands=[
        "Get-ScheduledTask -TaskName krb5-stage2 -ErrorAction SilentlyContinue | Format-List TaskName,State",
        "Get-ScheduledTaskInfo -TaskName krb5-stage2 -ErrorAction SilentlyContinue | Format-List LastRunTime,LastTaskResult,NumberOfMissedRuns",
        "if (Test-Path C:\\krb5\\stage1.log) { Get-Content C:\\krb5\\stage1.log -Tail 40 } else { \"no stage1.log\" }",
        "if (Test-Path C:\\krb5\\stage2.log) { Get-Content C:\\krb5\\stage2.log -Tail 60 } else { \"no stage2.log\" }",
        "if (Test-Path C:\\krb5\\stage2.ps1) { \"stage2.ps1 present, \" + (Get-Item C:\\krb5\\stage2.ps1).Length + \" bytes\" } else { \"no stage2.ps1\" }",
        "try { $e = $null; [void][ScriptBlock]::Create((Get-Content C:\\krb5\\stage2.ps1 -Raw)); \"stage2.ps1 parses\" } catch { \"stage2.ps1 PARSE ERROR: \" + $_.Exception.Message }",
        "Get-DnsClientServerAddress -AddressFamily IPv4 | Format-Table -AutoSize | Out-String",
        "try { (Resolve-DnsName s3.'"${AWS_REGION}"'.amazonaws.com -ErrorAction Stop)[0].IPAddress } catch { \"S3 DOES NOT RESOLVE: \" + $_.Exception.Message }",
        "(Get-Command aws -ErrorAction SilentlyContinue).Source"
      ]' \
      --query 'Command.CommandId' --output text 2>/dev/null || true)"
  if [ -n "${CMD_ID}" ];
  then
    sleep 25
    echo "---- SSM diagnostics ----"
    aws ssm get-command-invocation --command-id "${CMD_ID}" \
      --instance-id "${INSTANCE}" --region "${AWS_REGION}" \
      --query 'StandardOutputContent' --output text 2>/dev/null | head -80 || \
      say "SSM did not answer either — the instance is unreachable by every channel."
  else
    say "SSM would not accept a command; the agent is offline."
  fi

  say "NOTE: keeping the stack UP would let you look further —"
  say "      KRB5_KEEP=1 ./infra/krb5-test.sh"
  die "the domain controller never finished building; not running the test."
fi
say "bootstrap reported ok"

aws s3 cp "s3://${BUCKET}/bootstrap/dc.json" /tmp/krb5-dc.json \
  --region "${AWS_REGION}" --only-show-errors >/dev/null 2>&1 || \
  die "status said ok but dc.json is not readable."

KEYTAB_B64="$(node -e 'process.stdout.write(require("/tmp/krb5-dc.json").keytab_b64||"")')"
[ -n "${KEYTAB_B64}" ] || die "dc.json carries no keytab."

# ---------------------------------------------------------------------------
# Run the test.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Run whatever was asked for against the live DC.
#
# KRB5_TEST_SCRIPTS is a space-separated list of scripts under tests/, and it
# exists so that ./local-run-tests.sh --krb5-real-dc can choose between running
# the test and REFRESHING THE CAPTURE without a second copy of the apply / wait
# / teardown logic above. There must be exactly one implementation of the
# teardown: it is the only thing that stops a Windows instance running until
# somebody reads a bill, and two copies of it would be one too many.
#
# Every script gets the same environment. A non-zero from any of them is the
# script's own exit status, and the trap still tears the stack down.
# ---------------------------------------------------------------------------
: "${KRB5_TEST_SCRIPTS:=krb5_real_dc.js}"
TEST_RC=0
FAILED=""
for script in ${KRB5_TEST_SCRIPTS};
do
  if [ ! -f "${REPO_ROOT}/tests/${script}" ];
  then
    say "no such script: tests/${script}"
    TEST_RC=1
    FAILED="${FAILED} ${script}"
    continue
  fi
  say "running tests/${script}"
  set +e
  (
    cd "${REPO_ROOT}/tests" && \
    CONFIG_FILE="${CONFIG_FILE}" \
    KRB5_DC_HOST="${KDC_HOST}" \
    KRB5_DC_PORT="${KDC_PORT}" \
    KRB5_REALM="${REALM}" \
    KRB5_USER="${USER_NAME}" \
    KRB5_PASSWORD="${USER_PW}" \
    KRB5_SPN="${SPN}" \
    KRB5_KEYTAB_B64="${KEYTAB_B64}" \
    KRB5_DC_AMI="${KRB5_DC_AMI:-}" \
    KRB5_DC_JSON=/tmp/krb5-dc.json \
    KRB5_DELEG_TARGET=windows \
    node "${script}"
  )
  rc=$?
  set -e
  if [ ${rc} -eq 0 ];
  then
    say "${script} PASSED against a real Windows KDC"
  else
    say "${script} FAILED (exit ${rc})"
    TEST_RC=${rc}
    FAILED="${FAILED} ${script}"
  fi
done

if [ -n "${FAILED}" ];
then
  say "failed:${FAILED}"
fi

# The EXIT trap tears the stack down and exits with this status.
exit ${TEST_RC}
