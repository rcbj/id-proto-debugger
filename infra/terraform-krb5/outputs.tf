# ---------------------------------------------------------------------------
# What the test needs, and nothing it does not.
#
# infra/krb5-test.sh reads these and turns them into the KRB5_* environment
# variables tests/krb5_real_dc.js is gated on.
# ---------------------------------------------------------------------------
output "kdc_host" {
  description = "Public address of the domain controller. This is the KDC the test sends its AS-REQ to."
  value       = aws_instance.dc.public_ip
}

output "kdc_port" {
  description = "Kerberos port, opened on both TCP and UDP to allowed_cidr."
  value       = 88
}

output "realm" {
  description = "Kerberos realm — the AD DS domain, upper-cased."
  value       = local.realm
}

output "domain_name" {
  description = "AD DS DNS domain."
  value       = var.domain_name
}

output "test_user" {
  description = "The non-admin domain user the test authenticates as."
  value       = var.test_user
}

output "test_user_password" {
  description = "Password for the non-admin user. Generated per apply; lives as long as the stack does."
  value       = random_password.test_user.result
  sensitive   = true
}

output "spn" {
  description = "Service principal the test requests a ticket for."
  value       = local.spn
}

output "service_account" {
  description = "Account the SPN is mapped to."
  value       = var.service_account
}

output "artifacts_bucket" {
  description = "Bucket the bootstrap writes dc.json (with the keytab) and its status to."
  value       = aws_s3_bucket.artifacts.bucket
}

output "artifacts_status_uri" {
  description = "Poll this to find out whether the bootstrap finished. status.json says ok or failed; a failure also uploads the stage log beside it."
  value       = "s3://${aws_s3_bucket.artifacts.bucket}/bootstrap/status.json"
}

output "artifacts_dc_uri" {
  description = "The document carrying the realm, the SPN and the base64 service keytab."
  value       = "s3://${aws_s3_bucket.artifacts.bucket}/bootstrap/dc.json"
}

output "instance_id" {
  description = "For `aws ssm start-session` / `send-command` when the bootstrap needs interrogating."
  value       = aws_instance.dc.id
}

output "administrator_password" {
  description = "Domain Administrator / DSRM password. For debugging over RDP (which is closed unless enable_rdp is set)."
  value       = random_password.admin.result
  sensitive   = true
}

output "instance_private_key_pem" {
  description = "Private half of the EC2 key pair, for `aws ec2 get-password-data`. The bootstrap sets its own Administrator password, so this is a fallback only."
  value       = tls_private_key.dc.private_key_pem
  sensitive   = true
}

output "delegation" {
  description = "The four delegation roles and their SPNs. Keytabs and passwords are not here — they are in the bootstrap's dc.json, which is where the test reads them from."
  value = var.provision_delegation ? {
    for role, d in local.delegation : role => d.spn
  } : {}
}
