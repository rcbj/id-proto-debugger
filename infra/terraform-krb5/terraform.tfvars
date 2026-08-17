aws_region = "us-west-2"

# allowed_cidr is deliberately NOT set here.
#
# It is the address of whatever machine runs the test suite, which is a property
# of the run rather than of the configuration, and it changes. infra/krb5-test.sh
# resolves it and passes -var allowed_cidr=<ip>/32; a value committed here would
# go stale silently and the symptom would be a Kerberos timeout against a KDC
# that is up and healthy.
#
# To run Terraform by hand:
#   terraform apply -var "allowed_cidr=$(curl -s https://checkip.amazonaws.com)/32"

# t3.medium, not a free-tier size, and the reason is in variables.tf: a forest
# promotion on 1 GiB stalls, and a stalled KDC is indistinguishable from the
# Kerberos failure the test exists to detect.
instance_type = "t3.medium"

domain_name  = "krb5test.local"
netbios_name = "KRB5TEST"

test_user       = "kuser"
service_account = "svc-http"
service_class   = "HTTP"
service_host    = "target"

# Closed. Set true only to debug a promotion that went wrong by hand.
enable_rdp = false

tags = {
  Project     = "oauth2-oidc-debugger"
  Stack       = "krb5-interop"
  Environment = "ephemeral"
  ManagedBy   = "terraform"
  Lifecycle   = "destroy-after-test-run"
}
