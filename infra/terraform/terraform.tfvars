domain      = "idptools.com"
include_www = true
aws_region  = "us-west-2"

# Optional: name of the AWS CLI profile for the TARGET account (write access).
# Leave commented to use the default credential chain.
# aws_profile = "idptools-deploy"

tags = {
  Project   = "oauth2-oidc-debugger"
  Site      = "idptools.com"
  ManagedBy = "terraform"
}
