domain           = "test.idptools.com"
parent_zone_name = "idptools.com"
aws_region       = "us-west-2"

# Optional: AWS CLI profile for the target account.
# aws_profile = "idptools-deploy"

tags = {
  Project     = "oauth2-oidc-debugger"
  Site        = "test.idptools.com"
  Environment = "test"
  ManagedBy   = "terraform"
}
