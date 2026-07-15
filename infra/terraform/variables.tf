variable "domain" {
  description = "Apex domain for the site (e.g. idptools.com). Registered at the registrar; DNS is delegated to the Route 53 zone created here."
  type        = string
}

variable "include_www" {
  description = "Also serve and certify the www.<domain> hostname (apex + www on one distribution), matching the reference pattern."
  type        = bool
  default     = true
}

variable "aws_region" {
  description = "Region for the S3 buckets. CloudFront is global; ACM is pinned to us-east-1 automatically."
  type        = string
  default     = "us-west-2"
}

variable "aws_profile" {
  description = "Optional named AWS CLI profile to use for the TARGET account. Leave empty to use the default credential chain (env vars, default profile, SSO, instance role)."
  type        = string
  default     = ""
}

variable "price_class" {
  description = "CloudFront price class. PriceClass_All = every edge region (matches the reference)."
  type        = string
  default     = "PriceClass_All"
}

variable "log_prefix" {
  description = "Prefix for CloudFront access logs written into the dedicated logs bucket."
  type        = string
  default     = "prod"
}

variable "tags" {
  description = "Tags applied to all resources."
  type        = map(string)
  default = {
    Project   = "oauth2-oidc-debugger"
    Site      = "idptools.com"
    ManagedBy = "terraform"
  }
}

# --- GitHub Actions OIDC deploy role (see iam.tf) ---

variable "deploy_role_name" {
  description = "Name of the GitHub Actions OIDC deploy role."
  type        = string
  default     = "idptools-github-deploy"
}

variable "create_github_oidc_provider" {
  description = "Create the GitHub Actions OIDC provider (token.actions.githubusercontent.com). Set to false to reuse one that already exists in the account (only one per account is allowed)."
  type        = bool
  default     = true
}

variable "github_subject_claims" {
  description = "GitHub OIDC 'sub' claims allowed to assume the deploy role. Defaults to any ref/environment in the repo; tighten to e.g. 'repo:OWNER/REPO:ref:refs/heads/main' or 'repo:OWNER/REPO:environment:prod' to restrict."
  type        = list(string)
  default     = ["repo:rcbj/oauth2-oidc-debugger:*"]
}
