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
