variable "domain" {
  description = "Fully-qualified hostname for the test site (a subdomain of the parent zone)."
  type        = string
  default     = "test.idptools.com"
}

variable "parent_zone_name" {
  description = "Existing Route 53 hosted zone that is authoritative for the parent domain. Records for the test subdomain are created here; no new zone is created."
  type        = string
  default     = "idptools.com"
}

variable "aws_region" {
  description = "Region for the S3 buckets. CloudFront is global; ACM is pinned to us-east-1 automatically."
  type        = string
  default     = "us-west-2"
}

variable "aws_profile" {
  description = "Optional named AWS CLI profile for the target account. Empty = default credential chain."
  type        = string
  default     = ""
}

variable "price_class" {
  description = "CloudFront price class. PriceClass_100 is cheaper and fine for a test env."
  type        = string
  default     = "PriceClass_100"
}

variable "log_prefix" {
  description = "Prefix for CloudFront access logs in the dedicated logs bucket."
  type        = string
  default     = "test"
}

variable "tags" {
  description = "Tags applied to all resources."
  type        = map(string)
  default = {
    Project     = "oauth2-oidc-debugger"
    Site        = "test.idptools.com"
    Environment = "test"
    ManagedBy   = "terraform"
  }
}
