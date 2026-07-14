locals {
  # Content bucket is named after the primary hostname, matching the reference
  # (e.g. "www.iyasec.io"). Both apex and www serve from this single bucket.
  content_bucket_name = "www.${var.domain}"

  # Dedicated access-log bucket for this site (S3 bucket names can't contain
  # dots for this purpose, so the domain's dots become hyphens).
  logs_bucket_name = "${replace(var.domain, ".", "-")}-logs"

  # Hostnames served by the distribution / covered by the certificate.
  www_host  = "www.${var.domain}"
  aliases   = var.include_www ? [var.domain, local.www_host] : [var.domain]
  cert_sans = var.include_www ? [local.www_host] : []

  # CloudFront's log-delivery canonical user (a fixed AWS-owned constant).
  # Standard (legacy) CloudFront logging writes to S3 via this ACL grant.
  cloudfront_log_delivery_canonical_id = "c4c1ede66af53448b93c283ce9448c4ba468c9432aa01d700d3878632f77d2d0"
}
