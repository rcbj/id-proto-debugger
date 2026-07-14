locals {
  # For the test subdomain the content bucket is named for the hostname itself
  # (e.g. "test.idptools.com"), served as a single alias (no www).
  content_bucket_name = var.domain
  logs_bucket_name    = "${replace(var.domain, ".", "-")}-logs"
  aliases             = [var.domain]

  # CloudFront's log-delivery canonical user (fixed AWS-owned constant).
  cloudfront_log_delivery_canonical_id = "c4c1ede66af53448b93c283ce9448c4ba468c9432aa01d700d3878632f77d2d0"
}
