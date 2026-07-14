output "site_url" {
  description = "Public URL for the test site."
  value       = "https://${var.domain}"
}

output "content_bucket" {
  description = "S3 bucket to upload the built static client into."
  value       = aws_s3_bucket.site.bucket
}

output "logs_bucket" {
  description = "Dedicated CloudFront access-log bucket."
  value       = aws_s3_bucket.logs.bucket
}

output "cloudfront_distribution_id" {
  description = "CloudFront distribution ID (use for cache invalidations after deploys)."
  value       = aws_cloudfront_distribution.site.id
}

output "cloudfront_domain_name" {
  description = "CloudFront domain the alias records point at."
  value       = aws_cloudfront_distribution.site.domain_name
}

output "acm_certificate_arn" {
  description = "Validated ACM certificate ARN (us-east-1)."
  value       = aws_acm_certificate_validation.site.certificate_arn
}

output "parent_zone_id" {
  description = "Parent hosted zone the subdomain records were added to."
  value       = data.aws_route53_zone.parent.zone_id
}
