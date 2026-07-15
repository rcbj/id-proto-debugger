output "name_servers" {
  description = "Set these 4 name servers at the Namecheap registrar for the domain (Custom DNS). This is the one manual step."
  value       = aws_route53_zone.this.name_servers
}

output "hosted_zone_id" {
  description = "Route 53 hosted zone ID."
  value       = aws_route53_zone.this.zone_id
}

output "content_bucket" {
  description = "S3 bucket to upload the built static client into (contents of the client container's static output)."
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
  description = "CloudFront domain (e.g. dxxxx.cloudfront.net) the alias records point at."
  value       = aws_cloudfront_distribution.site.domain_name
}

output "acm_certificate_arn" {
  description = "Validated ACM certificate ARN (us-east-1)."
  value       = aws_acm_certificate_validation.site.certificate_arn
}

output "github_deploy_role_arn" {
  description = "ARN of the GitHub Actions OIDC deploy role. Use as role-to-assume in aws-actions/configure-aws-credentials."
  value       = aws_iam_role.deploy.arn
}

output "github_oidc_provider_arn" {
  description = "ARN of the GitHub Actions OIDC provider backing the deploy role."
  value       = local.github_oidc_provider_arn
}
