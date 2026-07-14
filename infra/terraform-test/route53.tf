# --- Reuse the existing parent hosted zone (no new zone for a subdomain) ---

data "aws_route53_zone" "parent" {
  name         = "${var.parent_zone_name}."
  private_zone = false
}

# Alias records for the test subdomain pointing at its CloudFront distribution.
resource "aws_route53_record" "site_a" {
  zone_id = data.aws_route53_zone.parent.zone_id
  name    = var.domain
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.site.domain_name
    zone_id                = aws_cloudfront_distribution.site.hosted_zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "site_aaaa" {
  zone_id = data.aws_route53_zone.parent.zone_id
  name    = var.domain
  type    = "AAAA"

  alias {
    name                   = aws_cloudfront_distribution.site.domain_name
    zone_id                = aws_cloudfront_distribution.site.hosted_zone_id
    evaluate_target_health = false
  }
}
