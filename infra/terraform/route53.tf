# --- Route 53 hosted zone (authoritative DNS for the domain) ---
#
# Create this zone FIRST, then paste its name servers into the Namecheap
# registrar so the domain delegates here. See README for the two-phase apply.

resource "aws_route53_zone" "this" {
  name = var.domain
}

# --- Alias records pointing apex (and www) at the CloudFront distribution ---

resource "aws_route53_record" "apex_a" {
  zone_id = aws_route53_zone.this.zone_id
  name    = var.domain
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.site.domain_name
    zone_id                = aws_cloudfront_distribution.site.hosted_zone_id
    evaluate_target_health = false
  }
}

# IPv6 alias (the distribution has IPv6 enabled). Small improvement over the
# reference, which only had the A record.
resource "aws_route53_record" "apex_aaaa" {
  zone_id = aws_route53_zone.this.zone_id
  name    = var.domain
  type    = "AAAA"

  alias {
    name                   = aws_cloudfront_distribution.site.domain_name
    zone_id                = aws_cloudfront_distribution.site.hosted_zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "www_a" {
  count   = var.include_www ? 1 : 0
  zone_id = aws_route53_zone.this.zone_id
  name    = local.www_host
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.site.domain_name
    zone_id                = aws_cloudfront_distribution.site.hosted_zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "www_aaaa" {
  count   = var.include_www ? 1 : 0
  zone_id = aws_route53_zone.this.zone_id
  name    = local.www_host
  type    = "AAAA"

  alias {
    name                   = aws_cloudfront_distribution.site.domain_name
    zone_id                = aws_cloudfront_distribution.site.hosted_zone_id
    evaluate_target_health = false
  }
}
