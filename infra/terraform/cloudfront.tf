# --- CloudFront distribution (mirrors the reference pattern) ---
#
# Origin is the S3 *website* endpoint over HTTP (S3 website endpoints do not
# support HTTPS), which is why the origin protocol policy is http-only and the
# bucket's own website config handles index/error routing.

resource "aws_cloudfront_distribution" "site" {
  enabled             = true
  is_ipv6_enabled     = true
  http_version        = "http2"
  price_class         = var.price_class
  aliases             = local.aliases
  default_root_object = "index.html"
  comment             = "Static site for ${var.domain} (oauth2-oidc-debugger)"

  origin {
    origin_id   = "S3-${local.content_bucket_name}"
    domain_name = aws_s3_bucket_website_configuration.site.website_endpoint

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "http-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id       = "S3-${local.content_bucket_name}"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true # improvement over the reference (was off)

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    min_ttl     = 0
    default_ttl = 86400
    max_ttl     = 31536000
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate_validation.site.certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021" # reference used TLSv1.2_2018
  }

  logging_config {
    include_cookies = false
    bucket          = aws_s3_bucket.logs.bucket_domain_name
    prefix          = var.log_prefix
  }

  # Ensure the log bucket ACL grant exists before the distribution starts
  # writing logs.
  depends_on = [aws_s3_bucket_acl.logs]
}
