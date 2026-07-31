# --- CloudFront distribution for the test site (same pattern as prod) ---

# Rewrite /callback -> /callback/index.html so the S3 website endpoint does not
# issue a trailing-slash redirect (which drops the OAuth query string) before
# the callback shim runs. Runs on viewer-request; the query string is preserved.
resource "aws_cloudfront_function" "callback_rewrite" {
  name    = "${replace(var.domain, ".", "-")}-callback-rewrite"
  runtime = "cloudfront-js-2.0"
  comment = "Rewrite /callback to /callback/index.html (preserve OAuth query string)"
  publish = true
  code    = <<-EOT
function handler(event) {
  var request = event.request;
  if (request.uri === '/callback') {
    request.uri = '/callback/index.html';
  }
  return request;
}
EOT
}

resource "aws_cloudfront_distribution" "site" {
  enabled             = true
  is_ipv6_enabled     = true
  http_version        = "http2"
  price_class         = var.price_class
  aliases             = local.aliases
  default_root_object = "index.html"
  comment             = "Static TEST site for ${var.domain} (oauth2-oidc-debugger)"

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
    compress               = true

    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.callback_rewrite.arn
    }

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

  # --- /wsfed: the WS-Federation landing (see lambda_edge.tf) ----------------
  #
  # Its own behavior because it needs three things the default behavior must not
  # have: POST allowed (the IdP auto-POSTs the token here), caching off (every
  # response carries a one-time security token), and the Lambda@Edge association
  # with include_body. Note that a cache behavior may carry a CloudFront Function
  # OR a Lambda@Edge on a given event type, never both — which is the other
  # reason this is separate from the default behavior and its callback_rewrite.
  #
  # The origin is never reached: the viewer-request function always generates the
  # response. One still has to be named, so it is the same S3 website origin.
  ordered_cache_behavior {
    path_pattern           = "/wsfed"
    target_origin_id       = "S3-${local.content_bucket_name}"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods         = ["GET", "HEAD"]
    compress               = false

    lambda_function_association {
      event_type = "viewer-request"
      lambda_arn = aws_lambda_function.wsfed_landing.qualified_arn
      # Without this the function is handed no body and every sign-in looks
      # exactly like a sign-out. It is the single setting the whole mechanism
      # rests on.
      include_body = true
    }

    forwarded_values {
      query_string = true
      cookies {
        forward = "none"
      }
    }

    min_ttl     = 0
    default_ttl = 0
    max_ttl     = 0
  }

  # --- /samlacs and /samlslo: the SAML landings (see lambda_edge.tf) ---------
  #
  # Same reasoning as /wsfed: POST allowed, caching off, Lambda@Edge with
  # include_body. Two behaviors because CloudFront path patterns are matched, not
  # rewritten, and the IdP posts to whichever of the two the SP metadata named.
  # One function serves both, exactly as the api registers one handler on both
  # routes.
  ordered_cache_behavior {
    path_pattern           = "/samlacs"
    target_origin_id       = "S3-${local.content_bucket_name}"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods         = ["GET", "HEAD"]
    compress               = false

    lambda_function_association {
      event_type   = "viewer-request"
      lambda_arn   = aws_lambda_function.saml_landing.qualified_arn
      include_body = true
    }

    forwarded_values {
      query_string = true
      cookies {
        forward = "none"
      }
    }

    min_ttl     = 0
    default_ttl = 0
    max_ttl     = 0
  }

  ordered_cache_behavior {
    path_pattern           = "/samlslo"
    target_origin_id       = "S3-${local.content_bucket_name}"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods         = ["GET", "HEAD"]
    compress               = false

    lambda_function_association {
      event_type   = "viewer-request"
      lambda_arn   = aws_lambda_function.saml_landing.qualified_arn
      include_body = true
    }

    forwarded_values {
      query_string = true
      cookies {
        forward = "none"
      }
    }

    min_ttl     = 0
    default_ttl = 0
    max_ttl     = 0
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate_validation.site.certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  logging_config {
    include_cookies = false
    bucket          = aws_s3_bucket.logs.bucket_domain_name
    prefix          = var.log_prefix
  }

  depends_on = [aws_s3_bucket_acl.logs]
}
