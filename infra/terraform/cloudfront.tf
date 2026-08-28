# --- CloudFront distribution (mirrors the reference pattern) ---
#
# Origin is the S3 *website* endpoint over HTTP (S3 website endpoints do not
# support HTTPS), which is why the origin protocol policy is http-only and the
# bucket's own website config handles index/error routing.

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

# --- The security headers the Express client sets on every response ---------
#
# client/server.js's FIRST middleware sets three headers on everything it
# serves, and the comment above it says why: RFC 9700 section 4.11 asks that an
# authorization response's URL not travel in a Referer, and section 4.16 asks
# for a CSP restricting frame-ancestors, with X-Frame-Options beside it for
# anything that does not implement that directive. None of the three is behind
# the compliance checkbox, because none is about a conversation with a provider
# — they are this deployment's own posture.
#
# A STATIC DEPLOYMENT HAD NONE OF THEM, and that is what this resource fixes.
# There is no Express here: S3 serves the bytes and CloudFront hands them on,
# so a middleware chain is not available and the headers have to be attached to
# the cache behaviors instead. The pages are the same pages — oauth2_oidc_2.html
# on the hosted site receives an authorization response in its URL exactly as it
# does locally — so the posture has to be the same too, and tests/
# rfc9700_flows.js asserts these OVER THE WIRE against whatever base URL it is
# pointed at for precisely this reason: it is the check that a CDN in front of
# the pages has not dropped what the origin meant to send.
#
# THE CSP IS frame-ancestors AND NOTHING ELSE, deliberately, and the reason is
# the same one written out in client/server.js: nearly every control on this
# site carries an inline event handler, so a default-src or a script-src here
# would take the whole application out at once.
#
# `override = true` on each: S3 sends none of these, but a policy that yielded
# to the origin would be one deploy of a bucket-level metadata setting away from
# silently doing nothing.
resource "aws_cloudfront_response_headers_policy" "security_headers" {
  name    = "${replace(var.domain, ".", "-")}-security-headers"
  comment = "Referrer-Policy / X-Frame-Options / CSP frame-ancestors, matching client/server.js"

  security_headers_config {
    referrer_policy {
      referrer_policy = "no-referrer"
      override        = true
    }

    frame_options {
      frame_option = "DENY"
      override     = true
    }

    content_security_policy {
      content_security_policy = "frame-ancestors 'none'"
      override                = true
    }
  }
}

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
    target_origin_id           = "S3-${local.content_bucket_name}"
    viewer_protocol_policy     = "redirect-to-https"
    allowed_methods            = ["GET", "HEAD"]
    cached_methods             = ["GET", "HEAD"]
    compress                   = true # improvement over the reference (was off)
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security_headers.id

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
    # The landings are generated by the Lambda@Edge rather than fetched, and a
    # response headers policy applies to a generated response too — which is
    # what keeps a page that has just received a SAML assertion or a WS-Fed
    # token under the same posture as every other page here.
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security_headers.id

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
    # The landings are generated by the Lambda@Edge rather than fetched, and a
    # response headers policy applies to a generated response too — which is
    # what keeps a page that has just received a SAML assertion or a WS-Fed
    # token under the same posture as every other page here.
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security_headers.id

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
    # The landings are generated by the Lambda@Edge rather than fetched, and a
    # response headers policy applies to a generated response too — which is
    # what keeps a page that has just received a SAML assertion or a WS-Fed
    # token under the same posture as every other page here.
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security_headers.id

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
