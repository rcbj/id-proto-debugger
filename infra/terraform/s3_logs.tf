# --- Dedicated access-log bucket for CloudFront ---

data "aws_canonical_user_id" "current" {}

resource "aws_s3_bucket" "logs" {
  bucket = local.logs_bucket_name
}

# CloudFront standard logging delivers via ACLs, so this bucket must keep ACLs
# enabled (BucketOwnerPreferred) — unlike the content bucket.
resource "aws_s3_bucket_ownership_controls" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# Logs are private. The ACL grant below is to a specific AWS canonical user,
# not "public", so these blocks do not interfere with log delivery.
resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# Grant CloudFront's log-delivery user FULL_CONTROL so it can write log files.
resource "aws_s3_bucket_acl" "logs" {
  bucket = aws_s3_bucket.logs.id

  access_control_policy {
    owner {
      id = data.aws_canonical_user_id.current.id
    }

    grant {
      grantee {
        type = "CanonicalUser"
        id   = data.aws_canonical_user_id.current.id
      }
      permission = "FULL_CONTROL"
    }

    grant {
      grantee {
        type = "CanonicalUser"
        id   = local.cloudfront_log_delivery_canonical_id
      }
      permission = "FULL_CONTROL"
    }
  }

  depends_on = [
    aws_s3_bucket_ownership_controls.logs,
    aws_s3_bucket_public_access_block.logs,
  ]
}
