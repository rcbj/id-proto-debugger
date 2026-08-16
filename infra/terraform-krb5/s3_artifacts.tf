# ---------------------------------------------------------------------------
# Where the instance puts what the test needs.
#
# The bootstrap has to hand three things back: the service keytab (the file
# `ktpass` writes, which carries the service's long-term key), the realm/SPN it
# actually settled on, and a status marker saying it finished. SSM Run Command
# could carry them, but only while the agent is healthy — and the agent's health
# is precisely what a botched DC promotion destroys. A bucket the instance writes
# to needs nothing on the instance to still be working when the test reads it.
#
# force_destroy is ON because that is the point of this stack: `terraform
# destroy` must not stop and ask about objects the bootstrap wrote. Safe here
# because nothing but this stack's own instance ever writes to it, and the bucket
# name carries the stack prefix.
# ---------------------------------------------------------------------------
resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "artifacts" {
  bucket        = "${local.name_prefix}-artifacts-${random_id.bucket_suffix.hex}"
  force_destroy = true

  tags = { Name = "${local.name_prefix}-artifacts" }
}

# The keytab is a credential. It lives for the length of one test run in a bucket
# that is private, encrypted and unversioned — unversioned deliberately, so that
# force_destroy has nothing left behind to leak.
resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_ownership_controls" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}
