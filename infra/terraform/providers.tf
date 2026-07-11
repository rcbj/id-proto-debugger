# Default provider — all regional resources (S3, CloudFront is global but
# managed here, Route 53 is global) use this region.
provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile != "" ? var.aws_profile : null

  default_tags {
    tags = var.tags
  }
}

# CloudFront requires its ACM certificate to live in us-east-1, regardless of
# where the rest of the infrastructure runs.
provider "aws" {
  alias   = "us_east_1"
  region  = "us-east-1"
  profile = var.aws_profile != "" ? var.aws_profile : null

  default_tags {
    tags = var.tags
  }
}
