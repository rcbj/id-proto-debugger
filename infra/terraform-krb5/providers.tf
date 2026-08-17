# Single region. Nothing here is global: no CloudFront, no ACM, no Route 53, so
# unlike the two site modules this one needs no us-east-1 alias.
provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile != "" ? var.aws_profile : null

  default_tags {
    tags = var.tags
  }
}
