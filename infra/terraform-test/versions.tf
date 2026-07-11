terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Remote state in S3 (bootstrapped by infra/bootstrap-state.sh). Separate
  # state key from prod, in the same bucket. S3-native locking (no DynamoDB).
  backend "s3" {
    bucket       = "idptools-terraform-state-721850476504"
    key          = "idptools.com/test.tfstate"
    region       = "us-west-2"
    encrypt      = true
    use_lockfile = true
  }
}
