terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Remote state in S3 (bootstrapped by infra/bootstrap-state.sh). Locking uses
  # S3-native lockfiles (Terraform >= 1.11), so no DynamoDB table is needed.
  backend "s3" {
    bucket       = "idptools-terraform-state-721850476504"
    key          = "idptools.com/prod.tfstate"
    region       = "us-west-2"
    encrypt      = true
    use_lockfile = true
  }
}
