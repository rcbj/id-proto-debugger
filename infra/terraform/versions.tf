terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # For a public repo, DO NOT commit local state (it can contain sensitive
  # values). Either rely on the .gitignore in this directory, or better, use a
  # remote backend. Example (uncomment and fill in an existing bucket/table):
  #
  # backend "s3" {
  #   bucket         = "my-terraform-state"
  #   key            = "idptools.com/static-site.tfstate"
  #   region         = "us-west-2"
  #   dynamodb_table = "terraform-locks"
  #   encrypt        = true
  # }
}
