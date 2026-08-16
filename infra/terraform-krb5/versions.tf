terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    # Generates the instance key pair, which is what decrypts the Windows
    # Administrator password. Nothing is read off disk.
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    # The domain, service and user passwords. Generated per apply and never
    # committed.
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # Remote state in S3 (bootstrapped by infra/bootstrap-state.sh), in the SAME
  # bucket as prod and test but under a DIFFERENT KEY — and that separate key is
  # the whole isolation story for this stack.
  #
  # `terraform destroy` can only destroy what is in the state file it is pointed
  # at. Because this stack's state lives at krb5-interop/dc.tfstate and the
  # static sites live at idptools.com/prod.tfstate and idptools.com/test.tfstate,
  # a destroy here cannot see, let alone remove, a bucket, distribution,
  # certificate or Route 53 record belonging to either site. There is no shared
  # resource and no data source reaching across: this module creates its own VPC
  # rather than borrowing the default one, so not even a network object is held
  # in common. See README.md in this directory.
  backend "s3" {
    bucket       = "idptools-terraform-state-721850476504"
    key          = "krb5-interop/dc.tfstate"
    region       = "us-west-2"
    encrypt      = true
    use_lockfile = true
  }
}
