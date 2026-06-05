terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # Remote state (optional). Create the bucket first, then uncomment and run
  # `terraform init -migrate-state`. See README.md "Remote state".
  #
  # backend "s3" {
  #   bucket       = "gitlawb-terraform-state"
  #   key          = "infra/aws/terraform.tfstate"
  #   region       = "us-east-1"
  #   use_lockfile = true
  # }
}

provider "aws" {
  region = var.region
}
