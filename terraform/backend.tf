# S3 backend for the main stack's state (PRD 0009 §2).
#
# Bucket + lock table are provisioned by terraform/bootstrap/.
# Bucket name is account-id-suffixed; pass it on first init:
#
#   terraform init \
#     -backend-config="bucket=coffer-tf-state-<account-id>"
#
# Subsequent inits reuse the bucket name cached in
# .terraform/terraform.tfstate.
terraform {
  backend "s3" {
    key            = "coffer/main.tfstate"
    region         = "us-west-1"
    dynamodb_table = "coffer-tf-lock"
    encrypt        = true
  }
}
