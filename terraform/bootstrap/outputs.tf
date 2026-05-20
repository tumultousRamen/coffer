output "state_bucket" {
  description = "S3 bucket holding terraform.tfstate for the main stack. Wire into ../backend.tf."
  value       = aws_s3_bucket.tf_state.bucket
}

output "lock_table" {
  description = "DynamoDB table used by the main stack's state backend for locks."
  value       = aws_dynamodb_table.tf_lock.name
}

output "region" {
  description = "Region the state backend lives in."
  value       = var.region
}

output "github_oidc_provider_arn" {
  description = "ARN of the GitHub OIDC provider. Both deploy + test roles trust this."
  value       = aws_iam_openid_connect_provider.github.arn
}

output "deploy_role_arn" {
  description = "Role ARN GH Actions deploy.yml assumes (locked to refs/heads/main)."
  value       = aws_iam_role.github_deploy.arn
}

output "test_role_arn" {
  description = "Role ARN GH Actions test.yml assumes (any ref on the trusted repo)."
  value       = aws_iam_role.github_test.arn
}
